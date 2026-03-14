/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file ecqv.c
 * @brief ECQV Implicit Certificate Protocol Implementation.
 * @details Implements ECQV over SM2 curves with OpenSSL backend and
 * zero-dependency CBOR.
 */

#include "sm2_implicit_cert.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>

/* ========================================== */
/* Internal Helpers */
/* ========================================== */

static BIGNUM *utils_bin_to_bn(const uint8_t *buf, size_t len)
{
    return BN_bin2bn(buf, len, NULL);
}

static void utils_bn_to_bin(const BIGNUM *bn, uint8_t *buf, size_t len)
{
    int num_bytes = BN_num_bytes(bn);
    int offset = len - num_bytes;
    if (offset < 0)
        offset = 0;
    memset(buf, 0, len);
    BN_bn2bin(bn, buf + offset);
}

static EC_GROUP *utils_get_sm2_group()
{
    return EC_GROUP_new_by_curve_name(NID_sm2);
}

static sm2_ic_error_t utils_point_is_valid(
    const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx)
{
    if (!group || !point || !ctx)
        return SM2_IC_ERR_PARAM;

    if (EC_POINT_is_at_infinity(group, point) == 1)
        return SM2_IC_ERR_VERIFY;

    int on_curve = EC_POINT_is_on_curve(group, point, ctx);
    if (on_curve == 1)
        return SM2_IC_SUCCESS;
    return on_curve == 0 ? SM2_IC_ERR_VERIFY : SM2_IC_ERR_CRYPTO;
}

static sm2_ic_error_t utils_octets_to_point_checked(const EC_GROUP *group,
    EC_POINT *point, const uint8_t *octets, size_t octets_len, BN_CTX *ctx)
{
    if (!group || !point || !octets || !ctx)
        return SM2_IC_ERR_PARAM;
    if (EC_POINT_oct2point(group, point, octets, octets_len, ctx) != 1)
        return SM2_IC_ERR_VERIFY;
    return utils_point_is_valid(group, point, ctx);
}

static sm2_ic_error_t utils_affine_to_point_checked(const EC_GROUP *group,
    EC_POINT *point, const sm2_ec_point_t *affine_point, BN_CTX *ctx)
{
    if (!group || !point || !affine_point || !ctx)
        return SM2_IC_ERR_PARAM;

    uint8_t buf[65];
    buf[0] = 0x04;
    memcpy(buf + 1, affine_point->x, SM2_KEY_LEN);
    memcpy(buf + 1 + SM2_KEY_LEN, affine_point->y, SM2_KEY_LEN);
    return utils_octets_to_point_checked(group, point, buf, sizeof(buf), ctx);
}

static sm2_ic_error_t utils_generate_serial(uint64_t *serial_out)
{
    if (!serial_out)
        return SM2_IC_ERR_PARAM;

    uint8_t rnd[sizeof(uint64_t)] = { 0 };
    if (RAND_bytes(rnd, sizeof(rnd)) != 1)
        return SM2_IC_ERR_CRYPTO;

    uint64_t serial = 0;
    for (size_t i = 0; i < sizeof(rnd); i++)
    {
        serial = (serial << 8) | rnd[i];
    }
    if (serial == 0)
        serial = 1;
    *serial_out = serial;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t utils_rand_scalar_nonzero(
    BIGNUM *out, const BIGNUM *order)
{
    if (!out || !order)
        return SM2_IC_ERR_PARAM;

    for (int i = 0; i < 64; i++)
    {
        if (BN_rand_range(out, order) != 1)
            return SM2_IC_ERR_CRYPTO;
        if (!BN_is_zero(out))
            return SM2_IC_SUCCESS;
    }

    return SM2_IC_ERR_CRYPTO;
}

static int utils_valid_field_mask(uint16_t field_mask)
{
    return (field_mask & (uint16_t)(~SM2_IC_FIELD_MASK_ALL)) == 0;
}

static int utils_valid_key_usage(uint8_t key_usage)
{
    const uint8_t allowed_mask = SM2_KU_DIGITAL_SIGNATURE
        | SM2_KU_NON_REPUDIATION | SM2_KU_KEY_ENCIPHERMENT
        | SM2_KU_DATA_ENCIPHERMENT | SM2_KU_KEY_AGREEMENT;
    return key_usage != 0 && (key_usage & (uint8_t)(~allowed_mask)) == 0;
}

static sm2_ic_error_t utils_require_secure_field_mask(uint16_t field_mask)
{
    return field_mask == SM2_IC_FIELD_MASK_ALL ? SM2_IC_SUCCESS
                                               : SM2_IC_ERR_PARAM;
}

static int utils_field_enabled(uint16_t mask, uint16_t field_bit)
{
    return (mask & field_bit) != 0;
}

static int utils_field_count(uint16_t mask)
{
    int count = 0;
    if (utils_field_enabled(mask, SM2_IC_FIELD_SUBJECT_ID))
        count++;
    if (utils_field_enabled(mask, SM2_IC_FIELD_ISSUER_ID))
        count++;
    if (utils_field_enabled(mask, SM2_IC_FIELD_VALID_FROM))
        count++;
    if (utils_field_enabled(mask, SM2_IC_FIELD_VALID_DURATION))
        count++;
    if (utils_field_enabled(mask, SM2_IC_FIELD_KEY_USAGE))
        count++;
    return count;
}

/**
 * @brief Computes the certificate hash: h = Hash(CBOR(Cert))
 * @note Enforces Big-Endian encoding via CBOR before hashing to ensure
 * cross-platform consistency.
 */
static sm2_ic_error_t utils_calc_cert_hash(const sm2_implicit_cert_t *cert,
    BIGNUM *h_bn, const BIGNUM *order, BN_CTX *ctx)
{
    (void)ctx;
    uint8_t hash_buf[SM3_DIGEST_LENGTH];

    /* Allocate temp buffer for canonicalization (1KB is sufficient for this */
    /* schema) */
    uint8_t cbor_temp[1024];
    size_t cbor_len = sizeof(cbor_temp);

    /* 1. Canonicalize cert data to byte stream */
    sm2_ic_error_t ret = sm2_ic_cbor_encode_cert(cbor_temp, &cbor_len, cert);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    /* 2. Compute SM3 Digest */
    if (sm2_ic_sm3_hash(cbor_temp, cbor_len, hash_buf) != SM2_IC_SUCCESS)
        return SM2_IC_ERR_CRYPTO;

    /* 3. Convert to Integer (mod n) */
    if (!BN_bin2bn(hash_buf, SM3_DIGEST_LENGTH, h_bn))
    {
        return SM2_IC_ERR_CRYPTO;
    }
    if (!BN_nnmod(h_bn, h_bn, order, ctx))
    {
        return SM2_IC_ERR_CRYPTO;
    }
    return SM2_IC_SUCCESS;
}

/* ========================================== */
/* Cryptographic Primitives */
/* ========================================== */

sm2_ic_error_t sm2_ic_generate_random(uint8_t *buf, size_t len)
{
    if (!buf && len > 0)
        return SM2_IC_ERR_PARAM;
    if (len == 0)
        return SM2_IC_SUCCESS;
    /* Note: For production embedded systems, replace with HAL_TRNG driver. */
    if (RAND_bytes(buf, len) != 1)
    {
        return SM2_IC_ERR_CRYPTO;
    }
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_ic_sm3_hash(
    const uint8_t *input, size_t input_len, uint8_t *output)
{
    if (!output || (!input && input_len > 0))
        return SM2_IC_ERR_PARAM;

    unsigned int len = SM3_DIGEST_LENGTH;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        return SM2_IC_ERR_MEMORY;

    const EVP_MD *md = EVP_sm3();
    if (!md || EVP_DigestInit_ex(mdctx, md, NULL) != 1
        || EVP_DigestUpdate(mdctx, input, input_len) != 1
        || EVP_DigestFinal_ex(mdctx, output, &len) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return SM2_IC_ERR_CRYPTO;
    }
    EVP_MD_CTX_free(mdctx);
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_ic_sm2_point_mult(sm2_ec_point_t *point,
    const uint8_t *scalar, size_t scalar_len, const sm2_ec_point_t *base_point)
{
    if (!point || !scalar || scalar_len == 0)
        return SM2_IC_ERR_PARAM;

    EC_GROUP *group = utils_get_sm2_group();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *k = utils_bin_to_bn(scalar, scalar_len);
    EC_POINT *R = NULL;
    EC_POINT *P = NULL;
    sm2_ic_error_t ret = SM2_IC_ERR_CRYPTO;

    if (!group || !ctx || !k)
    {
        ret = SM2_IC_ERR_MEMORY;
        goto clean_up;
    }

    R = EC_POINT_new(group);
    if (!R)
    {
        ret = SM2_IC_ERR_MEMORY;
        goto clean_up;
    }

    /* Perform Scalar Multiplication: R = k * G (if base_point is NULL) or R =
     * k
     */
    /* * P */
    if (base_point == NULL)
    {
        if (EC_POINT_mul(group, R, k, NULL, NULL, ctx) != 1)
            goto clean_up;
    }
    else
    {
        P = EC_POINT_new(group);
        if (!P)
        {
            ret = SM2_IC_ERR_MEMORY;
            goto clean_up;
        }

        ret = utils_affine_to_point_checked(group, P, base_point, ctx);
        if (ret != SM2_IC_SUCCESS)
            goto clean_up;
        if (EC_POINT_mul(group, R, NULL, P, k, ctx) != 1)
            goto clean_up;
    }

    {
        uint8_t point_buf[65];
        if (EC_POINT_point2oct(group, R, POINT_CONVERSION_UNCOMPRESSED,
                point_buf, sizeof(point_buf), ctx)
            != sizeof(point_buf))
        {
            goto clean_up;
        }
        memcpy(point->x, point_buf + 1, 32);
        memcpy(point->y, point_buf + 33, 32);
        ret = SM2_IC_SUCCESS;
    }

clean_up:
    BN_clear_free(k);
    EC_POINT_free(P);
    EC_POINT_free(R);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    return ret;
}

void sm2_ic_issue_ctx_init(sm2_ic_issue_ctx_t *ctx)
{
    if (!ctx)
        return;
    ctx->field_mask = SM2_IC_FIELD_MASK_ALL;
}

sm2_ic_error_t sm2_ic_issue_ctx_set_field_mask(
    sm2_ic_issue_ctx_t *ctx, uint16_t field_mask)
{
    if (!ctx || !utils_valid_field_mask(field_mask))
    {
        return SM2_IC_ERR_PARAM;
    }
    if (utils_require_secure_field_mask(field_mask) != SM2_IC_SUCCESS)
        return SM2_IC_ERR_PARAM;
    ctx->field_mask = field_mask;
    return SM2_IC_SUCCESS;
}

uint16_t sm2_ic_issue_ctx_get_field_mask(const sm2_ic_issue_ctx_t *ctx)
{
    if (!ctx)
        return SM2_IC_FIELD_MASK_ALL;
    return ctx->field_mask;
}

static sm2_ic_error_t utils_ca_public_key_matches_private(
    const sm2_private_key_t *ca_private_key,
    const sm2_ec_point_t *ca_public_key)
{
    sm2_ec_point_t derived;

    if (!ca_private_key || !ca_public_key)
        return SM2_IC_ERR_PARAM;

    if (sm2_ic_sm2_point_mult(&derived, ca_private_key->d, SM2_KEY_LEN, NULL)
        != SM2_IC_SUCCESS)
    {
        return SM2_IC_ERR_CRYPTO;
    }

    return memcmp(&derived, ca_public_key, sizeof(derived)) == 0
        ? SM2_IC_SUCCESS
        : SM2_IC_ERR_VERIFY;
}

/* ========================================== */
/* ECQV Protocol Logic */
/* ========================================== */

sm2_ic_error_t sm2_ic_create_cert_request(sm2_ic_cert_request_t *request,
    const uint8_t *subject_id, size_t subject_id_len, uint8_t key_usage,
    sm2_private_key_t *temp_private_key)
{
    if (!request || !subject_id || !temp_private_key)
        return SM2_IC_ERR_PARAM;
    if (subject_id_len > sizeof(request->subject_id))
        return SM2_IC_ERR_PARAM;
    if (!utils_valid_key_usage(key_usage))
        return SM2_IC_ERR_PARAM;

    memset(request, 0, sizeof(*request));

    EC_GROUP *group = utils_get_sm2_group();
    BN_CTX *ctx = BN_CTX_new();

    /* Generate Ephemeral Keypair (k, R_U) */
    BIGNUM *x = BN_new();
    const BIGNUM *order = group ? EC_GROUP_get0_order(group) : NULL;
    EC_POINT *X = NULL;
    sm2_ic_error_t ret = SM2_IC_ERR_CRYPTO;

    if (!group || !ctx || !x || !order)
    {
        ret = SM2_IC_ERR_MEMORY;
        goto clean_up;
    }

    X = EC_POINT_new(group);
    if (!X)
    {
        ret = SM2_IC_ERR_MEMORY;
        goto clean_up;
    }

    if (utils_rand_scalar_nonzero(x, order) != SM2_IC_SUCCESS)
        goto clean_up;

    if (EC_POINT_mul(group, X, x, NULL, NULL, ctx) != 1)
        goto clean_up;

    /* Export Results */
    utils_bn_to_bin(x, temp_private_key->d, 32);

    uint8_t point_buf[65];
    if (EC_POINT_point2oct(group, X, POINT_CONVERSION_UNCOMPRESSED, point_buf,
            sizeof(point_buf), ctx)
        != sizeof(point_buf))
    {
        goto clean_up;
    }
    memcpy(request->temp_public_key.x, point_buf + 1, 32);
    memcpy(request->temp_public_key.y, point_buf + 33, 32);

    memcpy(request->subject_id, subject_id, subject_id_len);
    request->subject_id_len = subject_id_len;
    request->key_usage = key_usage;
    ret = SM2_IC_SUCCESS;

clean_up:
    BN_clear_free(x);
    EC_POINT_free(X);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    return ret;
}

sm2_ic_error_t sm2_ic_ca_generate_cert_with_ctx(sm2_ic_cert_result_t *result,
    const sm2_ic_cert_request_t *request, const uint8_t *issuer_id,
    size_t issuer_id_len, const sm2_private_key_t *ca_private_key,
    const sm2_ec_point_t *ca_public_key, const sm2_ic_issue_ctx_t *issue_ctx,
    uint64_t now_ts)
{
    if (!result || !request || !ca_private_key || !ca_public_key)
        return SM2_IC_ERR_PARAM;
    memset(result, 0, sizeof(*result));
    if (request->subject_id_len > sizeof(result->cert.subject_id))
        return SM2_IC_ERR_PARAM;
    if (issuer_id_len > sizeof(result->cert.issuer_id))
        return SM2_IC_ERR_PARAM;
    if (issuer_id_len > 0 && issuer_id == NULL)
        return SM2_IC_ERR_PARAM;
    if (issue_ctx && !utils_valid_field_mask(issue_ctx->field_mask))
        return SM2_IC_ERR_PARAM;
    if (issue_ctx
        && utils_require_secure_field_mask(issue_ctx->field_mask)
            != SM2_IC_SUCCESS)
    {
        return SM2_IC_ERR_PARAM;
    }

    sm2_ic_error_t ret
        = utils_ca_public_key_matches_private(ca_private_key, ca_public_key);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    EC_GROUP *group = utils_get_sm2_group();
    BN_CTX *ctx = BN_CTX_new();
    const BIGNUM *order = group ? EC_GROUP_get0_order(group) : NULL;
    uint64_t serial = 0;
    BIGNUM *k = BN_new();
    BIGNUM *d_ca = utils_bin_to_bn(ca_private_key->d, 32);
    EC_POINT *X = group ? EC_POINT_new(group) : NULL;
    EC_POINT *V = group ? EC_POINT_new(group) : NULL;
    BIGNUM *h = BN_new();
    BIGNUM *s = BN_new();
    EC_POINT *kG = group ? EC_POINT_new(group) : NULL;
    BIGNUM *tmp = BN_new();
    ret = SM2_IC_ERR_CRYPTO;

    if (!group || !ctx || !order || !k || !d_ca || !X || !V || !h || !s || !kG
        || !tmp)
    {
        ret = SM2_IC_ERR_MEMORY;
        goto clean_up;
    }

    /* Import Ephemeral Key X */
    ret = utils_affine_to_point_checked(
        group, X, &request->temp_public_key, ctx);
    if (ret != SM2_IC_SUCCESS)
        goto clean_up;

    /* 1. Calculate Public Reconstruction Key: V = X + k*G */
    if (utils_rand_scalar_nonzero(k, order) != SM2_IC_SUCCESS)
        goto clean_up;
    if (EC_POINT_mul(group, kG, k, NULL, NULL, ctx) != 1)
        goto clean_up;
    if (EC_POINT_add(group, V, X, kG, ctx) != 1)
        goto clean_up;

    /* 2. Fill Certificate Metadata (fields controlled by global field mask */
    /* template) */
    const uint16_t mask
        = issue_ctx ? issue_ctx->field_mask : SM2_IC_FIELD_MASK_ALL;
    ret = utils_generate_serial(&serial);
    if (ret != SM2_IC_SUCCESS)
        goto clean_up;

    result->cert.type = SM2_CERT_TYPE_IMPLICIT;
    result->cert.serial_number = serial;
    result->cert.field_mask = mask;

    if (utils_field_enabled(mask, SM2_IC_FIELD_SUBJECT_ID))
    {
        memcpy(result->cert.subject_id, request->subject_id,
            request->subject_id_len);
        result->cert.subject_id_len = request->subject_id_len;
    }
    else
    {
        result->cert.subject_id_len = 0;
    }

    if (utils_field_enabled(mask, SM2_IC_FIELD_ISSUER_ID) && issuer_id_len > 0)
    {
        memcpy(result->cert.issuer_id, issuer_id, issuer_id_len);
        result->cert.issuer_id_len = issuer_id_len;
    }
    else
    {
        result->cert.issuer_id_len = 0;
    }

    if (utils_field_enabled(mask, SM2_IC_FIELD_VALID_FROM))
    {
        result->cert.valid_from = now_ts;
    }
    else
    {
        result->cert.valid_from = 0;
    }

    if (utils_field_enabled(mask, SM2_IC_FIELD_VALID_DURATION))
    {
        result->cert.valid_duration = 365 * 24 * 3600;
    }
    else
    {
        result->cert.valid_duration = 0;
    }

    if (utils_field_enabled(mask, SM2_IC_FIELD_KEY_USAGE))
    {
        result->cert.key_usage = request->key_usage;
    }
    else
    {
        result->cert.key_usage = 0;
    }

    /* 3. Export V (Compressed Format, 33 bytes) */
    if (EC_POINT_point2oct(group, V, POINT_CONVERSION_COMPRESSED,
            result->cert.public_recon_key, SM2_COMPRESSED_KEY_LEN, ctx)
        != SM2_COMPRESSED_KEY_LEN)
    {
        goto clean_up;
    }

    /* 4. Calculate Hash: h = SM3(CBOR(Cert)) */
    if ((ret = utils_calc_cert_hash(&result->cert, h, order, ctx))
        != SM2_IC_SUCCESS)
    {
        goto clean_up;
    }

    /* 5. Compute Private Reconstruction Data: s = (h * k + d_CA) mod n */
    if (BN_mod_mul(tmp, h, k, order, ctx) != 1)
        goto clean_up;
    if (BN_mod_add(s, tmp, d_ca, order, ctx) != 1)
        goto clean_up;

    utils_bn_to_bin(s, result->private_recon_value, 32);
    ret = SM2_IC_SUCCESS;

clean_up:
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    BN_clear_free(k);
    BN_clear_free(d_ca);
    EC_POINT_free(X);
    EC_POINT_free(V);
    BN_free(h);
    BN_clear_free(s);
    BN_clear_free(tmp);
    EC_POINT_free(kG);
    return ret;
}

sm2_ic_error_t sm2_ic_ca_generate_cert(sm2_ic_cert_result_t *result,
    const sm2_ic_cert_request_t *request, const uint8_t *issuer_id,
    size_t issuer_id_len, const sm2_private_key_t *ca_private_key,
    const sm2_ec_point_t *ca_public_key, uint64_t now_ts)
{
    sm2_ic_issue_ctx_t default_ctx;
    sm2_ic_issue_ctx_init(&default_ctx);
    return sm2_ic_ca_generate_cert_with_ctx(result, request, issuer_id,
        issuer_id_len, ca_private_key, ca_public_key, &default_ctx, now_ts);
}

sm2_ic_error_t sm2_ic_reconstruct_keys(sm2_private_key_t *private_key,
    sm2_ec_point_t *public_key, const sm2_ic_cert_result_t *cert_result,
    const sm2_private_key_t *temp_private_key,
    const sm2_ec_point_t *ca_public_key)
{
    if (!private_key || !public_key || !cert_result || !temp_private_key
        || !ca_public_key)
    {
        return SM2_IC_ERR_PARAM;
    }
    memset(private_key, 0, sizeof(*private_key));
    memset(public_key, 0, sizeof(*public_key));
    EC_GROUP *group = utils_get_sm2_group();
    BN_CTX *ctx = BN_CTX_new();
    const BIGNUM *order = group ? EC_GROUP_get0_order(group) : NULL;

    BIGNUM *x = utils_bin_to_bn(temp_private_key->d, 32);
    BIGNUM *s = utils_bin_to_bn(cert_result->private_recon_value, 32);
    BIGNUM *h = BN_new();
    BIGNUM *d_u = BN_new();
    BIGNUM *tmp = BN_new();
    EC_POINT *Q = group ? EC_POINT_new(group) : NULL;
    sm2_ic_error_t ret = SM2_IC_ERR_CRYPTO;

    if (!group || !ctx || !order || !x || !s || !h || !d_u || !tmp || !Q)
    {
        ret = SM2_IC_ERR_MEMORY;
        goto clean_up;
    }

    /* 1. Calculate Hash h */
    if ((ret = utils_calc_cert_hash(&cert_result->cert, h, order, ctx))
        != SM2_IC_SUCCESS)
        goto clean_up;

    /* 2. Recover User Private Key: d_U = (h * x + s) mod n */
    if (BN_mod_mul(tmp, h, x, order, ctx) != 1)
        goto clean_up;
    if (BN_mod_add(d_u, tmp, s, order, ctx) != 1)
        goto clean_up;

    utils_bn_to_bin(d_u, private_key->d, 32);

    /* 3. Derived User Public Key: Q_U = d_U * G */
    if (EC_POINT_mul(group, Q, d_u, NULL, NULL, ctx) != 1)
        goto clean_up;

    uint8_t point_buf[65];
    if (EC_POINT_point2oct(group, Q, POINT_CONVERSION_UNCOMPRESSED, point_buf,
            sizeof(point_buf), ctx)
        != sizeof(point_buf))
    {
        goto clean_up;
    }
    memcpy(public_key->x, point_buf + 1, 32);
    memcpy(public_key->y, point_buf + 33, 32);
    ret = sm2_ic_verify_cert(&cert_result->cert, public_key, ca_public_key);

clean_up:
    if (ret != SM2_IC_SUCCESS)
    {
        memset(private_key, 0, sizeof(*private_key));
        memset(public_key, 0, sizeof(*public_key));
    }
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    BN_clear_free(x);
    BN_clear_free(s);
    BN_free(h);
    BN_clear_free(d_u);
    BN_clear_free(tmp);
    EC_POINT_free(Q);
    return ret;
}

sm2_ic_error_t sm2_ic_verify_cert(const sm2_implicit_cert_t *cert,
    const sm2_ec_point_t *public_key, const sm2_ec_point_t *ca_public_key)
{
    if (!cert || !public_key || !ca_public_key)
        return SM2_IC_ERR_PARAM;
    if (cert->type != SM2_CERT_TYPE_IMPLICIT)
        return SM2_IC_ERR_VERIFY;
    if ((cert->field_mask & SM2_IC_FIELD_KEY_USAGE) != 0
        && !utils_valid_key_usage(cert->key_usage))
    {
        return SM2_IC_ERR_VERIFY;
    }

    EC_GROUP *group = utils_get_sm2_group();
    BN_CTX *ctx = BN_CTX_new();
    const BIGNUM *order = group ? EC_GROUP_get0_order(group) : NULL;

    BIGNUM *h = BN_new();
    EC_POINT *Q_U = group ? EC_POINT_new(group) : NULL;
    EC_POINT *P_CA = group ? EC_POINT_new(group) : NULL;
    EC_POINT *V = group ? EC_POINT_new(group) : NULL;
    EC_POINT *Calc_Q = group ? EC_POINT_new(group) : NULL;
    EC_POINT *hV = group ? EC_POINT_new(group) : NULL;
    sm2_ic_error_t ret = SM2_IC_ERR_CRYPTO;

    if (!group || !ctx || !order || !h || !Q_U || !P_CA || !V || !Calc_Q || !hV)
    {
        ret = SM2_IC_ERR_MEMORY;
        goto clean_up;
    }

    /* Helper: Point Conversion */
    ret = utils_affine_to_point_checked(group, Q_U, public_key, ctx);
    if (ret != SM2_IC_SUCCESS)
        goto clean_up;

    ret = utils_affine_to_point_checked(group, P_CA, ca_public_key, ctx);
    if (ret != SM2_IC_SUCCESS)
        goto clean_up;

    /* Decompress V */
    ret = utils_octets_to_point_checked(
        group, V, cert->public_recon_key, SM2_COMPRESSED_KEY_LEN, ctx);
    if (ret != SM2_IC_SUCCESS)
        goto clean_up;

    /* 1. Calculate Hash h */
    if ((ret = utils_calc_cert_hash(cert, h, order, ctx)) != SM2_IC_SUCCESS)
        goto clean_up;

    /* 2. Verify: Q_U == h * V + P_CA */
    if (EC_POINT_mul(group, hV, NULL, V, h, ctx) != 1)
        goto clean_up;
    if (EC_POINT_add(group, Calc_Q, hV, P_CA, ctx) != 1)
        goto clean_up;

    ret = (EC_POINT_cmp(group, Q_U, Calc_Q, ctx) == 0) ? SM2_IC_SUCCESS
                                                       : SM2_IC_ERR_VERIFY;

clean_up:
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    BN_free(h);
    EC_POINT_free(Q_U);
    EC_POINT_free(P_CA);
    EC_POINT_free(V);
    EC_POINT_free(Calc_Q);
    EC_POINT_free(hV);
    return ret;
}

/* ========================================== */
/* CBOR Serialization (Minimal Implementation) */
/* ========================================== */

static void utils_cbor_write_head(
    uint8_t *buf, size_t *offset, uint8_t major_type, uint64_t val)
{
    uint8_t *p = buf + *offset;
    major_type <<= 5;

    if (val < 24)
    {
        *p = major_type | (uint8_t)val;
        (*offset)++;
    }
    else if (val <= 0xFF)
    {
        *p++ = major_type | 24;
        *p = (uint8_t)val;
        (*offset) += 2;
    }
    else if (val <= 0xFFFF)
    {
        *p++ = major_type | 25;
        *p++ = (uint8_t)(val >> 8);
        *p = (uint8_t)(val);
        (*offset) += 3;
    }
    else if (val <= 0xFFFFFFFF)
    {
        *p++ = major_type | 26;
        *p++ = (uint8_t)(val >> 24);
        *p++ = (uint8_t)(val >> 16);
        *p++ = (uint8_t)(val >> 8);
        *p = (uint8_t)(val);
        (*offset) += 5;
    }
    else
    {
        *p++ = major_type | 27;
        for (int i = 7; i >= 0; i--)
        {
            *p++ = (uint8_t)(val >> (i * 8));
        }
        (*offset) += 9;
    }
}

static size_t utils_cbor_head_len(uint64_t val)
{
    if (val < 24)
        return 1;
    if (val <= 0xFF)
        return 2;
    if (val <= 0xFFFF)
        return 3;
    if (val <= 0xFFFFFFFF)
        return 5;
    return 9;
}

static sm2_ic_error_t utils_cbor_read_head(const uint8_t *buf, size_t len,
    size_t *offset, uint8_t expected_major, uint64_t *val)
{
    if (*offset >= len)
        return SM2_IC_ERR_CBOR;

    uint8_t byte = buf[*offset];
    uint8_t major = byte >> 5;
    uint8_t info = byte & 0x1F;
    (*offset)++;

    if (major != expected_major)
        return SM2_IC_ERR_CBOR;

    if (info < 24)
    {
        *val = info;
    }
    else if (info == 24)
    {
        if (*offset + 1 > len)
            return SM2_IC_ERR_CBOR;
        *val = buf[(*offset)++];
    }
    else if (info == 25)
    {
        if (*offset + 2 > len)
            return SM2_IC_ERR_CBOR;
        *val = ((uint64_t)buf[*offset] << 8) | buf[*offset + 1];
        (*offset) += 2;
    }
    else if (info == 26)
    {
        if (*offset + 4 > len)
            return SM2_IC_ERR_CBOR;
        *val = 0;
        for (int i = 0; i < 4; i++)
            *val = (*val << 8) | buf[(*offset)++];
    }
    else if (info == 27)
    {
        if (*offset + 8 > len)
            return SM2_IC_ERR_CBOR;
        *val = 0;
        for (int i = 0; i < 8; i++)
            *val = (*val << 8) | buf[(*offset)++];
    }
    else
    {
        return SM2_IC_ERR_CBOR;
    }
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_ic_cbor_encode_cert(
    uint8_t *output, size_t *output_len, const sm2_implicit_cert_t *cert)
{
    const uint16_t mask = cert ? cert->field_mask : 0;
    const int optional_field_count = utils_field_count(mask);
    const size_t array_len = (size_t)(4
        + optional_field_count); /* type + serial + mask + V + optional */

    if (!output || !output_len || !cert)
        return SM2_IC_ERR_PARAM;
    if (cert->subject_id_len > sizeof(cert->subject_id)
        || cert->issuer_id_len > sizeof(cert->issuer_id))
    {
        return SM2_IC_ERR_PARAM;
    }
    if (!utils_valid_field_mask(mask))
    {
        return SM2_IC_ERR_PARAM;
    }
    if (cert->type != SM2_CERT_TYPE_IMPLICIT)
    {
        return SM2_IC_ERR_PARAM;
    }
    if ((mask & SM2_IC_FIELD_KEY_USAGE) != 0
        && !utils_valid_key_usage(cert->key_usage))
    {
        return SM2_IC_ERR_PARAM;
    }

    const size_t cap = *output_len;
    size_t offset = 0;

    if (offset + utils_cbor_head_len(array_len) > cap)
        return SM2_IC_ERR_MEMORY;
    utils_cbor_write_head(output, &offset, 4, array_len);

    if (offset + utils_cbor_head_len(cert->type) > cap)
        return SM2_IC_ERR_MEMORY;
    utils_cbor_write_head(output, &offset, 0, cert->type);

    if (offset + utils_cbor_head_len(cert->serial_number) > cap)
        return SM2_IC_ERR_MEMORY;
    utils_cbor_write_head(output, &offset, 0, cert->serial_number);

    if (offset + utils_cbor_head_len(mask) > cap)
        return SM2_IC_ERR_MEMORY;
    utils_cbor_write_head(output, &offset, 0, mask);

    if (utils_field_enabled(mask, SM2_IC_FIELD_SUBJECT_ID))
    {
        if (offset + utils_cbor_head_len(cert->subject_id_len)
                + cert->subject_id_len
            > cap)
            return SM2_IC_ERR_MEMORY;
        utils_cbor_write_head(output, &offset, 2, cert->subject_id_len);
        memcpy(output + offset, cert->subject_id, cert->subject_id_len);
        offset += cert->subject_id_len;
    }

    if (utils_field_enabled(mask, SM2_IC_FIELD_ISSUER_ID))
    {
        if (offset + utils_cbor_head_len(cert->issuer_id_len)
                + cert->issuer_id_len
            > cap)
            return SM2_IC_ERR_MEMORY;
        utils_cbor_write_head(output, &offset, 2, cert->issuer_id_len);
        memcpy(output + offset, cert->issuer_id, cert->issuer_id_len);
        offset += cert->issuer_id_len;
    }

    if (utils_field_enabled(mask, SM2_IC_FIELD_VALID_FROM))
    {
        if (offset + utils_cbor_head_len(cert->valid_from) > cap)
            return SM2_IC_ERR_MEMORY;
        utils_cbor_write_head(output, &offset, 0, cert->valid_from);
    }

    if (utils_field_enabled(mask, SM2_IC_FIELD_VALID_DURATION))
    {
        if (offset + utils_cbor_head_len(cert->valid_duration) > cap)
            return SM2_IC_ERR_MEMORY;
        utils_cbor_write_head(output, &offset, 0, cert->valid_duration);
    }

    if (utils_field_enabled(mask, SM2_IC_FIELD_KEY_USAGE))
    {
        if (offset + utils_cbor_head_len(cert->key_usage) > cap)
            return SM2_IC_ERR_MEMORY;
        utils_cbor_write_head(output, &offset, 0, cert->key_usage);
    }

    if (offset + utils_cbor_head_len(SM2_COMPRESSED_KEY_LEN)
            + SM2_COMPRESSED_KEY_LEN
        > cap)
        return SM2_IC_ERR_MEMORY;
    utils_cbor_write_head(output, &offset, 2, SM2_COMPRESSED_KEY_LEN);
    memcpy(output + offset, cert->public_recon_key, SM2_COMPRESSED_KEY_LEN);
    offset += SM2_COMPRESSED_KEY_LEN;

    *output_len = offset;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_ic_cbor_decode_cert(
    sm2_implicit_cert_t *cert, const uint8_t *input, size_t input_len)
{
    if (!cert || !input)
        return SM2_IC_ERR_PARAM;

    memset(cert, 0, sizeof(*cert));
    size_t offset = 0;
    uint64_t val = 0;
    uint64_t field_mask = 0;
    uint64_t array_len = 0;
    uint64_t expected_len = 0;

    if (utils_cbor_read_head(input, input_len, &offset, 4, &array_len)
        != SM2_IC_SUCCESS)
        return SM2_IC_ERR_CBOR;
    if (utils_cbor_read_head(input, input_len, &offset, 0, &val)
        != SM2_IC_SUCCESS)
        return SM2_IC_ERR_CBOR;
    cert->type = (uint8_t)val;
    if (cert->type != SM2_CERT_TYPE_IMPLICIT)
        return SM2_IC_ERR_CBOR;

    if (utils_cbor_read_head(input, input_len, &offset, 0, &val)
        != SM2_IC_SUCCESS)
        return SM2_IC_ERR_CBOR;
    cert->serial_number = val;

    if (utils_cbor_read_head(input, input_len, &offset, 0, &field_mask)
        != SM2_IC_SUCCESS)
        return SM2_IC_ERR_CBOR;
    if (!utils_valid_field_mask((uint16_t)field_mask))
        return SM2_IC_ERR_CBOR;
    cert->field_mask = (uint16_t)field_mask;

    expected_len = (uint64_t)(4 + utils_field_count(cert->field_mask));
    if (array_len != expected_len)
        return SM2_IC_ERR_CBOR;

    if (utils_field_enabled(cert->field_mask, SM2_IC_FIELD_SUBJECT_ID))
    {
        if (utils_cbor_read_head(input, input_len, &offset, 2, &val)
            != SM2_IC_SUCCESS)
            return SM2_IC_ERR_CBOR;
        cert->subject_id_len = (size_t)val;
        if (cert->subject_id_len > sizeof(cert->subject_id))
            return SM2_IC_ERR_CBOR;
        if (offset + cert->subject_id_len > input_len)
            return SM2_IC_ERR_CBOR;
        memcpy(cert->subject_id, input + offset, cert->subject_id_len);
        offset += cert->subject_id_len;
    }

    if (utils_field_enabled(cert->field_mask, SM2_IC_FIELD_ISSUER_ID))
    {
        if (utils_cbor_read_head(input, input_len, &offset, 2, &val)
            != SM2_IC_SUCCESS)
            return SM2_IC_ERR_CBOR;
        cert->issuer_id_len = (size_t)val;
        if (cert->issuer_id_len > sizeof(cert->issuer_id))
            return SM2_IC_ERR_CBOR;
        if (offset + cert->issuer_id_len > input_len)
            return SM2_IC_ERR_CBOR;
        memcpy(cert->issuer_id, input + offset, cert->issuer_id_len);
        offset += cert->issuer_id_len;
    }

    if (utils_field_enabled(cert->field_mask, SM2_IC_FIELD_VALID_FROM))
    {
        if (utils_cbor_read_head(input, input_len, &offset, 0, &val)
            != SM2_IC_SUCCESS)
            return SM2_IC_ERR_CBOR;
        cert->valid_from = val;
    }

    if (utils_field_enabled(cert->field_mask, SM2_IC_FIELD_VALID_DURATION))
    {
        if (utils_cbor_read_head(input, input_len, &offset, 0, &val)
            != SM2_IC_SUCCESS)
            return SM2_IC_ERR_CBOR;
        cert->valid_duration = val;
    }

    if (utils_field_enabled(cert->field_mask, SM2_IC_FIELD_KEY_USAGE))
    {
        if (utils_cbor_read_head(input, input_len, &offset, 0, &val)
            != SM2_IC_SUCCESS)
            return SM2_IC_ERR_CBOR;
        if (val > UINT8_MAX)
            return SM2_IC_ERR_CBOR;
        cert->key_usage = (uint8_t)val;
        if (!utils_valid_key_usage(cert->key_usage))
            return SM2_IC_ERR_CBOR;
    }

    if (utils_cbor_read_head(input, input_len, &offset, 2, &val)
            != SM2_IC_SUCCESS
        || val != SM2_COMPRESSED_KEY_LEN)
        return SM2_IC_ERR_CBOR;
    if (offset + SM2_COMPRESSED_KEY_LEN > input_len)
        return SM2_IC_ERR_CBOR;
    memcpy(cert->public_recon_key, input + offset, SM2_COMPRESSED_KEY_LEN);
    offset += SM2_COMPRESSED_KEY_LEN;

    if (offset != input_len)
        return SM2_IC_ERR_CBOR;

    return SM2_IC_SUCCESS;
}
