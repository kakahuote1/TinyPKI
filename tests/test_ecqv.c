/* SPDX-License-Identifier: Apache-2.0 */

#include "test_common.h"

static int test_cbor_read_head(const uint8_t *buf, size_t len, size_t *offset,
    uint8_t expected_major, uint64_t *val)
{
    if (!buf || !offset || !val || *offset >= len)
        return 0;
    uint8_t byte = buf[*offset];
    uint8_t major = byte >> 5;
    uint8_t info = byte & 0x1F;
    (*offset)++;
    if (major != expected_major)
        return 0;

    if (info < 24)
    {
        *val = info;
        return 1;
    }
    if (info == 24)
    {
        if (*offset + 1 > len)
            return 0;
        *val = buf[(*offset)++];
        return 1;
    }
    if (info == 25)
    {
        if (*offset + 2 > len)
            return 0;
        *val = ((uint64_t)buf[*offset] << 8) | buf[*offset + 1];
        (*offset) += 2;
        return 1;
    }
    if (info == 26)
    {
        if (*offset + 4 > len)
            return 0;
        *val = 0;
        for (int i = 0; i < 4; i++)
            *val = (*val << 8) | buf[(*offset)++];
        return 1;
    }
    if (info == 27)
    {
        if (*offset + 8 > len)
            return 0;
        *val = 0;
        for (int i = 0; i < 8; i++)
            *val = (*val << 8) | buf[(*offset)++];
        return 1;
    }
    return 0;
}

static void test_setup_ca_case()
{
    test_setup_ca();
    TEST_PASS();
}

static void test_full_lifecycle()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    uint8_t sub_id[] = "UAV_TEST_001";
    uint8_t iss_id[] = "ROOT_CA";
    uint8_t usage = SM2_KU_DIGITAL_SIGNATURE;

    TEST_ASSERT(sm2_ic_create_cert_request(
                    &req, sub_id, strlen((char *)sub_id), usage, &temp_priv)
            == SM2_IC_SUCCESS,
        "Req Create");
    TEST_ASSERT(test_issue_cert(&res, &req, iss_id, strlen((char *)iss_id),
                    &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Cert Issue");
    TEST_ASSERT(
        res.cert.field_mask == SM2_IC_FIELD_MASK_ALL, "Default Field Mask");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Key Recon");
    TEST_ASSERT(
        sm2_ic_verify_cert(&res.cert, &user_pub, &g_ca_pub) == SM2_IC_SUCCESS,
        "Cert Verify");

    TEST_PASS();
}

static void test_tampered_cert()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"DEV", 3,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Create Tamper Request");
    TEST_ASSERT(
        test_issue_cert(&res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue Tamper Cert");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Reconstruct Tamper Keys");

    res.cert.serial_number++;
    TEST_ASSERT(
        sm2_ic_verify_cert(&res.cert, &user_pub, &g_ca_pub) != SM2_IC_SUCCESS,
        "Serial Tamper Detected");

    res.cert.serial_number--;
    res.cert.public_recon_key[5] ^= 0xFF;
    TEST_ASSERT(
        sm2_ic_verify_cert(&res.cert, &user_pub, &g_ca_pub) != SM2_IC_SUCCESS,
        "V-Key Tamper Detected");

    TEST_PASS();
}

static void test_cbor_robustness()
{
    sm2_implicit_cert_t cert;
    memset(&cert, 0, sizeof(cert));
    cert.type = SM2_CERT_TYPE_IMPLICIT;
    cert.serial_number = 1;
    cert.field_mask = 0;
    memset(cert.public_recon_key, 0xAB, SM2_COMPRESSED_KEY_LEN);

    uint8_t buf[1024];
    size_t len = sizeof(buf);

    TEST_ASSERT(sm2_ic_cbor_encode_cert(buf, &len, &cert) == SM2_IC_SUCCESS,
        "Encode OK");

    len = 5;
    TEST_ASSERT(sm2_ic_cbor_encode_cert(buf, &len, &cert) == SM2_IC_ERR_MEMORY,
        "Buffer Overflow Protection");

    /* malformed #1: truncated CBOR */
    for (size_t i = 1; i < 16 && i < len; i++)
    {
        sm2_implicit_cert_t out;
        TEST_ASSERT(sm2_ic_cbor_decode_cert(&out, buf, i) == SM2_IC_ERR_CBOR,
            "Truncated Must Fail");
    }

    /* malformed #2: type mismatch for first cert field (type should be unsigned
     */
    /* int) */
    uint8_t bad_type[1024];
    memcpy(bad_type, buf, len);
    size_t off = 0;
    uint64_t arr_len = 0;
    TEST_ASSERT(test_cbor_read_head(bad_type, len, &off, 4, &arr_len) == 1,
        "Read Array Head");
    TEST_ASSERT(off < len, "Type Field Present");
    bad_type[off] = 0x41; /* major type 2 (byte string, len=1) */
    {
        sm2_implicit_cert_t out;
        TEST_ASSERT(
            sm2_ic_cbor_decode_cert(&out, bad_type, len) == SM2_IC_ERR_CBOR,
            "Type Mismatch Must Fail");
    }

    /* malformed #2b: unsupported certificate type value */
    memcpy(bad_type, buf, len);
    off = 0;
    arr_len = 0;
    TEST_ASSERT(test_cbor_read_head(bad_type, len, &off, 4, &arr_len) == 1,
        "Read Array Head Type Value");
    TEST_ASSERT(off < len, "Type Value Present");
    bad_type[off] = 0x02; /* uint(2), not implicit cert type */
    {
        sm2_implicit_cert_t out;
        TEST_ASSERT(
            sm2_ic_cbor_decode_cert(&out, bad_type, len) == SM2_IC_ERR_CBOR,
            "Unsupported Cert Type Must Fail");
    }

    /* malformed #3: subject_id claimed length > 256 */
    uint8_t oversize[512];
    size_t o = 0;
    oversize[o++] = 0x85; /* array(5): type, serial, mask, subject, V */
    oversize[o++] = 0x01; /* type */
    oversize[o++] = 0x01; /* serial */
    oversize[o++] = 0x01; /* field_mask=SM2_IC_FIELD_SUBJECT_ID */
    oversize[o++] = 0x59; /* bytes with 2-byte length */
    oversize[o++] = 0x01;
    oversize[o++] = 0x01; /* len=257 */
    memset(oversize + o, 0x11, 257);
    o += 257;
    oversize[o++] = 0x58; /* bytes with 1-byte length */
    oversize[o++] = 0x21; /* len=33 */
    memset(oversize + o, 0x22, 33);
    o += 33;
    {
        sm2_implicit_cert_t out;
        TEST_ASSERT(
            sm2_ic_cbor_decode_cert(&out, oversize, o) == SM2_IC_ERR_CBOR,
            "Oversize Subject Must Fail");
    }

    TEST_PASS();
}

static void test_cbor_key_usage_overflow_rejected()
{
    uint8_t bad[128];
    size_t o = 0;

    bad[o++] = 0x85; /* array(5): type, serial, field_mask, key_usage, V */
    bad[o++] = 0x01; /* type implicit */
    bad[o++] = 0x01; /* serial */
    bad[o++] = 0x10; /* field_mask = SM2_IC_FIELD_KEY_USAGE */
    bad[o++] = 0x19; /* uint16 */
    bad[o++] = 0x01;
    bad[o++] = 0x2C; /* key_usage = 300 (> 255) */
    bad[o++] = 0x58;
    bad[o++] = 0x21; /* public_recon_key len=33 */
    memset(bad + o, 0x33, 33);
    o += 33;

    sm2_implicit_cert_t out;
    TEST_ASSERT(sm2_ic_cbor_decode_cert(&out, bad, o) == SM2_IC_ERR_CBOR,
        "Reject key_usage overflow");

    o = 0;
    bad[o++] = 0x85; /* array(5): type, serial, field_mask, key_usage, V */
    bad[o++] = 0x01; /* type implicit */
    bad[o++] = 0x01; /* serial */
    bad[o++] = 0x10; /* field_mask = SM2_IC_FIELD_KEY_USAGE */
    bad[o++] = 0x18; /* uint8 */
    bad[o++] = 0x80; /* invalid usage bit outside whitelist */
    bad[o++] = 0x58;
    bad[o++] = 0x21; /* public_recon_key len=33 */
    memset(bad + o, 0x44, 33);
    o += 33;

    TEST_ASSERT(sm2_ic_cbor_decode_cert(&out, bad, o) == SM2_IC_ERR_CBOR,
        "Reject key_usage invalid bits");

    TEST_PASS();
}

static void test_issue_ctx_secure_default_only()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_issue_ctx_t issue_ctx;
    sm2_ic_issue_ctx_init(&issue_ctx);
    const uint16_t custom_mask
        = SM2_IC_FIELD_SUBJECT_ID | SM2_IC_FIELD_KEY_USAGE;
    TEST_ASSERT(
        sm2_ic_issue_ctx_get_field_mask(&issue_ctx) == SM2_IC_FIELD_MASK_ALL,
        "Default Secure Mask");
    TEST_ASSERT(sm2_ic_issue_ctx_set_field_mask(&issue_ctx, custom_mask)
            == SM2_IC_ERR_PARAM,
        "Reject Custom Mask");
    TEST_ASSERT(
        sm2_ic_issue_ctx_get_field_mask(&issue_ctx) == SM2_IC_FIELD_MASK_ALL,
        "Mask Remains Secure Default");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t res;

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"MASK_CASE", 9,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Req Create");
    TEST_ASSERT(test_issue_cert_with_ctx(&res, &req, (uint8_t *)"CA_MASK", 7,
                    &g_ca_priv, &g_ca_pub, &issue_ctx)
            == SM2_IC_SUCCESS,
        "Issue With Secure Default");
    TEST_ASSERT(
        res.cert.field_mask == SM2_IC_FIELD_MASK_ALL, "Mask Stays Secure");
    TEST_ASSERT(res.cert.subject_id_len > 0, "Subject Present");
    TEST_ASSERT(res.cert.issuer_id_len > 0, "Issuer Present");
    TEST_ASSERT(res.cert.valid_from > 0, "ValidFrom Present");
    TEST_ASSERT(res.cert.valid_duration > 0, "Duration Present");
    TEST_ASSERT(
        res.cert.key_usage == SM2_KU_DIGITAL_SIGNATURE, "Usage Present");

    TEST_PASS();
}

static void test_ca_public_key_consistency_enforced()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_issue_ctx_t issue_ctx;
    sm2_ic_issue_ctx_init(&issue_ctx);
    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;
    sm2_private_key_t wrong_ca_priv;
    sm2_ec_point_t wrong_ca_pub;

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"SIZE_CASE", 9,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Req Create");
    TEST_ASSERT(test_generate_sm2_keypair(&wrong_ca_priv, &wrong_ca_pub),
        "Wrong CA Keypair");

    TEST_ASSERT(test_issue_cert_with_ctx(&cert_res, &req, (uint8_t *)"CA", 2,
                    &g_ca_priv, &wrong_ca_pub, &issue_ctx)
            == SM2_IC_ERR_VERIFY,
        "Reject Issuer Public Key Mismatch");
    TEST_ASSERT(test_issue_cert_with_ctx(&cert_res, &req, (uint8_t *)"CA", 2,
                    &g_ca_priv, &g_ca_pub, &issue_ctx)
            == SM2_IC_SUCCESS,
        "Issue With Matched CA");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &wrong_ca_pub)
            == SM2_IC_ERR_VERIFY,
        "Reject Reconstruct With Wrong CA");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Reconstruct With Matched CA");
    TEST_ASSERT(sm2_ic_verify_cert(&cert_res.cert, &user_pub, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Verify With Matched CA");

    TEST_PASS();
}

static void test_issue_ctx_accessor_and_param_defense()
{
    sm2_ic_issue_ctx_t issue_ctx;
    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    uint8_t subject[] = "CTX_CASE";

    TEST_ASSERT(sm2_ic_issue_ctx_get_field_mask(NULL) == SM2_IC_FIELD_MASK_ALL,
        "Get Mask NULL Default");

    sm2_ic_issue_ctx_init(&issue_ctx);
    TEST_ASSERT(
        sm2_ic_issue_ctx_get_field_mask(&issue_ctx) == SM2_IC_FIELD_MASK_ALL,
        "Get Mask Default");

    uint16_t custom_mask
        = (uint16_t)(SM2_IC_FIELD_SUBJECT_ID | SM2_IC_FIELD_KEY_USAGE);
    TEST_ASSERT(sm2_ic_issue_ctx_set_field_mask(&issue_ctx, custom_mask)
            == SM2_IC_ERR_PARAM,
        "Reject Custom Mask");
    TEST_ASSERT(
        sm2_ic_issue_ctx_set_field_mask(&issue_ctx, 0) == SM2_IC_ERR_PARAM,
        "Reject Zero Mask");
    TEST_ASSERT(
        sm2_ic_issue_ctx_get_field_mask(&issue_ctx) == SM2_IC_FIELD_MASK_ALL,
        "Mask Stays Secure");

    TEST_ASSERT(
        sm2_ic_issue_ctx_set_field_mask(&issue_ctx, 0xFFFF) == SM2_IC_ERR_PARAM,
        "Set Mask Invalid");
    TEST_ASSERT(
        sm2_ic_issue_ctx_set_field_mask(NULL, custom_mask) == SM2_IC_ERR_PARAM,
        "Set Mask NULL");

    issue_ctx.field_mask = custom_mask;
    TEST_ASSERT(sm2_ic_create_cert_request(&req, subject, sizeof(subject) - 1,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Create Req");
    TEST_ASSERT(sm2_ic_create_cert_request(
                    &req, subject, sizeof(subject) - 1, 0, &temp_priv)
            == SM2_IC_ERR_PARAM,
        "Reject Zero Key Usage");
    TEST_ASSERT(sm2_ic_create_cert_request(
                    &req, subject, sizeof(subject) - 1, 0x80, &temp_priv)
            == SM2_IC_ERR_PARAM,
        "Reject Invalid Key Usage Bits");
    TEST_ASSERT(test_issue_cert_with_ctx(&cert_res, &req, (uint8_t *)"CA", 2,
                    &g_ca_priv, &g_ca_pub, &issue_ctx)
            == SM2_IC_ERR_PARAM,
        "Reject Manually Tampered Issue Ctx");

    TEST_ASSERT(sm2_ic_create_cert_request(NULL, subject, sizeof(subject) - 1,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_ERR_PARAM,
        "Create Req NULL Req");
    TEST_ASSERT(sm2_ic_create_cert_request(&req, NULL, sizeof(subject) - 1,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_ERR_PARAM,
        "Create Req NULL Subject");
    TEST_ASSERT(sm2_ic_create_cert_request(&req, subject, sizeof(subject) - 1,
                    SM2_KU_DIGITAL_SIGNATURE, NULL)
            == SM2_IC_ERR_PARAM,
        "Create Req NULL Temp");

    TEST_PASS();
}

static void test_verify_rejects_non_implicit_type_and_invalid_usage()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;
    uint8_t encoded[1024];
    size_t encoded_len = sizeof(encoded);

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"VERIFY_CONTRACT",
                    15, SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Create Contract Req");
    TEST_ASSERT(test_issue_cert(
                    &cert_res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue Contract Cert");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Reconstruct Contract Keys");

    cert_res.cert.type = 0x02;
    TEST_ASSERT(sm2_ic_verify_cert(&cert_res.cert, &user_pub, &g_ca_pub)
            == SM2_IC_ERR_VERIFY,
        "Reject Non Implicit Cert Type");
    TEST_ASSERT(sm2_ic_cbor_encode_cert(encoded, &encoded_len, &cert_res.cert)
            == SM2_IC_ERR_PARAM,
        "Reject Encode Non Implicit Cert Type");

    cert_res.cert.type = SM2_CERT_TYPE_IMPLICIT;
    cert_res.cert.key_usage = 0x80;
    TEST_ASSERT(sm2_ic_verify_cert(&cert_res.cert, &user_pub, &g_ca_pub)
            == SM2_IC_ERR_VERIFY,
        "Reject Invalid Key Usage In Verify");
    encoded_len = sizeof(encoded);
    TEST_ASSERT(sm2_ic_cbor_encode_cert(encoded, &encoded_len, &cert_res.cert)
            == SM2_IC_ERR_PARAM,
        "Reject Encode Invalid Key Usage");

    TEST_PASS();
}

static void test_rejects_invalid_external_curve_points()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;
    sm2_ec_point_t invalid_point;

    memset(&invalid_point, 0, sizeof(invalid_point));
    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"ECQV_BAD_POINT",
                    14, SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Create Bad Point Request");
    TEST_ASSERT(test_issue_cert(
                    &cert_res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue Good Cert");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Reconstruct Good Cert");

    sm2_ic_cert_request_t invalid_req = req;
    invalid_req.temp_public_key = invalid_point;
    sm2_ic_cert_result_t invalid_res;
    memset(&invalid_res, 0, sizeof(invalid_res));
    TEST_ASSERT(test_issue_cert(&invalid_res, &invalid_req, (uint8_t *)"CA", 2,
                    &g_ca_priv, &g_ca_pub)
            == SM2_IC_ERR_VERIFY,
        "Reject Invalid Request Point");

    TEST_ASSERT(sm2_ic_verify_cert(&cert_res.cert, &invalid_point, &g_ca_pub)
            == SM2_IC_ERR_VERIFY,
        "Reject Invalid Subject Public Key");
    TEST_ASSERT(sm2_ic_verify_cert(&cert_res.cert, &user_pub, &invalid_point)
            == SM2_IC_ERR_VERIFY,
        "Reject Invalid CA Public Key");

    sm2_implicit_cert_t invalid_cert = cert_res.cert;
    memset(invalid_cert.public_recon_key, 0,
        sizeof(invalid_cert.public_recon_key));
    TEST_ASSERT(sm2_ic_verify_cert(&invalid_cert, &user_pub, &g_ca_pub)
            == SM2_IC_ERR_VERIFY,
        "Reject Invalid Reconstruction Point");

    TEST_PASS();
}

static void test_subject_id_boundary_under_secure_mask()
{
    if (!g_ca_initialized)
        test_setup_ca();

    uint8_t subject_id[256];
    memset(subject_id, 0x5A, sizeof(subject_id));

    sm2_ic_issue_ctx_t issue_ctx;
    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;
    uint8_t cbor[1024];
    size_t cbor_len = sizeof(cbor);

    sm2_ic_issue_ctx_init(&issue_ctx);
    TEST_ASSERT(sm2_ic_create_cert_request(&req, subject_id, sizeof(subject_id),
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Create Req Subject 256");
    TEST_ASSERT(test_issue_cert_with_ctx(&cert_res, &req, (uint8_t *)"CA", 2,
                    &g_ca_priv, &g_ca_pub, &issue_ctx)
            == SM2_IC_SUCCESS,
        "Issue Secure Mask Cert");

    TEST_ASSERT(cert_res.cert.field_mask == SM2_IC_FIELD_MASK_ALL,
        "Secure Mask Applied");
    TEST_ASSERT(cert_res.cert.subject_id_len == sizeof(subject_id),
        "Subject Preserved");
    TEST_ASSERT(cert_res.cert.issuer_id_len > 0, "Issuer Present");
    TEST_ASSERT(cert_res.cert.valid_from > 0, "ValidFrom Present");
    TEST_ASSERT(cert_res.cert.valid_duration > 0, "Duration Present");
    TEST_ASSERT(
        cert_res.cert.key_usage == SM2_KU_DIGITAL_SIGNATURE, "Usage Present");

    TEST_ASSERT(sm2_ic_cbor_encode_cert(cbor, &cbor_len, &cert_res.cert)
            == SM2_IC_SUCCESS,
        "Encode Zero Mask Cert");
    sm2_implicit_cert_t decoded;
    TEST_ASSERT(
        sm2_ic_cbor_decode_cert(&decoded, cbor, cbor_len) == SM2_IC_SUCCESS,
        "Decode Secure Mask Cert");
    TEST_ASSERT(
        decoded.field_mask == SM2_IC_FIELD_MASK_ALL, "Decode Secure Mask");

    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Reconstruct Secure Mask Cert");
    TEST_ASSERT(sm2_ic_verify_cert(&cert_res.cert, &user_pub, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Verify Secure Mask Cert");

    TEST_PASS();
}

static void test_performance()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t res;
    sm2_ic_create_cert_request(
        &req, (uint8_t *)"PERF", 4, SM2_KU_DIGITAL_SIGNATURE, &temp_priv);

    const int iterations = 1000;
    double start = now_ms_highres();

    for (int i = 0; i < iterations; i++)
    {
        test_issue_cert(&res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub);
    }

    double avg_time = (now_ms_highres() - start) / iterations;
    printf(
        "   [BENCH] Avg Issuance Time: %.3f ms (N=%d)\n", avg_time, iterations);
    TEST_PASS();
}

static void test_chain_success_rate()
{
    if (!g_ca_initialized)
        test_setup_ca();

    const int rounds = 2000;
    int success = 0;

    for (int i = 0; i < rounds; i++)
    {
        sm2_ic_cert_request_t req;
        sm2_private_key_t temp_priv;
        sm2_ic_cert_result_t res;
        sm2_private_key_t user_priv;
        sm2_ec_point_t user_pub;

        if (sm2_ic_create_cert_request(&req, (uint8_t *)"RATE_CASE", 9,
                SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            != SM2_IC_SUCCESS)
            continue;
        if (test_issue_cert(
                &res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            != SM2_IC_SUCCESS)
            continue;
        if (sm2_ic_reconstruct_keys(
                &user_priv, &user_pub, &res, &temp_priv, &g_ca_pub)
            != SM2_IC_SUCCESS)
            continue;
        if (sm2_ic_verify_cert(&res.cert, &user_pub, &g_ca_pub)
            != SM2_IC_SUCCESS)
            continue;
        success++;
    }

    double ratio = (double)success / (double)rounds;
    printf(
        "   [RATE] success=%d/%d (%.4f%%)\n", success, rounds, ratio * 100.0);
    TEST_ASSERT(ratio >= 0.999, "Chain Success Rate < 99.9%");
    TEST_PASS();
}

static void test_serial_unpredictable_and_low_conflict()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t res;
    uint64_t serials[256];
    size_t n = sizeof(serials) / sizeof(serials[0]);

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"SERIAL_CASE", 11,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Create Req");

    for (size_t i = 0; i < n; i++)
    {
        TEST_ASSERT(test_issue_cert(
                        &res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
                == SM2_IC_SUCCESS,
            "Issue Cert");

        TEST_ASSERT(res.cert.serial_number != 0, "Serial Non-Zero");
        serials[i] = res.cert.serial_number;
    }

    for (size_t i = 0; i < n; i++)
    {
        for (size_t j = i + 1; j < n; j++)
        {
            TEST_ASSERT(serials[i] != serials[j], "Serial Collision");
        }
    }

    TEST_PASS();
}

void run_test_ecqv_suite(void)
{
    RUN_TEST(test_setup_ca_case);
    RUN_TEST(test_full_lifecycle);
    RUN_TEST(test_tampered_cert);
    RUN_TEST(test_cbor_robustness);
    RUN_TEST(test_cbor_key_usage_overflow_rejected);
    RUN_TEST(test_issue_ctx_secure_default_only);
    RUN_TEST(test_ca_public_key_consistency_enforced);
    RUN_TEST(test_issue_ctx_accessor_and_param_defense);
    RUN_TEST(test_verify_rejects_non_implicit_type_and_invalid_usage);
    RUN_TEST(test_rejects_invalid_external_curve_points);
    RUN_TEST(test_subject_id_boundary_under_secure_mask);
    RUN_TEST(test_chain_success_rate);
    RUN_TEST(test_serial_unpredictable_and_low_conflict);
    if (test_benchmarks_enabled())
        RUN_TEST(test_performance);
}
