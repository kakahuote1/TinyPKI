/* SPDX-License-Identifier: Apache-2.0 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/time.h>
#endif

#include "sm2_pki_client.h"
#include "sm2_pki_service.h"

#define BENCH_BASELINE_X509_BITS 2048
#define BENCH_VERIFY_ROUNDS 21
#define BENCH_SESSION_ROUNDS 11
#define BENCH_SCALE_ROUNDS 7
#define BENCH_DELTA_ROUNDS 9
#define BENCH_ZIPF_RUNS 100
#define BENCH_ZIPF_VISITS 1000
#define BENCH_ZIPF_DOMAIN_POOL 100000
#define BENCH_ZIPF_EXPONENT 1.26

typedef struct
{
    size_t x509_der_bytes;
    size_t implicit_cert_bytes;
    size_t root_record_bytes;
    size_t compact_root_hint_bytes;
    size_t absence_proof_bytes;
    size_t auth_bundle_bytes;
    size_t auth_bundle_compact_bytes;
    double verify_bundle_median_ms;
    double verify_bundle_compact_median_ms;
    double secure_session_median_ms;
    double secure_session_compact_median_ms;
    double revoke_publish_median_ms;
    double service_refresh_root_median_ms;
    double client_refresh_root_median_ms;
} base_metric_t;

typedef struct
{
    size_t revoked_count;
    double tree_build_ms;
    double member_prove_ms;
    double member_verify_ms;
    double absence_prove_ms;
    double absence_verify_ms;
    size_t member_proof_bytes;
    size_t absence_proof_bytes;
} revocation_scale_metric_t;

typedef struct
{
    size_t query_count;
    double build_ms;
    double verify_ms;
    size_t multiproof_bytes;
    size_t single_member_total_bytes;
    size_t unique_hash_count;
    double compression_pct;
} multiproof_metric_t;

typedef struct
{
    size_t delta_items;
    double apply_ms;
} delta_metric_t;

typedef struct
{
    size_t revoked_count;
    size_t cache_top_levels;
    double directory_build_ms;
    double directory_verify_ms;
    double cached_proof_build_ms;
    double cached_proof_verify_ms;
    size_t directory_bytes;
    size_t cached_proof_bytes;
} epoch_cache_metric_t;

typedef struct
{
    size_t visits;
    double mean_unique_domains;
    double auth_bytes;
    double tx_ms_20kbps;
    double tx_ms_64kbps;
    double tx_ms_256kbps;
    double local_verify_ms;
    double secure_session_ms;
    double combined_local_ms;
    double combined_total_ms_20kbps;
    double combined_total_ms_64kbps;
    double combined_total_ms_256kbps;
} zipf_workload_point_t;

typedef struct
{
    sm2_pki_service_ctx_t *service;
    sm2_pki_client_ctx_t *client;
    sm2_pki_client_ctx_t *verifier;
    sm2_ec_point_t ca_pub;
    sm2_ic_cert_result_t cert_result;
    sm2_private_key_t temp_private_key;
    sm2_auth_signature_t signature;
    sm2_pki_revocation_evidence_t evidence;
    sm2_pki_verify_request_t verify_request;
    uint8_t message[64];
    size_t message_len;
    uint64_t auth_now;
} bench_flow_ctx_t;

typedef struct
{
    sm2_pki_service_ctx_t *service;
    sm2_pki_client_ctx_t *client_a;
    sm2_pki_client_ctx_t *client_b;
    uint64_t auth_now;
} bench_session_ctx_t;

static int cmp_double_asc(const void *lhs, const void *rhs)
{
    double a = *(const double *)lhs;
    double b = *(const double *)rhs;
    if (a < b)
        return -1;
    if (a > b)
        return 1;
    return 0;
}

static double now_ms_highres(void)
{
#if defined(_WIN32)
    static LARGE_INTEGER freq;
    static int initialized = 0;
    LARGE_INTEGER counter;
    if (!initialized)
    {
        QueryPerformanceFrequency(&freq);
        initialized = 1;
    }
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1000.0 / (double)freq.QuadPart;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
#endif
}

static double calc_median_value(double *samples, size_t count)
{
    if (!samples || count == 0)
        return 0.0;
    qsort(samples, count, sizeof(double), cmp_double_asc);
    if ((count & 1U) != 0U)
        return samples[count / 2U];
    return (samples[(count / 2U) - 1U] + samples[count / 2U]) / 2.0;
}

static uint64_t current_unix_ts(void)
{
    time_t now = time(NULL);
    return now < 0 ? 0U : (uint64_t)now;
}

static double tx_delay_ms(double bytes, double kbps)
{
    if (kbps <= 0.0)
        return 0.0;
    return ((bytes * 8.0) / (kbps * 1000.0)) * 1000.0;
}

static size_t rounds_for_revoked_count(size_t revoked_count)
{
    if (revoked_count >= 1048576U)
        return 3U;
    if (revoked_count >= 262144U)
        return 5U;
    return BENCH_SCALE_ROUNDS;
}

static sm2_ic_error_t bench_epoch_sign_cb(void *user_ctx, const uint8_t *data,
    size_t data_len, uint8_t *signature, size_t *signature_len)
{
    static const uint8_t secret[] = "TINYPKI_EPOCH_BENCH";
    uint8_t *buf = NULL;
    sm2_ic_error_t ret = SM2_IC_ERR_MEMORY;

    (void)user_ctx;
    if (!data || !signature || !signature_len
        || *signature_len < SM3_DIGEST_LENGTH)
        return SM2_IC_ERR_PARAM;

    buf = (uint8_t *)malloc(sizeof(secret) - 1U + data_len);
    if (!buf)
        return SM2_IC_ERR_MEMORY;
    memcpy(buf, secret, sizeof(secret) - 1U);
    memcpy(buf + sizeof(secret) - 1U, data, data_len);
    ret = sm2_ic_sm3_hash(buf, (sizeof(secret) - 1U) + data_len, signature);
    free(buf);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    *signature_len = SM3_DIGEST_LENGTH;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t bench_epoch_verify_cb(void *user_ctx, const uint8_t *data,
    size_t data_len, const uint8_t *signature, size_t signature_len)
{
    uint8_t expected[SM3_DIGEST_LENGTH];
    size_t expected_len = sizeof(expected);

    if (!signature || signature_len != sizeof(expected))
        return SM2_IC_ERR_VERIFY;
    if (bench_epoch_sign_cb(user_ctx, data, data_len, expected, &expected_len)
        != SM2_IC_SUCCESS)
    {
        return SM2_IC_ERR_VERIFY;
    }
    return memcmp(expected, signature, sizeof(expected)) == 0
        ? SM2_IC_SUCCESS
        : SM2_IC_ERR_VERIFY;
}

static int create_x509_baseline_der_size(int *der_len)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    X509 *cert = NULL;
    int ok = 0;

    if (!der_len)
        return 0;
    *der_len = 0;

    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!kctx)
        goto cleanup;
    if (EVP_PKEY_keygen_init(kctx) != 1)
        goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, BENCH_BASELINE_X509_BITS) != 1)
        goto cleanup;
    if (EVP_PKEY_keygen(kctx, &pkey) != 1)
        goto cleanup;

    cert = X509_new();
    if (!cert)
        goto cleanup;
    if (X509_set_version(cert, 2) != 1)
        goto cleanup;
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    if (X509_gmtime_adj(X509_get_notBefore(cert), 0) == NULL)
        goto cleanup;
    if (X509_gmtime_adj(X509_get_notAfter(cert), 31536000L) == NULL)
        goto cleanup;
    if (X509_set_pubkey(cert, pkey) != 1)
        goto cleanup;
    if (!X509_get_subject_name(cert))
        goto cleanup;
    if (X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN",
            MBSTRING_ASC, (const unsigned char *)"TINYPKI_BASELINE", -1, -1, 0)
        != 1)
    {
        goto cleanup;
    }
    if (X509_set_issuer_name(cert, X509_get_subject_name(cert)) != 1)
        goto cleanup;
    if (X509_sign(cert, pkey, EVP_sha256()) <= 0)
        goto cleanup;

    *der_len = i2d_X509(cert, NULL);
    ok = (*der_len > 0);

cleanup:
    X509_free(cert);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    return ok;
}

static int issue_identity_cert(sm2_pki_service_ctx_t *service,
    const uint8_t *identity, size_t identity_len, uint8_t key_usage,
    sm2_ic_cert_result_t *cert_result, sm2_private_key_t *temp_private_key)
{
    sm2_ic_cert_request_t request;
    memset(&request, 0, sizeof(request));
    if (sm2_ic_create_cert_request(
            &request, identity, identity_len, key_usage, temp_private_key)
        != SM2_IC_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_cert_authorize_request(service, &request) != SM2_PKI_SUCCESS)
        return 0;
    return sm2_pki_cert_issue(service, &request, current_unix_ts(), cert_result)
        == SM2_PKI_SUCCESS;
}

static int client_get_identity_material(sm2_pki_client_ctx_t *client,
    const sm2_implicit_cert_t **cert, const sm2_ec_point_t **public_key)
{
    if (cert && sm2_pki_client_get_cert(client, cert) != SM2_PKI_SUCCESS)
        return 0;
    if (public_key
        && sm2_pki_client_get_public_key(client, public_key) != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    return 1;
}

static int build_signed_verify_request(sm2_pki_client_ctx_t *signer,
    const uint8_t *message, size_t message_len, uint64_t now_ts,
    sm2_auth_signature_t *signature, sm2_pki_revocation_evidence_t *evidence,
    sm2_pki_verify_request_t *request)
{
    const sm2_implicit_cert_t *cert = NULL;
    const sm2_ec_point_t *public_key = NULL;

    if (!signer || !message || message_len == 0 || !signature || !evidence
        || !request)
    {
        return 0;
    }

    if (sm2_pki_sign(signer, message, message_len, signature)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (!client_get_identity_material(signer, &cert, &public_key))
        return 0;
    if (sm2_pki_client_export_revocation_evidence(signer, now_ts, evidence)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }

    memset(request, 0, sizeof(*request));
    request->cert = cert;
    request->public_key = public_key;
    request->message = message;
    request->message_len = message_len;
    request->signature = signature;
    request->revocation_evidence = evidence;
    return 1;
}

static int build_signed_verify_request_compact(sm2_pki_client_ctx_t *signer,
    const uint8_t *message, size_t message_len, uint64_t now_ts,
    sm2_auth_signature_t *signature, sm2_pki_revocation_evidence_t *evidence,
    sm2_pki_verify_request_t *request)
{
    const sm2_implicit_cert_t *cert = NULL;
    const sm2_ec_point_t *public_key = NULL;

    if (!signer || !message || message_len == 0 || !signature || !evidence
        || !request)
    {
        return 0;
    }

    if (sm2_pki_sign(signer, message, message_len, signature)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (!client_get_identity_material(signer, &cert, &public_key))
        return 0;
    if (sm2_pki_client_export_compact_revocation_evidence(
            signer, now_ts, evidence)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }

    memset(request, 0, sizeof(*request));
    request->cert = cert;
    request->public_key = public_key;
    request->message = message;
    request->message_len = message_len;
    request->signature = signature;
    request->revocation_evidence = evidence;
    return 1;
}

static int encode_cert_len(
    const sm2_implicit_cert_t *cert, uint8_t *buf, size_t cap, size_t *len)
{
    *len = cap;
    return sm2_ic_cbor_encode_cert(buf, len, cert) == SM2_IC_SUCCESS;
}

static int encode_root_len(const sm2_rev_root_record_t *root_record,
    uint8_t *buf, size_t cap, size_t *len)
{
    *len = cap;
    return sm2_rev_root_encode(root_record, buf, len) == SM2_IC_SUCCESS;
}

static int encode_absence_len(
    const sm2_rev_absence_proof_t *proof, uint8_t *buf, size_t cap, size_t *len)
{
    *len = cap;
    return sm2_rev_absence_proof_encode(proof, buf, len) == SM2_IC_SUCCESS;
}

static size_t compact_root_hint_wire_size(
    const sm2_pki_revocation_evidence_t *evidence)
{
    if (!evidence || evidence->mode != SM2_PKI_REV_EVIDENCE_CACHED_ROOT)
        return 0U;

    return 1U + 1U + evidence->cached_root_hint.authority_id_len
        + sizeof(evidence->cached_root_hint.root_version)
        + sizeof(evidence->cached_root_hint.root_hash);
}

static int build_flow_context(bench_flow_ctx_t *ctx)
{
    const uint8_t issuer[] = "BENCH_CA";
    const uint8_t identity[] = "BENCH_NODE";
    const uint8_t message[] = "TINYPKI_CAPABILITY_AUTH_MESSAGE";

    if (!ctx)
        return 0;
    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->message, message, sizeof(message) - 1U);
    ctx->message_len = sizeof(message) - 1U;

    if (sm2_pki_service_create(&ctx->service, issuer, sizeof(issuer) - 1U, 64,
            300, current_unix_ts())
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_identity_register(ctx->service, identity, sizeof(identity) - 1U,
            SM2_KU_DIGITAL_SIGNATURE)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (!issue_identity_cert(ctx->service, identity, sizeof(identity) - 1U,
            SM2_KU_DIGITAL_SIGNATURE, &ctx->cert_result,
            &ctx->temp_private_key))
    {
        return 0;
    }
    if (sm2_pki_service_get_ca_public_key(ctx->service, &ctx->ca_pub)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_client_create(&ctx->client, &ctx->ca_pub, ctx->service)
            != SM2_PKI_SUCCESS
        || sm2_pki_client_create(&ctx->verifier, &ctx->ca_pub, NULL)
            != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_client_import_cert(ctx->client, &ctx->cert_result,
            &ctx->temp_private_key, &ctx->ca_pub)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }

    ctx->auth_now = ctx->cert_result.cert.valid_from != 0
        ? ctx->cert_result.cert.valid_from
        : current_unix_ts();
    return build_signed_verify_request(ctx->client, ctx->message,
        ctx->message_len, ctx->auth_now, &ctx->signature, &ctx->evidence,
        &ctx->verify_request);
}

static void cleanup_flow_context(bench_flow_ctx_t *ctx)
{
    if (!ctx)
        return;
    sm2_pki_client_destroy(&ctx->verifier);
    sm2_pki_client_destroy(&ctx->client);
    sm2_pki_service_destroy(&ctx->service);
    memset(ctx, 0, sizeof(*ctx));
}

static int build_session_context(bench_session_ctx_t *ctx)
{
    const uint8_t issuer[] = "BENCH_SESSION_CA";
    const uint8_t id_a[] = "SESSION_A";
    const uint8_t id_b[] = "SESSION_B";
    const uint8_t usage = SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT;
    sm2_ic_cert_result_t cert_a;
    sm2_ic_cert_result_t cert_b;
    sm2_private_key_t temp_a;
    sm2_private_key_t temp_b;
    sm2_ec_point_t ca_pub;

    if (!ctx)
        return 0;
    memset(ctx, 0, sizeof(*ctx));
    memset(&cert_a, 0, sizeof(cert_a));
    memset(&cert_b, 0, sizeof(cert_b));
    memset(&temp_a, 0, sizeof(temp_a));
    memset(&temp_b, 0, sizeof(temp_b));
    memset(&ca_pub, 0, sizeof(ca_pub));

    if (sm2_pki_service_create(&ctx->service, issuer, sizeof(issuer) - 1U, 32,
            300, current_unix_ts())
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_identity_register(ctx->service, id_a, sizeof(id_a) - 1U, usage)
            != SM2_PKI_SUCCESS
        || sm2_pki_identity_register(
               ctx->service, id_b, sizeof(id_b) - 1U, usage)
            != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (!issue_identity_cert(
            ctx->service, id_a, sizeof(id_a) - 1U, usage, &cert_a, &temp_a)
        || !issue_identity_cert(
            ctx->service, id_b, sizeof(id_b) - 1U, usage, &cert_b, &temp_b))
    {
        return 0;
    }
    if (sm2_pki_service_get_ca_public_key(ctx->service, &ca_pub)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_client_create(&ctx->client_a, &ca_pub, ctx->service)
            != SM2_PKI_SUCCESS
        || sm2_pki_client_create(&ctx->client_b, &ca_pub, ctx->service)
            != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_client_import_cert(ctx->client_a, &cert_a, &temp_a, &ca_pub)
            != SM2_PKI_SUCCESS
        || sm2_pki_client_import_cert(ctx->client_b, &cert_b, &temp_b, &ca_pub)
            != SM2_PKI_SUCCESS)
    {
        return 0;
    }

    ctx->auth_now = cert_a.cert.valid_from > cert_b.cert.valid_from
        ? cert_a.cert.valid_from
        : cert_b.cert.valid_from;
    if (ctx->auth_now == 0)
        ctx->auth_now = current_unix_ts();
    return 1;
}

static void cleanup_session_context(bench_session_ctx_t *ctx)
{
    if (!ctx)
        return;
    sm2_pki_client_destroy(&ctx->client_a);
    sm2_pki_client_destroy(&ctx->client_b);
    sm2_pki_service_destroy(&ctx->service);
    memset(ctx, 0, sizeof(*ctx));
}

static double measure_verify_bundle_median(void)
{
    bench_flow_ctx_t flow;
    double samples[BENCH_VERIFY_ROUNDS];

    memset(&flow, 0, sizeof(flow));
    if (!build_flow_context(&flow))
        return 0.0;

    for (size_t i = 0; i < BENCH_VERIFY_ROUNDS; i++)
    {
        size_t matched = 0;
        double t0 = now_ms_highres();
        if (sm2_pki_verify(
                flow.verifier, &flow.verify_request, flow.auth_now, &matched)
            != SM2_PKI_SUCCESS)
        {
            cleanup_flow_context(&flow);
            return 0.0;
        }
        samples[i] = now_ms_highres() - t0;
    }

    cleanup_flow_context(&flow);
    return calc_median_value(samples, BENCH_VERIFY_ROUNDS);
}

static double measure_verify_bundle_compact_median(void)
{
    bench_flow_ctx_t flow;
    double samples[BENCH_VERIFY_ROUNDS];
    sm2_auth_signature_t signature;
    sm2_pki_revocation_evidence_t evidence;
    sm2_pki_verify_request_t request;
    size_t matched = 0;

    memset(&flow, 0, sizeof(flow));
    memset(&signature, 0, sizeof(signature));
    memset(&evidence, 0, sizeof(evidence));
    memset(&request, 0, sizeof(request));
    if (!build_flow_context(&flow))
        return 0.0;
    if (sm2_pki_verify(
            flow.verifier, &flow.verify_request, flow.auth_now, &matched)
        != SM2_PKI_SUCCESS)
    {
        cleanup_flow_context(&flow);
        return 0.0;
    }
    if (!build_signed_verify_request_compact(flow.client, flow.message,
            flow.message_len, flow.auth_now, &signature, &evidence, &request))
    {
        cleanup_flow_context(&flow);
        return 0.0;
    }

    for (size_t i = 0; i < BENCH_VERIFY_ROUNDS; i++)
    {
        double t0 = now_ms_highres();
        if (sm2_pki_verify(flow.verifier, &request, flow.auth_now, &matched)
            != SM2_PKI_SUCCESS)
        {
            cleanup_flow_context(&flow);
            return 0.0;
        }
        samples[i] = now_ms_highres() - t0;
    }

    cleanup_flow_context(&flow);
    return calc_median_value(samples, BENCH_VERIFY_ROUNDS);
}

static double measure_secure_session_median_internal(bool compact_evidence)
{
    bench_session_ctx_t ctx;
    double samples[BENCH_SESSION_ROUNDS];
    const uint8_t transcript[] = "TINYPKI_CAPABILITY_SESSION";

    memset(&ctx, 0, sizeof(ctx));
    if (!build_session_context(&ctx))
        return 0.0;
    if (compact_evidence
        && (sm2_pki_client_refresh_root(ctx.client_a, ctx.auth_now)
                != SM2_PKI_SUCCESS
            || sm2_pki_client_refresh_root(ctx.client_b, ctx.auth_now)
                != SM2_PKI_SUCCESS))
    {
        cleanup_session_context(&ctx);
        return 0.0;
    }

    for (size_t i = 0; i < BENCH_SESSION_ROUNDS; i++)
    {
        const sm2_implicit_cert_t *cert_a = NULL;
        const sm2_implicit_cert_t *cert_b = NULL;
        const sm2_ec_point_t *pub_a = NULL;
        const sm2_ec_point_t *pub_b = NULL;
        sm2_private_key_t eph_priv_a;
        sm2_private_key_t eph_priv_b;
        sm2_ec_point_t eph_pub_a;
        sm2_ec_point_t eph_pub_b;
        uint8_t bind_a[256];
        uint8_t bind_b[256];
        size_t bind_a_len = sizeof(bind_a);
        size_t bind_b_len = sizeof(bind_b);
        sm2_auth_signature_t sig_a;
        sm2_auth_signature_t sig_b;
        sm2_pki_revocation_evidence_t evidence_a;
        sm2_pki_revocation_evidence_t evidence_b;
        sm2_pki_verify_request_t req_a_to_b;
        sm2_pki_verify_request_t req_b_to_a;
        uint8_t sk_a[16];
        uint8_t sk_b[16];
        size_t matched_a = 0;
        size_t matched_b = 0;

        memset(&eph_priv_a, 0, sizeof(eph_priv_a));
        memset(&eph_priv_b, 0, sizeof(eph_priv_b));
        memset(&eph_pub_a, 0, sizeof(eph_pub_a));
        memset(&eph_pub_b, 0, sizeof(eph_pub_b));
        memset(&sig_a, 0, sizeof(sig_a));
        memset(&sig_b, 0, sizeof(sig_b));
        memset(&evidence_a, 0, sizeof(evidence_a));
        memset(&evidence_b, 0, sizeof(evidence_b));
        memset(&req_a_to_b, 0, sizeof(req_a_to_b));
        memset(&req_b_to_a, 0, sizeof(req_b_to_a));

        double t0 = now_ms_highres();
        if (sm2_pki_generate_ephemeral_keypair(&eph_priv_a, &eph_pub_a)
                != SM2_PKI_SUCCESS
            || sm2_pki_generate_ephemeral_keypair(&eph_priv_b, &eph_pub_b)
                != SM2_PKI_SUCCESS
            || sm2_auth_build_handshake_binding(&eph_pub_a, &eph_pub_b,
                   transcript, sizeof(transcript) - 1U, bind_a, &bind_a_len)
                != SM2_IC_SUCCESS
            || sm2_auth_build_handshake_binding(&eph_pub_b, &eph_pub_a,
                   transcript, sizeof(transcript) - 1U, bind_b, &bind_b_len)
                != SM2_IC_SUCCESS
            || sm2_pki_sign(ctx.client_a, bind_a, bind_a_len, &sig_a)
                != SM2_PKI_SUCCESS
            || sm2_pki_sign(ctx.client_b, bind_b, bind_b_len, &sig_b)
                != SM2_PKI_SUCCESS
            || (compact_evidence
                       ? sm2_pki_client_export_compact_revocation_evidence(
                             ctx.client_a, ctx.auth_now, &evidence_a)
                       : sm2_pki_client_export_revocation_evidence(
                             ctx.client_a, ctx.auth_now, &evidence_a))
                != SM2_PKI_SUCCESS
            || (compact_evidence
                       ? sm2_pki_client_export_compact_revocation_evidence(
                             ctx.client_b, ctx.auth_now, &evidence_b)
                       : sm2_pki_client_export_revocation_evidence(
                             ctx.client_b, ctx.auth_now, &evidence_b))
                != SM2_PKI_SUCCESS
            || !client_get_identity_material(ctx.client_a, &cert_a, &pub_a)
            || !client_get_identity_material(ctx.client_b, &cert_b, &pub_b))
        {
            cleanup_session_context(&ctx);
            return 0.0;
        }

        req_a_to_b.cert = cert_a;
        req_a_to_b.public_key = pub_a;
        req_a_to_b.message = bind_a;
        req_a_to_b.message_len = bind_a_len;
        req_a_to_b.signature = &sig_a;
        req_a_to_b.revocation_evidence = &evidence_a;

        req_b_to_a.cert = cert_b;
        req_b_to_a.public_key = pub_b;
        req_b_to_a.message = bind_b;
        req_b_to_a.message_len = bind_b_len;
        req_b_to_a.signature = &sig_b;
        req_b_to_a.revocation_evidence = &evidence_b;

        if (sm2_pki_secure_session_establish(ctx.client_a, &eph_priv_a,
                &eph_pub_a, &req_b_to_a, &eph_pub_b, transcript,
                sizeof(transcript) - 1U, ctx.auth_now, sk_a, sizeof(sk_a),
                &matched_a)
                != SM2_PKI_SUCCESS
            || sm2_pki_secure_session_establish(ctx.client_b, &eph_priv_b,
                   &eph_pub_b, &req_a_to_b, &eph_pub_a, transcript,
                   sizeof(transcript) - 1U, ctx.auth_now, sk_b, sizeof(sk_b),
                   &matched_b)
                != SM2_PKI_SUCCESS
            || memcmp(sk_a, sk_b, sizeof(sk_a)) != 0)
        {
            cleanup_session_context(&ctx);
            return 0.0;
        }
        samples[i] = now_ms_highres() - t0;
    }

    cleanup_session_context(&ctx);
    return calc_median_value(samples, BENCH_SESSION_ROUNDS);
}

static double measure_secure_session_median(void)
{
    return measure_secure_session_median_internal(false);
}

static double measure_secure_session_compact_median(void)
{
    return measure_secure_session_median_internal(true);
}

static int measure_revoke_refresh_medians(double *revoke_publish_median_ms,
    double *service_refresh_median_ms, double *client_refresh_median_ms)
{
    const uint8_t issuer[] = "BENCH_REVOKE_CA";
    sm2_pki_service_ctx_t *service = NULL;
    sm2_pki_client_ctx_t *observer = NULL;
    sm2_ec_point_t ca_pub;
    double revoke_samples[BENCH_VERIFY_ROUNDS];
    double service_refresh_samples[BENCH_VERIFY_ROUNDS];
    double refresh_samples[BENCH_VERIFY_ROUNDS];

    if (!revoke_publish_median_ms || !service_refresh_median_ms
        || !client_refresh_median_ms)
        return 0;

    memset(&ca_pub, 0, sizeof(ca_pub));
    memset(revoke_samples, 0, sizeof(revoke_samples));
    memset(service_refresh_samples, 0, sizeof(service_refresh_samples));
    memset(refresh_samples, 0, sizeof(refresh_samples));

    if (sm2_pki_service_create(
            &service, issuer, sizeof(issuer) - 1U, 64, 300, current_unix_ts())
            != SM2_PKI_SUCCESS
        || sm2_pki_service_get_ca_public_key(service, &ca_pub)
            != SM2_PKI_SUCCESS
        || sm2_pki_client_create(&observer, &ca_pub, service)
            != SM2_PKI_SUCCESS)
    {
        sm2_pki_client_destroy(&observer);
        sm2_pki_service_destroy(&service);
        return 0;
    }

    for (size_t i = 0; i < BENCH_VERIFY_ROUNDS; i++)
    {
        char identity[32];
        sm2_ic_cert_result_t cert_result;
        sm2_private_key_t temp_priv;
        uint64_t now_ts = current_unix_ts();

        memset(&cert_result, 0, sizeof(cert_result));
        memset(&temp_priv, 0, sizeof(temp_priv));
        snprintf(identity, sizeof(identity), "REVOKE_%02u", (unsigned int)i);
        identity[sizeof(identity) - 1U] = '\0';

        if (sm2_pki_identity_register(service, (const uint8_t *)identity,
                strlen(identity), SM2_KU_DIGITAL_SIGNATURE)
                != SM2_PKI_SUCCESS
            || !issue_identity_cert(service, (const uint8_t *)identity,
                strlen(identity), SM2_KU_DIGITAL_SIGNATURE, &cert_result,
                &temp_priv))
        {
            sm2_pki_client_destroy(&observer);
            sm2_pki_service_destroy(&service);
            return 0;
        }

        double t0 = now_ms_highres();
        if (sm2_pki_service_revoke(
                service, cert_result.cert.serial_number, now_ts)
            != SM2_PKI_SUCCESS)
        {
            sm2_pki_client_destroy(&observer);
            sm2_pki_service_destroy(&service);
            return 0;
        }
        revoke_samples[i] = now_ms_highres() - t0;

        t0 = now_ms_highres();
        if (sm2_pki_service_refresh_root(service, now_ts + 1U)
            != SM2_PKI_SUCCESS)
        {
            sm2_pki_client_destroy(&observer);
            sm2_pki_service_destroy(&service);
            return 0;
        }
        service_refresh_samples[i] = now_ms_highres() - t0;

        t0 = now_ms_highres();
        if (sm2_pki_client_refresh_root(observer, now_ts + 1U)
            != SM2_PKI_SUCCESS)
        {
            sm2_pki_client_destroy(&observer);
            sm2_pki_service_destroy(&service);
            return 0;
        }
        refresh_samples[i] = now_ms_highres() - t0;
    }

    sm2_pki_client_destroy(&observer);
    sm2_pki_service_destroy(&service);
    *revoke_publish_median_ms
        = calc_median_value(revoke_samples, BENCH_VERIFY_ROUNDS);
    *service_refresh_median_ms
        = calc_median_value(service_refresh_samples, BENCH_VERIFY_ROUNDS);
    *client_refresh_median_ms
        = calc_median_value(refresh_samples, BENCH_VERIFY_ROUNDS);
    return 1;
}

static int collect_base_metrics(base_metric_t *metrics)
{
    bench_flow_ctx_t flow;
    uint8_t cert_buf[1024];
    uint8_t root_buf[1024];
    uint8_t absence_buf[8192];
    double auth_bundle_samples[BENCH_SESSION_ROUNDS];
    double auth_bundle_compact_samples[BENCH_SESSION_ROUNDS];
    size_t cert_len = 0;
    size_t root_len = 0;
    size_t absence_len = 0;
    int x509_der_len = 0;

    if (!metrics)
        return 0;
    memset(metrics, 0, sizeof(*metrics));
    memset(&flow, 0, sizeof(flow));
    memset(auth_bundle_samples, 0, sizeof(auth_bundle_samples));
    memset(auth_bundle_compact_samples, 0, sizeof(auth_bundle_compact_samples));

    if (!build_flow_context(&flow)
        || !create_x509_baseline_der_size(&x509_der_len)
        || !encode_cert_len(
            &flow.cert_result.cert, cert_buf, sizeof(cert_buf), &cert_len)
        || !encode_root_len(
            &flow.evidence.root_record, root_buf, sizeof(root_buf), &root_len)
        || !encode_absence_len(&flow.evidence.absence_proof, absence_buf,
            sizeof(absence_buf), &absence_len))
    {
        cleanup_flow_context(&flow);
        return 0;
    }

    metrics->x509_der_bytes = (size_t)x509_der_len;
    metrics->implicit_cert_bytes = cert_len;
    metrics->root_record_bytes = root_len;
    metrics->absence_proof_bytes = absence_len;
    for (size_t i = 0; i < BENCH_SESSION_ROUNDS; i++)
    {
        sm2_auth_signature_t signature;
        sm2_auth_signature_t compact_signature;
        sm2_pki_revocation_evidence_t evidence;
        sm2_pki_revocation_evidence_t compact_evidence;
        sm2_pki_verify_request_t request;
        sm2_pki_verify_request_t compact_request;
        size_t root_round_len = sizeof(root_buf);
        size_t absence_round_len = sizeof(absence_buf);
        size_t compact_absence_len = sizeof(absence_buf);
        size_t compact_root_hint_len = 0;

        memset(&signature, 0, sizeof(signature));
        memset(&compact_signature, 0, sizeof(compact_signature));
        memset(&evidence, 0, sizeof(evidence));
        memset(&compact_evidence, 0, sizeof(compact_evidence));
        memset(&request, 0, sizeof(request));
        memset(&compact_request, 0, sizeof(compact_request));
        if (!build_signed_verify_request(flow.client, flow.message,
                flow.message_len, flow.auth_now, &signature, &evidence,
                &request)
            || !build_signed_verify_request_compact(flow.client, flow.message,
                flow.message_len, flow.auth_now, &compact_signature,
                &compact_evidence, &compact_request)
            || !encode_root_len(&evidence.root_record, root_buf,
                sizeof(root_buf), &root_round_len)
            || !encode_absence_len(&evidence.absence_proof, absence_buf,
                sizeof(absence_buf), &absence_round_len)
            || !encode_absence_len(&compact_evidence.absence_proof, absence_buf,
                sizeof(absence_buf), &compact_absence_len))
        {
            cleanup_flow_context(&flow);
            return 0;
        }

        compact_root_hint_len = compact_root_hint_wire_size(&compact_evidence);
        if (i == 0U)
            metrics->compact_root_hint_bytes = compact_root_hint_len;
        auth_bundle_samples[i] = (double)cert_len + (double)signature.der_len
            + (double)root_round_len + (double)absence_round_len;
        auth_bundle_compact_samples[i] = (double)cert_len
            + (double)compact_signature.der_len + (double)compact_root_hint_len
            + (double)compact_absence_len;
    }
    metrics->auth_bundle_bytes
        = (size_t)(calc_median_value(auth_bundle_samples, BENCH_SESSION_ROUNDS)
            + 0.5);
    metrics->auth_bundle_compact_bytes
        = (size_t)(calc_median_value(
                       auth_bundle_compact_samples, BENCH_SESSION_ROUNDS)
            + 0.5);
    metrics->verify_bundle_median_ms = measure_verify_bundle_median();
    metrics->verify_bundle_compact_median_ms
        = measure_verify_bundle_compact_median();
    metrics->secure_session_median_ms = measure_secure_session_median();
    metrics->secure_session_compact_median_ms
        = measure_secure_session_compact_median();
    if (!measure_revoke_refresh_medians(&metrics->revoke_publish_median_ms,
            &metrics->service_refresh_root_median_ms,
            &metrics->client_refresh_root_median_ms))
    {
        cleanup_flow_context(&flow);
        return 0;
    }

    cleanup_flow_context(&flow);
    return metrics->verify_bundle_median_ms > 0.0
        && metrics->verify_bundle_compact_median_ms > 0.0
        && metrics->secure_session_median_ms > 0.0
        && metrics->secure_session_compact_median_ms > 0.0
        && metrics->revoke_publish_median_ms > 0.0
        && metrics->service_refresh_root_median_ms > 0.0
        && metrics->client_refresh_root_median_ms > 0.0;
}

static void fill_revoked_serials(uint64_t *serials, size_t count, uint64_t base)
{
    if (!serials)
        return;
    for (size_t i = 0; i < count; i++)
        serials[i] = base + ((uint64_t)i * 2ULL);
}

static int collect_revocation_scaling_metrics(
    revocation_scale_metric_t *metrics, size_t metric_count)
{
    static const size_t revoked_counts[]
        = { 1024U, 4096U, 16384U, 65536U, 262144U, 1048576U };

    if (!metrics
        || metric_count != (sizeof(revoked_counts) / sizeof(revoked_counts[0])))
    {
        return 0;
    }

    for (size_t m = 0; m < metric_count; m++)
    {
        uint64_t *revoked = NULL;
        double build_samples[BENCH_SCALE_ROUNDS];
        double member_prove_samples[BENCH_SCALE_ROUNDS];
        double member_verify_samples[BENCH_SCALE_ROUNDS];
        double absence_prove_samples[BENCH_SCALE_ROUNDS];
        double absence_verify_samples[BENCH_SCALE_ROUNDS];
        size_t member_bytes = 0;
        size_t absence_bytes = 0;
        const size_t revoked_count = revoked_counts[m];

        memset(build_samples, 0, sizeof(build_samples));
        memset(member_prove_samples, 0, sizeof(member_prove_samples));
        memset(member_verify_samples, 0, sizeof(member_verify_samples));
        memset(absence_prove_samples, 0, sizeof(absence_prove_samples));
        memset(absence_verify_samples, 0, sizeof(absence_verify_samples));

        revoked = (uint64_t *)calloc(revoked_count, sizeof(uint64_t));
        if (!revoked)
            return 0;
        fill_revoked_serials(
            revoked, revoked_count, 1000000ULL + (uint64_t)m * 100000ULL);

        size_t round_count = rounds_for_revoked_count(revoked_count);
        for (size_t round = 0; round < round_count; round++)
        {
            sm2_rev_tree_t *tree = NULL;
            sm2_rev_member_proof_t member_proof;
            sm2_rev_absence_proof_t absence_proof;
            uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];
            uint8_t member_buf[4096];
            uint8_t absence_buf[8192];
            size_t member_len = sizeof(member_buf);
            size_t absence_len = sizeof(absence_buf);
            const uint64_t member_serial = revoked[revoked_count / 2U];
            const uint64_t absence_serial = member_serial + 1ULL;

            memset(&member_proof, 0, sizeof(member_proof));
            memset(&absence_proof, 0, sizeof(absence_proof));
            memset(root_hash, 0, sizeof(root_hash));

            double t0 = now_ms_highres();
            if (sm2_rev_tree_build(&tree, revoked, revoked_count,
                    2026032501ULL + (uint64_t)round)
                != SM2_IC_SUCCESS)
            {
                free(revoked);
                return 0;
            }
            build_samples[round] = now_ms_highres() - t0;

            if (sm2_rev_tree_get_root_hash(tree, root_hash) != SM2_IC_SUCCESS)
            {
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }

            t0 = now_ms_highres();
            if (sm2_rev_tree_prove_member(tree, member_serial, &member_proof)
                != SM2_IC_SUCCESS)
            {
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            member_prove_samples[round] = now_ms_highres() - t0;

            t0 = now_ms_highres();
            if (sm2_rev_tree_verify_member(root_hash, &member_proof)
                != SM2_IC_SUCCESS)
            {
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            member_verify_samples[round] = now_ms_highres() - t0;

            t0 = now_ms_highres();
            if (sm2_rev_tree_prove_absence(tree, absence_serial, &absence_proof)
                != SM2_IC_SUCCESS)
            {
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            absence_prove_samples[round] = now_ms_highres() - t0;

            t0 = now_ms_highres();
            if (sm2_rev_tree_verify_absence(root_hash, &absence_proof)
                != SM2_IC_SUCCESS)
            {
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            absence_verify_samples[round] = now_ms_highres() - t0;

            if (round == 0U)
            {
                if (sm2_rev_member_proof_encode(
                        &member_proof, member_buf, &member_len)
                        != SM2_IC_SUCCESS
                    || sm2_rev_absence_proof_encode(
                           &absence_proof, absence_buf, &absence_len)
                        != SM2_IC_SUCCESS)
                {
                    sm2_rev_tree_cleanup(&tree);
                    free(revoked);
                    return 0;
                }
                member_bytes = member_len;
                absence_bytes = absence_len;
            }

            sm2_rev_tree_cleanup(&tree);
        }

        metrics[m].revoked_count = revoked_count;
        metrics[m].tree_build_ms
            = calc_median_value(build_samples, round_count);
        metrics[m].member_prove_ms
            = calc_median_value(member_prove_samples, round_count);
        metrics[m].member_verify_ms
            = calc_median_value(member_verify_samples, round_count);
        metrics[m].absence_prove_ms
            = calc_median_value(absence_prove_samples, round_count);
        metrics[m].absence_verify_ms
            = calc_median_value(absence_verify_samples, round_count);
        metrics[m].member_proof_bytes = member_bytes;
        metrics[m].absence_proof_bytes = absence_bytes;
        free(revoked);
    }

    return 1;
}

static int collect_multiproof_metrics(
    multiproof_metric_t *metrics, size_t metric_count)
{
    static const size_t query_counts[] = { 1U, 4U, 8U, 16U, 32U, 64U };
    enum
    {
        revoked_count = 32768
    };
    uint64_t *revoked = NULL;
    sm2_rev_tree_t *tree = NULL;
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];

    if (!metrics
        || metric_count != (sizeof(query_counts) / sizeof(query_counts[0])))
    {
        return 0;
    }

    revoked = (uint64_t *)calloc(revoked_count, sizeof(uint64_t));
    if (!revoked)
        return 0;
    fill_revoked_serials(revoked, revoked_count, 4000000ULL);

    if (sm2_rev_tree_build(&tree, revoked, revoked_count, 2026032501ULL)
            != SM2_IC_SUCCESS
        || sm2_rev_tree_get_root_hash(tree, root_hash) != SM2_IC_SUCCESS)
    {
        sm2_rev_tree_cleanup(&tree);
        free(revoked);
        return 0;
    }

    for (size_t m = 0; m < metric_count; m++)
    {
        const size_t query_count = query_counts[m];
        uint64_t *queries = NULL;
        double build_samples[BENCH_SCALE_ROUNDS];
        double verify_samples[BENCH_SCALE_ROUNDS];
        size_t multiproof_bytes = 0;
        size_t single_total_bytes = 0;
        size_t unique_hash_count = 0;

        memset(build_samples, 0, sizeof(build_samples));
        memset(verify_samples, 0, sizeof(verify_samples));

        queries = (uint64_t *)calloc(query_count, sizeof(uint64_t));
        if (!queries)
        {
            sm2_rev_tree_cleanup(&tree);
            free(revoked);
            return 0;
        }

        size_t stride = revoked_count / query_count;
        if (stride == 0U)
            stride = 1U;
        for (size_t i = 0; i < query_count; i++)
        {
            size_t index = i * stride;
            if (index >= revoked_count)
                index = revoked_count - 1U;
            queries[i] = revoked[index];
        }

        for (size_t round = 0; round < BENCH_SCALE_ROUNDS; round++)
        {
            sm2_rev_multi_proof_t *proof = NULL;
            uint8_t proof_buf[1048576];
            size_t proof_len = sizeof(proof_buf);

            double t0 = now_ms_highres();
            if (sm2_rev_multi_proof_build(tree, queries, query_count, &proof)
                != SM2_IC_SUCCESS)
            {
                free(queries);
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            build_samples[round] = now_ms_highres() - t0;

            t0 = now_ms_highres();
            if (sm2_rev_multi_proof_verify(root_hash, proof) != SM2_IC_SUCCESS)
            {
                sm2_rev_multi_proof_cleanup(&proof);
                free(queries);
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            verify_samples[round] = now_ms_highres() - t0;

            if (round == 0U)
            {
                if (sm2_rev_multi_proof_encode(proof, proof_buf, &proof_len)
                    != SM2_IC_SUCCESS)
                {
                    sm2_rev_multi_proof_cleanup(&proof);
                    free(queries);
                    sm2_rev_tree_cleanup(&tree);
                    free(revoked);
                    return 0;
                }
                multiproof_bytes = proof_len;
                unique_hash_count
                    = sm2_rev_multi_proof_unique_hash_count(proof);
            }

            sm2_rev_multi_proof_cleanup(&proof);
        }

        for (size_t i = 0; i < query_count; i++)
        {
            sm2_rev_member_proof_t member_proof;
            uint8_t member_buf[4096];
            size_t member_len = sizeof(member_buf);

            memset(&member_proof, 0, sizeof(member_proof));
            if (sm2_rev_tree_prove_member(tree, queries[i], &member_proof)
                    != SM2_IC_SUCCESS
                || sm2_rev_member_proof_encode(
                       &member_proof, member_buf, &member_len)
                    != SM2_IC_SUCCESS)
            {
                free(queries);
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            single_total_bytes += member_len;
        }

        metrics[m].query_count = query_count;
        metrics[m].build_ms
            = calc_median_value(build_samples, BENCH_SCALE_ROUNDS);
        metrics[m].verify_ms
            = calc_median_value(verify_samples, BENCH_SCALE_ROUNDS);
        metrics[m].multiproof_bytes = multiproof_bytes;
        metrics[m].single_member_total_bytes = single_total_bytes;
        metrics[m].unique_hash_count = unique_hash_count;
        metrics[m].compression_pct = single_total_bytes == 0U
            ? 0.0
            : ((double)multiproof_bytes * 100.0) / (double)single_total_bytes;

        free(queries);
    }

    sm2_rev_tree_cleanup(&tree);
    free(revoked);
    return 1;
}

static int collect_delta_metrics(delta_metric_t *metrics, size_t metric_count)
{
    static const size_t delta_sizes[] = { 1U, 8U, 32U, 128U, 512U };

    if (!metrics
        || metric_count != (sizeof(delta_sizes) / sizeof(delta_sizes[0])))
    {
        return 0;
    }

    for (size_t m = 0; m < metric_count; m++)
    {
        const size_t item_count = delta_sizes[m];
        sm2_crl_delta_item_t *items = NULL;
        double samples[BENCH_DELTA_ROUNDS];

        items = (sm2_crl_delta_item_t *)calloc(item_count, sizeof(*items));
        if (!items)
            return 0;
        memset(samples, 0, sizeof(samples));

        for (size_t i = 0; i < item_count; i++)
        {
            items[i].serial_number
                = 6000000ULL + ((uint64_t)m * 10000ULL) + (uint64_t)i;
            items[i].revoked = true;
        }

        for (size_t round = 0; round < BENCH_DELTA_ROUNDS; round++)
        {
            sm2_rev_ctx_t *ctx = NULL;
            sm2_crl_delta_t delta;
            const uint64_t now_ts = current_unix_ts();

            memset(&delta, 0, sizeof(delta));
            if (sm2_rev_init(&ctx, item_count * 2U + 8U, 300, now_ts)
                != SM2_IC_SUCCESS)
            {
                free(items);
                return 0;
            }

            delta.base_version = 0U;
            delta.new_version = 1U;
            delta.items = items;
            delta.item_count = item_count;

            double t0 = now_ms_highres();
            if (sm2_rev_apply_delta(ctx, &delta, now_ts) != SM2_IC_SUCCESS)
            {
                sm2_rev_cleanup(&ctx);
                free(items);
                return 0;
            }
            samples[round] = now_ms_highres() - t0;
            sm2_rev_cleanup(&ctx);
        }

        metrics[m].delta_items = item_count;
        metrics[m].apply_ms = calc_median_value(samples, BENCH_DELTA_ROUNDS);
        free(items);
    }

    return 1;
}

static int collect_epoch_cache_metrics(
    epoch_cache_metric_t *metrics, size_t metric_count)
{
    static const size_t cache_levels[] = { 2U, 4U, 6U, 8U, 10U };
    enum
    {
        revoked_count = 65536
    };
    uint64_t *revoked = NULL;
    sm2_rev_tree_t *tree = NULL;
    const uint64_t member_serial
        = 7000001ULL + ((uint64_t)revoked_count / 2U) * 2ULL;

    if (!metrics
        || metric_count != (sizeof(cache_levels) / sizeof(cache_levels[0])))
    {
        return 0;
    }

    revoked = (uint64_t *)calloc(revoked_count, sizeof(uint64_t));
    if (!revoked)
        return 0;
    fill_revoked_serials(revoked, revoked_count, 7000001ULL);

    if (sm2_rev_tree_build(&tree, revoked, revoked_count, 2026032601ULL)
        != SM2_IC_SUCCESS)
    {
        free(revoked);
        return 0;
    }

    for (size_t i = 0; i < metric_count; i++)
    {
        double build_samples[BENCH_SCALE_ROUNDS];
        double verify_samples[BENCH_SCALE_ROUNDS];
        double proof_build_samples[BENCH_SCALE_ROUNDS];
        double proof_verify_samples[BENCH_SCALE_ROUNDS];
        size_t directory_bytes = 0;
        size_t cached_proof_bytes = 0;
        const size_t cache_top_levels = cache_levels[i];

        memset(build_samples, 0, sizeof(build_samples));
        memset(verify_samples, 0, sizeof(verify_samples));
        memset(proof_build_samples, 0, sizeof(proof_build_samples));
        memset(proof_verify_samples, 0, sizeof(proof_verify_samples));

        for (size_t round = 0; round < BENCH_SCALE_ROUNDS; round++)
        {
            sm2_rev_epoch_dir_t *directory = NULL;
            sm2_rev_cached_member_proof_t cached_proof;
            uint8_t dir_buf[262144];
            uint8_t proof_buf[8192];
            size_t dir_len = sizeof(dir_buf);
            size_t proof_len = sizeof(proof_buf);
            const uint64_t valid_from = 1000U;
            const uint64_t valid_until = 2000U;
            const uint64_t verify_now = 1500U;

            memset(&cached_proof, 0, sizeof(cached_proof));

            double t0 = now_ms_highres();
            if (sm2_rev_epoch_dir_build(tree, 2026032601ULL + (uint64_t)round,
                    cache_top_levels, valid_from, valid_until,
                    bench_epoch_sign_cb, NULL, &directory)
                != SM2_IC_SUCCESS)
            {
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            build_samples[round] = now_ms_highres() - t0;

            t0 = now_ms_highres();
            if (sm2_rev_epoch_dir_verify(
                    directory, verify_now, bench_epoch_verify_cb, NULL)
                != SM2_IC_SUCCESS)
            {
                sm2_rev_epoch_dir_cleanup(&directory);
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            verify_samples[round] = now_ms_highres() - t0;

            t0 = now_ms_highres();
            if (sm2_rev_epoch_prove_member_cached(
                    tree, member_serial, cache_top_levels, &cached_proof)
                != SM2_IC_SUCCESS)
            {
                sm2_rev_epoch_dir_cleanup(&directory);
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            proof_build_samples[round] = now_ms_highres() - t0;

            t0 = now_ms_highres();
            if (sm2_rev_epoch_verify_member_cached(directory, verify_now,
                    &cached_proof, bench_epoch_verify_cb, NULL)
                != SM2_IC_SUCCESS)
            {
                sm2_rev_epoch_dir_cleanup(&directory);
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            proof_verify_samples[round] = now_ms_highres() - t0;

            if (round == 0U)
            {
                if (sm2_rev_epoch_dir_encode(directory, dir_buf, &dir_len)
                        != SM2_IC_SUCCESS
                    || sm2_rev_cached_member_proof_encode(
                           &cached_proof, proof_buf, &proof_len)
                        != SM2_IC_SUCCESS)
                {
                    sm2_rev_epoch_dir_cleanup(&directory);
                    sm2_rev_tree_cleanup(&tree);
                    free(revoked);
                    return 0;
                }
                directory_bytes = dir_len;
                cached_proof_bytes = proof_len;
            }

            sm2_rev_epoch_dir_cleanup(&directory);
        }

        metrics[i].revoked_count = revoked_count;
        metrics[i].cache_top_levels = cache_top_levels;
        metrics[i].directory_build_ms
            = calc_median_value(build_samples, BENCH_SCALE_ROUNDS);
        metrics[i].directory_verify_ms
            = calc_median_value(verify_samples, BENCH_SCALE_ROUNDS);
        metrics[i].cached_proof_build_ms
            = calc_median_value(proof_build_samples, BENCH_SCALE_ROUNDS);
        metrics[i].cached_proof_verify_ms
            = calc_median_value(proof_verify_samples, BENCH_SCALE_ROUNDS);
        metrics[i].directory_bytes = directory_bytes;
        metrics[i].cached_proof_bytes = cached_proof_bytes;
    }

    sm2_rev_tree_cleanup(&tree);
    free(revoked);
    return 1;
}

static uint64_t rng_next(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 2685821657736338717ULL;
}

static double rng_unit_double(uint64_t *state)
{
    const uint64_t value = rng_next(state);
    return (double)(value >> 11) * (1.0 / 9007199254740992.0);
}

static void build_zipf_cdf(double *cdf, size_t count, double exponent)
{
    double total = 0.0;
    double running = 0.0;

    if (!cdf || count == 0U)
        return;
    for (size_t i = 0; i < count; i++)
        total += 1.0 / pow((double)(i + 1U), exponent);
    if (total <= 0.0)
        return;

    for (size_t i = 0; i < count; i++)
    {
        running += (1.0 / pow((double)(i + 1U), exponent)) / total;
        cdf[i] = running;
    }
    cdf[count - 1U] = 1.0;
}

static size_t zipf_pick_domain(const double *cdf, size_t count, double sample)
{
    size_t lo = 0;
    size_t hi = count;

    while (lo + 1U < hi)
    {
        size_t mid = lo + (hi - lo) / 2U;
        if (sample <= cdf[mid])
            hi = mid;
        else
            lo = mid;
    }
    if (sample <= cdf[lo])
        return lo;
    return hi < count ? hi : (count - 1U);
}

static int collect_zipf_workload_points(const base_metric_t *base_metrics,
    zipf_workload_point_t *points, size_t point_count)
{
    static const size_t milestones[] = { 100U, 250U, 500U, 750U, 1000U };
    double *cdf = NULL;
    double unique_sums[sizeof(milestones) / sizeof(milestones[0])];

    if (!base_metrics || !points
        || point_count != (sizeof(milestones) / sizeof(milestones[0])))
    {
        return 0;
    }

    memset(unique_sums, 0, sizeof(unique_sums));
    cdf = (double *)calloc(BENCH_ZIPF_DOMAIN_POOL, sizeof(*cdf));
    if (!cdf)
        return 0;
    build_zipf_cdf(cdf, BENCH_ZIPF_DOMAIN_POOL, BENCH_ZIPF_EXPONENT);

    for (size_t run = 0; run < BENCH_ZIPF_RUNS; run++)
    {
        bool *visited
            = (bool *)calloc(BENCH_ZIPF_DOMAIN_POOL, sizeof(*visited));
        uint64_t seed = 0xC0FFEE1234567890ULL ^ (uint64_t)run;
        size_t unique_count = 0;
        size_t milestone_index = 0;

        if (!visited)
        {
            free(cdf);
            return 0;
        }

        for (size_t visit = 1U; visit <= BENCH_ZIPF_VISITS; visit++)
        {
            size_t domain = zipf_pick_domain(
                cdf, BENCH_ZIPF_DOMAIN_POOL, rng_unit_double(&seed));
            if (!visited[domain])
            {
                visited[domain] = true;
                unique_count++;
            }

            while (milestone_index < point_count
                && visit == milestones[milestone_index])
            {
                unique_sums[milestone_index] += (double)unique_count;
                milestone_index++;
            }
        }

        free(visited);
    }

    for (size_t i = 0; i < point_count; i++)
    {
        double mean_unique = unique_sums[i] / (double)BENCH_ZIPF_RUNS;
        double repeated_contacts = (double)milestones[i] - mean_unique;
        double compact_bundle_bytes
            = base_metrics->auth_bundle_compact_bytes > 0U
            ? (double)base_metrics->auth_bundle_compact_bytes
            : (double)base_metrics->auth_bundle_bytes;
        double compact_verify_ms
            = base_metrics->verify_bundle_compact_median_ms > 0.0
            ? base_metrics->verify_bundle_compact_median_ms
            : base_metrics->verify_bundle_median_ms;
        double compact_session_ms
            = base_metrics->secure_session_compact_median_ms > 0.0
            ? base_metrics->secure_session_compact_median_ms
            : base_metrics->secure_session_median_ms;
        double auth_bytes
            = mean_unique * (double)base_metrics->auth_bundle_bytes
            + repeated_contacts * compact_bundle_bytes;
        double verify_ms = mean_unique * base_metrics->verify_bundle_median_ms
            + repeated_contacts * compact_verify_ms;
        double session_ms = mean_unique * base_metrics->secure_session_median_ms
            + repeated_contacts * compact_session_ms;

        points[i].visits = milestones[i];
        points[i].mean_unique_domains = mean_unique;
        points[i].auth_bytes = auth_bytes;
        points[i].tx_ms_20kbps = tx_delay_ms(auth_bytes, 20.0);
        points[i].tx_ms_64kbps = tx_delay_ms(auth_bytes, 64.0);
        points[i].tx_ms_256kbps = tx_delay_ms(auth_bytes, 256.0);
        points[i].local_verify_ms = verify_ms;
        points[i].secure_session_ms = session_ms;
        points[i].combined_local_ms = verify_ms + session_ms;
        points[i].combined_total_ms_20kbps
            = points[i].combined_local_ms + points[i].tx_ms_20kbps;
        points[i].combined_total_ms_64kbps
            = points[i].combined_local_ms + points[i].tx_ms_64kbps;
        points[i].combined_total_ms_256kbps
            = points[i].combined_local_ms + points[i].tx_ms_256kbps;
    }

    free(cdf);
    return 1;
}

static void emit_json(FILE *out, const base_metric_t *base_metrics,
    const revocation_scale_metric_t *revocation_metrics,
    size_t revocation_count, const multiproof_metric_t *multiproof_metrics,
    size_t multiproof_count, const delta_metric_t *delta_metrics,
    size_t delta_count, const epoch_cache_metric_t *epoch_metrics,
    size_t epoch_count, const zipf_workload_point_t *zipf_points,
    size_t zipf_count)
{
    double implicit_vs_x509_pct = 0.0;
    if (base_metrics->x509_der_bytes > 0U)
    {
        implicit_vs_x509_pct
            = ((double)base_metrics->implicit_cert_bytes * 100.0)
            / (double)base_metrics->x509_der_bytes;
    }

    fprintf(out, "{\n");
    fprintf(out, "  \"metadata\": {\n");
    fprintf(out, "    \"benchmark\": \"tinypki-capability-suite\",\n");
    fprintf(out, "    \"revocation_scale_rounds\": %d,\n", BENCH_SCALE_ROUNDS);
    fprintf(out, "    \"delta_rounds\": %d,\n", BENCH_DELTA_ROUNDS);
    fprintf(out, "    \"verify_rounds\": %d,\n", BENCH_VERIFY_ROUNDS);
    fprintf(out, "    \"session_rounds\": %d,\n", BENCH_SESSION_ROUNDS);
    fprintf(out, "    \"multiproof_max_queries\": %d,\n",
        SM2_REV_MERKLE_MULTI_MAX_QUERIES);
    fprintf(out, "    \"zipf_runs\": %d,\n", BENCH_ZIPF_RUNS);
    fprintf(out, "    \"zipf_visits\": %d,\n", BENCH_ZIPF_VISITS);
    fprintf(out, "    \"zipf_domain_pool\": %d,\n", BENCH_ZIPF_DOMAIN_POOL);
    fprintf(out, "    \"zipf_exponent\": %.2f\n", BENCH_ZIPF_EXPONENT);
    fprintf(out, "  },\n");
    fprintf(out, "  \"summary\": {\n");
    fprintf(
        out, "    \"x509_der_bytes\": %zu,\n", base_metrics->x509_der_bytes);
    fprintf(out, "    \"implicit_cert_bytes\": %zu,\n",
        base_metrics->implicit_cert_bytes);
    fprintf(out, "    \"implicit_vs_x509_pct\": %.2f,\n", implicit_vs_x509_pct);
    fprintf(out, "    \"compact_root_hint_bytes\": %zu,\n",
        base_metrics->compact_root_hint_bytes);
    fprintf(out, "    \"auth_bundle_bytes\": %zu,\n",
        base_metrics->auth_bundle_bytes);
    fprintf(out, "    \"auth_bundle_compact_bytes\": %zu,\n",
        base_metrics->auth_bundle_compact_bytes);
    fprintf(out, "    \"verify_bundle_median_ms\": %.3f,\n",
        base_metrics->verify_bundle_median_ms);
    fprintf(out, "    \"verify_bundle_compact_median_ms\": %.3f,\n",
        base_metrics->verify_bundle_compact_median_ms);
    fprintf(out, "    \"secure_session_median_ms\": %.3f,\n",
        base_metrics->secure_session_median_ms);
    fprintf(out, "    \"secure_session_compact_median_ms\": %.3f,\n",
        base_metrics->secure_session_compact_median_ms);
    fprintf(out, "    \"revoke_publish_median_ms\": %.3f,\n",
        base_metrics->revoke_publish_median_ms);
    fprintf(out, "    \"service_refresh_root_median_ms\": %.3f,\n",
        base_metrics->service_refresh_root_median_ms);
    fprintf(out, "    \"client_refresh_root_median_ms\": %.3f\n",
        base_metrics->client_refresh_root_median_ms);
    fprintf(out, "  },\n");

    fprintf(out, "  \"revocation_scaling\": [\n");
    for (size_t i = 0; i < revocation_count; i++)
    {
        fprintf(out,
            "    {\"revoked_count\": %zu, \"tree_build_ms\": %.3f, "
            "\"member_prove_ms\": %.3f, \"member_verify_ms\": %.3f, "
            "\"absence_prove_ms\": %.3f, \"absence_verify_ms\": %.3f, "
            "\"member_proof_bytes\": %zu, \"absence_proof_bytes\": %zu}%s\n",
            revocation_metrics[i].revoked_count,
            revocation_metrics[i].tree_build_ms,
            revocation_metrics[i].member_prove_ms,
            revocation_metrics[i].member_verify_ms,
            revocation_metrics[i].absence_prove_ms,
            revocation_metrics[i].absence_verify_ms,
            revocation_metrics[i].member_proof_bytes,
            revocation_metrics[i].absence_proof_bytes,
            (i + 1U) == revocation_count ? "" : ",");
    }
    fprintf(out, "  ],\n");

    fprintf(out, "  \"epoch_cache_scaling\": [\n");
    for (size_t i = 0; i < epoch_count; i++)
    {
        fprintf(out,
            "    {\"revoked_count\": %zu, \"cache_top_levels\": %zu, "
            "\"directory_build_ms\": %.3f, \"directory_verify_ms\": %.3f, "
            "\"cached_proof_build_ms\": %.3f, "
            "\"cached_proof_verify_ms\": %.3f, \"directory_bytes\": %zu, "
            "\"cached_proof_bytes\": %zu}%s\n",
            epoch_metrics[i].revoked_count, epoch_metrics[i].cache_top_levels,
            epoch_metrics[i].directory_build_ms,
            epoch_metrics[i].directory_verify_ms,
            epoch_metrics[i].cached_proof_build_ms,
            epoch_metrics[i].cached_proof_verify_ms,
            epoch_metrics[i].directory_bytes,
            epoch_metrics[i].cached_proof_bytes,
            (i + 1U) == epoch_count ? "" : ",");
    }
    fprintf(out, "  ],\n");

    fprintf(out, "  \"multiproof_scaling\": [\n");
    for (size_t i = 0; i < multiproof_count; i++)
    {
        fprintf(out,
            "    {\"query_count\": %zu, \"build_ms\": %.3f, "
            "\"verify_ms\": %.3f, \"multiproof_bytes\": %zu, "
            "\"single_member_total_bytes\": %zu, \"unique_hash_count\": %zu, "
            "\"compression_pct\": %.2f}%s\n",
            multiproof_metrics[i].query_count, multiproof_metrics[i].build_ms,
            multiproof_metrics[i].verify_ms,
            multiproof_metrics[i].multiproof_bytes,
            multiproof_metrics[i].single_member_total_bytes,
            multiproof_metrics[i].unique_hash_count,
            multiproof_metrics[i].compression_pct,
            (i + 1U) == multiproof_count ? "" : ",");
    }
    fprintf(out, "  ],\n");

    fprintf(out, "  \"delta_scaling\": [\n");
    for (size_t i = 0; i < delta_count; i++)
    {
        fprintf(out, "    {\"delta_items\": %zu, \"apply_ms\": %.3f}%s\n",
            delta_metrics[i].delta_items, delta_metrics[i].apply_ms,
            (i + 1U) == delta_count ? "" : ",");
    }
    fprintf(out, "  ],\n");

    fprintf(out, "  \"zipf_workload\": [\n");
    for (size_t i = 0; i < zipf_count; i++)
    {
        fprintf(out,
            "    {\"visits\": %zu, \"mean_unique_domains\": %.2f, "
            "\"auth_bytes\": %.2f, \"tx_ms_20kbps\": %.3f, "
            "\"tx_ms_64kbps\": %.3f, \"tx_ms_256kbps\": %.3f, "
            "\"local_verify_ms\": %.3f, \"secure_session_ms\": %.3f, "
            "\"combined_local_ms\": %.3f, \"combined_total_ms_20kbps\": %.3f, "
            "\"combined_total_ms_64kbps\": %.3f, "
            "\"combined_total_ms_256kbps\": %.3f}%s\n",
            zipf_points[i].visits, zipf_points[i].mean_unique_domains,
            zipf_points[i].auth_bytes, zipf_points[i].tx_ms_20kbps,
            zipf_points[i].tx_ms_64kbps, zipf_points[i].tx_ms_256kbps,
            zipf_points[i].local_verify_ms, zipf_points[i].secure_session_ms,
            zipf_points[i].combined_local_ms,
            zipf_points[i].combined_total_ms_20kbps,
            zipf_points[i].combined_total_ms_64kbps,
            zipf_points[i].combined_total_ms_256kbps,
            (i + 1U) == zipf_count ? "" : ",");
    }
    fprintf(out, "  ]\n");
    fprintf(out, "}\n");
}

int main(int argc, char **argv)
{
    base_metric_t base_metrics;
    revocation_scale_metric_t revocation_metrics[6];
    multiproof_metric_t multiproof_metrics[6];
    delta_metric_t delta_metrics[5];
    epoch_cache_metric_t epoch_metrics[5];
    zipf_workload_point_t zipf_points[5];
    FILE *out = stdout;

    memset(&base_metrics, 0, sizeof(base_metrics));
    memset(revocation_metrics, 0, sizeof(revocation_metrics));
    memset(multiproof_metrics, 0, sizeof(multiproof_metrics));
    memset(delta_metrics, 0, sizeof(delta_metrics));
    memset(epoch_metrics, 0, sizeof(epoch_metrics));
    memset(zipf_points, 0, sizeof(zipf_points));

    if (!collect_base_metrics(&base_metrics))
    {
        fprintf(stderr, "TinyPKI capability benchmark failed: base metrics.\n");
        return 1;
    }
    if (!collect_revocation_scaling_metrics(revocation_metrics,
            sizeof(revocation_metrics) / sizeof(revocation_metrics[0])))
    {
        fprintf(stderr,
            "TinyPKI capability benchmark failed: revocation scaling.\n");
        return 1;
    }
    if (!collect_multiproof_metrics(multiproof_metrics,
            sizeof(multiproof_metrics) / sizeof(multiproof_metrics[0])))
    {
        fprintf(stderr,
            "TinyPKI capability benchmark failed: multiproof scaling.\n");
        return 1;
    }
    if (!collect_delta_metrics(
            delta_metrics, sizeof(delta_metrics) / sizeof(delta_metrics[0])))
    {
        fprintf(
            stderr, "TinyPKI capability benchmark failed: delta scaling.\n");
        return 1;
    }
    if (!collect_epoch_cache_metrics(
            epoch_metrics, sizeof(epoch_metrics) / sizeof(epoch_metrics[0])))
    {
        fprintf(stderr, "TinyPKI capability benchmark failed: epoch cache.\n");
        return 1;
    }
    if (!collect_zipf_workload_points(&base_metrics, zipf_points,
            sizeof(zipf_points) / sizeof(zipf_points[0])))
    {
        fprintf(
            stderr, "TinyPKI capability benchmark failed: zipf workload.\n");
        return 1;
    }

    if (argc > 1)
    {
        out = fopen(argv[1], "wb");
        if (!out)
        {
            fprintf(stderr, "Failed to open output file: %s\n", argv[1]);
            return 1;
        }
    }

    emit_json(out, &base_metrics, revocation_metrics,
        sizeof(revocation_metrics) / sizeof(revocation_metrics[0]),
        multiproof_metrics,
        sizeof(multiproof_metrics) / sizeof(multiproof_metrics[0]),
        delta_metrics, sizeof(delta_metrics) / sizeof(delta_metrics[0]),
        epoch_metrics, sizeof(epoch_metrics) / sizeof(epoch_metrics[0]),
        zipf_points, sizeof(zipf_points) / sizeof(zipf_points[0]));

    if (out != stdout)
        fclose(out);
    return 0;
}
