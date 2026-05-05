/* SPDX-License-Identifier: Apache-2.0 */

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

#include "sm2_pki_service.h"
#include "sm2_pki_client.h"

#define BENCH_BASELINE_X509_BITS 2048
#define BENCH_LATENCY_ROUNDS 21
#define BENCH_SESSION_ROUNDS 11

typedef struct
{
    const char *name;
    size_t bytes;
    double tx_ms_20kbps;
    double tx_ms_64kbps;
    double tx_ms_256kbps;
} bench_payload_metric_t;

typedef struct
{
    const char *name;
    double median_ms;
} bench_timing_metric_t;

typedef struct
{
    sm2_pki_service_ctx_t *service;
    sm2_pki_client_ctx_t *client;
    sm2_pki_client_ctx_t *verifier;
    sm2_ec_point_t ca_pub;
    sm2_ic_cert_result_t cert_result;
    sm2_private_key_t temp_private_key;
    sm2_auth_signature_t signature;
    sm2_pki_evidence_bundle_t evidence;
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

static double tx_delay_ms(size_t bytes, double kbps)
{
    if (kbps <= 0.0)
        return 0.0;
    return ((double)bytes * 8.0 / (kbps * 1000.0)) * 1000.0;
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

static sm2_private_key_t g_bench_witness_priv;
static sm2_ec_point_t g_bench_witness_pub;
static sm2_pki_transparency_witness_t g_bench_witness;
static sm2_pki_transparency_policy_t g_bench_transparency_policy;
static int g_bench_witness_ready = 0;

static int bench_transparency_policy_init(void)
{
    static const uint8_t witness_id[] = "bench-witness-0";
    if (g_bench_witness_ready)
        return 1;
    if (sm2_auth_generate_ephemeral_keypair(
            &g_bench_witness_priv, &g_bench_witness_pub)
        != SM2_IC_SUCCESS)
    {
        return 0;
    }

    memset(&g_bench_witness, 0, sizeof(g_bench_witness));
    memcpy(g_bench_witness.witness_id, witness_id, sizeof(witness_id) - 1U);
    g_bench_witness.witness_id_len = sizeof(witness_id) - 1U;
    g_bench_witness.public_key = g_bench_witness_pub;
    g_bench_transparency_policy.witnesses = &g_bench_witness;
    g_bench_transparency_policy.witness_count = 1U;
    g_bench_transparency_policy.threshold = 1U;
    g_bench_witness_ready = 1;
    return 1;
}

static int bench_configure_transparency_verifier(sm2_pki_client_ctx_t *client)
{
    return client && bench_transparency_policy_init()
        && sm2_pki_client_set_transparency_policy(
               client, &g_bench_transparency_policy)
        == SM2_PKI_SUCCESS;
}

static int bench_attach_epoch_witness(sm2_pki_evidence_bundle_t *evidence)
{
    if (!evidence || !bench_transparency_policy_init())
        return 0;
    if (sm2_pki_epoch_witness_sign(&evidence->epoch_root_record,
            g_bench_witness.witness_id, g_bench_witness.witness_id_len,
            &g_bench_witness_priv, &evidence->witness_signatures[0])
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    evidence->witness_signature_count = 1U;
    return 1;
}

static int build_signed_verify_request(sm2_pki_client_ctx_t *signer,
    const uint8_t *message, size_t message_len, uint64_t now_ts,
    sm2_auth_signature_t *signature, sm2_pki_evidence_bundle_t *evidence,
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
    if (sm2_pki_client_export_epoch_evidence(signer, now_ts, evidence)
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
    request->evidence_bundle = evidence;
    if (!bench_attach_epoch_witness(evidence))
        return 0;
    return 1;
}

static int encode_cert_len(
    const sm2_implicit_cert_t *cert, uint8_t *buf, size_t cap, size_t *len)
{
    *len = cap;
    return sm2_ic_cbor_encode_cert(buf, len, cert) == SM2_IC_SUCCESS;
}

static size_t epoch_root_wire_size(
    const sm2_pki_epoch_root_record_t *root_record)
{
    if (!root_record)
        return 0U;
    return root_record->authority_id_len + (6U * sizeof(uint64_t))
        + (2U * SM2_REV_MERKLE_HASH_LEN) + root_record->signature_len;
}

static size_t issuance_proof_wire_size(
    const sm2_pki_issuance_member_proof_t *proof)
{
    if (!proof)
        return 0U;
    return SM2_PKI_ISSUANCE_COMMITMENT_LEN + (3U * sizeof(size_t))
        + proof->sibling_count * (SM2_REV_MERKLE_HASH_LEN + 1U);
}

static int encode_absence_len(
    const sm2_rev_absence_proof_t *proof, uint8_t *buf, size_t cap, size_t *len)
{
    *len = cap;
    return sm2_rev_absence_proof_encode(proof, buf, len) == SM2_IC_SUCCESS;
}

static int build_flow_context(bench_flow_ctx_t *ctx)
{
    const uint8_t issuer[] = "BENCH_CA";
    const uint8_t identity[] = "BENCH_NODE";
    const uint8_t message[] = "TINYPKI_BENCH_AUTH_MESSAGE";

    if (!ctx)
        return 0;
    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->message, message, sizeof(message) - 1);
    ctx->message_len = sizeof(message) - 1;

    if (sm2_pki_service_create(&ctx->service, issuer, sizeof(issuer) - 1, 64,
            300, current_unix_ts())
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_identity_register(ctx->service, identity, sizeof(identity) - 1,
            SM2_KU_DIGITAL_SIGNATURE)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (!issue_identity_cert(ctx->service, identity, sizeof(identity) - 1,
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
    if (!bench_configure_transparency_verifier(ctx->verifier))
        return 0;
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

    if (sm2_pki_service_create(&ctx->service, issuer, sizeof(issuer) - 1, 32,
            300, current_unix_ts())
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_identity_register(ctx->service, id_a, sizeof(id_a) - 1, usage)
            != SM2_PKI_SUCCESS
        || sm2_pki_identity_register(
               ctx->service, id_b, sizeof(id_b) - 1, usage)
            != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (!issue_identity_cert(
            ctx->service, id_a, sizeof(id_a) - 1, usage, &cert_a, &temp_a)
        || !issue_identity_cert(
            ctx->service, id_b, sizeof(id_b) - 1, usage, &cert_b, &temp_b))
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
    if (!bench_configure_transparency_verifier(ctx->client_a)
        || !bench_configure_transparency_verifier(ctx->client_b))
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

static int compute_payload_metrics(
    bench_payload_metric_t *metrics, size_t metric_count)
{
    bench_flow_ctx_t flow;
    uint8_t cert_buf[1024];
    uint8_t absence_buf[16384];
    size_t cert_len = 0;
    size_t root_len = 0;
    size_t absence_len = 0;
    size_t issuance_len = 0;
    size_t witness_len = 0;
    int x509_der_len = 0;

    enum
    {
        revoked_n = 2048,
        query_n = 16
    };
    uint64_t *revoked = NULL;
    sm2_rev_tree_t *tree = NULL;
    sm2_rev_multi_proof_t *multi = NULL;
    uint8_t multi_buf[1048576];
    size_t multi_len = sizeof(multi_buf);

    if (!metrics || metric_count < 7)
        return 0;

    memset(&flow, 0, sizeof(flow));
    if (!build_flow_context(&flow)
        || !create_x509_baseline_der_size(&x509_der_len))
        goto fail;
    if (!encode_cert_len(
            &flow.cert_result.cert, cert_buf, sizeof(cert_buf), &cert_len))
        goto fail;
    root_len = epoch_root_wire_size(&flow.evidence.epoch_root_record);
    issuance_len
        = issuance_proof_wire_size(&flow.evidence.issuance_proof.member_proof);
    for (size_t i = 0; i < flow.evidence.witness_signature_count; i++)
    {
        witness_len += flow.evidence.witness_signatures[i].witness_id_len
            + flow.evidence.witness_signatures[i].signature_len;
    }
    if (!encode_absence_len(&flow.evidence.revocation_proof.absence_proof,
            absence_buf, sizeof(absence_buf), &absence_len))
        goto fail;

    revoked = (uint64_t *)calloc(revoked_n, sizeof(uint64_t));
    if (!revoked)
        goto fail;
    for (size_t i = 0; i < revoked_n; i++)
        revoked[i] = 900000ULL + (uint64_t)i;
    if (sm2_rev_tree_build(&tree, revoked, revoked_n, 2026031401ULL)
        != SM2_IC_SUCCESS)
        goto fail;

    uint64_t queries[query_n];
    for (size_t i = 0; i < query_n; i++)
        queries[i] = revoked[1000 + i];
    if (sm2_rev_multi_proof_build(tree, queries, query_n, &multi)
            != SM2_IC_SUCCESS
        || sm2_rev_multi_proof_encode(multi, multi_buf, &multi_len)
            != SM2_IC_SUCCESS)
        goto fail;

    metrics[0].name = "X.509 DER Baseline";
    metrics[0].bytes = (size_t)x509_der_len;
    metrics[1].name = "ECQV Implicit Certificate";
    metrics[1].bytes = cert_len;
    metrics[2].name = "CA-signed Epoch Root";
    metrics[2].bytes = root_len;
    metrics[3].name = "Merkle Absence Proof";
    metrics[3].bytes = absence_len;
    metrics[4].name = "Epoch Evidence Bundle";
    metrics[4].bytes = root_len + absence_len + issuance_len + witness_len;
    metrics[5].name = "Authentication Bundle";
    metrics[5].bytes = cert_len + flow.signature.der_len + metrics[4].bytes;
    metrics[6].name = "Merkle Multiproof (16)";
    metrics[6].bytes = multi_len;

    for (size_t i = 0; i < 7; i++)
    {
        metrics[i].tx_ms_20kbps = tx_delay_ms(metrics[i].bytes, 20.0);
        metrics[i].tx_ms_64kbps = tx_delay_ms(metrics[i].bytes, 64.0);
        metrics[i].tx_ms_256kbps = tx_delay_ms(metrics[i].bytes, 256.0);
    }

    sm2_rev_multi_proof_cleanup(&multi);
    sm2_rev_tree_cleanup(&tree);
    free(revoked);
    cleanup_flow_context(&flow);
    return 1;

fail:
    sm2_rev_multi_proof_cleanup(&multi);
    sm2_rev_tree_cleanup(&tree);
    free(revoked);
    cleanup_flow_context(&flow);
    return 0;
}

static double measure_create_request_median(void)
{
    const uint8_t identity[] = "BENCH_REQ";
    double samples[BENCH_LATENCY_ROUNDS];

    for (size_t i = 0; i < BENCH_LATENCY_ROUNDS; i++)
    {
        sm2_ic_cert_request_t request;
        sm2_private_key_t temp_priv;
        double t0 = now_ms_highres();
        if (sm2_ic_create_cert_request(&request, identity, sizeof(identity) - 1,
                SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            != SM2_IC_SUCCESS)
        {
            return 0.0;
        }
        samples[i] = now_ms_highres() - t0;
    }
    return calc_median_value(samples, BENCH_LATENCY_ROUNDS);
}

static double measure_authorize_issue_median(void)
{
    const uint8_t issuer[] = "BENCH_ISSUE_CA";
    const uint8_t identity[] = "BENCH_ISSUE";
    double samples[BENCH_LATENCY_ROUNDS];
    sm2_pki_service_ctx_t *service = NULL;

    if (sm2_pki_service_create(
            &service, issuer, sizeof(issuer) - 1, 64, 300, current_unix_ts())
            != SM2_PKI_SUCCESS
        || sm2_pki_identity_register(service, identity, sizeof(identity) - 1,
               SM2_KU_DIGITAL_SIGNATURE)
            != SM2_PKI_SUCCESS)
    {
        sm2_pki_service_destroy(&service);
        return 0.0;
    }

    for (size_t i = 0; i < BENCH_LATENCY_ROUNDS; i++)
    {
        sm2_ic_cert_request_t request;
        sm2_private_key_t temp_priv;
        sm2_ic_cert_result_t cert_result;

        if (sm2_ic_create_cert_request(&request, identity, sizeof(identity) - 1,
                SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            != SM2_IC_SUCCESS)
        {
            sm2_pki_service_destroy(&service);
            return 0.0;
        }

        double t0 = now_ms_highres();
        if (sm2_pki_cert_authorize_request(service, &request) != SM2_PKI_SUCCESS
            || sm2_pki_cert_issue(
                   service, &request, current_unix_ts(), &cert_result)
                != SM2_PKI_SUCCESS)
        {
            sm2_pki_service_destroy(&service);
            return 0.0;
        }
        samples[i] = now_ms_highres() - t0;
    }

    sm2_pki_service_destroy(&service);
    return calc_median_value(samples, BENCH_LATENCY_ROUNDS);
}

static double measure_client_import_median(void)
{
    const uint8_t issuer[] = "BENCH_IMPORT_CA";
    const uint8_t identity[] = "BENCH_IMPORT";
    double samples[BENCH_LATENCY_ROUNDS];
    sm2_pki_service_ctx_t *service = NULL;
    sm2_pki_client_ctx_t *client = NULL;
    sm2_ec_point_t ca_pub;

    memset(&ca_pub, 0, sizeof(ca_pub));
    if (sm2_pki_service_create(
            &service, issuer, sizeof(issuer) - 1, 64, 300, current_unix_ts())
            != SM2_PKI_SUCCESS
        || sm2_pki_identity_register(service, identity, sizeof(identity) - 1,
               SM2_KU_DIGITAL_SIGNATURE)
            != SM2_PKI_SUCCESS
        || sm2_pki_service_get_ca_public_key(service, &ca_pub)
            != SM2_PKI_SUCCESS
        || sm2_pki_client_create(&client, &ca_pub, service) != SM2_PKI_SUCCESS)
    {
        sm2_pki_client_destroy(&client);
        sm2_pki_service_destroy(&service);
        return 0.0;
    }

    for (size_t i = 0; i < BENCH_LATENCY_ROUNDS; i++)
    {
        sm2_ic_cert_result_t cert_result;
        sm2_private_key_t temp_priv;
        if (!issue_identity_cert(service, identity, sizeof(identity) - 1,
                SM2_KU_DIGITAL_SIGNATURE, &cert_result, &temp_priv))
        {
            sm2_pki_client_destroy(&client);
            sm2_pki_service_destroy(&service);
            return 0.0;
        }

        double t0 = now_ms_highres();
        if (sm2_pki_client_import_cert(
                client, &cert_result, &temp_priv, &ca_pub)
            != SM2_PKI_SUCCESS)
        {
            sm2_pki_client_destroy(&client);
            sm2_pki_service_destroy(&service);
            return 0.0;
        }
        samples[i] = now_ms_highres() - t0;
    }

    sm2_pki_client_destroy(&client);
    sm2_pki_service_destroy(&service);
    return calc_median_value(samples, BENCH_LATENCY_ROUNDS);
}

static double measure_export_evidence_median(void)
{
    bench_flow_ctx_t flow;
    double samples[BENCH_LATENCY_ROUNDS];

    memset(&flow, 0, sizeof(flow));
    if (!build_flow_context(&flow))
        return 0.0;

    for (size_t i = 0; i < BENCH_LATENCY_ROUNDS; i++)
    {
        sm2_pki_evidence_bundle_t evidence;
        double t0 = now_ms_highres();
        if (sm2_pki_client_export_epoch_evidence(
                flow.client, flow.auth_now, &evidence)
            != SM2_PKI_SUCCESS)
        {
            cleanup_flow_context(&flow);
            return 0.0;
        }
        samples[i] = now_ms_highres() - t0;
    }

    cleanup_flow_context(&flow);
    return calc_median_value(samples, BENCH_LATENCY_ROUNDS);
}

static double measure_verify_bundle_median(void)
{
    bench_flow_ctx_t flow;
    double samples[BENCH_LATENCY_ROUNDS];

    memset(&flow, 0, sizeof(flow));
    if (!build_flow_context(&flow))
        return 0.0;

    for (size_t i = 0; i < BENCH_LATENCY_ROUNDS; i++)
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
    return calc_median_value(samples, BENCH_LATENCY_ROUNDS);
}

static double measure_secure_session_median(void)
{
    bench_session_ctx_t ctx;
    double samples[BENCH_SESSION_ROUNDS];
    const uint8_t transcript[] = "TINYPKI_SESSION_BENCH";

    memset(&ctx, 0, sizeof(ctx));
    if (!build_session_context(&ctx))
        return 0.0;

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
        sm2_pki_evidence_bundle_t evidence_a;
        sm2_pki_evidence_bundle_t evidence_b;
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
                   transcript, sizeof(transcript) - 1, bind_a, &bind_a_len)
                != SM2_IC_SUCCESS
            || sm2_auth_build_handshake_binding(&eph_pub_b, &eph_pub_a,
                   transcript, sizeof(transcript) - 1, bind_b, &bind_b_len)
                != SM2_IC_SUCCESS
            || sm2_pki_sign(ctx.client_a, bind_a, bind_a_len, &sig_a)
                != SM2_PKI_SUCCESS
            || sm2_pki_sign(ctx.client_b, bind_b, bind_b_len, &sig_b)
                != SM2_PKI_SUCCESS
            || sm2_pki_client_export_epoch_evidence(
                   ctx.client_a, ctx.auth_now, &evidence_a)
                != SM2_PKI_SUCCESS
            || sm2_pki_client_export_epoch_evidence(
                   ctx.client_b, ctx.auth_now, &evidence_b)
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
        req_a_to_b.evidence_bundle = &evidence_a;
        if (!bench_attach_epoch_witness(&evidence_a))
        {
            cleanup_session_context(&ctx);
            return 0.0;
        }

        req_b_to_a.cert = cert_b;
        req_b_to_a.public_key = pub_b;
        req_b_to_a.message = bind_b;
        req_b_to_a.message_len = bind_b_len;
        req_b_to_a.signature = &sig_b;
        req_b_to_a.evidence_bundle = &evidence_b;
        if (!bench_attach_epoch_witness(&evidence_b))
        {
            cleanup_session_context(&ctx);
            return 0.0;
        }

        if (sm2_pki_secure_session_establish(ctx.client_a, &eph_priv_a,
                &eph_pub_a, &req_b_to_a, &eph_pub_b, transcript,
                sizeof(transcript) - 1, ctx.auth_now, sk_a, sizeof(sk_a),
                &matched_a)
                != SM2_PKI_SUCCESS
            || sm2_pki_secure_session_establish(ctx.client_b, &eph_priv_b,
                   &eph_pub_b, &req_a_to_b, &eph_pub_a, transcript,
                   sizeof(transcript) - 1, ctx.auth_now, sk_b, sizeof(sk_b),
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

static int compute_timing_metrics(
    bench_timing_metric_t *metrics, size_t metric_count)
{
    if (!metrics || metric_count < 6)
        return 0;

    metrics[0].name = "Create Request";
    metrics[0].median_ms = measure_create_request_median();
    metrics[1].name = "Authorize + Issue";
    metrics[1].median_ms = measure_authorize_issue_median();
    metrics[2].name = "Client Import";
    metrics[2].median_ms = measure_client_import_median();
    metrics[3].name = "Export Evidence";
    metrics[3].median_ms = measure_export_evidence_median();
    metrics[4].name = "Verify Bundle";
    metrics[4].median_ms = measure_verify_bundle_median();
    metrics[5].name = "Secure Session";
    metrics[5].median_ms = measure_secure_session_median();

    for (size_t i = 0; i < 6; i++)
    {
        if (metrics[i].median_ms <= 0.0)
            return 0;
    }
    return 1;
}

static void emit_json(FILE *out, const bench_payload_metric_t *payloads,
    size_t payload_count, const bench_timing_metric_t *timings,
    size_t timing_count)
{
    size_t implicit_bytes = 0;
    size_t x509_bytes = 0;
    size_t auth_bundle_bytes = 0;
    double implicit_ratio_pct = 0.0;

    for (size_t i = 0; i < payload_count; i++)
    {
        if (strcmp(payloads[i].name, "X.509 DER Baseline") == 0)
            x509_bytes = payloads[i].bytes;
        else if (strcmp(payloads[i].name, "ECQV Implicit Certificate") == 0)
            implicit_bytes = payloads[i].bytes;
        else if (strcmp(payloads[i].name, "Authentication Bundle") == 0)
            auth_bundle_bytes = payloads[i].bytes;
    }
    if (x509_bytes > 0)
        implicit_ratio_pct = ((double)implicit_bytes * 100.0) / x509_bytes;

    fprintf(out, "{\n");
    fprintf(out, "  \"metadata\": {\n");
    fprintf(out, "    \"benchmark\": \"tinypki-network-overhead\",\n");
    fprintf(out, "    \"timing_rounds\": %d,\n", BENCH_LATENCY_ROUNDS);
    fprintf(out, "    \"session_rounds\": %d\n", BENCH_SESSION_ROUNDS);
    fprintf(out, "  },\n");
    fprintf(out, "  \"summary\": {\n");
    fprintf(out, "    \"implicit_vs_x509_pct\": %.2f,\n", implicit_ratio_pct);
    fprintf(
        out, "    \"authentication_bundle_bytes\": %zu\n", auth_bundle_bytes);
    fprintf(out, "  },\n");
    fprintf(out, "  \"payloads\": [\n");
    for (size_t i = 0; i < payload_count; i++)
    {
        fprintf(out,
            "    {\"name\": \"%s\", \"bytes\": %zu, \"tx_ms_20kbps\": %.3f, "
            "\"tx_ms_64kbps\": %.3f, \"tx_ms_256kbps\": %.3f}%s\n",
            payloads[i].name, payloads[i].bytes, payloads[i].tx_ms_20kbps,
            payloads[i].tx_ms_64kbps, payloads[i].tx_ms_256kbps,
            (i + 1U) == payload_count ? "" : ",");
    }
    fprintf(out, "  ],\n");
    fprintf(out, "  \"timings\": [\n");
    for (size_t i = 0; i < timing_count; i++)
    {
        fprintf(out, "    {\"name\": \"%s\", \"median_ms\": %.3f}%s\n",
            timings[i].name, timings[i].median_ms,
            (i + 1U) == timing_count ? "" : ",");
    }
    fprintf(out, "  ]\n");
    fprintf(out, "}\n");
}

int main(int argc, char **argv)
{
    bench_payload_metric_t payloads[7];
    bench_timing_metric_t timings[6];
    FILE *out = stdout;

    memset(payloads, 0, sizeof(payloads));
    memset(timings, 0, sizeof(timings));

    if (!compute_payload_metrics(
            payloads, sizeof(payloads) / sizeof(payloads[0]))
        || !compute_timing_metrics(
            timings, sizeof(timings) / sizeof(timings[0])))
    {
        fprintf(stderr, "TinyPKI benchmark failed to collect metrics.\n");
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

    emit_json(out, payloads, sizeof(payloads) / sizeof(payloads[0]), timings,
        sizeof(timings) / sizeof(timings[0]));

    if (out != stdout)
        fclose(out);
    return 0;
}
