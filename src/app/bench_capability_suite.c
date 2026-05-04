/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/time.h>
#endif

#include "sm2_pki_client.h"
#include "sm2_pki_service.h"

#define BENCH_ROUNDS 21U

typedef struct
{
    size_t cert_bytes;
    size_t signature_bytes;
    size_t epoch_root_bytes;
    size_t revocation_proof_bytes;
    size_t issuance_proof_bytes;
    size_t witness_signature_bytes;
    size_t evidence_bundle_bytes;
    size_t authentication_bundle_bytes;
} capability_size_metrics_t;

typedef struct
{
    double export_epoch_evidence_ms;
    double witness_sign_ms;
    double verify_epoch_bundle_ms;
} capability_timing_metrics_t;

typedef struct
{
    sm2_pki_service_ctx_t *service;
    sm2_pki_client_ctx_t *signer;
    sm2_pki_client_ctx_t *verifier;
    sm2_ec_point_t ca_pub;
    sm2_ic_cert_result_t cert_result;
    sm2_private_key_t temp_private_key;
    sm2_private_key_t witness_private_key;
    sm2_ec_point_t witness_public_key;
    sm2_pki_transparency_witness_t witness;
    sm2_pki_transparency_policy_t policy;
    sm2_auth_signature_t signature;
    sm2_pki_evidence_bundle_t evidence;
    sm2_pki_verify_request_t request;
    uint8_t message[64];
    size_t message_len;
    uint64_t auth_now;
} capability_flow_ctx_t;

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

static double median_ms(double *samples, size_t count)
{
    if (!samples || count == 0)
        return 0.0;
    qsort(samples, count, sizeof(samples[0]), cmp_double_asc);
    if ((count & 1U) != 0U)
        return samples[count / 2U];
    return (samples[(count / 2U) - 1U] + samples[count / 2U]) / 2.0;
}

static uint64_t current_unix_ts(void)
{
    time_t now = time(NULL);
    return now < 0 ? 0U : (uint64_t)now;
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

static int get_identity_material(sm2_pki_client_ctx_t *client,
    const sm2_implicit_cert_t **cert, const sm2_ec_point_t **public_key)
{
    return sm2_pki_client_get_cert(client, cert) == SM2_PKI_SUCCESS
        && sm2_pki_client_get_public_key(client, public_key) == SM2_PKI_SUCCESS;
}

static int attach_witness(capability_flow_ctx_t *ctx)
{
    if (!ctx)
        return 0;
    if (sm2_pki_epoch_witness_sign(&ctx->evidence.epoch_root_record,
            ctx->witness.witness_id, ctx->witness.witness_id_len,
            &ctx->witness_private_key, &ctx->evidence.witness_signatures[0])
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    ctx->evidence.witness_signature_count = 1U;
    ctx->request.transparency_policy = &ctx->policy;
    return 1;
}

static int build_flow(capability_flow_ctx_t *ctx)
{
    const uint8_t issuer[] = "CAPABILITY_CA";
    const uint8_t identity[] = "CAPABILITY_NODE";
    const uint8_t witness_id[] = "capability-witness-0";
    const uint8_t message[] = "TINYPKI_CAPABILITY_EPOCH_BUNDLE";
    const sm2_implicit_cert_t *cert = NULL;
    const sm2_ec_point_t *public_key = NULL;

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
    if (sm2_pki_client_create(&ctx->signer, &ctx->ca_pub, ctx->service)
            != SM2_PKI_SUCCESS
        || sm2_pki_client_create(&ctx->verifier, &ctx->ca_pub, NULL)
            != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_client_import_cert(ctx->signer, &ctx->cert_result,
            &ctx->temp_private_key, &ctx->ca_pub)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_generate_ephemeral_keypair(
            &ctx->witness_private_key, &ctx->witness_public_key)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    memcpy(ctx->witness.witness_id, witness_id, sizeof(witness_id) - 1U);
    ctx->witness.witness_id_len = sizeof(witness_id) - 1U;
    ctx->witness.public_key = ctx->witness_public_key;
    ctx->policy.witnesses = &ctx->witness;
    ctx->policy.witness_count = 1U;
    ctx->policy.threshold = 1U;

    ctx->auth_now = ctx->cert_result.cert.valid_from != 0
        ? ctx->cert_result.cert.valid_from
        : current_unix_ts();
    if (sm2_pki_sign(
            ctx->signer, ctx->message, ctx->message_len, &ctx->signature)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (!get_identity_material(ctx->signer, &cert, &public_key))
        return 0;
    if (sm2_pki_client_export_epoch_evidence(
            ctx->signer, ctx->auth_now, &ctx->evidence)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }

    ctx->request.cert = cert;
    ctx->request.public_key = public_key;
    ctx->request.message = ctx->message;
    ctx->request.message_len = ctx->message_len;
    ctx->request.signature = &ctx->signature;
    ctx->request.evidence_bundle = &ctx->evidence;
    return attach_witness(ctx);
}

static void cleanup_flow(capability_flow_ctx_t *ctx)
{
    if (!ctx)
        return;
    sm2_pki_client_destroy(&ctx->verifier);
    sm2_pki_client_destroy(&ctx->signer);
    sm2_pki_service_destroy(&ctx->service);
    memset(ctx, 0, sizeof(*ctx));
}

static size_t epoch_root_bytes(const sm2_pki_epoch_root_record_t *root)
{
    if (!root)
        return 0U;
    return root->authority_id_len + (6U * sizeof(uint64_t))
        + (2U * SM2_REV_MERKLE_HASH_LEN) + root->signature_len;
}

static size_t issuance_proof_bytes(const sm2_pki_issuance_member_proof_t *proof)
{
    if (!proof)
        return 0U;
    return SM2_PKI_ISSUANCE_COMMITMENT_LEN + (3U * sizeof(size_t))
        + proof->sibling_count * (SM2_REV_MERKLE_HASH_LEN + 1U);
}

static size_t witness_bytes(const sm2_pki_evidence_bundle_t *evidence)
{
    size_t total = 0;
    if (!evidence)
        return 0U;
    for (size_t i = 0; i < evidence->witness_signature_count; i++)
    {
        total += evidence->witness_signatures[i].witness_id_len
            + evidence->witness_signatures[i].signature_len;
    }
    return total;
}

static int collect_size_metrics(
    capability_flow_ctx_t *ctx, capability_size_metrics_t *metrics)
{
    uint8_t cert_buf[1024];
    uint8_t absence_buf[16384];
    size_t cert_len = sizeof(cert_buf);
    size_t absence_len = sizeof(absence_buf);

    if (!ctx || !metrics)
        return 0;
    memset(metrics, 0, sizeof(*metrics));

    if (sm2_ic_cbor_encode_cert(cert_buf, &cert_len, &ctx->cert_result.cert)
        != SM2_IC_SUCCESS)
    {
        return 0;
    }
    if (sm2_rev_absence_proof_encode(
            &ctx->evidence.revocation_proof.absence_proof, absence_buf,
            &absence_len)
        != SM2_IC_SUCCESS)
    {
        return 0;
    }

    metrics->cert_bytes = cert_len;
    metrics->signature_bytes = ctx->signature.der_len;
    metrics->epoch_root_bytes
        = epoch_root_bytes(&ctx->evidence.epoch_root_record);
    metrics->revocation_proof_bytes = absence_len;
    metrics->issuance_proof_bytes
        = issuance_proof_bytes(&ctx->evidence.issuance_proof.member_proof);
    metrics->witness_signature_bytes = witness_bytes(&ctx->evidence);
    metrics->evidence_bundle_bytes = metrics->epoch_root_bytes
        + metrics->revocation_proof_bytes + metrics->issuance_proof_bytes
        + metrics->witness_signature_bytes;
    metrics->authentication_bundle_bytes = metrics->cert_bytes
        + metrics->signature_bytes + metrics->evidence_bundle_bytes;
    return 1;
}

static int collect_timing_metrics(
    capability_flow_ctx_t *ctx, capability_timing_metrics_t *metrics)
{
    double export_samples[BENCH_ROUNDS];
    double witness_samples[BENCH_ROUNDS];
    double verify_samples[BENCH_ROUNDS];

    if (!ctx || !metrics)
        return 0;
    memset(metrics, 0, sizeof(*metrics));

    for (size_t i = 0; i < BENCH_ROUNDS; i++)
    {
        sm2_pki_evidence_bundle_t evidence;
        double t0 = now_ms_highres();
        if (sm2_pki_client_export_epoch_evidence(
                ctx->signer, ctx->auth_now, &evidence)
            != SM2_PKI_SUCCESS)
        {
            return 0;
        }
        export_samples[i] = now_ms_highres() - t0;
    }

    for (size_t i = 0; i < BENCH_ROUNDS; i++)
    {
        sm2_pki_transparency_witness_signature_t signature;
        double t0 = now_ms_highres();
        if (sm2_pki_epoch_witness_sign(&ctx->evidence.epoch_root_record,
                ctx->witness.witness_id, ctx->witness.witness_id_len,
                &ctx->witness_private_key, &signature)
            != SM2_PKI_SUCCESS)
        {
            return 0;
        }
        witness_samples[i] = now_ms_highres() - t0;
    }

    for (size_t i = 0; i < BENCH_ROUNDS; i++)
    {
        size_t matched = 0;
        double t0 = now_ms_highres();
        if (sm2_pki_verify(
                ctx->verifier, &ctx->request, ctx->auth_now, &matched)
            != SM2_PKI_SUCCESS)
        {
            return 0;
        }
        verify_samples[i] = now_ms_highres() - t0;
    }

    metrics->export_epoch_evidence_ms = median_ms(export_samples, BENCH_ROUNDS);
    metrics->witness_sign_ms = median_ms(witness_samples, BENCH_ROUNDS);
    metrics->verify_epoch_bundle_ms = median_ms(verify_samples, BENCH_ROUNDS);
    return 1;
}

static void emit_json(FILE *out, const capability_size_metrics_t *sizes,
    const capability_timing_metrics_t *timings)
{
    fprintf(out, "{\n");
    fprintf(out, "  \"metadata\": {\n");
    fprintf(out, "    \"benchmark\": \"tinypki-capability-suite\",\n");
    fprintf(out, "    \"evidence_model\": \"epoch_bundle\",\n");
    fprintf(out, "    \"rounds\": %u\n", (unsigned)BENCH_ROUNDS);
    fprintf(out, "  },\n");
    fprintf(out, "  \"sizes\": {\n");
    fprintf(out, "    \"cert_bytes\": %zu,\n", sizes->cert_bytes);
    fprintf(out, "    \"signature_bytes\": %zu,\n", sizes->signature_bytes);
    fprintf(out, "    \"epoch_root_bytes\": %zu,\n", sizes->epoch_root_bytes);
    fprintf(out, "    \"revocation_proof_bytes\": %zu,\n",
        sizes->revocation_proof_bytes);
    fprintf(out, "    \"issuance_proof_bytes\": %zu,\n",
        sizes->issuance_proof_bytes);
    fprintf(out, "    \"witness_signature_bytes\": %zu,\n",
        sizes->witness_signature_bytes);
    fprintf(out, "    \"evidence_bundle_bytes\": %zu,\n",
        sizes->evidence_bundle_bytes);
    fprintf(out, "    \"authentication_bundle_bytes\": %zu\n",
        sizes->authentication_bundle_bytes);
    fprintf(out, "  },\n");
    fprintf(out, "  \"timings_ms\": {\n");
    fprintf(out, "    \"export_epoch_evidence_median\": %.3f,\n",
        timings->export_epoch_evidence_ms);
    fprintf(
        out, "    \"witness_sign_median\": %.3f,\n", timings->witness_sign_ms);
    fprintf(out, "    \"verify_epoch_bundle_median\": %.3f\n",
        timings->verify_epoch_bundle_ms);
    fprintf(out, "  }\n");
    fprintf(out, "}\n");
}

int main(int argc, char **argv)
{
    capability_flow_ctx_t ctx;
    capability_size_metrics_t sizes;
    capability_timing_metrics_t timings;
    FILE *out = stdout;

    memset(&ctx, 0, sizeof(ctx));
    memset(&sizes, 0, sizeof(sizes));
    memset(&timings, 0, sizeof(timings));

    if (!build_flow(&ctx) || !collect_size_metrics(&ctx, &sizes)
        || !collect_timing_metrics(&ctx, &timings))
    {
        fprintf(stderr,
            "TinyPKI capability benchmark failed to collect metrics.\n");
        cleanup_flow(&ctx);
        return 1;
    }

    if (argc > 1)
    {
        out = fopen(argv[1], "wb");
        if (!out)
        {
            fprintf(stderr, "Failed to open output file: %s\n", argv[1]);
            cleanup_flow(&ctx);
            return 1;
        }
    }

    emit_json(out, &sizes, &timings);
    if (out != stdout)
        fclose(out);
    cleanup_flow(&ctx);
    return 0;
}
