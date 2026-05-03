/* SPDX-License-Identifier: Apache-2.0 */

#include "test_common.h"
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

typedef struct
{
    const sm2_ec_point_t *ca_pub;
} pki_merkle_verify_ctx_t;

typedef struct
{
    const sm2_private_key_t *ca_priv;
} pki_merkle_sign_ctx_t;

static int test_pki_sm4_gcm_available(void)
{
    return test_openssl_cipher_available("SM4-GCM");
}

static sm2_ic_error_t pki_ic_error_from_pki(sm2_pki_error_t ret)
{
    switch (ret)
    {
        case SM2_PKI_SUCCESS:
            return SM2_IC_SUCCESS;
        case SM2_PKI_ERR_PARAM:
            return SM2_IC_ERR_PARAM;
        case SM2_PKI_ERR_MEMORY:
            return SM2_IC_ERR_MEMORY;
        case SM2_PKI_ERR_VERIFY:
        case SM2_PKI_ERR_NOT_FOUND:
        case SM2_PKI_ERR_CONFLICT:
            return SM2_IC_ERR_VERIFY;
        default:
            return SM2_IC_ERR_CRYPTO;
    }
}

static sm2_ic_error_t pki_merkle_verify_cb(void *user_ctx, const uint8_t *data,
    size_t data_len, const uint8_t *signature, size_t signature_len)
{
    if (!user_ctx || !data || !signature)
        return SM2_IC_ERR_PARAM;

    pki_merkle_verify_ctx_t *ctx = (pki_merkle_verify_ctx_t *)user_ctx;
    if (!ctx->ca_pub)
        return SM2_IC_ERR_PARAM;
    if (signature_len == 0 || signature_len > SM2_AUTH_MAX_SIG_DER_LEN)
        return SM2_IC_ERR_VERIFY;

    sm2_auth_signature_t sig;
    memset(&sig, 0, sizeof(sig));
    memcpy(sig.der, signature, signature_len);
    sig.der_len = signature_len;

    return sm2_auth_verify_signature(ctx->ca_pub, data, data_len, &sig);
}

static sm2_ic_error_t pki_merkle_sign_cb(void *user_ctx, const uint8_t *data,
    size_t data_len, uint8_t *signature, size_t *signature_len)
{
    if (!user_ctx || !data || !signature || !signature_len)
        return SM2_IC_ERR_PARAM;

    pki_merkle_sign_ctx_t *ctx = (pki_merkle_sign_ctx_t *)user_ctx;
    if (!ctx->ca_priv)
        return SM2_IC_ERR_PARAM;

    sm2_auth_signature_t sig;
    sm2_ic_error_t ret = sm2_auth_sign(ctx->ca_priv, data, data_len, &sig);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    if (*signature_len < sig.der_len)
        return SM2_IC_ERR_MEMORY;

    memcpy(signature, sig.der, sig.der_len);
    *signature_len = sig.der_len;
    return SM2_IC_SUCCESS;
}

typedef struct
{
    sm2_pki_service_ctx_t *service;
    const sm2_rev_root_record_t *root_record;
    sm2_rev_sync_verify_fn verify_fn;
    void *verify_user_ctx;
} pki_merkle_root_query_ctx_t;

static sm2_ic_error_t pki_merkle_root_query_cb(const sm2_implicit_cert_t *cert,
    uint64_t now_ts, void *user_ctx, sm2_rev_status_t *status)
{
    if (!cert || !user_ctx || !status)
        return SM2_IC_ERR_PARAM;

    pki_merkle_root_query_ctx_t *ctx = (pki_merkle_root_query_ctx_t *)user_ctx;
    sm2_rev_member_proof_t member_proof;
    sm2_rev_absence_proof_t absence_proof;
    memset(&member_proof, 0, sizeof(member_proof));
    memset(&absence_proof, 0, sizeof(absence_proof));

    sm2_pki_error_t pki_ret = sm2_pki_service_export_member_proof(
        ctx->service, cert->serial_number, &member_proof);
    if (pki_ret == SM2_PKI_SUCCESS)
    {
        sm2_ic_error_t ret
            = sm2_rev_member_proof_verify_with_root(ctx->root_record, now_ts,
                &member_proof, ctx->verify_fn, ctx->verify_user_ctx);
        if (ret == SM2_IC_SUCCESS)
            *status = SM2_REV_STATUS_REVOKED;
        return ret;
    }
    if (pki_ret != SM2_PKI_ERR_VERIFY)
        return pki_ic_error_from_pki(pki_ret);

    pki_ret = sm2_pki_service_export_absence_proof(
        ctx->service, cert->serial_number, &absence_proof);
    if (pki_ret != SM2_PKI_SUCCESS)
        return pki_ic_error_from_pki(pki_ret);

    sm2_ic_error_t ret
        = sm2_rev_absence_proof_verify_with_root(ctx->root_record, now_ts,
            &absence_proof, ctx->verify_fn, ctx->verify_user_ctx);
    if (ret == SM2_IC_SUCCESS)
        *status = SM2_REV_STATUS_GOOD;
    return ret;
}

static int pki_create_and_authorize_request(sm2_pki_service_ctx_t *service,
    const uint8_t *identity, size_t identity_len, uint8_t key_usage,
    sm2_ic_cert_request_t *request, sm2_private_key_t *temp_private_key)
{
    if (sm2_ic_create_cert_request(
            request, identity, identity_len, key_usage, temp_private_key)
        != SM2_IC_SUCCESS)
    {
        return 0;
    }

    return sm2_pki_cert_authorize_request(service, request) == SM2_PKI_SUCCESS;
}

static int pki_issue_identity_cert(sm2_pki_service_ctx_t *service,
    const uint8_t *identity, size_t identity_len, uint8_t key_usage,
    sm2_ic_cert_result_t *cert_result, sm2_private_key_t *temp_private_key)
{
    sm2_ic_cert_request_t request;
    memset(&request, 0, sizeof(request));

    if (!pki_create_and_authorize_request(service, identity, identity_len,
            key_usage, &request, temp_private_key))
    {
        return 0;
    }

    return test_pki_issue_cert(service, &request, cert_result)
        == SM2_PKI_SUCCESS;
}

static int pki_client_get_identity_material(sm2_pki_client_ctx_t *client,
    const sm2_implicit_cert_t **cert, const sm2_ec_point_t **public_key)
{
    if (cert && sm2_pki_client_get_cert(client, cert) != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (public_key
        && sm2_pki_client_get_public_key(client, public_key) != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    return 1;
}

static int pki_build_signed_verify_request(sm2_pki_client_ctx_t *signer,
    const uint8_t *message, size_t message_len, uint64_t now_ts,
    sm2_auth_signature_t *signature, sm2_pki_revocation_evidence_t *evidence,
    sm2_pki_issuance_evidence_t *issuance_evidence,
    sm2_pki_verify_request_t *request)
{
    const sm2_implicit_cert_t *cert = NULL;
    const sm2_ec_point_t *public_key = NULL;

    if (!signer || !message || message_len == 0 || !signature || !evidence
        || !issuance_evidence || !request)
    {
        return 0;
    }

    if (sm2_pki_sign(signer, message, message_len, signature)
        != SM2_PKI_SUCCESS)
        return 0;
    if (!pki_client_get_identity_material(signer, &cert, &public_key))
        return 0;
    if (sm2_pki_client_export_revocation_evidence(signer, now_ts, evidence)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_client_export_issuance_evidence(
            signer, now_ts, issuance_evidence)
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
    request->issuance_evidence = issuance_evidence;
    return 1;
}

static int pki_build_signed_verify_request_compact(sm2_pki_client_ctx_t *signer,
    const uint8_t *message, size_t message_len, uint64_t now_ts,
    sm2_auth_signature_t *signature, sm2_pki_revocation_evidence_t *evidence,
    sm2_pki_issuance_evidence_t *issuance_evidence,
    sm2_pki_verify_request_t *request)
{
    const sm2_implicit_cert_t *cert = NULL;
    const sm2_ec_point_t *public_key = NULL;

    if (!signer || !message || message_len == 0 || !signature || !evidence
        || !issuance_evidence || !request)
    {
        return 0;
    }

    if (sm2_pki_sign(signer, message, message_len, signature)
        != SM2_PKI_SUCCESS)
        return 0;
    if (!pki_client_get_identity_material(signer, &cert, &public_key))
        return 0;
    if (sm2_pki_client_export_compact_revocation_evidence(
            signer, now_ts, evidence)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_client_export_issuance_evidence(
            signer, now_ts, issuance_evidence)
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
    request->issuance_evidence = issuance_evidence;
    return 1;
}

/* Split by theme to keep PKI tests focused on flow, revocation and security
 * policy. */
#include "test_pki_flow.inc"
#include "test_pki_revocation.inc"
#include "test_pki_security.inc"

void run_test_pki_suite(void)
{
    RUN_TEST(test_phase4_service_client_flow);
    RUN_TEST(test_phase4_revocation_ocsp_and_cross_domain);
    RUN_TEST(test_phase4_pki_controls_and_param_defense);
    RUN_TEST(test_phase8_merkle_hook_and_service_binding);
    RUN_TEST(test_phase9_epoch_lookup_unknown_query_override_behavior);
    RUN_TEST(test_phase11_merkle_freshness_e2e_gate);
    RUN_TEST(test_phase13_service_query_cannot_self_refresh_root);
    RUN_TEST(test_phase13_issue_requires_authorized_request_and_policy_match);
    RUN_TEST(test_phase13_key_agreement_requires_ka_usage);
    RUN_TEST(test_phase93_reissue_preserves_old_serial_revocability);
    RUN_TEST(test_phase93_reimport_clears_stale_sign_pool);
    RUN_TEST(test_phase93_service_certificate_history_grows_past_legacy_cap);
    RUN_TEST(test_phase13_secure_pki_session_default_api);
    RUN_TEST(test_phase133_revocation_service_binding_lifecycle);
    RUN_TEST(
        test_phase134_pki_verify_rejects_request_level_revocation_override);
    RUN_TEST(test_phase137_client_root_cache_import_refresh_and_rollback);
    RUN_TEST(test_phase138_service_binding_tracks_newer_root_versions);
    RUN_TEST(test_phase140_compact_evidence_requires_matching_cached_root);
    RUN_TEST(test_phase141_issuance_transparency_required_and_threshold);
    RUN_TEST(test_phase139_root_versions_are_scoped_per_authority);
    RUN_TEST(
        test_phase139_unpinned_multi_ca_root_import_rejects_spoofed_authority);
    RUN_TEST(test_x509_real_baseline_size);
    RUN_TEST(test_phase93_crypto_direct_api_min_coverage);
}
