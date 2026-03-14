/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_pki_client.h
 * @brief PKI client library interfaces for
 * parse/encode/reconstruct/sign/verify.
 */

#ifndef SM2_PKI_CLIENT_H
#define SM2_PKI_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "sm2_implicit_cert.h"
#include "sm2_auth.h"
#include "sm2_crypto.h"
#include "sm2_revocation.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct sm2_pki_service_ctx_st sm2_pki_service_ctx_t;
    typedef struct sm2_pki_client_ctx_st sm2_pki_client_ctx_t;
    typedef struct
    {
        sm2_rev_root_record_t root_record;
        sm2_rev_absence_proof_t absence_proof;
    } sm2_pki_revocation_evidence_t;

    typedef struct
    {
        const sm2_implicit_cert_t *cert;
        const sm2_ec_point_t *public_key;
        const uint8_t *message;
        size_t message_len;
        const sm2_auth_signature_t *signature;
        const sm2_pki_revocation_evidence_t *revocation_evidence;
    } sm2_pki_verify_request_t;

    /*
     * Opaque owning handle.
     * Instances must be created/destroyed via the API below.
     */
    sm2_pki_error_t sm2_pki_client_create(sm2_pki_client_ctx_t **ctx,
        const sm2_ec_point_t *default_ca_public_key,
        sm2_pki_service_ctx_t *revocation_service);

    void sm2_pki_client_destroy(sm2_pki_client_ctx_t **ctx);

    sm2_pki_error_t sm2_pki_client_add_trusted_ca(
        sm2_pki_client_ctx_t *ctx, const sm2_ec_point_t *ca_public_key);

    sm2_pki_error_t sm2_pki_client_get_cert(
        const sm2_pki_client_ctx_t *ctx, const sm2_implicit_cert_t **cert);

    sm2_pki_error_t sm2_pki_client_get_public_key(
        const sm2_pki_client_ctx_t *ctx, const sm2_ec_point_t **public_key);

    bool sm2_pki_client_is_sign_pool_enabled(const sm2_pki_client_ctx_t *ctx);

    /*
     * Bind the client to a service-managed revocation backend for exporting
     * local non-revocation evidence without exposing internal state objects.
     */
    sm2_pki_error_t sm2_pki_client_bind_revocation(
        sm2_pki_client_ctx_t *ctx, sm2_pki_service_ctx_t *service);

    /*
     * Imports a CA-signed revocation root record into the client-side cache.
     * The record must verify under one of the configured trusted CA keys and
     * must not roll back the highest version previously accepted by this
     * client. Same-version refresh is allowed only when the root hash is
     * unchanged. When multiple trusted CAs are configured, first import for an
     * authority requires an authority-specific CA binding established either by
     * a local identity certificate, a bound service, or a successful carried-
     * evidence verification for that authority.
     */
    sm2_pki_error_t sm2_pki_client_import_root_record(
        sm2_pki_client_ctx_t *ctx, const sm2_rev_root_record_t *root_record,
        uint64_t now_ts);

    /*
     * Refreshes the cached root record from a bound service-managed
     * revocation backend. This requires a live binding created via
     * sm2_pki_client_bind_revocation().
     */
    sm2_pki_error_t sm2_pki_client_refresh_root(
        sm2_pki_client_ctx_t *ctx, uint64_t now_ts);

    /*
     * Returns the most recently accepted cached CA-signed root record.
     */
    sm2_pki_error_t sm2_pki_client_get_cached_root_record(
        const sm2_pki_client_ctx_t *ctx, sm2_rev_root_record_t *root_record);

    /*
     * Returns the cached root record for the given authority/issuer.
     */
    sm2_pki_error_t sm2_pki_client_get_cached_root_record_for_authority(
        const sm2_pki_client_ctx_t *ctx, const uint8_t *authority_id,
        size_t authority_id_len, sm2_rev_root_record_t *root_record);

    /*
     * Exports the local client's exact non-revocation evidence bundle for the
     * currently imported identity certificate. This requires a live service
     * binding created via sm2_pki_client_bind_revocation().
     */
    sm2_pki_error_t sm2_pki_client_export_revocation_evidence(
        sm2_pki_client_ctx_t *ctx, uint64_t now_ts,
        sm2_pki_revocation_evidence_t *evidence);

    /*
     * Reconstructs local identity keys and verifies that the certificate is
     * consistent with the supplied issuer public key before importing it.
     */
    sm2_pki_error_t sm2_pki_client_import_cert(sm2_pki_client_ctx_t *ctx,
        const sm2_ic_cert_result_t *cert_result,
        const sm2_private_key_t *temp_private_key,
        const sm2_ec_point_t *ca_public_key);

    sm2_pki_error_t sm2_pki_client_enable_sign_pool(
        sm2_pki_client_ctx_t *ctx, size_t capacity, size_t target_available);

    void sm2_pki_client_disable_sign_pool(sm2_pki_client_ctx_t *ctx);

    /* Signing, verification and session protection entry points. */
    sm2_pki_error_t sm2_pki_sign(sm2_pki_client_ctx_t *ctx,
        const uint8_t *message, size_t message_len,
        sm2_auth_signature_t *signature);

    /*
     * High-level PKI verification requires the peer to carry an exact
     * non-revocation evidence bundle signed under the issuing CA root.
     */
    sm2_pki_error_t sm2_pki_verify(sm2_pki_client_ctx_t *ctx,
        const sm2_pki_verify_request_t *request, uint64_t now_ts,
        size_t *matched_ca_index);

    sm2_pki_error_t sm2_pki_batch_verify(const sm2_auth_verify_item_t *items,
        size_t item_count, size_t *valid_count);

    sm2_pki_error_t sm2_pki_generate_ephemeral_keypair(
        sm2_private_key_t *ephemeral_private_key,
        sm2_ec_point_t *ephemeral_public_key);

    sm2_pki_error_t sm2_pki_key_agreement(sm2_pki_client_ctx_t *ctx,
        const sm2_private_key_t *local_ephemeral_private_key,
        const sm2_ec_point_t *peer_public_key,
        const sm2_ec_point_t *peer_ephemeral_public_key,
        const uint8_t *transcript, size_t transcript_len, uint8_t *session_key,
        size_t session_key_len);

    sm2_pki_error_t sm2_pki_encrypt(sm2_pki_aead_mode_t mode,
        const uint8_t key[16], const uint8_t *iv, size_t iv_len,
        const uint8_t *aad, size_t aad_len, const uint8_t *plaintext,
        size_t plaintext_len, uint8_t *ciphertext, size_t *ciphertext_len,
        uint8_t *tag, size_t *tag_len);

    sm2_pki_error_t sm2_pki_decrypt(sm2_pki_aead_mode_t mode,
        const uint8_t key[16], const uint8_t *iv, size_t iv_len,
        const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext,
        size_t ciphertext_len, const uint8_t *tag, size_t tag_len,
        uint8_t *plaintext, size_t *plaintext_len);

#ifdef __cplusplus
}
#endif

#endif /* SM2_PKI_CLIENT_H */
