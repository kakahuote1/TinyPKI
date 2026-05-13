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
#include "sm2_pki_types.h"
#include "sm2_revocation.h"
#include "sm2_pki_transparency.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct sm2_pki_service_ctx_st sm2_pki_service_ctx_t;
    typedef struct sm2_pki_client_ctx_st sm2_pki_client_ctx_t;

    typedef struct
    {
        sm2_rev_absence_proof_t absence_proof;
    } sm2_pki_epoch_revocation_proof_t;

    typedef struct
    {
        sm2_pki_issuance_member_proof_t member_proof;
    } sm2_pki_epoch_issuance_proof_t;

    typedef struct
    {
        sm2_pki_epoch_root_record_t epoch_root_record;
        sm2_pki_transparency_witness_signature_t
            witness_signatures[SM2_PKI_TRANSPARENCY_MAX_WITNESSES];
        size_t witness_signature_count;
    } sm2_pki_epoch_checkpoint_t;

#define SM2_PKI_CLIENT_PERSISTED_STATE_VERSION 1U
#define SM2_PKI_CLIENT_PERSISTED_STATE_MAX_AUTHORITIES 16U

    typedef struct
    {
        uint8_t authority_id[SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN];
        size_t authority_id_len;
        sm2_ec_point_t ca_public_key;
        uint64_t highest_seen_epoch_version;
        uint8_t epoch_digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN];
        uint64_t highest_seen_revocation_root_version;
        uint8_t latest_revocation_root_hash[SM2_REV_MERKLE_HASH_LEN];
        uint64_t highest_seen_issuance_root_version;
        uint8_t latest_issuance_root_hash[SM2_REV_MERKLE_HASH_LEN];
    } sm2_pki_client_persisted_authority_state_t;

    typedef struct
    {
        uint32_t format_version;
        size_t record_count;
        sm2_pki_client_persisted_authority_state_t
            records[SM2_PKI_CLIENT_PERSISTED_STATE_MAX_AUTHORITIES];
    } sm2_pki_client_persisted_state_t;

    typedef struct
    {
        uint8_t epoch_digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN];
        sm2_pki_epoch_revocation_proof_t revocation_proof;
        sm2_pki_epoch_issuance_proof_t issuance_proof;
    } sm2_pki_evidence_bundle_t;

    typedef struct
    {
        const sm2_implicit_cert_t *cert;
        const sm2_ec_point_t *public_key;
        const uint8_t *message;
        size_t message_len;
        const sm2_auth_signature_t *signature;
        const sm2_pki_evidence_bundle_t *evidence_bundle;
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

    /* Sets the verifier-side t-of-n witness policy required for verify. */
    sm2_pki_error_t sm2_pki_client_set_transparency_policy(
        sm2_pki_client_ctx_t *ctx, const sm2_pki_transparency_policy_t *policy);

    /* Imports a CA-broadcast epoch checkpoint into the local cache. */
    /* Checks CA signature and witness threshold before caching. */
    /* Verify only accepts evidence anchored to a cached checkpoint. */
    sm2_pki_error_t sm2_pki_client_import_epoch_checkpoint(
        sm2_pki_client_ctx_t *ctx, const sm2_pki_epoch_checkpoint_t *checkpoint,
        uint64_t now_ts);

    /*
     * Exports/imports local anti-rollback high-water marks for durable storage.
     * Imported high-water marks reject stale checkpoints but are not accepted
     * as cached checkpoints for evidence verification.
     */
    sm2_pki_error_t sm2_pki_client_export_persisted_state(
        const sm2_pki_client_ctx_t *ctx,
        sm2_pki_client_persisted_state_t *state);

    sm2_pki_error_t sm2_pki_client_import_persisted_state(
        sm2_pki_client_ctx_t *ctx,
        const sm2_pki_client_persisted_state_t *state);

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

    /* Exports one evidence bundle binding revocation and issuance roots. */
    sm2_pki_error_t sm2_pki_client_export_epoch_evidence(
        sm2_pki_client_ctx_t *ctx, uint64_t now_ts,
        sm2_pki_evidence_bundle_t *evidence);

    void sm2_pki_epoch_witness_state_init(sm2_pki_epoch_witness_state_t *state);

    void sm2_pki_epoch_witness_state_cleanup(
        sm2_pki_epoch_witness_state_t *state);

    sm2_ic_error_t sm2_pki_epoch_root_digest(
        const sm2_pki_epoch_root_record_t *root_record,
        uint8_t digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN]);

    sm2_pki_error_t sm2_pki_epoch_witness_sign_append_only(
        sm2_pki_epoch_witness_state_t *state,
        const sm2_pki_epoch_root_record_t *root_record,
        const sm2_ec_point_t *ca_public_key, uint64_t now_ts,
        const sm2_pki_issuance_commitment_t *new_commitments,
        size_t new_commitment_count, const uint8_t *witness_id,
        size_t witness_id_len, const sm2_private_key_t *witness_private_key,
        sm2_pki_transparency_witness_signature_t *signature);

    sm2_pki_error_t sm2_pki_epoch_quorum_check(
        const sm2_pki_epoch_root_vote_t *votes, size_t vote_count,
        size_t threshold, sm2_pki_epoch_quorum_result_t *result);

    /* Imports a certificate from a CA already present in the trust store. */
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

    /* Verifies cert, signature, epoch evidence, and witness threshold. */
    sm2_pki_error_t sm2_pki_verify(sm2_pki_client_ctx_t *ctx,
        const sm2_pki_verify_request_t *request, uint64_t now_ts,
        size_t *matched_ca_index);

    sm2_pki_error_t sm2_pki_generate_ephemeral_keypair(
        sm2_private_key_t *ephemeral_private_key,
        sm2_ec_point_t *ephemeral_public_key);

    /* Establishes a session after peer evidence and handshake verification. */
    sm2_pki_error_t sm2_pki_secure_session_establish(sm2_pki_client_ctx_t *ctx,
        const sm2_private_key_t *local_ephemeral_private_key,
        const sm2_ec_point_t *local_ephemeral_public_key,
        const sm2_pki_verify_request_t *peer_request,
        const sm2_ec_point_t *peer_ephemeral_public_key,
        const uint8_t *transcript, size_t transcript_len, uint64_t now_ts,
        uint8_t *session_key, size_t session_key_len, size_t *matched_ca_index);

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
