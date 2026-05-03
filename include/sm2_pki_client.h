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
#include "sm2_pki_transparency.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct sm2_pki_service_ctx_st sm2_pki_service_ctx_t;
    typedef struct sm2_pki_client_ctx_st sm2_pki_client_ctx_t;

    typedef enum
    {
        SM2_PKI_REV_EVIDENCE_FULL_ROOT = 0,
        SM2_PKI_REV_EVIDENCE_CACHED_ROOT = 1
    } sm2_pki_revocation_evidence_mode_t;

    typedef struct
    {
        uint8_t authority_id[SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN];
        size_t authority_id_len;
        uint64_t root_version;
        uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];
    } sm2_pki_cached_root_hint_t;

    typedef struct
    {
        sm2_pki_revocation_evidence_mode_t mode;
        sm2_pki_cached_root_hint_t cached_root_hint;
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
        const sm2_pki_issuance_evidence_t *issuance_evidence;
        /* Kept for source compatibility. Issuance transparency is mandatory. */
        bool require_issuance_transparency;
        /* Optional per-request strictness; client policy cannot be weakened. */
        const sm2_pki_transparency_policy_t *transparency_policy;
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

    /*
     * Configures the verifier-side system policy for edge/witness
     * signatures
     * over issuance transparency roots. Passing NULL or a
     * zero threshold clears
     * the witness threshold while keeping
     * mandatory issuance-log membership.
     */
    sm2_pki_error_t sm2_pki_client_set_transparency_policy(
        sm2_pki_client_ctx_t *ctx, const sm2_pki_transparency_policy_t *policy);

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
    sm2_pki_error_t sm2_pki_client_import_root_record(sm2_pki_client_ctx_t *ctx,
        const sm2_rev_root_record_t *root_record, uint64_t now_ts);

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
     * Exports the local client's exact non-revocation evidence bundle
     * for the
     * currently imported identity certificate. This requires a
     * live service
     * binding created via sm2_pki_client_bind_revocation().
     * The returned
     * evidence carries the full CA-signed root record and
     * works for cold-start
     * verifiers that do not yet cache the issuer's
     * root state.
     */
    sm2_pki_error_t sm2_pki_client_export_revocation_evidence(
        sm2_pki_client_ctx_t *ctx, uint64_t now_ts,
        sm2_pki_revocation_evidence_t *evidence);

    /*
     * Exports a compact non-revocation evidence bundle for hot-path
     * peers that
     * already cache the same authority/root version locally.
     * The proof carries
     * only a root hint (authority + version + root
     * hash) instead of the full
     * signed root record and will be rejected
     * by verifiers without a matching
     * cached root.
     */
    sm2_pki_error_t sm2_pki_client_export_compact_revocation_evidence(
        sm2_pki_client_ctx_t *ctx, uint64_t now_ts,
        sm2_pki_revocation_evidence_t *evidence);

    /*
     * Exports proof that the local identity certificate appears in the
     * issuer's
     * append-only issuance log. This detects certificates that
     * were signed but
     * never logged.
     */
    sm2_pki_error_t sm2_pki_client_export_issuance_evidence(
        sm2_pki_client_ctx_t *ctx, uint64_t now_ts,
        sm2_pki_issuance_evidence_t *evidence);

    /*
     * Signs a CA-signed issuance root record as an external
     * transparency
     * witness. Verifiers should enforce t-of-n witness
     * signatures through
     * sm2_pki_client_set_transparency_policy().
 */
    sm2_pki_error_t sm2_pki_issuance_witness_sign(
        const sm2_rev_root_record_t *root_record, const uint8_t *witness_id,
        size_t witness_id_len, const sm2_private_key_t *witness_private_key,
        sm2_pki_transparency_witness_signature_t *signature);

    /*
     * Reconstructs local identity keys and verifies that the certificate
     * is
     * consistent with the supplied issuer public key before importing
     * it.
     * Importing a new certificate clears any existing sign pool
     * because cached
     * signing state is bound to the previous private
     * key.
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
     * High-level PKI verification requires the peer to carry both an
     * exact
     * non-revocation evidence bundle and issuance transparency
     * evidence signed
     * under the issuing CA root.
     */
    sm2_pki_error_t sm2_pki_verify(sm2_pki_client_ctx_t *ctx,
        const sm2_pki_verify_request_t *request, uint64_t now_ts,
        size_t *matched_ca_index);

    sm2_pki_error_t sm2_pki_batch_verify(const sm2_auth_verify_item_t *items,
        size_t item_count, size_t *valid_count);

    sm2_pki_error_t sm2_pki_generate_ephemeral_keypair(
        sm2_private_key_t *ephemeral_private_key,
        sm2_ec_point_t *ephemeral_public_key);

    /*
     * Low-level key agreement primitive. Callers must ensure the peer
     * identity,
     * revocation evidence, issuance transparency evidence and
     * key usage have
     * already been verified through a higher-level flow
     * before using it.
     */
    sm2_pki_error_t sm2_pki_key_agreement(sm2_pki_client_ctx_t *ctx,
        const sm2_private_key_t *local_ephemeral_private_key,
        const sm2_ec_point_t *peer_public_key,
        const sm2_ec_point_t *peer_ephemeral_public_key,
        const uint8_t *transcript, size_t transcript_len, uint8_t *session_key,
        size_t session_key_len);

    /*
     * High-level secure session establishment entry point. The peer
     * request must
     * already carry a signature over the canonical
     * handshake binding produced by
     * sm2_auth_build_handshake_binding(),
     * plus non-revocation and issuance
     * transparency evidence accepted by
     * sm2_pki_verify().
     */
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
