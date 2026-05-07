/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_auth.h
 * @brief High-throughput unified authentication based on SM2 implicit
 * certificates.
 */

#ifndef SM2_AUTH_H
#define SM2_AUTH_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "sm2_implicit_cert.h"
#include "sm2_revocation_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define SM2_AUTH_MAX_SIG_DER_LEN 96
#define SM2_AUTH_MAX_CA_STORE 16
#define SM2_AUTH_AEAD_IV_LEN 12
#define SM2_AUTH_AEAD_TAG_LEN 16
#define SM2_AUTH_AEAD_TAG_MAX_LEN 16

    typedef struct
    {
        uint8_t der[SM2_AUTH_MAX_SIG_DER_LEN];
        size_t der_len;
    } sm2_auth_signature_t;

    typedef struct
    {
        /*
         * Backend-dependent slot payload.
         * The current OpenSSL implementation may treat the slot as prepared
         * signing capacity only and leave kinv/r zeroed.
         */
        uint8_t kinv[SM2_KEY_LEN];
        uint8_t r[SM2_KEY_LEN];
        bool used;
    } sm2_auth_sign_slot_t;

    typedef struct
    {
        sm2_private_key_t signing_key;
        sm2_auth_sign_slot_t *slots;
        size_t capacity;
        size_t available;
        size_t next_slot;
        void *native_sign_key; /* Internal OpenSSL key cache. */
    } sm2_auth_sign_pool_t;

    typedef struct
    {
        sm2_ec_point_t ca_pub_keys[SM2_AUTH_MAX_CA_STORE];
        size_t count;
    } sm2_auth_trust_store_t;

    typedef sm2_ic_error_t (*sm2_auth_revocation_query_fn)(
        const sm2_implicit_cert_t *cert, uint64_t now_ts, void *user_ctx,
        sm2_rev_status_t *status);

    typedef enum
    {
        SM2_AUTH_REVOCATION_POLICY_PREFER_CALLBACK = 0,
        SM2_AUTH_REVOCATION_POLICY_STRICT_CROSS_CHECK = 1
    } sm2_auth_revocation_policy_t;

    typedef enum
    {
        SM2_AUTH_AEAD_MODE_SM4_GCM = 1,
        SM2_AUTH_AEAD_MODE_SM4_CCM = 2
    } sm2_auth_aead_mode_t;

    typedef struct
    {
        const sm2_implicit_cert_t *cert;
        const sm2_ec_point_t *public_key;
        const uint8_t *message;
        size_t message_len;
        const sm2_auth_signature_t *signature;
        sm2_auth_revocation_query_fn revocation_query_fn;
        void *revocation_query_user_ctx;
        sm2_auth_revocation_policy_t revocation_policy;
        bool lightweight_mode;
        /*
         * Off by default.
         * When false, authentication requires at least one revocation source
         * (caller-supplied query callback or local revocation context).
         * Enable only for trusted raw/offline verification flows where
         * revocation is intentionally unavailable.
         */
        bool allow_missing_revocation_check;
        /*
         * Off by default.
         * When false, a locally managed revocation context is not treated as
         * authoritative evidence of GOOD unless corroborated by a caller-
         * supplied revocation backend.
         * Enable only for trusted local/admin verification flows.
         */
        bool allow_local_revocation_state;
    } sm2_auth_request_t;

    typedef struct
    {
        const sm2_ec_point_t *public_key;
        const uint8_t *message;
        size_t message_len;
        const sm2_auth_signature_t *signature;
    } sm2_auth_verify_item_t;

    sm2_ic_error_t sm2_auth_sign_pool_init(sm2_auth_sign_pool_t *pool,
        const sm2_private_key_t *signing_key, size_t capacity);
    void sm2_auth_sign_pool_cleanup(sm2_auth_sign_pool_t *pool);
    sm2_ic_error_t sm2_auth_sign_pool_fill(
        sm2_auth_sign_pool_t *pool, size_t target_available);
    size_t sm2_auth_sign_pool_available(const sm2_auth_sign_pool_t *pool);

    sm2_ic_error_t sm2_auth_sign(const sm2_private_key_t *signing_key,
        const uint8_t *message, size_t message_len,
        sm2_auth_signature_t *signature);
    sm2_ic_error_t sm2_auth_sign_with_pool(sm2_auth_sign_pool_t *pool,
        const uint8_t *message, size_t message_len,
        sm2_auth_signature_t *signature);
    sm2_ic_error_t sm2_auth_verify_signature(const sm2_ec_point_t *public_key,
        const uint8_t *message, size_t message_len,
        const sm2_auth_signature_t *signature);

    sm2_ic_error_t sm2_auth_batch_verify(const sm2_auth_verify_item_t *items,
        size_t item_count, size_t *valid_count);

    sm2_ic_error_t sm2_auth_trust_store_init(sm2_auth_trust_store_t *store);
    sm2_ic_error_t sm2_auth_trust_store_add_ca(
        sm2_auth_trust_store_t *store, const sm2_ec_point_t *ca_public_key);

    sm2_ic_error_t sm2_auth_verify_cert_with_store(
        const sm2_implicit_cert_t *cert, const sm2_ec_point_t *public_key,
        const sm2_auth_trust_store_t *store, size_t *matched_ca_index);

    /* Initializes request fields to secure default values. */
    void sm2_auth_request_init(sm2_auth_request_t *request);

    sm2_ic_error_t sm2_auth_authenticate_request(
        const sm2_auth_request_t *request, const sm2_auth_trust_store_t *store,
        sm2_rev_ctx_t *rev_ctx, uint64_t now_ts, size_t *matched_ca_index);

    sm2_ic_error_t sm2_auth_derive_session_key_static(
        const sm2_private_key_t *local_private_key,
        const sm2_ec_point_t *peer_public_key, uint8_t *session_key,
        size_t session_key_len);

    sm2_ic_error_t sm2_auth_mutual_handshake_static(
        const sm2_auth_request_t *a_to_b,
        const sm2_private_key_t *a_private_key,
        const sm2_auth_trust_store_t *b_trust_store, sm2_rev_ctx_t *b_rev_ctx,
        const sm2_auth_request_t *b_to_a,
        const sm2_private_key_t *b_private_key,
        const sm2_auth_trust_store_t *a_trust_store, sm2_rev_ctx_t *a_rev_ctx,
        uint64_t now_ts, uint8_t *session_key_a, uint8_t *session_key_b,
        size_t session_key_len);

    sm2_ic_error_t sm2_auth_generate_ephemeral_keypair(
        sm2_private_key_t *ephemeral_private_key,
        sm2_ec_point_t *ephemeral_public_key);

    sm2_ic_error_t sm2_auth_derive_session_key(
        const sm2_private_key_t *local_private_key,
        const sm2_private_key_t *local_ephemeral_private_key,
        const sm2_ec_point_t *peer_public_key,
        const sm2_ec_point_t *peer_ephemeral_public_key,
        const uint8_t *transcript, size_t transcript_len, uint8_t *session_key,
        size_t session_key_len);

    /*
     * Builds the canonical handshake binding payload that must be signed by
     * each peer before calling sm2_auth_mutual_handshake().
     *
     * The payload direction is explicit: "local ephemeral first, peer
     * ephemeral second". Callers may pass output == NULL to query the required
     * buffer length via output_len.
     */
    sm2_ic_error_t sm2_auth_build_handshake_binding(
        const sm2_ec_point_t *local_ephemeral_public_key,
        const sm2_ec_point_t *peer_ephemeral_public_key,
        const uint8_t *transcript, size_t transcript_len, uint8_t *output,
        size_t *output_len);

    sm2_ic_error_t sm2_auth_mutual_handshake(const sm2_auth_request_t *a_to_b,
        const sm2_private_key_t *a_private_key,
        const sm2_private_key_t *a_ephemeral_private_key,
        const sm2_ec_point_t *a_ephemeral_public_key,
        const sm2_auth_trust_store_t *b_trust_store, sm2_rev_ctx_t *b_rev_ctx,
        const sm2_auth_request_t *b_to_a,
        const sm2_private_key_t *b_private_key,
        const sm2_private_key_t *b_ephemeral_private_key,
        const sm2_ec_point_t *b_ephemeral_public_key,
        const sm2_auth_trust_store_t *a_trust_store, sm2_rev_ctx_t *a_rev_ctx,
        uint64_t now_ts, const uint8_t *transcript, size_t transcript_len,
        uint8_t *session_key_a, uint8_t *session_key_b, size_t session_key_len);

    /* Authenticated session protection entry points. */
    sm2_ic_error_t sm2_auth_encrypt(sm2_auth_aead_mode_t mode,
        const uint8_t key[16], const uint8_t *iv, size_t iv_len,
        const uint8_t *aad, size_t aad_len, const uint8_t *plaintext,
        size_t plaintext_len, uint8_t *ciphertext, size_t *ciphertext_len,
        uint8_t *tag, size_t *tag_len);

    sm2_ic_error_t sm2_auth_decrypt(sm2_auth_aead_mode_t mode,
        const uint8_t key[16], const uint8_t *iv, size_t iv_len,
        const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext,
        size_t ciphertext_len, const uint8_t *tag, size_t tag_len,
        uint8_t *plaintext, size_t *plaintext_len);

#ifdef __cplusplus
}
#endif

#endif /* SM2_AUTH_H */
