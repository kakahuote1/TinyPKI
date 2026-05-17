/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SM2_PKI_INTERNAL_H
#define SM2_PKI_INTERNAL_H

#include "sm2_pki_client.h"
#include "sm2_pki_service.h"
#include "crypto_internal.h"
#include "../auth/auth_internal.h"
#include "../revoke/revoke_internal.h"

typedef struct sm2_pki_service_ctx_st sm2_pki_service_state_t;
typedef struct sm2_pki_client_ctx_st sm2_pki_client_state_t;

sm2_ic_error_t sm2_pki_rev_snapshot_create(
    const sm2_rev_ctx_t *src, sm2_rev_ctx_t **snapshot);
void sm2_pki_rev_snapshot_release(sm2_rev_ctx_t **snapshot);
void sm2_pki_rev_snapshot_restore(sm2_rev_ctx_t *dst, sm2_rev_ctx_t **snapshot);
sm2_ic_error_t sm2_pki_rev_prepare_root_publication(const sm2_rev_ctx_t *ctx,
    uint64_t now_ts, sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx,
    const uint8_t *authority_id, size_t authority_id_len, sm2_rev_tree_t **tree,
    sm2_rev_root_record_t *root_record, uint64_t *root_valid_until);
sm2_ic_error_t sm2_pki_rev_sign_existing_root(const sm2_rev_ctx_t *ctx,
    const sm2_rev_tree_t *tree, uint64_t now_ts, sm2_rev_sync_sign_fn sign_fn,
    void *sign_user_ctx, const uint8_t *authority_id, size_t authority_id_len,
    sm2_rev_root_record_t *root_record, uint64_t *root_valid_until);
sm2_ic_error_t sm2_pki_root_record_sign_hash(const uint8_t *authority_id,
    size_t authority_id_len, uint64_t root_version,
    const uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN], uint64_t valid_from,
    uint64_t valid_until, sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx,
    sm2_rev_root_record_t *root_record);
sm2_ic_error_t sm2_pki_epoch_root_sign(const uint8_t *authority_id,
    size_t authority_id_len, uint64_t epoch_version,
    uint64_t revocation_root_version,
    const uint8_t revocation_root_hash[SM2_REV_MERKLE_HASH_LEN],
    uint64_t issuance_root_version,
    const uint8_t issuance_root_hash[SM2_REV_MERKLE_HASH_LEN],
    uint64_t witness_policy_version,
    const uint8_t witness_policy_hash[SM2_PKI_POLICY_DIGEST_LEN],
    uint64_t sync_policy_version,
    const uint8_t sync_policy_hash[SM2_PKI_POLICY_DIGEST_LEN],
    uint64_t valid_from, uint64_t valid_until, sm2_rev_sync_sign_fn sign_fn,
    void *sign_user_ctx, sm2_pki_epoch_root_record_t *root_record);
sm2_ic_error_t sm2_pki_epoch_root_verify(
    const sm2_pki_epoch_root_record_t *root_record, uint64_t now_ts,
    sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx);
sm2_ic_error_t sm2_pki_epoch_root_encode_witness_payload(
    const sm2_pki_epoch_root_record_t *root_record, uint8_t *output,
    size_t output_cap, size_t *output_len);
void sm2_pki_rev_set_root_valid_until(
    sm2_rev_ctx_t *ctx, uint64_t root_valid_until);
sm2_ic_error_t sm2_pki_issuance_leaf_key(
    const sm2_implicit_cert_t *cert, uint64_t *leaf_key);
sm2_ic_error_t sm2_pki_issuance_cert_commitment(const sm2_implicit_cert_t *cert,
    uint8_t commitment[SM2_PKI_ISSUANCE_COMMITMENT_LEN]);

typedef struct sm2_pki_issuance_tree_st sm2_pki_issuance_tree_t;

void sm2_pki_issuance_tree_cleanup(sm2_pki_issuance_tree_t **tree);
sm2_ic_error_t sm2_pki_issuance_tree_build(sm2_pki_issuance_tree_t **tree,
    const uint8_t (*commitments)[SM2_PKI_ISSUANCE_COMMITMENT_LEN],
    size_t commitment_count, uint64_t root_version);
sm2_ic_error_t sm2_pki_issuance_tree_append(sm2_pki_issuance_tree_t **tree,
    const uint8_t commitment[SM2_PKI_ISSUANCE_COMMITMENT_LEN],
    uint64_t root_version);
sm2_ic_error_t sm2_pki_issuance_tree_get_root_hash(
    const sm2_pki_issuance_tree_t *tree,
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN]);
sm2_ic_error_t sm2_pki_issuance_frontier_append(
    const sm2_pki_issuance_frontier_t *current,
    const sm2_pki_issuance_commitment_t *new_commitments,
    size_t new_commitment_count, sm2_pki_issuance_frontier_t *next,
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN]);
sm2_ic_error_t sm2_pki_issuance_tree_prove_member(
    const sm2_pki_issuance_tree_t *tree,
    const uint8_t commitment[SM2_PKI_ISSUANCE_COMMITMENT_LEN],
    sm2_pki_issuance_member_proof_t *proof);
sm2_ic_error_t sm2_pki_issuance_tree_verify_member(
    const uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN],
    const sm2_pki_issuance_member_proof_t *proof);

sm2_pki_error_t sm2_pki_service_acquire_revocation_binding(
    sm2_pki_service_ctx_t *ctx, sm2_pki_service_state_t **bound_state);
void sm2_pki_service_release_revocation_binding(sm2_pki_service_state_t *state);
bool sm2_pki_service_binding_live(const sm2_pki_service_state_t *state);
sm2_pki_error_t sm2_pki_service_export_current_epoch_evidence(
    const sm2_pki_service_ctx_t *ctx, const sm2_implicit_cert_t *cert,
    sm2_pki_epoch_root_record_t *epoch_root,
    sm2_rev_absence_proof_t *revocation_proof,
    sm2_pki_issuance_member_proof_t *issuance_proof);
sm2_pki_error_t sm2_pki_service_get_root_record(
    const sm2_pki_service_ctx_t *ctx, sm2_rev_root_record_t *root_record);
sm2_pki_error_t sm2_pki_service_export_epoch_dir(sm2_pki_service_ctx_t *ctx,
    uint64_t epoch_id, uint64_t valid_from, uint64_t valid_until,
    sm2_rev_epoch_dir_t **directory);
sm2_pki_error_t sm2_pki_service_export_member_proof(
    const sm2_pki_service_ctx_t *ctx, uint64_t serial_number,
    sm2_rev_member_proof_t *proof);
sm2_pki_error_t sm2_pki_service_export_absence_proof(
    const sm2_pki_service_ctx_t *ctx, uint64_t serial_number,
    sm2_rev_absence_proof_t *proof);
sm2_pki_error_t sm2_pki_service_export_issuance_proof(
    const sm2_pki_service_ctx_t *ctx, const sm2_implicit_cert_t *cert,
    sm2_pki_issuance_member_proof_t *proof);
sm2_pki_error_t sm2_pki_key_agreement(sm2_pki_client_ctx_t *ctx,
    const sm2_private_key_t *local_ephemeral_private_key,
    const sm2_ec_point_t *peer_public_key,
    const sm2_ec_point_t *peer_ephemeral_public_key, const uint8_t *transcript,
    size_t transcript_len, uint8_t *session_key, size_t session_key_len);

typedef struct
{
    bool used;
    bool has_epoch_record;
    bool has_epoch_digest;
    bool has_pinned_ca_index;
    bool has_revocation_root;
    bool has_issuance_root;
    uint8_t authority_id[SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN];
    size_t authority_id_len;
    size_t pinned_ca_index;
    sm2_pki_epoch_root_record_t epoch_record;
    sm2_pki_transparency_witness_signature_t
        witness_signatures[SM2_PKI_TRANSPARENCY_MAX_WITNESSES];
    size_t witness_signature_count;
    uint8_t epoch_digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN];
    uint64_t highest_seen_epoch_version;
    uint64_t highest_seen_revocation_root_version;
    uint8_t latest_revocation_root_hash[SM2_REV_MERKLE_HASH_LEN];
    uint64_t highest_seen_issuance_root_version;
    uint8_t latest_issuance_root_hash[SM2_REV_MERKLE_HASH_LEN];
} sm2_pki_epoch_cache_entry_t;

typedef struct
{
    bool used;
    uint8_t identity[SM2_PKI_MAX_ID_LEN];
    size_t identity_len;
    uint8_t key_usage;
    bool has_pending_request;
    sm2_ec_point_t pending_temp_public_key;
} sm2_pki_identity_entry_t;

#define SM2_PKI_INITIAL_CERT_CAPACITY 16U
#define SM2_PKI_VERIFIED_EVIDENCE_CACHE_CAPACITY 16U

typedef struct
{
    bool used;
    size_t identity_index;
    uint64_t serial_number;
    uint64_t valid_until;
    bool revoked;
} sm2_pki_cert_entry_t;

typedef struct
{
    bool used;
    uint8_t authority_id[SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN];
    size_t authority_id_len;
    size_t pinned_ca_index;
    uint64_t serial_number;
    uint8_t cert_commitment[SM2_PKI_ISSUANCE_COMMITMENT_LEN];
    uint8_t epoch_digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN];
    uint8_t proof_digest[SM2_PKI_EPOCH_ROOT_DIGEST_LEN];
    uint64_t epoch_version;
    uint64_t revocation_root_version;
    uint8_t revocation_root_hash[SM2_REV_MERKLE_HASH_LEN];
    uint64_t issuance_root_version;
    uint8_t issuance_root_hash[SM2_REV_MERKLE_HASH_LEN];
    uint64_t valid_until;
    uint64_t last_used_counter;
} sm2_pki_verified_evidence_cache_entry_t;

struct sm2_pki_service_ctx_st
{
    bool initialized;
    uint8_t issuer_id[SM2_PKI_MAX_ISSUER_LEN];
    size_t issuer_id_len;

    sm2_private_key_t ca_private_key;
    sm2_ec_point_t ca_public_key;

    sm2_pki_identity_entry_t identities[SM2_PKI_MAX_IDENTITIES];
    size_t identity_count;
    sm2_pki_cert_entry_t *certs;
    size_t cert_count;
    size_t cert_capacity;

    sm2_rev_ctx_t *rev_ctx;
    sm2_rev_tree_t *rev_tree;
    sm2_rev_root_record_t rev_root_record;
    bool revocation_state_ready;

    uint8_t (*issuance_commitments)[SM2_PKI_ISSUANCE_COMMITMENT_LEN];
    size_t issued_count;
    size_t issued_capacity;
    sm2_pki_issuance_tree_t *issuance_tree;
    sm2_rev_root_record_t issuance_root_record;
    bool issuance_state_ready;
    uint64_t epoch_version;
    sm2_pki_epoch_root_record_t epoch_root_record;
    bool epoch_state_ready;
    bool epoch_policy_binding_ready;
    uint64_t witness_policy_version;
    uint8_t witness_policy_hash[SM2_PKI_POLICY_DIGEST_LEN];
    uint64_t sync_policy_version;
    uint8_t sync_policy_hash[SM2_PKI_POLICY_DIGEST_LEN];

    size_t revocation_binding_refs;
    bool revocation_binding_retired;
};

struct sm2_pki_client_ctx_st
{
    bool initialized;
    sm2_implicit_cert_t cert;
    sm2_private_key_t private_key;
    sm2_ec_point_t public_key;
    bool has_identity_keys;

    sm2_auth_trust_store_t trust_store;
    sm2_pki_service_state_t *revocation_service;
    sm2_pki_epoch_cache_entry_t epoch_root_cache[SM2_AUTH_MAX_CA_STORE];
    sm2_pki_verified_evidence_cache_entry_t
        evidence_cache[SM2_PKI_VERIFIED_EVIDENCE_CACHE_CAPACITY];
    uint64_t evidence_cache_counter;

    sm2_pki_transparency_witness_t
        transparency_witnesses[SM2_PKI_TRANSPARENCY_MAX_WITNESSES];
    sm2_pki_transparency_policy_t transparency_policy;
    bool has_transparency_policy;

    sm2_auth_sign_pool_t sign_pool;
    bool sign_pool_enabled;
};

#endif /* SM2_PKI_INTERNAL_H */
