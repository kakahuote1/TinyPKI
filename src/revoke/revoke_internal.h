/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file revoke_internal.h
 * @brief Internal helpers shared by split revocation implementation files.
 */

#ifndef SM2_REVOKE_INTERNAL_H
#define SM2_REVOKE_INTERNAL_H

#include "sm2_revocation.h"

#ifndef SM2_REVOKE_INTERNAL_TYPEDEFS
#define SM2_REVOKE_INTERNAL_TYPEDEFS
typedef struct sm2_rev_tree_st sm2_rev_tree_t;
typedef struct sm2_rev_multi_proof_st sm2_rev_multi_proof_t;
typedef struct sm2_rev_epoch_dir_st sm2_rev_epoch_dir_t;
#endif

#ifndef SM2_REVOKE_LOOKUP_CTX_TYPEDEF
#define SM2_REVOKE_LOOKUP_CTX_TYPEDEF
typedef struct
{
    const sm2_rev_epoch_dir_t *directory;
    sm2_ic_error_t (*verify_fn)(void *user_ctx, const uint8_t *data,
        size_t data_len, const uint8_t *signature, size_t signature_len);
    void *verify_user_ctx;
} sm2_rev_lookup_ctx_t;
#endif

struct sm2_rev_ctx_st
{
    uint64_t *revoked_serials;
    size_t revoked_count;
    size_t revoked_capacity;
    sm2_rev_tree_t *rev_tree;

    sm2_rev_lookup_fn merkle_query_fn;
    void *merkle_query_user_ctx;

    uint64_t rev_version;
    uint64_t root_valid_ttl_sec;
    uint64_t root_valid_until;
    uint8_t root_hash[SM2_REV_SYNC_DIGEST_LEN];

    size_t query_inflight;
    size_t congestion_busy_threshold;
    size_t congestion_overload_threshold;
    sm2_rev_congestion_signal_t congestion_signal;
    uint64_t clock_skew_tolerance_sec;
};

static inline bool sm2_rev_internal_node_id_len_valid(size_t node_id_len)
{
    return node_id_len > 0 && node_id_len <= SM2_REV_SYNC_NODE_ID_MAX_LEN;
}

static inline sm2_ic_error_t sm2_rev_internal_validate_candidate_count(
    size_t candidate_count)
{
    return candidate_count <= SM2_REV_REDIRECT_MAX_CANDIDATES
        ? SM2_IC_SUCCESS
        : SM2_IC_ERR_PARAM;
}

static inline sm2_ic_error_t sm2_rev_internal_validate_vote_count(
    size_t vote_count)
{
    return (vote_count > 0 && vote_count <= SM2_REV_QUORUM_MAX_VOTES)
        ? SM2_IC_SUCCESS
        : SM2_IC_ERR_PARAM;
}

sm2_ic_error_t sm2_rev_internal_snapshot_create(
    const sm2_rev_ctx_t *src, sm2_rev_ctx_t *snapshot);
void sm2_rev_internal_snapshot_release(sm2_rev_ctx_t *snapshot);
void sm2_rev_internal_snapshot_restore(
    sm2_rev_ctx_t *dst, sm2_rev_ctx_t *snapshot);

sm2_ic_error_t sm2_rev_internal_prepare_root_publication(
    const sm2_rev_ctx_t *ctx, uint64_t now_ts, sm2_rev_sync_sign_fn sign_fn,
    void *sign_user_ctx, const uint8_t *authority_id, size_t authority_id_len,
    sm2_rev_tree_t **tree, sm2_rev_root_record_t *root_record,
    uint64_t *root_valid_until);
void sm2_rev_internal_set_root_valid_until(
    sm2_rev_ctx_t *ctx, uint64_t root_valid_until);

sm2_ic_error_t sm2_rev_tree_build(sm2_rev_tree_t **tree,
    const uint64_t *revoked_serials, size_t revoked_count,
    uint64_t root_version);
void sm2_rev_tree_cleanup(sm2_rev_tree_t **tree);
size_t sm2_rev_tree_leaf_count(const sm2_rev_tree_t *tree);
uint64_t sm2_rev_tree_root_version(const sm2_rev_tree_t *tree);
sm2_ic_error_t sm2_rev_tree_get_root_hash(
    const sm2_rev_tree_t *tree, uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN]);

sm2_ic_error_t sm2_rev_tree_prove_member(const sm2_rev_tree_t *tree,
    uint64_t serial_number, sm2_rev_member_proof_t *proof);
sm2_ic_error_t sm2_rev_tree_verify_member(
    const uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN],
    const sm2_rev_member_proof_t *proof);

sm2_ic_error_t sm2_rev_tree_prove_absence(const sm2_rev_tree_t *tree,
    uint64_t serial_number, sm2_rev_absence_proof_t *proof);
sm2_ic_error_t sm2_rev_tree_verify_absence(
    const uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN],
    const sm2_rev_absence_proof_t *proof);

sm2_ic_error_t sm2_rev_member_proof_encode(
    const sm2_rev_member_proof_t *proof, uint8_t *output, size_t *output_len);
sm2_ic_error_t sm2_rev_member_proof_decode(
    sm2_rev_member_proof_t *proof, const uint8_t *input, size_t input_len);

sm2_ic_error_t sm2_rev_absence_proof_encode(
    const sm2_rev_absence_proof_t *proof, uint8_t *output, size_t *output_len);
sm2_ic_error_t sm2_rev_absence_proof_decode(
    sm2_rev_absence_proof_t *proof, const uint8_t *input, size_t input_len);

sm2_ic_error_t sm2_rev_root_sign_with_authority(const sm2_rev_tree_t *tree,
    const uint8_t *authority_id, size_t authority_id_len, uint64_t valid_from,
    uint64_t valid_until, sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx,
    sm2_rev_root_record_t *root_record);
sm2_ic_error_t sm2_rev_root_verify(const sm2_rev_root_record_t *root_record,
    uint64_t now_ts, sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx);

sm2_ic_error_t sm2_rev_member_proof_verify_with_root(
    const sm2_rev_root_record_t *root_record, uint64_t now_ts,
    const sm2_rev_member_proof_t *proof, sm2_rev_sync_verify_fn verify_fn,
    void *verify_user_ctx);
sm2_ic_error_t sm2_rev_absence_proof_verify_with_root(
    const sm2_rev_root_record_t *root_record, uint64_t now_ts,
    const sm2_rev_absence_proof_t *proof, sm2_rev_sync_verify_fn verify_fn,
    void *verify_user_ctx);

sm2_ic_error_t sm2_rev_root_encode(const sm2_rev_root_record_t *root_record,
    uint8_t *output, size_t *output_len);
sm2_ic_error_t sm2_rev_root_decode(
    sm2_rev_root_record_t *root_record, const uint8_t *input, size_t input_len);

void sm2_rev_multi_proof_cleanup(sm2_rev_multi_proof_t **proof);
sm2_ic_error_t sm2_rev_multi_proof_build(const sm2_rev_tree_t *tree,
    const uint64_t *serial_numbers, size_t serial_count,
    sm2_rev_multi_proof_t **proof);
sm2_ic_error_t sm2_rev_multi_proof_verify(
    const uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN],
    const sm2_rev_multi_proof_t *proof);
sm2_ic_error_t sm2_rev_multi_proof_verify_with_root(
    const sm2_rev_root_record_t *root_record, uint64_t now_ts,
    const sm2_rev_multi_proof_t *proof, sm2_rev_sync_verify_fn verify_fn,
    void *verify_user_ctx);
sm2_ic_error_t sm2_rev_multi_proof_encode(
    const sm2_rev_multi_proof_t *proof, uint8_t *output, size_t *output_len);
sm2_ic_error_t sm2_rev_multi_proof_decode(
    sm2_rev_multi_proof_t **proof, const uint8_t *input, size_t input_len);
size_t sm2_rev_multi_proof_query_count(const sm2_rev_multi_proof_t *proof);
size_t sm2_rev_multi_proof_unique_hash_count(
    const sm2_rev_multi_proof_t *proof);

void sm2_rev_epoch_dir_cleanup(sm2_rev_epoch_dir_t **directory);
sm2_ic_error_t sm2_rev_epoch_dir_build_with_authority(
    const sm2_rev_tree_t *tree, uint64_t epoch_id, const uint8_t *authority_id,
    size_t authority_id_len, uint64_t valid_from, uint64_t valid_until,
    sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx,
    sm2_rev_epoch_dir_t **directory);
sm2_ic_error_t sm2_rev_epoch_dir_verify(const sm2_rev_epoch_dir_t *directory,
    uint64_t now_ts, sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx);
sm2_ic_error_t sm2_rev_epoch_apply_patch(sm2_rev_epoch_dir_t *directory,
    uint64_t patch_version, const sm2_rev_delta_item_t *items,
    size_t item_count, sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx);

sm2_ic_error_t sm2_rev_epoch_prove_member(const sm2_rev_tree_t *tree,
    uint64_t serial_number, sm2_rev_member_proof_t *proof);
sm2_ic_error_t sm2_rev_epoch_verify_member(const sm2_rev_epoch_dir_t *directory,
    uint64_t now_ts, const sm2_rev_member_proof_t *proof,
    sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx);

sm2_ic_error_t sm2_rev_epoch_lookup(const sm2_rev_epoch_dir_t *directory,
    uint64_t now_ts, uint64_t serial_number, sm2_rev_sync_verify_fn verify_fn,
    void *verify_user_ctx, sm2_rev_status_t *status);

sm2_ic_error_t sm2_rev_epoch_switch(sm2_rev_epoch_dir_t **local_directory,
    const sm2_rev_epoch_dir_t *incoming_directory, uint64_t now_ts,
    sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx);

sm2_ic_error_t sm2_rev_epoch_lookup_cb(const sm2_implicit_cert_t *cert,
    uint64_t now_ts, void *user_ctx, sm2_rev_status_t *status);

sm2_ic_error_t sm2_rev_epoch_dir_encode(
    const sm2_rev_epoch_dir_t *directory, uint8_t *output, size_t *output_len);
sm2_ic_error_t sm2_rev_epoch_dir_decode(
    sm2_rev_epoch_dir_t **directory, const uint8_t *input, size_t input_len);
size_t sm2_rev_epoch_dir_tree_level_count(const sm2_rev_epoch_dir_t *directory);
uint64_t sm2_rev_epoch_dir_patch_version(const sm2_rev_epoch_dir_t *directory);
sm2_ic_error_t sm2_rev_epoch_dir_get_root_record(
    const sm2_rev_epoch_dir_t *directory, sm2_rev_root_record_t *root_record);

#endif
