/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file revoke_internal.h
 * @brief Internal helpers shared by split revocation implementation files.
 */

#ifndef SM2_REVOKE_INTERNAL_H
#define SM2_REVOKE_INTERNAL_H

#include "sm2_revocation.h"

struct sm2_rev_ctx_st
{
    uint64_t *revoked_serials;
    size_t revoked_count;
    size_t revoked_capacity;
    sm2_rev_tree_t *rev_tree;

    sm2_rev_lookup_fn merkle_query_fn;
    void *merkle_query_user_ctx;

    uint64_t crl_version;
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

#endif
