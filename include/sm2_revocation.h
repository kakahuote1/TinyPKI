/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_revocation.h
 * @brief Revocation management interfaces (Merkle-only path, CA-signed root
 * record + delta/heartbeat patch synchronization).
 */

#ifndef SM2_REVOCATION_H
#define SM2_REVOCATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "sm2_implicit_cert.h"
#include "sm2_revocation_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct sm2_rev_tree_st sm2_rev_tree_t;

    typedef enum
    {
        SM2_REV_CONGESTION_NORMAL = 0x00,
        SM2_REV_CONGESTION_BUSY = 0x01,
        SM2_REV_CONGESTION_OVERLOAD = 0x02
    } sm2_rev_congestion_signal_t;

#define SM2_REV_TRUST_HOP_COUNT 6

    typedef enum
    {
        SM2_REV_TRUST_HOP_CA_TO_NODE = 0,
        SM2_REV_TRUST_HOP_NODE_SYNC = 1,
        SM2_REV_TRUST_HOP_NODE_RESPONSE = 2,
        SM2_REV_TRUST_HOP_DEVICE_VERIFY = 3,
        SM2_REV_TRUST_HOP_FALLBACK_PATH = 4,
        SM2_REV_TRUST_HOP_TIME_WINDOW = 5
    } sm2_rev_trust_hop_t;
    typedef sm2_ic_error_t (*sm2_rev_lookup_fn)(const sm2_implicit_cert_t *cert,
        uint64_t now_ts, void *user_ctx, sm2_rev_status_t *status);

    typedef struct
    {
        uint64_t serial_number;
        bool revoked;
    } sm2_rev_delta_item_t;

    typedef struct
    {
        uint64_t base_version;
        uint64_t new_version;
        const sm2_rev_delta_item_t *items;
        size_t item_count;
    } sm2_rev_delta_t;
#define SM2_REV_SYNC_NODE_ID_MAX_LEN 32
#define SM2_REV_SYNC_DIGEST_LEN 32
#define SM2_REV_SYNC_MAX_SIG_LEN 128
#define SM2_REV_MERKLE_HASH_LEN 32
#define SM2_REV_MERKLE_MAX_DEPTH 256
#define SM2_REV_MERKLE_MULTI_MAX_QUERIES 64
#define SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN 64
#define SM2_REV_REDIRECT_MAX_CANDIDATES 64
#define SM2_REV_QUORUM_MAX_VOTES 256
#define SM2_REV_SYNC_DEFAULT_T_BASE_SEC 60
#define SM2_REV_SYNC_DEFAULT_FAST_POLL_SEC 15
#define SM2_REV_SYNC_DEFAULT_MAX_BACKOFF_SEC 300
#define SM2_REV_SYNC_DEFAULT_PROPAGATION_DELAY_SEC 30

    typedef enum
    {
        SM2_REV_SYNC_OBJECT_ROOT_RECORD = 0,
        SM2_REV_SYNC_OBJECT_DELTA_PATCH = 1,
        SM2_REV_SYNC_OBJECT_HEARTBEAT_PATCH = 2
    } sm2_rev_sync_object_type_t;

    typedef enum
    {
        SM2_REV_SYNC_REASON_NONE = 0,
        SM2_REV_SYNC_REASON_STALE = 1,
        SM2_REV_SYNC_REASON_ROLLBACK = 2,
        SM2_REV_SYNC_REASON_FORK = 3,
        SM2_REV_SYNC_REASON_BAD_SIGNATURE = 4,
        SM2_REV_SYNC_REASON_UNREACHABLE = 5,
        SM2_REV_SYNC_REASON_REDIRECT = 6
    } sm2_rev_sync_error_reason_t;

    typedef enum
    {
        SM2_REV_FRESHNESS_FRESH = 0,
        SM2_REV_FRESHNESS_STALE = 1,
        SM2_REV_FRESHNESS_EXPIRED = 2
    } sm2_rev_sync_freshness_t;

    typedef enum
    {
        SM2_REV_DELTA_DIR_NONE = 0,
        SM2_REV_DELTA_DIR_PULL = 1,
        SM2_REV_DELTA_DIR_PUSH = 2
    } sm2_rev_delta_direction_t;

    typedef struct
    {
        uint8_t node_id[SM2_REV_SYNC_NODE_ID_MAX_LEN];
        size_t node_id_len;
        uint64_t root_version;
        uint8_t root_hash[SM2_REV_SYNC_DIGEST_LEN];
        uint64_t root_valid_until;
        uint64_t local_now_ts;
        sm2_rev_congestion_signal_t congestion_signal;
        sm2_rev_sync_freshness_t freshness;
    } sm2_rev_sync_hello_t;

    typedef struct
    {
        uint8_t node_id[SM2_REV_SYNC_NODE_ID_MAX_LEN];
        size_t node_id_len;
        uint32_t base_weight;
        sm2_rev_congestion_signal_t congestion_signal;
        uint32_t fail_streak;
        uint64_t next_retry_ts;
        bool enabled;
    } sm2_rev_route_node_t;
    typedef struct
    {
        sm2_rev_delta_direction_t direction;
        uint64_t from_version;
        uint64_t to_version;
        bool fork_detected;
    } sm2_rev_sync_delta_plan_t;

    typedef struct
    {
        uint64_t t_base_sec;
        uint64_t fast_poll_sec;
        uint64_t max_backoff_sec;
        uint64_t propagation_delay_sec;
    } sm2_rev_sync_policy_t;

    typedef struct
    {
        uint64_t next_pull_after_sec;
        uint64_t staleness_upper_bound_sec;
        bool accelerated_mode;
        bool heartbeat_refresh_only;
    } sm2_rev_sync_schedule_t;

    typedef struct
    {
        uint64_t prev_version;
        uint64_t new_version;
        uint8_t prev_root_hash[SM2_REV_SYNC_DIGEST_LEN];
        uint8_t new_root_hash[SM2_REV_SYNC_DIGEST_LEN];
        uint64_t issued_at;
        uint64_t valid_until;
    } sm2_rev_patch_link_t;

    typedef struct
    {
        sm2_rev_sync_object_type_t object_type;
        uint64_t base_version;
        uint64_t new_version;
        uint8_t root_hash[SM2_REV_SYNC_DIGEST_LEN];
        uint64_t issued_at;
        uint64_t valid_until;
    } sm2_rev_heartbeat_patch_t;

    typedef enum
    {
        SM2_REV_REDIRECT_REASON_NONE = 0,
        SM2_REV_REDIRECT_REASON_EXPIRED = 1,
        SM2_REV_REDIRECT_REASON_VERSION_STALE = 2,
        SM2_REV_REDIRECT_REASON_NO_HEALTHY_NODE = 3
    } sm2_rev_redirect_reason_t;

    typedef struct
    {
        sm2_rev_route_node_t route;
        uint64_t root_version;
        uint64_t root_valid_until;
        uint32_t rtt_ms;
    } sm2_rev_node_health_sample_t;

    typedef struct
    {
        uint8_t node_id[SM2_REV_SYNC_NODE_ID_MAX_LEN];
        size_t node_id_len;
        uint64_t root_version;
        uint64_t root_valid_until;
        uint32_t rtt_ms;
        uint16_t health_score;
        sm2_rev_congestion_signal_t congestion_signal;
    } sm2_rev_redirect_candidate_t;

    typedef struct
    {
        bool redirect_required;
        sm2_rev_redirect_reason_t reason;
        sm2_rev_sync_freshness_t freshness;
        uint64_t local_version;
        uint64_t known_latest_version;
        uint64_t now_ts;
        size_t candidate_count;
    } sm2_rev_redirect_response_t;

    typedef struct
    {
        uint8_t node_id[SM2_REV_SYNC_NODE_ID_MAX_LEN];
        size_t node_id_len;
    } sm2_rev_trusted_node_t;

    typedef struct
    {
        bool ca_to_node_ok;
        bool node_sync_ok;
        bool node_response_ok;
        bool device_verify_ok;
        bool fallback_ok;
        uint64_t local_version;
        uint64_t remote_version;
        int64_t clock_skew_sec;
        uint64_t clock_tolerance_sec;
    } sm2_rev_trust_matrix_input_t;

    typedef struct
    {
        bool hop_pass[SM2_REV_TRUST_HOP_COUNT];
        bool overall_pass;
        uint32_t fail_mask;
    } sm2_rev_trust_matrix_result_t;

    typedef struct
    {
        uint64_t serial_number;
        uint8_t key[SM2_REV_MERKLE_HASH_LEN];
        size_t sibling_count;
        uint16_t sibling_depths[SM2_REV_MERKLE_MAX_DEPTH];
        uint8_t sibling_hashes[SM2_REV_MERKLE_MAX_DEPTH]
                              [SM2_REV_MERKLE_HASH_LEN];
        uint8_t sibling_on_left[SM2_REV_MERKLE_MAX_DEPTH];
    } sm2_rev_member_proof_t;

    typedef struct
    {
        uint64_t target_serial;
        uint8_t target_key[SM2_REV_MERKLE_HASH_LEN];
        bool tree_empty;
        size_t sibling_count;
        uint16_t sibling_depths[SM2_REV_MERKLE_MAX_DEPTH];
        uint8_t sibling_hashes[SM2_REV_MERKLE_MAX_DEPTH]
                              [SM2_REV_MERKLE_HASH_LEN];
        uint8_t sibling_on_left[SM2_REV_MERKLE_MAX_DEPTH];
    } sm2_rev_absence_proof_t;

    typedef struct
    {
        uint8_t authority_id[SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN];
        size_t authority_id_len;
        uint64_t root_version;
        uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];
        uint64_t valid_from;
        uint64_t valid_until;
        uint8_t signature[SM2_REV_SYNC_MAX_SIG_LEN];
        size_t signature_len;
    } sm2_rev_root_record_t;

    typedef struct
    {
        uint64_t serial_number;
        uint8_t key[SM2_REV_MERKLE_HASH_LEN];
        size_t sibling_count;
        uint16_t sibling_depths[SM2_REV_MERKLE_MAX_DEPTH];
        uint16_t sibling_ref[SM2_REV_MERKLE_MAX_DEPTH];
        uint8_t sibling_on_left[SM2_REV_MERKLE_MAX_DEPTH];
    } sm2_rev_multi_item_t;

    typedef struct sm2_rev_multi_proof_st sm2_rev_multi_proof_t;

    typedef struct sm2_rev_epoch_dir_st sm2_rev_epoch_dir_t;

    typedef struct
    {
        const sm2_rev_epoch_dir_t *directory;
        sm2_ic_error_t (*verify_fn)(void *user_ctx, const uint8_t *data,
            size_t data_len, const uint8_t *signature, size_t signature_len);
        void *verify_user_ctx;
    } sm2_rev_lookup_ctx_t;

    typedef struct
    {
        uint8_t node_id[SM2_REV_SYNC_NODE_ID_MAX_LEN];
        size_t node_id_len;
        uint64_t root_version;
        uint8_t root_hash[SM2_REV_SYNC_DIGEST_LEN];
        sm2_rev_status_t status;
        bool proof_valid;
    } sm2_rev_quorum_vote_t;

    typedef struct
    {
        uint64_t selected_root_version;
        uint8_t selected_root_hash[SM2_REV_SYNC_DIGEST_LEN];
        size_t unique_node_count;
        size_t valid_vote_count;
        size_t stale_vote_count;
        size_t conflict_vote_count;
        size_t good_votes;
        size_t revoked_votes;
        size_t unknown_votes;
        size_t threshold;
        bool quorum_met;
        sm2_rev_status_t decided_status;
    } sm2_rev_quorum_result_t;

    typedef struct
    {
        const sm2_rev_quorum_vote_t *votes;
        const sm2_rev_trust_matrix_input_t *trust_inputs;
        size_t vote_count;
        size_t threshold;
        uint64_t local_version;
        const uint8_t *local_root_hash;
        const sm2_rev_patch_link_t *patch;
        bool patch_ca_verified;
        uint64_t now_ts;
        uint64_t skew_tolerance_sec;
    } sm2_rev_bft_quorum_input_t;

    typedef struct
    {
        bool patch_verified;
        bool fork_detected;
        bool quorum_evaluated;
        bool quorum_met;
        bool live_honest_node_assumed;
        size_t trusted_vote_count;
        size_t rejected_vote_count;
        sm2_rev_quorum_result_t quorum_result;
    } sm2_rev_bft_quorum_result_t;

    typedef sm2_ic_error_t (*sm2_rev_sync_sign_fn)(void *user_ctx,
        const uint8_t *data, size_t data_len, uint8_t *signature,
        size_t *signature_len);

    typedef sm2_ic_error_t (*sm2_rev_sync_verify_fn)(void *user_ctx,
        const uint8_t *data, size_t data_len, const uint8_t *signature,
        size_t signature_len);
    sm2_ic_error_t sm2_rev_init(sm2_rev_ctx_t **ctx,
        size_t expected_revoked_items, uint64_t filter_ttl_sec,
        uint64_t now_ts);
    void sm2_rev_cleanup(sm2_rev_ctx_t **ctx);

    /*
     * Optional remote lookup hook. When configured, sm2_rev_query() will use
     * it as the authoritative status source. When unset, sm2_rev_query()
     * falls back to local revocation state in ctx.
     */
    sm2_ic_error_t sm2_rev_set_lookup(
        sm2_rev_ctx_t *ctx, sm2_rev_lookup_fn query_fn, void *user_ctx);

    sm2_ic_error_t sm2_rev_apply_delta(
        sm2_rev_ctx_t *ctx, const sm2_rev_delta_t *delta, uint64_t now_ts);

    /*
     * Queries revocation status from the current revocation context.
     * - If a lookup hook is configured, the hook result is returned.
     * - Otherwise local state is used while the local root is still fresh.
     * - If neither source can provide a trustworthy answer, status is UNKNOWN.
     */
    sm2_ic_error_t sm2_rev_query(sm2_rev_ctx_t *ctx, uint64_t serial_number,
        uint64_t now_ts, sm2_rev_status_t *status, sm2_rev_source_t *source);

    size_t sm2_rev_local_count(const sm2_rev_ctx_t *ctx);
    uint64_t sm2_rev_version(const sm2_rev_ctx_t *ctx);
    uint64_t sm2_rev_root_valid_until(const sm2_rev_ctx_t *ctx);
    sm2_ic_error_t sm2_rev_root_hash(
        const sm2_rev_ctx_t *ctx, uint8_t root_hash[SM2_REV_SYNC_DIGEST_LEN]);

    sm2_ic_error_t sm2_rev_set_congestion_limits(
        sm2_rev_ctx_t *ctx, size_t busy_threshold, size_t overload_threshold);
    sm2_ic_error_t sm2_rev_set_query_inflight(
        sm2_rev_ctx_t *ctx, size_t query_inflight);
    sm2_rev_congestion_signal_t sm2_rev_get_congestion_signal(
        const sm2_rev_ctx_t *ctx);

    sm2_ic_error_t sm2_rev_set_clock_skew_tolerance(
        sm2_rev_ctx_t *ctx, uint64_t tolerance_sec);

    sm2_ic_error_t sm2_rev_check_freshness(const sm2_rev_ctx_t *ctx,
        uint64_t now_ts, uint64_t skew_tolerance_sec,
        sm2_rev_sync_freshness_t *freshness);

    sm2_ic_error_t sm2_rev_sync_policy_init(sm2_rev_sync_policy_t *policy);

    sm2_ic_error_t sm2_rev_sync_staleness_bound(
        const sm2_rev_sync_policy_t *policy, uint64_t clock_skew_sec,
        uint64_t *upper_bound_sec);

    sm2_ic_error_t sm2_rev_sync_plan_schedule(const sm2_rev_ctx_t *ctx,
        const sm2_rev_sync_policy_t *policy, uint64_t known_latest_version,
        uint32_t fail_streak, uint64_t now_ts,
        sm2_rev_sync_schedule_t *schedule);

    sm2_ic_error_t sm2_rev_sync_build_hello(const sm2_rev_ctx_t *ctx,
        const uint8_t *node_id, size_t node_id_len, uint64_t now_ts,
        sm2_rev_sync_hello_t *hello);

    sm2_ic_error_t sm2_rev_sync_plan_delta(
        const sm2_rev_sync_hello_t *local_hello,
        const sm2_rev_sync_hello_t *remote_hello,
        sm2_rev_sync_delta_plan_t *plan);

    sm2_ic_error_t sm2_rev_sync_should_redirect(const sm2_rev_ctx_t *ctx,
        uint64_t known_latest_version, uint64_t max_version_lag,
        uint64_t now_ts, uint64_t skew_tolerance_sec, bool *redirect_required,
        sm2_rev_sync_freshness_t *freshness);

    sm2_ic_error_t sm2_rev_sync_verify_patch_link(
        const sm2_rev_patch_link_t *patch, uint64_t local_version,
        const uint8_t local_root_hash[SM2_REV_SYNC_DIGEST_LEN], uint64_t now_ts,
        uint64_t skew_tolerance_sec);

    sm2_ic_error_t sm2_rev_sync_build_heartbeat(uint64_t local_version,
        const uint8_t root_hash[SM2_REV_SYNC_DIGEST_LEN], uint64_t issued_at,
        uint64_t valid_until, sm2_rev_heartbeat_patch_t *patch);

    sm2_ic_error_t sm2_rev_sync_verify_heartbeat(
        const sm2_rev_heartbeat_patch_t *patch, uint64_t local_version,
        const uint8_t local_root_hash[SM2_REV_SYNC_DIGEST_LEN], uint64_t now_ts,
        uint64_t skew_tolerance_sec);

    sm2_ic_error_t sm2_rev_sync_apply_heartbeat(sm2_rev_ctx_t *ctx,
        const sm2_rev_heartbeat_patch_t *patch, uint64_t now_ts);

    sm2_ic_error_t sm2_rev_sync_apply_delta(sm2_rev_ctx_t *ctx,
        const sm2_rev_sync_delta_plan_t *plan, const sm2_rev_delta_t *delta,
        uint64_t now_ts, bool *converged);

    sm2_ic_error_t sm2_rev_route_rank_candidates(
        const sm2_rev_node_health_sample_t *samples, size_t sample_count,
        uint64_t min_root_version, uint64_t now_ts, uint64_t skew_tolerance_sec,
        size_t max_candidates, sm2_rev_redirect_candidate_t *candidates,
        size_t *candidate_count);

    sm2_ic_error_t sm2_rev_route_build_response(const sm2_rev_ctx_t *ctx,
        uint64_t known_latest_version, uint64_t max_version_lag,
        uint64_t now_ts, uint64_t skew_tolerance_sec,
        const sm2_rev_node_health_sample_t *samples, size_t sample_count,
        size_t max_candidates, sm2_rev_redirect_response_t *response,
        sm2_rev_redirect_candidate_t *candidates, size_t *candidate_count);

    sm2_ic_error_t sm2_rev_route_pick_candidate(
        const sm2_rev_redirect_response_t *response,
        const sm2_rev_redirect_candidate_t *candidates, size_t candidate_count,
        const sm2_rev_route_node_t *route_nodes, size_t route_node_count,
        uint64_t now_ts, uint64_t random_nonce, size_t *selected_index);

    sm2_ic_error_t sm2_rev_route_record_result(
        sm2_rev_route_node_t *route_nodes, size_t route_node_count,
        const sm2_rev_redirect_candidate_t *selected_candidate, bool success,
        uint64_t now_ts, uint64_t base_backoff_sec, uint64_t max_backoff_sec);

    sm2_ic_error_t sm2_rev_route_verify_metadata(
        const sm2_rev_redirect_response_t *response,
        const sm2_rev_redirect_candidate_t *candidates, size_t candidate_count,
        const sm2_rev_trusted_node_t *trusted_nodes, size_t trusted_node_count,
        const uint8_t *signature, size_t signature_len,
        sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx);

    sm2_ic_error_t sm2_rev_route_pick_node(const sm2_rev_route_node_t *nodes,
        size_t node_count, uint64_t now_ts, uint64_t random_nonce,
        size_t *selected_index);
    sm2_ic_error_t sm2_rev_route_record_feedback(sm2_rev_route_node_t *node,
        bool success, uint64_t now_ts, uint64_t base_backoff_sec,
        uint64_t max_backoff_sec);

    sm2_ic_error_t sm2_rev_trust_evaluate(
        const sm2_rev_trust_matrix_input_t *input,
        sm2_rev_trust_matrix_result_t *result);

    sm2_ic_error_t sm2_rev_quorum_check(const sm2_rev_quorum_vote_t *votes,
        size_t vote_count, size_t threshold, sm2_rev_quorum_result_t *result);

    sm2_ic_error_t sm2_rev_bft_check(const sm2_rev_bft_quorum_input_t *input,
        sm2_rev_bft_quorum_result_t *result);

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
        const sm2_rev_member_proof_t *proof, uint8_t *output,
        size_t *output_len);
    sm2_ic_error_t sm2_rev_member_proof_decode(
        sm2_rev_member_proof_t *proof, const uint8_t *input, size_t input_len);

    sm2_ic_error_t sm2_rev_absence_proof_encode(
        const sm2_rev_absence_proof_t *proof, uint8_t *output,
        size_t *output_len);
    sm2_ic_error_t sm2_rev_absence_proof_decode(
        sm2_rev_absence_proof_t *proof, const uint8_t *input, size_t input_len);

    sm2_ic_error_t sm2_rev_root_sign_with_authority(const sm2_rev_tree_t *tree,
        const uint8_t *authority_id, size_t authority_id_len,
        uint64_t valid_from, uint64_t valid_until, sm2_rev_sync_sign_fn sign_fn,
        void *sign_user_ctx, sm2_rev_root_record_t *root_record);
    sm2_ic_error_t sm2_rev_root_sign(const sm2_rev_tree_t *tree,
        uint64_t valid_from, uint64_t valid_until, sm2_rev_sync_sign_fn sign_fn,
        void *sign_user_ctx, sm2_rev_root_record_t *root_record);
    sm2_ic_error_t sm2_rev_root_verify(const sm2_rev_root_record_t *root_record,
        uint64_t now_ts, sm2_rev_sync_verify_fn verify_fn,
        void *verify_user_ctx);

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
    sm2_ic_error_t sm2_rev_root_decode(sm2_rev_root_record_t *root_record,
        const uint8_t *input, size_t input_len);

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
        const sm2_rev_multi_proof_t *proof, uint8_t *output,
        size_t *output_len);
    sm2_ic_error_t sm2_rev_multi_proof_decode(
        sm2_rev_multi_proof_t **proof, const uint8_t *input, size_t input_len);
    size_t sm2_rev_multi_proof_query_count(const sm2_rev_multi_proof_t *proof);
    size_t sm2_rev_multi_proof_unique_hash_count(
        const sm2_rev_multi_proof_t *proof);

    void sm2_rev_epoch_dir_cleanup(sm2_rev_epoch_dir_t **directory);
    sm2_ic_error_t sm2_rev_epoch_dir_build_with_authority(
        const sm2_rev_tree_t *tree, uint64_t epoch_id,
        const uint8_t *authority_id, size_t authority_id_len,
        uint64_t valid_from, uint64_t valid_until, sm2_rev_sync_sign_fn sign_fn,
        void *sign_user_ctx, sm2_rev_epoch_dir_t **directory);
    sm2_ic_error_t sm2_rev_epoch_dir_build(const sm2_rev_tree_t *tree,
        uint64_t epoch_id, uint64_t valid_from, uint64_t valid_until,
        sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx,
        sm2_rev_epoch_dir_t **directory);
    sm2_ic_error_t sm2_rev_epoch_dir_verify(
        const sm2_rev_epoch_dir_t *directory, uint64_t now_ts,
        sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx);
    sm2_ic_error_t sm2_rev_epoch_apply_patch(sm2_rev_epoch_dir_t *directory,
        uint64_t patch_version, const sm2_rev_delta_item_t *items,
        size_t item_count, sm2_rev_sync_sign_fn sign_fn, void *sign_user_ctx);

    sm2_ic_error_t sm2_rev_epoch_prove_member(const sm2_rev_tree_t *tree,
        uint64_t serial_number, sm2_rev_member_proof_t *proof);
    sm2_ic_error_t sm2_rev_epoch_verify_member(
        const sm2_rev_epoch_dir_t *directory, uint64_t now_ts,
        const sm2_rev_member_proof_t *proof, sm2_rev_sync_verify_fn verify_fn,
        void *verify_user_ctx);

    sm2_ic_error_t sm2_rev_epoch_lookup(const sm2_rev_epoch_dir_t *directory,
        uint64_t now_ts, uint64_t serial_number,
        sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx,
        sm2_rev_status_t *status);

    sm2_ic_error_t sm2_rev_epoch_switch(sm2_rev_epoch_dir_t **local_directory,
        const sm2_rev_epoch_dir_t *incoming_directory, uint64_t now_ts,
        sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx);

    sm2_ic_error_t sm2_rev_epoch_lookup_cb(const sm2_implicit_cert_t *cert,
        uint64_t now_ts, void *user_ctx, sm2_rev_status_t *status);

    sm2_ic_error_t sm2_rev_epoch_dir_encode(
        const sm2_rev_epoch_dir_t *directory, uint8_t *output,
        size_t *output_len);
    sm2_ic_error_t sm2_rev_epoch_dir_decode(sm2_rev_epoch_dir_t **directory,
        const uint8_t *input, size_t input_len);
    size_t sm2_rev_epoch_dir_tree_level_count(
        const sm2_rev_epoch_dir_t *directory);
    uint64_t sm2_rev_epoch_dir_patch_version(
        const sm2_rev_epoch_dir_t *directory);
    sm2_ic_error_t sm2_rev_epoch_dir_get_root_record(
        const sm2_rev_epoch_dir_t *directory,
        sm2_rev_root_record_t *root_record);

#ifdef __cplusplus
}
#endif

#endif /* SM2_REVOCATION_H */
