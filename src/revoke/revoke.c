/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file revoke.c
 * @brief Revocation state management for Merkle-only query path.
 */

#include "merkle_internal.h"
#include "revoke_internal.h"
#include "sm2_secure_mem.h"

#include <stdlib.h>
#include <string.h>

static sm2_rev_congestion_signal_t calc_congestion_signal(
    const sm2_rev_ctx_t *ctx)
{
    if (!ctx)
        return SM2_REV_CONGESTION_NORMAL;

    size_t busy = ctx->congestion_busy_threshold;
    size_t overload = ctx->congestion_overload_threshold;
    if (busy == 0)
        busy = 64;
    if (overload <= busy)
        overload = busy + 1;

    if (ctx->query_inflight >= overload)
        return SM2_REV_CONGESTION_OVERLOAD;
    if (ctx->query_inflight >= busy)
        return SM2_REV_CONGESTION_BUSY;
    return SM2_REV_CONGESTION_NORMAL;
}

static sm2_ic_error_t local_list_reserve(
    sm2_rev_ctx_t *ctx, size_t target_count)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;
    if (target_count <= ctx->revoked_capacity)
        return SM2_IC_SUCCESS;

    size_t new_cap = ctx->revoked_capacity == 0 ? 64 : ctx->revoked_capacity;
    while (new_cap < target_count)
    {
        if (new_cap > SIZE_MAX / 2)
            return SM2_IC_ERR_MEMORY;
        new_cap *= 2;
    }

    uint64_t *new_list
        = (uint64_t *)realloc(ctx->revoked_serials, new_cap * sizeof(uint64_t));
    if (!new_list)
        return SM2_IC_ERR_MEMORY;

    ctx->revoked_serials = new_list;
    ctx->revoked_capacity = new_cap;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t local_list_add(sm2_rev_ctx_t *ctx, uint64_t serial)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;

    for (size_t i = 0; i < ctx->revoked_count; i++)
    {
        if (ctx->revoked_serials[i] == serial)
            return SM2_IC_SUCCESS;
    }

    sm2_ic_error_t ret = local_list_reserve(ctx, ctx->revoked_count + 1);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ctx->revoked_serials[ctx->revoked_count++] = serial;
    return SM2_IC_SUCCESS;
}

static void local_list_remove(sm2_rev_ctx_t *ctx, uint64_t serial)
{
    if (!ctx)
        return;

    for (size_t i = 0; i < ctx->revoked_count; i++)
    {
        if (ctx->revoked_serials[i] == serial)
        {
            if (i + 1 < ctx->revoked_count)
            {
                memmove(&ctx->revoked_serials[i], &ctx->revoked_serials[i + 1],
                    (ctx->revoked_count - i - 1) * sizeof(uint64_t));
            }
            ctx->revoked_count--;
            return;
        }
    }
}

static bool local_list_contains(const sm2_rev_ctx_t *ctx, uint64_t serial)
{
    if (!ctx)
        return false;

    for (size_t i = 0; i < ctx->revoked_count; i++)
    {
        if (ctx->revoked_serials[i] == serial)
            return true;
    }
    return false;
}

static void rev_local_list_release(uint64_t **revoked_serials)
{
    if (!revoked_serials || !*revoked_serials)
        return;

    free(*revoked_serials);
    *revoked_serials = NULL;
}

static sm2_ic_error_t rev_ctx_clone_local_state(
    const sm2_rev_ctx_t *src, sm2_rev_ctx_t *dst)
{
    if (!src || !dst)
        return SM2_IC_ERR_PARAM;

    memset(dst, 0, sizeof(*dst));
    *dst = *src;
    dst->revoked_serials = NULL;
    dst->revoked_count = 0;
    dst->revoked_capacity = 0;
    dst->rev_tree = NULL;

    if (src->revoked_count > 0
        && (!src->revoked_serials
            || src->revoked_capacity < src->revoked_count))
    {
        return SM2_IC_ERR_VERIFY;
    }
    if (src->revoked_capacity > SIZE_MAX / sizeof(uint64_t))
        return SM2_IC_ERR_MEMORY;

    if (src->revoked_capacity > 0)
    {
        dst->revoked_serials
            = (uint64_t *)calloc(src->revoked_capacity, sizeof(uint64_t));
        if (!dst->revoked_serials)
            return SM2_IC_ERR_MEMORY;

        memcpy(dst->revoked_serials, src->revoked_serials,
            src->revoked_count * sizeof(uint64_t));
        dst->revoked_count = src->revoked_count;
        dst->revoked_capacity = src->revoked_capacity;
    }

    return sm2_rev_tree_build(&dst->rev_tree, dst->revoked_serials,
        dst->revoked_count, dst->crl_version);
}

static uint64_t rev_ctx_compute_valid_until(
    const sm2_rev_ctx_t *ctx, uint64_t now_ts)
{
    if (!ctx)
        return now_ts;
    if (ctx->root_valid_ttl_sec <= UINT64_MAX - now_ts)
        return now_ts + ctx->root_valid_ttl_sec;
    return UINT64_MAX;
}

static sm2_ic_error_t query_merkle_callback(sm2_rev_ctx_t *ctx,
    uint64_t serial_number, uint64_t now_ts, sm2_rev_status_t *status,
    sm2_rev_source_t *source)
{
    if (!ctx || !ctx->merkle_query_fn || !status || !source)
        return SM2_IC_ERR_PARAM;

    sm2_implicit_cert_t cert;
    memset(&cert, 0, sizeof(cert));
    cert.serial_number = serial_number;

    sm2_ic_error_t ret = ctx->merkle_query_fn(
        &cert, now_ts, ctx->merkle_query_user_ctx, status);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (*status != SM2_REV_STATUS_GOOD && *status != SM2_REV_STATUS_REVOKED
        && *status != SM2_REV_STATUS_UNKNOWN)
    {
        return SM2_IC_ERR_VERIFY;
    }

    *source = SM2_REV_SOURCE_MERKLE_NODE;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t query_local_state(const sm2_rev_ctx_t *ctx,
    uint64_t serial_number, uint64_t now_ts, sm2_rev_status_t *status,
    sm2_rev_source_t *source)
{
    if (!ctx || !status || !source)
        return SM2_IC_ERR_PARAM;

    if (now_ts > ctx->root_valid_until)
    {
        *status = SM2_REV_STATUS_UNKNOWN;
        *source = SM2_REV_SOURCE_NONE;
        return SM2_IC_SUCCESS;
    }

    *status = local_list_contains(ctx, serial_number) ? SM2_REV_STATUS_REVOKED
                                                      : SM2_REV_STATUS_GOOD;
    *source = SM2_REV_SOURCE_LOCAL_STATE;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t rev_ctx_refresh_root_hash(sm2_rev_ctx_t *ctx)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;

    if (!ctx->rev_tree)
    {
        sm2_ic_error_t ret = sm2_rev_tree_build(&ctx->rev_tree,
            ctx->revoked_serials, ctx->revoked_count, ctx->crl_version);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    merkle_tree_set_root_version(ctx->rev_tree, ctx->crl_version);
    sm2_ic_error_t ret
        = sm2_rev_tree_get_root_hash(ctx->rev_tree, ctx->root_hash);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    return SM2_IC_SUCCESS;
}

static void rev_ctx_compute_publication_window(const sm2_rev_ctx_t *ctx,
    uint64_t now_ts, uint64_t *valid_from, uint64_t *valid_until)
{
    uint64_t ttl = 300;

    if (ctx && ctx->root_valid_ttl_sec != 0)
        ttl = ctx->root_valid_ttl_sec;

    if (valid_from)
        *valid_from = now_ts > ttl ? now_ts - ttl : 0;
    if (valid_until)
    {
        if (ttl <= UINT64_MAX - now_ts)
            *valid_until = now_ts + ttl;
        else
            *valid_until = UINT64_MAX;
    }
}

static void rev_state_reset(sm2_rev_ctx_t *ctx)
{
    if (!ctx)
        return;

    if (ctx->revoked_serials && ctx->revoked_capacity > 0)
    {
        sm2_secure_memzero(
            ctx->revoked_serials, ctx->revoked_capacity * sizeof(uint64_t));
    }

    free(ctx->revoked_serials);
    sm2_rev_tree_cleanup(&ctx->rev_tree);
    sm2_secure_memzero(ctx, sizeof(*ctx));
}

sm2_ic_error_t sm2_rev_internal_snapshot_create(
    const sm2_rev_ctx_t *src, sm2_rev_ctx_t *snapshot)
{
    return rev_ctx_clone_local_state(src, snapshot);
}

void sm2_rev_internal_snapshot_release(sm2_rev_ctx_t *snapshot)
{
    if (!snapshot)
        return;

    rev_local_list_release(&snapshot->revoked_serials);
    sm2_rev_tree_cleanup(&snapshot->rev_tree);
    memset(snapshot, 0, sizeof(*snapshot));
}

void sm2_rev_internal_snapshot_restore(
    sm2_rev_ctx_t *dst, sm2_rev_ctx_t *snapshot)
{
    if (!dst || !snapshot)
        return;

    rev_local_list_release(&dst->revoked_serials);
    sm2_rev_tree_cleanup(&dst->rev_tree);
    *dst = *snapshot;
    snapshot->revoked_serials = NULL;
    snapshot->rev_tree = NULL;
    snapshot->revoked_count = 0;
    snapshot->revoked_capacity = 0;
    memset(snapshot, 0, sizeof(*snapshot));
}

sm2_ic_error_t sm2_rev_internal_prepare_root_publication(
    const sm2_rev_ctx_t *ctx, uint64_t now_ts, sm2_rev_sync_sign_fn sign_fn,
    void *sign_user_ctx, const uint8_t *authority_id, size_t authority_id_len,
    sm2_rev_tree_t **tree, sm2_rev_root_record_t *root_record,
    uint64_t *root_valid_until)
{
    if (!ctx || !tree || !root_record || !sign_fn || !root_valid_until)
        return SM2_IC_ERR_PARAM;
    if ((!authority_id && authority_id_len > 0)
        || authority_id_len > SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN)
    {
        return SM2_IC_ERR_PARAM;
    }

    *tree = NULL;
    *root_valid_until = 0;
    memset(root_record, 0, sizeof(*root_record));

    uint64_t valid_from = 0;
    uint64_t valid_until = 0;
    rev_ctx_compute_publication_window(ctx, now_ts, &valid_from, &valid_until);

    sm2_ic_error_t ret;
    if (ctx->rev_tree)
        ret = merkle_tree_clone(ctx->rev_tree, tree);
    else
        ret = sm2_rev_tree_build(
            tree, ctx->revoked_serials, ctx->revoked_count, ctx->crl_version);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    ret = sm2_rev_root_sign_with_authority(*tree, authority_id,
        authority_id_len, valid_from, valid_until, sign_fn, sign_user_ctx,
        root_record);
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_rev_tree_cleanup(tree);
        return ret;
    }

    *root_valid_until = root_record->valid_until;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_pki_rev_sign_existing_root(const sm2_rev_ctx_t *ctx,
    const sm2_rev_tree_t *tree, uint64_t now_ts, sm2_rev_sync_sign_fn sign_fn,
    void *sign_user_ctx, const uint8_t *authority_id, size_t authority_id_len,
    sm2_rev_root_record_t *root_record, uint64_t *root_valid_until)
{
    uint64_t valid_from = 0;
    uint64_t valid_until = 0;
    uint8_t tree_root_hash[SM2_REV_SYNC_DIGEST_LEN];

    if (!ctx || !tree || !sign_fn || !root_record || !root_valid_until)
        return SM2_IC_ERR_PARAM;
    if ((!authority_id && authority_id_len > 0)
        || authority_id_len > SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN)
    {
        return SM2_IC_ERR_PARAM;
    }

    if (sm2_rev_tree_root_version(tree) != ctx->crl_version)
        return SM2_IC_ERR_VERIFY;
    if (sm2_rev_tree_get_root_hash(tree, tree_root_hash) != SM2_IC_SUCCESS)
        return SM2_IC_ERR_VERIFY;
    if (memcmp(tree_root_hash, ctx->root_hash, sizeof(tree_root_hash)) != 0)
        return SM2_IC_ERR_VERIFY;

    memset(root_record, 0, sizeof(*root_record));
    *root_valid_until = 0;
    rev_ctx_compute_publication_window(ctx, now_ts, &valid_from, &valid_until);

    sm2_ic_error_t ret
        = sm2_rev_root_sign_with_authority(tree, authority_id, authority_id_len,
            valid_from, valid_until, sign_fn, sign_user_ctx, root_record);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    *root_valid_until = root_record->valid_until;
    return SM2_IC_SUCCESS;
}

void sm2_rev_internal_set_root_valid_until(
    sm2_rev_ctx_t *ctx, uint64_t root_valid_until)
{
    if (!ctx)
        return;

    ctx->root_valid_until = root_valid_until;
}

sm2_ic_error_t sm2_rev_init(sm2_rev_ctx_t **ctx, size_t expected_revoked_items,
    uint64_t filter_ttl_sec, uint64_t now_ts)
{
    if (!ctx || filter_ttl_sec == 0)
        return SM2_IC_ERR_PARAM;
    *ctx = NULL;

    sm2_rev_ctx_t *state = (sm2_rev_ctx_t *)calloc(1, sizeof(*state));
    if (!state)
        return SM2_IC_ERR_MEMORY;

    state->root_valid_ttl_sec = filter_ttl_sec;
    state->root_valid_until = rev_ctx_compute_valid_until(state, now_ts);

    state->query_inflight = 0;
    state->congestion_busy_threshold = 64;
    state->congestion_overload_threshold = 128;
    state->congestion_signal = SM2_REV_CONGESTION_NORMAL;
    state->clock_skew_tolerance_sec = 300;

    if (expected_revoked_items > 0)
    {
        sm2_ic_error_t ret = local_list_reserve(state, expected_revoked_items);
        if (ret != SM2_IC_SUCCESS)
        {
            sm2_rev_cleanup(&state);
            return ret;
        }
    }

    sm2_ic_error_t ret = rev_ctx_refresh_root_hash(state);
    if (ret != SM2_IC_SUCCESS)
    {
        sm2_rev_cleanup(&state);
        return ret;
    }

    *ctx = state;
    return SM2_IC_SUCCESS;
}

void sm2_rev_cleanup(sm2_rev_ctx_t **ctx)
{
    if (!ctx || !*ctx)
        return;
    rev_state_reset(*ctx);
    free(*ctx);
    *ctx = NULL;
}

sm2_ic_error_t sm2_rev_set_lookup(
    sm2_rev_ctx_t *ctx, sm2_rev_lookup_fn query_fn, void *user_ctx)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;

    ctx->merkle_query_fn = query_fn;
    ctx->merkle_query_user_ctx = user_ctx;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_apply_delta(
    sm2_rev_ctx_t *ctx, const sm2_crl_delta_t *delta, uint64_t now_ts)
{
    if (!ctx || !delta)
        return SM2_IC_ERR_PARAM;
    if (delta->item_count > 0 && !delta->items)
        return SM2_IC_ERR_PARAM;
    if (delta->base_version != ctx->crl_version)
        return SM2_IC_ERR_VERIFY;
    if (delta->new_version <= delta->base_version)
        return SM2_IC_ERR_PARAM;

    sm2_rev_ctx_t scratch;
    sm2_ic_error_t ret = rev_ctx_clone_local_state(ctx, &scratch);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    for (size_t i = 0; i < delta->item_count; i++)
    {
        const sm2_crl_delta_item_t *it = &delta->items[i];
        if (it->revoked)
        {
            ret = local_list_add(&scratch, it->serial_number);
            if (ret != SM2_IC_SUCCESS)
            {
                rev_local_list_release(&scratch.revoked_serials);
                sm2_rev_tree_cleanup(&scratch.rev_tree);
                return ret;
            }
            ret = merkle_tree_update_serial(
                scratch.rev_tree, it->serial_number, true);
        }
        else
        {
            local_list_remove(&scratch, it->serial_number);
            ret = merkle_tree_update_serial(
                scratch.rev_tree, it->serial_number, false);
        }
        if (ret != SM2_IC_SUCCESS)
        {
            rev_local_list_release(&scratch.revoked_serials);
            sm2_rev_tree_cleanup(&scratch.rev_tree);
            return ret;
        }
    }

    scratch.crl_version = delta->new_version;
    merkle_tree_set_root_version(scratch.rev_tree, scratch.crl_version);
    scratch.root_valid_until = rev_ctx_compute_valid_until(&scratch, now_ts);
    ret = rev_ctx_refresh_root_hash(&scratch);
    if (ret != SM2_IC_SUCCESS)
    {
        rev_local_list_release(&scratch.revoked_serials);
        sm2_rev_tree_cleanup(&scratch.rev_tree);
        return ret;
    }

    rev_local_list_release(&ctx->revoked_serials);
    sm2_rev_tree_cleanup(&ctx->rev_tree);
    ctx->revoked_serials = scratch.revoked_serials;
    ctx->revoked_count = scratch.revoked_count;
    ctx->revoked_capacity = scratch.revoked_capacity;
    ctx->rev_tree = scratch.rev_tree;
    ctx->crl_version = scratch.crl_version;
    ctx->root_valid_until = scratch.root_valid_until;
    memcpy(ctx->root_hash, scratch.root_hash, sizeof(ctx->root_hash));
    scratch.revoked_serials = NULL;
    scratch.rev_tree = NULL;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_query(sm2_rev_ctx_t *ctx, uint64_t serial_number,
    uint64_t now_ts, sm2_rev_status_t *status, sm2_rev_source_t *source)
{
    if (!ctx || !status || !source)
        return SM2_IC_ERR_PARAM;

    *status = SM2_REV_STATUS_UNKNOWN;
    *source = SM2_REV_SOURCE_NONE;

    if (!ctx->merkle_query_fn)
        return query_local_state(ctx, serial_number, now_ts, status, source);

    return query_merkle_callback(ctx, serial_number, now_ts, status, source);
}

size_t sm2_rev_local_count(const sm2_rev_ctx_t *ctx)
{
    return ctx ? ctx->revoked_count : 0;
}

uint64_t sm2_rev_version(const sm2_rev_ctx_t *ctx)
{
    return ctx ? ctx->crl_version : 0;
}

uint64_t sm2_rev_root_valid_until(const sm2_rev_ctx_t *ctx)
{
    return ctx ? ctx->root_valid_until : 0;
}

sm2_ic_error_t sm2_rev_root_hash(
    const sm2_rev_ctx_t *ctx, uint8_t root_hash[SM2_REV_SYNC_DIGEST_LEN])
{
    if (!ctx || !root_hash)
        return SM2_IC_ERR_PARAM;

    memcpy(root_hash, ctx->root_hash, SM2_REV_SYNC_DIGEST_LEN);
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_set_congestion_limits(
    sm2_rev_ctx_t *ctx, size_t busy_threshold, size_t overload_threshold)
{
    if (!ctx || busy_threshold == 0 || overload_threshold <= busy_threshold)
        return SM2_IC_ERR_PARAM;

    ctx->congestion_busy_threshold = busy_threshold;
    ctx->congestion_overload_threshold = overload_threshold;
    ctx->congestion_signal = calc_congestion_signal(ctx);
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_set_query_inflight(
    sm2_rev_ctx_t *ctx, size_t query_inflight)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;

    ctx->query_inflight = query_inflight;
    ctx->congestion_signal = calc_congestion_signal(ctx);
    return SM2_IC_SUCCESS;
}

sm2_rev_congestion_signal_t sm2_rev_get_congestion_signal(
    const sm2_rev_ctx_t *ctx)
{
    return calc_congestion_signal(ctx);
}

sm2_ic_error_t sm2_rev_set_clock_skew_tolerance(
    sm2_rev_ctx_t *ctx, uint64_t tolerance_sec)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;

    ctx->clock_skew_tolerance_sec = tolerance_sec;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_check_freshness(const sm2_rev_ctx_t *ctx,
    uint64_t now_ts, uint64_t skew_tolerance_sec,
    sm2_rev_sync_freshness_t *freshness)
{
    if (!ctx || !freshness)
        return SM2_IC_ERR_PARAM;

    uint64_t valid_until_limit = ctx->root_valid_until;
    if (valid_until_limit <= UINT64_MAX - skew_tolerance_sec)
        valid_until_limit += skew_tolerance_sec;
    else
        valid_until_limit = UINT64_MAX;

    if (now_ts > valid_until_limit)
    {
        *freshness = SM2_REV_FRESHNESS_EXPIRED;
        return SM2_IC_SUCCESS;
    }

    uint64_t stale_window = ctx->root_valid_ttl_sec / 5U;
    if (stale_window == 0)
        stale_window = 1;

    uint64_t remaining = 0;
    if (ctx->root_valid_until > now_ts)
        remaining = ctx->root_valid_until - now_ts;

    if (remaining <= stale_window)
        *freshness = SM2_REV_FRESHNESS_STALE;
    else
        *freshness = SM2_REV_FRESHNESS_FRESH;

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_sync_policy_init(sm2_rev_sync_policy_t *policy)
{
    if (!policy)
        return SM2_IC_ERR_PARAM;

    policy->t_base_sec = SM2_REV_SYNC_DEFAULT_T_BASE_SEC;
    policy->fast_poll_sec = SM2_REV_SYNC_DEFAULT_FAST_POLL_SEC;
    policy->max_backoff_sec = SM2_REV_SYNC_DEFAULT_MAX_BACKOFF_SEC;
    policy->propagation_delay_sec = SM2_REV_SYNC_DEFAULT_PROPAGATION_DELAY_SEC;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_sync_staleness_bound(const sm2_rev_sync_policy_t *policy,
    uint64_t clock_skew_sec, uint64_t *upper_bound_sec)
{
    if (!policy || !upper_bound_sec)
        return SM2_IC_ERR_PARAM;
    if (policy->t_base_sec == 0 || policy->fast_poll_sec == 0
        || policy->fast_poll_sec > policy->t_base_sec
        || policy->max_backoff_sec < policy->t_base_sec)
    {
        return SM2_IC_ERR_PARAM;
    }

    uint64_t upper = policy->t_base_sec;
    if (upper <= UINT64_MAX - policy->propagation_delay_sec)
        upper += policy->propagation_delay_sec;
    else
        upper = UINT64_MAX;

    if (upper <= UINT64_MAX - clock_skew_sec)
        upper += clock_skew_sec;
    else
        upper = UINT64_MAX;

    *upper_bound_sec = upper;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_sync_plan_schedule(const sm2_rev_ctx_t *ctx,
    const sm2_rev_sync_policy_t *policy, uint64_t known_latest_version,
    uint32_t fail_streak, uint64_t now_ts, sm2_rev_sync_schedule_t *schedule)
{
    if (!ctx || !policy || !schedule)
        return SM2_IC_ERR_PARAM;

    uint64_t upper_bound = 0;
    sm2_ic_error_t ret = sm2_rev_sync_staleness_bound(
        policy, ctx->clock_skew_tolerance_sec, &upper_bound);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    sm2_rev_sync_freshness_t freshness = SM2_REV_FRESHNESS_EXPIRED;
    ret = sm2_rev_check_freshness(
        ctx, now_ts, ctx->clock_skew_tolerance_sec, &freshness);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    memset(schedule, 0, sizeof(*schedule));
    schedule->next_pull_after_sec = policy->t_base_sec;
    schedule->staleness_upper_bound_sec = upper_bound;

    if (known_latest_version > ctx->crl_version)
    {
        schedule->accelerated_mode = true;
        schedule->next_pull_after_sec = policy->fast_poll_sec;
        return SM2_IC_SUCCESS;
    }

    if (freshness != SM2_REV_FRESHNESS_FRESH)
    {
        schedule->heartbeat_refresh_only = true;
        schedule->next_pull_after_sec = policy->fast_poll_sec;
        return SM2_IC_SUCCESS;
    }

    if (fail_streak > 0)
    {
        uint64_t next = policy->t_base_sec;
        uint32_t rounds = fail_streak - 1U;
        while (rounds-- > 0 && next < policy->max_backoff_sec)
        {
            if (next > (UINT64_MAX >> 1U))
            {
                next = UINT64_MAX;
                break;
            }
            next <<= 1U;
        }
        if (next > policy->max_backoff_sec)
            next = policy->max_backoff_sec;
        schedule->next_pull_after_sec = next;
    }

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_sync_build_hello(const sm2_rev_ctx_t *ctx,
    const uint8_t *node_id, size_t node_id_len, uint64_t now_ts,
    sm2_rev_sync_hello_t *hello)
{
    if (!ctx || !hello)
        return SM2_IC_ERR_PARAM;
    if (node_id_len > SM2_REV_SYNC_NODE_ID_MAX_LEN)
        return SM2_IC_ERR_PARAM;
    if (node_id_len > 0 && !node_id)
        return SM2_IC_ERR_PARAM;

    sm2_rev_sync_freshness_t freshness = SM2_REV_FRESHNESS_EXPIRED;
    sm2_ic_error_t ret = sm2_rev_check_freshness(
        ctx, now_ts, ctx->clock_skew_tolerance_sec, &freshness);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    memset(hello, 0, sizeof(*hello));
    if (node_id_len > 0)
        memcpy(hello->node_id, node_id, node_id_len);

    hello->node_id_len = node_id_len;
    hello->root_version = ctx->crl_version;
    memcpy(hello->root_hash, ctx->root_hash, SM2_REV_SYNC_DIGEST_LEN);
    hello->root_valid_until = ctx->root_valid_until;
    hello->local_now_ts = now_ts;
    hello->congestion_signal = calc_congestion_signal(ctx);
    hello->freshness = freshness;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_sync_plan_delta(const sm2_rev_sync_hello_t *local_hello,
    const sm2_rev_sync_hello_t *remote_hello, sm2_rev_sync_delta_plan_t *plan)
{
    if (!local_hello || !remote_hello || !plan)
        return SM2_IC_ERR_PARAM;
    if (local_hello->node_id_len > SM2_REV_SYNC_NODE_ID_MAX_LEN
        || remote_hello->node_id_len > SM2_REV_SYNC_NODE_ID_MAX_LEN)
    {
        return SM2_IC_ERR_PARAM;
    }

    memset(plan, 0, sizeof(*plan));
    plan->direction = SM2_REV_DELTA_DIR_NONE;
    plan->from_version = local_hello->root_version;
    plan->to_version = local_hello->root_version;
    plan->fork_detected = false;

    if (local_hello->root_version == remote_hello->root_version)
    {
        if (memcmp(local_hello->root_hash, remote_hello->root_hash,
                SM2_REV_SYNC_DIGEST_LEN)
            != 0)
        {
            plan->fork_detected = true;
            return SM2_IC_ERR_VERIFY;
        }
        return SM2_IC_SUCCESS;
    }

    if (remote_hello->root_version > local_hello->root_version)
    {
        plan->direction = SM2_REV_DELTA_DIR_PULL;
        plan->from_version = local_hello->root_version;
        plan->to_version = remote_hello->root_version;
    }
    else
    {
        plan->direction = SM2_REV_DELTA_DIR_PUSH;
        plan->from_version = remote_hello->root_version;
        plan->to_version = local_hello->root_version;
    }

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_sync_should_redirect(const sm2_rev_ctx_t *ctx,
    uint64_t known_latest_version, uint64_t max_version_lag, uint64_t now_ts,
    uint64_t skew_tolerance_sec, bool *redirect_required,
    sm2_rev_sync_freshness_t *freshness)
{
    if (!ctx || !redirect_required || !freshness)
        return SM2_IC_ERR_PARAM;

    sm2_ic_error_t ret
        = sm2_rev_check_freshness(ctx, now_ts, skew_tolerance_sec, freshness);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    *redirect_required = false;
    if (*freshness == SM2_REV_FRESHNESS_EXPIRED)
    {
        *redirect_required = true;
        return SM2_IC_SUCCESS;
    }

    if (known_latest_version > ctx->crl_version)
    {
        uint64_t lag = known_latest_version - ctx->crl_version;
        if (max_version_lag == 0 || lag > max_version_lag)
            *redirect_required = true;
    }

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_sync_verify_patch_link(const sm2_rev_patch_link_t *patch,
    uint64_t local_version,
    const uint8_t local_root_hash[SM2_REV_SYNC_DIGEST_LEN], uint64_t now_ts,
    uint64_t skew_tolerance_sec)
{
    if (!patch || !local_root_hash)
        return SM2_IC_ERR_PARAM;
    if (patch->new_version <= patch->prev_version)
        return SM2_IC_ERR_PARAM;
    if (patch->valid_until < patch->issued_at)
        return SM2_IC_ERR_PARAM;

    if (patch->prev_version != local_version)
        return SM2_IC_ERR_VERIFY;
    if (memcmp(patch->prev_root_hash, local_root_hash, SM2_REV_SYNC_DIGEST_LEN)
        != 0)
    {
        return SM2_IC_ERR_VERIFY;
    }

    uint64_t now_with_skew = now_ts;
    if (now_with_skew <= UINT64_MAX - skew_tolerance_sec)
        now_with_skew += skew_tolerance_sec;
    else
        now_with_skew = UINT64_MAX;

    if (now_with_skew < patch->issued_at)
        return SM2_IC_ERR_VERIFY;

    uint64_t valid_until_limit = patch->valid_until;
    if (valid_until_limit <= UINT64_MAX - skew_tolerance_sec)
        valid_until_limit += skew_tolerance_sec;
    else
        valid_until_limit = UINT64_MAX;

    if (now_ts > valid_until_limit)
        return SM2_IC_ERR_VERIFY;

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_sync_build_heartbeat(uint64_t local_version,
    const uint8_t root_hash[SM2_REV_SYNC_DIGEST_LEN], uint64_t issued_at,
    uint64_t valid_until, sm2_rev_heartbeat_patch_t *patch)
{
    if (!root_hash || !patch)
        return SM2_IC_ERR_PARAM;
    if (local_version == UINT64_MAX || valid_until < issued_at)
        return SM2_IC_ERR_PARAM;

    memset(patch, 0, sizeof(*patch));
    patch->object_type = SM2_REV_SYNC_OBJECT_HEARTBEAT_PATCH;
    patch->base_version = local_version;
    patch->new_version = local_version + 1U;
    memcpy(patch->root_hash, root_hash, SM2_REV_SYNC_DIGEST_LEN);
    patch->issued_at = issued_at;
    patch->valid_until = valid_until;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_sync_verify_heartbeat(
    const sm2_rev_heartbeat_patch_t *patch, uint64_t local_version,
    const uint8_t local_root_hash[SM2_REV_SYNC_DIGEST_LEN], uint64_t now_ts,
    uint64_t skew_tolerance_sec)
{
    if (!patch || !local_root_hash)
        return SM2_IC_ERR_PARAM;
    if (patch->object_type != SM2_REV_SYNC_OBJECT_HEARTBEAT_PATCH)
        return SM2_IC_ERR_PARAM;
    if (patch->new_version <= patch->base_version
        || patch->valid_until < patch->issued_at)
    {
        return SM2_IC_ERR_PARAM;
    }
    if (patch->base_version != local_version
        || patch->new_version != local_version + 1U)
    {
        return SM2_IC_ERR_VERIFY;
    }
    if (memcmp(patch->root_hash, local_root_hash, SM2_REV_SYNC_DIGEST_LEN) != 0)
    {
        return SM2_IC_ERR_VERIFY;
    }

    uint64_t now_with_skew = now_ts;
    if (now_with_skew <= UINT64_MAX - skew_tolerance_sec)
        now_with_skew += skew_tolerance_sec;
    else
        now_with_skew = UINT64_MAX;

    if (now_with_skew < patch->issued_at)
        return SM2_IC_ERR_VERIFY;

    uint64_t valid_until_limit = patch->valid_until;
    if (valid_until_limit <= UINT64_MAX - skew_tolerance_sec)
        valid_until_limit += skew_tolerance_sec;
    else
        valid_until_limit = UINT64_MAX;

    if (now_ts > valid_until_limit)
        return SM2_IC_ERR_VERIFY;

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_sync_apply_heartbeat(
    sm2_rev_ctx_t *ctx, const sm2_rev_heartbeat_patch_t *patch, uint64_t now_ts)
{
    if (!ctx || !patch)
        return SM2_IC_ERR_PARAM;
    if (patch->object_type != SM2_REV_SYNC_OBJECT_HEARTBEAT_PATCH)
        return SM2_IC_ERR_PARAM;
    if (patch->new_version <= patch->base_version
        || patch->valid_until < patch->issued_at)
    {
        return SM2_IC_ERR_PARAM;
    }
    if (patch->base_version != ctx->crl_version
        || patch->new_version != ctx->crl_version + 1U)
    {
        return SM2_IC_ERR_VERIFY;
    }
    if (memcmp(patch->root_hash, ctx->root_hash, SM2_REV_SYNC_DIGEST_LEN) != 0)
        return SM2_IC_ERR_VERIFY;

    uint64_t now_with_skew = now_ts;
    if (now_with_skew <= UINT64_MAX - ctx->clock_skew_tolerance_sec)
        now_with_skew += ctx->clock_skew_tolerance_sec;
    else
        now_with_skew = UINT64_MAX;

    if (now_with_skew < patch->issued_at)
        return SM2_IC_ERR_VERIFY;

    uint64_t valid_until_limit = patch->valid_until;
    if (valid_until_limit <= UINT64_MAX - ctx->clock_skew_tolerance_sec)
        valid_until_limit += ctx->clock_skew_tolerance_sec;
    else
        valid_until_limit = UINT64_MAX;

    if (now_ts > valid_until_limit)
        return SM2_IC_ERR_VERIFY;

    ctx->crl_version = patch->new_version;
    ctx->root_valid_until = patch->valid_until;
    if (patch->valid_until > now_ts)
        ctx->root_valid_ttl_sec = patch->valid_until - now_ts;
    else
        ctx->root_valid_ttl_sec = 1U;

    return SM2_IC_SUCCESS;
}
