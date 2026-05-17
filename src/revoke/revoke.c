/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file revoke.c
 * @brief Revocation state management for Merkle-only query path.
 */

#include "merkle_internal.h"
#include "revoke_internal.h"
#include "sm2_secure_mem.h"

#include <stdint.h>
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

typedef struct
{
    sm2_rev_delta_item_t item;
    size_t original_index;
} rev_delta_work_item_t;

static int rev_delta_work_cmp_serial_index(const void *a, const void *b)
{
    const rev_delta_work_item_t *lhs = (const rev_delta_work_item_t *)a;
    const rev_delta_work_item_t *rhs = (const rev_delta_work_item_t *)b;
    if (lhs->item.serial_number < rhs->item.serial_number)
        return -1;
    if (lhs->item.serial_number > rhs->item.serial_number)
        return 1;
    if (lhs->original_index < rhs->original_index)
        return -1;
    if (lhs->original_index > rhs->original_index)
        return 1;
    return 0;
}

static sm2_ic_error_t rev_delta_canonicalize_items(
    const sm2_rev_delta_item_t *items, size_t item_count,
    sm2_rev_delta_item_t **canonical_items, size_t *canonical_count)
{
    if (!canonical_items || !canonical_count)
        return SM2_IC_ERR_PARAM;
    if (item_count > 0 && !items)
        return SM2_IC_ERR_PARAM;

    *canonical_items = NULL;
    *canonical_count = 0;
    if (item_count == 0)
        return SM2_IC_SUCCESS;
    if (item_count > SIZE_MAX / sizeof(rev_delta_work_item_t)
        || item_count > SIZE_MAX / sizeof(sm2_rev_delta_item_t))
    {
        return SM2_IC_ERR_MEMORY;
    }

    rev_delta_work_item_t *work
        = (rev_delta_work_item_t *)calloc(item_count, sizeof(*work));
    sm2_rev_delta_item_t *out
        = (sm2_rev_delta_item_t *)calloc(item_count, sizeof(*out));
    if (!work || !out)
    {
        free(work);
        free(out);
        return SM2_IC_ERR_MEMORY;
    }

    for (size_t i = 0; i < item_count; i++)
    {
        if (items[i].serial_number == 0)
        {
            free(work);
            free(out);
            return SM2_IC_ERR_PARAM;
        }
        work[i].item = items[i];
        work[i].original_index = i;
    }
    qsort(work, item_count, sizeof(*work), rev_delta_work_cmp_serial_index);

    size_t out_count = 0;
    size_t i = 0;
    while (i < item_count)
    {
        size_t j = i + 1U;
        while (j < item_count
            && work[j].item.serial_number == work[i].item.serial_number)
        {
            j++;
        }
        out[out_count++] = work[j - 1U].item;
        i = j;
    }

    free(work);
    *canonical_items = out;
    *canonical_count = out_count;
    return SM2_IC_SUCCESS;
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

static bool local_list_find_index(
    const sm2_rev_ctx_t *ctx, uint64_t serial, size_t *index)
{
    if (index)
        *index = 0;
    if (!ctx)
        return false;

    size_t lo = 0;
    size_t hi = ctx->revoked_count;
    while (lo < hi)
    {
        size_t mid = lo + (hi - lo) / 2U;
        if (ctx->revoked_serials[mid] < serial)
            lo = mid + 1U;
        else
            hi = mid;
    }

    if (index)
        *index = lo;
    return lo < ctx->revoked_count && ctx->revoked_serials[lo] == serial;
}

static sm2_ic_error_t local_list_add(sm2_rev_ctx_t *ctx, uint64_t serial)
{
    if (!ctx)
        return SM2_IC_ERR_PARAM;

    size_t insert_at = 0;
    if (local_list_find_index(ctx, serial, &insert_at))
        return SM2_IC_SUCCESS;

    sm2_ic_error_t ret = local_list_reserve(ctx, ctx->revoked_count + 1);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (insert_at < ctx->revoked_count)
    {
        memmove(&ctx->revoked_serials[insert_at + 1U],
            &ctx->revoked_serials[insert_at],
            (ctx->revoked_count - insert_at) * sizeof(uint64_t));
    }
    ctx->revoked_serials[insert_at] = serial;
    ctx->revoked_count++;
    return SM2_IC_SUCCESS;
}

static void local_list_remove(sm2_rev_ctx_t *ctx, uint64_t serial)
{
    if (!ctx)
        return;

    size_t remove_at = 0;
    if (!local_list_find_index(ctx, serial, &remove_at))
        return;
    if (remove_at + 1U < ctx->revoked_count)
    {
        memmove(&ctx->revoked_serials[remove_at],
            &ctx->revoked_serials[remove_at + 1U],
            (ctx->revoked_count - remove_at - 1U) * sizeof(uint64_t));
    }
    ctx->revoked_count--;
}

static bool local_list_contains(const sm2_rev_ctx_t *ctx, uint64_t serial)
{
    if (!ctx)
        return false;

    return local_list_find_index(ctx, serial, NULL);
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
        dst->revoked_count, dst->rev_version);
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
            ctx->revoked_serials, ctx->revoked_count, ctx->rev_version);
        if (ret != SM2_IC_SUCCESS)
            return ret;
    }

    merkle_tree_set_root_version(ctx->rev_tree, ctx->rev_version);
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
            tree, ctx->revoked_serials, ctx->revoked_count, ctx->rev_version);
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

    if (sm2_rev_tree_root_version(tree) != ctx->rev_version)
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
    sm2_rev_ctx_t *ctx, const sm2_rev_delta_t *delta, uint64_t now_ts)
{
    if (!ctx || !delta)
        return SM2_IC_ERR_PARAM;
    if (delta->item_count > 0 && !delta->items)
        return SM2_IC_ERR_PARAM;
    if (delta->base_version != ctx->rev_version)
        return SM2_IC_ERR_VERIFY;
    if (delta->new_version <= delta->base_version)
        return SM2_IC_ERR_PARAM;

    sm2_rev_delta_item_t *canonical_items = NULL;
    size_t canonical_count = 0;
    sm2_ic_error_t ret = rev_delta_canonicalize_items(
        delta->items, delta->item_count, &canonical_items, &canonical_count);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    sm2_rev_ctx_t scratch;
    ret = rev_ctx_clone_local_state(ctx, &scratch);
    if (ret != SM2_IC_SUCCESS)
    {
        free(canonical_items);
        return ret;
    }

    for (size_t i = 0; i < canonical_count; i++)
    {
        const sm2_rev_delta_item_t *it = &canonical_items[i];
        if (it->revoked)
        {
            ret = local_list_add(&scratch, it->serial_number);
            if (ret != SM2_IC_SUCCESS)
            {
                free(canonical_items);
                rev_local_list_release(&scratch.revoked_serials);
                sm2_rev_tree_cleanup(&scratch.rev_tree);
                return ret;
            }
        }
        else
        {
            local_list_remove(&scratch, it->serial_number);
        }
    }

    ret = merkle_tree_apply_delta_items(
        scratch.rev_tree, canonical_items, canonical_count);
    if (ret != SM2_IC_SUCCESS)
    {
        free(canonical_items);
        rev_local_list_release(&scratch.revoked_serials);
        sm2_rev_tree_cleanup(&scratch.rev_tree);
        return ret;
    }

    scratch.rev_version = delta->new_version;
    merkle_tree_set_root_version(scratch.rev_tree, scratch.rev_version);
    scratch.root_valid_until = rev_ctx_compute_valid_until(&scratch, now_ts);
    ret = rev_ctx_refresh_root_hash(&scratch);
    if (ret != SM2_IC_SUCCESS)
    {
        free(canonical_items);
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
    ctx->rev_version = scratch.rev_version;
    ctx->root_valid_until = scratch.root_valid_until;
    memcpy(ctx->root_hash, scratch.root_hash, sizeof(ctx->root_hash));
    scratch.revoked_serials = NULL;
    scratch.rev_tree = NULL;
    free(canonical_items);
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
    return ctx ? ctx->rev_version : 0;
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

static uint64_t rev_sync_sat_add(uint64_t lhs, uint64_t rhs)
{
    if (rhs > UINT64_MAX - lhs)
        return UINT64_MAX;
    return lhs + rhs;
}

static uint64_t rev_sync_elapsed(uint64_t now_ts, uint64_t then_ts)
{
    return now_ts > then_ts ? now_ts - then_ts : 0;
}

static uint64_t rev_sync_limit_wait_to_expiry(
    uint64_t now_ts, uint64_t valid_until, uint64_t wait_sec)
{
    if (valid_until <= now_ts)
        return 0;
    uint64_t wait_to_expiry = valid_until - now_ts;
    return wait_sec < wait_to_expiry ? wait_sec : wait_to_expiry;
}

static sm2_ic_error_t rev_sync_validate_policy(
    const sm2_rev_sync_policy_t *policy)
{
    if (!policy)
        return SM2_IC_ERR_PARAM;
    if (policy->t_base_sec == 0 || policy->fast_poll_sec == 0
        || policy->fast_poll_sec > policy->t_base_sec
        || policy->max_backoff_sec < policy->t_base_sec
        || policy->full_checkpoint_interval_sec < policy->t_base_sec
        || policy->max_delta_chain_len == 0)
    {
        return SM2_IC_ERR_PARAM;
    }
    return SM2_IC_SUCCESS;
}

static void rev_sync_set_publication_plan(sm2_rev_publication_plan_t *plan,
    sm2_rev_publication_action_t action, uint64_t now_ts,
    uint64_t publish_after_sec, const sm2_rev_sync_policy_t *policy,
    uint64_t staleness_upper_bound_sec, uint64_t current_root_valid_until)
{
    memset(plan, 0, sizeof(*plan));
    plan->action = action;
    plan->publish_after_sec = publish_after_sec;
    plan->publish_now
        = action != SM2_REV_PUBLICATION_NONE && publish_after_sec == 0;
    plan->staleness_upper_bound_sec = staleness_upper_bound_sec;

    if (action == SM2_REV_PUBLICATION_NONE)
    {
        plan->object_type = SM2_REV_SYNC_OBJECT_HEARTBEAT_PATCH;
        plan->valid_until = current_root_valid_until;
        plan->next_update_ts = rev_sync_sat_add(now_ts, publish_after_sec);
        return;
    }

    plan->issued_at = rev_sync_sat_add(now_ts, publish_after_sec);
    plan->valid_until = rev_sync_sat_add(plan->issued_at, policy->t_base_sec);
    plan->next_update_ts = plan->valid_until;

    if (action == SM2_REV_PUBLICATION_DELTA_PATCH)
    {
        plan->object_type = SM2_REV_SYNC_OBJECT_DELTA_PATCH;
        return;
    }
    if (action == SM2_REV_PUBLICATION_HEARTBEAT_PATCH)
    {
        plan->object_type = SM2_REV_SYNC_OBJECT_HEARTBEAT_PATCH;
        plan->heartbeat_refresh_only = true;
        return;
    }
    plan->object_type = SM2_REV_SYNC_OBJECT_ROOT_RECORD;
}

sm2_ic_error_t sm2_rev_sync_policy_init(sm2_rev_sync_policy_t *policy)
{
    if (!policy)
        return SM2_IC_ERR_PARAM;

    policy->t_base_sec = SM2_REV_SYNC_DEFAULT_T_BASE_SEC;
    policy->fast_poll_sec = SM2_REV_SYNC_DEFAULT_FAST_POLL_SEC;
    policy->max_backoff_sec = SM2_REV_SYNC_DEFAULT_MAX_BACKOFF_SEC;
    policy->propagation_delay_sec = SM2_REV_SYNC_DEFAULT_PROPAGATION_DELAY_SEC;
    policy->full_checkpoint_interval_sec
        = SM2_REV_SYNC_DEFAULT_FULL_CHECKPOINT_SEC;
    policy->max_delta_chain_len = SM2_REV_SYNC_DEFAULT_MAX_DELTA_CHAIN_LEN;
    policy->urgent_delta_grace_sec
        = SM2_REV_SYNC_DEFAULT_URGENT_DELTA_GRACE_SEC;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_sync_staleness_bound(const sm2_rev_sync_policy_t *policy,
    uint64_t clock_skew_sec, uint64_t *upper_bound_sec)
{
    if (!policy || !upper_bound_sec)
        return SM2_IC_ERR_PARAM;
    sm2_ic_error_t ret = rev_sync_validate_policy(policy);
    if (ret != SM2_IC_SUCCESS)
        return ret;

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

sm2_ic_error_t sm2_rev_sync_plan_publication(
    const sm2_rev_sync_policy_t *policy, uint64_t now_ts,
    const sm2_rev_publication_input_t *input, sm2_rev_publication_plan_t *plan)
{
    if (!policy || !input || !plan)
        return SM2_IC_ERR_PARAM;

    uint64_t upper_bound = 0;
    sm2_ic_error_t ret = sm2_rev_sync_staleness_bound(policy, 0, &upper_bound);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    bool has_pending_delta
        = input->has_pending_delta || input->pending_delta_count > 0;
    uint64_t elapsed_since_publish
        = rev_sync_elapsed(now_ts, input->last_publish_ts);
    uint64_t elapsed_since_full
        = rev_sync_elapsed(now_ts, input->last_full_checkpoint_ts);

    if (input->delta_chain_len >= policy->max_delta_chain_len
        || elapsed_since_full >= policy->full_checkpoint_interval_sec)
    {
        rev_sync_set_publication_plan(plan, SM2_REV_PUBLICATION_FULL_CHECKPOINT,
            now_ts, 0, policy, upper_bound, input->current_root_valid_until);
        return SM2_IC_SUCCESS;
    }

    if (has_pending_delta && input->urgent_delta)
    {
        uint64_t wait_sec = 0;
        if (elapsed_since_publish < policy->urgent_delta_grace_sec)
            wait_sec = policy->urgent_delta_grace_sec - elapsed_since_publish;
        wait_sec = rev_sync_limit_wait_to_expiry(
            now_ts, input->current_root_valid_until, wait_sec);
        rev_sync_set_publication_plan(plan, SM2_REV_PUBLICATION_DELTA_PATCH,
            now_ts, wait_sec, policy, upper_bound,
            input->current_root_valid_until);
        return SM2_IC_SUCCESS;
    }

    if (has_pending_delta)
    {
        uint64_t wait_sec = 0;
        if (elapsed_since_publish < policy->fast_poll_sec)
            wait_sec = policy->fast_poll_sec - elapsed_since_publish;
        wait_sec = rev_sync_limit_wait_to_expiry(
            now_ts, input->current_root_valid_until, wait_sec);
        rev_sync_set_publication_plan(plan, SM2_REV_PUBLICATION_DELTA_PATCH,
            now_ts, wait_sec, policy, upper_bound,
            input->current_root_valid_until);
        return SM2_IC_SUCCESS;
    }

    if (input->current_root_valid_until <= now_ts
        || elapsed_since_publish >= policy->t_base_sec)
    {
        rev_sync_set_publication_plan(plan, SM2_REV_PUBLICATION_HEARTBEAT_PATCH,
            now_ts, 0, policy, upper_bound, input->current_root_valid_until);
        return SM2_IC_SUCCESS;
    }

    uint64_t wait_for_heartbeat = policy->t_base_sec - elapsed_since_publish;
    uint64_t wait_for_expire = input->current_root_valid_until - now_ts;
    uint64_t wait_sec = wait_for_heartbeat < wait_for_expire
        ? wait_for_heartbeat
        : wait_for_expire;
    rev_sync_set_publication_plan(plan, SM2_REV_PUBLICATION_NONE, now_ts,
        wait_sec, policy, upper_bound, input->current_root_valid_until);
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

    if (known_latest_version > ctx->rev_version)
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
    hello->root_version = ctx->rev_version;
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

    if (known_latest_version > ctx->rev_version)
    {
        uint64_t lag = known_latest_version - ctx->rev_version;
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
    if (patch->base_version != ctx->rev_version
        || patch->new_version != ctx->rev_version + 1U)
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

    ctx->rev_version = patch->new_version;
    ctx->root_valid_until = patch->valid_until;
    if (patch->valid_until > now_ts)
        ctx->root_valid_ttl_sec = patch->valid_until - now_ts;
    else
        ctx->root_valid_ttl_sec = 1U;

    return SM2_IC_SUCCESS;
}
