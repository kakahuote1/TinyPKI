/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file revoke_sync.c
 * @brief Revocation station sync, redirect, and routing helpers.
 */

#include "sm2_revocation.h"
#include "revoke_internal.h"

#include <stdlib.h>
#include <string.h>

static uint32_t route_effective_weight(
    const sm2_rev_route_node_t *node, bool include_overload)
{
    if (!node || !node->enabled || node->node_id_len == 0
        || node->node_id_len > SM2_REV_SYNC_NODE_ID_MAX_LEN
        || node->base_weight == 0)
    {
        return 0;
    }

    if (!include_overload
        && node->congestion_signal == SM2_REV_CONGESTION_OVERLOAD)
    {
        return 0;
    }

    uint32_t weight = node->base_weight;
    if (node->congestion_signal == SM2_REV_CONGESTION_BUSY)
    {
        weight = (weight + 1U) / 2U;
    }
    else if (node->congestion_signal == SM2_REV_CONGESTION_OVERLOAD)
    {
        weight = (weight + 7U) / 8U;
    }

    return weight == 0 ? 1U : weight;
}

static bool sample_root_expired(
    uint64_t root_valid_until, uint64_t now_ts, uint64_t skew_tolerance_sec)
{
    uint64_t valid_until_limit = root_valid_until;
    if (valid_until_limit <= UINT64_MAX - skew_tolerance_sec)
        valid_until_limit += skew_tolerance_sec;
    else
        valid_until_limit = UINT64_MAX;

    return now_ts > valid_until_limit;
}

static uint16_t redirect_health_score(
    const sm2_rev_node_health_sample_t *sample, uint64_t min_root_version,
    uint64_t now_ts, uint64_t skew_tolerance_sec)
{
    uint32_t score = 1000U;
    uint64_t version_delta = 0;

    if (sample->root_version > min_root_version)
        version_delta = sample->root_version - min_root_version;
    if (version_delta > 8U)
        version_delta = 8U;
    score += (uint32_t)version_delta * 128U;

    if (sample->route.base_weight > 256U)
        score += 256U;
    else
        score += sample->route.base_weight;

    if (sample->route.congestion_signal == SM2_REV_CONGESTION_BUSY)
        score = score > 96U ? score - 96U : 1U;
    else if (sample->route.congestion_signal == SM2_REV_CONGESTION_OVERLOAD)
        score = score > 256U ? score - 256U : 1U;

    uint32_t fail_penalty = sample->route.fail_streak;
    if (fail_penalty > 8U)
        fail_penalty = 8U;
    fail_penalty *= 32U;
    score = score > fail_penalty ? score - fail_penalty : 1U;

    uint32_t rtt_penalty = sample->rtt_ms / 4U;
    if (rtt_penalty > 256U)
        rtt_penalty = 256U;
    score = score > rtt_penalty ? score - rtt_penalty : 1U;

    if (!sample_root_expired(
            sample->root_valid_until, now_ts, skew_tolerance_sec))
    {
        if (sample->root_valid_until <= now_ts)
            score = score > 160U ? score - 160U : 1U;
        else if (sample->root_valid_until - now_ts <= 30U)
            score = score > 80U ? score - 80U : 1U;
    }

    if (score > UINT16_MAX)
        score = UINT16_MAX;
    return (uint16_t)score;
}

static bool redirect_candidate_better(const sm2_rev_redirect_candidate_t *lhs,
    const sm2_rev_redirect_candidate_t *rhs)
{
    if (lhs->health_score != rhs->health_score)
        return lhs->health_score > rhs->health_score;
    if (lhs->root_version != rhs->root_version)
        return lhs->root_version > rhs->root_version;
    if (lhs->congestion_signal != rhs->congestion_signal)
        return lhs->congestion_signal < rhs->congestion_signal;
    if (lhs->rtt_ms != rhs->rtt_ms)
        return lhs->rtt_ms < rhs->rtt_ms;

    size_t min_len = lhs->node_id_len < rhs->node_id_len ? lhs->node_id_len
                                                         : rhs->node_id_len;
    int cmp = memcmp(lhs->node_id, rhs->node_id, min_len);
    if (cmp != 0)
        return cmp < 0;
    return lhs->node_id_len < rhs->node_id_len;
}

static bool node_id_equal(
    const uint8_t *lhs, size_t lhs_len, const uint8_t *rhs, size_t rhs_len);

static bool redirect_find_candidate_index(
    const sm2_rev_redirect_candidate_t *candidates, size_t candidate_count,
    const uint8_t *node_id, size_t node_id_len, size_t *index)
{
    if (!candidates || !node_id || !index)
        return false;

    for (size_t i = 0; i < candidate_count; i++)
    {
        if (node_id_equal(candidates[i].node_id, candidates[i].node_id_len,
                node_id, node_id_len))
        {
            *index = i;
            return true;
        }
    }
    return false;
}

sm2_ic_error_t sm2_rev_sync_apply_delta(sm2_rev_ctx_t *ctx,
    const sm2_rev_sync_delta_plan_t *plan, const sm2_rev_delta_t *delta,
    uint64_t now_ts, bool *converged)
{
    if (!ctx || !plan || !converged)
        return SM2_IC_ERR_PARAM;

    *converged = false;
    if (plan->fork_detected)
        return SM2_IC_ERR_VERIFY;

    if (plan->direction == SM2_REV_DELTA_DIR_NONE)
    {
        *converged = ctx->rev_version == plan->to_version;
        return SM2_IC_SUCCESS;
    }

    if (plan->direction != SM2_REV_DELTA_DIR_PULL || !delta)
        return plan->direction == SM2_REV_DELTA_DIR_PUSH ? SM2_IC_ERR_VERIFY
                                                         : SM2_IC_ERR_PARAM;

    if (delta->base_version != ctx->rev_version)
        return SM2_IC_ERR_VERIFY;
    if (delta->new_version > plan->to_version)
        return SM2_IC_ERR_VERIFY;

    sm2_ic_error_t ret = sm2_rev_apply_delta(ctx, delta, now_ts);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    *converged = ctx->rev_version >= plan->to_version;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_route_rank_candidates(
    const sm2_rev_node_health_sample_t *samples, size_t sample_count,
    uint64_t min_root_version, uint64_t now_ts, uint64_t skew_tolerance_sec,
    size_t max_candidates, sm2_rev_redirect_candidate_t *candidates,
    size_t *candidate_count)
{
    sm2_ic_error_t ret
        = sm2_rev_internal_validate_candidate_count(max_candidates);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    if ((!samples && sample_count > 0) || !candidate_count)
        return SM2_IC_ERR_PARAM;
    if (max_candidates > 0 && !candidates)
        return SM2_IC_ERR_PARAM;

    *candidate_count = 0;
    if (sample_count == 0 || max_candidates == 0)
        return SM2_IC_SUCCESS;

    size_t limit
        = sample_count < max_candidates ? sample_count : max_candidates;
    for (size_t i = 0; i < sample_count; i++)
    {
        const sm2_rev_node_health_sample_t *sample = &samples[i];
        if (!sample->route.enabled
            || !sm2_rev_internal_node_id_len_valid(sample->route.node_id_len))
        {
            continue;
        }
        if (sample->route.next_retry_ts > now_ts)
            continue;
        if (sample->root_version < min_root_version)
            continue;
        if (sample_root_expired(
                sample->root_valid_until, now_ts, skew_tolerance_sec))
        {
            continue;
        }

        sm2_rev_redirect_candidate_t candidate;
        memset(&candidate, 0, sizeof(candidate));
        memcpy(candidate.node_id, sample->route.node_id,
            sample->route.node_id_len);
        candidate.node_id_len = sample->route.node_id_len;
        candidate.root_version = sample->root_version;
        candidate.root_valid_until = sample->root_valid_until;
        candidate.rtt_ms = sample->rtt_ms;
        candidate.congestion_signal = sample->route.congestion_signal;
        candidate.health_score = redirect_health_score(
            sample, min_root_version, now_ts, skew_tolerance_sec);

        size_t existing_index = 0;
        if (redirect_find_candidate_index(candidates, *candidate_count,
                candidate.node_id, candidate.node_id_len, &existing_index))
        {
            if (!redirect_candidate_better(
                    &candidate, &candidates[existing_index]))
            {
                continue;
            }

            for (size_t j = existing_index; j + 1 < *candidate_count; j++)
                candidates[j] = candidates[j + 1];
            (*candidate_count)--;
        }

        size_t insert_at = 0;
        while (insert_at < *candidate_count
            && !redirect_candidate_better(&candidate, &candidates[insert_at]))
        {
            insert_at++;
        }

        if (insert_at >= limit)
            continue;

        if (*candidate_count < limit)
            (*candidate_count)++;

        for (size_t j = *candidate_count - 1; j > insert_at; j--)
            candidates[j] = candidates[j - 1];
        candidates[insert_at] = candidate;
    }

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_route_build_response(const sm2_rev_ctx_t *ctx,
    uint64_t known_latest_version, uint64_t max_version_lag, uint64_t now_ts,
    uint64_t skew_tolerance_sec, const sm2_rev_node_health_sample_t *samples,
    size_t sample_count, size_t max_candidates,
    sm2_rev_redirect_response_t *response,
    sm2_rev_redirect_candidate_t *candidates, size_t *candidate_count)
{
    sm2_ic_error_t ret
        = sm2_rev_internal_validate_candidate_count(max_candidates);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    if (!ctx || !response || !candidate_count)
        return SM2_IC_ERR_PARAM;
    if (max_candidates > 0 && !candidates)
        return SM2_IC_ERR_PARAM;

    sm2_rev_sync_freshness_t freshness = SM2_REV_FRESHNESS_EXPIRED;
    bool redirect_required = false;
    ret = sm2_rev_sync_should_redirect(ctx, known_latest_version,
        max_version_lag, now_ts, skew_tolerance_sec, &redirect_required,
        &freshness);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    memset(response, 0, sizeof(*response));
    response->redirect_required = redirect_required;
    response->freshness = freshness;
    response->local_version = ctx->rev_version;
    response->known_latest_version = known_latest_version;
    response->now_ts = now_ts;
    response->reason = SM2_REV_REDIRECT_REASON_NONE;
    *candidate_count = 0;

    if (!redirect_required)
        return SM2_IC_SUCCESS;

    uint64_t min_root_version = ctx->rev_version;
    if (known_latest_version > min_root_version)
        min_root_version = known_latest_version;

    ret = sm2_rev_route_rank_candidates(samples, sample_count, min_root_version,
        now_ts, skew_tolerance_sec, max_candidates, candidates,
        candidate_count);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    response->candidate_count = *candidate_count;
    if (*candidate_count == 0)
        response->reason = SM2_REV_REDIRECT_REASON_NO_HEALTHY_NODE;
    else if (freshness == SM2_REV_FRESHNESS_EXPIRED)
        response->reason = SM2_REV_REDIRECT_REASON_EXPIRED;
    else
        response->reason = SM2_REV_REDIRECT_REASON_VERSION_STALE;

    return SM2_IC_SUCCESS;
}
static bool node_id_equal(
    const uint8_t *lhs, size_t lhs_len, const uint8_t *rhs, size_t rhs_len)
{
    if (!lhs || !rhs || lhs_len != rhs_len)
        return false;
    if (!sm2_rev_internal_node_id_len_valid(lhs_len))
        return false;
    return memcmp(lhs, rhs, lhs_len) == 0;
}

static const sm2_rev_route_node_t *find_route_node_state(
    const sm2_rev_route_node_t *route_nodes, size_t route_node_count,
    const uint8_t *node_id, size_t node_id_len)
{
    if (!route_nodes || !node_id || node_id_len == 0)
        return NULL;

    for (size_t i = 0; i < route_node_count; i++)
    {
        const sm2_rev_route_node_t *node = &route_nodes[i];
        if (node_id_equal(
                node->node_id, node->node_id_len, node_id, node_id_len))
            return node;
    }
    return NULL;
}

static sm2_rev_route_node_t *find_route_node_state_mut(
    sm2_rev_route_node_t *route_nodes, size_t route_node_count,
    const uint8_t *node_id, size_t node_id_len)
{
    if (!route_nodes || !node_id || node_id_len == 0)
        return NULL;

    for (size_t i = 0; i < route_node_count; i++)
    {
        sm2_rev_route_node_t *node = &route_nodes[i];
        if (node_id_equal(
                node->node_id, node->node_id_len, node_id, node_id_len))
            return node;
    }
    return NULL;
}

static void write_u16_be(uint8_t *dst, uint16_t v)
{
    dst[0] = (uint8_t)((v >> 8) & 0xFF);
    dst[1] = (uint8_t)(v & 0xFF);
}

static void write_u32_be(uint8_t *dst, uint32_t v)
{
    dst[0] = (uint8_t)((v >> 24) & 0xFF);
    dst[1] = (uint8_t)((v >> 16) & 0xFF);
    dst[2] = (uint8_t)((v >> 8) & 0xFF);
    dst[3] = (uint8_t)(v & 0xFF);
}

static void write_u64_be(uint8_t *dst, uint64_t v)
{
    dst[0] = (uint8_t)((v >> 56) & 0xFF);
    dst[1] = (uint8_t)((v >> 48) & 0xFF);
    dst[2] = (uint8_t)((v >> 40) & 0xFF);
    dst[3] = (uint8_t)((v >> 32) & 0xFF);
    dst[4] = (uint8_t)((v >> 24) & 0xFF);
    dst[5] = (uint8_t)((v >> 16) & 0xFF);
    dst[6] = (uint8_t)((v >> 8) & 0xFF);
    dst[7] = (uint8_t)(v & 0xFF);
}

static sm2_ic_error_t serialize_redirect_metadata(
    const sm2_rev_redirect_response_t *response,
    const sm2_rev_redirect_candidate_t *candidates, size_t candidate_count,
    uint8_t **out_buf, size_t *out_len)
{
    sm2_ic_error_t ret
        = sm2_rev_internal_validate_candidate_count(candidate_count);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    if (!response || !out_buf || !out_len)
        return SM2_IC_ERR_PARAM;
    if (candidate_count > 0 && !candidates)
        return SM2_IC_ERR_PARAM;

    size_t header_len = 1 + 1 + 1 + 8 + 8 + 8 + 8;
    size_t total_len = header_len;
    for (size_t i = 0; i < candidate_count; i++)
    {
        const sm2_rev_redirect_candidate_t *candidate = &candidates[i];
        if (!sm2_rev_internal_node_id_len_valid(candidate->node_id_len))
            return SM2_IC_ERR_PARAM;

        size_t per_candidate = 1 + candidate->node_id_len + 8 + 8 + 4 + 2 + 1;
        if (total_len > SIZE_MAX - per_candidate)
            return SM2_IC_ERR_PARAM;
        total_len += per_candidate;
    }
    uint8_t *buf = (uint8_t *)calloc(total_len, sizeof(uint8_t));
    if (!buf)
        return SM2_IC_ERR_MEMORY;

    size_t off = 0;
    buf[off++] = response->redirect_required ? 1U : 0U;
    buf[off++] = (uint8_t)response->reason;
    buf[off++] = (uint8_t)response->freshness;
    write_u64_be(&buf[off], response->local_version);
    off += 8;
    write_u64_be(&buf[off], response->known_latest_version);
    off += 8;
    write_u64_be(&buf[off], response->now_ts);
    off += 8;
    write_u64_be(&buf[off], (uint64_t)candidate_count);
    off += 8;

    for (size_t i = 0; i < candidate_count; i++)
    {
        const sm2_rev_redirect_candidate_t *c = &candidates[i];
        buf[off++] = (uint8_t)c->node_id_len;
        if (c->node_id_len > 0)
        {
            memcpy(&buf[off], c->node_id, c->node_id_len);
            off += c->node_id_len;
        }
        write_u64_be(&buf[off], c->root_version);
        off += 8;
        write_u64_be(&buf[off], c->root_valid_until);
        off += 8;
        write_u32_be(&buf[off], c->rtt_ms);
        off += 4;
        write_u16_be(&buf[off], c->health_score);
        off += 2;
        buf[off++] = (uint8_t)c->congestion_signal;
    }

    *out_buf = buf;
    *out_len = total_len;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_route_pick_candidate(
    const sm2_rev_redirect_response_t *response,
    const sm2_rev_redirect_candidate_t *candidates, size_t candidate_count,
    const sm2_rev_route_node_t *route_nodes, size_t route_node_count,
    uint64_t now_ts, uint64_t random_nonce, size_t *selected_index)
{
    sm2_ic_error_t ret
        = sm2_rev_internal_validate_candidate_count(candidate_count);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    if (!response || !selected_index)
        return SM2_IC_ERR_PARAM;
    if (candidate_count > 0 && !candidates)
        return SM2_IC_ERR_PARAM;
    if (route_node_count > 0 && !route_nodes)
        return SM2_IC_ERR_PARAM;
    if (!response->redirect_required || candidate_count == 0)
        return SM2_IC_ERR_VERIFY;
    if (response->candidate_count != candidate_count)
        return SM2_IC_ERR_VERIFY;

    if (candidate_count > SIZE_MAX / sizeof(sm2_rev_route_node_t))
        return SM2_IC_ERR_MEMORY;

    sm2_rev_route_node_t *temp_nodes = (sm2_rev_route_node_t *)calloc(
        candidate_count, sizeof(sm2_rev_route_node_t));
    if (!temp_nodes)
        return SM2_IC_ERR_MEMORY;

    for (size_t i = 0; i < candidate_count; i++)
    {
        const sm2_rev_redirect_candidate_t *cand = &candidates[i];
        sm2_rev_route_node_t *temp = &temp_nodes[i];

        temp->enabled = true;
        temp->node_id_len = cand->node_id_len;
        if (cand->node_id_len > 0
            && cand->node_id_len <= SM2_REV_SYNC_NODE_ID_MAX_LEN)
            memcpy(temp->node_id, cand->node_id, cand->node_id_len);
        temp->base_weight = cand->health_score == 0 ? 1U : cand->health_score;
        temp->congestion_signal = cand->congestion_signal;
        temp->next_retry_ts = now_ts;
        temp->fail_streak = 0;

        const sm2_rev_route_node_t *state = find_route_node_state(
            route_nodes, route_node_count, cand->node_id, cand->node_id_len);
        if (state)
        {
            temp->enabled = state->enabled;
            temp->next_retry_ts = state->next_retry_ts;
            temp->fail_streak = state->fail_streak;
        }
    }

    ret = sm2_rev_route_pick_node(
        temp_nodes, candidate_count, now_ts, random_nonce, selected_index);
    free(temp_nodes);
    return ret;
}

sm2_ic_error_t sm2_rev_route_record_result(sm2_rev_route_node_t *route_nodes,
    size_t route_node_count,
    const sm2_rev_redirect_candidate_t *selected_candidate, bool success,
    uint64_t now_ts, uint64_t base_backoff_sec, uint64_t max_backoff_sec)
{
    if (!route_nodes || route_node_count == 0 || !selected_candidate)
        return SM2_IC_ERR_PARAM;

    sm2_rev_route_node_t *state
        = find_route_node_state_mut(route_nodes, route_node_count,
            selected_candidate->node_id, selected_candidate->node_id_len);
    if (!state)
        return SM2_IC_ERR_VERIFY;

    return sm2_rev_route_record_feedback(
        state, success, now_ts, base_backoff_sec, max_backoff_sec);
}

sm2_ic_error_t sm2_rev_route_verify_metadata(
    const sm2_rev_redirect_response_t *response,
    const sm2_rev_redirect_candidate_t *candidates, size_t candidate_count,
    const sm2_rev_trusted_node_t *trusted_nodes, size_t trusted_node_count,
    const uint8_t *signature, size_t signature_len,
    sm2_rev_sync_verify_fn verify_fn, void *verify_user_ctx)
{
    sm2_ic_error_t ret
        = sm2_rev_internal_validate_candidate_count(candidate_count);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    if (!response)
        return SM2_IC_ERR_PARAM;
    if (candidate_count > 0 && !candidates)
        return SM2_IC_ERR_PARAM;
    if (trusted_node_count > 0 && !trusted_nodes)
        return SM2_IC_ERR_PARAM;
    if (response->candidate_count != candidate_count)
        return SM2_IC_ERR_VERIFY;
    if (!response->redirect_required && candidate_count > 0)
        return SM2_IC_ERR_VERIFY;

    for (size_t i = 0; i < candidate_count; i++)
    {
        const sm2_rev_redirect_candidate_t *cand = &candidates[i];
        if (cand->node_id_len == 0
            || cand->node_id_len > SM2_REV_SYNC_NODE_ID_MAX_LEN)
            return SM2_IC_ERR_VERIFY;

        if (i > 0 && redirect_candidate_better(cand, &candidates[i - 1]))
            return SM2_IC_ERR_VERIFY;

        for (size_t j = 0; j < i; j++)
        {
            if (node_id_equal(cand->node_id, cand->node_id_len,
                    candidates[j].node_id, candidates[j].node_id_len))
            {
                return SM2_IC_ERR_VERIFY;
            }
        }

        if (trusted_node_count > 0)
        {
            bool trusted = false;
            for (size_t t = 0; t < trusted_node_count; t++)
            {
                if (node_id_equal(cand->node_id, cand->node_id_len,
                        trusted_nodes[t].node_id, trusted_nodes[t].node_id_len))
                {
                    trusted = true;
                    break;
                }
            }
            if (!trusted)
                return SM2_IC_ERR_VERIFY;
        }
    }

    if (response->redirect_required && signature_len == 0)
        return SM2_IC_ERR_VERIFY;

    if (signature_len > 0)
    {
        if (!verify_fn || !signature)
            return SM2_IC_ERR_PARAM;

        uint8_t *data = NULL;
        size_t data_len = 0;
        ret = serialize_redirect_metadata(
            response, candidates, candidate_count, &data, &data_len);
        if (ret != SM2_IC_SUCCESS)
            return ret;

        ret = verify_fn(
            verify_user_ctx, data, data_len, signature, signature_len);
        free(data);
        return ret == SM2_IC_SUCCESS ? SM2_IC_SUCCESS : SM2_IC_ERR_VERIFY;
    }

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_rev_route_pick_node(const sm2_rev_route_node_t *nodes,
    size_t node_count, uint64_t now_ts, uint64_t random_nonce,
    size_t *selected_index)
{
    if (!nodes || node_count == 0 || !selected_index)
        return SM2_IC_ERR_PARAM;

    bool has_non_overload = false;
    for (size_t i = 0; i < node_count; i++)
    {
        const sm2_rev_route_node_t *node = &nodes[i];
        if (node->next_retry_ts > now_ts)
            continue;
        if (route_effective_weight(node, true) == 0)
            continue;
        if (node->congestion_signal != SM2_REV_CONGESTION_OVERLOAD)
            has_non_overload = true;
    }

    uint64_t total_weight = 0;
    for (size_t i = 0; i < node_count; i++)
    {
        const sm2_rev_route_node_t *node = &nodes[i];
        if (node->next_retry_ts > now_ts)
            continue;

        uint32_t w = route_effective_weight(node, !has_non_overload);
        if (w == 0)
            continue;

        if (total_weight > UINT64_MAX - (uint64_t)w)
            total_weight = UINT64_MAX;
        else
            total_weight += (uint64_t)w;
    }

    if (total_weight == 0)
        return SM2_IC_ERR_VERIFY;

    uint64_t ticket = random_nonce % total_weight;
    for (size_t i = 0; i < node_count; i++)
    {
        const sm2_rev_route_node_t *node = &nodes[i];
        if (node->next_retry_ts > now_ts)
            continue;

        uint32_t w = route_effective_weight(node, !has_non_overload);
        if (w == 0)
            continue;

        if (ticket < (uint64_t)w)
        {
            *selected_index = i;
            return SM2_IC_SUCCESS;
        }
        ticket -= (uint64_t)w;
    }

    return SM2_IC_ERR_VERIFY;
}

sm2_ic_error_t sm2_rev_route_record_feedback(sm2_rev_route_node_t *node,
    bool success, uint64_t now_ts, uint64_t base_backoff_sec,
    uint64_t max_backoff_sec)
{
    if (!node || base_backoff_sec == 0 || max_backoff_sec < base_backoff_sec)
        return SM2_IC_ERR_PARAM;

    if (success)
    {
        node->fail_streak = 0;
        node->next_retry_ts = now_ts;
        return SM2_IC_SUCCESS;
    }

    if (node->fail_streak < UINT32_MAX)
        node->fail_streak++;

    uint32_t shift = node->fail_streak == 0 ? 0U : (node->fail_streak - 1U);
    if (shift > 30U)
        shift = 30U;

    uint64_t backoff = base_backoff_sec;
    if (shift > 0)
    {
        if (backoff > (UINT64_MAX >> shift))
            backoff = UINT64_MAX;
        else
            backoff <<= shift;
    }

    if (backoff > max_backoff_sec)
        backoff = max_backoff_sec;

    if (now_ts > UINT64_MAX - backoff)
        node->next_retry_ts = UINT64_MAX;
    else
        node->next_retry_ts = now_ts + backoff;

    return SM2_IC_SUCCESS;
}
