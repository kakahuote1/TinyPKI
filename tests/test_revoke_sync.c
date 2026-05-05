/* SPDX-License-Identifier: Apache-2.0 */

#include "test_revoke_helpers.h"

static void test_revocation_phase11_sync_hello_and_plan(void)
{
    sm2_rev_ctx_t *ctx = NULL;
    TEST_ASSERT(
        sm2_rev_init(&ctx, 16, 120, 100) == SM2_IC_SUCCESS, "Revocation Init");

    sm2_rev_delta_t delta = { 0, 2, NULL, 0 };
    TEST_ASSERT(
        sm2_rev_apply_delta(ctx, &delta, 110) == SM2_IC_SUCCESS, "Apply Delta");
    TEST_ASSERT(
        sm2_rev_set_query_inflight(ctx, 90) == SM2_IC_SUCCESS, "Set Inflight");

    uint8_t local_root[SM2_REV_SYNC_DIGEST_LEN];
    TEST_ASSERT(
        sm2_rev_root_hash(ctx, local_root) == SM2_IC_SUCCESS, "Read Root Hash");

    const uint8_t node_id[] = "NODE-A";
    sm2_rev_sync_hello_t local_hello;
    TEST_ASSERT(sm2_rev_sync_build_hello(
                    ctx, node_id, sizeof(node_id) - 1, 120, &local_hello)
            == SM2_IC_SUCCESS,
        "Build Local Hello");
    TEST_ASSERT(local_hello.root_version == 2, "Hello Version");
    TEST_ASSERT(
        memcmp(local_hello.root_hash, local_root, sizeof(local_root)) == 0,
        "Hello Root Hash Bound To Context");
    TEST_ASSERT(local_hello.congestion_signal == SM2_REV_CONGESTION_BUSY,
        "Hello Congestion");

    sm2_rev_sync_hello_t remote_hello = local_hello;
    remote_hello.root_version = 5;
    memset(remote_hello.root_hash, 0x22, sizeof(remote_hello.root_hash));

    sm2_rev_sync_delta_plan_t plan;
    TEST_ASSERT(sm2_rev_sync_plan_delta(&local_hello, &remote_hello, &plan)
            == SM2_IC_SUCCESS,
        "Plan Pull Delta");
    TEST_ASSERT(plan.direction == SM2_REV_DELTA_DIR_PULL, "Plan Pull Dir");
    TEST_ASSERT(
        plan.from_version == 2 && plan.to_version == 5, "Plan Pull Range");

    TEST_ASSERT(sm2_rev_sync_plan_delta(&remote_hello, &local_hello, &plan)
            == SM2_IC_SUCCESS,
        "Plan Push Delta");
    TEST_ASSERT(plan.direction == SM2_REV_DELTA_DIR_PUSH, "Plan Push Dir");
    TEST_ASSERT(
        plan.from_version == 2 && plan.to_version == 5, "Plan Push Range");

    remote_hello.root_version = local_hello.root_version;
    memset(remote_hello.root_hash, 0x33, sizeof(remote_hello.root_hash));
    TEST_ASSERT(sm2_rev_sync_plan_delta(&local_hello, &remote_hello, &plan)
            == SM2_IC_ERR_VERIFY,
        "Plan Fork Detect");
    TEST_ASSERT(plan.fork_detected, "Fork Flag");

    sm2_rev_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_phase11_patch_link_and_redirect(void)
{
    sm2_rev_ctx_t *ctx = NULL;
    TEST_ASSERT(
        sm2_rev_init(&ctx, 8, 60, 100) == SM2_IC_SUCCESS, "Revocation Init");

    sm2_rev_delta_t delta = { 0, 10, NULL, 0 };
    TEST_ASSERT(
        sm2_rev_apply_delta(ctx, &delta, 110) == SM2_IC_SUCCESS, "Apply Delta");

    uint8_t local_root[SM2_REV_SYNC_DIGEST_LEN];
    memset(local_root, 0xAB, sizeof(local_root));

    sm2_rev_patch_link_t patch;
    memset(&patch, 0, sizeof(patch));
    patch.prev_version = 10;
    patch.new_version = 11;
    patch.issued_at = 120;
    patch.valid_until = 160;
    memcpy(patch.prev_root_hash, local_root, sizeof(local_root));
    memset(patch.new_root_hash, 0xCD, sizeof(patch.new_root_hash));

    TEST_ASSERT(sm2_rev_sync_verify_patch_link(&patch, 10, local_root, 130, 5)
            == SM2_IC_SUCCESS,
        "Patch Link Verify");

    patch.prev_version = 9;
    TEST_ASSERT(sm2_rev_sync_verify_patch_link(&patch, 10, local_root, 130, 5)
            == SM2_IC_ERR_VERIFY,
        "Patch Prev Version Reject");
    patch.prev_version = 10;

    patch.prev_root_hash[0] ^= 0x01;
    TEST_ASSERT(sm2_rev_sync_verify_patch_link(&patch, 10, local_root, 130, 5)
            == SM2_IC_ERR_VERIFY,
        "Patch Prev Hash Reject");
    patch.prev_root_hash[0] ^= 0x01;

    patch.valid_until = 110;
    TEST_ASSERT(sm2_rev_sync_verify_patch_link(&patch, 10, local_root, 130, 5)
            == SM2_IC_ERR_PARAM,
        "Patch Invalid Window");
    patch.valid_until = 160;

    sm2_rev_sync_freshness_t freshness;
    bool redirect = false;
    TEST_ASSERT(
        sm2_rev_check_freshness(ctx, 165, 5, &freshness) == SM2_IC_SUCCESS,
        "Assess Freshness");
    TEST_ASSERT(freshness == SM2_REV_FRESHNESS_STALE, "Freshness Stale");

    TEST_ASSERT(
        sm2_rev_sync_should_redirect(ctx, 20, 5, 130, 5, &redirect, &freshness)
            == SM2_IC_SUCCESS,
        "Redirect Lag Check");
    TEST_ASSERT(redirect, "Redirect By Lag");

    TEST_ASSERT(
        sm2_rev_sync_should_redirect(ctx, 12, 5, 130, 5, &redirect, &freshness)
            == SM2_IC_SUCCESS,
        "Redirect No Lag");
    TEST_ASSERT(!redirect, "No Redirect When Acceptable");

    TEST_ASSERT(
        sm2_rev_sync_should_redirect(ctx, 10, 5, 200, 0, &redirect, &freshness)
            == SM2_IC_SUCCESS,
        "Redirect Expired");
    TEST_ASSERT(redirect, "Redirect By Expire");
    TEST_ASSERT(freshness == SM2_REV_FRESHNESS_EXPIRED, "Freshness Expired");

    sm2_rev_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_phase11_sync_apply_and_rank_candidates(void)
{
    sm2_rev_ctx_t *ctx = NULL;
    TEST_ASSERT(
        sm2_rev_init(&ctx, 8, 120, 100) == SM2_IC_SUCCESS, "Revocation Init");

    sm2_rev_delta_t bootstrap = { 0, 2, NULL, 0 };
    TEST_ASSERT(sm2_rev_apply_delta(ctx, &bootstrap, 110) == SM2_IC_SUCCESS,
        "Bootstrap Delta");

    sm2_rev_sync_delta_plan_t plan;
    memset(&plan, 0, sizeof(plan));
    plan.direction = SM2_REV_DELTA_DIR_PULL;
    plan.from_version = 2;
    plan.to_version = 4;

    sm2_rev_delta_item_t items1[] = { { 5001, true } };
    sm2_rev_delta_t delta1 = { 2, 3, items1, 1 };
    bool converged = false;
    TEST_ASSERT(sm2_rev_sync_apply_delta(ctx, &plan, &delta1, 120, &converged)
            == SM2_IC_SUCCESS,
        "Apply Planned Delta 1");
    TEST_ASSERT(!converged, "Not Converged After Delta 1");
    TEST_ASSERT(sm2_rev_version(ctx) == 3, "Version After Delta 1");

    sm2_rev_delta_item_t items2[] = { { 5002, true } };
    sm2_rev_delta_t delta2 = { 3, 4, items2, 1 };
    TEST_ASSERT(sm2_rev_sync_apply_delta(ctx, &plan, &delta2, 130, &converged)
            == SM2_IC_SUCCESS,
        "Apply Planned Delta 2");
    TEST_ASSERT(converged, "Converged After Delta 2");
    TEST_ASSERT(sm2_rev_version(ctx) == 4, "Version After Delta 2");
    TEST_ASSERT(sm2_rev_local_count(ctx) == 2, "Local Count After Apply");

    sm2_rev_sync_delta_plan_t push_plan = plan;
    push_plan.direction = SM2_REV_DELTA_DIR_PUSH;
    TEST_ASSERT(
        sm2_rev_sync_apply_delta(ctx, &push_plan, &delta2, 130, &converged)
            == SM2_IC_ERR_VERIFY,
        "Push Plan Reject");

    sm2_rev_node_health_sample_t samples[5];
    memset(samples, 0, sizeof(samples));

    memcpy(samples[0].route.node_id, "node-a", 6);
    samples[0].route.node_id_len = 6;
    samples[0].route.base_weight = 120;
    samples[0].route.congestion_signal = SM2_REV_CONGESTION_NORMAL;
    samples[0].route.enabled = true;
    samples[0].root_version = 4;
    samples[0].root_valid_until = 260;
    samples[0].rtt_ms = 100;

    memcpy(samples[1].route.node_id, "node-b", 6);
    samples[1].route.node_id_len = 6;
    samples[1].route.base_weight = 120;
    samples[1].route.congestion_signal = SM2_REV_CONGESTION_BUSY;
    samples[1].route.enabled = true;
    samples[1].root_version = 5;
    samples[1].root_valid_until = 280;
    samples[1].rtt_ms = 20;

    memcpy(samples[2].route.node_id, "node-c", 6);
    samples[2].route.node_id_len = 6;
    samples[2].route.base_weight = 120;
    samples[2].route.congestion_signal = SM2_REV_CONGESTION_NORMAL;
    samples[2].route.enabled = true;
    samples[2].route.next_retry_ts = 999;
    samples[2].root_version = 6;
    samples[2].root_valid_until = 300;
    samples[2].rtt_ms = 10;

    memcpy(samples[3].route.node_id, "node-d", 6);
    samples[3].route.node_id_len = 6;
    samples[3].route.base_weight = 120;
    samples[3].route.congestion_signal = SM2_REV_CONGESTION_NORMAL;
    samples[3].route.enabled = true;
    samples[3].root_version = 6;
    samples[3].root_valid_until = 120;
    samples[3].rtt_ms = 10;

    memcpy(samples[4].route.node_id, "node-b", 6);
    samples[4].route.node_id_len = 6;
    samples[4].route.base_weight = 120;
    samples[4].route.congestion_signal = SM2_REV_CONGESTION_NORMAL;
    samples[4].route.enabled = true;
    samples[4].root_version = 4;
    samples[4].root_valid_until = 260;
    samples[4].rtt_ms = 200;

    sm2_rev_redirect_candidate_t candidates[5];
    size_t candidate_count = 0;
    TEST_ASSERT(sm2_rev_route_rank_candidates(
                    samples, 5, 4, 130, 5, 5, candidates, &candidate_count)
            == SM2_IC_SUCCESS,
        "Rank Redirect Candidates");
    TEST_ASSERT(candidate_count == 2, "Healthy Candidate Count Deduped");
    TEST_ASSERT(candidates[0].node_id_len == 6, "Candidate 0 Len");
    TEST_ASSERT(
        memcmp(candidates[0].node_id, "node-b", 6) == 0, "Candidate 0 Order");
    TEST_ASSERT(
        memcmp(candidates[1].node_id, "node-a", 6) == 0, "Candidate 1 Order");
    TEST_ASSERT(candidates[0].rtt_ms == 20, "Duplicate Keeps Better Candidate");

    sm2_rev_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_phase11_redirect_response(void)
{
    sm2_rev_ctx_t *ctx = NULL;
    TEST_ASSERT(
        sm2_rev_init(&ctx, 8, 60, 100) == SM2_IC_SUCCESS, "Revocation Init");

    sm2_rev_delta_t bootstrap = { 0, 4, NULL, 0 };
    TEST_ASSERT(sm2_rev_apply_delta(ctx, &bootstrap, 110) == SM2_IC_SUCCESS,
        "Bootstrap Delta");

    sm2_rev_node_health_sample_t samples[2];
    memset(samples, 0, sizeof(samples));

    memcpy(samples[0].route.node_id, "node-x", 6);
    samples[0].route.node_id_len = 6;
    samples[0].route.base_weight = 80;
    samples[0].route.congestion_signal = SM2_REV_CONGESTION_NORMAL;
    samples[0].route.enabled = true;
    samples[0].root_version = 6;
    samples[0].root_valid_until = 260;
    samples[0].rtt_ms = 25;

    memcpy(samples[1].route.node_id, "node-y", 6);
    samples[1].route.node_id_len = 6;
    samples[1].route.base_weight = 80;
    samples[1].route.congestion_signal = SM2_REV_CONGESTION_BUSY;
    samples[1].route.enabled = true;
    samples[1].root_version = 5;
    samples[1].root_valid_until = 260;
    samples[1].rtt_ms = 25;

    sm2_rev_redirect_response_t response;
    sm2_rev_redirect_candidate_t candidates[2];
    size_t candidate_count = 0;
    TEST_ASSERT(sm2_rev_route_build_response(ctx, 6, 1, 130, 5, samples, 2, 2,
                    &response, candidates, &candidate_count)
            == SM2_IC_SUCCESS,
        "Build Redirect Response");
    TEST_ASSERT(response.redirect_required, "Redirect Required");
    TEST_ASSERT(response.reason == SM2_REV_REDIRECT_REASON_VERSION_STALE,
        "Redirect Reason Stale");
    TEST_ASSERT(candidate_count == 1, "Redirect Candidate Count");
    TEST_ASSERT(memcmp(candidates[0].node_id, "node-x", 6) == 0,
        "Redirect Candidate Picked");

    TEST_ASSERT(sm2_rev_route_build_response(ctx, 6, 1, 500, 0, NULL, 0, 2,
                    &response, candidates, &candidate_count)
            == SM2_IC_SUCCESS,
        "Build Redirect Response No Healthy Node");
    TEST_ASSERT(response.redirect_required, "Redirect Required No Healthy");
    TEST_ASSERT(response.reason == SM2_REV_REDIRECT_REASON_NO_HEALTHY_NODE,
        "Redirect Reason No Healthy Node");
    TEST_ASSERT(candidate_count == 0, "No Healthy Candidate Count");

    sm2_rev_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_phase11_auto_switch_and_feedback(void)
{
    sm2_rev_redirect_response_t response;
    memset(&response, 0, sizeof(response));
    response.redirect_required = true;
    response.reason = SM2_REV_REDIRECT_REASON_VERSION_STALE;
    response.freshness = SM2_REV_FRESHNESS_STALE;
    response.local_version = 10;
    response.known_latest_version = 12;
    response.now_ts = 200;
    response.candidate_count = 2;

    sm2_rev_redirect_candidate_t candidates[2];
    memset(candidates, 0, sizeof(candidates));
    memcpy(candidates[0].node_id, "node-a", 6);
    candidates[0].node_id_len = 6;
    candidates[0].root_version = 12;
    candidates[0].root_valid_until = 400;
    candidates[0].rtt_ms = 10;
    candidates[0].health_score = 900;
    candidates[0].congestion_signal = SM2_REV_CONGESTION_NORMAL;

    memcpy(candidates[1].node_id, "node-b", 6);
    candidates[1].node_id_len = 6;
    candidates[1].root_version = 12;
    candidates[1].root_valid_until = 400;
    candidates[1].rtt_ms = 20;
    candidates[1].health_score = 800;
    candidates[1].congestion_signal = SM2_REV_CONGESTION_NORMAL;

    sm2_rev_route_node_t route_nodes[2];
    memset(route_nodes, 0, sizeof(route_nodes));
    memcpy(route_nodes[0].node_id, "node-a", 6);
    route_nodes[0].node_id_len = 6;
    route_nodes[0].base_weight = 100;
    route_nodes[0].enabled = true;
    route_nodes[0].next_retry_ts = 500;

    memcpy(route_nodes[1].node_id, "node-b", 6);
    route_nodes[1].node_id_len = 6;
    route_nodes[1].base_weight = 100;
    route_nodes[1].enabled = true;
    route_nodes[1].next_retry_ts = 200;

    size_t picked = 0;
    TEST_ASSERT(sm2_rev_route_pick_candidate(
                    &response, candidates, 2, route_nodes, 2, 200, 7, &picked)
            == SM2_IC_SUCCESS,
        "Select Redirect Candidate");
    TEST_ASSERT(picked == 1, "Pick Available Candidate");

    TEST_ASSERT(sm2_rev_route_record_result(
                    route_nodes, 2, &candidates[picked], false, 200, 5, 20)
            == SM2_IC_SUCCESS,
        "Record Redirect Failure");
    TEST_ASSERT(route_nodes[1].fail_streak == 1, "Fail Streak Increased");
    TEST_ASSERT(route_nodes[1].next_retry_ts > 200, "Backoff Applied");

    TEST_ASSERT(sm2_rev_route_pick_candidate(
                    &response, candidates, 2, route_nodes, 2, 202, 7, &picked)
            == SM2_IC_ERR_VERIFY,
        "No Candidate During Backoff");

    TEST_ASSERT(sm2_rev_route_record_result(
                    route_nodes, 2, &candidates[1], true, 206, 5, 20)
            == SM2_IC_SUCCESS,
        "Record Redirect Success");
    TEST_ASSERT(route_nodes[1].fail_streak == 0, "Fail Streak Reset");

    TEST_ASSERT(sm2_rev_route_pick_candidate(
                    &response, candidates, 2, route_nodes, 2, 206, 11, &picked)
            == SM2_IC_SUCCESS,
        "Select Redirect Candidate After Recovery");
    TEST_ASSERT(picked == 1, "Pick Recovered Candidate");

    TEST_PASS();
}

static void test_revocation_phase11_redirect_metadata_integrity(void)
{
    sm2_rev_redirect_response_t response;
    memset(&response, 0, sizeof(response));
    response.redirect_required = true;
    response.reason = SM2_REV_REDIRECT_REASON_VERSION_STALE;
    response.freshness = SM2_REV_FRESHNESS_STALE;
    response.local_version = 9;
    response.known_latest_version = 11;
    response.now_ts = 300;
    response.candidate_count = 2;

    sm2_rev_redirect_candidate_t candidates[2];
    memset(candidates, 0, sizeof(candidates));
    memcpy(candidates[0].node_id, "node-x", 6);
    candidates[0].node_id_len = 6;
    candidates[0].root_version = 11;
    candidates[0].root_valid_until = 500;
    candidates[0].rtt_ms = 20;
    candidates[0].health_score = 900;
    candidates[0].congestion_signal = SM2_REV_CONGESTION_NORMAL;

    memcpy(candidates[1].node_id, "node-y", 6);
    candidates[1].node_id_len = 6;
    candidates[1].root_version = 11;
    candidates[1].root_valid_until = 500;
    candidates[1].rtt_ms = 40;
    candidates[1].health_score = 700;
    candidates[1].congestion_signal = SM2_REV_CONGESTION_BUSY;

    sm2_rev_trusted_node_t trusted[2];
    memset(trusted, 0, sizeof(trusted));
    memcpy(trusted[0].node_id, "node-x", 6);
    trusted[0].node_id_len = 6;
    memcpy(trusted[1].node_id, "node-y", 6);
    trusted[1].node_id_len = 6;

    mock_redirect_verify_ctx_t verify_ctx;
    memset(&verify_ctx, 0, sizeof(verify_ctx));
    verify_ctx.expect_tag = 0xA5;

    uint8_t signature[1] = { 0xA5 };
    TEST_ASSERT(
        sm2_rev_route_verify_metadata(&response, candidates, 2, trusted, 2,
            signature, sizeof(signature), mock_redirect_verify, &verify_ctx)
            == SM2_IC_SUCCESS,
        "Verify Redirect Metadata Signature");
    TEST_ASSERT(verify_ctx.called, "Verify Callback Called");
    verify_ctx.called = false;

    TEST_ASSERT(
        sm2_rev_route_verify_metadata(&response, candidates, 2, NULL, 0,
            signature, sizeof(signature), mock_redirect_verify, &verify_ctx)
            == SM2_IC_SUCCESS,
        "Verify Signature Without Trusted List");
    TEST_ASSERT(verify_ctx.called, "Verify Callback Called Without Trusted");

    sm2_rev_redirect_candidate_t unsorted[2];
    memcpy(unsorted, candidates, sizeof(unsorted));
    sm2_rev_redirect_candidate_t tmp = unsorted[0];
    unsorted[0] = unsorted[1];
    unsorted[1] = tmp;
    TEST_ASSERT(
        sm2_rev_route_verify_metadata(&response, unsorted, 2, trusted, 2,
            signature, sizeof(signature), mock_redirect_verify, &verify_ctx)
            == SM2_IC_ERR_VERIFY,
        "Reject Unsorted Candidates");

    TEST_ASSERT(sm2_rev_route_verify_metadata(
                    &response, candidates, 2, trusted, 1, NULL, 0, NULL, NULL)
            == SM2_IC_ERR_VERIFY,
        "Reject Untrusted Candidate");

    TEST_ASSERT(sm2_rev_route_verify_metadata(
                    &response, candidates, 2, trusted, 2, NULL, 0, NULL, NULL)
            == SM2_IC_ERR_VERIFY,
        "Reject Unsigned Metadata With Trusted List");

    TEST_ASSERT(sm2_rev_route_verify_metadata(
                    &response, candidates, 2, NULL, 0, NULL, 0, NULL, NULL)
            == SM2_IC_ERR_VERIFY,
        "Reject Unsigned Metadata Without Signature");

    sm2_rev_redirect_response_t zero_candidate = response;
    zero_candidate.reason = SM2_REV_REDIRECT_REASON_NO_HEALTHY_NODE;
    zero_candidate.candidate_count = 0;
    verify_ctx.called = false;
    TEST_ASSERT(
        sm2_rev_route_verify_metadata(&zero_candidate, NULL, 0, NULL, 0,
            signature, sizeof(signature), mock_redirect_verify, &verify_ctx)
            == SM2_IC_SUCCESS,
        "Accept Signed Redirect Without Candidates");
    TEST_ASSERT(verify_ctx.called, "Verify Zero Candidate Metadata");

    TEST_ASSERT(sm2_rev_route_verify_metadata(
                    &zero_candidate, NULL, 0, NULL, 0, NULL, 0, NULL, NULL)
            == SM2_IC_ERR_VERIFY,
        "Reject Unsigned Redirect Without Candidates");

    TEST_PASS();
}

static void test_revocation_phase11_policy_heartbeat_and_upper_bound(void)
{
    sm2_rev_ctx_t *ctx = NULL;
    TEST_ASSERT(
        sm2_rev_init(&ctx, 8, 60, 100) == SM2_IC_SUCCESS, "Revocation Init");
    TEST_ASSERT(sm2_rev_set_clock_skew_tolerance(ctx, 5) == SM2_IC_SUCCESS,
        "Set Clock Skew");

    sm2_rev_delta_t delta = { 0, 10, NULL, 0 };
    TEST_ASSERT(
        sm2_rev_apply_delta(ctx, &delta, 110) == SM2_IC_SUCCESS, "Apply Delta");

    sm2_rev_sync_policy_t policy;
    TEST_ASSERT(sm2_rev_sync_policy_init(&policy) == SM2_IC_SUCCESS,
        "Init Sync Policy");
    TEST_ASSERT(policy.t_base_sec == 60, "Policy Base");
    TEST_ASSERT(policy.fast_poll_sec == 15, "Policy Fast");
    TEST_ASSERT(policy.max_backoff_sec == 300, "Policy Max Backoff");

    sm2_rev_sync_schedule_t schedule;
    TEST_ASSERT(sm2_rev_sync_plan_schedule(ctx, &policy, 10, 0, 120, &schedule)
            == SM2_IC_SUCCESS,
        "Plan Base Schedule");
    TEST_ASSERT(schedule.next_pull_after_sec == 60, "Base Interval");
    TEST_ASSERT(!schedule.accelerated_mode, "Base Not Accelerated");
    TEST_ASSERT(!schedule.heartbeat_refresh_only, "Base No Heartbeat");
    TEST_ASSERT(
        schedule.staleness_upper_bound_sec == 95, "Staleness Upper Bound");

    TEST_ASSERT(sm2_rev_sync_plan_schedule(ctx, &policy, 12, 0, 120, &schedule)
            == SM2_IC_SUCCESS,
        "Plan Accelerated Schedule");
    TEST_ASSERT(schedule.accelerated_mode, "Accelerated Mode");
    TEST_ASSERT(schedule.next_pull_after_sec == 15, "Fast Interval");

    TEST_ASSERT(sm2_rev_sync_plan_schedule(ctx, &policy, 10, 3, 120, &schedule)
            == SM2_IC_SUCCESS,
        "Plan Backoff Schedule");
    TEST_ASSERT(schedule.next_pull_after_sec == 240, "Backoff Interval");

    TEST_ASSERT(sm2_rev_sync_plan_schedule(ctx, &policy, 10, 0, 165, &schedule)
            == SM2_IC_SUCCESS,
        "Plan Heartbeat Schedule");
    TEST_ASSERT(schedule.heartbeat_refresh_only, "Heartbeat Only");
    TEST_ASSERT(schedule.next_pull_after_sec == 15, "Heartbeat Fast Interval");

    uint8_t root_hash[SM2_REV_SYNC_DIGEST_LEN];
    TEST_ASSERT(
        sm2_rev_root_hash(ctx, root_hash) == SM2_IC_SUCCESS, "Read Root Hash");
    sm2_rev_heartbeat_patch_t heartbeat;
    TEST_ASSERT(sm2_rev_sync_build_heartbeat(
                    sm2_rev_version(ctx), root_hash, 166, 260, &heartbeat)
            == SM2_IC_SUCCESS,
        "Build Heartbeat");
    TEST_ASSERT(heartbeat.object_type == SM2_REV_SYNC_OBJECT_HEARTBEAT_PATCH,
        "Heartbeat Object Type");
    TEST_ASSERT(sm2_rev_sync_verify_heartbeat(
                    &heartbeat, sm2_rev_version(ctx), root_hash, 170, 5)
            == SM2_IC_SUCCESS,
        "Verify Heartbeat");
    TEST_ASSERT(
        sm2_rev_sync_apply_heartbeat(ctx, &heartbeat, 170) == SM2_IC_SUCCESS,
        "Apply Heartbeat");
    TEST_ASSERT(sm2_rev_version(ctx) == 11, "Heartbeat Version Increment");
    TEST_ASSERT(sm2_rev_local_count(ctx) == 0, "Heartbeat Keeps Local List");
    TEST_ASSERT(
        sm2_rev_root_valid_until(ctx) == 260, "Heartbeat Refresh ValidUntil");

    uint64_t upper_bound = 0;
    TEST_ASSERT(sm2_rev_sync_staleness_bound(&policy, 5, &upper_bound)
            == SM2_IC_SUCCESS,
        "Compute Upper Bound");
    TEST_ASSERT(upper_bound == 95, "Upper Bound Formula");

    sm2_rev_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_phase11_network_partition_and_reconnect(void)
{
    sm2_rev_ctx_t *ctx = NULL;
    TEST_ASSERT(
        sm2_rev_init(&ctx, 8, 60, 100) == SM2_IC_SUCCESS, "Revocation Init");
    TEST_ASSERT(sm2_rev_set_clock_skew_tolerance(ctx, 5) == SM2_IC_SUCCESS,
        "Set Clock Skew");

    sm2_rev_delta_t bootstrap = { 0, 2, NULL, 0 };
    TEST_ASSERT(sm2_rev_apply_delta(ctx, &bootstrap, 110) == SM2_IC_SUCCESS,
        "Bootstrap Delta");

    sm2_rev_sync_hello_t local_hello;
    uint8_t local_root[SM2_REV_SYNC_DIGEST_LEN];
    TEST_ASSERT(
        sm2_rev_root_hash(ctx, local_root) == SM2_IC_SUCCESS, "Read Root Hash");
    TEST_ASSERT(sm2_rev_sync_build_hello(
                    ctx, (const uint8_t *)"node-l", 6, 120, &local_hello)
            == SM2_IC_SUCCESS,
        "Build Local Hello");
    TEST_ASSERT(
        memcmp(local_hello.root_hash, local_root, sizeof(local_root)) == 0,
        "Reconnect Hello Root Hash Bound To Context");

    sm2_rev_sync_hello_t remote_hello = local_hello;
    remote_hello.root_version = 5;
    remote_hello.root_valid_until = 260;
    memset(remote_hello.root_hash, 0x22, sizeof(remote_hello.root_hash));

    sm2_rev_sync_delta_plan_t plan;
    TEST_ASSERT(sm2_rev_sync_plan_delta(&local_hello, &remote_hello, &plan)
            == SM2_IC_SUCCESS,
        "Plan Reconnect Pull");
    TEST_ASSERT(plan.direction == SM2_REV_DELTA_DIR_PULL, "Reconnect Pull Dir");

    sm2_rev_route_node_t route_node;
    memset(&route_node, 0, sizeof(route_node));
    memcpy(route_node.node_id, "node-r", 6);
    route_node.node_id_len = 6;
    route_node.base_weight = 100;
    route_node.enabled = true;
    TEST_ASSERT(sm2_rev_route_record_feedback(&route_node, false, 126, 5, 20)
            == SM2_IC_SUCCESS,
        "Partition Feedback Failure");
    size_t route_index = 0;
    TEST_ASSERT(sm2_rev_route_pick_node(&route_node, 1, 127, 1, &route_index)
            == SM2_IC_ERR_VERIFY,
        "Partition Select Reject");
    TEST_ASSERT(sm2_rev_route_record_feedback(&route_node, true, 131, 5, 20)
            == SM2_IC_SUCCESS,
        "Reconnect Feedback Success");
    TEST_ASSERT(sm2_rev_route_pick_node(&route_node, 1, 132, 1, &route_index)
            == SM2_IC_SUCCESS,
        "Reconnect Select Success");

    bool converged = false;
    size_t rounds = 0;
    sm2_rev_delta_t d1 = { 2, 3, NULL, 0 };
    sm2_rev_delta_t d2 = { 3, 4, NULL, 0 };
    sm2_rev_delta_t d3 = { 4, 5, NULL, 0 };
    TEST_ASSERT(sm2_rev_sync_apply_delta(ctx, &plan, &d1, 132, &converged)
            == SM2_IC_SUCCESS,
        "Apply Delta 1");
    rounds++;
    TEST_ASSERT(!converged, "Round 1 Not Converged");
    TEST_ASSERT(sm2_rev_sync_apply_delta(ctx, &plan, &d2, 136, &converged)
            == SM2_IC_SUCCESS,
        "Apply Delta 2");
    rounds++;
    TEST_ASSERT(!converged, "Round 2 Not Converged");
    TEST_ASSERT(sm2_rev_sync_apply_delta(ctx, &plan, &d3, 140, &converged)
            == SM2_IC_SUCCESS,
        "Apply Delta 3");
    rounds++;
    TEST_ASSERT(converged, "Round 3 Converged");
    TEST_ASSERT(rounds == 3, "Converged Within Three Rounds");
    TEST_ASSERT(sm2_rev_version(ctx) == 5, "Reconnect Version Updated");

    sm2_rev_node_health_sample_t sample;
    memset(&sample, 0, sizeof(sample));
    memcpy(sample.route.node_id, "node-r", 6);
    sample.route.node_id_len = 6;
    sample.route.base_weight = 100;
    sample.route.enabled = true;
    sample.root_version = 5;
    sample.root_valid_until = 520;
    sample.rtt_ms = 20;

    sm2_rev_redirect_response_t response;
    sm2_rev_redirect_candidate_t candidate;
    size_t candidate_count = 0;
    TEST_ASSERT(sm2_rev_route_build_response(ctx, 5, 1, 400, 5, &sample, 1, 1,
                    &response, &candidate, &candidate_count)
            == SM2_IC_SUCCESS,
        "Build Redirect After Expire");
    TEST_ASSERT(response.redirect_required, "Expired Node Redirects");
    TEST_ASSERT(response.reason == SM2_REV_REDIRECT_REASON_EXPIRED,
        "Expired Redirect Reason");
    TEST_ASSERT(candidate_count == 1, "Redirect Candidate Available");

    sm2_rev_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_phase12_redirect_candidate_count_bounds(void)
{
    sm2_rev_node_health_sample_t sample;
    memset(&sample, 0, sizeof(sample));
    memcpy(sample.route.node_id, "node-z", 6);
    sample.route.node_id_len = 6;
    sample.route.base_weight = 100;
    sample.route.enabled = true;
    sample.root_version = 9;
    sample.root_valid_until = 300;
    sample.rtt_ms = 10;

    sm2_rev_redirect_candidate_t candidate;
    size_t candidate_count = 0;
    TEST_ASSERT(
        sm2_rev_route_rank_candidates(&sample, 1, 9, 100, 5,
            SM2_REV_REDIRECT_MAX_CANDIDATES + 1, &candidate, &candidate_count)
            == SM2_IC_ERR_PARAM,
        "Reject Oversized Candidate Capacity");

    sm2_rev_ctx_t *ctx = NULL;
    TEST_ASSERT(
        sm2_rev_init(&ctx, 4, 60, 100) == SM2_IC_SUCCESS, "Revocation Init");
    TEST_ASSERT(sm2_rev_route_build_response(ctx, 10, 1, 100, 5, &sample, 1,
                    SM2_REV_REDIRECT_MAX_CANDIDATES + 1, NULL, &candidate,
                    &candidate_count)
            == SM2_IC_ERR_PARAM,
        "Reject Oversized Redirect Capacity");
    sm2_rev_cleanup(&ctx);

    sm2_rev_redirect_response_t response;
    memset(&response, 0, sizeof(response));
    response.redirect_required = true;
    response.candidate_count = SM2_REV_REDIRECT_MAX_CANDIDATES + 1;
    TEST_ASSERT(
        sm2_rev_route_verify_metadata(&response, &candidate,
            SM2_REV_REDIRECT_MAX_CANDIDATES + 1, NULL, 0, NULL, 0, NULL, NULL)
            == SM2_IC_ERR_PARAM,
        "Reject Oversized Candidate Count");

    TEST_PASS();
}
void run_test_revoke_sync_suite(void)
{
    RUN_TEST(test_revocation_phase11_sync_hello_and_plan);
    RUN_TEST(test_revocation_phase11_patch_link_and_redirect);
    RUN_TEST(test_revocation_phase11_sync_apply_and_rank_candidates);
    RUN_TEST(test_revocation_phase11_redirect_response);
    RUN_TEST(test_revocation_phase11_auto_switch_and_feedback);
    RUN_TEST(test_revocation_phase11_redirect_metadata_integrity);
    RUN_TEST(test_revocation_phase11_policy_heartbeat_and_upper_bound);
    RUN_TEST(test_revocation_phase11_network_partition_and_reconnect);
    RUN_TEST(test_revocation_phase12_redirect_candidate_count_bounds);
}
