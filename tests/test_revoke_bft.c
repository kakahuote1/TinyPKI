/* SPDX-License-Identifier: Apache-2.0 */

#include "test_revoke_helpers.h"

static void test_revocation_phase11_bft_quorum_accepts_trusted_votes(void)
{
    uint8_t local_root[SM2_REV_SYNC_DIGEST_LEN];
    memset(local_root, 0xAA, sizeof(local_root));

    sm2_rev_patch_link_t patch;
    memset(&patch, 0, sizeof(patch));
    patch.prev_version = 10;
    patch.new_version = 11;
    patch.issued_at = 120;
    patch.valid_until = 220;
    memcpy(patch.prev_root_hash, local_root, sizeof(local_root));
    memset(patch.new_root_hash, 0xBB, sizeof(patch.new_root_hash));

    sm2_rev_quorum_vote_t votes[3];
    memset(votes, 0, sizeof(votes));
    memcpy(votes[0].node_id, "node-a", 6);
    votes[0].node_id_len = 6;
    votes[0].root_version = 12;
    votes[0].status = SM2_REV_STATUS_GOOD;
    votes[0].proof_valid = true;
    memset(votes[0].root_hash, 0x11, SM2_REV_SYNC_DIGEST_LEN);

    memcpy(votes[1].node_id, "node-b", 6);
    votes[1].node_id_len = 6;
    votes[1].root_version = 12;
    votes[1].status = SM2_REV_STATUS_GOOD;
    votes[1].proof_valid = true;
    memset(votes[1].root_hash, 0x11, SM2_REV_SYNC_DIGEST_LEN);

    memcpy(votes[2].node_id, "node-c", 6);
    votes[2].node_id_len = 6;
    votes[2].root_version = 13;
    votes[2].status = SM2_REV_STATUS_REVOKED;
    votes[2].proof_valid = true;
    memset(votes[2].root_hash, 0x22, SM2_REV_SYNC_DIGEST_LEN);

    sm2_rev_trust_matrix_input_t trust[3];
    memset(trust, 0, sizeof(trust));
    for (size_t i = 0; i < 3; i++)
    {
        trust[i].ca_to_node_ok = true;
        trust[i].node_sync_ok = true;
        trust[i].node_response_ok = true;
        trust[i].device_verify_ok = true;
        trust[i].fallback_ok = true;
        trust[i].local_version = 10;
        trust[i].remote_version = votes[i].root_version;
        trust[i].clock_skew_sec = 0;
        trust[i].clock_tolerance_sec = 5;
    }
    trust[2].ca_to_node_ok = false;

    sm2_rev_bft_quorum_input_t input;
    memset(&input, 0, sizeof(input));
    input.votes = votes;
    input.trust_inputs = trust;
    input.vote_count = 3;
    input.threshold = 2;
    input.local_version = 10;
    input.local_root_hash = local_root;
    input.patch = &patch;
    input.patch_ca_verified = true;
    input.now_ts = 130;
    input.skew_tolerance_sec = 5;

    sm2_rev_bft_quorum_result_t result;
    TEST_ASSERT(sm2_rev_bft_check(&input, &result) == SM2_IC_SUCCESS,
        "BFT Quorum Evaluate Success");
    TEST_ASSERT(result.patch_verified, "Patch Verified");
    TEST_ASSERT(result.live_honest_node_assumed, "Honest Node Assumed");
    TEST_ASSERT(result.trusted_vote_count == 2, "Trusted Vote Count");
    TEST_ASSERT(result.rejected_vote_count == 1, "Rejected Vote Count");
    TEST_ASSERT(result.quorum_evaluated, "Quorum Evaluated");
    TEST_ASSERT(result.quorum_met, "Quorum Met");
    TEST_ASSERT(result.quorum_result.selected_root_version == 12,
        "Selected Highest Trusted Version");
    TEST_ASSERT(result.quorum_result.decided_status == SM2_REV_STATUS_GOOD,
        "Decided Good");

    TEST_PASS();
}

static void test_revocation_phase11_bft_rejects_invalid_paths(void)
{
    uint8_t local_root[SM2_REV_SYNC_DIGEST_LEN];
    memset(local_root, 0xAA, sizeof(local_root));

    sm2_rev_quorum_vote_t votes[2];
    memset(votes, 0, sizeof(votes));
    memcpy(votes[0].node_id, "node-a", 6);
    votes[0].node_id_len = 6;
    votes[0].root_version = 12;
    votes[0].status = SM2_REV_STATUS_GOOD;
    votes[0].proof_valid = true;
    memset(votes[0].root_hash, 0x11, SM2_REV_SYNC_DIGEST_LEN);

    memcpy(votes[1].node_id, "node-b", 6);
    votes[1].node_id_len = 6;
    votes[1].root_version = 12;
    votes[1].status = SM2_REV_STATUS_GOOD;
    votes[1].proof_valid = true;
    memset(votes[1].root_hash, 0x22, SM2_REV_SYNC_DIGEST_LEN);

    sm2_rev_trust_matrix_input_t trust[2];
    memset(trust, 0, sizeof(trust));
    for (size_t i = 0; i < 2; i++)
    {
        trust[i].ca_to_node_ok = true;
        trust[i].node_sync_ok = true;
        trust[i].node_response_ok = true;
        trust[i].device_verify_ok = true;
        trust[i].fallback_ok = true;
        trust[i].local_version = 10;
        trust[i].remote_version = 12;
        trust[i].clock_skew_sec = 0;
        trust[i].clock_tolerance_sec = 5;
    }

    sm2_rev_patch_link_t bad_patch;
    memset(&bad_patch, 0, sizeof(bad_patch));
    bad_patch.prev_version = 9;
    bad_patch.new_version = 10;
    bad_patch.issued_at = 120;
    bad_patch.valid_until = 200;
    memcpy(bad_patch.prev_root_hash, local_root, sizeof(local_root));
    memset(bad_patch.new_root_hash, 0x33, sizeof(bad_patch.new_root_hash));

    sm2_rev_bft_quorum_input_t input;
    memset(&input, 0, sizeof(input));
    input.votes = votes;
    input.trust_inputs = trust;
    input.vote_count = 2;
    input.threshold = 2;
    input.local_version = 10;
    input.local_root_hash = local_root;
    input.patch = &bad_patch;
    input.patch_ca_verified = true;
    input.now_ts = 130;
    input.skew_tolerance_sec = 5;

    sm2_rev_bft_quorum_result_t result;
    TEST_ASSERT(sm2_rev_bft_check(&input, &result) == SM2_IC_ERR_VERIFY,
        "Reject Non Monotonic Patch");

    input.patch = NULL;
    TEST_ASSERT(sm2_rev_bft_check(&input, &result) == SM2_IC_ERR_VERIFY,
        "Reject Forked Highest Version");
    TEST_ASSERT(result.fork_detected, "Fork Detected");

    trust[0].ca_to_node_ok = false;
    trust[1].ca_to_node_ok = false;
    memset(&result, 0, sizeof(result));
    TEST_ASSERT(sm2_rev_bft_check(&input, &result) == SM2_IC_SUCCESS,
        "No Honest Node Boundary");
    TEST_ASSERT(!result.live_honest_node_assumed, "No Honest Node Assumed");
    TEST_ASSERT(result.trusted_vote_count == 0, "Trusted Vote Count Zero");
    TEST_ASSERT(!result.quorum_evaluated, "Quorum Not Evaluated");

    TEST_PASS();
}

static void test_revocation_phase11_attack_surface_negative_cases(void)
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_rev_tree_t *tree = NULL;
    uint8_t tree_root_hash[SM2_REV_MERKLE_HASH_LEN];
    uint64_t revoked[] = { 101, 202, 303 };
    TEST_ASSERT(sm2_rev_tree_build(
                    &tree, revoked, sizeof(revoked) / sizeof(revoked[0]), 7)
            == SM2_IC_SUCCESS,
        "Merkle Build");
    TEST_ASSERT(
        sm2_rev_tree_get_root_hash(tree, tree_root_hash) == SM2_IC_SUCCESS,
        "Read Tree Root Hash");

    revoke_merkle_sig_ctx_t sig_ctx = { &g_ca_priv, &g_ca_pub };
    const uint8_t authority[] = "BFT_TEST_CA";
    sm2_rev_root_record_t root_record;
    memset(&root_record, 0, sizeof(root_record));
    TEST_ASSERT(
        sm2_rev_root_sign_with_authority(tree, authority, sizeof(authority) - 1,
            1000, 1300, revoke_merkle_sign_cb, &sig_ctx, &root_record)
            == SM2_IC_SUCCESS,
        "Sign Root Record");
    TEST_ASSERT(sm2_rev_root_verify(
                    &root_record, 1100, revoke_merkle_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Verify Root Record");
    root_record.signature[0] ^= 0x01;
    TEST_ASSERT(sm2_rev_root_verify(
                    &root_record, 1100, revoke_merkle_verify_cb, &sig_ctx)
            == SM2_IC_ERR_VERIFY,
        "Reject Fake Root Signature");
    root_record.signature[0] ^= 0x01;

    sm2_rev_patch_link_t patch;
    memset(&patch, 0, sizeof(patch));
    patch.prev_version = 7;
    patch.new_version = 8;
    patch.issued_at = 1005;
    patch.valid_until = 1300;
    memcpy(patch.prev_root_hash, tree_root_hash, sizeof(tree_root_hash));
    memset(patch.new_root_hash, 0x44, sizeof(patch.new_root_hash));
    TEST_ASSERT(
        sm2_rev_sync_verify_patch_link(&patch, 7, tree_root_hash, 1100, 5)
            == SM2_IC_SUCCESS,
        "Verify Patch Link");
    TEST_ASSERT(
        sm2_rev_sync_verify_patch_link(&patch, 8, tree_root_hash, 1100, 5)
            == SM2_IC_ERR_VERIFY,
        "Reject Replay Old Version");

    sm2_rev_sync_hello_t local_hello;
    memset(&local_hello, 0, sizeof(local_hello));
    local_hello.root_version = 8;
    memset(local_hello.root_hash, 0x11, sizeof(local_hello.root_hash));
    sm2_rev_sync_hello_t remote_hello = local_hello;
    remote_hello.root_hash[0] ^= 0x01;

    sm2_rev_sync_delta_plan_t plan;
    TEST_ASSERT(sm2_rev_sync_plan_delta(&local_hello, &remote_hello, &plan)
            == SM2_IC_ERR_VERIFY,
        "Reject Same-Version Fork");
    TEST_ASSERT(plan.fork_detected, "Fork Flag Set");

    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}

static void test_revocation_phase11_byzantine_redirect_and_tofn_3of5(void)
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
    candidates[1].root_valid_until = 380;
    candidates[1].rtt_ms = 30;
    candidates[1].health_score = 700;
    candidates[1].congestion_signal = SM2_REV_CONGESTION_BUSY;

    sm2_rev_trusted_node_t trusted[2];
    memset(trusted, 0, sizeof(trusted));
    memcpy(trusted[0].node_id, "node-a", 6);
    trusted[0].node_id_len = 6;
    memcpy(trusted[1].node_id, "node-b", 6);
    trusted[1].node_id_len = 6;

    mock_redirect_verify_ctx_t verify_ctx;
    memset(&verify_ctx, 0, sizeof(verify_ctx));
    verify_ctx.expect_tag = 0xA5;
    uint8_t bad_signature[1] = { 0x5A };
    TEST_ASSERT(sm2_rev_route_verify_metadata(&response, candidates, 2, trusted,
                    2, bad_signature, sizeof(bad_signature),
                    mock_redirect_verify, &verify_ctx)
            == SM2_IC_ERR_VERIFY,
        "Reject Malicious Redirect Metadata");

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
    route_nodes[1].enabled = false;
    route_nodes[1].next_retry_ts = 500;

    size_t selected_index = 0;
    TEST_ASSERT(sm2_rev_route_pick_candidate(&response, candidates, 2,
                    route_nodes, 2, 200, 1, &selected_index)
            == SM2_IC_ERR_VERIFY,
        "Reject Delayed Or Refusing Nodes");

    uint8_t local_root[SM2_REV_SYNC_DIGEST_LEN];
    memset(local_root, 0xAA, sizeof(local_root));
    sm2_rev_quorum_vote_t votes[5];
    memset(votes, 0, sizeof(votes));
    for (size_t i = 0; i < 3; i++)
    {
        memcpy(votes[i].node_id, i == 0 ? "qa" : (i == 1 ? "qb" : "qc"), 2);
        votes[i].node_id_len = 2;
        votes[i].root_version = 12;
        votes[i].status = SM2_REV_STATUS_GOOD;
        votes[i].proof_valid = true;
        memset(votes[i].root_hash, 0x11, sizeof(votes[i].root_hash));
    }
    memcpy(votes[3].node_id, "qd", 2);
    votes[3].node_id_len = 2;
    votes[3].root_version = 15;
    votes[3].status = SM2_REV_STATUS_REVOKED;
    votes[3].proof_valid = true;
    memset(votes[3].root_hash, 0x22, sizeof(votes[3].root_hash));

    memcpy(votes[4].node_id, "qe", 2);
    votes[4].node_id_len = 2;
    votes[4].root_version = 11;
    votes[4].status = SM2_REV_STATUS_GOOD;
    votes[4].proof_valid = true;
    memset(votes[4].root_hash, 0x33, sizeof(votes[4].root_hash));

    sm2_rev_trust_matrix_input_t trust[5];
    memset(trust, 0, sizeof(trust));
    for (size_t i = 0; i < 5; i++)
    {
        trust[i].ca_to_node_ok = true;
        trust[i].node_sync_ok = true;
        trust[i].node_response_ok = true;
        trust[i].device_verify_ok = true;
        trust[i].fallback_ok = true;
        trust[i].local_version = 10;
        trust[i].remote_version = votes[i].root_version;
        trust[i].clock_skew_sec = 0;
        trust[i].clock_tolerance_sec = 5;
    }
    trust[3].ca_to_node_ok = false;

    sm2_rev_bft_quorum_input_t input;
    memset(&input, 0, sizeof(input));
    input.votes = votes;
    input.trust_inputs = trust;
    input.vote_count = 5;
    input.threshold = 3;
    input.local_version = 10;
    input.local_root_hash = local_root;
    input.patch = NULL;
    input.now_ts = 200;
    input.skew_tolerance_sec = 5;

    sm2_rev_bft_quorum_result_t result;
    TEST_ASSERT(sm2_rev_bft_check(&input, &result) == SM2_IC_SUCCESS,
        "BFT 3of5 Success");
    TEST_ASSERT(result.quorum_met, "BFT 3of5 Quorum Met");
    TEST_ASSERT(result.quorum_result.selected_root_version == 12,
        "BFT 3of5 Select Highest Trusted");
    TEST_ASSERT(result.quorum_result.decided_status == SM2_REV_STATUS_GOOD,
        "BFT 3of5 Decided Good");
    TEST_ASSERT(result.rejected_vote_count == 1, "BFT 3of5 Reject Malicious");

    TEST_PASS();
}

static void test_revocation_phase12_vote_count_bounds(void)
{
    sm2_rev_quorum_vote_t vote;
    memset(&vote, 0, sizeof(vote));
    memcpy(vote.node_id, "qa", 2);
    vote.node_id_len = 2;
    vote.root_version = 1;
    vote.status = SM2_REV_STATUS_GOOD;
    vote.proof_valid = true;

    sm2_rev_trust_matrix_input_t trust;
    memset(&trust, 0, sizeof(trust));
    trust.ca_to_node_ok = true;
    trust.node_sync_ok = true;
    trust.node_response_ok = true;
    trust.device_verify_ok = true;
    trust.fallback_ok = true;
    trust.clock_tolerance_sec = 5;

    sm2_rev_bft_quorum_input_t input;
    memset(&input, 0, sizeof(input));
    input.votes = &vote;
    input.trust_inputs = &trust;
    input.vote_count = SM2_REV_QUORUM_MAX_VOTES + 1;
    input.threshold = 1;

    sm2_rev_bft_quorum_result_t result;
    TEST_ASSERT(sm2_rev_bft_check(&input, &result) == SM2_IC_ERR_PARAM,
        "Reject Oversized BFT Vote Count");
    TEST_ASSERT(sm2_rev_quorum_check(&vote, SM2_REV_QUORUM_MAX_VOTES + 1, 1,
                    &result.quorum_result)
            == SM2_IC_ERR_PARAM,
        "Reject Oversized Quorum Vote Count");

    TEST_PASS();
}
void run_test_revoke_bft_suite(void)
{
    RUN_TEST(test_revocation_phase11_bft_quorum_accepts_trusted_votes);
    RUN_TEST(test_revocation_phase11_bft_rejects_invalid_paths);
    RUN_TEST(test_revocation_phase11_attack_surface_negative_cases);
    RUN_TEST(test_revocation_phase11_byzantine_redirect_and_tofn_3of5);
    RUN_TEST(test_revocation_phase12_vote_count_bounds);
}
