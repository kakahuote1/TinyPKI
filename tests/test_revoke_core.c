/* SPDX-License-Identifier: Apache-2.0 */

#include "test_revoke_helpers.h"
#include "../src/revoke/merkle_internal.h"

static void test_rev_lookup_callback_priority(void)
{
    sm2_rev_ctx_t *ctx = NULL;
    TEST_ASSERT(
        sm2_rev_init(&ctx, 32, 120, 100) == SM2_IC_SUCCESS, "Revocation Init");

    sm2_rev_delta_item_t items[] = { { 7777, true } };
    sm2_rev_delta_t delta = { 0, 1, items, 1 };
    TEST_ASSERT(
        sm2_rev_apply_delta(ctx, &delta, 110) == SM2_IC_SUCCESS, "Apply Delta");

    mock_merkle_query_state_t merkle_state;
    memset(&merkle_state, 0, sizeof(merkle_state));
    merkle_state.status = SM2_REV_STATUS_GOOD;

    TEST_ASSERT(sm2_rev_set_lookup(ctx, mock_merkle_query, &merkle_state)
            == SM2_IC_SUCCESS,
        "Set Merkle Callback");

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(
        sm2_rev_query(ctx, 7777, 120, &status, &source) == SM2_IC_SUCCESS,
        "Query Merkle Callback");
    TEST_ASSERT(source == SM2_REV_SOURCE_MERKLE_NODE, "Source Merkle Node");
    TEST_ASSERT(status == SM2_REV_STATUS_GOOD, "Merkle Callback Override");
    TEST_ASSERT(merkle_state.call_count == 1, "Merkle Callback Call Count");
    TEST_ASSERT(merkle_state.last_serial == 7777, "Merkle Callback Serial");

    TEST_ASSERT(sm2_rev_set_lookup(ctx, NULL, NULL) == SM2_IC_SUCCESS,
        "Clear Merkle Callback");
    status = SM2_REV_STATUS_GOOD;
    source = SM2_REV_SOURCE_MERKLE_NODE;
    TEST_ASSERT(
        sm2_rev_query(ctx, 7777, 120, &status, &source) == SM2_IC_SUCCESS,
        "Query Falls Back To Local State");
    TEST_ASSERT(source == SM2_REV_SOURCE_LOCAL_STATE, "Source Local State");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "Status Revoked Locally");

    TEST_ASSERT(
        sm2_rev_query(ctx, 8888, 120, &status, &source) == SM2_IC_SUCCESS,
        "Unknown Serial Uses Fresh Local Root");
    TEST_ASSERT(source == SM2_REV_SOURCE_LOCAL_STATE, "Fresh Local Source");
    TEST_ASSERT(status == SM2_REV_STATUS_GOOD, "Fresh Local Good");

    TEST_ASSERT(
        sm2_rev_query(ctx, 8888, 240, &status, &source) == SM2_IC_SUCCESS,
        "Expired Local Root Returns Unknown");
    TEST_ASSERT(source == SM2_REV_SOURCE_NONE, "Expired Source None");
    TEST_ASSERT(status == SM2_REV_STATUS_UNKNOWN, "Expired Status Unknown");

    sm2_rev_cleanup(&ctx);
    TEST_PASS();
}

static void test_revocation_cleanup_idempotent_and_param_defense(void)
{
    sm2_rev_ctx_t *ctx = NULL;
    TEST_ASSERT(
        sm2_rev_init(&ctx, 32, 300, 100) == SM2_IC_SUCCESS, "Revocation Init");

    sm2_rev_cleanup(&ctx);
    sm2_rev_cleanup(&ctx);

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(
        sm2_rev_query(NULL, 1, 100, &status, &source) == SM2_IC_ERR_PARAM,
        "Query NULL Ctx");
    TEST_ASSERT(sm2_rev_query(ctx, 1, 100, NULL, &source) == SM2_IC_ERR_PARAM,
        "Query NULL Status");
    TEST_ASSERT(sm2_rev_query(ctx, 1, 100, &status, NULL) == SM2_IC_ERR_PARAM,
        "Query NULL Source");
    TEST_ASSERT(
        sm2_rev_set_lookup(NULL, mock_merkle_query, ctx) == SM2_IC_ERR_PARAM,
        "Set Merkle Callback NULL Ctx");

    TEST_PASS();
}

static void test_revocation_batch_update_baseline_metrics(void)
{
    enum
    {
        INITIAL_REVOKED = 512,
        UPDATE_ITEMS = 256
    };

    sm2_rev_ctx_t *ctx = NULL;
    sm2_rev_delta_item_t initial[INITIAL_REVOKED];
    sm2_rev_delta_item_t updates[UPDATE_ITEMS];

    for (size_t i = 0; i < INITIAL_REVOKED; i++)
    {
        initial[i].serial_number = 100000U + (uint64_t)i;
        initial[i].revoked = true;
    }
    sm2_rev_delta_t initial_delta = { 0, 1, initial, INITIAL_REVOKED };

    TEST_ASSERT(sm2_rev_init(&ctx, INITIAL_REVOKED + UPDATE_ITEMS, 300, 100)
            == SM2_IC_SUCCESS,
        "Revocation Init");
    TEST_ASSERT(sm2_rev_apply_delta(ctx, &initial_delta, 110) == SM2_IC_SUCCESS,
        "Apply Initial Batch");

    for (size_t i = 0; i < UPDATE_ITEMS; i++)
    {
        if ((i & 1U) == 0)
        {
            updates[i].serial_number = 200000U + (uint64_t)i;
            updates[i].revoked = true;
        }
        else
        {
            updates[i].serial_number = 100000U + (uint64_t)i;
            updates[i].revoked = false;
        }
    }
    sm2_rev_delta_t update_delta = { 1, 2, updates, UPDATE_ITEMS };

    merkle_tree_debug_stats_reset();
    double start_ms = now_ms_highres();
    TEST_ASSERT(sm2_rev_apply_delta(ctx, &update_delta, 120) == SM2_IC_SUCCESS,
        "Apply Mixed Batch");
    double elapsed_ms = now_ms_highres() - start_ms;

    sm2_rev_tree_debug_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    merkle_tree_debug_stats_get(&stats);
    printf("   [REV-BATCH-BASELINE] initial=%u, updates=%u, elapsed=%.3f ms, "
           "alloc=%zu, free=%zu, pool_blocks=%zu, refresh=%zu, "
           "refresh_visits=%zu\n",
        (unsigned)INITIAL_REVOKED, (unsigned)UPDATE_ITEMS, elapsed_ms,
        stats.node_alloc_count, stats.node_free_count,
        stats.node_pool_block_alloc_count, stats.root_refresh_count,
        stats.root_refresh_node_visit_count);

    TEST_ASSERT(stats.node_alloc_count > 0, "Node Allocations Recorded");
    TEST_ASSERT(stats.node_pool_block_alloc_count > 0,
        "Pool Block Allocations Recorded");
    TEST_ASSERT(stats.root_refresh_count > 0, "Root Refreshes Recorded");
    TEST_ASSERT(
        sm2_rev_local_count(ctx) == INITIAL_REVOKED, "Final Revoked Count");

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(
        sm2_rev_query(ctx, 200000U, 130, &status, &source) == SM2_IC_SUCCESS,
        "Query Added Serial");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "Added Serial Revoked");
    TEST_ASSERT(
        sm2_rev_query(ctx, 100001U, 130, &status, &source) == SM2_IC_SUCCESS,
        "Query Removed Serial");
    TEST_ASSERT(status == SM2_REV_STATUS_GOOD, "Removed Serial Good");

    sm2_rev_cleanup(&ctx);
    TEST_PASS();
}

void run_test_revoke_core_suite(void)
{
    RUN_TEST(test_rev_lookup_callback_priority);
    RUN_TEST(test_revocation_cleanup_idempotent_and_param_defense);
    RUN_TEST(test_revocation_batch_update_baseline_metrics);
}
