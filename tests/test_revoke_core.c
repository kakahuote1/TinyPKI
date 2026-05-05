/* SPDX-License-Identifier: Apache-2.0 */

#include "test_revoke_helpers.h"

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

void run_test_revoke_core_suite(void)
{
    RUN_TEST(test_rev_lookup_callback_priority);
    RUN_TEST(test_revocation_cleanup_idempotent_and_param_defense);
}
