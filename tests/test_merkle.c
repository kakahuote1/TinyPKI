/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file test_merkle.c
 * @brief Tests for Merkle tree (member/absence proofs, CBOR codec,
 *        root signature, multiproof, epoch and hot-patch).
 */

#include "test_common.h"
typedef struct
{
    const sm2_private_key_t *ca_priv;
    const sm2_ec_point_t *ca_pub;
} merkle_ca_sig_ctx_t;

static const uint8_t g_merkle_authority[] = "MERKLE_TEST_CA";

static sm2_ic_error_t merkle_ca_sign_cb(void *user_ctx, const uint8_t *data,
    size_t data_len, uint8_t *signature, size_t *signature_len)
{
    if (!user_ctx || !data || !signature || !signature_len)
        return SM2_IC_ERR_PARAM;

    merkle_ca_sig_ctx_t *ctx = (merkle_ca_sig_ctx_t *)user_ctx;
    if (!ctx->ca_priv)
        return SM2_IC_ERR_PARAM;

    sm2_auth_signature_t sig;
    sm2_ic_error_t ret = sm2_auth_sign(ctx->ca_priv, data, data_len, &sig);
    if (ret != SM2_IC_SUCCESS)
        return ret;

    if (*signature_len < sig.der_len)
        return SM2_IC_ERR_MEMORY;

    memcpy(signature, sig.der, sig.der_len);
    *signature_len = sig.der_len;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t merkle_ca_verify_cb(void *user_ctx, const uint8_t *data,
    size_t data_len, const uint8_t *signature, size_t signature_len)
{
    if (!user_ctx || !data || !signature)
        return SM2_IC_ERR_PARAM;

    merkle_ca_sig_ctx_t *ctx = (merkle_ca_sig_ctx_t *)user_ctx;
    if (!ctx->ca_pub)
        return SM2_IC_ERR_PARAM;
    if (signature_len == 0 || signature_len > SM2_AUTH_MAX_SIG_DER_LEN)
        return SM2_IC_ERR_VERIFY;

    sm2_auth_signature_t sig;
    memset(&sig, 0, sizeof(sig));
    memcpy(sig.der, signature, signature_len);
    sig.der_len = signature_len;

    return sm2_auth_verify_signature(ctx->ca_pub, data, data_len, &sig);
}
/* Split by theme to keep Merkle tests grouped by primitive, advanced flow and
 * negative cases. */
#include "test_merkle_core.inc"
#include "test_merkle_advanced.inc"
#include "test_merkle_negative.inc"

void run_test_merkle_suite(void)
{
    test_setup_ca();
    RUN_TEST(test_rev_tree_member_and_absence);
    RUN_TEST(test_rev_tree_codec_roundtrip);
    RUN_TEST(test_rev_root_signature_and_light_verify);
    RUN_TEST(test_rev_multi_proof_roundtrip);
    RUN_TEST(test_rev_multi_proof_bandwidth_gain);
    RUN_TEST(test_rev_epoch_dir_sparse_proof);
    RUN_TEST(test_rev_epoch_patch_priority);
    RUN_TEST(test_rev_epoch_switch_monotonic);
    RUN_TEST(test_rev_multi_proof_dynamic_growth_path);
    RUN_TEST(test_rev_phase8_metric_bundle);
    /* -- Phase 3 negative / boundary tests -- */
    RUN_TEST(test_merkle_empty_tree_prove_member_fails);
    RUN_TEST(test_merkle_expired_root_record_rejected);
    RUN_TEST(test_merkle_hot_patch_stale_version_rejected);
    RUN_TEST(test_merkle_multiproof_over_limit_rejected);
    RUN_TEST(test_merkle_member_sparse_key_path_bound);
    RUN_TEST(test_merkle_absence_sparse_path_commitment);
    RUN_TEST(test_merkle_quorum_dedup_node_id);
}
