/* SPDX-License-Identifier: Apache-2.0 */

#include "test_common.h"

typedef struct
{
    sm2_rev_status_t status;
} auth_revocation_cb_ctx_t;

static sm2_ic_error_t auth_revocation_status_cb(const sm2_implicit_cert_t *cert,
    uint64_t now_ts, void *user_ctx, sm2_rev_status_t *status)
{
    (void)cert;
    (void)now_ts;
    if (!user_ctx || !status)
        return SM2_IC_ERR_PARAM;
    auth_revocation_cb_ctx_t *ctx = (auth_revocation_cb_ctx_t *)user_ctx;
    *status = ctx->status;
    return SM2_IC_SUCCESS;
}

static int test_auth_aead_mode_available(sm2_auth_aead_mode_t mode)
{
    switch (mode)
    {
        case SM2_AUTH_AEAD_MODE_SM4_GCM:
            return test_openssl_cipher_available("SM4-GCM");
        case SM2_AUTH_AEAD_MODE_SM4_CCM:
            return test_openssl_cipher_available("SM4-CCM");
        default:
            return 0;
    }
}

/* Split by theme to keep auth tests navigable without duplicating helpers. */
#include "test_auth_core.inc"
#include "test_auth_session.inc"
#include "test_auth_policy.inc"

void run_test_auth_suite(void)
{
    RUN_TEST(test_auth_sign_pool);
    RUN_TEST(test_auth_batch_verify);
    RUN_TEST(test_auth_batch_verify_param_cleanup_path);
    RUN_TEST(test_auth_rejects_invalid_public_points);
    RUN_TEST(test_auth_cleanup_idempotent_and_param_defense);
    RUN_TEST(test_auth_cert_policy_time_and_usage);
    RUN_TEST(test_auth_cross_domain_unified);
    RUN_TEST(test_auth_static_handshake_and_session_key);
    RUN_TEST(test_auth_session_aead_protect);
    if (test_benchmarks_enabled())
        RUN_TEST(test_auth_phase3_perf_targets);
    RUN_TEST(test_auth_with_revocation_block);
    RUN_TEST(test_auth_local_revocation_good_requires_opt_in);
    RUN_TEST(test_auth_revocation_policy_strict_cross_check);
    RUN_TEST(test_auth_forward_secure_session_key);
    RUN_TEST(test_auth_aead_integrity);
}
