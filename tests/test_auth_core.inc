static void test_auth_sign_pool()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"AUTH_PRECOMP", 12,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Req");
    TEST_ASSERT(test_issue_cert(
                    &cert_res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon");

    sm2_auth_sign_pool_t pool;
    TEST_ASSERT(
        sm2_auth_sign_pool_init(&pool, &user_priv, 256) == SM2_IC_SUCCESS,
        "Pool Init");
    TEST_ASSERT(
        sm2_auth_sign_pool_fill(&pool, 256) == SM2_IC_SUCCESS, "Pool Fill");
    TEST_ASSERT(sm2_auth_sign_pool_available(&pool) == 256, "Pool Available");

    const uint8_t msg[] = "SIGN_POOL_CACHE_MESSAGE";
    sm2_auth_signature_t sig;
    TEST_ASSERT(sm2_auth_sign_with_pool(&pool, msg, sizeof(msg) - 1, &sig)
            == SM2_IC_SUCCESS,
        "Sign Pool");
    TEST_ASSERT(sm2_auth_verify_signature(&user_pub, msg, sizeof(msg) - 1, &sig)
            == SM2_IC_SUCCESS,
        "Verify Sig");
    for (int i = 0; i < 64; i++)
    {
        uint8_t m[32];
        memset(m, (uint8_t)i, sizeof(m));
        TEST_ASSERT(sm2_auth_sign_with_pool(&pool, m, sizeof(m), &sig)
                == SM2_IC_SUCCESS,
            "Loop Sign Pool");
    }
    TEST_ASSERT(sm2_auth_sign_pool_available(&pool) < 256,
        "Pool Availability Must Decrease");
    sm2_auth_sign_pool_cleanup(&pool);
    TEST_PASS();
}

static void test_auth_batch_verify()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"AUTH_BATCH", 10,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Req");
    TEST_ASSERT(test_issue_cert(
                    &cert_res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon");

    const size_t n = 256;
    sm2_auth_signature_t *sigs
        = (sm2_auth_signature_t *)calloc(n, sizeof(sm2_auth_signature_t));
    uint8_t *msgs = (uint8_t *)calloc(n * 16, sizeof(uint8_t));
    sm2_auth_verify_item_t *items
        = (sm2_auth_verify_item_t *)calloc(n, sizeof(sm2_auth_verify_item_t));
    TEST_ASSERT(sigs && msgs && items, "Alloc Batch Buffers");

    for (size_t i = 0; i < n; i++)
    {
        memset(msgs + i * 16, (int)i, 16);
        TEST_ASSERT(sm2_auth_sign(&user_priv, msgs + i * 16, 16, &sigs[i])
                == SM2_IC_SUCCESS,
            "Sign");
        items[i].public_key = &user_pub;
        items[i].message = msgs + i * 16;
        items[i].message_len = 16;
        items[i].signature = &sigs[i];
    }

    size_t valid_count = 0;
    TEST_ASSERT(sm2_auth_batch_verify(items, n, &valid_count) == SM2_IC_SUCCESS,
        "Batch Verify");
    TEST_ASSERT(valid_count == n, "Batch Valid Count");

    /* tamper one signature and ensure batch detects */
    sigs[0].der[0] ^= 0xFF;
    TEST_ASSERT(
        sm2_auth_batch_verify(items, n, &valid_count) == SM2_IC_ERR_VERIFY,
        "Batch Tamper Detect");

    free(items);
    free(msgs);
    free(sigs);
    TEST_PASS();
}

static void test_auth_batch_verify_param_cleanup_path()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"AUTH_BATCH_PARAM",
                    16, SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Req");
    TEST_ASSERT(test_issue_cert(
                    &cert_res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon");

    const uint8_t msg[] = "AUTH_BATCH_PARAM_MSG";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_auth_sign(&user_priv, msg, sizeof(msg) - 1, &sig) == SM2_IC_SUCCESS,
        "Sign");

    sm2_auth_verify_item_t items[2];
    memset(items, 0, sizeof(items));
    items[0].public_key = &user_pub;
    items[0].message = msg;
    items[0].message_len = sizeof(msg) - 1;
    items[0].signature = &sig;
    items[1].public_key = &user_pub;
    items[1].message = NULL;
    items[1].message_len = sizeof(msg) - 1;
    items[1].signature = &sig;

    size_t valid_count = 0;
    TEST_ASSERT(
        sm2_auth_batch_verify(items, 2, &valid_count) == SM2_IC_ERR_PARAM,
        "Batch Param Reject After Cache Build");
    TEST_ASSERT(valid_count == 0, "Batch Param Reject Count Reset");

    TEST_ASSERT(sm2_auth_batch_verify(items, 1, &valid_count) == SM2_IC_SUCCESS,
        "Batch Verify Still Usable");
    TEST_ASSERT(valid_count == 1, "Batch Verify Single Count");

    TEST_PASS();
}

static void test_auth_rejects_invalid_public_points()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;
    sm2_ec_point_t invalid_pub;

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"AUTH_BAD_POINT",
                    14, SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Req");
    TEST_ASSERT(test_issue_cert(
                    &cert_res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon");

    memset(&invalid_pub, 0, sizeof(invalid_pub));
    const uint8_t msg[] = "AUTH_INVALID_POINT";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_auth_sign(&user_priv, msg, sizeof(msg) - 1, &sig) == SM2_IC_SUCCESS,
        "Sign");
    TEST_ASSERT(
        sm2_auth_verify_signature(&invalid_pub, msg, sizeof(msg) - 1, &sig)
            == SM2_IC_ERR_VERIFY,
        "Reject Invalid Verify Key");

    sm2_auth_verify_item_t item;
    memset(&item, 0, sizeof(item));
    item.public_key = &invalid_pub;
    item.message = msg;
    item.message_len = sizeof(msg) - 1;
    item.signature = &sig;

    size_t valid_count = 123;
    TEST_ASSERT(
        sm2_auth_batch_verify(&item, 1, &valid_count) == SM2_IC_ERR_VERIFY,
        "Batch Reject Invalid Verify Key");
    TEST_ASSERT(valid_count == 0, "Batch Invalid Count Reset");

    sm2_auth_trust_store_t store;
    TEST_ASSERT(sm2_auth_trust_store_init(&store) == SM2_IC_SUCCESS,
        "Trust Store Init");
    TEST_ASSERT(
        sm2_auth_trust_store_add_ca(&store, &invalid_pub) == SM2_IC_ERR_VERIFY,
        "Reject Invalid CA Key");

    uint8_t session_key[16];
    TEST_ASSERT(sm2_auth_derive_session_key_static(
                    &user_priv, &invalid_pub, session_key, sizeof(session_key))
            == SM2_IC_ERR_VERIFY,
        "Reject Invalid Peer KEX Key");

    TEST_PASS();
}

static void test_auth_cleanup_idempotent_and_param_defense()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_auth_sign_pool_t pool;
    TEST_ASSERT(sm2_auth_sign_pool_init(&pool, &g_ca_priv, 8) == SM2_IC_SUCCESS,
        "Pool Init");
    TEST_ASSERT(
        sm2_auth_sign_pool_fill(&pool, 4) == SM2_IC_SUCCESS, "Pool Fill");

    sm2_auth_sign_pool_cleanup(&pool);
    TEST_ASSERT(pool.slots == NULL, "Cleanup Reset Slots");
    TEST_ASSERT(pool.native_sign_key == NULL, "Cleanup Reset Native");
    TEST_ASSERT(pool.available == 0, "Cleanup Reset Available");

    sm2_auth_sign_pool_cleanup(&pool);
    TEST_ASSERT(pool.slots == NULL, "Cleanup Idempotent Slots");
    TEST_ASSERT(pool.native_sign_key == NULL, "Cleanup Idempotent Native");

    TEST_ASSERT(
        sm2_auth_sign_pool_init(NULL, &g_ca_priv, 8) == SM2_IC_ERR_PARAM,
        "Pool Init NULL");
    TEST_ASSERT(
        sm2_auth_sign_pool_fill(NULL, 1) == SM2_IC_ERR_PARAM, "Pool Fill NULL");
    TEST_ASSERT(
        sm2_auth_sign(NULL, (const uint8_t *)"A", 1, NULL) == SM2_IC_ERR_PARAM,
        "Sign NULL");
    TEST_ASSERT(sm2_auth_verify_signature(NULL, (const uint8_t *)"A", 1, NULL)
            == SM2_IC_ERR_PARAM,
        "Verify NULL");

    TEST_PASS();
}
