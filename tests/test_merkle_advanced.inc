{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_rev_tree_t *tree = NULL;

    uint64_t revoked[2048];
    for (size_t i = 0; i < 2048; i++)
        revoked[i] = 200000 + i;

    TEST_ASSERT(sm2_rev_tree_build(&tree, revoked,
                    sizeof(revoked) / sizeof(revoked[0]), 2026030604ULL)
            == SM2_IC_SUCCESS,
        "Build Tree");

    merkle_ca_sig_ctx_t sig_ctx = { &g_ca_priv, &g_ca_pub };
    sm2_rev_epoch_dir_t *dir = NULL;
    TEST_ASSERT(sm2_rev_epoch_dir_build(
                    tree, 42, 8, 1000, 2000, merkle_ca_sign_cb, &sig_ctx, &dir)
            == SM2_IC_SUCCESS,
        "Build Epoch Directory");

    uint8_t dir_buf[262144];
    size_t dir_len = sizeof(dir_buf);
    TEST_ASSERT(
        sm2_rev_epoch_dir_encode(dir, dir_buf, &dir_len) == SM2_IC_SUCCESS,
        "Epoch Directory Encode");

    sm2_rev_epoch_dir_t *dir_dec = NULL;
    TEST_ASSERT(
        sm2_rev_epoch_dir_decode(&dir_dec, dir_buf, dir_len) == SM2_IC_SUCCESS,
        "Epoch Directory Decode");

    TEST_ASSERT(
        sm2_rev_epoch_dir_verify(dir_dec, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Epoch Directory Verify");

    uint64_t target = revoked[777];
    sm2_rev_member_proof_t full;
    TEST_ASSERT(
        sm2_rev_tree_prove_member(tree, target, &full) == SM2_IC_SUCCESS,
        "Full Member Proof");

    sm2_rev_cached_member_proof_t cached;
    TEST_ASSERT(sm2_rev_epoch_prove_member_cached(tree, target, 8, &cached)
            == SM2_IC_SUCCESS,
        "Cached Member Proof");

    uint8_t full_buf[8192];
    size_t full_len = sizeof(full_buf);
    TEST_ASSERT(sm2_rev_member_proof_encode(&full, full_buf, &full_len)
            == SM2_IC_SUCCESS,
        "Full Proof Encode");

    uint8_t cached_buf[8192];
    size_t cached_len = sizeof(cached_buf);
    TEST_ASSERT(
        sm2_rev_cached_member_proof_encode(&cached, cached_buf, &cached_len)
            == SM2_IC_SUCCESS,
        "Cached Proof Encode");

    sm2_rev_cached_member_proof_t cached_dec;
    TEST_ASSERT(
        sm2_rev_cached_member_proof_decode(&cached_dec, cached_buf, cached_len)
            == SM2_IC_SUCCESS,
        "Cached Proof Decode");

    TEST_ASSERT(sm2_rev_epoch_verify_member_cached(
                    dir_dec, 1500, &cached_dec, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Cached Proof Verify");

    double reduction = 1.0 - ((double)cached_len / (double)full_len);
    printf("   [EPOCH-CACHE] full=%zu, cached=%zu, reduction=%.2f%%\n",
        full_len, cached_len, reduction * 100.0);
    TEST_ASSERT(reduction >= 0.40, "Epoch Cache Reduction < 40%");

    sm2_rev_epoch_dir_cleanup(&dir_dec);
    sm2_rev_epoch_dir_cleanup(&dir);
    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}

static void test_rev_epoch_patch_priority()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_rev_tree_t *tree = NULL;

    uint64_t revoked[] = { 900001, 900002, 900003 };
    TEST_ASSERT(sm2_rev_tree_build(
                    &tree, revoked, sizeof(revoked) / sizeof(revoked[0]), 501)
            == SM2_IC_SUCCESS,
        "Build Tree");

    merkle_ca_sig_ctx_t sig_ctx = { &g_ca_priv, &g_ca_pub };
    sm2_rev_epoch_dir_t *dir = NULL;
    TEST_ASSERT(sm2_rev_epoch_dir_build(
                    tree, 50, 6, 1000, 2000, merkle_ca_sign_cb, &sig_ctx, &dir)
            == SM2_IC_SUCCESS,
        "Build Epoch Directory");

    sm2_crl_delta_item_t patch1[] = { { 999999, true } };
    TEST_ASSERT(sm2_rev_epoch_apply_patch(
                    dir, 1, patch1, 1, merkle_ca_sign_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Apply Patch v1");

    sm2_rev_status_t st;
    TEST_ASSERT(sm2_rev_epoch_lookup(
                    dir, 1500, 999999, merkle_ca_verify_cb, &sig_ctx, &st)
            == SM2_IC_SUCCESS,
        "Patch Query v1");
    TEST_ASSERT(st == SM2_REV_STATUS_REVOKED, "Patch Priority Revoked");

    sm2_crl_delta_item_t patch2[] = { { 999999, false } };
    TEST_ASSERT(sm2_rev_epoch_apply_patch(
                    dir, 2, patch2, 1, merkle_ca_sign_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Apply Epoch Patch");
    TEST_ASSERT(sm2_rev_epoch_lookup(
                    dir, 1500, 999999, merkle_ca_verify_cb, &sig_ctx, &st)
            == SM2_IC_SUCCESS,
        "Epoch Lookup Updated");
    TEST_ASSERT(st == SM2_REV_STATUS_GOOD, "Patch Override Good");

    TEST_ASSERT(sm2_rev_epoch_apply_patch(
                    dir, 2, patch1, 1, merkle_ca_sign_cb, &sig_ctx)
            == SM2_IC_ERR_VERIFY,
        "Patch Version Monotonic");

    sm2_rev_epoch_dir_cleanup(&dir);
    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}

static void test_rev_epoch_switch_monotonic()
{
    if (!g_ca_initialized)
        test_setup_ca();

    merkle_ca_sig_ctx_t sig_ctx = { &g_ca_priv, &g_ca_pub };

    sm2_rev_tree_t *t1 = NULL;
    sm2_rev_tree_t *t2 = NULL;

    uint64_t revoked1[] = { 1001, 1002, 1003 };
    uint64_t revoked2[] = { 1001, 1002, 1003, 1004, 1005 };

    TEST_ASSERT(sm2_rev_tree_build(
                    &t1, revoked1, sizeof(revoked1) / sizeof(revoked1[0]), 10)
            == SM2_IC_SUCCESS,
        "Build T1");
    TEST_ASSERT(sm2_rev_tree_build(
                    &t2, revoked2, sizeof(revoked2) / sizeof(revoked2[0]), 11)
            == SM2_IC_SUCCESS,
        "Build T2");

    sm2_rev_epoch_dir_t *d1 = NULL;
    sm2_rev_epoch_dir_t *d2 = NULL;
    sm2_rev_epoch_dir_t *local = NULL;

    TEST_ASSERT(sm2_rev_epoch_dir_build(
                    t1, 60, 4, 1000, 3000, merkle_ca_sign_cb, &sig_ctx, &d1)
            == SM2_IC_SUCCESS,
        "Build D1");
    TEST_ASSERT(sm2_rev_epoch_dir_build(
                    t2, 61, 4, 1000, 3000, merkle_ca_sign_cb, &sig_ctx, &d2)
            == SM2_IC_SUCCESS,
        "Build D2");

    TEST_ASSERT(
        sm2_rev_epoch_switch(&local, d1, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Switch To D1");
    TEST_ASSERT(local != NULL, "Local Directory Materialized");
    TEST_ASSERT(
        sm2_rev_epoch_switch(&local, d2, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Switch To D2");
    TEST_ASSERT(
        sm2_rev_epoch_switch(&local, d1, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_ERR_VERIFY,
        "Reject Older Epoch");

    sm2_rev_epoch_dir_cleanup(&local);
    sm2_rev_epoch_dir_cleanup(&d2);
    sm2_rev_epoch_dir_cleanup(&d1);
    sm2_rev_tree_cleanup(&t2);
    sm2_rev_tree_cleanup(&t1);
    TEST_PASS();
}

static void test_rev_multi_proof_dynamic_growth_path()
{
    sm2_rev_tree_t *tree = NULL;
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];

    uint64_t revoked[2048];
    for (size_t i = 0; i < sizeof(revoked) / sizeof(revoked[0]); i++)
        revoked[i] = 910000ULL + i;

    TEST_ASSERT(sm2_rev_tree_build(&tree, revoked,
                    sizeof(revoked) / sizeof(revoked[0]), 2026030701ULL)
            == SM2_IC_SUCCESS,
        "Build Tree For Dynamic Growth");
    merkle_read_root_hash_or_fail(tree, root_hash);

    uint64_t query = revoked[1024];
    sm2_rev_multi_proof_t *mp = NULL;

    TEST_ASSERT(
        sm2_rev_multi_proof_build(tree, &query, 1, &mp) == SM2_IC_SUCCESS,
        "Build MultiProof Dynamic Growth");
    TEST_ASSERT(sm2_rev_multi_proof_query_count(mp) == 1, "Query Count");
    TEST_ASSERT(sm2_rev_multi_proof_unique_hash_count(mp) > 1,
        "Dynamic Growth Triggered");
    TEST_ASSERT(sm2_rev_multi_proof_verify(root_hash, mp) == SM2_IC_SUCCESS,
        "Verify Dynamic Growth MultiProof");

    sm2_rev_multi_proof_cleanup(&mp);
    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}

static void test_rev_phase8_metric_bundle()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_rev_tree_t *tree = NULL;

    enum
    {
        revoked_n = 2048,
        k = 16
    };

    uint64_t *revoked = (uint64_t *)calloc(revoked_n, sizeof(uint64_t));
    TEST_ASSERT(revoked != NULL, "Alloc Metric Tree Data");
    for (size_t i = 0; i < revoked_n; i++)
        revoked[i] = 600000ULL + i;

    TEST_ASSERT(sm2_rev_tree_build(&tree, revoked, revoked_n, 2026030606ULL)
            == SM2_IC_SUCCESS,
        "Build Metric Tree");

    uint64_t queries[k];
    for (size_t i = 0; i < k; i++)
        queries[i] = revoked[900 + i];

    sm2_rev_multi_proof_t *mp = NULL;
    TEST_ASSERT(
        sm2_rev_multi_proof_build(tree, queries, k, &mp) == SM2_IC_SUCCESS,
        "Build Metric MultiProof");

    uint8_t mp_buf[262144];
    size_t mp_len = sizeof(mp_buf);
    TEST_ASSERT(
        sm2_rev_multi_proof_encode(mp, mp_buf, &mp_len) == SM2_IC_SUCCESS,
        "Encode Metric MultiProof");

    size_t single_total = 0;
    size_t sibling_refs = 0;
    for (size_t i = 0; i < k; i++)
    {
        sm2_rev_member_proof_t member;
        uint8_t single_buf[8192];
        size_t single_len = sizeof(single_buf);

        TEST_ASSERT(sm2_rev_tree_prove_member(tree, queries[i], &member)
                == SM2_IC_SUCCESS,
            "Build Single Proof");
        TEST_ASSERT(
            sm2_rev_member_proof_encode(&member, single_buf, &single_len)
                == SM2_IC_SUCCESS,
            "Encode Single Proof");

        single_total += single_len;
        sibling_refs += member.sibling_count;
    }

    TEST_ASSERT(single_total > 0, "Metric Single Total Zero");
    TEST_ASSERT(sibling_refs > 0, "Metric Sibling Refs Zero");
    TEST_ASSERT(sm2_rev_multi_proof_unique_hash_count(mp) <= sibling_refs,
        "Unique Hashes Overflow");

    double reuse_rate = 1.0
        - ((double)sm2_rev_multi_proof_unique_hash_count(mp)
            / (double)sibling_refs);
    double bandwidth_gain = 1.0 - ((double)mp_len / (double)single_total);

    merkle_ca_sig_ctx_t sig_ctx = { &g_ca_priv, &g_ca_pub };
    sm2_rev_epoch_dir_t *dir = NULL;
    TEST_ASSERT(sm2_rev_epoch_dir_build(
                    tree, 66, 8, 1000, 3000, merkle_ca_sign_cb, &sig_ctx, &dir)
            == SM2_IC_SUCCESS,
        "Build Metric Epoch Directory");

    sm2_rev_member_proof_t full;
    sm2_rev_cached_member_proof_t cached;
    TEST_ASSERT(
        sm2_rev_tree_prove_member(tree, queries[0], &full) == SM2_IC_SUCCESS,
        "Build Full Proof For Cache");
    TEST_ASSERT(sm2_rev_epoch_prove_member_cached(tree, queries[0], 8, &cached)
            == SM2_IC_SUCCESS,
        "Build Cached Proof For Cache");

    TEST_ASSERT(full.sibling_count > 0, "Full Sibling Count Zero");
    double cache_hit_rate
        = (double)cached.omitted_top_levels / (double)full.sibling_count;

    printf("   [P8-METRIC] reuse=%.2f%%, cache_hit=%.2f%%, bandwidth=%.2f%%\n",
        reuse_rate * 100.0, cache_hit_rate * 100.0, bandwidth_gain * 100.0);

    TEST_ASSERT(reuse_rate >= 0.30, "Reuse Rate < 30%");
    TEST_ASSERT(cache_hit_rate >= 0.40, "Cache Hit < 40%");
    TEST_ASSERT(bandwidth_gain >= 0.60, "Bandwidth Gain < 60%");

    sm2_rev_epoch_dir_cleanup(&dir);
    sm2_rev_multi_proof_cleanup(&mp);
    sm2_rev_tree_cleanup(&tree);
    free(revoked);
    TEST_PASS();
}
/* ----- Negative / Boundary Tests (Phase 3 hardening) ----- */
