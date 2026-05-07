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
                    tree, 42, 1000, 2000, merkle_ca_sign_cb, &sig_ctx, &dir)
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

    sm2_rev_member_proof_t epoch_proof;
    TEST_ASSERT(sm2_rev_epoch_prove_member(tree, target, &epoch_proof)
            == SM2_IC_SUCCESS,
        "Epoch Member Proof");

    uint8_t full_buf[16384];
    size_t full_len = sizeof(full_buf);
    TEST_ASSERT(sm2_rev_member_proof_encode(&full, full_buf, &full_len)
            == SM2_IC_SUCCESS,
        "Full Proof Encode");

    uint8_t epoch_buf[16384];
    size_t epoch_len = sizeof(epoch_buf);
    TEST_ASSERT(sm2_rev_member_proof_encode(&epoch_proof, epoch_buf, &epoch_len)
            == SM2_IC_SUCCESS,
        "Epoch Proof Encode");

    sm2_rev_member_proof_t epoch_dec;
    TEST_ASSERT(sm2_rev_member_proof_decode(&epoch_dec, epoch_buf, epoch_len)
            == SM2_IC_SUCCESS,
        "Epoch Proof Decode");

    TEST_ASSERT(sm2_rev_epoch_verify_member(
                    dir_dec, 1500, &epoch_dec, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Epoch Proof Verify");

    TEST_ASSERT(
        epoch_len == full_len, "Epoch proof should be one sparse proof");
    printf("   [EPOCH-SPARSE] full=%zu, epoch=%zu\n", full_len, epoch_len);

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
                    tree, 50, 1000, 2000, merkle_ca_sign_cb, &sig_ctx, &dir)
            == SM2_IC_SUCCESS,
        "Build Epoch Directory");

    sm2_rev_delta_item_t patch1[] = { { 999999, true } };
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

    sm2_rev_delta_item_t patch2[] = { { 999999, false } };
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
    sm2_rev_tree_t *t_conflict = NULL;

    uint64_t revoked1[] = { 1001, 1002, 1003 };
    uint64_t revoked2[] = { 1001, 1002, 1003, 1004, 1005 };
    uint64_t revoked_conflict[] = { 2001, 2002, 2003 };

    TEST_ASSERT(sm2_rev_tree_build(
                    &t1, revoked1, sizeof(revoked1) / sizeof(revoked1[0]), 10)
            == SM2_IC_SUCCESS,
        "Build T1");
    TEST_ASSERT(sm2_rev_tree_build(
                    &t2, revoked2, sizeof(revoked2) / sizeof(revoked2[0]), 11)
            == SM2_IC_SUCCESS,
        "Build T2");
    TEST_ASSERT(sm2_rev_tree_build(&t_conflict, revoked_conflict,
                    sizeof(revoked_conflict) / sizeof(revoked_conflict[0]), 10)
            == SM2_IC_SUCCESS,
        "Build Conflicting T1");

    sm2_rev_epoch_dir_t *d1 = NULL;
    sm2_rev_epoch_dir_t *d2 = NULL;
    sm2_rev_epoch_dir_t *d_conflict = NULL;
    sm2_rev_epoch_dir_t *local = NULL;

    TEST_ASSERT(sm2_rev_epoch_dir_build(
                    t1, 60, 1000, 3000, merkle_ca_sign_cb, &sig_ctx, &d1)
            == SM2_IC_SUCCESS,
        "Build D1");
    TEST_ASSERT(sm2_rev_epoch_dir_build(
                    t2, 61, 1000, 3000, merkle_ca_sign_cb, &sig_ctx, &d2)
            == SM2_IC_SUCCESS,
        "Build D2");
    TEST_ASSERT(sm2_rev_epoch_dir_build(t_conflict, 60, 1000, 3000,
                    merkle_ca_sign_cb, &sig_ctx, &d_conflict)
            == SM2_IC_SUCCESS,
        "Build Conflicting D1");

    TEST_ASSERT(
        sm2_rev_epoch_switch(&local, d1, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Switch To D1");
    TEST_ASSERT(local != NULL, "Local Directory Materialized");
    TEST_ASSERT(sm2_rev_epoch_switch(
                    &local, d_conflict, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_ERR_VERIFY,
        "Reject Same Version Fork");
    TEST_ASSERT(
        sm2_rev_epoch_switch(&local, d2, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Switch To D2");
    TEST_ASSERT(
        sm2_rev_epoch_switch(&local, d1, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_ERR_VERIFY,
        "Reject Older Epoch");

    sm2_rev_epoch_dir_cleanup(&local);
    sm2_rev_epoch_dir_cleanup(&d_conflict);
    sm2_rev_epoch_dir_cleanup(&d2);
    sm2_rev_epoch_dir_cleanup(&d1);
    sm2_rev_tree_cleanup(&t_conflict);
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

    uint8_t mp_buf[1048576];
    size_t mp_len = sizeof(mp_buf);
    TEST_ASSERT(
        sm2_rev_multi_proof_encode(mp, mp_buf, &mp_len) == SM2_IC_SUCCESS,
        "Encode Metric MultiProof");

    size_t single_total = 0;
    size_t sibling_refs = 0;
    for (size_t i = 0; i < k; i++)
    {
        sm2_rev_member_proof_t member;
        uint8_t single_buf[16384];
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
                    tree, 66, 1000, 3000, merkle_ca_sign_cb, &sig_ctx, &dir)
            == SM2_IC_SUCCESS,
        "Build Metric Epoch Directory");

    sm2_rev_member_proof_t full;
    sm2_rev_member_proof_t epoch_proof;
    TEST_ASSERT(
        sm2_rev_tree_prove_member(tree, queries[0], &full) == SM2_IC_SUCCESS,
        "Build Full Proof For Epoch");
    TEST_ASSERT(sm2_rev_epoch_prove_member(tree, queries[0], &epoch_proof)
            == SM2_IC_SUCCESS,
        "Build Epoch Proof");

    TEST_ASSERT(full.sibling_count > 0, "Full Sibling Count Zero");

    printf("   [P8-METRIC] reuse=%.2f%%, bandwidth=%.2f%%\n",
        reuse_rate * 100.0, bandwidth_gain * 100.0);

    TEST_ASSERT(reuse_rate >= 0.20, "Reuse Rate < 20% after compressed proofs");
    TEST_ASSERT(epoch_proof.sibling_count == full.sibling_count,
        "Epoch proof should preserve sparse membership path");
    TEST_ASSERT(
        bandwidth_gain >= 0.05, "Bandwidth Gain < 5% after compressed proofs");

    sm2_rev_epoch_dir_cleanup(&dir);
    sm2_rev_multi_proof_cleanup(&mp);
    sm2_rev_tree_cleanup(&tree);
    free(revoked);
    TEST_PASS();
}
/* ----- Negative / Boundary Tests (Phase 3 hardening) ----- */
