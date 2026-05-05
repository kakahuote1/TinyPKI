static void test_merkle_empty_tree_prove_member_fails(void)
{
    sm2_rev_tree_t *tree = NULL;
    TEST_ASSERT(sm2_rev_tree_build(&tree, NULL, 0, 1) == SM2_IC_SUCCESS,
        "Build empty tree");
    TEST_ASSERT(sm2_rev_tree_leaf_count(tree) == 0, "Empty tree has 0 leaves");

    sm2_rev_member_proof_t mp;
    TEST_ASSERT(sm2_rev_tree_prove_member(tree, 42, &mp) == SM2_IC_ERR_VERIFY,
        "prove_member on empty tree must fail");

    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}

static void test_merkle_expired_root_record_rejected(void)
{
    uint64_t revoked[] = { 10, 20, 30 };
    sm2_rev_tree_t *tree = NULL;
    TEST_ASSERT(sm2_rev_tree_build(&tree, revoked, 3, 1) == SM2_IC_SUCCESS,
        "Build tree");

    merkle_ca_sig_ctx_t ctx = { &g_ca_priv, &g_ca_pub };
    sm2_rev_root_record_t root;
    TEST_ASSERT(
        sm2_rev_root_sign(tree, 1000, 2000, merkle_ca_sign_cb, &ctx, &root)
            == SM2_IC_SUCCESS,
        "Sign root");

    /* now_ts=3000 > valid_until=2000 -> should reject */
    TEST_ASSERT(sm2_rev_root_verify(&root, 3000, merkle_ca_verify_cb, &ctx)
            == SM2_IC_ERR_VERIFY,
        "Expired root must be rejected");

    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}

static void test_merkle_hot_patch_stale_version_rejected(void)
{
    uint64_t revoked[] = { 100, 200, 300 };
    sm2_rev_tree_t *tree = NULL;
    TEST_ASSERT(sm2_rev_tree_build(&tree, revoked, 3, 1) == SM2_IC_SUCCESS,
        "Build tree");

    merkle_ca_sig_ctx_t ctx = { &g_ca_priv, &g_ca_pub };
    sm2_rev_epoch_dir_t *dir = NULL;
    TEST_ASSERT(sm2_rev_epoch_dir_build(
                    tree, 1, 1000, 9000, merkle_ca_sign_cb, &ctx, &dir)
            == SM2_IC_SUCCESS,
        "Build epoch dir");

    sm2_rev_delta_item_t patch1 = { 400, true };
    TEST_ASSERT(
        sm2_rev_epoch_apply_patch(dir, 5, &patch1, 1, merkle_ca_sign_cb, &ctx)
            == SM2_IC_SUCCESS,
        "Hot patch v5");

    /* Apply same version again -> should fail */
    sm2_rev_delta_item_t patch2 = { 500, true };
    sm2_ic_error_t stale_ret = sm2_rev_epoch_apply_patch(
        dir, 5, &patch2, 1, merkle_ca_sign_cb, &ctx);
    TEST_ASSERT(
        stale_ret != SM2_IC_SUCCESS, "Stale patch version must be rejected");

    /* Apply older version -> should fail */
    sm2_ic_error_t older_ret = sm2_rev_epoch_apply_patch(
        dir, 3, &patch2, 1, merkle_ca_sign_cb, &ctx);
    TEST_ASSERT(
        older_ret != SM2_IC_SUCCESS, "Older patch version must be rejected");

    sm2_rev_epoch_dir_cleanup(&dir);
    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}

static void test_merkle_multiproof_over_limit_rejected(void)
{
    uint64_t serials[SM2_REV_MERKLE_MULTI_MAX_QUERIES + 1];
    for (size_t i = 0; i < SM2_REV_MERKLE_MULTI_MAX_QUERIES + 1; i++)
        serials[i] = (uint64_t)(i + 1);

    sm2_rev_tree_t *tree = NULL;
    TEST_ASSERT(sm2_rev_tree_build(
                    &tree, serials, SM2_REV_MERKLE_MULTI_MAX_QUERIES + 1, 1)
            == SM2_IC_SUCCESS,
        "Build tree");

    sm2_rev_multi_proof_t *mp = NULL;
    sm2_ic_error_t ret = sm2_rev_multi_proof_build(
        tree, serials, SM2_REV_MERKLE_MULTI_MAX_QUERIES + 1, &mp);
    TEST_ASSERT(ret == SM2_IC_ERR_PARAM,
        "Multiproof over MULTI_MAX_QUERIES must be rejected");

    sm2_rev_multi_proof_cleanup(&mp);

    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}

static void test_merkle_member_sparse_key_path_bound(void)
{
    uint64_t revoked[] = { 10, 20, 30, 40, 50, 60, 70, 80 };
    sm2_rev_tree_t *tree = NULL;
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];
    TEST_ASSERT(sm2_rev_tree_build(
                    &tree, revoked, sizeof(revoked) / sizeof(revoked[0]), 1)
            == SM2_IC_SUCCESS,
        "Build tree");
    merkle_read_root_hash_or_fail(tree, root_hash);

    sm2_rev_member_proof_t proof;
    TEST_ASSERT(sm2_rev_tree_prove_member(tree, 40, &proof) == SM2_IC_SUCCESS,
        "Build member proof");
    TEST_ASSERT(proof.sibling_count == SM2_REV_MERKLE_MAX_DEPTH,
        "Sparse proof has fixed depth");

    sm2_rev_member_proof_t tampered = proof;
    tampered.key[0] ^= 0x01U;
    TEST_ASSERT(
        sm2_rev_tree_verify_member(root_hash, &tampered) == SM2_IC_ERR_VERIFY,
        "Tampered sparse key must be path-bound");

    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}

static void test_merkle_absence_sparse_path_commitment(void)
{
    uint64_t revoked[] = { 2, 5, 9 };
    sm2_rev_tree_t *tree = NULL;
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];
    TEST_ASSERT(sm2_rev_tree_build(
                    &tree, revoked, sizeof(revoked) / sizeof(revoked[0]), 1)
            == SM2_IC_SUCCESS,
        "Build tree");
    merkle_read_root_hash_or_fail(tree, root_hash);

    sm2_rev_absence_proof_t proof;
    TEST_ASSERT(sm2_rev_tree_prove_absence(tree, 3, &proof) == SM2_IC_SUCCESS,
        "Build absence proof");
    TEST_ASSERT(!proof.tree_empty, "Absence proof is non-empty sparse path");
    TEST_ASSERT(proof.sibling_count == SM2_REV_MERKLE_MAX_DEPTH,
        "Absence proof has fixed sparse depth");
    TEST_ASSERT(
        sm2_rev_tree_verify_absence(root_hash, &proof) == SM2_IC_SUCCESS,
        "Verify absence proof");

    sm2_rev_absence_proof_t tampered = proof;
    tampered.sibling_hashes[0][0] ^= 0x01U;
    TEST_ASSERT(
        sm2_rev_tree_verify_absence(root_hash, &tampered) == SM2_IC_ERR_VERIFY,
        "Tampered sparse path must fail");

    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}

static void test_merkle_quorum_dedup_node_id(void)
{
    sm2_rev_quorum_vote_t votes[3];
    memset(votes, 0, sizeof(votes));

    uint8_t node_a[] = "node_A";
    uint8_t node_b[] = "node_B";

    /* Vote 0 and Vote 1: same node_id, different revocation status */
    memcpy(votes[0].node_id, node_a, sizeof(node_a));
    votes[0].node_id_len = sizeof(node_a);
    votes[0].proof_valid = true;
    votes[0].root_version = 10;
    votes[0].status = SM2_REV_STATUS_REVOKED;
    memset(votes[0].root_hash, 0xAA, SM2_REV_SYNC_DIGEST_LEN);

    memcpy(votes[1].node_id, node_a, sizeof(node_a));
    votes[1].node_id_len = sizeof(node_a);
    votes[1].proof_valid = true;
    votes[1].root_version = 10;
    votes[1].status = SM2_REV_STATUS_GOOD;
    memset(votes[1].root_hash, 0xAA, SM2_REV_SYNC_DIGEST_LEN);

    memcpy(votes[2].node_id, node_b, sizeof(node_b));
    votes[2].node_id_len = sizeof(node_b);
    votes[2].proof_valid = true;
    votes[2].root_version = 10;
    votes[2].status = SM2_REV_STATUS_REVOKED;
    memset(votes[2].root_hash, 0xAA, SM2_REV_SYNC_DIGEST_LEN);

    sm2_rev_quorum_result_t result;
    sm2_ic_error_t ret = sm2_rev_quorum_check(votes, 3, 2, &result);
    TEST_ASSERT(ret == SM2_IC_SUCCESS, "Quorum evaluate ok");
    TEST_ASSERT(result.unique_node_count == 2,
        "Duplicate node_id must be deduped (2 unique)");

    TEST_PASS();
}
