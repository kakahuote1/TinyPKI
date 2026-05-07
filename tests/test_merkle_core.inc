static void merkle_read_root_hash_or_fail(
    const sm2_rev_tree_t *tree, uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN])
{
    TEST_ASSERT(sm2_rev_tree_get_root_hash(tree, root_hash) == SM2_IC_SUCCESS,
        "Read Merkle Root Hash");
}

static void test_rev_tree_member_and_absence()
{
    sm2_rev_tree_t *tree = NULL;
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];

    uint64_t revoked[] = { 500, 100, 300, 300, 900 };
    TEST_ASSERT(sm2_rev_tree_build(
                    &tree, revoked, sizeof(revoked) / sizeof(revoked[0]), 77)
            == SM2_IC_SUCCESS,
        "Merkle Build");
    TEST_ASSERT(sm2_rev_tree_root_version(tree) == 77, "Merkle Root Version");
    TEST_ASSERT(sm2_rev_tree_leaf_count(tree) == 4, "Merkle Dedup Leaf Count");
    merkle_read_root_hash_or_fail(tree, root_hash);

    sm2_rev_member_proof_t mp;
    TEST_ASSERT(sm2_rev_tree_prove_member(tree, 300, &mp) == SM2_IC_SUCCESS,
        "Member Proof Build");
    TEST_ASSERT(sm2_rev_tree_verify_member(root_hash, &mp) == SM2_IC_SUCCESS,
        "Member Proof Verify");

    sm2_rev_absence_proof_t nmp;
    TEST_ASSERT(sm2_rev_tree_prove_absence(tree, 301, &nmp) == SM2_IC_SUCCESS,
        "NonMember Proof Build");
    TEST_ASSERT(sm2_rev_tree_verify_absence(root_hash, &nmp) == SM2_IC_SUCCESS,
        "NonMember Proof Verify");

    TEST_ASSERT(
        sm2_rev_tree_prove_absence(tree, 300, &nmp) == SM2_IC_ERR_VERIFY,
        "Member Cannot Use NonMember Proof");

    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}

static void test_rev_tree_codec_roundtrip()
{
    sm2_rev_tree_t *tree = NULL;
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];

    uint64_t revoked[] = { 11, 33, 55, 77, 99 };
    TEST_ASSERT(sm2_rev_tree_build(
                    &tree, revoked, sizeof(revoked) / sizeof(revoked[0]), 101)
            == SM2_IC_SUCCESS,
        "Merkle Build");
    merkle_read_root_hash_or_fail(tree, root_hash);

    sm2_rev_member_proof_t mp;
    TEST_ASSERT(sm2_rev_tree_prove_member(tree, 55, &mp) == SM2_IC_SUCCESS,
        "Member Proof");

    uint8_t member_buf[16384];
    size_t member_len = sizeof(member_buf);
    TEST_ASSERT(sm2_rev_member_proof_encode(&mp, member_buf, &member_len)
            == SM2_IC_SUCCESS,
        "Member CBOR Encode");

    sm2_rev_member_proof_t mp_dec;
    TEST_ASSERT(sm2_rev_member_proof_decode(&mp_dec, member_buf, member_len)
            == SM2_IC_SUCCESS,
        "Member CBOR Decode");
    TEST_ASSERT(
        sm2_rev_tree_verify_member(root_hash, &mp_dec) == SM2_IC_SUCCESS,
        "Member CBOR Verify");

    sm2_rev_absence_proof_t nmp;
    TEST_ASSERT(sm2_rev_tree_prove_absence(tree, 56, &nmp) == SM2_IC_SUCCESS,
        "NonMember Proof");

    uint8_t non_buf[16384];
    size_t non_len = sizeof(non_buf);
    TEST_ASSERT(
        sm2_rev_absence_proof_encode(&nmp, non_buf, &non_len) == SM2_IC_SUCCESS,
        "NonMember CBOR Encode");

    sm2_rev_absence_proof_t nmp_dec;
    TEST_ASSERT(sm2_rev_absence_proof_decode(&nmp_dec, non_buf, non_len)
            == SM2_IC_SUCCESS,
        "NonMember CBOR Decode");
    TEST_ASSERT(
        sm2_rev_tree_verify_absence(root_hash, &nmp_dec) == SM2_IC_SUCCESS,
        "NonMember CBOR Verify");

    if (member_len > 8)
    {
        sm2_ic_error_t tamper_ret;

        member_buf[8] ^= 0x01;
        tamper_ret
            = sm2_rev_member_proof_decode(&mp_dec, member_buf, member_len);
        if (tamper_ret == SM2_IC_SUCCESS)
        {
            TEST_ASSERT(sm2_rev_tree_verify_member(root_hash, &mp_dec)
                    == SM2_IC_ERR_VERIFY,
                "Member Tamper Verify Fail");
        }
        else
        {
            TEST_ASSERT(
                tamper_ret == SM2_IC_ERR_CBOR, "Member Tamper Decode Reject");
        }
    }

    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}
static void test_rev_root_signature_and_light_verify()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_rev_tree_t *tree = NULL;

    uint64_t revoked[] = { 1001, 1002, 2001, 3003 };
    TEST_ASSERT(sm2_rev_tree_build(&tree, revoked,
                    sizeof(revoked) / sizeof(revoked[0]), 2026030601ULL)
            == SM2_IC_SUCCESS,
        "Merkle Build");

    merkle_ca_sig_ctx_t sig_ctx = { &g_ca_priv, &g_ca_pub };

    sm2_rev_root_record_t root_record;
    TEST_ASSERT(sm2_rev_root_sign_with_authority(tree, g_merkle_authority,
                    sizeof(g_merkle_authority) - 1, 1000, 2000,
                    merkle_ca_sign_cb, &sig_ctx, &root_record)
            == SM2_IC_SUCCESS,
        "Root Sign");

    uint8_t root_buf[1024];
    size_t root_len = sizeof(root_buf);
    TEST_ASSERT(sm2_rev_root_encode(&root_record, root_buf, &root_len)
            == SM2_IC_SUCCESS,
        "Root CBOR Encode");

    sm2_rev_root_record_t root_dec;
    TEST_ASSERT(
        sm2_rev_root_decode(&root_dec, root_buf, root_len) == SM2_IC_SUCCESS,
        "Root CBOR Decode");

    TEST_ASSERT(
        sm2_rev_root_verify(&root_dec, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Root Verify");

    sm2_rev_member_proof_t mp;
    TEST_ASSERT(sm2_rev_tree_prove_member(tree, 2001, &mp) == SM2_IC_SUCCESS,
        "Member Proof");
    TEST_ASSERT(sm2_rev_member_proof_verify_with_root(
                    &root_dec, 1500, &mp, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Member Verify With Root");

    sm2_rev_absence_proof_t nmp;
    TEST_ASSERT(sm2_rev_tree_prove_absence(tree, 2002, &nmp) == SM2_IC_SUCCESS,
        "NonMember Proof");
    TEST_ASSERT(sm2_rev_absence_proof_verify_with_root(
                    &root_dec, 1500, &nmp, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "NonMember Verify With Root");

    root_dec.signature[0] ^= 0x01;
    TEST_ASSERT(
        sm2_rev_root_verify(&root_dec, 1500, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_ERR_VERIFY,
        "Root Tamper Reject");
    root_dec.signature[0] ^= 0x01;

    TEST_ASSERT(sm2_rev_member_proof_verify_with_root(
                    &root_dec, 2001, &mp, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_ERR_VERIFY,
        "Root Expire Reject");

    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}
static void test_rev_multi_proof_roundtrip()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_rev_tree_t *tree = NULL;
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];

    uint64_t revoked[64];
    for (size_t i = 0; i < 64; i++)
        revoked[i] = 1000 + i;

    TEST_ASSERT(sm2_rev_tree_build(&tree, revoked,
                    sizeof(revoked) / sizeof(revoked[0]), 2026030602ULL)
            == SM2_IC_SUCCESS,
        "Merkle Build");
    merkle_read_root_hash_or_fail(tree, root_hash);

    uint64_t queries[] = { 1010, 1011, 1012, 1020, 1021, 1030, 1031, 1032 };
    sm2_rev_multi_proof_t *mp = NULL;

    TEST_ASSERT(sm2_rev_multi_proof_build(
                    tree, queries, sizeof(queries) / sizeof(queries[0]), &mp)
            == SM2_IC_SUCCESS,
        "Build MultiProof");
    TEST_ASSERT(sm2_rev_multi_proof_unique_hash_count(mp) > 0,
        "MultiProof Unique Hashes");
    TEST_ASSERT(sm2_rev_multi_proof_verify(root_hash, mp) == SM2_IC_SUCCESS,
        "Verify MultiProof");

    uint8_t mp_buf[65536];
    size_t mp_len = sizeof(mp_buf);
    TEST_ASSERT(
        sm2_rev_multi_proof_encode(mp, mp_buf, &mp_len) == SM2_IC_SUCCESS,
        "MultiProof CBOR Encode");

    sm2_rev_multi_proof_t *mp_dec = NULL;
    TEST_ASSERT(
        sm2_rev_multi_proof_decode(&mp_dec, mp_buf, mp_len) == SM2_IC_SUCCESS,
        "MultiProof CBOR Decode");
    TEST_ASSERT(sm2_rev_multi_proof_verify(root_hash, mp_dec) == SM2_IC_SUCCESS,
        "Verify MultiProof Decoded");

    merkle_ca_sig_ctx_t sig_ctx = { &g_ca_priv, &g_ca_pub };
    sm2_rev_root_record_t root_record;
    TEST_ASSERT(sm2_rev_root_sign_with_authority(tree, g_merkle_authority,
                    sizeof(g_merkle_authority) - 1, 1000, 2000,
                    merkle_ca_sign_cb, &sig_ctx, &root_record)
            == SM2_IC_SUCCESS,
        "Sign Root For MultiProof");
    TEST_ASSERT(sm2_rev_multi_proof_verify_with_root(
                    &root_record, 1500, mp_dec, merkle_ca_verify_cb, &sig_ctx)
            == SM2_IC_SUCCESS,
        "Verify MultiProof With Root");

    mp_buf[mp_len - 1] ^= 0x01;
    sm2_rev_multi_proof_t *mp_tampered = NULL;
    sm2_ic_error_t tampered_decode
        = sm2_rev_multi_proof_decode(&mp_tampered, mp_buf, mp_len);
    TEST_ASSERT(tampered_decode != SM2_IC_SUCCESS
            || sm2_rev_multi_proof_verify(root_hash, mp_tampered)
                == SM2_IC_ERR_VERIFY,
        "MultiProof Tamper Reject");

    sm2_rev_multi_proof_cleanup(&mp_tampered);
    sm2_rev_multi_proof_cleanup(&mp_dec);
    sm2_rev_multi_proof_cleanup(&mp);
    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}

static void test_rev_multi_proof_bandwidth_gain()
{
    sm2_rev_tree_t *tree = NULL;

    uint64_t revoked[2048];
    for (size_t i = 0; i < 2048; i++)
        revoked[i] = 100000 + i;

    TEST_ASSERT(sm2_rev_tree_build(&tree, revoked,
                    sizeof(revoked) / sizeof(revoked[0]), 2026030603ULL)
            == SM2_IC_SUCCESS,
        "Merkle Build Large");

    const size_t ks[] = { 8, 16, 32 };
    for (size_t t = 0; t < sizeof(ks) / sizeof(ks[0]); t++)
    {
        size_t k = ks[t];
        uint64_t queries[32];
        for (size_t i = 0; i < k; i++)
            queries[i] = revoked[900 + i];

        sm2_rev_multi_proof_t *mp = NULL;
        TEST_ASSERT(
            sm2_rev_multi_proof_build(tree, queries, k, &mp) == SM2_IC_SUCCESS,
            "Build MultiProof K");

        uint8_t multi_buf[1048576];
        size_t multi_len = sizeof(multi_buf);
        TEST_ASSERT(sm2_rev_multi_proof_encode(mp, multi_buf, &multi_len)
                == SM2_IC_SUCCESS,
            "Encode MultiProof K");

        size_t single_total = 0;
        for (size_t i = 0; i < k; i++)
        {
            sm2_rev_member_proof_t member;
            TEST_ASSERT(sm2_rev_tree_prove_member(tree, queries[i], &member)
                    == SM2_IC_SUCCESS,
                "Single Proof Build");

            uint8_t single_buf[16384];
            size_t single_len = sizeof(single_buf);
            TEST_ASSERT(
                sm2_rev_member_proof_encode(&member, single_buf, &single_len)
                    == SM2_IC_SUCCESS,
                "Single Proof Encode");
            single_total += single_len;
        }

        TEST_ASSERT(single_total > 0, "Single Total NonZero");
        TEST_ASSERT(multi_len < single_total, "MultiProof Smaller");

        double reduction = 1.0 - ((double)multi_len / (double)single_total);
        printf(
            "   [MULTIPROOF] k=%zu, single=%zu, multi=%zu, reduction=%.2f%%\n",
            k, single_total, multi_len, reduction * 100.0);

        if (k == 16)
        {
            TEST_ASSERT(reduction >= 0.05,
                "k=16 MultiProof Reduction < 5% after compressed proofs");
        }

        sm2_rev_multi_proof_cleanup(&mp);
    }

    sm2_rev_tree_cleanup(&tree);
    TEST_PASS();
}
static void test_rev_epoch_dir_sparse_proof()
