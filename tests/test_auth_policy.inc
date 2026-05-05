static void test_auth_with_revocation_block()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"REVOKE_AUTH", 11,
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

    sm2_auth_trust_store_t trust;
    TEST_ASSERT(
        sm2_auth_trust_store_init(&trust) == SM2_IC_SUCCESS, "Trust Init");
    TEST_ASSERT(
        sm2_auth_trust_store_add_ca(&trust, &g_ca_pub) == SM2_IC_SUCCESS,
        "Trust Add");

    sm2_rev_ctx_t *rev_ctx = NULL;
    uint64_t now = test_cert_now(&cert_res.cert);
    TEST_ASSERT(
        sm2_rev_init(&rev_ctx, 32, 300, now) == SM2_IC_SUCCESS, "Rev Init");
    sm2_rev_delta_item_t items[] = { { cert_res.cert.serial_number, true } };
    sm2_rev_delta_t delta = { 0, 1, items, 1 };
    TEST_ASSERT(
        sm2_rev_apply_delta(rev_ctx, &delta, now + 20) == SM2_IC_SUCCESS,
        "Apply Delta");

    const uint8_t msg[] = "AUTH_WITH_REVOCATION";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_auth_sign(&user_priv, msg, sizeof(msg) - 1, &sig) == SM2_IC_SUCCESS,
        "Sign");
    sm2_auth_request_t request
        = { &cert_res.cert, &user_pub, msg, sizeof(msg) - 1, &sig };
    TEST_ASSERT(
        sm2_auth_authenticate_request(&request, &trust, rev_ctx, now + 30, NULL)
            == SM2_IC_ERR_VERIFY,
        "Revocation Block");

    sm2_rev_cleanup(&rev_ctx);
    TEST_PASS();
}

static void test_auth_local_revocation_good_requires_opt_in()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"LOCAL_REV_TRUST",
                    15, SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
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

    sm2_auth_trust_store_t trust;
    TEST_ASSERT(
        sm2_auth_trust_store_init(&trust) == SM2_IC_SUCCESS, "Trust Init");
    TEST_ASSERT(
        sm2_auth_trust_store_add_ca(&trust, &g_ca_pub) == SM2_IC_SUCCESS,
        "Trust Add");

    sm2_rev_ctx_t *rev_ctx = NULL;
    uint64_t now = test_cert_now(&cert_res.cert);
    TEST_ASSERT(
        sm2_rev_init(&rev_ctx, 8, 300, now) == SM2_IC_SUCCESS, "Rev Init");

    const uint8_t msg[] = "LOCAL_REV_TRUST_MSG";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_auth_sign(&user_priv, msg, sizeof(msg) - 1, &sig) == SM2_IC_SUCCESS,
        "Sign");

    sm2_auth_request_t request
        = { &cert_res.cert, &user_pub, msg, sizeof(msg) - 1, &sig };
    TEST_ASSERT(
        sm2_auth_authenticate_request(&request, &trust, rev_ctx, now + 1, NULL)
            == SM2_IC_ERR_VERIFY,
        "Local GOOD Requires Opt-In");

    request.allow_local_revocation_state = true;
    TEST_ASSERT(
        sm2_auth_authenticate_request(&request, &trust, rev_ctx, now + 1, NULL)
            == SM2_IC_SUCCESS,
        "Explicit Local GOOD Opt-In");

    sm2_rev_cleanup(&rev_ctx);
    TEST_PASS();
}

static void test_auth_cert_policy_time_and_usage()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"AUTH_POLICY_SIG",
                    15, SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Create Policy Req");
    TEST_ASSERT(test_issue_cert(
                    &cert_res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue Policy Cert");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon Policy Keys");

    sm2_auth_trust_store_t trust;
    TEST_ASSERT(sm2_auth_trust_store_init(&trust) == SM2_IC_SUCCESS,
        "Policy Trust Init");
    TEST_ASSERT(
        sm2_auth_trust_store_add_ca(&trust, &g_ca_pub) == SM2_IC_SUCCESS,
        "Policy Trust Add");

    const uint8_t msg[] = "AUTH_POLICY_MESSAGE";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_auth_sign(&user_priv, msg, sizeof(msg) - 1, &sig) == SM2_IC_SUCCESS,
        "Policy Sign");

    sm2_auth_request_t request
        = { &cert_res.cert, &user_pub, msg, sizeof(msg) - 1, &sig };

    uint64_t now = cert_res.cert.valid_from;
    if (now == 0)
        now = (uint64_t)time(NULL);
    TEST_ASSERT(sm2_auth_authenticate_request(&request, &trust, NULL, now, NULL)
            == SM2_IC_ERR_VERIFY,
        "Reject Missing Revocation Source By Default");
    request.allow_missing_revocation_check = true;
    TEST_ASSERT(sm2_auth_authenticate_request(&request, &trust, NULL, now, NULL)
            == SM2_IC_SUCCESS,
        "Policy Baseline Accept");
    TEST_ASSERT(
        sm2_auth_authenticate_request(&request, &trust, NULL, 1000, NULL)
            == SM2_IC_ERR_VERIFY,
        "Reject Mixed Timescale Timestamp");

    if (cert_res.cert.valid_from > 0)
    {
        uint64_t before = cert_res.cert.valid_from - 1;
        TEST_ASSERT(
            sm2_auth_authenticate_request(&request, &trust, NULL, before, NULL)
                == SM2_IC_ERR_VERIFY,
            "Reject Not Yet Valid");
    }

    uint64_t expired = cert_res.cert.valid_from;
    if (cert_res.cert.valid_duration <= UINT64_MAX - expired)
        expired += cert_res.cert.valid_duration + 1;
    else
        expired = UINT64_MAX;
    TEST_ASSERT(
        sm2_auth_authenticate_request(&request, &trust, NULL, expired, NULL)
            == SM2_IC_ERR_VERIFY,
        "Reject Expired Cert");

    sm2_ic_cert_request_t req_usage;
    sm2_private_key_t temp_usage;
    sm2_ic_cert_result_t cert_usage;
    sm2_private_key_t priv_usage;
    sm2_ec_point_t pub_usage;
    TEST_ASSERT(
        sm2_ic_create_cert_request(&req_usage, (uint8_t *)"AUTH_POLICY_KA", 14,
            SM2_KU_KEY_AGREEMENT, &temp_usage)
            == SM2_IC_SUCCESS,
        "Create Usage Req");
    TEST_ASSERT(test_issue_cert(&cert_usage, &req_usage, (uint8_t *)"CA", 2,
                    &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue Usage Cert");
    TEST_ASSERT(sm2_ic_reconstruct_keys(&priv_usage, &pub_usage, &cert_usage,
                    &temp_usage, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon Usage Keys");

    sm2_auth_signature_t sig_usage;
    TEST_ASSERT(sm2_auth_sign(&priv_usage, msg, sizeof(msg) - 1, &sig_usage)
            == SM2_IC_SUCCESS,
        "Usage Sign");
    sm2_auth_request_t req_non_sig
        = { &cert_usage.cert, &pub_usage, msg, sizeof(msg) - 1, &sig_usage };
    req_non_sig.allow_missing_revocation_check = true;
    uint64_t now_usage = cert_usage.cert.valid_from;
    if (now_usage == 0)
        now_usage = now;
    TEST_ASSERT(sm2_auth_authenticate_request(
                    &req_non_sig, &trust, NULL, now_usage, NULL)
            == SM2_IC_ERR_VERIFY,
        "Reject Non Signature Usage");

    sm2_implicit_cert_t cert_missing_duration = cert_res.cert;
    cert_missing_duration.field_mask
        &= (uint16_t)(~SM2_IC_FIELD_VALID_DURATION);
    sm2_auth_request_t req_missing_duration
        = { &cert_missing_duration, &user_pub, msg, sizeof(msg) - 1, &sig };
    req_missing_duration.allow_missing_revocation_check = true;
    TEST_ASSERT(sm2_auth_authenticate_request(
                    &req_missing_duration, &trust, NULL, now, NULL)
            == SM2_IC_ERR_VERIFY,
        "Reject Missing ValidDuration Field");

    sm2_implicit_cert_t cert_missing_from = cert_res.cert;
    cert_missing_from.field_mask &= (uint16_t)(~SM2_IC_FIELD_VALID_FROM);
    sm2_auth_request_t req_missing_from
        = { &cert_missing_from, &user_pub, msg, sizeof(msg) - 1, &sig };
    req_missing_from.allow_missing_revocation_check = true;
    TEST_ASSERT(sm2_auth_authenticate_request(
                    &req_missing_from, &trust, NULL, now, NULL)
            == SM2_IC_ERR_VERIFY,
        "Reject Missing ValidFrom Field");

    TEST_PASS();
}

static void test_auth_revocation_policy_strict_cross_check()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"AUTH_STRICT_REV",
                    15, SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "Create Req");
    TEST_ASSERT(test_issue_cert(
                    &cert_res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue Cert");
    TEST_ASSERT(sm2_ic_reconstruct_keys(
                    &user_priv, &user_pub, &cert_res, &temp_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Reconstruct Keys");

    sm2_auth_trust_store_t trust;
    TEST_ASSERT(
        sm2_auth_trust_store_init(&trust) == SM2_IC_SUCCESS, "Trust Init");
    TEST_ASSERT(
        sm2_auth_trust_store_add_ca(&trust, &g_ca_pub) == SM2_IC_SUCCESS,
        "Trust Add");

    sm2_rev_ctx_t *rev_ctx = NULL;
    uint64_t now = test_cert_now(&cert_res.cert);
    TEST_ASSERT(
        sm2_rev_init(&rev_ctx, 32, 300, now) == SM2_IC_SUCCESS, "Rev Init");
    sm2_rev_delta_item_t items[] = { { cert_res.cert.serial_number, true } };
    sm2_rev_delta_t delta = { 0, 1, items, 1 };
    TEST_ASSERT(sm2_rev_apply_delta(rev_ctx, &delta, now + 1) == SM2_IC_SUCCESS,
        "Apply Delta");

    const uint8_t msg[] = "AUTH_STRICT_REV_MSG";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_auth_sign(&user_priv, msg, sizeof(msg) - 1, &sig) == SM2_IC_SUCCESS,
        "Sign Msg");

    auth_revocation_cb_ctx_t cb_ctx;
    cb_ctx.status = SM2_REV_STATUS_GOOD;

    sm2_auth_request_t request = { .cert = &cert_res.cert,
        .public_key = &user_pub,
        .message = msg,
        .message_len = sizeof(msg) - 1,
        .signature = &sig,
        .revocation_query_fn = auth_revocation_status_cb,
        .revocation_query_user_ctx = &cb_ctx,
        .revocation_policy = SM2_AUTH_REVOCATION_POLICY_PREFER_CALLBACK };

    TEST_ASSERT(
        sm2_auth_authenticate_request(&request, &trust, rev_ctx, now + 2, NULL)
            == SM2_IC_SUCCESS,
        "Prefer Callback Accept");

    request.revocation_policy = SM2_AUTH_REVOCATION_POLICY_STRICT_CROSS_CHECK;
    TEST_ASSERT(
        sm2_auth_authenticate_request(&request, &trust, rev_ctx, now + 2, NULL)
            == SM2_IC_ERR_VERIFY,
        "Strict Cross Check Reject");

    TEST_ASSERT(
        sm2_auth_authenticate_request(&request, &trust, NULL, now + 2, NULL)
            == SM2_IC_ERR_VERIFY,
        "Strict Without Local Source Reject");

    sm2_rev_cleanup(&rev_ctx);
    TEST_PASS();
}

static void test_auth_forward_secure_session_key()
{
    if (!g_ca_initialized)
        test_setup_ca();

    sm2_ic_cert_request_t req_a, req_b;
    sm2_private_key_t temp_a, temp_b;
    sm2_ic_cert_result_t cert_a, cert_b;
    sm2_private_key_t priv_a, priv_b;
    sm2_ec_point_t pub_a, pub_b;

    TEST_ASSERT(sm2_ic_create_cert_request(&req_a, (uint8_t *)"FS_A", 4,
                    SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT, &temp_a)
            == SM2_IC_SUCCESS,
        "Req A");
    TEST_ASSERT(sm2_ic_create_cert_request(&req_b, (uint8_t *)"FS_B", 4,
                    SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT, &temp_b)
            == SM2_IC_SUCCESS,
        "Req B");
    TEST_ASSERT(test_issue_cert(
                    &cert_a, &req_a, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue A");
    TEST_ASSERT(test_issue_cert(
                    &cert_b, &req_b, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Issue B");
    TEST_ASSERT(
        sm2_ic_reconstruct_keys(&priv_a, &pub_a, &cert_a, &temp_a, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon A");
    TEST_ASSERT(
        sm2_ic_reconstruct_keys(&priv_b, &pub_b, &cert_b, &temp_b, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "Recon B");

    sm2_auth_signature_t sig_a, sig_b;

    sm2_auth_trust_store_t trust_a, trust_b;
    TEST_ASSERT(
        sm2_auth_trust_store_init(&trust_a) == SM2_IC_SUCCESS, "TrustA Init");
    TEST_ASSERT(
        sm2_auth_trust_store_init(&trust_b) == SM2_IC_SUCCESS, "TrustB Init");
    TEST_ASSERT(
        sm2_auth_trust_store_add_ca(&trust_a, &g_ca_pub) == SM2_IC_SUCCESS,
        "TrustA Add");
    TEST_ASSERT(
        sm2_auth_trust_store_add_ca(&trust_b, &g_ca_pub) == SM2_IC_SUCCESS,
        "TrustB Add");

    sm2_auth_request_t a_to_b = { .cert = &cert_a.cert,
        .public_key = &pub_a,
        .message = NULL,
        .message_len = 0,
        .signature = &sig_a,
        .revocation_query_fn = NULL,
        .revocation_query_user_ctx = NULL,
        .revocation_policy = SM2_AUTH_REVOCATION_POLICY_PREFER_CALLBACK,
        .allow_missing_revocation_check = true };

    sm2_auth_request_t b_to_a = { .cert = &cert_b.cert,
        .public_key = &pub_b,
        .message = NULL,
        .message_len = 0,
        .signature = &sig_b,
        .revocation_query_fn = NULL,
        .revocation_query_user_ctx = NULL,
        .revocation_policy = SM2_AUTH_REVOCATION_POLICY_PREFER_CALLBACK,
        .allow_missing_revocation_check = true };
    uint64_t now = test_cert_pair_now(&cert_a.cert, &cert_b.cert);

    sm2_private_key_t eph_priv_a1, eph_priv_b1;
    sm2_private_key_t eph_priv_a2, eph_priv_b2;
    sm2_ec_point_t eph_pub_a1, eph_pub_b1;
    sm2_ec_point_t eph_pub_a2, eph_pub_b2;

    TEST_ASSERT(sm2_auth_generate_ephemeral_keypair(&eph_priv_a1, &eph_pub_a1)
            == SM2_IC_SUCCESS,
        "Eph A1");
    TEST_ASSERT(sm2_auth_generate_ephemeral_keypair(&eph_priv_b1, &eph_pub_b1)
            == SM2_IC_SUCCESS,
        "Eph B1");

    uint8_t sk_a1[16], sk_b1[16];
    const uint8_t transcript1[] = "TRANSCRIPT_1";
    uint8_t bind_a1[256];
    uint8_t bind_b1[256];
    size_t bind_a1_len = sizeof(bind_a1);
    size_t bind_b1_len = sizeof(bind_b1);
    TEST_ASSERT(sm2_auth_build_handshake_binding(&eph_pub_a1, &eph_pub_b1,
                    transcript1, sizeof(transcript1) - 1, bind_a1, &bind_a1_len)
            == SM2_IC_SUCCESS,
        "Build Bind A1");
    TEST_ASSERT(sm2_auth_build_handshake_binding(&eph_pub_b1, &eph_pub_a1,
                    transcript1, sizeof(transcript1) - 1, bind_b1, &bind_b1_len)
            == SM2_IC_SUCCESS,
        "Build Bind B1");
    TEST_ASSERT(sm2_auth_sign(&priv_a, bind_a1, bind_a1_len, &sig_a)
            == SM2_IC_SUCCESS,
        "Sign Bind A1");
    TEST_ASSERT(sm2_auth_sign(&priv_b, bind_b1, bind_b1_len, &sig_b)
            == SM2_IC_SUCCESS,
        "Sign Bind B1");
    a_to_b.message = bind_a1;
    a_to_b.message_len = bind_a1_len;
    b_to_a.message = bind_b1;
    b_to_a.message_len = bind_b1_len;
    TEST_ASSERT(sm2_auth_mutual_handshake(&a_to_b, &priv_a, &eph_priv_a1,
                    &eph_pub_a1, &trust_b, NULL, &b_to_a, &priv_b, &eph_priv_b1,
                    &eph_pub_b1, &trust_a, NULL, now, transcript1,
                    sizeof(transcript1) - 1, sk_a1, sk_b1, sizeof(sk_a1))
            == SM2_IC_SUCCESS,
        "V2 Key Agreement S1");
    TEST_ASSERT(memcmp(sk_a1, sk_b1, sizeof(sk_a1)) == 0, "V2 Equal S1");

    TEST_ASSERT(sm2_auth_generate_ephemeral_keypair(&eph_priv_a2, &eph_pub_a2)
            == SM2_IC_SUCCESS,
        "Eph A2");
    TEST_ASSERT(sm2_auth_generate_ephemeral_keypair(&eph_priv_b2, &eph_pub_b2)
            == SM2_IC_SUCCESS,
        "Eph B2");

    uint8_t sk_a2[16], sk_b2[16];
    TEST_ASSERT(sm2_auth_mutual_handshake(&a_to_b, &priv_a, &eph_priv_a2,
                    &eph_pub_a2, &trust_b, NULL, &b_to_a, &priv_b, &eph_priv_b2,
                    &eph_pub_b2, &trust_a, NULL, now, transcript1,
                    sizeof(transcript1) - 1, sk_a2, sk_b2, sizeof(sk_a2))
            == SM2_IC_ERR_VERIFY,
        "Reject Stale Handshake Binding");
    uint8_t bind_a2[256];
    uint8_t bind_b2[256];
    size_t bind_a2_len = sizeof(bind_a2);
    size_t bind_b2_len = sizeof(bind_b2);
    TEST_ASSERT(sm2_auth_build_handshake_binding(&eph_pub_a2, &eph_pub_b2,
                    transcript1, sizeof(transcript1) - 1, bind_a2, &bind_a2_len)
            == SM2_IC_SUCCESS,
        "Build Bind A2");
    TEST_ASSERT(sm2_auth_build_handshake_binding(&eph_pub_b2, &eph_pub_a2,
                    transcript1, sizeof(transcript1) - 1, bind_b2, &bind_b2_len)
            == SM2_IC_SUCCESS,
        "Build Bind B2");
    TEST_ASSERT(sm2_auth_sign(&priv_a, bind_a2, bind_a2_len, &sig_a)
            == SM2_IC_SUCCESS,
        "Sign Bind A2");
    TEST_ASSERT(sm2_auth_sign(&priv_b, bind_b2, bind_b2_len, &sig_b)
            == SM2_IC_SUCCESS,
        "Sign Bind B2");
    a_to_b.message = bind_a2;
    a_to_b.message_len = bind_a2_len;
    b_to_a.message = bind_b2;
    b_to_a.message_len = bind_b2_len;
    TEST_ASSERT(sm2_auth_mutual_handshake(&a_to_b, &priv_a, &eph_priv_a2,
                    &eph_pub_a2, &trust_b, NULL, &b_to_a, &priv_b, &eph_priv_b2,
                    &eph_pub_b2, &trust_a, NULL, now, transcript1,
                    sizeof(transcript1) - 1, sk_a2, sk_b2, sizeof(sk_a2))
            == SM2_IC_SUCCESS,
        "V2 Key Agreement S2");
    TEST_ASSERT(memcmp(sk_a2, sk_b2, sizeof(sk_a2)) == 0, "V2 Equal S2");
    TEST_ASSERT(memcmp(sk_a1, sk_a2, sizeof(sk_a1)) != 0,
        "Ephemeral Rotation Changes Key");

    uint8_t tkey1[16], tkey2[16];
    const uint8_t transcript2[] = "TRANSCRIPT_2";
    TEST_ASSERT(
        sm2_auth_derive_session_key(&priv_a, &eph_priv_a1, &pub_b, &eph_pub_b1,
            transcript1, sizeof(transcript1) - 1, tkey1, sizeof(tkey1))
            == SM2_IC_SUCCESS,
        "Derive Transcript1");
    TEST_ASSERT(
        sm2_auth_derive_session_key(&priv_a, &eph_priv_a1, &pub_b, &eph_pub_b1,
            transcript2, sizeof(transcript2) - 1, tkey2, sizeof(tkey2))
            == SM2_IC_SUCCESS,
        "Derive Transcript2");
    TEST_ASSERT(memcmp(tkey1, tkey2, sizeof(tkey1)) != 0,
        "Transcript Binding Changes Key");

    TEST_PASS();
}

static void test_auth_aead_integrity()
{
    uint8_t key[16];
    uint8_t iv[12];
    TEST_ASSERT(sm2_ic_generate_random(key, sizeof(key)) == SM2_IC_SUCCESS,
        "AEAD Key Rand");
    TEST_ASSERT(sm2_ic_generate_random(iv, sizeof(iv)) == SM2_IC_SUCCESS,
        "AEAD IV Rand");

    const uint8_t aad[] = "AEAD_AAD";
    const uint8_t plain[] = "AEAD_PROTECTED_PAYLOAD";

    sm2_auth_aead_mode_t modes[]
        = { SM2_AUTH_AEAD_MODE_SM4_GCM, SM2_AUTH_AEAD_MODE_SM4_CCM };

    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++)
    {
        uint8_t cipher[sizeof(plain)];
        size_t cipher_len = sizeof(cipher);
        uint8_t tag[SM2_AUTH_AEAD_TAG_MAX_LEN];
        size_t tag_len = sizeof(tag);

        int supported = test_auth_aead_mode_available(modes[i]);
        sm2_ic_error_t enc_ret = sm2_auth_encrypt(modes[i], key, iv, sizeof(iv),
            aad, sizeof(aad) - 1, plain, sizeof(plain) - 1, cipher, &cipher_len,
            tag, &tag_len);
        if (!supported)
        {
            TEST_ASSERT(enc_ret == SM2_IC_ERR_CRYPTO,
                "Unsupported AEAD Mode Must Return Crypto Err");
            printf("   [AUTH-AEAD] mode=%d unsupported in current runtime "
                   "OpenSSL/provider config, skip integrity sub-checks\\n",
                (int)modes[i]);
            continue;
        }
        TEST_ASSERT(enc_ret == SM2_IC_SUCCESS, "AEAD Encrypt");

        TEST_ASSERT(cipher_len == sizeof(plain) - 1, "AEAD Cipher Len");

        uint8_t recover[sizeof(plain)];
        size_t recover_len = sizeof(recover);
        TEST_ASSERT(sm2_auth_decrypt(modes[i], key, iv, sizeof(iv), aad,
                        sizeof(aad) - 1, cipher, cipher_len, tag, tag_len,
                        recover, &recover_len)
                == SM2_IC_SUCCESS,
            "AEAD Decrypt");
        TEST_ASSERT(recover_len == sizeof(plain) - 1, "AEAD Recover Len");
        TEST_ASSERT(memcmp(recover, plain, sizeof(plain) - 1) == 0,
            "AEAD Recover Plain");

        cipher[0] ^= 0x80;
        recover_len = sizeof(recover);
        TEST_ASSERT(sm2_auth_decrypt(modes[i], key, iv, sizeof(iv), aad,
                        sizeof(aad) - 1, cipher, cipher_len, tag, tag_len,
                        recover, &recover_len)
                == SM2_IC_ERR_VERIFY,
            "AEAD Tampered Cipher Reject");
        cipher[0] ^= 0x80;

        tag[0] ^= 0x5A;
        recover_len = sizeof(recover);
        TEST_ASSERT(sm2_auth_decrypt(modes[i], key, iv, sizeof(iv), aad,
                        sizeof(aad) - 1, cipher, cipher_len, tag, tag_len,
                        recover, &recover_len)
                == SM2_IC_ERR_VERIFY,
            "AEAD Tampered Tag Reject");
    }

    TEST_PASS();
}
