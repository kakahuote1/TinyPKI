static void test_phase8_merkle_hook_and_service_binding()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P8_MERKLE_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P8_NODE";
    TEST_ASSERT(sm2_pki_identity_register(service, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity Register");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    TEST_ASSERT(
        pki_create_and_authorize_request(service, identity,
            sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE, &req, &temp_priv),
        "Cert Request");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req, &cert_res) == SM2_PKI_SUCCESS,
        "Cert Issue");
    uint64_t auth_now = test_cert_now(&cert_res.cert);

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *signer = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&signer, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");

    const uint8_t msg[] = "P8_CARRIED_EVIDENCE";
    sm2_auth_signature_t sig;
    sm2_pki_revocation_evidence_t evidence;
    sm2_pki_verify_request_t auth_req;
    TEST_ASSERT(pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1,
                    auth_now, &sig, &evidence, &auth_req),
        "Build Carried Evidence Request");

    sm2_pki_client_ctx_t *verifier = NULL;
    TEST_ASSERT(sm2_pki_client_create(&verifier, &ca_pub, NULL)
            == SM2_PKI_SUCCESS,
        "Verifier Init");

    size_t matched = 0;
    TEST_ASSERT(sm2_pki_verify(verifier, &auth_req, auth_now, &matched)
            == SM2_PKI_SUCCESS,
        "Carried Evidence Verify");

    TEST_ASSERT(sm2_pki_service_revoke(
                    service, cert_res.cert.serial_number, auth_now + 100)
            == SM2_PKI_SUCCESS,
        "Revoke Serial");
    TEST_ASSERT(sm2_pki_client_export_revocation_evidence(
                    signer, auth_now + 200, &evidence)
            == SM2_PKI_ERR_VERIFY,
        "Revoked Signer Cannot Export Good Evidence");

    sm2_rev_root_record_t newer_root;
    memset(&newer_root, 0, sizeof(newer_root));
    TEST_ASSERT(sm2_pki_service_get_root_record(service, &newer_root)
            == SM2_PKI_SUCCESS,
        "Get Newer Root");
    TEST_ASSERT(sm2_pki_client_import_root_record(
                    verifier, &newer_root, auth_now + 200)
            == SM2_PKI_SUCCESS,
        "Import Newer Root");
    TEST_ASSERT(sm2_pki_verify(verifier, &auth_req, auth_now + 200, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Old Carried Evidence Rejected After Root Advance");

    sm2_pki_client_destroy(&verifier);
    sm2_pki_client_destroy(&signer);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase9_epoch_lookup_unknown_query_override_behavior()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P9_MERKLE_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");
    const uint8_t identity[] = "P9_NODE";
    TEST_ASSERT(sm2_pki_identity_register(service, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity Register");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    TEST_ASSERT(
        pki_create_and_authorize_request(service, identity,
            sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE, &req, &temp_priv),
        "Cert Request");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req, &cert_res) == SM2_PKI_SUCCESS,
        "Cert Issue");
    uint64_t auth_now = test_cert_now(&cert_res.cert);

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *signer = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&signer, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");

    const uint8_t msg[] = "P9_CARRIED_EVIDENCE";
    sm2_auth_signature_t sig;
    sm2_pki_revocation_evidence_t evidence;
    sm2_pki_verify_request_t auth_req;
    TEST_ASSERT(pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1,
                    auth_now, &sig, &evidence, &auth_req),
        "Build Signed Request");

    sm2_pki_client_ctx_t *verifier = NULL;
    TEST_ASSERT(sm2_pki_client_create(&verifier, &ca_pub, NULL)
            == SM2_PKI_SUCCESS,
        "Verifier Init");

    size_t matched = 0;
    TEST_ASSERT(sm2_pki_verify(verifier, &auth_req, auth_now + 100, &matched)
            == SM2_PKI_SUCCESS,
        "Baseline Verify");

    sm2_pki_verify_request_t missing_evidence = auth_req;
    missing_evidence.revocation_evidence = NULL;
    TEST_ASSERT(sm2_pki_verify(verifier, &missing_evidence, auth_now + 100,
                    &matched)
            == SM2_PKI_ERR_VERIFY,
        "Missing Carried Evidence Reject");

    sm2_pki_revocation_evidence_t wrong_serial = evidence;
    wrong_serial.absence_proof.target_serial ^= 0x01U;
    sm2_pki_verify_request_t wrong_serial_req = auth_req;
    wrong_serial_req.revocation_evidence = &wrong_serial;
    TEST_ASSERT(sm2_pki_verify(verifier, &wrong_serial_req, auth_now + 100,
                    &matched)
            == SM2_PKI_ERR_VERIFY,
        "Wrong Serial Evidence Reject");

    sm2_pki_revocation_evidence_t wrong_authority = evidence;
    wrong_authority.root_record.authority_id[0] ^= 0x01U;
    sm2_pki_verify_request_t wrong_authority_req = auth_req;
    wrong_authority_req.revocation_evidence = &wrong_authority;
    TEST_ASSERT(sm2_pki_verify(verifier, &wrong_authority_req,
                    auth_now + 100, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Wrong Authority Evidence Reject");

    sm2_pki_client_destroy(&verifier);
    sm2_pki_client_destroy(&signer);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase93_crypto_direct_api_min_coverage()
{
    if (!g_ca_initialized)
        test_setup_ca();

    uint8_t rnd[32];
    TEST_ASSERT(
        sm2_pki_random(rnd, sizeof(rnd)) == SM2_PKI_SUCCESS, "PKI Random");
    bool any_nonzero = false;
    for (size_t i = 0; i < sizeof(rnd); i++)
    {
        if (rnd[i] != 0)
        {
            any_nonzero = true;
            break;
        }
    }
    TEST_ASSERT(any_nonzero, "PKI Random NonZero");

    const uint8_t msg[] = "PKI_DIRECT_API";
    uint8_t d1[SM3_DIGEST_LENGTH];
    uint8_t d2[SM3_DIGEST_LENGTH];
    TEST_ASSERT(sm2_pki_sm3_hash(msg, sizeof(msg) - 1, d1) == SM2_PKI_SUCCESS,
        "PKI SM3 Hash");
    TEST_ASSERT(sm2_ic_sm3_hash(msg, sizeof(msg) - 1, d2) == SM2_IC_SUCCESS,
        "IC SM3 Hash");
    TEST_ASSERT(memcmp(d1, d2, sizeof(d1)) == 0, "SM3 Hash Match");

    sm2_ic_cert_request_t req_a, req_b;
    sm2_private_key_t temp_a, temp_b;
    sm2_ic_cert_result_t cert_a, cert_b;
    sm2_private_key_t priv_a, priv_b;
    sm2_ec_point_t pub_a, pub_b;

    TEST_ASSERT(sm2_ic_create_cert_request(&req_a, (uint8_t *)"PKI_DIR_A", 9,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_a)
            == SM2_IC_SUCCESS,
        "Create Req A");
    TEST_ASSERT(sm2_ic_create_cert_request(&req_b, (uint8_t *)"PKI_DIR_B", 9,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_b)
            == SM2_IC_SUCCESS,
        "Create Req B");
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

    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_crypto_sign(&priv_a, msg, sizeof(msg) - 1, &sig) == SM2_PKI_SUCCESS,
        "Crypto Sign");
    TEST_ASSERT(sm2_crypto_verify(&pub_a, msg, sizeof(msg) - 1, &sig)
            == SM2_PKI_SUCCESS,
        "Crypto Verify");

    uint8_t tampered[sizeof(msg)];
    memcpy(tampered, msg, sizeof(msg));
    tampered[0] ^= 0x01;
    TEST_ASSERT(sm2_crypto_verify(&pub_a, tampered, sizeof(msg) - 1, &sig)
            == SM2_PKI_ERR_VERIFY,
        "Crypto Verify Tamper Reject");

    uint8_t sk_a[16], sk_b[16];
    TEST_ASSERT(
        sm2_auth_derive_session_key_static(&priv_a, &pub_b, sk_a, sizeof(sk_a))
            == SM2_IC_SUCCESS,
        "Direct Derive A");
    TEST_ASSERT(
        sm2_auth_derive_session_key_static(&priv_b, &pub_a, sk_b, sizeof(sk_b))
            == SM2_IC_SUCCESS,
        "Direct Derive B");
    TEST_ASSERT(memcmp(sk_a, sk_b, sizeof(sk_a)) == 0, "Derived Key Equal");

    uint8_t iv[12];
    TEST_ASSERT(
        sm2_pki_random(iv, sizeof(iv)) == SM2_PKI_SUCCESS, "AEAD IV Random");
    uint8_t cipher[sizeof(msg)];
    size_t cipher_len = sizeof(msg) - 1;
    uint8_t tag[SM2_AUTH_AEAD_TAG_MAX_LEN];
    size_t tag_len = sizeof(tag);
    int gcm_available = test_pki_sm4_gcm_available();
    sm2_pki_error_t aead_ret
        = sm2_pki_aead_encrypt(SM2_AUTH_AEAD_MODE_SM4_GCM, sk_a, iv, sizeof(iv),
            NULL, 0, msg, sizeof(msg) - 1, cipher, &cipher_len, tag, &tag_len);
    if (!gcm_available)
    {
        TEST_ASSERT(aead_ret == SM2_PKI_ERR_CRYPTO,
            "Unsupported GCM Must Return Crypto Err");
        printf("   [PKI-AEAD] SM4-GCM unsupported in current runtime "
               "OpenSSL/provider config, skip AEAD wrapper checks\n");
    }
    else
    {
        TEST_ASSERT(aead_ret == SM2_PKI_SUCCESS, "PKI AEAD Encrypt");

        uint8_t recover[sizeof(msg)];
        size_t recover_len = sizeof(recover);
        TEST_ASSERT(sm2_pki_aead_decrypt(SM2_AUTH_AEAD_MODE_SM4_GCM, sk_b, iv,
                        sizeof(iv), NULL, 0, cipher, cipher_len, tag, tag_len,
                        recover, &recover_len)
                == SM2_PKI_SUCCESS,
            "PKI AEAD Decrypt");
        TEST_ASSERT(recover_len == sizeof(msg) - 1, "PKI AEAD Recover Len");
        TEST_ASSERT(memcmp(recover, msg, sizeof(msg) - 1) == 0,
            "PKI AEAD Recover Plain");

        tag[0] ^= 0x33;
        recover_len = sizeof(recover);
        TEST_ASSERT(sm2_pki_aead_decrypt(SM2_AUTH_AEAD_MODE_SM4_GCM, sk_b, iv,
                        sizeof(iv), NULL, 0, cipher, cipher_len, tag, tag_len,
                        recover, &recover_len)
                == SM2_PKI_ERR_VERIFY,
            "PKI AEAD Tag Reject");
    }

    TEST_PASS();
}

static void test_phase11_merkle_freshness_e2e_gate()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P11_MERKLE_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P11_NODE";
    TEST_ASSERT(sm2_pki_identity_register(service, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity Register");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    TEST_ASSERT(
        pki_create_and_authorize_request(service, identity,
            sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE, &req, &temp_priv),
        "Cert Request");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req, &cert_res) == SM2_PKI_SUCCESS,
        "Cert Issue");
    uint64_t auth_now = test_cert_now(&cert_res.cert);

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *signer = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&signer, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");

    const uint8_t msg[] = "P11_MERKLE_FRESH";
    sm2_auth_signature_t sig;
    sm2_pki_revocation_evidence_t evidence;
    sm2_pki_verify_request_t auth_req;
    TEST_ASSERT(pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1,
                    auth_now, &sig, &evidence, &auth_req),
        "Build Fresh Evidence Request");

    sm2_pki_client_ctx_t *verifier = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&verifier, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Verifier Init");

    size_t matched = 0;
    TEST_ASSERT(sm2_pki_verify(verifier, &auth_req, auth_now + 100, &matched)
            == SM2_PKI_SUCCESS,
        "Fresh Proof Allows Auth");
    TEST_ASSERT(sm2_pki_verify(verifier, &auth_req,
                    evidence.root_record.valid_until + 1, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Expired Proof Blocks Auth");

    sm2_pki_client_destroy(&verifier);
    sm2_pki_client_destroy(&signer);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}
