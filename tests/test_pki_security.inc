static void test_phase13_service_query_cannot_self_refresh_root()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P13_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 60, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P13_NODE";
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

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *client = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&client, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Client Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(client, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Import Cert");

    const uint8_t msg[] = "P13_FRESHNESS";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_pki_sign(client, msg, sizeof(msg) - 1, &sig) == SM2_PKI_SUCCESS,
        "Sign");
    const sm2_implicit_cert_t *client_cert = NULL;
    const sm2_ec_point_t *client_pub = NULL;
    TEST_ASSERT(
        pki_client_get_identity_material(client, &client_cert, &client_pub),
        "Get Client Material");

    sm2_pki_verify_request_t request
        = { client_cert, client_pub, msg, sizeof(msg) - 1, &sig };
    size_t matched = 0;

    sm2_rev_root_record_t root_before;
    sm2_rev_root_record_t root_after_fail;
    sm2_rev_root_record_t root_after_refresh;
    TEST_ASSERT(sm2_pki_service_get_root_record(service, &root_before)
            == SM2_PKI_SUCCESS,
        "Get Root Before");
    uint64_t fresh_now = test_cert_now(&cert_res.cert);
    if (fresh_now < root_before.valid_from)
        fresh_now = root_before.valid_from;
    uint64_t expired_now = root_before.valid_until + 1;

    TEST_ASSERT(sm2_pki_verify(client, &request, fresh_now, &matched)
            == SM2_PKI_SUCCESS,
        "Fresh Root Verify");
    TEST_ASSERT(sm2_pki_verify(client, &request, expired_now, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Expired Root Reject");

    TEST_ASSERT(sm2_pki_service_get_root_record(service, &root_after_fail)
            == SM2_PKI_SUCCESS,
        "Get Root After Fail");
    TEST_ASSERT(root_after_fail.valid_until == root_before.valid_until,
        "Query Path Must Not Refresh Root");

    TEST_ASSERT(sm2_pki_service_refresh_root(service, expired_now + 19)
            == SM2_PKI_SUCCESS,
        "Explicit Refresh Root");
    TEST_ASSERT(sm2_pki_service_get_root_record(service, &root_after_refresh)
            == SM2_PKI_SUCCESS,
        "Get Root After Refresh");
    TEST_ASSERT(root_after_refresh.valid_until > root_before.valid_until,
        "Explicit Refresh Extends Validity");
    TEST_ASSERT(sm2_pki_verify(client, &request, expired_now + 20, &matched)
            == SM2_PKI_SUCCESS,
        "Explicit Refresh Restores Verify");

    sm2_pki_client_destroy(&client);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase13_issue_requires_authorized_request_and_policy_match()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P13_BIND_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P13_BIND_NODE";
    TEST_ASSERT(sm2_pki_identity_register(service, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity Register");

    sm2_ic_cert_request_t req_good;
    sm2_ic_cert_request_t req_other;
    sm2_ic_cert_request_t req_bad_usage;
    sm2_private_key_t temp_good;
    sm2_private_key_t temp_other;
    sm2_private_key_t temp_bad_usage;
    sm2_ic_cert_result_t cert_res;
    memset(&req_good, 0, sizeof(req_good));
    memset(&req_other, 0, sizeof(req_other));
    memset(&req_bad_usage, 0, sizeof(req_bad_usage));
    memset(&cert_res, 0, sizeof(cert_res));

    TEST_ASSERT(sm2_ic_create_cert_request(&req_good, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE, &temp_good)
            == SM2_IC_SUCCESS,
        "Create Good Request");
    TEST_ASSERT(test_pki_issue_cert(service, &req_good, &cert_res)
            == SM2_PKI_ERR_VERIFY,
        "Issue Without Authorization Reject");

    TEST_ASSERT(
        sm2_ic_create_cert_request(&req_bad_usage, identity,
            sizeof(identity) - 1,
            SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT, &temp_bad_usage)
            == SM2_IC_SUCCESS,
        "Create Bad Usage Request");
    TEST_ASSERT(sm2_pki_cert_authorize_request(service, &req_bad_usage)
            == SM2_PKI_ERR_VERIFY,
        "Authorize Usage Escalation Reject");

    TEST_ASSERT(
        sm2_pki_cert_authorize_request(service, &req_good) == SM2_PKI_SUCCESS,
        "Authorize Good Request");
    TEST_ASSERT(sm2_ic_create_cert_request(&req_other, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE, &temp_other)
            == SM2_IC_SUCCESS,
        "Create Other Request");
    TEST_ASSERT(sm2_pki_cert_authorize_request(service, &req_other)
            == SM2_PKI_ERR_CONFLICT,
        "Authorize Conflicting Pending Request Reject");

    sm2_ic_cert_request_t req_tampered = req_good;
    req_tampered.temp_public_key.x[0] ^= 0x01;
    TEST_ASSERT(test_pki_issue_cert(service, &req_tampered, &cert_res)
            == SM2_PKI_ERR_VERIFY,
        "Issue Tampered Authorized Request Reject");

    TEST_ASSERT(
        test_pki_issue_cert(service, &req_good, &cert_res) == SM2_PKI_SUCCESS,
        "Issue Authorized Request");

    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase13_key_agreement_requires_ka_usage()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P13_KA_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P13_KA_NODE";
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
        "Create Request");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req, &cert_res) == SM2_PKI_SUCCESS,
        "Issue Cert");

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *client = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&client, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Client Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(client, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Import Cert");
    const sm2_ec_point_t *client_pub = NULL;
    TEST_ASSERT(pki_client_get_identity_material(client, NULL, &client_pub),
        "Get Client Public Key");

    sm2_private_key_t eph_priv;
    sm2_ec_point_t eph_pub;
    TEST_ASSERT(sm2_pki_generate_ephemeral_keypair(&eph_priv, &eph_pub)
            == SM2_PKI_SUCCESS,
        "Generate Ephemeral");

    uint8_t session_key[16];
    const uint8_t transcript[] = "P13_KA_POLICY";
    TEST_ASSERT(sm2_pki_key_agreement(client, &eph_priv, client_pub, &eph_pub,
                    transcript, sizeof(transcript) - 1, session_key,
                    sizeof(session_key))
            == SM2_PKI_ERR_VERIFY,
        "Key Agreement Requires KA Usage");

    sm2_pki_client_destroy(&client);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase13_secure_pki_session_default_api()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P13_SECURE_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t id_a[] = "P13_A";
    const uint8_t id_b[] = "P13_B";
    TEST_ASSERT(sm2_pki_identity_register(service, id_a, sizeof(id_a) - 1,
                    SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT)
            == SM2_PKI_SUCCESS,
        "Register A");
    TEST_ASSERT(sm2_pki_identity_register(service, id_b, sizeof(id_b) - 1,
                    SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT)
            == SM2_PKI_SUCCESS,
        "Register B");

    sm2_ic_cert_request_t req_a;
    sm2_ic_cert_request_t req_b;
    sm2_private_key_t temp_a;
    sm2_private_key_t temp_b;
    sm2_ic_cert_result_t cert_a;
    sm2_ic_cert_result_t cert_b;
    TEST_ASSERT(
        pki_create_and_authorize_request(service, id_a, sizeof(id_a) - 1,
            SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT, &req_a, &temp_a),
        "Req A");
    TEST_ASSERT(
        pki_create_and_authorize_request(service, id_b, sizeof(id_b) - 1,
            SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT, &req_b, &temp_b),
        "Req B");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req_a, &cert_a) == SM2_PKI_SUCCESS,
        "Issue A");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req_b, &cert_b) == SM2_PKI_SUCCESS,
        "Issue B");

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *client_a = NULL;
    sm2_pki_client_ctx_t *client_b = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&client_a, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Client A Init");
    TEST_ASSERT(
        sm2_pki_client_create(&client_b, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Client B Init");
    TEST_ASSERT(sm2_pki_client_import_cert(client_a, &cert_a, &temp_a, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Import A");
    TEST_ASSERT(sm2_pki_client_import_cert(client_b, &cert_b, &temp_b, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Import B");
    const sm2_ec_point_t *client_a_pub = NULL;
    const sm2_ec_point_t *client_b_pub = NULL;
    TEST_ASSERT(pki_client_get_identity_material(client_a, NULL, &client_a_pub),
        "Get Client A Public Key");
    TEST_ASSERT(pki_client_get_identity_material(client_b, NULL, &client_b_pub),
        "Get Client B Public Key");

    sm2_private_key_t eph_priv_a;
    sm2_private_key_t eph_priv_b;
    sm2_ec_point_t eph_pub_a;
    sm2_ec_point_t eph_pub_b;
    TEST_ASSERT(sm2_pki_generate_ephemeral_keypair(&eph_priv_a, &eph_pub_a)
            == SM2_PKI_SUCCESS,
        "Generate Eph A");
    TEST_ASSERT(sm2_pki_generate_ephemeral_keypair(&eph_priv_b, &eph_pub_b)
            == SM2_PKI_SUCCESS,
        "Generate Eph B");

    const uint8_t transcript[] = "P13_SECURE_SESSION";
    uint8_t sk_a[16];
    uint8_t sk_b[16];
    TEST_ASSERT(
        sm2_pki_key_agreement(client_a, &eph_priv_a, client_b_pub, &eph_pub_b,
            transcript, sizeof(transcript) - 1, sk_a, sizeof(sk_a))
            == SM2_PKI_SUCCESS,
        "Key Agreement A");
    TEST_ASSERT(
        sm2_pki_key_agreement(client_b, &eph_priv_b, client_a_pub, &eph_pub_a,
            transcript, sizeof(transcript) - 1, sk_b, sizeof(sk_b))
            == SM2_PKI_SUCCESS,
        "Key Agreement B");
    TEST_ASSERT(
        memcmp(sk_a, sk_b, sizeof(sk_a)) == 0, "Secure Session Keys Match");

    const uint8_t aad[] = "P13_AAD";
    const uint8_t plain[] = "P13_SECURE_PAYLOAD";
    uint8_t iv[12];
    TEST_ASSERT(sm2_pki_random(iv, sizeof(iv)) == SM2_PKI_SUCCESS, "Random IV");
    uint8_t cipher[sizeof(plain)];
    uint8_t recover[sizeof(plain)];
    uint8_t tag[SM2_AUTH_AEAD_TAG_MAX_LEN];
    size_t cipher_len = sizeof(plain) - 1;
    size_t recover_len = sizeof(recover);
    size_t tag_len = sizeof(tag);

    int gcm_available = test_pki_sm4_gcm_available();
    sm2_pki_error_t aead_ret = sm2_pki_encrypt(SM2_AUTH_AEAD_MODE_SM4_GCM, sk_a,
        iv, sizeof(iv), aad, sizeof(aad) - 1, plain, sizeof(plain) - 1, cipher,
        &cipher_len, tag, &tag_len);
    if (!gcm_available)
    {
        TEST_ASSERT(aead_ret == SM2_PKI_ERR_CRYPTO,
            "Unsupported GCM Must Return Crypto Err");
        printf("   [PKI-SESSION] SM4-GCM unsupported in current runtime "
               "OpenSSL/provider config, skip secure AEAD round-trip\n");
    }
    else
    {
        TEST_ASSERT(aead_ret == SM2_PKI_SUCCESS, "Encrypt AEAD");
        TEST_ASSERT(sm2_pki_decrypt(SM2_AUTH_AEAD_MODE_SM4_GCM, sk_b, iv,
                        sizeof(iv), aad, sizeof(aad) - 1, cipher, cipher_len,
                        tag, tag_len, recover, &recover_len)
                == SM2_PKI_SUCCESS,
            "Decrypt");
        TEST_ASSERT(recover_len == sizeof(plain) - 1, "Recover Len");
        TEST_ASSERT(
            memcmp(recover, plain, sizeof(plain) - 1) == 0, "Recover Plain");

        tag[0] ^= 0x55;
        recover_len = sizeof(recover);
        TEST_ASSERT(sm2_pki_decrypt(SM2_AUTH_AEAD_MODE_SM4_GCM, sk_b, iv,
                        sizeof(iv), aad, sizeof(aad) - 1, cipher, cipher_len,
                        tag, tag_len, recover, &recover_len)
                == SM2_PKI_ERR_VERIFY,
            "Tampered Tag Reject");
    }

    sm2_pki_client_destroy(&client_b);
    sm2_pki_client_destroy(&client_a);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase133_revocation_service_binding_lifecycle()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P133_BIND_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 16, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P133_NODE";
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
        "Create Request");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req, &cert_res) == SM2_PKI_SUCCESS,
        "Issue Cert");

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *client = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&client, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Client Init");
    TEST_ASSERT(
        sm2_pki_client_bind_revocation(client, service) == SM2_PKI_SUCCESS,
        "Bind Revocation Service");
    TEST_ASSERT(
        sm2_pki_client_import_cert(client, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Import Cert");

    const uint8_t msg[] = "P133_BINDING";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_pki_sign(client, msg, sizeof(msg) - 1, &sig) == SM2_PKI_SUCCESS,
        "Sign");
    const sm2_implicit_cert_t *client_cert = NULL;
    const sm2_ec_point_t *client_pub = NULL;
    TEST_ASSERT(
        pki_client_get_identity_material(client, &client_cert, &client_pub),
        "Get Client Material");

    sm2_pki_verify_request_t request
        = { client_cert, client_pub, msg, sizeof(msg) - 1, &sig };
    size_t matched = 0;
    uint64_t auth_now = test_cert_now(&cert_res.cert);
    TEST_ASSERT(
        sm2_pki_verify(client, &request, auth_now, &matched) == SM2_PKI_SUCCESS,
        "Verify Before Service Cleanup");

    sm2_pki_service_destroy(&service);
    TEST_ASSERT(sm2_pki_verify(client, &request, auth_now + 1, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Bound Service Cleanup Must Fail Closed");
    TEST_ASSERT(
        sm2_pki_client_bind_revocation(client, service) == SM2_PKI_ERR_PARAM,
        "Bind Cleaned Service Reject");

    sm2_pki_client_destroy(&client);
    TEST_PASS();
}

static void test_phase134_pki_verify_rejects_request_level_revocation_override()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P134_OVERRIDE_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 16, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P134_NODE";
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
        "Create Request");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req, &cert_res) == SM2_PKI_SUCCESS,
        "Issue Cert");

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *client = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&client, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Client Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(client, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Import Cert");

    const uint8_t msg[] = "P134_OVERRIDE";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_pki_sign(client, msg, sizeof(msg) - 1, &sig) == SM2_PKI_SUCCESS,
        "Sign");
    const sm2_implicit_cert_t *client_cert = NULL;
    const sm2_ec_point_t *client_pub = NULL;
    TEST_ASSERT(
        pki_client_get_identity_material(client, &client_cert, &client_pub),
        "Get Client Material");

    sm2_pki_verify_request_t request
        = { client_cert, client_pub, msg, sizeof(msg) - 1, &sig };
    size_t matched = 0;
    uint64_t auth_now = test_cert_now(&cert_res.cert);
    TEST_ASSERT(
        sm2_pki_verify(client, &request, auth_now, &matched) == SM2_PKI_SUCCESS,
        "Baseline Verify");

    TEST_ASSERT(sm2_pki_service_revoke(
                    service, cert_res.cert.serial_number, auth_now + 10)
            == SM2_PKI_SUCCESS,
        "Revoke Cert");

    TEST_ASSERT(sm2_pki_verify(client, &request, auth_now + 20, &matched)
            == SM2_PKI_ERR_VERIFY,
        "High-Level Verify Uses Bound Revocation Backend");

    sm2_pki_client_destroy(&client);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase137_client_root_cache_import_refresh_and_rollback()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P137_ROOT_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 16, 60, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P137_NODE";
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
        "Create Request");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req, &cert_res) == SM2_PKI_SUCCESS,
        "Issue Cert");

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *client = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&client, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Client Init");

    sm2_rev_root_record_t root_initial;
    memset(&root_initial, 0, sizeof(root_initial));
    TEST_ASSERT(sm2_pki_service_get_root_record(service, &root_initial)
            == SM2_PKI_SUCCESS,
        "Get Initial Root");
    TEST_ASSERT(root_initial.authority_id_len == sizeof(issuer) - 1,
        "Initial Root Authority Len");
    TEST_ASSERT(memcmp(root_initial.authority_id, issuer, sizeof(issuer) - 1)
            == 0,
        "Initial Root Authority Match");
    sm2_rev_root_record_t root_tampered = root_initial;
    root_tampered.authority_id[0] ^= 0x01;
    TEST_ASSERT(sm2_pki_client_import_root_record(
                    client, &root_tampered, root_initial.valid_from)
            == SM2_PKI_ERR_VERIFY,
        "Tampered Authority Reject");
    TEST_ASSERT(sm2_pki_client_import_root_record(
                    client, &root_initial, root_initial.valid_from)
            == SM2_PKI_SUCCESS,
        "Import Initial Root");

    sm2_rev_root_record_t cached_root;
    memset(&cached_root, 0, sizeof(cached_root));
    TEST_ASSERT(sm2_pki_client_get_cached_root_record(client, &cached_root)
            == SM2_PKI_SUCCESS,
        "Get Cached Root");
    TEST_ASSERT(sm2_pki_client_get_cached_root_record_for_authority(client,
                    issuer, sizeof(issuer) - 1, &cached_root)
            == SM2_PKI_SUCCESS,
        "Get Cached Root By Authority");
    TEST_ASSERT(cached_root.root_version == root_initial.root_version,
        "Initial Root Version Cached");
    TEST_ASSERT(memcmp(cached_root.root_hash, root_initial.root_hash,
                    sizeof(cached_root.root_hash))
            == 0,
        "Initial Root Hash Cached");

    TEST_ASSERT(
        sm2_pki_service_refresh_root(service, base_now + 10) == SM2_PKI_SUCCESS,
        "Refresh Same Version Root");
    sm2_rev_root_record_t root_refreshed;
    memset(&root_refreshed, 0, sizeof(root_refreshed));
    TEST_ASSERT(sm2_pki_service_get_root_record(service, &root_refreshed)
            == SM2_PKI_SUCCESS,
        "Get Refreshed Root");
    TEST_ASSERT(root_refreshed.root_version == root_initial.root_version,
        "Same Version Refresh");
    TEST_ASSERT(root_refreshed.valid_until > root_initial.valid_until,
        "Refresh Extends Validity");
    TEST_ASSERT(sm2_pki_client_import_root_record(
                    client, &root_refreshed, base_now + 10)
            == SM2_PKI_SUCCESS,
        "Import Refreshed Root");
    TEST_ASSERT(sm2_pki_client_get_cached_root_record(client, &cached_root)
            == SM2_PKI_SUCCESS,
        "Get Cached Refreshed Root");
    TEST_ASSERT(cached_root.valid_until == root_refreshed.valid_until,
        "Cached Validity Extended");

    TEST_ASSERT(sm2_pki_service_revoke(
                    service, cert_res.cert.serial_number, base_now + 20)
            == SM2_PKI_SUCCESS,
        "Revoke Cert");
    sm2_rev_root_record_t root_newer;
    memset(&root_newer, 0, sizeof(root_newer));
    TEST_ASSERT(sm2_pki_service_get_root_record(service, &root_newer)
            == SM2_PKI_SUCCESS,
        "Get Newer Root");
    TEST_ASSERT(root_newer.root_version > root_refreshed.root_version,
        "Newer Root Version");
    TEST_ASSERT(sm2_pki_client_import_root_record(
                    client, &root_newer, base_now + 20)
            == SM2_PKI_SUCCESS,
        "Import Newer Root");
    TEST_ASSERT(sm2_pki_client_import_root_record(
                    client, &root_initial, base_now + 30)
            == SM2_PKI_ERR_VERIFY,
        "Rollback Root Reject");

    sm2_pki_client_destroy(&client);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase138_service_binding_tracks_newer_root_versions()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P138_ROOT_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t signer_id[] = "P138_SIGNER";
    const uint8_t aux_id[] = "P138_AUX";
    TEST_ASSERT(sm2_pki_identity_register(service, signer_id,
                    sizeof(signer_id) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Signer Register");
    TEST_ASSERT(sm2_pki_identity_register(service, aux_id,
                    sizeof(aux_id) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Aux Register");

    sm2_ic_cert_request_t req_signer;
    sm2_ic_cert_request_t req_aux;
    sm2_private_key_t temp_signer;
    sm2_private_key_t temp_aux;
    sm2_ic_cert_result_t cert_signer;
    sm2_ic_cert_result_t cert_aux;
    TEST_ASSERT(pki_create_and_authorize_request(service, signer_id,
                    sizeof(signer_id) - 1, SM2_KU_DIGITAL_SIGNATURE,
                    &req_signer, &temp_signer),
        "Signer Request");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req_signer, &cert_signer)
            == SM2_PKI_SUCCESS,
        "Signer Issue");
    TEST_ASSERT(
        pki_issue_identity_cert(service, aux_id, sizeof(aux_id) - 1,
            SM2_KU_DIGITAL_SIGNATURE, &cert_aux, &temp_aux),
        "Aux Issue");
    uint64_t auth_now = test_cert_now(&cert_signer.cert);

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *signer = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&signer, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer, &cert_signer, &temp_signer, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");

    const uint8_t msg[] = "P138_TRACK_ROOT";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_pki_sign(signer, msg, sizeof(msg) - 1, &sig) == SM2_PKI_SUCCESS,
        "Signer Sign");
    const sm2_implicit_cert_t *signer_cert = NULL;
    const sm2_ec_point_t *signer_pub = NULL;
    TEST_ASSERT(
        pki_client_get_identity_material(signer, &signer_cert, &signer_pub),
        "Get Signer Material");

    sm2_pki_verify_request_t request = { .cert = signer_cert,
        .public_key = signer_pub,
        .message = msg,
        .message_len = sizeof(msg) - 1,
        .signature = &sig };

    sm2_pki_client_ctx_t *verifier = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&verifier, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Verifier Init");

    sm2_rev_root_record_t cached_root;
    memset(&cached_root, 0, sizeof(cached_root));
    TEST_ASSERT(
        sm2_pki_client_get_cached_root_record(verifier, &cached_root)
            == SM2_PKI_ERR_STATE,
        "No Cached Root Before Refresh");
    TEST_ASSERT(
        sm2_pki_client_refresh_root(verifier, auth_now) == SM2_PKI_SUCCESS,
        "Initial Root Refresh");
    TEST_ASSERT(sm2_pki_client_get_cached_root_record(verifier, &cached_root)
            == SM2_PKI_SUCCESS,
        "Get Refreshed Cached Root");
    TEST_ASSERT(sm2_pki_client_get_cached_root_record_for_authority(verifier,
                    issuer, sizeof(issuer) - 1, &cached_root)
            == SM2_PKI_SUCCESS,
        "Get Cached Root By Issuer");
    uint64_t initial_version = cached_root.root_version;

    TEST_ASSERT(sm2_pki_service_revoke(
                    service, cert_aux.cert.serial_number, auth_now + 10)
            == SM2_PKI_SUCCESS,
        "Revoke Aux Cert");

    size_t matched = 0;
    TEST_ASSERT(sm2_pki_verify(verifier, &request, auth_now + 20, &matched)
            == SM2_PKI_SUCCESS,
        "Verify With Updated Root");
    TEST_ASSERT(sm2_pki_client_get_cached_root_record(verifier, &cached_root)
            == SM2_PKI_SUCCESS,
        "Get Updated Cached Root");
    TEST_ASSERT(cached_root.root_version > initial_version,
        "Cached Root Advanced");

    sm2_pki_client_destroy(&verifier);
    sm2_pki_client_destroy(&signer);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase139_root_versions_are_scoped_per_authority()
{
    sm2_pki_service_ctx_t *service_a = NULL;
    sm2_pki_service_ctx_t *service_b = NULL;
    const uint8_t issuer_a[] = "P139_CA_A";
    const uint8_t issuer_b[] = "P139_CA_B";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(&service_a, issuer_a,
                    sizeof(issuer_a) - 1, 16, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service A Init");
    TEST_ASSERT(sm2_pki_service_create(&service_b, issuer_b,
                    sizeof(issuer_b) - 1, 16, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service B Init");

    const uint8_t identity_a[] = "P139_NODE_A";
    TEST_ASSERT(sm2_pki_identity_register(service_a, identity_a,
                    sizeof(identity_a) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity A Register");

    sm2_ic_cert_request_t req_a;
    sm2_private_key_t temp_a;
    sm2_ic_cert_result_t cert_a;
    TEST_ASSERT(pki_create_and_authorize_request(service_a, identity_a,
                    sizeof(identity_a) - 1, SM2_KU_DIGITAL_SIGNATURE, &req_a,
                    &temp_a),
        "Request A");
    TEST_ASSERT(
        test_pki_issue_cert(service_a, &req_a, &cert_a) == SM2_PKI_SUCCESS,
        "Issue A");
    TEST_ASSERT(sm2_pki_service_revoke(
                    service_a, cert_a.cert.serial_number, base_now + 10)
            == SM2_PKI_SUCCESS,
        "Revoke A");

    sm2_ec_point_t ca_pub_a;
    sm2_ec_point_t ca_pub_b;
    TEST_ASSERT(sm2_pki_service_get_ca_public_key(service_a, &ca_pub_a)
            == SM2_PKI_SUCCESS,
        "Get CA A");
    TEST_ASSERT(sm2_pki_service_get_ca_public_key(service_b, &ca_pub_b)
            == SM2_PKI_SUCCESS,
        "Get CA B");

    sm2_pki_client_ctx_t *client = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&client, &ca_pub_a, NULL) == SM2_PKI_SUCCESS,
        "Client Init");
    TEST_ASSERT(
        sm2_pki_client_add_trusted_ca(client, &ca_pub_b) == SM2_PKI_SUCCESS,
        "Add CA B");

    sm2_rev_root_record_t root_a;
    sm2_rev_root_record_t root_b;
    memset(&root_a, 0, sizeof(root_a));
    memset(&root_b, 0, sizeof(root_b));
    TEST_ASSERT(sm2_pki_service_get_root_record(service_a, &root_a)
            == SM2_PKI_SUCCESS,
        "Get Root A");
    TEST_ASSERT(sm2_pki_service_get_root_record(service_b, &root_b)
            == SM2_PKI_SUCCESS,
        "Get Root B");
    TEST_ASSERT(root_a.root_version > root_b.root_version,
        "Root A Version Higher");

    TEST_ASSERT(sm2_pki_client_import_root_record(client, &root_a, base_now + 20)
            == SM2_PKI_SUCCESS,
        "Import Root A");
    TEST_ASSERT(sm2_pki_client_import_root_record(client, &root_b, base_now + 20)
            == SM2_PKI_SUCCESS,
        "Import Root B With Lower Scoped Version");

    sm2_rev_root_record_t cached_a;
    sm2_rev_root_record_t cached_b;
    memset(&cached_a, 0, sizeof(cached_a));
    memset(&cached_b, 0, sizeof(cached_b));
    TEST_ASSERT(sm2_pki_client_get_cached_root_record_for_authority(client,
                    issuer_a, sizeof(issuer_a) - 1, &cached_a)
            == SM2_PKI_SUCCESS,
        "Cached A");
    TEST_ASSERT(sm2_pki_client_get_cached_root_record_for_authority(client,
                    issuer_b, sizeof(issuer_b) - 1, &cached_b)
            == SM2_PKI_SUCCESS,
        "Cached B");
    TEST_ASSERT(cached_a.root_version == root_a.root_version,
        "Cached A Version");
    TEST_ASSERT(cached_b.root_version == root_b.root_version,
        "Cached B Version");

    TEST_ASSERT(sm2_pki_client_import_root_record(client, &root_b, base_now + 21)
            == SM2_PKI_SUCCESS,
        "Reimport Same Root B");
    TEST_ASSERT(sm2_pki_client_import_root_record(client, &root_a, base_now + 21)
            == SM2_PKI_SUCCESS,
        "Reimport Root A");

    sm2_pki_client_destroy(&client);
    sm2_pki_service_destroy(&service_b);
    sm2_pki_service_destroy(&service_a);
    TEST_PASS();
}
