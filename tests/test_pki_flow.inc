static void test_x509_real_baseline_size()
{
    if (!g_ca_initialized)
        test_setup_ca();

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    TEST_ASSERT(kctx != NULL, "RSA Keygen Ctx");
    TEST_ASSERT(EVP_PKEY_keygen_init(kctx) == 1, "RSA Keygen Init");
    TEST_ASSERT(EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) == 1, "RSA Bits");
    TEST_ASSERT(EVP_PKEY_keygen(kctx, &pkey) == 1, "RSA Keygen");

    X509 *cert = X509_new();
    TEST_ASSERT(cert != NULL, "X509 New");
    TEST_ASSERT(X509_set_version(cert, 2) == 1, "Set Version");
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    TEST_ASSERT(
        X509_gmtime_adj(X509_get_notBefore(cert), 0) != NULL, "NotBefore");
    TEST_ASSERT(X509_gmtime_adj(X509_get_notAfter(cert), 31536000L) != NULL,
        "NotAfter");
    TEST_ASSERT(X509_set_pubkey(cert, pkey) == 1, "Set PubKey");

    X509_NAME *name = X509_get_subject_name(cert);
    TEST_ASSERT(name != NULL, "Get Subject");
    TEST_ASSERT(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                    (const unsigned char *)"BASELINE", -1, -1, 0)
            == 1,
        "Set CN");
    TEST_ASSERT(X509_set_issuer_name(cert, name) == 1, "Set Issuer");
    TEST_ASSERT(X509_sign(cert, pkey, EVP_sha256()) > 0, "X509 Sign");

    int x509_der_len = i2d_X509(cert, NULL);
    TEST_ASSERT(x509_der_len > 0, "X509 DER Len");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t res;
    uint8_t buf[1024];
    size_t implicit_len = sizeof(buf);
    TEST_ASSERT(sm2_ic_create_cert_request(&req, (uint8_t *)"DER_BASE", 8,
                    SM2_KU_DIGITAL_SIGNATURE, &temp_priv)
            == SM2_IC_SUCCESS,
        "IC Req");
    TEST_ASSERT(
        test_issue_cert(&res, &req, (uint8_t *)"CA", 2, &g_ca_priv, &g_ca_pub)
            == SM2_IC_SUCCESS,
        "IC Issue");
    TEST_ASSERT(sm2_ic_cbor_encode_cert(buf, &implicit_len, &res.cert)
            == SM2_IC_SUCCESS,
        "IC Encode");

    double ratio = (double)implicit_len / (double)x509_der_len;
    printf("   [X509-BASELINE] implicit=%zu, x509_der=%d, ratio=%.4f%%\n",
        implicit_len, x509_der_len, ratio * 100.0);
    TEST_ASSERT(ratio <= 0.30, "Implicit/X509 Ratio > 30%");

    X509_free(cert);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    TEST_PASS();
}

static void test_phase4_service_client_flow()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "PHASE4_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 64, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "AIRCRAFT_A";
    TEST_ASSERT(
        sm2_pki_identity_register(service, identity, sizeof(identity) - 1,
            SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT)
            == SM2_PKI_SUCCESS,
        "Identity Register");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    TEST_ASSERT(
        pki_create_and_authorize_request(service, identity,
            sizeof(identity) - 1,
            SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT, &req, &temp_priv),
        "Cert Request");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req, &cert_res) == SM2_PKI_SUCCESS,
        "Cert Issue");
    uint64_t auth_now = test_cert_now(&cert_res.cert);

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
    TEST_ASSERT(
        sm2_pki_client_enable_sign_pool(client, 64, 32) == SM2_PKI_SUCCESS,
        "Enable Precompute");

    const uint8_t msg[] = "PHASE4_FLOW_MESSAGE";
    sm2_auth_signature_t sig;
    sm2_pki_evidence_bundle_t evidence;
    sm2_pki_verify_request_t request;
    TEST_ASSERT(pki_build_signed_verify_request(client, msg, sizeof(msg) - 1,
                    auth_now, &sig, &evidence, &request),
        "Build Signed Verify Request");
    size_t matched = 0;
    TEST_ASSERT(
        sm2_pki_verify(client, &request, auth_now, &matched) == SM2_PKI_SUCCESS,
        "PKI Verify");
    TEST_ASSERT(matched == 0, "Matched Default CA");

    sm2_private_key_t eph_priv;
    sm2_ec_point_t eph_pub;
    TEST_ASSERT(sm2_pki_generate_ephemeral_keypair(&eph_priv, &eph_pub)
            == SM2_PKI_SUCCESS,
        "Generate Ephemeral");

    const uint8_t transcript[] = "PHASE4_SECURE_SESSION";
    uint8_t session_key[16];
    TEST_ASSERT(sm2_pki_key_agreement(client, &eph_priv, request.public_key,
                    &eph_pub, transcript, sizeof(transcript) - 1, session_key,
                    sizeof(session_key))
            == SM2_PKI_SUCCESS,
        "Key Agreement");

    sm2_pki_client_destroy(&client);
    sm2_pki_client_destroy(&client);
    sm2_pki_service_destroy(&service);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase4_revocation_epoch_and_cross_domain()
{
    sm2_pki_service_ctx_t *svc_a = NULL;
    sm2_pki_service_ctx_t *svc_b = NULL;
    const uint8_t issuer_a[] = "CA_A";
    const uint8_t issuer_b[] = "CA_B";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &svc_a, issuer_a, sizeof(issuer_a) - 1, 64, 300, base_now)
            == SM2_PKI_SUCCESS,
        "SvcA Init");
    TEST_ASSERT(sm2_pki_service_create(
                    &svc_b, issuer_b, sizeof(issuer_b) - 1, 64, 300, base_now)
            == SM2_PKI_SUCCESS,
        "SvcB Init");

    const uint8_t id_b[] = "NODE_B";
    TEST_ASSERT(sm2_pki_identity_register(
                    svc_b, id_b, sizeof(id_b) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Register B");

    sm2_ic_cert_request_t req_b;
    sm2_private_key_t temp_b;
    sm2_ic_cert_result_t cert_b;
    TEST_ASSERT(pki_create_and_authorize_request(svc_b, id_b, sizeof(id_b) - 1,
                    SM2_KU_DIGITAL_SIGNATURE, &req_b, &temp_b),
        "Req B");
    TEST_ASSERT(test_pki_issue_cert(svc_b, &req_b, &cert_b) == SM2_PKI_SUCCESS,
        "Issue B");
    uint64_t auth_now = test_cert_now(&cert_b.cert);

    sm2_rev_status_t status;
    sm2_rev_source_t source;
    TEST_ASSERT(sm2_pki_service_check_revocation(svc_b,
                    cert_b.cert.serial_number, auth_now + 10, &status, &source)
            == SM2_PKI_SUCCESS,
        "Revoke Check Good");
    TEST_ASSERT(status == SM2_REV_STATUS_GOOD, "Initial Good");
    TEST_ASSERT(source == SM2_REV_SOURCE_MERKLE_NODE, "Source Merkle");

    sm2_ec_point_t ca_b_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(svc_b, &ca_b_pub) == SM2_PKI_SUCCESS,
        "Get CA_B");

    sm2_pki_client_ctx_t *client_b = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&client_b, &ca_b_pub, svc_b) == SM2_PKI_SUCCESS,
        "ClientB Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(client_b, &cert_b, &temp_b, &ca_b_pub)
            == SM2_PKI_SUCCESS,
        "ClientB Import");

    sm2_ec_point_t ca_a_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(svc_a, &ca_a_pub) == SM2_PKI_SUCCESS,
        "Get CA_A");
    sm2_pki_client_ctx_t *verifier = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&verifier, &ca_a_pub, svc_b) == SM2_PKI_SUCCESS,
        "Verifier Init");
    TEST_ASSERT(pki_configure_default_transparency_policy(verifier),
        "Verifier Witness Policy");
    TEST_ASSERT(
        sm2_pki_client_add_trusted_ca(verifier, &ca_b_pub) == SM2_PKI_SUCCESS,
        "Add Cross Domain CA");

    const uint8_t msg[] = "CROSS_DOMAIN_AUTH";
    sm2_auth_signature_t sig_b;
    sm2_pki_evidence_bundle_t evidence_b;
    sm2_pki_verify_request_t req_auth;
    sm2_pki_epoch_checkpoint_t checkpoint_b;
    TEST_ASSERT(pki_build_signed_verify_request(client_b, msg, sizeof(msg) - 1,
                    auth_now + 20, &sig_b, &evidence_b, &req_auth),
        "Build Cross Verify Request");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    verifier, client_b, auth_now + 20, &checkpoint_b),
        "Verifier Imports CA_B Checkpoint");

    size_t matched = 0;
    TEST_ASSERT(sm2_pki_verify(verifier, &req_auth, auth_now + 20, &matched)
            == SM2_PKI_SUCCESS,
        "Cross Verify");
    TEST_ASSERT(matched == 1, "Matched CA_B");

    TEST_ASSERT(
        sm2_pki_service_revoke(svc_b, cert_b.cert.serial_number, auth_now + 30)
            == SM2_PKI_SUCCESS,
        "Revoke B Cert");
    TEST_ASSERT(sm2_pki_service_check_revocation(svc_b,
                    cert_b.cert.serial_number, auth_now + 40, &status, &source)
            == SM2_PKI_SUCCESS,
        "Revoke Check Revoked");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "Status Revoked");

    sm2_pki_evidence_bundle_t after_revoke_evidence;
    memset(&after_revoke_evidence, 0, sizeof(after_revoke_evidence));
    TEST_ASSERT(sm2_pki_client_export_epoch_evidence(
                    client_b, auth_now + 50, &after_revoke_evidence)
            == SM2_PKI_ERR_VERIFY,
        "Revoked Peer Cannot Export Fresh Evidence");

    TEST_ASSERT(sm2_pki_verify(verifier, &req_auth,
                    checkpoint_b.epoch_root_record.valid_until + 1, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Verify Blocked After Evidence Expiry");

    sm2_pki_client_destroy(&verifier);
    sm2_pki_client_destroy(&client_b);
    sm2_pki_service_destroy(&svc_b);
    sm2_pki_service_destroy(&svc_a);
    TEST_PASS();
}

static void test_phase4_pki_controls_and_param_defense()
{
    sm2_pki_service_ctx_t *service = NULL;
    sm2_pki_service_ctx_t *bad_service = NULL;
    const uint8_t issuer[] = "CTRL_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &bad_service, issuer, sizeof(issuer) - 1, 32, 0, base_now)
            == SM2_PKI_ERR_PARAM,
        "Service Init Zero TTL Reject");
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "CTRL_NODE";
    TEST_ASSERT(
        sm2_pki_identity_register(service, identity, sizeof(identity) - 1,
            SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT)
            == SM2_PKI_SUCCESS,
        "Identity Register");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    TEST_ASSERT(
        pki_create_and_authorize_request(service, identity,
            sizeof(identity) - 1,
            SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT, &req, &temp_priv),
        "Cert Request");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req, &cert_res) == SM2_PKI_SUCCESS,
        "Cert Issue");
    TEST_ASSERT(cert_res.cert.field_mask == SM2_IC_FIELD_MASK_ALL,
        "Issued Mask Secure");

    sm2_ec_point_t ca_pub;
    sm2_private_key_t wrong_ca_priv;
    sm2_ec_point_t wrong_ca_pub;
    sm2_ic_cert_result_t tampered_cert_res;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");
    TEST_ASSERT(test_generate_sm2_keypair(&wrong_ca_priv, &wrong_ca_pub),
        "Generate Wrong CA");

    sm2_pki_client_ctx_t *client = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&client, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Client Init");
    TEST_ASSERT(
        sm2_pki_client_add_trusted_ca(client, NULL) == SM2_PKI_ERR_PARAM,
        "Add Trusted NULL");

    TEST_ASSERT(
        sm2_pki_client_enable_sign_pool(client, 32, 16) == SM2_PKI_ERR_PARAM,
        "Enable Precompute Without Keys");

    tampered_cert_res = cert_res;
    tampered_cert_res.cert.public_recon_key[0] ^= 0x01;
    TEST_ASSERT(
        sm2_pki_client_import_cert(client, &cert_res, &temp_priv, &wrong_ca_pub)
            == SM2_PKI_ERR_VERIFY,
        "Import Wrong CA Reject");
    TEST_ASSERT(sm2_pki_client_import_cert(
                    client, &tampered_cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_ERR_VERIFY,
        "Import Tampered Cert Reject");
    TEST_ASSERT(
        sm2_pki_client_import_cert(client, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Import Cert");
    TEST_ASSERT(
        sm2_pki_client_enable_sign_pool(client, 0, 0) == SM2_PKI_ERR_PARAM,
        "Enable Precompute Zero Capacity");
    TEST_ASSERT(
        sm2_pki_client_enable_sign_pool(client, 32, 16) == SM2_PKI_SUCCESS,
        "Enable Precompute");

    sm2_pki_client_disable_sign_pool(client);
    TEST_ASSERT(
        !sm2_pki_client_is_sign_pool_enabled(client), "Disable Precompute");
    sm2_pki_client_disable_sign_pool(client);
    TEST_ASSERT(!sm2_pki_client_is_sign_pool_enabled(client),
        "Disable Precompute Idempotent");

    const uint8_t msg[] = "CTRL_SIGN";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_pki_sign(client, msg, sizeof(msg) - 1, &sig) == SM2_PKI_SUCCESS,
        "Sign After Disable");
    const sm2_ec_point_t *client_pub = NULL;
    TEST_ASSERT(pki_client_get_identity_material(client, NULL, &client_pub),
        "Get Client Public Key");

    uint8_t session_key[16];
    sm2_private_key_t eph_priv;
    sm2_ec_point_t eph_pub;
    TEST_ASSERT(sm2_pki_generate_ephemeral_keypair(&eph_priv, &eph_pub)
            == SM2_PKI_SUCCESS,
        "Generate Ephemeral For Controls");
    {
        EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
        BIGNUM *order = BN_new();
        BIGNUM *eph_bn = BN_bin2bn(eph_priv.d, SM2_KEY_LEN, NULL);
        int alloc_ok = group && order && eph_bn;
        int order_ok = alloc_ok && EC_GROUP_get_order(group, order, NULL) == 1;
        int nonzero_ok = order_ok && !BN_is_zero(eph_bn);
        int range_ok = order_ok && BN_cmp(eph_bn, order) < 0;
        BN_clear_free(eph_bn);
        BN_free(order);
        EC_GROUP_free(group);
        TEST_ASSERT(alloc_ok, "Ephemeral Range Alloc");
        TEST_ASSERT(order_ok, "Ephemeral Read Order");
        TEST_ASSERT(nonzero_ok, "Ephemeral Scalar NonZero");
        TEST_ASSERT(range_ok, "Ephemeral Scalar Below Order");
    }
    TEST_ASSERT(sm2_pki_key_agreement(client, NULL, client_pub, &eph_pub, NULL,
                    0, session_key, sizeof(session_key))
            == SM2_PKI_ERR_PARAM,
        "Key Agreement NULL Ephemeral");

    uint8_t aead_iv[12] = { 0 };
    uint8_t tag[SM2_AUTH_AEAD_TAG_MAX_LEN] = { 0 };
    size_t ciphertext_len = 0;
    size_t tag_len = 16;
    TEST_ASSERT(sm2_pki_encrypt(SM2_AUTH_AEAD_MODE_SM4_GCM, session_key,
                    aead_iv, sizeof(aead_iv), NULL, 0, msg, sizeof(msg) - 1,
                    NULL, &ciphertext_len, tag, &tag_len)
            == SM2_PKI_ERR_PARAM,
        "Encrypt NULL Ciphertext");
    TEST_ASSERT(sm2_pki_service_refresh_root(NULL, 0) == SM2_PKI_ERR_PARAM,
        "Refresh Root NULL Service");

    sm2_pki_client_destroy(&client);
    sm2_pki_client_destroy(&client);
    sm2_pki_service_destroy(&service);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}
