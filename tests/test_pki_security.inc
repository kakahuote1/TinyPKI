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
    sm2_pki_evidence_bundle_t evidence;
    sm2_pki_verify_request_t request;
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

    TEST_ASSERT(pki_build_signed_verify_request(client, msg, sizeof(msg) - 1,
                    fresh_now, &sig, &evidence, &request),
        "Build Initial Evidence Request");

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
        "Verify Path Must Not Refresh Root");

    TEST_ASSERT(sm2_pki_service_refresh_root(service, expired_now + 19)
            == SM2_PKI_SUCCESS,
        "Explicit Refresh Root");
    TEST_ASSERT(sm2_pki_service_get_root_record(service, &root_after_refresh)
            == SM2_PKI_SUCCESS,
        "Get Root After Refresh");
    TEST_ASSERT(root_after_refresh.valid_until > root_before.valid_until,
        "Explicit Refresh Extends Validity");
    TEST_ASSERT(pki_build_signed_verify_request(client, msg, sizeof(msg) - 1,
                    expired_now + 20, &sig, &evidence, &request),
        "Build Refreshed Evidence Request");
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

static void test_phase93_reissue_preserves_old_serial_revocability()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P93_REISSUE_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P93_NODE";
    TEST_ASSERT(sm2_pki_identity_register(service, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity Register");

    sm2_ic_cert_request_t req_old;
    sm2_ic_cert_request_t req_new;
    sm2_private_key_t temp_old;
    sm2_private_key_t temp_new;
    sm2_ic_cert_result_t cert_old;
    sm2_ic_cert_result_t cert_new;
    memset(&req_old, 0, sizeof(req_old));
    memset(&req_new, 0, sizeof(req_new));
    memset(&cert_old, 0, sizeof(cert_old));
    memset(&cert_new, 0, sizeof(cert_new));

    TEST_ASSERT(pki_create_and_authorize_request(service, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE, &req_old,
                    &temp_old),
        "Authorize Old");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req_old, &cert_old) == SM2_PKI_SUCCESS,
        "Issue Old");

    TEST_ASSERT(pki_create_and_authorize_request(service, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE, &req_new,
                    &temp_new),
        "Authorize New");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req_new, &cert_new) == SM2_PKI_SUCCESS,
        "Issue New");

    TEST_ASSERT(cert_old.cert.serial_number != cert_new.cert.serial_number,
        "Reissue Must Mint New Serial");

    TEST_ASSERT(sm2_pki_service_revoke(
                    service, cert_old.cert.serial_number, base_now + 10)
            == SM2_PKI_SUCCESS,
        "Revoke Old Serial");

    sm2_rev_status_t status = SM2_REV_STATUS_UNKNOWN;
    sm2_rev_source_t source = SM2_REV_SOURCE_NONE;
    TEST_ASSERT(
        sm2_pki_service_check_revocation(service, cert_old.cert.serial_number,
            base_now + 11, &status, &source)
            == SM2_PKI_SUCCESS,
        "Old Revoke Check");
    TEST_ASSERT(status == SM2_REV_STATUS_REVOKED, "Old Serial Revoked");

    TEST_ASSERT(
        sm2_pki_service_check_revocation(service, cert_new.cert.serial_number,
            base_now + 11, &status, &source)
            == SM2_PKI_SUCCESS,
        "New Revoke Check");
    TEST_ASSERT(status == SM2_REV_STATUS_GOOD, "New Serial Still Good");

    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase93_reimport_clears_stale_sign_pool()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P93_REIMPORT_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P93_REIMPORT_NODE";
    TEST_ASSERT(sm2_pki_identity_register(service, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity Register");

    sm2_ic_cert_request_t req_old;
    sm2_ic_cert_request_t req_new;
    sm2_private_key_t temp_old;
    sm2_private_key_t temp_new;
    sm2_ic_cert_result_t cert_old;
    sm2_ic_cert_result_t cert_new;
    memset(&req_old, 0, sizeof(req_old));
    memset(&req_new, 0, sizeof(req_new));
    memset(&cert_old, 0, sizeof(cert_old));
    memset(&cert_new, 0, sizeof(cert_new));

    TEST_ASSERT(pki_create_and_authorize_request(service, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE, &req_old,
                    &temp_old),
        "Authorize Old");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req_old, &cert_old) == SM2_PKI_SUCCESS,
        "Issue Old");
    TEST_ASSERT(pki_create_and_authorize_request(service, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE, &req_new,
                    &temp_new),
        "Authorize New");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req_new, &cert_new) == SM2_PKI_SUCCESS,
        "Issue New");

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *client = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&client, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Client Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(client, &cert_old, &temp_old, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Import Old");

    const sm2_ec_point_t *current_pub = NULL;
    TEST_ASSERT(pki_client_get_identity_material(client, NULL, &current_pub),
        "Get Old Public Key");
    sm2_ec_point_t old_pub = *current_pub;

    TEST_ASSERT(
        sm2_pki_client_enable_sign_pool(client, 4, 4) == SM2_PKI_SUCCESS,
        "Enable Sign Pool");
    TEST_ASSERT(sm2_pki_client_is_sign_pool_enabled(client), "Pool Enabled");

    TEST_ASSERT(
        sm2_pki_client_import_cert(client, &cert_new, &temp_new, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Import New");
    TEST_ASSERT(
        !sm2_pki_client_is_sign_pool_enabled(client), "Stale Pool Cleared");
    TEST_ASSERT(pki_client_get_identity_material(client, NULL, &current_pub),
        "Get New Public Key");

    const uint8_t msg[] = "P93_REIMPORT_SIGN";
    sm2_auth_signature_t sig;
    TEST_ASSERT(
        sm2_pki_sign(client, msg, sizeof(msg) - 1, &sig) == SM2_PKI_SUCCESS,
        "Sign With New Identity");
    TEST_ASSERT(
        sm2_auth_verify_signature(current_pub, msg, sizeof(msg) - 1, &sig)
            == SM2_IC_SUCCESS,
        "Verify Against New Key");
    TEST_ASSERT(sm2_auth_verify_signature(&old_pub, msg, sizeof(msg) - 1, &sig)
            == SM2_IC_ERR_VERIFY,
        "Reject Old Sign Pool Key");

    sm2_pki_client_destroy(&client);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase93_service_certificate_history_grows_past_previous_cap()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P93_HISTORY_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P93_HISTORY_NODE";
    TEST_ASSERT(sm2_pki_identity_register(service, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity Register");

    const size_t previous_cap = (size_t)SM2_PKI_MAX_IDENTITIES * 4U;
    const size_t issue_total = previous_cap + 8U;
    uint64_t first_serial = 0;
    uint64_t last_serial = 0;

    for (size_t i = 0; i < issue_total; i++)
    {
        sm2_ic_cert_request_t req;
        sm2_private_key_t temp_priv;
        sm2_ic_cert_result_t cert_res;
        memset(&req, 0, sizeof(req));
        memset(&cert_res, 0, sizeof(cert_res));

        TEST_ASSERT(pki_create_and_authorize_request(service, identity,
                        sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE, &req,
                        &temp_priv),
            "Authorize Loop");
        TEST_ASSERT(
            test_pki_issue_cert(service, &req, &cert_res) == SM2_PKI_SUCCESS,
            "Issue Loop");

        if (i == 0)
            first_serial = cert_res.cert.serial_number;
        last_serial = cert_res.cert.serial_number;
    }

    TEST_ASSERT(first_serial != 0 && last_serial != 0, "Serials Captured");
    TEST_ASSERT(sm2_pki_service_revoke(service, first_serial, base_now + 10)
            == SM2_PKI_SUCCESS,
        "Revoke First Serial");
    TEST_ASSERT(sm2_pki_service_revoke(service, last_serial, base_now + 11)
            == SM2_PKI_SUCCESS,
        "Revoke Last Serial");

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
        sm2_pki_client_create(&client_a, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Client A Init");
    TEST_ASSERT(
        sm2_pki_client_create(&client_b, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Client B Init");
    TEST_ASSERT(pki_configure_default_transparency_policy(client_a),
        "Client A Witness Policy");
    TEST_ASSERT(pki_configure_default_transparency_policy(client_b),
        "Client B Witness Policy");
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
    uint8_t bind_a[256];
    uint8_t bind_b[256];
    size_t bind_a_len = sizeof(bind_a);
    size_t bind_b_len = sizeof(bind_b);
    TEST_ASSERT(sm2_pki_secure_session_build_binding(&eph_pub_a, &eph_pub_b,
                    transcript, sizeof(transcript) - 1, bind_a, &bind_a_len)
            == SM2_PKI_SUCCESS,
        "Build Bind A");
    TEST_ASSERT(sm2_pki_secure_session_build_binding(&eph_pub_b, &eph_pub_a,
                    transcript, sizeof(transcript) - 1, bind_b, &bind_b_len)
            == SM2_PKI_SUCCESS,
        "Build Bind B");

    sm2_auth_signature_t sig_a;
    sm2_auth_signature_t sig_b;
    TEST_ASSERT(
        sm2_pki_sign(client_a, bind_a, bind_a_len, &sig_a) == SM2_PKI_SUCCESS,
        "Sign Bind A");
    TEST_ASSERT(
        sm2_pki_sign(client_b, bind_b, bind_b_len, &sig_b) == SM2_PKI_SUCCESS,
        "Sign Bind B");

    uint64_t auth_now = test_cert_pair_now(&cert_a.cert, &cert_b.cert);
    sm2_pki_evidence_bundle_t evidence_a;
    sm2_pki_evidence_bundle_t evidence_b;
    sm2_pki_verify_request_t req_a_to_b;
    sm2_pki_verify_request_t req_b_to_a;
    memset(&evidence_a, 0, sizeof(evidence_a));
    memset(&evidence_b, 0, sizeof(evidence_b));
    memset(&req_a_to_b, 0, sizeof(req_a_to_b));
    memset(&req_b_to_a, 0, sizeof(req_b_to_a));
    TEST_ASSERT(
        sm2_pki_client_export_epoch_evidence(client_a, auth_now, &evidence_a)
            == SM2_PKI_SUCCESS,
        "Evidence A");
    TEST_ASSERT(
        sm2_pki_client_export_epoch_evidence(client_b, auth_now, &evidence_b)
            == SM2_PKI_SUCCESS,
        "Evidence B");

    const sm2_implicit_cert_t *client_a_cert = NULL;
    const sm2_implicit_cert_t *client_b_cert = NULL;
    TEST_ASSERT(
        sm2_pki_client_get_cert(client_a, &client_a_cert) == SM2_PKI_SUCCESS,
        "Get Client A Cert");
    TEST_ASSERT(
        sm2_pki_client_get_cert(client_b, &client_b_cert) == SM2_PKI_SUCCESS,
        "Get Client B Cert");
    req_a_to_b.cert = client_a_cert;
    req_a_to_b.public_key = client_a_pub;
    req_a_to_b.message = bind_a;
    req_a_to_b.message_len = bind_a_len;
    req_a_to_b.signature = &sig_a;
    req_a_to_b.evidence_bundle = &evidence_a;

    req_b_to_a.cert = client_b_cert;
    req_b_to_a.public_key = client_b_pub;
    req_b_to_a.message = bind_b;
    req_b_to_a.message_len = bind_b_len;
    req_b_to_a.signature = &sig_b;
    req_b_to_a.evidence_bundle = &evidence_b;
    TEST_ASSERT(
        pki_import_epoch_checkpoint_from_signer(client_a, client_b,
            auth_now, NULL),
        "Client A Imports Peer Checkpoint");
    TEST_ASSERT(
        pki_import_epoch_checkpoint_from_signer(client_b, client_a,
            auth_now, NULL),
        "Client B Imports Peer Checkpoint");

    uint8_t sk_a[16];
    uint8_t sk_b[16];
    size_t matched_a = 0;
    size_t matched_b = 0;
    TEST_ASSERT(
        sm2_pki_secure_session_establish(client_a, &eph_priv_a, &eph_pub_a,
            &req_b_to_a, &eph_pub_a, transcript, sizeof(transcript) - 1,
            auth_now, sk_a, sizeof(sk_a), &matched_a)
            == SM2_PKI_ERR_VERIFY,
        "Reject Unbound Peer Ephemeral");
    TEST_ASSERT(
        sm2_pki_secure_session_establish(client_a, &eph_priv_a, &eph_pub_a,
            &req_b_to_a, &eph_pub_b, transcript, sizeof(transcript) - 1,
            auth_now, sk_a, sizeof(sk_a), &matched_a)
            == SM2_PKI_SUCCESS,
        "Secure Session A");
    TEST_ASSERT(
        sm2_pki_secure_session_establish(client_b, &eph_priv_b, &eph_pub_b,
            &req_a_to_b, &eph_pub_a, transcript, sizeof(transcript) - 1,
            auth_now, sk_b, sizeof(sk_b), &matched_b)
            == SM2_PKI_SUCCESS,
        "Secure Session B");
    TEST_ASSERT(matched_a == 0 && matched_b == 0, "Matched Default CA");
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
    sm2_pki_evidence_bundle_t evidence;
    uint64_t auth_now = test_cert_now(&cert_res.cert);
    TEST_ASSERT(
        pki_build_signed_verify_request(client, msg, sizeof(msg) - 1, auth_now,
            &sig, &evidence, &(sm2_pki_verify_request_t) { 0 }),
        "Build Evidence Before Service Cleanup");

    sm2_pki_service_destroy(&service);
    TEST_ASSERT(
        sm2_pki_client_export_epoch_evidence(client, auth_now + 1, &evidence)
            == SM2_PKI_ERR_VERIFY,
        "Bound Service Cleanup Must Fail Closed");
    TEST_ASSERT(
        sm2_pki_client_bind_revocation(client, service) == SM2_PKI_ERR_PARAM,
        "Bind Cleaned Service Reject");

    sm2_pki_client_destroy(&client);
    TEST_PASS();
}

static void test_phase134_pki_verify_requires_epoch_bundle()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P134_EPOCH_CA";
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

    const uint8_t msg[] = "P134_EPOCH_REQUIRED";
    sm2_auth_signature_t sig;
    sm2_pki_verify_request_t request;
    size_t matched = 0;
    uint64_t auth_now = test_cert_now(&cert_res.cert);
    TEST_ASSERT(
        sm2_pki_sign(client, msg, sizeof(msg) - 1, &sig) == SM2_PKI_SUCCESS,
        "Sign");
    const sm2_implicit_cert_t *client_cert = NULL;
    const sm2_ec_point_t *client_pub = NULL;
    TEST_ASSERT(
        pki_client_get_identity_material(client, &client_cert, &client_pub),
        "Get Client Material");
    memset(&request, 0, sizeof(request));
    request.cert = client_cert;
    request.public_key = client_pub;
    request.message = msg;
    request.message_len = sizeof(msg) - 1;
    request.signature = &sig;
    TEST_ASSERT(sm2_pki_verify(client, &request, auth_now, &matched)
            == SM2_PKI_ERR_VERIFY,
        "High-Level Verify Rejects Missing Carried Evidence");

    sm2_pki_client_destroy(&client);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase137_client_epoch_cache_refresh_and_rollback()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P137_EPOCH_CA";
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

    sm2_pki_client_ctx_t *signer = NULL;
    sm2_pki_client_ctx_t *verifier = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&signer, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_create(&verifier, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Verifier Init");
    TEST_ASSERT(pki_configure_default_transparency_policy(verifier),
        "Verifier Witness Policy");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");

    const uint8_t msg[] = "P137_EPOCH_CACHE";
    uint64_t auth_now = test_cert_now(&cert_res.cert);
    sm2_auth_signature_t sig_initial;
    sm2_auth_signature_t sig_refreshed;
    sm2_pki_evidence_bundle_t evidence_initial;
    sm2_pki_evidence_bundle_t evidence_refreshed;
    sm2_pki_verify_request_t request_initial;
    sm2_pki_verify_request_t request_refreshed;
    sm2_pki_epoch_checkpoint_t checkpoint_initial;
    sm2_pki_epoch_checkpoint_t checkpoint_refreshed;
    TEST_ASSERT(
        pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1, auth_now,
            &sig_initial, &evidence_initial, &request_initial),
        "Build Initial Request");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    verifier, signer, auth_now, &checkpoint_initial),
        "Verifier Imports Initial Checkpoint");

    size_t matched = 0;
    TEST_ASSERT(sm2_pki_verify(verifier, &request_initial, auth_now, &matched)
            == SM2_PKI_SUCCESS,
        "Verify Initial Epoch");

    sm2_pki_evidence_bundle_t tampered_evidence = evidence_initial;
    tampered_evidence.epoch_digest[0] ^= 0x01U;
    sm2_pki_verify_request_t tampered_request = request_initial;
    tampered_request.evidence_bundle = &tampered_evidence;
    TEST_ASSERT(sm2_pki_verify(verifier, &tampered_request, auth_now, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Tampered Epoch Digest Reject");

    TEST_ASSERT(
        sm2_pki_service_refresh_root(service, auth_now + 10) == SM2_PKI_SUCCESS,
        "Refresh Epoch Root");
    TEST_ASSERT(pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1,
                    auth_now + 10, &sig_refreshed, &evidence_refreshed,
                    &request_refreshed),
        "Build Refreshed Request");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    verifier, signer, auth_now + 10, &checkpoint_refreshed),
        "Verifier Imports Refreshed Checkpoint");
    TEST_ASSERT(checkpoint_refreshed.epoch_root_record.epoch_version
            > checkpoint_initial.epoch_root_record.epoch_version,
        "Refreshed Epoch Version Advanced");
    TEST_ASSERT(
        sm2_pki_verify(verifier, &request_refreshed, auth_now + 10, &matched)
            == SM2_PKI_SUCCESS,
        "Verify Refreshed Epoch");
    TEST_ASSERT(
        sm2_pki_verify(verifier, &request_initial, auth_now + 10, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Rollback Epoch Reject");

    sm2_pki_client_destroy(&verifier);
    sm2_pki_client_destroy(&signer);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase137_epoch_cache_survives_local_cert_import()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P137_IMPORT_CACHE_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t peer_identity[] = "P137_IMPORT_PEER";
    const uint8_t local_identity[] = "P137_IMPORT_LOCAL";
    TEST_ASSERT(sm2_pki_identity_register(service, peer_identity,
                    sizeof(peer_identity) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Peer Identity Register");
    TEST_ASSERT(sm2_pki_identity_register(service, local_identity,
                    sizeof(local_identity) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Local Identity Register");

    sm2_private_key_t peer_temp;
    sm2_private_key_t local_temp;
    sm2_ic_cert_result_t peer_cert;
    sm2_ic_cert_result_t local_cert;
    TEST_ASSERT(pki_issue_identity_cert(service, peer_identity,
                    sizeof(peer_identity) - 1, SM2_KU_DIGITAL_SIGNATURE,
                    &peer_cert, &peer_temp),
        "Issue Peer Cert");
    TEST_ASSERT(pki_issue_identity_cert(service, local_identity,
                    sizeof(local_identity) - 1, SM2_KU_DIGITAL_SIGNATURE,
                    &local_cert, &local_temp),
        "Issue Local Cert");

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *peer = NULL;
    sm2_pki_client_ctx_t *verifier = NULL;
    TEST_ASSERT(sm2_pki_client_create(&peer, &ca_pub, service)
            == SM2_PKI_SUCCESS,
        "Peer Init");
    TEST_ASSERT(sm2_pki_client_import_cert(peer, &peer_cert, &peer_temp, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Peer Import");
    TEST_ASSERT(sm2_pki_client_create(&verifier, &ca_pub, NULL)
            == SM2_PKI_SUCCESS,
        "Verifier Init");
    TEST_ASSERT(pki_configure_default_transparency_policy(verifier),
        "Verifier Witness Policy");

    const uint8_t msg[] = "P137_IMPORT_CACHE";
    uint64_t auth_now = test_cert_now(&peer_cert.cert);
    sm2_auth_signature_t sig_initial;
    sm2_auth_signature_t sig_refreshed;
    sm2_pki_evidence_bundle_t evidence_initial;
    sm2_pki_evidence_bundle_t evidence_refreshed;
    sm2_pki_verify_request_t request_initial;
    sm2_pki_verify_request_t request_refreshed;
    TEST_ASSERT(
        pki_build_signed_verify_request(peer, msg, sizeof(msg) - 1, auth_now,
            &sig_initial, &evidence_initial, &request_initial),
        "Build Initial Request");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    verifier, peer, auth_now, NULL),
        "Verifier Imports Initial Checkpoint");

    size_t matched = 0;
    TEST_ASSERT(sm2_pki_verify(verifier, &request_initial, auth_now, &matched)
            == SM2_PKI_SUCCESS,
        "Verify Initial Epoch");

    TEST_ASSERT(
        sm2_pki_service_refresh_root(service, auth_now + 10) == SM2_PKI_SUCCESS,
        "Refresh Epoch Root");
    TEST_ASSERT(pki_build_signed_verify_request(peer, msg, sizeof(msg) - 1,
                    auth_now + 10, &sig_refreshed, &evidence_refreshed,
                    &request_refreshed),
        "Build Refreshed Request");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    verifier, peer, auth_now + 10, NULL),
        "Verifier Imports Refreshed Checkpoint");
    TEST_ASSERT(
        sm2_pki_verify(verifier, &request_refreshed, auth_now + 10, &matched)
            == SM2_PKI_SUCCESS,
        "Verify Refreshed Epoch");

    TEST_ASSERT(
        sm2_pki_client_import_cert(verifier, &local_cert, &local_temp, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Verifier Local Import");
    TEST_ASSERT(
        sm2_pki_verify(verifier, &request_initial, auth_now + 10, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Local Import Must Preserve Epoch Anti-Rollback");

    sm2_pki_client_destroy(&verifier);
    sm2_pki_client_destroy(&peer);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase137_persisted_highwater_blocks_restart_rollback()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P137_PERSIST_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P137_PERSIST_NODE";
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

    sm2_pki_client_ctx_t *signer = NULL;
    sm2_pki_client_ctx_t *verifier = NULL;
    sm2_pki_client_ctx_t *restarted = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&signer, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");
    TEST_ASSERT(
        sm2_pki_client_create(&verifier, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Verifier Init");
    TEST_ASSERT(pki_configure_default_transparency_policy(verifier),
        "Verifier Witness Policy");

    const uint8_t msg[] = "P137_PERSIST_HIGHWATER";
    uint64_t auth_now = test_cert_now(&cert_res.cert);
    sm2_auth_signature_t sig_initial;
    sm2_auth_signature_t sig_refreshed;
    sm2_pki_evidence_bundle_t evidence_initial;
    sm2_pki_evidence_bundle_t evidence_refreshed;
    sm2_pki_verify_request_t request_initial;
    sm2_pki_verify_request_t request_refreshed;
    sm2_pki_epoch_checkpoint_t checkpoint_initial;
    sm2_pki_epoch_checkpoint_t checkpoint_refreshed;

    TEST_ASSERT(
        pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1, auth_now,
            &sig_initial, &evidence_initial, &request_initial),
        "Build Initial Request");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    verifier, signer, auth_now, &checkpoint_initial),
        "Verifier Imports Initial Checkpoint");

    TEST_ASSERT(
        sm2_pki_service_refresh_root(service, auth_now + 10) == SM2_PKI_SUCCESS,
        "Refresh Epoch Root");
    TEST_ASSERT(pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1,
                    auth_now + 10, &sig_refreshed, &evidence_refreshed,
                    &request_refreshed),
        "Build Refreshed Request");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    verifier, signer, auth_now + 10, &checkpoint_refreshed),
        "Verifier Imports Refreshed Checkpoint");
    TEST_ASSERT(checkpoint_refreshed.epoch_root_record.epoch_version
            > checkpoint_initial.epoch_root_record.epoch_version,
        "Refreshed Epoch Version Advanced");

    sm2_pki_client_persisted_state_t persisted;
    memset(&persisted, 0, sizeof(persisted));
    TEST_ASSERT(sm2_pki_client_export_persisted_state(verifier, &persisted)
            == SM2_PKI_SUCCESS,
        "Export Persisted State");
    TEST_ASSERT(persisted.record_count == 1, "Persisted Record Count");

    TEST_ASSERT(
        sm2_pki_client_create(&restarted, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Restarted Verifier Init");
    TEST_ASSERT(sm2_pki_client_import_persisted_state(
                    restarted, &persisted, auth_now + 10)
            == SM2_PKI_SUCCESS,
        "Import Persisted State");
    TEST_ASSERT(pki_configure_default_transparency_policy(restarted),
        "Restarted Witness Policy");

    TEST_ASSERT(sm2_pki_client_import_epoch_checkpoint(
                    restarted, &checkpoint_initial, auth_now + 10)
            == SM2_PKI_ERR_VERIFY,
        "Restarted Verifier Rejects Old Checkpoint");

    size_t matched = 0;
    TEST_ASSERT(
        sm2_pki_verify(restarted, &request_initial, auth_now + 10, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Persisted Highwater Is Not A Cached Checkpoint");
    TEST_ASSERT(sm2_pki_client_import_epoch_checkpoint(
                    restarted, &checkpoint_refreshed, auth_now + 10)
            == SM2_PKI_SUCCESS,
        "Restarted Verifier Imports Refreshed Checkpoint");
    TEST_ASSERT(
        sm2_pki_verify(restarted, &request_refreshed, auth_now + 10, &matched)
            == SM2_PKI_SUCCESS,
        "Restarted Verifier Accepts Fresh Evidence");

    sm2_pki_client_destroy(&restarted);
    sm2_pki_client_destroy(&verifier);
    sm2_pki_client_destroy(&signer);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase137_persisted_checkpoint_restores_offline_verify()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P137_PERSIST_RECOVER_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P137_PERSIST_RECOVER_NODE";
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

    sm2_pki_client_ctx_t *signer = NULL;
    sm2_pki_client_ctx_t *verifier = NULL;
    sm2_pki_client_ctx_t *restarted = NULL;
    sm2_pki_client_ctx_t *tampered_client = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&signer, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");
    TEST_ASSERT(
        sm2_pki_client_create(&verifier, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Verifier Init");
    TEST_ASSERT(pki_configure_default_transparency_policy(verifier),
        "Verifier Witness Policy");

    const uint8_t msg[] = "P137_PERSIST_CHECKPOINT";
    uint64_t auth_now = test_cert_now(&cert_res.cert);
    sm2_auth_signature_t sig_refreshed;
    sm2_pki_evidence_bundle_t evidence_refreshed;
    sm2_pki_verify_request_t request_refreshed;
    sm2_pki_epoch_checkpoint_t checkpoint_refreshed;

    TEST_ASSERT(
        sm2_pki_service_refresh_root(service, auth_now + 10) == SM2_PKI_SUCCESS,
        "Refresh Epoch Root");
    TEST_ASSERT(pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1,
                    auth_now + 10, &sig_refreshed, &evidence_refreshed,
                    &request_refreshed),
        "Build Refreshed Request");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    verifier, signer, auth_now + 10, &checkpoint_refreshed),
        "Verifier Imports Refreshed Checkpoint");

    sm2_pki_client_persisted_state_t persisted;
    memset(&persisted, 0, sizeof(persisted));
    TEST_ASSERT(sm2_pki_client_export_persisted_state(verifier, &persisted)
            == SM2_PKI_SUCCESS,
        "Export Persisted State");
    TEST_ASSERT(persisted.record_count == 1, "Persisted Record Count");
    TEST_ASSERT(persisted.records[0].has_checkpoint,
        "Persisted State Carries Checkpoint");

    sm2_pki_client_persisted_state_t tampered = persisted;
    TEST_ASSERT(tampered.records[0].checkpoint.witness_signature_count > 0,
        "Tamper Has Witness Signature");
    tampered.records[0].checkpoint.witness_signatures[0].signature[0] ^= 0x01U;

    TEST_ASSERT(
        sm2_pki_client_create(&restarted, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Restarted Verifier Init");
    TEST_ASSERT(pki_configure_default_transparency_policy(restarted),
        "Restarted Witness Policy");
    TEST_ASSERT(sm2_pki_client_import_persisted_state(
                    restarted, &persisted, auth_now + 10)
            == SM2_PKI_SUCCESS,
        "Import Persisted State");

    size_t matched = 0;
    TEST_ASSERT(
        sm2_pki_verify(restarted, &request_refreshed, auth_now + 10, &matched)
            == SM2_PKI_SUCCESS,
        "Persisted Checkpoint Restores Offline Verify");

    TEST_ASSERT(
        sm2_pki_client_create(&tampered_client, &ca_pub, NULL)
            == SM2_PKI_SUCCESS,
        "Tampered Client Init");
    TEST_ASSERT(pki_configure_default_transparency_policy(tampered_client),
        "Tampered Client Witness Policy");
    TEST_ASSERT(sm2_pki_client_import_persisted_state(
                    tampered_client, &tampered, auth_now + 10)
            == SM2_PKI_ERR_VERIFY,
        "Tampered Persisted Checkpoint Rejects");

    sm2_pki_client_destroy(&tampered_client);
    sm2_pki_client_destroy(&restarted);
    sm2_pki_client_destroy(&verifier);
    sm2_pki_client_destroy(&signer);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase137_offline_checkpoint_export_syncs_peer_state()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P137_OFFLINE_SYNC_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P137_OFFLINE_SYNC_NODE";
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

    sm2_pki_client_ctx_t *signer = NULL;
    sm2_pki_client_ctx_t *receiver = NULL;
    sm2_pki_client_ctx_t *tampered_receiver = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&signer, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");
    TEST_ASSERT(
        sm2_pki_client_create(&receiver, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Receiver Init");
    TEST_ASSERT(pki_configure_default_transparency_policy(receiver),
        "Receiver Witness Policy");

    const uint8_t msg[] = "P137_OFFLINE_CHECKPOINT_SYNC";
    uint64_t auth_now = test_cert_now(&cert_res.cert);
    sm2_auth_signature_t sig_initial;
    sm2_auth_signature_t sig_refreshed;
    sm2_pki_evidence_bundle_t evidence_initial;
    sm2_pki_evidence_bundle_t evidence_refreshed;
    sm2_pki_verify_request_t request_initial;
    sm2_pki_verify_request_t request_refreshed;
    sm2_pki_epoch_checkpoint_t checkpoint_initial;
    sm2_pki_epoch_checkpoint_t exported_checkpoint;

    TEST_ASSERT(
        pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1, auth_now,
            &sig_initial, &evidence_initial, &request_initial),
        "Build Initial Request");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    receiver, signer, auth_now, &checkpoint_initial),
        "Receiver Imports Initial Checkpoint");

    TEST_ASSERT(
        sm2_pki_service_refresh_root(service, auth_now + 10) == SM2_PKI_SUCCESS,
        "Refresh Epoch Root");
    TEST_ASSERT(pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1,
                    auth_now + 10, &sig_refreshed, &evidence_refreshed,
                    &request_refreshed),
        "Build Refreshed Request");

    size_t matched = 0;
    TEST_ASSERT(
        sm2_pki_verify(receiver, &request_refreshed, auth_now + 10, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Receiver Rejects New Evidence Before Sync");

    TEST_ASSERT(
        sm2_pki_client_export_epoch_checkpoint(signer, cert_res.cert.issuer_id,
            cert_res.cert.issuer_id_len, &exported_checkpoint)
            == SM2_PKI_SUCCESS,
        "Signer Exports Cached Checkpoint");
    TEST_ASSERT(sm2_pki_client_import_epoch_checkpoint(
                    receiver, &exported_checkpoint, auth_now + 10)
            == SM2_PKI_SUCCESS,
        "Receiver Imports Offline Checkpoint");
    TEST_ASSERT(
        sm2_pki_verify(receiver, &request_refreshed, auth_now + 10, &matched)
            == SM2_PKI_SUCCESS,
        "Offline Checkpoint Sync Restores Verify");
    TEST_ASSERT(sm2_pki_client_import_epoch_checkpoint(
                    receiver, &checkpoint_initial, auth_now + 10)
            == SM2_PKI_ERR_VERIFY,
        "Receiver Rejects Older Offline Checkpoint");

    sm2_pki_epoch_checkpoint_t tampered = exported_checkpoint;
    TEST_ASSERT(tampered.witness_signature_count > 0,
        "Tampered Checkpoint Has Witness");
    tampered.witness_signatures[0].signature[0] ^= 0x01U;
    TEST_ASSERT(sm2_pki_client_create(&tampered_receiver, &ca_pub, NULL)
            == SM2_PKI_SUCCESS,
        "Tampered Receiver Init");
    TEST_ASSERT(pki_configure_default_transparency_policy(tampered_receiver),
        "Tampered Receiver Witness Policy");
    TEST_ASSERT(sm2_pki_client_import_epoch_checkpoint(
                    tampered_receiver, &tampered, auth_now + 10)
            == SM2_PKI_ERR_VERIFY,
        "Tampered Offline Checkpoint Rejects");

    sm2_pki_client_destroy(&tampered_receiver);
    sm2_pki_client_destroy(&receiver);
    sm2_pki_client_destroy(&signer);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase137_persisted_storage_double_slot_recovery()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P137_STORAGE_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P137_STORAGE_NODE";
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

    sm2_pki_client_ctx_t *signer = NULL;
    sm2_pki_client_ctx_t *verifier = NULL;
    sm2_pki_client_ctx_t *restarted = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&signer, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");
    TEST_ASSERT(
        sm2_pki_client_create(&verifier, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Verifier Init");
    TEST_ASSERT(pki_configure_default_transparency_policy(verifier),
        "Verifier Witness Policy");

    const uint8_t msg[] = "P137_STORAGE_STATE";
    uint64_t auth_now = test_cert_now(&cert_res.cert);
    sm2_auth_signature_t sig_initial;
    sm2_auth_signature_t sig_refreshed;
    sm2_pki_evidence_bundle_t evidence_initial;
    sm2_pki_evidence_bundle_t evidence_refreshed;
    sm2_pki_verify_request_t request_initial;
    sm2_pki_verify_request_t request_refreshed;
    TEST_ASSERT(
        pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1, auth_now,
            &sig_initial, &evidence_initial, &request_initial),
        "Build Initial Request");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    verifier, signer, auth_now, NULL),
        "Verifier Imports Initial Checkpoint");

    sm2_pki_client_persisted_state_t state_initial;
    memset(&state_initial, 0, sizeof(state_initial));
    TEST_ASSERT(sm2_pki_client_export_persisted_state(verifier, &state_initial)
            == SM2_PKI_SUCCESS,
        "Export Initial State");

    sm2_pki_client_persisted_storage_t storage;
    sm2_pki_client_persisted_storage_init(&storage);
    const uint8_t device_secret[] = "P137_STORAGE_DEVICE_SECRET";
    const uint8_t wrong_secret[] = "P137_STORAGE_WRONG_SECRET";
    TEST_ASSERT(sm2_pki_client_persisted_storage_store(&storage, &state_initial,
                    device_secret, sizeof(device_secret) - 1)
            == SM2_PKI_SUCCESS,
        "Store Initial State");

    TEST_ASSERT(
        sm2_pki_service_refresh_root(service, auth_now + 10) == SM2_PKI_SUCCESS,
        "Refresh Epoch Root");
    TEST_ASSERT(pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1,
                    auth_now + 10, &sig_refreshed, &evidence_refreshed,
                    &request_refreshed),
        "Build Refreshed Request");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    verifier, signer, auth_now + 10, NULL),
        "Verifier Imports Refreshed Checkpoint");

    sm2_pki_client_persisted_state_t state_refreshed;
    memset(&state_refreshed, 0, sizeof(state_refreshed));
    TEST_ASSERT(
        sm2_pki_client_export_persisted_state(verifier, &state_refreshed)
            == SM2_PKI_SUCCESS,
        "Export Refreshed State");
    TEST_ASSERT(state_refreshed.records[0].highest_seen_epoch_version
            > state_initial.records[0].highest_seen_epoch_version,
        "Refreshed State Advanced");
    TEST_ASSERT(sm2_pki_client_persisted_storage_store(&storage,
                    &state_refreshed, device_secret, sizeof(device_secret) - 1)
            == SM2_PKI_SUCCESS,
        "Store Refreshed State");

    sm2_pki_client_persisted_state_t loaded;
    memset(&loaded, 0, sizeof(loaded));
    uint64_t selected_sequence = 0;
    TEST_ASSERT(
        sm2_pki_client_persisted_storage_load(&storage, &loaded, device_secret,
            sizeof(device_secret) - 1, &selected_sequence)
            == SM2_PKI_SUCCESS,
        "Load Latest State");
    TEST_ASSERT(selected_sequence == 2, "Latest Sequence Selected");
    TEST_ASSERT(loaded.records[0].highest_seen_epoch_version
            == state_refreshed.records[0].highest_seen_epoch_version,
        "Loaded Refreshed State");

    TEST_ASSERT(
        sm2_pki_client_create(&restarted, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Restarted Verifier Init");
    TEST_ASSERT(pki_configure_default_transparency_policy(restarted),
        "Restarted Witness Policy");
    TEST_ASSERT(
        sm2_pki_client_import_persisted_state(restarted, &loaded, auth_now + 10)
            == SM2_PKI_SUCCESS,
        "Import Loaded State");
    size_t matched = 0;
    TEST_ASSERT(
        sm2_pki_verify(restarted, &request_refreshed, auth_now + 10, &matched)
            == SM2_PKI_SUCCESS,
        "Loaded State Restores Verify");

    size_t latest_slot
        = storage.slots[0].sequence > storage.slots[1].sequence ? 0U : 1U;
    size_t older_slot = latest_slot == 0U ? 1U : 0U;
    storage.slots[latest_slot].state.records[0].epoch_digest[0] ^= 0x40U;
    memset(&loaded, 0, sizeof(loaded));
    selected_sequence = 0;
    TEST_ASSERT(
        sm2_pki_client_persisted_storage_load(&storage, &loaded, device_secret,
            sizeof(device_secret) - 1, &selected_sequence)
            == SM2_PKI_SUCCESS,
        "Load Falls Back From Tampered Latest Slot");
    TEST_ASSERT(selected_sequence == 1, "Fallback Sequence Selected");
    TEST_ASSERT(loaded.records[0].highest_seen_epoch_version
            == state_initial.records[0].highest_seen_epoch_version,
        "Fallback Loaded Initial State");

    TEST_ASSERT(sm2_pki_client_persisted_storage_load(&storage, &loaded,
                    wrong_secret, sizeof(wrong_secret) - 1, NULL)
            == SM2_PKI_ERR_NOT_FOUND,
        "Wrong Device Secret Rejects Storage");
    storage.slots[older_slot].tag[0] ^= 0x01U;
    TEST_ASSERT(sm2_pki_client_persisted_storage_load(&storage, &loaded,
                    device_secret, sizeof(device_secret) - 1, NULL)
            == SM2_PKI_ERR_NOT_FOUND,
        "All Invalid Slots Reject");

    sm2_pki_client_destroy(&restarted);
    sm2_pki_client_destroy(&verifier);
    sm2_pki_client_destroy(&signer);
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
    TEST_ASSERT(sm2_pki_identity_register(service, aux_id, sizeof(aux_id) - 1,
                    SM2_KU_DIGITAL_SIGNATURE)
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
    TEST_ASSERT(test_pki_issue_cert(service, &req_signer, &cert_signer)
            == SM2_PKI_SUCCESS,
        "Signer Issue");
    TEST_ASSERT(pki_issue_identity_cert(service, aux_id, sizeof(aux_id) - 1,
                    SM2_KU_DIGITAL_SIGNATURE, &cert_aux, &temp_aux),
        "Aux Issue");
    uint64_t auth_now = test_cert_now(&cert_signer.cert);

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *signer = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&signer, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer, &cert_signer, &temp_signer, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");

    const uint8_t msg[] = "P138_TRACK_ROOT";
    sm2_auth_signature_t sig;
    sm2_pki_evidence_bundle_t evidence;
    sm2_pki_verify_request_t request;
    sm2_pki_epoch_checkpoint_t checkpoint_initial;
    sm2_pki_epoch_checkpoint_t checkpoint_updated;
    TEST_ASSERT(pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1,
                    auth_now, &sig, &evidence, &request),
        "Build Initial Evidence Request");

    sm2_pki_client_ctx_t *verifier = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&verifier, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Verifier Init");
    TEST_ASSERT(pki_configure_default_transparency_policy(verifier),
        "Verifier Witness Policy");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    verifier, signer, auth_now, &checkpoint_initial),
        "Verifier Imports Initial Checkpoint");

    size_t matched = 0;
    TEST_ASSERT(sm2_pki_verify(verifier, &request, auth_now, &matched)
            == SM2_PKI_SUCCESS,
        "Initial Verify Imports Epoch");
    uint64_t initial_version
        = checkpoint_initial.epoch_root_record.revocation_root_version;

    TEST_ASSERT(sm2_pki_service_revoke(
                    service, cert_aux.cert.serial_number, auth_now + 10)
            == SM2_PKI_SUCCESS,
        "Revoke Aux Cert");

    TEST_ASSERT(pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1,
                    auth_now + 20, &sig, &evidence, &request),
        "Build Updated Evidence Request");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    verifier, signer, auth_now + 20, &checkpoint_updated),
        "Verifier Imports Updated Checkpoint");
    TEST_ASSERT(sm2_pki_verify(verifier, &request, auth_now + 20, &matched)
            == SM2_PKI_SUCCESS,
        "Verify With Updated Epoch");
    TEST_ASSERT(
        checkpoint_updated.epoch_root_record.revocation_root_version
            > initial_version,
        "Epoch Revocation Root Advanced");

    sm2_pki_client_destroy(&verifier);
    sm2_pki_client_destroy(&signer);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase140_epoch_bundle_requires_matching_checkpoint()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P140_EPOCH_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t signer_id[] = "P140_SIGNER";
    const uint8_t aux_id[] = "P140_AUX";
    TEST_ASSERT(sm2_pki_identity_register(service, signer_id,
                    sizeof(signer_id) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Signer Register");
    TEST_ASSERT(sm2_pki_identity_register(service, aux_id, sizeof(aux_id) - 1,
                    SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Aux Register");

    sm2_ic_cert_request_t req_signer;
    sm2_private_key_t temp_signer;
    sm2_private_key_t temp_aux;
    sm2_ic_cert_result_t cert_signer;
    sm2_ic_cert_result_t cert_aux;
    TEST_ASSERT(pki_create_and_authorize_request(service, signer_id,
                    sizeof(signer_id) - 1, SM2_KU_DIGITAL_SIGNATURE,
                    &req_signer, &temp_signer),
        "Signer Request");
    TEST_ASSERT(test_pki_issue_cert(service, &req_signer, &cert_signer)
            == SM2_PKI_SUCCESS,
        "Signer Issue");
    TEST_ASSERT(pki_issue_identity_cert(service, aux_id, sizeof(aux_id) - 1,
                    SM2_KU_DIGITAL_SIGNATURE, &cert_aux, &temp_aux),
        "Aux Issue");

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *signer = NULL;
    sm2_pki_client_ctx_t *verifier = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&signer, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_create(&verifier, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Verifier Init");
    TEST_ASSERT(pki_configure_default_transparency_policy(verifier),
        "Verifier Witness Policy");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer, &cert_signer, &temp_signer, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");

    const uint8_t msg[] = "P140_EPOCH_BUNDLE";
    uint64_t auth_now = test_cert_now(&cert_signer.cert);
    sm2_auth_signature_t sig_initial;
    sm2_auth_signature_t sig_updated;
    sm2_pki_evidence_bundle_t evidence_initial;
    sm2_pki_evidence_bundle_t evidence_updated;
    sm2_pki_verify_request_t request_initial;
    sm2_pki_verify_request_t request_updated;
    size_t matched = 0;

    TEST_ASSERT(
        pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1, auth_now,
            &sig_initial, &evidence_initial, &request_initial),
        "Build Initial Evidence");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    verifier, signer, auth_now, NULL),
        "Verifier Imports Initial Checkpoint");
    TEST_ASSERT(sm2_pki_verify(verifier, &request_initial, auth_now, &matched)
            == SM2_PKI_SUCCESS,
        "Verify Initial Evidence");
    TEST_ASSERT(pki_client_evidence_cache_count(verifier) == 1,
        "Initial Evidence Cached");
    TEST_ASSERT(sm2_pki_verify(verifier, &request_initial, auth_now, &matched)
            == SM2_PKI_SUCCESS,
        "Replay Same Evidence Uses Bound Cache");
    TEST_ASSERT(pki_client_evidence_cache_count(verifier) == 1,
        "Replay Does Not Duplicate Cache");

    sm2_pki_evidence_bundle_t wrong_revocation = evidence_initial;
    wrong_revocation.revocation_proof.absence_proof.target_serial ^= 0x01U;
    sm2_pki_verify_request_t wrong_revocation_req = request_initial;
    wrong_revocation_req.evidence_bundle = &wrong_revocation;
    TEST_ASSERT(
        sm2_pki_verify(verifier, &wrong_revocation_req, auth_now, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Wrong Revocation Proof Reject");

    sm2_pki_evidence_bundle_t wrong_issuance = evidence_initial;
    wrong_issuance.issuance_proof.member_proof.cert_commitment[0] ^= 0x01U;
    sm2_pki_verify_request_t wrong_issuance_req = request_initial;
    wrong_issuance_req.evidence_bundle = &wrong_issuance;
    TEST_ASSERT(
        sm2_pki_verify(verifier, &wrong_issuance_req, auth_now, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Wrong Issuance Proof Reject");

    TEST_ASSERT(sm2_pki_service_revoke(
                    service, cert_aux.cert.serial_number, auth_now + 10)
            == SM2_PKI_SUCCESS,
        "Advance Epoch");
    TEST_ASSERT(
        pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1,
            auth_now + 20, &sig_updated, &evidence_updated, &request_updated),
        "Build Updated Evidence");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    verifier, signer, auth_now + 20, NULL),
        "Verifier Imports Updated Checkpoint");
    TEST_ASSERT(
        sm2_pki_verify(verifier, &request_updated, auth_now + 20, &matched)
            == SM2_PKI_SUCCESS,
        "Verify Updated Evidence");
    TEST_ASSERT(pki_client_evidence_cache_count(verifier) == 2,
        "Updated Evidence Cached Separately");
    TEST_ASSERT(
        sm2_pki_verify(verifier, &request_initial, auth_now + 20, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Stale Epoch Reject");

    sm2_pki_client_destroy(&verifier);
    sm2_pki_client_destroy(&signer);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase141_issuance_transparency_required_and_threshold()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P141_CT_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t signer_id[] = "P141_SIGNER";
    TEST_ASSERT(sm2_pki_identity_register(service, signer_id,
                    sizeof(signer_id) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Signer Register");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    TEST_ASSERT(
        pki_create_and_authorize_request(service, signer_id,
            sizeof(signer_id) - 1, SM2_KU_DIGITAL_SIGNATURE, &req, &temp_priv),
        "Signer Request");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req, &cert_res) == SM2_PKI_SUCCESS,
        "Signer Issue");

    sm2_ec_point_t ca_pub;
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *signer = NULL;
    sm2_pki_client_ctx_t *verifier = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&signer, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_create(&verifier, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Verifier Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer, &cert_res, &temp_priv, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");

    const uint8_t msg[] = "P141_TRANSPARENCY";
    uint64_t auth_now = test_cert_now(&cert_res.cert);
    sm2_auth_signature_t sig;
    sm2_pki_evidence_bundle_t rev_evidence;
    sm2_pki_verify_request_t request;
    memset(&sig, 0, sizeof(sig));
    memset(&rev_evidence, 0, sizeof(rev_evidence));
    memset(&request, 0, sizeof(request));

    TEST_ASSERT(pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1,
                    auth_now, &sig, &rev_evidence, &request),
        "Build Verify Request");

    size_t matched = 0;
    sm2_pki_verify_request_t missing_bundle = request;
    missing_bundle.evidence_bundle = NULL;
    TEST_ASSERT(sm2_pki_verify(verifier, &missing_bundle, auth_now, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Missing Mandatory Epoch Bundle Reject");

    TEST_ASSERT(sm2_pki_verify(verifier, &request, auth_now, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Missing Verifier Witness Policy Reject");
    TEST_ASSERT(sm2_pki_client_set_transparency_policy(verifier, NULL)
            == SM2_PKI_ERR_PARAM,
        "Null Witness Policy Reject");
    sm2_pki_transparency_policy_t zero_policy
        = { &g_pki_default_witness, 1, 0 };
    TEST_ASSERT(sm2_pki_client_set_transparency_policy(verifier, &zero_policy)
            == SM2_PKI_ERR_PARAM,
        "Zero Witness Threshold Reject");
    TEST_ASSERT(pki_configure_default_transparency_policy(verifier),
        "Configure Default Witness Policy");

    request.evidence_bundle = &rev_evidence;
    TEST_ASSERT(sm2_pki_verify(verifier, &request, auth_now, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Missing Imported Checkpoint Reject");

    sm2_pki_epoch_checkpoint_t default_checkpoint;
    TEST_ASSERT(pki_build_default_epoch_checkpoint(signer, &default_checkpoint),
        "Build Default Checkpoint");
    sm2_pki_epoch_checkpoint_t no_witness = default_checkpoint;
    no_witness.witness_signature_count = 0;
    TEST_ASSERT(sm2_pki_client_import_epoch_checkpoint(
                    verifier, &no_witness, auth_now)
            != SM2_PKI_SUCCESS,
        "Missing Mandatory Witness Signature Reject");

    request.evidence_bundle = &rev_evidence;
    TEST_ASSERT(sm2_pki_client_import_epoch_checkpoint(
                    verifier, &default_checkpoint, auth_now)
            == SM2_PKI_SUCCESS,
        "Verifier Imports Default Checkpoint");
    TEST_ASSERT(sm2_pki_verify(verifier, &request, auth_now, &matched)
            == SM2_PKI_SUCCESS,
        "Epoch Evidence Verify");

    sm2_pki_evidence_bundle_t wrong_commitment = rev_evidence;
    wrong_commitment.issuance_proof.member_proof.cert_commitment[0] ^= 0x01U;
    request.evidence_bundle = &wrong_commitment;
    TEST_ASSERT(sm2_pki_verify(verifier, &request, auth_now, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Wrong Issuance Commitment Reject");
    request.evidence_bundle = &rev_evidence;

    sm2_private_key_t witness_priv[3];
    sm2_ec_point_t witness_pub[3];
    sm2_pki_transparency_witness_t witnesses[3];
    memset(witness_priv, 0, sizeof(witness_priv));
    memset(witness_pub, 0, sizeof(witness_pub));
    memset(witnesses, 0, sizeof(witnesses));
    const uint8_t wid0[] = "witness-0";
    const uint8_t wid1[] = "witness-1";
    const uint8_t wid2[] = "witness-2";
    const uint8_t *wids[] = { wid0, wid1, wid2 };
    const size_t wid_lens[]
        = { sizeof(wid0) - 1, sizeof(wid1) - 1, sizeof(wid2) - 1 };
    for (size_t i = 0; i < 3; i++)
    {
        TEST_ASSERT(
            test_generate_sm2_keypair(&witness_priv[i], &witness_pub[i]),
            "Generate Witness Key");
        memcpy(witnesses[i].witness_id, wids[i], wid_lens[i]);
        witnesses[i].witness_id_len = wid_lens[i];
        witnesses[i].public_key = witness_pub[i];
    }
    sm2_pki_transparency_witness_t duplicate_key_witnesses[2];
    duplicate_key_witnesses[0] = witnesses[0];
    duplicate_key_witnesses[1] = witnesses[1];
    duplicate_key_witnesses[1].public_key = witnesses[0].public_key;
    sm2_pki_transparency_policy_t duplicate_key_policy
        = { duplicate_key_witnesses, 2, 2 };
    TEST_ASSERT(
        sm2_pki_client_set_transparency_policy(verifier, &duplicate_key_policy)
            == SM2_PKI_ERR_PARAM,
        "Duplicate Witness Public Key Reject");
    sm2_pki_transparency_policy_t policy
        = { witnesses, sizeof(witnesses) / sizeof(witnesses[0]), 2 };
    TEST_ASSERT(sm2_pki_client_set_transparency_policy(verifier, &policy)
            == SM2_PKI_SUCCESS,
        "Set Verifier Witness Policy");

    size_t threshold_commitment_count = 0;
    TEST_ASSERT(sm2_pki_service_get_issuance_commitment_count(
                    service, &threshold_commitment_count)
            == SM2_PKI_SUCCESS,
        "Read Issuance Commitment Count");
    sm2_pki_issuance_commitment_t *threshold_commitments
        = (sm2_pki_issuance_commitment_t *)calloc(
            threshold_commitment_count, sizeof(*threshold_commitments));
    TEST_ASSERT(threshold_commitments != NULL, "Alloc Issuance Commitments");
    size_t threshold_exported_count = 0;
    TEST_ASSERT(sm2_pki_service_export_issuance_commitments(service, 0,
                    threshold_commitments, threshold_commitment_count,
                    &threshold_exported_count)
            == SM2_PKI_SUCCESS,
        "Export Issuance Commitments");
    TEST_ASSERT(threshold_exported_count == threshold_commitment_count,
        "Exported Issuance Count");

    sm2_pki_epoch_checkpoint_t one_sig_checkpoint;
    memset(&one_sig_checkpoint, 0, sizeof(one_sig_checkpoint));
    TEST_ASSERT(sm2_pki_service_get_epoch_root_record(
                    service, &one_sig_checkpoint.epoch_root_record)
            == SM2_PKI_SUCCESS,
        "Read Threshold Epoch Root");
    sm2_pki_epoch_witness_state_t witness_state0;
    sm2_pki_epoch_witness_state_init(&witness_state0);
    TEST_ASSERT(sm2_pki_epoch_witness_sign_append_only(&witness_state0,
                    &one_sig_checkpoint.epoch_root_record, &ca_pub,
                    one_sig_checkpoint.epoch_root_record.valid_from,
                    threshold_commitments, threshold_commitment_count, wid0,
                    sizeof(wid0) - 1, &witness_priv[0],
                    &one_sig_checkpoint.witness_signatures[0])
            == SM2_PKI_SUCCESS,
        "Witness Sign 0");
    sm2_pki_epoch_witness_state_cleanup(&witness_state0);
    one_sig_checkpoint.witness_signature_count = 1;
    TEST_ASSERT(sm2_pki_client_import_epoch_checkpoint(
                    verifier, &one_sig_checkpoint, auth_now)
            != SM2_PKI_SUCCESS,
        "One Of Two Checkpoint Import Reject");
    TEST_ASSERT(sm2_pki_verify(verifier, &request, auth_now, &matched)
            == SM2_PKI_ERR_VERIFY,
        "One Of Two Witnesses Reject");

    sm2_pki_epoch_checkpoint_t two_sig_checkpoint = one_sig_checkpoint;
    sm2_pki_epoch_witness_state_t witness_state1;
    sm2_pki_epoch_witness_state_init(&witness_state1);
    TEST_ASSERT(sm2_pki_epoch_witness_sign_append_only(&witness_state1,
                    &two_sig_checkpoint.epoch_root_record, &ca_pub,
                    two_sig_checkpoint.epoch_root_record.valid_from,
                    threshold_commitments, threshold_commitment_count, wid1,
                    sizeof(wid1) - 1, &witness_priv[1],
                    &two_sig_checkpoint.witness_signatures[1])
            == SM2_PKI_SUCCESS,
        "Witness Sign 1");
    sm2_pki_epoch_witness_state_cleanup(&witness_state1);
    two_sig_checkpoint.witness_signature_count = 2;
    TEST_ASSERT(sm2_pki_client_import_epoch_checkpoint(
                    verifier, &two_sig_checkpoint, auth_now)
            == SM2_PKI_SUCCESS,
        "Two Of Three Checkpoint Import Accept");
    TEST_ASSERT(sm2_pki_verify(verifier, &request, auth_now, &matched)
            == SM2_PKI_SUCCESS,
        "Two Of Three Witnesses Accept");

    free(threshold_commitments);
    sm2_pki_client_destroy(&verifier);
    sm2_pki_client_destroy(&signer);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase142_epoch_witness_append_only_and_quorum()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P142_EPOCH_CA";
    const uint8_t id_a[] = "P142_A";
    const uint8_t id_b[] = "P142_B";
    const uint8_t id_c[] = "P142_C";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");
    TEST_ASSERT(sm2_pki_identity_register(
                    service, id_a, sizeof(id_a) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Register A");
    TEST_ASSERT(sm2_pki_identity_register(
                    service, id_b, sizeof(id_b) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Register B");
    TEST_ASSERT(sm2_pki_identity_register(
                    service, id_c, sizeof(id_c) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Register C");

    sm2_ic_cert_result_t cert_a;
    sm2_ic_cert_result_t cert_b;
    sm2_ic_cert_result_t cert_c;
    sm2_private_key_t temp_a;
    sm2_private_key_t temp_b;
    sm2_private_key_t temp_c;
    memset(&cert_a, 0, sizeof(cert_a));
    memset(&cert_b, 0, sizeof(cert_b));
    memset(&cert_c, 0, sizeof(cert_c));
    memset(&temp_a, 0, sizeof(temp_a));
    memset(&temp_b, 0, sizeof(temp_b));
    memset(&temp_c, 0, sizeof(temp_c));
    TEST_ASSERT(pki_issue_identity_cert(service, id_a, sizeof(id_a) - 1,
                    SM2_KU_DIGITAL_SIGNATURE, &cert_a, &temp_a),
        "Issue A");
    TEST_ASSERT(pki_issue_identity_cert(service, id_b, sizeof(id_b) - 1,
                    SM2_KU_DIGITAL_SIGNATURE, &cert_b, &temp_b),
        "Issue B");

    sm2_ec_point_t ca_pub;
    memset(&ca_pub, 0, sizeof(ca_pub));
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_epoch_root_record_t root_ab;
    memset(&root_ab, 0, sizeof(root_ab));
    TEST_ASSERT(sm2_pki_service_get_epoch_root_record(service, &root_ab)
            == SM2_PKI_SUCCESS,
        "Get AB Epoch Root");
    sm2_pki_issuance_commitment_t commitments[4];
    size_t commitment_count = 0;
    TEST_ASSERT(sm2_pki_service_export_issuance_commitments(
                    service, 0, commitments, 4, &commitment_count)
            == SM2_PKI_SUCCESS,
        "Export Initial Commitments");
    TEST_ASSERT(commitment_count == 2, "Initial Commitment Count");

    sm2_private_key_t witness_priv;
    sm2_ec_point_t witness_pub;
    (void)witness_pub;
    TEST_ASSERT(test_generate_sm2_keypair(&witness_priv, &witness_pub),
        "Generate Witness Key");
    const uint8_t witness_id[] = "append-witness";
    sm2_pki_epoch_witness_state_t witness_state;
    sm2_pki_transparency_witness_signature_t witness_sig;
    memset(&witness_sig, 0, sizeof(witness_sig));
    sm2_pki_epoch_witness_state_init(&witness_state);
    TEST_ASSERT(
        sm2_pki_epoch_witness_sign_append_only(&witness_state, &root_ab,
            &ca_pub, base_now, commitments, commitment_count, witness_id,
            sizeof(witness_id) - 1, &witness_priv, &witness_sig)
            == SM2_PKI_SUCCESS,
        "Initial Append-Only Witness Sign");

    sm2_pki_epoch_root_record_t rollback_root = root_ab;
    rollback_root.epoch_version--;
    TEST_ASSERT(sm2_pki_epoch_witness_sign_append_only(&witness_state,
                    &rollback_root, &ca_pub, base_now, NULL, 0, witness_id,
                    sizeof(witness_id) - 1, &witness_priv, &witness_sig)
            == SM2_PKI_ERR_VERIFY,
        "Reject Rollback Epoch");

    TEST_ASSERT(pki_issue_identity_cert(service, id_c, sizeof(id_c) - 1,
                    SM2_KU_DIGITAL_SIGNATURE, &cert_c, &temp_c),
        "Issue C");
    sm2_pki_epoch_root_record_t root_abc;
    memset(&root_abc, 0, sizeof(root_abc));
    TEST_ASSERT(sm2_pki_service_get_epoch_root_record(service, &root_abc)
            == SM2_PKI_SUCCESS,
        "Get ABC Epoch Root");
    size_t append_count = 0;
    TEST_ASSERT(sm2_pki_service_export_issuance_commitments(
                    service, commitment_count, commitments, 4, &append_count)
            == SM2_PKI_SUCCESS,
        "Export Append Commitments");
    TEST_ASSERT(append_count == 1, "Append Commitment Count");

    commitments[0][0] ^= 0x01U;
    TEST_ASSERT(
        sm2_pki_epoch_witness_sign_append_only(&witness_state, &root_abc,
            &ca_pub, base_now, commitments, append_count, witness_id,
            sizeof(witness_id) - 1, &witness_priv, &witness_sig)
            == SM2_PKI_ERR_VERIFY,
        "Reject Tampered Append Batch");
    commitments[0][0] ^= 0x01U;
    TEST_ASSERT(
        sm2_pki_epoch_witness_sign_append_only(&witness_state, &root_abc,
            &ca_pub, base_now, commitments, append_count, witness_id,
            sizeof(witness_id) - 1, &witness_priv, &witness_sig)
            == SM2_PKI_SUCCESS,
        "Accept Append Batch");

    uint8_t digest_ab[SM2_PKI_EPOCH_ROOT_DIGEST_LEN];
    uint8_t digest_abc[SM2_PKI_EPOCH_ROOT_DIGEST_LEN];
    TEST_ASSERT(
        sm2_pki_epoch_root_digest(&root_ab, digest_ab) == SM2_IC_SUCCESS,
        "Digest AB Epoch");
    TEST_ASSERT(
        sm2_pki_epoch_root_digest(&root_abc, digest_abc) == SM2_IC_SUCCESS,
        "Digest ABC Epoch");

    sm2_pki_epoch_root_vote_t votes[3];
    memset(votes, 0, sizeof(votes));
    memcpy(votes[0].node_id, "ea", 2);
    votes[0].node_id_len = 2;
    votes[0].epoch_version = root_abc.epoch_version;
    memcpy(votes[0].epoch_digest, digest_abc, sizeof(votes[0].epoch_digest));
    votes[0].proof_valid = true;
    memcpy(votes[1].node_id, "eb", 2);
    votes[1].node_id_len = 2;
    votes[1].epoch_version = root_abc.epoch_version;
    memcpy(votes[1].epoch_digest, digest_abc, sizeof(votes[1].epoch_digest));
    votes[1].proof_valid = true;
    memcpy(votes[2].node_id, "ec", 2);
    votes[2].node_id_len = 2;
    votes[2].epoch_version = root_abc.epoch_version;
    memcpy(votes[2].epoch_digest, digest_abc, sizeof(votes[2].epoch_digest));
    votes[2].epoch_digest[0] ^= 0x80U;
    votes[2].proof_valid = true;

    sm2_pki_epoch_quorum_result_t quorum;
    TEST_ASSERT(
        sm2_pki_epoch_quorum_check(votes, 3, 2, &quorum) == SM2_PKI_ERR_VERIFY,
        "Quorum Detects Fork");
    TEST_ASSERT(quorum.fork_detected, "Fork Flag Set");

    votes[2].epoch_version = root_ab.epoch_version;
    memcpy(votes[2].epoch_digest, digest_ab, sizeof(votes[2].epoch_digest));
    TEST_ASSERT(
        sm2_pki_epoch_quorum_check(votes, 3, 2, &quorum) == SM2_PKI_SUCCESS,
        "Quorum Accepts Matching Latest Epoch");
    TEST_ASSERT(quorum.quorum_met, "Epoch Quorum Met");
    TEST_ASSERT(quorum.stale_vote_count == 1, "Stale Vote Count");

    sm2_pki_epoch_witness_state_cleanup(&witness_state);
    sm2_pki_service_destroy(&service);
    TEST_PASS();
}
static void test_phase143_epoch_bundle_binds_roots_and_witnesses()
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P143_EPOCH_CA";
    const uint8_t signer_id[] = "P143_SIGNER";
    const uint8_t aux_id[] = "P143_AUX";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 32, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");
    TEST_ASSERT(sm2_pki_identity_register(service, signer_id,
                    sizeof(signer_id) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Signer Register");
    TEST_ASSERT(sm2_pki_identity_register(service, aux_id, sizeof(aux_id) - 1,
                    SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Aux Register");

    sm2_ic_cert_result_t signer_cert;
    sm2_ic_cert_result_t aux_cert;
    sm2_private_key_t signer_temp;
    sm2_private_key_t aux_temp;
    memset(&signer_cert, 0, sizeof(signer_cert));
    memset(&aux_cert, 0, sizeof(aux_cert));
    memset(&signer_temp, 0, sizeof(signer_temp));
    memset(&aux_temp, 0, sizeof(aux_temp));
    TEST_ASSERT(
        pki_issue_identity_cert(service, signer_id, sizeof(signer_id) - 1,
            SM2_KU_DIGITAL_SIGNATURE, &signer_cert, &signer_temp),
        "Issue Signer");

    sm2_ec_point_t ca_pub;
    memset(&ca_pub, 0, sizeof(ca_pub));
    TEST_ASSERT(
        sm2_pki_service_get_ca_public_key(service, &ca_pub) == SM2_PKI_SUCCESS,
        "Get CA Pub");

    sm2_pki_client_ctx_t *signer = NULL;
    sm2_pki_client_ctx_t *verifier = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&signer, &ca_pub, service) == SM2_PKI_SUCCESS,
        "Signer Init");
    TEST_ASSERT(
        sm2_pki_client_create(&verifier, &ca_pub, NULL) == SM2_PKI_SUCCESS,
        "Verifier Init");
    TEST_ASSERT(pki_configure_default_transparency_policy(verifier),
        "Verifier Witness Policy");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer, &signer_cert, &signer_temp, &ca_pub)
            == SM2_PKI_SUCCESS,
        "Signer Import");

    const uint8_t msg[] = "P143_EPOCH_BUNDLE";
    uint64_t auth_now = test_cert_now(&signer_cert.cert);
    sm2_auth_signature_t sig;
    sm2_pki_evidence_bundle_t bundle;
    sm2_pki_verify_request_t request;
    memset(&sig, 0, sizeof(sig));
    memset(&bundle, 0, sizeof(bundle));
    memset(&request, 0, sizeof(request));
    TEST_ASSERT(pki_build_signed_verify_request(signer, msg, sizeof(msg) - 1,
                    auth_now, &sig, &bundle, &request),
        "Build Epoch Verify Request");

    size_t matched = 0;
    sm2_pki_epoch_checkpoint_t checkpoint;
    TEST_ASSERT(pki_build_default_epoch_checkpoint(signer, &checkpoint),
        "Build Epoch Checkpoint");
    sm2_pki_epoch_checkpoint_t missing_witness = checkpoint;
    missing_witness.witness_signature_count = 0;
    TEST_ASSERT(sm2_pki_client_import_epoch_checkpoint(
                    verifier, &missing_witness, auth_now)
            != SM2_PKI_SUCCESS,
        "Epoch Missing Witness Reject");
    TEST_ASSERT(sm2_pki_client_import_epoch_checkpoint(
                    verifier, &checkpoint, auth_now)
            == SM2_PKI_SUCCESS,
        "Verifier Imports Epoch Checkpoint");
    TEST_ASSERT(sm2_pki_verify(verifier, &request, auth_now, &matched)
            == SM2_PKI_SUCCESS,
        "Epoch Bundle Verify");

    sm2_pki_evidence_bundle_t wrong_rev_hint = bundle;
    wrong_rev_hint.revocation_proof.absence_proof.target_serial ^= 0x01U;
    request.evidence_bundle = &wrong_rev_hint;
    TEST_ASSERT(sm2_pki_verify(verifier, &request, auth_now, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Epoch Revocation Root Binding Reject");

    sm2_pki_evidence_bundle_t wrong_issuance = bundle;
    wrong_issuance.issuance_proof.member_proof.cert_commitment[0] ^= 0x01U;
    request.evidence_bundle = &wrong_issuance;
    TEST_ASSERT(sm2_pki_verify(verifier, &request, auth_now, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Epoch Issuance Proof Binding Reject");
    request.evidence_bundle = &bundle;

    sm2_private_key_t witness_priv;
    sm2_ec_point_t witness_pub;
    (void)witness_pub;
    TEST_ASSERT(test_generate_sm2_keypair(&witness_priv, &witness_pub),
        "Generate Epoch Witness Key");
    const uint8_t witness_id[] = "epoch-append-witness";
    sm2_pki_epoch_witness_state_t witness_state;
    sm2_pki_transparency_witness_signature_t witness_sig;
    memset(&witness_sig, 0, sizeof(witness_sig));
    sm2_pki_epoch_witness_state_init(&witness_state);

    sm2_pki_epoch_root_record_t epoch_root;
    memset(&epoch_root, 0, sizeof(epoch_root));
    TEST_ASSERT(sm2_pki_service_get_epoch_root_record(service, &epoch_root)
            == SM2_PKI_SUCCESS,
        "Get Initial Epoch Root");
    sm2_pki_issuance_commitment_t commitments[8];
    size_t commitment_count = 0;
    TEST_ASSERT(sm2_pki_service_export_issuance_commitments(
                    service, 0, commitments, 8, &commitment_count)
            == SM2_PKI_SUCCESS,
        "Export Initial Epoch Commitments");
    TEST_ASSERT(
        sm2_pki_epoch_witness_sign_append_only(&witness_state, &epoch_root,
            &ca_pub, auth_now, commitments, commitment_count, witness_id,
            sizeof(witness_id) - 1, &witness_priv, &witness_sig)
            == SM2_PKI_SUCCESS,
        "Epoch Witness Initial Sign");

    TEST_ASSERT(pki_issue_identity_cert(service, aux_id, sizeof(aux_id) - 1,
                    SM2_KU_DIGITAL_SIGNATURE, &aux_cert, &aux_temp),
        "Issue Aux");
    sm2_pki_epoch_root_record_t appended_epoch;
    memset(&appended_epoch, 0, sizeof(appended_epoch));
    TEST_ASSERT(sm2_pki_service_get_epoch_root_record(service, &appended_epoch)
            == SM2_PKI_SUCCESS,
        "Get Appended Epoch Root");
    size_t append_count = 0;
    TEST_ASSERT(sm2_pki_service_export_issuance_commitments(
                    service, commitment_count, commitments, 8, &append_count)
            == SM2_PKI_SUCCESS,
        "Export Epoch Append Commitments");
    TEST_ASSERT(append_count == 1, "Epoch Append Commitment Count");
    commitments[0][0] ^= 0x01U;
    TEST_ASSERT(
        sm2_pki_epoch_witness_sign_append_only(&witness_state, &appended_epoch,
            &ca_pub, auth_now, commitments, append_count, witness_id,
            sizeof(witness_id) - 1, &witness_priv, &witness_sig)
            == SM2_PKI_ERR_VERIFY,
        "Epoch Witness Rejects Tampered Append");
    commitments[0][0] ^= 0x01U;
    TEST_ASSERT(
        sm2_pki_epoch_witness_sign_append_only(&witness_state, &appended_epoch,
            &ca_pub, auth_now, commitments, append_count, witness_id,
            sizeof(witness_id) - 1, &witness_priv, &witness_sig)
            == SM2_PKI_SUCCESS,
        "Epoch Witness Accepts Append");

    TEST_ASSERT(sm2_pki_service_revoke(
                    service, aux_cert.cert.serial_number, auth_now + 10)
            == SM2_PKI_SUCCESS,
        "Advance Revocation Root");
    sm2_pki_epoch_root_record_t rev_only_epoch;
    memset(&rev_only_epoch, 0, sizeof(rev_only_epoch));
    TEST_ASSERT(sm2_pki_service_get_epoch_root_record(service, &rev_only_epoch)
            == SM2_PKI_SUCCESS,
        "Get Rev-Only Epoch Root");
    TEST_ASSERT(
        sm2_pki_epoch_witness_sign_append_only(&witness_state, &rev_only_epoch,
            &ca_pub, auth_now + 10, NULL, 0, witness_id, sizeof(witness_id) - 1,
            &witness_priv, &witness_sig)
            == SM2_PKI_SUCCESS,
        "Epoch Witness Accepts Rev-Only Advance");

    sm2_pki_epoch_witness_state_cleanup(&witness_state);
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
    const uint8_t identity_a_live[] = "P139_NODE_A_LIVE";
    const uint8_t identity_b[] = "P139_NODE_B";
    TEST_ASSERT(sm2_pki_identity_register(service_a, identity_a,
                    sizeof(identity_a) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity A Register");
    TEST_ASSERT(sm2_pki_identity_register(service_a, identity_a_live,
                    sizeof(identity_a_live) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity A Live Register");
    TEST_ASSERT(sm2_pki_identity_register(service_b, identity_b,
                    sizeof(identity_b) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity B Register");

    sm2_ic_cert_request_t req_a;
    sm2_ic_cert_request_t req_a_live;
    sm2_ic_cert_request_t req_b;
    sm2_private_key_t temp_a;
    sm2_private_key_t temp_a_live;
    sm2_private_key_t temp_b;
    sm2_ic_cert_result_t cert_a;
    sm2_ic_cert_result_t cert_a_live;
    sm2_ic_cert_result_t cert_b;
    TEST_ASSERT(
        pki_create_and_authorize_request(service_a, identity_a,
            sizeof(identity_a) - 1, SM2_KU_DIGITAL_SIGNATURE, &req_a, &temp_a),
        "Request A");
    TEST_ASSERT(
        test_pki_issue_cert(service_a, &req_a, &cert_a) == SM2_PKI_SUCCESS,
        "Issue A");
    TEST_ASSERT(pki_create_and_authorize_request(service_a, identity_a_live,
                    sizeof(identity_a_live) - 1, SM2_KU_DIGITAL_SIGNATURE,
                    &req_a_live, &temp_a_live),
        "Request A Live");
    TEST_ASSERT(test_pki_issue_cert(service_a, &req_a_live, &cert_a_live)
            == SM2_PKI_SUCCESS,
        "Issue A Live");
    TEST_ASSERT(
        pki_create_and_authorize_request(service_b, identity_b,
            sizeof(identity_b) - 1, SM2_KU_DIGITAL_SIGNATURE, &req_b, &temp_b),
        "Request B");
    TEST_ASSERT(
        test_pki_issue_cert(service_b, &req_b, &cert_b) == SM2_PKI_SUCCESS,
        "Issue B");

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
    TEST_ASSERT(pki_configure_default_transparency_policy(client),
        "Client Witness Policy");
    TEST_ASSERT(
        sm2_pki_client_add_trusted_ca(client, &ca_pub_b) == SM2_PKI_SUCCESS,
        "Add CA B");

    sm2_pki_client_ctx_t *signer_a = NULL;
    sm2_pki_client_ctx_t *signer_b = NULL;
    sm2_auth_signature_t sig_a;
    sm2_auth_signature_t sig_b;
    sm2_pki_evidence_bundle_t evidence_a;
    sm2_pki_evidence_bundle_t evidence_b;
    sm2_pki_verify_request_t request_a;
    sm2_pki_verify_request_t request_b;
    sm2_pki_epoch_checkpoint_t checkpoint_a;
    sm2_pki_epoch_checkpoint_t checkpoint_b;
    sm2_pki_epoch_checkpoint_t checkpoint_a_new;
    const uint8_t msg_a[] = "P139_PIN_A";
    const uint8_t msg_b[] = "P139_PIN_B";
    uint64_t auth_now_a = test_cert_now(&cert_a_live.cert);
    uint64_t auth_now_b = test_cert_now(&cert_b.cert);

    TEST_ASSERT(sm2_pki_client_create(&signer_a, &ca_pub_a, service_a)
            == SM2_PKI_SUCCESS,
        "Signer A Init");
    TEST_ASSERT(sm2_pki_client_import_cert(
                    signer_a, &cert_a_live, &temp_a_live, &ca_pub_a)
            == SM2_PKI_SUCCESS,
        "Signer A Import");
    TEST_ASSERT(sm2_pki_client_create(&signer_b, &ca_pub_b, service_b)
            == SM2_PKI_SUCCESS,
        "Signer B Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer_b, &cert_b, &temp_b, &ca_pub_b)
            == SM2_PKI_SUCCESS,
        "Signer B Import");
    TEST_ASSERT(
        pki_build_signed_verify_request(signer_a, msg_a, sizeof(msg_a) - 1,
            auth_now_a, &sig_a, &evidence_a, &request_a),
        "Build Pin A Request");
    TEST_ASSERT(
        pki_build_signed_verify_request(signer_b, msg_b, sizeof(msg_b) - 1,
            auth_now_b, &sig_b, &evidence_b, &request_b),
        "Build Pin B Request");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    client, signer_a, auth_now_a, &checkpoint_a),
        "Client Imports Authority A Checkpoint");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    client, signer_b, auth_now_b, &checkpoint_b),
        "Client Imports Authority B Checkpoint");

    size_t matched = 0;
    TEST_ASSERT(sm2_pki_verify(client, &request_a, auth_now_a, &matched)
            == SM2_PKI_SUCCESS,
        "Pin Authority A");
    TEST_ASSERT(sm2_pki_verify(client, &request_b, auth_now_b, &matched)
            == SM2_PKI_SUCCESS,
        "Pin Authority B");

    TEST_ASSERT(sm2_pki_service_revoke(
                    service_a, cert_a.cert.serial_number, base_now + 10)
            == SM2_PKI_SUCCESS,
        "Revoke A");

    sm2_auth_signature_t sig_a_new;
    sm2_pki_evidence_bundle_t evidence_a_new;
    sm2_pki_verify_request_t request_a_new;
    TEST_ASSERT(
        pki_build_signed_verify_request(signer_a, msg_a, sizeof(msg_a) - 1,
            base_now + 20, &sig_a_new, &evidence_a_new, &request_a_new),
        "Build Advanced A Request");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    client, signer_a, base_now + 20, &checkpoint_a_new),
        "Client Imports Advanced A Checkpoint");
    TEST_ASSERT(checkpoint_a_new.epoch_root_record.revocation_root_version
            > checkpoint_b.epoch_root_record.revocation_root_version,
        "Authority A Version Higher Than B");
    TEST_ASSERT(sm2_pki_verify(client, &request_a_new, base_now + 20, &matched)
            == SM2_PKI_SUCCESS,
        "Verify Advanced A");
    TEST_ASSERT(sm2_pki_verify(client, &request_b, auth_now_b, &matched)
            == SM2_PKI_SUCCESS,
        "Authority B Lower Version Still Accepted");
    TEST_ASSERT(sm2_pki_verify(client, &request_a, base_now + 20, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Authority A Stale Epoch Reject");

    sm2_pki_client_destroy(&signer_b);
    sm2_pki_client_destroy(&signer_a);
    sm2_pki_client_destroy(&client);
    sm2_pki_service_destroy(&service_b);
    sm2_pki_service_destroy(&service_a);
    TEST_PASS();
}

static void test_phase139_multi_ca_epoch_rejects_spoofed_authority()
{
    sm2_pki_service_ctx_t *service_a = NULL;
    sm2_pki_service_ctx_t *service_b = NULL;
    const uint8_t authority[] = "P139_SPOOF_AUTH";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(&service_a, authority,
                    sizeof(authority) - 1, 16, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service A Init");
    TEST_ASSERT(sm2_pki_service_create(&service_b, authority,
                    sizeof(authority) - 1, 16, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service B Init");

    const uint8_t identity_a[] = "P139_SPOOF_A";
    const uint8_t identity_b[] = "P139_SPOOF_B";
    TEST_ASSERT(sm2_pki_identity_register(service_a, identity_a,
                    sizeof(identity_a) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity A Register");
    TEST_ASSERT(sm2_pki_identity_register(service_b, identity_b,
                    sizeof(identity_b) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity B Register");

    sm2_ic_cert_result_t cert_a;
    sm2_ic_cert_result_t cert_b;
    sm2_private_key_t temp_a;
    sm2_private_key_t temp_b;
    TEST_ASSERT(
        pki_issue_identity_cert(service_a, identity_a, sizeof(identity_a) - 1,
            SM2_KU_DIGITAL_SIGNATURE, &cert_a, &temp_a),
        "Issue A");
    TEST_ASSERT(
        pki_issue_identity_cert(service_b, identity_b, sizeof(identity_b) - 1,
            SM2_KU_DIGITAL_SIGNATURE, &cert_b, &temp_b),
        "Issue B");

    sm2_ec_point_t ca_pub_a;
    sm2_ec_point_t ca_pub_b;
    TEST_ASSERT(sm2_pki_service_get_ca_public_key(service_a, &ca_pub_a)
            == SM2_PKI_SUCCESS,
        "Get CA A");
    TEST_ASSERT(sm2_pki_service_get_ca_public_key(service_b, &ca_pub_b)
            == SM2_PKI_SUCCESS,
        "Get CA B");

    sm2_pki_client_ctx_t *client = NULL;
    sm2_pki_client_ctx_t *signer_a = NULL;
    sm2_pki_client_ctx_t *signer_b = NULL;
    TEST_ASSERT(
        sm2_pki_client_create(&client, &ca_pub_a, NULL) == SM2_PKI_SUCCESS,
        "Client Init");
    TEST_ASSERT(pki_configure_default_transparency_policy(client),
        "Client Witness Policy");
    TEST_ASSERT(
        sm2_pki_client_add_trusted_ca(client, &ca_pub_b) == SM2_PKI_SUCCESS,
        "Add CA B");
    TEST_ASSERT(sm2_pki_client_create(&signer_a, &ca_pub_a, service_a)
            == SM2_PKI_SUCCESS,
        "Signer A Init");
    TEST_ASSERT(sm2_pki_client_create(&signer_b, &ca_pub_b, service_b)
            == SM2_PKI_SUCCESS,
        "Signer B Init");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer_a, &cert_a, &temp_a, &ca_pub_a)
            == SM2_PKI_SUCCESS,
        "Signer A Import");
    TEST_ASSERT(
        sm2_pki_client_import_cert(signer_b, &cert_b, &temp_b, &ca_pub_b)
            == SM2_PKI_SUCCESS,
        "Signer B Import");

    const uint8_t msg_a[] = "P139_SPOOF_PIN_A";
    const uint8_t msg_b[] = "P139_SPOOF_PIN_B";
    uint64_t auth_now = test_cert_pair_now(&cert_a.cert, &cert_b.cert);
    sm2_auth_signature_t sig_a;
    sm2_auth_signature_t sig_b;
    sm2_pki_evidence_bundle_t evidence_a;
    sm2_pki_evidence_bundle_t evidence_b;
    sm2_pki_verify_request_t request_a;
    sm2_pki_verify_request_t request_b;
    TEST_ASSERT(
        pki_build_signed_verify_request(signer_a, msg_a, sizeof(msg_a) - 1,
            auth_now, &sig_a, &evidence_a, &request_a),
        "Build A Request");
    TEST_ASSERT(
        pki_build_signed_verify_request(signer_b, msg_b, sizeof(msg_b) - 1,
            auth_now, &sig_b, &evidence_b, &request_b),
        "Build B Request");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    client, signer_a, auth_now, NULL),
        "Client Imports Authority A Checkpoint");
    TEST_ASSERT(pki_import_epoch_checkpoint_from_signer(
                    client, signer_b, auth_now, NULL)
            == 0,
        "Same Authority From CA B Checkpoint Reject");

    size_t matched = 0;
    TEST_ASSERT(sm2_pki_verify(client, &request_a, auth_now, &matched)
            == SM2_PKI_SUCCESS,
        "Pin Authority To CA A");
    TEST_ASSERT(sm2_pki_verify(client, &request_b, auth_now, &matched)
            == SM2_PKI_ERR_VERIFY,
        "Same Authority From CA B Reject");

    sm2_pki_client_destroy(&signer_b);
    sm2_pki_client_destroy(&signer_a);
    sm2_pki_client_destroy(&client);
    sm2_pki_service_destroy(&service_b);
    sm2_pki_service_destroy(&service_a);
    TEST_PASS();
}
