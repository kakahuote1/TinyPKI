/* SPDX-License-Identifier: Apache-2.0 */

#include "test_common.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include "../src/pki/pki_internal.h"

static int pki_internal_create_and_authorize_request(
    sm2_pki_service_ctx_t *service, const uint8_t *identity,
    size_t identity_len, uint8_t key_usage, sm2_ic_cert_request_t *request,
    sm2_private_key_t *temp_private_key)
{
    if (sm2_ic_create_cert_request(
            request, identity, identity_len, key_usage, temp_private_key)
        != SM2_IC_SUCCESS)
    {
        return 0;
    }

    return sm2_pki_cert_authorize_request(service, request) == SM2_PKI_SUCCESS;
}

static void test_phase7_service_ca_key_range_check(void)
{
    for (size_t i = 0; i < 16; i++)
    {
        sm2_pki_service_ctx_t *service = NULL;
        const uint8_t issuer[] = "P7_CA";
        TEST_ASSERT(sm2_pki_service_create(&service, issuer, sizeof(issuer) - 1,
                        16, 300, (uint64_t)(5000 + i))
                == SM2_PKI_SUCCESS,
            "Service Init");

        TEST_ASSERT(sm2_pki_service_validate_ca_key_material(service)
                == SM2_PKI_SUCCESS,
            "CA Key Material In Range");

        EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
        BIGNUM *order = BN_new();
        BIGNUM *max_valid = BN_new();
        TEST_ASSERT(group && order && max_valid, "CA Key Range Alloc");
        TEST_ASSERT(EC_GROUP_get_order(group, order, NULL) == 1,
            "CA Key Range Read Order");
        TEST_ASSERT(BN_copy(max_valid, order) != NULL, "CA Key Range Copy");
        TEST_ASSERT(BN_sub_word(max_valid, 1) == 1, "CA Key Range NMinusOne");
        TEST_ASSERT(BN_bn2binpad(max_valid, service->ca_private_key.d,
                        sizeof(service->ca_private_key.d))
                == SM2_KEY_LEN,
            "CA Key Range Write Max Valid");
        TEST_ASSERT(sm2_pki_service_validate_ca_key_material(service)
                == SM2_PKI_SUCCESS,
            "CA Key Range Accept NMinusOne");

        TEST_ASSERT(BN_bn2binpad(order, service->ca_private_key.d,
                        sizeof(service->ca_private_key.d))
                == SM2_KEY_LEN,
            "CA Key Range Write Order");
        TEST_ASSERT(sm2_pki_service_validate_ca_key_material(service)
                == SM2_PKI_ERR_VERIFY,
            "CA Key Range Reject Order");

        BN_free(max_valid);
        BN_free(order);
        EC_GROUP_free(group);
        sm2_pki_service_destroy(&service);
    }
    TEST_PASS();
}

static void test_phase134_service_revoke_failure_rolls_back_state(void)
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P134_ROLLBACK_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 16, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity[] = "P134_ROLLBACK_NODE";
    TEST_ASSERT(sm2_pki_identity_register(service, identity,
                    sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity Register");

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    TEST_ASSERT(
        pki_internal_create_and_authorize_request(service, identity,
            sizeof(identity) - 1, SM2_KU_DIGITAL_SIGNATURE, &req, &temp_priv),
        "Create Request");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req, &cert_res) == SM2_PKI_SUCCESS,
        "Issue Cert");

    sm2_rev_status_t status = SM2_REV_STATUS_UNKNOWN;
    sm2_rev_source_t source = SM2_REV_SOURCE_NONE;
    uint64_t auth_now = test_cert_now(&cert_res.cert);
    TEST_ASSERT(sm2_pki_service_check_revocation(service,
                    cert_res.cert.serial_number, auth_now, &status, &source)
            == SM2_PKI_SUCCESS,
        "Initial Revocation Check");
    TEST_ASSERT(status == SM2_REV_STATUS_GOOD, "Initial Status Good");

    sm2_private_key_t saved_ca_key = service->ca_private_key;
    memset(service->ca_private_key.d, 0, sizeof(service->ca_private_key.d));

    TEST_ASSERT(sm2_pki_service_revoke(
                    service, cert_res.cert.serial_number, auth_now + 10)
            != SM2_PKI_SUCCESS,
        "Revoke With Broken CA Key Reject");
    TEST_ASSERT(
        sm2_pki_service_check_revocation(service, cert_res.cert.serial_number,
            auth_now + 11, &status, &source)
            == SM2_PKI_SUCCESS,
        "Check After Failed Revoke");
    TEST_ASSERT(status == SM2_REV_STATUS_GOOD,
        "Failed Revoke Must Preserve Published State");

    service->ca_private_key = saved_ca_key;
    TEST_ASSERT(
        sm2_pki_service_refresh_root(service, auth_now + 20) == SM2_PKI_SUCCESS,
        "Refresh Root After CA Restore");
    TEST_ASSERT(
        sm2_pki_service_check_revocation(service, cert_res.cert.serial_number,
            auth_now + 21, &status, &source)
            == SM2_PKI_SUCCESS,
        "Check After Refresh");
    TEST_ASSERT(status == SM2_REV_STATUS_GOOD,
        "Failed Revoke Must Not Leak Into Later Refresh");

    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase135_service_issue_failure_rolls_back_state(void)
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P135_ISSUE_ROLLBACK_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 16, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    const uint8_t identity_a[] = "P135_NODE_A";
    TEST_ASSERT(sm2_pki_identity_register(service, identity_a,
                    sizeof(identity_a) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity A Register");

    sm2_ic_cert_request_t req_a;
    sm2_private_key_t temp_priv_a;
    sm2_ic_cert_result_t cert_a;
    TEST_ASSERT(pki_internal_create_and_authorize_request(service, identity_a,
                    sizeof(identity_a) - 1, SM2_KU_DIGITAL_SIGNATURE, &req_a,
                    &temp_priv_a),
        "Create Request A");
    TEST_ASSERT(
        test_pki_issue_cert(service, &req_a, &cert_a) == SM2_PKI_SUCCESS,
        "Issue Cert A");

    size_t issued_count_before = service->issued_count;
    size_t cert_count_before = service->cert_count;
    sm2_rev_root_record_t issuance_before = service->issuance_root_record;
    sm2_pki_epoch_root_record_t epoch_before = service->epoch_root_record;

    const uint8_t identity_b[] = "P135_NODE_B";
    TEST_ASSERT(sm2_pki_identity_register(service, identity_b,
                    sizeof(identity_b) - 1, SM2_KU_DIGITAL_SIGNATURE)
            == SM2_PKI_SUCCESS,
        "Identity B Register");

    sm2_ic_cert_request_t req_b;
    sm2_private_key_t temp_priv_b;
    TEST_ASSERT(pki_internal_create_and_authorize_request(service, identity_b,
                    sizeof(identity_b) - 1, SM2_KU_DIGITAL_SIGNATURE, &req_b,
                    &temp_priv_b),
        "Create Request B");

    uint64_t issue_now = test_cert_now(&cert_a.cert) + 20U;
    service->rev_root_record.valid_until = issue_now - 1U;

    sm2_ic_cert_result_t failed_cert;
    memset(&failed_cert, 0xA5, sizeof(failed_cert));
    TEST_ASSERT(sm2_pki_cert_issue(service, &req_b, issue_now, &failed_cert)
            != SM2_PKI_SUCCESS,
        "Issue With Stale Revocation Root Reject");

    TEST_ASSERT(service->issued_count == issued_count_before,
        "Issued Count Rolled Back");
    TEST_ASSERT(
        service->cert_count == cert_count_before, "Cert Count Rolled Back");
    TEST_ASSERT(memcmp(&service->issuance_root_record, &issuance_before,
                    sizeof(issuance_before))
            == 0,
        "Issuance Root Rolled Back");
    TEST_ASSERT(
        memcmp(&service->epoch_root_record, &epoch_before, sizeof(epoch_before))
            == 0,
        "Epoch Root Rolled Back");
    TEST_ASSERT(failed_cert.cert.serial_number == 0, "Failed Result Cleared");

    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

static void test_phase136_fresh_root_record_matches_sync_state(void)
{
    sm2_pki_service_ctx_t *service = NULL;
    const uint8_t issuer[] = "P136_SYNC_CA";
    uint64_t base_now = test_now_unix();
    TEST_ASSERT(sm2_pki_service_create(
                    &service, issuer, sizeof(issuer) - 1, 8, 300, base_now)
            == SM2_PKI_SUCCESS,
        "Service Init");

    sm2_rev_root_record_t root_record;
    TEST_ASSERT(sm2_pki_service_get_root_record(service, &root_record)
            == SM2_PKI_SUCCESS,
        "Get Root Record");

    const uint8_t node_id[] = "P136_NODE";
    sm2_rev_sync_hello_t hello;
    TEST_ASSERT(sm2_rev_sync_build_hello(service->rev_ctx, node_id,
                    sizeof(node_id) - 1, base_now, &hello)
            == SM2_IC_SUCCESS,
        "Build Hello");

    TEST_ASSERT(
        hello.root_version == root_record.root_version, "Root Version Match");
    TEST_ASSERT(
        memcmp(hello.root_hash, root_record.root_hash, sizeof(hello.root_hash))
            == 0,
        "Root Hash Match");
    TEST_ASSERT(
        hello.root_valid_until == root_record.valid_until, "ValidUntil Match");

    sm2_pki_service_destroy(&service);
    TEST_PASS();
}

void run_test_pki_internal_suite(void)
{
    RUN_TEST(test_phase7_service_ca_key_range_check);
    RUN_TEST(test_phase134_service_revoke_failure_rolls_back_state);
    RUN_TEST(test_phase135_service_issue_failure_rolls_back_state);
    RUN_TEST(test_phase136_fresh_root_record_matches_sync_state);
}
