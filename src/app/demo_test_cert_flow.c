/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Demo Test 1:
 * End-to-end certificate issuance -> proof-carrying verification
 * -> revocation block.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sm2_pki_service.h"
#include "sm2_pki_client.h"

static int check_pki(sm2_pki_error_t err, const char *step)
{
    if (err != SM2_PKI_SUCCESS)
    {
        printf("[FAIL] %s, err=%d\n", step, (int)err);
        return 0;
    }
    printf("[OK]   %s\n", step);
    return 1;
}

int main(void)
{
    sm2_pki_service_ctx_t *svc = NULL;
    sm2_pki_client_ctx_t *cli = NULL;
    sm2_pki_error_t err = SM2_PKI_SUCCESS;

    const uint8_t issuer[] = "ROOT_CA";
    const uint8_t dev_id[] = "NODE_01";
    const uint8_t msg[] = "DEMO_CERT_FLOW_MESSAGE";

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t cert_res;
    sm2_ec_point_t ca_pub;
    sm2_private_key_t witness_priv;
    sm2_ec_point_t witness_pub;
    sm2_pki_transparency_witness_t witness;
    sm2_pki_transparency_policy_t transparency_policy;
    sm2_auth_signature_t sig;
    sm2_pki_evidence_bundle_t evidence;
    size_t matched_idx = 0;
    sm2_pki_verify_request_t auth_req;
    const sm2_implicit_cert_t *cli_cert = NULL;
    const sm2_ec_point_t *cli_pub = NULL;

    sm2_rev_status_t rev_status = SM2_REV_STATUS_UNKNOWN;
    sm2_rev_source_t rev_source = SM2_REV_SOURCE_NONE;
    uint64_t base_now = (uint64_t)time(NULL);
    uint64_t auth_now = 0;

    memset(&req, 0, sizeof(req));
    memset(&temp_priv, 0, sizeof(temp_priv));
    memset(&cert_res, 0, sizeof(cert_res));
    memset(&ca_pub, 0, sizeof(ca_pub));
    memset(&witness_priv, 0, sizeof(witness_priv));
    memset(&witness_pub, 0, sizeof(witness_pub));
    memset(&witness, 0, sizeof(witness));
    memset(&transparency_policy, 0, sizeof(transparency_policy));
    memset(&sig, 0, sizeof(sig));
    memset(&evidence, 0, sizeof(evidence));
    memset(&auth_req, 0, sizeof(auth_req));

    /* 1) Initialize in-memory CA/RA service */
    err = sm2_pki_service_create(
        &svc, issuer, sizeof(issuer) - 1, 64, 300, base_now);
    if (!check_pki(err, "Service Init"))
        goto cleanup;

    /* 2) Register identity and create certificate request */
    err = sm2_pki_identity_register(
        svc, dev_id, sizeof(dev_id) - 1, SM2_KU_DIGITAL_SIGNATURE);
    if (!check_pki(err, "Identity Register"))
        goto cleanup;

    err = sm2_ic_create_cert_request(
        &req, dev_id, sizeof(dev_id) - 1, SM2_KU_DIGITAL_SIGNATURE, &temp_priv);
    if (!check_pki(err, "Create Cert Request"))
        goto cleanup;
    err = sm2_pki_cert_authorize_request(svc, &req);
    if (!check_pki(err, "Authorize Cert Request"))
        goto cleanup;

    /* 3) Issue implicit certificate from CA */
    err = sm2_pki_cert_issue(svc, &req, base_now, &cert_res);
    if (!check_pki(err, "Cert Issue"))
        goto cleanup;

    err = sm2_pki_service_get_ca_public_key(svc, &ca_pub);
    if (!check_pki(err, "Get CA Public Key"))
        goto cleanup;

    /* 4) Initialize client and reconstruct identity keys */
    err = sm2_pki_client_create(&cli, &ca_pub, svc);
    if (!check_pki(err, "Client Init"))
        goto cleanup;
    err = sm2_pki_generate_ephemeral_keypair(&witness_priv, &witness_pub);
    if (!check_pki(err, "Generate Witness Key"))
        goto cleanup;
    const uint8_t witness_id[] = "demo-witness-0";
    memcpy(witness.witness_id, witness_id, sizeof(witness_id) - 1);
    witness.witness_id_len = sizeof(witness_id) - 1;
    witness.public_key = witness_pub;
    transparency_policy.witnesses = &witness;
    transparency_policy.witness_count = 1;
    transparency_policy.threshold = 1;
    err = sm2_pki_client_set_transparency_policy(cli, &transparency_policy);
    if (!check_pki(err, "Configure Witness Policy"))
        goto cleanup;

    err = sm2_pki_client_import_cert(cli, &cert_res, &temp_priv, &ca_pub);
    if (!check_pki(err, "Import Cert"))
        goto cleanup;
    err = sm2_pki_client_get_cert(cli, &cli_cert);
    if (!check_pki(err, "Get Client Cert"))
        goto cleanup;
    err = sm2_pki_client_get_public_key(cli, &cli_pub);
    if (!check_pki(err, "Get Client Public Key"))
        goto cleanup;

    /* 5) Sign and verify (before revocation should pass) */
    err = sm2_pki_sign(cli, msg, sizeof(msg) - 1, &sig);
    if (!check_pki(err, "Sign Message"))
        goto cleanup;

    auth_req.cert = cli_cert;
    auth_req.public_key = cli_pub;
    auth_req.message = msg;
    auth_req.message_len = sizeof(msg) - 1;
    auth_req.signature = &sig;
    auth_now
        = cert_res.cert.valid_from != 0 ? cert_res.cert.valid_from : base_now;
    err = sm2_pki_client_export_epoch_evidence(cli, auth_now, &evidence);
    if (!check_pki(err, "Export Epoch Evidence Bundle"))
        goto cleanup;
    err = sm2_pki_epoch_witness_sign(&evidence.epoch_root_record,
        witness.witness_id, witness.witness_id_len, &witness_priv,
        &evidence.witness_signatures[0]);
    if (!check_pki(err, "Witness Sign Epoch Root"))
        goto cleanup;
    evidence.witness_signature_count = 1;
    auth_req.evidence_bundle = &evidence;

    err = sm2_pki_verify(cli, &auth_req, auth_now, &matched_idx);
    if (!check_pki(err, "Verify Before Revoke"))
        goto cleanup;
    printf("[INFO] matched_ca_index=%zu\n", matched_idx);

    /* 6) Revoke certificate and confirm revocation state */
    err = sm2_pki_service_revoke(
        svc, cert_res.cert.serial_number, auth_now + 5);
    if (!check_pki(err, "Revoke Cert"))
        goto cleanup;

    err = sm2_pki_service_check_revocation(svc, cert_res.cert.serial_number,
        auth_now + 6, &rev_status, &rev_source);
    if (!check_pki(err, "Revoke Check"))
        goto cleanup;
    printf("[INFO] revoke_status=%d, source=%d\n", (int)rev_status,
        (int)rev_source);

    if (rev_status != SM2_REV_STATUS_REVOKED)
    {
        printf("[FAIL] Revoke status is not REVOKED\n");
        goto cleanup;
    }

    sm2_pki_evidence_bundle_t after_revoke_evidence;
    memset(&after_revoke_evidence, 0, sizeof(after_revoke_evidence));

    /* 7) A revoked certificate cannot mint a fresh epoch evidence bundle. */
    err = sm2_pki_client_export_epoch_evidence(
        cli, auth_now + 7, &after_revoke_evidence);
    if (err == SM2_PKI_SUCCESS)
    {
        printf("[FAIL] Export After Revoke unexpectedly succeeded\n");
        goto cleanup;
    }
    printf(
        "[OK]   Export After Revoke blocked as expected, err=%d\n", (int)err);

    printf("[PASS] demo_test_cert_flow\n");
    sm2_pki_client_destroy(&cli);
    sm2_pki_service_destroy(&svc);
    return 0;

cleanup:
    sm2_pki_client_destroy(&cli);
    sm2_pki_service_destroy(&svc);
    return 1;
}
