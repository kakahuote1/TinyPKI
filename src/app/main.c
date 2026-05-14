/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file main.c
 * @brief TinyPKI ECQV demo application.
 * @details
 * Demonstrates the full lifecycle of SM2 Implicit Certificates.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#if defined(_WIN32)
#include <windows.h>
#endif
#include "sm2_implicit_cert.h"
#include "sm2_pki_client.h"

/* ANSI Color Codes */
#define CLR_RESET "\033[0m"
#define CLR_RED "\033[31m"
#define CLR_GREEN "\033[32m"
#define CLR_YELLOW "\033[33m"
#define CLR_CYAN "\033[36m"

#define BASELINE_X509_DER_SIZE 675

static void log_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("    %-24s: %s", label, CLR_YELLOW);
    for (size_t i = 0; i < len; i++)
        printf("%02X", data[i]);
    printf("%s\n", CLR_RESET);
}

static void log_point(const char *label, const sm2_ec_point_t *point)
{
    printf("    %s:\n", label);
    printf("      x: %s", CLR_YELLOW);
    for (int i = 0; i < 32; i++)
        printf("%02X", point->x[i]);
    printf("%s\n", CLR_RESET);
    printf("      y: %s", CLR_YELLOW);
    for (int i = 0; i < 32; i++)
        printf("%02X", point->y[i]);
    printf("%s\n", CLR_RESET);
}

static void log_redacted_secret(const char *label)
{
    printf("    %-24s: %s[redacted]%s\n", label, CLR_YELLOW, CLR_RESET);
}

int main()
{
#if defined(_WIN32)
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
#endif

    printf("\n%s=== TinyPKI ECQV Demo ===%s\n\n", CLR_CYAN, CLR_RESET);

    sm2_ic_error_t ret;
    clock_t start_time, end_time;

    /* --- Phase 0: System Initialization --- */
    printf("%s[INFO] Phase 0: CA Initialization%s\n", CLR_CYAN, CLR_RESET);

    sm2_private_key_t ca_priv;
    sm2_ec_point_t ca_pub;
    uint64_t issue_now = (uint64_t)time(NULL);

    if (sm2_pki_generate_ephemeral_keypair(&ca_priv, &ca_pub)
        != SM2_PKI_SUCCESS)
    {
        fprintf(stderr, "%s[ERROR] Failed to generate CA keys.\n%s", CLR_RED,
            CLR_RESET);
        return -1;
    }
    log_redacted_secret("CA Private Key");
    log_point("CA Public Key (P)", &ca_pub);
    printf("\n");

    /* --- Phase 1: Certificate Request --- */
    printf("%s[INFO] Phase 1: Device Certificate Request%s\n", CLR_CYAN,
        CLR_RESET);

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_device_priv;
    const char *device_id = "UAV-ID-CN-2025-X01";
    uint8_t key_usage = SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT;

    if (sm2_ic_create_cert_request(&req, (uint8_t *)device_id,
            strlen(device_id), key_usage, &temp_device_priv)
        != SM2_IC_SUCCESS)
    {
        fprintf(stderr, "%s[ERROR] Failed to create request.\n%s", CLR_RED,
            CLR_RESET);
        return -1;
    }

    log_redacted_secret("Ephemeral Priv Key");
    log_point("Ephemeral Pub Key (R)", &req.temp_public_key);
    printf("    Subject ID              : %.*s\n\n", (int)req.subject_id_len,
        req.subject_id);

    /* --- Phase 2: Issuance --- */
    printf("%s[INFO] Phase 2: CA Issuance (ECQV Generation)%s\n", CLR_CYAN,
        CLR_RESET);

    sm2_ic_cert_result_t issue_result;
    const char *issuer_id = "TinyPKI-Root-CA-G1";

    start_time = clock();
    ret = sm2_ic_ca_generate_cert(&issue_result, &req, (uint8_t *)issuer_id,
        strlen(issuer_id), &ca_priv, &ca_pub, issue_now);
    end_time = clock();

    if (ret != SM2_IC_SUCCESS)
    {
        fprintf(stderr, "%s[ERROR] Issuance failed.\n%s", CLR_RED, CLR_RESET);
        return -1;
    }

    printf("%s[SUCCESS] Certificate Issued in %.2f ms%s\n", CLR_GREEN,
        ((double)(end_time - start_time)) / CLOCKS_PER_SEC * 1000.0, CLR_RESET);
    printf("    Serial Number           : %llu\n",
        issue_result.cert.serial_number);
    printf(
        "    Field Mask              : 0x%04X\n", issue_result.cert.field_mask);
    log_hex("Reconstruction Key (V)", issue_result.cert.public_recon_key,
        SM2_COMPRESSED_KEY_LEN);
    log_redacted_secret("Reconstruction Scalar (s)");
    printf("\n");

    /* --- Phase 3: Performance Metrics --- */
    printf("%s[INFO] Phase 3: Encoding Analysis%s\n", CLR_CYAN, CLR_RESET);

    uint8_t cbor_buf[1024];
    size_t cbor_len = sizeof(cbor_buf);

    if (sm2_ic_cbor_encode_cert(cbor_buf, &cbor_len, &issue_result.cert)
        != SM2_IC_SUCCESS)
    {
        fprintf(
            stderr, "%s[ERROR] CBOR encoding failed.\n%s", CLR_RED, CLR_RESET);
        return -1;
    }

    float ratio_x509
        = (1.0f - (float)cbor_len / (float)BASELINE_X509_DER_SIZE) * 100.0f;

    log_hex("CBOR Payload", cbor_buf, cbor_len);
    printf("\n");
    printf("  +-----------------------------+------------------------+\n");
    printf("  | Metric                      | Value                  |\n");
    printf("  +-----------------------------+------------------------+\n");
    printf("  | Standard X.509 DER Baseline | %4d Bytes             |\n",
        BASELINE_X509_DER_SIZE);
    printf("  | ECQV Implicit Cert (CBOR)   | %s%4zu Bytes%s             |\n",
        CLR_GREEN, cbor_len, CLR_RESET);
    printf("  +-----------------------------+------------------------+\n");
    printf("  | Space Savings               | %s%.2f%%%s                 |\n",
        CLR_YELLOW, ratio_x509, CLR_RESET);
    printf("  +-----------------------------+------------------------+\n");
    printf("\n");

    /* --- Phase 4: Key Reconstruction --- */
    printf(
        "%s[INFO] Phase 4: Client Key Reconstruction%s\n", CLR_CYAN, CLR_RESET);

    sm2_private_key_t final_device_priv;
    sm2_ec_point_t final_device_pub;
    sm2_implicit_cert_t received_cert;
    memset(&received_cert, 0, sizeof(received_cert));

    if (sm2_ic_cbor_decode_cert(&received_cert, cbor_buf, cbor_len)
        != SM2_IC_SUCCESS)
    {
        fprintf(
            stderr, "%s[ERROR] CBOR decoding failed.\n%s", CLR_RED, CLR_RESET);
        return -1;
    }

    if (sm2_ic_reconstruct_keys(&final_device_priv, &final_device_pub,
            &issue_result, &temp_device_priv, &ca_pub)
        != SM2_IC_SUCCESS)
    {
        fprintf(stderr, "%s[ERROR] Key reconstruction failed.\n%s", CLR_RED,
            CLR_RESET);
        return -1;
    }

    log_redacted_secret("Recovered Priv Key");
    log_point("Derived Pub Key (Q)", &final_device_pub);
    printf("\n");

    /* --- Phase 5: Self-Verification --- */
    printf("%s[INFO] Phase 5: Public Key Binding Verification%s\n", CLR_CYAN,
        CLR_RESET);

    if (sm2_ic_verify_cert(&received_cert, &final_device_pub, &ca_pub)
        == SM2_IC_SUCCESS)
    {
        printf("%s[PASS] Implicit Certificate binding is valid.%s\n", CLR_GREEN,
            CLR_RESET);
    }
    else
    {
        printf("%s[FAIL] Certificate binding verification failed.%s\n", CLR_RED,
            CLR_RESET);
    }

    printf("\n================================================\n");
    return 0;
}
