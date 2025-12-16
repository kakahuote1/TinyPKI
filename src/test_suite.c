#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "sm2_implicit_cert.h"

// ==========================================
// Minimal Test Framework
// ==========================================
int g_tests_run = 0;
int g_tests_passed = 0;
int g_tests_failed = 0;

#define TEST_ASSERT(condition, msg) do { \
    if (!(condition)) { \
        printf("\033[31m[FAIL] %s: %s\033[0m\n", __func__, msg); \
        g_tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_PASS() do { \
    printf("\033[32m[PASS] %s\033[0m\n", __func__); \
    g_tests_passed++; \
} while(0)

#define RUN_TEST(test_func) do { \
    g_tests_run++; \
    test_func(); \
} while(0)

static sm2_private_key_t g_ca_priv;
static sm2_ec_point_t g_ca_pub;
static int g_ca_initialized = 0;

void test_setup_ca() {
    TEST_ASSERT(sm2_ic_generate_random(g_ca_priv.d, 32) == SM2_IC_SUCCESS, "CA KeyGen Failed");
    TEST_ASSERT(sm2_ic_sm2_point_mult(&g_ca_pub, g_ca_priv.d, 32, NULL) == SM2_IC_SUCCESS, "CA PubKey Failed");
    g_ca_initialized = 1;
    TEST_PASS();
}

void test_full_lifecycle() {
    if (!g_ca_initialized) test_setup_ca();
    
    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    uint8_t sub_id[] = "UAV_TEST_001";
    uint8_t iss_id[] = "ROOT_CA";
    uint8_t usage = SM2_KU_DIGITAL_SIGNATURE;
    
    TEST_ASSERT(sm2_ic_create_cert_request(&req, sub_id, strlen((char*)sub_id), usage, &temp_priv) == SM2_IC_SUCCESS, "Req Create");
    TEST_ASSERT(sm2_ic_ca_generate_cert(&res, &req, iss_id, strlen((char*)iss_id), &g_ca_priv, &g_ca_pub) == SM2_IC_SUCCESS, "Cert Issue");
    TEST_ASSERT(sm2_ic_reconstruct_keys(&user_priv, &user_pub, &res, &temp_priv, &g_ca_pub) == SM2_IC_SUCCESS, "Key Recon");
    TEST_ASSERT(sm2_ic_verify_cert(&res.cert, &user_pub, &g_ca_pub) == SM2_IC_SUCCESS, "Cert Verify");

    TEST_PASS();
}

void test_tampered_cert() {
    if (!g_ca_initialized) test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t res;
    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;

    sm2_ic_create_cert_request(&req, (uint8_t*)"DEV", 3, SM2_KU_DIGITAL_SIGNATURE, &temp_priv);
    sm2_ic_ca_generate_cert(&res, &req, (uint8_t*)"CA", 2, &g_ca_priv, &g_ca_pub);
    sm2_ic_reconstruct_keys(&user_priv, &user_pub, &res, &temp_priv, &g_ca_pub);

    // Case 1: Tamper Serial Number
    res.cert.serial_number++; 
    TEST_ASSERT(sm2_ic_verify_cert(&res.cert, &user_pub, &g_ca_pub) != SM2_IC_SUCCESS, "Serial Tamper Detected");

    // Case 2: Tamper Public Reconstruction Key (V)
    res.cert.serial_number--; 
    res.cert.public_recon_key[5] ^= 0xFF; 
    TEST_ASSERT(sm2_ic_verify_cert(&res.cert, &user_pub, &g_ca_pub) != SM2_IC_SUCCESS, "V-Key Tamper Detected");

    TEST_PASS();
}

void test_cbor_robustness() {
    sm2_implicit_cert_t cert;
    memset(&cert, 0, sizeof(cert));
    
    uint8_t buf[1024];
    size_t len = sizeof(buf);
    
    TEST_ASSERT(sm2_ic_cbor_encode_cert(buf, &len, &cert) == SM2_IC_SUCCESS, "Encode OK");

    len = 5; // Buffer too small
    TEST_ASSERT(sm2_ic_cbor_encode_cert(buf, &len, &cert) == SM2_IC_ERR_MEMORY, "Buffer Overflow Protection");

    TEST_PASS();
}

void test_performance() {
    if (!g_ca_initialized) test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_cert_result_t res;
    sm2_ic_create_cert_request(&req, (uint8_t*)"PERF", 4, SM2_KU_DIGITAL_SIGNATURE, &temp_priv);

    int ITERATIONS = 1000;
    clock_t start = clock();
    
    for(int i=0; i<ITERATIONS; i++) {
        sm2_ic_ca_generate_cert(&res, &req, (uint8_t*)"CA", 2, &g_ca_priv, &g_ca_pub);
    }
    
    double avg_time = ((double)(clock() - start)) / CLOCKS_PER_SEC * 1000.0 / ITERATIONS;
    printf("   [PERF] Avg Issuance Time: %.3f ms (N=%d)\n", avg_time, ITERATIONS);
    TEST_PASS();
}

int main() {
    printf("--- Aviation PKI Test Suite ---\n");
    RUN_TEST(test_setup_ca);
    RUN_TEST(test_full_lifecycle);
    RUN_TEST(test_tampered_cert);
    RUN_TEST(test_cbor_robustness);
    RUN_TEST(test_performance);

    printf("\nSummary: %d Run, %d Passed, %d Failed.\n", g_tests_run, g_tests_passed, g_tests_failed);
    return g_tests_failed == 0 ? 0 : -1;
}