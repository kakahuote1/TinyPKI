#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "sm2_implicit_cert.h"

// ==========================================
// 简易测试框架
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

// 场景 0: 初始化 CA 环境
void test_setup_ca() {
    sm2_ic_error_t ret;
    ret = sm2_ic_generate_random(g_ca_priv.d, 32);
    TEST_ASSERT(ret == SM2_IC_SUCCESS, "CA PrivKey Gen Failed");
    ret = sm2_ic_sm2_point_mult(&g_ca_pub, g_ca_priv.d, 32, NULL);
    TEST_ASSERT(ret == SM2_IC_SUCCESS, "CA PubKey Gen Failed");
    g_ca_initialized = 1;
    TEST_PASS();
}

// 场景 1: 完整的生命周期
void test_full_lifecycle() {
    if (!g_ca_initialized) test_setup_ca();
    
    sm2_ic_error_t ret;
    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    uint8_t sub_id[] = "UAV_001";
    
    // 使用宏定义，不再使用魔术数字
    uint8_t usage = SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT;
    
    ret = sm2_ic_create_cert_request(&req, sub_id, strlen((char*)sub_id), usage, &temp_priv);
    TEST_ASSERT(ret == SM2_IC_SUCCESS, "Request Creation Failed");

    sm2_ic_cert_result_t res;
    uint8_t iss_id[] = "ROOT_CA";
    ret = sm2_ic_ca_generate_cert(&res, &req, iss_id, strlen((char*)iss_id), &g_ca_priv, &g_ca_pub);
    TEST_ASSERT(ret == SM2_IC_SUCCESS, "Cert Issuance Failed");

    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;
    ret = sm2_ic_reconstruct_keys(&user_priv, &user_pub, &res, &temp_priv, &g_ca_pub);
    TEST_ASSERT(ret == SM2_IC_SUCCESS, "Key Reconstruction Failed");

    ret = sm2_ic_verify_cert(&res.cert, &user_pub, &g_ca_pub);
    TEST_ASSERT(ret == SM2_IC_SUCCESS, "Verification Failed");

    TEST_PASS();
}

// 场景 2: 安全性测试 - 篡改证书
void test_tampered_cert() {
    if (!g_ca_initialized) test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_create_cert_request(&req, (uint8_t*)"DEVICE", 6, SM2_KU_DIGITAL_SIGNATURE, &temp_priv);
    
    sm2_ic_cert_result_t res;
    sm2_ic_ca_generate_cert(&res, &req, (uint8_t*)"CA", 2, &g_ca_priv, &g_ca_pub);

    sm2_private_key_t user_priv;
    sm2_ec_point_t user_pub;
    sm2_ic_reconstruct_keys(&user_priv, &user_pub, &res, &temp_priv, &g_ca_pub);

    // 攻击：篡改序列号
    res.cert.serial_number++; 
    sm2_ic_error_t ret = sm2_ic_verify_cert(&res.cert, &user_pub, &g_ca_pub);
    TEST_ASSERT(ret != SM2_IC_SUCCESS, "Tampered Cert Should FAIL Verify");

    // 攻击：篡改 V (公钥重构值)
    res.cert.serial_number--; // 恢复序列号
    // [变动] public_recon_key 现在是 flat 数组，直接修改其中一个字节
    res.cert.public_recon_key[3] ^= 0xFF; 
    ret = sm2_ic_verify_cert(&res.cert, &user_pub, &g_ca_pub);
    TEST_ASSERT(ret != SM2_IC_SUCCESS, "Tampered V Should FAIL Verify");

    TEST_PASS();
}

// 场景 3: 编码鲁棒性测试 
void test_cbor_robustness() {
    sm2_implicit_cert_t cert;
    memset(&cert, 0, sizeof(cert));
    cert.subject_id_len = 5;
    
    // [变动] 扩大测试缓冲区
    uint8_t buf[1024];
    size_t len = sizeof(buf);
    
    sm2_ic_error_t ret = sm2_ic_cbor_encode_cert(buf, &len, &cert);
    TEST_ASSERT(ret == SM2_IC_SUCCESS, "Normal Encode Failed");

    len = 5; // 缓冲区过小
    ret = sm2_ic_cbor_encode_cert(buf, &len, &cert);
    TEST_ASSERT(ret == SM2_IC_ERR_MEMORY, "Should Detect Small Buffer");

    TEST_PASS();
}

// 场景 4: 性能基准测试
void test_performance() {
    if (!g_ca_initialized) test_setup_ca();

    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_priv;
    sm2_ic_create_cert_request(&req, (uint8_t*)"BENCH", 5, SM2_KU_DIGITAL_SIGNATURE, &temp_priv);

    sm2_ic_cert_result_t res;
    clock_t start, end;
    double cpu_time_used;

    int ITERATIONS = 100;
    start = clock();
    for(int i=0; i<ITERATIONS; i++) {
        sm2_ic_ca_generate_cert(&res, &req, (uint8_t*)"CA", 2, &g_ca_priv, &g_ca_pub);
    }
    end = clock();
    
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC * 1000.0;
    printf("   [PERF] Issue Cert Avg Time: %.2f ms (over %d runs)\n", cpu_time_used/ITERATIONS, ITERATIONS);

    TEST_PASS();
}

int main() {
    printf("========================================\n");
    printf("   Aviation PKI Test Suite (v1.1)       \n");
    printf("========================================\n");

    RUN_TEST(test_setup_ca);
    RUN_TEST(test_full_lifecycle);
    RUN_TEST(test_tampered_cert);
    RUN_TEST(test_cbor_robustness);
    RUN_TEST(test_performance);

    printf("========================================\n");
    printf("Tests Run: %d\n", g_tests_run);
    printf("Passed:    %d\n", g_tests_passed);
    printf("Failed:    %d\n", g_tests_failed);
    
    return g_tests_failed == 0 ? 0 : -1;
}