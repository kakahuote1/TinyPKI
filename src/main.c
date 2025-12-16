/**
 * @file main.c
 * @brief 面向航空系统的轻量化 PKI 体系 - 第一Step验证演示
 * @details 包含 ECQV 隐式证书全生命周期流程及压缩性能分析。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sm2_implicit_cert.h"

// ==========================================
// 终端格式控制 (ANSI Escape Codes)
// ==========================================
#define FMT_RESET     "\033[0m"
#define FMT_BOLD      "\033[1m"
#define COLOR_ERROR   "\033[31m"
#define COLOR_SUCCESS "\033[32m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_KEY     "\033[33m"
#define COLOR_TITLE   "\033[36m"
#define COLOR_INFO    "\033[34m"

#define ESTIMATED_X509_SIZE 1024 

static void print_hex_data(const char *label, const uint8_t *data, size_t len) {
    printf("%s  %-26s: %s", COLOR_INFO, label, COLOR_KEY);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("%s\n", FMT_RESET);
}

static void print_ec_point(const char *label, const sm2_ec_point_t *point) {
    printf("%s  %s:%s\n", COLOR_INFO, label, FMT_RESET);
    printf("    x: %s", COLOR_KEY);
    for(int i=0; i<32; i++) printf("%02X", point->x[i]);
    printf("%s\n", FMT_RESET);
    printf("    y: %s", COLOR_KEY);
    for(int i=0; i<32; i++) printf("%02X", point->y[i]);
    printf("%s\n", FMT_RESET);
}

int main() {
    // 切换终端到 UTF-8 (仅 Windows 需要)
    #ifdef _WIN32
        system("chcp 65001 > nul");
    #endif

    printf("\n\n");

    sm2_ic_error_t ret;
    clock_t start_time, end_time;

    // Step 0
    printf("%s[Step 0] 初始化 %s\n", COLOR_TITLE, FMT_RESET);
    
    sm2_private_key_t ca_priv;
    sm2_ec_point_t ca_pub;

    if (sm2_ic_generate_random(ca_priv.d, 32) != SM2_IC_SUCCESS ||
        sm2_ic_sm2_point_mult(&ca_pub, ca_priv.d, 32, NULL) != SM2_IC_SUCCESS) {
        fprintf(stderr, "%s[错误] CA 密钥生成失败\n%s", COLOR_ERROR, FMT_RESET);
        return -1;
    }
    print_hex_data("CA 根私钥 (d_CA)", ca_priv.d, 32);
    print_ec_point("CA 根公钥 (P_CA)", &ca_pub);
    printf("\n\n");

    // Step 1
    printf("%s[Step 1] 设备证书申请 %s\n", COLOR_TITLE, FMT_RESET);
    
    sm2_ic_cert_request_t req;
    sm2_private_key_t temp_device_priv; 
    
    const char *device_id = "UAV-ID-CN-2025-X01";
    uint8_t key_usage = SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT;

    ret = sm2_ic_create_cert_request(&req, (uint8_t*)device_id, strlen(device_id), key_usage, &temp_device_priv);
    if (ret != SM2_IC_SUCCESS) {
        fprintf(stderr, "%s[错误] 证书申请创建失败\n%s", COLOR_ERROR, FMT_RESET);
        return -1;
    }

    print_hex_data("临时私钥 (x)", temp_device_priv.d, 32);
    print_ec_point("临时公钥 (X)", &req.temp_public_key);
    printf("%s  主体标识 (Subject ID)   : %s%s\n", COLOR_INFO, FMT_RESET, req.subject_id);
    printf("\n\n");

    // Step 2
    printf("%s[Step 2] CA 签发隐式证书 %s\n", COLOR_TITLE, FMT_RESET);
    
    sm2_ic_cert_result_t issue_result;
    const char *issuer_id = "Aviation-Root-CA-G1";

    start_time = clock(); 
    ret = sm2_ic_ca_generate_cert(&issue_result, &req, (uint8_t*)issuer_id, strlen(issuer_id), &ca_priv, &ca_pub);
    end_time = clock();  

    if (ret != SM2_IC_SUCCESS) {
        fprintf(stderr, "%s[错误] 证书签发失败\n%s", COLOR_ERROR, FMT_RESET);
        return -1;
    }

    double time_ms = ((double)(end_time - start_time)) / CLOCKS_PER_SEC * 1000.0;
    
    printf("%s  [成功] 证书签发完成，耗时: %.2f ms%s\n", COLOR_SUCCESS, time_ms, FMT_RESET);
    printf("  证书序列号 (Serial)     : %llu\n", issue_result.cert.serial_number);
    // [变动] 打印压缩后的 V (33字节)
    print_hex_data("公钥重构值 V (Compressed)", issue_result.cert.public_recon_key, SM2_COMPRESSED_KEY_LEN);
    print_hex_data("私钥重构数据 (S)", issue_result.private_recon_value, 32);
    printf("\n\n");

    // Step 3
    printf("%s[Step 3] 编码效率分析 %s\n", COLOR_TITLE, FMT_RESET);
    
    // [变动] 扩大缓冲区
    uint8_t cbor_buf[1024];
    size_t cbor_len = sizeof(cbor_buf);

    ret = sm2_ic_cbor_encode_cert(cbor_buf, &cbor_len, &issue_result.cert);
    
    if (ret == SM2_IC_SUCCESS) {
        size_t struct_size = sizeof(sm2_implicit_cert_t);
        float ratio_struct = (1.0f - (float)cbor_len / (float)struct_size) * 100.0f;
        float ratio_x509 = (1.0f - (float)cbor_len / (float)ESTIMATED_X509_SIZE) * 100.0f;

        printf("  编码格式: CBOR\n");
        print_hex_data("编码后数据", cbor_buf, cbor_len);
        printf("\n");
        printf("  ------------------------------------------------------------\n");
        printf("  | 指标项                      | 数值                       |\n");
        printf("  |-----------------------------|----------------------------|\n");
        printf("  | 传统 X.509 证书大小 (估算)  | %4d Bytes                 |\n", ESTIMATED_X509_SIZE);
        printf("  | 本系统内存结构体大小        | %4zu Bytes                 |\n", struct_size);
        printf("  | %sECQV 隐式证书编码后大小%s     | %s%4zu Bytes%s                 |\n", 
               COLOR_GREEN, FMT_RESET, COLOR_GREEN, cbor_len, FMT_RESET);
        printf("  |-----------------------------|----------------------------|\n");
        printf("  | %s相比 X.509 空间节省率%s       | %s%.2f%%%s                     |\n", 
               COLOR_KEY, FMT_RESET, COLOR_KEY, ratio_x509, FMT_RESET);
        printf("  | 相比内存结构压缩率          | %.2f%%                     |\n", ratio_struct);
        printf("  ------------------------------------------------------------\n");

    } else {
        fprintf(stderr, "%s[错误] CBOR 编码失败\n%s", COLOR_ERROR, FMT_RESET);
    }
    printf("\n\n");

    // Step 4
    printf("%s[Step 4] 密钥重构 %s\n", COLOR_TITLE, FMT_RESET);
    
    sm2_private_key_t final_device_priv; 
    sm2_ec_point_t final_device_pub;    

    sm2_implicit_cert_t received_cert;
    sm2_ic_cbor_decode_cert(&received_cert, cbor_buf, cbor_len);

    ret = sm2_ic_reconstruct_keys(&final_device_priv, &final_device_pub, &issue_result, &temp_device_priv, &ca_pub);
    if (ret != SM2_IC_SUCCESS) {
        fprintf(stderr, "%s[错误] 密钥重构失败\n%s", COLOR_ERROR, FMT_RESET);
        return -1;
    }

    print_hex_data("重构后完整私钥 (d_U)", final_device_priv.d, 32);
    print_ec_point("重构后完整公钥 (Q_U)", &final_device_pub);
    printf("\n\n");

    // Step 5
    printf("%s[Step 5] 公钥有效性自验证 %s\n", COLOR_TITLE, FMT_RESET);
    
    ret = sm2_ic_verify_cert(&received_cert, &final_device_pub, &ca_pub);
    
    if (ret == SM2_IC_SUCCESS) {
        printf("%s  [验证通过] 隐式证书数学关系成立%s\n", COLOR_SUCCESS, FMT_RESET);
    } else {
        printf("%s  [验证失败] 错误码: %d%s\n", COLOR_ERROR, ret, FMT_RESET);
    }

    printf("\n==============================================================\n");
    return 0;
}