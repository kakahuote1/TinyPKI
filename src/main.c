#include <stdio.h>
#include "sm2_implicit_cert.h"

/**
 * @brief 打印十六进制数据
 */
static void print_hex(const char *prefix, const uint8_t *data, size_t len) {
    printf("%s: ", prefix);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if (i % 4 == 3 && i != len - 1) {
            printf(" ");
        }
    }
    printf("\n");
}

/**
 * @brief 打印点坐标
 */
static void print_point(const char *prefix, const sm2_ec_point_t *point) {
    printf("%s:\n", prefix);
    print_hex("  X", point->x, sizeof(point->x));
    print_hex("  Y", point->y, sizeof(point->y));
}

/**
 * @brief 打印隐式证书信息
 */
static void print_cert(const sm2_implicit_cert_t *cert) {
    printf("证书信息:\n");
    printf("  类型: %s\n", cert->type == SM2_IC_TYPE_IMPLICIT ? "隐式" : "显式");
    printf("  序列号: %llu\n", cert->serial_number);
    printf("  主体ID: ");
    for (size_t i = 0; i < cert->subject_id_len; i++) {
        printf("%c", cert->subject_id[i]);
    }
    printf("\n");
    printf("  颁发者ID: ");
    for (size_t i = 0; i < cert->issuer_id_len; i++) {
        printf("%c", cert->issuer_id[i]);
    }
    printf("\n");
    printf("  有效期开始: %llu\n", cert->valid_from);
    printf("  有效期持续: %llu 秒\n", cert->valid_duration);
    printf("  密钥用途: 0x%02x", cert->key_usage);
    if (cert->key_usage & SM2_IC_KEY_USAGE_SIGN) printf(" (签名)");
    if (cert->key_usage & SM2_IC_KEY_USAGE_ENC) printf(" (加密)");
    if (cert->key_usage & SM2_IC_KEY_USAGE_KEX) printf(" (密钥交换)");
    if (cert->key_usage & SM2_IC_KEY_USAGE_CERT_SIGN) printf(" (证书签名)");
    printf("\n");
    print_point("  公钥重构值V", &cert->public_recon_key);
}

/**
 * @brief 主函数，演示隐式证书签发和使用流程
 */
int main() {
    printf("=== SM2隐式证书签发与使用演示 ===\n\n");
    
    // 1. CA初始化：生成CA密钥对（示例中使用固定值）
    sm2_private_key_t ca_private_key;
    sm2_ec_point_t ca_public_key;
    
    // 生成CA私钥（示例中使用随机值）
    sm2_ic_error_t ret = sm2_ic_generate_random(ca_private_key.d, sizeof(ca_private_key.d));
    if (ret != SM2_IC_SUCCESS) {
        printf("错误: 生成CA私钥失败，错误码: %d\n", ret);
        return -1;
    }
    
    // 计算CA公钥
    ret = sm2_ic_sm2_point_mult(&ca_public_key, ca_private_key.d, sizeof(ca_private_key.d), &SM2_BASE_POINT_G);
    if (ret != SM2_IC_SUCCESS) {
        printf("错误: 计算CA公钥失败，错误码: %d\n", ret);
        return -1;
    }
    
    printf("CA初始化完成:\n");
    print_hex("CA私钥", ca_private_key.d, sizeof(ca_private_key.d));
    print_point("CA公钥", &ca_public_key);
    printf("\n");
    
    // 2. 设备侧：创建证书请求
    sm2_ic_cert_request_t request;
    sm2_private_key_t temp_private_key;
    uint8_t subject_id[] = "UAV_001";
    uint8_t key_usage = SM2_IC_KEY_USAGE_SIGN | SM2_IC_KEY_USAGE_KEX;
    
    ret = sm2_ic_create_cert_request(&request, subject_id, sizeof(subject_id) - 1, key_usage, &temp_private_key);
    if (ret != SM2_IC_SUCCESS) {
        printf("错误: 创建证书请求失败，错误码: %d\n", ret);
        return -1;
    }
    
    printf("设备创建证书请求:\n");
    print_hex("临时私钥x", temp_private_key.d, sizeof(temp_private_key.d));
    print_point("临时公钥X", &request.temp_public_key);
    printf("主体ID: %s\n", subject_id);
    printf("密钥用途: 0x%02x\n", key_usage);
    printf("\n");
    
    // 3. CA侧：生成隐式证书
    sm2_ic_cert_result_t cert_result;
    uint8_t issuer_id[] = "SM2_CA";
    
    ret = sm2_ic_ca_generate_cert(&cert_result, &request, issuer_id, sizeof(issuer_id) - 1, &ca_private_key, &ca_public_key);
    if (ret != SM2_IC_SUCCESS) {
        printf("错误: CA生成证书失败，错误码: %d\n", ret);
        return -1;
    }
    
    printf("CA生成隐式证书:\n");
    print_cert(&cert_result.cert);
    print_hex("私钥重构值S", cert_result.private_recon_value, sizeof(cert_result.private_recon_value));
    printf("\n");
    
    // 4. 设备侧：重构最终密钥对
    sm2_private_key_t final_private_key;
    sm2_ec_point_t final_public_key;
    
    ret = sm2_ic_reconstruct_keys(&final_private_key, &final_public_key, &cert_result, &temp_private_key, &ca_public_key);
    if (ret != SM2_IC_SUCCESS) {
        printf("错误: 重构密钥失败，错误码: %d\n", ret);
        return -1;
    }
    
    printf("设备重构最终密钥对:\n");
    print_hex("最终私钥d_U", final_private_key.d, sizeof(final_private_key.d));
    print_point("最终公钥Q_U", &final_public_key);
    printf("\n");
    
    // 5. 验证证书和公钥
    ret = sm2_ic_verify_cert(&cert_result.cert, &final_public_key, &ca_public_key);
    if (ret == SM2_IC_SUCCESS) {
        printf("✓ 证书验证成功！\n");
        printf("✓ 公钥验证成功！\n");
    } else {
        printf("✗ 证书验证失败，错误码: %d\n", ret);
    }
    printf("\n");
    
    // 6. CBOR编码和解码证书
    uint8_t cbor_buffer[1024];
    size_t cbor_len = sizeof(cbor_buffer);
    
    ret = sm2_ic_cbor_encode_cert(cbor_buffer, &cbor_len, &cert_result.cert);
    if (ret != SM2_IC_SUCCESS) {
        printf("错误: CBOR编码证书失败，错误码: %d\n", ret);
        return -1;
    }
    
    printf("CBOR编码证书:\n");
    print_hex("编码后数据", cbor_buffer, cbor_len);
    printf("编码长度: %zu 字节\n", cbor_len);
    printf("\n");
    
    sm2_implicit_cert_t decoded_cert;
    ret = sm2_ic_cbor_decode_cert(&decoded_cert, cbor_buffer, cbor_len);
    if (ret != SM2_IC_SUCCESS) {
        printf("错误: CBOR解码证书失败，错误码: %d\n", ret);
        return -1;
    }
    
    printf("CBOR解码证书:\n");
    print_cert(&decoded_cert);
    printf("\n");
    
    printf("=== 演示完成 ===\n");
    
    return 0;
}