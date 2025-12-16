/**
 * @file sm2_implicit_cert.h
 * @brief 面向航空系统的 SM2 轻量化隐式证书核心定义
 * @details 定义了 ECQV 隐式证书的数据结构、错误码及核心算法接口
 * @version 1.1.0 (Optimized)
 */

#ifndef SM2_IMPLICIT_CERT_H
#define SM2_IMPLICIT_CERT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* 支持 C++ 混合编译 */
#ifdef __cplusplus
extern "C" {
#endif

// ==========================================
// 常量与宏定义
// ==========================================

/** SM2 密钥长度 (字节) */
#define SM2_KEY_LEN             32
/** SM2 压缩公钥长度 (字节, 02/03 + X) */
#define SM2_COMPRESSED_KEY_LEN  33
/** SM2 未压缩公钥长度 (字节, 04 + X + Y) */
#define SM2_UNCOMPRESSED_KEY_LEN 65
/** SM3 哈希长度 (字节) */
#define SM3_DIGEST_LENGTH       32

/* 密钥用途定义 (参考 X.509 KeyUsage) */
#define SM2_KU_DIGITAL_SIGNATURE    0x01  // 数字签名
#define SM2_KU_NON_REPUDIATION      0x02  // 不可否认性
#define SM2_KU_KEY_ENCIPHERMENT     0x04  // 密钥加密
#define SM2_KU_DATA_ENCIPHERMENT    0x08  // 数据加密
#define SM2_KU_KEY_AGREEMENT        0x10  // 密钥协商

/* 证书类型 */
#define SM2_CERT_TYPE_IMPLICIT      0x01  // 隐式证书

// ==========================================
// 数据结构定义
// ==========================================

/**
 * @brief SM2 椭圆曲线点 (用于内存中计算)
 * @note 存储 256 位大整数 X 和 Y 分量，主要用于运行时计算接口
 */
typedef struct {
    uint8_t x[SM2_KEY_LEN];
    uint8_t y[SM2_KEY_LEN];
} sm2_ec_point_t;

/**
 * @brief SM2 私钥
 */
typedef struct {
    uint8_t d[SM2_KEY_LEN];
} sm2_private_key_t;

/**
 * @brief 隐式证书结构体
 * @note 对应文档中裁剪后的证书结构，不包含显式签名和完整公钥
 */
typedef struct {
    uint8_t type;                       ///< 证书类型
    uint64_t serial_number;             ///< 序列号 (8字节)
    
    uint8_t subject_id[256];            ///< 主体标识 (如 UAV ID)
    size_t subject_id_len;              ///< 主体标识长度
    
    uint8_t issuer_id[256];             ///< 颁发者标识 (CA ID)
    size_t issuer_id_len;               ///< 颁发者标识长度
    
    uint64_t valid_from;                ///< 有效期开始 (Unix时间戳)
    uint64_t valid_duration;            ///< 有效期持续时间 (秒)
    
    uint8_t key_usage;                  ///< 密钥用途位掩码
    
    /** * @brief 公钥重构值 V (核心字段)
     * @note [优化] 使用压缩格式 (33字节) 以节省存储空间和传输带宽
     */
    uint8_t public_recon_key[SM2_COMPRESSED_KEY_LEN]; 
} sm2_implicit_cert_t;

/**
 * @brief 证书生成结果容器
 */
typedef struct {
    sm2_implicit_cert_t cert;           ///< 生成的隐式证书
    uint8_t private_recon_value[SM2_KEY_LEN]; ///< 私钥重构数据 S
} sm2_ic_cert_result_t;

/**
 * @brief 证书请求结构
 */
typedef struct {
    uint8_t subject_id[256];
    size_t subject_id_len;
    uint8_t key_usage;
    sm2_ec_point_t temp_public_key;     ///< 设备临时公钥 X
} sm2_ic_cert_request_t;

/**
 * @brief 错误码定义
 */
typedef enum {
    SM2_IC_SUCCESS = 0,
    SM2_IC_ERR_PARAM = -1,
    SM2_IC_ERR_MEMORY = -2,
    SM2_IC_ERR_CRYPTO = -3,
    SM2_IC_ERR_VERIFY = -4,
    SM2_IC_ERR_CBOR = -5
} sm2_ic_error_t;

// ==========================================
// API 接口声明
// ==========================================

/* 基础辅助 */
sm2_ic_error_t sm2_ic_generate_random(uint8_t *buf, size_t len);
sm2_ic_error_t sm2_ic_sm3_hash(const uint8_t *input, size_t input_len, uint8_t *output);
sm2_ic_error_t sm2_ic_sm2_point_mult(sm2_ec_point_t *point, const uint8_t *scalar, size_t scalar_len, const sm2_ec_point_t *base_point);

/* ECQV 核心流程 */
sm2_ic_error_t sm2_ic_create_cert_request(sm2_ic_cert_request_t *request, const uint8_t *subject_id, size_t subject_id_len, uint8_t key_usage, sm2_private_key_t *temp_private_key);
sm2_ic_error_t sm2_ic_ca_generate_cert(sm2_ic_cert_result_t *result, const sm2_ic_cert_request_t *request, const uint8_t *issuer_id, size_t issuer_id_len, const sm2_private_key_t *ca_private_key, const sm2_ec_point_t *ca_public_key);
sm2_ic_error_t sm2_ic_reconstruct_keys(sm2_private_key_t *private_key, sm2_ec_point_t *public_key, const sm2_ic_cert_result_t *cert_result, const sm2_private_key_t *temp_private_key, const sm2_ec_point_t *ca_public_key);
sm2_ic_error_t sm2_ic_verify_cert(const sm2_implicit_cert_t *cert, const sm2_ec_point_t *public_key, const sm2_ec_point_t *ca_public_key);

/* 编码与序列化 */
sm2_ic_error_t sm2_ic_cbor_encode_cert(uint8_t *output, size_t *output_len, const sm2_implicit_cert_t *cert);
sm2_ic_error_t sm2_ic_cbor_decode_cert(sm2_implicit_cert_t *cert, const uint8_t *input, size_t input_len);

#ifdef __cplusplus
}
#endif

#endif // SM2_IMPLICIT_CERT_H