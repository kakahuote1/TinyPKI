#ifndef SM2_IMPLICIT_CERT_H
#define SM2_IMPLICIT_CERT_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

// 常量定义
#define SM2_CURVE_NIST_P256 256  // SM2曲线参数长度（位）
#define SM3_DIGEST_LENGTH 32     // SM3哈希长度（字节）
#define MAX_SUBJECT_ID_LEN 64    // 最大主体ID长度
#define MAX_ISSUER_ID_LEN 32     // 最大颁发者ID长度
#define MAX_KEY_USAGE_LEN 16     // 最大密钥用途长度

// 错误码定义
typedef enum {
    SM2_IC_SUCCESS = 0,
    SM2_IC_ERR_PARAM = -1,
    SM2_IC_ERR_MEMORY = -2,
    SM2_IC_ERR_CRYPTO = -3,
    SM2_IC_ERR_CBOR = -4,
    SM2_IC_ERR_VERIFY = -5
} sm2_ic_error_t;

// 证书类型
typedef enum {
    SM2_IC_TYPE_IMPLICIT = 1,
    SM2_IC_TYPE_EXPLICIT = 2
} sm2_ic_cert_type_t;

// 密钥用途标志
typedef enum {
    SM2_IC_KEY_USAGE_SIGN = 0x01,
    SM2_IC_KEY_USAGE_ENC = 0x02,
    SM2_IC_KEY_USAGE_KEX = 0x04,
    SM2_IC_KEY_USAGE_CERT_SIGN = 0x08
} sm2_ic_key_usage_t;

// SM2椭圆曲线点
typedef struct {
    uint8_t x[SM2_CURVE_NIST_P256 / 8];
    uint8_t y[SM2_CURVE_NIST_P256 / 8];
} sm2_ec_point_t;

// SM2私钥
typedef struct {
    uint8_t d[SM2_CURVE_NIST_P256 / 8];
} sm2_private_key_t;

// 裁剪后的隐式证书结构
typedef struct {
    sm2_ic_cert_type_t type;           // 证书类型
    uint64_t serial_number;            // 序列号
    uint8_t subject_id[MAX_SUBJECT_ID_LEN];  // 主体ID
    size_t subject_id_len;             // 主体ID长度
    uint8_t issuer_id[MAX_ISSUER_ID_LEN];    // 颁发者ID
    size_t issuer_id_len;              // 颁发者ID长度
    uint64_t valid_from;               // 有效期开始时间戳
    uint64_t valid_duration;           // 有效期持续时间（秒）
    uint8_t key_usage;                 // 密钥用途
    sm2_ec_point_t public_recon_key;   // 公钥重构值V
} sm2_implicit_cert_t;

// 证书请求结构
typedef struct {
    sm2_ec_point_t temp_public_key;    // 临时公钥X
    uint8_t subject_id[MAX_SUBJECT_ID_LEN];  // 主体ID
    size_t subject_id_len;             // 主体ID长度
    uint8_t key_usage;                 // 密钥用途
} sm2_ic_cert_request_t;

// 证书生成结果结构
typedef struct {
    sm2_implicit_cert_t cert;          // 隐式证书
    uint8_t private_recon_value[SM2_CURVE_NIST_P256 / 8];  // 私钥重构值S
} sm2_ic_cert_result_t;

// 函数声明

/**
 * @brief 生成随机数
 * @param buf 输出缓冲区
 * @param len 缓冲区长度
 * @return 成功返回SM2_IC_SUCCESS，失败返回错误码
 */
sm2_ic_error_t sm2_ic_generate_random(uint8_t *buf, size_t len);

/**
 * @brief 计算SM3哈希
 * @param input 输入数据
 * @param input_len 输入数据长度
 * @param output 输出哈希值（SM3_DIGEST_LENGTH字节）
 * @return 成功返回SM2_IC_SUCCESS，失败返回错误码
 */
sm2_ic_error_t sm2_ic_sm3_hash(const uint8_t *input, size_t input_len, uint8_t *output);

/**
 * @brief SM2椭圆曲线点乘
 * @param point 输出点
 * @param scalar 标量
 * @param scalar_len 标量长度
 * @param base_point 基点（NULL表示使用SM2默认基点G）
 * @return 成功返回SM2_IC_SUCCESS，失败返回错误码
 */
sm2_ic_error_t sm2_ic_sm2_point_mult(sm2_ec_point_t *point, const uint8_t *scalar, size_t scalar_len, const sm2_ec_point_t *base_point);

/**
 * @brief SM2椭圆曲线点加
 * @param result 结果点
 * @param point1 第一个点
 * @param point2 第二个点
 * @return 成功返回SM2_IC_SUCCESS，失败返回错误码
 */
sm2_ic_error_t sm2_ic_sm2_point_add(sm2_ec_point_t *result, const sm2_ec_point_t *point1, const sm2_ec_point_t *point2);

/**
 * @brief 比较两个SM2椭圆曲线点是否相等
 * @param point1 第一个点
 * @param point2 第二个点
 * @return 相等返回true，否则返回false
 */
bool sm2_ic_sm2_point_equal(const sm2_ec_point_t *point1, const sm2_ec_point_t *point2);

/**
 * @brief 创建证书请求
 * @param request 输出证书请求
 * @param subject_id 主体ID
 * @param subject_id_len 主体ID长度
 * @param key_usage 密钥用途
 * @param temp_private_key 输出临时私钥
 * @return 成功返回SM2_IC_SUCCESS，失败返回错误码
 */
sm2_ic_error_t sm2_ic_create_cert_request(sm2_ic_cert_request_t *request, const uint8_t *subject_id, size_t subject_id_len, uint8_t key_usage, sm2_private_key_t *temp_private_key);

/**
 * @brief CA生成隐式证书
 * @param result 输出证书生成结果
 * @param request 证书请求
 * @param issuer_id 颁发者ID
 * @param issuer_id_len 颁发者ID长度
 * @param ca_private_key CA私钥
 * @param ca_public_key CA公钥
 * @return 成功返回SM2_IC_SUCCESS，失败返回错误码
 */
sm2_ic_error_t sm2_ic_ca_generate_cert(sm2_ic_cert_result_t *result, const sm2_ic_cert_request_t *request, const uint8_t *issuer_id, size_t issuer_id_len, const sm2_private_key_t *ca_private_key, const sm2_ec_point_t *ca_public_key);

/**
 * @brief 设备重构私钥和公钥
 * @param private_key 输出最终私钥
 * @param public_key 输出最终公钥
 * @param cert_result 证书生成结果
 * @param temp_private_key 临时私钥
 * @param ca_public_key CA公钥
 * @return 成功返回SM2_IC_SUCCESS，失败返回错误码
 */
sm2_ic_error_t sm2_ic_reconstruct_keys(sm2_private_key_t *private_key, sm2_ec_point_t *public_key, const sm2_ic_cert_result_t *cert_result, const sm2_private_key_t *temp_private_key, const sm2_ec_point_t *ca_public_key);

/**
 * @brief 验证隐式证书
 * @param cert 隐式证书
 * @param public_key 重构的公钥
 * @param ca_public_key CA公钥
 * @return 成功返回SM2_IC_SUCCESS，失败返回错误码
 */
sm2_ic_error_t sm2_ic_verify_cert(const sm2_implicit_cert_t *cert, const sm2_ec_point_t *public_key, const sm2_ec_point_t *ca_public_key);

/**
 * @brief CBOR编码隐式证书
 * @param output 输出编码后的字节串
 * @param output_len 输出缓冲区长度/实际编码长度
 * @param cert 隐式证书
 * @return 成功返回SM2_IC_SUCCESS，失败返回错误码
 */
sm2_ic_error_t sm2_ic_cbor_encode_cert(uint8_t *output, size_t *output_len, const sm2_implicit_cert_t *cert);

/**
 * @brief CBOR解码隐式证书
 * @param cert 输出解码后的隐式证书
 * @param input 输入编码后的字节串
 * @param input_len 输入字节串长度
 * @return 成功返回SM2_IC_SUCCESS，失败返回错误码
 */
sm2_ic_error_t sm2_ic_cbor_decode_cert(sm2_implicit_cert_t *cert, const uint8_t *input, size_t input_len);

#endif  // SM2_IMPLICIT_CERT_H