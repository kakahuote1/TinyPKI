# SM2隐式证书轻量化PKI系统

## 项目概述

本项目实现了基于国密SM2算法的隐式证书轻量化PKI系统，面向航空系统资源受限的特点，提供高效、安全的证书管理方案。

## 项目结构

```
sm2/
├── include/                  # 头文件目录
│   └── sm2_implicit_cert.h  # 核心头文件，定义数据结构和接口
├── src/                     # 源文件目录
│   ├── sm2_implicit_cert.c  # 核心实现文件
│   └── main.c               # 示例程序
├── doc/                     # 文档目录
├── Makefile                 # 编译脚本
└── README.md                # 项目说明文件
```

## 核心功能

### 1. 基于ECQV的隐式证书生成
- 支持SM2曲线上的ECQV隐式证书协议
- 实现证书请求、证书生成、证书接收与密钥重构流程

### 2. 轻量化证书结构
- 裁剪传统X.509证书的冗余字段
- 仅包含必要的元数据和公钥重构值
- 预计证书大小可降至显式证书的约30%

### 3. 高效密钥管理
- 隐式证书无需存储完整公钥
- 通过密钥重构机制恢复最终密钥对
- 支持证书验证和公钥验证

### 4. CBOR紧凑编码
- 支持CBOR编码和解码隐式证书
- 减少证书传输和存储开销

## 接口说明

### 证书请求与生成
```c
// 创建证书请求
sm2_ic_error_t sm2_ic_create_cert_request(sm2_ic_cert_request_t *request, const uint8_t *subject_id, size_t subject_id_len, uint8_t key_usage, sm2_private_key_t *temp_private_key);

// CA生成隐式证书
sm2_ic_error_t sm2_ic_ca_generate_cert(sm2_ic_cert_result_t *result, const sm2_ic_cert_request_t *request, const uint8_t *issuer_id, size_t issuer_id_len, const sm2_private_key_t *ca_private_key, const sm2_ec_point_t *ca_public_key);
```

### 密钥重构与验证
```c
// 重构私钥和公钥
sm2_ic_error_t sm2_ic_reconstruct_keys(sm2_private_key_t *private_key, sm2_ec_point_t *public_key, const sm2_ic_cert_result_t *cert_result, const sm2_private_key_t *temp_private_key, const sm2_ec_point_t *ca_public_key);

// 验证隐式证书
sm2_ic_error_t sm2_ic_verify_cert(const sm2_implicit_cert_t *cert, const sm2_ec_point_t *public_key, const sm2_ec_point_t *ca_public_key);
```

### CBOR编解码
```c
// CBOR编码隐式证书
sm2_ic_error_t sm2_ic_cbor_encode_cert(uint8_t *output, size_t *output_len, const sm2_implicit_cert_t *cert);

// CBOR解码隐式证书
sm2_ic_error_t sm2_ic_cbor_decode_cert(sm2_implicit_cert_t *cert, const uint8_t *input, size_t input_len);
```

## 编译与运行

### 编译项目

```bash
# 使用gcc编译
gcc -Wall -Wextra -I./include src/sm2_implicit_cert.c src/main.c -o sm2_implicit_cert_demo

# 或使用Makefile
make
```

### 运行示例

```bash
./sm2_implicit_cert_demo
```

## 示例流程

1. **CA初始化**：生成CA密钥对
2. **设备侧**：创建证书请求（生成临时密钥对）
3. **CA侧**：生成隐式证书和私钥重构值
4. **设备侧**：重构最终密钥对
5. **验证**：验证证书和公钥的有效性
6. **CBOR编解码**：演示证书的CBOR编码和解码

## 技术特点

### 轻量化设计
- 证书结构裁剪，去除冗余字段
- 隐式证书无需存储完整公钥
- CBOR紧凑编码，减少传输和存储开销

### 安全性
- 基于SM2椭圆曲线密码算法
- 遵循ECQV隐式证书协议
- 支持证书验证和公钥验证

### 可扩展性
- 模块化设计，易于集成到现有系统
- 支持密钥用途扩展
- 可扩展支持在线/离线证书撤销管理

## 注意事项

1. **安全随机数**：当前实现使用时间作为随机源，实际应用中应替换为安全随机数生成器
2. **密码算法**：当前实现中的SM2和SM3算法为示例实现，实际应用中应替换为标准实现
3. **CBOR编解码**：当前实现为简化版本，实际应用中应使用标准CBOR库

## 后续扩展

1. 实现完整的SM2和SM3国密算法
2. 集成标准CBOR库
3. 实现在线/离线相结合的证书撤销管理机制
4. 实现基于预计算和批处理的高效身份认证方法
5. 提供更完善的测试用例和文档

## 联系方式

如有问题或建议，请联系项目维护人员。