# TinyPKI

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/Language-C11-orange.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()
[![Build](https://img.shields.io/badge/Build-CMake-brightgreen.svg)]()

<p align="center">
  <img src="https://img.shields.io/badge/TinyPKI-black?style=for-the-badge&logo=c&logoColor=white" alt="TinyPKI Logo">
  <br>
  <span style="font-size:16px">
    <b>TinyPKI</b> 是一个纯 C11 实现的极轻量级、高安全的公钥基础设施（PKI）原型系统。基于 OpenSSL 3.0 EVP 接口与完整的国密算法套件（SM2/SM3/SM4），专为<b>极度资源受限的物联网 (IoT)</b> 场景设计。
  </span>
</p>

---

## 🌟 核心理念与亮点

传统 X.509 PKI 体系在由于证书体积庞大、撤销列表查询开销高，往往难以在嵌入式系统或窄带无线电环境中落地。TinyPKI 通过以下两大核心技术彻底重构了设备认证链路：

**1. 极轻量隐式证书 (ECQV)**
- 摒弃了传统的 X.509 DER 编码，采用 Elliptic Curve Qu-Vanstone (ECQV) 隐式证书模型。
- 结合极简的 CBOR 二进制序列化，单张设备的身份证书被极限压缩至 **~67 字节**（相较于标准 X.509 缩小约 90%）。

**2. Merkle 累加器与零存储撤销**
- **设备端零存储**：轻量节点无需在本地维护任何状态，只需凭借一个由 CA 签名的 32 字节根哈希即可开始验证。
- **可验证查询证明**：当节点查询证书撤销状态时，服务端返回具备密码学防伪造的 Merkle Proof（Membership / Non-membership）。设备自行验真，节点无法欺骗。
- **k-匿名隐私保护**：设备发起的查询会被 SM3-PRNG 安全洗牌，混入 k-1 个诱饵序列号，确保服务端无法分析出设备的真实交互轨迹。
- **大并发压缩增强**：首创 Multi-Proof 结构压缩算法，支持批量混淆查询时的哈希分支去重，节省最高 70% 的下行带宽。

## 📂 架构与目录结构

整个库采用严格的模块化 C11 开发，零第三方逻辑混入，内存安全与生命周期边界清晰：

```text
TinyPKI/
├── include/                   # 核心公开 API 头文件
│   └── sm2ecqv/               # 对外暴露的业务逻辑接口
├── src/
│   ├── ecqv/                  # ECQV 隐式证书签发与从构建引擎
│   ├── revoke/                # 【核心】Merkle 树累加器与撤销证明引擎
│   │   ├── merkle.c           # Merkle 树构建、成员/非成员证明生成与验证
│   │   ├── merkle_cbor.c      # 面向网络传输的 CBOR 紧凑编解码实现
│   │   ├── merkle_epoch.c     # Epoch 目录切分、热补丁 (Hot Patch) 与分层缓存
│   │   ├── merkle_k_anon.c    # k-匿名混淆查询、风险评估、PRNG 策略
│   │   └── revoke.c           # 高吞吐 P2P 信任评估矩阵、路由调配与共识
│   ├── auth/                  # 证书认证、预计算并发验证、SM4 AEAD 会话协商
│   ├── pki/                   # CA 签发服务端逻辑与终端 Client 状态机
│   └── app/                   # 使用 TinyPKI 库编写的演示入口
├── tests/                     # 覆盖超过 75+ 用例的全量 CTest 套件 (含负面/边界测试)
├── CMakeLists.txt             # 现代 CMake 跨平台构建脚本
└── Makefile                   # 通用快捷构建包装
```

---

## 🚀 快速开始与构建

### 环境要求
- 兼容 C11 标准的编译器（`gcc` / `clang` / `msvc` / 集成环境自带 `MinGW-w64` 等）
- `CMake >= 3.14`
- `OpenSSL >= 3.0` (推荐配置于系统路径或手工指定 `OPENSSL_ROOT_DIR`)

### 一键构建命令 (以 Windows/MinGW 为例)

```bash
# 生成 Ninja 或 MinGW Makefile 工程 (可依据本地环境更改 -G 参数)
cmake -S . -B build_local -DCMAKE_BUILD_TYPE=Release -G "MinGW Makefiles"

# 并发编译整个项目
cmake --build build_local -j 4

# 执行 CTest 集成测试框架
ctest --test-dir build_local --output-on-failure

# 或者直接运行包含聚合测试结果的可执行文件
./build_local/test_all.exe
```

---

## README 演示测试（可直接运行）

### 演示 1：证书签发 -> 认证验签 -> 吊销拦截
文件：`src/app/demo_test_cert_flow.c`

展示能力：
1. 服务端注册身份并签发隐式证书。
2. 客户端导入证书并完成签名验签。
3. 服务端吊销后，验证链路被正确阻断。

运行：
```bash
cmake --build build_local --target sm2_test_cert_flow -j 1
./build_local/sm2_test_cert_flow.exe
```

示例输出：
```text
[OK]   Service Init
[OK]   Identity Register
[OK]   Cert Request
[OK]   Cert Issue
[OK]   Client Init
[OK]   Verify Before Revoke
[OK]   Revoke Cert
[OK]   Revoke Check
[OK]   Verify After Revoke blocked as expected
[PASS] demo_test_cert_flow
```

### 演示 2：Merkle 证明 + Multi-Proof 压缩 + k-匿名风险
文件：`src/app/demo_test_merkle_flow.c`

展示能力：
1. 构建 Merkle 累加器并验证 member/non-member 证明。
2. 将 k-匿名查询打包为 Multi-Proof 并验证。
3. 输出单证明总字节与 Multi-Proof 字节，量化带宽压缩收益。
4. 输出 k-匿名风险评分与跨度指标。

运行：
```bash
cmake --build build_local --target sm2_test_merkle_flow -j 1
./build_local/sm2_test_merkle_flow.exe
```

示例输出：
```text
[OK]   Build Merkle Tree
[OK]   Verify Member Proof
[OK]   Verify Non-Member Proof
[OK]   Build K-Anon Query
[OK]   Verify Multi-Proof
[METRIC] single_total=xxxx bytes, multiproof=xxxx bytes, reduction=xx.xx%
[METRIC] k=16, real_index=x, span=xxx, risk=0.xxxxxx
[PASS] demo_test_merkle_flow
```

## English Summary
TinyPKI is a C11 lightweight PKI prototype based on OpenSSL EVP.

Current revocation path is Merkle-only, featuring:
- verifiable membership/non-membership proofs,
- multiproof bandwidth reduction,
- k-anonymity query packaging.

Quick start:
```bash
cmake -S . -B build_local -DCMAKE_BUILD_TYPE=Release
cmake --build build_local -j 1
ctest --test-dir build_local --output-on-failure
./build_local/test_all.exe
```
