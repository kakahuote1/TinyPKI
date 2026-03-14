# TinyPKI: Lightweight & Resilient PKI for Constrained Environments

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/Language-C11-orange.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()
[![Build](https://img.shields.io/badge/Build-CMake-brightgreen.svg)]()

[**English Summary**](#english-summary) | [**快速开始**](#-快速开始-getting-started) | [**演示与测试**](#-场景演示-demos) | [**项目文档**](#-文档与接口-documentation--api)

TinyPKI 是一个专为Iot资源受限场景打造的高性能、轻量级公开密钥基础设施 C11 核心库。

本项目基于 OpenSSL EVP 架构与国密算法族（SM2/SM3/SM4）深度定制，跳出了传统大体量 X.509 体系的包袱，原生提供 ECQV 隐式证书、CA 签名的 Merkle 撤销根、携带式非吊销证明以及同步能力。

无论是微控制器、智能网关还是需要极高并发吞吐的服务端集群，TinyPKI 都能提供开箱即用、安全且极简的集成体验。

---

## ✨ 核心特性 (Key Features)

本项目具备以下四大核心应用价值：

* 🪶 **“轻量级”证书，专为弱网与物联网设计**
  
  传统数字证书动辄上千字节，在 NB-IoT、LoRa 等窄带网络中传输极其耗时。本项目采用基于国密算法的隐式证书（ECQV）技术，将证书体积极限压缩至传统证书的 **30% 以下（仅几十字节）**。极大降低了网络唤醒时间和传输功耗。
* 🌳 **极速且保护隐私的证书吊销校验**
  
  传统的 OCSP 或 CRL 往往存在查询慢、暴露用户隐私行为的缺陷。本项目采用“CA 签名根 + 哈希树 absence proof”机制，由证书持有方在握手时直接携带精确的非吊销证明，对端仅需结合本地缓存的根记录即可**瞬间完成校验**。整个认证过程无需再向第三方在线查询，从而同时降低网络开销并隐藏具体查询目标。
* 🛡️ **抗断网、抗恶意攻击的高可用集群**
  
  在真实的边缘计算场景下，网络离线或部分站点被黑客劫持是常态。本项目内置了分布式容错同步（Anti-Entropy）机制。只要设备能连上少数几个健康的节点，就能自动剔除恶意数据、修复状态，在**极端恶劣和不稳定的网络下依然能可靠提供身份认证服务**。
* ⚡ **开箱即用的“认证即加密”全链路保护**
  
  不再需要复杂的二次开发，提供一站式接入。设备之间可以在双向身份核验的同时，自动协商出一次性“会话密钥”，立刻启动基于国密 SM4 的金融级加密会话机制，杜绝窃听与报文伪造。
* 🏗️ **极致的安全守护与防滥用设计**
  
  代码库严格限制内存占用上限，自带抗网络泛洪攻击保护。不仅运行飞快，而且对错误调用有强防范力，可以直接用于对抗性高、安全性要求严苛的生产环境。

---

## 📦 快速开始 (Getting Started)

### 环境依赖
- **编译器**: 支持 C11 标准（GCC / Clang / MSVC）
- **构建工具**: CMake (>= 3.14)
- **底层密码库**: OpenSSL (>= 3.0)

### 编译构建
TinyPKI 使用极简无侵入式的 CMake 构建体系，您可以将其直接作为子模块（submodule）集成到您的主项目中：

```bash
# 获取源码
git clone https://github.com/kakahuote1/TinyPKI.git
cd TinyPKI

# 生成配置与编译
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4
```

构建完成后，主库静态目标 `tinypki` 即已就绪。您可在自己的 `CMakeLists.txt` 中通过 `target_link_libraries(your_app PRIVATE tinypki)` 直接引用。

---

## 🚀 场景演示 (Demos)

项目中内置了贴近真实业务场景的演练程序，助您快速理解核心 PKI 交互流。编译完毕后可直接执行：

**1. 证书生命周期主链路 (签发/认证/双向加密/撤销拦截)**
```bash
cmake --build build --target sm2_test_cert_flow -j 4
./build/sm2_test_cert_flow.exe
```

**2. Merkle 撤销证明与批量压缩性能模拟**
```bash
cmake --build build --target sm2_test_merkle_flow -j 4
./build/sm2_test_merkle_flow.exe
```

---

## 🧪 测试验证 (Testing)

TinyPKI 实施 100% 测试覆盖策略（含网络欺骗、负面边界截断、BFT故障转移等 130+ 实战用例）。

**运行全量自动化集成测试：**
```bash
ctest --test-dir build --output-on-failure
```

**聚合命令行直观输出验证：**
```bash
./build/test_all.exe
```
> 为方便审计与排查，完整的测试已按领域拆分。您可单独执行 `suite_ecqv` (证书构造)、`suite_revoke` (BFT集群防伪同步)、`suite_auth` (会话建立)、`suite_merkle` (哈希树证明与压缩) 等套件模块。

---

## 📖 文档与接口 (Documentation & API)

公开安全接口采用单一、清晰明了的命名空间设定。接入时，只需包含需要引用业务能力的对应头文件即可：

* `include/sm2_implicit_cert.h`: 证书物理结构与编解码规则定义
* `include/sm2_revocation.h` / `sm2_revocation_sync.h`: 撤销池生命周期维度与分布式 BFT 状态维护
* `include/sm2_auth.h`: 身份鉴权验证与会话加密密钥托管
* `include/sm2_crypto.h`: 底层通用密码学安全门限封装
* `include/sm2_pki_service.h` / `sm2_pki_client.h`: 面向 CA 服务端 / IoT 设备的全局流程 API (全 Opaque Handle 隔离)


---

## 🌍 English Summary

**TinyPKI** is a high-performance, C11-based PKI core framework specifically engineered for resource-constrained environments (such as IoT and edge computing nodes). Built on top of the OpenSSL EVP architecture and integrating the Chinese Commercial Cryptographic algorithms (SM2/SM3/SM4), it delivers:

- **ECQV Implicit Certificates** designed for drastically reduced network transmission payloads compared to conventional X.509.
- **CA-Signed Merkle Roots plus Proof-Carrying Non-Revocation Evidence** enabling exact offline revocation checks with low bandwidth and no third-party query exposure during authentication.
- **BFT State Synchronization (Anti-Entropy)** mechanism ensuring robust consistency across decentralized edge nodes facing hostile environments, routing overrides, and temporal disconnectivity.
- **Mutual Authentication & AEAD** session protection seamlessly bundled into one resilient pipeline utilizing SM4-GCM/CCM encryption.
- **Misuse-Resistant Architecture** leveraging rigorous memory upper-boundaries and purely opaque contexts. Over 130+ rigorous unit & Byzantine integration edge-case tests (`test_all`) ensure flawless deployment in production from day one.

## 📄 开源许可证 (License)

本项目遵循自由、开源协议基准，采用 [Apache License 2.0](LICENSE) 授权。
