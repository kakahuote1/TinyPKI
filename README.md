# TinyPKI: Lightweight & Resilient PKI for Constrained Environments

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/Language-C11-orange.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()
[![Build](https://img.shields.io/badge/Build-CMake-brightgreen.svg)]()

[**English Summary**](#english-summary) | [**快速开始**](#-快速开始-getting-started) | [**演示与测试**](#-场景演示-demos) | [**项目文档**](#-文档与接口-documentation--api)

TinyPKI 是一个面向 IoT 资源受限、弱网与边缘节点场景的轻量 PKI C11 核心库，覆盖证书签发、吊销证明、认证与会话保护等主链路能力。

本项目基于 OpenSSL EVP 架构与国密算法族（SM2/SM3/SM4）实现，围绕 ECQV 隐式证书构建，并原生提供 CA 签名的 Merkle 撤销根、携带式非吊销证明、强制发证透明证明、撤销状态同步以及面向 service/client 的高层 PKI API。

无论是微控制器、智能网关，还是需要本地化吊销校验与安全会话建立的边缘服务组件，TinyPKI 都能提供较低集成成本且接口清晰的实现基础。

---

## ✨ 核心特性 (Key Features)

本项目具备以下几类核心能力：

* 🪶 **“轻量级”证书，专为弱网与物联网设计**
  
  传统数字证书动辄上千字节，在 NB-IoT、LoRa 等窄带网络中传输成本很高。本项目采用基于国密算法的隐式证书（ECQV）技术，提供请求生成、CA 签发、终端侧公私钥重构与证书一致性验证的完整链路，显著降低证书载荷与设备侧处理负担。当前仓库内 benchmark 快照下，ECQV 隐式证书编码为 `79 bytes`，对照本机生成的 X.509 DER 基线 `691 bytes`，约为其 `11.43%`。
* 🌳 **极速且保护隐私的证书吊销校验**

  传统的 OCSP 或 CRL 往往带来额外在线查询和隐私暴露。本项目采用“CA 签名根记录 + Merkle member/absence proof”机制，由证书持有方在认证时直接携带精确的非吊销证明，对端结合本地缓存根记录即可完成离线校验，并支持根记录刷新与携带式证据导出。
* 🔎 **强制发证透明与边缘见证门限**

  高层 `sm2_pki_verify()` 默认要求每个对端同时携带 issuance transparency evidence。CA 侧维护按签发顺序追加的 32-byte 证书承诺 Merkle log，验证端检查成员证明、CA 签名 issuance root，并可通过客户端级 `t-of-n` witness policy 要求多个边缘节点对 root 见证签名。
* 📌 **统一 PKI epoch 证据包**

  新增 CA 签名的 `epoch root`，将当前吊销 Merkle root 与发证透明 root 绑定成一个检查点；验证端可使用 `sm2_pki_evidence_bundle_t` 一次性验证非吊销证明、发证成员证明和 `t-of-n` witness 签名，witness 签名前会检查 issuance log 的 append-only 演进。
* 🛡️ **面向断网与多节点同步的撤销状态维护**

  在边缘与弱连接场景中，撤销状态往往需要跨节点同步而不是依赖单点在线查询。本项目提供 delta/heartbeat、重定向候选、quorum/BFT 检查以及 epoch/cached proof 相关能力，用于在断网、时钟漂移和部分节点异常时维持撤销状态的一致性与可用性。
* ⚡ **开箱即用的“认证即加密”全链路保护**
  
  项目同时提供静态与临时密钥握手路径。设备可以在双向身份核验、吊销证据校验和用途检查通过后，基于 canonical handshake binding 协商会话密钥，并直接接入 SM4-GCM/CCM 的 AEAD 会话保护。
* 🏗️ **默认安全策略与防误用设计**
  
  公开 API 采用 opaque handle 封装，并在高层流程中默认要求可信 CA、非吊销证据、密钥用途与握手绑定等安全前提；同时提供统一错误映射、显式边界检查以及更易于审计的状态生命周期管理。

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

构建完成后，主库静态目标 `tinypki`、场景 demo、benchmark 与各测试目标即已就绪。您可在自己的 `CMakeLists.txt` 中通过 `target_link_libraries(your_app PRIVATE tinypki)` 直接引用。

---

## 🚀 场景演示 (Demos)

项目中内置了贴近真实业务场景的演练程序，助您快速理解核心 PKI 交互流。编译完毕后可直接执行：

**1. 证书生命周期主链路（签发 / 携带式非吊销证明导出 / 认证 / 撤销拦截）**
```bash
cmake --build build --target sm2_test_cert_flow -j 4
./build/sm2_test_cert_flow.exe
```

**2. Merkle Root Hash、member/absence proof 与 multiproof 压缩演示**
```bash
cmake --build build --target sm2_test_merkle_flow -j 4
./build/sm2_test_merkle_flow.exe
```
---

## 🧪 测试验证 (Testing)

当前仓库测试主链路由 `ctest` 与 `test_all` 两个入口组成。按当前基线，`ctest` 拆分为 6 个 suite，`test_all` 聚合执行 88 个用例。

**运行与 CI 相同的格式检查（固定 clang-format 18）：**
```bash
# Windows PowerShell
./tools/check_format.ps1

# Linux / CI
bash tools/check_format.sh
```

**自动修复格式：**
```bash
# Windows PowerShell
./tools/format.ps1

# Linux / CI
bash tools/format.sh
```

**运行全量自动化集成测试：**
```bash
ctest --test-dir build --output-on-failure
```

**聚合命令行直观输出验证：**
```bash
./build/test_all.exe
```

**运行载荷 / 时延 benchmark：**
```bash
cmake --build build --target sm2_bench_network_overhead -j 4
./build/sm2_bench_network_overhead.exe
```

**输出结构化 benchmark 结果：**
```bash
./build/sm2_bench_network_overhead.exe ./tmp/bench_network_overhead.json
```

**运行能力实验集（revocation scaling / epoch cache / multiproof / delta / Zipf workload）：**
```bash
cmake --build build --target sm2_bench_capability_suite -j 4
./build/sm2_bench_capability_suite.exe
```

**输出结构化能力实验结果（含 revoke publish / client refresh 中位时延摘要）：**
```bash
./build/sm2_bench_capability_suite.exe ./tmp/bench_capability_suite.json
```

> `bench_capability_suite` 目前同时输出三类结果：
> TinyPKI 主链路实测、基于 OpenSSL 本地生成并校验的真实 `CRL/OCSP` 基线、以及参考 CRLite 论文参数的 workload/CRLite 建模对比。
> 当指定 JSON 输出路径时，还会自动生成同名 `.md` 表格报告，便于直接查看和写材料。

> 为方便审计与排查，完整测试已按领域拆分。当前可单独执行：
> `suite_ecqv`（隐式证书构造与验证）、
> `suite_revoke`（撤销同步与 BFT 路径）、
> `suite_auth`（认证与会话保护）、
> `suite_pki`（服务端 / 客户端主流程与安全策略）、
> `suite_pki_internal`（PKI 内部一致性与回滚路径）、
> `suite_merkle`（哈希树证明与压缩）。
>
> 例如只运行 PKI 相关测试：
> ```bash
> ctest --test-dir build -R suite_pki --output-on-failure
> ```

---

## 📖 文档与接口 (Documentation & API)

公开安全接口采用清晰一致的命名空间。接入时，可按能力维度包含对应头文件：

* `include/sm2_implicit_cert.h`: ECQV 请求生成、CA 签发、证书验证与终端侧密钥重构
* `include/sm2_revocation.h`: Merkle 根记录、member/absence proof、multiproof、epoch 缓存与撤销同步/BFT 辅助能力
* `include/sm2_pki_transparency.h`: 发证透明 proof、统一 epoch root、witness 签名与 `t-of-n` 见证策略类型
* `include/sm2_auth.h`: 认证请求校验、revocation policy、握手绑定、双向握手与 AEAD 会话保护
* `include/sm2_crypto.h`: 底层签名、验签、随机数、哈希、AEAD 以及统一 PKI 错误映射
* `include/sm2_pki_service.h` / `sm2_pki_client.h`: 面向内存态 CA/RA 服务端与设备侧客户端的高层流程 API（Opaque Handle 隔离）


---

## 🌍 English Summary

**TinyPKI** is a lightweight C11 PKI core for constrained IoT, weakly connected, and edge deployment scenarios. Built on top of OpenSSL EVP with SM2/SM3/SM4, it provides end-to-end flows for ECQV implicit certificates, CA-signed Merkle revocation roots, mandatory issuance transparency evidence, proof-carrying non-revocation evidence, and high-level PKI/auth/session APIs.

- **ECQV Implicit Certificate Flows** covering request generation, CA issuance, endpoint key reconstruction, and certificate verification with substantially smaller payloads than conventional X.509.
- **Measured Footprint Snapshot**: the current in-repo benchmark reports a `79-byte` ECQV implicit certificate versus a `691-byte` X.509 DER baseline. With mandatory issuance transparency evidence included, the full authentication bundle is `4140 bytes` and the compact-root bundle is `4060 bytes`.
- **CA-Signed Merkle Revocation Roots and Carried Proofs** supporting exact offline non-revocation checks via member/absence proofs and cached root records.
- **Mandatory Issuance Transparency and Unified Epoch Evidence** using 32-byte certificate commitments, a CA-signed epoch root that binds issuance and revocation roots, and client-level `t-of-n` edge witness policies.
- **Revocation State Sync Tooling** including delta/heartbeat refresh, redirect hints, quorum/BFT helpers, multiproof compression, and epoch/cached proof support.
- **Mutual Authentication and Secure Sessions** spanning static or ephemeral key agreement, canonical handshake binding, key-usage enforcement, and SM4-GCM/CCM AEAD protection.
- **Misuse-Resistant High-Level APIs** built around opaque handles, secure defaults, unified error mapping, and a current automated test baseline of 88 cases across `ctest` and `test_all`.

## 📄 开源许可证 (License)

本项目遵循自由、开源协议基准，采用 [Apache License 2.0](LICENSE) 授权。
