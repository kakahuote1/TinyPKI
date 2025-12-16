# Lightweight ECQV-SM2 SDK for Aviation Systems

A high-performance, autonomous PKI infrastructure library designed for resource-constrained aviation networks (UAV swarms). It implements the **ECQV Implicit Certificate** scheme over **SM2** curves, offering significant bandwidth savings compared to X.509.

---

## Key Features

* **Implicit Certificates (ECQV)**: eliminates explicit signatures and public keys, reducing certificate size by **~85%**.
* **National Standard (SM2/SM3)**: fully compliant with Chinese cryptography standards (GM/T).
* **Point Compression**: optimized storage using 33-byte compressed elliptic curve points.
* **Embedded Friendly**: 
    * Zero-dependency CBOR encoding.
    * Endian-safe hashing for cross-architecture consistency (x86/ARM).
    * Modular design suitable for RTOS/Bare-metal.

## Project Structure

```bash
├── include/
│   └── sm2_implicit_cert.h   # API Contracts & Data Structures
├── src/
│   ├── sm2_implicit_cert.c   # Core Logic (ECQV, CBOR, Math)
│   ├── main.c                # Demo Application
│   └── test_suite.c          # Unit Tests & Benchmarks
└── Makefile                  # Build Script
```

## Quick Start

### Prerequisites

- GCC / MinGW
- OpenSSL Development Libraries (`libssl-dev`)

### Build & Run

```bash
# Build the demo
make

# Run the demo (Certificate Lifecycle)
make run
```

### Benchmarks

```bash
[PERF] Avg Issuance Time: ~1.2 ms
Certificate Size: < 130 Bytes (vs 1KB X.509)
```

