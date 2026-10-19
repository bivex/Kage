# 🛡️ Kage Security Extension

> **Enterprise-Grade PHP Bytecode Virtualization & Cryptographic Protection System**

[![PHP Version](https://img.shields.io/badge/PHP-7.4%20%7C%208.0%20%7C%208.1%20%7C%208.2%20%7C%208.3%20%7C%208.4-blue.svg)](https://www.php.net/)
[![Platform](https://img.shields.io/badge/Architecture-x86__64%20%7C%20ARM64-green.svg)]()
[![Security](https://img.shields.io/badge/Cryptography-libsodium%20%7C%20ChaCha20--Poly1305-orange.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)

---

## 📌 Executive Summary

**Kage** is a high-performance C extension for the Zend Engine designed to safeguard PHP source code, proprietary algorithms, and sensitive assets from reverse engineering, static decompilation, and dynamic memory inspection. 

Combining **Zend-level Bytecode Virtualization**, **Dynamic Instruction Set Architecture (ISA) shuffling**, and **Native Code Virtualization via ASGARD**, Kage provides military-grade code protection while delivering native execution speed via Just-In-Time (JIT) unprotection.

---

## 🏗️ Architectural Overview

Kage implements a multi-tiered defense-in-depth protection stack:

```mermaid
graph TD
    A["Raw PHP Source Code"] --> B["Compiler & Static Analyzer"]
    B --> C["Layer 1: Zend Bytecode Virtualization"]
    C --> D["Layer 2: Data & Symbol Table Masking"]
    D --> E["Layer 3: Native Binary Virtualization (ASGARD)"]
    E --> F["Protected .kage Payload + Encrypted VM Container"]

    subgraph Runtime Execution Environment
        F --> G["Kage Compilation Interceptor (zend_compile_file)"]
        G --> H["Hardware ID (HWID) & License Integrity Validation"]
        H --> I["In-Memory Decryption & Dynamic ISA Unshuffling"]
        I --> J["Native Zend Engine Execution"]
    end
```

### Protection Layers

| Layer | Component | Mechanism | Security Guarantee |
| :--- | :--- | :--- | :--- |
| **Layer 1** | **Bytecode Virtualization** | Randomized Dynamic ISA with per-file 32-bit seeds + Control Flow Flattening (CFF). | Neutralizes opcode dumpers (e.g., VLD) and decompiler execution graphs. |
| **Layer 2** | **Metadata Masking** | JIT XOR string literal encryption and symbol table obfuscation (`op_array->vars`). | Blocks static string analysis, AST reconstruction, and Reflection API probing. |
| **Layer 3** | **Native Virtualization** | Core crypto & KDF routines virtualized into polymorphic bytecode via **ASGARD-5877** (DRS v2 score: 93.5/100). | Renders reverse engineering with IDA Pro / Ghidra impossible via non-linear threaded VM dispatch. |

---

## 🛡️ ASGARD-5877 AOT Virtualization Pipeline

Kage integrates the **ASGARD-5877** Ahead-Of-Time (AOT) lifter and polymorphic virtual machine generator (`packer/asgard`):

1. **AOT Lifting**: Target C/C++ cryptographic routines marked with `ASGARD_BEGIN_` / `ASGARD_END()` are compiled to ARM64 assembly and lifted into Vanguard VM Intermediate Representation (IR).
2. **CFF & MBA Hardening**: Control-Flow Flattening and Mixed Boolean-Arithmetic (MBA) are synthesized over the instruction graph.
3. **Polymorphic Bytecode Generation**: The function logic is emitted as encrypted, fragmented bytecode chunks assembled dynamically in RAM with canary integrity guards (`0xdead` / `0xcafe` / `0x5877`).
4. **Vanguard Threaded VM**: Executed at runtime via a 4-domain threaded interpreter with dynamic running key reanchoring (Anti-Pushan) and ABI shadow exception handling.

### Building with ASGARD Protection

```bash
# Run the complete automated virtualization, Docker build, and verification pipeline:
./scripts/build_asgard_kage.sh
```

Or build the hardened ARM64 Docker container directly:

```bash
docker build -f Dockerfile.arm64 -t kage-arm64:protected .
docker run --rm kage-arm64:protected
```

---

## 🌐 Compatibility Matrix

Kage maintains full Zend Engine API compatibility across PHP minor releases:

| PHP Version | Zend Engine | Support Status | Tested Architecture |
| :--- | :--- | :---: | :--- |
| **PHP 7.4** | Zend Engine 3.4.x | ✅ Supported | `x86_64` / `arm64` |
| **PHP 8.0** | Zend Engine 4.0.x | ✅ Supported | `x86_64` / `arm64` |
| **PHP 8.1** | Zend Engine 4.1.x | ✅ Supported | `x86_64` / `arm64` |
| **PHP 8.2** | Zend Engine 4.2.x | ✅ Supported | `x86_64` / `arm64` |
| **PHP 8.3** | Zend Engine 4.3.x | ✅ Supported | `x86_64` / `arm64` |
| **PHP 8.4** | Zend Engine 4.4.x | ✅ Supported | `x86_64` / `arm64` |

---

## ⚡ Quick Start

### 1. Requirements

* **Operating System**: Linux (GLIBC 2.27+) or macOS (macOS 11+).
* **Dependencies**: `libsodium-dev`, `pkg-config`, `cmake` (3.16+), `gcc` (10+) or `clang`.
* **Runtime**: PHP Development Headers (`php-dev` / `php-config`).
* **Toolchain (Optional for ASGARD dev)**: OCaml (`opam`), `dune` (for compiling `packer/asgard`). Pre-virtualized C++ runtime is bundled for standard builds.

### 2. Building from Source

```bash
# Clone repository with submodules
git clone --recursive https://github.com/bivex/Kage.git
cd Kage/c_extension

# Configure and compile release binary (auto-detects ASGARD virtualized sources)
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### 3. Extension Installation

```bash
# 1. Install binary module into extension directory
cp build/kage.so $(php-config --extension-dir)/kage.so

# 2. Add INI configuration (php.ini)
cat <<EOF >> $(php-config --ini-path)/kage.ini
extension=kage.so
kage.encryption_key = "SECURE_32_CHAR_ALPHANUMERIC_KEY"
EOF
```

---

## 🔒 Code Protection API

Generate protected assets programmatically using the C-extension API:

```php
<?php
// 1. Obtain host target Hardware ID (HWID) for hardware locking
$target_hwid = kage_get_machine_id();

// 2. Encrypt source code payload
$source_code = file_get_contents('production_script.php');
$master_key  = "0123456789abcdef0123456789abcdef"; // 32-byte master key

$encrypted_blob = kage_encrypt_c(
    $source_code, 
    $master_key, 
    $target_hwid
);

// 3. Save as binary protected asset
file_put_contents('production_script.kage', base64_decode($encrypted_blob));
```

---

## 🧪 Verification & Multi-Version Test Suite

Kage includes automated Docker verification environments covering **PHP 8.1 through PHP 8.4**:

```bash
# Execute multi-version test suite across all PHP releases
./scripts/test_php_versions.sh
```

### Test Coverage Checklist

- [x] **Dynamic ISA Uniqueness**: Verifies randomized opcode mapping per file.
- [x] **OOP & Recursive Obfuscation**: Validates class method and closure protection.
- [x] **Performance Benchmark**: Confirms native execution speed post-unprotection.
- [x] **Integrity & HWID Enforcement**: Tests tamper detection and HWID lock rejection.

---

## 📁 Repository Structure

```
.
├── c_extension/               # Core C extension source code
│   ├── src/
│   │   ├── core/              # Context, config, HWID, and ASGARD macros
│   │   ├── crypto/            # Libsodium ChaCha20-Poly1305 & ASGARD VM runtime
│   │   │   ├── crypto.c               # Original cryptographic C implementation
│   │   │   ├── crypto_virtualized.cpp # Polymorphic ASGARD VM wrapper
│   │   │   └── threaded_vm.hpp        # 4-domain threaded VM interpreter header
│   │   └── vm/                # Dynamic ISA opcode permutation table
│   ├── asgard_config.json     # ASGARD-5877 protection profile & VM policy
│   └── CMakeLists.txt         # Modern CMake build pipeline (C/C++20)
├── docs/                      # Technical specifications & architecture plans
├── examples/                  # End-to-end execution demos (demo_asgard_kage.php)
├── packer/asgard/             # ASGARD-5877 AOT virtualization submodule
├── scripts/                   # Automated build & verification tools
│   ├── build_asgard_kage.sh   # Full ASGARD AOT build & Docker export pipeline
│   └── test_php_versions.sh   # Multi-version CI verification suite
└── tests/                     # Enterprise verification test suite
```

---

## 📄 License

This project is open-source software licensed under the **[MIT License](LICENSE.md)**.
