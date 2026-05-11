# Kage: Professional PHP Bytecode Protection & Obfuscation System

Kage is an enterprise-grade security extension for PHP 7.4+ designed to protect intellectual property through multi-layered bytecode virtualization and native-level hardening. Unlike traditional obfuscators, Kage operates at the Zend Engine level, ensuring that your source code never touches the disk or memory in plaintext.

[![Security Level: Enterprise](https://img.shields.io/badge/Security-Enterprise-red.svg)](#)
[![PHP Version: 7.4+](https://img.shields.io/badge/PHP-7.4+-blue.svg)](#)
[![Hardening: VMPacker](https://img.shields.io/badge/Hardening-VMPacker-orange.svg)](#)

---

## 🛡️ Multi-Layered Defense Architecture

Kage implements a "Defense in Depth" strategy, combining several proprietary technologies to thwart reverse engineering:

### 1. Bytecode Virtualization (Phase 3 & 6)
- **Dynamic ISA (Per-file Mapping)**: Every protected file uses a unique, randomized Opcode instruction set. A `ZEND_ECHO` in File A might be `0x4A`, while in File B it is `0xFF`. This makes mass-analysis and universal decoders impossible.
- **Control Flow Flattening (CFF)**: The execution graph is scrambled. Jump targets (if/else, loops) are XOR-encrypted and manually re-linked in memory JIT, preventing logic reconstruction via opcode dumpers.
- **Recursive Protection**: Automatically secures the main script, nested functions, closures, and class methods within the same file.

### 2. Data & Variable Obfuscation (Phase 3.3)
- **Literal Hiding**: Constant strings and long integers are XOR-encrypted at compile time.
- **Variable Name Masking**: All local variable names in the `op_array->vars` table are encrypted, hiding them from debuggers, stack traces, and reflection tools.

### 3. Native Hardening (VMPacker Strategy A)
- **Protector Protection**: The core logic of the Kage extension (`kage.so`) is itself protected via native-level virtualization.
- **Hidden Decryption Logic**: Functions like `kage_raw_decrypt` and `kage_get_machine_id` are transformed into a custom VM-bytecode, making the binary a "black box" even for IDA Pro or Ghidra experts.

### 4. Environment Binding (Phase 4)
- **HWID Machine Lock**: Cryptographically bind scripts to a specific server's hardware fingerprint (Linux/macOS).
- **Anti-Debugging Environment**: Detects and blocks execution in environments with VLD, Xdebug, or other analysis tools enabled.
- **Integrity Check**: Payloads are verified via CRC32 in the professional header before execution.

---

## 🚀 Performance: Zero Overhead JIT

Kage utilizes a high-performance **"One-Opcode Intercept"** strategy:
1. Only the first instruction of a protected function is hooked via a `ZEND_NOP` carrier.
2. Upon the **first call**, Kage unprotects the function in memory and restores native Zend handlers.
3. Subsequent executions run at **100% native PHP speed** with zero overhead.

---

## 📦 Installation & Usage

### 1. Requirements
- PHP 7.4 (Zend Engine 3.4)
- libsodium (for military-grade encryption)
- Docker (for building the hardened artifacts)

### 2. Using the Protected Artifact
We recommend using the pre-built hardened loader:
```bash
# 1. Copy the artifact to your extensions directory
cp artifacts/kage_protected.so /usr/lib/php/20190902/kage.so

# 2. Add to your php.ini
extension=kage.so
kage.encryption_key = "your_32_char_master_key_here"
```

### 3. Encrypting Files (Developer API)
```php
<?php
// Get the unique ID of the target server
$hwid = kage_get_machine_id();

// Encrypt source code with HWID lock and Dynamic ISA
$code = file_get_contents('source.php');
$key = "0123456789abcdef0123456789abcdef"; // 32 chars
$encrypted_base64 = kage_encrypt_c($code, $key, $hwid);

file_put_contents('protected.kage', base64_decode($encrypted_base64));
```

---

## 🛠️ Project Structure
- `/c_extension`: Source code of the C extension.
- `/packer/VMPacker`: Submodule for native binary virtualization.
- `/artifacts`: Pre-built, VMP-hardened binaries for production.
- `/tests`: Comprehensive security verification suite.

---

## 📜 License
This software is proprietary. All rights reserved. Unauthorized copying, modification, or distribution is strictly prohibited.
