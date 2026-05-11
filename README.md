# Technical Specification: Kage Security Extension
## Professional PHP Bytecode Protection & Virtualization System

**Project Identification:** Kage (Enterprise Edition)  
**Target Environment:** PHP 7.4 (Zend Engine 3.4.x)  
**Security Standard:** High-Assurance Code Protection  
**Document Compliance:** ISO/IEC 26514:2008 Professional Standard  

---

## 1. Executive Summary
Kage is a high-performance, enterprise-grade PHP extension designed for the cryptographic protection of intellectual property. It implements advanced **Bytecode Virtualization** and **Native Code Hardening** to ensure that PHP source code and execution logic remain fully opaque to static and dynamic analysis.

## 2. Architectural Design Specification
The system utilizes a multi-layered defense architecture, ensuring no single point of failure in the security chain.

### 2.1 Layer 1: Bytecode Virtualization (Zend Level)
- **Dynamic ISA (Instruction Set Architecture)**: Each protected file is compiled into a unique, randomized instruction set based on a per-file 32-bit entropy seed.
- **Control Flow Flattening (CFF)**: The execution graph is scrambled via **Jump Target Obfuscation**. Original jump destinations are XOR-encrypted and dynamically re-linked in memory during runtime.
- **Recursive Logic Hardening**: Automated obfuscation of all child structures, including nested functions, class methods, and anonymous closures.

### 2.2 Layer 2: Data & Metadata Encryption
- **Literal Table Protection**: Constant strings and numeric values are XOR-encrypted at the compiler level and decrypted JIT within protected memory blocks.
- **Symbol Table Masking**: Variable name indices and names in the `op_array->vars` table are obfuscated to prevent information leakage through Reflection API or debuggers.

### 2.3 Layer 3: Native Hardening (VMPacker)
- **Binary Virtualization**: Critical core functions (`kage_raw_decrypt`, `kage_get_machine_id`) are virtualized using **VMPacker**.
- **Interpreter-in-Interpreter**: The C-logic is transformed into custom VM-bytecode, preventing reverse engineering of the decryption algorithms using standard disassemblers (IDA Pro, Ghidra).

## 3. Operational Characteristics
### 3.1 Just-In-Time (JIT) Unprotection
Kage implements a high-efficiency **"One-Opcode Intercept"** strategy:
1. **Interception**: The entry point of protected functions is replaced with a `ZEND_NOP` carrier.
2. **Restoration**: On first invocation, the dispatcher restores native Zend handlers and unprotects the `op_array` in-place.
3. **Execution**: Subsequent executions incur **zero overhead**, running at 100% native PHP speed.

### 3.2 Environment Binding (HWID)
- **Hardware-Locked Execution**: Scripts can be cryptographically bound to a specific hardware fingerprint (supports Linux `/etc/machine-id` and macOS `gethostname`).
- **Integrity Validation**: 64-byte professional header with CRC32 verification ensures that tampered or corrupted payloads are blocked before execution.

## 4. System Integration & Deployment
### 4.1 Requirements
- **Runtime**: PHP 7.4 (AMD64/ARM64 architectures).
- **Dependencies**: `libsodium` (Standardized Cryptographic Library).
- **Build System**: CMake 3.16+, GCC 10+, or Docker.

### 4.2 Installation Procedure
Deploy the pre-hardened binary artifact:
```bash
# 1. Integrate the binary module
cp artifacts/kage_protected.so $(php-config --extension-dir)/kage.so

# 2. Configure the PHP environment (php.ini)
extension=kage.so
kage.encryption_key = "SECURE_32_CHAR_ALPHANUMERIC_KEY"
```

### 4.3 Encryption Protocol (API)
Developers must use the following procedure to generate protected assets:
```php
<?php
// Retrieve target system HWID for binding
$target_hwid = kage_get_machine_id();

// Standard Encryption Workflow
$source_code = file_get_contents('production_script.php');
$master_key = "0123456789abcdef0123456789abcdef"; 
$encrypted_blob = kage_encrypt_c($source_code, $master_key, $target_hwid);

file_put_contents('production_script.kage', base64_decode($encrypted_blob));
```

## 5. Technical Maintenance
### 5.1 Project Structure
- `/c_extension`: Core C-source code and Zend Engine integration.
- `/packer/VMPacker`: Submodule for native virtualization (x86_64/ARM64 support).
- `/artifacts`: Pre-compiled, VMP-hardened production binaries.
- `/tests`: Automated security and stability verification suite.

### 5.2 Verification Suite
Compliance is verified using `tests/test_enterprise_suite.php`, covering:
- **ISA Uniqueness**: Confirmation of randomized opcode mapping.
- **Performance Benchmarking**: Verification of zero-overhead hot loops.
- **Integrity Enforcement**: Tamper detection and HWID lock validation.

## 6. Legal & Compliance
**Licensing**: This software is Proprietary and Confidential.  
**Usage Policy**: Redistribution, reverse engineering, or modification is strictly prohibited under intellectual property laws.  
**Compliance**: Designed for high-security commercial software distribution.
