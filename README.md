# Kage Security Extension
## PHP Bytecode Protection & Virtualization System

**Project:** Kage  
**Target Environment:** PHP 7.4 – 8.4 (Zend Engine 3.4.x – 4.4.x)  

---

## 1. Introduction
Kage is a high-performance PHP extension designed for the cryptographic protection of code. It implements **Bytecode Virtualization** and **Native Code Virtualization** to protect PHP source code and execution logic from static and dynamic analysis.

## 2. Architectural Design
The system utilizes a layered protection architecture.

### 2.1 Layer 1: Bytecode Virtualization (Zend Level)
- **Dynamic ISA (Instruction Set Architecture)**: Protected files are compiled into a unique, randomized instruction set based on a per-file 32-bit seed.
- **Control Flow Flattening (CFF)**: The execution graph is modified via **Jump Target Obfuscation**. Original jump destinations are XOR-encrypted and re-linked in memory during runtime.
- **Recursive Logic Obfuscation**: Obfuscation of child structures, including nested functions, class methods, and anonymous closures.

### 2.2 Layer 2: Data & Metadata Encryption
- **Literal Table Protection**: Constant strings and numeric values are XOR-encrypted at the compiler level and decrypted JIT within protected memory blocks.
- **Symbol Table Masking**: Variable name indices and names in the `op_array->vars` table are obfuscated to prevent information leakage through Reflection API or debuggers.

### 2.3 Layer 3: Native Virtualization (VMPacker)
- **Binary Virtualization**: Core functions (`kage_raw_decrypt`, `kage_get_machine_id`) are virtualized using **VMPacker**.
- **Interpreter-in-Interpreter**: C-logic is transformed into custom VM-bytecode, preventing analysis of decryption algorithms using standard disassemblers.

## 3. Operational Characteristics
### 3.1 Just-In-Time (JIT) Unprotection
Kage implements an intercept strategy:
1. **Interception**: The entry point of protected functions is replaced with a `ZEND_NOP` carrier.
2. **Restoration**: On first invocation, the dispatcher restores native Zend handlers and unprotects the `op_array` in-place.
3. **Execution**: Subsequent executions run at native PHP speed.

### 3.2 Environment Binding (HWID)
- **Hardware-Locked Execution**: Scripts can be bound to a specific hardware fingerprint (supports Linux `/etc/machine-id` and macOS `gethostname`).
- **Integrity Validation**: Header with CRC32 verification ensures that tampered payloads are blocked before execution.

## 4. System Integration & Deployment
### 4.1 Requirements
- **Runtime**: PHP 7.4, 8.0, 8.1, 8.2, 8.3, 8.4 (AMD64/ARM64 architectures).
- **Dependencies**: `libsodium`.
- **Build System**: CMake 3.16+, GCC 10+, or Docker.

### 4.2 Installation Procedure
Deploy the binary artifact:
```bash
# 1. Integrate the binary module
cp artifacts/kage_protected.so $(php-config --extension-dir)/kage.so

# 2. Configure the PHP environment (php.ini)
extension=kage.so
kage.encryption_key = "SECURE_32_CHAR_ALPHANUMERIC_KEY"
```

### 4.3 Encryption Protocol (API)
Procedure to generate protected assets:
```php
<?php
// Retrieve target system HWID for binding
$target_hwid = kage_get_machine_id();

// Encryption Workflow
$source_code = file_get_contents('production_script.php');
$master_key = "0123456789abcdef0123456789abcdef"; 
$encrypted_blob = kage_encrypt_c($source_code, $master_key, $target_hwid);

file_put_contents('production_script.kage', base64_decode($encrypted_blob));
```

## 5. Maintenance & Testing
### 5.1 Project Structure
- `/c_extension`: Core C-source code and Zend Engine multi-version compatibility layer (`kage_compat.h`).
- `/packer/VMPacker`: Submodule for native virtualization (x86_64/ARM64 support).
- `/artifacts`: Pre-compiled binaries.
- `/tests`: Security and stability verification suite.
- `/scripts`: Automated multi-PHP version verification tools.

### 5.2 Verification Suite
Compliance and multi-version stability are verified across PHP versions (8.1 – 8.4) via:
```bash
./scripts/test_php_versions.sh
```
This suite validates:
- **ISA Uniqueness**: Randomized opcode mapping.
- **Performance Benchmarking**: Native speed execution verification.
- **Integrity Enforcement**: Tamper detection and HWID lock validation.
- **Multi-Version Zend Compatibility**: Verifies compilation and runtime execution on PHP 8.1, 8.2, 8.3, and 8.4.

## 6. Legal & Compliance
**Licensing**: Proprietary.  
**Usage Policy**: Redistribution, reverse engineering, or modification is prohibited.  
**Compliance**: Designed for secure software distribution.

