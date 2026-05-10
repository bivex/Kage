# Roadmap: Kage Professional Loader Upgrade

This document outlines the steps required to modernize the Kage extension, transforming it into a high-end professional protector and loader.

---

## Phase 1: Environment Hardening (Anti-Debug)
*Goal: Block tools and environments that allow runtime code analysis.*

- [x] **Detection of Hostile Extensions**: Implement checks in `MINIT` for the presence of `vld`, `xdebug`, and `blackfire`. If found, terminate execution immediately.
- [ ] **Dump Function Blocking**: Prevent execution if functions like `debug_backtrace` or `var_dump` are called within protected blocks.
- [ ] **Restrict Unencoded Mode**: Add an INI directive `kage.restrict_unencoded`. When enabled, PHP will only execute files encrypted by Kage, blocking any unauthorized scripts.

## Phase 2: Seamless Integration (Transparent Execution)
*Goal: Remove the need for `eval()` and make the protection invisible to the end-user.*

- [x] **Hook `zend_compile_file`**: Intercept the standard PHP compiler.
    - If the file contains a Kage signature, decrypt it in memory and return the `op_array`.
    - If not, delegate to the original compiler.
- [x] **In-Memory Decryption**: Ensure the source code never appears as temporary files or strings. Decryption should occur directly into structures compatible with the Zend VM.

## Phase 3: Bytecode Transformation & Obfuscation
*Goal: Ensure that even if the protection is bypassed, the opcode dump remains unreadable.*

- [ ] **Virtual Opcode Mapping**:
    - **Concept**: Map standard Zend Opcodes (e.g., `ZEND_ECHO`, `ZEND_JMP`) to randomized internal IDs.
    - **Implementation**: Create a `kage_opcode_map` that changes with every build.
    - **New Names**: `KAGE_OP_INTERNAL_0x1A`, `KAGE_OP_SIG_ALFA`, etc., instead of using PHP constants.
- [ ] **Custom Opcode Handlers**:
    - **Mechanism**: Use `zend_set_user_opcode_handler` to redirect execution to Kage.
    - **New Function Names**:
        - `kage_handler_dispatcher`: The main entry point for all intercepted opcodes.
        - `kage_exec_vjmp`: Custom handler for jumps that calculates the target address at runtime using an encrypted offset.
        - `kage_exec_vstr`: Custom handler for string operations that decrypts literals only at the moment of use.
- [ ] **Control Flow Flattening (CFF)**:
    - **Mechanism**: Convert the linear code structure into a large `switch-case` inside a loop (a "dispatcher").
    - **New Logic**: Replace direct `JMP` instructions with `kage_next_op` variable updates, making it impossible for VLD to draw a correct execution graph.
- [ ] **Operand Encryption**:
    - **Concept**: Encrypt the `op1`, `op2`, and `result` fields within the `zend_op` structure.
    - **New Structure**: `kage_transformed_op` which mirrors `zend_op` but contains encrypted data and a "decoy" opcode to mislead simple dumpers.
- [ ] **Dynamic Handler Table**:
    - Periodically shuffle the function pointer table used to execute opcodes, so that even memory analysis becomes a "moving target."

## Phase 4: Licensing & Fingerprinting
*Goal: Restrict code execution to specific servers, environments, or timeframes.*

- [ ] **Hardware Fingerprinting**: Collect machine IDs (MAC address, disk serial number, CPU ID) and verify them during decryption.
- [ ] **Time-Limited Licenses**: Embed expiration dates into the encrypted packets.
- [ ] **IP/Domain Binding**: Restrict execution to authorized IP addresses or domains.

## Phase 5: Loader Self-Protection (Integrity Control)
*Goal: Prevent modification of the `kage.so` extension itself.*

- [ ] **Checksum Validation**: The extension should verify its own integrity (checksum) upon startup.
- [ ] **Symbol Stripping & Obfuscation**: Remove debugging symbols from the `kage.so` binary to hinder analysis via tools like `IDA Pro` or `Ghidra`.

---

## Quick Wins (Starting Points)
1. **Implement VLD/Xdebug protection** in `kage.c`.
2. **Add a compilation hook** to enable running files via `include 'file.php'` instead of explicit decryption functions.
