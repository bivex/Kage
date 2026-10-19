# Kage ARM64 + ASGARD-5877 Protection

Hardened Kage PHP extension built for ARM64 Linux with function-level VM protection via **ASGARD-5877** (Virtualization-Based Obfuscation).

## Architectural Overview

```
┌─────────────────────────────────────────────────────┐
│                   Docker Build (ARM64)               │
│                                                      │
│  Stage 1: Kage Builder                              │
│  ┌──────────────────────────────┐                   │
│  │ php:7.4-cli (arm64)          │                   │
│  │  • cmake + make kage.so      │                   │
│  │  • Exported symbols listed   │                   │
│  └──────────┬───────────────────┘                   │
│             │                                        │
│  Stage 2: ASGARD Protection Pipeline                │
│  ┌──────────────────────────────────────────────┐   │
│  │ ASGARD-5877 processes kage.so:               │   │
│  │                                              │   │
│  │  1. Strip debug symbols                      │   │
│  │  2. Virtualize sensitive inner C primitives: │   │
│  │     • kage_raw_decrypt (crypto.c)            │   │
│  │     • kage_get_machine_id (kage_config.c)    │   │
│  │  3. Transform to polymorphic VM bytecode     │   │
│  │  4. Control-Flow Flattening (CFF)            │   │
│  │  5. 5th-order Non-Linear MBA expansions      │   │
│  │                                              │   │
│  │  Original:   BL kage_raw_decrypt             │   │
│  │  Protected:  BL trampoline → VM interpreter  │   │
│  └──────────┬───────────────────────────────────┘   │
│             │                                        │
│  Stage 4: Runtime (default tag)                     │
│  ┌──────────────────────────────┐                   │
│  │ php:7.4-cli + libsodium23    │                   │
│  │  • kage_protected.so         │                   │
│  │  • PHP loads extension       │                   │
│  │  • Protected functions run   │                   │
│  │    through VM interpreter    │                   │
│  └──────────────────────────────┘                   │
└─────────────────────────────────────────────────────┘
```

## Protection Targets

| Function | File | Impact |
|----------|------|--------|
| `kage_raw_decrypt` | `crypto.c:25` | Core decryption primitive — holds key unwrap logic. |
| `kage_get_machine_id` | `kage_config.c:27` | HWID fingerprint generation — prevents license bypass. |

## ASGARD Protection Features

1. **Polymorphic Virtual Machine (VBO)**:
   - Dynamic opcode mapping per build
   - Direct-Threaded / RD-JIT VM execution
2. **Control-Flow Flattening (CFF)**:
   - State dispatcher topology destroying basic block graph recovery
3. **High-Order Mixed Boolean-Arithmetic (MBA)**:
   - Defeats automated SMT solvers (Z3, Arybo) and symbolic tracing engines
4. **Cross-Architecture Support**:
   - Supports ARM64 (`aarch64`), x86_64, and RISC-V targets
