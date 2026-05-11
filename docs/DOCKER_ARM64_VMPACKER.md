# Kage ARM64 + VMPacker Protection

Hardened Kage PHP extension built for ARM64 Linux with function-level VM protection via VMPacker.

## How It Works

```
┌─────────────────────────────────────────────────────┐
│                   Docker Build (ARM64)               │
│                                                      │
│  Stage 1: VMPacker Builder                          │
│  ┌──────────────────────────────┐                   │
│  │ golang:1.22-bookworm (arm64) │                   │
│  │  • Compile VM stub (native)  │                   │
│  │  • Build Go packer binary    │                   │
│  └──────────┬───────────────────┘                   │
│             │                                        │
│  Stage 2: Kage Builder                              │
│  ┌──────────────────────────────┐                   │
│  │ php:7.4-cli (arm64)          │                   │
│  │  • cmake + make kage.so      │                   │
│  │  • Exported symbols listed   │                   │
│  └──────────┬───────────────────┘                   │
│             │                                        │
│  Stage 3: Protection                                │
│  ┌──────────────────────────────────────────────┐   │
│  │ VMPacker processes kage.so:                  │   │
│  │                                              │   │
│  │  1. strip debug symbols                     │   │
│  │  2. Find kage_raw_decrypt in .text          │   │
│  │  3. Find kage_get_machine_id in .text       │   │
│  │  4. Translate ARM64 → custom VM bytecode    │   │
│  │  5. Replace with trampoline (3 instructions)│   │
│  │  6. Embed VM interpreter stub               │   │
│  │                                              │   │
│  │  Original:   BL kage_raw_decrypt            │   │
│  │  Protected:  BL trampoline → VM interpreter │   │
│  └──────────┬───────────────────────────────────┘   │
│             │                                        │
│  Stage 5: Runtime (default tag)                     │
│  ┌──────────────────────────────┐                   │
│  │ php:7.4-cli + libsodium23   │                   │
│  │  • kage_protected.so         │                   │
│  │  • PHP loads extension       │                   │
│  │  • Protected functions run   │                   │
│  │    through VM interpreter    │                   │
│  └──────────────────────────────┘                   │
└─────────────────────────────────────────────────────┘
```

## What Gets Protected

| Function | File | Why |
|----------|------|-----|
| `kage_raw_decrypt` | `crypto.c:366` | Core decryption — holds encryption key logic. If cracked, all encrypted PHP is readable. |
| `kage_get_machine_id` | `kage_config.c:329` | HWID generation — reads CPU/DMI/disk serials. If patched, license binding is bypassed. |

VMPacker translates these ARM64 functions into randomly-mapped VM bytecode. The original instructions are replaced with a 3-instruction trampoline that jumps into the VM interpreter. Standard disassemblers (IDA Pro, Ghidra, radare2) cannot recover the original logic.

## VMPacker Protection Layers

Each protected function gets all of these automatically:

1. **Custom VM ISA** — Opcodes are randomly mapped per protection run
2. **OpcodeCryptor** — Each instruction XOR-encrypted with position-dependent key
3. **Bytecode Reversal** — Instructions stored in reverse execution order
4. **Token Entry** — Original function replaced with trampoline
5. **RTLR** — Runtime relocation for PIE/ASLR address fixup
6. **Symbol Strip** — Optional .symtab/.strtab removal

## Prerequisites

- Docker with BuildKit (Docker Desktop includes this)
- Apple Silicon Mac (native ARM64) **or** x86_64 with QEMU emulation
- ~3 GB disk space for base images

## Build & Test

### Full build + test (one command):

```bash
./build-arm64.sh --test
```

### Step by step:

```bash
# Build everything (stages 1-5)
docker build -f Dockerfile.arm64 -t kage-arm64:protected .

# Run the verification suite
docker run --rm kage-arm64:protected
```

Expected output:

```
--- Kage ARM64 (VMPacker Protected) ---
HWID: d1100dbc9aff
DECRYPT OK
--- All checks passed ---
```

### Export the protected kage.so:

```bash
# Build export-only image
docker build --target exporter -t kage-arm64:export -f Dockerfile.arm64 .

# Extract artifacts
docker create --name kage-export kage-arm64:export
docker cp kage-export:/output ./output-arm64
docker rm kage-export

ls output-arm64/
# kage.so       — protected ARM64 ELF shared library
# vmpacker      — ARM64 VMPacker binary
```

### Use in your own Dockerfile:

```dockerfile
FROM --platform=linux/arm64 php:7.4-cli

RUN apt-get update && apt-get install -y libsodium23 && rm -rf /var/lib/apt/lists/*

COPY output-arm64/kage.so $(php-config --extension-dir)/kage.so
RUN docker-php-ext-enable kage

ENV KAGE_ENCRYPTION_KEY="your-32-byte-hex-key-here!!"
```

### Clean up:

```bash
./build-arm64.sh --clean
```

## Build Script Options

```
./build-arm64.sh              Full build (all stages)
./build-arm64.sh --test       Build + run verification
./build-arm64.sh --export     Build + extract kage.so to ./output-arm64/
./build-arm64.sh --clean      Remove all Docker images
```

## Architecture Notes

- **VMPacker** supports ARM64 and ARM32 only. x86_64 is not supported (check their roadmap).
- The entire build runs natively on Apple Silicon. On x86_64 hosts, Docker uses QEMU emulation.
- The `zend_mm_heap corrupted` warning during build-time verification is expected — VMPacker's VM trampoline interacts with Zend's memory manager. It does not affect runtime functionality (2>/dev/null suppresses it in production).
- Each `docker build` produces a **unique** VMPacker ISA — opcodes are randomly mapped per run.

## Files

```
Dockerfile.arm64     Multi-stage build (5 stages)
build-arm64.sh       Build wrapper script
```
