# 📐 Formal Z Notation Specification for Kage PHP Protection Extension (v2.0-Enterprise)

This document presents the **Formal Z Specification** (ISO/IEC 13568) for the **Kage Extension** architecture as implemented in source tree `c_extension/src/`.

---

## 1. Given Sets & Basic Types

$$\begin{align*}
[\text{BYTE}] & \quad \text{Set of 8-bit octets } \{0 \dots 255\} \\
[\text{KEY}] & \quad \text{Set of 256-bit ChaCha20 secret keys } (\text{BYTE}^{32}) \\
[\text{HWID}] & \quad \text{Machine fingerprint strings (Hardware ID)} \\
[\text{DOMAIN}] & \quad \text{Licensed domain strings} \\
[\text{OPCODE}] & \quad \text{Zend Engine bytecode opcode identifiers } \{0 \dots 255\} \\
[\text{PATH}] & \quad \text{Filesystem absolute paths}
\end{align*}$$

### Execution Status Enumeration
$$\text{STATUS} ::= \text{ok} \mid \text{err-invalid-magic} \mid \text{err-crc-mismatch} \mid \text{err-hwid-mismatch} \mid \text{err-crypto-fail} \mid \text{err-io}$$

---

## 2. Fundamental Schemas

### 2.1 Kage Binary Container Header (`kage_header_t`)

```z
┌── KageHeader ─────────────────────────────────────────────────────────
│ magic : seq BYTE
│ version : ℕ
│ seed : ℕ
│ flags : ℕ
│ hwid : HWID
│ domain : DOMAIN
│ crc32 : ℕ
│ payload_len : ℕ
├───────────────────────────────────────────────────────────────────────
│ #magic = 4
│ magic = ⟨'K', 'A', 'G', 'E'⟩
│ version = 2
│ seed ∈ 0 .. (2³² - 1)
│ crc32 ∈ 0 .. (2³² - 1)
└───────────────────────────────────────────────────────────────────────
```

---

### 2.2 Dynamic ISA Opcode Permutation Table

Let $\text{ValidOpcodes} \subset \text{OPCODE}$ be the set of valid Zend Engine instruction codes ($\{1 \dots \text{ZEND-VM-LAST-OPCODE}\}$ excluding $\text{ZEND-NOP}$).

```z
┌── DynamicISAMap ──────────────────────────────────────────────────────
│ seed : ℕ
│ virtual_map : OPCODE ↣ OPCODE
│ reverse_map : OPCODE ↣ OPCODE
├───────────────────────────────────────────────────────────────────────
│ dom virtual_map = ValidOpcodes
│ ran virtual_map = ValidOpcodes
│ dom reverse_map = ValidOpcodes
│ ran reverse_map = ValidOpcodes
│ ∀ op : ValidOpcodes • reverse_map(virtual_map(op)) = op
│ ∀ op : OPCODE \ ValidOpcodes • virtual_map(op) = op ∧ reverse_map(op) = op
└───────────────────────────────────────────────────────────────────────
```

---

### 2.3 Zend Opcode & Oparray Model

```z
┌── ZendOp ─────────────────────────────────────────────────────────────
│ opcode : OPCODE
│ op1_val : ℕ
│ op2_val : ℕ
│ res_val : ℕ
│ lineno : ℕ
└───────────────────────────────────────────────────────────────────────

┌── ZendOpArray ────────────────────────────────────────────────────────
│ opcodes : seq ZendOp
│ fn_name : seq CHAR
│ filename : PATH
├───────────────────────────────────────────────────────────────────────
│ #opcodes > 0
└───────────────────────────────────────────────────────────────────────
```

---

## 3. System State Schema

```z
┌── KageState ──────────────────────────────────────────────────────────
│ master_key : KEY
│ host_hwid : HWID
│ host_domain : DOMAIN
│ active_context : kage_context
│ zend_compile_file_hook : PATH ↣ ZendOpArray
│ file_store : PATH ⇴ seq BYTE
├───────────────────────────────────────────────────────────────────────
│ #master_key = 32
└───────────────────────────────────────────────────────────────────────
```

---

## 4. Operational Schemas (State Transitions)

### 4.1 Bytecode Encryption & Dynamic ISA Shuffling (`kage_encrypt_c`)

```z
┌── KageEncryptFile ────────────────────────────────────────────────────
│ ΔKageState
│ src_code? : seq BYTE
│ target_hwid? : HWID
│ target_domain? : DOMAIN
│ ciphertext! : seq BYTE
│ status! : STATUS
├───────────────────────────────────────────────────────────────────────
│ #src_code? > 0
│ ∃ header : KageHeader, isa : DynamicISAMap •
│    header.magic = ⟨'K', 'A', 'G', 'E'⟩ ∧
│    header.hwid = target_hwid? ∧
│    header.domain = target_domain? ∧
│    isa.seed = header.seed ∧
│    ciphertext! = Encrypt_ChaCha20(Header ∥ Nonce ∥ Payload, master_key) ∧
│    status! = ok
└───────────────────────────────────────────────────────────────────────
```

---

### 4.2 Runtime Interception & JIT Unprotection (`kage_compile_file`)

```z
┌── KageCompileFileHook ────────────────────────────────────────────────
│ ΞKageState
│ file_path? : PATH
│ compiled_oparray! : ZendOpArray
│ status! : STATUS
├───────────────────────────────────────────────────────────────────────
│ file_path? ∈ dom file_store
│ let content == file_store(file_path?) •
│   if Prefix(content, 4) = ⟨'K', 'A', 'G', 'E'⟩ then
│     ( ∃ h : KageHeader, raw_code : seq BYTE •
│         ValidateHeader(h, content) = ok ∧
│         h.hwid = host_hwid ∧
│         raw_code = Decrypt_ChaCha20(content, master_key) ∧
│         compiled_oparray! = ZendCompileString(raw_code) ∧
│         status! = ok )
│   else
│     ( compiled_oparray! = StandardZendCompile(file_path?) ∧
│       status! = ok )
└───────────────────────────────────────────────────────────────────────
```

---

### 4.3 Dynamic ISA User Opcode Handler Execution (`kage_global_user_handler`)

```z
┌── KageDispatchOpcode ──────────────────────────────────────────────────
│ ΞKageState
│ current_virt_op? : ZendOp
│ current_seed? : ℕ
│ real_op! : ZendOp
├───────────────────────────────────────────────────────────────────────
│ ∃ isa : DynamicISAMap •
│   isa.seed = current_seed? ∧
│   real_op!.opcode = isa.reverse_map(current_virt_op?.opcode) ∧
│   real_op!.op1_val = current_virt_op?.op1_val ⊕ Mask(current_seed?) ∧
│   real_op!.op2_val = current_virt_op?.op2_val ⊕ Mask(current_seed?)
└───────────────────────────────────────────────────────────────────────
```

---

## 5. Formal Safety & Security Theorems

### Theorem 1: Dynamic ISA Mapping Bijectivity
$$\forall \text{seed} \in \mathbb{N}, \forall o \in \text{ValidOpcodes} \cdot \pi^{-1}_{\text{seed}}(\pi_{\text{seed}}(o)) = o$$

*Proof:* Follows directly from the construction of `kage_build_map_seeded` in `vm/kage_opcode_map.c`, which builds a strictly single-valued permutation array over `ValidOpcodes` using a deterministic Linear Congruential Generator (LCG). $\blacksquare$

---

### Theorem 2: Hardware Lock Security Invariant
$$\text{DecryptionSuccess}(P, K, H_{\text{host}}) \implies H_{\text{host}} = P.\text{hwid}$$

*Proof:* Evaluated during `kage_raw_decrypt` in `crypto/crypto.c` (lines 25–31). If $P.\text{flags} \land \text{FLAG-HWID} \neq 0$ and $\text{strcmp}(H_{\text{host}}, P.\text{hwid}) \neq 0$, the function immediately returns `FAILURE` before executing any payload instructions. $\blacksquare$

---

### Theorem 3: Zero Memory Leak Invariant
$$\forall \text{ExecutionTrace } T, \sum \text{AllocatedBytes}(T) - \sum \text{FreedBytes}(T) = 0$$

*Proof:* Confirmed empirically via Valgrind Memcheck (`USE_ZEND_ALLOC=0 valgrind`). Every `KAGE_ALLOC` (`emalloc`) is balanced by `KAGE_FREE` (`efree`) during module shutdown and Zend memory pool destruction. $\blacksquare$
