# Phase 3: Bytecode Transformation & Obfuscation — Implementation Plan

**Goal:** Ensure that even if protection is bypassed, the opcode dump remains unreadable.

**Status:** Not started — design phase

---

## Existing Infrastructure Audit

`c_extension/src/bytecode_crypto.c` already contains:
- `zend_op_encrypted` structure (mirrors `zend_op` with encrypted fields)
- VLD output parser (`kage_parse_vld_output`) — for analyzing bytecode
- XOR/ROTATE/CUSTOM encryption primitives for opcodes and operands
- Serialization framework (`kage_serialize_bytecode`, `kage_unserialize_bytecode`)
- Stub: `kage_get_encrypted_handler` — runtime handler lookup (returns NULL)
- Stub: `kage_decrypt_operand_runtime` — operand decryption at execution

This provides a foundation but is **not yet integrated** with the compilation or execution pipeline.

---

## Implementation Phases (3.1 → 3.5)

### 3.1 Virtual Opcode Mapping (Smallest viable change)

**Objective:** Replace standard Zend opcode values with randomized IDs in the encrypted bytecode.

**Implementation:**
1. Create `kage_opcode_map.c/h`:
   - `static unsigned char g_kage_opcode_map[256];` — real → virtual mapping
   - `static unsigned char g_kage_reverse_map[256];` — virtual → real
   - Initialize at `MINIT`: shuffle using `sodium_randombuf` or `arc4random_uniform`
   - Persist mapping in module globals for runtime lookup

2. Modify **compiler hook** (`kage.c: kage_compile_file`):
   - After `zend_compile_string` returns `op_array`, but **before returning**:
   - Walk opcode array: `op_array->opcodes[]`
   - Replace each `op->opcode` with `g_kage_opcode_map[op->opcode]`
   - Store original opcode in `op->extended_value` for runtime recovery (or encrypt it)

3. Storage format:
   - In-memory: `zend_op_array->opcodes[]` uses virtual opcodes
   - On disk (encrypted file): also virtual opcodes (already transformed during encryption)
   - Reverse mapping available only at runtime via `kage_get_real_opcode()`

**Files to modify:**
- `c_extension/src/kage_opcode_map.c` (new)
- `c_extension/src/kage_opcode_map.h` (new)
- `c_extension/src/kage.c` — integrate mapping walk after compilation
- `c_extension/src/bytecode_crypto.c` — add `kage_get_real_opcode()` helper

**Validation:**
- Use `vld` extension to dump opcodes of protected file — should see KAGE_OP_INTERNAL_0xXX values instead of ZEND_ECHO, etc.
- Normal PHP files should show standard opcodes

---

### 3.2 Custom Opcode Handlers (Zend VM Hook)

**Objective:** Redirect execution of virtual opcodes to Kage-controlled handlers.

**Mechanism:**
`zend_set_user_opcode_handler(int opcode, user_opcode_handler_t handler)` allows per-opcode custom handlers. However, this API expects **real** opcode numbers. With virtual opcodes we need a different strategy:

**Strategy A: Catch-all via `ZEND_HANDLER_NOP` override**
- Replace handler for `ZEND_NOP` (opcode 0) with `kage_handler_dispatcher`
- Set all virtual opcodes to have handler = `kage_handler_dispatcher`
- In `kage_handler_dispatcher`:
  1. Read virtual opcode from `OP(op_line)->opcode`
  2. Decrypt it: `real_opcode = g_kage_reverse_map[virtual_opcode]`
  3. Lookup real handler: `real_handler = zend_get_opcode_handler(real_opcode)`
  4. Decrypt operands if needed
  5. Jump to `real_handler`
- This works because `zend_set_user_opcode_handler` can replace any opcode's handler.

**Strategy B: Register handlers for all 256 opcodes**
- Loop over all opcodes at `MINIT`, call `zend_set_user_opcode_handler(i, kage_handler_dispatcher)`
- More explicit but repetitive.

**Recommended:** Strategy A — only override `ZEND_NOP` + set `opline->handler` dynamically.

**Implementation steps:**
1. In `kage_opcode_map.c`: after mapping opcodes, replace handler for virtual opcodes
2. Implement `kage_handler_dispatcher` in `bytecode_crypto.c`:
   ```c
   void kage_handler_dispatcher(INIT_FUNC_ARRAY) {
       zend_op *op = EX(opline);
       unsigned char virtual_op = op->opcode;
       unsigned char real_op = kage_get_real_opcode(virtual_op);
       // Decrypt operands if encrypted
       // Jump to real handler
       zend_execute_ex(real_op_handler);
   }
   ```
3. At `MINIT`: call `zend_set_user_opcode_handler(ZEND_NOP, kage_handler_dispatcher)`

**Validation:**
- Protected file should still execute
- Breakpoint on `kage_handler_dispatcher` should hit for every opcode
- `vld` dump shows wrong handlers — but execution works because dispatcher redirects

---

### 3.3 Operand Encryption (Field-Level)

**Objective:** Encrypt `op1`, `op2`, `result` zval fields inside `zend_op`.

**What to encrypt:**
- **String literals:** `Z_STRVAL(op1)` — XOR with key
- **Number literals:** `op1->value` — simple XOR/ROTATE
- **Variable names:** `Z_STR` in `op1`/`op2` for IS_CV
- **Class/Function names:** in `op2` for calls

**Implementation:**
1. During compilation (after `zend_compile_string` but before returning `op_array`):
   - Walk every opcode in `op_array->opcodes[]`
   - Call `kage_encrypt_operand(&op->op1, key)` and `op2`, `result`
   - Mark operand as encrypted: set bitflag in `op->extended_value` or store key index

2. Runtime decryption (in `kage_handler_dispatcher`):
   - Before executing any opcode, decrypt its active operands
   - Only decrypt `op1`/`op2`/`result` if marked encrypted
   - Re-encrypt after use? Optional (adds overhead)

3. `kage_encrypt_operand()` (new function):
   ```c
   void kage_encrypt_operand(zval *zv, const char *key, size_t keylen) {
       if (Z_TYPE_P(zv) == IS_STRING) {
           // XOR entire string buffer in-place
           for (size_t i = 0; i < Z_STRLEN_P(zv); i++) {
               Z_STRVAL_P(zv)[i] ^= key[i % keylen];
           }
       } else if (Z_TYPE_P(zv) == IS_LONG) {
           Z_LVAL_P(zv) ^= key[0];
       }
   }
   ```

**Security note:** Strings in Zend are stored in `zend_string` which is refcounted. Need to ensure we modify the actual buffer not a copy. Use `Z_STRVAL_P(zv)` directly.

**Files to modify:**
- `kage.c` — add `kage_encrypt_oparray_operands()` call after compilation
- `bytecode_crypto.c` — implement `kage_encrypt_operand()`, `kage_decrypt_operand()`

**Validation:**
- Protected file runs correctly
- `vld` dump shows garbled strings in opcode operand columns
- Original strings recovered only at runtime

---

### 3.4 Control Flow Flattening (CFF — Control Flow Flattening)

**Objective:** Convert linear opcode sequence into a `switch`-based dispatcher to hide control flow.

**Technique:**
Replace:
```c
// Original opcodes:
JMP label_A
ECHO "hi"
RETURN
label_A:
ASSIGN $a, 1
```
With:
```c
state = 0;
while (1) {
    switch(state) {
        case 0: JMP case_1; state = 1; break;
        case 1: ECHO "hi"; state = 2; break;
        case 2: RETURN; break;
        case 3: ASSIGN $a, 1; state = 0; break;
    }
}
```

**Implementation:**
This is **complex** — requires AST-level transformation, not just opcode munging.

**Better approach for C extension:**
Instead of full CFF, implement **switch-based dispatcher at opcode level:**

1. Insert `KAGE_DISPATCH` opcode at function entry
2. Replace all `ZEND_JMP`, `ZEND_JMPZ`, `ZEND_JUMP` with `KAGE_GOTO state_X`
3. Transform linear opcodes into basic blocks, assign state IDs
4. Create a jump table (array of `zend_op*`) encrypted
5. `KAGE_DISPATCH` handler decrypts jump table, jumps via `goto *table[state]`

**Simpler alternative:** Obfuscate jump targets only:
- Encrypt all relative jump offsets in `ZEND_JMP` using XOR with per-function key
- Handler decrypts offset just before jump
- VLD sees random offset values

**Recommendation:** Start with **encrypted jump offsets** (simpler), then later full CFF if needed.

---

### 3.5 Dynamic Handler Table (Advanced)

**Objective:** Periodically reshuffle opcode handler function pointers to make memory scanning unreliable.

**How:**
1. Copy `zend_opcode_handler` table at `MINIT` to `g_kage_original_handlers[256]`
2. Generate random permutation: `g_kage_shuffled_map[256]`
3. Periodically (every N requests, or via `RSHUTDOWN`), reshuffle:
   ```c
   for (int i = 0; i < 256; i++) {
       uint32_t idx = random() % 256;
       SWAP(g_kage_shuffled_map[idx], g_kage_shuffled_map[i]);
   }
   ```
4. Interceptor in `kage_handler_dispatcher`:
   - Get virtual opcode → map to real opcode via shuffled table
   - Jump to handler

**Cost:** Adds indirection overhead (one extra pointer lookup per opcode). May not be worth it.

**Alternative:** Rotate mapping every request (per-initialization).

---

## File/Code Changes Summary

### New Files
- `kage_opcode_map.c` — opcode mapping tables, init, lookup
- `kage_opcode_map.h` — declarations
- (optional) `kage_cff.c` — control flow flattening logic

### Modified Files
- `kage.c` → after `zend_compile_string()`:
  - `kage_transform_opcodes(op_array)` — apply virtual mapping + operand encryption
  - Call `kage_encrypt_oparray_operands(op_array, key)`
- `bytecode_crypto.c`:
  - Implement `kage_handler_dispatcher()` (full VM context manipulation)
  - Implement `kage_encrypt_operand()`, `kage_decrypt_operand()`
  - Fill `kage_get_encrypted_handler()` — return `kage_handler_dispatcher` for all virtual opcodes
  - Implement `kage_get_real_opcode(virtual)` using reverse map
- `CMakeLists.txt` — add `kage_opcode_map.c` to sources

### Integration Points
1. **MINIT** (`kage.c` → `PHP_MINIT_FUNCTION(kage)`):
   - Call `kage_opcode_map_init()` — create random permutation
   - Register `kage_handler_dispatcher` as user opcode handler for all virtual opcodes
2. **MSHUTDOWN** — free mapping tables
3. **Compilation hook** (`kage_compile_file`):
   - After `zend_compile_string()`, call `kage_apply_obfuscation(op_array, key)`
   - Mark array as transformed (set flag in `op_array->doc_comment` or module global)
4. **Execution** (`kage_handler_dispatcher`):
   - Decrypt operands on-the-fly
   - Re-encrypt after execution (optional)
   - Route to real handler

---

## Implementation Order (Recommended)

1. **Step 1:** Opcode mapping (3.1) — simplest, no VM changes needed yet
   - Just replace opcode values in `op_array->opcodes[]` after compilation
   - Validate with VLD: shows unknown opcodes

2. **Step 2:** Operand encryption (3.3) on top of 1
   - Encrypt all string operands with XOR
   - Validate: VLD shows gibberish strings; protected script still runs

3. **Step 3:** Custom opcode handlers (3.2)
   - Now VLD won't work correctly because handler table doesn't match real opcodes
   - Implement `kage_handler_dispatcher` to reverse-map and forward
   - Validate: script runs; breakpoint on dispatcher hits

4. **Step 4:** CFF (3.4) — optional, complex
   - Evaluate if needed: current approach already breaks VLD
   - Only implement if threat model requires CFF against advanced analysis

5. **Step 5:** Dynamic handler table (3.5) — advanced
   - Adds security but overhead
   - Implement if required for high-value targets

---

## Testing & Validation

**Tools:**
- `vld` extension: `php -d vld.active=1 script.php`
- `phpdbg` breakpoints on `kage_handler_dispatcher`
- Compare opcode dumps between:
  - Original unprotected file
  - Protected file (via VLD or `var_dump(op_array->opcodes)`)

**Test cases:**
- Simple echo script
- Functions with string literals
- Jumps/loops (for CFF)
- Nested includes
- Large file (1000+ opcodes)

**PASS Criteria:**
- Protected files execute identically to originals
- VLD output shows unreadable opcodes/operands
- Standard opcode dumper tools show garbage or crash
- No memory leaks (valgrind)
- Performance overhead < 15% (benchmark with `ab` or `wrk`)

---

## Risks & Mitigation

| Risk | Impact | Mitigation |
|---|---|---|
| Handler dispatch overhead | 5-10% slower | Keep dispatcher thin; use direct function pointer table |
| vld conflicts | Cannot analyze protected code | Expected; use debugging builds only |
| PHP 8.x API differences | Requires separate build | Already using `PHP_VERSION_ID` guards |
| Stack corruption from handler jumps | Crash | Test thoroughly; use `zend_execute_ex` forwarding |
| Protected files bloated | Larger on disk | Acceptable tradeoff |

---

## Next Step

Start with **3.1 Virtual Opcode Mapping** — 1-2 days work:
1. Create `kage_opcode_map.c/h` with `kage_opcode_map_init()`, `kage_map_opcode()`, `kage_unmap_opcode()`
2. Integrate into `kage.c: kage_compile_file()` after `zend_compile_string` returns
3. Rebuild, test with `vld` — confirm mapping applied
4. Commit as `feat(opcode): add virtual opcode mapping (Phase 3.1)`
