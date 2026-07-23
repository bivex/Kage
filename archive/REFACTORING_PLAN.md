# Kage Security Extension: Post-Clenz Refactoring Plan
## Quality Improvement & Technical Debt Reduction

**Target Environment:** PHP 7.4 (Zend Engine 3.4.x)  
**Standard Compliance:** MISRA C:2012 / SEI CERT C  
**Reference Document:** Clenz Smell Scan Report (2026-05-11)

---

## 1. Executive Summary
The `clenz` analysis identified several critical "code smells" that impact maintainability, readability, and long-term architectural stability. While the system is functionally complete and secure, this refactoring plan addresses structural risks such as file size, cyclomatic complexity, and improper use of literal constants.

---

## 2. Step-by-Step Refactoring Tasks

### Step 1: Opcode Literal Decoupling (Priority: High)
**File:** `c_extension/src/bytecode_crypto.c`  
**Problem:** Direct usage of numeric IDs for Zend Opcodes (e.g., `case 42` for `ZEND_JMP`).  
**Action:** 
- Replace all raw integers with standard Zend constants defined in `zend_vm_opcodes.h`.
- Create a private header `kage_op_defs.h` for custom Carrier/Virtual opcode aliases.
- **Benefit:** Prevents breakage if PHP internals change opcode IDs in minor versions.

### Step 2: AST Module Decomposition (Priority: High)
**File:** `c_extension/src/ast.c` (788 lines)  
**Problem:** Violation of Single Responsibility Principle (SRP). One file handles parsing, transformation, and PHP integration.  
**Action:** 
- Split `ast.c` into three focused modules:
  - `ast_parser.c`: Lexical and syntax analysis logic.
  - `ast_converter.c`: Logic for transforming AST nodes to bytecode.
  - `ast_resource.c`: Zend resource registration and memory management.
- **Benefit:** Reduces file size to < 300 lines, improving navigation and debuggability.

### Step 3: Complexity Reduction in Tokenizer (Priority: Medium)
**File:** `c_extension/src/php_compiler.c`  
**Problem:** `php_tokenizer_next` has a cyclomatic complexity of 20 (Max recommended: 8).  
**Action:** 
- Extract sub-token handling (Strings, Variables, Comments) into private static helper functions.
- Implement a lookup table for single-character tokens.
- **Benefit:** Simplifies unit testing of the lexical analyzer.

### Step 4: Global Variable Encapsulation (Priority: Medium)
**File:** `c_extension/src/kage_opcode_map.c`  
**Problem:** Global static tables `g_kage_opcode_map` and `g_kage_reverse_map`.  
**Action:** 
- Move these tables into the `kage_context` structure.
- Access them only through the context handle retrieved via `kage_get_context()`.
- **Benefit:** Thread-safety and better isolation between different request lifecycles.

### Step 5: Defensive Memory Hardening (Priority: Low)
**Files:** `kage_context.c`, `kage_memory.c`  
**Problem:** Clenz warning on "unchecked malloc" (False positive for `emalloc`, but good for hygiene).  
**Action:** 
- Wrap `emalloc` calls in a custom `KAGE_ALLOC` macro that includes an explicit `assert` or logging.
- Ensure all function parameters that are not modified are marked `const`.
- **Benefit:** Satisfies static analysis tools and improves type safety.

---

## 3. Implementation Schedule

| Phase | Milestone | Focus | Est. Effort |
|-------|-----------|-------|-------------|
| 1 | **Clean Constants** | Bytecode Crypto (Step 1) | 0.5 Day |
| 2 | **Modularization** | AST Split (Step 2) | 1.5 Days |
| 3 | **Logic Refinement** | Tokenizer & Globals (Step 3 & 4) | 1 Day |
| 4 | **Final Hardening** | Defensive coding (Step 5) | 0.5 Day |

---

## 4. Verification Protocol
Post-refactoring, the system must undergo:
1. **Functional Check**: `docker run --rm kage-verify` (Must pass all 100%).
2. **Regression Check**: `php tests/test_enterprise_suite.php`.
3. **Smell Check**: Re-run `clenz smell-dir c_extension/src` (Expect < 5 warnings).

---

## Conclusion
Completion of this refactoring plan will transition Kage from a "working prototype" to a "high-quality engineering asset," ready for long-term support and compliance auditing.
