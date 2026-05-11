/**
 * Bytecode-level Cryptography Implementation
 */

#include "config.h"
#include "bytecode_crypto.h"
#include "zend_compile.h"
#include "zend_execute.h"
#include "zend_smart_str.h"
#include <zend_vm.h>
#include "kage_opcode_map.h"

/**
 * Helper: Check if opcode is a jump and return which operand holds the target.
 */
static int kage_get_jump_target_operand(unsigned char opcode) {
    switch (opcode) {
        case 42: // ZEND_JMP
            return 1;
        case 43:  // ZEND_JMPZ
        case 44:  // ZEND_JMPNZ
        case 45:  // ZEND_JMPZ_EX
        case 46:  // ZEND_JMPNZ_EX
        case 77:  // ZEND_FE_RESET_R
        case 78:  // ZEND_FE_FETCH_R
        case 152: // ZEND_JMP_SET
        case 153: // ZEND_COALESCE
        case 154: // ZEND_ASSERT_CHECK
        case 164: // ZEND_FE_RESET_RW
        case 165: // ZEND_FE_FETCH_RW
            return 2;
        case 107: // ZEND_CATCH
            return 3;
        default:
            return 0;
    }
}

/**
 * XOR-encrypt all constant string and long operands in an op_array.
 * Also obfuscates jump offsets for control flow protection (Phase 3.4).
 */
PHPAPI void kage_encrypt_operands(zend_op_array *op_array, zend_string *key) {
    if (!op_array || !key) return;

    unsigned char *k = (unsigned char*)ZSTR_VAL(key);
    size_t keylen = ZSTR_LEN(key);

    uint32_t xor_mask = 0;
    if (keylen >= 4) {
        memcpy(&xor_mask, k, 4);
    } else if (keylen > 0) {
        xor_mask = k[0] | (k[0] << 8) | (k[0] << 16) | (k[0] << 24);
    }

    // 1. Encrypt Jump Targets (Phase 3.4)
    if (xor_mask != 0) {
        for (uint32_t i = 0; i < op_array->last; i++) {
            zend_op *op = &op_array->opcodes[i];
            int jump_target_op = kage_get_jump_target_operand(op->opcode);
            if (jump_target_op == 1) {
                op->op1.opline_num ^= xor_mask;
            } else if (jump_target_op == 2) {
                op->op2.opline_num ^= xor_mask;
            } else if (jump_target_op == 3) {
                op->extended_value ^= xor_mask;
            }
        }
    }

    // 2. Encrypt Literals (Phase 3.3)
    if (op_array->literals) {
        for (int i = 0; i < op_array->last_literal; i++) {
            zval *zv = &op_array->literals[i];
            if (Z_TYPE_P(zv) == IS_STRING && Z_STRVAL_P(zv)) {
                char *s = Z_STRVAL_P(zv);
                for (size_t j = 0; j < Z_STRLEN_P(zv); j++) s[j] ^= k[j % keylen];
            } else if (Z_TYPE_P(zv) == IS_LONG) {
                Z_LVAL_P(zv) ^= k[0];
            }
        }
    }

    // 3. Obfuscate variable names
    if (op_array->vars) {
        for (int i = 0; i < op_array->last_var; i++) {
            zend_string *var = op_array->vars[i];
            if (var && !ZSTR_IS_INTERNED(var)) {
                char *s = ZSTR_VAL(var);
                for (size_t j = 0; j < ZSTR_LEN(var); j++) s[j] ^= k[j % keylen];
            }
        }
    }
}

static void kage_protect_op_array(zend_op_array *op_array, zend_string *key, uint32_t seed) {
    if (!op_array || op_array->type != ZEND_USER_FUNCTION) return;

    // 1. Encrypt this op_array
    kage_encrypt_operands(op_array, key);
    kage_map_oparray_seeded(op_array, seed);

    // 2. Carrier Setup
    if (op_array->last > 0) {
        op_array->reserved[1] = (void*)(uintptr_t)(op_array->opcodes[0].opcode | ((uint64_t)seed << 8));
        op_array->opcodes[0].opcode = 0; // ZEND_NOP
    }
    op_array->reserved[0] = (void*)1;
}

PHPAPI void kage_protect_recursive(zend_op_array *op_array, zend_string *key, uint32_t seed) {
    if (!op_array) return;

    // Protect the main op_array
    kage_protect_op_array(op_array, key, seed);

    // Protect nested functions
    if (CG(function_table)) {
        zend_function *func;
        ZEND_HASH_FOREACH_PTR(CG(function_table), func) {
            if (func->type == ZEND_USER_FUNCTION) {
                kage_protect_op_array(&func->op_array, key, seed);
            }
        } ZEND_HASH_FOREACH_END();
    }
    
    // Protect class methods
    if (CG(class_table)) {
        zend_class_entry *ce;
        ZEND_HASH_FOREACH_PTR(CG(class_table), ce) {
            if (ce->type == ZEND_USER_CLASS) {
                zend_function *func;
                ZEND_HASH_FOREACH_PTR(&ce->function_table, func) {
                    if (func->type == ZEND_USER_FUNCTION) {
                        kage_protect_op_array(&func->op_array, key, seed);
                    }
                } ZEND_HASH_FOREACH_END();
            }
        } ZEND_HASH_FOREACH_END();
    }
}

// Professional LZSS Decompressor (Phase 5/6)
#define KAGE_LZSS_MIN_LEN 3
static void kage_lzss_decompress(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_len) {
    size_t i = 0, j = 0;
    uint16_t flags = 0;
    for (;;) {
        if (((flags >>= 1) & 256) == 0) {
            if (i >= input_len) break;
            flags = input[i++] | 0xff00;
        }
        if (flags & 1) {
            if (i >= input_len || j >= output_len) break;
            output[j++] = input[i++];
        } else {
            if (i + 1 >= input_len) break;
            size_t pos = input[i++];
            size_t len = input[i++];
            pos |= (len & 0xf0) << 4;
            len = (len & 0x0f) + KAGE_LZSS_MIN_LEN;
            for (size_t k = 0; k < len; k++) {
                if (j >= output_len) break;
                output[j] = (pos < j) ? output[j - pos] : 0;
                j++;
            }
        }
    }
}

 __attribute__((optimize("O1")))
 PHPAPI int kage_global_user_handler(zend_execute_data *execute_data) {
     zend_function *func = execute_data->func; 
     if (func && (func->type == ZEND_USER_FUNCTION || func->type == ZEND_EVAL_CODE)) {
         zend_op_array *op_array = &func->op_array;
 
         if (op_array->reserved[0] == (void*)1) {
             // 1. Unpack Seed & Carrier from reserved[1]
             uintptr_t packed = (uintptr_t)op_array->reserved[1];
             unsigned char virtual_first = (unsigned char)(packed & 0xFF);
             uint32_t oparray_seed = (uint32_t)(packed >> 8);
             op_array->opcodes[0].opcode = virtual_first;
 
             // 2. Key Resolution
             zend_string *key_str = KAGE_G(encryption_key);
             int release_key = 0;
             if (!key_str) {
                 char *env = getenv("KAGE_ENCRYPTION_KEY");
                 if (env) {
                     key_str = zend_string_init(env, 32, 0);
                     release_key = 1;
                 }
             }
 
             if (key_str) {
                 unsigned char map[256], reverse[256];
                 kage_build_map_seeded(map, reverse, oparray_seed);
 
                 for (uint32_t i = 0; i < op_array->last; i++) {
                     zend_op *op = &op_array->opcodes[i];
                     op->opcode = reverse[op->opcode];
                     zend_vm_set_opcode_handler(op);
                 }
                 
                 kage_encrypt_operands(op_array, key_str);
 
                 for (uint32_t i = 0; i < op_array->last; i++) {
                     zend_op *op = &op_array->opcodes[i];
                     int target_op = kage_get_jump_target_operand(op->opcode);
                     if (target_op == 1) {
                         uint32_t t = op->op1.opline_num;
                         if (t < op_array->last) {
 #if ZEND_USE_ABS_JMP_ADDR
                             op->op1.jmp_addr = &op_array->opcodes[t];
 #else
                             op->op1.jmp_offset = (uint32_t)((int32_t)t - (int32_t)i);
 #endif
                         }
                     } else if (target_op == 2) {
                         uint32_t t = op->op2.opline_num;
                         if (t < op_array->last) {
 #if ZEND_USE_ABS_JMP_ADDR
                             op->op2.jmp_addr = &op_array->opcodes[t];
 #else
                             op->op2.jmp_offset = (uint32_t)((int32_t)t - (int32_t)i);
 #endif
                         }
                     }
                 }
                 if (release_key) zend_string_release(key_str);
             }
             op_array->reserved[0] = 0;
         }
     }
     return ZEND_USER_OPCODE_DISPATCH;
 }
