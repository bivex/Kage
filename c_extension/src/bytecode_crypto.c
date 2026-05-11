/**
 * Bytecode-level Cryptography Implementation (Ultimate Stability Edition)
 */

#include "config.h"
#include "bytecode_crypto.h"
#include "zend_compile.h"
#include "zend_execute.h"
#include "zend_smart_str.h"
#include <zend_vm.h>
#include "kage_opcode_map.h"

static int kage_get_jump_target_operand(unsigned char opcode) {
    switch (opcode) {
        case 42: return 1;
        case 43: case 44: case 45: case 46:
        case 77: case 78: case 152: case 153:
        case 154: case 164: case 165: return 2;
        case 107: return 3;
        default: return 0;
    }
}

PHPAPI void kage_encrypt_operands(zend_op_array *op_array, zend_string *key) {
    if (!op_array || !key) return;
    unsigned char *k = (unsigned char*)ZSTR_VAL(key);
    size_t keylen = ZSTR_LEN(key);
    uint32_t xor_mask = 0;
    if (keylen >= 4) memcpy(&xor_mask, k, 4);
    else if (keylen > 0) xor_mask = k[0] | (k[0] << 8) | (k[0] << 16) | (k[0] << 24);

    if (xor_mask != 0) {
        for (uint32_t i = 0; i < op_array->last; i++) {
            zend_op *op = &op_array->opcodes[i];
            int j = kage_get_jump_target_operand(op->opcode);
            if (j == 1) op->op1.opline_num ^= xor_mask;
            else if (j == 2) op->op2.opline_num ^= xor_mask;
            else if (j == 3) op->extended_value ^= xor_mask;
        }
    }
    if (op_array->literals) {
        for (int i = 0; i < op_array->last_literal; i++) {
            zval *zv = &op_array->literals[i];
            if (Z_TYPE_P(zv) == IS_STRING && Z_STRVAL_P(zv)) {
                char *s = Z_STRVAL_P(zv);
                for (size_t j = 0; j < Z_STRLEN_P(zv); j++) s[j] ^= k[j % keylen];
            } else if (Z_TYPE_P(zv) == IS_LONG) Z_LVAL_P(zv) ^= k[0];
        }
    }
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
    if (op_array->reserved[0] == (void*)1) return;
    
    kage_encrypt_operands(op_array, key);
    kage_map_oparray_seeded(op_array, seed);
    
    // Store seed for dispatcher
    op_array->reserved[1] = (void*)(uintptr_t)seed;
    op_array->reserved[0] = (void*)1;
}

PHPAPI void kage_protect_recursive(zend_op_array *op_array, zend_string *key, uint32_t seed) {
    if (!op_array || !op_array->filename) return;
    zend_string *target = op_array->filename;
    kage_protect_op_array(op_array, key, seed);

    if (CG(function_table)) {
        zend_function *f;
        ZEND_HASH_FOREACH_PTR(CG(function_table), f) {
            if (f->type == ZEND_USER_FUNCTION && f->op_array.filename && zend_string_equals(f->op_array.filename, target))
                kage_protect_op_array(&f->op_array, key, seed);
        } ZEND_HASH_FOREACH_END();
    }
    if (CG(class_table)) {
        zend_class_entry *ce;
        ZEND_HASH_FOREACH_PTR(CG(class_table), ce) {
            if (ce->type == ZEND_USER_CLASS && ce->info.user.filename && zend_string_equals(ce->info.user.filename, target)) {
                zend_function *m;
                ZEND_HASH_FOREACH_PTR(&ce->function_table, m) {
                    if (m->type == ZEND_USER_FUNCTION) kage_protect_op_array(&m->op_array, key, seed);
                } ZEND_HASH_FOREACH_END();
            }
        } ZEND_HASH_FOREACH_END();
    }
}

// Global user opcode handler (Intercepts every opcode execution)
PHPAPI int kage_global_user_handler(zend_execute_data *execute_data) {
    zend_function *func = execute_data->func;
    if (func && (func->type == ZEND_USER_FUNCTION || func->type == ZEND_EVAL_CODE)) {
        zend_op_array *op_array = &func->op_array;
        
        // Fast path: most calls will skip this
        if (op_array->reserved && op_array->reserved[0] == (void*)1) {
            uint32_t seed = (uint32_t)(uintptr_t)op_array->reserved[1];
            op_array->reserved[0] = 0; // Unmark
            
            zend_string *key = KAGE_G(encryption_key);
            if (!key) {
                char *e = getenv("KAGE_ENCRYPTION_KEY");
                if (e) key = zend_string_init(e, 32, 0);
            }

            if (key) {
                unsigned char m[256], r[256];
                kage_build_map_seeded(m, r, seed);
                for (uint32_t i = 0; i < op_array->last; i++) {
                    zend_op *op = &op_array->opcodes[i];
                    op->opcode = r[op->opcode];
                }
                kage_encrypt_operands(op_array, key);
                for (uint32_t i = 0; i < op_array->last; i++) {
                    zend_op *op = &op_array->opcodes[i];
                    int t = kage_get_jump_target_operand(op->opcode);
                    if (t == 1) { uint32_t idx = op->op1.opline_num; if (idx < op_array->last) {
#if ZEND_USE_ABS_JMP_ADDR
                        op->op1.jmp_addr = &op_array->opcodes[idx];
#else
                        op->op1.jmp_offset = (uint32_t)((int32_t)idx - (int32_t)i);
#endif
                    }} else if (t == 2) { uint32_t idx = op->op2.opline_num; if (idx < op_array->last) {
#if ZEND_USE_ABS_JMP_ADDR
                        op->op2.jmp_addr = &op_array->opcodes[idx];
#else
                        op->op2.jmp_offset = (uint32_t)((int32_t)idx - (int32_t)i);
#endif
                    }}
                }
                // Cleanup temp key if created
                if (key != KAGE_G(encryption_key)) zend_string_release(key);
            }
        }
    }
    
    // Return DISPATCH to use native handler for the current opcode
    return ZEND_USER_OPCODE_DISPATCH;
}
