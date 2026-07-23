/**
 * Kage Extension — Zend Engine Multi-Version Compatibility Layer
 * Supports PHP 7.4, 8.0, 8.1, 8.2, 8.3, and 8.4
 */

#ifndef KAGE_COMPAT_H
#define KAGE_COMPAT_H

#include "php.h"
#include "zend_compile.h"
#include "zend_execute.h"
#include "zend_vm.h"
#include "zend_vm_opcodes.h"

/* -------------------------------------------------------------------------
 * 1. zend_file_handle Filename Abstraction
 * ------------------------------------------------------------------------- */
#if PHP_VERSION_ID >= 80100
# define KAGE_FH_FILENAME(fh) ((fh) && (fh)->filename ? ZSTR_VAL((fh)->filename) : NULL)
#else
# define KAGE_FH_FILENAME(fh) ((fh) ? (fh)->filename : NULL)
#endif

/* -------------------------------------------------------------------------
 * 2. zend_compile_string Abstraction
 * ------------------------------------------------------------------------- */
static inline zend_op_array *kage_compat_compile_string(const char *code_start, size_t code_len, const char *filename) {
#if PHP_VERSION_ID >= 80200
    zend_string *zcode = zend_string_init(code_start, code_len, 0);
    zend_op_array *op_array = zend_compile_string(zcode, filename, ZEND_COMPILE_POSITION_AFTER_OPEN_TAG);
    zend_string_release(zcode);
    return op_array;
#elif PHP_VERSION_ID >= 80000
    zend_string *zcode = zend_string_init(code_start, code_len, 0);
    zend_op_array *op_array = zend_compile_string(zcode, (char*)filename);
    zend_string_release(zcode);
    return op_array;
#else
    zval code_zv;
    ZVAL_STRINGL(&code_zv, code_start, code_len);
    zend_op_array *op_array = zend_compile_string(&code_zv, (char*)filename);
    zval_ptr_dtor(&code_zv);
    return op_array;
#endif
}

/* -------------------------------------------------------------------------
 * 3. Jump Target Operand Helpers
 * ------------------------------------------------------------------------- */
#if PHP_VERSION_ID >= 80000
# define KAGE_OPLINE_NUM(op_array, target_opline) ((uint32_t)((target_opline) - (op_array)->opcodes))
#else
# define KAGE_OPLINE_NUM(op_array, target_opline) ((target_opline)->op1.opline_num)
#endif

#endif /* KAGE_COMPAT_H */
