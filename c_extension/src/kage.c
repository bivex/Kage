/**
 * Kage Extension — Core Implementation
 */

#include "config.h"
#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "kage_context.h"
#include "kage_config.h"
#include "kage_compat.h"
#include "bytecode_crypto.h"
#include "kage_opcode_map.h"
#include "kage_memory.h"
#include "zend_smart_str.h"
#include "zend_vm.h"
#include "crypto.h"

ZEND_DECLARE_MODULE_GLOBALS(kage)
int le_kage_ast;

static zend_op_array *(*original_compile_file)(zend_file_handle *file_handle, int type);

static zend_op_array *kage_compile_file(zend_file_handle *file_handle, int type) {
    const char *filename = KAGE_FH_FILENAME(file_handle);
    zend_op_array *op_array = NULL;
    FILE *fp = NULL;
    char header_magic[4];
    int is_kage_file = 0;
    char *encrypted_buf = NULL;
    zend_string *key = NULL;
    uint32_t oparray_seed = 0;

    if (filename && (strstr(filename, ".kage") || strstr(filename, ".php"))) {
        fp = fopen(filename, "rb");
        if (fp) {
            if (fread(header_magic, 1, 4, fp) == 4 && memcmp(header_magic, "KAGE", 4) == 0) {
                is_kage_file = 1;
                fseek(fp, 0, SEEK_END);
                size_t file_size = ftell(fp);
                fseek(fp, 0, SEEK_SET);
                encrypted_buf = KAGE_ALLOC(file_size);
                if (fread(encrypted_buf, 1, file_size, fp) != file_size) {
                    goto cleanup;
                }
                fclose(fp); fp = NULL;

                kage_config *config = kage_config_get();
                const char *key_str = config ? kage_config_get_string(config, KAGE_CONFIG_ENCRYPTION_KEY) : NULL;
                if (!key_str) key_str = getenv("KAGE_ENCRYPTION_KEY");
                if (!key_str) goto cleanup;

                key = zend_string_init(key_str, 32, 1); // Persistent for Apache
                
                zval decrypted_zv; ZVAL_NULL(&decrypted_zv);
                if (kage_raw_decrypt(&decrypted_zv, (unsigned char*)encrypted_buf, file_size, key, &oparray_seed) != SUCCESS) {
                    goto cleanup;
                }

                char *src = Z_STRVAL(decrypted_zv);
                size_t src_len = Z_STRLEN(decrypted_zv);
                
                // Strip tags
                char *code_start = src;
                size_t code_len = src_len;
                if (code_len >= 5 && memcmp(code_start, "<?php", 5) == 0) {
                    code_start += 5; code_len -= 5;
                } else if (code_len >= 2 && memcmp(code_start, "<?", 2) == 0) {
                    code_start += 2; code_len -= 2;
                }
                if (code_len >= 2 && memcmp(code_start + code_len - 2, "?>", 2) == 0) {
                    code_len -= 2;
                }

                op_array = kage_compat_compile_string(code_start, code_len, filename);
                zval_ptr_dtor(&decrypted_zv);

                if (op_array) {
                    kage_protect_recursive(op_array, key, oparray_seed);
                }
            }
        }
    }

cleanup:
    if (fp) fclose(fp);
    if (encrypted_buf) efree(encrypted_buf);
    if (key) zend_string_release(key);

    if (is_kage_file) {
        if (!op_array) {
            php_error_docref(NULL, E_WARNING, "Kage: Failed to load encrypted file");
            return NULL;
        }
        return op_array;
    }

    return original_compile_file(file_handle, type);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_encrypt_c, 0, 0, 2)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, hwid)
    ZEND_ARG_INFO(0, domain)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_decrypt_c, 0, 0, 2)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_get_machine_id, 0, 0, 0)
ZEND_END_ARG_INFO()

const zend_function_entry kage_functions[] = {
    PHP_FE(kage_encrypt_c, arginfo_kage_encrypt_c)
    PHP_FE(kage_decrypt_c, arginfo_kage_decrypt_c)
    PHP_FE(kage_get_machine_id, arginfo_kage_get_machine_id)
    PHP_FE_END
};

static void php_kage_init_globals(zend_kage_globals *kage_globals) {
    kage_globals->encryption_key = NULL;
}

PHP_MINIT_FUNCTION(kage) {
    ZEND_INIT_MODULE_GLOBALS(kage, php_kage_init_globals, NULL);
    kage_opcode_map_init(kage_get_context());
    
    // REDIRECTION FOR ALL OPCODES (0-255)
    for (int i = 0; i < 256; i++) {
        zend_set_user_opcode_handler(i, kage_global_user_handler);
    }
    
    original_compile_file = zend_compile_file;
    zend_compile_file = kage_compile_file;
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(kage) {
    zend_compile_file = original_compile_file;
    return SUCCESS;
}

PHP_MINFO_FUNCTION(kage) {
    php_info_print_table_start();
    php_info_print_table_header(2, "Kage support", "enabled");
    php_info_print_table_row(2, "Version", "2.0.0-Enterprise");
    php_info_print_table_end();
}

zend_module_entry kage_module_entry = {
    STANDARD_MODULE_HEADER,
    "kage",
    kage_functions,
    PHP_MINIT(kage),
    PHP_MSHUTDOWN(kage),
    NULL,
    NULL,
    PHP_MINFO(kage),
    "2.0.0",
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_KAGE
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(kage)
#endif
