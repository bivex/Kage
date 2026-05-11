/**
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-06-06 21:47
 * Last Updated: 2025-06-07 02:32
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#include "config.h"
#include "kage_context.h"
#include "kage_config.h"
#include "bytecode_crypto.h"
#include "crypto.h"
#include "kage_opcode_map.h"
#include <zend_compile.h>

// Define the module globals
ZEND_DECLARE_MODULE_GLOBALS(kage)

// INI entries
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("kage.debug", "0", PHP_INI_ALL, OnUpdateBool, debug, zend_kage_globals, kage_globals)
    STD_PHP_INI_ENTRY("kage.restrict_unencoded", "0", PHP_INI_ALL, OnUpdateBool, restrict_unencoded, zend_kage_globals, kage_globals)
PHP_INI_END()

// Register AST resource type
int le_kage_ast;

// Original zend_compile_file pointer
static zend_op_array *(*original_compile_file)(zend_file_handle *file_handle, int type);

// Hook for zend_compile_file
static zend_op_array *kage_compile_file(zend_file_handle *file_handle, int type) {
    const char *filename = file_handle->filename;
    FILE *fp = NULL;
    char header[4];
    zend_op_array *op_array = NULL;
    unsigned char *encrypted_buf = NULL;
    zend_string *key = NULL;
    zval decrypted_zv;
    int is_kage_file = 0;
    int decryption_failed = 0;

    ZVAL_NULL(&decrypted_zv);

    if (filename) {
        fp = fopen(filename, "rb");
        if (fp) {
            if (fread(header, 1, 4, fp) == 4 && memcmp(header, "KAGE", 4) == 0) {
                is_kage_file = 1;

                 // 1. Read encrypted payload
                 fseek(fp, 0, SEEK_END);
                 size_t file_size = ftell(fp);
                 fseek(fp, 4, SEEK_SET);
                 size_t encrypted_len = file_size - 4;
                 encrypted_buf = emalloc(encrypted_len);
                 if (!encrypted_buf) goto cleanup;

                 if (fread(encrypted_buf, 1, encrypted_len, fp) != encrypted_len) {
                     goto cleanup;
                 }
                 fclose(fp);
                 fp = NULL;

                 // Phase 4.1: Integrity Check (CRC32)
                 uint32_t file_crc = kage_crc32(encrypted_buf, encrypted_len);
                 // In a real SG-like scenario, we would compare this with a CRC stored in the header.
                 // For now, we use it to ensure the payload is at least readable.

                 // Phase 4.2: Machine Binding (Placeholder)
                 char *mid = kage_get_machine_id();
                 if (mid) {
                     // In Phase 4, we would compare 'mid' with the machine ID embedded in the license/file.
                     efree(mid);
                 }

                // 2. Get encryption key from configuration (INI > env > fallback)
                kage_config *config = kage_config_get();
                const char *key_str = NULL;
                if (config) {
                    key_str = kage_config_get_string(config, KAGE_CONFIG_ENCRYPTION_KEY);
                }
                if (!key_str) {
                    key_str = getenv("KAGE_ENCRYPTION_KEY");
                }
                if (!key_str) {
                    php_error_docref(NULL, E_WARNING, "Kage: Encryption key not configured. Set 'kage.encryption_key' in php.ini or KAGE_ENCRYPTION_KEY environment variable");
                    decryption_failed = 1;
                    goto cleanup;
                }
                key = zend_string_init(key_str, 32, 0);

                // 3. Decrypt (raw binary format)
                if (kage_raw_decrypt(&decrypted_zv, encrypted_buf, encrypted_len, key) != SUCCESS) {
                    decryption_failed = 1;
                    goto cleanup;
                }

                // 4. Compile the decrypted PHP code directly (strip <?php ?> tags)
                char *src = Z_STRVAL(decrypted_zv);
                size_t src_len = Z_STRLEN(decrypted_zv);
                char *code_start = src;
                size_t code_len = src_len;

                // Strip opening tag
                if (code_len >= 5 && memcmp(code_start, "<?php", 5) == 0) {
                    code_start += 5;
                    code_len -= 5;
                } else if (code_len >= 2 && memcmp(code_start, "<?", 2) == 0) {
                    code_start += 2;
                    code_len -= 2;
                }

                 // Strip closing tag
                 if (code_len >= 2 && memcmp(code_start + code_len - 2, "?>", 2) == 0) {
                     code_len -= 2;
                 }
 
 #if PHP_VERSION_ID < 80000
                 zval code_zv;
                 ZVAL_STRINGL(&code_zv, code_start, code_len);
                 op_array = zend_compile_string(&code_zv, filename);
                 zval_ptr_dtor(&code_zv);
 #else
                 zend_string *code_str = zend_string_init(code_start, code_len, 0);
                 op_array = zend_compile_string(code_str, filename);
                 zend_string_release(code_str);
 #endif
                   // Phase 3.1 & 3.3 & 3.4: Obfuscate bytecode
                   if (op_array) {
                       // 1. Encrypt operands and jump offsets (uses real opcodes)
                       if (key) {
                           kage_encrypt_operands(op_array, key);
                       }
                       // 2. Transform real opcodes to virtual ones
                       kage_map_oparray(op_array);
                       
                       // 3. Set first opcode to ZEND_NOP carrier (Phase 3.2 Strategy A)
                       if (op_array->last > 0) {
                           // Save original virtual opcode to reserved[1] for restoration
                           op_array->reserved[1] = (void*)(uintptr_t)op_array->opcodes[0].opcode;
                           op_array->opcodes[0].opcode = 0; // ZEND_NOP
                       }

                       // Mark this op_array as protected so runtime dispatcher knows to decrypt
                       op_array->reserved[0] = (void*)1;
                   }
             } else {
                // Not a Kage-protected file
                if (fp) {
                    fclose(fp);
                    fp = NULL;
                }
            }
        }
    }

cleanup:
    // Close file if still open
    if (fp) {
        fclose(fp);
    }
    // Destroy decrypted zval
    if (decrypted_zv.value.str) {
        zval_ptr_dtor(&decrypted_zv);
    }
    // Release key
    if (key) {
        zend_string_release(key);
    }
    // Free encrypted buffer if still allocated
    if (encrypted_buf) {
        efree(encrypted_buf);
    }

    if (decryption_failed) {
        php_error_docref(NULL, E_WARNING, "Kage: Invalid license or corrupted encrypted file '%s'", filename);
        // op_array remains NULL, compilation failed
    } else if (!is_kage_file) {
        // Non-protected file, delegate to original compiler
        op_array = original_compile_file(file_handle, type);
    }

    return op_array;
}

// Module initialization
PHP_GINIT_FUNCTION(kage)
{
#if defined(COMPILE_DL_KAGE) && defined(ZTS)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    kage_globals->debug = 0;
    kage_globals->restrict_unencoded = 0;
}

// AST resource destructor
static void kage_ast_dtor(zend_resource *res) {
    kage_ast_node *ast = (kage_ast_node*)res->ptr;
    if (ast) {
        kage_ast_free(ast);
    }
}

PHP_MINIT_FUNCTION(kage)
{
    REGISTER_INI_ENTRIES();

    // Phase 1: Environment Hardening
    // Detect hostile extensions that can be used for reverse engineering
    const char *hostile_exts[] = {"vld", "xdebug", "blackfire", NULL};
    for (int i = 0; hostile_exts[i] != NULL; i++) {
        if (zend_hash_str_exists(&module_registry, hostile_exts[i], strlen(hostile_exts[i]))) {
            // Clean exit with a clear message to stderr
            fprintf(stderr, "\n[KAGE SECURITY] Hostile extension '%s' detected.\n", hostile_exts[i]);
            fprintf(stderr, "[KAGE SECURITY] Execution blocked for safety. Please disable '%s' to run this script.\n\n", hostile_exts[i]);
            exit(1);
        }
    }

    // Initialize libsodium
    if (sodium_init() == -1) {
        zend_error(E_WARNING, "Kage: libsodium initialization failed.");
        return FAILURE;
    }

    // Initialize Kage context system
    // kage_context *ctx = kage_context_get();
    // if (!ctx || kage_context_init(ctx) != KAGE_SUCCESS) {
    //     zend_error(E_WARNING, "Kage: Context initialization failed.");
    //     return FAILURE;
    // }

    // Initialize configuration system
    kage_config *config = kage_config_get();
    if (!config || kage_config_init(config) != KAGE_SUCCESS) {
        zend_error(E_WARNING, "Kage: Configuration initialization failed.");
        return FAILURE;
    }

     // Load configuration from environment and PHP ini
     kage_config_load_from_env(config);
     kage_config_load_from_php_ini(config);

     // Cache encryption key in module globals for runtime dispatcher
     const char *key_str = kage_config_get_string(config, KAGE_CONFIG_ENCRYPTION_KEY);
     if (!key_str) {
         key_str = getenv("KAGE_ENCRYPTION_KEY");
     }
     if (key_str) {
         KAGE_G(encryption_key) = zend_string_init(key_str, 32, 0);
     } else {
         KAGE_G(encryption_key) = NULL;
     }

      // Register AST resource type
    le_kage_ast = zend_register_list_destructors_ex(
        kage_ast_dtor, NULL, "Kage AST", module_number
    );

     // Register constants
     REGISTER_STRING_CONSTANT("KAGE_VERSION", PHP_KAGE_VERSION, CONST_CS | CONST_PERSISTENT);

      // Phase 3.1: Initialize opcode mapping
      if (kage_opcode_map_init() != SUCCESS) {
          zend_error(E_WARNING, "Kage: Opcode map initialization failed");
          return FAILURE;
      }

      // Phase 3.2: Register catch-all handler for ZEND_NOP (Strategy A)
      // We use ZEND_NOP as a carrier to intercept the first execution of a function.
      zend_set_user_opcode_handler(0, kage_global_user_handler); // 0 is ZEND_NOP

      // Phase 2: Register compiler hook
      original_compile_file = zend_compile_file;
      zend_compile_file = kage_compile_file;

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(kage)
{
     // Restore original compiler hook
     zend_compile_file = original_compile_file;

      // Clean up context system
      kage_context *ctx = kage_get_context();
      if (ctx) {
          kage_context_destroy(ctx);
      }

      // Clean up configuration system
      kage_config *config = kage_config_get();
      if (config) {
          kage_config_destroy(config);
      }

      // Phase 3.1: Cleanup opcode mapping
      kage_opcode_map_shutdown();

      // Phase 3.2/3.3: Release cached encryption key
      if (KAGE_G(encryption_key)) {
          zend_string_release(KAGE_G(encryption_key));
          KAGE_G(encryption_key) = NULL;
      }

      UNREGISTER_INI_ENTRIES();
      return SUCCESS;
  }

PHP_RINIT_FUNCTION(kage)
{
#if defined(COMPILE_DL_KAGE) && defined(ZTS)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(kage)
{
    return SUCCESS;
}

PHP_MINFO_FUNCTION(kage)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "Kage Extension Support", "enabled");
    php_info_print_table_row(2, "Version", PHP_KAGE_VERSION);
    php_info_print_table_end();
    DISPLAY_INI_ENTRIES();
}

// Function argument info
ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_encrypt_c, 0, 0, 2)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_decrypt_c, 0, 0, 2)
    ZEND_ARG_INFO(0, encrypted_data_base64)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_vm_encrypt, 0, 0, 2)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_vm_decrypt, 0, 0, 2)
    ZEND_ARG_INFO(0, encrypted_data_base64)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_ast_parse, 0, 0, 1)
    ZEND_ARG_INFO(0, source)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_ast_to_bytecode, 0, 0, 2)
    ZEND_ARG_INFO(0, ast)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

// Temporarily commented out until implementations are complete
// ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_compile_php, 0, 0, 2)
//     ZEND_ARG_INFO(0, php_code)
//     ZEND_ARG_INFO(0, encryption_key)
// ZEND_END_ARG_INFO()
//
// ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_execute_php_bytecode, 0, 0, 1)
//     ZEND_ARG_INFO(0, bytecode_data)
// ZEND_END_ARG_INFO()
//
// ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_extract_php_bytecode, 0, 0, 1)
//     ZEND_ARG_INFO(0, php_code)
// ZEND_END_ARG_INFO()
//
// ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_compile_php, 0, 0, 2)
//     ZEND_ARG_INFO(0, php_code)
//     ZEND_ARG_INFO(0, encryption_key)
// ZEND_END_ARG_INFO()
//
// ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_execute_php_bytecode, 0, 0, 1)
//     ZEND_ARG_INFO(0, bytecode_data)
// ZEND_END_ARG_INFO()
//
// ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_extract_php_bytecode, 0, 0, 1)
//     ZEND_ARG_INFO(0, php_code)
// ZEND_END_ARG_INFO()
//
// ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_compile_php_code, 0, 0, 1)
//     ZEND_ARG_INFO(0, php_code)
// ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_encrypt_bytecode, 0, 0, 2)
    ZEND_ARG_INFO(0, bytecode_info)
    ZEND_ARG_INFO(0, config)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_kage_decrypt_bytecode, 0, 0, 2)
    ZEND_ARG_INFO(0, encrypted_bytecode)
    ZEND_ARG_INFO(0, config)
ZEND_END_ARG_INFO()

// Forward declarations for functions
PHP_FUNCTION(kage_encrypt_bytecode);
PHP_FUNCTION(kage_decrypt_bytecode);

// Function entries
const zend_function_entry kage_functions[] = {
    PHP_FE(kage_encrypt_c, arginfo_kage_encrypt_c)
    PHP_FE(kage_decrypt_c, arginfo_kage_decrypt_c)
    PHP_FE(kage_vm_encrypt, arginfo_kage_vm_encrypt)
    PHP_FE(kage_vm_decrypt, arginfo_kage_vm_decrypt)
    PHP_FE(kage_ast_parse, arginfo_kage_ast_parse)
    PHP_FE(kage_ast_to_bytecode, arginfo_kage_ast_to_bytecode)
    // PHP_FE(kage_extract_php_bytecode, arginfo_kage_extract_php_bytecode)
    // PHP_FE(kage_compile_php_code, arginfo_kage_compile_php_code)
    PHP_FE(kage_encrypt_bytecode, arginfo_kage_encrypt_bytecode)
    PHP_FE(kage_decrypt_bytecode, arginfo_kage_decrypt_bytecode)
    PHP_FE_END
};

// Module entry
zend_module_entry kage_module_entry = {
    STANDARD_MODULE_HEADER,
    PHP_KAGE_EXTNAME,
    kage_functions,
    PHP_MINIT(kage),
    PHP_MSHUTDOWN(kage),
    PHP_RINIT(kage),
    PHP_RSHUTDOWN(kage),
    PHP_MINFO(kage),
    PHP_KAGE_VERSION,
    PHP_MODULE_GLOBALS(kage),
    PHP_GINIT(kage),
    NULL,
    NULL,
    STANDARD_MODULE_PROPERTIES_EX
};

// PHP Function implementations will be added when ready
// PHP_FUNCTION(kage_extract_php_bytecode) { ... }
// PHP_FUNCTION(kage_compile_php_code) { ... }

// PHP Function: kage_encrypt_bytecode
PHP_FUNCTION(kage_encrypt_bytecode) {
    zval *bytecode_zv, *config_zv;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "aa", &bytecode_zv, &config_zv) == FAILURE) {
        RETURN_FALSE;
    }

    // Получаем VLD вывод из массива
    zval *vld_output_zv = zend_hash_str_find(Z_ARRVAL_P(bytecode_zv), "vld_output", sizeof("vld_output") - 1);
    if (!vld_output_zv || Z_TYPE_P(vld_output_zv) != IS_STRING) {
        RETURN_FALSE;
    }

    // Создаём конфигурацию шифрования
    kage_bytecode_crypto_config crypto_config = {0};

    zval *algorithm_zv = zend_hash_str_find(Z_ARRVAL_P(config_zv), "algorithm", sizeof("algorithm") - 1);
    if (algorithm_zv && Z_TYPE_P(algorithm_zv) == IS_STRING) {
        if (strcmp(Z_STRVAL_P(algorithm_zv), "XOR") == 0) {
            crypto_config.algorithm = KAGE_OPCODE_ENCRYPT_XOR;
        } else if (strcmp(Z_STRVAL_P(algorithm_zv), "AES") == 0) {
            crypto_config.algorithm = KAGE_OPCODE_ENCRYPT_AES;
        } else if (strcmp(Z_STRVAL_P(algorithm_zv), "ROTATE") == 0) {
            crypto_config.algorithm = KAGE_OPCODE_ENCRYPT_ROTATE;
        } else {
            crypto_config.algorithm = KAGE_OPCODE_ENCRYPT_CUSTOM;
        }
    } else {
        crypto_config.algorithm = KAGE_OPCODE_ENCRYPT_XOR; // default
    }

    zval *key_zv = zend_hash_str_find(Z_ARRVAL_P(config_zv), "key", sizeof("key") - 1);
    if (key_zv && Z_TYPE_P(key_zv) == IS_STRING) {
        crypto_config.key = Z_STRVAL_P(key_zv);
        crypto_config.key_length = Z_STRLEN_P(key_zv);
    } else {
        crypto_config.key = "DEFAULT_KAGE_KEY_123";
        crypto_config.key_length = strlen(crypto_config.key);
    }

    zval *selective_zv = zend_hash_str_find(Z_ARRVAL_P(config_zv), "selective", sizeof("selective") - 1);
    crypto_config.selective_encryption = selective_zv && Z_TYPE_P(selective_zv) == IS_TRUE;

    // Парсим VLD вывод
    vld_bytecode_info *bytecode = kage_parse_vld_output(Z_STRVAL_P(vld_output_zv));
    if (!bytecode) {
        RETURN_FALSE;
    }

    // Шифруем опкоды
    kage_result_t result = kage_encrypt_opcodes(bytecode, &crypto_config);

    // Освобождаем память
    kage_free_bytecode_info(bytecode);

    if (result.error != KAGE_SUCCESS) {
        RETURN_FALSE;
    }

    // Возвращаем результат
    RETURN_ZVAL(result.result.value, 0, 1);
}

// PHP Function: kage_decrypt_bytecode
PHP_FUNCTION(kage_decrypt_bytecode) {
    zval *encrypted_zv, *config_zv;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "aa", &encrypted_zv, &config_zv) == FAILURE) {
        RETURN_FALSE;
    }

    // Получаем VLD вывод из массива
    zval *vld_output_zv = zend_hash_str_find(Z_ARRVAL_P(encrypted_zv), "vld_output", sizeof("vld_output") - 1);
    if (!vld_output_zv || Z_TYPE_P(vld_output_zv) != IS_STRING) {
        RETURN_FALSE;
    }

    // Создаём конфигурацию шифрования (та же что и для дешифрования)
    kage_bytecode_crypto_config crypto_config = {0};

    zval *algorithm_zv = zend_hash_str_find(Z_ARRVAL_P(config_zv), "algorithm", sizeof("algorithm") - 1);
    if (algorithm_zv && Z_TYPE_P(algorithm_zv) == IS_STRING) {
        if (strcmp(Z_STRVAL_P(algorithm_zv), "XOR") == 0) {
            crypto_config.algorithm = KAGE_OPCODE_ENCRYPT_XOR;
        } else if (strcmp(Z_STRVAL_P(algorithm_zv), "AES") == 0) {
            crypto_config.algorithm = KAGE_OPCODE_ENCRYPT_AES;
        } else if (strcmp(Z_STRVAL_P(algorithm_zv), "ROTATE") == 0) {
            crypto_config.algorithm = KAGE_OPCODE_ENCRYPT_ROTATE;
        } else {
            crypto_config.algorithm = KAGE_OPCODE_ENCRYPT_CUSTOM;
        }
    } else {
        crypto_config.algorithm = KAGE_OPCODE_ENCRYPT_XOR; // default
    }

    zval *key_zv = zend_hash_str_find(Z_ARRVAL_P(config_zv), "key", sizeof("key") - 1);
    if (key_zv && Z_TYPE_P(key_zv) == IS_STRING) {
        crypto_config.key = Z_STRVAL_P(key_zv);
        crypto_config.key_length = Z_STRLEN_P(key_zv);
    } else {
        crypto_config.key = "DEFAULT_KAGE_KEY_123";
        crypto_config.key_length = strlen(crypto_config.key);
    }

    crypto_config.selective_encryption = 0; // Для дешифрования шифруем все

    // Парсим VLD вывод
    vld_bytecode_info *bytecode = kage_parse_vld_output(Z_STRVAL_P(vld_output_zv));
    if (!bytecode) {
        RETURN_FALSE;
    }

    // Дешифруем опкоды (симметричный алгоритм)
    kage_result_t result = kage_decrypt_opcodes(bytecode, &crypto_config);

    // Освобождаем память
    kage_free_bytecode_info(bytecode);

    if (result.error != KAGE_SUCCESS) {
        RETURN_FALSE;
    }

    // Возвращаем результат
    RETURN_ZVAL(result.result.value, 0, 1);
}

#ifdef COMPILE_DL_KAGE
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE();
#endif
ZEND_GET_MODULE(kage)
#endif 