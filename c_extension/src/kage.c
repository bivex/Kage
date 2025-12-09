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

// Define the module globals
ZEND_DECLARE_MODULE_GLOBALS(kage)

// INI entries
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("kage.debug", "0", PHP_INI_ALL, OnUpdateBool, debug, zend_kage_globals, kage_globals)
PHP_INI_END()

// Register AST resource type
int le_kage_ast;

// Module initialization
PHP_GINIT_FUNCTION(kage)
{
#if defined(COMPILE_DL_KAGE) && defined(ZTS)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    kage_globals->debug = 0;
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

    // Register AST resource type
    le_kage_ast = zend_register_list_destructors_ex(
        kage_ast_dtor, NULL, "Kage AST", module_number
    );

    // Register constants
    REGISTER_STRING_CONSTANT("KAGE_VERSION", PHP_KAGE_VERSION, CONST_CS | CONST_PERSISTENT);

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(kage)
{
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