/**
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-06-06 21:47
 * Last Updated: 2025-06-07 02:32
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#include "config.h"
#include "crypto.h"
#include "vm.h"
#include "ast.h"

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

// Function entries
const zend_function_entry kage_functions[] = {
    PHP_FE(kage_encrypt_c, arginfo_kage_encrypt_c)
    PHP_FE(kage_decrypt_c, arginfo_kage_decrypt_c)
    PHP_FE(kage_vm_encrypt, arginfo_kage_vm_encrypt)
    PHP_FE(kage_vm_decrypt, arginfo_kage_vm_decrypt)
    PHP_FE(kage_ast_parse, arginfo_kage_ast_parse)
    PHP_FE(kage_ast_to_bytecode, arginfo_kage_ast_to_bytecode)
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

#ifdef COMPILE_DL_KAGE
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE();
#endif
ZEND_GET_MODULE(kage)
#endif 