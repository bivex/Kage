/**
 * PHP Bytecode Extractor for Kage Extension
 * 
 * Extracts Zend bytecode from PHP source code using tokenizer
 */

#include "php.h"
#include "zend.h"
#include "zend_compile.h"
#include "kage_context.h"

// Function to extract PHP tokens and convert to our format
PHPAPI kage_result_t kage_extract_php_bytecode(const char *php_code) {
    kage_result_t result = {KAGE_SUCCESS, {NULL}};
    
    if (!php_code) {
        result.error = KAGE_ERROR_INVALID_INPUT;
        return result;
    }
    
    // Get PHP tokens
    zval tokens_zv;
    php_token_get_all(php_code, strlen(php_code), &tokens_zv);
    
    if (Z_TYPE(tokens_zv) != IS_ARRAY) {
        result.error = KAGE_ERROR_INVALID_INPUT;
        return result;
    }
    
    // Convert tokens to our internal format
    HashTable *tokens = Z_ARRVAL(tokens_zv);
    zval *token_entry;
    
    // Create result string with token information
    smart_str bytecode = {0};
    smart_str_appends(&bytecode, "PHP_BYTECODE_DUMP\n");
    
    ZEND_HASH_FOREACH_VAL(tokens, token_entry) {
        if (Z_TYPE_P(token_entry) == IS_ARRAY) {
            zval *token_type = zend_hash_index_find(Z_ARRVAL_P(token_entry), 0);
            zval *token_value = zend_hash_index_find(Z_ARRVAL_P(token_entry), 1);
            
            if (token_type && token_value && Z_TYPE_P(token_type) == IS_LONG) {
                const char *token_name = token_name(Z_LVAL_P(token_type));
                smart_str_appends(&bytecode, token_name);
                smart_str_appends(&bytecode, ": ");
                
                if (Z_TYPE_P(token_value) == IS_STRING) {
                    smart_str_appendl(&bytecode, Z_STRVAL_P(token_value), Z_STRLEN_P(token_value));
                }
                smart_str_appends(&bytecode, "\n");
            }
        } else if (Z_TYPE_P(token_entry) == IS_STRING) {
            smart_str_appends(&bytecode, "RAW: ");
            smart_str_appendl(&bytecode, Z_STRVAL_P(token_entry), Z_STRLEN_P(token_entry));
            smart_str_appends(&bytecode, "\n");
        }
    } ZEND_HASH_FOREACH_END();
    
    smart_str_0(&bytecode);
    
    // Create result zval
    zval *result_zv = emalloc(sizeof(zval));
    ZVAL_STRINGL(result_zv, bytecode.s->val, bytecode.s->len);
    smart_str_free(&bytecode);
    
    zval_ptr_dtor(&tokens_zv); // Clean up tokens
    
    result.result.value = result_zv;
    return result;
}

// Function to compile PHP code to Zend opcodes (simplified)
PHPAPI kage_result_t kage_compile_php_code(const char *php_code) {
    kage_result_t result = {KAGE_SUCCESS, {NULL}};
    
    if (!php_code) {
        result.error = KAGE_ERROR_INVALID_INPUT;
        return result;
    }
    
    // Create a temporary PHP file
    char temp_file[] = "/tmp/kage_compile_XXXXXX";
    int fd = mkstemp(temp_file);
    if (fd == -1) {
        result.error = KAGE_ERROR_IO;
        return result;
    }
    
    // Write PHP code to temp file
    write(fd, php_code, strlen(php_code));
    close(fd);
    
    // Try to compile with opcache if available
    zval *bytecode_result = emalloc(sizeof(zval));
    ZVAL_BOOL(bytecode_result, 0); // Default to false
    
    if (zend_hash_str_exists(&module_registry, "Zend OPcache", sizeof("Zend OPcache") - 1)) {
        // Opcache is available, try to compile
        zval file_zv;
        ZVAL_STRING(&file_zv, temp_file);
        
        // Call opcache_compile_file if available
        if (zend_function_exists("opcache_compile_file", sizeof("opcache_compile_file") - 1)) {
            zval retval;
            zend_call_known_function(opcache_compile_file, NULL, NULL, 1, &retval, &file_zv);
            
            if (Z_TYPE(retval) == IS_TRUE) {
                ZVAL_TRUE(bytecode_result);
            }
        }
        
        zval_ptr_dtor(&file_zv);
    }
    
    // Cleanup
    unlink(temp_file);
    
    result.result.value = bytecode_result;
    return result;
}
