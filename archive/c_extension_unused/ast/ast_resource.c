/**
 * Kage AST Resource — PHP Integration and Memory Management
 */

#include "ast.h"
#include "crypto.h"
#include <stdbool.h>

/**
 * Frees an AST node and all its children recursively.
 */
PHPAPI void kage_ast_free(kage_ast_node *node) {
    if (node == NULL) return;
    kage_ast_free(node->left);
    kage_ast_free(node->right);
    kage_ast_free(node->next);
    zval_ptr_dtor(&node->value);
    efree(node);
}

/**
 * Attempts to decrypt a zval in-place using the provided key.
 */
static bool try_decrypt_zval(zval *value, zend_string *key) {
    zval decrypted_result;
    if (value == NULL || key == NULL || Z_TYPE_P(value) != IS_STRING) return false;

    if (kage_internal_decrypt(&decrypted_result, value, key) != SUCCESS) return false;

    zval_ptr_dtor(value);
    ZVAL_COPY_VALUE(value, &decrypted_result);
    ZVAL_UNDEF(&decrypted_result);
    return true;
}

/**
 * Fully decrypts a result by iteratively decrypting.
 */
static void fully_decrypt_result(zval *result, zend_string *key) {
    if (result == NULL || key == NULL) return;
    while (try_decrypt_zval(result, key));
}

// PHP Function: Parse AST
PHP_FUNCTION(kage_ast_parse) {
    zend_string *source;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "S", &source) == FAILURE) RETURN_FALSE;
    
    kage_ast_node *ast = kage_ast_parse(ZSTR_VAL(source));
    if (ast == NULL) RETURN_FALSE;
    
    zend_resource *res = zend_register_resource(ast, le_kage_ast);
    RETURN_RES(res);
}

// PHP Function: Execute AST via Bytecode
PHP_FUNCTION(kage_ast_to_bytecode) {
    zval *ast_zv;
    zend_string *key;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "rS", &ast_zv, &key) == FAILURE) RETURN_FALSE;

    kage_ast_node *ast = (kage_ast_node*)zend_fetch_resource(Z_RES_P(ast_zv), "Kage AST", le_kage_ast);
    if (ast == NULL) RETURN_FALSE;

    kage_vm_state state;
    if (kage_vm_init(&state, KAGE_VM_STACK_SIZE) != SUCCESS) RETURN_FALSE;

    state.key = key;

    if (kage_ast_to_bytecode(ast, &state) != SUCCESS) {
        kage_vm_destroy(&state);
        RETURN_FALSE;
    }

    zval result;
    if (kage_vm_execute(&state) != SUCCESS || kage_vm_pop(&state, &result) != SUCCESS) {
        kage_vm_destroy(&state);
        RETURN_FALSE;
    }

    fully_decrypt_result(&result, key);
    kage_vm_destroy(&state);
    RETURN_ZVAL(&result, 0, 1);
}
