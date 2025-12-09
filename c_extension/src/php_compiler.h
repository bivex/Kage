/**
 * PHP Compiler for Kage Extension
 * 
 * Extends Kage to compile full PHP syntax to Zend bytecode
 */

#ifndef PHP_KAGE_COMPILER_H
#define PHP_KAGE_COMPILER_H

#include "kage_context.h"

// PHP opcodes that we can generate
typedef enum {
    PHP_OP_NOP = 0,
    PHP_OP_ADD,
    PHP_OP_SUB,
    PHP_OP_MUL,
    PHP_OP_DIV,
    PHP_OP_ASSIGN,
    PHP_OP_ECHO,
    PHP_OP_RETURN,
    // ... more opcodes
} php_opcode;

// Extended AST node types for full PHP syntax
typedef enum {
    // Existing Kage types
    PHP_NODE_PROGRAM = KAGE_AST_PROGRAM,
    PHP_NODE_ENCRYPT = KAGE_AST_ENCRYPT,
    PHP_NODE_DECRYPT = KAGE_AST_DECRYPT,
    PHP_NODE_STRING = KAGE_AST_STRING,
    
    // New PHP syntax types
    PHP_NODE_VARIABLE,
    PHP_NODE_ASSIGNMENT,
    PHP_NODE_BINARY_OP,
    PHP_NODE_FUNCTION_CALL,
    PHP_NODE_IF_STATEMENT,
    PHP_NODE_WHILE_LOOP,
    PHP_NODE_ECHO_STATEMENT,
    PHP_NODE_RETURN_STATEMENT,
    PHP_NODE_CLASS_DECLARATION,
    PHP_NODE_FUNCTION_DECLARATION,
    // ... more node types
} php_node_type;

// Function declarations
PHPAPI kage_result_t kage_compile_php_to_bytecode(const char *php_code, const char *encryption_key);
PHPAPI kage_result_t kage_execute_php_bytecode(const char *bytecode_data, size_t data_length, zval *result);

#endif /* PHP_KAGE_COMPILER_H */
