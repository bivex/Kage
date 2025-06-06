/**
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-06-06 23:18
 * Last Updated: 2025-06-07 02:32
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#ifndef PHP_KAGE_AST_H
#define PHP_KAGE_AST_H

#include "config.h"
#include "vm.h"

// AST Node Types
typedef enum {
    KAGE_AST_PROGRAM,
    KAGE_AST_ENCRYPT,
    KAGE_AST_DECRYPT,
    KAGE_AST_STRING,
    KAGE_AST_VARIABLE,
    KAGE_AST_BINARY_OP,
    KAGE_AST_UNARY_OP,
    KAGE_AST_CALL
} kage_ast_type;

// AST Node Structure
typedef struct kage_ast_node {
    kage_ast_type type;
    zval value;
    struct kage_ast_node *left;
    struct kage_ast_node *right;
    struct kage_ast_node *next;
} kage_ast_node;

// AST Parser Structure
typedef struct {
    const char *source;
    size_t position;
    size_t length;
    zend_error_handling error_handling;
} kage_ast_parser;

// AST Functions
PHPAPI kage_ast_node* kage_ast_parse(const char *source);
PHPAPI void kage_ast_free(kage_ast_node *node);
PHPAPI zend_result kage_ast_to_bytecode(kage_ast_node *node, kage_vm_state *state);

// PHP Functions
PHP_FUNCTION(kage_ast_parse);
PHP_FUNCTION(kage_ast_to_bytecode);

extern int le_kage_ast;

#endif /* PHP_KAGE_AST_H */ 