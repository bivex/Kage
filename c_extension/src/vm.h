/**
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-06-06 23:04
 * Last Updated: 2025-06-06 23:14
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#ifndef PHP_KAGE_VM_H
#define PHP_KAGE_VM_H

#include "config.h"

// VM instruction types
typedef enum {
    KAGE_OP_PUSH,
    KAGE_OP_POP,
    KAGE_OP_ENCRYPT,
    KAGE_OP_DECRYPT
} kage_opcode;

// VM instruction structure
typedef struct {
    kage_opcode opcode;
    zval operand;
} kage_instruction;

// VM state structure
typedef struct {
    zval *stack;
    size_t stack_size;
    size_t stack_ptr;
    HashTable *variables;
    zend_string *key;
    kage_instruction *instructions;
    size_t instruction_count;
} kage_vm_state;

// VM stack size constant
#define KAGE_VM_STACK_SIZE 1024

// VM functions
PHPAPI zend_result kage_vm_init(kage_vm_state *state, size_t stack_size);
PHPAPI void kage_vm_destroy(kage_vm_state *state);
PHPAPI zend_result kage_vm_push(kage_vm_state *state, zval *value);
PHPAPI zend_result kage_vm_pop(kage_vm_state *state, zval *result);
PHPAPI zend_result kage_vm_execute(kage_vm_state *state);

// PHP functions
PHP_FUNCTION(kage_vm_encrypt);
PHP_FUNCTION(kage_vm_decrypt);

#endif /* PHP_KAGE_VM_H */ 