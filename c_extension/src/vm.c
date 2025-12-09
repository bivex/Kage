/**
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-06-06 23:05
 * Last Updated: 2025-06-07 02:32
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#include "vm.h"
#include "crypto.h"
#include "base64.h"

// Initialize VM state
PHPAPI int kage_vm_init(kage_vm_state *state, size_t stack_size) {
    state->stack = ecalloc(stack_size, sizeof(zval));
    state->stack_size = 0;  // Current stack size
    state->stack_ptr = 0;   // Stack pointer
    state->variables = emalloc(sizeof(HashTable));
    zend_hash_init(state->variables, 8, NULL, ZVAL_PTR_DTOR, 0);
    state->instructions = NULL;
    state->instruction_count = 0;
    return SUCCESS;
}

// Clean up VM state
PHPAPI void kage_vm_destroy(kage_vm_state *state) {
    if (state == NULL) {
        return;
    }
    if (state->stack) {
        for (size_t i = 0; i < state->stack_ptr; i++) {
            zval_ptr_dtor(&state->stack[i]);
        }
        efree(state->stack);
    }
    if (state->variables) {
        zend_hash_destroy(state->variables);
        efree(state->variables);
    }
    if (state->instructions) {
        for (size_t i = 0; i < state->instruction_count; i++) {
            zval_ptr_dtor(&state->instructions[i].operand);
        }
        efree(state->instructions);
    }
}

// Push value onto stack
PHPAPI int kage_vm_push(kage_vm_state *state, zval *value) {
    if (state->stack_ptr >= KAGE_VM_STACK_SIZE) {
        return FAILURE;
    }
    ZVAL_COPY(&state->stack[state->stack_ptr++], value);
    state->stack_size = state->stack_ptr;
    return SUCCESS;
}

// Pop value from stack
PHPAPI int kage_vm_pop(kage_vm_state *state, zval *result) {
    if (state->stack_ptr == 0) {
        return FAILURE;
    }
    ZVAL_COPY(result, &state->stack[--state->stack_ptr]);
    state->stack_size = state->stack_ptr;
    return SUCCESS;
}

// Execute VM instructions
PHPAPI int kage_vm_execute(kage_vm_state *state) {
    if (!state || !state->instructions) {
        return FAILURE;
    }

    zval temp, encrypted, decrypted;
    ZVAL_NULL(&temp);
    ZVAL_NULL(&encrypted);
    ZVAL_NULL(&decrypted);

    for (size_t i = 0; i < state->instruction_count; i++) {
        kage_instruction *instr = &state->instructions[i];
        
        switch (instr->opcode) {
            case KAGE_OP_PUSH:
                if (kage_vm_push(state, &instr->operand) != SUCCESS) {
                    goto cleanup;
                }
                break;

            case KAGE_OP_POP:
                if (kage_vm_pop(state, &temp) != SUCCESS) {
                    goto cleanup;
                }
                break;

            case KAGE_OP_ENCRYPT:
                if (kage_vm_pop(state, &temp) != SUCCESS) {
                    goto cleanup;
                }
                if (kage_internal_encrypt(&encrypted, &temp, state->key) != SUCCESS) {
                    goto cleanup;
                }
                if (kage_vm_push(state, &encrypted) != SUCCESS) {
                    goto cleanup;
                }
                break;

            case KAGE_OP_DECRYPT:
                if (kage_vm_pop(state, &temp) != SUCCESS) {
                    goto cleanup;
                }
                if (kage_internal_decrypt(&decrypted, &temp, state->key) != SUCCESS) {
                    goto cleanup;
                }
                if (kage_vm_push(state, &decrypted) != SUCCESS) {
                    goto cleanup;
                }
                break;

            default:
                goto cleanup;
        }
    }

    // Clean up temporary values
    zval_ptr_dtor(&temp);
    zval_ptr_dtor(&encrypted);
    zval_ptr_dtor(&decrypted);

    return SUCCESS;

cleanup:
    zval_ptr_dtor(&temp);
    zval_ptr_dtor(&encrypted);
    zval_ptr_dtor(&decrypted);
    return FAILURE;
}

// PHP Function: VM-based encryption
PHP_FUNCTION(kage_vm_encrypt) {
    zend_string *data;
    zend_string *key;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "SS", &data, &key) == FAILURE) {
        RETURN_FALSE;
    }
    
    // Initialize VM state
    kage_vm_state state;
    if (kage_vm_init(&state, KAGE_VM_STACK_SIZE) != SUCCESS) {
        RETURN_FALSE;
    }
    
    // Set encryption key
    state.key = key;
    
    // Create instructions
    state.instructions = emalloc(2 * sizeof(kage_instruction));
    if (state.instructions == NULL) {
        kage_vm_destroy(&state);
        RETURN_FALSE;
    }
    state.instruction_count = 2;
    
    // Initialize instructions
    state.instructions[0].opcode = KAGE_OP_PUSH;
    ZVAL_STR(&state.instructions[0].operand, data);
    
    state.instructions[1].opcode = KAGE_OP_ENCRYPT;
    ZVAL_NULL(&state.instructions[1].operand);
    
    // Execute VM
    zval result;
    if (kage_vm_execute(&state) == SUCCESS && 
        kage_vm_pop(&state, &result) == SUCCESS) {
        RETURN_ZVAL(&result, 0, 1);
    }
    
    kage_vm_destroy(&state);
    RETURN_FALSE;
}

// PHP Function: VM-based decryption
PHP_FUNCTION(kage_vm_decrypt) {
    zend_string *data;
    zend_string *key;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "SS", &data, &key) == FAILURE) {
        RETURN_FALSE;
    }
    
    // Initialize VM state
    kage_vm_state state;
    if (kage_vm_init(&state, KAGE_VM_STACK_SIZE) != SUCCESS) {
        RETURN_FALSE;
    }
    
    // Set decryption key
    state.key = key;
    
    // Create instructions
    state.instructions = emalloc(2 * sizeof(kage_instruction));
    if (state.instructions == NULL) {
        kage_vm_destroy(&state);
        RETURN_FALSE;
    }
    state.instruction_count = 2;
    
    // Initialize instructions
    state.instructions[0].opcode = KAGE_OP_PUSH;
    ZVAL_STR(&state.instructions[0].operand, data);
    
    state.instructions[1].opcode = KAGE_OP_DECRYPT;
    ZVAL_NULL(&state.instructions[1].operand);
    
    // Execute VM
    zval result;
    if (kage_vm_execute(&state) == SUCCESS && 
        kage_vm_pop(&state, &result) == SUCCESS) {
        RETURN_ZVAL(&result, 0, 1);
    }
    
    kage_vm_destroy(&state);
    RETURN_FALSE;
} 