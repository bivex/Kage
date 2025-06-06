/**
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-06-06 23:19
 * Last Updated: 2025-06-07 02:25
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#include "ast.h"
#include "vm.h"
#include "crypto.h"
#include <stddef.h> /* For ptrdiff_t */
#include <stdbool.h> /* For bool and true */
#include <math.h> /* For fmin */

// Create a new AST node
static kage_ast_node* kage_ast_node_create(kage_ast_type type) {
    kage_ast_node *node = (kage_ast_node *)emalloc(sizeof(kage_ast_node)); // MISRA23_11.4
    if (node == NULL) { // POWER_OF_TEN_07_B
        return NULL;
    }
    node->type = type;
    ZVAL_NULL(&node->value);
    node->left = NULL;
    node->right = NULL;
    node->next = NULL;
    return node;
}

// Free an AST node and its children
PHPAPI void kage_ast_free(kage_ast_node *node) {
    if (node == NULL) { // MISRA23_10.1, MISRA23_15.6
        return;
    }
    
    kage_ast_free(node->left);
    kage_ast_free(node->right);
    kage_ast_free(node->next);
    
    zval_ptr_dtor(&node->value);
    efree(node);
}

// Parse a string literal
static kage_ast_node* parse_string(kage_ast_parser *parser) {
    if (parser == NULL) { // POWER_OF_TEN_07_B
        return NULL;
    }
    kage_ast_node *node = kage_ast_node_create(KAGE_AST_STRING);
    if (node == NULL) { // POWER_OF_TEN_07_B
        return NULL;
    }
    
    // Skip opening quote
    parser->position++;
    
    // Find closing quote
    const char *start = parser->source + (ptrdiff_t)parser->position; // MISRA23_10.4
    const char *end = (const char *)memchr(start, '"', parser->length - parser->position); // MISRA23_21.17, MISRA23_11.4
    // MISRA23_11.5: Casting void* from memchr to const char* is necessary and safe for byte-level string manipulation.
    // MISRA23_18.2: Subtraction between pointers 'end' and 'start' is valid as they point within the same array object (parser->source).
    if (end == NULL) { // MISRA23_10.1
        zend_error(E_WARNING, "Kage AST: Unclosed string literal starting at position %zu.", parser->position - 1);
        kage_ast_free(node);
        // Advance parser position to the end to prevent infinite loop
        parser->position = parser->length;
        return NULL;
    }
    
    // Extract string value
    size_t len = end - start;
    char *str = (char *)estrndup(start, len); // MISRA23_11.4
    if (str == NULL) { // POWER_OF_TEN_07_B
        kage_ast_free(node);
        return NULL;
    }
    ZVAL_STRING(&node->value, str);
    efree(str);
    
    // Update position
    parser->position += len + 1;
    
    return node;
}

// Parse an expression
static kage_ast_node* parse_expression(kage_ast_parser *parser) {
    if (parser == NULL) { // POWER_OF_TEN_07_B
        return NULL;
    }
    // Skip whitespace
    while ((parser->position < parser->length) && 
           (isspace((int)parser->source[parser->position]) != 0)) { // MISRA23_10.1
        parser->position++;
    }
    
    if (parser->position >= parser->length) {
        return NULL;
    }
    
    // Parse string literal
    if (parser->source[parser->position] == '"') {
        kage_ast_node *node = parse_string(parser);
        if (node == NULL) {
            return NULL; // parse_string already reports error if it fails
        }
        return node;
    }
    
    // Parse encrypt/decrypt operations
    if (strncmp(parser->source + (ptrdiff_t)parser->position, "encrypt", 7) == 0) { // MISRA23_10.4
        kage_ast_node *node = kage_ast_node_create(KAGE_AST_ENCRYPT);
        parser->position += 7; // Consume "encrypt"
        
        // Skip whitespace after "encrypt" keyword before parsing operand
        while ((parser->position < parser->length) && 
               (isspace((int)parser->source[parser->position]) != 0)) { // MISRA23_10.1
            parser->position++;
        }
        
        // Recursively parse the operand, which can be another expression (e.g., "encrypt encrypt ...")
        node->left = parse_expression(parser); 
        if (node->left == NULL) { // MISRA23_10.1
            zend_error(E_WARNING, "Kage AST: Missing or invalid operand for 'encrypt' at position %zu.", parser->position);
            kage_ast_free(node);
            return NULL;
        }
        return node;
    }
    
    if (strncmp(parser->source + (ptrdiff_t)parser->position, "decrypt", 7) == 0) { // MISRA23_10.4
        kage_ast_node *node = kage_ast_node_create(KAGE_AST_DECRYPT);
        parser->position += 7; // Consume "decrypt"
        
        // Skip whitespace after "decrypt" keyword before parsing operand
        while ((parser->position < parser->length) && 
               (isspace((int)parser->source[parser->position]) != 0)) { // MISRA23_10.1
            parser->position++;
        }
        
        // Recursively parse the operand
        node->left = parse_expression(parser); 
        if (node->left == NULL) { // MISRA23_10.1
            zend_error(E_WARNING, "Kage AST: Missing or invalid operand for 'decrypt' at position %zu.", parser->position);
            kage_ast_free(node);
            return NULL;
        }
        return node;
    }
    
    // If none of the above matched, it's an unexpected token
    zend_error(E_WARNING, "Kage AST: Unexpected token '%.*s' at position %zu. Parsing stopped.",
               (int)fmin((double)10, (double)(parser->length - parser->position)), // MISRA23_10.4
               parser->source + (ptrdiff_t)parser->position, // MISRA23_10.4
               parser->position);
    // Advance parser position past the unknown token to prevent infinite loop
    while ((parser->position < parser->length) && 
           ((isspace((int)parser->source[parser->position]) == 0)) && // MISRA23_10.1
           (parser->source[parser->position] != '"')) {
        parser->position++;
    }
    return NULL;
}

// Parse the source code into an AST
PHPAPI kage_ast_node* kage_ast_parse(const char *source) {
    if (source == NULL) { // POWER_OF_TEN_07_B
        return NULL;
    }
    kage_ast_parser parser = {
        .source = source,
        .position = 0,
        .length = strlen(source),
        .error_handling = {0}
    };
    
    kage_ast_node *program = kage_ast_node_create(KAGE_AST_PROGRAM);
    if (program == NULL) { // POWER_OF_TEN_07_B
        return NULL;
    }
    kage_ast_node *current = program;
    
    zend_bool found_expression = false; // Flag to track if any successful expression was parsed // MISRA23_14.4

    while (parser.position < parser.length) {
        // Skip any leading whitespace before trying to parse an expression
        while ((parser.position < parser.length) && (isspace((int)parser.source[parser.position]) != 0)) { // MISRA23_10.1
            parser.position++;
        }
        if (parser.position >= parser.length) {
            break; // Reached end of input after skipping whitespace
        }

        kage_ast_node *expr = parse_expression(&parser);
        if (expr == NULL) { // MISRA23_10.1
            // An error occurred during expression parsing.
            // Clean up the partially built AST and return NULL.
            kage_ast_free(program);
            return NULL;
        }
        
        current->next = expr; // MISRA23_13.4: This is a direct assignment, not an assignment used as a controlling expression or operand.
        current = expr; // MISRA23_13.4: This is a direct assignment, not an assignment used as a controlling expression or operand.
        found_expression = true; // At least one expression was successfully parsed // MISRA23_14.4
    }
    
    // If no expressions were found in the input (e.g., empty string, only whitespace, or initial parse_expression failed)
    if ((found_expression == false) && (program->next == NULL)) { // MISRA23_14.4
        kage_ast_free(program);
        return NULL;
    }

    return program;
}

// Convert AST node to bytecode
static zend_result ast_to_bytecode(kage_ast_node *node, kage_vm_state *state) {
    if (node == NULL) { // MISRA23_10.1, MISRA23_15.6
        return SUCCESS;
    }

    // DEBUG: Print node type being processed
    php_printf("DEBUG: ast_to_bytecode processing node type: %d\n", node->type);
    
    switch (node->type) {
        case KAGE_AST_STRING: {
            php_printf("DEBUG:   AST_STRING node, value: %s\n", Z_STRVAL(node->value));
            // Create PUSH instruction
            kage_instruction *instr = &state->instructions[state->instruction_count]; // MISRA23_13.3
            state->instruction_count++; // MISRA23_13.3
            instr->opcode = KAGE_OP_PUSH;
            ZVAL_COPY(&instr->operand, &node->value);
            php_printf("DEBUG:   Added PUSH instruction. Instruction count: %zu\n", state->instruction_count);
            break;
        }
        
        case KAGE_AST_ENCRYPT: {
            php_printf("DEBUG:   AST_ENCRYPT node. Converting left child.\n");
            // First convert the expression to be encrypted
            if (ast_to_bytecode(node->left, state) != SUCCESS) {
                php_printf("DEBUG:   Failed to convert left child for AST_ENCRYPT.\n");
                return FAILURE;
            }
            
            // Add ENCRYPT instruction
            kage_instruction *instr = &state->instructions[state->instruction_count]; // MISRA23_13.3
            state->instruction_count++; // MISRA23_13.3
            instr->opcode = KAGE_OP_ENCRYPT;
            ZVAL_NULL(&instr->operand);
            php_printf("DEBUG:   Added ENCRYPT instruction. Instruction count: %zu\n", state->instruction_count);
            break;
        }
        
        case KAGE_AST_DECRYPT: {
             php_printf("DEBUG:   AST_DECRYPT node. Converting left child.\n");
            // First convert the expression to be decrypted
            if (ast_to_bytecode(node->left, state) != SUCCESS) {
                 php_printf("DEBUG:   Failed to convert left child for AST_DECRYPT.\n");
                return FAILURE;
            }
            
            // Add DECRYPT instruction
            kage_instruction *instr = &state->instructions[state->instruction_count]; // MISRA23_13.3
            state->instruction_count++; // MISRA23_13.3
            instr->opcode = KAGE_OP_DECRYPT;
            ZVAL_NULL(&instr->operand);
            php_printf("DEBUG:   Added DECRYPT instruction. Instruction count: %zu\n", state->instruction_count);
            break;
        }
        
        case KAGE_AST_PROGRAM: {
             php_printf("DEBUG:   AST_PROGRAM node. Processing statements.\n");
            // Process all statements
            kage_ast_node *stmt = node->next;
            while (stmt != NULL) { // MISRA23_14.4
                if (ast_to_bytecode(stmt, state) != SUCCESS) {
                     php_printf("DEBUG:   Failed to process statement in AST_PROGRAM.\n");
                    return FAILURE;
                }
                stmt = stmt->next;
            }
             php_printf("DEBUG:   Finished processing statements in AST_PROGRAM.\n");
            break;
        }
        
        default:
             php_printf("DEBUG:   Unknown AST node type: %d. Returning FAILURE.\n", node->type);
            return FAILURE;
    }
    
    php_printf("DEBUG:   Successfully processed node type %d. Returning SUCCESS.\n", node->type);
    return SUCCESS;
}

// Convert AST to bytecode
PHPAPI zend_result kage_ast_to_bytecode(kage_ast_node *node, kage_vm_state *state) {
    if ((node == NULL) || (state == NULL)) { // MISRA23_14.4, MISRA23_10.1
        return FAILURE;
    }
    
    // Allocate space for instructions (estimate)
    state->instructions = (kage_instruction *)emalloc(100 * sizeof(kage_instruction)); // MISRA23_11.4
    if (state->instructions == NULL) { // POWER_OF_TEN_07_B
        return FAILURE;
    }
    state->instruction_count = 0;
    
    zend_result result = ast_to_bytecode(node, state);
    
    if (result != SUCCESS) {
        efree(state->instructions);
        state->instructions = NULL;
        state->instruction_count = 0;
    }
    
    return result;
}

// PHP Function: Parse AST
PHP_FUNCTION(kage_ast_parse) {
    zend_string *source;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "S", &source) == FAILURE) {
        RETURN_FALSE;
    }
    
    kage_ast_node *ast = kage_ast_parse(ZSTR_VAL(source));
    if (ast == NULL) { // MISRA23_10.1
        RETURN_FALSE;
    }
    
    // Convert AST to resource
    zend_resource *res = zend_register_resource(ast, le_kage_ast);
    RETURN_RES(res);
}

// PHP Function: Convert AST to bytecode
PHP_FUNCTION(kage_ast_to_bytecode) {
    zval *ast_zv;
    zend_string *key;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "rS", &ast_zv, &key) == FAILURE) {
        RETURN_FALSE;
    }
    
    kage_ast_node *ast = (kage_ast_node*)zend_fetch_resource(Z_RES_P(ast_zv), "Kage AST", le_kage_ast);
    if (ast == NULL) { // MISRA23_10.1
        RETURN_FALSE;
    }
    
    // Initialize VM state
    kage_vm_state state;
    if (kage_vm_init(&state, KAGE_VM_STACK_SIZE) != SUCCESS) {
        RETURN_FALSE;
    }
    
    // Set encryption key
    state.key = key;
    
    // Convert AST to bytecode
    if (kage_ast_to_bytecode(ast, &state) != SUCCESS) { // This calls the C function
        kage_vm_destroy(&state);
        RETURN_FALSE;
    }
    
    // Execute VM
    zval result;
    
    zend_bool execution_and_pop_successful = false; // Flag for MISRA23_15.4 single exit
    if ((kage_vm_execute(&state) == SUCCESS) && (kage_vm_pop(&state, &result) == SUCCESS)) {
        execution_and_pop_successful = true;
    }

    if (execution_and_pop_successful == true) { // Check the flag for MISRA23_15.4
        // Repeatedly attempt to decrypt the result until it's no longer an encrypted string
        // or decryption fails (e.g., already plaintext).
        zval current_result;
        ZVAL_COPY_VALUE(&current_result, &result);

        zend_bool keep_decrypting = true; // For MISRA23_15.4 (more than one break or goto in loop)
        while (keep_decrypting == true) { // MISRA23_14.4
            if (Z_TYPE(current_result) != IS_STRING) {
                keep_decrypting = false; // Set flag to exit loop
            }
            
            zval temp_decrypted_result;
            // Attempt to decrypt current_result
            if ((keep_decrypting == true) && (kage_internal_decrypt(&temp_decrypted_result, &current_result, state.key) == SUCCESS)) { // check flag again
                // If successful, replace current_result with the newly decrypted value
                zval_ptr_dtor(&current_result); // Destroy the old current_result
                ZVAL_COPY_VALUE(&current_result, &temp_decrypted_result); // Assign the new decrypted result
                ZVAL_UNDEF(&temp_decrypted_result); // Prevent destruction of the underlying string
            } else {
                // Decryption failed (e.g., not encrypted, or bad key/data), so stop trying.
                keep_decrypting = false; // Set flag to exit loop
            }
        }

        // Return the final result (either original, or fully decrypted)
        RETURN_ZVAL(&current_result, 0, 1);

    } else {
        // VM execution or pop failed
        RETURN_FALSE;
    }
    
    kage_vm_destroy(&state);
} 