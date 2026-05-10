/**
 * Kage AST (Abstract Syntax Tree) Parser and Bytecode Generator
 *
 * This module provides comprehensive AST parsing and bytecode generation
 * for the Kage PHP encryption language. It implements a recursive descent
 * parser with proper error handling and memory management.
 *
 * Architecture:
 * - AST Node: Represents language constructs (strings, encrypt/decrypt operations)
 * - Parser: Converts source text to AST using recursive descent
 * - Bytecode Generator: Converts AST to VM instructions
 *
 * Key Features:
 * - Memory-safe parsing with automatic cleanup
 * - Comprehensive error reporting
 * - Support for nested encryption/decryption operations
 * - Efficient bytecode generation for VM execution
 *
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-06-06 23:19
 * Last Updated: 2025-12-09 12:00
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#include "ast.h"
#include "vm.h"
#include "crypto.h"
#include "kage_memory.h"
#include <stddef.h> /* For ptrdiff_t */
#include <stdbool.h> /* For bool and true */
#include <math.h> /* For fmin */
#include <ctype.h> /* For isspace */

/* Internal constants */
#define KAGE_PARSER_MAX_ERROR_LENGTH 256
#define KAGE_PARSER_DEFAULT_STACK_SIZE 100

/* Error codes for consistent error handling */
typedef enum {
    KAGE_PARSER_SUCCESS = 0,
    KAGE_PARSER_ERROR_NULL_POINTER = -1,
    KAGE_PARSER_ERROR_MEMORY_ALLOCATION = -2,
    KAGE_PARSER_ERROR_SYNTAX_ERROR = -3,
    KAGE_PARSER_ERROR_INVALID_TOKEN = -4,
    KAGE_PARSER_ERROR_UNCLOSED_STRING = -5
} kage_parser_error_t;

/* Forward declarations for internal functions */
static kage_parser_error_t validate_parser_state(const kage_ast_parser *parser);
static void report_parser_error(kage_parser_error_t error, size_t position, const char *context);
static bool skip_whitespace(kage_ast_parser *parser);
static kage_ast_node* parse_string_internal(kage_ast_parser *parser, kage_parser_error_t *error);
static kage_ast_node* parse_expression(kage_ast_parser *parser, kage_scope *scope);
static kage_ast_node* parse_encrypt_operation(kage_ast_parser *parser, kage_parser_error_t *error);
static kage_ast_node* parse_decrypt_operation(kage_ast_parser *parser, kage_parser_error_t *error);
static int add_instruction(kage_vm_state *state, kage_opcode opcode, zval *operand);
static int convert_string_node(kage_ast_node *node, kage_vm_state *state);
static int convert_encrypt_node(kage_ast_node *node, kage_vm_state *state);
static int convert_decrypt_node(kage_ast_node *node, kage_vm_state *state);
static int convert_program_node(kage_ast_node *node, kage_vm_state *state);
static int ast_to_bytecode(kage_ast_node *node, kage_vm_state *state);

/**
 * Creates a new AST node with proper initialization.
 *
 * @param type The AST node type to create
 * @return Pointer to the new node, or NULL on allocation failure
 */
static kage_ast_node* kage_ast_node_create(kage_ast_type type) {
    kage_ast_node *node = NULL;

    if (type >= KAGE_AST_PROGRAM && type <= KAGE_AST_CALL) {
        node = (kage_ast_node *)emalloc(sizeof(kage_ast_node));
        if (node) {
            node->type = type;
            ZVAL_NULL(&node->value);
            node->left = node->right = node->next = NULL;
        } else {
            zend_error(E_WARNING, "Kage AST: Memory allocation failed for AST node");
        }
    } else {
        zend_error(E_WARNING, "Kage AST: Invalid node type %d", type);
    }

    return node;
}

/**
 * Validates parser state before operations.
 *
 * @param parser The parser to validate
 * @return Error code indicating validation result
 */
static kage_parser_error_t validate_parser_state(const kage_ast_parser *parser) {
    kage_parser_error_t result = KAGE_PARSER_SUCCESS;

    if (parser == NULL || parser->source == NULL) {
        result = KAGE_PARSER_ERROR_NULL_POINTER;
    } else if (parser->position > parser->length) {
        result = KAGE_PARSER_ERROR_SYNTAX_ERROR;
    }

    return result;
}

// Get error message string for parser error code
static const char* kage_parser_error_message(kage_parser_error_t error) {
    const char *msg = "Unknown parser error";
    switch (error) {
        case KAGE_PARSER_ERROR_NULL_POINTER:      msg = "Null pointer encountered";      break;
        case KAGE_PARSER_ERROR_MEMORY_ALLOCATION: msg = "Memory allocation failed";      break;
        case KAGE_PARSER_ERROR_SYNTAX_ERROR:      msg = "Syntax error";                  break;
        case KAGE_PARSER_ERROR_INVALID_TOKEN:     msg = "Invalid token";                 break;
        case KAGE_PARSER_ERROR_UNCLOSED_STRING:   msg = "Unclosed string literal";       break;
        default:                                  msg = "Unknown parser error";          break;
    }
    return msg;
}

/**
 * Reports parser errors with consistent formatting.
 *
 * @param error The error code
 * @param position Position in source where error occurred
 * @param context Additional context information
 */
static void report_parser_error(kage_parser_error_t error, size_t position, const char *context) {
    const char *error_msg = kage_parser_error_message(error);

    if (context && *context) {
        zend_error(E_WARNING, "Kage AST: %s at position %zu (%s)", error_msg, position, context);
    } else {
        zend_error(E_WARNING, "Kage AST: %s at position %zu", error_msg, position);
    }
}

/**
 * Skips whitespace characters in the parser input.
 *
 * @param parser The parser instance
 * @return true if whitespace was found and skipped, false otherwise
 */
static bool skip_whitespace(kage_ast_parser *parser) {
    bool skipped = false;
    while (parser->position < parser->length &&
           isspace((unsigned char)parser->source[parser->position])) {
        parser->position++;
        skipped = true;
    }
    return skipped;
}

/**
 * Frees an AST node and all its children recursively.
 * Uses post-order traversal to ensure safe cleanup.
 *
 * @param node The root node to free
 */
PHPAPI void kage_ast_free(kage_ast_node *node) {
    if (node == NULL) {
        return;
    }

    /* Recursively free children first (post-order traversal) */
    kage_ast_free(node->left);
    kage_ast_free(node->right);
    kage_ast_free(node->next);

    /* Clean up node value and free node itself */
    zval_ptr_dtor(&node->value);
    efree(node);
}

/**
 * Internal string parsing implementation with detailed error handling.
 *
 * @param parser The parser instance
 * @param error Pointer to store error code
 * @return Parsed AST node or NULL on error
 */
static kage_ast_node* parse_string_internal(kage_ast_parser *parser, kage_parser_error_t *error) {
    kage_ast_node *node = NULL;
    char *str = NULL;
    const char *start = NULL, *end = NULL;
    size_t len = 0;
    kage_parser_error_t local_error = KAGE_PARSER_SUCCESS;

    local_error = validate_parser_state(parser);
    if (local_error != KAGE_PARSER_SUCCESS) {
        *error = local_error;
        goto cleanup;
    }

    node = kage_ast_node_create(KAGE_AST_STRING);
    if (!node) {
        *error = KAGE_PARSER_ERROR_MEMORY_ALLOCATION;
        goto cleanup;
    }

    parser->position++;

    if (parser->position >= parser->length) {
        *error = KAGE_PARSER_ERROR_UNCLOSED_STRING;
        goto cleanup;
    }

    start = parser->source + parser->position;
    end = (const char *)memchr(start, '"', parser->length - parser->position);
    if (!end) {
        report_parser_error(KAGE_PARSER_ERROR_UNCLOSED_STRING, parser->position - 1, NULL);
        parser->position = parser->length;
        *error = KAGE_PARSER_ERROR_UNCLOSED_STRING;
        goto cleanup;
    }

    len = (size_t)(end - start);
    if (len == 0) {
        ZVAL_EMPTY_STRING(&node->value);
    } else {
        str = (char *)estrndup(start, len);
        if (!str) {
            *error = KAGE_PARSER_ERROR_MEMORY_ALLOCATION;
            goto cleanup;
        }
        ZVAL_STRING(&node->value, str);
        efree(str);
        str = NULL;
    }

    parser->position += len + 1;
    *error = KAGE_PARSER_SUCCESS;
    return node;

cleanup:
    if (node) {
        kage_ast_free(node);
    }
    if (str) {
        efree(str);
    }
    return NULL;
}


/**
 * Parses an encrypt operation with its operand.
 *
 * @param parser The parser instance
 * @param error Pointer to store error code
 * @return Parsed encrypt node or NULL on error
 */
static kage_ast_node* parse_encrypt_operation(kage_ast_parser *parser, kage_parser_error_t *error) {
    kage_ast_node *node = NULL;
    kage_parser_error_t local_error = KAGE_PARSER_SUCCESS;

    local_error = validate_parser_state(parser);
    if (local_error != KAGE_PARSER_SUCCESS) {
        *error = local_error;
        goto cleanup;
    }

    node = kage_ast_node_create(KAGE_AST_ENCRYPT);
    if (!node) {
        *error = KAGE_PARSER_ERROR_MEMORY_ALLOCATION;
        goto cleanup;
    }

    parser->position += 7;
    skip_whitespace(parser);

    if (parser->position >= parser->length) {
        report_parser_error(KAGE_PARSER_ERROR_SYNTAX_ERROR, parser->position, "missing operand for encrypt");
        *error = KAGE_PARSER_ERROR_SYNTAX_ERROR;
        goto cleanup;
    }

    node->left = parse_expression(parser, NULL);
    if (!node->left) {
        *error = KAGE_PARSER_ERROR_SYNTAX_ERROR;
        goto cleanup;
    }

    *error = KAGE_PARSER_SUCCESS;
    return node;

cleanup:
    if (node) {
        kage_ast_free(node);
    }
    return NULL;
}

/**
 * Parses a decrypt operation with its operand.
 *
 * @param parser The parser instance
 * @param error Pointer to store error code
 * @return Parsed decrypt node or NULL on error
 */
static kage_ast_node* parse_decrypt_operation(kage_ast_parser *parser, kage_parser_error_t *error) {
    kage_ast_node *node = NULL;
    kage_parser_error_t local_error = KAGE_PARSER_SUCCESS;

    local_error = validate_parser_state(parser);
    if (local_error != KAGE_PARSER_SUCCESS) {
        *error = local_error;
        goto cleanup;
    }

    node = kage_ast_node_create(KAGE_AST_DECRYPT);
    if (!node) {
        *error = KAGE_PARSER_ERROR_MEMORY_ALLOCATION;
        goto cleanup;
    }

    parser->position += 7;
    skip_whitespace(parser);

    if (parser->position >= parser->length) {
        report_parser_error(KAGE_PARSER_ERROR_SYNTAX_ERROR, parser->position, "missing operand for decrypt");
        *error = KAGE_PARSER_ERROR_SYNTAX_ERROR;
        goto cleanup;
    }

    node->left = parse_expression(parser, NULL);
    if (!node->left) {
        *error = KAGE_PARSER_ERROR_SYNTAX_ERROR;
        goto cleanup;
    }

    *error = KAGE_PARSER_SUCCESS;
    return node;

cleanup:
    if (node) {
        kage_ast_free(node);
    }
    return NULL;
}

/**
 * Parses a complete expression from the input stream.
 * This is the main expression parser that handles all expression types.
 * Uses memory scope for automatic cleanup.
 *
 * @param parser The parser instance
 * @param scope Memory scope for automatic resource management
 * @return Parsed expression node or NULL on error
 */
static kage_ast_node* parse_expression(kage_ast_parser *parser, kage_scope *scope) {
    kage_ast_node *result = NULL;
    kage_parser_error_t error;

    error = validate_parser_state(parser);
    if (error == KAGE_PARSER_SUCCESS) {
        skip_whitespace(parser);
        if (parser->position < parser->length) {
            char current_char = parser->source[parser->position];
            if (current_char == '"') {
                result = parse_string_internal(parser, &error);
            } else if (parser->position + 6 < parser->length &&
                       strncmp(parser->source + parser->position, "encrypt", 7) == 0) {
                result = parse_encrypt_operation(parser, &error);
            } else if (parser->position + 6 < parser->length &&
                       strncmp(parser->source + parser->position, "decrypt", 7) == 0) {
                result = parse_decrypt_operation(parser, &error);
            } else {
                report_parser_error(KAGE_PARSER_ERROR_INVALID_TOKEN, parser->position,
                                   "expected string, 'encrypt', or 'decrypt'");
                while (parser->position < parser->length &&
                       !isspace((unsigned char)parser->source[parser->position]) &&
                                               parser->source[parser->position] != '"') {
                    parser->position++;
                }
                result = NULL;
            }
        }
    } else {
        report_parser_error(error, parser->position, "invalid parser state");
    }

    if (result && scope) {
        kage_scope_register_ast_node(scope, result);
    }
    return result;
}

/**
 * Parses source code into an Abstract Syntax Tree (AST).
 * This is the main entry point for parsing Kage language source code.
 * Uses memory scope for automatic resource management.
 *
 * The parser supports:
 * - String literals: "hello world"
 * - Encrypt operations: encrypt "secret"
 * - Decrypt operations: decrypt "encrypted_data"
 * - Nested operations: encrypt decrypt "data"
 *
 * @param source The source code string to parse
 * @return Root AST node on success, NULL on error (errors are logged)
 */
PHPAPI kage_ast_node* kage_ast_parse(const char *source) {
    kage_ast_node *result = NULL;
    kage_scope *scope = NULL;
    kage_ast_node *program = NULL;
    kage_ast_node *current = NULL;
    bool found_expression = false;
    kage_ast_parser parser = {0};

    if (source == NULL) {
        zend_error(E_WARNING, "Kage AST: Cannot parse NULL source");
        goto end;
    }

    size_t source_length = strlen(source);
    if (source_length == 0) {
        zend_error(E_WARNING, "Kage AST: Cannot parse empty source");
        goto end;
    }

    scope = kage_scope_create(NULL);
    if (!scope) {
        goto end;
    }

    parser = (kage_ast_parser){
        .source = source,
        .position = 0,
        .length = source_length,
        .error_handling = {0}
    };

    KAGE_SCOPE_ALLOC_AST_NODE(scope, program);
    if (!program) {
        goto end; /* Error already logged by allocation macro */
    }
    program->type = KAGE_AST_PROGRAM;

    current = program;
    found_expression = false;

    while (parser.position < parser.length) {
        skip_whitespace(&parser);
        if (parser.position >= parser.length) {
            break;
        }

        kage_ast_node *expr = parse_expression(&parser, scope);
        if (!expr) {
            goto end;
        }

        current->next = expr;
        current = expr;
        found_expression = true;
    }

    if (!found_expression) {
        zend_error(E_WARNING, "Kage AST: No valid expressions found in source");
        goto end;
    }

    /* Success: transfer ownership to caller */
    scope->cleanup_on_exit = false;
    result = program;
    program = NULL; // Prevent cleanup

end:
    if (scope) {
        kage_scope_destroy(scope);
    }
    return result;
}

/**
 * Adds an instruction to the VM state with bounds checking.
 *
 * @param state The VM state
 * @param opcode The operation code
 * @param operand The operand value (can be NULL)
 * @return SUCCESS on success, FAILURE on error
 */
static int add_instruction(kage_vm_state *state, kage_opcode opcode, zval *operand) {
    int result = FAILURE;

    if (state != NULL && state->instructions != NULL) {
        if (state->instruction_count < KAGE_PARSER_DEFAULT_STACK_SIZE) {
            kage_instruction *instr = &state->instructions[state->instruction_count++];
            instr->opcode = opcode;
            if (operand != NULL) {
                ZVAL_COPY(&instr->operand, operand);
            } else {
                ZVAL_NULL(&instr->operand);
            }
            result = SUCCESS;
        } else {
            zend_error(E_WARNING, "Kage AST: Too many instructions generated");
        }
    }

    return result;
}

/**
 * Converts a string AST node to bytecode.
 *
 * @param node The string node
 * @param state The VM state
 * @return SUCCESS on success, FAILURE on error
 */
static int convert_string_node(kage_ast_node *node, kage_vm_state *state) {
    if (node == NULL || state == NULL) {
        return FAILURE;
    }
    return add_instruction(state, KAGE_OP_PUSH, &node->value);
}

/**
 * Converts an encrypt AST node to bytecode.
 *
 * @param node The encrypt node
 * @param state The VM state
 * @return SUCCESS on success, FAILURE on error
 */
static int convert_encrypt_node(kage_ast_node *node, kage_vm_state *state) {
    int result = FAILURE;

    if (node != NULL && state != NULL && node->left != NULL) {
        if (ast_to_bytecode(node->left, state) == SUCCESS) {
            result = add_instruction(state, KAGE_OP_ENCRYPT, NULL);
        }
    }

    return result;
}

/**
 * Converts a decrypt AST node to bytecode.
 *
 * @param node The decrypt node
 * @param state The VM state
 * @return SUCCESS on success, FAILURE on error
 */
static int convert_decrypt_node(kage_ast_node *node, kage_vm_state *state) {
    int result = FAILURE;

    if (node != NULL && state != NULL && node->left != NULL) {
        if (ast_to_bytecode(node->left, state) == SUCCESS) {
            result = add_instruction(state, KAGE_OP_DECRYPT, NULL);
        }
    }

    return result;
}

/**
 * Converts a program AST node to bytecode.
 *
 * @param node The program node
 * @param state The VM state
 * @return SUCCESS on success, FAILURE on error
 */
static int convert_program_node(kage_ast_node *node, kage_vm_state *state) {
    int result = FAILURE;
    kage_ast_node *stmt = NULL;

    if (node == NULL || state == NULL) {
        goto end;
    }

    stmt = node->next;
    while (stmt != NULL) {
        if (ast_to_bytecode(stmt, state) != SUCCESS) {
            goto end;
        }
        stmt = stmt->next;
    }

    result = SUCCESS;

end:
    return result;
}

/**
 * Converts an AST node to bytecode instructions for VM execution.
 * This function dispatches to specialized handlers based on node type.
 *
 * @param node The AST node to convert
 * @param state The VM state to store generated instructions
 * @return SUCCESS on success, FAILURE on error
 */
static int ast_to_bytecode(kage_ast_node *node, kage_vm_state *state) {
    int result = FAILURE;

    if (node == NULL || state == NULL) {
        goto end;
    }

    /* Dispatch to appropriate conversion function based on node type */
    switch (node->type) {
        case KAGE_AST_STRING:
            result = convert_string_node(node, state);
            break;
        case KAGE_AST_ENCRYPT:
            result = convert_encrypt_node(node, state);
            break;
        case KAGE_AST_DECRYPT:
            result = convert_decrypt_node(node, state);
            break;
        case KAGE_AST_PROGRAM:
            result = convert_program_node(node, state);
            break;
        default:
            zend_error(E_WARNING, "Kage AST: Unknown AST node type: %d", node->type);
            result = FAILURE;
            break;
    }

end:
    return result;
}

/**
 * Converts an AST to bytecode instructions for VM execution.
 * This function allocates instruction memory and performs the conversion.
 *
 * @param node The root AST node to convert
 * @param state The VM state to populate with instructions
 * @return SUCCESS on successful conversion, FAILURE on error
 */
PHPAPI int kage_ast_to_bytecode(kage_ast_node *node, kage_vm_state *state) {
    int result = FAILURE;

    /* Input validation */
    if (node == NULL || state == NULL) {
        zend_error(E_WARNING, "Kage AST: Invalid parameters for bytecode conversion");
        goto end;
    }

    /* Allocate instruction buffer */
    state->instructions = (kage_instruction *)emalloc(KAGE_PARSER_DEFAULT_STACK_SIZE * sizeof(kage_instruction));
    if (state->instructions == NULL) {
        zend_error(E_WARNING, "Kage AST: Failed to allocate instruction memory");
        goto end;
    }

    /* Initialize instruction counter */
    state->instruction_count = 0;

    /* Perform conversion */
    result = ast_to_bytecode(node, state);
    if (result != SUCCESS) {
        efree(state->instructions);
        state->instructions = NULL;
        state->instruction_count = 0;
        result = FAILURE;
    }

end:
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

/**
 * Attempts to decrypt a zval in-place using the provided key.
 * This is a helper function for iterative decryption.
 *
 * @param value The zval to decrypt
 * @param key The decryption key
 * @return true if decryption succeeded, false otherwise
 */
static bool try_decrypt_zval(zval *value, zend_string *key) {
    bool success = false;
    zval decrypted_result;

    if (value == NULL || key == NULL) {
        goto end;
    }

    /* Only attempt decryption on strings */
    if (Z_TYPE_P(value) != IS_STRING) {
        goto end;
    }

    if (kage_internal_decrypt(&decrypted_result, value, key) != SUCCESS) {
        goto end;
    }

    /* Replace original value with decrypted result */
    zval_ptr_dtor(value);
    ZVAL_COPY_VALUE(value, &decrypted_result);
    ZVAL_UNDEF(&decrypted_result);
    success = true;

end:
    return success;
}

/**
 * Fully decrypts a result by iteratively decrypting until no further
 * decryption is possible or decryption fails.
 *
 * @param result The result to decrypt
 * @param key The decryption key
 */
static void fully_decrypt_result(zval *result, zend_string *key) {
    if (result == NULL || key == NULL) {
        return;
    }

    /* Iteratively decrypt until we can't decrypt anymore */
    while (try_decrypt_zval(result, key)) {
        continue; // Decryption happens in condition; loop until no more layers
    }
}

/**
 * PHP Function: kage_ast_to_bytecode
 * Converts an AST resource to bytecode and executes it.
 *
 * @param resource $ast AST resource from kage_ast_parse()
 * @param string $key Encryption/decryption key
 * @return mixed Execution result or FALSE on error
 */
PHP_FUNCTION(kage_ast_to_bytecode) {
    zval *ast_zv;
    zend_string *key;

    /* Parse PHP parameters */
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "rS", &ast_zv, &key) == FAILURE) {
        RETURN_FALSE;
    }

    /* Extract AST from resource */
    kage_ast_node *ast = (kage_ast_node*)zend_fetch_resource(Z_RES_P(ast_zv), "Kage AST", le_kage_ast);
    if (ast == NULL) {
        RETURN_FALSE;
    }

    /* Initialize VM state */
    kage_vm_state state;
    if (kage_vm_init(&state, KAGE_VM_STACK_SIZE) != SUCCESS) {
        RETURN_FALSE;
    }

    /* Set encryption key */
    state.key = key;

    /* Convert AST to bytecode */
    if (kage_ast_to_bytecode(ast, &state) != SUCCESS) {
        kage_vm_destroy(&state);
        RETURN_FALSE;
    }

    /* Execute VM */
    zval result;
    if (kage_vm_execute(&state) != SUCCESS || kage_vm_pop(&state, &result) != SUCCESS) {
        kage_vm_destroy(&state);
        RETURN_FALSE;
    }

    /* Fully decrypt the result */
    fully_decrypt_result(&result, key);

    /* Clean up and return result */
    kage_vm_destroy(&state);
    RETURN_ZVAL(&result, 0, 1);
} 