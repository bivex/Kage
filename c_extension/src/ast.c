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
    /* Validate input */
    if (type < KAGE_AST_PROGRAM || type > KAGE_AST_CALL) {
        zend_error(E_WARNING, "Kage AST: Invalid node type %d", type);
        return NULL;
    }

    /* Allocate and initialize node */
    kage_ast_node *node = (kage_ast_node *)emalloc(sizeof(kage_ast_node));
    if (node == NULL) {
        zend_error(E_WARNING, "Kage AST: Memory allocation failed for AST node");
        return NULL;
    }

    /* Initialize all fields to prevent undefined behavior */
    node->type = type;
    ZVAL_NULL(&node->value);
    node->left = NULL;
    node->right = NULL;
    node->next = NULL;

    return node;
}

/**
 * Validates parser state before operations.
 *
 * @param parser The parser to validate
 * @return Error code indicating validation result
 */
static kage_parser_error_t validate_parser_state(const kage_ast_parser *parser) {
    if (parser == NULL) {
        return KAGE_PARSER_ERROR_NULL_POINTER;
    }
    if (parser->source == NULL) {
        return KAGE_PARSER_ERROR_NULL_POINTER;
    }
    if (parser->position > parser->length) {
        return KAGE_PARSER_ERROR_SYNTAX_ERROR;
    }
    return KAGE_PARSER_SUCCESS;
}

/**
 * Reports parser errors with consistent formatting.
 *
 * @param error The error code
 * @param position Position in source where error occurred
 * @param context Additional context information
 */
static void report_parser_error(kage_parser_error_t error, size_t position, const char *context) {
    const char *error_msg;

    switch (error) {
        case KAGE_PARSER_ERROR_NULL_POINTER:
            error_msg = "Null pointer encountered";
            break;
        case KAGE_PARSER_ERROR_MEMORY_ALLOCATION:
            error_msg = "Memory allocation failed";
            break;
        case KAGE_PARSER_ERROR_SYNTAX_ERROR:
            error_msg = "Syntax error";
            break;
        case KAGE_PARSER_ERROR_INVALID_TOKEN:
            error_msg = "Invalid token";
            break;
        case KAGE_PARSER_ERROR_UNCLOSED_STRING:
            error_msg = "Unclosed string literal";
            break;
        default:
            error_msg = "Unknown parser error";
    }

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
    *error = validate_parser_state(parser);
    if (*error != KAGE_PARSER_SUCCESS) {
        return NULL;
    }

    /* Create string node */
    kage_ast_node *node = kage_ast_node_create(KAGE_AST_STRING);
    if (node == NULL) {
        *error = KAGE_PARSER_ERROR_MEMORY_ALLOCATION;
        return NULL;
    }

    /* Skip opening quote */
    parser->position++;

    /* Validate we have content after opening quote */
    if (parser->position >= parser->length) {
        *error = KAGE_PARSER_ERROR_UNCLOSED_STRING;
        kage_ast_free(node);
        return NULL;
    }

    /* Find closing quote */
    const char *start = parser->source + parser->position;
    const char *end = (const char *)memchr(start, '"', parser->length - parser->position);

    if (end == NULL) {
        report_parser_error(KAGE_PARSER_ERROR_UNCLOSED_STRING, parser->position - 1, NULL);
        kage_ast_free(node);
        parser->position = parser->length; /* Prevent infinite loops */
        *error = KAGE_PARSER_ERROR_UNCLOSED_STRING;
        return NULL;
    }

    /* Extract and validate string content */
    size_t len = (size_t)(end - start);
    if (len == 0) {
        /* Empty string is valid */
        ZVAL_EMPTY_STRING(&node->value);
    } else {
        char *str = (char *)estrndup(start, len);
        if (str == NULL) {
            kage_ast_free(node);
            *error = KAGE_PARSER_ERROR_MEMORY_ALLOCATION;
            return NULL;
        }
        ZVAL_STRING(&node->value, str);
        efree(str);
    }

    /* Update parser position */
    parser->position += len + 1;
    *error = KAGE_PARSER_SUCCESS;
    return node;
}


/**
 * Parses an encrypt operation with its operand.
 *
 * @param parser The parser instance
 * @param error Pointer to store error code
 * @return Parsed encrypt node or NULL on error
 */
static kage_ast_node* parse_encrypt_operation(kage_ast_parser *parser, kage_parser_error_t *error) {
    *error = validate_parser_state(parser);
    if (*error != KAGE_PARSER_SUCCESS) {
        return NULL;
    }

    /* Create encrypt node */
    kage_ast_node *node = kage_ast_node_create(KAGE_AST_ENCRYPT);
    if (node == NULL) {
        *error = KAGE_PARSER_ERROR_MEMORY_ALLOCATION;
        return NULL;
    }

    /* Consume "encrypt" keyword */
    parser->position += 7;

    /* Skip whitespace after keyword */
    skip_whitespace(parser);

    /* Validate we have an operand */
    if (parser->position >= parser->length) {
        report_parser_error(KAGE_PARSER_ERROR_SYNTAX_ERROR, parser->position, "missing operand for encrypt");
        kage_ast_free(node);
        *error = KAGE_PARSER_ERROR_SYNTAX_ERROR;
        return NULL;
    }

    /* Parse operand (can be nested) */
    node->left = parse_expression(parser, NULL); // No scope needed for sub-expressions
    if (node->left == NULL) {
        kage_ast_free(node);
        *error = KAGE_PARSER_ERROR_SYNTAX_ERROR;
        return NULL;
    }

    *error = KAGE_PARSER_SUCCESS;
    return node;
}

/**
 * Parses a decrypt operation with its operand.
 *
 * @param parser The parser instance
 * @param error Pointer to store error code
 * @return Parsed decrypt node or NULL on error
 */
static kage_ast_node* parse_decrypt_operation(kage_ast_parser *parser, kage_parser_error_t *error) {
    *error = validate_parser_state(parser);
    if (*error != KAGE_PARSER_SUCCESS) {
        return NULL;
    }

    /* Create decrypt node */
    kage_ast_node *node = kage_ast_node_create(KAGE_AST_DECRYPT);
    if (node == NULL) {
        *error = KAGE_PARSER_ERROR_MEMORY_ALLOCATION;
        return NULL;
    }

    /* Consume "decrypt" keyword */
    parser->position += 7;

    /* Skip whitespace after keyword */
    skip_whitespace(parser);

    /* Validate we have an operand */
    if (parser->position >= parser->length) {
        report_parser_error(KAGE_PARSER_ERROR_SYNTAX_ERROR, parser->position, "missing operand for decrypt");
        kage_ast_free(node);
        *error = KAGE_PARSER_ERROR_SYNTAX_ERROR;
        return NULL;
    }

    /* Parse operand (can be nested) */
    node->left = parse_expression(parser, NULL); // No scope needed for sub-expressions
    if (node->left == NULL) {
        kage_ast_free(node);
        *error = KAGE_PARSER_ERROR_SYNTAX_ERROR;
        return NULL;
    }

    *error = KAGE_PARSER_SUCCESS;
    return node;
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
    kage_parser_error_t error;

    /* Validate parser state */
    error = validate_parser_state(parser);
    if (error != KAGE_PARSER_SUCCESS) {
        report_parser_error(error, parser->position, "invalid parser state");
        return NULL;
    }

    /* Skip leading whitespace */
    skip_whitespace(parser);

    /* Check for end of input */
    if (parser->position >= parser->length) {
        return NULL;
    }

    /* Dispatch to appropriate parser based on next token */
    char current_char = parser->source[parser->position];

    if (current_char == '"') {
        /* String literal */
        kage_ast_node *node = parse_string_internal(parser, &error);
        if (node && scope) {
            kage_scope_register_ast_node(scope, node);
        }
        return node;
    }
    else if (parser->position + 6 < parser->length &&
             strncmp(parser->source + parser->position, "encrypt", 7) == 0) {
        /* Encrypt operation */
        kage_ast_node *node = parse_encrypt_operation(parser, &error);
        if (node && scope) {
            kage_scope_register_ast_node(scope, node);
        }
        return node;
    }
    else if (parser->position + 6 < parser->length &&
             strncmp(parser->source + parser->position, "decrypt", 7) == 0) {
        /* Decrypt operation */
        kage_ast_node *node = parse_decrypt_operation(parser, &error);
        if (node && scope) {
            kage_scope_register_ast_node(scope, node);
        }
        return node;
    }
    else {
        /* Invalid token */
        report_parser_error(KAGE_PARSER_ERROR_INVALID_TOKEN, parser->position,
                           "expected string, 'encrypt', or 'decrypt'");
        /* Skip invalid token to prevent infinite loops */
        while (parser->position < parser->length &&
               !isspace((unsigned char)parser->source[parser->position]) &&
               parser->source[parser->position] != '"') {
            parser->position++;
        }
        return NULL;
    }
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
    /* Input validation */
    if (source == NULL) {
        zend_error(E_WARNING, "Kage AST: Cannot parse NULL source");
        return NULL;
    }

    size_t source_length = strlen(source);
    if (source_length == 0) {
        zend_error(E_WARNING, "Kage AST: Cannot parse empty source");
        return NULL;
    }

    /* Create memory scope for automatic cleanup */
    kage_scope *scope = kage_scope_create(NULL);
    if (!scope) {
        return NULL;
    }

    /* Initialize parser */
    kage_ast_parser parser = {
        .source = source,
        .position = 0,
        .length = source_length,
        .error_handling = {0}
    };

    /* Create program root node */
    KAGE_SCOPE_ALLOC_AST_NODE(scope, program);
    if (!program) {
        kage_scope_destroy(scope);
        return NULL; /* Error already logged */
    }
    program->type = KAGE_AST_PROGRAM;

    kage_ast_node *current = program;
    bool found_expression = false;

    /* Parse expressions until end of input */
    while (parser.position < parser.length) {
        /* Skip whitespace between expressions */
        skip_whitespace(&parser);
        if (parser.position >= parser.length) {
            break;
        }

        /* Parse next expression */
        kage_ast_node *expr = parse_expression(&parser, scope);
        if (expr == NULL) {
            /* Parse error - scope will clean up automatically */
            kage_scope_destroy(scope);
            return NULL;
        }

        /* Add expression to program */
        current->next = expr;
        current = expr;
        found_expression = true;
    }

    /* Validate that we parsed at least one expression */
    if (!found_expression) {
        zend_error(E_WARNING, "Kage AST: No valid expressions found in source");
        kage_scope_destroy(scope);
        return NULL;
    }

    /* Return the program node (scope will keep it alive) */
    scope->cleanup_on_exit = false; // Don't clean up the result
    kage_scope_destroy(scope);
    return program;

    /* Should not reach here */
    return NULL;
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
    if (state == NULL || state->instructions == NULL) {
        return FAILURE;
    }

    /* Check bounds - this is a simple check, in production you'd want dynamic resizing */
    if (state->instruction_count >= KAGE_PARSER_DEFAULT_STACK_SIZE) {
        zend_error(E_WARNING, "Kage AST: Too many instructions generated");
        return FAILURE;
    }

    kage_instruction *instr = &state->instructions[state->instruction_count++];
    instr->opcode = opcode;

    if (operand != NULL) {
        ZVAL_COPY(&instr->operand, operand);
    } else {
        ZVAL_NULL(&instr->operand);
    }

    return SUCCESS;
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
    if (node == NULL || state == NULL || node->left == NULL) {
        return FAILURE;
    }

    /* Convert operand first */
    if (ast_to_bytecode(node->left, state) != SUCCESS) {
        return FAILURE;
    }

    /* Add encrypt instruction */
    return add_instruction(state, KAGE_OP_ENCRYPT, NULL);
}

/**
 * Converts a decrypt AST node to bytecode.
 *
 * @param node The decrypt node
 * @param state The VM state
 * @return SUCCESS on success, FAILURE on error
 */
static int convert_decrypt_node(kage_ast_node *node, kage_vm_state *state) {
    if (node == NULL || state == NULL || node->left == NULL) {
        return FAILURE;
    }

    /* Convert operand first */
    if (ast_to_bytecode(node->left, state) != SUCCESS) {
        return FAILURE;
    }

    /* Add decrypt instruction */
    return add_instruction(state, KAGE_OP_DECRYPT, NULL);
}

/**
 * Converts a program AST node to bytecode.
 *
 * @param node The program node
 * @param state The VM state
 * @return SUCCESS on success, FAILURE on error
 */
static int convert_program_node(kage_ast_node *node, kage_vm_state *state) {
    if (node == NULL || state == NULL) {
        return FAILURE;
    }

    /* Process all statements in the program */
    kage_ast_node *stmt = node->next;
    while (stmt != NULL) {
        if (ast_to_bytecode(stmt, state) != SUCCESS) {
            return FAILURE;
        }
        stmt = stmt->next;
    }

    return SUCCESS;
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
    if (node == NULL || state == NULL) {
        return FAILURE;
    }

    /* Dispatch to appropriate conversion function based on node type */
    switch (node->type) {
        case KAGE_AST_STRING:
            return convert_string_node(node, state);

        case KAGE_AST_ENCRYPT:
            return convert_encrypt_node(node, state);

        case KAGE_AST_DECRYPT:
            return convert_decrypt_node(node, state);

        case KAGE_AST_PROGRAM:
            return convert_program_node(node, state);

        default:
            zend_error(E_WARNING, "Kage AST: Unknown AST node type: %d", node->type);
            return FAILURE;
    }
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
    /* Input validation */
    if (node == NULL || state == NULL) {
        zend_error(E_WARNING, "Kage AST: Invalid parameters for bytecode conversion");
        return FAILURE;
    }

    /* Allocate instruction buffer */
    state->instructions = (kage_instruction *)emalloc(KAGE_PARSER_DEFAULT_STACK_SIZE * sizeof(kage_instruction));
    if (state->instructions == NULL) {
        zend_error(E_WARNING, "Kage AST: Failed to allocate instruction memory");
        return FAILURE;
    }

    /* Initialize instruction counter */
    state->instruction_count = 0;

    /* Perform conversion */
    int result = ast_to_bytecode(node, state);

    /* Clean up on failure */
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

/**
 * Attempts to decrypt a zval in-place using the provided key.
 * This is a helper function for iterative decryption.
 *
 * @param value The zval to decrypt
 * @param key The decryption key
 * @return true if decryption succeeded, false otherwise
 */
static bool try_decrypt_zval(zval *value, zend_string *key) {
    if (value == NULL || key == NULL) {
        return false;
    }

    /* Only attempt decryption on strings */
    if (Z_TYPE_P(value) != IS_STRING) {
        return false;
    }

    zval decrypted_result;
    if (kage_internal_decrypt(&decrypted_result, value, key) != SUCCESS) {
        return false;
    }

    /* Replace original value with decrypted result */
    zval_ptr_dtor(value);
    ZVAL_COPY_VALUE(value, &decrypted_result);
    ZVAL_UNDEF(&decrypted_result); /* Prevent double destruction */

    return true;
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
        /* Continue decrypting - the loop condition handles the stopping */
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