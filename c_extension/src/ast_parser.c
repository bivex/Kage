/**
 * Kage AST Parser — Lexical and Syntax Analysis
 */

#include "ast.h"
#include "kage_memory.h"
#include <ctype.h>
#include <string.h>

/* Internal constants */
#define KAGE_PARSER_MAX_ERROR_LENGTH 256

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

/**
 * Creates a new AST node with proper initialization.
 */
static kage_ast_node* kage_ast_node_create(kage_ast_type type) {
    kage_ast_node *node = NULL;

    if (type >= KAGE_AST_PROGRAM && type <= KAGE_AST_CALL) {
        node = (kage_ast_node *)KAGE_ALLOC(sizeof(kage_ast_node));
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
 */
static kage_parser_error_t validate_parser_state(const kage_ast_parser *parser) {
    if (parser == NULL || parser->source == NULL) {
        return KAGE_PARSER_ERROR_NULL_POINTER;
    } else if (parser->position > parser->length) {
        return KAGE_PARSER_ERROR_SYNTAX_ERROR;
    }
    return KAGE_PARSER_SUCCESS;
}

// Get error message string for parser error code
static const char* kage_parser_error_message(kage_parser_error_t error) {
    switch (error) {
        case KAGE_PARSER_ERROR_NULL_POINTER:      return "Null pointer encountered";
        case KAGE_PARSER_ERROR_MEMORY_ALLOCATION: return "Memory allocation failed";
        case KAGE_PARSER_ERROR_SYNTAX_ERROR:      return "Syntax error";
        case KAGE_PARSER_ERROR_INVALID_TOKEN:     return "Invalid token";
        case KAGE_PARSER_ERROR_UNCLOSED_STRING:   return "Unclosed string literal";
        default:                                  return "Unknown parser error";
    }
}

/**
 * Reports parser errors with consistent formatting.
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
 * Internal string parsing implementation with detailed error handling.
 */
static kage_ast_node* parse_string_internal(kage_ast_parser *parser, kage_parser_error_t *error) {
    kage_ast_node *node = NULL;
    char *str = NULL;
    const char *start = NULL, *end = NULL;
    size_t len = 0;
    kage_parser_error_t local_error = validate_parser_state(parser);

    if (local_error != KAGE_PARSER_SUCCESS) {
        *error = local_error;
        return NULL;
    }

    node = kage_ast_node_create(KAGE_AST_STRING);
    if (!node) {
        *error = KAGE_PARSER_ERROR_MEMORY_ALLOCATION;
        return NULL;
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
 */
static kage_ast_node* parse_encrypt_operation(kage_ast_parser *parser, kage_parser_error_t *error) {
    kage_ast_node *node = NULL;
    kage_parser_error_t local_error = validate_parser_state(parser);

    if (local_error != KAGE_PARSER_SUCCESS) {
        *error = local_error;
        return NULL;
    }

    node = kage_ast_node_create(KAGE_AST_ENCRYPT);
    if (!node) {
        *error = KAGE_PARSER_ERROR_MEMORY_ALLOCATION;
        return NULL;
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
 */
static kage_ast_node* parse_decrypt_operation(kage_ast_parser *parser, kage_parser_error_t *error) {
    kage_ast_node *node = NULL;
    kage_parser_error_t local_error = validate_parser_state(parser);

    if (local_error != KAGE_PARSER_SUCCESS) {
        *error = local_error;
        return NULL;
    }

    node = kage_ast_node_create(KAGE_AST_DECRYPT);
    if (!node) {
        *error = KAGE_PARSER_ERROR_MEMORY_ALLOCATION;
        return NULL;
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
 */
PHPAPI kage_ast_node* kage_ast_parse(const char *source) {
    kage_ast_node *result = NULL;
    kage_scope *scope = NULL;
    kage_ast_node *current = NULL;
    bool found_expression = false;
    kage_ast_parser parser = {0};

    if (source == NULL) {
        zend_error(E_WARNING, "Kage AST: Cannot parse NULL source");
        return NULL;
    }

    size_t source_length = strlen(source);
    if (source_length == 0) {
        zend_error(E_WARNING, "Kage AST: Cannot parse empty source");
        return NULL;
    }

    scope = kage_scope_create(NULL);
    if (!scope) {
        return NULL;
    }

    parser = (kage_ast_parser){
        .source = source,
        .position = 0,
        .length = source_length,
        .error_handling = {0}
    };

    KAGE_SCOPE_ALLOC_AST_NODE(scope, program);
    if (!program) {
        goto end;
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
