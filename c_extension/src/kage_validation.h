/**
 * Kage Input Validation and Sanitization
 *
 * Comprehensive input validation and sanitization system for security
 * and data integrity.
 *
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-12-09
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#ifndef PHP_KAGE_VALIDATION_H
#define PHP_KAGE_VALIDATION_H

#include "config.h"
#include <stdbool.h>

// Validation result structure
typedef struct {
    bool is_valid;
    const char *error_message;
    size_t error_offset;
} kage_validation_result_t;

// Input types for validation
typedef enum {
    KAGE_INPUT_TYPE_STRING,
    KAGE_INPUT_TYPE_BINARY,
    KAGE_INPUT_TYPE_KEY,
    KAGE_INPUT_TYPE_SOURCE_CODE,
    KAGE_INPUT_TYPE_IDENTIFIER,
    KAGE_INPUT_TYPE_PATH,
    KAGE_INPUT_TYPE_URL
} kage_input_type;

// Validation rules
typedef enum {
    KAGE_RULE_NOT_NULL,
    KAGE_RULE_NOT_EMPTY,
    KAGE_RULE_MIN_LENGTH,
    KAGE_RULE_MAX_LENGTH,
    KAGE_RULE_ALPHANUMERIC_ONLY,
    KAGE_RULE_PRINTABLE_ONLY,
    KAGE_RULE_NO_CONTROL_CHARS,
    KAGE_RULE_VALID_UTF8,
    KAGE_RULE_VALID_BASE64,
    KAGE_RULE_VALID_KEY_LENGTH,
    KAGE_RULE_NO_PATH_TRAVERSAL,
    KAGE_RULE_NO_NULL_BYTES,
    KAGE_RULE_VALID_IDENTIFIER,
    KAGE_RULE_MAX_NESTING_DEPTH
} kage_validation_rule;

// Validation rule configuration
typedef struct {
    kage_validation_rule rule;
    union {
        size_t length;
        int depth;
    } parameter;
} kage_validation_rule_config;

// Validation configuration for input types
typedef struct {
    kage_input_type input_type;
    kage_validation_rule_config *rules;
    size_t rule_count;
    bool strict_mode;
} kage_validation_config;

// Main validation functions
PHPAPI kage_validation_result_t kage_validate_input(const void *input, size_t input_length, kage_input_type type);
PHPAPI kage_validation_result_t kage_validate_string(const char *input, kage_input_type type);
PHPAPI kage_validation_result_t kage_validate_binary(const unsigned char *input, size_t length, kage_input_type type);

// Specific validation functions
PHPAPI kage_validation_result_t kage_validate_encryption_key(const unsigned char *key, size_t key_length);
PHPAPI kage_validation_result_t kage_validate_source_code(const char *source, size_t source_length);
PHPAPI kage_validation_result_t kage_validate_identifier(const char *identifier);
PHPAPI kage_validation_result_t kage_validate_path(const char *path);
PHPAPI kage_validation_result_t kage_validate_url(const char *url);

// Sanitization functions
PHPAPI char* kage_sanitize_string(const char *input, size_t input_length, kage_input_type type);
PHPAPI char* kage_sanitize_path(const char *path);
PHPAPI char* kage_sanitize_identifier(const char *identifier);

// Utility functions
PHPAPI bool kage_is_valid_utf8(const char *str, size_t length);
PHPAPI bool kage_is_valid_base64(const char *str, size_t length);
PHPAPI bool kage_contains_null_bytes(const char *str, size_t length);
PHPAPI bool kage_contains_control_chars(const char *str, size_t length);
PHPAPI bool kage_is_path_traversal(const char *path);
PHPAPI size_t kage_get_nesting_depth(const char *source);

// Safe input processing macros
#define KAGE_VALIDATE_STRING(input, type) \
    ({ kage_validation_result_t _result = kage_validate_string(input, type); _result; })

#define KAGE_VALIDATE_BINARY(input, length, type) \
    ({ kage_validation_result_t _result = kage_validate_binary(input, length, type); _result; })

#define KAGE_VALIDATE_OR_RETURN(input, type) \
    do { \
        kage_validation_result_t _result = kage_validate_string(input, type); \
        if (!_result.is_valid) { \
            zend_error(E_WARNING, "Kage Validation Error: %s", _result.error_message); \
            RETURN_FALSE; \
        } \
    } while (0)

// Configuration management
PHPAPI kage_validation_config* kage_validation_get_config(kage_input_type type);
PHPAPI kage_error_t kage_validation_set_config(kage_input_type type, kage_validation_config *config);
PHPAPI kage_error_t kage_validation_add_rule(kage_input_type type, kage_validation_rule rule, ...);
PHPAPI kage_error_t kage_validation_remove_rule(kage_input_type type, kage_validation_rule rule);

// Security hardening functions
PHPAPI void kage_validation_enable_strict_mode(kage_input_type type);
PHPAPI void kage_validation_disable_strict_mode(kage_input_type type);
PHPAPI bool kage_validation_is_strict_mode(kage_input_type type);

// Performance optimization
PHPAPI void kage_validation_enable_caching(void);
PHPAPI void kage_validation_disable_caching(void);
PHPAPI void kage_validation_clear_cache(void);

// Statistics and monitoring
typedef struct {
    size_t total_validations;
    size_t validation_failures;
    size_t sanitizations_performed;
    size_t cache_hits;
    size_t cache_misses;
} kage_validation_stats;

PHPAPI kage_validation_stats* kage_validation_get_stats(void);
PHPAPI void kage_validation_reset_stats(void);

#endif /* PHP_KAGE_VALIDATION_H */
