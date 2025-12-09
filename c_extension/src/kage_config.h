/**
 * Kage Configuration Management
 *
 * Centralized configuration management system to reduce global variables
 * and provide consistent configuration handling.
 *
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-12-09
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#ifndef PHP_KAGE_CONFIG_H
#define PHP_KAGE_CONFIG_H

#include "config.h"
#include "kage_context.h"
#include <stdbool.h>

// Configuration keys
#define KAGE_CONFIG_ENCRYPTION_KEY      "encryption_key"
#define KAGE_CONFIG_DEBUG_MODE         "debug_mode"
#define KAGE_CONFIG_LOG_LEVEL          "log_level"
#define KAGE_CONFIG_MAX_MEMORY         "max_memory"
#define KAGE_CONFIG_STACK_SIZE         "stack_size"
#define KAGE_CONFIG_TIMEOUT            "timeout"
#define KAGE_CONFIG_CACHE_ENABLED      "cache_enabled"
#define KAGE_CONFIG_CACHE_SIZE         "cache_size"
#define KAGE_CONFIG_CRYPTO_ALGORITHM   "crypto_algorithm"

// Default values
#define KAGE_DEFAULT_DEBUG_MODE        0
#define KAGE_DEFAULT_LOG_LEVEL         0
#define KAGE_DEFAULT_MAX_MEMORY        (256 * 1024 * 1024)  // 256MB
#define KAGE_DEFAULT_STACK_SIZE        1024
#define KAGE_DEFAULT_TIMEOUT           300
#define KAGE_DEFAULT_CACHE_ENABLED     1
#define KAGE_DEFAULT_CACHE_SIZE        (10 * 1024 * 1024)   // 10MB
#define KAGE_DEFAULT_CRYPTO_ALGORITHM  "aes256gcm"

// Configuration value types
typedef enum {
    KAGE_CONFIG_TYPE_BOOL,
    KAGE_CONFIG_TYPE_INT,
    KAGE_CONFIG_TYPE_SIZE,
    KAGE_CONFIG_TYPE_STRING,
    KAGE_CONFIG_TYPE_DOUBLE
} kage_config_type;

// Configuration value union
typedef union {
    bool bool_val;
    int int_val;
    size_t size_val;
    char *string_val;
    double double_val;
} kage_config_value;

// Configuration entry
typedef struct kage_config_entry {
    const char *key;
    kage_config_type type;
    kage_config_value value;
    kage_config_value default_value;
    bool is_set;
} kage_config_entry;

// Main configuration structure
typedef struct kage_config {
    HashTable *entries;
    bool initialized;
} kage_config;

// Global configuration accessor
PHPAPI kage_config* kage_config_get(void);

// Configuration management functions
PHPAPI kage_config* kage_config_create(void);
PHPAPI void kage_config_destroy(kage_config *config);
PHPAPI kage_error_t kage_config_init(kage_config *config);
PHPAPI kage_error_t kage_config_load_defaults(kage_config *config);

// Configuration setting/getting functions
PHPAPI kage_error_t kage_config_set_bool(kage_config *config, const char *key, bool value);
PHPAPI kage_error_t kage_config_set_int(kage_config *config, const char *key, int value);
PHPAPI kage_error_t kage_config_set_size(kage_config *config, const char *key, size_t value);
PHPAPI kage_error_t kage_config_set_string(kage_config *config, const char *key, const char *value);
PHPAPI kage_error_t kage_config_set_double(kage_config *config, const char *key, double value);

PHPAPI bool kage_config_get_bool(kage_config *config, const char *key);
PHPAPI int kage_config_get_int(kage_config *config, const char *key);
PHPAPI size_t kage_config_get_size(kage_config *config, const char *key);
PHPAPI const char* kage_config_get_string(kage_config *config, const char *key);
PHPAPI double kage_config_get_double(kage_config *config, const char *key);

// PHP integration functions
PHPAPI kage_error_t kage_config_load_from_php_ini(kage_config *config);
PHPAPI kage_error_t kage_config_load_from_env(kage_config *config);
PHPAPI kage_error_t kage_config_load_from_array(kage_config *config, HashTable *array);

// Validation functions
PHPAPI kage_error_t kage_config_validate(kage_config *config);
PHPAPI bool kage_config_is_valid_key(const char *key);
PHPAPI kage_config_type kage_config_get_key_type(const char *key);

// Utility functions
PHPAPI void kage_config_dump(kage_config *config);
PHPAPI kage_error_t kage_config_reset_to_defaults(kage_config *config);
PHPAPI bool kage_config_is_modified(kage_config *config);

// Memory-safe configuration access macros
#define KAGE_CONFIG_BOOL(key) kage_config_get_bool(kage_config_get(), key)
#define KAGE_CONFIG_INT(key) kage_config_get_int(kage_config_get(), key)
#define KAGE_CONFIG_SIZE(key) kage_config_get_size(kage_config_get(), key)
#define KAGE_CONFIG_STRING(key) kage_config_get_string(kage_config_get(), key)
#define KAGE_CONFIG_DOUBLE(key) kage_config_get_double(kage_config_get(), key)

// Configuration change callbacks
typedef void (*kage_config_change_callback)(const char *key, kage_config_value old_value, kage_config_value new_value);

PHPAPI kage_error_t kage_config_register_callback(kage_config *config, const char *key, kage_config_change_callback callback);
PHPAPI kage_error_t kage_config_unregister_callback(kage_config *config, const char *key, kage_config_change_callback callback);

#endif /* PHP_KAGE_CONFIG_H */
