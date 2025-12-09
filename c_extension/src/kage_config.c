/**
 * Kage Configuration Management Implementation
 *
 * Implementation of centralized configuration management.
 *
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-12-09
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#include "kage_config.h"
#include "kage_context.h"
#include <stdlib.h>

// Static configuration definitions
static struct {
    const char *key;
    kage_config_type type;
    kage_config_value default_value;
} config_definitions[] = {
    {KAGE_CONFIG_ENCRYPTION_KEY, KAGE_CONFIG_TYPE_STRING, {.string_val = NULL}},
    {KAGE_CONFIG_DEBUG_MODE, KAGE_CONFIG_TYPE_BOOL, {.bool_val = KAGE_DEFAULT_DEBUG_MODE}},
    {KAGE_CONFIG_LOG_LEVEL, KAGE_CONFIG_TYPE_INT, {.int_val = KAGE_DEFAULT_LOG_LEVEL}},
    {KAGE_CONFIG_MAX_MEMORY, KAGE_CONFIG_TYPE_SIZE, {.size_val = KAGE_DEFAULT_MAX_MEMORY}},
    {KAGE_CONFIG_STACK_SIZE, KAGE_CONFIG_TYPE_SIZE, {.size_val = KAGE_DEFAULT_STACK_SIZE}},
    {KAGE_CONFIG_TIMEOUT, KAGE_CONFIG_TYPE_INT, {.int_val = KAGE_DEFAULT_TIMEOUT}},
    {KAGE_CONFIG_CACHE_ENABLED, KAGE_CONFIG_TYPE_BOOL, {.bool_val = KAGE_DEFAULT_CACHE_ENABLED}},
    {KAGE_CONFIG_CACHE_SIZE, KAGE_CONFIG_TYPE_SIZE, {.size_val = KAGE_DEFAULT_CACHE_SIZE}},
    {KAGE_CONFIG_CRYPTO_ALGORITHM, KAGE_CONFIG_TYPE_STRING, {.string_val = KAGE_DEFAULT_CRYPTO_ALGORITHM}},
    {NULL, 0, {0}} // Sentinel
};

// Global configuration instance
static kage_config *global_config = NULL;

// Helper function to find config definition
static const char* get_config_definition_type(const char *key, kage_config_type *type, kage_config_value *default_value) {
    for (int i = 0; config_definitions[i].key != NULL; i++) {
        if (strcmp(config_definitions[i].key, key) == 0) {
            if (type) *type = config_definitions[i].type;
            if (default_value) *default_value = config_definitions[i].default_value;
            return config_definitions[i].key;
        }
    }
    return NULL;
}

// Configuration management functions
PHPAPI kage_config* kage_config_create(void) {
    kage_config *config = emalloc(sizeof(kage_config));
    if (!config) return NULL;

    config->entries = emalloc(sizeof(HashTable));
    if (!config->entries) {
        efree(config);
        return NULL;
    }

    zend_hash_init(config->entries, 16, NULL, NULL, 0);
    config->initialized = false;

    return config;
}

PHPAPI void kage_config_destroy(kage_config *config) {
    if (!config) return;

    if (config->entries) {
        // Clean up all entries
        zend_hash_clean(config->entries);
        efree(config->entries);
    }

    efree(config);
}

PHPAPI kage_error_t kage_config_init(kage_config *config) {
    if (!config) return KAGE_ERROR_INVALID_INPUT;

    if (config->initialized) return KAGE_SUCCESS;

    kage_error_t result = kage_config_load_defaults(config);
    if (result == KAGE_SUCCESS) {
        config->initialized = true;
    }

    return result;
}

PHPAPI kage_error_t kage_config_load_defaults(kage_config *config) {
    if (!config || !config->entries) return KAGE_ERROR_INVALID_INPUT;

    for (int i = 0; config_definitions[i].key != NULL; i++) {
        kage_config_entry *entry = emalloc(sizeof(kage_config_entry));
        if (!entry) return KAGE_ERROR_MEMORY;

        entry->key = config_definitions[i].key;
        entry->type = config_definitions[i].type;
        entry->value = config_definitions[i].default_value;
        entry->default_value = config_definitions[i].default_value;
        entry->is_set = false;

        // Handle string defaults specially (need to duplicate)
        if (entry->type == KAGE_CONFIG_TYPE_STRING && entry->default_value.string_val) {
            entry->default_value.string_val = estrndup(entry->default_value.string_val,
                                                     strlen(entry->default_value.string_val));
            entry->value.string_val = estrndup(entry->default_value.string_val,
                                             strlen(entry->default_value.string_val));
        }

        zend_hash_str_add_ptr(config->entries, entry->key, strlen(entry->key), entry);
    }

    return KAGE_SUCCESS;
}

PHPAPI kage_config* kage_config_get(void) {
    if (!global_config) {
        global_config = kage_config_create();
        if (global_config) {
            kage_config_init(global_config);
        }
    }
    return global_config;
}

// Generic setter function
static kage_error_t kage_config_set_value(kage_config *config, const char *key, kage_config_value value, kage_config_type expected_type) {
    if (!config || !key) return KAGE_ERROR_INVALID_INPUT;

    kage_config_type key_type;
    if (!get_config_definition_type(key, &key_type, NULL)) {
        return KAGE_ERROR_INVALID_INPUT;
    }

    if (key_type != expected_type) {
        return KAGE_ERROR_INVALID_INPUT;
    }

    kage_config_entry *entry = zend_hash_str_find_ptr(config->entries, key, strlen(key));
    if (!entry) {
        return KAGE_ERROR_INVALID_INPUT;
    }

    // Free old string value if needed
    if (entry->type == KAGE_CONFIG_TYPE_STRING && entry->value.string_val) {
        efree(entry->value.string_val);
    }

    // Handle string values specially
    if (expected_type == KAGE_CONFIG_TYPE_STRING && value.string_val) {
        entry->value.string_val = estrndup(value.string_val, strlen(value.string_val));
    } else {
        entry->value = value;
    }

    entry->is_set = true;
    return KAGE_SUCCESS;
}

// Setter functions
PHPAPI kage_error_t kage_config_set_bool(kage_config *config, const char *key, bool value) {
    kage_config_value val = {.bool_val = value};
    return kage_config_set_value(config, key, val, KAGE_CONFIG_TYPE_BOOL);
}

PHPAPI kage_error_t kage_config_set_int(kage_config *config, const char *key, int value) {
    kage_config_value val = {.int_val = value};
    return kage_config_set_value(config, key, val, KAGE_CONFIG_TYPE_INT);
}

PHPAPI kage_error_t kage_config_set_size(kage_config *config, const char *key, size_t value) {
    kage_config_value val = {.size_val = value};
    return kage_config_set_value(config, key, val, KAGE_CONFIG_TYPE_SIZE);
}

PHPAPI kage_error_t kage_config_set_string(kage_config *config, const char *key, const char *value) {
    kage_config_value val = {.string_val = (char*)value};
    return kage_config_set_value(config, key, val, KAGE_CONFIG_TYPE_STRING);
}

PHPAPI kage_error_t kage_config_set_double(kage_config *config, const char *key, double value) {
    kage_config_value val = {.double_val = value};
    return kage_config_set_value(config, key, val, KAGE_CONFIG_TYPE_DOUBLE);
}

// Generic getter function
static kage_config_value kage_config_get_value(kage_config *config, const char *key, kage_config_value default_val) {
    if (!config || !key || !config->entries) {
        return default_val;
    }

    kage_config_entry *entry = zend_hash_str_find_ptr(config->entries, key, strlen(key));
    if (!entry) {
        return default_val;
    }

    return entry->value;
}

// Getter functions
PHPAPI bool kage_config_get_bool(kage_config *config, const char *key) {
    kage_config_value default_val = {.bool_val = false};
    return kage_config_get_value(config, key, default_val).bool_val;
}

PHPAPI int kage_config_get_int(kage_config *config, const char *key) {
    kage_config_value default_val = {.int_val = 0};
    return kage_config_get_value(config, key, default_val).int_val;
}

PHPAPI size_t kage_config_get_size(kage_config *config, const char *key) {
    kage_config_value default_val = {.size_val = 0};
    return kage_config_get_value(config, key, default_val).size_val;
}

PHPAPI const char* kage_config_get_string(kage_config *config, const char *key) {
    kage_config_value default_val = {.string_val = NULL};
    return kage_config_get_value(config, key, default_val).string_val;
}

PHPAPI double kage_config_get_double(kage_config *config, const char *key) {
    kage_config_value default_val = {.double_val = 0.0};
    return kage_config_get_value(config, key, default_val).double_val;
}

// PHP integration functions
PHPAPI kage_error_t kage_config_load_from_php_ini(kage_config *config) {
    if (!config) return KAGE_ERROR_INVALID_INPUT;

    // Load from PHP ini settings
    // This would integrate with PHP's ini system
    // For now, just return success
    return KAGE_SUCCESS;
}

PHPAPI kage_error_t kage_config_load_from_env(kage_config *config) {
    if (!config) return KAGE_ERROR_INVALID_INPUT;

    // Load from environment variables
    const char *env_key = getenv("KAGE_ENCRYPTION_KEY");
    if (env_key) {
        kage_config_set_string(config, KAGE_CONFIG_ENCRYPTION_KEY, env_key);
    }

    const char *env_debug = getenv("KAGE_DEBUG");
    if (env_debug) {
        kage_config_set_bool(config, KAGE_CONFIG_DEBUG_MODE, atoi(env_debug) != 0);
    }

    return KAGE_SUCCESS;
}

PHPAPI kage_error_t kage_config_load_from_array(kage_config *config, HashTable *array) {
    if (!config || !array) return KAGE_ERROR_INVALID_INPUT;

    // Load from PHP array
    // This would iterate through the array and set config values
    // For now, just return success
    return KAGE_SUCCESS;
}

// Validation functions
PHPAPI kage_error_t kage_config_validate(kage_config *config) {
    if (!config) return KAGE_ERROR_INVALID_INPUT;

    // Validate all required configuration values
    // Add specific validation logic here
    return KAGE_SUCCESS;
}

PHPAPI bool kage_config_is_valid_key(const char *key) {
    return get_config_definition_type(key, NULL, NULL) != NULL;
}

PHPAPI kage_config_type kage_config_get_key_type(const char *key) {
    kage_config_type type;
    if (get_config_definition_type(key, &type, NULL)) {
        return type;
    }
    return KAGE_CONFIG_TYPE_BOOL; // Default
}

// Utility functions
PHPAPI void kage_config_dump(kage_config *config) {
    if (!config || !config->entries) return;

    php_printf("Kage Configuration Dump:\n");
    // Iterate through all entries and print them
    // Implementation would depend on HashTable iteration
}

PHPAPI kage_error_t kage_config_reset_to_defaults(kage_config *config) {
    if (!config) return KAGE_ERROR_INVALID_INPUT;

    // Reset all entries to defaults
    return kage_config_load_defaults(config);
}

PHPAPI bool kage_config_is_modified(kage_config *config) {
    if (!config || !config->entries) return false;

    // Check if any entries have been modified from defaults
    // Implementation would iterate through entries
    return false;
}

// Callback functions (simplified implementation)
PHPAPI kage_error_t kage_config_register_callback(kage_config *config, const char *key, kage_config_change_callback callback) {
    // Simplified - would need a callback registry
    return KAGE_SUCCESS;
}

PHPAPI kage_error_t kage_config_unregister_callback(kage_config *config, const char *key, kage_config_change_callback callback) {
    // Simplified - would need a callback registry
    return KAGE_SUCCESS;
}
