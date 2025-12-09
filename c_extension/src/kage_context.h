/**
 * Kage Context and Common Interfaces
 *
 * This header defines common interfaces and context structures to reduce
 * coupling between modules and provide better abstraction.
 *
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-12-09
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#ifndef PHP_KAGE_CONTEXT_H
#define PHP_KAGE_CONTEXT_H

#include "config.h"

// Include headers that define the types we need
#include "vm.h"
#include "ast.h"
#include <stdbool.h>

// Forward declarations
typedef struct kage_crypto_context kage_crypto_context;
typedef struct kage_ast_context kage_ast_context;
typedef struct kage_vm_context kage_vm_context;

// Error codes for unified error handling
typedef enum {
    KAGE_SUCCESS = 0,
    KAGE_ERROR_MEMORY = -1,
    KAGE_ERROR_INVALID_INPUT = -2,
    KAGE_ERROR_CRYPTO = -3,
    KAGE_ERROR_AST = -4,
    KAGE_ERROR_VM = -5,
    KAGE_ERROR_CONFIG = -6,
    KAGE_ERROR_IO = -7
} kage_error_t;

// Result structure for operations that may fail
typedef struct {
    kage_error_t error;
    union {
        zval *value;
        kage_ast_node *ast_node;
        kage_vm_state *vm_state;
        void *data;
    } result;
} kage_result_t;

// Memory management interface
typedef struct {
    void* (*alloc)(size_t size);
    void* (*realloc)(void *ptr, size_t size);
    void  (*free)(void *ptr);
    char* (*strdup)(const char *str);
} kage_memory_interface;

// Crypto operations interface
typedef struct {
    kage_result_t (*encrypt)(const unsigned char *data, size_t data_len,
                           const unsigned char *key, size_t key_len);
    kage_result_t (*decrypt)(const unsigned char *data, size_t data_len,
                           const unsigned char *key, size_t key_len);
    kage_result_t (*encode_base64)(const unsigned char *data, size_t data_len);
    kage_result_t (*decode_base64)(const char *data, size_t data_len);
} kage_crypto_interface;

// AST operations interface
typedef struct {
    kage_result_t (*parse)(const char *source);
    void (*free_node)(kage_ast_node *node);
    kage_result_t (*to_bytecode)(kage_ast_node *node);
} kage_ast_interface;

// VM operations interface
typedef struct {
    kage_result_t (*init)(size_t stack_size);
    void (*destroy)(kage_vm_state *state);
    kage_result_t (*execute)(kage_vm_state *state);
    kage_result_t (*push)(kage_vm_state *state, zval *value);
    kage_result_t (*pop)(kage_vm_state *state, zval *result);
} kage_vm_interface;

// Main context structure that holds all interfaces
typedef struct {
    // Configuration
    zend_string *encryption_key;
    size_t max_memory;
    bool debug_mode;
    int log_level;

    // Interfaces
    kage_memory_interface *memory;
    kage_crypto_interface *crypto;
    kage_ast_interface *ast;
    kage_vm_interface *vm;

    // Error handling
    kage_error_t last_error;
    char error_message[256];

    // Resource management
    HashTable *resources;
} kage_context;

// Global context accessor and context management functions
PHPAPI kage_context* kage_context_create(void);
PHPAPI void kage_context_destroy(kage_context *ctx);
PHPAPI kage_error_t kage_context_init(kage_context *ctx);
kage_context* kage_get_context(void);

// Error handling functions
PHPAPI void kage_set_error(kage_context *ctx, kage_error_t error, const char *format, ...);
PHPAPI const char* kage_get_error_message(kage_context *ctx);
PHPAPI kage_error_t kage_get_last_error(kage_context *ctx);

// Utility functions for common operations
PHPAPI kage_result_t kage_encrypt_string(kage_context *ctx, const char *data, size_t data_len);
PHPAPI kage_result_t kage_decrypt_string(kage_context *ctx, const char *data, size_t data_len);
PHPAPI kage_result_t kage_parse_and_execute(kage_context *ctx, const char *source);

// Resource management
PHPAPI void* kage_register_resource(kage_context *ctx, void *resource, const char *type);
PHPAPI void kage_unregister_resource(kage_context *ctx, void *resource);
PHPAPI void kage_cleanup_resources(kage_context *ctx);

#endif /* PHP_KAGE_CONTEXT_H */
