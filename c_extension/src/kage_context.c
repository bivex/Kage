/**
 * Kage Context Implementation
 *
 * Implementation of the unified context system for reduced coupling.
 *
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-12-09
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#include "kage_context.h"
#include "crypto.h"
#include "ast.h"
#include "vm.h"
#include "base64.h"
#include <stdarg.h>

// Global context instance
static kage_context *global_context = NULL;

// Memory interface implementation
static void* kage_memory_alloc(size_t size) {
    return emalloc(size);
}

static void* kage_memory_realloc(void *ptr, size_t size) {
    return erealloc(ptr, size);
}

static void kage_memory_free(void *ptr) {
    if (ptr) efree(ptr);
}

static char* kage_memory_strdup(const char *str) {
    return estrndup(str, strlen(str));
}

static kage_memory_interface memory_interface = {
    .alloc = kage_memory_alloc,
    .realloc = kage_memory_realloc,
    .free = kage_memory_free,
    .strdup = kage_memory_strdup
};

// Crypto interface implementation
static kage_result_t kage_crypto_encrypt(const unsigned char *data, size_t data_len,
                                       const unsigned char *key, size_t key_len) {
    kage_result_t result = {KAGE_SUCCESS, {NULL}};

    if (!data || !key || data_len == 0 || key_len != crypto_secretbox_KEYBYTES) {
        result.error = KAGE_ERROR_INVALID_INPUT;
        return result;
    }

    zval data_zv, result_zv;
    ZVAL_STRINGL(&data_zv, (char*)data, data_len);

    zend_string *key_str = zend_string_init((char*)key, key_len, 0);

    if (kage_internal_encrypt(&result_zv, &data_zv, key_str) != SUCCESS) {
        result.error = KAGE_ERROR_CRYPTO;
        zval_ptr_dtor(&data_zv);
        zend_string_release(key_str);
        return result;
    }

    result.result.value = &result_zv;
    zval_ptr_dtor(&data_zv);
    zend_string_release(key_str);

    return result;
}

static kage_result_t kage_crypto_decrypt(const unsigned char *data, size_t data_len,
                                       const unsigned char *key, size_t key_len) {
    kage_result_t result = {KAGE_SUCCESS, {NULL}};

    if (!data || !key || data_len == 0 || key_len != crypto_secretbox_KEYBYTES) {
        result.error = KAGE_ERROR_INVALID_INPUT;
        return result;
    }

    zval data_zv, result_zv;
    ZVAL_STRINGL(&data_zv, (char*)data, data_len);

    zend_string *key_str = zend_string_init((char*)key, key_len, 0);

    if (kage_internal_decrypt(&result_zv, &data_zv, key_str) != SUCCESS) {
        result.error = KAGE_ERROR_CRYPTO;
        zval_ptr_dtor(&data_zv);
        zend_string_release(key_str);
        return result;
    }

    result.result.value = &result_zv;
    zval_ptr_dtor(&data_zv);
    zend_string_release(key_str);

    return result;
}

static kage_result_t kage_crypto_encode_base64(const unsigned char *data, size_t data_len) {
    kage_result_t result = {KAGE_SUCCESS, {NULL}};

    if (!data || data_len == 0) {
        result.error = KAGE_ERROR_INVALID_INPUT;
        return result;
    }

    size_t encoded_len;
    char *encoded = kage_base64_encode(data, data_len, &encoded_len);

    if (!encoded) {
        result.error = KAGE_ERROR_CRYPTO;
        return result;
    }

    zval *result_zv = emalloc(sizeof(zval));
    ZVAL_STRINGL(result_zv, encoded, encoded_len);
    efree(encoded);

    result.result.value = result_zv;
    return result;
}

static kage_result_t kage_crypto_decode_base64(const char *data, size_t data_len) {
    kage_result_t result = {KAGE_SUCCESS, {NULL}};

    if (!data || data_len == 0) {
        result.error = KAGE_ERROR_INVALID_INPUT;
        return result;
    }

    size_t decoded_len;
    unsigned char *decoded = kage_base64_decode(data, data_len, &decoded_len);

    if (!decoded) {
        result.error = KAGE_ERROR_CRYPTO;
        return result;
    }

    zval *result_zv = emalloc(sizeof(zval));
    ZVAL_STRINGL(result_zv, (char*)decoded, decoded_len);
    efree(decoded);

    result.result.value = result_zv;
    return result;
}

static kage_crypto_interface crypto_interface = {
    .encrypt = kage_crypto_encrypt,
    .decrypt = kage_crypto_decrypt,
    .encode_base64 = kage_crypto_encode_base64,
    .decode_base64 = kage_crypto_decode_base64
};

// AST interface implementation
static kage_result_t kage_ast_parse_source(const char *source) {
    kage_result_t result = {KAGE_SUCCESS, {NULL}};

    if (!source) {
        result.error = KAGE_ERROR_INVALID_INPUT;
        return result;
    }

    kage_ast_node *node = kage_ast_parse(source);
    if (!node) {
        result.error = KAGE_ERROR_AST;
        return result;
    }

    result.result.ast_node = node;
    return result;
}

static void kage_ast_free_node(kage_ast_node *node) {
    kage_ast_free(node);
}

static kage_result_t kage_ast_convert_to_bytecode(kage_ast_node *node) {
    kage_result_t result = {KAGE_SUCCESS, {NULL}};

    if (!node) {
        result.error = KAGE_ERROR_INVALID_INPUT;
        return result;
    }

    kage_vm_state *state = emalloc(sizeof(kage_vm_state));
    if (!state) {
        result.error = KAGE_ERROR_MEMORY;
        return result;
    }

    if (kage_ast_to_bytecode(node, state) != SUCCESS) {
        efree(state);
        result.error = KAGE_ERROR_AST;
        return result;
    }

    result.result.vm_state = state;
    return result;
}

static kage_ast_interface ast_interface = {
    .parse = kage_ast_parse_source,
    .free_node = kage_ast_free_node,
    .to_bytecode = kage_ast_convert_to_bytecode
};

// VM interface implementation
static kage_result_t kage_vm_initialize(size_t stack_size) {
    kage_result_t result = {KAGE_SUCCESS, {NULL}};

    kage_vm_state *state = emalloc(sizeof(kage_vm_state));
    if (!state) {
        result.error = KAGE_ERROR_MEMORY;
        return result;
    }

    if (kage_vm_init(state, stack_size) != SUCCESS) {
        efree(state);
        result.error = KAGE_ERROR_VM;
        return result;
    }

    result.result.vm_state = state;
    return result;
}

static void kage_vm_destroy_state(kage_vm_state *state) {
    kage_vm_destroy(state);
}

static kage_result_t kage_vm_execute_instructions(kage_vm_state *state) {
    kage_result_t result = {KAGE_SUCCESS, {NULL}};

    if (!state) {
        result.error = KAGE_ERROR_INVALID_INPUT;
        return result;
    }

    if (kage_vm_execute(state) != SUCCESS) {
        result.error = KAGE_ERROR_VM;
        return result;
    }

    return result;
}

static kage_result_t kage_vm_push_value(kage_vm_state *state, zval *value) {
    kage_result_t result = {KAGE_SUCCESS, {NULL}};

    if (!state || !value) {
        result.error = KAGE_ERROR_INVALID_INPUT;
        return result;
    }

    if (kage_vm_push(state, value) != SUCCESS) {
        result.error = KAGE_ERROR_VM;
        return result;
    }

    return result;
}

static kage_result_t kage_vm_pop_value(kage_vm_state *state, zval *result_value) {
    kage_result_t result = {KAGE_SUCCESS, {NULL}};

    if (!state || !result_value) {
        result.error = KAGE_ERROR_INVALID_INPUT;
        return result;
    }

    if (kage_vm_pop(state, result_value) != SUCCESS) {
        result.error = KAGE_ERROR_VM;
        return result;
    }

    return result;
}

static kage_vm_interface vm_interface = {
    .init = kage_vm_initialize,
    .destroy = kage_vm_destroy_state,
    .execute = kage_vm_execute_instructions,
    .push = kage_vm_push_value,
    .pop = kage_vm_pop_value
};

// Context management
PHPAPI kage_context* kage_context_create(void) {
    kage_context *ctx = emalloc(sizeof(kage_context));
    if (!ctx) {
        return NULL;
    }

    memset(ctx, 0, sizeof(kage_context));

    // Initialize interfaces
    ctx->memory = &memory_interface;
    ctx->crypto = &crypto_interface;
    ctx->ast = &ast_interface;
    ctx->vm = &vm_interface;

    // Initialize resource table
    ctx->resources = emalloc(sizeof(HashTable));
    if (!ctx->resources) {
        efree(ctx);
        return NULL;
    }
    zend_hash_init(ctx->resources, 8, NULL, NULL, 0);

    // Set defaults
    ctx->max_memory = 256 * 1024 * 1024; // 256MB
    ctx->debug_mode = 0;
    ctx->log_level = 0;

    return ctx;
}

PHPAPI void kage_context_destroy(kage_context *ctx) {
    if (!ctx) return;

    // Clean up resources
    kage_cleanup_resources(ctx);

    // Free resource table
    if (ctx->resources) {
        zend_hash_destroy(ctx->resources);
        efree(ctx->resources);
    }

    // Free encryption key
    if (ctx->encryption_key) {
        zend_string_release(ctx->encryption_key);
    }

    efree(ctx);
}

PHPAPI kage_error_t kage_context_init(kage_context *ctx) {
    if (!ctx) return KAGE_ERROR_INVALID_INPUT;

    // Initialize libsodium if not already done
    if (sodium_init() == -1) {
        kage_set_error(ctx, KAGE_ERROR_CRYPTO, "Failed to initialize libsodium");
        return KAGE_ERROR_CRYPTO;
    }

    return KAGE_SUCCESS;
}

kage_context* kage_get_context(void) {
    if (!global_context) {
        global_context = kage_context_create();
        if (global_context) {
            kage_context_init(global_context);
        }
    }
    return global_context;
}

// Error handling
PHPAPI void kage_set_error(kage_context *ctx, kage_error_t error, const char *format, ...) {
    if (!ctx) return;

    ctx->last_error = error;

    va_list args;
    va_start(args, format);
    vsnprintf(ctx->error_message, sizeof(ctx->error_message), format, args);
    va_end(args);

    if (ctx->debug_mode) {
        php_error_docref(NULL, E_WARNING, "Kage Error [%d]: %s", error, ctx->error_message);
    }
}

PHPAPI const char* kage_get_error_message(kage_context *ctx) {
    return ctx ? ctx->error_message : "Unknown error";
}

PHPAPI kage_error_t kage_get_last_error(kage_context *ctx) {
    return ctx ? ctx->last_error : KAGE_ERROR_INVALID_INPUT;
}

// High-level utility functions
PHPAPI kage_result_t kage_encrypt_string(kage_context *ctx, const char *data, size_t data_len) {
    if (!ctx || !ctx->crypto || !ctx->encryption_key) {
        kage_result_t result = {KAGE_ERROR_INVALID_INPUT, {NULL}};
        return result;
    }

    return ctx->crypto->encrypt((const unsigned char*)data, data_len,
                               (const unsigned char*)ZSTR_VAL(ctx->encryption_key),
                               ZSTR_LEN(ctx->encryption_key));
}

PHPAPI kage_result_t kage_decrypt_string(kage_context *ctx, const char *data, size_t data_len) {
    if (!ctx || !ctx->crypto || !ctx->encryption_key) {
        kage_result_t result = {KAGE_ERROR_INVALID_INPUT, {NULL}};
        return result;
    }

    return ctx->crypto->decrypt((const unsigned char*)data, data_len,
                               (const unsigned char*)ZSTR_VAL(ctx->encryption_key),
                               ZSTR_LEN(ctx->encryption_key));
}

PHPAPI kage_result_t kage_parse_and_execute(kage_context *ctx, const char *source) {
    kage_result_t result = {KAGE_SUCCESS, {NULL}};

    if (!ctx || !source) {
        result.error = KAGE_ERROR_INVALID_INPUT;
        return result;
    }

    // Parse AST
    kage_result_t ast_result = ctx->ast->parse(source);
    if (ast_result.error != KAGE_SUCCESS) {
        return ast_result;
    }

    // Convert to bytecode
    kage_result_t bytecode_result = ctx->ast->to_bytecode(ast_result.result.ast_node);
    if (bytecode_result.error != KAGE_SUCCESS) {
        ctx->ast->free_node(ast_result.result.ast_node);
        return bytecode_result;
    }

    // Set encryption key
    bytecode_result.result.vm_state->key = ctx->encryption_key;

    // Execute
    kage_result_t exec_result = ctx->vm->execute(bytecode_result.result.vm_state);
    if (exec_result.error != KAGE_SUCCESS) {
        ctx->vm->destroy(bytecode_result.result.vm_state);
        ctx->ast->free_node(ast_result.result.ast_node);
        return exec_result;
    }

    // Pop result
    zval *final_result = emalloc(sizeof(zval));
    kage_result_t pop_result = ctx->vm->pop(bytecode_result.result.vm_state, final_result);
    if (pop_result.error != KAGE_SUCCESS) {
        efree(final_result);
        ctx->vm->destroy(bytecode_result.result.vm_state);
        ctx->ast->free_node(ast_result.result.ast_node);
        return pop_result;
    }

    // Clean up
    ctx->vm->destroy(bytecode_result.result.vm_state);
    ctx->ast->free_node(ast_result.result.ast_node);

    result.result.value = final_result;
    return result;
}

// Resource management
PHPAPI void* kage_register_resource(kage_context *ctx, void *resource, const char *type) {
    if (!ctx || !ctx->resources || !resource) return NULL;

    zend_string *key = zend_string_init(type, strlen(type), 0);
    zend_hash_add_ptr(ctx->resources, key, resource);
    zend_string_release(key);

    return resource;
}

PHPAPI void kage_unregister_resource(kage_context *ctx, void *resource) {
    if (!ctx || !ctx->resources) return;

    // Find and remove the resource
    zend_hash_apply_with_argument(ctx->resources, NULL, resource);
}

PHPAPI void kage_cleanup_resources(kage_context *ctx) {
    if (!ctx || !ctx->resources) return;

    // Clean up all resources
    zend_hash_clean(ctx->resources);
}
