/**
 * Kage Memory Management
 *
 * Provides RAII-like resource management patterns to reduce memory leaks
 * and simplify cleanup throughout the codebase.
 *
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-12-09
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#ifndef PHP_KAGE_MEMORY_H
#define PHP_KAGE_MEMORY_H

#include "config.h"
#include "vm.h"
#include "ast.h"
#include <stdbool.h>

// Memory pool for efficient allocation
typedef struct kage_memory_pool {
    void **blocks;
    size_t block_count;
    size_t block_capacity;
    size_t total_allocated;
} kage_memory_pool;

// Auto-cleanup resource types
typedef enum {
    KAGE_RESOURCE_ZVAL,
    KAGE_RESOURCE_STRING,
    KAGE_RESOURCE_AST_NODE,
    KAGE_RESOURCE_VM_STATE,
    KAGE_RESOURCE_BUFFER
} kage_resource_type;

// Resource cleanup function type
typedef void (*kage_cleanup_func)(void *resource);

// Resource tracker for automatic cleanup
typedef struct kage_resource {
    void *data;
    kage_resource_type type;
    kage_cleanup_func cleanup;
    struct kage_resource *next;
} kage_resource;

// Scope-based resource manager (RAII-like)
typedef struct kage_scope {
    kage_resource *resources;
    struct kage_scope *parent;
    bool cleanup_on_exit;
} kage_scope;

// Memory pool functions
PHPAPI kage_memory_pool* kage_memory_pool_create(size_t initial_capacity);
PHPAPI void kage_memory_pool_destroy(kage_memory_pool *pool);
PHPAPI void* kage_memory_pool_alloc(kage_memory_pool *pool, size_t size);
PHPAPI void kage_memory_pool_reset(kage_memory_pool *pool);

// Scope management functions (RAII-like)
PHPAPI kage_scope* kage_scope_create(kage_scope *parent);
PHPAPI void kage_scope_destroy(kage_scope *scope);
PHPAPI void kage_scope_cleanup(kage_scope *scope);

// Resource registration functions
PHPAPI bool kage_scope_register_zval(kage_scope *scope, zval *zv);
PHPAPI bool kage_scope_register_string(kage_scope *scope, char *str);
PHPAPI bool kage_scope_register_ast_node(kage_scope *scope, kage_ast_node *node);
PHPAPI bool kage_scope_register_vm_state(kage_scope *scope, kage_vm_state *state);
PHPAPI bool kage_scope_register_buffer(kage_scope *scope, void *buffer);

// Safe allocation macros with automatic cleanup
#define KAGE_SCOPE_ALLOC_ZVAL(scope, zv) \
    zval *zv = emalloc(sizeof(zval)); \
    if (zv) { \
        memset(zv, 0, sizeof(zval)); \
        kage_scope_register_zval(scope, zv); \
    }

#define KAGE_SCOPE_ALLOC_STRING(scope, str, len) \
    char *str = emalloc(len + 1); \
    if (str) { \
        kage_scope_register_string(scope, str); \
    }

#define KAGE_SCOPE_ALLOC_AST_NODE(scope, node) \
    kage_ast_node *node = kage_ast_node_create(0); \
    if (node) { \
        kage_scope_register_ast_node(scope, node); \
    }

#define KAGE_SCOPE_ALLOC_VM_STATE(scope, state) \
    kage_vm_state *state = emalloc(sizeof(kage_vm_state)); \
    if (state) { \
        memset(state, 0, sizeof(kage_vm_state)); \
        kage_scope_register_vm_state(scope, state); \
    }

// Safe function execution with automatic cleanup
#define KAGE_WITH_SCOPE(scope_var, statements) \
    do { \
        kage_scope *scope_var = kage_scope_create(NULL); \
        if (scope_var) { \
            statements \
            kage_scope_destroy(scope_var); \
        } \
    } while (0)

// Utility functions for common patterns
PHPAPI zval* kage_safe_zval_copy(kage_scope *scope, zval *src);
PHPAPI char* kage_safe_string_copy(kage_scope *scope, const char *src, size_t len);
PHPAPI kage_ast_node* kage_safe_ast_node_copy(kage_scope *scope, kage_ast_node *src);

// Memory statistics for debugging
typedef struct {
    size_t total_allocated;
    size_t total_freed;
    size_t current_usage;
    size_t peak_usage;
    size_t allocation_count;
} kage_memory_stats;

PHPAPI kage_memory_stats* kage_memory_get_stats(void);
PHPAPI void kage_memory_reset_stats(void);

// Memory-safe wrapper for existing functions
#define kage_safe_emalloc(size) kage_memory_safe_alloc(size, __FILE__, __LINE__)
#define kage_safe_efree(ptr) kage_memory_safe_free(ptr, __FILE__, __LINE__)

PHPAPI void* kage_memory_safe_alloc(size_t size, const char *file, int line);
PHPAPI void kage_memory_safe_free(void *ptr, const char *file, int line);

// Leak detection (debug mode only)
#ifdef KAGE_DEBUG_MEMORY
#define kage_memory_check_leaks() kage_memory_detect_leaks(__FILE__, __LINE__)
PHPAPI void kage_memory_detect_leaks(const char *file, int line);
#else
#define kage_memory_check_leaks() ((void)0)
#endif

#endif /* PHP_KAGE_MEMORY_H */
