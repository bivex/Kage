/**
 * Kage Memory Management Implementation
 *
 * Implementation of RAII-like memory management patterns.
 *
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-12-09
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#include "kage_memory.h"
#include "ast.h"
#include "vm.h"

// Global memory statistics
static kage_memory_stats global_stats = {0};

// Memory pool implementation
PHPAPI kage_memory_pool* kage_memory_pool_create(size_t initial_capacity) {
    kage_memory_pool *pool = emalloc(sizeof(kage_memory_pool));
    if (!pool) return NULL;

    pool->blocks = emalloc(sizeof(void*) * initial_capacity);
    if (!pool->blocks) {
        efree(pool);
        return NULL;
    }

    pool->block_count = 0;
    pool->block_capacity = initial_capacity;
    pool->total_allocated = 0;

    return pool;
}

PHPAPI void kage_memory_pool_destroy(kage_memory_pool *pool) {
    if (!pool) return;

    // Free all blocks
    for (size_t i = 0; i < pool->block_count; i++) {
        if (pool->blocks[i]) {
            efree(pool->blocks[i]);
        }
    }

    efree(pool->blocks);
    efree(pool);
}

PHPAPI void* kage_memory_pool_alloc(kage_memory_pool *pool, size_t size) {
    if (!pool || size == 0) return NULL;

    // Expand block array if needed
    if (pool->block_count >= pool->block_capacity) {
        size_t new_capacity = pool->block_capacity * 2;
        void **new_blocks = erealloc(pool->blocks, sizeof(void*) * new_capacity);
        if (!new_blocks) return NULL;

        pool->blocks = new_blocks;
        pool->block_capacity = new_capacity;
    }

    // Allocate block
    void *block = emalloc(size);
    if (!block) return NULL;

    pool->blocks[pool->block_count++] = block;
    pool->total_allocated += size;

    global_stats.total_allocated += size;
    global_stats.current_usage += size;
    if (global_stats.current_usage > global_stats.peak_usage) {
        global_stats.peak_usage = global_stats.current_usage;
    }
    global_stats.allocation_count++;

    return block;
}

PHPAPI void kage_memory_pool_reset(kage_memory_pool *pool) {
    if (!pool) return;

    global_stats.current_usage -= pool->total_allocated;
    global_stats.total_freed += pool->total_allocated;

    // Free all blocks but keep the array
    for (size_t i = 0; i < pool->block_count; i++) {
        if (pool->blocks[i]) {
            efree(pool->blocks[i]);
            pool->blocks[i] = NULL;
        }
    }

    pool->block_count = 0;
    pool->total_allocated = 0;
}

// Scope implementation (RAII-like)
PHPAPI kage_scope* kage_scope_create(kage_scope *parent) {
    kage_scope *scope = emalloc(sizeof(kage_scope));
    if (!scope) return NULL;

    scope->resources = NULL;
    scope->parent = parent;
    scope->cleanup_on_exit = true;

    return scope;
}

PHPAPI void kage_scope_destroy(kage_scope *scope) {
    if (!scope) return;

    if (scope->cleanup_on_exit) {
        kage_scope_cleanup(scope);
    }

    efree(scope);
}

PHPAPI void kage_scope_cleanup(kage_scope *scope) {
    if (!scope) return;

    kage_resource *current = scope->resources;
    while (current) {
        kage_resource *next = current->next;

        if (current->cleanup && current->data) {
            current->cleanup(current->data);
        }

        efree(current);
        current = next;
    }

    scope->resources = NULL;
}

// Resource cleanup functions
static void kage_cleanup_zval(void *resource) {
    if (resource) {
        zval_ptr_dtor((zval*)resource);
        efree(resource);
    }
}

static void kage_cleanup_string(void *resource) {
    if (resource) {
        efree(resource);
    }
}

static void kage_cleanup_ast_node(void *resource) {
    if (resource) {
        kage_ast_free((kage_ast_node*)resource);
    }
}

static void kage_cleanup_vm_state(void *resource) {
    if (resource) {
        kage_vm_destroy((kage_vm_state*)resource);
        efree(resource);
    }
}

static void kage_cleanup_buffer(void *resource) {
    if (resource) {
        efree(resource);
    }
}

// Helper function to add resource to scope
static bool kage_scope_add_resource(kage_scope *scope, void *data, kage_resource_type type) {
    if (!scope || !data) return false;

    kage_resource *resource = emalloc(sizeof(kage_resource));
    if (!resource) return false;

    resource->data = data;
    resource->type = type;

    // Set appropriate cleanup function
    switch (type) {
        case KAGE_RESOURCE_ZVAL:
            resource->cleanup = kage_cleanup_zval;
            break;
        case KAGE_RESOURCE_STRING:
            resource->cleanup = kage_cleanup_string;
            break;
        case KAGE_RESOURCE_AST_NODE:
            resource->cleanup = kage_cleanup_ast_node;
            break;
        case KAGE_RESOURCE_VM_STATE:
            resource->cleanup = kage_cleanup_vm_state;
            break;
        case KAGE_RESOURCE_BUFFER:
            resource->cleanup = kage_cleanup_buffer;
            break;
        default:
            efree(resource);
            return false;
    }

    // Add to linked list
    resource->next = scope->resources;
    scope->resources = resource;

    return true;
}

// Public resource registration functions
PHPAPI bool kage_scope_register_zval(kage_scope *scope, zval *zv) {
    return kage_scope_add_resource(scope, zv, KAGE_RESOURCE_ZVAL);
}

PHPAPI bool kage_scope_register_string(kage_scope *scope, char *str) {
    return kage_scope_add_resource(scope, str, KAGE_RESOURCE_STRING);
}

PHPAPI bool kage_scope_register_ast_node(kage_scope *scope, kage_ast_node *node) {
    return kage_scope_add_resource(scope, node, KAGE_RESOURCE_AST_NODE);
}

PHPAPI bool kage_scope_register_vm_state(kage_scope *scope, kage_vm_state *state) {
    return kage_scope_add_resource(scope, state, KAGE_RESOURCE_VM_STATE);
}

PHPAPI bool kage_scope_register_buffer(kage_scope *scope, void *buffer) {
    return kage_scope_add_resource(scope, buffer, KAGE_RESOURCE_BUFFER);
}

// Safe utility functions
PHPAPI zval* kage_safe_zval_copy(kage_scope *scope, zval *src) {
    if (!scope || !src) return NULL;

    KAGE_SCOPE_ALLOC_ZVAL(scope, dest);
    if (!dest) return NULL;

    ZVAL_COPY(dest, src);
    return dest;
}

PHPAPI char* kage_safe_string_copy(kage_scope *scope, const char *src, size_t len) {
    if (!scope || !src) return NULL;

    KAGE_SCOPE_ALLOC_STRING(scope, dest, len);
    if (!dest) return NULL;

    memcpy(dest, src, len);
    dest[len] = '\0';
    return dest;
}

PHPAPI kage_ast_node* kage_safe_ast_node_copy(kage_scope *scope, kage_ast_node *src) {
    if (!scope || !src) return NULL;

    // For now, just return the source (deep copy would be more complex)
    // In a full implementation, this would create a deep copy
    return src;
}

// Memory statistics
PHPAPI kage_memory_stats* kage_memory_get_stats(void) {
    return &global_stats;
}

PHPAPI void kage_memory_reset_stats(void) {
    memset(&global_stats, 0, sizeof(global_stats));
}

// Safe allocation wrappers
PHPAPI void* kage_memory_safe_alloc(size_t size, const char *file, int line) {
    void *ptr = emalloc(size);
    if (ptr) {
        global_stats.total_allocated += size;
        global_stats.current_usage += size;
        if (global_stats.current_usage > global_stats.peak_usage) {
            global_stats.peak_usage = global_stats.current_usage;
        }
        global_stats.allocation_count++;
    }
    return ptr;
}

PHPAPI void kage_memory_safe_free(void *ptr, const char *file, int line) {
    if (ptr) {
        // Note: We can't track exact size freed, so we estimate
        global_stats.total_freed += 1; // Placeholder
        global_stats.current_usage -= 1; // Placeholder
        efree(ptr);
    }
}

#ifdef KAGE_DEBUG_MEMORY
PHPAPI void kage_memory_detect_leaks(const char *file, int line) {
    if (global_stats.current_usage > 0) {
        php_error_docref(NULL, E_WARNING,
            "Kage Memory Leak Detected: %zu bytes still allocated (%s:%d)",
            global_stats.current_usage, file, line);
    }
}
#endif
