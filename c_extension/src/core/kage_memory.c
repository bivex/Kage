/**
 * Kage Memory Management Implementation
 */

#include "kage_memory.h"

PHPAPI void* kage_memory_safe_alloc(size_t size, const char *file, int line) {
    void *ptr = emalloc(size);
    if (!ptr) {
        php_error_docref(NULL, E_WARNING, "Kage Memory: Critical allocation failure of %zu bytes at %s:%d", size, file, line);
        return NULL;
    }
    return ptr;
}

PHPAPI void kage_memory_safe_free(void *ptr, const char *file, int line) {
    if (ptr) {
        efree(ptr);
    }
}
