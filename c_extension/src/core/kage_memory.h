/**
 * Kage Memory Management Header
 */

#ifndef PHP_KAGE_MEMORY_H
#define PHP_KAGE_MEMORY_H

#include "config.h"
#include <stdbool.h>

#define KAGE_ALLOC(size) kage_memory_safe_alloc(size, __FILE__, __LINE__)
#define KAGE_FREE(ptr) kage_memory_safe_free(ptr, __FILE__, __LINE__)

PHPAPI void* kage_memory_safe_alloc(size_t size, const char *file, int line);
PHPAPI void kage_memory_safe_free(void *ptr, const char *file, int line);

#endif /* PHP_KAGE_MEMORY_H */
