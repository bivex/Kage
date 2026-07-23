/**
 * Kage Context Header
 */

#ifndef PHP_KAGE_CONTEXT_H
#define PHP_KAGE_CONTEXT_H

#include "config.h"
#include <stdbool.h>

typedef enum {
    KAGE_SUCCESS = 0,
    KAGE_ERROR_MEMORY = -1,
    KAGE_ERROR_INVALID_INPUT = -2,
    KAGE_ERROR_CRYPTO = -3,
    KAGE_ERROR_CONFIG = -6,
    KAGE_ERROR_IO = -7
} kage_error_t;

typedef struct {
    kage_error_t error;
    zval *value;
} kage_result_t;

typedef struct kage_context_s {
    zend_string *encryption_key;
    size_t max_memory;
    bool debug_mode;
    int log_level;

    kage_error_t last_error;
    char error_message[256];

    unsigned char opcode_map[256];
    unsigned char reverse_map[256];
    int map_initialized;
} kage_context;

PHPAPI kage_context* kage_context_create(void);
PHPAPI void kage_context_destroy(kage_context *ctx);
PHPAPI kage_error_t kage_context_init(kage_context *ctx);
kage_context* kage_get_context(void);

PHPAPI void kage_set_error(kage_context *ctx, kage_error_t error, const char *format, ...);
PHPAPI const char* kage_get_error_message(kage_context *ctx);
PHPAPI kage_error_t kage_get_last_error(kage_context *ctx);

#endif /* PHP_KAGE_CONTEXT_H */
