/**
 * Kage Context Implementation
 */

#include "kage_context.h"
#include "kage_memory.h"
#include <stdarg.h>
#include <string.h>

static kage_context *global_context = NULL;

PHPAPI kage_context* kage_context_create(void) {
    kage_context *ctx = KAGE_ALLOC(sizeof(kage_context));
    if (!ctx) return NULL;

    memset(ctx, 0, sizeof(kage_context));
    ctx->max_memory = 256 * 1024 * 1024;
    return ctx;
}

PHPAPI void kage_context_destroy(kage_context *ctx) {
    if (!ctx) return;
    if (ctx->encryption_key) {
        zend_string_release(ctx->encryption_key);
    }
    efree(ctx);
}

PHPAPI kage_error_t kage_context_init(kage_context *ctx) {
    if (!ctx) return KAGE_ERROR_INVALID_INPUT;
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
