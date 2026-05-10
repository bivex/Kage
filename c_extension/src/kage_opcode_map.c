/**
 * Kage Extension — Virtual Opcode Mapping Implementation
 * Phase 3.1: Bytecode Transformation
 */

#include "config.h"
#include <zend_compile.h>  // for zend_op_array, zend_op
#include "kage_opcode_map.h"
#include <stdlib.h>        // for arc4random_uniform

// Global mapping tables (256 entries for all possible opcodes)
unsigned char g_kage_opcode_map[256];
unsigned char g_kage_reverse_map[256];
static int g_kage_map_initialized = 0;

/**
 * Fisher-Yates shuffle on array of 256 bytes.
 */
static void kage_shuffle_opcode_map(void) {
    unsigned char map[256];
    for (int i = 0; i < 256; i++) {
        map[i] = (unsigned char)i;
    }

    // Fisher-Yates: swap each element with a random later element
    for (int i = 0; i < 255; i++) {
        unsigned int j = arc4random_uniform(256 - i) + i;
        unsigned char tmp = map[i];
        map[i] = map[j];
        map[j] = tmp;
    }

    // Preserve NOP as NOP (opcode 0) for safety — some VM assumptions rely on it
    g_kage_opcode_map[0] = 0;
    for (int i = 1; i < 256; i++) {
        g_kage_opcode_map[i] = map[i];
    }

    // Build reverse map: virtual → real
    for (int i = 0; i < 256; i++) {
        g_kage_reverse_map[g_kage_opcode_map[i]] = (unsigned char)i;
    }
}

/**
 * Initialize the opcode mapping at module startup (MINIT).
 */
int kage_opcode_map_init(void) {
    if (g_kage_map_initialized) {
        return SUCCESS;
    }

    kage_shuffle_opcode_map();
    g_kage_map_initialized = 1;

    return SUCCESS;
}

/**
 * Shutdown (MSHUTDOWN) — nothing to free currently.
 */
void kage_opcode_map_shutdown(void) {
    // No dynamic allocations to free
}

/**
 * Apply virtual opcode mapping to an entire op_array.
 * Walks op_array->opcodes and replaces each op->opcode with its mapped value.
 *
 * @param op_array The compiled opcode array to transform
 */
void kage_map_oparray(zend_op_array *op_array) {
    if (!op_array || !g_kage_map_initialized) {
        return;
    }

    // Transform main opcode list
    for (uint32_t i = 0; i < op_array->last; i++) {
        zend_op *op = &op_array->opcodes[i];
        unsigned char real_op = op->opcode;
        unsigned char virtual_op = g_kage_opcode_map[real_op];
        op->opcode = virtual_op;

        // Store original opcode in extended_value for debugging (optional)
        // op->extended_value = real_op;
    }

    // Note: try/handlers are rare; skip transformation for now
}
