/**
 * Kage Extension — Virtual Opcode Mapping Implementation
 * Phase 3.1: Bytecode Transformation
 */

#include "config.h"
#include <zend_compile.h>
#include "kage_opcode_map.h"
#include <stdlib.h>

// Global mapping tables
unsigned char g_kage_opcode_map[256];
unsigned char g_kage_reverse_map[256];
static int g_kage_map_initialized = 0;

/**
 * Fisher-Yates shuffle: random permutation preserving NOP=0.
 */
static void kage_shuffle_opcode_map(void) {
    unsigned char map[256];
    for (int i = 0; i < 256; i++) map[i] = (unsigned char)i;

    for (int i = 0; i < 255; i++) {
        unsigned int j = arc4random_uniform(256 - i) + i;
        unsigned char tmp = map[i];
        map[i] = map[j];
        map[j] = tmp;
    }

    g_kage_opcode_map[0] = 0;
    for (int i = 1; i < 256; i++) g_kage_opcode_map[i] = map[i];

    for (int i = 0; i < 256; i++) {
        g_kage_reverse_map[g_kage_opcode_map[i]] = (unsigned char)i;
    }
}

int kage_opcode_map_init(void) {
    if (g_kage_map_initialized) return SUCCESS;
    kage_shuffle_opcode_map();
    g_kage_map_initialized = 1;
    return SUCCESS;
}

void kage_opcode_map_shutdown(void) { }

void kage_map_oparray(zend_op_array *op_array) {
    if (!op_array || !g_kage_map_initialized) return;
    for (uint32_t i = 0; i < op_array->last; i++) {
        zend_op *op = &op_array->opcodes[i];
        op->opcode = g_kage_opcode_map[op->opcode];
    }
}
