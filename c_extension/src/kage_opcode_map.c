/**
 * Kage Extension — Virtual Opcode Mapping Implementation
 * Phase 3.1: Bytecode Transformation
 */

#include "config.h"
#include <zend_compile.h>
#include <zend_execute.h>
#include <zend_vm_opcodes.h>
#include "kage_opcode_map.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
// Global mapping tables
unsigned char g_kage_opcode_map[256];
unsigned char g_kage_reverse_map[256];
static int g_kage_map_initialized = 0;

/**
 * Build random bijective mapping over defined opcodes only.
 * NOP (0) is preserved identity.
 */
static void kage_shuffle_opcode_map(void) {
    for (int i = 0; i < 256; i++) {
        g_kage_opcode_map[i] = (unsigned char)i;
        g_kage_reverse_map[i] = (unsigned char)i;
    }

    unsigned char valid[256];
    int count = 0;
    for (int i = 0; i <= ZEND_VM_LAST_OPCODE; i++) {
        const char *name = zend_get_opcode_name((zend_uchar)i);
        if (name && strcmp(name, "UNKNOWN") != 0 && i != 0) {
            valid[count++] = (unsigned char)i;
        }
    }

    unsigned char shuffled[256];
     memcpy(shuffled, valid, count * sizeof(unsigned char));
     for (int i = count - 1; i > 0; i--) {
         unsigned int j = randombytes_uniform(i + 1);
         unsigned char tmp = shuffled[i];
         shuffled[i] = shuffled[j];
         shuffled[j] = tmp;
     }

    for (int i = 0; i < count; i++) {
        unsigned char real = valid[i];
        unsigned char virt = shuffled[i];
        g_kage_opcode_map[real] = virt;
    }

    for (int i = 0; i < 256; i++) {
        g_kage_reverse_map[g_kage_opcode_map[i]] = (unsigned char)i;
    }
}
 /**
  * Deterministic LCG for seed-based shuffling (Phase 6)
  */
 uint32_t kage_lcg(uint32_t *state) {
     *state = (*state * 1103515245 + 12345) & 0x7FFFFFFF;
     return *state;
 }
 
 /**
  * Build a deterministic map for a specific seed.
  */
 void kage_build_map_seeded(unsigned char *map, unsigned char *reverse, uint32_t seed) {
    unsigned char valid[256];
    int count = 0;
    uint32_t state = seed;

    for (int i = 0; i < 256; i++) {
        map[i] = (unsigned char)i;
        reverse[i] = (unsigned char)i;
    }

    for (int i = 0; i <= ZEND_VM_LAST_OPCODE; i++) {
        const char *name = zend_get_opcode_name((zend_uchar)i);
        if (name && strcmp(name, "UNKNOWN") != 0 && i != 0) {
            valid[count++] = (unsigned char)i;
        }
    }

    unsigned char shuffled[256];
    memcpy(shuffled, valid, count * sizeof(unsigned char));
    for (int i = count - 1; i > 0; i--) {
        unsigned int j = kage_lcg(&state) % (i + 1);
        unsigned char tmp = shuffled[i];
        shuffled[i] = shuffled[j];
        shuffled[j] = tmp;
    }

    for (int i = 0; i < count; i++) {
        unsigned char real = valid[i];
        unsigned char virt = shuffled[i];
        map[real] = virt;
        reverse[virt] = real;
    }
}

unsigned char kage_unmap_opcode_seeded(unsigned char virtual_opcode, uint32_t seed) {
    unsigned char map[256], reverse[256];
    kage_build_map_seeded(map, reverse, seed);
    return reverse[virtual_opcode];
}

void kage_map_oparray_seeded(zend_op_array *op_array, uint32_t seed) {
    if (!op_array) return;
    unsigned char map[256], reverse[256];
    kage_build_map_seeded(map, reverse, seed);

    for (uint32_t i = 0; i < op_array->last; i++) {
        zend_op *op = &op_array->opcodes[i];
        op->opcode = map[op->opcode];
    }
}

 int kage_opcode_map_init(void) {
     if (g_kage_map_initialized) return 0;
     kage_shuffle_opcode_map();
     g_kage_map_initialized = 1;
     return 0;
 }

void kage_opcode_map_shutdown(void) { }

void kage_map_oparray(zend_op_array *op_array) {
    if (!op_array || !g_kage_map_initialized) return;
    for (uint32_t i = 0; i < op_array->last; i++) {
        zend_op *op = &op_array->opcodes[i];
        unsigned char real = op->opcode;
        unsigned char virt = g_kage_opcode_map[real];
        op->opcode = virt;
    }
}
