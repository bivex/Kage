/**
 * Kage Extension — Virtual Opcode Mapping Implementation
 * Cryptographically Secure Dynamic ISA Permutation
 */

#include "config.h"
#include <zend_compile.h>
#include <zend_execute.h>
#include <zend_vm_opcodes.h>
#include "kage_opcode_map.h"
#include "kage_context.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

/**
 * Build random bijective mapping over defined opcodes only.
 */
static void kage_shuffle_opcode_map(kage_context *ctx) {
    if (!ctx) return;

    for (int i = 0; i < 256; i++) {
        ctx->opcode_map[i] = (unsigned char)i;
        ctx->reverse_map[i] = (unsigned char)i;
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
        ctx->opcode_map[real] = virt;
    }

    for (int i = 0; i < 256; i++) {
        ctx->reverse_map[ctx->opcode_map[i]] = (unsigned char)i;
    }
}

/**
 * Cryptographically secure PRNG Fisher-Yates Shuffle driven by Seed Hash
 */
void kage_build_map_seeded(unsigned char *map, unsigned char *reverse, uint32_t seed) {
    unsigned char valid[256];
    int count = 0;

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

    // Expand 32-bit seed into 64-byte PRNG entropy block via BLAKE2b (crypto_generichash max 64 bytes)
    unsigned char prng_stream[64];
    crypto_generichash(prng_stream, 64, (const unsigned char*)&seed, sizeof(seed), NULL, 0);

    unsigned char shuffled[256];
    memcpy(shuffled, valid, count * sizeof(unsigned char));
    for (int i = count - 1; i > 0; i--) {
        unsigned int random_val = prng_stream[(i * 2) % 64] | (prng_stream[(i * 2 + 1) % 64] << 8);
        unsigned int j = random_val % (i + 1);
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

int kage_opcode_map_init(kage_context *ctx) {
    if (!ctx || ctx->map_initialized) return 0;
    kage_shuffle_opcode_map(ctx);
    ctx->map_initialized = 1;
    return 0;
}
