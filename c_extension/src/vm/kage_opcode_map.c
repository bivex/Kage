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
 * Cryptographically secure PRNG Fisher-Yates Shuffle with Unbiased Rejection Sampling
 */
static void kage_generate_prng_stream(unsigned char *out, size_t outlen, uint32_t seed) {
    uint32_t counter = 0;
    size_t offset = 0;
    while (offset < outlen) {
        struct {
            uint32_t seed;
            uint32_t counter;
        } input = { seed, counter++ };
        
        size_t block_len = (outlen - offset < 64) ? (outlen - offset) : 64;
        unsigned char block[64];
        crypto_generichash(block, block_len, (const unsigned char*)&input, sizeof(input), NULL, 0);
        memcpy(out + offset, block, block_len);
        offset += block_len;
    }
}

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

    // Expand 32-bit seed into 1024 bytes of CSPRNG entropy via BLAKE2b counter mode
    uint32_t prng_buf[256];
    kage_generate_prng_stream((unsigned char*)prng_buf, sizeof(prng_buf), seed);

    unsigned char shuffled[256];
    memcpy(shuffled, valid, count * sizeof(unsigned char));
    
    size_t prng_idx = 0;
    for (int i = count - 1; i > 0; i--) {
        uint32_t range = i + 1;
        uint32_t limit = UINT32_MAX - (UINT32_MAX % range);
        uint32_t val;
        
        // Unbiased Rejection Sampling to eliminate Modulo Bias
        do {
            val = prng_buf[prng_idx % 256];
            prng_idx++;
        } while (val >= limit);

        uint32_t j = val % range;
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
