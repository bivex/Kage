/**
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-06-06 21:46
 * Last Updated: 2025-06-07 02:32
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#ifndef PHP_KAGE_CRYPTO_H
#define PHP_KAGE_CRYPTO_H

#include "config.h"
#include <stdint.h>

// KAGE File Header (Professional Grade)
// Total size: 96 bytes (aligned)
typedef struct {
    char magic[4];          // "KAGE"
    uint32_t version;       // Format version (2)
    uint32_t flags;         // Bit 0: LZSS, Bit 1: HWID, Bit 2: Domain
    uint32_t payload_len;   // Length of encrypted data
    uint32_t crc32;         // CRC32 of payload
    char hwid[32];          // Target Machine HWID
    char domain[32];        // Target Domain
    uint32_t seed;          // Dynamic ISA Seed
    uint32_t reserved[2];   // Future use
} kage_header_t;

#define KAGE_HEADER_MAGIC   "KAGE"
#define KAGE_FLAG_LZSS      0x01
#define KAGE_FLAG_HWID      0x02
#define KAGE_FLAG_DOMAIN    0x04

// Internal functions
int kage_internal_encrypt(zval *return_value, zval *data, zend_string *key);
int kage_internal_decrypt(zval *return_value, zval *encrypted_data, zend_string *key);
PHPAPI int kage_raw_decrypt(zval *return_value, const unsigned char *data, size_t data_len, zend_string *key, uint32_t *out_seed);

// Compression (Phase 5)
char* kage_compress_lzss(const char *input, size_t input_len, size_t *output_len);
char* kage_decompress_lzss(const char *input, size_t input_len, size_t original_len);

PHP_FUNCTION(kage_encrypt_c);
PHP_FUNCTION(kage_decrypt_c);
PHP_FUNCTION(kage_get_machine_id);

#endif /* PHP_KAGE_CRYPTO_H */
