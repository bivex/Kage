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
// Total size: 64 bytes
typedef struct {
    char magic[4];          // "KAGE"
    uint32_t version;       // Format version (2)
    uint32_t flags;         // Bit 0: LZSS Compressed, Bit 1: HWID Bound, Bit 2: Domain Bound
    uint32_t payload_len;   // Length of encrypted data
    uint32_t crc32;         // CRC32 of payload for integrity
    char hwid[32];          // Target Machine HWID (if flags & 0x02)
    uint32_t reserved[3];   // Future use
} kage_header_t;

#define KAGE_HEADER_MAGIC   "KAGE"
#define KAGE_FLAG_LZSS      0x01
#define KAGE_FLAG_HWID      0x02
#define KAGE_FLAG_DOMAIN    0x04

// Internal functions
int kage_internal_encrypt(zval *return_value, zval *data, zend_string *key);
int kage_internal_decrypt(zval *return_value, zval *encrypted_data, zend_string *key);
PHPAPI int kage_raw_decrypt(zval *return_value, const unsigned char *data, size_t data_len, zend_string *key);

// Compression (Phase 5)char* kage_compress_lzss(const char *input, size_t input_len, size_t *output_len);
char* kage_decompress_lzss(const char *input, size_t input_len, size_t original_len);

/**
 * Encrypts data using libsodium's crypto_secretbox_easy

 * @param data_str Input data to encrypt
 * @param key_str Encryption key
 * @return Base64 encoded (nonce + ciphertext) or FALSE on failure
 */
PHP_FUNCTION(kage_encrypt_c);

/**
 * Decrypts data using libsodium's crypto_secretbox_open_easy
 * @param encrypted_data_base64_str Base64 encoded (nonce + ciphertext)
 * @param key_str Decryption key
 * @return Decrypted plaintext or FALSE on failure
 */
 PHP_FUNCTION(kage_decrypt_c);

 /**
 * Returns the unique hardware ID of the current machine.
 * @return string Machine ID
 */
 PHP_FUNCTION(kage_get_machine_id);

 #endif /* PHP_KAGE_CRYPTO_H */