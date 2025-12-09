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

// Internal functions
int kage_internal_encrypt(zval *return_value, zval *data, zend_string *key);
int kage_internal_decrypt(zval *return_value, zval *encrypted_data, zend_string *key);

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

#endif /* PHP_KAGE_CRYPTO_H */ 