/**
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-06-06 21:47
 * Last Updated: 2025-06-07 02:32
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#include "crypto.h"
#include "base64.h"

// Internal encryption function
zend_result kage_internal_encrypt(zval *return_value, zval *data, zend_string *key) {
    // Convert data to string if needed
    if (Z_TYPE_P(data) != IS_STRING) {
        convert_to_string(data);
    }
    
    // Get key length
    size_t key_len = ZSTR_LEN(key);
    if (key_len != crypto_secretbox_KEYBYTES) {
        return FAILURE;
    }
    
    // Generate nonce
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);
    
    // Prepare message
    size_t message_len = Z_STRLEN_P(data);
    unsigned char *message = (unsigned char *)Z_STRVAL_P(data);
    
    // Prepare ciphertext
    size_t ciphertext_len = crypto_secretbox_MACBYTES + message_len;
    unsigned char *ciphertext = emalloc(ciphertext_len);
    if (ciphertext == NULL) {
        return FAILURE;
    }
    
    // Encrypt
    if (crypto_secretbox_easy(ciphertext, message, message_len, nonce, (unsigned char *)ZSTR_VAL(key)) != 0) {
        efree(ciphertext);
        return FAILURE;
    }
    
    // Combine nonce and ciphertext
    size_t combined_len = sizeof nonce + ciphertext_len;
    unsigned char *combined = emalloc(combined_len);
    if (combined == NULL) {
        efree(ciphertext);
        return FAILURE;
    }
    memcpy(combined, nonce, sizeof nonce);
    memcpy(combined + sizeof nonce, ciphertext, ciphertext_len);
    
    // Base64 encode
    size_t encoded_len;
    char *encoded = kage_base64_encode(combined, combined_len, &encoded_len);
    efree(combined);
    efree(ciphertext);
    
    if (encoded == NULL) {
        return FAILURE;
    }
    
    // Set return value
    ZVAL_STRINGL(return_value, encoded, encoded_len);
    efree(encoded);
    
    return SUCCESS;
}

// Internal decryption function
zend_result kage_internal_decrypt(zval *return_value, zval *encrypted_data, zend_string *key) {
    // Convert encrypted data to string if needed
    if (Z_TYPE_P(encrypted_data) != IS_STRING) {
        convert_to_string(encrypted_data);
    }
    
    // Get key length
    size_t key_len = ZSTR_LEN(key);
    if (key_len != crypto_secretbox_KEYBYTES) {
        return FAILURE;
    }
    
    // Base64 decode
    size_t decoded_len;
    unsigned char *decoded = kage_base64_decode(Z_STRVAL_P(encrypted_data), Z_STRLEN_P(encrypted_data), &decoded_len);
    if (!decoded) {
        return FAILURE;
    }
    
    // Check minimum length
    if (decoded_len < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        efree(decoded);
        return FAILURE;
    }
    
    // Extract nonce and ciphertext
    unsigned char *nonce = decoded;
    unsigned char *ciphertext = decoded + crypto_secretbox_NONCEBYTES;
    size_t ciphertext_len = decoded_len - crypto_secretbox_NONCEBYTES;
    
    // Prepare plaintext
    unsigned char *plaintext = emalloc(ciphertext_len - crypto_secretbox_MACBYTES);
    if (plaintext == NULL) {
        efree(decoded);
        return FAILURE;
    }
    
    // Decrypt
    if (crypto_secretbox_open_easy(plaintext, ciphertext, ciphertext_len, nonce, (unsigned char *)ZSTR_VAL(key)) != 0) {
        efree(plaintext);
        efree(decoded);
        return FAILURE;
    }
    
    // Set return value
    ZVAL_STRINGL(return_value, (char *)plaintext, ciphertext_len - crypto_secretbox_MACBYTES);
    
    efree(plaintext);
    efree(decoded);
    
    return SUCCESS;
}

// PHP Function: Encrypt
PHP_FUNCTION(kage_encrypt_c) {
    zend_string *data;
    zend_string *key;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "SS", &data, &key) == FAILURE) {
        RETURN_FALSE;
    }
    
    zval data_zv;
    ZVAL_STR(&data_zv, data);
    
    if (kage_internal_encrypt(return_value, &data_zv, key) != SUCCESS) {
        RETURN_FALSE;
    }
}

// PHP Function: Decrypt
PHP_FUNCTION(kage_decrypt_c) {
    zend_string *encrypted_data;
    zend_string *key;
    
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "SS", &encrypted_data, &key) == FAILURE) {
        RETURN_FALSE;
    }
    
    zval encrypted_data_zv;
    ZVAL_STR(&encrypted_data_zv, encrypted_data);
    
    if (kage_internal_decrypt(return_value, &encrypted_data_zv, key) != SUCCESS) {
        RETURN_FALSE;
    }
} 