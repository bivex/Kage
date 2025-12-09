/**
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-06-06 21:47
 * Last Updated: 2025-12-09
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#include "crypto.h"
#include "base64.h"
#include "kage_context.h"
#include "bytecode_crypto.h"
#include "zend_compile.h"
#include "zend_execute.h"
#include "zend_smart_str.h"

// Function to extract bytecode from PHP source code
static vld_bytecode_info* kage_extract_bytecode_from_php(const char *php_code, size_t code_len) {
    if (!php_code || code_len == 0) {
        return NULL;
    }

    // Compile PHP code to get op_array
    zval code_zv;
    ZVAL_STRINGL(&code_zv, php_code, code_len);

    zend_op_array *op_array = zend_compile_string(&code_zv, "kage_compiled");
    if (!op_array) {
        zval_ptr_dtor(&code_zv);
        return NULL;
    }

    zval_ptr_dtor(&code_zv);

    // Create vld_bytecode_info structure
    vld_bytecode_info *bytecode = emalloc(sizeof(vld_bytecode_info));
    memset(bytecode, 0, sizeof(vld_bytecode_info));

    // Initialize hashtables
    bytecode->functions = emalloc(sizeof(HashTable));
    bytecode->opcodes = emalloc(sizeof(HashTable));
    bytecode->source_file = estrdup("compiled_php");
    bytecode->total_opcodes = 0;

    zend_hash_init(bytecode->functions, 8, NULL, NULL, 0);
    zend_hash_init(bytecode->opcodes, 64, NULL, NULL, 0);

    // Process opcodes
    if (op_array->opcodes && op_array->last > 0) {
        for (uint32_t i = 0; i < op_array->last; i++) {
            // Create encrypted op structure
            zend_op_encrypted *op = emalloc(sizeof(zend_op_encrypted));
            memset(op, 0, sizeof(zend_op_encrypted));

            op->lineno = op_array->opcodes[i].lineno;
            op->opcode = op_array->opcodes[i].opcode;
            op->handler = NULL;

            // Copy operands (simplified)
            ZVAL_COPY(&op->op1, &op_array->opcodes[i].op1);
            ZVAL_COPY(&op->op2, &op_array->opcodes[i].op2);
            ZVAL_COPY(&op->result, &op_array->opcodes[i].result);

            // Add to opcodes hashtable
            zend_hash_index_add_ptr(bytecode->opcodes, i, op);
            bytecode->total_opcodes++;
        }
    }

    // Clean up op_array
    destroy_op_array(op_array);
    efree(op_array);

    return bytecode;
}

// Function to reconstruct PHP code from decrypted bytecode (simplified)
static char* kage_reconstruct_php_from_bytecode(vld_bytecode_info *bytecode) {
    if (!bytecode || !bytecode->functions) {
        return NULL;
    }

    smart_str result = {0};
    smart_str_appends(&result, "<?php\n");

    // For now, just return a placeholder - full reconstruction would be complex
    smart_str_appends(&result, "// Decrypted bytecode placeholder\n");
    smart_str_appends(&result, "echo \"Bytecode decrypted successfully\\n\";\n");

    smart_str_0(&result);

    char *php_code = estrndup(result.s->val, result.s->len);
    smart_str_free(&result);

    return php_code;
}

// Internal encryption function - improved with error handling
int kage_internal_encrypt(zval *return_value, zval *data, zend_string *key) {
    // Convert data to string if needed
    if (Z_TYPE_P(data) != IS_STRING) {
        convert_to_string(data);
    }

    // Get key length
    size_t key_len = ZSTR_LEN(key);
    if (key_len != crypto_secretbox_KEYBYTES) {
        zend_error(E_WARNING, "Kage: Invalid encryption key length");
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
        zend_error(E_WARNING, "Kage: Memory allocation failed");
        return FAILURE;
    }

    // Encrypt
    if (crypto_secretbox_easy(ciphertext, message, message_len, nonce, (unsigned char *)ZSTR_VAL(key)) != 0) {
        efree(ciphertext);
        zend_error(E_WARNING, "Kage: Encryption failed");
        return FAILURE;
    }

    // Combine nonce and ciphertext
    size_t combined_len = sizeof nonce + ciphertext_len;
    unsigned char *combined = emalloc(combined_len);
    if (combined == NULL) {
        efree(ciphertext);
        zend_error(E_WARNING, "Kage: Memory allocation failed");
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
        zend_error(E_WARNING, "Kage: Base64 encoding failed");
        return FAILURE;
    }

    // Set return value
    ZVAL_STRINGL(return_value, encoded, encoded_len);
    efree(encoded);

    return SUCCESS;
}

// Internal decryption function - improved with error handling
int kage_internal_decrypt(zval *return_value, zval *encrypted_data, zend_string *key) {
    // Convert encrypted data to string if needed
    if (Z_TYPE_P(encrypted_data) != IS_STRING) {
        convert_to_string(encrypted_data);
    }

    // Get key length
    size_t key_len = ZSTR_LEN(key);
    if (key_len != crypto_secretbox_KEYBYTES) {
        zend_error(E_WARNING, "Kage: Invalid decryption key length");
        return FAILURE;
    }

    // Base64 decode
    size_t decoded_len;
    unsigned char *decoded = kage_base64_decode(Z_STRVAL_P(encrypted_data), Z_STRLEN_P(encrypted_data), &decoded_len);
    if (!decoded) {
        zend_error(E_WARNING, "Kage: Base64 decoding failed");
        return FAILURE;
    }

    // Check minimum length
    if (decoded_len < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        efree(decoded);
        zend_error(E_WARNING, "Kage: Invalid encrypted data length");
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
        zend_error(E_WARNING, "Kage: Memory allocation failed");
        return FAILURE;
    }

    // Decrypt
    if (crypto_secretbox_open_easy(plaintext, ciphertext, ciphertext_len, nonce, (unsigned char *)ZSTR_VAL(key)) != 0) {
        efree(plaintext);
        efree(decoded);
        zend_error(E_WARNING, "Kage: Decryption failed");
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
    zend_string *php_code;
    zend_string *key;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "SS", &php_code, &key) == FAILURE) {
        RETURN_FALSE;
    }

    // Extract bytecode from PHP code
    vld_bytecode_info *bytecode = kage_extract_bytecode_from_php(ZSTR_VAL(php_code), ZSTR_LEN(php_code));
    if (!bytecode) {
        zend_error(E_WARNING, "Kage: Failed to extract bytecode from PHP code");
        RETURN_FALSE;
    }

    // Create encryption config
    kage_bytecode_crypto_config crypto_config = {0};
    crypto_config.algorithm = KAGE_OPCODE_ENCRYPT_XOR; // Default algorithm
    crypto_config.key = ZSTR_VAL(key);
    crypto_config.key_length = ZSTR_LEN(key);
    crypto_config.selective_encryption = 0; // Encrypt all opcodes

    // Encrypt opcodes
    kage_result_t encrypt_result = kage_encrypt_opcodes(bytecode, &crypto_config);
    if (encrypt_result.error != KAGE_SUCCESS) {
        kage_free_bytecode_info(bytecode);
        zend_error(E_WARNING, "Kage: Failed to encrypt bytecode");
        RETURN_FALSE;
    }

    // Serialize encrypted bytecode
    char *serialized = kage_serialize_bytecode(bytecode);
    if (!serialized) {
        kage_free_bytecode_info(bytecode);
        zend_error(E_WARNING, "Kage: Failed to serialize encrypted bytecode");
        RETURN_FALSE;
    }

    // Clean up
    kage_free_bytecode_info(bytecode);

    // Return base64 encoded result for easier handling
    size_t encoded_len;
    char *encoded = kage_base64_encode((unsigned char*)serialized, strlen(serialized), &encoded_len);
    efree(serialized);

    if (!encoded) {
        zend_error(E_WARNING, "Kage: Failed to encode result");
        RETURN_FALSE;
    }

    RETVAL_STRINGL(encoded, encoded_len);
    efree(encoded);
}

// PHP Function: Decrypt
PHP_FUNCTION(kage_decrypt_c) {
    zend_string *encrypted_data;
    zend_string *key;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "SS", &encrypted_data, &key) == FAILURE) {
        RETURN_FALSE;
    }

    // Decode from base64 first
    size_t decoded_len;
    unsigned char *decoded = kage_base64_decode(ZSTR_VAL(encrypted_data), ZSTR_LEN(encrypted_data), &decoded_len);
    if (!decoded) {
        zend_error(E_WARNING, "Kage: Failed to decode encrypted data");
        RETURN_FALSE;
    }

    // Unserialize bytecode
    vld_bytecode_info *bytecode = kage_unserialize_bytecode((char*)decoded);
    efree(decoded);

    if (!bytecode) {
        zend_error(E_WARNING, "Kage: Failed to unserialize bytecode");
        RETURN_FALSE;
    }

    // Create decryption config (same as encryption)
    kage_bytecode_crypto_config crypto_config = {0};
    crypto_config.algorithm = KAGE_OPCODE_ENCRYPT_XOR; // Same algorithm as encryption
    crypto_config.key = ZSTR_VAL(key);
    crypto_config.key_length = ZSTR_LEN(key);
    crypto_config.selective_encryption = 0; // Decrypt all opcodes

    // Decrypt opcodes
    kage_result_t decrypt_result = kage_decrypt_opcodes(bytecode, &crypto_config);
    if (decrypt_result.error != KAGE_SUCCESS) {
        kage_free_bytecode_info(bytecode);
        zend_error(E_WARNING, "Kage: Failed to decrypt bytecode");
        RETURN_FALSE;
    }

    // Reconstruct PHP code from decrypted bytecode
    char *php_code = kage_reconstruct_php_from_bytecode(bytecode);

    // Clean up
    kage_free_bytecode_info(bytecode);

    if (!php_code) {
        zend_error(E_WARNING, "Kage: Failed to reconstruct PHP code from bytecode");
        RETURN_FALSE;
    }

    RETVAL_STRING(php_code);
    efree(php_code);
} 