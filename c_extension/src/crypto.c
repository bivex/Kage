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

// Structure to hold PHP code with encrypted bytecode
typedef struct {
    char *original_php_code;
    vld_bytecode_info *encrypted_bytecode;
} php_bytecode_package;

// Function to create a package with original PHP code and encrypted bytecode
static php_bytecode_package* kage_create_php_package(const char *php_code, size_t code_len) {
    php_bytecode_package *package = emalloc(sizeof(php_bytecode_package));
    package->original_php_code = estrndup(php_code, code_len);

    // Extract and encrypt bytecode
    package->encrypted_bytecode = kage_extract_bytecode_from_php(php_code, code_len);

    return package;
}

// Function to serialize PHP package
static char* kage_serialize_php_package(php_bytecode_package *package) {
    if (!package) return NULL;

    smart_str result = {0};

    // Store original PHP code length and content
    uint32_t code_len = strlen(package->original_php_code);
    smart_str_appendc(&result, 'P'); // Package marker
    smart_str_append_long(&result, code_len);
    smart_str_appendc(&result, ':');
    smart_str_appendl(&result, package->original_php_code, code_len);

    // Serialize encrypted bytecode
    char *serialized_bytecode = kage_serialize_bytecode(package->encrypted_bytecode);
    if (serialized_bytecode) {
        uint32_t bytecode_len = strlen(serialized_bytecode);
        smart_str_appendc(&result, 'B'); // Bytecode marker
        smart_str_append_long(&result, bytecode_len);
        smart_str_appendc(&result, ':');
        smart_str_appendl(&result, serialized_bytecode, bytecode_len);
        efree(serialized_bytecode);
    }

    smart_str_0(&result);

    char *serialized = estrndup(result.s->val, result.s->len);
    smart_str_free(&result);

    return serialized;
}

// Function to unserialize PHP package
static php_bytecode_package* kage_unserialize_php_package(const char *serialized) {
    if (!serialized || serialized[0] != 'P') return NULL;

    php_bytecode_package *package = emalloc(sizeof(php_bytecode_package));
    memset(package, 0, sizeof(php_bytecode_package));

    const char *ptr = serialized + 1; // Skip 'P' marker

    // Parse PHP code
    char *endptr;
    uint32_t code_len = strtol(ptr, &endptr, 10);
    if (*endptr != ':') {
        efree(package);
        return NULL;
    }
    ptr = endptr + 1;
    package->original_php_code = estrndup(ptr, code_len);
    ptr += code_len;

    // Parse bytecode if present
    if (*ptr == 'B') {
        ptr++; // Skip 'B' marker
        uint32_t bytecode_len = strtol(ptr, &endptr, 10);
        if (*endptr == ':') {
            ptr = endptr + 1;
            char *bytecode_data = estrndup(ptr, bytecode_len);
            package->encrypted_bytecode = kage_unserialize_bytecode(bytecode_data);
            efree(bytecode_data);
        }
    }

    return package;
}

// Function to free PHP package
static void kage_free_php_package(php_bytecode_package *package) {
    if (!package) return;

    if (package->original_php_code) {
        efree(package->original_php_code);
    }
    if (package->encrypted_bytecode) {
        kage_free_bytecode_info(package->encrypted_bytecode);
    }
    efree(package);
}

// Function to reconstruct PHP code from decrypted bytecode (now returns original code)
static char* kage_reconstruct_php_from_bytecode(php_bytecode_package *package) {
    if (!package || !package->original_php_code) {
        return NULL;
    }

    // Return the original PHP code
    return estrndup(package->original_php_code, strlen(package->original_php_code));
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

    // Validate inputs
    if (ZSTR_LEN(php_code) == 0) {
        zend_error(E_WARNING, "Kage: PHP code cannot be empty");
        RETURN_FALSE;
    }

    if (ZSTR_LEN(key) != 32) {
        zend_error(E_WARNING, "Kage: Invalid encryption key length (must be 32 bytes)");
        RETURN_FALSE;
    }

    // Create PHP package with original code and encrypted bytecode
    php_bytecode_package *package = kage_create_php_package(ZSTR_VAL(php_code), ZSTR_LEN(php_code));
    if (!package || !package->encrypted_bytecode) {
        if (package) kage_free_php_package(package);
        zend_error(E_WARNING, "Kage: Failed to create PHP bytecode package");
        RETURN_FALSE;
    }

    // Create encryption config
    kage_bytecode_crypto_config crypto_config = {0};
    crypto_config.algorithm = KAGE_OPCODE_ENCRYPT_XOR; // Default algorithm
    crypto_config.key = ZSTR_VAL(key);
    crypto_config.key_length = ZSTR_LEN(key);
    crypto_config.selective_encryption = 0; // Encrypt all opcodes

    // Encrypt opcodes
    kage_result_t encrypt_result = kage_encrypt_opcodes(package->encrypted_bytecode, &crypto_config);
    if (encrypt_result.error != KAGE_SUCCESS) {
        kage_free_php_package(package);
        zend_error(E_WARNING, "Kage: Failed to encrypt bytecode");
        RETURN_FALSE;
    }

    // Serialize the complete package
    char *serialized = kage_serialize_php_package(package);
    if (!serialized) {
        kage_free_php_package(package);
        zend_error(E_WARNING, "Kage: Failed to serialize PHP package");
        RETURN_FALSE;
    }

    // Clean up
    kage_free_php_package(package);

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

    // Validate inputs
    if (ZSTR_LEN(encrypted_data) == 0) {
        zend_error(E_WARNING, "Kage: Encrypted data cannot be empty");
        RETURN_FALSE;
    }

    if (ZSTR_LEN(key) != 32) {
        zend_error(E_WARNING, "Kage: Invalid decryption key length (must be 32 bytes)");
        RETURN_FALSE;
    }

    // Decode from base64 first
    size_t decoded_len;
    unsigned char *decoded = kage_base64_decode(ZSTR_VAL(encrypted_data), ZSTR_LEN(encrypted_data), &decoded_len);
    if (!decoded) {
        zend_error(E_WARNING, "Kage: Failed to decode encrypted data");
        RETURN_FALSE;
    }

    // Unserialize PHP package
    php_bytecode_package *package = kage_unserialize_php_package((char*)decoded);
    efree(decoded);

    if (!package) {
        zend_error(E_WARNING, "Kage: Failed to unserialize PHP package");
        RETURN_FALSE;
    }

    // Create decryption config (same as encryption)
    kage_bytecode_crypto_config crypto_config = {0};
    crypto_config.algorithm = KAGE_OPCODE_ENCRYPT_XOR; // Same algorithm as encryption
    crypto_config.key = ZSTR_VAL(key);
    crypto_config.key_length = ZSTR_LEN(key);
    crypto_config.selective_encryption = 0; // Decrypt all opcodes

    // Decrypt opcodes
    kage_result_t decrypt_result = kage_decrypt_opcodes(package->encrypted_bytecode, &crypto_config);
    if (decrypt_result.error != KAGE_SUCCESS) {
        kage_free_php_package(package);
        zend_error(E_WARNING, "Kage: Failed to decrypt bytecode");
        RETURN_FALSE;
    }

    // Reconstruct PHP code from decrypted bytecode (returns original code)
    char *php_code = kage_reconstruct_php_from_bytecode(package);

    // Clean up
    kage_free_php_package(package);

    if (!php_code) {
        zend_error(E_WARNING, "Kage: Failed to reconstruct PHP code from bytecode");
        RETURN_FALSE;
    }

    RETVAL_STRING(php_code);
    efree(php_code);
}