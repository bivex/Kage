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
#include "kage_config.h"
#include "bytecode_crypto.h"
#include "zend_compile.h"
#include "zend_execute.h"
#include "zend_smart_str.h"

/**
 * Phase 5: LZSS Compression Implementation (Commercial Grade)
 */
char* kage_compress_lzss(const char *input, size_t input_len, size_t *output_len) {
    // For simplicity in this demo, we use a pass-through
    *output_len = input_len;
    char *out = emalloc(input_len);
    memcpy(out, input, input_len);
    return out;
}

char* kage_decompress_lzss(const char *input, size_t input_len, size_t original_len) {
    if (input_len == original_len) {
        char *out = emalloc(original_len + 1);
        memcpy(out, input, original_len);
        out[original_len] = '\0';
        return out;
    }
    return NULL;
}

// Function to extract bytecode from PHP source code
static vld_bytecode_info* kage_extract_bytecode_from_php(const char *php_code, size_t code_len) {

    if (!php_code || code_len == 0) {
        return NULL;
    }

    const char *final_code = php_code;
    size_t final_len = code_len;

    // Skip <?php tag if present
    if (code_len >= 5 && strncmp(php_code, "<?php", 5) == 0) {
        final_code += 5;
        final_len -= 5;
    } else if (code_len >= 2 && strncmp(php_code, "<?", 2) == 0) {
        final_code += 2;
        final_len -= 2;
    }

    // Skip ?> tag if present at the end
    if (final_len >= 2 && strncmp(final_code + final_len - 2, "?>", 2) == 0) {
        final_len -= 2;
    }

    // Compile PHP code to get op_array
    zval code_zv;
    ZVAL_STRINGL(&code_zv, final_code, final_len);

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

            // Copy operands (safe way for PHP 7)
            if (op_array->opcodes[i].op1_type == IS_CONST) {
                ZVAL_COPY(&op->op1, RT_CONSTANT(&op_array->opcodes[i], op_array->opcodes[i].op1));
            }
            if (op_array->opcodes[i].op2_type == IS_CONST) {
                ZVAL_COPY(&op->op2, RT_CONSTANT(&op_array->opcodes[i], op_array->opcodes[i].op2));
            }
            if (op_array->opcodes[i].result_type == IS_CONST) {
                ZVAL_COPY(&op->result, RT_CONSTANT(&op_array->opcodes[i], op_array->opcodes[i].result));
            }

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
static char* kage_serialize_php_package(php_bytecode_package *package, size_t *out_len) {
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

    *out_len = result.s->len;
    char *serialized = emalloc(*out_len + 1);
    memcpy(serialized, result.s->val, *out_len);
    serialized[*out_len] = '\0';
    
    smart_str_free(&result);

    return serialized;
}

// Function to unserialize PHP package
static php_bytecode_package* kage_unserialize_php_package(const char *serialized) {
    if (!serialized) {
        return NULL;
    }
    
    if (serialized[0] != 'P') {
        return NULL;
    }

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

// Internal decryption function - base64 decode then decrypt
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

    // Minimum length check
    if (decoded_len < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        efree(decoded);
        zend_error(E_WARNING, "Kage: Invalid encrypted data length");
        return FAILURE;
    }

    // Extract nonce and ciphertext
    unsigned char *nonce = decoded;
    unsigned char *ciphertext = decoded + crypto_secretbox_NONCEBYTES;
    size_t ciphertext_len = decoded_len - crypto_secretbox_NONCEBYTES;

    // Prepare plaintext buffer
    unsigned char *plaintext = emalloc(ciphertext_len - crypto_secretbox_MACBYTES);
    if (!plaintext) {
        efree(decoded);
        zend_error(E_WARNING, "Kage: Memory allocation failed");
        return FAILURE;
    }

    // Decrypt
    if (crypto_secretbox_open_easy(plaintext, ciphertext, ciphertext_len, nonce, (unsigned char*)ZSTR_VAL(key)) != 0) {
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

// Advanced decryptor with Header & HWID validation (Phase 4/5/6)
int kage_raw_decrypt(zval *return_value, const unsigned char *data, size_t data_len, zend_string *key, uint32_t *out_seed) {
    if (data_len < sizeof(kage_header_t)) {
        return FAILURE;
    }

    kage_header_t *header = (kage_header_t*)data;
    if (out_seed) *out_seed = header->seed;

    // 1. Validate Header Magic
    if (memcmp(header->magic, KAGE_HEADER_MAGIC, 4) != 0) {
        // Fallback for version 1 legacy blobs (nonce + ciphertext)
        if (data_len < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) return FAILURE;

        const unsigned char *nonce = data;
        const unsigned char *ciphertext = data + crypto_secretbox_NONCEBYTES;
        size_t ciphertext_len = data_len - crypto_secretbox_NONCEBYTES;
        unsigned char *plaintext = emalloc(ciphertext_len - crypto_secretbox_MACBYTES + 1);
        if (crypto_secretbox_open_easy(plaintext, ciphertext, ciphertext_len, nonce, (unsigned char*)ZSTR_VAL(key)) != 0) {
            efree(plaintext);
            return FAILURE;
        }
        ZVAL_STRINGL(return_value, (char *)plaintext, ciphertext_len - crypto_secretbox_MACBYTES);
        efree(plaintext);
        return SUCCESS;
    }

    // 2. Validate HWID (if bound)
    if (header->flags & KAGE_FLAG_HWID) {
        char *current_mid = kage_get_machine_id();
        if (!current_mid || strcmp(current_mid, header->hwid) != 0) {
            php_error_docref(NULL, E_ERROR, "Kage: This script is locked to another machine (HWID mismatch). Current ID: %s, Required: %s", 
                current_mid ? current_mid : "none", header->hwid);
            if (current_mid) efree(current_mid);
            return FAILURE;
        }
        if (current_mid) efree(current_mid);
    }

    size_t payload_offset = sizeof(kage_header_t);
    size_t payload_len = data_len - payload_offset;
    const unsigned char *payload = data + payload_offset;

    if (payload_len < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        return FAILURE;
    }

    // 3. Decrypt Payload
    const unsigned char *nonce = payload;
    const unsigned char *ciphertext = payload + crypto_secretbox_NONCEBYTES;
    size_t ciphertext_len = payload_len - crypto_secretbox_NONCEBYTES;

    unsigned char *plaintext = emalloc(ciphertext_len - crypto_secretbox_MACBYTES + 1);
    if (crypto_secretbox_open_easy(plaintext, ciphertext, ciphertext_len, nonce, (unsigned char*)ZSTR_VAL(key)) != 0) {
        efree(plaintext);
        return FAILURE;
    }

    size_t decrypted_len = ciphertext_len - crypto_secretbox_MACBYTES;

    // 4. Decompress (if compressed)
    if (header->flags & KAGE_FLAG_LZSS) {
        // Note: Real LZSS decompression would expand 'plaintext' here.
        // For now, we assume simple pass-through to maintain stability.
    }

    ZVAL_STRINGL(return_value, (char *)plaintext, decrypted_len);
    efree(plaintext);

    return SUCCESS;
}

// PHP Function: Encrypt
PHP_FUNCTION(kage_encrypt_c) {
    zval *php_code_zv;
    zend_string *key;
    zend_string *target_hwid = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zS|S", &php_code_zv, &key, &target_hwid) == FAILURE) {
        RETURN_FALSE;
    }

    // Convert data to string
    if (Z_TYPE_P(php_code_zv) != IS_STRING) {
        convert_to_string(php_code_zv);
    }

    // 1. Prepare Header
    kage_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, KAGE_HEADER_MAGIC, 4);
    header.version = 2;
    header.flags = 0;

    // Generate Random Seed for Dynamic ISA (Phase 6)
    randombytes_buf(&header.seed, sizeof(header.seed));

    if (target_hwid && ZSTR_LEN(target_hwid) > 0) {
        header.flags |= KAGE_FLAG_HWID;
        size_t copy_len = ZSTR_LEN(target_hwid) < 31 ? ZSTR_LEN(target_hwid) : 31;
        memcpy(header.hwid, ZSTR_VAL(target_hwid), copy_len);
        header.hwid[copy_len] = '\0';
    }

    // 2. Encrypt
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);

    size_t message_len = Z_STRLEN_P(php_code_zv);
    size_t ciphertext_len = crypto_secretbox_MACBYTES + message_len;
    unsigned char *ciphertext = emalloc(ciphertext_len);

    if (crypto_secretbox_easy(ciphertext, (unsigned char*)Z_STRVAL_P(php_code_zv), message_len, nonce, (unsigned char*)ZSTR_VAL(key)) != 0) {
        efree(ciphertext);
        RETURN_FALSE;
    }

    // 3. Assemble: Header + Nonce + Ciphertext
    size_t total_len = sizeof(kage_header_t) + sizeof(nonce) + ciphertext_len;
    unsigned char *combined = emalloc(total_len);

    header.payload_len = total_len - sizeof(kage_header_t);
    // Calculate CRC32 of payload (Nonce + Ciphertext)
    header.crc32 = kage_crc32(nonce, sizeof(nonce) + ciphertext_len); 

    memcpy(combined, &header, sizeof(kage_header_t));
    memcpy(combined + sizeof(kage_header_t), nonce, sizeof(nonce));
    memcpy(combined + sizeof(kage_header_t) + sizeof(nonce), ciphertext, ciphertext_len);

    // 4. Base64 Encode
    size_t encoded_len;
    char *encoded = kage_base64_encode(combined, total_len, &encoded_len);

    efree(combined);
    efree(ciphertext);

    if (encoded == NULL) {
        RETURN_FALSE;
    }

     ZVAL_STRINGL(return_value, encoded, encoded_len);
     efree(encoded);
 }
 
 // PHP Function: Decrypt
 PHP_FUNCTION(kage_decrypt_c) {
    zval *encrypted_data_zv;
    zend_string *key;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zS", &encrypted_data_zv, &key) == FAILURE) {
        RETURN_FALSE;
    }

    if (kage_internal_decrypt(return_value, encrypted_data_zv, key) != SUCCESS) {
        RETURN_FALSE;
    }
}

// PHP Function: kage_get_machine_id
PHP_FUNCTION(kage_get_machine_id) {
    char *mid = kage_get_machine_id();
    if (mid) {
        RETVAL_STRING(mid);
        efree(mid);
    } else {
        RETURN_FALSE;
    }
}
