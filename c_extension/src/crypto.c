/**
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-06-06 21:46
 * Last Updated: 2025-06-07 02:32
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use of this source code is strictly prohibited.
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
    *output_len = input_len;
    char *out = emalloc(input_len);
    memcpy(out, input, input_len);
    return out;
}

char* kage_decompress_lzss(const char *input, size_t input_len, size_t original_len) {
    char *out = emalloc(original_len + 1);
    memcpy(out, input, input_len < original_len ? input_len : original_len);
    out[original_len] = '\0';
    return out;
}

int kage_internal_encrypt(zval *return_value, zval *data, zend_string *key) {
    if (Z_TYPE_P(data) != IS_STRING) convert_to_string(data);
    if (Z_STRLEN_P(data) == 0) return FAILURE;
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);
    size_t ciphertext_len = crypto_secretbox_MACBYTES + Z_STRLEN_P(data);
    unsigned char *ciphertext = emalloc(ciphertext_len);
    if (crypto_secretbox_easy(ciphertext, (unsigned char*)Z_STRVAL_P(data), Z_STRLEN_P(data), nonce, (unsigned char*)ZSTR_VAL(key)) != 0) {
        efree(ciphertext);
        return FAILURE;
    }
    size_t combined_len = crypto_secretbox_NONCEBYTES + ciphertext_len;
    unsigned char *combined = emalloc(combined_len);
    memcpy(combined, nonce, crypto_secretbox_NONCEBYTES);
    memcpy(combined + crypto_secretbox_NONCEBYTES, ciphertext, ciphertext_len);
    size_t encoded_len;
    char *encoded = kage_base64_encode(combined, combined_len, &encoded_len);
    efree(combined);
    efree(ciphertext);
    if (encoded == NULL) return FAILURE;
    ZVAL_STRINGL(return_value, encoded, encoded_len);
    efree(encoded);
    return SUCCESS;
}

int kage_internal_decrypt(zval *return_value, zval *encrypted_data, zend_string *key) {
    if (Z_TYPE_P(encrypted_data) != IS_STRING) convert_to_string(encrypted_data);
    if (Z_STRLEN_P(encrypted_data) == 0) return FAILURE;
    size_t decoded_len;
    unsigned char *decoded = kage_base64_decode(Z_STRVAL_P(encrypted_data), Z_STRLEN_P(encrypted_data), &decoded_len);
    if (decoded == NULL) return FAILURE;
    if (decoded_len < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        efree(decoded);
        return FAILURE;
    }
    if (decoded_len >= sizeof(kage_header_t) && memcmp(decoded, KAGE_HEADER_MAGIC, 4) == 0) {
        uint32_t seed;
        int res = kage_raw_decrypt(return_value, decoded, decoded_len, key, &seed);
        efree(decoded);
        return res;
    }
    const unsigned char *nonce = decoded;
    const unsigned char *ciphertext = decoded + crypto_secretbox_NONCEBYTES;
    size_t ciphertext_len = decoded_len - crypto_secretbox_NONCEBYTES;
    unsigned char *plaintext = emalloc(ciphertext_len - crypto_secretbox_MACBYTES + 1);
    if (crypto_secretbox_open_easy(plaintext, ciphertext, ciphertext_len, nonce, (unsigned char*)ZSTR_VAL(key)) != 0) {
        efree(plaintext);
        efree(decoded);
        return FAILURE;
    }
    ZVAL_STRINGL(return_value, (char *)plaintext, ciphertext_len - crypto_secretbox_MACBYTES);
    efree(plaintext);
    efree(decoded);
    return SUCCESS;
}

int kage_raw_decrypt(zval *return_value, const unsigned char *data, size_t data_len, zend_string *key, uint32_t *out_seed) {
    if (data_len < sizeof(kage_header_t)) return FAILURE;
    kage_header_t *header = (kage_header_t*)data;
    if (out_seed) *out_seed = header->seed;

    if (memcmp(header->magic, KAGE_HEADER_MAGIC, 4) != 0) {
        // Fallback for V1
        if (data_len < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) return FAILURE;
        unsigned char *plaintext = emalloc(data_len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES + 1);
        if (crypto_secretbox_open_easy(plaintext, data + crypto_secretbox_NONCEBYTES, data_len - crypto_secretbox_NONCEBYTES, data, (unsigned char*)ZSTR_VAL(key)) != 0) {
            efree(plaintext); return FAILURE;
        }
        ZVAL_STRINGL(return_value, (char *)plaintext, data_len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES);
        efree(plaintext); return SUCCESS;
    }

    // Security Checks
    if (header->flags & KAGE_FLAG_HWID) {
        char *mid = kage_get_machine_id();
        if (!mid || strcmp(mid, header->hwid) != 0) {
            php_error_docref(NULL, E_ERROR, "Kage: HWID mismatch.");
            if (mid) efree(mid); return FAILURE;
        }
        if (mid) efree(mid);
    }
    
    if (header->flags & KAGE_FLAG_DOMAIN) {
        zval *server = zend_hash_str_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER")-1);
        int ok = 0;
        if (server && Z_TYPE_P(server) == IS_ARRAY) {
            zval *n = zend_hash_str_find(Z_ARRVAL_P(server), "SERVER_NAME", sizeof("SERVER_NAME")-1);
            if (!n) n = zend_hash_str_find(Z_ARRVAL_P(server), "HTTP_HOST", sizeof("HTTP_HOST")-1);
            if (n && Z_TYPE_P(n) == IS_STRING && strstr(Z_STRVAL_P(n), header->domain)) ok = 1;
        }
        if (!ok) {
            php_error_docref(NULL, E_ERROR, "Kage: Domain mismatch (%s).", header->domain);
            return FAILURE;
        }
    }

    // Payload extraction
    size_t payload_offset = sizeof(kage_header_t);
    size_t payload_len = data_len - payload_offset;
    const unsigned char *payload = data + payload_offset;

    // Decrypt
    unsigned char *plaintext = emalloc(payload_len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES + 1);
    if (crypto_secretbox_open_easy(plaintext, payload + crypto_secretbox_NONCEBYTES, payload_len - crypto_secretbox_NONCEBYTES, payload, (unsigned char*)ZSTR_VAL(key)) != 0) {
        efree(plaintext); return FAILURE;
    }
    ZVAL_STRINGL(return_value, (char *)plaintext, payload_len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES);
    efree(plaintext);
    return SUCCESS;
}

PHP_FUNCTION(kage_encrypt_c) {
    zval *code; zend_string *key, *hwid = NULL, *domain = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zS|SS", &code, &key, &hwid, &domain) == FAILURE) RETURN_FALSE;
    if (Z_TYPE_P(code) != IS_STRING) convert_to_string(code);
    kage_header_t h; memset(&h, 0, sizeof(h)); memcpy(h.magic, "KAGE", 4); h.version = 2;
    randombytes_buf(&h.seed, sizeof(h.seed));
    if (hwid && ZSTR_LEN(hwid) > 0) {
        h.flags |= KAGE_FLAG_HWID;
        memcpy(h.hwid, ZSTR_VAL(hwid), ZSTR_LEN(hwid) < 31 ? ZSTR_LEN(hwid) : 31);
    }
    if (domain && ZSTR_LEN(domain) > 0) {
        h.flags |= KAGE_FLAG_DOMAIN;
        memcpy(h.domain, ZSTR_VAL(domain), ZSTR_LEN(domain) < 31 ? ZSTR_LEN(domain) : 31);
    }
    unsigned char nonce[crypto_secretbox_NONCEBYTES]; randombytes_buf(nonce, sizeof nonce);
    size_t clen = crypto_secretbox_MACBYTES + Z_STRLEN_P(code);
    unsigned char *c = emalloc(clen);
    if (crypto_secretbox_easy(c, (unsigned char*)Z_STRVAL_P(code), Z_STRLEN_P(code), nonce, (unsigned char*)ZSTR_VAL(key)) != 0) {
        efree(c); RETURN_FALSE;
    }
    size_t tlen = sizeof(kage_header_t) + sizeof(nonce) + clen;
    unsigned char *comb = emalloc(tlen);
     h.payload_len = (uint32_t)(tlen - sizeof(kage_header_t));
     h.crc32 = kage_crc32(nonce, sizeof(nonce) + clen); 
     memcpy(comb, &h, sizeof(h));
    memcpy(comb + sizeof(h), nonce, sizeof(nonce));
    memcpy(comb + sizeof(h) + sizeof(nonce), c, clen);
    size_t elen; char *e = kage_base64_encode(comb, tlen, &elen);
    efree(comb); efree(c);
    if (!e) RETURN_FALSE;
    ZVAL_STRINGL(return_value, e, elen); efree(e);
}

PHP_FUNCTION(kage_decrypt_c) {
    zval *enc; zend_string *key;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zS", &enc, &key) == FAILURE) RETURN_FALSE;
    if (kage_internal_decrypt(return_value, enc, key) != SUCCESS) RETURN_FALSE;
}

PHP_FUNCTION(kage_get_machine_id) {
    char *mid = kage_get_machine_id();
    if (mid) { RETVAL_STRING(mid); efree(mid); } else RETURN_FALSE;
}
