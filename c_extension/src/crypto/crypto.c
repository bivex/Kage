/**
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 */

#include "crypto.h"
#include "base64.h"
#include "kage_context.h"
#include "kage_config.h"
#include "bytecode_crypto.h"
#include "zend_compile.h"
#include "zend_execute.h"
#include "zend_smart_str.h"
#include "kage_memory.h"

char* kage_compress_lzss(const char *i, size_t il, size_t *ol) { *ol=il; char *o=KAGE_ALLOC(il); memcpy(o,i,il); return o; }
char* kage_decompress_lzss(const char *i, size_t il, size_t rl) { char *o=KAGE_ALLOC(rl+1); memcpy(o,i,il<rl?il:rl); o[rl]='\0'; return o; }

int kage_raw_decrypt(zval *rv, const unsigned char *d, size_t dl, zend_string *k, uint32_t *os) {
    if (dl < sizeof(kage_header_t)) return FAILURE;
    kage_header_t *h = (kage_header_t*)d;
    if (memcmp(h->magic, KAGE_HEADER_MAGIC, 4) != 0) return FAILURE;
    if (os) *os = h->seed;

    // Security Checks
    if (h->flags & KAGE_FLAG_HWID) {
        char *mid = kage_get_machine_id();
        if (!mid || strcmp(mid, h->hwid) != 0) {
            if (mid) efree(mid); return FAILURE;
        }
        if (mid) efree(mid);
    }

    size_t po = sizeof(kage_header_t);
    size_t pl = dl - po;
    const unsigned char *pld = d + po;
    if (pl < 40) return FAILURE;

    unsigned char *p = KAGE_ALLOC(pl - 24 - 16 + 1);
    if (crypto_secretbox_open_easy(p, pld + 24, pl - 24, pld, (unsigned char*)ZSTR_VAL(k)) != 0) {
        efree(p); return FAILURE;
    }
    ZVAL_STRINGL(rv, (char *)p, pl - 24 - 16);
    efree(p);
    return SUCCESS;
}

PHP_FUNCTION(kage_encrypt_c) {
    zval *c; zend_string *k, *h_in = NULL, *d_in = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zS|S!S!", &c, &k, &h_in, &d_in) == FAILURE) RETURN_FALSE;
    if (ZSTR_LEN(k) != 32) RETURN_FALSE;
    if (Z_TYPE_P(c) != IS_STRING) convert_to_string(c);
    
    kage_header_t h;
    memset(&h, 0, sizeof(h));
    memcpy(h.magic, KAGE_HEADER_MAGIC, 4);
    h.version = 2;
    randombytes_buf(&h.seed, sizeof(h.seed));

    if (h_in && ZSTR_LEN(h_in) > 0) {
        h.flags |= KAGE_FLAG_HWID;
        memcpy(h.hwid, ZSTR_VAL(h_in), ZSTR_LEN(h_in) < 31 ? ZSTR_LEN(h_in) : 31);
    }
    if (d_in && ZSTR_LEN(d_in) > 0) {
        h.flags |= KAGE_FLAG_DOMAIN;
        memcpy(h.domain, ZSTR_VAL(d_in), ZSTR_LEN(d_in) < 31 ? ZSTR_LEN(d_in) : 31);
    }

    unsigned char n[24]; randombytes_buf(n, 24);
    size_t cl = 16 + Z_STRLEN_P(c); unsigned char *cv = KAGE_ALLOC(cl);
    crypto_secretbox_easy(cv, (unsigned char*)Z_STRVAL_P(c), Z_STRLEN_P(c), n, (unsigned char*)ZSTR_VAL(k));
    
    size_t tl = sizeof(h) + 24 + cl;
    unsigned char *cb = KAGE_ALLOC(tl);
    h.payload_len = (uint32_t)(24 + cl);
    h.crc32 = kage_crc32(n, 24 + cl);

    memcpy(cb, &h, sizeof(h));
    memcpy(cb + sizeof(h), n, 24);
    memcpy(cb + sizeof(h) + 24, cv, cl);
    
    size_t el; char *e = kage_base64_encode(cb, tl, &el);
    efree(cb); efree(cv); if (!e) RETURN_FALSE;
    ZVAL_STRINGL(return_value, e, el); efree(e);
}

PHP_FUNCTION(kage_decrypt_c) {
    zval *e; zend_string *k;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zS", &e, &k) == FAILURE) RETURN_FALSE;
    if (ZSTR_LEN(k) != 32) RETURN_FALSE;
    if (Z_TYPE_P(e) != IS_STRING) convert_to_string(e);
    size_t dl; unsigned char *d = kage_base64_decode(Z_STRVAL_P(e), Z_STRLEN_P(e), &dl);
    if (!d) RETURN_FALSE;
    uint32_t s; if (kage_raw_decrypt(return_value, d, dl, k, &s) == SUCCESS) { efree(d); } else { efree(d); RETURN_FALSE; }
}

PHP_FUNCTION(kage_get_machine_id) {
    char *m = kage_get_machine_id();
    if (m) { RETVAL_STRING(m); efree(m); } else RETURN_FALSE;
}

int kage_internal_encrypt(zval *rv, zval *d, zend_string *k) { return FAILURE; }
int kage_internal_decrypt(zval *rv, zval *ed, zend_string *k) { return FAILURE; }
