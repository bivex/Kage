#include "base64.h"
#include "ext/standard/base64.h"
#include <string.h>

char* kage_base64_encode(const unsigned char *input, size_t input_length, size_t *output_length) {
    zend_string *encoded = php_base64_encode(input, input_length);
    if (!encoded) {
        if (output_length) *output_length = 0;
        return NULL;
    }
    
    if (output_length) *output_length = ZSTR_LEN(encoded);
    char *result = estrndup(ZSTR_VAL(encoded), ZSTR_LEN(encoded));
    zend_string_release(encoded);
    return result;
}

unsigned char* kage_base64_decode(const char *data, size_t input_length, size_t *output_length) {
    zend_string *decoded = php_base64_decode((unsigned char*)data, input_length);
    if (!decoded) {
        if (output_length) *output_length = 0;
        return NULL;
    }
    
    if (output_length) *output_length = ZSTR_LEN(decoded);
    unsigned char *result = emalloc(ZSTR_LEN(decoded) + 1);
    memcpy(result, ZSTR_VAL(decoded), ZSTR_LEN(decoded));
    result[ZSTR_LEN(decoded)] = '\0';
    zend_string_release(decoded);
    return result;
}
