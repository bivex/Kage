/**
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-06-06 21:46
 * Last Updated: 2025-06-07 02:32
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#ifndef PHP_KAGE_BASE64_H
#define PHP_KAGE_BASE64_H

#include "config.h"

/**
 * Custom Base64 encoding function
 * @param input Input data to encode
 * @param input_length Length of input data
 * @param output_length Pointer to store output length
 * @return Base64 encoded string or NULL on failure
 */
char* kage_base64_encode(const unsigned char *input, size_t input_length, size_t *output_length);

/**
 * Custom Base64 decoding function
 * @param data Base64 encoded input string
 * @param input_length Length of input string
 * @param output_length Pointer to store output length
 * @return Decoded data or NULL on failure
 */
unsigned char* kage_base64_decode(const char *data, size_t input_length, size_t *output_length);

#endif /* PHP_KAGE_BASE64_H */ 