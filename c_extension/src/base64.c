/**
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-06-06 21:46
 * Last Updated: 2025-06-07 02:25
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#include "base64.h"

// Base64 algorithm constants
#define KAGE_BASE64_PADDING_CHAR '='
#define KAGE_BASE64_INPUT_GROUP_SIZE 3
#define KAGE_BASE64_OUTPUT_GROUP_SIZE 4
#define KAGE_BASE64_MASK_6BIT 0x3F
#define KAGE_BASE64_MASK_4BIT 0x0F
#define KAGE_BASE64_MASK_2BIT 0x03

char* kage_base64_encode(const unsigned char *input, size_t input_length, size_t *output_length) {
    if (input == NULL) {
        if (output_length != NULL) {
            *output_length = 0;
        }
        return NULL;
    }
    if (output_length == NULL) {
        return NULL;
    }
    static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    // Calculate output length (KAGE_BASE64_OUTPUT_GROUP_SIZE * ceil(input_length / KAGE_BASE64_INPUT_GROUP_SIZE))
    *output_length = KAGE_BASE64_OUTPUT_GROUP_SIZE * ((input_length + KAGE_BASE64_INPUT_GROUP_SIZE - 1) / KAGE_BASE64_INPUT_GROUP_SIZE);
    
    // Allocate memory for output
    char *encoded_data = emalloc(*output_length + 1);  // +1 for null terminator
    if (!encoded_data) {
        *output_length = 0;
        return NULL;
    }
    
    // Encode the input data
    size_t i = 0;
    size_t j = 0;
    unsigned char a = 0;
    unsigned char b = 0;
    unsigned char c = 0;
    
    for (i = 0; i < input_length; i += 3) {
        // Get the next three bytes (or fewer if at the end)
        a = input[i];
        b = (i + 1 < input_length) ? input[i + 1] : 0;
        c = (i + 2 < input_length) ? input[i + 2] : 0;
        
        // Encode these bytes into 4 characters
        encoded_data[j++] = base64_chars[(a >> 2) & 0x3F];
        encoded_data[j++] = base64_chars[((a << 4) & 0x30) | ((b >> 4) & 0x0F)];
        
        if (i + 1 < input_length) {
            encoded_data[j++] = base64_chars[((b << 4) & 0x3C) | ((c >> 6) & KAGE_BASE64_MASK_2BIT)];
        } else {
            encoded_data[j++] = KAGE_BASE64_PADDING_CHAR;  // Padding
        }

        if (i + 2 < input_length) {
            encoded_data[j++] = base64_chars[c & KAGE_BASE64_MASK_6BIT];
        } else {
            encoded_data[j++] = KAGE_BASE64_PADDING_CHAR;  // Padding
        }
        
        if (i + 2 < input_length) {
            encoded_data[j++] = base64_chars[c & 0x3F];
        } else {
            encoded_data[j++] = '=';  // Padding
        }
    }
    
    // Add null terminator
    encoded_data[j] = '\0';
    
    return encoded_data;
}

// Base64 decoding lookup table
static const char BASE64_DECODE_TABLE[] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
};

// Helper function to validate base64 input (single exit)
static int kage_base64_validate_input(const char *data, size_t input_length, size_t *padding) {
    int valid = 1;

    if (!data || input_length == 0) {
        valid = 0;
    } else if (input_length % 4 != 0) {
        valid = 0;
    } else {
        *padding = 0;
        if (data[input_length - 1] == KAGE_BASE64_PADDING_CHAR) {
            (*padding)++;
        }
        if (input_length > 1 && data[input_length - 2] == KAGE_BASE64_PADDING_CHAR) {
            (*padding)++;
        }
    }

    return valid;
}

// Helper function to decode a single base64 character
static int kage_base64_decode_char(char c) {
    // No need to check c >= 128 since char can be negative
    return BASE64_DECODE_TABLE[(unsigned char)c];
}

// Decode quartet when only 3 bytes present (2 padding chars)
static int decode_quartet_padding3(const char *input, unsigned char *output, size_t *output_pos) {
    int b1 = kage_base64_decode_char(input[0]);
    int b2 = kage_base64_decode_char(input[1]);
    if (b1 < 0 || b2 < 0) return 0;
    output[(*output_pos)++] = (b1 << 2) | (b2 >> 4);
    return 1;
}

// Decode quartet when only 2 bytes present (1 padding char)
static int decode_quartet_padding2(const char *input, unsigned char *output, size_t *output_pos) {
    int b1 = kage_base64_decode_char(input[0]);
    int b2 = kage_base64_decode_char(input[1]);
    int b3 = kage_base64_decode_char(input[2]);
    if (b1 < 0 || b2 < 0 || b3 < 0) return 0;
    output[(*output_pos)++] = (b1 << 2) | (b2 >> 4);
    output[(*output_pos)++] = ((b2 & 0x0F) << 4) | (b3 >> 2);
    return 1;
}

// Decode full quartet (no padding)
static int decode_quartet_full(const char *input, unsigned char *output, size_t *output_pos) {
    int b1 = kage_base64_decode_char(input[0]);
    int b2 = kage_base64_decode_char(input[1]);
    int b3 = kage_base64_decode_char(input[2]);
    int b4 = kage_base64_decode_char(input[3]);
    if (b1 < 0 || b2 < 0 || b3 < 0 || b4 < 0) return 0;
    output[(*output_pos)++] = (b1 << 2) | (b2 >> 4);
    output[(*output_pos)++] = ((b2 & 0x0F) << 4) | (b3 >> 2);
    output[(*output_pos)++] = ((b3 & 0x03) << 6) | b4;
    return 1;
}

// Helper function to decode a base64 quartet (delegates to specific handlers)
static int kage_base64_decode_quartet(const char *input, unsigned char *output, size_t *output_pos, int *remaining) {
    int success = 0;

    if (input[2] == KAGE_BASE64_PADDING_CHAR) {
        *remaining = 1;
        success = decode_quartet_padding3(input, output, output_pos);
    } else if (input[3] == KAGE_BASE64_PADDING_CHAR) {
        *remaining = 2;
        success = decode_quartet_padding2(input, output, output_pos);
    } else {
        *remaining = 3;
        success = decode_quartet_full(input, output, output_pos);
    }

    return success;
}

unsigned char* kage_base64_decode(const char *data, size_t input_length, size_t *output_length) {
    if (!data || !output_length) {
        if (output_length) *output_length = 0;
        return NULL;
    }

    // Trim whitespace
    const char *start = data;
    const char *end = data + input_length - 1;

    while (start <= end && (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r')) {
        start++;
    }
    while (end >= start && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
        end--;
    }

    size_t trimmed_length = end - start + 1;
    if (trimmed_length == 0) {
        *output_length = 0;
        return emalloc(1); // Return empty buffer
    }

    // Validate input
    size_t padding = 0;
    if (!kage_base64_validate_input(start, trimmed_length, &padding)) {
        *output_length = 0;
        return NULL;
    }

    // Calculate output size
    *output_length = (trimmed_length / 4) * 3 - padding;

    // Allocate output buffer
    unsigned char *decoded_data = emalloc(*output_length + 1);
    if (!decoded_data) {
        *output_length = 0;
        return NULL;
    }

    // Decode in quartets
    size_t output_pos = 0;
    for (size_t i = 0; i < trimmed_length; i += 4) {
        int remaining = 0;
        if (!kage_base64_decode_quartet(start + i, decoded_data, &output_pos, &remaining)) {
            efree(decoded_data);
            *output_length = 0;
            return NULL;
        }

        if (remaining < 3) {
            break; // Reached padding
        }
    }

    // Null terminate
    decoded_data[*output_length] = '\0';
    return decoded_data;
} 