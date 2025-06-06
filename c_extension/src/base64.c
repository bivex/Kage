/**
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-06-06 21:46
 * Last Updated: 2025-06-07 02:25
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#include "base64.h"

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
    
    // Calculate output length (4 * ceil(n/3))
    *output_length = 4 * ((input_length + 2) / 3);
    
    // Allocate memory for output
    char *encoded_data = emalloc(*output_length + 1);  // +1 for null terminator
    if (!encoded_data) {
        *output_length = 0;
        return NULL;
    }
    
    // Encode the input data
    size_t i = 0;
    size_t j = 0;
    unsigned char a;
    unsigned char b;
    unsigned char c;
    
    for (i = 0; i < input_length; i += 3) {
        // Get the next three bytes (or fewer if at the end)
        a = input[i];
        b = (i + 1 < input_length) ? input[i + 1] : 0;
        c = (i + 2 < input_length) ? input[i + 2] : 0;
        
        // Encode these bytes into 4 characters
        encoded_data[j++] = base64_chars[(a >> 2) & 0x3F];
        encoded_data[j++] = base64_chars[((a << 4) & 0x30) | ((b >> 4) & 0x0F)];
        
        if (i + 1 < input_length) {
            encoded_data[j++] = base64_chars[((b << 2) & 0x3C) | ((c >> 6) & 0x03)];
        } else {
            encoded_data[j++] = '=';  // Padding
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

unsigned char* kage_base64_decode(const char *data, size_t input_length, size_t *output_length) {
    if (data == NULL) {
        if (output_length != NULL) {
            *output_length = 0;
        }
        return NULL;
    }
    if (output_length == NULL) {
        return NULL;
    }
    static const char T[] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };

    *output_length = 0;
    
    // Skip any leading whitespace
    while (input_length > 0 && (*data == ' ' || *data == '\t' || *data == '\n' || *data == '\r')) {
        data++;
        input_length--;
    }
    
    // Skip any trailing whitespace
    while (input_length > 0 && (data[input_length - 1] == ' ' || data[input_length - 1] == '\t' || 
           data[input_length - 1] == '\n' || data[input_length - 1] == '\r')) {
        input_length--;
    }
    
    if (input_length % 4 != 0) {
        return NULL;
    }

    size_t padding = 0;
    if (input_length > 0) {
        if (data[input_length - 1] == '=') {
            padding++;
        }
        if ((input_length > 1) && (data[input_length - 2] == '=')) {
            padding++;
        }
    }
    
    *output_length = (input_length / 4) * 3 - padding;
    
    unsigned char *decoded_data = emalloc(*output_length + 1);
    if (decoded_data == NULL) {
        return NULL;
    }

    uint32_t i_val = 0;
    uint32_t j_val = 0;
    for (i_val = 0; i_val < input_length; i_val += 4) {
        int v = 0;
        int k;
        
        // Skip any whitespace between groups
        while ((i_val < input_length) && ((data[i_val] == ' ') || (data[i_val] == '\t') || (data[i_val] == '\n') || (data[i_val] == '\r'))) {
            i_val++;
        }
        if (i_val >= input_length) {
            break;
        }
        
        k = data[i_val]; 
        if ((k < 0) || (k >= 128) || (v = T[k]) < 0) {
            efree(decoded_data); 
            return NULL;
        }
        uint32_t b1 = (uint32_t)v;

        k = data[i_val+1]; 
        if ((k < 0) || (k >= 128) || (v = T[k]) < 0) {
            efree(decoded_data); 
            return NULL;
        }
        uint32_t b2 = (uint32_t)v;
        
        decoded_data[j_val++] = (b1 << 2) | (b2 >> 4);
        
        if (data[i_val+2] == '=') {
            break;
        }
        k = data[i_val+2];
        if ((k < 0) || (k >= 128) || (v = T[k]) < 0) {
            efree(decoded_data); 
            return NULL;
        }
        uint32_t b3 = (uint32_t)v;
        
        decoded_data[j_val++] = ((b2 & 0x0F) << 4) | (b3 >> 2);

        if (data[i_val+3] == '=') {
            break;
        }
        k = data[i_val+3];
        if ((k < 0) || (k >= 128) || (v = T[k]) < 0) {
            efree(decoded_data); 
            return NULL;
        }
        uint32_t b4 = (uint32_t)v;
        
        decoded_data[j_val++] = ((b3 & 0x03) << 6) | b4;
    }

    decoded_data[*output_length] = '\0';
    return decoded_data;
} 