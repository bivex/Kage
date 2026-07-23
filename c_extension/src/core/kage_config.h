/**
 * Kage Configuration Management & System Security Headers
 */

#ifndef PHP_KAGE_CONFIG_H
#define PHP_KAGE_CONFIG_H

#include "config.h"
#include "kage_context.h"
#include <stdbool.h>

#define KAGE_CONFIG_ENCRYPTION_KEY "encryption_key"

typedef struct kage_config {
    HashTable *entries;
    bool initialized;
} kage_config;

// Global configuration accessor
PHPAPI kage_config* kage_config_get(void);
PHPAPI const char* kage_config_get_string(kage_config *config, const char *key);

// Machine Fingerprinting & Security Check API
PHPAPI char* kage_get_machine_id(void);
PHPAPI uint32_t kage_crc32(const unsigned char *data, size_t len);

#endif /* PHP_KAGE_CONFIG_H */
