/**
 * Kage Configuration Management & System Security Implementation
 */

#include "kage_config.h"
#include "kage_context.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

static kage_config global_config_instance = { NULL, true };

PHPAPI kage_config* kage_config_get(void) {
    return &global_config_instance;
}

PHPAPI const char* kage_config_get_string(kage_config *config, const char *key) {
    if (!config || !key) return NULL;
    if (strcmp(key, KAGE_CONFIG_ENCRYPTION_KEY) == 0) {
        return getenv("KAGE_ENCRYPTION_KEY");
    }
    return NULL;
}

// Phase 4: Machine Fingerprinting & HWID Detection
PHPAPI char* kage_get_machine_id(void) {
    char buf[256];
    FILE *f = fopen("/etc/machine-id", "r");
    if (f == NULL) {
        f = fopen("/var/lib/dbus/machine-id", "r");
        if (f == NULL) {
            goto fallback_hostname;
        }
    }

    char *read_ptr = fgets(buf, sizeof(buf), f);
    if (read_ptr != NULL) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            buf[len - 1] = '\0';
        }
        fclose(f);
        return estrdup(buf);
    }
    fclose(f);

fallback_hostname:
    if (gethostname(buf, sizeof(buf)) == 0) {
        return estrdup(buf);
    }

    return estrdup("unknown-kage-machine");
}

// IEEE 802.3 CRC32 Implementation
PHPAPI uint32_t kage_crc32(const unsigned char *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}
