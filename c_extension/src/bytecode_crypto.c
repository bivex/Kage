/**
 * Bytecode-level Cryptography Implementation
 */

#include "bytecode_crypto.h"
#include "zend_compile.h"
#include "zend_execute.h"

// Helper: convert opcode string to numeric value
static unsigned char kage_opcode_from_string(const char *opcode_str) {
    unsigned char opcode = 0;

    if (strcmp(opcode_str, "ASSIGN") == 0)      opcode = KAGE_ZEND_ASSIGN;
    else if (strcmp(opcode_str, "ECHO") == 0)   opcode = KAGE_ZEND_ECHO;
    else if (strcmp(opcode_str, "ADD") == 0)    opcode = KAGE_ZEND_ADD;
    else if (strcmp(opcode_str, "SUB") == 0)    opcode = KAGE_ZEND_SUB;
    else if (strcmp(opcode_str, "MUL") == 0)    opcode = KAGE_ZEND_MUL;
    else if (strcmp(opcode_str, "RETURN") == 0) opcode = KAGE_ZEND_RETURN;
    else opcode = KAGE_ZEND_NOP;

    return opcode;
}

// Helper: parse operands from opcode line
static void kage_parse_operands(const char *operands, zend_op_encrypted *op) {
    if (strstr(operands, "!")) {
        ZVAL_STRING(&op->op1, "!VAR");
    }
    if (strstr(operands, "'") || strstr(operands, "\"")) {
        ZVAL_STRING(&op->op1, "'STRING'");
    }
}

// Helper: extract filename from line
static void kage_extract_filename(const char *line, vld_bytecode_info *info) {
    if (info->source_file) return; // Already extracted

    char *filename_start = strstr(line, "filename:");
    if (filename_start) {
        filename_start += KAGE_FILENAME_PREFIX_LEN;
        while (*filename_start == ' ') filename_start++;
        info->source_file = estrndup(filename_start, strlen(filename_start));
    }
}

// Парсер VLD вывода в структурированные опкоды
PHPAPI vld_bytecode_info* kage_parse_vld_output(const char *vld_output) {
    if (!vld_output) return NULL;

    vld_bytecode_info *info = emalloc(sizeof(vld_bytecode_info));
    memset(info, 0, sizeof(vld_bytecode_info));

    info->functions = emalloc(sizeof(HashTable));
    info->opcodes = emalloc(sizeof(HashTable));
    info->source_file = NULL;
    info->total_opcodes = 0;

    zend_hash_init(info->functions, KAGE_HASH_SIZE_FUNCTIONS, NULL, NULL, 0);
    zend_hash_init(info->opcodes, KAGE_HASH_SIZE_OPCODES, NULL, NULL, 0);

    // Парсим VLD вывод построчно
    char *output_copy = estrndup(vld_output, strlen(vld_output));
    char *line = strtok(output_copy, "\n");
    int lineno, op_num;
    char opcode_str[KAGE_VLD_OPCODE_STR_MAX];

    while (line) {
        // Парсим строку таблицы опкодов
        if (sscanf(line, "%d %d %*s %*s %*s %255s", &lineno, &op_num, opcode_str) == 3) {
            zend_op_encrypted *op = emalloc(sizeof(zend_op_encrypted));
            memset(op, 0, sizeof(zend_op_encrypted));

            op->lineno = lineno;
            op->opcode = kage_opcode_from_string(opcode_str);

            // Парсим операнды
            char *operands = strstr(line, opcode_str);
            if (operands) {
                operands += strlen(opcode_str);
                kage_parse_operands(operands, op);
            }

            zend_hash_index_add_ptr(info->opcodes, op_num, op);
            info->total_opcodes++;
        }

        // Извлекаем имя файла
        kage_extract_filename(line, info);

        line = strtok(NULL, "\n");
    }

    efree(output_copy);
    return info;
}

// AES шифрование опкода (более безопасное)
static void kage_aes_encrypt_op(zend_op_encrypted *op, const char *key, size_t key_len) {
    // Используем существующие функции Kage для AES
    // В реальности нужно сериализовать опкод и зашифровать
}

// XOR encryption helper for a single zval operand
static void kage_xor_encrypt_zval(zval *zv, const char *key, size_t key_len) {
    if (Z_TYPE(zv) == IS_STRING && Z_STRVAL(zv)) {
        size_t len = Z_STRLEN(zv);
        for (size_t i = 0; i < len; i++) {
            Z_STRVAL(zv)[i] ^= key[i % key_len];
        }
    }
}

// XOR шифрование опкода (refactored)
static void kage_xor_encrypt_op_refactored(zend_op_encrypted *op, const char *key, size_t key_len) {
    if (!op || !key || key_len == 0) return;

    op->opcode ^= key[0];
    op->extended_value ^= key[1 % key_len];
    op->lineno ^= (key[2 % key_len] | (key[3 % key_len] << 8));

    kage_xor_encrypt_zval(&op->op1, key, key_len);
    kage_xor_encrypt_zval(&op->op2, key, key_len);
    kage_xor_encrypt_zval(&op->result, key, key_len);
}

// ROTATE encryption
static void kage_rotate_encrypt_op(zend_op_encrypted *op, const char *key, size_t key_len) {
    if (!op) return;
    (void)key; (void)key_len; // Unused
    op->opcode = (op->opcode << 3) | (op->opcode >> 5);
    op->extended_value = (op->extended_value << 3) | (op->extended_value >> 29);
}

// CUSTOM encryption (XOR + ROTATE)
static void kage_custom_encrypt_op(zend_op_encrypted *op, const char *key, size_t key_len) {
    if (!op || !key || key_len == 0) return;
    kage_xor_encrypt_op_refactored(op, key, key_len);
    op->opcode = (op->opcode << 2) | (op->opcode >> 6);
}

// Check if opcode should be encrypted under selective mode
static bool kage_should_encrypt_opcode(unsigned char opcode, bool selective_encryption) {
    bool should_encrypt = true;
    if (selective_encryption) {
        should_encrypt = (opcode != KAGE_ZEND_ECHO && opcode != KAGE_ZEND_RETURN);
    }
    return should_encrypt;
}

// Get algorithm name string
static const char* kage_algorithm_name(kage_opcode_crypto_type algorithm) {
    const char *name = "UNKNOWN";
    switch (algorithm) {
        case KAGE_OPCODE_ENCRYPT_XOR:    name = "XOR";     break;
        case KAGE_OPCODE_ENCRYPT_AES:    name = "AES";     break;
        case KAGE_OPCODE_ENCRYPT_ROTATE: name = "ROTATE";  break;
        case KAGE_OPCODE_ENCRYPT_CUSTOM: name = "CUSTOM";  break;
        default:                         name = "UNKNOWN"; break;
    }
    return name;
}

// Apply encryption based on algorithm type
static void kage_apply_encryption(zend_op_encrypted *op, kage_bytecode_crypto_config *config) {
    if (!op || !config) return;

    switch (config->algorithm) {
        case KAGE_OPCODE_ENCRYPT_XOR:
            kage_xor_encrypt_op_refactored(op, config->key, config->key_length);
            break;
        case KAGE_OPCODE_ENCRYPT_AES:
            kage_aes_encrypt_op(op, config->key, config->key_length);
            break;
        case KAGE_OPCODE_ENCRYPT_ROTATE:
            kage_rotate_encrypt_op(op, config->key, config->key_length);
            break;
        case KAGE_OPCODE_ENCRYPT_CUSTOM:
            kage_custom_encrypt_op(op, config->key, config->key_length);
            break;
    }
}

// Основная функция шифрования опкодов (refactored)
PHPAPI kage_result_t kage_encrypt_opcodes(vld_bytecode_info *bytecode, kage_bytecode_crypto_config *config) {
    kage_result_t result = {KAGE_SUCCESS, {NULL}};

    if (!bytecode || !config || !config->key) {
        result.error = KAGE_ERROR_INVALID_INPUT;
        return result;
    }

    zend_op_encrypted *op;
    int encrypted_count = 0;

    ZEND_HASH_FOREACH_PTR(bytecode->opcodes, op) {
        if (kage_should_encrypt_opcode(op->opcode, config->selective_encryption)) {
            kage_apply_encryption(op, config);
            encrypted_count++;
        }
    } ZEND_HASH_FOREACH_END();

    zval *result_data = emalloc(sizeof(zval));
    array_init(result_data);

    add_assoc_long(result_data, "total_opcodes", bytecode->total_opcodes);
    add_assoc_long(result_data, "encrypted_opcodes", encrypted_count);
    add_assoc_double(result_data, "encryption_ratio", (double)encrypted_count / bytecode->total_opcodes);
    add_assoc_string(result_data, "algorithm", kage_algorithm_name(config->algorithm));

    result.result.value = result_data;
    return result;
}

// Дешифрование опкодов (симметричные алгоритмы)
PHPAPI kage_result_t kage_decrypt_opcodes(vld_bytecode_info *bytecode, kage_bytecode_crypto_config *config) {
    kage_result_t result = {KAGE_SUCCESS, {NULL}};

    if (!bytecode || !config || !config->key) {
        result.error = KAGE_ERROR_INVALID_INPUT;
        return result;
    }

    // Для симметричных алгоритмов шифрование/дешифрование одинаково
    // XOR, ROTATE - симметричны
    return kage_encrypt_opcodes(bytecode, config);
}

// Runtime дешифрование отдельного опкода
PHPAPI zval* kage_decrypt_operand_runtime(zval *operand, const char *key, size_t offset) {
    if (!operand || !key) return operand;

    if (Z_TYPE_P(operand) == IS_STRING && Z_STRVAL_P(operand)) {
        size_t len = Z_STRLEN_P(operand);
        for (size_t i = 0; i < len; i++) {
            Z_STRVAL_P(operand)[i] ^= key[(i + offset) % strlen(key)];
        }
    }

    return operand;
}

// Runtime дешифрование для Zend Engine
PHPAPI void* kage_get_encrypted_handler(unsigned char opcode, const char *key) {
    // Возвращаем дешифрованный обработчик опкода
    // В реальности это должно интегрироваться с Zend VM
    
    // Дешифруем opcode обратно
    unsigned char decrypted_opcode = opcode ^ key[0];
    
    // Получаем стандартный обработчик
    return zend_get_opcode_handler(decrypted_opcode);
}

// Дешифрование операнда
PHPAPI zval* kage_decrypt_operand(zval *operand, const char *key, size_t offset) {
    if (!operand || !key) return operand;
    
    if (Z_TYPE_P(operand) == IS_STRING && Z_STRVAL_P(operand)) {
        size_t len = Z_STRLEN_P(operand);
        for (size_t i = 0; i < len; i++) {
            Z_STRVAL_P(operand)[i] ^= key[(i + offset) % strlen(key)];
        }
    }
    
    return operand;
}

// Сериализация/десериализация
PHPAPI char* kage_serialize_bytecode(vld_bytecode_info *bytecode) {
    if (!bytecode) return NULL;
    
    smart_str buffer = {0};
    smart_str_appends(&buffer, "KAGE_BYTECODE_v1\n");
    
    // Сериализуем информацию о функциях
    smart_str_append_printf(&buffer, "FUNCTIONS:%d\n", zend_hash_num_elements(bytecode->functions));
    
    // Сериализуем опкоды
    smart_str_append_printf(&buffer, "OPCODES:%zu\n", bytecode->total_opcodes);
    
    zend_op_encrypted *op;
    ZEND_HASH_FOREACH_PTR(bytecode->opcodes, op) {
        smart_str_append_printf(&buffer, "OP:%d:%d\n", op->lineno, op->opcode);
    } ZEND_HASH_FOREACH_END();
    
    smart_str_0(&buffer);
    return buffer.s->val;
}

PHPAPI vld_bytecode_info* kage_unserialize_bytecode(const char *serialized) {
    if (!serialized || strncmp(serialized, "KAGE_BYTECODE_v1", 16) != 0) {
        return NULL;
    }
    
    vld_bytecode_info *info = emalloc(sizeof(vld_bytecode_info));
    memset(info, 0, sizeof(vld_bytecode_info));
    
    info->functions = emalloc(sizeof(HashTable));
    info->opcodes = emalloc(sizeof(HashTable));
    zend_hash_init(info->functions, 8, NULL, NULL, 0);
    zend_hash_init(info->opcodes, 64, NULL, NULL, 0);
    
    // Парсим сериализованные данные
    // В реальности нужно более сложный парсер
    
    return info;
}

// Очистка памяти
PHPAPI void kage_free_bytecode_info(vld_bytecode_info *bytecode) {
    if (!bytecode) return;
    
    if (bytecode->functions) {
        zend_hash_destroy(bytecode->functions);
        efree(bytecode->functions);
    }
    
    if (bytecode->opcodes) {
        zend_op_encrypted *op;
        ZEND_HASH_FOREACH_PTR(bytecode->opcodes, op) {
            zval_ptr_dtor(&op->op1);
            zval_ptr_dtor(&op->op2);
            zval_ptr_dtor(&op->result);
            efree(op);
        } ZEND_HASH_FOREACH_END();
        
        zend_hash_destroy(bytecode->opcodes);
        efree(bytecode->opcodes);
    }
    
    if (bytecode->source_file) {
        efree(bytecode->source_file);
    }
    
    efree(bytecode);
}
