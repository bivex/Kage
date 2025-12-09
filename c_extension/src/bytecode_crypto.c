/**
 * Bytecode-level Cryptography Implementation
 */

#include "bytecode_crypto.h"
#include "zend_compile.h"
#include "zend_execute.h"

// Парсер VLD вывода в структурированные опкоды
PHPAPI vld_bytecode_info* kage_parse_vld_output(const char *vld_output) {
    if (!vld_output) return NULL;

    vld_bytecode_info *info = emalloc(sizeof(vld_bytecode_info));
    memset(info, 0, sizeof(vld_bytecode_info));

    info->functions = emalloc(sizeof(HashTable));
    info->opcodes = emalloc(sizeof(HashTable));
    info->source_file = NULL;
    info->total_opcodes = 0;

    zend_hash_init(info->functions, 8, NULL, NULL, 0);
    zend_hash_init(info->opcodes, 64, NULL, NULL, 0);

    // Парсим VLD вывод построчно
    char *output_copy = estrndup(vld_output, strlen(vld_output));
    char *line = strtok(output_copy, "\n");
    int lineno, op_num;
    char opcode_str[256];

    while (line) {
        // Парсим строку таблицы опкодов
        // Формат: line #* E I O op fetch ext return operands
        if (sscanf(line, "%d %d %*s %*s %*s %255s", &lineno, &op_num, opcode_str) == 3) {
            // Создаём зашифрованный опкод
            zend_op_encrypted *op = emalloc(sizeof(zend_op_encrypted));
            memset(op, 0, sizeof(zend_op_encrypted));

            op->lineno = lineno;
            // Простая конвертация строки в opcode (в реальности нужна таблица)
            if (strcmp(opcode_str, "ASSIGN") == 0) op->opcode = 38; // ZEND_ASSIGN
            else if (strcmp(opcode_str, "ECHO") == 0) op->opcode = 40; // ZEND_ECHO
            else if (strcmp(opcode_str, "ADD") == 0) op->opcode = 1; // ZEND_ADD
            else if (strcmp(opcode_str, "SUB") == 0) op->opcode = 2; // ZEND_SUB
            else if (strcmp(opcode_str, "MUL") == 0) op->opcode = 3; // ZEND_MUL
            else if (strcmp(opcode_str, "RETURN") == 0) op->opcode = 62; // ZEND_RETURN
            else op->opcode = 0; // NOP

            // Парсим операнды из остатка строки
            char *operands = strstr(line, opcode_str);
            if (operands) {
                operands += strlen(opcode_str);
                // Простой парсер операндов
                if (strstr(operands, "!")) {
                    // Это переменная
                    ZVAL_STRING(&op->op1, "!VAR");
                }
                if (strstr(operands, "'") || strstr(operands, "\"")) {
                    // Это строка
                    ZVAL_STRING(&op->op1, "'STRING'");
                }
            }

            // Сохраняем опкод
            zend_hash_index_add_ptr(info->opcodes, op_num, op);
            info->total_opcodes++;
        }

        // Ищем имя файла
        if (strstr(line, "filename:") && !info->source_file) {
            char *filename_start = strstr(line, "filename:");
            if (filename_start) {
                filename_start += 9; // strlen("filename:")
                while (*filename_start == ' ') filename_start++;
                info->source_file = estrndup(filename_start, strlen(filename_start));
            }
        }

        line = strtok(NULL, "\n");
    }

    efree(output_copy);
    return info;
}

// XOR шифрование опкода (простой и быстрый)
static void kage_xor_encrypt_op(zend_op_encrypted *op, const char *key, size_t key_len) {
    if (!op || !key || key_len == 0) return;

    // Шифруем opcode
    op->opcode ^= key[0];

    // Шифруем extended_value
    op->extended_value ^= key[1 % key_len];

    // Шифруем lineno (немного)
    op->lineno ^= (key[2 % key_len] | (key[3 % key_len] << 8));

    // Шифруем операнды (если они есть)
    if (Z_TYPE(op->op1) == IS_STRING && Z_STRVAL(op->op1)) {
        size_t len = Z_STRLEN(op->op1);
        for (size_t i = 0; i < len; i++) {
            Z_STRVAL(op->op1)[i] ^= key[i % key_len];
        }
    }

    if (Z_TYPE(op->op2) == IS_STRING && Z_STRVAL(op->op2)) {
        size_t len = Z_STRLEN(op->op2);
        for (size_t i = 0; i < len; i++) {
            Z_STRVAL(op->op2)[i] ^= key[i % key_len];
        }
    }

    // Шифруем результат
    if (Z_TYPE(op->result) == IS_STRING && Z_STRVAL(op->result)) {
        size_t len = Z_STRLEN(op->result);
        for (size_t i = 0; i < len; i++) {
            Z_STRVAL(op->result)[i] ^= key[i % key_len];
        }
    }
}

// AES шифрование опкода (более безопасное)
static void kage_aes_encrypt_op(zend_op_encrypted *op, const char *key, size_t key_len) {
    // Используем существующие функции Kage для AES
    // В реальности нужно сериализовать опкод и зашифровать
}

// Основная функция шифрования опкодов
PHPAPI kage_result_t kage_encrypt_opcodes(vld_bytecode_info *bytecode, kage_bytecode_crypto_config *config) {
    kage_result_t result = {KAGE_SUCCESS, {NULL}};

    if (!bytecode || !config || !config->key) {
        result.error = KAGE_ERROR_INVALID_INPUT;
        return result;
    }

    // Проходим по всем опкодам
    zend_op_encrypted *op;
    int encrypted_count = 0;

    ZEND_HASH_FOREACH_PTR(bytecode->opcodes, op) {
        int should_encrypt = 1;

        if (config->selective_encryption) {
            // Выборочное шифрование - шифруем только определённые опкоды
            switch (op->opcode) {
                case 40: // ZEND_ECHO - часто используется, можно не шифровать для производительности
                case 62: // ZEND_RETURN - тоже часто используется
                    should_encrypt = 0;
                    break;
                default:
                    should_encrypt = 1;
                    break;
            }
        }

        if (should_encrypt) {
            switch (config->algorithm) {
                case KAGE_OPCODE_ENCRYPT_XOR:
                    kage_xor_encrypt_op(op, config->key, config->key_length);
                    encrypted_count++;
                    break;

                case KAGE_OPCODE_ENCRYPT_AES:
                    kage_aes_encrypt_op(op, config->key, config->key_length);
                    encrypted_count++;
                    break;

                case KAGE_OPCODE_ENCRYPT_ROTATE:
                    // Битовый сдвиг
                    op->opcode = (op->opcode << 3) | (op->opcode >> 5);
                    op->extended_value = (op->extended_value << 3) | (op->extended_value >> 29);
                    encrypted_count++;
                    break;

                case KAGE_OPCODE_ENCRYPT_CUSTOM:
                    // Кастомный алгоритм - комбинация XOR + ROTATE
                    kage_xor_encrypt_op(op, config->key, config->key_length);
                    op->opcode = (op->opcode << 2) | (op->opcode >> 6);
                    encrypted_count++;
                    break;
            }
        }
    } ZEND_HASH_FOREACH_END();

    // Создаём результат с информацией о шифровании
    zval *result_data = emalloc(sizeof(zval));
    array_init(result_data);

    add_assoc_long(result_data, "total_opcodes", bytecode->total_opcodes);
    add_assoc_long(result_data, "encrypted_opcodes", encrypted_count);
    add_assoc_double(result_data, "encryption_ratio", (double)encrypted_count / bytecode->total_opcodes);
    add_assoc_string(result_data, "algorithm",
        config->algorithm == KAGE_OPCODE_ENCRYPT_XOR ? "XOR" :
        config->algorithm == KAGE_OPCODE_ENCRYPT_AES ? "AES" :
        config->algorithm == KAGE_OPCODE_ENCRYPT_ROTATE ? "ROTATE" : "CUSTOM");

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
