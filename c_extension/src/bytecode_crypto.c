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
    zend_hash_init(info->functions, 8, NULL, NULL, 0);
    zend_hash_init(info->opcodes, 64, NULL, NULL, 0);
    
    // Парсим VLD вывод построчно
    char *output_copy = estrndup(vld_output, strlen(vld_output));
    char *line = strtok(output_copy, "\n");
    zend_op_array *current_op_array = NULL;
    
    while (line) {
        // Парсим строку таблицы опкодов
        // Формат: line #* E I O op fetch ext return operands
        if (sscanf(line, "%d %d %*s %*s %*s %s", &lineno, &op_num, opcode_str) == 3) {
            // Создаём зашифрованный опкод
            zend_op_encrypted *op = emalloc(sizeof(zend_op_encrypted));
            memset(op, 0, sizeof(zend_op_encrypted));
            
            op->lineno = lineno;
            op->opcode = zend_get_opcode_by_name(opcode_str);
            
            // Парсим операнды (упрощённо)
            // В реальности нужно более сложный парсер
            
            // Сохраняем опкод
            zend_hash_index_add_ptr(info->opcodes, op_num, op);
            info->total_opcodes++;
        }
        
        // Ищем начало функции
        if (strstr(line, "Function ") && strstr(line, ":")) {
            char func_name[256];
            if (sscanf(line, "Function %255[^:]", func_name) == 1) {
                // Создаём новый op_array для функции
                current_op_array = emalloc(sizeof(zend_op_array));
                memset(current_op_array, 0, sizeof(zend_op_array));
                zend_hash_str_add_ptr(info->functions, func_name, strlen(func_name), current_op_array);
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
    ZEND_HASH_FOREACH_PTR(bytecode->opcodes, op) {
        if (config->selective_encryption) {
            // Выборочное шифрование - шифруем только определённые опкоды
            if (op->opcode == ZEND_ECHO || op->opcode == ZEND_ASSIGN) {
                // Пропускаем часто используемые опкоды для производительности
                continue;
            }
        }
        
        switch (config->algorithm) {
            case KAGE_OPCODE_ENCRYPT_XOR:
                kage_xor_encrypt_op(op, config->key, config->key_length);
                break;
                
            case KAGE_OPCODE_ENCRYPT_AES:
                kage_aes_encrypt_op(op, config->key, config->key_length);
                break;
                
            case KAGE_OPCODE_ENCRYPT_ROTATE:
                // Битовый сдвиг
                op->opcode = (op->opcode << 3) | (op->opcode >> 5);
                break;
                
            case KAGE_OPCODE_ENCRYPT_CUSTOM:
                // Кастомный алгоритм
                // Можно реализовать более сложную логику
                break;
        }
    } ZEND_HASH_FOREACH_END();
    
    return result;
}

// Дешифрование опкодов
PHPAPI kage_result_t kage_decrypt_opcodes(vld_bytecode_info *bytecode, kage_bytecode_crypto_config *config) {
    // Для симметричных алгоритмов шифрование/дешифрование одинаково
    return kage_encrypt_opcodes(bytecode, config);
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
