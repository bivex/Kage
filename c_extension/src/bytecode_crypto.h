/**
 * Bytecode-level Cryptography for Kage Extension
 * 
 * Шифрование отдельных Zend опкодов для максимальной эффективности
 */

#ifndef PHP_KAGE_BYTECODE_CRYPTO_H
#define PHP_KAGE_BYTECODE_CRYPTO_H

#include "kage_context.h"

// Структура Zend опкода
typedef struct {
    int lineno;           // Номер строки
    unsigned char opcode; // Код операции
    zval op1;            // Первый операнд
    zval op2;            // Второй операнд
    zval result;         // Результат
    uint32_t extended_value; // Расширенное значение
    void *handler;       // Обработчик операции
} zend_op_encrypted;

// Парсер VLD вывода
typedef struct {
    HashTable *functions;  // Хэш-таблица функций
    HashTable *opcodes;    // Хэш-таблица опкодов
    char *source_file;     // Исходный файл
    size_t total_opcodes;  // Общее количество опкодов
} vld_bytecode_info;

// Алгоритмы шифрования опкодов
typedef enum {
    KAGE_OPCODE_ENCRYPT_AES,     // AES шифрование
    KAGE_OPCODE_ENCRYPT_XOR,     // Простое XOR
    KAGE_OPCODE_ENCRYPT_ROTATE,  // Битовый сдвиг
    KAGE_OPCODE_ENCRYPT_CUSTOM   // Кастомный алгоритм
} kage_opcode_crypto_type;

// Конфигурация шифрования опкодов
typedef struct {
    kage_opcode_crypto_type algorithm;
    const char *key;
    size_t key_length;
    bool encrypt_operands;     // Шифровать операнды
    bool encrypt_handlers;     // Шифровать обработчики
    bool selective_encryption; // Выборочное шифрование
} kage_bytecode_crypto_config;

// API функции
PHPAPI vld_bytecode_info* kage_parse_vld_output(const char *vld_output);
PHPAPI kage_result_t kage_encrypt_opcodes(vld_bytecode_info *bytecode, kage_bytecode_crypto_config *config);
PHPAPI kage_result_t kage_decrypt_opcodes(vld_bytecode_info *bytecode, kage_bytecode_crypto_config *config);
PHPAPI void kage_free_bytecode_info(vld_bytecode_info *bytecode);

// Runtime дешифрование
PHPAPI void* kage_get_encrypted_handler(unsigned char opcode, const char *key);
PHPAPI zval* kage_decrypt_operand(zval *operand, const char *key, size_t offset);

// Утилиты
PHPAPI char* kage_serialize_bytecode(vld_bytecode_info *bytecode);
PHPAPI vld_bytecode_info* kage_unserialize_bytecode(const char *serialized);

#endif /* PHP_KAGE_BYTECODE_CRYPTO_H */
