# Зашифрованные Self-Decrypting PHP Файлы

## Front Matter

**Название документа:** Руководство пользователя: Зашифрованные Self-Decrypting PHP Файлы с Kage Bytecode Encryption

**Версия:** 1.0

**Дата:** 2025-01-15

**Автор:** Kage Development Team

**Copyright:** © 2025 Kage Project. Все права защищены.

**Целевая аудитория:** Разработчики PHP, системные администраторы, специалисты по безопасности.

**Предполагаемое использование:** Это руководство предназначено для помощи пользователям в создании и использовании зашифрованных self-decrypting PHP файлов с помощью системы Kage bytecode encryption.

## Table of Contents

1. [Introduction](#introduction)
2. [Concept of Operations](#concept-of-operations)
3. [Procedures](#procedures)
4. [Information for Uninstallation](#information-for-uninstallation)
5. [Glossary](#glossary)
6. [Index](#index)

## Introduction

### Purpose

Это руководство описывает использование системы Kage для создания зашифрованных self-decrypting PHP файлов. Документация предоставляет полную информацию о концепции, процедурах и лучших практиках для защиты PHP кода на уровне байткода.

### Scope

Руководство охватывает:
- Создание зашифрованных файлов
- Управление ключами шифрования
- Тестирование функциональности
- Меры безопасности

### Audience Analysis

**Основная аудитория:** Разработчики PHP с опытом работы с расширениями PHP и шифрованием.

**Предполагаемые знания:**
- Основы PHP программирования
- Понимание концепций шифрования
- Знание командной строки Linux/Unix

**Цели пользователей:**
- Создавать защищенные PHP файлы
- Обеспечивать конфиденциальность исходного кода
- Интегрировать шифрование в существующие проекты

### Conventions Used

- **Жирный текст:** Важные термины при первом упоминании
- `Моноширинный шрифт:` Команды, код, пути к файлам
- ⚠️ Предупреждения о безопасности
- ✅ Рекомендуемые действия

## Concept of Operations

### Overview

Система Kage предоставляет возможность шифрования PHP кода на уровне байткода Zend VM, а не на уровне текста. Это обеспечивает более высокий уровень защиты по сравнению с традиционными методами шифрования.

### Operational Context

**Входные данные:**
- PHP исходный код для шифрования
- Ключ шифрования (32 байта)

**Выходные данные:**
- Self-decrypting PHP файл
- Зашифрованные данные в формате base64

**Процесс работы:**
1. Компиляция PHP кода в Zend опкоды
2. Шифрование опкодов выбранным алгоритмом
3. Сериализация зашифрованных данных
4. Создание PHP файла с кодом расшифровки

### Key Features

- **Bytecode-level encryption:** Шифрование на уровне Zend VM опкодов
- **Self-decrypting files:** Файлы сами расшифровываются при выполнении
- **Multiple algorithms:** Поддержка XOR, AES, ROTATE алгоритмов
- **Runtime decryption:** Расшифровка без хранения ключей в памяти

### Security Model

- **Конфиденциальность:** Исходный код полностью скрыт
- **Целостность:** Проверка целостности зашифрованных данных
- **Аутентификация:** Проверка ключей шифрования

## Procedures

### Prerequisites

1. **Установленное расширение Kage**
   ```bash
   # Проверьте наличие расширения
   php -m | grep kage
   ```

2. **PHP 7.4+ с поддержкой расширения**
3. **Ключ шифрования длиной 32 байта**

### Creating Encrypted Files

#### Procedure 1: Using the Creation Script

1. Перейдите в каталог проекта:
   ```bash
   cd /path/to/kage
   ```

2. Запустите скрипт создания:
   ```bash
   php create_encrypted_file.php
   ```

3. Проверьте созданный файл:
   ```bash
   ls -la generated_encrypted_file.php
   ```

#### Procedure 2: Manual Creation

1. Подготовьте PHP код для шифрования:
   ```php
   $secret_code = '<?php echo "Secret data"; ?>';
   ```

2. Выполните шифрование:
   ```php
   $key = '0123456789abcdef0123456789abcdef';
   $encrypted = kage_encrypt_c($secret_code, $key);
   ```

3. Создайте self-decrypting файл:
   ```php
   $encrypted_file = '<?php
   $encrypted_data = "' . $encrypted . '";
   $key = "' . $key . '";
   $decrypted = kage_decrypt_c($encrypted_data, $key);
   eval(trim($decrypted));
   ?>';
   file_put_contents('my_encrypted_file.php', $encrypted_file);
   ```

### Executing Encrypted Files

#### Basic Execution

1. Убедитесь, что расширение Kage загружено
2. Запустите файл:
   ```bash
   php my_encrypted_file.php
   ```

#### Troubleshooting

- **Ошибка "Kage extension not loaded":**
  - Проверьте конфигурацию PHP
  - Перезапустите веб-сервер

- **Ошибка "Invalid key length":**
  - Убедитесь, что ключ ровно 32 байта

### Testing Functionality

1. Запустите unit-тесты:
   ```bash
   php tests/test_bytecode_encryption.php
   ```

2. Выполните интеграционные тесты:
   ```bash
   php tests/test_integration.php
   ```

## Information for Uninstallation

### Removing Encrypted Files

Поскольку зашифрованные файлы являются обычными PHP файлами, их удаление производится стандартными методами:

```bash
rm encrypted_file.php
```

### Key Management

⚠️ **Важно:** При удалении зашифрованных файлов также удаляйте соответствующие ключи шифрования.

### System Cleanup

Если расширение Kage больше не требуется:

1. Удалите расширение из конфигурации PHP
2. Перезапустите веб-сервер
3. Удалите все зашифрованные файлы

## Glossary

**Bytecode:** Компилированный код, исполняемый виртуальной машиной Zend VM.

**Kage:** Система шифрования PHP кода на уровне байткода.

**Opcode:** Единица инструкции в bytecode.

**Self-decrypting file:** Файл, который содержит зашифрованные данные и код для их расшифровки.

**Zend VM:** Виртуальная машина PHP, исполняющая bytecode.

## Index

A
- Algorithms, 1.3.4, 2.4
- Audience, 1.3

B
- Bytecode, 2.1, 2.2, Glossary
- Bytecode encryption, 1.1, 2.4

C
- Concept of operations, 2
- Creating encrypted files, 3.2

E
- Encrypted files, 3.2, 3.3
- Executing files, 3.3

G
- Glossary, 5

I
- Index, 6
- Installation, Prerequisites in 3.1

K
- Key management, 4.2
- Kage extension, 3.1, 3.3

P
- PHP code, 2.2, 3.2
- Prerequisites, 3.1
- Procedures, 3

S
- Security, 2.5
- Self-decrypting, 1.1, 2.3, Glossary

T
- Testing, 3.4
- Troubleshooting, 3.3

U
- Uninstallation, 4
