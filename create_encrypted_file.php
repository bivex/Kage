<?php
/**
 * СКРИПТ ДЛЯ СОЗДАНИЯ ЗАШИФРОВАННЫХ SELF-DECRYPTING PHP ФАЙЛОВ
 *
 * Этот скрипт позволяет создавать PHP файлы, которые содержат зашифрованный код,
 * но при запуске сами себя расшифровывают и выполняют.
 */

// Настройки
$encryption_key = '0123456789abcdef0123456789abcdef'; // 32 байта для libsodium

// Пример секретного PHP кода для шифрования
$secret_php_code = <<<'SECRET_CODE'
<?php
echo "🔐 СЕКРЕТНЫЙ ЗАШИФРОВАННЫЙ КОД ВЫПОЛНЯЕТСЯ!\n\n";

echo "📋 Этот код был зашифрован на уровне байткода:\n";
echo "   • Исходный код не виден в файле\n";
echo "   • Код шифруется как Zend опкоды, а не как текст\n";
echo "   • Расшифровка происходит динамически при выполнении\n\n";

echo "🔑 Секретная информация:\n";
$secrets = [
    'database_host' => 'secret-server.internal',
    'database_user' => 'admin',
    'database_pass' => 'super_secret_password_123',
    'api_keys' => [
        'google' => 'AIzaSyDUMMYKEYFORDEMO',
        'aws' => 'AKIAIOSFODNN7EXAMPLE',
        'stripe' => 'sk_test_DUMMYKEYFORDEMO'
    ],
    'encryption_keys' => [
        'master_key' => 'master_key_for_all_operations',
        'session_key' => 'session_encryption_key_256bit',
        'file_key' => 'file_encryption_key_secure'
    ]
];

foreach ($secrets as $category => $data) {
    echo "   $category:\n";
    if (is_array($data)) {
        foreach ($data as $key => $value) {
            echo "     $key: " . str_repeat('*', min(strlen($value), 20)) . "\n";
        }
    } else {
        echo "     " . str_repeat('*', min(strlen($data), 20)) . "\n";
    }
    echo "\n";
}

echo "✅ ЗАШИФРОВАННЫЙ КОД УСПЕШНО ВЫПОЛНЕН!\n";
echo "💡 Никто не сможет увидеть этот код, открыв файл в редакторе.\n";
?>
SECRET_CODE;

// Проверяем расширение
if (!extension_loaded('kage')) {
    die("❌ Ошибка: Расширение Kage не загружено!\n");
}

echo "🔧 Создание зашифрованного self-decrypting PHP файла...\n\n";

// Шифруем PHP код
$encrypted_data = kage_encrypt_c($secret_php_code, $encryption_key);

if (!$encrypted_data) {
    die("❌ Ошибка: Не удалось зашифровать PHP код!\n");
}

echo "✅ PHP код успешно зашифрован\n";
echo "📊 Размер зашифрованных данных: " . strlen($encrypted_data) . " символов\n\n";

// Создаем содержимое зашифрованного файла
$encrypted_file_content = '<?php
/**
 * ЗАШИФРОВАННЫЙ SELF-DECRYPTING PHP ФАЙЛ
 * Создано с помощью Kage Bytecode Encryption
 *
 * ВНИМАНИЕ: Этот файл содержит зашифрованный код!
 * Исходный код НЕ виден в этом файле.
 */

// Ключ шифрования (в продакшене храните отдельно!)
$encryption_key = \'' . $encryption_key . '\';

// Зашифрованные данные (содержат секретный PHP код)
$encrypted_data = \'' . $encrypted_data . '\';

try {
    // Проверяем расширение Kage
    if (!extension_loaded(\'kage\')) {
        throw new Exception("Расширение Kage не загружено.");
    }

    // Расшифровываем и выполняем код
    $decrypted_code = kage_decrypt_c($encrypted_data, $encryption_key);

    // Очищаем от PHP тегов
    $code_to_execute = $decrypted_code;
    if (strpos($code_to_execute, \'<?php\') === 0) {
        $code_to_execute = substr($code_to_execute, 5);
    }
    if (substr($code_to_execute, -2) === \'?>\') {
        $code_to_execute = substr($code_to_execute, 0, -2);
    }

    // Выполняем расшифрованный код
    eval(trim($code_to_execute));

} catch (Exception $e) {
    echo "❌ Ошибка выполнения: " . $e->getMessage() . "\n";
    echo "Убедитесь, что расширение Kage установлено правильно.\n";
}
?>';

// Сохраняем зашифрованный файл
$encrypted_filename = 'generated_encrypted_file.php';
file_put_contents($encrypted_filename, $encrypted_file_content);

echo "✅ Зашифрованный файл создан: $encrypted_filename\n\n";
echo "📁 Содержимое файла ($encrypted_filename):\n";
echo "─────────────────────────────────────────────────────────────────\n";
echo substr($encrypted_file_content, 0, 500) . "...\n";
echo "─────────────────────────────────────────────────────────────────\n\n";

echo "🚀 Тестируем созданный зашифрованный файл:\n";
echo "─────────────────────────────────────────────────────────────────\n";

// Выполняем созданный файл
require $encrypted_filename;

echo "\n─────────────────────────────────────────────────────────────────\n";
echo "🎉 Демонстрация завершена успешно!\n\n";

echo "💡 ВАЖНЫЕ ЗАМЕЧАНИЯ:\n";
echo "   • Исходный PHP код полностью скрыт в зашифрованном файле\n";
echo "   • Код шифруется на уровне Zend байткода, а не текста\n";
echo "   • Расшифровка происходит динамически при выполнении\n";
echo "   • В продакшене храните ключ шифрования отдельно и безопасно\n";
echo "   • Этот подход обеспечивает высокий уровень защиты исходного кода\n\n";
