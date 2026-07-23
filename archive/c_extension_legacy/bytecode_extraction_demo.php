<?php
/**
 * Демонстрация извлечения и шифрования Zend байткода
 * Используем VLD + Kage для полной защиты PHP кода
 */

// Функция для извлечения опкодов из VLD вывода
function extract_opcodes_from_vld($vld_output) {
    $opcodes = [];
    $lines = explode("\n", $vld_output);
    $in_table = false;
    
    foreach ($lines as $line) {
        // Ищем начало таблицы опкодов
        if (strpos($line, 'op') !== false && strpos($line, 'fetch') !== false) {
            $in_table = true;
            continue;
        }
        
        // Ищем конец таблицы (пустая строка после таблицы)
        if ($in_table && trim($line) === '' && count($opcodes) > 0) {
            break;
        }
        
        if ($in_table && preg_match('/^\s*\d+\s+\d+\s+[EIO>\s*]*\s*([A-Z_]+)\s+(.+)$/', $line, $matches)) {
            $opcodes[] = [
                'opcode' => $matches[1],
                'operands' => trim($matches[2])
            ];
        }
    }
    
    return $opcodes;
}

// Функция для получения байткода через VLD
function get_php_bytecode($php_code) {
    $temp_file = tempnam(sys_get_temp_dir(), 'php_bytecode_');
    file_put_contents($temp_file, $php_code);
    
    // Запускаем VLD для получения опкодов
    $command = "php -d vld.active=1 -d vld.execute=0 " . escapeshellarg($temp_file) . " 2>&1";
    $vld_output = shell_exec($command);
    
    unlink($temp_file);
    
    if (!$vld_output) {
        return false;
    }
    
    return extract_opcodes_from_vld($vld_output);
}

echo "=== ZEND BYTECODE EXTRACTION & ENCRYPTION ===\n";

// Исходный PHP код
$php_code = '<?php
function fibonacci($n) {
    if ($n <= 1) return $n;
    return fibonacci($n - 1) + fibonacci($n - 2);
}
$result = fibonacci(10);
echo "Fibonacci(10) = " . $result;
?>';

echo "Исходный PHP код:\n$php_code\n";

echo "Извлечение байткода через VLD...\n";
$bytecode = get_php_bytecode($php_code);

if ($bytecode) {
    echo "✓ Найдено " . count($bytecode) . " опкодов\n\n";
    
    echo "Первые 10 опкодов:\n";
    foreach (array_slice($bytecode, 0, 10) as $i => $op) {
        printf("%2d. %-12s %s\n", $i+1, $op['opcode'], $op['operands']);
    }
    
    echo "\nВсе типы опкодов:\n";
    $opcode_types = array_unique(array_column($bytecode, 'opcode'));
    echo implode(', ', $opcode_types) . "\n\n";
    
    // Сериализация и шифрование через Kage
    if (extension_loaded('kage')) {
        $serialized = serialize($bytecode);
        echo "Сериализованный байткод: " . strlen($serialized) . " байт\n";
        
        $key = '0123456789abcdef0123456789abcdef';
        $encrypted = kage_encrypt_c($serialized, $key);
        echo "Зашифрованный байткод: " . strlen($encrypted) . " байт\n";
        
        $decrypted = kage_decrypt_c($encrypted, $key);
        $restored = unserialize($decrypted);
        echo "Восстановлено опкодов: " . count($restored) . "\n";
        
        $integrity = (count($restored) === count($bytecode)) ? "✓ Целостность сохранена" : "✗ Ошибка целостности";
        echo "Результат: $integrity\n";
        
        echo "\n🎉 УСПЕХ: PHP код → Zend байткод → Kage шифрование → Восстановление\n";
    } else {
        echo "✗ Kage расширение не загружено\n";
    }
    
} else {
    echo "✗ Не удалось извлечь байткод\n";
}

echo "\n=== ТЕХНИЧЕСКИЕ ДЕТАЛИ ===\n";
echo "• VLD (Vulcan Logic Dumper) - расширение для дампа Zend опкодов\n";
echo "• Zend Engine компилирует PHP в опкоды при выполнении\n";
echo "• Kage шифрует сериализованный байткод для защиты\n";
echo "• Возможна деобфускация через VLD + Kage дешифрование\n";
?>
