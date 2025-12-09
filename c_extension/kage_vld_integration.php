<?php
/**
 * Интеграция VLD + Kage для получения и шифрования Zend байткода
 */

// Функция для получения байткода через VLD
function get_zend_bytecode($php_code) {
    // Сохраняем код во временный файл
    $temp_file = tempnam(sys_get_temp_dir(), 'vld_');
    file_put_contents($temp_file, $php_code);
    
    // Запускаем VLD для получения опкодов
    $command = "php -d vld.active=1 -d vld.execute=0 -d vld.format=0 " . escapeshellarg($temp_file) . " 2>&1";
    $output = shell_exec($command);
    
    // Очищаем временный файл
    unlink($temp_file);
    
    return $output;
}

// Функция для извлечения опкодов из VLD вывода
function extract_opcodes($vld_output) {
    $lines = explode("\n", $vld_output);
    $opcodes = [];
    $in_table = false;
    
    foreach ($lines as $line) {
        // Ищем начало таблицы опкодов
        if (strpos($line, 'op                               fetch') !== false) {
            $in_table = true;
            continue;
        }
        
        if ($in_table && trim($line) === '') {
            break; // Конец таблицы
        }
        
        if ($in_table && preg_match('/^\s*\d+\s+\d+\s+[EIO>\s]*\s*([A-Z_]+)\s+(.+)$/', $line, $matches)) {
            $opcodes[] = [
                'line' => trim(substr($line, 0, 8)),
                'op' => $matches[1],
                'operands' => trim($matches[2])
            ];
        }
    }
    
    return $opcodes;
}

echo "=== KAGE + VLD INTEGRATION DEMO ===\n";

// Исходный PHP код
$php_code = '<?php
$x = 10;
$y = $x * 2;
echo "Result: " . $y;
?>';

echo "PHP Code:\n$php_code\n";

// Получаем байткод через VLD
echo "Getting bytecode via VLD...\n";
$bytecode = get_zend_bytecode($php_code);
echo "Raw VLD output:\n$bytecode\n";

// Извлекаем опкоды
$opcodes = extract_opcodes($bytecode);
echo "\nExtracted opcodes:\n";
foreach ($opcodes as $i => $opcode) {
    printf("%d. %s - %s\n", $i+1, $opcode['op'], $opcode['operands']);
}

// Сериализуем опкоды для хранения/передачи
$serialized = serialize($opcodes);
echo "\nSerialized opcodes length: " . strlen($serialized) . " bytes\n";

// Теперь можем зашифровать через Kage
if (extension_loaded('kage')) {
    $key = '0123456789abcdef0123456789abcdef';
    $encrypted = kage_encrypt_c($serialized, $key);
    echo "Encrypted bytecode length: " . strlen($encrypted) . " bytes\n";
    
    $decrypted = kage_decrypt_c($encrypted, $key);
    $restored_opcodes = unserialize($decrypted);
    echo "Decryption successful: " . (count($restored_opcodes) == count($opcodes) ? "YES" : "NO") . "\n";
} else {
    echo "Kage extension not loaded\n";
}
?>
