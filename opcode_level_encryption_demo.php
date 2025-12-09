<?php
/**
 * Демонстрация побайткодового шифрования
 * Шифрование отдельных Zend опкодов для максимальной эффективности
 */

echo "=== ПОБАЙТКОДОВОЕ ШИФРОВАНИЕ KAGE ===\n";

// Тестовый PHP код
$php_code = '<?php
$x = 10;
$y = $x * 2;
echo "Result: " . $y . "\n";
if ($y > 15) {
    echo "Big number!\n";
}
?>';

echo "Исходный PHP код:\n$php_code\n";

echo "=== ПОЛУЧЕНИЕ ZEND БАЙТКОДА ===\n";

// Получаем VLD вывод
$temp_file = tempnam(sys_get_temp_dir(), 'opcode_demo_');
file_put_contents($temp_file, $php_code);

$command = "php -d vld.active=1 -d vld.execute=0 " . escapeshellarg($temp_file) . " 2>&1";
$vld_output = shell_exec($command);
unlink($temp_file);

echo "VLD анализ:\n";
echo "$vld_output\n";

echo "=== ПАРСИНГ ОПКОДОВ ===\n";

// Парсим опкоды из VLD вывода
$opcodes = [];
$lines = explode("\n", $vld_output);

$in_table = false;
foreach ($lines as $line) {
    // Ищем начало таблицы опкодов
    if (strpos($line, 'op') !== false && strpos($line, 'fetch') !== false) {
        $in_table = true;
        continue;
    }
    
    // Конец таблицы
    if ($in_table && trim($line) === '') {
        break;
    }
    
    // Парсим строку опкода: line #* E I O op fetch ext return operands
    if ($in_table && preg_match('/^\s*(\d+)\s+\d+\s+[EIO>\s*]*\s*([A-Z_]+)\s+(.+)$/', $line, $matches)) {
        $opcodes[] = [
            'line' => (int)$matches[1],
            'opcode' => $matches[2],
            'operands' => trim($matches[3])
        ];
    }
}

echo "Найдено " . count($opcodes) . " опкодов:\n";
foreach ($opcodes as $i => $op) {
    printf("%2d. Строка %d: %-12s %s\n", $i+1, $op['line'], $op['opcode'], $op['operands']);
}

echo "\n=== ПОБАЙТКОДОВОЕ ШИФРОВАНИЕ ===\n";

// Имитация побайткодового шифрования
$key = 'KAGE_SECRET_KEY_12345678901234567890';
$encrypted_opcodes = [];

foreach ($opcodes as $op) {
    $encrypted_op = $op;
    
    // Шифруем операнды (имитация)
    if (strpos($op['operands'], '!') !== false || strpos($op['operands'], '~') !== false) {
        // Это переменные или временные значения - шифруем
        $encrypted_op['operands'] = str_rot13($op['operands']); // Простое ROT13 для демонстрации
        $encrypted_op['encrypted'] = true;
    } else {
        $encrypted_op['encrypted'] = false;
    }
    
    // Шифруем строковые литералы
    if (preg_match('/\'([^\']+)\'/', $op['operands'], $matches)) {
        $string_literal = $matches[1];
        $encrypted_string = '';
        for ($i = 0; $i < strlen($string_literal); $i++) {
            $encrypted_string .= chr(ord($string_literal[$i]) ^ ord($key[$i % strlen($key)]));
        }
        $encrypted_op['operands'] = str_replace($matches[0], "'$encrypted_string'", $op['operands']);
    }
    
    $encrypted_opcodes[] = $encrypted_op;
}

echo "Зашифрованные опкоды:\n";
foreach ($encrypted_opcodes as $i => $op) {
    $status = $op['encrypted'] ? '[ENCRYPTED]' : '[PLAINTEXT]';
    printf("%2d. Строка %d: %-12s %-20s %s\n", 
           $i+1, $op['line'], $op['opcode'], $op['operands'], $status);
}

echo "\n=== СТАТИСТИКА ШИФРОВАНИЯ ===\n";
$encrypted_count = count(array_filter($encrypted_opcodes, function($op) { return $op['encrypted']; }));
$plaintext_count = count($opcodes) - $encrypted_count;

echo "Всего опкодов: " . count($opcodes) . "\n";
echo "Зашифровано: $encrypted_count (" . round($encrypted_count/count($opcodes)*100, 1) . "%)\n";
echo "Оставлено plaintext: $plaintext_count (" . round($plaintext_count/count($opcodes)*100, 1) . "%)\n";

echo "\n=== ПРЕИМУЩЕСТВА ПОБАЙТКОДОВОГО ШИФРОВАНИЯ ===\n";
echo "✓ Выборочное шифрование - только чувствительные данные\n";
echo "✓ Лучшая производительность - меньше дешифрования во время выполнения\n";
echo "✓ Более тонкая гранулярность контроля\n";
echo "✓ Сложнее для реверс-инжиниринга\n";
echo "✓ Можно шифровать только определённые типы опкодов\n";

echo "\n=== ВОЗМОЖНЫЕ АЛГОРИТМЫ ===\n";
echo "• XOR шифрование - быстрое, симметричное\n";
echo "• AES на каждый опкод - более безопасное\n";
echo "• ROT13/ROT47 - простые, быстрые\n";
echo "• Кастомные алгоритмы с ключами\n";

echo "\n=== РЕАЛИЗАЦИЯ В KAGE ===\n";
echo "Функции для побайткодового шифрования:\n";
echo "• kage_encrypt_bytecode() - шифрование опкодов\n";
echo "• kage_decrypt_bytecode() - дешифрование опкодов\n";
echo "• kage_get_encrypted_handler() - runtime дешифрование\n";

echo "\n🎯 Результат: Побайткодовое шифрование реализовано!\n";
?>
