<?php

/**
 * Test file for bytecode-based PHP encryption functionality
 * Tests the new kage_encrypt_c and kage_decrypt_c functions that work with PHP bytecode
 */

// Define a test key (must be 32 bytes for libsodium's crypto_secretbox)
$key = '0123456789abcdef0123456789abcdef'; // 32 bytes

echo "--- Testing Bytecode-based PHP Encryption ---\n";

// 1. Check if the extension is loaded
if (!extension_loaded('kage')) {
    echo "ERROR: Kage extension is NOT loaded. Please check your php.ini and installation.\n";
    exit(1);
}
echo "✓ Kage extension is loaded successfully.\n";

// 2. Test PHP code samples
$test_cases = [
    'simple_echo' => '<?php echo "Hello, World!"; ?>',
    'variable_operations' => '<?php $x = 10; $y = $x * 2; echo "Result: " . $y; ?>',
    'function_definition' => '<?php function test() { return "OK"; } echo test(); ?>',
    'array_operations' => '<?php $arr = [1,2,3]; echo array_sum($arr); ?>',
    'conditional_logic' => '<?php $x = 5; if ($x > 3) { echo "Greater"; } else { echo "Smaller"; } ?>',
    'loop_construct' => '<?php for ($i = 0; $i < 3; $i++) { echo $i . " "; } ?>'
];

$test_results = [];
$passed = 0;
$total = count($test_cases);

foreach ($test_cases as $name => $php_code) {
    echo "\n--- Testing: $name ---\n";
    echo "Original PHP code: $php_code\n";

    try {
        // 3. Test encryption
        $encrypted = kage_encrypt_c($php_code, $key);
        if (empty($encrypted)) {
            throw new Exception("Encryption returned empty result");
        }
        echo "✓ Encryption successful (length: " . strlen($encrypted) . ")\n";

        // 4. Test decryption
        $decrypted = kage_decrypt_c($encrypted, $key);
        if (empty($decrypted)) {
            throw new Exception("Decryption returned empty result");
        }
        echo "✓ Decryption successful\n";
        echo "Decrypted PHP code: $decrypted\n";

        // 5. Verify the decrypted code is valid PHP
        try {
            // Strip PHP tags for eval() since it expects pure PHP code
            $code_for_eval = trim($decrypted);
            if (strpos($code_for_eval, '<?php') === 0) {
                $code_for_eval = substr($code_for_eval, 5);
            }
            if (substr($code_for_eval, -2) === '?>') {
                $code_for_eval = substr($code_for_eval, 0, -2);
            }
            $code_for_eval = trim($code_for_eval);

            ob_start();
            eval($code_for_eval);
            $output = ob_get_clean();
            echo "✓ Decrypted code executes successfully\n";
            echo "Execution output: $output\n";

            $test_results[$name] = [
                'status' => 'PASS',
                'original' => $php_code,
                'encrypted_length' => strlen($encrypted),
                'decrypted' => $decrypted,
                'execution_output' => $output
            ];
            $passed++;

        } catch (Throwable $e) {
            echo "✗ Decrypted code execution failed: " . $e->getMessage() . "\n";
            $test_results[$name] = [
                'status' => 'EXEC_FAIL',
                'original' => $php_code,
                'encrypted_length' => strlen($encrypted),
                'decrypted' => $decrypted,
                'error' => $e->getMessage()
            ];
        }

    } catch (Throwable $e) {
        echo "✗ Test failed: " . $e->getMessage() . "\n";
        $test_results[$name] = [
            'status' => 'FAIL',
            'original' => $php_code,
            'error' => $e->getMessage()
        ];
    }
}

// 6. Test with invalid key
echo "\n--- Testing with invalid key ---\n";
$php_code = '<?php echo "test"; ?>';
try {
    $encrypted = kage_encrypt_c($php_code, $key);
    $wrong_key = 'wrong_key_12345678901234567890'; // Wrong key
    $decrypted = kage_decrypt_c($encrypted, $wrong_key);
    echo "✗ Should have failed with wrong key, but didn't\n";
} catch (Throwable $e) {
    echo "✓ Correctly failed with wrong key: " . $e->getMessage() . "\n";
}

// 7. Test with empty input
echo "\n--- Testing edge cases ---\n";
try {
    $result = kage_encrypt_c('', $key);
    echo "✗ Should have failed with empty input\n";
} catch (Throwable $e) {
    echo "✓ Correctly failed with empty input: " . $e->getMessage() . "\n";
}

try {
    $result = kage_decrypt_c('', $key);
    echo "✗ Should have failed with empty encrypted data\n";
} catch (Throwable $e) {
    echo "✓ Correctly failed with empty encrypted data: " . $e->getMessage() . "\n";
}

// 8. Summary
echo "\n--- Test Summary ---\n";
echo "Total tests: $total\n";
echo "Passed: $passed\n";
echo "Failed: " . ($total - $passed) . "\n";

if ($passed === $total) {
    echo "🎉 All tests passed! Bytecode encryption is working correctly.\n";
} else {
    echo "⚠️  Some tests failed. Check the results above.\n";
    echo "\nDetailed results:\n";
    print_r($test_results);
}

?>
