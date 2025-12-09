<?php
echo "=== PHP BYTECODE EXTRACTION METHODS ===\n";

// Method 1: Using opcache to get cached bytecode
echo "\n1. OPCACHE METHOD:\n";
$test_file = '/tmp/test_code.php';
file_put_contents($test_file, '<?php echo "Hello from bytecode!"; $x = 42; ?>');

if (function_exists('opcache_compile_file')) {
    echo "Compiling file with opcache...\n";
    $result = opcache_compile_file($test_file);
    echo "Opcache compile result: " . ($result ? "SUCCESS" : "FAILED") . "\n";
    
    // Try to get cached data (if available)
    if (function_exists('opcache_get_status')) {
        $status = opcache_get_status();
        if (isset($status['scripts'][$test_file])) {
            echo "Cached script found!\n";
            print_r($status['scripts'][$test_file]);
        }
    }
} else {
    echo "opcache_compile_file not available\n";
}

// Method 2: Using PHP's tokenizer and compilation
echo "\n2. PHP TOKENIZER METHOD:\n";
$code = '<?php echo "Hello World!"; $x = 42 + 24; ?>';
echo "Code: $code\n";

$tokens = token_get_all($code);
echo "Tokens found: " . count($tokens) . "\n";
foreach (array_slice($tokens, 0, 10) as $token) {
    if (is_array($token)) {
        echo "Token: " . token_name($token[0]) . " = '" . $token[1] . "'\n";
    } else {
        echo "Token: '$token'\n";
    }
}

// Method 3: Using eval with output capture (runtime)
echo "\n3. RUNTIME EXECUTION METHOD:\n";
ob_start();
eval('echo "Direct execution: "; $y = 10 * 5; echo $y;');
$output = ob_get_clean();
echo "Runtime output: $output\n";

// Cleanup
unlink($test_file);

echo "\n=== CONCLUSION ===\n";
echo "PHP bytecode can be extracted via:\n";
echo "- Opcache compiled cache\n";
echo "- Custom tokenizer + AST builder\n";
echo "- Runtime execution tracing\n";
echo "- VLD extension (not installed)\n";
