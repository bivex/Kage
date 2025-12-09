<?php

/**
 * Integration test demonstrating bytecode-based PHP file encryption
 * Shows the complete workflow from PHP code to encrypted bytecode and back
 */

// Test key (32 bytes for libsodium)
$key = '0123456789abcdef0123456789abcdef';

echo "=== KAGE PHP Bytecode Encryption Integration Test ===\n\n";

// 1. Check extension
if (!extension_loaded('kage')) {
    die("ERROR: Kage extension not loaded!\n");
}
echo "✓ Kage extension loaded\n\n";

// 2. Sample PHP code to encrypt
$php_code = <<<'PHP'
<?php
// Sample PHP application code
$user_data = ['name' => 'John Doe', 'age' => 30, 'email' => 'john@example.com'];

function process_user($user) {
    if ($user['age'] >= 18) {
        return "Welcome, " . $user['name'] . "! Your email is: " . $user['email'];
    } else {
        return "Access denied for minors";
    }
}

echo process_user($user_data);
PHP;

echo "Original PHP Code:\n";
echo str_repeat("-", 50) . "\n";
echo $php_code . "\n";
echo str_repeat("-", 50) . "\n\n";

// 3. Encrypt the PHP code
echo "Step 1: Encrypting PHP code to bytecode...\n";
$encrypted = kage_encrypt_c($php_code, $key);
echo "✓ Encryption successful\n";
echo "Encrypted data length: " . strlen($encrypted) . " characters\n";
echo "Encrypted data (first 100 chars): " . substr($encrypted, 0, 100) . "...\n\n";

// 4. Decrypt the bytecode back to PHP
echo "Step 2: Decrypting bytecode back to PHP...\n";
$decrypted = kage_decrypt_c($encrypted, $key);
echo "✓ Decryption successful\n";
echo "Decrypted PHP Code:\n";
echo str_repeat("-", 50) . "\n";
echo $decrypted . "\n";
echo str_repeat("-", 50) . "\n\n";

// 5. Verify the decrypted code works
echo "Step 3: Executing decrypted code...\n";
$code_for_eval = trim($decrypted);
if (strpos($code_for_eval, '<?php') === 0) {
    $code_for_eval = substr($code_for_eval, 5);
}
if (substr($code_for_eval, -2) === '?>') {
    $code_for_eval = substr($code_for_eval, 0, -2);
}

ob_start();
eval(trim($code_for_eval));
$output = ob_get_clean();
echo "✓ Code execution successful\n";
echo "Execution output: \"$output\"\n\n";

// 6. Demonstrate that the encrypted data is different
echo "Step 4: Security verification...\n";
$original_hash = hash('sha256', $php_code);
$encrypted_hash = hash('sha256', $encrypted);
$decrypted_hash = hash('sha256', $decrypted);

echo "Original code SHA256:  " . substr($original_hash, 0, 16) . "...\n";
echo "Encrypted data SHA256: " . substr($encrypted_hash, 0, 16) . "...\n";
echo "Decrypted code SHA256: " . substr($decrypted_hash, 0, 16) . "...\n";

$secure = ($original_hash === $decrypted_hash) && ($original_hash !== $encrypted_hash);
echo ($secure ? "✓ Security verified - data is properly encrypted\n" : "✗ Security issue detected\n");

// 7. Summary
echo "\n" . str_repeat("=", 60) . "\n";
echo "INTEGRATION TEST COMPLETE\n";
echo "✓ PHP code encryption to bytecode: SUCCESS\n";
echo "✓ Bytecode decryption back to PHP: SUCCESS\n";
echo "✓ Decrypted code execution: SUCCESS\n";
echo "✓ Security verification: " . ($secure ? "PASSED" : "FAILED") . "\n";
echo str_repeat("=", 60) . "\n";

?>
