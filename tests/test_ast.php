<?php
/**
 * Test script for Kage AST parsing and bytecode generation
 */

// Test data
$key = str_repeat("A", 32); // 32 bytes for crypto_secretbox_KEYBYTES

// Test cases
$test_cases = [
    // Simple encryption
    [
        'input' => 'encrypt "Hello, World!"',
        'expected' => 'Hello, World!'
    ],
    
    // Nested encryption
    [
        'input' => 'encrypt encrypt "Double encrypted!"',
        'expected' => 'Double encrypted!'
    ],
    
    // Encryption and decryption
    [
        'input' => 'decrypt encrypt "Encrypted and decrypted!"',
        'expected' => 'Encrypted and decrypted!'
    ],
    
    // Multiple operations
    [
        'input' => 'encrypt "First" encrypt "Second"',
        'expected' => 'Second'
    ],
    
    // Deeply nested encryption
    [
        'input' => 'encrypt encrypt encrypt "Triple encrypted!"' ,
        'expected' => 'Triple encrypted!'
    ],

    // Encrypt then decrypt, then encrypt again
    [
        'input' => 'encrypt decrypt encrypt "Complex chain!"' ,
        'expected' => 'Complex chain!'
    ],

    // Decrypt a plaintext string (should remain plaintext if decryption fails)
    [
        'input' => 'decrypt "This is plaintext."' ,
        'expected' => 'This is plaintext.'
    ],
    
    // Encrypt an empty string
    [
        'input' => 'encrypt ""' ,
        'expected' => ''
    ]
];

echo "Testing AST parsing and bytecode generation:\n\n";

$all_tests_passed = true;

foreach ($test_cases as $i => $test) {
    echo "Test case " . ($i + 1) . ": ";
    
    // Parse AST
    $ast = kage_ast_parse($test['input']);
    if ($ast === false) {
        echo "Failed to parse AST (Unexpected)\n";
        $all_tests_passed = false;
        continue;
    }
    
    // Convert to bytecode and execute
    $result = kage_ast_to_bytecode($ast, $key);
    if ($result === false) {
        echo "Failed to generate bytecode (Unexpected)\n";
        $all_tests_passed = false;
        continue;
    }
    
    if ($result === $test['expected']) {
        echo "Passed\n";
    } else {
        echo "Failed (Expected: '" . $test['expected'] . "', Got: '" . $result . "')\n";
        $all_tests_passed = false;
    }
}

echo "\nTesting error cases:\n\n";

// Invalid syntax
$invalid_cases = [
    'encrypt',           // Missing operand
    'decrypt',          // Missing operand
    'encrypt decrypt',  // Invalid nesting
    'unknown "test"',   // Unknown operation
    '"unclosed string', // Unclosed string
];

foreach ($invalid_cases as $i => $input) {
    echo "Error case " . ($i + 1) . ": ";
    
    // Parse AST
    $ast = kage_ast_parse($input);
    
    // If AST parsing fails, it's an expected error
    if ($ast === false) {
        echo "Passed (Failed as expected)\n";
        continue;
    }
    
    // If AST parsing succeeded for an invalid input, it's an unexpected success
    echo "Failed (Unexpected success: AST parsed for invalid input)\n";
    $all_tests_passed = false;

    // Try to convert to bytecode and execute (this part might also fail, which is expected)
    $result = kage_ast_to_bytecode($ast, $key);
    if ($result === false) {
        // This is expected for malformed input that somehow got parsed.
    } else {
        echo "Failed (Bytecode generated and VM executed for invalid input: " . $result . ")\n";
        $all_tests_passed = false;
    }
}

echo "\n-- Test Summary --\n";
if ($all_tests_passed) {
    echo "All tests passed successfully!\n";
} else {
    echo "Some tests failed. Please review the output above.\n";
} 