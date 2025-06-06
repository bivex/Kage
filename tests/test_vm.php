<?php
/**
 * Test script for Kage VM-based encryption/decryption
 */

// Test data
$test_data = "Hello, this is a test message!";
$key = str_repeat("A", 32); // 32 bytes for crypto_secretbox_KEYBYTES

echo "Original data: " . $test_data . "\n";

// Test VM-based encryption
$encrypted = kage_vm_encrypt($test_data, $key);
if ($encrypted === false) {
    die("VM encryption failed\n");
}
echo "VM Encrypted: " . $encrypted . "\n";

// Test VM-based decryption
$decrypted = kage_vm_decrypt($encrypted, $key);
if ($decrypted === false) {
    die("VM decryption failed\n");
}
echo "VM Decrypted: " . $decrypted . "\n";

// Verify the result
if ($decrypted === $test_data) {
    echo "Test passed: Decrypted data matches original\n";
} else {
    echo "Test failed: Decrypted data does not match original\n";
}

// Test with different data types
echo "\nTesting with different data types:\n";

// Test with empty string
$empty = "";
$encrypted_empty = kage_vm_encrypt($empty, $key);
$decrypted_empty = kage_vm_decrypt($encrypted_empty, $key);
echo "Empty string test: " . ($decrypted_empty === $empty ? "passed" : "failed") . "\n";

// Test with long string
$long_string = str_repeat("A", 1000);
$encrypted_long = kage_vm_encrypt($long_string, $key);
$decrypted_long = kage_vm_decrypt($encrypted_long, $key);
echo "Long string test: " . ($decrypted_long === $long_string ? "passed" : "failed") . "\n";

// Test with binary data
$binary_data = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09";
$encrypted_binary = kage_vm_encrypt($binary_data, $key);
$decrypted_binary = kage_vm_decrypt($encrypted_binary, $key);
echo "Binary data test: " . ($decrypted_binary === $binary_data ? "passed" : "failed") . "\n";

// Test error cases
echo "\nTesting error cases:\n";

// Test with invalid key length
$invalid_key = "short_key";
$result = kage_vm_encrypt($test_data, $invalid_key);
echo "Invalid key test: " . ($result === false ? "passed" : "failed") . "\n";

// Test with invalid encrypted data
$result = kage_vm_decrypt("invalid_base64_data", $key);
echo "Invalid encrypted data test: " . ($result === false ? "passed" : "failed") . "\n";

// Test with wrong key
$wrong_key = str_repeat("B", 32);
$result = kage_vm_decrypt($encrypted, $wrong_key);
echo "Wrong key test: " . ($result === false ? "passed" : "failed") . "\n"; 