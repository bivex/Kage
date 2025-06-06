<?php
/**
 * Test script for Kage PHP Extension
 * This script verifies the basic functionality of the encryption/decryption features
 */

// Test data
$test_data = "Hello, this is a test message for the Kage extension!";
$key = random_bytes(32); // crypto_secretbox_KEYBYTES = 32

echo "Testing Kage Extension\n";
echo "=====================\n\n";

// Test 1: Basic encryption/decryption
echo "Test 1: Basic encryption/decryption\n";
echo "--------------------------------\n";
echo "Original data: " . $test_data . "\n";

// Encrypt
$encrypted = kage_encrypt_c($test_data, $key);
if ($encrypted === false) {
    die("Encryption failed!\n");
}
echo "Encrypted (Base64): " . $encrypted . "\n";

// Decrypt
$decrypted = kage_decrypt_c($encrypted, $key);
if ($decrypted === false) {
    die("Decryption failed!\n");
}
echo "Decrypted: " . $decrypted . "\n";

// Verify
if ($decrypted === $test_data) {
    echo "✓ Test 1 passed: Data matches after encryption/decryption\n\n";
} else {
    echo "✗ Test 1 failed: Data mismatch after encryption/decryption\n\n";
}

// Test 2: Empty string
echo "Test 2: Empty string\n";
echo "-----------------\n";
$empty_data = "";
$encrypted_empty = kage_encrypt_c($empty_data, $key);
$decrypted_empty = kage_decrypt_c($encrypted_empty, $key);

if ($decrypted_empty === $empty_data) {
    echo "✓ Test 2 passed: Empty string handled correctly\n\n";
} else {
    echo "✗ Test 2 failed: Empty string handling failed\n\n";
}

// Test 3: Long string
echo "Test 3: Long string\n";
echo "-----------------\n";
$long_data = str_repeat("This is a test message. ", 100);
$encrypted_long = kage_encrypt_c($long_data, $key);
$decrypted_long = kage_decrypt_c($encrypted_long, $key);

if ($decrypted_long === $long_data) {
    echo "✓ Test 3 passed: Long string handled correctly\n\n";
} else {
    echo "✗ Test 3 failed: Long string handling failed\n\n";
}

// Test 4: Invalid key
echo "Test 4: Invalid key\n";
echo "-----------------\n";
$invalid_key = random_bytes(16); // Wrong key size
$decrypted_invalid = kage_decrypt_c($encrypted, $invalid_key);

if ($decrypted_invalid === false) {
    echo "✓ Test 4 passed: Invalid key correctly rejected\n\n";
} else {
    echo "✗ Test 4 failed: Invalid key not rejected\n\n";
}

// Test 5: Corrupted data
echo "Test 5: Corrupted data\n";
echo "--------------------\n";
$corrupted_data = substr($encrypted, 0, -1) . "X"; // Corrupt the last character
$decrypted_corrupted = kage_decrypt_c($corrupted_data, $key);

if ($decrypted_corrupted === false) {
    echo "✓ Test 5 passed: Corrupted data correctly rejected\n\n";
} else {
    echo "✗ Test 5 failed: Corrupted data not rejected\n\n";
}

echo "All tests completed!\n"; 