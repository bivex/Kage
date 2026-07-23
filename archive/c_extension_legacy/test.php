<?php

// Enable error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Test data
$test_data = "Hello, this is a test message!";
$key = random_bytes(32); // Generate a random 32-byte key for crypto_secretbox

echo "Original data: " . $test_data . "\n";
echo "Key (hex): " . bin2hex($key) . "\n\n";

// Test encryption
echo "Testing encryption...\n";
try {
    $encrypted = kage_encrypt_c($test_data, $key);
    if ($encrypted === false) {
        throw new Exception("Encryption failed");
    }
    echo "Encrypted data (base64): " . $encrypted . "\n\n";
} catch (Throwable $e) {
    die("Encryption error: " . $e->getMessage() . "\n");
}

// Test decryption
echo "Testing decryption...\n";
try {
    $decrypted = kage_decrypt_c($encrypted, $key);
    if ($decrypted === false) {
        throw new Exception("Decryption failed");
    }
    echo "Decrypted data: " . $decrypted . "\n\n";
} catch (Throwable $e) {
    die("Decryption error: " . $e->getMessage() . "\n");
}

// Verify the result
if ($decrypted === $test_data) {
    echo "Test passed: Decrypted data matches original data\n";
} else {
    echo "Test failed: Decrypted data does not match original data\n";
    echo "Original: " . bin2hex($test_data) . "\n";
    echo "Decrypted: " . bin2hex($decrypted) . "\n";
}

// Test with invalid key
echo "\nTesting with invalid key...\n";
try {
    $invalid_key = random_bytes(32);
    $decrypted_invalid = @kage_decrypt_c($encrypted, $invalid_key);
    if ($decrypted_invalid === false) {
        echo "Test passed: Decryption correctly failed with invalid key\n";
    } else {
        echo "Test failed: Decryption succeeded with invalid key\n";
    }
} catch (Throwable $e) {
    echo "Test passed: Decryption correctly failed with invalid key (exception: " . $e->getMessage() . ")\n";
}

// Test with corrupted data
echo "\nTesting with corrupted data...\n";
try {
    $corrupted = substr($encrypted, 0, -1) . chr(ord(substr($encrypted, -1)) ^ 1);
    $decrypted_corrupted = @kage_decrypt_c($corrupted, $key);
    if ($decrypted_corrupted === false) {
        echo "Test passed: Decryption correctly failed with corrupted data\n";
    } else {
        echo "Test failed: Decryption succeeded with corrupted data\n";
    }
} catch (Throwable $e) {
    echo "Test passed: Decryption correctly failed with corrupted data (exception: " . $e->getMessage() . ")\n";
}

// Test with empty data
echo "\nTesting with empty data...\n";
try {
    $empty_encrypted = @kage_encrypt_c("", $key);
    if ($empty_encrypted === false) {
        echo "Test failed: Encryption failed with empty data\n";
    } else {
        $empty_decrypted = @kage_decrypt_c($empty_encrypted, $key);
        if ($empty_decrypted === "") {
            echo "Test passed: Empty data encryption/decryption works correctly\n";
        } else {
            echo "Test failed: Empty data decryption returned non-empty string\n";
        }
    }
} catch (Throwable $e) {
    echo "Test failed: Empty data test threw exception: " . $e->getMessage() . "\n";
}

// Test with large data
echo "\nTesting with large data...\n";
try {
    $large_data = str_repeat("A", 1024 * 1024); // 1MB of data
    $large_encrypted = @kage_encrypt_c($large_data, $key);
    if ($large_encrypted === false) {
        echo "Test failed: Encryption failed with large data\n";
    } else {
        $large_decrypted = @kage_decrypt_c($large_encrypted, $key);
        if ($large_decrypted === $large_data) {
            echo "Test passed: Large data encryption/decryption works correctly\n";
        } else {
            echo "Test failed: Large data decryption returned incorrect data\n";
        }
    }
} catch (Throwable $e) {
    echo "Test failed: Large data test threw exception: " . $e->getMessage() . "\n";
} 