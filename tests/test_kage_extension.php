<?php

// Define a test key (must be 32 bytes for libsodium's crypto_secretbox)
$key = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

// Test data
$data = "Hello from Kage PHP Extension!";

echo "--- Testing Kage PHP Extension (libsodium) ---\n";

// 1. Check if the extension is loaded
if (extension_loaded('kage')) {
    echo "Kage extension is loaded successfully.\n";
} else {
    echo "Kage extension is NOT loaded. Please check your php.ini and installation.\n";
    exit(1);
}

// 2. Test kage_encrypt_c
try {
    $encrypted_data_base64 = kage_encrypt_c($data, $key);
    echo "kage_encrypt_c output: " . $encrypted_data_base64 . "\n";

    if (empty($encrypted_data_base64)) {
        echo "Error: kage_encrypt_c returned empty data.\n";
        exit(1);
    }
} catch (Throwable $e) {
    echo "Error encrypting: " . $e->getMessage() . "\n";
    exit(1);
}

// 3. Test kage_decrypt_c
try {
    $decrypted_data = kage_decrypt_c($encrypted_data_base64, $key);
    echo "kage_decrypt_c output: " . $decrypted_data . "\n";

    if ($decrypted_data !== $data) {
        echo "Error: Decrypted data does not match original data!\n";
        exit(1);
    }
} catch (Throwable $e) {
    echo "Error decrypting: " . $e->getMessage() . "\n";
    exit(1);
}

echo "--- Kage PHP Extension tests passed successfully! ---\n";

?> 