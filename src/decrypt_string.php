<?php
if (!extension_loaded('kage')) {
    die("Error: Kage extension is not loaded\n");
}

// Enable error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

// The encrypted string
$encryptedString = "vnVLlJHoBMpu4OErd9WV6DWCm+4S5DGHC6EWV8MgQBSj3EtgpvLvGvZLBe648vblDTb7gPYWy484auoCdky/3bt8eZidVqc1OXqFCcGG5xseKztCNrEc078hMDqvwn1j9ZldcBAu2Mc/RcOwT8DriUyX7lS+XZnYMZnjmP/V9z9mDqv+VHVGNwOwVYsacCk/VvFESJBvVszPsvuiB6QRU63PaBaOueji2JhyIMz9d6+XDyb6E9J2Pb9qnveLYsbKxZcROTwCBuKj+2FsYT3GMgufgSz3XOX1QoadU4iDZfpWNkmxI0FrWsh99MQRRQdJqdQGJ5Y8DjUJBmpmND0QBeZNyjrnTYQkmQR6WENy8B6y7ve9psh+NWQUz7yb1ZiPpyp/tzMdToKNkDxzItsVYjPDo/cl5SZgY+I2r6HnszRVMaD1CDioNWnQmPblvFNGR2qRErEnQKc29JQp7JYK0DJ1OZC7G4vHKlwjNNZJEfTLbi8J+Rwl5iutB4PSi5kCRcb9PAtN+UMxi5E/R/RpgCLbQ11MZAuCQvW1t/ujW6DBdrknQdP3YwWk48BsVu8y6DWCL8CohyR/n0x0aMVMWOVR3PF7SlkAwmC6jLN0SeAIhuk0rZP+pP/agsRikhOfW74=";

// The key
$key = "123abc";

// Make sure the key is the correct length
if (strlen($key) != SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
    // Pad or truncate the key to the correct length
    $key = str_pad(substr($key, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES), 
                   SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 
                   "\0");
    echo "Debug: Key adjusted to " . SODIUM_CRYPTO_SECRETBOX_KEYBYTES . " bytes\n";
}

// Decrypt the content
echo "Debug: Attempting decryption...\n";
$decryptedContent = kage_decrypt_c($encryptedString, $key);
if ($decryptedContent === false) {
    die("Error: Failed to decrypt content\n");
}

echo "Debug: Decryption successful\n";
echo "Debug: Decrypted content length: " . strlen($decryptedContent) . " bytes\n";
echo "\nDecrypted content:\n";
echo $decryptedContent;
?> 