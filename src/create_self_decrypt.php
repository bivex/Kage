<?php

if (!extension_loaded('kage')) {
    die("Error: Kage extension is not loaded\n");
}

// Get the source file and key from command line arguments
if ($argc < 3) {
    die("Usage: php create_self_decrypt.php <source_file> <key>\n");
}

$sourceFile = $argv[1];
$key = $argv[2];

echo "Debug: Source file: $sourceFile\n";
echo "Debug: Key: $key\n";

// Read the source file
if (!file_exists($sourceFile)) {
    die("Error: Source file not found: $sourceFile\n");
}

$sourceCode = file_get_contents($sourceFile);
if ($sourceCode === false) {
    die("Error: Failed to read source file\n");
}

echo "Debug: Source code length: " . strlen($sourceCode) . " bytes\n";

// Make sure the key is the correct length for libsodium
if (strlen($key) != SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
    // Pad or truncate the key to the correct length
    $key = str_pad(substr($key, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES), 
                  SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 
                  "\0");
    echo "Debug: Key adjusted to " . SODIUM_CRYPTO_SECRETBOX_KEYBYTES . " bytes\n";
}

// Encrypt the source code
$encryptedCode = kage_encrypt_c($sourceCode, $key);
if ($encryptedCode === false) {
    die("Error: Failed to encrypt source code\n");
}

echo "Debug: Encrypted code length: " . strlen($encryptedCode) . " bytes\n";

// Get the expected length of the encrypted Base64 string for the generated file
$expectedEncryptedLength = strlen($encryptedCode);

// Define the PHP part of the self-decrypting file (everything before the encrypted content)
// No encrypted content directly here, it will be appended separately
$phpPart = <<<PHP
<?php
// This is a self-decrypting PHP file
// Usage: php self_decrypt.php <key>

if (!extension_loaded('kage')) {
    die("Error: Kage extension is not loaded\\n");
}

// Enable error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Define the expected length of the encrypted Base64 string
const EXPECTED_ENCRYPTED_LENGTH = {$expectedEncryptedLength};

echo "Debug: Starting decryption process...\\n";

echo "Debug: EXPECTED_ENCRYPTED_LENGTH: " . EXPECTED_ENCRYPTED_LENGTH . " bytes\\n";

// Get the key from command line argument
\$key = \$argv[1] ?? null;
if (!\$key) {
    die("Error: Please provide the decryption key as a command line argument\\n");
}

echo "Debug: Key length: " . strlen(\$key) . " bytes\\n";

// Make sure the key is the correct length
if (strlen(\$key) != SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
    // Pad or truncate the key to the correct length
    \$key = str_pad(substr(\$key, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES), 
                   SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 
                   "\\0");
    echo "Debug: Key adjusted to " . SODIUM_CRYPTO_SECRETBOX_KEYBYTES . " bytes\\n";
}

// Get the current file's content
\$fileContent = file_get_contents(__FILE__);

if (\$fileContent === false) {
    die("Error: Failed to read file contents\\n");
}

echo "Debug: File content length: " . strlen(\$fileContent) . " bytes\\n";

// Find the encrypted content (after the marker)
\$marker = "##!!!##";
\$markerPos = strrpos(\$fileContent, \$marker);  // Use strrpos to find last occurrence

echo "Debug: Marker length: " . strlen(\$marker) . " bytes\\n";
echo "Debug: Substr start position: " . (\$markerPos + strlen(\$marker)) . " bytes\\n";

if (\$markerPos === false) {
    die("Error: No encrypted content found\\n");
}

echo "Debug: Found marker at position: " . \$markerPos . "\\n";

// Extract the encrypted content with a fixed length to avoid trailing garbage
\$encryptedContent = trim(substr(\$fileContent, \$markerPos + strlen(\$marker), EXPECTED_ENCRYPTED_LENGTH));
echo "Debug: Encrypted content length (fixed): " . strlen(\$encryptedContent) . " bytes\\n";
echo "Debug: First 10 chars of encrypted content: " . substr(\$encryptedContent, 0, 10) . "\\n";

// Decrypt the content
echo "Debug: Attempting decryption...\\n";
\$decryptedContent = kage_decrypt_c(\$encryptedContent, \$key);
if (\$decryptedContent === false) {
    die("Error: Failed to decrypt content\\n");
}

echo "Debug: Decryption successful\\n";
echo "Debug: Decrypted content length: " . strlen(\$decryptedContent) . " bytes\\n";
echo "Debug: First 100 chars of decrypted content: " . substr(\$decryptedContent, 0, 100) . "\\n";

// Execute the decrypted content
echo "Debug: Executing decrypted content...\\n";
ob_start();
// Write the decrypted content to a temporary file and include it
\$tempFile = tempnam(sys_get_temp_dir(), 'kage_');
file_put_contents(\$tempFile, \$decryptedContent);
\$result = include(\$tempFile);
unlink(\$tempFile); // Clean up the temporary file
\$output = ob_get_clean();

// Display the output
echo \$output;

if (\$result !== false) {
    echo "Debug: Execution completed successfully\\n";
} else {
    echo "Debug: Execution completed with errors\\n";
}
exit(0); // Exit after execution to prevent parsing trailing encrypted data as PHP code
?>
PHP;

// Write the PHP part of the self-decrypting file
$outputFile = pathinfo($sourceFile, PATHINFO_FILENAME) . '_encrypted.php';
$result = file_put_contents($outputFile, $phpPart);

if ($result === false) {
    die("Error: Failed to write PHP part to output file: $outputFile\n");
}

// Append the marker and the encrypted content (Base64 string) without any extra newlines
$result = file_put_contents($outputFile, "##!!!##" . $encryptedCode, FILE_APPEND);

if ($result === false) {
    die("Error: Failed to append encrypted content to $outputFile\n");
}

echo "Debug: Wrote " . filesize($outputFile) . " bytes to $outputFile\n";
echo "Created self-decrypting file: $outputFile\n";
echo "Use it with: php $outputFile $key\n"; 