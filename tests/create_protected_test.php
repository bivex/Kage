<?php
/**
 * Create a Kage-protected file for testing the compilation hook.
 */

$code = '<?php echo "SEAMLESS EXECUTION SUCCESSFUL!\n"; echo "This file was decrypted and compiled in-memory by Kage.\n"; ?>';
$key = "0123456789abcdef0123456789abcdef"; // 32 bytes

// 1. Encrypt the code
$encrypted_base64 = kage_encrypt_c($code, $key);
$encrypted_binary = base64_decode($encrypted_base64);

// 2. Create the protected file with KAGE signature
$filename = "protected_test.php";
$handle = fopen($filename, "wb");
fwrite($handle, "KAGE"); // Signature
fwrite($handle, $encrypted_binary);
fclose($handle);

echo "Created protected file: $filename\n";
