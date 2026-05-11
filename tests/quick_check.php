<?php
$code = 'echo "Kage Protection is ACTIVE!\n"; $a = 5; $b = 10; echo "Sum: " . ($a + $b) . "\n";';
$key = "0123456789abcdef0123456789abcdef"; // 32 bytes

echo "--- 1. Original Code ---\n";
echo $code . "\n\n";

echo "--- 2. Encrypting... ---\n";
$encrypted = kage_encrypt_c($code, $key);
echo "Protected Data: " . substr($encrypted, 0, 50) . "...\n\n";

echo "--- 3. Decrypting & Executing ---\n";
$decrypted = kage_decrypt_c($encrypted, $key);
eval($decrypted);
