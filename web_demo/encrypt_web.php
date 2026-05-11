<?php
/**
 * Production Encryption Script
 */
$key = "0123456789abcdef0123456789abcdef"; // Master Key
$src_dir = __DIR__ . '/src';
$dist_dir = __DIR__ . '/dist';

$files = ['config.php', 'functions.php', 'index.php'];

echo "--- 🔐 Kage Enterprise Web Encryptor ---\n";

foreach ($files as $file) {
    $code = file_get_contents($src_dir . '/' . $file);
    
    // Encrypt with Dynamic ISA (seed is generated internally)
    $encrypted_base64 = kage_encrypt_c($code, $key);
    
    $out_file = str_replace('.php', '.kage', $file);
    file_put_contents($dist_dir . '/' . $out_file, base64_decode($encrypted_base64));
    
    echo "✔ Protected: $file -> $out_file\n";
}

echo "--- 🏁 Encryption Complete ---\n";
?>
