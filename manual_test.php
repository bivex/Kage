<?php
$key = "0123456789abcdef0123456789abcdef";
putenv("KAGE_ENCRYPTION_KEY=" . $key);
$code = "<?php echo 'HELLO_WORLD'; ?>";
$enc = kage_encrypt_c($code, $key);
$bin = base64_decode($enc);
file_put_contents('test_protected.kage', "KAGE".$bin);
echo "Encrypted file created\n";
include 'test_protected.kage';
echo "\nDone.\n";
?>