<?php
/**
 * Test Issue #4: In-place XOR modification of interned strings in literals table
 * ensures interned strings (constants, global symbols) are NOT corrupted across requests/files.
 */

$key = '0123456789abcdef0123456789abcdef';

echo "=== Test Issue #4: Interned Strings Integrity ===\n";

define('TEST_INTERNED_CONST', 'EXPECTED_LITERAL_VALUE');
define('ANOTHER_CONST', 'ANOTHER_VALUE');

// Create protected code that references these exact constants as literals
$code = '<?php
$val = TEST_INTERNED_CONST;
$val2 = ANOTHER_CONST;
$php_ver = PHP_VERSION;
return $val . " | " . $val2 . " | " . $php_ver;
';

$encrypted = kage_encrypt_c($code, $key);
$tmp_kage = '/tmp/test_interned.kage';
file_put_contents($tmp_kage, base64_decode($encrypted));

// Execute protected file
$result = include $tmp_kage;
echo "[+] Included protected file returned: " . $result . "\n";

// Now check if TEST_INTERNED_CONST and ANOTHER_CONST and PHP_VERSION are still intact
if (TEST_INTERNED_CONST !== 'EXPECTED_LITERAL_VALUE') {
    echo "[-] FAILED: TEST_INTERNED_CONST was corrupted! Got: " . var_export(TEST_INTERNED_CONST, true) . "\n";
    exit(1);
}

if (ANOTHER_CONST !== 'ANOTHER_VALUE') {
    echo "[-] FAILED: ANOTHER_CONST was corrupted! Got: " . var_export(ANOTHER_CONST, true) . "\n";
    exit(1);
}

if (!defined('TEST_INTERNED_CONST') || !defined('ANOTHER_CONST')) {
    echo "[-] FAILED: Constant lookup failed!\n";
    exit(1);
}

// Check standard PHP interned strings
if (constant('TEST_INTERNED_CONST') !== 'EXPECTED_LITERAL_VALUE') {
    echo "[-] FAILED: constant() lookup failed!\n";
    exit(1);
}

unlink($tmp_kage);
echo "[+] SUCCESS: All interned string literals remained uncorrupted in shared memory!\n";
