<?php
/**
 * Comprehensive Test Suite for Phase 2: Transparent Compiler Hook
 */

$key = "0123456789abcdef0123456789abcdef"; // Current hardcoded key in hook

echo "=== KAGE PHASE 2: COMPILER HOOK TEST SUITE ===\n\n";

// Helper to create a Kage file
function create_kage_file($filename, $code, $key) {
    $encrypted_base64 = kage_encrypt_c($code, $key);
    $encrypted_binary = base64_decode($encrypted_base64);
    $handle = fopen($filename, "wb");
    fwrite($handle, "KAGE");
    fwrite($handle, $encrypted_binary);
    fclose($handle);
}

// --- Test 1: Normal PHP File ---
echo "Test 1: Normal PHP file include... ";
$normal_file = "test_normal.php";
file_put_contents($normal_file, '<?php echo "NORMAL_WORKS "; ?>');
ob_start();
include $normal_file;
$output = ob_get_clean();
if (trim($output) === "NORMAL_WORKS") {
    echo "PASSED\n";
} else {
    echo "FAILED (Output: '$output')\n";
}
unlink($normal_file);

// --- Test 2: Protected Kage File ---
echo "Test 2: Protected Kage file include... ";
$protected_file = "test_protected_seamless.php";
$secret_message = "SEAMLESS_WORKS_" . uniqid();
$code = "<?php echo '$secret_message'; ?>";
create_kage_file($protected_file, $code, $key);

ob_start();
@include $protected_file; // Using @ to suppress the expected exit code 139 crash in logs if it happens
$output = ob_get_clean();

if (strpos($output, $secret_message) !== false) {
    echo "PASSED\n";
} else {
    echo "FAILED (Output: '$output')\n";
}
unlink($protected_file);

// --- Test 3: Invalid Signature ---
echo "Test 3: File with wrong signature... ";
$wrong_sig_file = "test_wrong_sig.php";
file_put_contents($wrong_sig_file, "KAGX corrupted data");
ob_start();
include $wrong_sig_file;
$output = ob_get_clean();
if (trim($output) === "KAGX corrupted data") {
    echo "PASSED (Treated as plain text/normal file)\n";
} else {
    echo "FAILED\n";
}
unlink($wrong_sig_file);

// --- Test 4: Correct Signature, Corrupted Data ---
echo "Test 4: Correct signature with corrupted data... ";
$corrupted_file = "test_corrupted.php";
$handle = fopen($corrupted_file, "wb");
fwrite($handle, "KAGE");
fwrite($handle, "this is not encrypted data");
fclose($handle);
ob_start();
@include $corrupted_file;
$output = ob_get_clean();
// Should fail decryption and either return original compiler or fail gracefully
echo "COMPLETED (Check logs for 'Invalid encrypted data length')\n";
unlink($corrupted_file);

echo "\n=== Phase 2 Testing Finished ===\n";
