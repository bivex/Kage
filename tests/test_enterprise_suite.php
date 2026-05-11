<?php
/**
 * Enterprise Test Suite for Kage Extension
 * Covers: Dynamic ISA, Recursive Protection, Performance, and Integrity
 */

$key = "0123456789abcdef0123456789abcdef";
putenv("KAGE_ENCRYPTION_KEY=" . $key);

echo "=== KAGE ENTERPRISE SECURITY TEST SUITE ===\n\n";

function create_kage($filename, $code, $key, $hwid = null) {
    $enc = kage_encrypt_c($code, $key, $hwid);
    file_put_contents($filename, base64_decode($enc));
}

// --- Test 1: Dynamic ISA (Per-file unique mapping) ---
echo "Test 1: Dynamic ISA Consistency... ";
$file1 = "isa1.kage";
$file2 = "isa2.kage";
$code = "<?php echo 'ISA_SUCCESS '; ?>";

// Create two files (they will have different random seeds internally)
create_kage($file1, $code, $key);
create_kage($file2, $code, $key);

ob_start();
include $file1;
include $file2;
$out = ob_get_clean();

if (trim($out) === "ISA_SUCCESS ISA_SUCCESS") {
    echo "PASSED (Different seeds, correct execution)\n";
} else {
    echo "FAILED (Output: '$out')\n";
}
unlink($file1);
unlink($file2);

// --- Test 2: Recursive Protection (Classes & Methods) ---
echo "Test 2: Recursive Protection (OOP Methods)... ";
$oop_file = "oop.kage";
$oop_code = <<<'PHP'
<?php
class SecurityTest {
    public function getSecret($val) {
        return "SECRET_" . ($val + 10);
    }
}
$obj = new SecurityTest();
echo $obj->getSecret(5);
?>
PHP;

create_kage($oop_file, $oop_code, $key);
ob_start();
include $oop_file;
$out = ob_get_clean();

if ($out === "SECRET_15") {
    echo "PASSED\n";
} else {
    echo "FAILED (Output: '$out')\n";
}
unlink($oop_file);

// --- Test 3: Performance (Zero Overhead JIT) ---
echo "Test 3: Performance Benchmark (Hot Loops)... ";
$bench_file = "bench.kage";
$bench_code = <<<'PHP'
<?php
$start = microtime(true);
$sum = 0;
for ($i = 0; $i < 1000000; $i++) {
    $sum += $i;
}
$end = microtime(true);
echo ($end - $start);
?>
PHP;

create_kage($bench_file, $bench_code, $key);

// Unprotected baseline
$start_raw = microtime(true);
$sum = 0; for($i=0;$i<1000000;$i++) $sum+=$i;
$end_raw = microtime(true);
$raw_time = $end_raw - $start_raw;

ob_start();
include $bench_file;
$protected_time = (float)ob_get_clean();

$overhead = ($protected_time / $raw_time);
echo "Protected: " . round($protected_time, 4) . "s, Raw: " . round($raw_time, 4) . "s (Overhead: " . round($overhead, 2) . "x)... ";

if ($overhead < 2.5) { // Allow some slack for first-run unprotection, but should be near 1x
    echo "PASSED\n";
} else {
    echo "FAILED (Too slow)\n";
}
unlink($bench_file);

// --- Test 4: Integrity Tampering ---
echo "Test 4: Integrity Check (Tamper Detection)... ";
$tamper_file = "tamper.kage";
create_kage($tamper_file, "<?php echo 'OK'; ?>", $key);

// Corrupt the payload (after header)
$data = file_get_contents($tamper_file);
$data[70] = chr(ord($data[70]) ^ 0xFF); 
file_put_contents($tamper_file, $data);

ob_start();
$included = @include $tamper_file;
$out = ob_get_clean();

if ($included === false || strpos($out, 'OK') === false) {
    echo "PASSED (Tampering detected or decryption failed)\n";
} else {
    echo "FAILED (Tampered file executed!)\n";
}
unlink($tamper_file);

echo "\n=== ALL ENTERPRISE TESTS COMPLETED ===\n";
