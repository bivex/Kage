<?php
/**
 * Comprehensive Unit Test Suite to Maximize Code Coverage
 */

$key = "0123456789abcdef0123456789abcdef";
putenv("KAGE_ENCRYPTION_KEY=" . $key);

echo "=== KAGE FULL CODE COVERAGE UNIT TEST SUITE ===\n\n";

$passed = 0;
$failed = 0;

function assert_test($description, $condition) {
    global $passed, $failed;
    if ($condition) {
        echo "  [PASS] $description\n";
        $passed++;
    } else {
        echo "  [FAIL] $description\n";
        $failed++;
    }
}

// -------------------------------------------------------------
// 1. Machine ID & System Fingerprinting
// -------------------------------------------------------------
echo "[1] Testing Machine ID & HWID Detection...\n";
$machine_id = kage_get_machine_id();
assert_test("kage_get_machine_id() returns non-empty string", is_string($machine_id) && strlen($machine_id) > 0);

// -------------------------------------------------------------
// 2. Encryption API Edge Cases (kage_encrypt_c)
// -------------------------------------------------------------
echo "[2] Testing kage_encrypt_c API & Error Handling...\n";

// Valid encryption
$code = '<?php echo "Coverage Test Output"; ?>';
$enc = kage_encrypt_c($code, $key);
assert_test("kage_encrypt_c returns base64 string", is_string($enc) && strlen($enc) > 0);

$raw = base64_decode($enc);
assert_test("Encrypted payload has 'KAGE' magic header", substr($raw, 0, 4) === "KAGE");

// HWID and Domain parameters
$machine_id = kage_get_machine_id();
$enc_hwid = kage_encrypt_c($code, $key, $machine_id, "example.com");
assert_test("kage_encrypt_c accepts HWID and Domain", is_string($enc_hwid));

$dec_hwid = kage_decrypt_c($enc_hwid, $key);
assert_test("kage_decrypt_c succeeds when HWID matches machine_id", $dec_hwid === $code);

$enc_wrong_hwid = kage_encrypt_c($code, $key, "NON_MATCHING_HWID_12345");
$dec_wrong_hwid = @kage_decrypt_c($enc_wrong_hwid, $key);
assert_test("kage_decrypt_c fails when HWID does not match machine_id", $dec_wrong_hwid === false);

// Error case: Key too short
$short_key_enc = @kage_encrypt_c($code, "shortkey");
assert_test("kage_encrypt_c returns false on short key", $short_key_enc === false || $short_key_enc === null);

// -------------------------------------------------------------
// 3. Decryption API Edge Cases (kage_decrypt_c)
// -------------------------------------------------------------
echo "[3] Testing kage_decrypt_c API & Error Handling...\n";

// Valid decryption
$dec = kage_decrypt_c($enc, $key);
assert_test("kage_decrypt_c restores original code", $dec === $code);

// Error case: Wrong key
$wrong_key = "11111111111111111111111111111111";
$wrong_dec = @kage_decrypt_c($enc, $wrong_key);
assert_test("kage_decrypt_c fails on wrong key", $wrong_dec === false || $wrong_dec === null);

// Error case: Corrupted payload base64
$corrupted_b64 = @kage_decrypt_c("InvalidBase64!@#$", $key);
assert_test("kage_decrypt_c fails on corrupted base64", $corrupted_b64 === false || $corrupted_b64 === null);

// Error case: Invalid magic header payload
$bad_magic_payload = base64_encode("BADM" . substr($raw, 4));
$bad_magic_dec = @kage_decrypt_c($bad_magic_payload, $key);
assert_test("kage_decrypt_c fails on bad magic header", $bad_magic_dec === false || $bad_magic_dec === null);

// Error case: Tampered ciphertext
$tampered_raw = $raw;
$tampered_raw[strlen($tampered_raw) - 1] = chr(ord($tampered_raw[strlen($tampered_raw) - 1]) ^ 0xFF);
$tampered_dec = @kage_decrypt_c(base64_encode($tampered_raw), $key);
assert_test("kage_decrypt_c fails on tampered ciphertext", $tampered_dec === false || $tampered_dec === null);

// -------------------------------------------------------------
// 4. File Execution & Interception (kage_compile_file)
// -------------------------------------------------------------
echo "[4] Testing File Interception & Runtime Execution...\n";

$test_file = __DIR__ . '/test_unit_run.kage';
file_put_contents($test_file, $raw);

ob_start();
include $test_file;
$out = ob_get_clean();
assert_test("Encrypted .kage file executes cleanly via include", trim($out) === "Coverage Test Output");
@unlink($test_file);

// Execution of file without '<?php' tags
$raw_no_tag_code = 'echo "No Tag Code";';
$enc_no_tag = kage_encrypt_c($raw_no_tag_code, $key);
file_put_contents($test_file, base64_decode($enc_no_tag));

ob_start();
include $test_file;
$out_no_tag = ob_get_clean();
assert_test("Encrypted file without <?php tags executes cleanly", trim($out_no_tag) === "No Tag Code");
@unlink($test_file);

// Execution of corrupted .kage file
file_put_contents($test_file, "KAGE" . "corrupted_garbage_bytes_1234567890");
ob_start();
$include_res = @include $test_file;
ob_end_clean();
assert_test("Corrupted .kage file fails inclusion gracefully", $include_res === false);
@unlink($test_file);

// -------------------------------------------------------------
// 5. Complex PHP Constructs & OOP Method Virtualization
// -------------------------------------------------------------
echo "[5] Testing Complex PHP Constructs & OOP Virtualization...\n";

$complex_code = <<<'PHP'
<?php
namespace KageTest;

interface Calculable {
    public function compute(int $val): int;
}

trait MathTrait {
    public function double(int $x): int {
        return $x * 2;
    }
}

class TestProcessor implements Calculable {
    use MathTrait;
    
    private int $factor;
    
    public function __construct(int $factor) {
        $this->factor = $factor;
    }
    
    public function compute(int $val): int {
        $acc = 0;
        for ($i = 0; $i < $val; $i++) {
            $acc += $this->double($i) + $this->factor;
        }
        return $acc;
    }
}

$proc = new TestProcessor(5);
$res = $proc->compute(4); // (0+5) + (2+5) + (4+5) + (6+5) = 5+7+9+11 = 32
echo "Result: " . $res;
PHP;

$enc_complex = kage_encrypt_c($complex_code, $key);
file_put_contents($test_file, base64_decode($enc_complex));

ob_start();
include $test_file;
$out_complex = ob_get_clean();
assert_test("Complex OOP & Trait code executes with correct result", trim($out_complex) === "Result: 32");
@unlink($test_file);

// -------------------------------------------------------------
// 6. Internal Memory & Context Coverage Test
// -------------------------------------------------------------
echo "[6] Testing Internal Extension Core Memory & Context...\n";
$internal_res = kage_test_internal();
assert_test("kage_test_internal() returns true", $internal_res === true);

// -------------------------------------------------------------
// Summary
// -------------------------------------------------------------
echo "\n=============================================================\n";
echo "Unit Test Coverage Summary: Passed: $passed, Failed: $failed\n";
echo "=============================================================\n";

if ($failed > 0) {
    exit(1);
}
