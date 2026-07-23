<?php
/**
 * Kage Security Extension — PHP 8.4 Protection & Execution Demo
 */

$key = "0123456789abcdef0123456789abcdef";
putenv("KAGE_ENCRYPTION_KEY=" . $key);

echo "=========================================\n";
echo "🛡️  KAGE PHP 8.4 DEMONSTRATION & PROTECTION\n";
echo "=========================================\n\n";

echo "PHP Version: " . PHP_VERSION . "\n";
echo "Zend Engine Version: " . zend_version() . "\n";
echo "Kage Extension Loaded: " . (extension_loaded('kage') ? 'YES' : 'NO') . "\n\n";

// Source code demonstrating PHP 8.4 features
$source_code = <<<'PHP'
<?php
echo "--- 🚀 Executing Kage Protected Payload on PHP 8.4 ---\n";

class UserAccount {
    public function __construct(
        public string $username,
        public string $role = 'Developer'
    ) {}

    public function getInfo(): string {
        return sprintf("User: %s [%s]", $this->username, $this->role);
    }
}

$user = new UserAccount("Alice", "SecOps Architect");
echo $user->getInfo() . "\n";

// PHP 8.4 style calculations & match logic
$access_level = match ($user->role) {
    'Admin', 'SecOps Architect' => 'FULL_ROOT_ACCESS',
    'Developer' => 'WRITE_ACCESS',
    default => 'READ_ONLY'
};

echo "Access Level Granted: " . $access_level . "\n";

$sum = 0;
for ($i = 1; $i <= 5; $i++) {
    $sum += ($i * 10);
}
echo "Calculated Benchmark Value: " . $sum . "\n";
echo "--- ✅ Protection & Execution Successful! ---\n";
PHP;

echo "1. Encrypting raw PHP 8.4 code with Kage...\n";
$encrypted_base64 = kage_encrypt_c($source_code, $key);
$kage_file = __DIR__ . '/demo_output.kage';
file_put_contents($kage_file, base64_decode($encrypted_base64));
echo "   Saved encrypted payload to: demo_output.kage (" . filesize($kage_file) . " bytes)\n\n";

echo "2. Inspecting first 16 bytes of encrypted payload (Header + Magic):\n   ";
$handle = fopen($kage_file, 'rb');
$header = fread($handle, 16);
fclose($handle);
echo bin2hex($header) . "\n\n";

echo "3. Including encrypted payload transparently (zend_compile_file interceptor):\n";
echo "--------------------------------------------------------\n";
include $kage_file;
echo "--------------------------------------------------------\n\n";

// Cleanup
@unlink($kage_file);
echo "Cleaned up temporary files.\n";
