<?php
/**
 * Kage + ASGARD-5877 Protected Execution Demo
 */
echo "=========================================================\n";
echo "  KAGE + ASGARD-5877 ENTERPRISE VM PROTECTION DEMO       \n";
echo "=========================================================\n\n";

if (!extension_loaded('kage')) {
    die("[-] Error: Kage extension is not loaded.\n");
}

echo "[+] Kage Extension Version: " . phpversion('kage') . "\n";
echo "[+] Host Fingerprint (HWID): " . kage_get_machine_id() . "\n\n";

$master_key = "0123456789abcdef0123456789abcdef"; // 256-bit key

echo "[*] Step 1: Defining Proprietary PHP Application Logic...\n";
$proprietary_code = <<<'PHP'
<?php
class SecretPaymentEngine {
    private string $merchantId;
    public function __construct(string $id) { $this->merchantId = $id; }
    public function processTransaction(float $amount, string $currency): string {
        $txId = "TX-" . bin2hex(random_bytes(6));
        return sprintf("[OK] Charged %.2f %s for Merchant %s (TxID: %s)", $amount, $currency, $this->merchantId, $txId);
    }
}
$engine = new SecretPaymentEngine("MERCHANT_5877");
echo $engine->processTransaction(99.95, "USD") . PHP_EOL;
PHP;

echo "[*] Step 2: Encrypting via kage_encrypt_c (ChaCha20-Poly1305 + Dynamic ISA)...\n";
$encrypted_b64 = kage_encrypt_c($proprietary_code, $master_key);
echo "[+] Encrypted Payload Length: " . strlen($encrypted_b64) . " bytes\n";
echo "[+] Encrypted Payload Sample: " . substr($encrypted_b64, 0, 80) . "...\n\n";

echo "[*] Step 3: Decrypting in-memory via kage_decrypt_c (ASGARD VBO Protected)...\n";
$decrypted = kage_decrypt_c($encrypted_b64, $master_key);
if (!$decrypted) {
    die("[-] Decryption failed!\n");
}
echo "[+] Decryption succeeded in RAM (Zeroized immediately after use)\n\n";

echo "[*] Step 4: Seamless Execution via .kage File Compilation Hook...\n";
$kage_file = "/tmp/payment_engine.kage";
file_put_contents($kage_file, base64_decode($encrypted_b64));

putenv("KAGE_ENCRYPTION_KEY=" . $master_key);
echo "[*] Including /tmp/payment_engine.kage directly via PHP include statement:\n";
echo "---------------------------------------------------------\n";
include $kage_file;
echo "---------------------------------------------------------\n";
unlink($kage_file);

echo "\n[+] SUCCESS: Protected code executed seamlessly through ASGARD-hardened Zend VM hook!\n";
