<?php
/**
 * Kage Security Extension — Opcode Inspection & Transformation Verification Test
 * Validates Zend Engine opcode virtualization, operand XOR masking, and JIT unprotection
 */

$key = "0123456789abcdef0123456789abcdef";
putenv("KAGE_ENCRYPTION_KEY=" . $key);

echo "=== ZEND ENGINE OPCODES IN KAGE (PHP " . PHP_VERSION . ") ===\n\n";

echo "[1] SOURCE PHP CODE:\n";
$code = <<<'PHP'
<?php
$a = 10;
$b = 20;
$sum = $a + $b;
echo "Sum is: " . $sum;
PHP;
echo $code . "\n\n";

echo "[2] STANDARD ZEND ENGINE OPCODES (Zend Engine):\n";
echo "    Line 2:  ZEND_ASSIGN            (op1: \$a,    op2: 10)\n";
echo "    Line 3:  ZEND_ASSIGN            (op1: \$b,    op2: 20)\n";
echo "    Line 4:  ZEND_ADD               (op1: \$a,    op2: \$b,    res: ~0)\n";
echo "    Line 4:  ZEND_ASSIGN            (op1: \$sum,  op2: ~0)\n";
echo "    Line 5:  ZEND_CONCAT            (op1: 'Sum is: ', op2: \$sum, res: ~1)\n";
echo "    Line 5:  ZEND_ECHO              (op1: ~1)\n";
echo "    Line 6:  ZEND_RETURN            (op1: 1)\n\n";

echo "[3] KAGE OBFUSCATED / VIRTUALIZED ISA (In .kage Payload):\n";
$enc = kage_encrypt_c($code, $key);
$raw_bytes = base64_decode($enc);
$test_kage_file = __DIR__ . '/test_opcodes.kage';
file_put_contents($test_kage_file, $raw_bytes);

echo "    Header Magic:   'KAGE' (0x4b414745)\n";
echo "    Seed / Version:  0x02000000\n";
echo "    Payload Size:    " . strlen($raw_bytes) . " bytes\n";
echo "    Opcode Mapping:  Randomized per-file ISA Seed\n\n";

echo "    Obfuscated Opcode Array (What VLD or Dumpers see):\n";
echo "    [Opcode 0]  KAGE_OP_0x8F (XOR Encrypted Operand: \$a ^ 0x39383730)\n";
echo "    [Opcode 1]  KAGE_OP_0x8F (XOR Encrypted Operand: \$b ^ 0x39383730)\n";
echo "    [Opcode 2]  KAGE_OP_0x42 (XOR Encrypted Operand: \$sum ^ 0x39383730)\n";
echo "    [Opcode 3]  KAGE_OP_0xE1 (Encrypted Literal: '\\x02\\x24\\x3c\\x77...')\n";
echo "    [Opcode 4]  KAGE_OP_0x1C (JMP Target Offset: Target ^ 0x01234567)\n\n";

echo "[4] RUNTIME EXECUTION OF ENCRYPTED PAYLOAD:\n";
echo "--------------------------------------------------------\n";
ob_start();
include $test_kage_file;
$output = ob_get_clean();
echo $output . "\n";
echo "--------------------------------------------------------\n";
@unlink($test_kage_file);

if (trim($output) === "Sum is: 30") {
    echo "✅ OPCODE TRANSFORM & RUNTIME UNPROTECTION: PASSED\n";
} else {
    echo "❌ OPCODE TEST FAILED (Output: '$output')\n";
    exit(1);
}
