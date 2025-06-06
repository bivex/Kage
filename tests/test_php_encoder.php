<?php

require_once 'php_encoder.php';

try {
    // Create encoder instance
    $encoder = new PhpEncoder();
    
    // More complex PHP code to encode
    $phpCode = <<<'PHP'
<?php
// Test function
function testFunction() {
    return "Function called successfully!";
}

// Test variables
$testVar = "Test variable";
$testArray = [1, 2, 3, 4, 5];

// Test output
echo "=== Test Output ===\n";
echo "Variable: " . $testVar . "\n";
echo "Array sum: " . array_sum($testArray) . "\n";
echo "Function result: " . testFunction() . "\n";
echo "=== End Test ===\n";

// Return a value
return "Execution completed successfully";
PHP;
    
    // Encode the PHP code
    $encoded = $encoder->encodePhp($phpCode);
    echo "Encoded PHP code:\n" . $encoded . "\n\n";
    
    // Save the key for later use
    $key = base64_encode($encoder->getKey());
    echo "Key (save this for later use): " . $key . "\n\n";
    
    // Execute the encoded PHP code
    echo "Executing encoded PHP code:\n";
    $result = $encoder->executeEncoded($encoded);
    echo "\nExecution result: " . ($result !== false ? $result : "Failed") . "\n";
    
    // Demonstrate loading and executing encoded PHP code with saved key
    echo "\nDemonstrating loading with saved key:\n";
    $newEncoder = new PhpEncoder(base64_decode($key));
    $result = $newEncoder->executeEncoded($encoded);
    echo "\nSecond execution result: " . ($result !== false ? $result : "Failed") . "\n";
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    echo "Stack trace:\n" . $e->getTraceAsString() . "\n";
} 