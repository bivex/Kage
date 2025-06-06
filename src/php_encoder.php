<?php

class PhpEncoder {
    private $key;
    private $debug = true;
    
    public function __construct($key = null) {
        // If no key provided, generate a random one
        $this->key = $key ?? random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    }
    
    public function getKey() {
        return $this->key;
    }
    
    public function encodePhp($phpCode) {
        if (!extension_loaded('kage')) {
            throw new Exception('Kage extension is not loaded');
        }
        
        if ($this->debug) {
            echo "Debug: Encoding PHP code of length " . strlen($phpCode) . " bytes\n";
        }
        
        // Encode the PHP code
        $encoded = kage_encrypt_c($phpCode, $this->key);
        if (empty($encoded)) {
            throw new Exception('Failed to encode PHP code');
        }
        
        if ($this->debug) {
            echo "Debug: Encoded length is " . strlen($encoded) . " bytes\n";
        }
        
        return $encoded;
    }
    
    public function executeEncoded($encodedPhp) {
        if (!extension_loaded('kage')) {
            throw new Exception('Kage extension is not loaded');
        }
        
        if ($this->debug) {
            echo "Debug: Decoding PHP code of length " . strlen($encodedPhp) . " bytes\n";
        }
        
        // Decode the PHP code
        $decoded = kage_decrypt_c($encodedPhp, $this->key);
        if (empty($decoded)) {
            throw new Exception('Failed to decode PHP code');
        }
        
        if ($this->debug) {
            echo "Debug: Decoded length is " . strlen($decoded) . " bytes\n";
            echo "Debug: First 100 chars of decoded code: " . substr($decoded, 0, 100) . "\n";
        }
        
        // Execute the decoded PHP code
        ob_start();
        $result = eval($decoded);
        $output = ob_get_clean();
        
        // Display the output
        echo $output;
        
        if ($this->debug) {
            echo "Debug: Execution completed\n";
        }
        
        return $result;
    }
} 