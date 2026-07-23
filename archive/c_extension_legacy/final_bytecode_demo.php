<?php
/**
 * Финальная демонстрация: PHP -> Zend Bytecode -> Kage шифрование
 */

class Calculator {
    private $memory = 0;
    
    public function add($x, $y) {
        $result = $x + $y;
        $this->memory = $result;
        return $result;
    }
    
    public function multiply($x, $y) {
        return $x * $y;
    }
    
    public function getMemory() {
        return $this->memory;
    }
}

// Использование класса
$calc = new Calculator();
$sum = $calc->add(10, 20);
$product = $calc->multiply(5, 4);
$memory = $calc->getMemory();

echo "Sum: $sum, Product: $product, Memory: $memory\n";
?>
