<?php

// This is your original PHP code.
// It will be encrypted by Kage/encoder.php

function greet($name) {
    echo "Hello, " . $name . "!\n";
}

greet("World");

class MyClass {
    public function __construct() {
        echo "MyClass instance created.\n";
    }
}

new MyClass();

echo "Original code executed successfully.\n";

?> 