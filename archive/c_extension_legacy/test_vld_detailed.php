<?php
function calculate($a, $b) {
    if ($a > $b) {
        return $a + $b;
    } else {
        return $a * $b;
    }
}

$result = calculate(10, 5);
echo "Result: " . $result . "\n";
?>
