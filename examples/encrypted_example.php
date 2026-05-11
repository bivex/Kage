<?php
/**
 * ЗАШИФРОВАННЫЙ ПРИМЕР - SELF-DECRYPTING PHP FILE
 *
 * Этот файл содержит зашифрованный PHP код, который расшифровывается и выполняется динамически.
 * В исходном коде файла НЕТ видимого секретного кода!
 */

// Ключ для расшифровки (в реальном приложении храните ключ отдельно и безопасно!)
$encryption_key = '0123456789abcdef0123456789abcdef';

// Зашифрованные данные (PHP код в зашифрованном виде)
$encrypted_data = 'QJT7wnu+/YEGUV6UFTQ6NOA/Bqm93+PCp9p7muoxVj3jR/JQTzZCg7pTMJ8nqBdKW0aIjUwebKmYonq2NZNuU4oezgTYBkRus/N2uSKZYh91jjeqNkSQaHrHTFh4ozvCF7HRdkB6jhCFuIsFRADBekbJew8QGKi+bF+vILigh85zb43N8OqH/6mWB+Ody54+uqSOPr42oyGA/X7a8DQQd+ByGArPFIQfXUc0eI2F53VjEbFd4JXKQTKy4qa8ghFPo2WftNjUR+edtwEv6fvpoWuglVN7+pdRDbRCOB/PHJgaKXQ16dgnyTaJEanb+0DzNBUjXLAtg1tFtGvCRHdgGIrAu0ZQCfOR8HWsRMyCrm1hurz0bz+wvcChU5k44zTk+h3/Y/adew+6QdiRHdd4HBL5xqeNPivGh7KDItmgsL9QBPTTJQRZFUcnk2xMfPTW01JpMSEHid3/B1cHidMys7MmhpK7n44VN9de+IIa86uaQ+KZoEfzWxBxl80b/ejAPYvDHNpclg/oOeP1p/v6WxNPkcDqKPOrB4fmnxOmtOLJLA/RyUuRWwe6OOwb9QHkL1l2gEH7MuTBHb1DP6c9BgFOFFtTagEk+IIJHrvKx8EW6GkqUGsOiABEtDc3CUdd8oU4dNL3hKZlLoZkcJfafHPhixVH7Lo/a+DmoFPEkMlYCFW81tHLpuffU6VZAAOgSB4ylKMwHTQfApnfspdJ1lbPFpNncOLzb+GkC5q8HA4RPEL+RX7JMwDWPXgfN5YtXD/9Fg80RFCLyEjcholjgFOl5/ougJYAUJirmWi03OCuIZQ1k28U9YfiKZauUk6fYeBOkI+b/MdC16+t8gOpaPXLFtfd+IWBBMmdv/2HH8AQXBYVYPinIyeU94nDkBueP1QvCjo0aOnqAo3baNUmu/KBIHH9PvYYtHjVdvEbtHGlTpVBmtyC12UAFa7SpNOx63HtmFnUt3FGxxEofbvxZjViERFP+58qEYJoHWiGzXQb352ZnSHDYwd3BGenLMvD4Ydr+ayx1lY+PS7cEP6HbMxXfl7T5w+8CMGQ8jrKOXIH6NGw31bdFAt9+jH90LepoIMek4R9ScMcX0R9XoTXe/MB7i314MD2vazFZ6Ob2S1Ok4zoxWr8cLwibVelOOou2CggQvYiWmnHjj+jK4w=';

try {
    // Проверяем, загружено ли расширение Kage
    if (!extension_loaded('kage')) {
        throw new Exception("Расширение Kage не загружено. Установите и настройте расширение Kage.");
    }

    // Расшифровываем зашифрованные данные
    $decrypted_code = kage_decrypt_c($encrypted_data, $encryption_key);

    // Очищаем код от PHP тегов перед выполнением
    $code_to_execute = $decrypted_code;
    if (strpos($code_to_execute, '<?php') === 0) {
        $code_to_execute = substr($code_to_execute, 5);
    }
    if (substr($code_to_execute, -2) === '?>') {
        $code_to_execute = substr($code_to_execute, 0, -2);
    }

    // Выполняем очищенный расшифрованный код
    eval(trim($code_to_execute));

} catch (Exception $e) {
    echo "❌ Ошибка при выполнении зашифрованного кода: " . $e->getMessage() . "\n";
    echo "Убедитесь, что расширение Kage правильно установлено и настроено.\n";
}
?>
