<?php
$config = include 'config.kage';
require_once 'functions.kage';

$hwid = kage_get_machine_id();
?>
<!DOCTYPE html>
<html>
<head>
    <title>Kage Enterprise Dashboard</title>
    <style>
        body { background: #0f0f0f; color: #00ff00; font-family: 'Courier New', monospace; padding: 50px; }
        .box { border: 1px solid #00ff00; padding: 20px; box-shadow: 0 0 15px #00ff00; }
        h1 { border-bottom: 2px solid #00ff00; padding-bottom: 10px; }
        .secret { color: #ff0000; }
        .status { font-weight: bold; background: #004400; padding: 5px; }
    </style>
</head>
<body>
    <div class="box">
        <h1>KAGE SECURITY CORE v2.0</h1>
        <p>Status: <span class="status"><?php echo get_security_status(); ?></span></p>
        <hr>
        <h3>Environment Binding:</h3>
        <p>Machine HWID: <?php echo $hwid; ?></p>
        <p>Loaded Domain: <?php echo $_SERVER['HTTP_HOST'] ?? 'localhost'; ?></p>
        <hr>
        <h3>Protected Data (from config.kage):</h3>
        <ul>
            <li>Security Level: <?php echo $config['security_level']; ?></li>
            <li>DB Password: <span class="secret">[ENCRYPTED_IN_BYTECODE]</span> (Internal: <?php echo substr($config['db_password'], 0, 5); ?>...)</li>
            <li>Logic Integrity: <?php echo calculate_risk($hwid); ?></li>
        </ul>
        <p style="color: #666; font-size: 0.8em; margin-top: 30px;">
            Note: All PHP files on this server are stored as .kage (Zend Bytecode). 
            Source code is 100% invisible.
        </p>
    </div>
</body>
</html>
