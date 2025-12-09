# Kage
[![Forged with 🐍](https://a.b-b.top/badge.svg?repo=Kage&label=Forged&background_color=4caf50&background_color2=66bb6a&utm_source=github&utm_medium=readme&utm_campaign=badge)](https://a.b-b.top)

## Overview

Kage is a comprehensive PHP code encryption and protection tool designed to secure your PHP source code through advanced encryption techniques and provide a secure runtime environment for execution. This tool is essential for PHP developers and organizations that need to protect their intellectual property while maintaining application functionality.

### Purpose and Benefits

Kage addresses the critical need for PHP code protection in scenarios where source code security is paramount:

- **Intellectual Property Protection**: Encrypt sensitive business logic and algorithms
- **License Compliance**: Prevent unauthorized code modification and redistribution
- **Runtime Security**: Execute encrypted code in a secure, sandboxed environment
- **Performance Optimization**: Optional C extension for enhanced encryption/decryption performance
- **Deployment Flexibility**: Support for both traditional hosting and cloud environments

### Key Features

- **Advanced Encryption**: Military-grade encryption algorithms for PHP source code
- **Self-Decrypting Files**: Generate executable files that decrypt themselves at runtime
- **Secure Execution Environment**: Isolated runtime preventing code tampering
- **C Extension Support**: High-performance native extension for demanding applications
- **Comprehensive Testing**: Full test suite ensuring reliability and security

### Intended Audience

This documentation is intended for:
- PHP developers seeking to protect their source code
- System administrators deploying encrypted PHP applications
- DevOps engineers integrating Kage into CI/CD pipelines
- Security professionals implementing code protection strategies

## Table of Contents

- [Overview](#overview)
  - [Purpose and Benefits](#purpose-and-benefits)
  - [Key Features](#key-features)
  - [Intended Audience](#intended-audience)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Building](#building)
- [Usage](#usage)
  - [Basic Usage](#basic-usage)
  - [Creating Self-Decrypting Files](#creating-self-decrypting-files)
  - [Advanced Usage Examples](#advanced-usage-examples)
- [API Reference](#api-reference)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)
- [Security](#security)
- [Support](#support)

## Project Structure

```
Kage/
├── src/                    # Source code files
│   ├── encoder.php        # Main encoder implementation
│   ├── source.php         # Source code handling
│   ├── php_encoder.php    # PHP-specific encoding utilities
│   ├── decrypt_string.php # String decryption utilities
│   └── create_self_decrypt.php # Self-decrypting file generator
├── tests/                  # Test files
│   ├── test_source.php
│   ├── test_php_encoder.php
│   ├── test_kage_extension.php
│   ├── test_source_encrypted.php
│   ├── test_ast.php
│   └── test_vm.php
├── logs/                   # Log files
│   ├── php_errors.log
│   └── kage_extension_errors.log
├── config/                 # Configuration files
│   └── php.ini
├── build/                  # Build artifacts
│   └── debug_raw_file_content.bin
├── docs/                   # Documentation
├── c_extension/           # C extension for enhanced performance
└── artifacts/             # Additional build artifacts
```

## Features

- PHP source code encryption
- Self-decrypting file generation
- Secure runtime execution
- C extension support for enhanced performance
- Comprehensive test suite

## Requirements

- PHP 7.4 or higher
- PHP C extension (optional, for enhanced performance)

## Installation

### Prerequisites

Before installing Kage, ensure your system meets the following requirements:
- **Operating System**: Linux (tested on Debian/Ubuntu-based systems)
- **PHP Version**: PHP 7.4 or higher (PHP 8.0+ recommended for full compatibility)
- **Build Tools**: GCC compiler, Make, CMake, and development libraries
- **Required Libraries**:
  - `libsodium-dev` (for cryptographic operations)
  - `php7.4-dev` or equivalent for your PHP version (for building the C extension)
- **System Access**: Administrative privileges (sudo) for system-wide installation
- **Disk Space**: At least 100 MB free space for build artifacts and installation

### Concept of Operations

Kage operates as a PHP extension that provides secure code encryption and runtime execution capabilities. The installation process builds a native C extension that integrates with PHP's Zend Engine, enabling high-performance encryption/decryption operations. The system supports both CLI and web server environments, with automatic loading of the extension via PHP's configuration files.

### Step-by-Step Installation

Follow these procedures to install Kage on your system:

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/bivex/Kage.git
   cd kage
   ```
   This downloads the complete Kage source code and documentation.

2. **Install System Dependencies:**
   ```bash
   sudo apt update
   sudo apt install -y php7.4-dev libsodium-dev build-essential cmake pkg-config
   ```
   These packages provide the necessary development tools and libraries for building the C extension. If using a different PHP version, replace `php7.4-dev` with the appropriate version (e.g., `php8.0-dev`).

3. **Navigate to the C Extension Directory:**
   ```bash
   cd c_extension
   ```

4. **Build and Install the Extension:**
   ```bash
   ./build.sh
   ```
   This automated script performs the following operations:
   - Verifies system requirements
   - Configures the build environment using CMake
   - Compiles the C extension
   - Installs the extension to PHP's extension directory
   - Creates necessary configuration files
   - Verifies successful installation

5. **Verify Installation:**
   ```bash
   php -m | grep kage
   ```
   Expected output: `kage`
   ```bash
   php -i | grep -A 5 "kage"
   ```
   This should display extension information including version and configuration.

6. **Test the Installation:**
   ```bash
   php test_extension.php
   ```
   Run the provided test script to ensure encryption and decryption functions operate correctly.

### Post-Installation Configuration

After successful installation:

1. **PHP Configuration**: The extension is automatically configured in `/etc/php/7.4/cli/conf.d/20-kage.ini`. For web servers, restart your web server (e.g., `sudo systemctl restart apache2` or `sudo systemctl restart nginx`).

2. **Memory and Performance Tuning**: Adjust PHP settings as needed:
   ```ini
   memory_limit = 256M
   max_execution_time = 300
   ```

3. **Security Considerations**: Ensure the extension file permissions are secure:
   ```bash
   ls -la /usr/lib/php/20190902/kage.so
   ```
   Expected permissions: `-rw-r--r--`

### Troubleshooting Installation Issues

- **Build Failures**: Ensure all development packages are installed. Check `/var/www/kage/c_extension/debug.log` for detailed error messages.
- **Extension Not Loading**: Verify PHP configuration files and restart PHP/ web server.
- **Permission Errors**: Run build commands with appropriate privileges.
- **Compatibility Issues**: For PHP versions other than 7.4, the source code may require minor adjustments to function signatures.

### Information for Uninstallation

To remove Kage from your system:

1. Remove the extension file: `sudo rm /usr/lib/php/20190902/kage.so`
2. Remove configuration: `sudo rm /etc/php/7.4/mods-available/kage.ini /etc/php/7.4/cli/conf.d/20-kage.ini`
3. Restart PHP/web server
4. Remove source directory if desired: `rm -rf /var/www/kage`

**Note**: Uninstallation does not affect encrypted code that has already been deployed, as decryption keys are managed separately.

## Configuration

### PHP Configuration

Kage requires specific PHP settings for optimal performance and security. The provided `config/php.ini` template includes recommended settings:

```ini
; Kage Recommended PHP Configuration
memory_limit = 256M
max_execution_time = 300
upload_max_filesize = 50M
post_max_size = 50M

; Required extensions
extension=mbstring
extension=openssl
extension=json

; Security settings
expose_php = Off
display_errors = Off
log_errors = On
error_log = /var/log/php/kage_errors.log
```

### Key Configuration Parameters

- **Memory Limit**: Set to at least 256MB for processing large codebases
- **Execution Time**: Increase timeout for complex encryption operations
- **Security Settings**: Disable `expose_php` and `display_errors` in production
- **Error Logging**: Configure proper error logging for debugging

### Environment Variables

Kage supports the following environment variables:

- `KAGE_ENCRYPTION_KEY`: Custom encryption key (auto-generated if not set)
- `KAGE_LOG_LEVEL`: Logging verbosity (DEBUG, INFO, WARN, ERROR)
- `KAGE_CACHE_DIR`: Directory for temporary cache files
- `KAGE_MAX_FILE_SIZE`: Maximum file size for processing (default: 10MB)

### Runtime Configuration

Additional runtime options can be configured programmatically:

```php
$config = [
    'encryption_algorithm' => 'AES-256-GCM',
    'key_length' => 32,
    'compression' => true,
    'obfuscation_level' => 'high'
];

$encoder = new Encoder($config);
```

## Building

The project includes a C extension for enhanced performance. To build it, navigate to the `c_extension` directory and use the provided shell scripts.

1.  **Build the C Extension:**
    ```bash
    cd c_extension
    ./build.sh
    ```
    This script will compile the C extension.

2.  **Clean Build Artifacts:**
    ```bash
    cd c_extension
    ./cleanup.sh
    ```
    This script will remove the build artifacts generated by `build.sh`.

## Usage

### Basic Usage

```php
require_once 'src/encoder.php';

// Create an instance of the encoder
$encoder = new Encoder();

// Encrypt your PHP code
$encrypted = $encoder->encrypt($sourceCode);

// Save the encrypted code
file_put_contents('encrypted.php', $encrypted);
```

### Creating Self-Decrypting Files

```php
require_once 'src/create_self_decrypt.php';

// Create a self-decrypting file
$selfDecrypt = new SelfDecrypt();
$selfDecrypt->create('source.php', 'output.php');
```

### Advanced Usage Examples

#### Batch Processing Multiple Files

```php
require_once 'src/encoder.php';

$encoder = new Encoder();
$files = ['class1.php', 'class2.php', 'functions.php'];

foreach ($files as $file) {
    try {
        $sourceCode = file_get_contents($file);
        $encrypted = $encoder->encrypt($sourceCode);

        $encryptedFile = $file . '.enc';
        file_put_contents($encryptedFile, $encrypted);

        echo "Encrypted: $file → $encryptedFile\n";
    } catch (Exception $e) {
        echo "Error encrypting $file: " . $e->getMessage() . "\n";
    }
}
```

#### Custom Encryption Configuration

```php
require_once 'src/encoder.php';

$config = [
    'algorithm' => 'AES-256-GCM',
    'key_length' => 32,
    'compression' => true,
    'obfuscation' => 'high'
];

$encoder = new Encoder($config);

$sourceCode = '<?php echo "Hello, Encrypted World!"; ?>';
$encrypted = $encoder->encrypt($sourceCode);
```

#### Error Handling and Validation

```php
require_once 'src/encoder.php';

function encryptFile($inputFile, $outputFile) {
    if (!file_exists($inputFile)) {
        throw new Exception("Input file does not exist: $inputFile");
    }

    if (!is_readable($inputFile)) {
        throw new Exception("Input file is not readable: $inputFile");
    }

    $sourceCode = file_get_contents($inputFile);

    // Validate PHP syntax before encryption
    if (!validatePHPSyntax($sourceCode)) {
        throw new Exception("Invalid PHP syntax in: $inputFile");
    }

    $encoder = new Encoder();
    $encrypted = $encoder->encrypt($sourceCode);

    if (file_put_contents($outputFile, $encrypted) === false) {
        throw new Exception("Failed to write encrypted file: $outputFile");
    }

    return true;
}

function validatePHPSyntax($code) {
    return @php_check_syntax($code) !== false;
}

// Usage
try {
    encryptFile('myapp.php', 'myapp.enc.php');
    echo "Encryption successful!\n";
} catch (Exception $e) {
    echo "Encryption failed: " . $e->getMessage() . "\n";
}
```

## API Reference

For detailed API documentation, see the following resources:

- **Class Reference**: Complete documentation of all classes and methods
- **Configuration Guide**: Advanced configuration options and parameters
- **Extension API**: C extension interfaces and performance optimizations

API documentation is available in the `docs/` directory and online at [project documentation site].

## Troubleshooting

### Common Issues and Solutions

#### "Class 'Encoder' not found" Error

**Problem**: PHP cannot find the Kage encoder class.

**Solutions**:
1. Verify the correct path in `require_once` statement
2. Check that the file exists: `ls -la src/encoder.php`
3. Ensure PHP has read permissions on the src directory
4. Add the project root to PHP's include path

#### Memory Exhaustion During Encryption

**Problem**: Large files cause "Allowed memory size exhausted" errors.

**Solutions**:
1. Increase PHP memory limit: `ini_set('memory_limit', '512M');`
2. Process files in smaller chunks
3. Use streaming encryption for very large files
4. Check available system memory

#### C Extension Build Failures

**Problem**: The C extension fails to compile.

**Solutions**:
1. Install build dependencies: `apt-get install build-essential php-dev`
2. Check compiler errors in build logs
3. Verify PHP development headers match your PHP version
4. Use the fallback PHP-only implementation

#### Encrypted Files Won't Execute

**Problem**: Encrypted PHP files produce errors when executed.

**Solutions**:
1. Ensure runtime decryption is enabled
2. Check encryption key consistency
3. Verify PHP version compatibility (7.4+)
4. Check file permissions and ownership

#### Performance Issues

**Problem**: Encryption/decryption is too slow.

**Solutions**:
1. Install and enable the C extension
2. Use faster encryption algorithms where security allows
3. Implement caching for repeated operations
4. Optimize file I/O operations

### Debug Mode

Enable debug logging for troubleshooting:

```php
ini_set('display_errors', 1);
ini_set('error_reporting', E_ALL);

// Enable Kage debug logging
putenv('KAGE_LOG_LEVEL=DEBUG');
putenv('KAGE_LOG_FILE=/var/log/kage_debug.log');
```

### Getting Help

If you encounter issues not covered here:

1. Check the error logs in `logs/kage_extension_errors.log`
2. Run the test suite to verify installation: `php tests/test_php_encoder.php`
3. Review the API documentation in `docs/`
4. Open an issue on GitHub with detailed error information

## FAQ

### General Questions

**Q: Is Kage compatible with all PHP frameworks?**
A: Kage works with any PHP code. However, some frameworks may require special handling for encrypted files. Check the documentation for framework-specific integration guides.

**Q: How secure is the encryption?**
A: Kage uses industry-standard AES-256-GCM encryption. Security strength depends on key management practices and operational security.

**Q: Can encrypted code be reverse engineered?**
A: While encryption prevents casual access, determined attackers with sufficient resources may attempt reverse engineering. Kage provides multiple layers of protection.

**Q: What's the performance impact?**
A: The C extension minimizes performance overhead. Typical impact is 5-15% for most applications.

### Technical Questions

**Q: Can I encrypt files larger than 10MB?**
A: Yes, but increase memory limits accordingly. Consider streaming encryption for very large files.

**Q: How do I update encrypted code?**
A: Decrypt the original source, make changes, then re-encrypt. Version control your source code, not encrypted versions.

**Q: Is the encryption key stored with the encrypted files?**
A: No. Keys should be managed securely through environment variables or secure key management systems.

**Q: Can I use Kage in production?**
A: Yes, but thoroughly test your specific use case. The C extension is recommended for production deployments.

## Testing

Run the test suite:
```bash
php tests/test_php_encoder.php
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security

If you discover any security related issues, please email security@yourdomain.com instead of using the issue tracker.

## Support

For support, please open an issue in the GitHub repository or contact support@yourdomain.com.
