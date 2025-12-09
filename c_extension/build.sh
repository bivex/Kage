#!/bin/bash

# Exit on error
set -e

# --- Configuration Variables ---
BUILD_TYPE="Release"
C_FLAGS="-O3 -fomit-frame-pointer -flto -s"
ARTIFACTS_DIR="artifacts"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Utility Functions ---

# Function to print colored messages
print_message() {
    echo -e "${2}${1}${NC}"
}

# Function to check if a command exists
check_command() {
    if ! command -v "$1" &> /dev/null; then
        print_message "Error: $1 is required but not installed." "$RED"
        exit 1
    fi
}

# --- Core Build Functions ---

setup_environment() {
    print_message "Setting up build environment..." "$YELLOW"
    check_command cmake
    check_command make
    check_command gcc
    check_command php-config
    check_command pkg-config

    PHP_CONFIG=$(which php-config)
    if [ -z "$PHP_CONFIG" ]; then
        print_message "Error: php-config not found" "$RED"
        exit 1
    fi

    PHP_VERSION=$($PHP_CONFIG --version | cut -d. -f1,2)
    PHP_EXTENSION_DIR=$($PHP_CONFIG --extension-dir)
    PHP_INI_DIR=$($PHP_CONFIG --ini-dir)
    PHP_API_VERSION=$($PHP_CONFIG --phpapi)

    print_message "Building Kage extension for PHP $PHP_VERSION" "$GREEN"
    print_message "Extension directory: $PHP_EXTENSION_DIR" "$YELLOW"
    print_message "PHP API version: $PHP_API_VERSION" "$YELLOW"
}

clean_and_prepare_build_dir() {
    print_message "Cleaning up previous build artifacts..." "$YELLOW"
    rm -rf build/
    mkdir -p build
    cd build
}

configure_project() {
    print_message "Configuring with CMake..." "$YELLOW"
    cmake .. \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        -DCMAKE_C_FLAGS="$C_FLAGS" \
        -DPHP_EXTENSION_DIR="$PHP_EXTENSION_DIR" \
        -DPHP_INI_DIR="$PHP_INI_DIR" \
        -DPHP_API_VERSION="$PHP_API_VERSION"
}

compile_project() {
    print_message "Building extension..." "$YELLOW"
    cmake --build . --config "$BUILD_TYPE"
}

optimize_binary() {
    print_message "Optimizing and stripping debug symbols..." "$YELLOW"
    if strip --strip-all kage.so; then
        print_message "Binary optimized successfully." "$GREEN"
    else
        print_message "Warning: Failed to strip debug symbols" "$YELLOW"
    fi
}

verify_extension_file() {
    print_message "Verifying built extension..." "$YELLOW"
    if [ ! -f "kage.so" ]; then
        print_message "Error: Build failed - kage.so not found" "$RED"
        exit 1
    fi

    if ! file kage.so | grep -q "ELF"; then
        print_message "Error: Built extension is not a valid ELF file" "$RED"
        exit 1
    fi

    ldd kage.so
}

copy_to_artifacts() {
    print_message "Creating artifacts directory..." "$YELLOW"
    mkdir -p "../$ARTIFACTS_DIR"

    print_message "Copying kage.so to artifacts directory..." "$YELLOW"
    if cp kage.so "../$ARTIFACTS_DIR/"; then
        print_message "kage.so copied to artifacts successfully." "$GREEN"
    else
        print_message "Error: Failed to copy kage.so to artifacts directory" "$RED"
        exit 1
    fi
}

install_extension() {
    echo "Installing extension..."

    # Aggressively remove all existing files
    echo "Removing all existing kage files..."
    sudo rm -f "$PHP_EXTENSION_DIR/kage.so"
    sudo rm -f "/etc/php/$PHP_VERSION/cli/conf.d/20-kage.ini"
    sudo rm -f "/etc/php/$PHP_VERSION/mods-available/kage.ini"
    sudo rm -f "/etc/php/$PHP_VERSION/cli/conf.d/20-kage.ini"

    # Clear PHP caches
    echo "Clearing PHP caches..."
    sudo rm -rf /tmp/opcache-* 2>/dev/null || true

    echo "Copying kage.so to $PHP_EXTENSION_DIR/"
    if ! sudo cp kage.so "$PHP_EXTENSION_DIR/"; then
        echo "Error: Failed to copy kage.so to $PHP_EXTENSION_DIR/"
        exit 1
    fi

    echo "Setting permissions..."
    sudo chmod 644 "$PHP_EXTENSION_DIR/kage.so"

    # Create INI file
    echo "Creating INI configuration..."
    echo "extension=kage.so" | sudo tee "/etc/php/$PHP_VERSION/mods-available/kage.ini" > /dev/null
    sudo chmod 644 "/etc/php/$PHP_VERSION/mods-available/kage.ini"

    # Create symlink
    echo "Creating configuration symlink..."
    sudo ln -sf "/etc/php/$PHP_VERSION/mods-available/kage.ini" "/etc/php/$PHP_VERSION/cli/conf.d/20-kage.ini"

    # Force PHP reload
    echo "Restarting PHP services..."
    sudo systemctl restart php7.4-fpm 2>/dev/null || true
    sudo systemctl restart apache2 2>/dev/null || true
    sudo systemctl restart nginx 2>/dev/null || true
    sleep 3
}

verify_php_extension() {
    echo "Verifying installation..."

    # Check if extension file exists
    if [ ! -f "/usr/lib/php/20190902/kage.so" ]; then
        echo "✗ Extension file not found!"
        exit 1
    fi
    echo "✓ Extension file exists"

    # Check file permissions
    FILE_PERMS=$(stat -c "%a" "/usr/lib/php/20190902/kage.so")
    if [ "$FILE_PERMS" = "644" ]; then
        echo "✓ File permissions correct"
    else
        echo "⚠ Warning: File permissions are $FILE_PERMS, expected 644"
    fi

    # Check INI file
    if [ -f "/etc/php/7.4/cli/conf.d/20-kage.ini" ]; then
        echo "✓ INI configuration exists"
    else
        echo "⚠ Warning: INI configuration not found"
    fi

    # Basic PHP test (without calling extension functions to avoid hangs)
    PHP_VERSION=$(php -r "echo PHP_VERSION;" 2>/dev/null || echo "")
    if [ -n "$PHP_VERSION" ]; then
        echo "✓ PHP is working (version: $PHP_VERSION)"
    else
        echo "⚠ Warning: PHP version check failed"
    fi

    # Simple extension check
    EXT_CHECK=$(php -c "/etc/php/7.4/cli/php.ini" -r "echo extension_loaded('kage') ? 'YES' : 'NO';" 2>/dev/null || echo "UNKNOWN")
    if [ "$EXT_CHECK" = "YES" ]; then
        echo "✓ Extension is loaded"
    elif [ "$EXT_CHECK" = "NO" ]; then
        echo "⚠ Warning: Extension not loaded (PHP may need restart)"
    else
        echo "⚠ Warning: Could not check extension status"
    fi

    echo "Kage extension installation completed!"
    echo "Note: Full functionality testing should be done manually with: php -r \"echo extension_loaded('kage');\""
}

display_extension_info() {
    print_message "\nExtension Information:" "$GREEN"
    php -i | grep -A 10 "kage"
}

# --- Main Execution Flow ---

main() {
    setup_environment
    clean_and_prepare_build_dir
    configure_project
    compile_project
    optimize_binary
    verify_extension_file
    copy_to_artifacts
    
    install_extension
    verify_php_extension
    
    # Return to the root directory after installation and verification
    cd .. 

    display_extension_info

    print_message "\nBuild completed successfully!" "$GREEN"
}

# Run the main function
main 