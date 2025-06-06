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
    print_message "Installing extension..." "$YELLOW"

    # Remove existing extension if it exists
    if [ -f "$PHP_EXTENSION_DIR/kage.so" ]; then
        print_message "Removing existing kage.so..." "$YELLOW"
        sudo rm -f "$PHP_EXTENSION_DIR/kage.so"
    fi

    print_message "Copying kage.so to $PHP_EXTENSION_DIR/" "$YELLOW"
    if ! sudo cp kage.so "$PHP_EXTENSION_DIR/"; then
        print_message "Error: Failed to copy kage.so to $PHP_EXTENSION_DIR/" "$RED"
        exit 1
    fi

    print_message "Setting permissions for $PHP_EXTENSION_DIR/kage.so..." "$YELLOW"
    if ! sudo chmod 644 "$PHP_EXTENSION_DIR/kage.so"; then
        print_message "Error: Failed to set permissions for $PHP_EXTENSION_DIR/kage.so" "$RED"
        exit 1
    fi

    # Create mods-available directory if it doesn't exist
    MODS_AVAILABLE_DIR="/etc/php/$PHP_VERSION/mods-available"
    if [ ! -d "$MODS_AVAILABLE_DIR" ]; then
        print_message "Creating mods-available directory..." "$YELLOW"
        sudo mkdir -p "$MODS_AVAILABLE_DIR"
    fi

    # Create the mods-available ini file
    MODS_AVAILABLE_INI="$MODS_AVAILABLE_DIR/kage.ini"
    print_message "Creating mods-available ini file at $MODS_AVAILABLE_INI..." "$YELLOW"
    echo "extension=kage.so" | sudo tee "$MODS_AVAILABLE_INI" > /dev/null # Suppress tee output
    sudo chmod 644 "$MODS_AVAILABLE_INI"

    # Create PHP configuration directory if it doesn't exist
    PHP_CONF_DIR="/etc/php/$PHP_VERSION/cli/conf.d"
    if [ ! -d "$PHP_CONF_DIR" ]; then
        print_message "Creating PHP configuration directory..." "$YELLOW"
        sudo mkdir -p "$PHP_CONF_DIR"
    fi

    # Create symbolic link in conf.d
    print_message "Creating symbolic link in conf.d..." "$YELLOW"
    sudo ln -sf "$MODS_AVAILABLE_INI" "$PHP_CONF_DIR/20-kage.ini"
}

verify_php_extension() {
    print_message "Verifying installation..." "$YELLOW"
    TEST_FILE=$(mktemp)
    cat > "$TEST_FILE" << EOF
<?php
if (extension_loaded('kage')) {
    echo "Kage extension is loaded\n";
    echo "Version: " . phpversion('kage') . "\n";
} else {
    echo "Kage extension is NOT loaded\n";
    echo "Loaded extensions:\n";
    print_r(get_loaded_extensions());
    echo "\nPHP configuration:\n";
    echo "extension_dir: " . ini_get('extension_dir') . "\n";
    echo "Loaded configuration file: " . php_ini_loaded_file() . "\n";
    echo "\nChecking extension file:\n";
    \$ext_file = ini_get('extension_dir') . '/kage.so';
    echo "Extension file exists: " . (file_exists(\$ext_file) ? 'Yes' : 'No') . "\n";
    if (file_exists(\$ext_file)) {
        echo "Extension file permissions: " . substr(sprintf('%o', fileperms(\$ext_file)), -4) . "\n";
        echo "Extension file type: " . mime_content_type(\$ext_file) . "\n";
        echo "Extension file size: " . filesize(\$ext_file) . " bytes\n";
    }
}
EOF

    PHP_TEST_OUTPUT=$(php "$TEST_FILE" 2>&1) # Capture all output, including stderr

    if echo "$PHP_TEST_OUTPUT" | grep -q "Kage extension is loaded"; then
        print_message "Kage extension successfully installed and enabled!" "$GREEN"
        echo "$PHP_TEST_OUTPUT" # Print success output too
    else
        print_message "Error: Extension installation verification failed" "$RED"
        echo "$PHP_TEST_OUTPUT" # Print full PHP output for debugging
        exit 1
    fi
    rm -f "$TEST_FILE"
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