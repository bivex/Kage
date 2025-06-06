#!/bin/bash

# Exit on error
set -e

# Colors for output (re-define if this script is run standalone)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages (re-define if this script is run standalone)
print_message() {
    echo -e "${2}${1}${NC}"
}

# --- Cleanup Functions ---

cleanup_cmake_artifacts() {
    print_message "Removing CMake build directory and cache..." "$YELLOW"
    # Remove CMake build directory
    if [ -d "build" ]; then
        rm -rf build
    fi

    # Remove CMake cache files
    if [ -f "CMakeCache.txt" ]; then
        rm -f CMakeCache.txt
    fi

    # Remove CMake generated files
    if [ -d "CMakeFiles" ]; then
        rm -rf CMakeFiles
    fi
}

cleanup_compiled_extension() {
    print_message "Removing compiled extension and object files..." "$YELLOW"
    # Remove compiled extension
    if [ -f "kage.so" ]; then
        rm -f kage.so
    fi

    # Remove object files
    find . -name "*.o" -type f -delete
    find . -name "*.lo" -type f -delete
}

cleanup_autotools_artifacts() {
    print_message "Removing autotools generated files (if any)..." "$YELLOW"
    rm -f config.h
    rm -f config.log
    rm -f config.status
    rm -f libtool
    rm -f Makefile
    rm -f Makefile.fragments
    rm -f Makefile.objects
    rm -f run-tests.php
}

cleanup_php_test_files() {
    print_message "Removing PHP extension test files..." "$YELLOW"
    # Remove PHP extension test files
    if [ -f "test.php.bak" ]; then
        rm -f test.php.bak
    fi
}

# --- Main Cleanup Flow ---

main_cleanup() {
    print_message "Starting cleanup..." "$GREEN"
    cleanup_cmake_artifacts
    cleanup_compiled_extension
    cleanup_autotools_artifacts
    cleanup_php_test_files
    print_message "Cleanup complete!" "$GREEN"
}

# Run the main cleanup function
main_cleanup 