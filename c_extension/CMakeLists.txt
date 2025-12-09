cmake_minimum_required(VERSION 3.10)
project(kage VERSION 0.1.0 LANGUAGES C)

# --- Configuration Variables ---
# These variables can be set externally via -DVAR=VALUE when calling cmake
# Defaults are retrieved from php-config

# PHP API version and directories
# Default values are retrieved via execute_process commands below if not provided
if (NOT DEFINED PHP_EXTENSION_DIR)
    execute_process(
        COMMAND php-config --extension-dir
        OUTPUT_VARIABLE PHP_EXTENSION_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

if (NOT DEFINED PHP_INI_DIR)
    execute_process(
        COMMAND php-config --ini-dir
        OUTPUT_VARIABLE PHP_INI_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

if (NOT DEFINED PHP_API_VERSION)
    execute_process(
        COMMAND php-config --phpapi
        OUTPUT_VARIABLE PHP_API_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

# PHP include directory (always derived from php-config)
execute_process(
    COMMAND php-config --include-dir
    OUTPUT_VARIABLE PHP_INCLUDE_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Extension properties
set(EXTENSION_NAME "kage")
set(EXTENSION_VERSION "0.1.0")

# --- Find Dependencies ---

# Find PkgConfig (required for libsodium)
find_package(PkgConfig REQUIRED)

# Find libsodium using PkgConfig
pkg_check_modules(SODIUM REQUIRED libsodium)

# --- Source Files ---

set(SOURCES
    src/kage.c
    src/kage_context.c
    src/kage_memory.c
    src/kage_config.c
    src/bytecode_crypto.c
    src/crypto.c
    src/base64.c
    src/vm.c
    src/ast.c
)

# --- Define PHP Extension Target ---

# Create shared library
add_library(${EXTENSION_NAME} SHARED ${SOURCES})

# Set include directories
target_include_directories(${EXTENSION_NAME} PRIVATE
    ${PHP_INCLUDE_DIR}
    ${PHP_INCLUDE_DIR}/main
    ${PHP_INCLUDE_DIR}/Zend
    ${PHP_INCLUDE_DIR}/TSRM
    ${SODIUM_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Set compile definitions
target_compile_definitions(${EXTENSION_NAME} PRIVATE
    COMPILE_DL_KAGE
    ZEND_ENABLE_STATIC_TSRMLS_CACHE=1
    PHP_EXTENSION
    ZEND_MODULE_API_NO=${PHP_API_VERSION}
    HAVE_CONFIG_H
)

# Set compile options
target_compile_options(${EXTENSION_NAME} PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
)

# Link libraries
target_link_libraries(${EXTENSION_NAME} PRIVATE
    ${SODIUM_LIBRARIES}
)

# Set output properties
set_target_properties(${EXTENSION_NAME} PROPERTIES
    PREFIX ""
    OUTPUT_NAME "${EXTENSION_NAME}"
    # Output to CMAKE_BINARY_DIR so it's easily accessible from build.sh
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

# --- Installation Rules ---

# Install shared library to PHP extension directory
install(TARGETS ${EXTENSION_NAME}
    LIBRARY DESTINATION ${PHP_EXTENSION_DIR}
)

# Create INI file from template
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/kage.ini.in
    ${CMAKE_BINARY_DIR}/kage.ini
    @ONLY
)

# Install INI file to PHP INI directory
install(FILES ${CMAKE_BINARY_DIR}/kage.ini
    DESTINATION ${PHP_INI_DIR}
) 