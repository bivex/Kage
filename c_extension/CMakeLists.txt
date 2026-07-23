cmake_minimum_required(VERSION 3.16)
project(kage LANGUAGES C)

# Modern CMake policies
cmake_policy(SET CMP0074 NEW)  # find_package uses <PackageName>_ROOT variables

# --- Options ---

option(BUILD_TESTS "Build test suite" OFF)
option(KAGE_DEBUG "Enable debug logging" OFF)
option(KAGE_COVERAGE "Enable code coverage" OFF)

# --- Find Dependencies ---

# PHP (prefer pkg-config, fallback to php-config)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PHP QUIET php)
endif()

if(NOT PHP_FOUND)
    find_program(PHP_CONFIG php-config)
    if(PHP_CONFIG)
        execute_process(
            COMMAND ${PHP_CONFIG} --include-dir
            OUTPUT_VARIABLE PHP_INCLUDE_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        execute_process(
            COMMAND ${PHP_CONFIG} --extension-dir
            OUTPUT_VARIABLE PHP_EXTENSION_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        execute_process(
            COMMAND ${PHP_CONFIG} --ini-dir
            OUTPUT_VARIABLE PHP_INI_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    else()
        message(FATAL_ERROR "php-config not found. Install PHP development tools.")
    endif()
else()
    set(PHP_INCLUDE_DIR ${PHP_INCLUDE_DIRS})
    # Derive extension/ini dirs from PHP_ROOT or use defaults
    if(NOT DEFINED PHP_EXTENSION_DIR)
        set(PHP_EXTENSION_DIR "${PHP_LIBDIR}/php/extensions/no-debug-non-zts-${PHP_MAJOR_VERSION}${PHP_MINOR_VERSION}")
    endif()
    if(NOT DEFINED PHP_INI_DIR)
        set(PHP_INI_DIR "${PHP_ROOT}/etc/php/${PHP_MAJOR_VERSION}.${PHP_MINOR_VERSION}")
    endif()
endif()

# libsodium via PkgConfig (required)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# --- Source Files ---

set(SOURCES
    src/core/kage.c
    src/core/kage_context.c
    src/core/kage_memory.c
    src/core/kage_config.c
    src/crypto/bytecode_crypto.c
    src/crypto/crypto.c
    src/crypto/base64.c
    src/vm/kage_opcode_map.c
)

# --- PHP Extension Target ---

add_library(${PROJECT_NAME} SHARED ${SOURCES})

# Modern target properties
set_target_properties(${PROJECT_NAME} PROPERTIES
    PREFIX ""
    OUTPUT_NAME "${PROJECT_NAME}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)

# Include directories — SYSTEM for external deps
target_include_directories(${PROJECT_NAME}
    SYSTEM PRIVATE
        ${PHP_INCLUDE_DIR}
        ${PHP_INCLUDE_DIR}/main
        ${PHP_INCLUDE_DIR}/Zend
        ${PHP_INCLUDE_DIR}/TSRM
        ${SODIUM_INCLUDE_DIRS}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/core
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto
        ${CMAKE_CURRENT_SOURCE_DIR}/src/vm
)

# Compile definitions
target_compile_definitions(${PROJECT_NAME}
    PRIVATE
        COMPILE_DL_KAGE
        ZEND_ENABLE_STATIC_TSRMLS_CACHE=1
        PHP_EXTENSION
        HAVE_CONFIG_H
        $<$<CONFIG:DEBUG>:KAGE_DEBUG>
)

# Compile options
target_compile_options(${PROJECT_NAME}
    PRIVATE
        -Wall
        -Wextra
        -Wno-unused-parameter
)

if(KAGE_COVERAGE)
    target_compile_options(${PROJECT_NAME} PRIVATE -fprofile-arcs -ftest-coverage --coverage)
    target_link_options(${PROJECT_NAME} PRIVATE --coverage)
endif()

# Link libraries
target_link_libraries(${PROJECT_NAME}
    PRIVATE
        ${SODIUM_LIBRARIES}
)

# Link directories for sodium (if needed)
if(SODIUM_LIBRARY_DIRS)
    target_link_directories(${PROJECT_NAME} PRIVATE ${SODIUM_LIBRARY_DIRS})
endif()

# macOS: allow unresolved symbols from PHP runtime
if(APPLE)
    target_link_options(${PROJECT_NAME} PRIVATE "-undefined" "dynamic_lookup")
endif()

# --- Installation ---

install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION ${PHP_EXTENSION_DIR}
    RUNTIME DESTINATION ${PHP_EXTENSION_DIR}
)

# Generate INI from template
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/kage.ini.in
    ${CMAKE_BINARY_DIR}/kage.ini
    @ONLY
)

install(FILES ${CMAKE_BINARY_DIR}/kage.ini
    DESTINATION ${PHP_INI_DIR}
)

# --- Testing (optional) ---

if(BUILD_TESTS)
    enable_testing()
    # Add test targets here if needed
endif()

# --- Summary ---

message(STATUS "PHP extension: ${PROJECT_NAME}")
message(STATUS "  Extension dir: ${PHP_EXTENSION_DIR}")
message(STATUS "  INI dir: ${PHP_INI_DIR}")
message(STATUS "  Include dir: ${PHP_INCLUDE_DIR}")
message(STATUS "  Sodium: ${SODIUM_LIBRARIES}")
