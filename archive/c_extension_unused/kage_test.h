/**
 * Kage Unit Test Framework
 *
 * Simple unit testing framework for individual components.
 *
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-12-09
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#ifndef PHP_KAGE_TEST_H
#define PHP_KAGE_TEST_H

#include "config.h"
#include <stdbool.h>
#include <setjmp.h>

// Test result types
typedef enum {
    KAGE_TEST_PASS,
    KAGE_TEST_FAIL,
    KAGE_TEST_SKIP,
    KAGE_TEST_ERROR
} kage_test_result;

// Test function signature
typedef kage_test_result (*kage_test_func)(void);

// Test case structure
typedef struct {
    const char *name;
    const char *description;
    kage_test_func function;
    kage_test_result expected_result;
} kage_test_case;

// Test suite structure
typedef struct {
    const char *name;
    const char *description;
    kage_test_case *tests;
    size_t test_count;
    size_t passed;
    size_t failed;
    size_t skipped;
    size_t errors;
} kage_test_suite;

// Global test context for error handling
typedef struct {
    jmp_buf jump_buffer;
    const char *current_test;
    char error_message[512];
    bool error_occurred;
} kage_test_context;

// Global test context
extern kage_test_context *kage_test_get_context(void);

// Test framework macros
#define KAGE_TEST_BEGIN(test_name) \
    kage_test_context *ctx = kage_test_get_context(); \
    ctx->current_test = test_name; \
    ctx->error_occurred = false; \
    if (setjmp(ctx->jump_buffer) == 0) {

#define KAGE_TEST_END \
    } \
    if (ctx->error_occurred) { \
        return KAGE_TEST_ERROR; \
    } \
    return KAGE_TEST_PASS;

#define KAGE_TEST_ASSERT(condition) \
    if (!(condition)) { \
        kage_test_fail("Assertion failed: %s", #condition); \
        return KAGE_TEST_FAIL; \
    }

#define KAGE_TEST_ASSERT_NULL(ptr) \
    KAGE_TEST_ASSERT((ptr) == NULL)

#define KAGE_TEST_ASSERT_NOT_NULL(ptr) \
    KAGE_TEST_ASSERT((ptr) != NULL)

#define KAGE_TEST_ASSERT_EQUAL(a, b) \
    KAGE_TEST_ASSERT((a) == (b))

#define KAGE_TEST_ASSERT_NOT_EQUAL(a, b) \
    KAGE_TEST_ASSERT((a) != (b))

#define KAGE_TEST_ASSERT_STR_EQUAL(a, b) \
    KAGE_TEST_ASSERT(a != NULL && b != NULL && strcmp(a, b) == 0)

#define KAGE_TEST_ASSERT_STR_NOT_EQUAL(a, b) \
    KAGE_TEST_ASSERT(a != NULL && b != NULL && strcmp(a, b) != 0)

#define KAGE_TEST_ASSERT_MEM_EQUAL(a, b, size) \
    KAGE_TEST_ASSERT(a != NULL && b != NULL && memcmp(a, b, size) == 0)

#define KAGE_TEST_FAIL(format, ...) \
    kage_test_fail(format, ##__VA_ARGS__); \
    return KAGE_TEST_FAIL;

#define KAGE_TEST_SKIP(reason) \
    kage_test_skip(reason); \
    return KAGE_TEST_SKIP;

// Test function declarations
PHPAPI void kage_test_fail(const char *format, ...);
PHPAPI void kage_test_skip(const char *reason);
PHPAPI void kage_test_error(const char *format, ...);

// Test suite management
PHPAPI kage_test_suite* kage_test_suite_create(const char *name, const char *description);
PHPAPI void kage_test_suite_destroy(kage_test_suite *suite);
PHPAPI kage_error_t kage_test_suite_add_test(kage_test_suite *suite, const char *name, const char *description, kage_test_func function);
PHPAPI kage_error_t kage_test_suite_run(kage_test_suite *suite);
PHPAPI void kage_test_suite_print_results(kage_test_suite *suite);

// Test runner
PHPAPI int kage_test_run_all(void);
PHPAPI int kage_test_run_suite(const char *suite_name);
PHPAPI int kage_test_run_test(const char *suite_name, const char *test_name);

// Predefined test suites
PHPAPI kage_test_suite* kage_test_create_crypto_suite(void);
PHPAPI kage_test_suite* kage_test_create_ast_suite(void);
PHPAPI kage_test_suite* kage_test_create_vm_suite(void);
PHPAPI kage_test_suite* kage_test_create_base64_suite(void);
PHPAPI kage_test_suite* kage_test_create_memory_suite(void);
PHPAPI kage_test_suite* kage_test_create_config_suite(void);

// Benchmarking support
typedef struct {
    const char *name;
    void (*function)(void);
    double execution_time;
    size_t iterations;
} kage_benchmark;

PHPAPI void kage_test_benchmark(const char *name, void (*function)(void), size_t iterations);
PHPAPI void kage_test_print_benchmarks(void);

// Memory leak detection
PHPAPI void kage_test_enable_memory_checking(void);
PHPAPI void kage_test_disable_memory_checking(void);
PHPAPI bool kage_test_memory_leaks_detected(void);

// Coverage reporting (simplified)
typedef struct {
    const char *file;
    int lines_covered;
    int total_lines;
} kage_coverage_info;

PHPAPI void kage_test_coverage_start(void);
PHPAPI void kage_test_coverage_stop(void);
PHPAPI void kage_test_coverage_report(void);

// Integration with PHP
PHPAPI PHP_FUNCTION(kage_run_tests);
PHPAPI PHP_FUNCTION(kage_run_test_suite);
PHPAPI PHP_FUNCTION(kage_get_test_results);

#endif /* PHP_KAGE_TEST_H */
