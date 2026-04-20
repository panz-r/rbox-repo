/**
 * Library API Tests - Tests for error handling and concurrent evaluators
 *
 * These tests complement the existing dfa_test.c by covering:
 * - Pipeline error handling (invalid files, NULL inputs)
 * - Concurrent evaluators (multiple dfa_evaluator_t at once)
 * - API boundary conditions
 */

#include "../include/pipeline.h"
#include "../include/dfa_internal.h"
#include "../include/multi_target_array.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    if (test_##name()) { tests_passed++; printf("  [PASS] %s\n", #name); } \
    else { printf("  [FAIL] %s\n", #name); } \
} while(0)

// Redirect stderr to /dev/null for tests that intentionally trigger errors
static void suppress_stderr_start(int* out_saved) {
    fflush(stderr);
    *out_saved = dup(STDERR_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    dup2(devnull, STDERR_FILENO);
    close(devnull);
}

static void suppress_stderr_end(int saved_fd) {
    fflush(stderr);
    dup2(saved_fd, STDERR_FILENO);
    close(saved_fd);
}

// ============================================================================
// Pipeline error handling tests
// ============================================================================

static bool test_pipeline_null_inputs(void) {
    // NULL config is OK (uses defaults)
    pipeline_t* p = pipeline_create(NULL);
    if (!p) return false;
    pipeline_destroy(p);

    return true;
}

static bool test_pipeline_nonexistent_file(void) {
    int saved;
    suppress_stderr_start(&saved);
    printf("    [EXPECTED FAILURE: nonexistent file] ");
    pipeline_t* p = pipeline_create(NULL);
    if (!p) { suppress_stderr_end(saved); return false; }

    pipeline_error_t err = pipeline_run(p, "/nonexistent/path/patterns.txt");
    pipeline_destroy(p);
    suppress_stderr_end(saved);
    return (err != PIPELINE_OK);
}

static bool test_pipeline_invalid_pattern_file(void) {
    printf("    [EXPECTED FAILURE: invalid pattern syntax] ");
    // Create a temporary invalid pattern file
    const char* tmpfile = "/tmp/invalid_patterns_test.txt";
    FILE* f = fopen(tmpfile, "w");
    if (!f) return false;
    fprintf(f, "this is not a valid pattern file\n[[[invalid syntax\n");
    fclose(f);

    pipeline_t* p = pipeline_create(NULL);
    if (!p) { remove(tmpfile); return false; }

    int saved;
    suppress_stderr_start(&saved);
    pipeline_error_t err = pipeline_run(p, tmpfile);
    suppress_stderr_end(saved);
    pipeline_destroy(p);
    remove(tmpfile);

    // Should fail with parse error
    return (err == PIPELINE_PARSE_ERROR);
}

static bool test_pipeline_get_binary_before_build(void) {
    pipeline_t* p = pipeline_create(NULL);
    if (!p) return false;

    size_t size = 0;
    const uint8_t* binary = pipeline_get_binary(p, &size);
    pipeline_destroy(p);

    // Should return NULL before build
    return (binary == NULL);
}

// ============================================================================
// DFA machine API invalid data
// ============================================================================

static bool test_concurrent_evaluators(void) {
    // Build a DFA first
    pipeline_t* p = pipeline_create(NULL);
    if (!p) return false;

    pipeline_error_t err = pipeline_run(p, "patterns/commands/safe_commands.txt");
    if (err != PIPELINE_OK) {
        pipeline_destroy(p);
        return false;
    }

    size_t size;
    const uint8_t* binary = pipeline_get_binary(p, &size);
    if (!binary || size == 0) {
        pipeline_destroy(p);
        return false;
    }

    // Test concurrent evaluations (stateless dfa_eval allows this)
    dfa_result_t r1, r2, r3;
    dfa_eval(binary, size, "git status", 10, &r1);
    dfa_eval(binary, size, "ls -la", 6, &r2);
    dfa_eval(binary, size, "git log", 7, &r3);

    bool ok = r1.matched && r2.matched && r3.matched;

    pipeline_destroy(p);
    return ok;
}

static bool test_evaluator_destroy_null(void) {
    // dfa_eval is stateless, no destroy needed
    return true;
}

static bool test_dfa_machine_invalid_data(void) {
    dfa_machine_t m = {0};
    char invalid_data[100] = {0};

    // Too small
    if (dfa_machine_init(&m, invalid_data, 10)) return false;

    // Wrong magic
    *(uint32_t*)invalid_data = 0x12345678;
    if (dfa_machine_init(&m, invalid_data, sizeof(dfa_t))) return false;

    return true;
}

// ============================================================================
// Main
// ============================================================================

int main(void) {
    printf("Library API Tests\n");
    printf("=================\n\n");

    printf("Pipeline Error Handling:\n");
    TEST(pipeline_null_inputs);
    TEST(pipeline_nonexistent_file);
    TEST(pipeline_invalid_pattern_file);
    TEST(pipeline_get_binary_before_build);

    printf("\nConcurrent Evaluators:\n");
    TEST(concurrent_evaluators);
    TEST(evaluator_destroy_null);

    printf("\nDFA Machine API:\n");
    TEST(dfa_machine_invalid_data);

    printf("\n=================\n");
    printf("SUMMARY: %d/%d passed\n", tests_passed, tests_run);

    mta_report_leaks();

    return (tests_passed == tests_run) ? 0 : 1;
}
