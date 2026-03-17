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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    if (test_##name()) { tests_passed++; printf("  [PASS] %s\n", #name); } \
    else { printf("  [FAIL] %s\n", #name); } \
} while(0)

// ============================================================================
// Pipeline error handling tests
// ============================================================================

static bool test_pipeline_null_inputs(void) {
    // NULL config is OK (uses defaults)
    pipeline_t* p = pipeline_create(NULL);
    if (!p) return false;
    pipeline_destroy(p);

    // NULL pattern file should fail
    p = pipeline_create(NULL);
    pipeline_error_t err = pipeline_run(p, NULL);
    pipeline_destroy(p);
    return (err != PIPELINE_OK);
}

static bool test_pipeline_nonexistent_file(void) {
    pipeline_t* p = pipeline_create(NULL);
    if (!p) return false;

    pipeline_error_t err = pipeline_run(p, "/nonexistent/path/patterns.txt");
    pipeline_destroy(p);
    return (err != PIPELINE_OK);
}

static bool test_pipeline_invalid_pattern_file(void) {
    // Create a temporary invalid pattern file
    const char* tmpfile = "/tmp/invalid_patterns_test.txt";
    FILE* f = fopen(tmpfile, "w");
    if (!f) return false;
    fprintf(f, "this is not a valid pattern file\n[[[invalid syntax\n");
    fclose(f);

    pipeline_t* p = pipeline_create(NULL);
    if (!p) { remove(tmpfile); return false; }

    pipeline_error_t err = pipeline_run(p, tmpfile);
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
// Concurrent evaluator tests (validates Phase 3 global state removal)
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

    // Create two independent evaluators
    dfa_evaluator_t* e1 = dfa_eval_create(binary, size);
    dfa_evaluator_t* e2 = dfa_eval_create(binary, size);

    if (!e1 || !e2) {
        dfa_eval_destroy(e1);
        dfa_eval_destroy(e2);
        pipeline_destroy(p);
        return false;
    }

    // Both should work independently
    dfa_result_t r1 = dfa_eval_evaluate(e1, "git status");
    dfa_result_t r2 = dfa_eval_evaluate(e2, "ls -la");

    bool ok = (r1.matched && r2.matched);

    // Destroy in different order - e1 first while e2 still exists
    dfa_eval_destroy(e1);

    // e2 should still work after e1 is destroyed
    dfa_result_t r3 = dfa_eval_evaluate(e2, "git log");
    ok = ok && r3.matched;

    dfa_eval_destroy(e2);
    pipeline_destroy(p);

    return ok;
}

static bool test_evaluator_destroy_null(void) {
    // Should not crash
    dfa_eval_destroy(NULL);
    return true;
}

static bool test_evaluator_null_input(void) {
    // Build a DFA
    pipeline_t* p = pipeline_create(NULL);
    if (!p) return false;

    pipeline_error_t err = pipeline_run(p, "patterns/commands/safe_commands.txt");
    if (err != PIPELINE_OK) {
        pipeline_destroy(p);
        return false;
    }

    size_t size;
    const uint8_t* binary = pipeline_get_binary(p, &size);
    dfa_evaluator_t* e = dfa_eval_create(binary, size);
    if (!e) {
        pipeline_destroy(p);
        return false;
    }

    // NULL input should return unmatched result
    dfa_result_t result = dfa_eval_evaluate(e, NULL);
    bool ok = !result.matched;

    dfa_eval_destroy(e);
    pipeline_destroy(p);
    return ok;
}

// ============================================================================
// DFA machine API edge cases
// ============================================================================

static bool test_dfa_machine_null_inputs(void) {
    dfa_machine_t m = {0};

    // NULL machine should return false/NULL
    if (dfa_machine_is_valid(NULL)) return false;
    if (dfa_machine_get_dfa(NULL) != NULL) return false;
    if (dfa_machine_get_identifier(NULL) == NULL) return false;

    // Reset on NULL should not crash
    dfa_machine_reset(NULL);

    // Init with NULL should return false
    if (dfa_machine_init(NULL, "data", 10)) return false;
    if (dfa_machine_init(&m, NULL, 10)) return false;
    if (dfa_machine_init(&m, "data", 0)) return false;

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
    TEST(evaluator_null_input);

    printf("\nDFA Machine API:\n");
    TEST(dfa_machine_null_inputs);
    TEST(dfa_machine_invalid_data);

    printf("\n=================\n");
    printf("SUMMARY: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
