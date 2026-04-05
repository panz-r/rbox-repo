/**
 * test_eval_only.c - Tests the eval-only library API (libdfa_eval.a)
 *
 * This test exercises the public API that eval-only users see.
 * Links against libdfa_eval.a only - no pipeline, no builder, no I/O.
 *
 * Uses a pre-built DFA binary (built by nfa_builder + nfa2dfa_advanced).
 */

#include "../include/dfa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { printf("  %s: ", name); } while(0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL - %s\n", msg); tests_failed++; } while(0)

/**
 * Load test DFA from /tmp/eval_test_dfa.dfa
 * (Built by nfa_builder + nfa2dfa_advanced before running this test)
 */
static void* load_test_dfa(size_t* out_size) {
    FILE* f = fopen("/tmp/eval_test_dfa.dfa", "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    void* data = malloc(size);
    if (!data) { fclose(f); return NULL; }
    if (fread(data, 1, size, f) != (size_t)size) { free(data); fclose(f); return NULL; }
    fclose(f);
    *out_size = (size_t)size;
    return data;
}

static bool test_basic_eval(void) {
    TEST("dfa_eval basic matching");

    size_t dfa_size;
    void* dfa_data = load_test_dfa(&dfa_size);
    if (!dfa_data) { FAIL("load_test_dfa failed"); return false; }

    dfa_result_t result;
    memset(&result, 0, sizeof(result));

    // "cat" should match
    if (!dfa_eval(dfa_data, dfa_size, "cat", 3, &result)) {
        free(dfa_data);
        FAIL("should match 'cat'");
        return false;
    }

    free(dfa_data);
    PASS();
    return true;
}

static bool test_no_match(void) {
    TEST("dfa_eval non-matching input");

    size_t dfa_size;
    void* dfa_data = load_test_dfa(&dfa_size);
    if (!dfa_data) { FAIL("load_test_dfa failed"); return false; }

    dfa_result_t result;
    memset(&result, 0, sizeof(result));

    // "dog file.txt" should NOT match
    if (dfa_eval(dfa_data, dfa_size, "dog file.txt", 12, &result)) {
        free(dfa_data);
        FAIL("should not match 'dog file.txt'");
        return false;
    }

    free(dfa_data);
    PASS();
    return true;
}

static bool test_validate_id(void) {
    TEST("dfa_eval_validate_id");

    size_t dfa_size;
    void* dfa_data = load_test_dfa(&dfa_size);
    if (!dfa_data) { FAIL("load_test_dfa failed"); return false; }

    // Correct identifier should match (this is the key test that catches offset bugs)
    if (!dfa_eval_validate_id(dfa_data, dfa_size, "dfa-eval-test-only")) {
        free(dfa_data);
        FAIL("correct identifier should match");
        return false;
    }

    // Wrong identifier should NOT match
    if (dfa_eval_validate_id(dfa_data, dfa_size, "wrong-identifier")) {
        free(dfa_data);
        FAIL("wrong identifier should not match");
        return false;
    }

    // Truncated size should fail
    if (dfa_eval_validate_id(dfa_data, 10, "dfa-eval-test-only")) {
        free(dfa_data);
        FAIL("should reject truncated data");
        return false;
    }

    free(dfa_data);
    PASS();
    return true;
}

static bool test_capture_count(void) {
    TEST("dfa_result_get_capture_count");

    size_t dfa_size;
    void* dfa_data = load_test_dfa(&dfa_size);
    if (!dfa_data) { FAIL("load_test_dfa failed"); return false; }

    dfa_result_t result;
    memset(&result, 0, sizeof(result));
    dfa_eval(dfa_data, dfa_size, "cat", 3, &result);

    int count = dfa_result_get_capture_count(&result);
    if (count < 0) {
        free(dfa_data);
        FAIL("capture count should be >= 0");
        return false;
    }

    free(dfa_data);
    PASS();
    return true;
}

static bool test_category_string(void) {
    TEST("dfa_category_string");

    const char* name = dfa_category_string(DFA_CMD_UNKNOWN);
    if (!name) {
        FAIL("should return non-NULL for DFA_CMD_UNKNOWN");
        return false;
    }

    name = dfa_category_string(DFA_CMD_READONLY_SAFE);
    if (!name) {
        FAIL("should return non-NULL for DFA_CMD_READONLY_SAFE");
        return false;
    }

    PASS();
    return true;
}

int main(void) {
    printf("Eval-Only Library Tests (libdfa_eval.a)\n");
    printf("========================================\n\n");

    test_basic_eval();
    test_no_match();
    test_validate_id();
    test_capture_count();
    test_category_string();

    printf("\n========================================\n");
    printf("SUMMARY: %d/%d passed\n", tests_passed, tests_passed + tests_failed);
    printf("========================================\n");

    return tests_failed > 0 ? 1 : 0;
}
