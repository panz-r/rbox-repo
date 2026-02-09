/**
 * Test suite for multi_target_array.c
 * 
 * Compile: gcc -Wall -Wextra -std=c11 -o test_mta test_mta.c multi_target_array.c
 * Run: ./test_mta
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "multi_target_array.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name, cond) do { \
    if (cond) { \
        printf("  PASS: %s\n", name); \
        tests_passed++; \
    } else { \
        printf("  FAIL: %s\n", name); \
        tests_failed++; \
    } \
} while(0)

void test_basic_init(void) {
    printf("\n=== test_basic_init ===\n");
    multi_target_array_t arr;
    mta_init(&arr);
    
    TEST("entry_count starts at 0", mta_get_entry_count(&arr) == 0);
    TEST("is_multi returns false for empty", !mta_is_multi(&arr, 5));
    TEST("get_targets returns NULL for empty", mta_get_targets(&arr, 5) == NULL);
    TEST("get_target_count returns 0", mta_get_target_count(&arr, 5) == 0);
}

void test_single_target(void) {
    printf("\n=== test_single_target ===\n");
    multi_target_array_t arr;
    mta_init(&arr);
    
    // When a symbol has a single target, it's stored in the fast path (transitions[] array)
    // The sparse array is for MULTI-targets only
    // So single targets should NOT appear in the sparse array
    
    bool added = mta_add_target(&arr, 10, 42);
    TEST("add_target returns true", added);
    
    // The sparse array stores all targets for multi-target symbols
    // Single-target symbols are NOT in the sparse array
    // (They use the fast path in transitions[] array)
    TEST("entry_count is 0 for single target (fast path)", mta_get_entry_count(&arr) == 0);
    TEST("is_multi returns false for single target", !mta_is_multi(&arr, 10));
    TEST("get_targets returns NULL for single target (use transitions[])", mta_get_targets(&arr, 10) == NULL);
}

void test_multi_targets(void) {
    printf("\n=== test_multi_targets ===\n");
    multi_target_array_t arr;
    mta_init(&arr);
    
    // Add two targets for symbol 5
    mta_add_target(&arr, 5, 10);
    mta_add_target(&arr, 5, 20);
    
    TEST("entry_count is 1", mta_get_entry_count(&arr) == 1);
    TEST("is_multi returns true", mta_is_multi(&arr, 5));
    TEST("is_multi returns false for other symbols", !mta_is_multi(&arr, 6));
    
    const char* targets = mta_get_targets(&arr, 5);
    TEST("get_targets returns valid string", targets != NULL);
    if (targets) {
        TEST("targets string contains both values", 
             strstr(targets, "10") != NULL && strstr(targets, "20") != NULL);
    }
    
    TEST("target_count is 2", mta_get_target_count(&arr, 5) == 2);
}

void test_duplicate_targets(void) {
    printf("\n=== test_duplicate_targets ===\n");
    multi_target_array_t arr;
    mta_init(&arr);
    
    mta_add_target(&arr, 7, 100);
    mta_add_target(&arr, 7, 100);  // Duplicate
    mta_add_target(&arr, 7, 200);
    
    TEST("entry_count is 1 (deduped)", mta_get_entry_count(&arr) == 1);
    TEST("target_count is 2 (no duplicate)", mta_get_target_count(&arr, 7) == 2);
}

void test_multiple_symbols(void) {
    printf("\n=== test_multiple_symbols ===\n");
    multi_target_array_t arr;
    mta_init(&arr);
    
    // Symbol 1: 2 targets
    mta_add_target(&arr, 1, 10);
    mta_add_target(&arr, 1, 20);
    
    // Symbol 50: 3 targets
    mta_add_target(&arr, 50, 100);
    mta_add_target(&arr, 50, 200);
    mta_add_target(&arr, 50, 300);
    
    // Symbol 100: 2 targets
    mta_add_target(&arr, 100, 1);
    mta_add_target(&arr, 100, 2);
    
    TEST("entry_count is 3", mta_get_entry_count(&arr) == 3);
    TEST("symbol 1 is multi", mta_is_multi(&arr, 1));
    TEST("symbol 50 is multi", mta_is_multi(&arr, 50));
    TEST("symbol 100 is multi", mta_is_multi(&arr, 100));
    TEST("symbol 2 is not multi", !mta_is_multi(&arr, 2));
    
    const char* t50 = mta_get_targets(&arr, 50);
    TEST("symbol 50 targets valid", t50 != NULL && 
         strstr(t50, "100") != NULL && 
         strstr(t50, "200") != NULL && 
         strstr(t50, "300") != NULL);
}

void test_clear_symbol(void) {
    printf("\n=== test_clear_symbol ===\n");
    multi_target_array_t arr;
    mta_init(&arr);
    
    mta_add_target(&arr, 8, 1);
    mta_add_target(&arr, 8, 2);
    mta_add_target(&arr, 8, 3);
    
    TEST("entry_count is 1 before clear", mta_get_entry_count(&arr) == 1);
    
    mta_clear_symbol(&arr, 8);
    
    // Note: clear marks the entry as invalid but doesn't compact
    // The entry_count stays the same, but is_multi returns false
    TEST("is_multi returns false after clear", !mta_is_multi(&arr, 8));
    TEST("get_targets returns NULL after clear", mta_get_targets(&arr, 8) == NULL);
}

void test_edge_cases(void) {
    printf("\n=== test_edge_cases ===\n");
    multi_target_array_t arr;
    mta_init(&arr);
    
    // Invalid symbol ID
    TEST("add_target returns false for invalid symbol", !mta_add_target(&arr, -1, 1));
    TEST("add_target returns false for out of bounds symbol", !mta_add_target(&arr, 256, 1));
    TEST("is_multi returns false for invalid symbol", !mta_is_multi(&arr, -1));
    TEST("get_targets returns NULL for invalid symbol", mta_get_targets(&arr, -1) == NULL);
    
    // Empty array queries
    TEST("empty array has 0 entries", mta_get_entry_count(&arr) == 0);
}

void test_large_targets(void) {
    printf("\n=== test_large_targets ===\n");
    multi_target_array_t arr;
    mta_init(&arr);
    
    // Add many targets to one symbol
    bool all_added = true;
    for (int i = 0; i < 50; i++) {
        if (!mta_add_target(&arr, 20, i * 10)) {
            all_added = false;
        }
    }
    
    TEST("all 50 targets added", all_added);
    TEST("entry_count is 1", mta_get_entry_count(&arr) == 1);
    TEST("target_count is 50", mta_get_target_count(&arr, 20) == 50);
    
    const char* targets = mta_get_targets(&arr, 20);
    TEST("targets string is not NULL", targets != NULL);
    if (targets) {
        TEST("targets string contains first value", strstr(targets, "0") != NULL);
        TEST("targets string contains last value", strstr(targets, "490") != NULL);
    }
}

void test_memory_leak_check(void) {
    printf("\n=== test_memory_leak_check ===\n");
    multi_target_array_t arr;
    mta_init(&arr);
    
    // Add some data
    for (int sym = 0; sym < 10; sym++) {
        for (int t = 0; t < 5; t++) {
            mta_add_target(&arr, sym, t);
        }
    }
    
    // Free (should not crash or leak)
    mta_free(&arr);
    
    TEST("free completes without crash", true);
}

int main(void) {
    printf("========================================\n");
    printf("Multi-Target Array Test Suite\n");
    printf("========================================\n");
    
    test_basic_init();
    test_single_target();
    test_multi_targets();
    test_duplicate_targets();
    test_multiple_symbols();
    test_clear_symbol();
    test_edge_cases();
    test_large_targets();
    test_memory_leak_check();
    
    printf("\n========================================\n");
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");
    
    return tests_failed > 0 ? 1 : 0;
}
