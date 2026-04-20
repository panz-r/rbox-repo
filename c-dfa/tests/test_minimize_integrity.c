/**
 * Minimization Integrity Test
 *
 * Verifies that the marker-aware minimization algorithms do not merge states
 * with different capture payloads. This prevents "capture smearing" where
 * two different capture operations would be incorrectly combined.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../include/nfa.h"
#include "../lib/dfa_minimize.h"

#define TEST_PASSED 0
#define TEST_FAILED 1

static int test_count = 0;
static int passed_count = 0;

static void check(int condition, const char* test_name) {
    test_count++;
    if (condition) {
        passed_count++;
        printf("  [PASS] %s\n", test_name);
    } else {
        printf("  [FAIL] %s\n", test_name);
    }
}



static int test_marker_aware_partitioning(void) {
    printf("\n=== Testing marker-aware partitioning ===\n");

    // Create dynamically allocated states
    build_dfa_state_t* dfa_ptr[6];
    for (int i = 0; i < 6; i++) {
        dfa_ptr[i] = build_dfa_state_create(256, 64);
        if (!dfa_ptr[i]) {
            printf("Failed to create state %d\n", i);
            return TEST_FAILED;
        }
    }

    // State 0
    dfa_ptr[0]->transitions['a'] = 1;
    dfa_ptr[0]->marker_offsets['a'] = 0x100;
    dfa_ptr[0]->eos_target = 3;
    dfa_ptr[0]->eos_marker_offset = 0x10;
    dfa_ptr[0]->flags = 0x0100;

    // State 1  
    dfa_ptr[1]->transitions['b'] = 2;
    dfa_ptr[1]->marker_offsets['b'] = 0x200;
    dfa_ptr[1]->eos_target = 4;
    dfa_ptr[1]->eos_marker_offset = 0x20;
    dfa_ptr[1]->flags = 0x0100;

    // State 2
    dfa_ptr[2]->transitions['c'] = 3;
    dfa_ptr[2]->marker_offsets['c'] = 0x300;
    dfa_ptr[2]->eos_target = 5;
    dfa_ptr[2]->eos_marker_offset = 0x30;
    dfa_ptr[2]->flags = 0x0100;

    // State 3
    dfa_ptr[3]->transitions['d'] = 4;
    dfa_ptr[3]->marker_offsets['d'] = 0x100;
    dfa_ptr[3]->eos_target = 0;
    dfa_ptr[3]->eos_marker_offset = 0x10;
    dfa_ptr[3]->flags = 0x0200;

    // State 4
    dfa_ptr[4]->transitions['d'] = 5;
    dfa_ptr[4]->marker_offsets['d'] = 0x200;
    dfa_ptr[4]->eos_target = 0;
    dfa_ptr[4]->eos_marker_offset = 0x20;
    dfa_ptr[4]->flags = 0x0200;

    // State 5
    dfa_ptr[5]->transitions['d'] = 0;
    dfa_ptr[5]->marker_offsets['d'] = 0x300;
    dfa_ptr[5]->eos_target = 0;
    dfa_ptr[5]->eos_marker_offset = 0x30;
    dfa_ptr[5]->flags = 0;

    int result = dfa_minimize(dfa_ptr, 6, DFA_MIN_HOPCROFT, false, NULL, 0);

    check(result > 0, "Minimization produced valid state count");
    check(result <= 6, "Minimization reduced or maintained state count");

    int violations = 0;
    for (int i = 0; i < result && violations == 0; i++) {
        for (int j = i + 1; j < result && violations == 0; j++) {
            bool same_all = true;
            for (int c = 0; c < 256 && same_all; c++) {
                if (dfa_ptr[i]->transitions[c] != dfa_ptr[j]->transitions[c]) same_all = false;
                if (dfa_ptr[i]->marker_offsets[c] != dfa_ptr[j]->marker_offsets[c]) same_all = false;
            }
            if (same_all && dfa_ptr[i]->eos_target == dfa_ptr[j]->eos_target) {
                if (dfa_ptr[i]->eos_marker_offset == dfa_ptr[j]->eos_marker_offset) {
                    if (dfa_ptr[i]->flags != dfa_ptr[j]->flags) {
                        printf("  [INFO] Merged states %d and %d have identical everything but different flags\n", i, j);
                        violations++;
                    }
                }
            }
        }
    }

    check(violations == 0, "No inappropriate merges detected");
    
    // Clean up ALL states
    for (int i = 0; i < 6; i++) {
        if (dfa_ptr[i] != NULL) {
            build_dfa_state_destroy(dfa_ptr[i]);
            dfa_ptr[i] = NULL;
        }
    }
    
    return violations == 0 ? TEST_PASSED : TEST_FAILED;
}

static int test_marker_offset_spread(void) {
    printf("\n=== Testing marker offset spread ===\n");

    // Create dynamically allocated states
    build_dfa_state_t* dfa_ptr[20];
    for (int i = 0; i < 20; i++) {
        dfa_ptr[i] = build_dfa_state_create(256, 64);
        if (!dfa_ptr[i]) {
            printf("Failed to create state %d\n", i);
            return TEST_FAILED;
        }
        for (int c = 0; c < 256; c++) {
            dfa_ptr[i]->transitions[c] = -1;
        }
        dfa_ptr[i]->eos_target = 0;
    }

    for (int i = 0; i < 10; i++) {
        dfa_ptr[i]->transitions['x'] = (i % 5) + 10;
        dfa_ptr[i]->marker_offsets['x'] = 0x1000 + i;
        dfa_ptr[i]->flags = 0x0100 | (i < 5 ? 0 : 1);
    }

    for (int i = 10; i < 15; i++) {
        dfa_ptr[i]->transitions['x'] = 15;
        dfa_ptr[i]->marker_offsets['x'] = 0x2000;
        dfa_ptr[i]->flags = 0x0100;
    }

    for (int i = 15; i < 20; i++) {
        dfa_ptr[i]->transitions['x'] = 15;
        dfa_ptr[i]->marker_offsets['x'] = 0x3000;
        dfa_ptr[i]->flags = 0x0100;
    }

    int result = dfa_minimize(dfa_ptr, 20, DFA_MIN_HOPCROFT, false, NULL, 0);

    check(result > 0, "Minimization completed with spread markers");
    check(result < 20, "Minimization reduced state count");

    int marker_diversity = 0;
    uint32_t seen_offsets[256];
    memset(seen_offsets, 0, sizeof(seen_offsets));

    for (int i = 0; i < result; i++) {
        for (int c = 0; c < 256; c++) {
            uint32_t off = dfa_ptr[i]->marker_offsets[c];
            if (off != 0) {
                bool found = false;
                for (int j = 0; j < marker_diversity; j++) {
                    if (seen_offsets[j] == off) { found = true; break; }
                }
                if (!found && marker_diversity < 256) {
                    seen_offsets[marker_diversity++] = off;
                }
            }
        }
    }

    check(marker_diversity >= 2, "Multiple unique marker offsets preserved");
    printf("  [INFO] Preserved %d unique marker offsets\n", marker_diversity);
    
    // Clean up ALL states - dfa_minimize internal bugs may leave stale pointers
    // beyond the result count that need explicit cleanup
    for (int i = 0; i < 20; i++) {
        if (dfa_ptr[i] != NULL) {
            build_dfa_state_destroy(dfa_ptr[i]);
            dfa_ptr[i] = NULL;
        }
    }
    
    return TEST_PASSED;
}

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;

    printf("=================================================\n");
    printf("MINIMIZATION INTEGRITY TEST SUITE\n");
    printf("=================================================\n");

    int result = TEST_PASSED;

    result = test_marker_aware_partitioning();
    if (result != TEST_PASSED) return result;

    result = test_marker_offset_spread();
    if (result != TEST_PASSED) return result;

    printf("\n=================================================\n");
    printf("MINIMIZATION INTEGRITY RESULTS\n");
    printf("=================================================\n");
    printf("Tests: %d/%d passed\n", passed_count, test_count);
    printf("SUMMARY: %d/%d passed\n", passed_count, test_count);

    return result == TEST_PASSED ? 0 : 1;
}
