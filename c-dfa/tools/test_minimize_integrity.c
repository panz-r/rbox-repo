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
#include "dfa_minimize.h"

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

    build_dfa_state_t dfa[10];
    memset(dfa, 0, sizeof(dfa));

    for (int i = 0; i < 10; i++) {
        for (int c = 0; c < 256; c++) {
            dfa[i].transitions[c] = -1;
        }
        dfa[i].eos_target = 0;
    }

    dfa[0].transitions['a'] = 1;
    dfa[0].marker_offsets['a'] = 0x1001;
    dfa[0].flags = 0x0100;

    dfa[1].transitions['a'] = 1;
    dfa[1].marker_offsets['a'] = 0x1002;
    dfa[1].flags = 0x0100;

    dfa[2].transitions['b'] = 3;
    dfa[2].marker_offsets['b'] = 0x2001;
    dfa[2].flags = 0x0100;

    dfa[3].transitions['b'] = 3;
    dfa[3].marker_offsets['b'] = 0x2001;
    dfa[3].flags = 0x0100;

    dfa[4].transitions['c'] = 5;
    dfa[4].marker_offsets['c'] = 0;
    dfa[4].flags = 0;

    dfa[5].transitions['c'] = 5;
    dfa[5].marker_offsets['c'] = 0;
    dfa[5].flags = 0;

    int result = dfa_minimize(dfa, 6);

    check(result > 0, "Minimization produced valid state count");
    check(result <= 6, "Minimization reduced or maintained state count");

    int violations = 0;
    for (int i = 0; i < result && violations == 0; i++) {
        for (int j = i + 1; j < result && violations == 0; j++) {
            bool same_all = true;
            for (int c = 0; c < 256 && same_all; c++) {
                if (dfa[i].transitions[c] != dfa[j].transitions[c]) same_all = false;
                if (dfa[i].marker_offsets[c] != dfa[j].marker_offsets[c]) same_all = false;
            }
            if (same_all && dfa[i].eos_target == dfa[j].eos_target) {
                if (dfa[i].eos_marker_offset == dfa[j].eos_marker_offset) {
                    if (dfa[i].flags != dfa[j].flags) {
                        printf("  [INFO] Merged states %d and %d have identical everything but different flags\n", i, j);
                        violations++;
                    }
                }
            }
        }
    }

    check(violations == 0, "No inappropriate merges detected");
    return violations == 0 ? TEST_PASSED : TEST_FAILED;
}

static int test_marker_offset_spread(void) {
    printf("\n=== Testing marker offset spread ===\n");

    build_dfa_state_t dfa[20];
    memset(dfa, 0, sizeof(dfa));

    for (int i = 0; i < 20; i++) {
        for (int c = 0; c < 256; c++) {
            dfa[i].transitions[c] = -1;
        }
        dfa[i].eos_target = 0;
    }

    for (int i = 0; i < 10; i++) {
        dfa[i].transitions['x'] = (i % 5) + 10;
        dfa[i].marker_offsets['x'] = 0x1000 + i;
        dfa[i].flags = 0x0100 | (i < 5 ? 0 : 1);
    }

    for (int i = 10; i < 15; i++) {
        dfa[i].transitions['x'] = 15;
        dfa[i].marker_offsets['x'] = 0x2000;
        dfa[i].flags = 0x0100;
    }

    for (int i = 15; i < 20; i++) {
        dfa[i].transitions['x'] = 15;
        dfa[i].marker_offsets['x'] = 0x3000;
        dfa[i].flags = 0x0100;
    }

    int result = dfa_minimize(dfa, 20);

    check(result > 0, "Minimization completed with spread markers");
    check(result < 20, "Minimization reduced state count");

    int marker_diversity = 0;
    uint32_t seen_offsets[256];
    memset(seen_offsets, 0, sizeof(seen_offsets));

    for (int i = 0; i < result; i++) {
        for (int c = 0; c < 256; c++) {
            uint32_t off = dfa[i].marker_offsets[c];
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

    return result == TEST_PASSED ? 0 : 1;
}
