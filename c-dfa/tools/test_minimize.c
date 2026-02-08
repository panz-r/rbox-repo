/**
 * Simple test for DFA minimization
 * 
 * This creates a simple DFA with redundant states and verifies minimization works.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "dfa_minimize.h"

// Mock structure for testing - same as build_dfa_state_t
typedef struct {
    uint32_t transitions_offset;
    uint16_t transition_count;
    uint16_t flags;
    int transitions[256];
    bool transitions_from_any[256];
    int nfa_states[8192];
    int nfa_state_count;
    int8_t capture_start_id;
    int8_t capture_end_id;
    int8_t capture_defer_id;
    uint32_t eos_target;
} test_state_t;

static void init_test_state(test_state_t* s) {
    memset(s, 0, sizeof(test_state_t));
    s->capture_start_id = -1;
    s->capture_end_id = -1;
    s->capture_defer_id = -1;
    for (int i = 0; i < 256; i++) {
        s->transitions[i] = -1;
    }
    for (int i = 0; i < 8192; i++) {
        s->nfa_states[i] = -1;
    }
}

static bool test_simple_minimization() {
    printf("Test: Simple minimization...\n");
    
    // Create a DFA that accepts "ab" with redundant states:
    // State 0: initial
    // State 1: after 'a' 
    // State 2: after 'ab' (accepting)
    // State 3: redundant copy of state 2
    // State 4: redundant copy of state 1
    
    test_state_t dfa[5];
    for (int i = 0; i < 5; i++) {
        init_test_state(&dfa[i]);
    }
    
    // State 0: on 'a' -> state 1 and 4 (both should be equivalent)
    dfa[0].transitions['a'] = 1;
    
    // State 1: on 'b' -> state 2
    dfa[1].transitions['b'] = 2;
    
    // State 2: accepting (EOS target)
    dfa[2].flags = 0x0100;  // CAT_MASK_SAFE in upper bits
    dfa[2].eos_target = 2;  // Self-loop
    
    // State 3: redundant accepting state (same as state 2)
    dfa[3].flags = 0x0100;
    dfa[3].eos_target = 3;  // Self-loop
    
    // State 4: redundant intermediate state (same as state 1)
    dfa[4].transitions['b'] = 3;
    
    dfa_minimize_set_verbose(false);
    int new_count = dfa_minimize((build_dfa_state_t*)dfa, 5);
    
    printf("  Result: %d states after minimization\n", new_count);
    
    // Should be reduced to 3 states: 0, (1/4 merged), (2/3 merged)
    if (new_count <= 4) {
        printf("  PASS: States were reduced\n");
        return true;
    } else {
        printf("  FAIL: Expected reduction didn't happen\n");
        return false;
    }
}

static bool test_already_minimal() {
    printf("\nTest: Already minimal DFA...\n");
    
    // Create a minimal DFA that accepts "ab"
    // States: 0 (initial), 1 (after 'a'), 2 (accepting)
    // This should not be reducible
    
    test_state_t dfa[3];
    for (int i = 0; i < 3; i++) {
        init_test_state(&dfa[i]);
    }
    
    dfa[0].transitions['a'] = 1;
    dfa[1].transitions['b'] = 2;
    dfa[2].flags = 0x0100;  // Accepting
    dfa[2].eos_target = 2;  // Self-loop
    
    int new_count = dfa_minimize((build_dfa_state_t*)dfa, 3);
    
    printf("  Result: %d states after minimization\n", new_count);
    
    if (new_count == 3) {
        printf("  PASS: Minimal DFA unchanged\n");
        return true;
    } else {
        printf("  FAIL: Minimal DFA was incorrectly reduced\n");
        return false;
    }
}

static bool test_eos_target_remapping() {
    printf("\nTest: EOS target remapping...\n");
    
    // Create DFA with accepting states that have self-referencing EOS targets
    test_state_t dfa[4];
    for (int i = 0; i < 4; i++) {
        init_test_state(&dfa[i]);
    }
    
    dfa[0].transitions['a'] = 1;
    dfa[1].transitions['b'] = 2;
    dfa[2].flags = 0x0100;  // Accepting
    dfa[2].eos_target = 2;  // Self-loop
    dfa[3].flags = 0x0100;  // Accepting (duplicate)
    dfa[3].eos_target = 3;  // Self-loop
    
    int new_count = dfa_minimize((build_dfa_state_t*)dfa, 4);
    
    printf("  Result: %d states\n", new_count);
    
    // Find the accepting state and check its EOS target
    bool found_accepting = false;
    bool eos_correct = false;
    
    for (int i = 0; i < new_count; i++) {
        if (dfa[i].flags & 0xFF00) {  // Accepting
            found_accepting = true;
            if (dfa[i].eos_target == (uint32_t)i) {
                eos_correct = true;
                printf("  Accepting state %d: eos_target=%u (correctly self-referencing)\n", 
                       i, dfa[i].eos_target);
            } else {
                printf("  Accepting state %d: eos_target=%u (expected %d)\n", 
                       i, dfa[i].eos_target, i);
            }
            break;
        }
    }
    
    if (new_count == 3 && found_accepting && eos_correct) {
        printf("  PASS: EOS target correctly remapped\n");
        return true;
    } else {
        printf("  FAIL: Expected 3 states with accepting state having self-referencing EOS\n");
        return false;
    }
}

static bool test_capture_preservation() {
    printf("\nTest: Capture marker preservation...\n");
    
    test_state_t dfa[3];
    for (int i = 0; i < 3; i++) {
        init_test_state(&dfa[i]);
    }
    
    dfa[0].transitions['a'] = 1;
    dfa[1].flags = 0x0100;
    dfa[1].capture_start_id = 5;
    dfa[1].capture_end_id = 3;
    dfa[2].flags = 0x0100;
    dfa[2].capture_start_id = 5;  // Same as state 1
    dfa[2].capture_end_id = 3;    // Same as state 1
    
    int new_count = dfa_minimize((build_dfa_state_t*)dfa, 3);
    
    printf("  Result: %d states\n", new_count);
    
    if (new_count == 2) {
        // Find accepting state and check capture markers
        for (int i = 0; i < new_count; i++) {
            if (dfa[i].flags & 0xFF00) {
                if (dfa[i].capture_start_id == 5 && dfa[i].capture_end_id == 3) {
                    printf("  PASS: Capture markers preserved\n");
                    return true;
                }
            }
        }
    }
    
    printf("  FAIL: Capture markers not preserved\n");
    return false;
}

int main() {
    printf("================================\n");
    printf("DFA Minimization Test Suite\n");
    printf("================================\n\n");
    
    int passed = 0;
    int total = 0;
    
    total++; if (test_simple_minimization()) passed++;
    total++; if (test_already_minimal()) passed++;
    total++; if (test_eos_target_remapping()) passed++;
    total++; if (test_capture_preservation()) passed++;
    
    printf("\n================================\n");
    printf("Results: %d/%d tests passed\n", passed, total);
    printf("================================\n");
    
    return (passed == total) ? 0 : 1;
}
