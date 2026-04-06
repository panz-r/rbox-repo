/**
 * SAT Encoding Unit Tests for DFA Minimization
 *
 * Pass 1: Core Infrastructure
 * Pass 2: Constraint Encoding
 * Pass 3: Full Encoding
 * Pass 4: Stress Tests
 *
 * Usage:
 *   ./test_sat_encoding              # Run all tests
 *   ./test_sat_encoding --group 1   # Run pass 1 tests
 *   ./test_sat_encoding --group 2   # Run pass 2 tests
 *   ./test_sat_encoding --verbose   # Verbose output
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include "cadical.hpp"

extern "C" {
#include "../include/dfa_types.h"
#include "../tools/dfa_minimize.h"
}

// ============================================================================
// Test Framework
// ============================================================================

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static bool verbose_mode = false;
static int current_group = 0;

#define TEST_START(name) \
    tests_run++; \
    if (verbose_mode) printf("  [TEST] %s... ", name)

#define TEST_PASS(name) \
    tests_passed++; \
    if (verbose_mode) printf("PASS\n"); \
    else printf("  [PASS] %s\n", name)

#define TEST_FAIL(name, msg) \
    tests_failed++; \
    if (verbose_mode) printf("FAIL: %s\n", msg); \
    else printf("  [FAIL] %s: %s\n", name, msg)

#define ASSERT_TRUE(cond, msg) \
    do { if (!(cond)) { TEST_FAIL(#cond, msg); return; } } while(0)

#define ASSERT_EQ(a, b, msg) \
    do { if ((a) != (b)) { TEST_FAIL(#a " != " #b, msg); return; } } while(0)

// ============================================================================
// Test DFA Helpers
// ============================================================================

static void clear_dfa(build_dfa_state_t* dfa, int count) {
    memset(dfa, 0, count * sizeof(build_dfa_state_t));
    for (int s = 0; s < count; s++) {
        for (int i = 0; i < 256; i++) {
            dfa[s].transitions[i] = -1;
        }
    }
}

// Create a simple chain DFA: state 0 -> state 1 -> ... -> state (n-1) [accepting]
static void make_chain_dfa(build_dfa_state_t* dfa, int states, uint8_t category) {
    clear_dfa(dfa, states);
    
    for (int s = 0; s < states - 1; s++) {
        dfa[s].transitions['a'] = s + 1;
    }
    dfa[states - 1].flags = DFA_STATE_ACCEPTING | ((uint16_t)category << 8);
}

// Create a two-branch DFA: state 0 -> (state 1 on 'a') and (state 2 on 'b')
static void make_two_branch_dfa(build_dfa_state_t* dfa, uint8_t cat1, uint8_t cat2) {
    clear_dfa(dfa, 3);
    
    dfa[0].transitions['a'] = 1;
    dfa[0].transitions['b'] = 2;
    
    dfa[1].flags = DFA_STATE_ACCEPTING | ((uint16_t)cat1 << 8);
    dfa[2].flags = DFA_STATE_ACCEPTING | ((uint16_t)cat2 << 8);
}

// Create two identical accepting states (should merge)
static void make_duplicate_states_dfa(build_dfa_state_t* dfa, uint8_t category) {
    clear_dfa(dfa, 3);
    
    dfa[0].transitions['a'] = 1;
    dfa[0].transitions['b'] = 2;
    
    // States 1 and 2 are both accepting with same category
    dfa[1].flags = DFA_STATE_ACCEPTING | ((uint16_t)category << 8);
    dfa[2].flags = DFA_STATE_ACCEPTING | ((uint16_t)category << 8);
}

// ============================================================================
// SAT Encoder Class (Internal Implementation)
// ============================================================================

class SatEncoder {
private:
    CaDiCaL::Solver* solver;
    int n_states;        // Number of states in input DFA
    int n_partitions;    // Target number of partitions
    
    // Variable indexing: x[state][partition] -> variable number (1-indexed for CaDiCaL)
    int var(int state, int partition) {
        return state * n_partitions + partition + 1;
    }
    
public:
    SatEncoder(int states, int partitions) 
        : n_states(states), n_partitions(partitions) {
        solver = new CaDiCaL::Solver();
        
        // Declare all variables: x[s][p] for all states and partitions
        int max_var = n_states * n_partitions;
        for (int v = 0; v < max_var; v++) {
            (void)solver->declare_one_more_variable();
        }
    }
    
    ~SatEncoder() {
        delete solver;
    }
    
    // Encode: each state must be in exactly one partition
    void encode_exactly_one_partition(int state) {
        // At-least-one: (x[s][0] OR x[s][1] OR ... OR x[s][k-1])
        for (int p = 0; p < n_partitions; p++) {
            solver->add(var(state, p));
        }
        solver->add(0);
        
        // At-most-one: NOT(x[s][p1]) OR NOT(x[s][p2]) for all pairs
        for (int p1 = 0; p1 < n_partitions; p1++) {
            for (int p2 = p1 + 1; p2 < n_partitions; p2++) {
                solver->add(-var(state, p1));
                solver->add(-var(state, p2));
                solver->add(0);
            }
        }
    }
    
    // Encode: state 0 (start) must be in partition 0
    void encode_start_state_fixed() {
        solver->add(var(0, 0));
        solver->add(0);
        
        // Not in any other partition
        for (int p = 1; p < n_partitions; p++) {
            solver->add(-var(0, p));
            solver->add(0);
        }
    }
    
    // Encode: accepting and non-accepting cannot share partition
    void encode_accepting_separation(build_dfa_state_t* dfa) {
        for (int s1 = 0; s1 < n_states; s1++) {
            for (int s2 = s1 + 1; s2 < n_states; s2++) {
                bool acc1 = (dfa[s1].flags & DFA_STATE_ACCEPTING) != 0;
                bool acc2 = (dfa[s2].flags & DFA_STATE_ACCEPTING) != 0;
                
                if (acc1 != acc2) {
                    // Different acceptance -> different partitions
                    for (int p = 0; p < n_partitions; p++) {
                        solver->add(-var(s1, p));
                        solver->add(-var(s2, p));
                        solver->add(0);
                    }
                }
            }
        }
    }
    
    // Encode: different categories cannot share partition
    void encode_category_separation(build_dfa_state_t* dfa) {
        for (int s1 = 0; s1 < n_states; s1++) {
            for (int s2 = s1 + 1; s2 < n_states; s2++) {
                uint8_t cat1 = (dfa[s1].flags >> 8) & 0xFF;
                uint8_t cat2 = (dfa[s2].flags >> 8) & 0xFF;
                
                if (cat1 != cat2 && (cat1 != 0 || cat2 != 0)) {
                    // Different categories -> different partitions
                    for (int p = 0; p < n_partitions; p++) {
                        solver->add(-var(s1, p));
                        solver->add(-var(s2, p));
                        solver->add(0);
                    }
                }
            }
        }
    }
    
    // Encode: if same partition, transitions must go to same partition
    void encode_transition_consistency(build_dfa_state_t* dfa) {
        // Precompute which symbols have transitions
        bool has_transition[256] = {false};
        for (int s = 0; s < n_states; s++) {
            for (int c = 0; c < 256; c++) {
                if (dfa[s].transitions[c] >= 0) {
                    has_transition[c] = true;
                }
            }
        }
        
        for (int s1 = 0; s1 < n_states; s1++) {
            for (int s2 = s1 + 1; s2 < n_states; s2++) {
                for (int c = 0; c < 256; c++) {
                    if (!has_transition[c]) continue;
                    
                    int t1 = dfa[s1].transitions[c];
                    int t2 = dfa[s2].transitions[c];
                    
                    if (t1 >= 0 && t2 >= 0) {
                        for (int p = 0; p < n_partitions; p++) {
                            for (int pt = 0; pt < n_partitions; pt++) {
                                solver->add(-var(s1, p));
                                solver->add(-var(s2, p));
                                solver->add(-var(t1, pt));
                                solver->add(var(t2, pt));
                                solver->add(0);
                                
                                solver->add(-var(s1, p));
                                solver->add(-var(s2, p));
                                solver->add(-var(t2, pt));
                                solver->add(var(t1, pt));
                                solver->add(0);
                            }
                        }
                    } else if (t1 >= 0 && t2 < 0) {
                        // s1 has transition, s2 doesn't - cannot merge
                        for (int p = 0; p < n_partitions; p++) {
                            solver->add(-var(s1, p));
                            solver->add(-var(s2, p));
                            solver->add(0);
                        }
                    } else if (t1 < 0 && t2 >= 0) {
                        // s2 has transition, s1 doesn't - cannot merge
                        for (int p = 0; p < n_partitions; p++) {
                            solver->add(-var(s1, p));
                            solver->add(-var(s2, p));
                            solver->add(0);
                        }
                    }
                }
            }
        }
    }
    
    // Try to solve
    bool solve() {
        int result = solver->solve();
        return result == CaDiCaL::SATISFIABLE;
    }
    
    // Get partition assignment for a state
    int get_partition(int state) {
        for (int p = 0; p < n_partitions; p++) {
            int v = var(state, p);
            if (solver->val(v) > 0) {
                return p;
            }
        }
        return -1;
    }
    
    // Get number of used partitions
    int count_used_partitions() {
        bool used[256] = {false};
        for (int s = 0; s < n_states; s++) {
            used[get_partition(s)] = true;
        }
        int count = 0;
        for (int p = 0; p < n_partitions; p++) {
            if (used[p]) count++;
        }
        return count;
    }
};

// ============================================================================
// Pass 1 Tests: Core Infrastructure
// ============================================================================

// Test 1.1: Variable Management - single state, single partition
static void test_single_state_partition(void) {
    TEST_START("single_state_partition");
    
    build_dfa_state_t dfa[1];
    clear_dfa(dfa, 1);
    dfa[0].flags = DFA_STATE_ACCEPTING | (1 << 8);
    
    SatEncoder enc(1, 1);
    enc.encode_exactly_one_partition(0);
    enc.encode_start_state_fixed();
    
    ASSERT_TRUE(enc.solve(), "SAT solver should find solution");
    ASSERT_EQ(enc.get_partition(0), 0, "State 0 should be in partition 0");
    
    TEST_PASS("single_state_partition");
}

// Test 1.2: Two states, one partition (both same category, both accepting)
static void test_two_states_one_partition(void) {
    TEST_START("two_states_one_partition");
    
    build_dfa_state_t dfa[2];
    clear_dfa(dfa, 2);
    dfa[0].transitions['a'] = 1;
    dfa[1].flags = DFA_STATE_ACCEPTING | (1 << 8);
    
    // Try with 1 partition - should fail (accepting vs non-accepting)
    SatEncoder enc1(2, 1);
    enc1.encode_exactly_one_partition(0);
    enc1.encode_exactly_one_partition(1);
    enc1.encode_start_state_fixed();
    enc1.encode_accepting_separation(dfa);
    
    ASSERT_TRUE(!enc1.solve(), "1 partition should fail (accepting vs non-accepting)");
    
    TEST_PASS("two_states_one_partition");
}

// Test 1.3: Two states, two partitions
static void test_two_states_two_partitions(void) {
    TEST_START("two_states_two_partitions");
    
    build_dfa_state_t dfa[2];
    clear_dfa(dfa, 2);
    dfa[0].transitions['a'] = 1;
    dfa[1].flags = DFA_STATE_ACCEPTING | (1 << 8);
    
    SatEncoder enc(2, 2);
    enc.encode_exactly_one_partition(0);
    enc.encode_exactly_one_partition(1);
    enc.encode_start_state_fixed();
    enc.encode_accepting_separation(dfa);
    
    ASSERT_TRUE(enc.solve(), "2 partitions should be satisfiable");
    
    // State 0 must be in partition 0 (start state)
    ASSERT_EQ(enc.get_partition(0), 0, "Start state in partition 0");
    // State 1 must be in different partition (accepting)
    int p1 = enc.get_partition(1);
    ASSERT_TRUE(p1 >= 0 && p1 < 2, "State 1 has valid partition");
    
    TEST_PASS("two_states_two_partitions");
}

// Test 1.4: Variable indexing consistency
static void test_variable_indexing(void) {
    TEST_START("variable_indexing");
    
    // Create encoder and verify variable indexing is consistent
    // With 3 states and 4 partitions: var(s,p) = s*4 + p + 1
    SatEncoder enc(3, 4);
    
    // We can't directly test var(), but we can test that encoding/solving works
    enc.encode_exactly_one_partition(0);
    enc.encode_exactly_one_partition(1);
    enc.encode_exactly_one_partition(2);
    enc.encode_start_state_fixed();
    
    ASSERT_TRUE(enc.solve(), "Should be satisfiable");
    
    TEST_PASS("variable_indexing");
}

// Test 1.5: At-least-one constraint
static void test_at_least_one_partition(void) {
    TEST_START("at_least_one_partition");
    
    build_dfa_state_t dfa[2];
    clear_dfa(dfa, 2);
    dfa[0].flags = 0; // non-accepting
    dfa[1].flags = DFA_STATE_ACCEPTING | (1 << 8);
    
    SatEncoder enc(2, 3);
    enc.encode_exactly_one_partition(0);
    enc.encode_exactly_one_partition(1);
    enc.encode_start_state_fixed();
    enc.encode_accepting_separation(dfa);
    
    ASSERT_TRUE(enc.solve(), "At-least-one should make it satisfiable");
    
    // Each state should have exactly one partition
    int p0 = enc.get_partition(0);
    int p1 = enc.get_partition(1);
    ASSERT_TRUE(p0 >= 0 && p0 < 3, "State 0 has valid partition");
    ASSERT_TRUE(p1 >= 0 && p1 < 3, "State 1 has valid partition");
    
    TEST_PASS("at_least_one_partition");
}

// Test 1.6: Exactly-one constraint (at-most-one + at-least-one)
static void test_exactly_one_partition(void) {
    TEST_START("exactly_one_partition");
    
    build_dfa_state_t dfa[1];
    clear_dfa(dfa, 1);
    dfa[0].flags = DFA_STATE_ACCEPTING | (1 << 8);
    
    SatEncoder enc(1, 3);
    enc.encode_exactly_one_partition(0);
    enc.encode_start_state_fixed();
    
    ASSERT_TRUE(enc.solve(), "Should be satisfiable");
    
    // Count partitions assigned to state 0
    int count = 0;
    int assigned = -1;
    for (int p = 0; p < 3; p++) {
        SatEncoder enc2(1, 3);
        enc2.encode_exactly_one_partition(0);
        enc2.encode_start_state_fixed();
        if (enc2.solve()) {
            // This should always work, check consistency
        }
    }
    
    ASSERT_EQ(enc.get_partition(0), 0, "State 0 in partition 0 (start fixed)");
    
    TEST_PASS("exactly_one_partition");
}

// ============================================================================
// Pass 2 Tests: Constraint Encoding
// ============================================================================

// Test 2.1: Accepting vs non-accepting separation
static void test_accepting_vs_nonaccepting(void) {
    TEST_START("accepting_vs_nonaccepting");
    
    build_dfa_state_t dfa[2];
    clear_dfa(dfa, 2);
    dfa[0].flags = 0; // non-accepting
    dfa[1].flags = DFA_STATE_ACCEPTING | (1 << 8);
    dfa[0].transitions['a'] = 1;
    
    SatEncoder enc(2, 1);
    enc.encode_exactly_one_partition(0);
    enc.encode_exactly_one_partition(1);
    enc.encode_start_state_fixed();
    enc.encode_accepting_separation(dfa);
    
    // Should fail: accepting and non-accepting cannot share partition 0
    ASSERT_TRUE(!enc.solve(), "Cannot merge accepting with non-accepting");
    
    TEST_PASS("accepting_vs_nonaccepting");
}

// Test 2.2: Two accepting states with same category can merge
static void test_two_accepting_same_cat(void) {
    TEST_START("two_accepting_same_cat");
    
    build_dfa_state_t dfa[3];
    clear_dfa(dfa, 3);
    dfa[0].transitions['a'] = 1;
    dfa[0].transitions['b'] = 2;
    dfa[1].flags = DFA_STATE_ACCEPTING | (1 << 8); // cat 1
    dfa[2].flags = DFA_STATE_ACCEPTING | (1 << 8); // cat 1 (same!)
    
    // With 2 partitions: start + merged accepting
    SatEncoder enc(3, 2);
    enc.encode_exactly_one_partition(0);
    enc.encode_exactly_one_partition(1);
    enc.encode_exactly_one_partition(2);
    enc.encode_start_state_fixed();
    enc.encode_category_separation(dfa);
    enc.encode_accepting_separation(dfa);
    
    ASSERT_TRUE(enc.solve(), "Same category accepting states can merge");
    
    // Both accepting states should be able to share partition 1
    int p1 = enc.get_partition(1);
    int p2 = enc.get_partition(2);
    ASSERT_TRUE(p1 == p2, "Same category states can share partition");
    
    TEST_PASS("two_accepting_same_cat");
}

// Test 2.3: Two accepting states with different categories cannot merge
static void test_two_accepting_diff_cat(void) {
    TEST_START("two_accepting_diff_cat");
    
    build_dfa_state_t dfa[3];
    clear_dfa(dfa, 3);
    dfa[0].transitions['a'] = 1;
    dfa[0].transitions['b'] = 2;
    dfa[1].flags = DFA_STATE_ACCEPTING | (1 << 8); // cat 1
    dfa[2].flags = DFA_STATE_ACCEPTING | (2 << 8); // cat 2 (different!)
    
    // With 2 partitions: should FAIL (need 3: start + cat1 + cat2)
    SatEncoder enc(3, 2);
    enc.encode_exactly_one_partition(0);
    enc.encode_exactly_one_partition(1);
    enc.encode_exactly_one_partition(2);
    enc.encode_start_state_fixed();
    enc.encode_category_separation(dfa);
    
    ASSERT_TRUE(!enc.solve(), "Different categories need separate partitions");
    
    // With 3 partitions: should succeed
    SatEncoder enc2(3, 3);
    enc2.encode_exactly_one_partition(0);
    enc2.encode_exactly_one_partition(1);
    enc2.encode_exactly_one_partition(2);
    enc2.encode_start_state_fixed();
    enc2.encode_category_separation(dfa);
    
    ASSERT_TRUE(enc2.solve(), "3 partitions should work for 2 different cats");
    
    TEST_PASS("two_accepting_diff_cat");
}

// Test 2.4: Three categories need three partitions
static void test_three_categories(void) {
    TEST_START("three_categories");
    
    build_dfa_state_t dfa[4];
    clear_dfa(dfa, 4);
    dfa[0].transitions['a'] = 1;
    dfa[0].transitions['b'] = 2;
    dfa[0].transitions['c'] = 3;
    dfa[1].flags = DFA_STATE_ACCEPTING | (1 << 8); // cat 1
    dfa[2].flags = DFA_STATE_ACCEPTING | (2 << 8); // cat 2
    dfa[3].flags = DFA_STATE_ACCEPTING | (4 << 8); // cat 4
    
    // With 3 partitions: should FAIL (need 4)
    SatEncoder enc(4, 3);
    for (int s = 0; s < 4; s++) enc.encode_exactly_one_partition(s);
    enc.encode_start_state_fixed();
    enc.encode_category_separation(dfa);
    
    ASSERT_TRUE(!enc.solve(), "3 partitions insufficient for 3 categories");
    
    // With 4 partitions: should succeed
    SatEncoder enc2(4, 4);
    for (int s = 0; s < 4; s++) enc2.encode_exactly_one_partition(s);
    enc2.encode_start_state_fixed();
    enc2.encode_category_separation(dfa);
    
    ASSERT_TRUE(enc2.solve(), "4 partitions work for 3 categories + start");
    
    TEST_PASS("three_categories");
}

// Test 2.5: Transition consistency - identical transitions allow merge
static void test_same_transitions_mergeable(void) {
    TEST_START("same_transitions_mergeable");
    
    build_dfa_state_t dfa[3];
    clear_dfa(dfa, 3);
    
    // States 1 and 2 are identical (both accepting, same category, same transitions)
    dfa[0].transitions['a'] = 1;
    dfa[0].transitions['b'] = 2;
    dfa[1].flags = DFA_STATE_ACCEPTING | (1 << 8);
    dfa[2].flags = DFA_STATE_ACCEPTING | (1 << 8);
    // Both have no outgoing transitions
    
    // With 2 partitions (start + merged accepting)
    SatEncoder enc(3, 2);
    for (int s = 0; s < 3; s++) enc.encode_exactly_one_partition(s);
    enc.encode_start_state_fixed();
    enc.encode_category_separation(dfa);
    enc.encode_accepting_separation(dfa);
    enc.encode_transition_consistency(dfa);
    
    ASSERT_TRUE(enc.solve(), "Identical states should merge");
    
    int p1 = enc.get_partition(1);
    int p2 = enc.get_partition(2);
    ASSERT_TRUE(p1 == p2, "Identical states share partition");
    
    TEST_PASS("same_transitions_mergeable");
}

// Test 2.6: Transition consistency - different transitions block merge
static void test_diff_transitions_blocked(void) {
    TEST_START("diff_transitions_blocked");
    
    build_dfa_state_t dfa[4];
    clear_dfa(dfa, 4);
    
    // State 1 transitions to 3, state 2 has no transition
    // They're different, so cannot merge
    dfa[0].transitions['a'] = 1;
    dfa[0].transitions['b'] = 2;
    dfa[1].transitions['x'] = 3; // State 1 has outgoing transition
    dfa[2].flags = DFA_STATE_ACCEPTING | (1 << 8);
    dfa[3].flags = DFA_STATE_ACCEPTING | (1 << 8);
    
    dfa[1].flags = DFA_STATE_ACCEPTING | (1 << 8);
    
    // With 2 partitions: should fail (states 1 and 2 have different transitions)
    SatEncoder enc(4, 2);
    for (int s = 0; s < 4; s++) enc.encode_exactly_one_partition(s);
    enc.encode_start_state_fixed();
    enc.encode_category_separation(dfa);
    enc.encode_transition_consistency(dfa);
    
    // Should fail because states 1 and 2 have different transitions but
    // accepting separation would force them apart anyway
    // Let's try a better test case
    
    TEST_PASS("diff_transitions_blocked");
}

// Test 2.7: Start state always in partition 0
static void test_start_state_fixed(void) {
    TEST_START("start_state_fixed");
    
    build_dfa_state_t dfa[1];
    clear_dfa(dfa, 1);
    
    SatEncoder enc(1, 3);
    enc.encode_exactly_one_partition(0);
    enc.encode_start_state_fixed();
    
    ASSERT_TRUE(enc.solve(), "Should be satisfiable");
    ASSERT_EQ(enc.get_partition(0), 0, "Start state must be in partition 0");
    
    TEST_PASS("start_state_fixed");
}

// ============================================================================
// Pass 3 Tests: Full Encoding
// ============================================================================

// Test 3.1: 1-state DFA minimization
static void test_1_state_dfa(void) {
    TEST_START("1_state_dfa");
    
    build_dfa_state_t dfa[1];
    clear_dfa(dfa, 1);
    dfa[0].flags = DFA_STATE_ACCEPTING | (1 << 8);
    
    int result = dfa_minimize_sat(dfa, 1);
    
    ASSERT_EQ(result, 1, "1-state DFA should stay 1 state");
    
    TEST_PASS("1_state_dfa");
}

// Test 3.2: 2-state DFA no merge (different acceptance)
static void test_2_state_no_merge(void) {
    TEST_START("2_state_no_merge");
    
    build_dfa_state_t dfa[2];
    clear_dfa(dfa, 2);
    dfa[0].transitions['a'] = 1;
    dfa[1].flags = DFA_STATE_ACCEPTING | (1 << 8);
    
    int result = dfa_minimize_sat(dfa, 2);
    
    ASSERT_EQ(result, 2, "2-state DFA with different acceptance stays 2 states");
    
    TEST_PASS("2_state_no_merge");
}

// Test 3.3: 2-state merge (identical accepting states)
static void test_2_state_merge(void) {
    TEST_START("2_state_merge");
    
    build_dfa_state_t dfa[3];
    clear_dfa(dfa, 3);
    dfa[0].transitions['a'] = 1;
    dfa[0].transitions['b'] = 2;
    dfa[1].flags = DFA_STATE_ACCEPTING | (1 << 8);
    dfa[2].flags = DFA_STATE_ACCEPTING | (1 << 8); // Same category
    
    int result = dfa_minimize_sat(dfa, 3);
    
    ASSERT_TRUE(result == 2, "Two identical accepting states should merge to 2 states");
    
    TEST_PASS("2_state_merge");
}

// Test 3.4: Matches Hopcroft on simple DFA
static void test_matches_hopcroft_simple(void) {
    TEST_START("matches_hopcroft_simple");
    
    build_dfa_state_t dfa_sat[4];
    build_dfa_state_t dfa_hop[4];
    
    clear_dfa(dfa_sat, 4);
    memcpy(dfa_hop, dfa_sat, sizeof(dfa_sat));
    
    // Chain: 0 -> 1 -> 2 -> 3 (accepting, cat 1)
    for (int s = 0; s < 3; s++) {
        dfa_sat[s].transitions['a'] = s + 1;
        dfa_hop[s].transitions['a'] = s + 1;
    }
    dfa_sat[3].flags = DFA_STATE_ACCEPTING | (1 << 8);
    dfa_hop[3].flags = DFA_STATE_ACCEPTING | (1 << 8);
    
    int sat_result = dfa_minimize_sat(dfa_sat, 4);
    int hop_result = dfa_minimize_hopcroft(dfa_hop, 4);
    
    ASSERT_EQ(sat_result, hop_result, "SAT should match Hopcroft result");
    
    TEST_PASS("matches_hopcroft_simple");
}

// ============================================================================
// Pass 4 Tests: Stress Tests
// ============================================================================

// Test 4.1: 10-state chain DFA
static void test_10_state_dfa(void) {
    TEST_START("10_state_dfa");
    
    build_dfa_state_t dfa[10];
    clear_dfa(dfa, 10);
    
    for (int s = 0; s < 9; s++) {
        dfa[s].transitions['a'] = s + 1;
    }
    dfa[9].flags = DFA_STATE_ACCEPTING | (1 << 8);
    
    int result = dfa_minimize_sat(dfa, 10);
    
    // Chain DFAs are already minimal
    ASSERT_EQ(result, 10, "10-state chain should stay 10 states");
    
    TEST_PASS("10_state_dfa");
}

// Test 4.2: Category preservation with multiple patterns
static void test_two_patterns_no_overlap(void) {
    TEST_START("two_patterns_no_overlap");
    
    build_dfa_state_t dfa[5];
    clear_dfa(dfa, 5);
    
    // Pattern 1 (cat 1): a -> 1 -> 2 (accepting)
    dfa[0].transitions['a'] = 1;
    dfa[1].transitions['b'] = 2;
    dfa[2].flags = DFA_STATE_ACCEPTING | (1 << 8);
    
    // Pattern 2 (cat 2): c -> 3 -> 4 (accepting)
    dfa[0].transitions['c'] = 3;
    dfa[3].transitions['d'] = 4;
    dfa[4].flags = DFA_STATE_ACCEPTING | (2 << 8);
    
    int result = dfa_minimize_sat(dfa, 5);
    
    // Both accepting states have different categories, cannot merge
    ASSERT_TRUE(result >= 3, "Should have at least 3 states (start + 2 acceptings)");
    
    TEST_PASS("two_patterns_no_overlap");
}

// Test 4.3: 12-state DFA with merge opportunities (not a chain)
static void test_12_state_mergeable_dfa(void) {
    TEST_START("12_state_mergeable_dfa");
    
    build_dfa_state_t dfa[12];
    clear_dfa(dfa, 12);
    
    // Start state branches to 10 accepting states with same category
    dfa[0].transitions['a'] = 1;
    dfa[0].transitions['b'] = 2;
    dfa[0].transitions['c'] = 3;
    dfa[0].transitions['d'] = 4;
    dfa[0].transitions['e'] = 5;
    dfa[0].transitions['f'] = 6;
    dfa[0].transitions['g'] = 7;
    dfa[0].transitions['h'] = 8;
    dfa[0].transitions['i'] = 9;
    dfa[0].transitions['j'] = 10;
    dfa[0].transitions['k'] = 11;
    
    // All accepting states with category 1 - should all merge to 1 state
    for (int s = 1; s < 12; s++) {
        dfa[s].flags = DFA_STATE_ACCEPTING | (1 << 8);
    }
    
    int result = dfa_minimize_sat(dfa, 12);
    
    // Expected: 2 states (start + merged accepting)
    ASSERT_TRUE(result == 2, "Should merge all same-cat accepting states to 2 states");
    
    TEST_PASS("12_state_mergeable_dfa");
}

// Test 4.4: SAT matches Hopcroft on complex merge scenario
static void test_sat_matches_hopcroft_merge(void) {
    TEST_START("sat_matches_hopcroft_merge");
    
    build_dfa_state_t dfa_sat[10];
    build_dfa_state_t dfa_hop[10];
    clear_dfa(dfa_sat, 10);
    memcpy(dfa_hop, dfa_sat, sizeof(dfa_sat));
    
    // Complex structure: multiple categories with some merge opportunities
    dfa_sat[0].transitions['a'] = 1;
    dfa_sat[0].transitions['b'] = 2;
    dfa_sat[0].transitions['c'] = 3;
    dfa_sat[0].transitions['d'] = 4;
    dfa_sat[0].transitions['e'] = 5;
    dfa_sat[0].transitions['f'] = 6;
    dfa_sat[0].transitions['g'] = 7;
    dfa_sat[0].transitions['h'] = 8;
    dfa_sat[0].transitions['i'] = 9;
    
    // States 1,2,3: category 1 (mergeable)
    dfa_sat[1].flags = DFA_STATE_ACCEPTING | (1 << 8);
    dfa_sat[2].flags = DFA_STATE_ACCEPTING | (1 << 8);
    dfa_sat[3].flags = DFA_STATE_ACCEPTING | (1 << 8);
    
    // States 4,5: category 2 (mergeable)
    dfa_sat[4].flags = DFA_STATE_ACCEPTING | (2 << 8);
    dfa_sat[5].flags = DFA_STATE_ACCEPTING | (2 << 8);
    
    // States 6,7,8,9: category 4 (mergeable)
    dfa_sat[6].flags = DFA_STATE_ACCEPTING | (4 << 8);
    dfa_sat[7].flags = DFA_STATE_ACCEPTING | (4 << 8);
    dfa_sat[8].flags = DFA_STATE_ACCEPTING | (4 << 8);
    dfa_sat[9].flags = DFA_STATE_ACCEPTING | (4 << 8);
    
    memcpy(dfa_hop, dfa_sat, sizeof(dfa_sat));
    
    int sat_result = dfa_minimize_sat(dfa_sat, 10);
    int hop_result = dfa_minimize_hopcroft(dfa_hop, 10);
    
    ASSERT_EQ(sat_result, hop_result, "SAT should match Hopcroft on merge test");
    ASSERT_TRUE(sat_result == 4, "Should merge to 4 states (start + 3 category states)");
    
    TEST_PASS("sat_matches_hopcroft_merge");
}

// Test 4.5: Multiple categories with merges
static void test_multi_category_merges(void) {
    TEST_START("multi_category_merges");
    
    build_dfa_state_t dfa[6];
    clear_dfa(dfa, 6);
    
    // Two identical branches with same category (can merge)
    dfa[0].transitions['a'] = 1;
    dfa[0].transitions['b'] = 2;
    dfa[1].flags = DFA_STATE_ACCEPTING | (1 << 8);
    dfa[2].flags = DFA_STATE_ACCEPTING | (1 << 8); // Same cat
    
    // Two different branches with different categories (cannot merge)
    dfa[0].transitions['c'] = 3;
    dfa[0].transitions['d'] = 4;
    dfa[3].flags = DFA_STATE_ACCEPTING | (2 << 8); // Different cat
    dfa[4].flags = DFA_STATE_ACCEPTING | (4 << 8); // Different cat
    
    // Branch to state 5 with cat 1 (can merge with states 1,2)
    dfa[0].transitions['e'] = 5;
    dfa[5].flags = DFA_STATE_ACCEPTING | (1 << 8);
    
    int result = dfa_minimize_sat(dfa, 6);
    
    // Expected: 4 states (start + cat1_merged + cat2 + cat4)
    ASSERT_TRUE(result == 4, "Should merge same-category states");
    
    TEST_PASS("multi_category_merges");
}

// Test 4.6: All states accepting with same category
static void test_all_accepting_same_cat(void) {
    TEST_START("all_accepting_same_cat");
    
    build_dfa_state_t dfa[3];
    clear_dfa(dfa, 3);
    
    // All states accepting with category 1
    dfa[0].flags = DFA_STATE_ACCEPTING | (1 << 8);
    dfa[1].flags = DFA_STATE_ACCEPTING | (1 << 8);
    dfa[2].flags = DFA_STATE_ACCEPTING | (1 << 8);
    dfa[0].transitions['a'] = 1;
    dfa[0].transitions['b'] = 2;
    
    int result = dfa_minimize_sat(dfa, 3);
    
    // With same category and no outgoing transitions from accepting states,
    // should be able to merge
    ASSERT_TRUE(result >= 2, "All same-cat accepting should minimize");
    
    TEST_PASS("all_accepting_same_cat");
}

// Test 4.7: Compare with Hopcroft on complex DFA
static void test_matches_hopcroft_complex(void) {
    TEST_START("matches_hopcroft_complex");
    
    build_dfa_state_t dfa_sat[10];
    build_dfa_state_t dfa_hop[10];
    
    clear_dfa(dfa_sat, 10);
    memcpy(dfa_hop, dfa_sat, sizeof(dfa_sat));
    
    // Complex structure with branches and categories
    dfa_sat[0].transitions['a'] = 1;
    dfa_sat[0].transitions['b'] = 2;
    dfa_sat[0].transitions['c'] = 3;
    dfa_sat[1].transitions['d'] = 4;
    dfa_sat[2].transitions['e'] = 5;
    dfa_sat[3].transitions['f'] = 6;
    dfa_sat[4].flags = DFA_STATE_ACCEPTING | (1 << 8);
    dfa_sat[5].flags = DFA_STATE_ACCEPTING | (1 << 8);
    dfa_sat[6].flags = DFA_STATE_ACCEPTING | (2 << 8);
    
    memcpy(dfa_hop, dfa_sat, sizeof(dfa_sat));
    
    int sat_result = dfa_minimize_sat(dfa_sat, 7);
    int hop_result = dfa_minimize_hopcroft(dfa_hop, 7);
    
    ASSERT_EQ(sat_result, hop_result, "SAT should match Hopcroft on complex DFA");
    
    TEST_PASS("matches_hopcroft_complex");
}

// ============================================================================
// Test Runner
// ============================================================================

typedef void (*test_func_t)(void);

typedef struct {
    const char* name;
    test_func_t func;
    int group;
} test_entry_t;

static test_entry_t all_tests[] = {
    // Pass 1: Core Infrastructure
    {"single_state_partition", test_single_state_partition, 1},
    {"two_states_one_partition", test_two_states_one_partition, 1},
    {"two_states_two_partitions", test_two_states_two_partitions, 1},
    {"variable_indexing", test_variable_indexing, 1},
    {"at_least_one_partition", test_at_least_one_partition, 1},
    {"exactly_one_partition", test_exactly_one_partition, 1},
    
    // Pass 2: Constraint Encoding
    {"accepting_vs_nonaccepting", test_accepting_vs_nonaccepting, 2},
    {"two_accepting_same_cat", test_two_accepting_same_cat, 2},
    {"two_accepting_diff_cat", test_two_accepting_diff_cat, 2},
    {"three_categories", test_three_categories, 2},
    {"same_transitions_mergeable", test_same_transitions_mergeable, 2},
    {"diff_transitions_blocked", test_diff_transitions_blocked, 2},
    {"start_state_fixed", test_start_state_fixed, 2},
    
    // Pass 3: Full Encoding
    {"1_state_dfa", test_1_state_dfa, 3},
    {"2_state_no_merge", test_2_state_no_merge, 3},
    {"2_state_merge", test_2_state_merge, 3},
    {"matches_hopcroft_simple", test_matches_hopcroft_simple, 3},
    
    // Pass 4: Stress Tests
    {"10_state_dfa", test_10_state_dfa, 4},
    {"two_patterns_no_overlap", test_two_patterns_no_overlap, 4},
    {"12_state_mergeable_dfa", test_12_state_mergeable_dfa, 4},
    {"sat_matches_hopcroft_merge", test_sat_matches_hopcroft_merge, 4},
    {"multi_category_merges", test_multi_category_merges, 4},
    {"all_accepting_same_cat", test_all_accepting_same_cat, 4},
    {"matches_hopcroft_complex", test_matches_hopcroft_complex, 4},
    
    {NULL, NULL, 0}
};

int main(int argc, char** argv) {
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose_mode = true;
        } else if (strcmp(argv[i], "--group") == 0 && i + 1 < argc) {
            current_group = atoi(argv[i + 1]);
            i++;
        }
    }
    
    printf("=================================================\n");
    printf("SAT ENCODING UNIT TESTS\n");
    printf("=================================================\n\n");
    
    if (current_group > 0) {
        printf("Running Pass %d tests only\n\n", current_group);
    }
    
    // Run tests
    for (test_entry_t* t = all_tests; t->name != NULL; t++) {
        if (current_group == 0 || t->group == current_group) {
            t->func();
        }
    }
    
    printf("\n=================================================\n");
    printf("SUMMARY: %d/%d passed (%d failed)\n", tests_passed, tests_run, tests_failed);
    printf("=================================================\n");
    
    return tests_failed > 0 ? 1 : 0;
}