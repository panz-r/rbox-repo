/**
 * nfa_dsl_utils.h - DSL utilities for NFA and DFA testing
 *
 * Provides helper functions and macros for verifying NFA and DFA structure
 * by inspecting serialized DSL output.
 *
 * Two sets of helpers:
 *   - DSL NFA Query Helpers: work with dsl_nfa_t (parsed NFA DSL)
 *   - DSL DFA Query Helpers: work with dsl_dfa_t (parsed DFA DSL)
 */

#ifndef _NFA_DSL_UTILS_H
#define _NFA_DSL_UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "../include/nfa_dsl.h"
#include "../lib/nfa_builder.h"

/**
 * DSL NFA Query Helpers
 * 
 * These functions work with dsl_nfa_t (parsed from DSL) to verify
 * transition structure without needing a full nfa_graph_t.
 */

/**
 * Check if a state has a transition on a symbol to a specific target.
 */
bool dsl_has_transition(const dsl_nfa_t *nfa, int from, int sym, int to);

/**
 * Check if a state has an epsilon transition to a specific target.
 */
static inline bool dsl_has_epsilon(const dsl_nfa_t *nfa, int from, int to) {
    return dsl_has_transition(nfa, from, VSYM_EPS, to);
}

/**
 * Check if a state is accepting with optional category mask.
 */
bool dsl_state_is_accepting(const dsl_nfa_t *nfa, int state, uint8_t mask);

/**
 * Check if a transition has a specific marker value.
 */
bool dsl_has_marker(const dsl_nfa_t *nfa, int from, int sym, uint32_t marker);

/**
 * Check if a path exists from 'from' to 'to' following the symbol sequence.
 * Uses BFS to find any valid path.
 */
bool dsl_has_path(const dsl_nfa_t *nfa, int from, int to, const int *seq, int len);

/**
 * Extract symbol sequence from a canonical NFA DSL string.
 * Skips epsilon transitions (VSYM_EPS) if skip_eps is true.
 * Also skips SPACE/TAB transitions (whitespace normalization artifacts).
 * Returns the number of symbols extracted (up to max_syms).
 */
int dsl_extract_symbol_sequence(const char *dsl, int *symbols, int max_syms, bool skip_eps);

/**
 * Assert that the NFA's transition sequence matches the expected list.
 * Prints diagnostics to stderr on mismatch.
 * @param graph: nfa_graph_t to check
 * @param expected: array of expected symbol IDs
 * @param count: number of expected symbols
 * @param skip_eps: if true, skip epsilon transitions
 * @return: true if sequence matches, false otherwise
 */
bool nfa_assert_symbol_sequence(const nfa_graph_t *graph,
                                 const int *expected_symbols,
                                 int expected_count,
                                 bool skip_eps);

/**
 * Macro wrapper for nfa_assert_symbol_sequence that infers array size.
 * Usage: ASSERT_NFA_SYMBOL_SEQUENCE(graph, (int[]){'a','b','c'}, true);
 */
#define ASSERT_NFA_SYMBOL_SEQUENCE(graph, expected, skip_eps) \
    nfa_assert_symbol_sequence(graph, expected, sizeof(expected)/sizeof(int), skip_eps)

/* ============================================================================
 * DSL DFA Query Helpers
 *
 * These functions work with dsl_dfa_t (parsed from DFA DSL) to verify
 * transition structure without needing the full build_dfa_state_t array.
 * ============================================================================ */

/**
 * Get the number of states in a parsed DFA.
 */
int dfa_dsl_get_state_count(const dsl_dfa_t *dfa);

/**
 * Get the number of transitions in a state.
 */
int dfa_dsl_get_transition_count(const dsl_dfa_t *dfa, int state_id);

/**
 * Check if a state has a transition on the given symbol.
 */
bool dfa_dsl_has_transition(const dsl_dfa_t *dfa, int state_id, int symbol);

/**
 * Get the target state for a transition on a given symbol.
 * Returns -1 if no such transition exists.
 */
int dfa_dsl_get_target(const dsl_dfa_t *dfa, int state_id, int symbol);

/**
 * Check if a state is accepting.
 */
bool dfa_dsl_is_accepting(const dsl_dfa_t *dfa, int state_id);

/**
 * Check if a state is the start state.
 */
bool dfa_dsl_is_start(const dsl_dfa_t *dfa, int state_id);

/**
 * Get the category mask for a state.
 * Returns 0 if state doesn't exist or has no category.
 */
uint8_t dfa_dsl_get_category(const dsl_dfa_t *dfa, int state_id);

/**
 * Check if a transition has a marker with the given value.
 */
bool dfa_dsl_transition_has_marker(const dsl_dfa_t *dfa, int state_id,
                                   int symbol, uint32_t marker_value);

/**
 * Check if a state has the EOS (end-of-sequence) flag.
 */
bool dfa_dsl_state_has_eos(const dsl_dfa_t *dfa, int state_id);

/**
 * Get the EOS target for a state.
 * Returns -1 if no EOS target.
 */
int dfa_dsl_get_eos_target(const dsl_dfa_t *dfa, int state_id);

/**
 * Find states that are reachable from the start state via BFS.
 * Fills the provided array with state IDs (max count elements).
 * Returns the actual number of states found.
 */
int dfa_dsl_find_reachable_states(const dsl_dfa_t *dfa, int *out_states, int max_count);

/**
 * Check if two DFAs are structurally isomorphic (same shape, different state IDs).
 * Uses canonical BFS numbering to determine isomorphism.
 * Returns true if isomorphic.
 */
bool dfa_dsl_is_isomorphic(const dsl_dfa_t *a, const dsl_dfa_t *b);

#endif /* _NFA_DSL_UTILS_H */
