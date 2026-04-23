/**
 * nfa_dsl_utils.h - DSL utilities for NFA testing
 *
 * Provides helper functions and macros for verifying NFA structure
 * by inspecting serialized DSL output.
 */

#ifndef _NFA_DSL_UTILS_H
#define _NFA_DSL_UTILS_H

#include <stdbool.h>
#include <stddef.h>
#include "../lib/nfa_builder.h"

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

#endif /* _NFA_DSL_UTILS_H */
