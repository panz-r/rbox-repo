/**
 * DFA Layout Optimizer
 * 
 * Optimizes the binary layout of DFA states for cache performance.
 * Uses BFS-based ordering to place frequently-accessed states together.
 */

#ifndef DFA_LAYOUT_H
#define DFA_LAYOUT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "../include/dfa_types.h"
#include "dfa_minimize.h"  // For build_dfa_state_t

/**
 * Layout optimization options
 */
typedef struct {
    bool reorder_states;        // Reorder states by access frequency
    bool place_rules_near_state; // Place rule tables near their source state
    bool align_cache_lines;     // Align structures to 64-byte cache lines
    int cache_line_size;        // Cache line size (default 64)
} layout_options_t;

/**
 * Get default layout options (all optimizations enabled)
 */
layout_options_t get_default_layout_options(void);

/**
 * Build state access order using BFS from start state.
 * Returns an array mapping old_state -> new_position.
 * Caller must free the returned array.
 */
int* build_state_order_bfs(build_dfa_state_t** dfa, int state_count);

/**
 * Calculate the size of the optimized DFA layout.
 * Returns the total size in bytes.
 */
size_t calculate_optimized_layout_size(
    const build_dfa_state_t** dfa,
    int state_count,
    const layout_options_t* options
);

/**
 * Apply layout optimization to the DFA.
 * Reorders states and rules for cache performance.
 * Returns the new state order (old_state -> new_position).
 */
int* optimize_dfa_layout(
    build_dfa_state_t** dfa,
    int state_count,
    const layout_options_t* options
);

#endif // DFA_LAYOUT_H
