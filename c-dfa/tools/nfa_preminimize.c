/**
 * NFA Pre-Minimization Implementation
 * 
 * Reduces NFA states before subset construction using:
 * 1. Bisimulation reduction - merge states with identical futures
 * 2. Common suffix merging - patterns with same endings share states
 * 3. Unreachable state pruning
 * 
 * Key advantage: We have global knowledge of the full NFA, unlike the
 * per-pattern RDP parser which has no look-ahead.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "nfa_preminimize.h"
#include "../include/multi_target_array.h"

// Statistics from last run
static nfa_premin_stats_t last_stats = {0};
static bool premin_verbose = false;

#define VERBOSE_PRINT(...) do { \
    if (premin_verbose) fprintf(stderr, "[PREMIN] " __VA_ARGS__); \
} while(0)

// Maximum iterations for bisimulation convergence
#define MAX_BISIM_ITERATIONS 100

/**
 * Get default options
 */
nfa_premin_options_t nfa_premin_default_options(void) {
    nfa_premin_options_t opts = {
        .enable_epsilon_elim = false,  // Disabled - needs deep copy of multi_targets
        .enable_landing_pad = false,   // Disable common suffix merging - too aggressive
        .enable_prune = true,          // Remove unreachable states
        .enable_merge = false,         // Disabled - old bisimulation is too aggressive
        .enable_sat = false,           // Disable SAT - needs more work
        .verbose = false
    };
    return opts;
}

/**
 * Get statistics from last run
 */
void nfa_premin_get_stats(nfa_premin_stats_t* stats) {
    if (stats) *stats = last_stats;
}

/**
 * Compute a signature hash for an NFA state.
 * 
 * The signature captures:
 * - Outgoing transitions (symbol → target)
 * - Category mask
 * - Accepting status
 * - Pending markers
 */
uint64_t nfa_compute_state_signature(const nfa_state_t* nfa, int state_idx) {
    const nfa_state_t* state = &nfa[state_idx];
    
    // FNV-1a hash
    uint64_t hash = 14695981039346656037ULL;
    
    // Hash category mask
    hash ^= state->category_mask;
    hash *= 1099511628211ULL;
    
    // Hash pattern ID
    hash ^= state->pattern_id;
    hash *= 1099511628211ULL;
    
    // Hash pending marker count
    hash ^= state->pending_marker_count;
    hash *= 1099511628211ULL;
    
    // Hash pending markers
    for (int i = 0; i < state->pending_marker_count; i++) {
        hash ^= state->pending_markers[i].pattern_id;
        hash *= 1099511628211ULL;
        hash ^= state->pending_markers[i].type;
        hash *= 1099511628211ULL;
    }
    
    // Hash transitions - only non-negative transitions
    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
        if (state->transitions[sym] >= 0) {
            hash ^= (uint64_t)sym;
            hash *= 1099511628211ULL;
            hash ^= (uint64_t)state->transitions[sym];
            hash *= 1099511628211ULL;
        }
    }
    
    // Hash multi-targets if present
    int mta_count = mta_get_entry_count((multi_target_array_t*)&state->multi_targets);
    if (mta_count > 0) {
        hash ^= mta_count;
        hash *= 1099511628211ULL;
        // Hash first few multi-targets
        for (int sym = 0; sym < MAX_SYMBOLS && mta_count > 0; sym++) {
            int target_count;
            int* targets = mta_get_target_array((multi_target_array_t*)&state->multi_targets, sym, &target_count);
            if (targets && target_count > 0) {
                hash ^= sym;
                hash *= 1099511628211ULL;
                for (int i = 0; i < target_count && i < 4; i++) {
                    hash ^= targets[i];
                    hash *= 1099511628211ULL;
                }
                mta_count--;
            }
        }
    }
    
    return hash;
}

/**
 * Partition-based bisimulation reduction.
 * 
 * This is similar to DFA minimization but for NFAs.
 * States in the same partition have the same "future behavior".
 */
static int bisimulation_reduce(nfa_state_t* nfa, int state_count, bool* dead_states, int* partition) {
    // Initialize: accepting states in different partitions based on category/pattern
    // Use small partition IDs (0, 1, 2, ...) for array indexing
    int next_partition_id = 0;
    
    // First pass: assign initial partitions based on state properties
    for (int s = 0; s < state_count; s++) {
        if (dead_states[s]) {
            partition[s] = -1;
            continue;
        }
        
        const nfa_state_t* state = &nfa[s];
        
        // Find existing partition with same properties
        int props = (state->category_mask << 16) | (state->pattern_id << 8) | state->pending_marker_count;
        
        int found = -1;
        for (int s2 = 0; s2 < s; s2++) {
            if (dead_states[s2]) continue;
            const nfa_state_t* state2 = &nfa[s2];
            int props2 = (state2->category_mask << 16) | (state2->pattern_id << 8) | state2->pending_marker_count;
            if (props == props2) {
                found = partition[s2];
                break;
            }
        }
        
        if (found >= 0) {
            partition[s] = found;
        } else {
            partition[s] = next_partition_id++;
        }
    }
    
    VERBOSE_PRINT("  Initial partitions: %d\n", next_partition_id);
    
    // Iterative refinement
    bool changed = true;
    int iterations = 0;
    
    while (changed && iterations < MAX_BISIM_ITERATIONS) {
        changed = false;
        iterations++;
        
        // For each pair of states in the same partition, check if they still belong together
        for (int s1 = 0; s1 < state_count; s1++) {
            if (dead_states[s1] || partition[s1] < 0) continue;
            
            for (int s2 = s1 + 1; s2 < state_count; s2++) {
                if (dead_states[s2] || partition[s2] != partition[s1]) continue;
                
                // Check if s1 and s2 have compatible transitions
                bool compatible = true;
                const nfa_state_t* state1 = &nfa[s1];
                const nfa_state_t* state2 = &nfa[s2];
                
                // Check single transitions
                for (int sym = 0; sym < MAX_SYMBOLS && compatible; sym++) {
                    int t1 = state1->transitions[sym];
                    int t2 = state2->transitions[sym];
                    
                    if (t1 >= 0 && t2 >= 0) {
                        // Both have transition - targets must be in same partition
                        if (partition[t1] != partition[t2]) {
                            compatible = false;
                        }
                    } else if (t1 >= 0 || t2 >= 0) {
                        // Only one has transition - incompatible
                        compatible = false;
                    }
                }
                
                // Check multi-targets
                if (compatible) {
                    int mta1 = mta_get_entry_count((multi_target_array_t*)&state1->multi_targets);
                    int mta2 = mta_get_entry_count((multi_target_array_t*)&state2->multi_targets);
                    if (mta1 != mta2) {
                        compatible = false;
                    }
                }
                
                if (!compatible) {
                    // Split partition - move s2 to a new partition
                    partition[s2] = next_partition_id++;
                    changed = true;
                }
            }
        }
    }
    
    VERBOSE_PRINT("  Bisimulation converged in %d iterations, %d partitions\n", iterations, next_partition_id);
    
    // Now merge states in the same partition
    // For each partition, keep the first state, redirect others to it
    int* partition_rep = malloc(state_count * sizeof(int));
    memset(partition_rep, -1, state_count * sizeof(int));
    
    int merged = 0;
    
    for (int s = 0; s < state_count; s++) {
        if (dead_states[s] || partition[s] < 0) continue;
        
        int p = partition[s];
        
        if (p < state_count && partition_rep[p] < 0) {
            // First state in this partition - becomes representative
            partition_rep[p] = s;
        } else if (p < state_count) {
            // Redirect all transitions to the representative
            int rep = partition_rep[p];
            
            // Redirect incoming transitions
            for (int src = 0; src < state_count; src++) {
                if (dead_states[src]) continue;
                
                nfa_state_t* src_state = &nfa[src];
                
                for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                    if (src_state->transitions[sym] == s) {
                        src_state->transitions[sym] = rep;
                    }
                }
                
                // Check multi-targets
                for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                    int count;
                    int* targets = mta_get_target_array(&src_state->multi_targets, sym, &count);
                    if (targets && count > 0) {
                        for (int i = 0; i < count; i++) {
                            if (targets[i] == s) {
                                targets[i] = rep;
                            }
                        }
                    }
                }
            }
            
            // Merge pending markers if any
            if (nfa[s].pending_marker_count > 0 && nfa[rep].pending_marker_count < MAX_PENDING_MARKERS) {
                for (int i = 0; i < nfa[s].pending_marker_count && nfa[rep].pending_marker_count < MAX_PENDING_MARKERS; i++) {
                    nfa[rep].pending_markers[nfa[rep].pending_marker_count++] = nfa[s].pending_markers[i];
                }
            }
            
            dead_states[s] = true;
            merged++;
            VERBOSE_PRINT("  Merged bisimilar state %d into %d\n", s, rep);
        }
    }
    
    free(partition_rep);
    return merged;
}

/**
 * Find and merge common suffix states.
 * 
 * Multiple patterns ending with the same character sequence can share states.
 * This is a backward analysis from accepting states.
 */
static int merge_common_suffixes(nfa_state_t* nfa, int state_count, bool* dead_states) {
    int merged = 0;
    
    // Find all accepting states
    int* accepting = malloc(state_count * sizeof(int));
    int accept_count = 0;
    
    for (int s = 0; s < state_count; s++) {
        if (!dead_states[s] && nfa[s].category_mask != 0) {
            accepting[accept_count++] = s;
        }
    }
    
    VERBOSE_PRINT("  Found %d accepting states\n", accept_count);
    
    // For each pair of accepting states with same category and pattern_id
    for (int i = 0; i < accept_count; i++) {
        int s1 = accepting[i];
        if (dead_states[s1]) continue;
        
        for (int j = i + 1; j < accept_count; j++) {
            int s2 = accepting[j];
            if (dead_states[s2]) continue;
            
            // Check if they have same category and pattern_id
            if (nfa[s1].category_mask != nfa[s2].category_mask) continue;
            if (nfa[s1].pattern_id != nfa[s2].pattern_id) continue;
            if (nfa[s1].pending_marker_count != nfa[s2].pending_marker_count) continue;
            
            // Check pending markers
            bool markers_match = true;
            for (int m = 0; m < nfa[s1].pending_marker_count && markers_match; m++) {
                if (nfa[s1].pending_markers[m].pattern_id != nfa[s2].pending_markers[m].pattern_id ||
                    nfa[s1].pending_markers[m].type != nfa[s2].pending_markers[m].type) {
                    markers_match = false;
                }
            }
            if (!markers_match) continue;
            
            // Check if they have identical outgoing transitions
            bool transitions_match = true;
            for (int sym = 0; sym < MAX_SYMBOLS && transitions_match; sym++) {
                if (nfa[s1].transitions[sym] != nfa[s2].transitions[sym]) {
                    transitions_match = false;
                }
            }
            
            // Check multi-targets
            if (transitions_match) {
                int mta1 = mta_get_entry_count((multi_target_array_t*)&nfa[s1].multi_targets);
                int mta2 = mta_get_entry_count((multi_target_array_t*)&nfa[s2].multi_targets);
                if (mta1 != mta2) {
                    transitions_match = false;
                }
            }
            
            if (transitions_match) {
                // Merge s2 into s1
                for (int src = 0; src < state_count; src++) {
                    if (dead_states[src]) continue;
                    
                    nfa_state_t* src_state = &nfa[src];
                    
                    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                        if (src_state->transitions[sym] == s2) {
                            src_state->transitions[sym] = s1;
                        }
                    }
                    
                    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                        int count;
                        int* targets = mta_get_target_array(&src_state->multi_targets, sym, &count);
                        if (targets && count > 0) {
                            for (int k = 0; k < count; k++) {
                                if (targets[k] == s2) {
                                    targets[k] = s1;
                                }
                            }
                        }
                    }
                }
                
                dead_states[s2] = true;
                merged++;
                VERBOSE_PRINT("  Merged accepting state %d into %d (common suffix)\n", s2, s1);
            }
        }
    }
    
    free(accepting);
    return merged;
}

/**
 * Remove unreachable states using BFS from state 0
 * Note: Epsilon transitions use symbol ID 257 (VSYM_EPS)
 */
static int remove_unreachable(nfa_state_t* nfa, int state_count, bool* dead_states) {
    bool* reachable = calloc(state_count, sizeof(bool));
    int* queue = malloc(state_count * sizeof(int));
    int queue_head = 0, queue_tail = 0;
    
    // Start from state 0
    queue[queue_tail++] = 0;
    reachable[0] = true;
    
    // BFS
    while (queue_head < queue_tail) {
        int s = queue[queue_head++];
        nfa_state_t* state = &nfa[s];
        
        // Check all transitions (including epsilon = 257)
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int target = state->transitions[sym];
            if (target >= 0 && !reachable[target] && !dead_states[target]) {
                reachable[target] = true;
                queue[queue_tail++] = target;
            }
        }
        
        // Check multi-targets using API (including epsilon)
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int count;
            int* targets = mta_get_target_array(&state->multi_targets, sym, &count);
            if (targets && count > 0) {
                for (int i = 0; i < count; i++) {
                    int target = targets[i];
                    if (target >= 0 && !reachable[target] && !dead_states[target]) {
                        reachable[target] = true;
                        queue[queue_tail++] = target;
                    }
                }
            }
        }
    }
    
    // Mark unreachable as dead
    int removed = 0;
    for (int s = 0; s < state_count; s++) {
        if (!reachable[s] && !dead_states[s]) {
            dead_states[s] = true;
            removed++;
        }
    }
    
    free(reachable);
    free(queue);
    
    return removed;
}

/**
 * Redirect transitions away from dead states
 */
static void redirect_transitions(nfa_state_t* nfa, int state_count, const bool* dead_states, const int* remap) {
    for (int s = 0; s < state_count; s++) {
        if (dead_states[s]) continue;
        
        nfa_state_t* state = &nfa[s];
        
        // Redirect symbol transitions
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int target = state->transitions[sym];
            if (target >= 0 && dead_states[target]) {
                state->transitions[sym] = remap[target];
            }
        }
        
        // Redirect multi-targets using API
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int count;
            int* targets = mta_get_target_array(&state->multi_targets, sym, &count);
            if (targets && count > 0) {
                for (int i = 0; i < count; i++) {
                    if (targets[i] >= 0 && dead_states[targets[i]]) {
                        targets[i] = remap[targets[i]];
                    }
                }
            }
        }
    }
}

/**
 * Compact NFA by removing dead states
 * This requires deep-copying multi_targets to avoid pointer corruption
 */
static int compact_nfa(nfa_state_t* nfa, int state_count, const bool* dead_states) {
    int* remap = malloc(state_count * sizeof(int));
    int new_count = 0;
    
    // Compute remapping
    for (int s = 0; s < state_count; s++) {
        if (!dead_states[s]) {
            remap[s] = new_count++;
        } else {
            remap[s] = -1;
        }
    }
    
    // First, redirect all transitions to use the new state indices
    // This must be done BEFORE moving states
    for (int s = 0; s < state_count; s++) {
        if (dead_states[s]) continue;
        
        nfa_state_t* state = &nfa[s];
        
        // Redirect symbol transitions
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int target = state->transitions[sym];
            if (target >= 0) {
                if (dead_states[target]) {
                    // Transition to dead state - remove it
                    state->transitions[sym] = -1;
                } else {
                    // Remap to new index
                    state->transitions[sym] = remap[target];
                }
            }
        }
        
        // Redirect multi-targets
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int count;
            int* targets = mta_get_target_array(&state->multi_targets, sym, &count);
            if (targets && count > 0) {
                int write_i = 0;
                for (int i = 0; i < count; i++) {
                    int target = targets[i];
                    if (target >= 0 && !dead_states[target]) {
                        targets[write_i++] = remap[target];
                    }
                }
                // Update count if we removed any targets
                if (write_i != count) {
                    // Need to update the count in the entry
                    // This is handled by clearing and re-adding
                    mta_entry_t* entry = state->multi_targets.symbol_map[sym];
                    if (entry) {
                        entry->target_count = write_i;
                    }
                }
            }
        }
    }
    
    // Now compact states - need to handle multi_targets carefully
    int write_idx = 0;
    for (int s = 0; s < state_count; s++) {
        if (!dead_states[s]) {
            if (write_idx != s) {
                // Move state - this is safe because we already remapped all indices
                // and we're moving from higher index to lower index
                nfa[write_idx] = nfa[s];
                // Clear the old state's multi_targets to prevent double-free
                // (the pointers are now owned by the new location)
                memset(&nfa[s].multi_targets, 0, sizeof(multi_target_array_t));
            }
            write_idx++;
        }
    }
    
    free(remap);
    return new_count;
}

/**
 * Main pre-minimization function
 */
int nfa_preminimize(nfa_state_t* nfa, int* state_count, const nfa_premin_options_t* options) {
    nfa_premin_options_t opts = options ? *options : nfa_premin_default_options();
    premin_verbose = opts.verbose;
    
    int original_count = *state_count;
    memset(&last_stats, 0, sizeof(last_stats));
    last_stats.original_states = original_count;
    
    if (original_count <= 1) return 0;
    
    // Early exit if no optimizations enabled - avoid allocating dead_states
    if (!opts.enable_prune && !opts.enable_landing_pad && !opts.enable_merge && !opts.enable_sat) {
        VERBOSE_PRINT("Pre-minimization: No optimizations enabled, skipping\n");
        return 0;
    }
    
    VERBOSE_PRINT("Pre-minimizing NFA with %d states\n", original_count);
    
    // Allocate dead state tracking and partition array
    bool* dead_states = calloc(original_count, sizeof(bool));
    int* partition = malloc(original_count * sizeof(int));
    
    // Phase 1: Remove unreachable states first
    if (opts.enable_prune) {
        VERBOSE_PRINT("Removing unreachable states...\n");
        last_stats.unreachable_removed = remove_unreachable(nfa, original_count, dead_states);
        VERBOSE_PRINT("Removed %d unreachable states\n", last_stats.unreachable_removed);
    }
    
    // Phase 2: Merge common suffix states (accepting states with same behavior)
    if (opts.enable_landing_pad) {
        VERBOSE_PRINT("Merging common suffix states...\n");
        last_stats.landing_pads_removed = merge_common_suffixes(nfa, original_count, dead_states);
        VERBOSE_PRINT("Merged %d common suffix states\n", last_stats.landing_pads_removed);
    }
    
    // Phase 3: Bisimulation reduction (most powerful - finds states with identical futures)
    if (opts.enable_merge) {
        VERBOSE_PRINT("Running bisimulation reduction...\n");
        last_stats.states_merged = bisimulation_reduce(nfa, original_count, dead_states, partition);
        VERBOSE_PRINT("Merged %d bisimilar states\n", last_stats.states_merged);
    }
    
    // Phase 3.5: SAT-based bisimulation verification (more accurate than old approach)
    if (opts.enable_sat && nfa_preminimize_sat_available()) {
        VERBOSE_PRINT("Running SAT-based bisimulation verification...\n");
        last_stats.sat_merged = nfa_preminimize_sat(nfa, original_count, dead_states, opts.verbose);
        VERBOSE_PRINT("SAT merged %d states\n", last_stats.sat_merged);
    }
    
    // Phase 4: Final unreachable cleanup
    if (opts.enable_prune) {
        VERBOSE_PRINT("Final unreachable cleanup...\n");
        int final_unreachable = remove_unreachable(nfa, original_count, dead_states);
        last_stats.unreachable_removed += final_unreachable;
        VERBOSE_PRINT("Removed %d more unreachable states\n", final_unreachable);
    }
    
    // Count how many states were marked dead
    int dead_count = 0;
    for (int i = 0; i < original_count; i++) {
        if (dead_states[i]) dead_count++;
    }
    
    // Compact the NFA by removing dead states
    int new_count = original_count;
    if (dead_count > 0) {
        new_count = compact_nfa(nfa, original_count, dead_states);
        *state_count = new_count;
    }
    last_stats.minimized_states = new_count;
    
    free(dead_states);
    free(partition);
    
    int total_removed = original_count - new_count;
    if (total_removed > 0) {
        VERBOSE_PRINT("Pre-minimized NFA: %d → %d states (%.1f%% reduction)\n",
                      original_count, new_count,
                      100.0 * total_removed / original_count);
    } else {
        VERBOSE_PRINT("Pre-minimization: No states removed (NFA already optimal)\n");
    }
    
    return total_removed;
}
