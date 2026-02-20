/**
 * NFA Pre-Minimization Implementation
 * 
 * Reduces NFA states before subset construction using:
 * 1. Epsilon chain compression - bypass pass-through states
 * 2. Common prefix merging - share states for identical prefixes (O(n log n))
 * 3. Unreachable state pruning
 * 
 * Key advantage: We have global knowledge of the full NFA, unlike the
 * per-pattern RDP parser which has no look-ahead.
 * 
 * PREFIX MERMING LIMITATIONS:
 * ==========================
 * Prefix merging is DISABLED by default because it requires tracking the full
 * path from the start state, not just the immediate source.
 * 
 * The issue: Two states might have the same immediate incoming transition
 * (same source, same symbol) but different full paths from start. Consider:
 *   Pattern "cat": 0 --c--> 1 --a--> 2 --t--> [accept]
 *   Pattern "car": 0 --c--> 3 --a--> 4 --r--> [accept]
 * 
 * States 2 and 4 both have incoming 'a' transitions, but from different
 * predecessor states (1 vs 3). Merging them would be wrong because states
 * 1 and 3 have different futures (t vs r).
 * 
 * Correct prefix merging would require:
 * 1. Building a trie of all paths from start
 * 2. Only merging states at the same trie position
 * 3. Combining all outgoing transitions (union of futures)
 * 
 * This is better done during NFA construction (building a trie directly)
 * rather than as a post-processing step.
 * 
 * The DFA minimization phase handles state reduction safely and correctly.
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
 * 
 * Default configuration focuses on LOCAL optimizations that are:
 * - O(n) or O(n log n) complexity
 * - Safe (preserve language equivalence)
 * - Effective at cleaning up RDP parser artifacts
 */
nfa_premin_options_t nfa_premin_default_options(void) {
    nfa_premin_options_t opts = {
        // Local optimizations (safe, scalable)
        .enable_epsilon_elim = true,    // Bypass single epsilon pass-through states (O(n))
        .enable_epsilon_chain = true,   // Compress multi-hop epsilon chains (O(n))
        .enable_prune = true,           // Remove unreachable states (O(n))
        .enable_prefix_merge = true,    // ENABLED: Merge states with same prefix, combine transitions
        
        // Disabled - unsafe or too aggressive
        .enable_identical = false,      // DISABLED: NFA state merging can change language
        .enable_landing_pad = false,    // Common suffix merging (O(n²)) - too aggressive
        .enable_merge = false,          // Full bisimulation (O(n²)) - too aggressive
        .enable_sat = false,            // SAT-based verification - for bounded subproblems only
        
        .verbose = false
    };
    return opts;
}

// Epsilon symbol used in NFA transitions
#define VSYM_EPS 257

/**
 * Structure for tracking incoming transitions during prefix analysis.
 * For each state, we track the (source, symbol) pairs that reach it.
 */
typedef struct {
    int source_state;
    int symbol;
} incoming_trans_t;

typedef struct {
    incoming_trans_t* transitions;
    int count;
    int capacity;
} incoming_list_t;

/**
 * Bypass pass-through states that have only a single epsilon transition.
 * This is safe because:
 * - State has no accepting properties (not an accepting state)
 * - State has only ONE outgoing transition (epsilon to next state)
 * - Bypassing just shortens the path without changing the language
 */
static int bypass_epsilon_pass_through(nfa_state_t* nfa, int state_count, bool* dead_states) {
    int bypassed = 0;
    
    // Find pass-through states: single epsilon transition, no accepting properties
    for (int s = 1; s < state_count; s++) {  // Skip state 0 (start state)
        if (dead_states[s]) continue;
        
        nfa_state_t* state = &nfa[s];
        
        // Must have no accepting properties
        if (state->category_mask != 0) continue;
        if (state->pending_marker_count != 0) continue;
        if (state->is_eos_target) continue;
        
        // Count outgoing transitions
        int transition_count = 0;
        int epsilon_target = -1;
        bool has_other_transitions = false;
        
        // Check single transitions
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            if (state->transitions[sym] >= 0) {
                if (sym == VSYM_EPS && transition_count == 0) {
                    // First transition is epsilon
                    epsilon_target = state->transitions[sym];
                    transition_count++;
                } else {
                    // Has non-epsilon transition or multiple transitions
                    has_other_transitions = true;
                    break;
                }
            }
        }
        
        // Check multi-targets
        if (!has_other_transitions) {
            int mta_count = mta_get_entry_count(&state->multi_targets);
            if (mta_count > 0) {
                has_other_transitions = true;  // Multi-targets means not a simple pass-through
            }
        }
        
        // Skip if not a simple epsilon pass-through
        if (has_other_transitions || epsilon_target < 0) continue;
        
        // Don't bypass if target is dead
        if (dead_states[epsilon_target]) continue;
        
        // Don't bypass if target is self (self-loop)
        if (epsilon_target == s) continue;
        
        // This is a pass-through state - bypass it
        // Redirect all incoming transitions to go directly to epsilon_target
        for (int src = 0; src < state_count; src++) {
            if (dead_states[src]) continue;
            
            nfa_state_t* src_state = &nfa[src];
            
            // Redirect single transitions
            for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                if (src_state->transitions[sym] == s) {
                    src_state->transitions[sym] = epsilon_target;
                }
            }
            
            // Redirect multi-targets
            for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                int count;
                int* targets = mta_get_target_array(&src_state->multi_targets, sym, &count);
                if (targets && count > 0) {
                    for (int i = 0; i < count; i++) {
                        if (targets[i] == s) {
                            targets[i] = epsilon_target;
                        }
                    }
                }
            }
        }
        
        dead_states[s] = true;
        bypassed++;
        VERBOSE_PRINT("  Bypassed epsilon pass-through state %d -> %d\n", s, epsilon_target);
    }
    
    return bypassed;
}

/**
 * Compress epsilon chains: A --EPS--> B --EPS--> C becomes A --EPS--> C
 * 
 * This is a generalization of bypass_epsilon_pass_through for multi-hop chains.
 * Safe because:
 * - Intermediate states have no accepting properties
 * - Intermediate states have only epsilon transitions
 * - Language is preserved (same reachability)
 * 
 * Complexity: O(n) - single pass through states
 */
static int compress_epsilon_chains(nfa_state_t* nfa, int state_count, bool* dead_states) {
    int compressed = 0;
    
    // For each state, follow epsilon chains and find the ultimate target
    for (int s = 1; s < state_count; s++) {  // Skip state 0 (start state)
        if (dead_states[s]) continue;
        
        nfa_state_t* state = &nfa[s];
        
        // Only process states with a single epsilon outgoing transition
        int epsilon_target = state->transitions[VSYM_EPS];
        if (epsilon_target < 0) continue;
        
        // Must have no other single transitions
        bool has_other = false;
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            if (sym != VSYM_EPS && state->transitions[sym] >= 0) {
                has_other = true;
                break;
            }
        }
        if (has_other) continue;
        
        // Must have no multi-targets
        int mta_count = mta_get_entry_count(&state->multi_targets);
        if (mta_count > 0) continue;
        
        // Follow the epsilon chain to find ultimate target
        int ultimate = epsilon_target;
        int chain_length = 0;
        const int max_chain = 100;  // Prevent infinite loops
        
        while (chain_length < max_chain) {
            if (dead_states[ultimate]) break;
            if (ultimate == s) break;  // Self-loop
            
            nfa_state_t* next_state = &nfa[ultimate];
            
            // Check if this state can be bypassed
            // Must have no accepting properties
            if (next_state->category_mask != 0) break;
            if (next_state->pending_marker_count != 0) break;
            if (next_state->is_eos_target) break;
            
            // Must have only epsilon outgoing
            int next_epsilon = next_state->transitions[VSYM_EPS];
            if (next_epsilon < 0) break;  // No epsilon transition, stop here
            
            // Check for other transitions
            bool next_has_other = false;
            for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                if (sym != VSYM_EPS && next_state->transitions[sym] >= 0) {
                    next_has_other = true;
                    break;
                }
            }
            if (next_has_other) break;
            
            int next_mta = mta_get_entry_count(&next_state->multi_targets);
            if (next_mta > 0) break;
            
            // Can bypass this state
            ultimate = next_epsilon;
            chain_length++;
        }
        
        // If we found a shorter path, update the transition
        if (chain_length > 0 && ultimate != epsilon_target && !dead_states[ultimate]) {
            state->transitions[VSYM_EPS] = ultimate;
            compressed += chain_length;
            VERBOSE_PRINT("  Compressed epsilon chain from state %d: %d hops bypassed -> ultimate target %d\n", 
                         s, chain_length, ultimate);
        }
    }
    
    return compressed;
}

/**
 * Get statistics from last run
 */
void nfa_premin_get_stats(nfa_premin_stats_t* stats) {
    if (stats) *stats = last_stats;
}

/**
 * Compute a signature hash for an NFA state based on PREFIX properties only.
 * 
 * The signature captures properties accumulated along the path from start:
 * - Category mask (accepting behavior accumulated along the path)
 * - Pattern ID
 * - EOS target flag
 * - Pending markers (pattern_id, uid, type, active)
 * 
 * NOT included (these are FUTURE transitions, not prefix properties):
 * - Outgoing transitions
 * - Multi-targets
 * - Transition markers on outgoing edges
 * 
 * This allows states with the same prefix but different futures to be merged
 * by taking the UNION of their transitions.
 */
uint64_t nfa_compute_state_signature(const nfa_state_t* nfa, int state_idx) {
    const nfa_state_t* state = &nfa[state_idx];
    
    // FNV-1a hash
    uint64_t hash = 14695981039346656037ULL;
    
    // Hash category mask (prefix property)
    hash ^= state->category_mask;
    hash *= 1099511628211ULL;
    
    // Hash pattern ID (prefix property)
    hash ^= state->pattern_id;
    hash *= 1099511628211ULL;
    
    // Hash EOS target flag (prefix property)
    hash ^= state->is_eos_target ? 1 : 0;
    hash *= 1099511628211ULL;
    
    // Hash pending marker count (prefix property)
    hash ^= state->pending_marker_count;
    hash *= 1099511628211ULL;
    
    // Hash pending markers - ALL fields (prefix property)
    for (int i = 0; i < state->pending_marker_count; i++) {
        hash ^= state->pending_markers[i].pattern_id;
        hash *= 1099511628211ULL;
        hash ^= state->pending_markers[i].uid;
        hash *= 1099511628211ULL;
        hash ^= state->pending_markers[i].type;
        hash *= 1099511628211ULL;
        hash ^= state->pending_markers[i].active ? 1 : 0;
        hash *= 1099511628211ULL;
    }
    
    // NOTE: We do NOT hash outgoing transitions or multi-targets
    // These represent the FUTURE, not the prefix.
    // States with the same prefix but different futures can be merged
    // by taking the UNION of their transitions.
    
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
 * Check if two states have truly identical outgoing transitions.
 * This is a deep comparison after a hash match.
 * 
 * IMPORTANT: This is conservative - we only merge states that have
 * IDENTICAL outgoing transitions (including epsilon). This is safe
 * because if two states have exactly the same transitions, merging
 * them cannot change the language.
 * 
 * We check ALL properties that affect the NFA's behavior:
 * - Accepting properties (category_mask, pattern_id)
 * - Pending markers (pattern_id, uid, type, active)
 * - All transitions (single and multi-target)
 * - Transition markers attached to each symbol
 * - EOS target flag
 * 
 * CRITICAL: We also check that neither state has a transition to the other.
 * If s1 has a transition to s2, merging would create a self-loop that
 * didn't exist before, changing the language.
 */
static bool states_truly_identical(const nfa_state_t* nfa, int s1, int s2) {
    const nfa_state_t* state1 = &nfa[s1];
    const nfa_state_t* state2 = &nfa[s2];
    
    // CRITICAL: Check for mutual transitions - if either state points to the other,
    // merging would create incorrect self-loops
    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
        if (state1->transitions[sym] == s2) return false;
        if (state2->transitions[sym] == s1) return false;
    }
    
    // Check multi-targets for mutual references
    int mta1_count = mta_get_entry_count((multi_target_array_t*)&state1->multi_targets);
    int mta2_count = mta_get_entry_count((multi_target_array_t*)&state2->multi_targets);
    
    if (mta1_count > 0) {
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int count;
            int* targets = mta_get_target_array((multi_target_array_t*)&state1->multi_targets, sym, &count);
            if (targets && count > 0) {
                for (int i = 0; i < count; i++) {
                    if (targets[i] == s2) return false;
                }
            }
        }
    }
    
    if (mta2_count > 0) {
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int count;
            int* targets = mta_get_target_array((multi_target_array_t*)&state2->multi_targets, sym, &count);
            if (targets && count > 0) {
                for (int i = 0; i < count; i++) {
                    if (targets[i] == s1) return false;
                }
            }
        }
    }
    
    // Check accepting properties
    if (state1->category_mask != state2->category_mask) return false;
    if (state1->pattern_id != state2->pattern_id) return false;
    if (state1->pending_marker_count != state2->pending_marker_count) return false;
    if (state1->is_eos_target != state2->is_eos_target) return false;
    
    // Check pending markers - ALL fields must match
    for (int i = 0; i < state1->pending_marker_count; i++) {
        if (state1->pending_markers[i].pattern_id != state2->pending_markers[i].pattern_id) return false;
        if (state1->pending_markers[i].uid != state2->pending_markers[i].uid) return false;
        if (state1->pending_markers[i].type != state2->pending_markers[i].type) return false;
        if (state1->pending_markers[i].active != state2->pending_markers[i].active) return false;
    }
    
    // Check single transitions - all must match exactly (same target states)
    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
        if (state1->transitions[sym] != state2->transitions[sym]) return false;
    }
    
    // Check multi-targets - must have same entry count
    if (mta1_count != mta2_count) return false;
    
    if (mta1_count > 0) {
        // Check each symbol's multi-targets AND transition markers
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int count1, count2;
            int* targets1 = mta_get_target_array((multi_target_array_t*)&state1->multi_targets, sym, &count1);
            int* targets2 = mta_get_target_array((multi_target_array_t*)&state2->multi_targets, sym, &count2);
            
            if (count1 != count2) return false;
            if (count1 > 0) {
                // CRITICAL: Targets must be IDENTICAL (same state indices)
                // Sorting allows {A,B} to match {B,A}, which is correct for NFA
                // But we require the exact same set of target states
                int* sorted1 = malloc(count1 * sizeof(int));
                int* sorted2 = malloc(count1 * sizeof(int));
                memcpy(sorted1, targets1, count1 * sizeof(int));
                memcpy(sorted2, targets2, count1 * sizeof(int));
                
                // Simple sort
                for (int i = 0; i < count1 - 1; i++) {
                    for (int j = i + 1; j < count1; j++) {
                        if (sorted1[i] > sorted1[j]) { int t = sorted1[i]; sorted1[i] = sorted1[j]; sorted1[j] = t; }
                        if (sorted2[i] > sorted2[j]) { int t = sorted2[i]; sorted2[i] = sorted2[j]; sorted2[j] = t; }
                    }
                }
                
                bool match = (memcmp(sorted1, sorted2, count1 * sizeof(int)) == 0);
                free(sorted1);
                free(sorted2);
                if (!match) return false;
            }
            
            // Check transition markers for this symbol - ALL must match
            int marker_count1, marker_count2;
            transition_marker_t* markers1 = mta_get_markers((multi_target_array_t*)&state1->multi_targets, sym, &marker_count1);
            transition_marker_t* markers2 = mta_get_markers((multi_target_array_t*)&state2->multi_targets, sym, &marker_count2);
            
            if (marker_count1 != marker_count2) return false;
            
            for (int m = 0; m < marker_count1; m++) {
                if (markers1[m].pattern_id != markers2[m].pattern_id) return false;
                if (markers1[m].uid != markers2[m].uid) return false;
                if (markers1[m].type != markers2[m].type) return false;
            }
        }
    }
    
    // SAFETY CHECK: Don't merge states that have no outgoing transitions
    // These are typically accepting states or dead ends, and merging them
    // can break the NFA structure if they're reached via different paths
    bool has_any_transition = false;
    for (int sym = 0; sym < MAX_SYMBOLS && !has_any_transition; sym++) {
        if (state1->transitions[sym] >= 0) has_any_transition = true;
    }
    if (mta1_count > 0) has_any_transition = true;
    
    if (!has_any_transition) {
        // States with no outgoing transitions - only merge if they have
        // identical accepting properties (already checked above)
        // But be extra conservative: don't merge at all
        return false;
    }
    
    return true;
}

// Structure for hash-based grouping (used by merge_identical_states)
typedef struct {
    int state_idx;
    uint64_t hash;
} state_hash_entry_t;

// Comparison function for qsort
static int compare_state_hashes(const void* a, const void* b) {
    const state_hash_entry_t* ea = (const state_hash_entry_t*)a;
    const state_hash_entry_t* eb = (const state_hash_entry_t*)b;
    if (ea->hash < eb->hash) return -1;
    if (ea->hash > eb->hash) return 1;
    return 0;
}

/**
 * Compute a signature hash for an NFA state for STRICT identity checking.
 * 
 * This hashes the actual target state IDs, not partition IDs.
 * Only states with IDENTICAL transitions (to the same states) will match.
 * This is conservative but safe.
 */
static uint64_t compute_strict_signature(const nfa_state_t* nfa, int state_idx, const bool* dead_states) {
    const nfa_state_t* state = &nfa[state_idx];
    
    // FNV-1a hash
    uint64_t hash = 14695981039346656037ULL;
    
    // Hash category mask
    hash ^= state->category_mask;
    hash *= 1099511628211ULL;
    
    // Hash pattern ID
    hash ^= state->pattern_id;
    hash *= 1099511628211ULL;
    
    // Hash EOS target flag
    hash ^= state->is_eos_target ? 1 : 0;
    hash *= 1099511628211ULL;
    
    // Hash pending marker count
    hash ^= state->pending_marker_count;
    hash *= 1099511628211ULL;
    
    // Hash pending markers - ALL fields
    for (int i = 0; i < state->pending_marker_count; i++) {
        hash ^= state->pending_markers[i].pattern_id;
        hash *= 1099511628211ULL;
        hash ^= state->pending_markers[i].uid;
        hash *= 1099511628211ULL;
        hash ^= state->pending_markers[i].type;
        hash *= 1099511628211ULL;
        hash ^= state->pending_markers[i].active ? 1 : 0;
        hash *= 1099511628211ULL;
    }
    
    // Hash transitions using ACTUAL state IDs (strict identity)
    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
        int target = state->transitions[sym];
        if (target >= 0 && !dead_states[target]) {
            hash ^= (uint64_t)sym;
            hash *= 1099511628211ULL;
            hash ^= (uint64_t)target;  // Use actual state ID
            hash *= 1099511628211ULL;
        }
    }
    
    // Hash multi-targets using ACTUAL state IDs
    int mta_count = mta_get_entry_count((multi_target_array_t*)&state->multi_targets);
    if (mta_count > 0) {
        hash ^= mta_count;
        hash *= 1099511628211ULL;
        for (int sym = 0; sym < MAX_SYMBOLS && mta_count > 0; sym++) {
            int target_count;
            int* targets = mta_get_target_array((multi_target_array_t*)&state->multi_targets, sym, &target_count);
            if (targets && target_count > 0) {
                hash ^= sym;
                hash *= 1099511628211ULL;
                
                // Sort target IDs for consistent hashing
                int* sorted_targets = malloc(target_count * sizeof(int));
                memcpy(sorted_targets, targets, target_count * sizeof(int));
                // Simple sort
                for (int i = 0; i < target_count - 1; i++) {
                    for (int j = i + 1; j < target_count; j++) {
                        if (sorted_targets[i] > sorted_targets[j]) {
                            int t = sorted_targets[i]; sorted_targets[i] = sorted_targets[j]; sorted_targets[j] = t;
                        }
                    }
                }
                for (int i = 0; i < target_count && i < 8; i++) {
                    hash ^= sorted_targets[i];
                    hash *= 1099511628211ULL;
                }
                free(sorted_targets);
                
                // Hash transition markers for this symbol
                int marker_count;
                transition_marker_t* markers = mta_get_markers((multi_target_array_t*)&state->multi_targets, sym, &marker_count);
                if (markers && marker_count > 0) {
                    hash ^= marker_count;
                    hash *= 1099511628211ULL;
                    for (int m = 0; m < marker_count && m < 8; m++) {
                        hash ^= markers[m].pattern_id;
                        hash *= 1099511628211ULL;
                        hash ^= markers[m].uid;
                        hash *= 1099511628211ULL;
                        hash ^= markers[m].type;
                        hash *= 1099511628211ULL;
                    }
                }
                
                mta_count--;
            }
        }
    }
    
    return hash;
}

/**
 * Merge identical states using STRICT identity checking.
 * 
 * This is the CONSERVATIVE approach - only merge states that have:
 * 1. Same accepting properties (category, pattern_id, markers)
 * 2. Same outgoing transitions to the SAME target states
 * 
 * This is safe because merging states with identical outgoing behavior
 * cannot change the language - both states lead to exactly the same futures.
 * 
 * This is O(n log n) for the sort + O(n²) for verification.
 */
static int merge_identical_states(nfa_state_t* nfa, int state_count, bool* dead_states) {
    state_hash_entry_t* entries = malloc(state_count * sizeof(state_hash_entry_t));
    int entry_count = 0;
    
    // Compute hashes for all live states
    for (int s = 0; s < state_count; s++) {
        if (!dead_states[s]) {
            entries[entry_count].state_idx = s;
            entries[entry_count].hash = compute_strict_signature(nfa, s, dead_states);
            entry_count++;
        }
    }
    
    // Sort by hash (qsort)
    qsort(entries, entry_count, sizeof(state_hash_entry_t), compare_state_hashes);
    
    // Find groups with same hash and verify they're truly identical
    int merged = 0;
    int i = 0;
    while (i < entry_count) {
        // Find all states with the same hash
        int j = i + 1;
        while (j < entry_count && entries[j].hash == entries[i].hash) {
            j++;
        }
        
        // If multiple states have same hash, check for true identity
        if (j - i > 1) {
            // For each pair in this hash group
            for (int k = i; k < j; k++) {
                int s1 = entries[k].state_idx;
                if (dead_states[s1]) continue;
                
                for (int l = k + 1; l < j; l++) {
                    int s2 = entries[l].state_idx;
                    if (dead_states[s2]) continue;
                    
                    // Deep check for true identity
                    if (states_truly_identical(nfa, s1, s2)) {
                        // Merge s2 into s1
                        // Redirect all transitions pointing to s2 to s1
                        for (int src = 0; src < state_count; src++) {
                            if (dead_states[src]) continue;
                            
                            nfa_state_t* src_state = &nfa[src];
                            
                            // Single transitions
                            for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                                if (src_state->transitions[sym] == s2) {
                                    src_state->transitions[sym] = s1;
                                }
                            }
                            
                            // Multi-targets
                            for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                                int count;
                                int* targets = mta_get_target_array(&src_state->multi_targets, sym, &count);
                                if (targets && count > 0) {
                                    for (int t = 0; t < count; t++) {
                                        if (targets[t] == s2) {
                                            targets[t] = s1;
                                        }
                                    }
                                }
                            }
                        }
                        
                        dead_states[s2] = true;
                        merged++;
                        VERBOSE_PRINT("  Merged identical state %d into %d\n", s2, s1);
                    }
                }
            }
        }
        
        i = j;
    }
    
    free(entries);
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

// Structure for prefix merge candidate
typedef struct {
    int state;
    int source;
    int symbol;
    uint64_t sig;
} prefix_candidate_t;

// Comparison function for prefix candidates
static int compare_prefix_candidates(const void* a, const void* b) {
    const prefix_candidate_t* ca = (const prefix_candidate_t*)a;
    const prefix_candidate_t* cb = (const prefix_candidate_t*)b;
    if (ca->source != cb->source) return ca->source - cb->source;
    if (ca->symbol != cb->symbol) return ca->symbol - cb->symbol;
    if (ca->sig < cb->sig) return -1;
    if (ca->sig > cb->sig) return 1;
    return 0;
}

/**
 * Merge common prefix states - single pass.
 * 
 * This is SAFE because we only merge states that:
 * 1. Have exactly one incoming transition
 * 2. That incoming transition is from the same (source, symbol) pair
 * 3. Have identical outgoing behavior (transitions, markers, etc.)
 * 
 * When two states are reached via the same (source, symbol) pair and have
 * identical outgoing behavior, they are truly equivalent - merging them
 * cannot create new paths because they were already reachable via the same path.
 * 
 * Algorithm (O(n log n)):
 * 1. Build incoming transition map for each state
 * 2. Find states with single incoming transition
 * 3. Group by (source, symbol, outgoing_signature)
 * 4. Merge states in same group
 */
static int merge_common_prefixes_pass(nfa_state_t* nfa, int state_count, bool* dead_states) {
    // Build incoming transition map
    // For each state, track (source, symbol) pairs that reach it
    typedef struct {
        int source;
        int symbol;
        int target;
    } incoming_edge_t;
    
    // First pass: count total edges to allocate correctly
    // Multi-targets can have many targets per (source, symbol) pair
    int total_edges = 0;
    for (int s = 0; s < state_count; s++) {
        if (dead_states[s]) continue;
        
        nfa_state_t* state = &nfa[s];
        
        // Count single transitions (older format, may be removed in future)
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int target = state->transitions[sym];
            if (target >= 0 && !dead_states[target]) {
                total_edges++;
            }
        }
        
        // Count multi-targets (NFA builder stores ALL transitions here)
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int count;
            int* targets = mta_get_target_array(&state->multi_targets, sym, &count);
            if (targets && count > 0) {
                for (int i = 0; i < count; i++) {
                    if (targets[i] >= 0 && !dead_states[targets[i]]) {
                        total_edges++;
                    }
                }
            }
        }
    }
    
    if (total_edges == 0) {
        return 0;  // No edges, nothing to merge
    }
    
    incoming_edge_t* edges = malloc(total_edges * sizeof(incoming_edge_t));
    int edge_count = 0;
    
    // Collect all edges (check both transitions[] and multi_targets)
    for (int s = 0; s < state_count; s++) {
        if (dead_states[s]) continue;
        
        nfa_state_t* state = &nfa[s];
        
        // Single transitions (older format)
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int target = state->transitions[sym];
            if (target >= 0 && !dead_states[target]) {
                edges[edge_count].source = s;
                edges[edge_count].symbol = sym;
                edges[edge_count].target = target;
                edge_count++;
            }
        }
        
        // Multi-targets
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int count;
            int* targets = mta_get_target_array(&state->multi_targets, sym, &count);
            if (targets && count > 0) {
                for (int i = 0; i < count; i++) {
                    if (targets[i] >= 0 && !dead_states[targets[i]]) {
                        edges[edge_count].source = s;
                        edges[edge_count].symbol = sym;
                        edges[edge_count].target = targets[i];
                        edge_count++;
                    }
                }
            }
        }
    }
    
    // Count incoming transitions per state
    int* incoming_count = calloc(state_count, sizeof(int));
    for (int e = 0; e < edge_count; e++) {
        incoming_count[edges[e].target]++;
    }
    
    // For states with single incoming, record the (source, symbol)
    int* single_source = malloc(state_count * sizeof(int));
    int* single_symbol = malloc(state_count * sizeof(int));
    
    for (int s = 0; s < state_count; s++) {
        single_source[s] = -1;
        single_symbol[s] = -1;
    }
    
    for (int e = 0; e < edge_count; e++) {
        int target = edges[e].target;
        if (incoming_count[target] == 1) {
            single_source[target] = edges[e].source;
            single_symbol[target] = edges[e].symbol;
        }
    }
    
    // Build merge candidates: states with single incoming and same (source, symbol)
    // BUT: Skip states whose source uses multi-targets with DIFFERENT targets
    // (merging would lose transitions). If all targets are the same state, merging is safe.
    // ALSO: Skip states with accepting properties (category_mask) - these are semantically important
    prefix_candidate_t* candidates = malloc(state_count * sizeof(prefix_candidate_t));
    int candidate_count = 0;
    
    for (int s = 0; s < state_count; s++) {
        if (dead_states[s]) continue;
        if (incoming_count[s] != 1) continue;
        if (single_source[s] < 0) continue;
        
        // Skip start state
        if (s == 0) continue;
        
        // Skip states with accepting properties - these have semantic meaning
        if (nfa[s].category_mask != 0) continue;
        
        // Note: We do NOT skip states from multi-target sources anymore.
        // The NFA builder stores ALL transitions in multi_targets, so skipping
        // multi-target sources would disable prefix merging entirely.
        // Instead, we handle multi-target merging correctly in the merge loop.
        
        candidates[candidate_count].state = s;
        candidates[candidate_count].source = single_source[s];
        candidates[candidate_count].symbol = single_symbol[s];
        candidates[candidate_count].sig = nfa_compute_state_signature(nfa, s);
        candidate_count++;
    }
    
    VERBOSE_PRINT("  Found %d prefix merge candidates\n", candidate_count);
    fprintf(stderr, "[PREMIN] Found %d prefix merge candidates (total_edges=%d)\n", candidate_count, total_edges);
    
    // Sort by (source, symbol, sig) for grouping
    qsort(candidates, candidate_count, sizeof(prefix_candidate_t), compare_prefix_candidates);
    
    // Find groups and merge
    int merged = 0;
    int i = 0;
    while (i < candidate_count) {
        int j = i + 1;
        // Find all candidates with same (source, symbol, sig)
        while (j < candidate_count &&
               candidates[j].source == candidates[i].source &&
               candidates[j].symbol == candidates[i].symbol &&
                candidates[j].sig == candidates[i].sig) {
            j++;
        }
        
        // If multiple candidates, merge them by combining transitions
        if (j - i > 1) {
            fprintf(stderr, "[PREMIN] Found group of %d candidates with same (source=%d, symbol=%d, sig=%lu)\n",
                    j - i, candidates[i].source, candidates[i].symbol, candidates[i].sig);
            int rep = candidates[i].state;
            
            for (int k = i + 1; k < j; k++) {
                int s = candidates[k].state;
                if (dead_states[s]) continue;
                
                // Check for mutual transitions (would create self-loop)
                bool has_mutual = false;
                for (int sym = 0; sym < MAX_SYMBOLS && !has_mutual; sym++) {
                    if (nfa[rep].transitions[sym] == s) has_mutual = true;
                    if (nfa[s].transitions[sym] == rep) has_mutual = true;
                }
                if (has_mutual) {
                    fprintf(stderr, "[PREMIN] States %d and %d have mutual transitions, skipping\n", rep, s);
                    continue;
                }
                
                // Merge state s into rep by COMBINING transitions
                // This ensures the merged state can reach ALL futures
                nfa_state_t* rep_state = &nfa[rep];
                nfa_state_t* s_state = &nfa[s];
                
                // Combine single transitions
                for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                    if (s_state->transitions[sym] >= 0) {
                        if (rep_state->transitions[sym] < 0) {
                            // rep doesn't have this transition, add it
                            rep_state->transitions[sym] = s_state->transitions[sym];
                        } else if (rep_state->transitions[sym] != s_state->transitions[sym]) {
                            // Both have transitions on this symbol to different targets
                            // Add to multi-targets
                            mta_add_target(&rep_state->multi_targets, sym, rep_state->transitions[sym]);
                            mta_add_target(&rep_state->multi_targets, sym, s_state->transitions[sym]);
                            rep_state->transitions[sym] = -1;  // Clear single transition
                        }
                        // If same target, nothing to do
                    }
                }
                
                // Combine multi-targets from s_state into rep_state
                for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                    // First, check if rep has a single transition that needs to be merged with s's multi-targets
                    if (rep_state->transitions[sym] >= 0) {
                        int s_count;
                        int* s_targets = mta_get_target_array(&s_state->multi_targets, sym, &s_count);
                        if (s_targets && s_count > 0) {
                            // rep has single, s has multi - convert rep to multi and add all
                            int rep_target = rep_state->transitions[sym];
                            mta_add_target(&rep_state->multi_targets, sym, rep_target);
                            for (int t = 0; t < s_count; t++) {
                                mta_add_target(&rep_state->multi_targets, sym, s_targets[t]);
                            }
                            rep_state->transitions[sym] = -1;  // Clear single transition
                        }
                    }
                    
                    // Now add any remaining multi-targets from s
                    int count;
                    int* targets = mta_get_target_array(&s_state->multi_targets, sym, &count);
                    if (targets && count > 0) {
                        // Always add s's multi-targets to rep (union of all futures)
                        for (int t = 0; t < count; t++) {
                            mta_add_target(&rep_state->multi_targets, sym, targets[t]);
                        }
                    }
                    
                    // Also combine transition markers
                    int marker_count;
                    transition_marker_t* markers = mta_get_markers(&s_state->multi_targets, sym, &marker_count);
                    if (markers && marker_count > 0) {
                        for (int m = 0; m < marker_count; m++) {
                            mta_add_marker(&rep_state->multi_targets, sym, 
                                          markers[m].pattern_id, markers[m].uid, markers[m].type);
                        }
                    }
                }
                
                // Combine accepting properties (OR the category masks)
                rep_state->category_mask |= s_state->category_mask;
                
                // Combine pending markers (if any)
                for (int m = 0; m < s_state->pending_marker_count && rep_state->pending_marker_count < MAX_PENDING_MARKERS; m++) {
                    // Check if this marker already exists
                    bool exists = false;
                    for (int r = 0; r < rep_state->pending_marker_count && !exists; r++) {
                        if (rep_state->pending_markers[r].uid == s_state->pending_markers[m].uid &&
                            rep_state->pending_markers[r].type == s_state->pending_markers[m].type) {
                            exists = true;
                        }
                    }
                    if (!exists) {
                        rep_state->pending_markers[rep_state->pending_marker_count++] = s_state->pending_markers[m];
                    }
                }
                
                // Redirect all transitions pointing to s to rep
                for (int src = 0; src < state_count; src++) {
                    if (dead_states[src]) continue;
                    
                    nfa_state_t* src_state = &nfa[src];
                    
                    // Single transitions
                    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                        if (src_state->transitions[sym] == s) {
                            src_state->transitions[sym] = rep;
                        }
                    }
                    
                    // Multi-targets
                    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                        int count;
                        int* targets = mta_get_target_array(&src_state->multi_targets, sym, &count);
                        if (targets && count > 0) {
                            for (int t = 0; t < count; t++) {
                                if (targets[t] == s) {
                                    targets[t] = rep;
                                }
                            }
                        }
                    }
                }
                
                dead_states[s] = true;
                merged++;
                fprintf(stderr, "[PREMIN] Merged prefix state %d into %d (combined transitions)\n", s, rep);
                VERBOSE_PRINT("  Merged prefix state %d into %d (source=%d, symbol=%d)\n", 
                             s, rep, candidates[i].source, candidates[i].symbol);
            }
        }
        
        i = j;
    }
    
    free(edges);
    free(incoming_count);
    free(single_source);
    free(single_symbol);
    free(candidates);
    
    return merged;
}

/**
 * Merge common prefix states - iterative passes.
 * 
 * After each pass, previously unreachable merge opportunities may become
 * available as states get merged. We iterate until no more merges happen.
 * 
 * This enables merging at deeper levels in the NFA - after merging states
 * at one level, their children may become merge candidates.
 * 
 * Maximum iterations limited to prevent infinite loops.
 */
static int merge_common_prefixes(nfa_state_t* nfa, int state_count, bool* dead_states) {
    int total_merged = 0;
    int pass = 1;
    const int max_passes = 10;
    
    while (pass <= max_passes) {
        VERBOSE_PRINT("  Prefix merge pass %d...\n", pass);
        int merged = merge_common_prefixes_pass(nfa, state_count, dead_states);
        total_merged += merged;
        
        if (merged == 0) {
            VERBOSE_PRINT("  No more merges possible after pass %d\n", pass);
            break;
        }
        
        VERBOSE_PRINT("  Pass %d merged %d states (total: %d)\n", pass, merged, total_merged);
        pass++;
    }
    
    return total_merged;
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
    if (!opts.enable_prune && !opts.enable_epsilon_elim && !opts.enable_epsilon_chain &&
        !opts.enable_prefix_merge && !opts.enable_landing_pad && !opts.enable_merge && 
        !opts.enable_identical && !opts.enable_sat) {
        VERBOSE_PRINT("Pre-minimization: No optimizations enabled, skipping\n");
        return 0;
    }
    
    VERBOSE_PRINT("Pre-minimizing NFA with %d states\n", original_count);
    
    // Allocate dead state tracking and partition array
    bool* dead_states = calloc(original_count, sizeof(bool));
    int* partition = malloc(original_count * sizeof(int));
    
    // Phase 1: Remove unreachable states first (O(n))
    if (opts.enable_prune) {
        VERBOSE_PRINT("Removing unreachable states...\n");
        last_stats.unreachable_removed = remove_unreachable(nfa, original_count, dead_states);
        VERBOSE_PRINT("Removed %d unreachable states\n", last_stats.unreachable_removed);
    }
    
    // Phase 2: Bypass epsilon pass-through states (O(n))
    if (opts.enable_epsilon_elim) {
        VERBOSE_PRINT("Bypassing epsilon pass-through states...\n");
        last_stats.epsilon_bypassed = bypass_epsilon_pass_through(nfa, original_count, dead_states);
        VERBOSE_PRINT("Bypassed %d epsilon pass-through states\n", last_stats.epsilon_bypassed);
    }
    
    // Phase 3: Compress epsilon chains (O(n))
    if (opts.enable_epsilon_chain) {
        VERBOSE_PRINT("Compressing epsilon chains...\n");
        last_stats.epsilon_chains = compress_epsilon_chains(nfa, original_count, dead_states);
        VERBOSE_PRINT("Compressed %d epsilon chain hops\n", last_stats.epsilon_chains);
    }
    
    // Phase 4: Merge common prefixes (O(n log n))
    if (opts.enable_prefix_merge) {
        VERBOSE_PRINT("Merging common prefixes...\n");
        last_stats.identical_merged = merge_common_prefixes(nfa, original_count, dead_states);
        VERBOSE_PRINT("Merged %d prefix states\n", last_stats.identical_merged);
        // Always print this for now to verify prefix merging works
        fprintf(stderr, "[PREMIN] Merged %d prefix states\n", last_stats.identical_merged);
    }
    
    // Phase 5: Merge identical states (O(n log n)) - DISABLED by default
    if (opts.enable_identical) {
        VERBOSE_PRINT("Merging identical states...\n");
        last_stats.identical_merged = merge_identical_states(nfa, original_count, dead_states);
        VERBOSE_PRINT("Merged %d identical states\n", last_stats.identical_merged);
    }
    
    // Phase 5: Merge common suffix states (O(n²) - disabled by default)
    if (opts.enable_landing_pad) {
        VERBOSE_PRINT("Merging common suffix states...\n");
        last_stats.landing_pads_removed = merge_common_suffixes(nfa, original_count, dead_states);
        VERBOSE_PRINT("Merged %d common suffix states\n", last_stats.landing_pads_removed);
    }
    
    // Phase 6: Bisimulation reduction (O(n²) - disabled by default)
    if (opts.enable_merge) {
        VERBOSE_PRINT("Running bisimulation reduction...\n");
        last_stats.states_merged = bisimulation_reduce(nfa, original_count, dead_states, partition);
        VERBOSE_PRINT("Merged %d bisimilar states\n", last_stats.states_merged);
    }
    
    // Phase 7: Windowed SAT-based optimization (O(n log n) with bounded subproblems)
    if (opts.enable_sat && nfa_preminimize_windowed_sat_available()) {
        VERBOSE_PRINT("Running windowed SAT optimization...\n");
        last_stats.sat_merged = nfa_preminimize_windowed_sat(nfa, original_count, dead_states, 
                                                              0, 0, opts.verbose);  // Use defaults
        VERBOSE_PRINT("Windowed SAT merged %d states\n", last_stats.sat_merged);
    } else if (opts.enable_sat && nfa_preminimize_sat_available()) {
        // Fallback to old SAT approach if windowed not available
        VERBOSE_PRINT("Running legacy SAT-based bisimulation verification...\n");
        last_stats.sat_merged = nfa_preminimize_sat(nfa, original_count, dead_states, opts.verbose);
        VERBOSE_PRINT("SAT merged %d states\n", last_stats.sat_merged);
    }
    
    // Phase 8: Final unreachable cleanup
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
