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

// ============================================================================
// SIGNATURE CACHE - Avoid recomputing signatures between passes
// ============================================================================

/**
 * Cached signatures for a single state.
 * 
 * Signatures are invalidated when:
 * - State is merged into another (transitions change)
 * - Transitions are redirected (during merge operations)
 * - New states are created (initially invalid)
 */
typedef struct {
    uint64_t accepting_sig;   // Hash of accepting properties (category, markers)
    uint64_t outgoing_sig;    // Hash of outgoing transitions
    uint64_t prefix_sig;      // Hash of prefix properties (same as accepting for now)
    bool accepting_valid;     // Is accepting_sig valid?
    bool outgoing_valid;      // Is outgoing_sig valid?
    bool prefix_valid;        // Is prefix_sig valid?
} signature_cache_entry_t;

/**
 * Global signature cache for the current preminimization run.
 * Allocated once at start, freed at end.
 */
static signature_cache_entry_t* sig_cache = NULL;
static int sig_cache_capacity = 0;

/**
 * Initialize signature cache for n states.
 */
static void sig_cache_init(int capacity) {
    if (sig_cache != NULL && sig_cache_capacity >= capacity) {
        // Reuse existing cache, just clear valid flags
        for (int i = 0; i < capacity; i++) {
            sig_cache[i].accepting_valid = false;
            sig_cache[i].outgoing_valid = false;
            sig_cache[i].prefix_valid = false;
        }
        return;
    }
    
    // Free old cache if exists
    free(sig_cache);
    
    // Allocate new cache
    sig_cache = calloc(capacity, sizeof(signature_cache_entry_t));
    sig_cache_capacity = capacity;
}

/**
 * Free signature cache.
 */
static void sig_cache_free(void) {
    free(sig_cache);
    sig_cache = NULL;
    sig_cache_capacity = 0;
}

/**
 * Invalidate all signatures for a state (called after merge).
 */
static void sig_cache_invalidate(int state_idx) {
    if (sig_cache && state_idx < sig_cache_capacity) {
        sig_cache[state_idx].accepting_valid = false;
        sig_cache[state_idx].outgoing_valid = false;
        sig_cache[state_idx].prefix_valid = false;
    }
}

/**
 * Grow signature cache to accommodate new states from suffix factorization.
 */
static void sig_cache_grow(int new_capacity) {
    if (new_capacity <= sig_cache_capacity) return;
    
    signature_cache_entry_t* new_cache = realloc(sig_cache, new_capacity * sizeof(signature_cache_entry_t));
    if (!new_cache) return;  // Keep old cache on failure
    
    // Initialize new entries
    for (int i = sig_cache_capacity; i < new_capacity; i++) {
        new_cache[i].accepting_valid = false;
        new_cache[i].outgoing_valid = false;
        new_cache[i].prefix_valid = false;
    }
    
    sig_cache = new_cache;
    sig_cache_capacity = new_capacity;
}

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
        // All optimizations enabled by default
        .enable_epsilon_elim = true,    // Bypass single epsilon pass-through states (O(n))
        .enable_epsilon_chain = true,   // Compress multi-hop epsilon chains (O(n))
        .enable_prune = true,           // Remove unreachable states (O(n))
        .enable_final_dedup = true,     // Deduplicate equivalent final states
        .enable_bidirectional = true,   // Bidirectional incremental merging (O(n log n))
        .enable_sat_optimal = true,     // SAT-based optimal merge selection (continuation of bidirectional)
        .max_sat_candidates = 200,      // Maximum candidates for SAT (bounds complexity)
        
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
    // Check cache first
    if (sig_cache && state_idx < sig_cache_capacity && sig_cache[state_idx].prefix_valid) {
        return sig_cache[state_idx].prefix_sig;
    }
    
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
    if (state->pending_marker_count > 0) {
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
    }
    
    // NOTE: We do NOT hash outgoing transitions or multi-targets
    // These represent the FUTURE, not the prefix.
    // States with the same prefix but different futures can be merged
    // by taking the UNION of their transitions.
    
    // Store in cache
    if (sig_cache && state_idx < sig_cache_capacity) {
        sig_cache[state_idx].prefix_sig = hash;
        sig_cache[state_idx].prefix_valid = true;
    }
    
    return hash;
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
        
        // Skip if source is dead (can happen after multiple passes)
        int src = single_source[s];
        if (src < 0 || src >= state_count || dead_states[src]) continue;
        
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
            int rep = candidates[i].state;
            
            // Skip if rep is dead (was merged in a previous iteration)
            if (dead_states[rep]) {
                i = j;
                continue;
            }
            
            for (int k = i + 1; k < j; k++) {
                int s = candidates[k].state;
                if (dead_states[s]) continue;
                if (s == rep) continue;  // Skip if same state
                
                // Check if rep was merged in a previous iteration
                if (dead_states[rep]) {
                    break;
                }
                
                // Skip if either state is out of bounds
                if (s >= state_count || rep >= state_count) {
                    continue;
                }
                
                // Check for mutual transitions (would create self-loop)
                bool has_mutual = false;
                for (int sym = 0; sym < MAX_SYMBOLS && !has_mutual; sym++) {
                    int rep_target = nfa[rep].transitions[sym];
                    int s_target = nfa[s].transitions[sym];
                    if (rep_target >= 0 && rep_target == s) has_mutual = true;
                    if (s_target >= 0 && s_target == rep) has_mutual = true;
                }
                if (has_mutual) {
                    continue;
                }
                
                // Merge state s into rep by COMBINING transitions
                // This ensures the merged state can reach ALL futures
                nfa_state_t* rep_state = &nfa[rep];
                nfa_state_t* s_state = &nfa[s];
                
                // Combine single transitions
                for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                    int s_trans = s_state->transitions[sym];
                    int rep_trans = rep_state->transitions[sym];
                    if (s_trans >= 0) {
                        if (rep_trans < 0) {
                            // rep doesn't have this transition, add it
                            rep_state->transitions[sym] = s_trans;
                        } else if (rep_trans != s_trans) {
                            // Both have transitions on this symbol to different targets
                            // Add to multi-targets
                            mta_add_target(&rep_state->multi_targets, sym, rep_trans);
                            mta_add_target(&rep_state->multi_targets, sym, s_trans);
                            rep_state->transitions[sym] = -1;  // Clear single transition
                        }
                        // If same target, nothing to do
                    }
                }
                
                // Combine multi-targets from s_state into rep_state
                for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                    // First, check if rep has a single transition that needs to be merged with s's multi-targets
                    int rep_trans_val = rep_state->transitions[sym];
                    
                    if (rep_trans_val >= 0) {
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
                    // Sanity check: marker_count should be reasonable
                    if (markers && marker_count > 0 && marker_count < 1000) {
                        for (int m = 0; m < marker_count; m++) {
                            mta_add_marker(&rep_state->multi_targets, sym, 
                                          markers[m].pattern_id, markers[m].uid, markers[m].type);
                        }
                    }
                }
                
                // Combine accepting properties (OR the category masks)
                rep_state->category_mask |= s_state->category_mask;
                
                // Combine pending markers (if any)
                if (s_state->pending_marker_count > 0) {
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
                // Invalidate cache for merged state and representative
                sig_cache_invalidate(s);
                sig_cache_invalidate(rep);
                merged++;
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

// ============================================================================
// FINAL STATE DEDUPLICATION - O(n log n)
// ============================================================================

// Forward declarations - defined later in suffix merging section
static uint64_t compute_accepting_signature(const nfa_state_t* nfa, int state_idx);
static uint64_t compute_final_state_signature(const nfa_state_t* nfa, int state_idx);

/**
 * Final state deduplication merges accepting states that have:
 * 1. Identical accepting properties (category_mask, pattern_id, pending_markers)
 * 2. Identical outgoing transitions (typically none for final states)
 * 
 * This is a prerequisite for effective suffix merging - by merging equivalent
 * final states first, we create longer common suffixes that suffix merging
 * can then optimize.
 * 
 * Algorithm (O(n log n)):
 * 1. Find all accepting states
 * 2. Group by (accepting_signature, outgoing_signature)
 * 3. Merge states in same group
 */

// Structure for final state deduplication candidate
typedef struct {
    int state;
    uint64_t accept_sig;    // Hash of accepting properties
    uint64_t outgoing_sig;  // Hash of outgoing transitions
} final_state_candidate_t;

// Comparison function for final state candidates
static int compare_final_state_candidates(const void* a, const void* b) {
    const final_state_candidate_t* ca = (const final_state_candidate_t*)a;
    const final_state_candidate_t* cb = (const final_state_candidate_t*)b;
    if (ca->accept_sig < cb->accept_sig) return -1;
    if (ca->accept_sig > cb->accept_sig) return 1;
    if (ca->outgoing_sig < cb->outgoing_sig) return -1;
    if (ca->outgoing_sig > cb->outgoing_sig) return 1;
    return 0;
}

/**
 * Compute hash of outgoing transitions for a state.
 * This captures the "future" of the state - where it can transition to.
 */
static uint64_t compute_outgoing_signature(const nfa_state_t* state) {
    // FNV-1a hash
    uint64_t hash = 14695981039346656037ULL;
    
    // Hash single transitions
    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
        if (state->transitions[sym] >= 0) {
            hash ^= (uint64_t)sym;
            hash *= 1099511628211ULL;
            hash ^= (uint64_t)state->transitions[sym];
            hash *= 1099511628211ULL;
        }
    }
    
    // Hash multi-targets
    int mta_count = mta_get_entry_count((multi_target_array_t*)&state->multi_targets);
    if (mta_count > 0) {
        hash ^= mta_count;
        hash *= 1099511628211ULL;
        
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int count;
            int* targets = mta_get_target_array((multi_target_array_t*)&state->multi_targets, sym, &count);
            if (targets && count > 0) {
                hash ^= (uint64_t)sym;
                hash *= 1099511628211ULL;
                hash ^= (uint64_t)count;
                hash *= 1099511628211ULL;
                
                // Sort targets for consistent hashing
                int* sorted = malloc(count * sizeof(int));
                memcpy(sorted, targets, count * sizeof(int));
                for (int i = 0; i < count - 1; i++) {
                    for (int j = i + 1; j < count; j++) {
                        if (sorted[i] > sorted[j]) {
                            int t = sorted[i]; sorted[i] = sorted[j]; sorted[j] = t;
                        }
                    }
                }
                for (int i = 0; i < count; i++) {
                    hash ^= (uint64_t)sorted[i];
                    hash *= 1099511628211ULL;
                }
                free(sorted);
            }
        }
    }
    
    return hash;
}

/**
 * Deduplicate equivalent final states - O(n log n).
 * 
 * Merges accepting states that have identical accepting properties
 * and identical outgoing transitions.
 */
static int deduplicate_final_states(nfa_state_t* nfa, int state_count, bool* dead_states) {
    // Count accepting states
    int accept_count = 0;
    for (int s = 0; s < state_count; s++) {
        if (!dead_states[s] && nfa[s].category_mask != 0) {
            accept_count++;
        }
    }
    
    if (accept_count < 2) {
        return 0;  // Need at least 2 accepting states to merge
    }
    
    // Build candidate list
    final_state_candidate_t* candidates = malloc(accept_count * sizeof(final_state_candidate_t));
    int idx = 0;
    
    for (int s = 0; s < state_count; s++) {
        if (!dead_states[s] && nfa[s].category_mask != 0) {
            candidates[idx].state = s;
            candidates[idx].accept_sig = compute_final_state_signature(nfa, s);
            candidates[idx].outgoing_sig = compute_outgoing_signature(&nfa[s]);
            idx++;
        }
    }
    
    VERBOSE_PRINT("  Found %d accepting states for deduplication\n", accept_count);
    
    // Sort by (accept_sig, outgoing_sig)
    qsort(candidates, accept_count, sizeof(final_state_candidate_t), compare_final_state_candidates);
    
    // Find groups and merge
    int merged = 0;
    int i = 0;
    while (i < accept_count) {
        int j = i + 1;
        // Find all candidates with same (accept_sig, outgoing_sig)
        while (j < accept_count &&
               candidates[j].accept_sig == candidates[i].accept_sig &&
               candidates[j].outgoing_sig == candidates[i].outgoing_sig) {
            j++;
        }
        
        // If multiple candidates, merge them
        if (j - i > 1) {
            int rep = candidates[i].state;
            
            for (int k = i + 1; k < j; k++) {
                int s = candidates[k].state;
                if (dead_states[s]) continue;
                
                // Merge state s into rep by redirecting all incoming transitions
                for (int src = 0; src < state_count; src++) {
                    if (dead_states[src]) continue;
                    
                    nfa_state_t* src_state = &nfa[src];
                    
                    // Redirect single transitions
                    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                        if (src_state->transitions[sym] == s) {
                            src_state->transitions[sym] = rep;
                        }
                    }
                    
                    // Redirect multi-targets
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
                // Invalidate cache for merged state and representative
                sig_cache_invalidate(s);
                sig_cache_invalidate(rep);
                merged++;
                VERBOSE_PRINT("  Merged final state %d into %d\n", s, rep);
            }
        }
        
        i = j;
    }
    
    free(candidates);
    return merged;
}

// ============================================================================
// SUFFIX MERGING - O(n log n) backward analysis
// ============================================================================

/**
 * Suffix merging is the reverse of prefix merging:
 * 
 * PREFIX: Same INCOMING (source, symbol) + identical accepting props → merge by combining outgoing
 * SUFFIX: Same OUTGOING (set of transitions) + identical accepting props → merge by combining incoming
 * 
 * Key insight: Two states that have the same SET of outgoing transitions
 * and identical accepting properties can be merged by combining their
 * incoming transitions (union of pasts).
 * 
 * CRITICAL: Accepting states have semantic meaning (category, pattern_id).
 * Two accepting states can only be merged if they have IDENTICAL accepting
 * properties (category_mask, pattern_id, pending_markers).
 * 
 * Algorithm (O(n log n)):
 * 1. Compute outgoing signature for each state (hash of all outgoing transitions)
 * 2. Group by (outgoing_signature, accepting_properties)
 * 3. For each group, verify states have identical outgoing transitions
 * 4. Merge states in same group by redirecting incoming transitions
 */

// Structure for suffix merge candidate
typedef struct {
    int state;
    int target;           // Single outgoing transition target
    int symbol;           // Single outgoing transition symbol
    uint64_t accept_sig;  // Hash of accepting properties (prefix properties)
} suffix_candidate_t;

// Comparison function for suffix candidates
static int compare_suffix_candidates(const void* a, const void* b) {
    const suffix_candidate_t* ca = (const suffix_candidate_t*)a;
    const suffix_candidate_t* cb = (const suffix_candidate_t*)b;
    if (ca->target != cb->target) return ca->target - cb->target;
    if (ca->symbol != cb->symbol) return ca->symbol - cb->symbol;
    if (ca->accept_sig < cb->accept_sig) return -1;
    if (ca->accept_sig > cb->accept_sig) return 1;
    return 0;
}

/**
 * Compute hash of accepting properties for a state.
 * 
 * For suffix merging, we need to be conservative - states from different
 * patterns should NOT be merged even if they have the same category_mask,
 * because they represent different pattern matches.
 * 
 * ALWAYS include pattern_id to ensure states from different patterns
 * are kept separate.
 * 
 * Uses signature cache to avoid recomputation.
 */
static uint64_t compute_accepting_signature(const nfa_state_t* nfa, int state_idx) {
    // Check cache first
    if (sig_cache && state_idx < sig_cache_capacity && sig_cache[state_idx].accepting_valid) {
        return sig_cache[state_idx].accepting_sig;
    }
    
    const nfa_state_t* state = &nfa[state_idx];
    
    // FNV-1a hash
    uint64_t hash = 14695981039346656037ULL;
    
    // Hash category mask (the actual outcome)
    hash ^= state->category_mask;
    hash *= 1099511628211ULL;
    
    // Hash pattern_id - ALWAYS include to keep patterns separate
    hash ^= state->pattern_id;
    hash *= 1099511628211ULL;
    
    // Hash EOS target flag (affects outcome)
    hash ^= state->is_eos_target ? 1 : 0;
    hash *= 1099511628211ULL;
    
    // Hash pending markers
    hash ^= state->pending_marker_count;
    hash *= 1099511628211ULL;
    
    if (state->pending_marker_count > 0) {
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
    }
    
    // Store in cache
    if (sig_cache && state_idx < sig_cache_capacity) {
        sig_cache[state_idx].accepting_sig = hash;
        sig_cache[state_idx].accepting_valid = true;
    }
    
    return hash;
}

/**
 * Compute hash for final state deduplication.
 * 
 * For final state deduplication, we only care about the OUTCOME,
 * not which pattern produced it. Two accepting states with:
 *   - Same category_mask
 *   - Same EOS target flag
 *   - No pending markers (or identical markers)
 * can be safely merged because they produce identical outcomes.
 * 
 * This is different from compute_accepting_signature() which keeps
 * patterns separate for suffix merging.
 * 
 * Uses signature cache to avoid recomputation.
 */
static uint64_t compute_final_state_signature(const nfa_state_t* nfa, int state_idx) {
    // Note: We don't cache this separately as it's only used once in final dedup
    // But we could add a separate cache field if needed
    const nfa_state_t* state = &nfa[state_idx];
    
    // FNV-1a hash
    uint64_t hash = 14695981039346656037ULL;
    
    // Hash category mask (the actual outcome)
    hash ^= state->category_mask;
    hash *= 1099511628211ULL;
    
    // Hash EOS target flag (affects outcome)
    hash ^= state->is_eos_target ? 1 : 0;
    hash *= 1099511628211ULL;
    
    // Hash pending markers - if present, we need full details
    hash ^= state->pending_marker_count;
    hash *= 1099511628211ULL;
    
    if (state->pending_marker_count > 0) {
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
    }
    
    // NOTE: We do NOT include pattern_id - final states with the same
    // outcome can be merged regardless of which pattern produced them.
    
    return hash;
}

/**
 * Merge common suffix states - single pass (O(n log n)).
 * 
 * Finds states with a SINGLE outgoing transition and identical accepting properties.
 * States that transition to the same (target, symbol) pair can be safely merged
 * by combining their incoming transitions (union of pasts).
 * 
 * This is the reverse of prefix merging:
 * - PREFIX: Same incoming (source, symbol) → merge by combining outgoing
 * - SUFFIX: Same outgoing (target, symbol) → merge by combining incoming
 */
static int merge_common_suffixes_pass(nfa_state_t* nfa, int state_count, bool* dead_states) {
    // First pass: count states with single outgoing transition
    int candidate_count = 0;
    
    for (int s = 0; s < state_count; s++) {
        if (dead_states[s]) continue;
        if (s == 0) continue;  // Don't merge start state
        
        nfa_state_t* state = &nfa[s];
        
        // Count outgoing transitions
        int out_count = 0;
        int out_target = -1;
        int single_trans_count = 0;  // Count from transitions[] array
        int mta_trans_count = 0;     // Count from multi_targets
        
        // Check single transitions (old format)
        for (int sym = 0; sym < MAX_SYMBOLS && out_count <= 1; sym++) {
            if (state->transitions[sym] >= 0) {
                if (out_count == 0) {
                    out_target = state->transitions[sym];
                }
                out_count++;
                single_trans_count++;
            }
        }
        
        // Check multi-targets (new format - used for ALL transitions in NFA builder)
        if (out_count <= 1) {
            // First check the fast-path single targets (has_first_target)
            for (int sym = 0; sym < MAX_SYMBOLS && out_count <= 1; sym++) {
                if (state->multi_targets.has_first_target[sym]) {
                    if (out_count == 0) {
                        out_target = state->multi_targets.first_targets[sym];
                    }
                    out_count++;
                    mta_trans_count++;
                }
            }
        }
        
        // Then check multi-target entries (2+ targets on same symbol)
        if (out_count <= 1) {
            int mta_entries = mta_get_entry_count(&state->multi_targets);
            if (mta_entries > 0) {
                // Count all multi-target transitions
                for (int sym = 0; sym < MAX_SYMBOLS && out_count <= 1; sym++) {
                    int count;
                    int* targets = mta_get_target_array(&state->multi_targets, sym, &count);
                    if (targets && count > 0) {
                        for (int i = 0; i < count && out_count <= 1; i++) {
                            if (out_count == 0) {
                                out_target = targets[i];
                            }
                            out_count++;
                            mta_trans_count++;
                        }
                    }
                }
            }
        }
        
        // Only consider states with exactly one outgoing transition
        if (out_count == 1 && out_target >= 0 && !dead_states[out_target]) {
            candidate_count++;
        }
    }
    
    VERBOSE_PRINT("  Found %d suffix merge candidates\n", candidate_count);
    
    if (candidate_count < 2) {
        VERBOSE_PRINT("  Not enough suffix candidates (found %d)\n", candidate_count);
        return 0;  // Need at least 2 candidates to merge
    }
    
    // Build candidate list
    suffix_candidate_t* candidates = malloc(candidate_count * sizeof(suffix_candidate_t));
    int idx = 0;
    
    for (int s = 0; s < state_count; s++) {
        if (dead_states[s]) continue;
        if (s == 0) continue;
        
        nfa_state_t* state = &nfa[s];
        
        // Find single outgoing transition
        int out_target = -1;
        int out_symbol = -1;
        int out_count = 0;
        
        // Check single transitions (old format)
        for (int sym = 0; sym < MAX_SYMBOLS && out_count <= 1; sym++) {
            if (state->transitions[sym] >= 0) {
                if (out_count == 0) {
                    out_target = state->transitions[sym];
                    out_symbol = sym;
                }
                out_count++;
            }
        }
        
        // Check fast-path single targets (has_first_target)
        if (out_count <= 1) {
            for (int sym = 0; sym < MAX_SYMBOLS && out_count <= 1; sym++) {
                if (state->multi_targets.has_first_target[sym]) {
                    if (out_count == 0) {
                        out_target = state->multi_targets.first_targets[sym];
                        out_symbol = sym;
                    }
                    out_count++;
                }
            }
        }
        
        // Check multi-target entries (2+ targets on same symbol)
        if (out_count <= 1) {
            int mta_entries = mta_get_entry_count(&state->multi_targets);
            if (mta_entries > 0) {
                for (int sym = 0; sym < MAX_SYMBOLS && out_count <= 1; sym++) {
                    int count;
                    int* targets = mta_get_target_array(&state->multi_targets, sym, &count);
                    if (targets && count > 0) {
                        for (int i = 0; i < count && out_count <= 1; i++) {
                            if (out_count == 0) {
                                out_target = targets[i];
                                out_symbol = sym;
                            }
                            out_count++;
                        }
                    }
                }
            }
        }
         
        if (out_count == 1 && out_target >= 0 && !dead_states[out_target]) {
            candidates[idx].state = s;
            candidates[idx].target = out_target;
            candidates[idx].symbol = out_symbol;
            candidates[idx].accept_sig = compute_accepting_signature(nfa, s);
            idx++;
        }
    }
    
    VERBOSE_PRINT("  Found %d suffix merge candidates\n", candidate_count);
    
    // Sort by (target, symbol, accept_sig)
    qsort(candidates, candidate_count, sizeof(suffix_candidate_t), compare_suffix_candidates);
    
    // Find groups and merge
    int merged = 0;
    int i = 0;
    while (i < candidate_count) {
        int j = i + 1;
        // Find all candidates with same (target, symbol, accept_sig)
        while (j < candidate_count &&
               candidates[j].target == candidates[i].target &&
               candidates[j].symbol == candidates[i].symbol &&
               candidates[j].accept_sig == candidates[i].accept_sig) {
            j++;
        }
        
        // If multiple candidates, merge them
        if (j - i > 1) {
            VERBOSE_PRINT("  Found group of %d states with same (target=%d, sym=%d, accept_sig=%016lx)\n",
                         j - i, candidates[i].target, candidates[i].symbol, 
                         (unsigned long)candidates[i].accept_sig);
            int rep = candidates[i].state;
            
            for (int k = i + 1; k < j; k++) {
                int s = candidates[k].state;
                if (dead_states[s]) continue;
                if (dead_states[rep]) {
                    // Representative was merged, pick a new one
                    rep = s;
                    continue;
                }
                
                // Check for mutual transitions (would create self-loop)
                bool has_mutual = false;
                for (int sym = 0; sym < MAX_SYMBOLS && !has_mutual; sym++) {
                    if (nfa[rep].transitions[sym] == s) has_mutual = true;
                    if (nfa[s].transitions[sym] == rep) has_mutual = true;
                }
                if (has_mutual) {
                    VERBOSE_PRINT("  Skipping merge due to mutual transition between %d and %d\n", rep, s);
                    continue;
                }
                
                // Merge state s into rep by redirecting all incoming transitions
                // This is the "union of pasts" - all sources now point to rep
                for (int src = 0; src < state_count; src++) {
                    if (dead_states[src]) continue;
                    
                    nfa_state_t* src_state = &nfa[src];
                    
                    // Redirect single transitions
                    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                        if (src_state->transitions[sym] == s) {
                            src_state->transitions[sym] = rep;
                        }
                    }
                    
                    // Redirect multi-targets
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
                // Invalidate cache for merged state and representative
                sig_cache_invalidate(s);
                sig_cache_invalidate(rep);
                merged++;
                VERBOSE_PRINT("  Merged suffix state %d into %d (target=%d, symbol=%d)\n", 
                             s, rep, candidates[i].target, candidates[i].symbol);
            }
        }
        
        i = j;
    }
    
    free(candidates);
    return merged;
}

/**
 * Merge common suffix states - iterative passes.
 * 
 * After each pass, previously unreachable merge opportunities may become
 * available as states get merged. We iterate until no more merges happen.
 */
static int merge_common_suffixes_fast(nfa_state_t* nfa, int state_count, bool* dead_states) {
    int total_merged = 0;
    int pass = 1;
    const int max_passes = 10;
    
    while (pass <= max_passes) {
        VERBOSE_PRINT("  Suffix merge pass %d...\n", pass);
        int merged = merge_common_suffixes_pass(nfa, state_count, dead_states);
        total_merged += merged;
        
        if (merged == 0) {
            VERBOSE_PRINT("  No more suffix merges possible after pass %d\n", pass);
            break;
        }
        
        VERBOSE_PRINT("  Pass %d merged %d suffix states (total: %d)\n", pass, merged, total_merged);
        pass++;
    }
    
    return total_merged;
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
 * Suffix Factorization Pass
 * 
 * Creates NEW intermediate states to factor out common suffixes.
 * 
 * Pattern:
 *   Before: X --a--> T, Y --a--> T (both reach T on symbol 'a')
 *   After:  X --a--> A', Y --a--> A', A' --EPSILON--> T
 * 
 * This reduces transitions by sharing intermediate states.
 * The intermediate state uses EPSILON to preserve semantics:
 * - Original: X consumes 'a' to reach T
 * - After: X consumes 'a' to reach A', then EPSILON (free) to T
 * - Same language, fewer transitions!
 * 
 * IMPORTANT: The intermediate state MUST use EPSILON, not the original symbol.
 * Using the same symbol would change the language:
 *   WRONG: X --a--> A' --a--> T (requires TWO 'a' symbols!)
 *   RIGHT: X --a--> A' --EPSILON--> T (still one 'a' symbol)
 * 
 * Algorithm:
 * 1. Find all transitions grouped by (target, symbol)
 * 2. For groups with 2+ sources pointing to same (target, symbol):
 *    - Create a new intermediate state
 *    - Add EPSILON transition from intermediate to target
 *    - Redirect all sources to point to intermediate instead of target
 */
static int factorize_suffixes_pass(nfa_state_t* nfa, int state_count, bool** dead_states_ptr, int* dead_states_capacity_ptr, int* next_state) {
    int merged = 0;
    bool* dead_states = *dead_states_ptr;
    int dead_states_capacity = *dead_states_capacity_ptr;
    
    // Find all (source, symbol, target) transitions
    // Group by (target, symbol) to find common suffixes
    typedef struct {
        int source;
        int symbol;
        int target;
    } transition_t;
    
    // Use dynamic allocation with growth factor
    int trans_capacity = 1024;  // Start with reasonable initial capacity
    transition_t* transitions = malloc(trans_capacity * sizeof(transition_t));
    if (!transitions) {
        VERBOSE_PRINT("  Failed to allocate transitions array\n");
        return 0;
    }
    int trans_count = 0;
    
    for (int s = 0; s < state_count; s++) {
        if (dead_states[s]) continue;
        if (s == 0) continue;  // Don't factorize start state
        
        nfa_state_t* state = &nfa[s];
        
        // Collect all outgoing transitions using mta_get_target_array
        // which handles both single targets (fast-path) and multi-targets
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int cnt;
            int* targets = mta_get_target_array(&state->multi_targets, sym, &cnt);
            if (targets && cnt > 0) {
                for (int i = 0; i < cnt; i++) {
                    // Only factorize through ORIGINAL states (not newly created intermediate states)
                    // This prevents infinite chains of intermediate states
                    if (targets[i] >= 0 && targets[i] < state_count && !dead_states[targets[i]]) {
                        // Grow buffer if needed
                        if (trans_count >= trans_capacity) {
                            int new_capacity = trans_capacity * 2;
                            transition_t* new_transitions = realloc(transitions, new_capacity * sizeof(transition_t));
                            if (!new_transitions) {
                                free(transitions);
                                VERBOSE_PRINT("  Failed to grow transitions array\n");
                                return 0;
                            }
                            transitions = new_transitions;
                            trans_capacity = new_capacity;
                        }
                        transitions[trans_count].source = s;
                        transitions[trans_count].symbol = sym;
                        transitions[trans_count].target = targets[i];
                        trans_count++;
                    }
                }
            }
        }
    }
    
    // Group by (target, symbol) to find common suffixes
    // Use a simple O(n²) approach for now
    for (int i = 0; i < trans_count; i++) {
        int target = transitions[i].target;
        int symbol = transitions[i].symbol;
        
        if (dead_states[target]) continue;
        
        // Skip if we've already processed this (target, symbol) pair
        bool already_processed = false;
        for (int j = 0; j < i && !already_processed; j++) {
            if (transitions[j].target == target && transitions[j].symbol == symbol) {
                already_processed = true;
            }
        }
        if (already_processed) continue;
        
        // Find all sources with same (target, symbol)
        // Use a small fixed-size buffer since source_count is typically small
        int sources_buf[64];
        int* sources = sources_buf;
        int source_capacity = 64;
        int source_count = 0;
        
        for (int j = i; j < trans_count; j++) {
            if (transitions[j].target == target && transitions[j].symbol == symbol) {
                // Check if this source is already in the list
                bool found = false;
                for (int k = 0; k < source_count && !found; k++) {
                    if (sources[k] == transitions[j].source) found = true;
                }
                if (!found) {
                    // Grow buffer if needed (rare case)
                    if (source_count >= source_capacity) {
                        int new_capacity = source_capacity * 2;
                        int* new_sources = malloc(new_capacity * sizeof(int));
                        if (!new_sources) continue;
                        memcpy(new_sources, sources, source_count * sizeof(int));
                        if (sources != sources_buf) free(sources);
                        sources = new_sources;
                        source_capacity = new_capacity;
                    }
                    sources[source_count++] = transitions[j].source;
                }
            }
        }
        
        // If 2+ sources share the same (target, symbol), factorize
        if (source_count >= 2) {
            VERBOSE_PRINT("  Found %d sources with common suffix (target=%d, symbol=%d)\n",
                         source_count, target, symbol);
            
            // Grow dead_states array if needed to accommodate new state
            if (*next_state >= dead_states_capacity) {
                int new_capacity = dead_states_capacity * 2;
                if (new_capacity <= *next_state) {
                    new_capacity = *next_state + 64;  // Ensure we have room
                }
                // Don't exceed MAX_STATES - the NFA array is fixed size
                if (new_capacity > MAX_STATES) {
                    new_capacity = MAX_STATES;
                }
                if (*next_state >= new_capacity) {
                    VERBOSE_PRINT("  Cannot create new state: would exceed MAX_STATES\n");
                    if (sources != sources_buf) free(sources);
                    continue;
                }
                bool* new_dead_states = realloc(dead_states, new_capacity * sizeof(bool));
                if (!new_dead_states) {
                    VERBOSE_PRINT("  Failed to grow dead_states array\n");
                    if (sources != sources_buf) free(sources);
                    continue;
                }
                // Initialize new slots to false (not dead)
                memset(new_dead_states + dead_states_capacity, 0, (new_capacity - dead_states_capacity) * sizeof(bool));
                dead_states = new_dead_states;
                dead_states_capacity = new_capacity;
                *dead_states_ptr = dead_states;
                *dead_states_capacity_ptr = dead_states_capacity;
                // Also grow signature cache
                sig_cache_grow(new_capacity);
                VERBOSE_PRINT("  Grew dead_states array to %d capacity\n", dead_states_capacity);
            }
            
            // Create a new intermediate state
            int new_state = (*next_state)++;
            memset(&nfa[new_state], 0, sizeof(nfa_state_t));
            
            // Initialize all transitions to -1 (no transition)
            for (int t = 0; t < MAX_SYMBOLS; t++) {
                nfa[new_state].transitions[t] = -1;
            }
            
            // The new state is a PURE INTERMEDIATE - it does NOT inherit accepting properties
            // It simply passes through to the target via EPSILON
            // This preserves semantics: the intermediate state doesn't consume input
            
            // Add EPSILON transition from new_state to target
            // This is CRITICAL: using the same symbol would change the language!
            // (e.g., X --a--> A' --a--> T requires TWO 'a' symbols, not one)
            nfa[new_state].multi_targets.has_first_target[VSYM_EPS] = true;
            nfa[new_state].multi_targets.first_targets[VSYM_EPS] = target;
            
            // Redirect all sources to point to new_state instead of target
            for (int k = 0; k < source_count; k++) {
                int src = sources[k];
                if (dead_states[src]) continue;
                
                nfa_state_t* src_state = &nfa[src];
                
                // Redirect fast-path single target
                if (src_state->multi_targets.has_first_target[symbol] &&
                    src_state->multi_targets.first_targets[symbol] == target) {
                    src_state->multi_targets.first_targets[symbol] = new_state;
                }
                
                // Redirect multi-targets
                int cnt;
                int* tgts = mta_get_target_array(&src_state->multi_targets, symbol, &cnt);
                if (tgts && cnt > 0) {
                    for (int t = 0; t < cnt; t++) {
                        if (tgts[t] == target) {
                            tgts[t] = new_state;
                        }
                    }
                }
            }
            
            merged += source_count - 1;  // Net reduction
            VERBOSE_PRINT("    Created new state %d, merged %d paths\n", new_state, source_count - 1);
        }
        
        // Free dynamically allocated buffer if it was grown
        if (sources != sources_buf) free(sources);
    }
    
    free(transitions);
    return merged;
}

/**
 * Suffix Factorization - iterative passes.
 * 
 * Creates NEW intermediate states to factor out common suffixes.
 * This is different from suffix merging - it creates new states
 * rather than merging existing ones.
 * 
 * IMPORTANT: Only factorizes through ORIGINAL states (not newly created ones)
 * to prevent infinite chains of intermediate states.
 * 
 * next_state_ptr is tracked persistently across calls to prevent reusing state slots.
 */
static int factorize_suffixes(nfa_state_t* nfa, int state_count, bool** dead_states_ptr, int* dead_states_capacity_ptr, int* next_state_ptr) {
    int total_merged = 0;
    int pass = 1;
    const int max_passes = 1;  // Single pass is sufficient and prevents chains
    
    while (pass <= max_passes) {
        VERBOSE_PRINT("  Suffix factorization pass %d...\n", pass);
        int merged = factorize_suffixes_pass(nfa, state_count, dead_states_ptr, dead_states_capacity_ptr, next_state_ptr);
        total_merged += merged;
        
        if (merged == 0) {
            VERBOSE_PRINT("  No more suffix factorization possible after pass %d\n", pass);
            break;
        }
        
        VERBOSE_PRINT("  Pass %d factorized %d paths (total: %d)\n", pass, merged, total_merged);
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
        !opts.enable_final_dedup && !opts.enable_bidirectional && !opts.enable_sat_optimal) {
        VERBOSE_PRINT("Pre-minimization: No optimizations enabled, skipping\n");
        return 0;
    }
    
    VERBOSE_PRINT("Pre-minimizing NFA with %d states\n", original_count);
    
    // Initialize signature cache for the lifetime of this preminimization run
    sig_cache_init(original_count);
    
    // Allocate dead state tracking and partition array
    // dead_states is dynamic - it can grow when suffix factorization creates new states
    int dead_states_capacity = original_count;
    bool* dead_states = calloc(dead_states_capacity, sizeof(bool));
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
    
    // Phase 4: Deduplicate equivalent final states (O(n log n))
    // This MUST run before bidirectional merging to create longer common suffixes
    if (opts.enable_final_dedup) {
        VERBOSE_PRINT("Deduplicating final states...\n");
        last_stats.final_deduped = deduplicate_final_states(nfa, original_count, dead_states);
        VERBOSE_PRINT("Deduplicated %d final states\n", last_stats.final_deduped);
    }
    
    // Phase 5: Bidirectional incremental merging (O(n log n))
    // This combines prefix and suffix merging in an incremental fixpoint iteration.
    // We alternate between prefix and suffix passes until no more merges happen.
    // Then, if SAT optimal is enabled, we try harder merges on remaining candidates.
    
    // Track effective state count - this includes newly created intermediate states
    // from suffix factorization (which are created beyond original_count)
    int effective_count = original_count;
    
    if (opts.enable_bidirectional) {
        VERBOSE_PRINT("Running bidirectional incremental merging...\n");
        int total_bidir_merged = 0;
        int pass = 1;
        const int max_passes = 20;  // Safety limit
        
        // Track next available state slot for suffix factorization (persists across passes)
        int next_state = original_count;
        
        while (pass <= max_passes) {
            VERBOSE_PRINT("  Bidirectional pass %d...\n", pass);
            
            // Use next_state as the current state count - it includes any newly created states
            int current_count = next_state;
            
            // Try prefix merging
            int prefix_merged = merge_common_prefixes(nfa, current_count, dead_states);
            VERBOSE_PRINT("    Prefix merging: %d states\n", prefix_merged);
            
            // Try suffix merging
            int suffix_merged = merge_common_suffixes_fast(nfa, current_count, dead_states);
            VERBOSE_PRINT("    Suffix merging: %d states\n", suffix_merged);
            
            // Try suffix factorization (creates new intermediate states)
            int suffix_factored = factorize_suffixes(nfa, current_count, &dead_states, &dead_states_capacity, &next_state);
            VERBOSE_PRINT("    Suffix factorization: %d paths\n", suffix_factored);
            
            int pass_merged = prefix_merged + suffix_merged + suffix_factored;
            total_bidir_merged += pass_merged;
            
            // If no merges happened, we've reached fixpoint
            if (pass_merged == 0) {
                VERBOSE_PRINT("  Fixpoint reached after %d passes\n", pass);
                break;
            }
            
            VERBOSE_PRINT("  Pass %d merged %d states (total: %d)\n", pass, pass_merged, total_bidir_merged);
            pass++;
        }
        
        if (pass > max_passes) {
            VERBOSE_PRINT("  Warning: Reached max passes limit (%d)\n", max_passes);
        }
        
        last_stats.prefix_merged = total_bidir_merged;
        VERBOSE_PRINT("Bidirectional merging eliminated %d states\n", total_bidir_merged);
        
        // Update effective_count to include any new intermediate states created
        effective_count = next_state;
        VERBOSE_PRINT("Effective state count after factorization: %d\n", effective_count);
        
        // Phase 5b: SAT-based optimal merge selection (continuation of bidirectional)
        // After greedy fixpoint, try harder merges on remaining conflicting candidates.
        // This reuses the same NFA state and continues where bidirectional left off.
        if (opts.enable_sat_optimal && nfa_preminimize_optimal_available()) {
            VERBOSE_PRINT("Continuing with SAT optimal merge selection...\n");
            int max_cand = opts.max_sat_candidates > 0 ? opts.max_sat_candidates : 200;
            last_stats.sat_optimal = nfa_preminimize_optimal_merges(nfa, effective_count, dead_states,
                                                                      max_cand, opts.verbose);
            if (last_stats.sat_optimal > 0) {
                VERBOSE_PRINT("SAT optimal merged %d additional states\n", last_stats.sat_optimal);
            }
        }
    }
    
    // Phase 6: Final unreachable cleanup
    if (opts.enable_prune) {
        VERBOSE_PRINT("Final unreachable cleanup...\n");
        int final_unreachable = remove_unreachable(nfa, effective_count, dead_states);
        last_stats.unreachable_removed += final_unreachable;
        VERBOSE_PRINT("Removed %d more unreachable states\n", final_unreachable);
    }
    
    // Count how many states were marked dead
    int dead_count = 0;
    for (int i = 0; i < effective_count; i++) {
        if (dead_states[i]) dead_count++;
    }
    
    // Compact the NFA by removing dead states
    int new_count = effective_count;
    if (dead_count > 0) {
        new_count = compact_nfa(nfa, effective_count, dead_states);
        *state_count = new_count;
    } else if (effective_count > original_count) {
        // No dead states, but we created new intermediate states - update caller's count
        *state_count = effective_count;
    }
    last_stats.minimized_states = new_count;
    
    free(dead_states);
    free(partition);
    
    // Free signature cache
    sig_cache_free();
    
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
