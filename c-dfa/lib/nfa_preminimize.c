/**
 * NFA Pre-Minimization Implementation
 *
 * Reduces NFA states before subset construction using:
 * 1. Epsilon pass-through elimination - bypass simple epsilon-only states
 * 2. Common prefix merging - share states for identical prefixes (O(n log n))
 * 3. Unreachable state pruning
 *
 * Key advantage: We have global knowledge of the full NFA, unlike the
 * per-pattern RDP parser which has no look-ahead.
 *
 * PREFIX MERGING SAFETY:
 * ======================
 * Prefix merging is now SAFE because we use compute_full_signature() which
 * combines prefix properties AND outgoing transitions AND markers. Two states
 * with the same full signature have:
 *   - Same prefix properties (category, pattern_id, eos_target, pending_markers)
 *   - Same outgoing transitions (where they can go next)
 *   - Same markers on transitions
 *
 * When states are reached via the same (source, symbol) pair AND have
 * identical full signatures, they are truly equivalent - merging them cannot
 * change the language because they have identical behavior both before and
 * after the current state. The merge operation only redirects incoming edges;
 * no outgoing transitions are combined.
 *
 * The DFA minimization phase handles additional state reduction safely.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "nfa_preminimize.h"
#include "../include/multi_target_array.h"

// Maximum epsilon closure depth - caps complexity of epsilon-aware signatures
// A value of 16 handles typical chained epsilon transitions while limiting computation
#define MAX_EPSILON_CLOSURE 16

// Sentinel value indicating epsilon closure was truncated (unbounded)
// States with TRUNCATED signature cannot be merged with any other state
#define TRUNCATED UINT64_MAX

// Statistics from last run
static nfa_premin_stats_t last_stats = {
    .original_states = 0,
    .minimized_states = 0,
    .epsilon_bypassed = 0,
    .epsilon_chains = 0,
    .landing_pads_removed = 0,
    .unreachable_removed = 0,
    .states_merged = 0,
    .identical_merged = 0,
    .prefix_merged = 0,
    .final_deduped = 0,
    .suffix_merged = 0,
    .sat_merged = 0,
    .sat_optimal = 0
};
static bool premin_verbose = false;

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
    uint64_t full_sig;        // Hash of full signature (prefix + outgoing)
    bool accepting_valid;     // Is accepting_sig valid?
    bool outgoing_valid;      // Is outgoing_sig valid?
    bool prefix_valid;        // Is prefix_sig valid?
    bool full_valid;          // Is full_sig valid?
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
            sig_cache[i].full_valid = false;
        }
        return;
    }

    // Free old cache if exists
    free(sig_cache);

    // Allocate new cache
    sig_cache = calloc(capacity, sizeof(signature_cache_entry_t));
    if (!sig_cache) {
        sig_cache_capacity = 0;  // OOM - cache disabled
        return;
    }
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
        sig_cache[state_idx].full_valid = false;
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
        new_cache[i].full_valid = false;
    }

    sig_cache = new_cache;
    sig_cache_capacity = new_capacity;
}

/**
 * Check if a state has a transition to a specific target on a symbol.
 * Examines all transition representations:
 * 1. transitions[] array (legacy format)
 * 2. has_first_target/first_targets fast-path
 * 3. symbol_map multi-target entries
 */
static bool nfa_has_transition_to(const nfa_state_t* state, int sym, int target) {
    if (!state || sym < 0 || sym >= MAX_SYMBOLS || target < 0) {
        return false;
    }

    if (state->transitions[sym] == target) {
        return true;
    }

    if (state->multi_targets.has_first_target[sym] &&
        state->multi_targets.first_targets[sym] == target) {
        return true;
    }

    mta_entry_t* entry = state->multi_targets.symbol_map[sym];
    if (entry) {
        for (int i = 0; i < entry->target_count; i++) {
            if (entry->targets[i] == target) {
                return true;
            }
        }
    }

    return false;
}

/**
 * Compute epsilon closure of a state set with a maximum depth cap.
 * Uses BFS to find all states reachable via epsilon transitions.
 * Results are sorted for deterministic hashing.
 *
 * @param nfa NFA state array
 * @param initial_states Array of initial state indices
 * @param initial_count Number of initial states
 * @param out_states Output buffer for closure (must have capacity MAX_EPSILON_CLOSURE)
 * @param out_truncated Output: true if actual closure was larger than MAX_EPSILON_CLOSURE
 * @return Number of states in closure (capped at MAX_EPSILON_CLOSURE)
 */
static int compute_epsilon_closure(const nfa_state_t* nfa, int* initial_states, int initial_count,
                                   int* out_states, bool* out_truncated) {
    bool visited[MAX_STATES] = {false};
    int stack[MAX_STATES];
    int stack_top = 0;
    int result_count = 0;
    bool truncated = false;

    for (int i = 0; i < initial_count && result_count < MAX_EPSILON_CLOSURE; i++) {
        int state = initial_states[i];
        if (state < 0 || state >= MAX_STATES || visited[state]) continue;
        visited[state] = true;
        stack[stack_top++] = state;
    }

    while (stack_top > 0 && result_count < MAX_EPSILON_CLOSURE) {
        int current = stack[--stack_top];
        out_states[result_count++] = current;

        int eps_count;
        int* eps_targets = mta_get_target_array((multi_target_array_t*)&nfa[current].multi_targets, VSYM_EPS, &eps_count);
        if (eps_targets && eps_count > 0) {
            for (int i = 0; i < eps_count; i++) {
                int t = eps_targets[i];
                if (t >= 0 && t < MAX_STATES && !visited[t]) {
                    if (result_count >= MAX_EPSILON_CLOSURE) {
                        truncated = true;
                        break;
                    }
                    visited[t] = true;
                    stack[stack_top++] = t;
                }
            }
        }
    }

    if (stack_top > 0 && result_count >= MAX_EPSILON_CLOSURE) {
        truncated = true;
    }

    for (int i = 0; i < result_count - 1; i++) {
        for (int j = i + 1; j < result_count; j++) {
            if (out_states[i] > out_states[j]) {
                int tmp = out_states[i];
                out_states[i] = out_states[j];
                out_states[j] = tmp;
            }
        }
    }

    *out_truncated = truncated;
    return result_count;
}

/**
 * Get epsilon-closed targets for a symbol.
 * Returns the union of epsilon closures of all immediate targets.
 *
 * @param nfa NFA state array
 * @param state_idx State to query
 * @param sym Symbol to check
 * @param out_targets Output buffer (capacity MAX_EPSILON_CLOSURE)
 * @param out_truncated Output: true if ANY component closure was truncated
 * @return Number of targets in epsilon-closed set
 */
static int get_epsilon_closed_targets(const nfa_state_t* nfa, int state_idx, int sym, int* out_targets, bool* out_truncated) {
    int immediate_targets[MAX_STATES];
    int immediate_count = 0;

    const nfa_state_t* state = &nfa[state_idx];

    if (state->transitions[sym] >= 0) {
        immediate_targets[immediate_count++] = state->transitions[sym];
    }

    if (state->multi_targets.has_first_target[sym]) {
        immediate_targets[immediate_count++] = state->multi_targets.first_targets[sym];
    }

    int mta_count = mta_get_entry_count((multi_target_array_t*)&state->multi_targets);
    for (int s = 0; s < MAX_SYMBOLS; s++) {
        int count;
        int* targets = mta_get_target_array((multi_target_array_t*)&state->multi_targets, s, &count);
        if (targets && count > 0 && s == sym) {
            for (int i = 0; i < count && immediate_count < MAX_STATES; i++) {
                immediate_targets[immediate_count++] = targets[i];
            }
        }
    }

    bool truncated = false;
    int closure[MAX_EPSILON_CLOSURE];
    int result_count = 0;

    for (int i = 0; i < immediate_count && result_count < MAX_EPSILON_CLOSURE; i++) {
        int closed[MAX_EPSILON_CLOSURE];
        bool closed_truncated;
        int closed_count = compute_epsilon_closure(nfa, &immediate_targets[i], 1, closed, &closed_truncated);
        if (closed_truncated) {
            truncated = true;
        }
        for (int j = 0; j < closed_count && result_count < MAX_EPSILON_CLOSURE; j++) {
            bool exists = false;
            for (int k = 0; k < result_count; k++) {
                if (out_targets[k] == closed[j]) {
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                out_targets[result_count++] = closed[j];
            }
        }
    }

    for (int i = 0; i < result_count - 1; i++) {
        for (int j = i + 1; j < result_count; j++) {
            if (out_targets[i] > out_targets[j]) {
                int tmp = out_targets[i];
                out_targets[i] = out_targets[j];
                out_targets[j] = tmp;
            }
        }
    }

    *out_truncated = truncated;
    return result_count;
}

/**
 * Compute epsilon-aware outgoing signature.
 * Instead of hashing immediate targets, hashes epsilon-closed target sets.
 * Returns TRUNCATED if ANY symbol's closure was truncated.
 */
static uint64_t compute_epsilon_aware_outgoing_signature(const nfa_state_t* nfa, int state_idx) {
    uint64_t hash = 14695981039346656037ULL;

    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
        int targets[MAX_EPSILON_CLOSURE];
        bool sym_truncated;
        int count = get_epsilon_closed_targets(nfa, state_idx, sym, targets, &sym_truncated);

        if (sym_truncated) {
            return TRUNCATED;
        }

        hash ^= (uint64_t)sym;
        hash *= 1099511628211ULL;
        hash ^= (uint64_t)count;
        hash *= 1099511628211ULL;

        for (int i = 0; i < count; i++) {
            hash ^= (uint64_t)targets[i];
            hash *= 1099511628211ULL;
        }
    }

    return hash;
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
        .enable_prune = true,           // Remove unreachable states (O(n))
        .enable_final_dedup = true,     // Deduplicate equivalent final states
        .enable_bidirectional = true,   // Bidirectional incremental merging (O(n log n))
        .enable_sat_optimal = true,     // SAT-based optimal merge selection (continuation of bidirectional)
        .max_sat_candidates = 200,     // Maximum candidates for SAT (bounds complexity)

        .verbose = false
    };
    return opts;
}

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
 * Epsilon elimination pass with peephole optimizations:
 * 1. Remove self-loop epsilon transitions (state -> state on epsilon)
 * 2. Deduplicate multiple epsilon transitions to the same target
 * 3. Bypass single epsilon pass-through states (no accepting props, single epsilon out)
 *
 * All safe - preserves language equivalence.
 */
static int bypass_epsilon_pass_through(nfa_state_t* nfa, int state_count, bool* dead_states) {
    int bypassed = 0;

    for (int s = 1; s < state_count; s++) {
        if (dead_states[s]) continue;
        nfa_state_t* state = &nfa[s];

        int eps_targets[64];
        int eps_count = 0;

        int cnt;
        int* targets = mta_get_target_array(&state->multi_targets, VSYM_EPS, &cnt);
        if (targets) {
            for (int i = 0; i < cnt; i++) {
                int t = targets[i];
                if (t == s) continue;
                bool dup = false;
                for (int j = 0; j < eps_count; j++) {
                    if (eps_targets[j] == t) { dup = true; break; }
                }
                if (!dup && eps_count < 64) eps_targets[eps_count++] = t;
            }
        }

        if (state->transitions[VSYM_EPS] >= 0) {
            int t = state->transitions[VSYM_EPS];
            if (t != s) {
                bool dup = false;
                for (int j = 0; j < eps_count; j++) {
                    if (eps_targets[j] == t) { dup = true; break; }
                }
                if (!dup && eps_count < 64) eps_targets[eps_count++] = t;
            }
        }

        bool needs_update = (eps_count != cnt) ||
            (state->transitions[VSYM_EPS] >= 0 && state->transitions[VSYM_EPS] == s);

        if (needs_update) {
            mta_clear_symbol(&state->multi_targets, VSYM_EPS);
            state->transitions[VSYM_EPS] = -1;
            for (int i = 0; i < eps_count; i++) {
                mta_add_target(&state->multi_targets, VSYM_EPS, eps_targets[i]);
            }
        }

        if (eps_count != 1) continue;

        bool has_other = false;
        for (int sym = 0; sym < MAX_SYMBOLS && !has_other; sym++) {
            if (sym == VSYM_EPS) continue;
            if (mta_get_target_count(&state->multi_targets, sym) > 0) has_other = true;
            if (state->transitions[sym] >= 0) has_other = true;
        }
        if (has_other) continue;

        if (state->category_mask != 0 || state->pending_marker_count != 0 || state->is_eos_target) continue;

        int epsilon_target = eps_targets[0];
        if (dead_states[epsilon_target]) continue;
        if (epsilon_target == s) continue;

        for (int src = 0; src < state_count; src++) {
            if (dead_states[src]) continue;
            nfa_state_t* src_state = &nfa[src];

            for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                if (src_state->transitions[sym] == s) {
                    src_state->transitions[sym] = epsilon_target;
                }
            }

            for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                int count;
                int* targs = mta_get_target_array(&src_state->multi_targets, sym, &count);
                if (targs && count > 0) {
                    for (int i = 0; i < count; i++) {
                        if (targs[i] == s) {
                            targs[i] = epsilon_target;
                        }
                    }
                }
            }
        }

        dead_states[s] = true;
        bypassed++;
        VERBOSE_PRINT(premin, "  Bypassed epsilon pass-through state %d -> %d\n", s, epsilon_target);
    }

    return bypassed;
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

/**
 * Context for prefix merge passes - reusable buffers to avoid repeated allocations.
 */
typedef struct {
    int* incoming_count;
    int* single_source;
    int* single_symbol;
    prefix_candidate_t* candidates;
    int candidates_capacity;
} prefix_merge_ctx_t;

static prefix_merge_ctx_t* prefix_merge_ctx_create(int state_count) {
    prefix_merge_ctx_t* ctx = malloc(sizeof(prefix_merge_ctx_t));
    if (!ctx) return NULL;

    ctx->incoming_count = calloc(state_count, sizeof(int));
    ctx->single_source = malloc(state_count * sizeof(int));
    ctx->single_symbol = malloc(state_count * sizeof(int));
    ctx->candidates_capacity = state_count;
    ctx->candidates = malloc((size_t)state_count * sizeof(prefix_candidate_t));

    if (!ctx->incoming_count || !ctx->single_source || !ctx->single_symbol || !ctx->candidates) {
        free(ctx->incoming_count);
        free(ctx->single_source);
        free(ctx->single_symbol);
        free(ctx->candidates);
        free(ctx);
        return NULL;
    }

return ctx;
}

static void prefix_merge_ctx_free(prefix_merge_ctx_t* ctx) {
    if (!ctx) return;
    free(ctx->incoming_count);
    free(ctx->single_source);
    free(ctx->single_symbol);
    free(ctx->candidates);
    free(ctx);
}

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

// Forward declaration
static uint64_t compute_full_signature(const nfa_state_t* nfa, int state_idx);

/**
 * Merge common prefix states - single pass.
 *
 * This is SAFE because we only merge states that:
 * 1. Have exactly one incoming transition
 * 2. That incoming transition is from the same (source, symbol) pair
 * 3. Have identical prefix signatures (computed via nfa_compute_state_signature)
 * 4. Are checked for mutual transitions before merging
 *
 * Algorithm (O(n log n)):
 * 1. Build incoming transition map for each state
 * 2. Find states with single incoming transition
 * 3. Group by (source, symbol, prefix_signature)
 * 4. Merge states in same group - only redirect incoming edges
 */
static int merge_common_prefixes_pass(nfa_state_t* nfa, int state_count, bool* dead_states, prefix_merge_ctx_t* ctx) {
    typedef struct {
        int source;
        int symbol;
        int target;
    } incoming_edge_t;

    int total_edges = 0;
    for (int s = 0; s < state_count; s++) {
        if (dead_states[s]) continue;

        nfa_state_t* state = &nfa[s];

        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int target = state->transitions[sym];
            if (target >= 0 && !dead_states[target]) {
                total_edges++;
            }
        }

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
        return 0;
    }

    incoming_edge_t* edges = malloc((size_t)total_edges * sizeof(incoming_edge_t));
    if (!edges) return 0;

    int edge_count = 0;
    for (int s = 0; s < state_count; s++) {
        if (dead_states[s]) continue;

        nfa_state_t* state = &nfa[s];

        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int target = state->transitions[sym];
            if (target >= 0 && !dead_states[target]) {
                edges[edge_count].source = s;
                edges[edge_count].symbol = sym;
                edges[edge_count].target = target;
                edge_count++;
            }
        }

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

    if (edge_count == 0) {
        free(edges);
        return 0;
    }

    memset(ctx->incoming_count, 0, (size_t)state_count * sizeof(int));
    for (int e = 0; e < edge_count; e++) {
        ctx->incoming_count[edges[e].target]++;
    }

    for (int s = 0; s < state_count; s++) {
        ctx->single_source[s] = -1;
        ctx->single_symbol[s] = -1;
    }

    for (int e = 0; e < edge_count; e++) {
        int target = edges[e].target;
        if (ctx->incoming_count[target] == 1) {
            ctx->single_source[target] = edges[e].source;
            ctx->single_symbol[target] = edges[e].symbol;
        }
    }

    int candidate_count = 0;

    for (int s = 0; s < state_count; s++) {
        if (dead_states[s]) continue;
        if (ctx->incoming_count[s] != 1) continue;
        if (ctx->single_source[s] < 0) continue;
        if (s == 0) continue;

        int src = ctx->single_source[s];
        if (src < 0 || src >= state_count || dead_states[src]) continue;

        ctx->candidates[candidate_count].state = s;
        ctx->candidates[candidate_count].source = ctx->single_source[s];
        ctx->candidates[candidate_count].symbol = ctx->single_symbol[s];
        ctx->candidates[candidate_count].sig = compute_full_signature(nfa, s);
        candidate_count++;
    }

    free(edges);

    VERBOSE_PRINT(premin, "  Found %d prefix merge candidates\n", candidate_count);

    if (candidate_count == 0) {
        return 0;
    }

    qsort(ctx->candidates, (size_t)candidate_count, sizeof(prefix_candidate_t), compare_prefix_candidates);

    int merged = 0;
    int i = 0;
    while (i < candidate_count) {
        int j = i + 1;
        while (j < candidate_count &&
               ctx->candidates[j].source == ctx->candidates[i].source &&
               ctx->candidates[j].symbol == ctx->candidates[i].symbol &&
               ctx->candidates[j].sig == ctx->candidates[i].sig) {
            j++;
        }

        if (j - i > 1) {
            int rep = ctx->candidates[i].state;

            if (dead_states[rep]) {
                i = j;
                continue;
            }

            for (int k = i + 1; k < j; k++) {
                int s = ctx->candidates[k].state;
                if (dead_states[s]) continue;
                if (s == rep) continue;
                if (dead_states[rep]) break;
                if (s >= state_count || rep >= state_count) continue;

                if (ctx->candidates[k].sig == TRUNCATED || ctx->candidates[i].sig == TRUNCATED) {
                    continue;
                }

                bool has_mutual = false;
                for (int sym = 0; sym < MAX_SYMBOLS && !has_mutual; sym++) {
                    if (nfa_has_transition_to(&nfa[rep], sym, s)) has_mutual = true;
                    if (nfa_has_transition_to(&nfa[s], sym, rep)) has_mutual = true;
                }
                if (has_mutual) continue;

                nfa_state_t* rep_state = &nfa[rep];
                nfa_state_t* s_state = &nfa[s];

                rep_state->category_mask |= s_state->category_mask;

                if (s_state->pending_marker_count > 0) {
                    for (int m = 0; m < s_state->pending_marker_count && rep_state->pending_marker_count < MAX_PENDING_MARKERS; m++) {
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

                for (int src = 0; src < state_count; src++) {
                    if (dead_states[src]) continue;

                    nfa_state_t* src_state = &nfa[src];

                    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                        if (src_state->transitions[sym] == s) {
                            src_state->transitions[sym] = rep;
                        }
                    }

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
                sig_cache_invalidate(s);
                sig_cache_invalidate(rep);
                merged++;
                VERBOSE_PRINT(premin, "  Merged prefix state %d into %d (source=%d, symbol=%d)\n",
                             s, rep, ctx->candidates[i].source, ctx->candidates[i].symbol);
            }
        }

        i = j;
    }

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
 * Hash markers for a specific symbol.
 * Markers are sorted by (pattern_id, uid, type) for deterministic hashing.
 * Uses insertion sort - efficient for small arrays (max 16 markers).
 */
static uint64_t hash_markers(const transition_marker_t* markers, int count) {
    uint64_t hash = 14695981039346656037ULL;

    if (count <= 0) return hash;

    transition_marker_t* sorted = malloc((size_t)count * sizeof(transition_marker_t));
    if (!sorted) return hash;

    memcpy(sorted, markers, (size_t)count * sizeof(transition_marker_t));

    for (int i = 1; i < count; i++) {
        transition_marker_t tmp = sorted[i];
        int j = i - 1;
        while (j >= 0 && (sorted[j].pattern_id > tmp.pattern_id ||
                          (sorted[j].pattern_id == tmp.pattern_id && sorted[j].uid > tmp.uid) ||
                          (sorted[j].pattern_id == tmp.pattern_id && sorted[j].uid == tmp.uid && sorted[j].type > tmp.type))) {
            sorted[j + 1] = sorted[j];
            j--;
        }
        sorted[j + 1] = tmp;
    }

    for (int i = 0; i < count; i++) {
        hash ^= (uint64_t)sorted[i].pattern_id;
        hash *= 1099511628211ULL;
        hash ^= (uint64_t)sorted[i].uid;
        hash *= 1099511628211ULL;
        hash ^= (uint64_t)sorted[i].type;
        hash *= 1099511628211ULL;
    }

    free(sorted);
    return hash;
}

/**
 * Compute hash of outgoing transitions for a state.
 * Does NOT include markers - markers are handled separately in compute_full_signature.
 */
static uint64_t compute_outgoing_signature(const nfa_state_t* state) {
    uint64_t hash = 14695981039346656037ULL;

    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
        if (state->transitions[sym] >= 0) {
            hash ^= (uint64_t)sym;
            hash *= 1099511628211ULL;
            hash ^= (uint64_t)state->transitions[sym];
            hash *= 1099511628211ULL;
        }
    }

    int mta_count = mta_get_entry_count((multi_target_array_t*)&state->multi_targets);
    if (mta_count > 0) {
        hash ^= (uint64_t)mta_count;
        hash *= 1099511628211ULL;

        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int count;
            int* targets = mta_get_target_array((multi_target_array_t*)&state->multi_targets, sym, &count);
            if (targets && count > 0) {
                hash ^= (uint64_t)sym;
                hash *= 1099511628211ULL;
                hash ^= (uint64_t)count;
                hash *= 1099511628211ULL;

                int* sorted = malloc((size_t)count * sizeof(int));
                if (!sorted) continue;
                memcpy(sorted, targets, (size_t)count * sizeof(int));
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
 * Compute full signature combining prefix properties + outgoing transitions + markers.
 * This is used for language-preserving prefix merging. Two states with the
 * same full signature have:
 * 1. Same prefix properties (category, pattern_id, eos_target, pending_markers)
 * 2. Same outgoing transitions (where they can go next)
 * 3. Same markers on transitions
 *
 * Since full signatures match, the states are truly equivalent - merging them
 * cannot change the language because they have identical behavior both before
 * and after the current state.
 */
static uint64_t compute_full_signature(const nfa_state_t* nfa, int state_idx) {
    if (sig_cache && state_idx < sig_cache_capacity && sig_cache[state_idx].full_valid) {
        return sig_cache[state_idx].full_sig;
    }

    uint64_t prefix_sig = nfa_compute_state_signature(nfa, state_idx);
    uint64_t outgoing_sig = compute_epsilon_aware_outgoing_signature(nfa, state_idx);

    if (outgoing_sig == TRUNCATED) {
        return TRUNCATED;
    }

    uint64_t hash = prefix_sig;
    hash ^= outgoing_sig;
    hash *= 1099511628211ULL;

    const nfa_state_t* state = &nfa[state_idx];
    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
        int marker_count;
        transition_marker_t* markers = mta_get_markers((multi_target_array_t*)&state->multi_targets, sym, &marker_count);
        if (markers && marker_count > 0) {
            hash ^= hash_markers(markers, marker_count);
            hash *= 1099511628211ULL;
        }
    }

    if (sig_cache && state_idx < sig_cache_capacity) {
        sig_cache[state_idx].full_sig = hash;
        sig_cache[state_idx].full_valid = true;
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

    VERBOSE_PRINT(premin, "  Found %d accepting states for deduplication\n", accept_count);

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
                VERBOSE_PRINT(premin, "  Merged final state %d into %d\n", s, rep);
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

        // Check single transitions (legacy format)
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

    VERBOSE_PRINT(premin, "  Found %d suffix merge candidates\n", candidate_count);

    if (candidate_count < 2) {
        VERBOSE_PRINT(premin, "  Not enough suffix candidates (found %d)\n", candidate_count);
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

        // Check single transitions (legacy format)
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

    VERBOSE_PRINT(premin, "  Found %d suffix merge candidates\n", candidate_count);

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
            VERBOSE_PRINT(premin, "  Found group of %d states with same (target=%d, sym=%d, accept_sig=%016lx)\n",
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
                    if (nfa_has_transition_to(&nfa[rep], sym, s)) has_mutual = true;
                    if (nfa_has_transition_to(&nfa[s], sym, rep)) has_mutual = true;
                }
                if (has_mutual) {
                    VERBOSE_PRINT(premin, "  Skipping merge due to mutual transition between %d and %d\n", rep, s);
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
                VERBOSE_PRINT(premin, "  Merged suffix state %d into %d (target=%d, symbol=%d)\n",
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
        VERBOSE_PRINT(premin, "  Suffix merge pass %d...\n", pass);
        int merged = merge_common_suffixes_pass(nfa, state_count, dead_states);
        total_merged += merged;

        if (merged == 0) {
            VERBOSE_PRINT(premin, "  No more suffix merges possible after pass %d\n", pass);
            break;
        }

        VERBOSE_PRINT(premin, "  Pass %d merged %d suffix states (total: %d)\n", pass, merged, total_merged);
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
    prefix_merge_ctx_t* ctx = prefix_merge_ctx_create(state_count);
    if (!ctx) {
        return 0;
    }

    int total_merged = 0;
    int pass = 1;
    const int max_passes = 10;

    while (pass <= max_passes) {
        VERBOSE_PRINT(premin, "  Prefix merge pass %d...\n", pass);
        int merged = merge_common_prefixes_pass(nfa, state_count, dead_states, ctx);
        total_merged += merged;

        if (merged == 0) {
            VERBOSE_PRINT(premin, "  No more merges possible after pass %d\n", pass);
            break;
        }

        VERBOSE_PRINT(premin, "  Pass %d merged %d states (total: %d)\n", pass, merged, total_merged);
        pass++;
    }

    prefix_merge_ctx_free(ctx);
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
        VERBOSE_PRINT(premin, "  Failed to allocate transitions array\n");
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
                                VERBOSE_PRINT(premin, "  Failed to grow transitions array\n");
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
            VERBOSE_PRINT(premin, "  Found %d sources with common suffix (target=%d, symbol=%d)\n",
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
                    VERBOSE_PRINT(premin, "  Cannot create new state: would exceed MAX_STATES\n");
                    if (sources != sources_buf) free(sources);
                    continue;
                }
                bool* new_dead_states = realloc(dead_states, new_capacity * sizeof(bool));
                if (!new_dead_states) {
                    VERBOSE_PRINT(premin, "  Failed to grow dead_states array\n");
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
                VERBOSE_PRINT(premin, "  Grew dead_states array to %d capacity\n", dead_states_capacity);
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
            VERBOSE_PRINT(premin, "    Created new state %d, merged %d paths\n", new_state, source_count - 1);
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
        VERBOSE_PRINT(premin, "  Suffix factorization pass %d...\n", pass);
        int merged = factorize_suffixes_pass(nfa, state_count, dead_states_ptr, dead_states_capacity_ptr, next_state_ptr);
        total_merged += merged;

        if (merged == 0) {
            VERBOSE_PRINT(premin, "  No more suffix factorization possible after pass %d\n", pass);
            break;
        }

        VERBOSE_PRINT(premin, "  Pass %d factorized %d paths (total: %d)\n", pass, merged, total_merged);
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
    last_stats = (nfa_premin_stats_t){
        .original_states = original_count,
        .minimized_states = 0,
        .epsilon_bypassed = 0,
        .epsilon_chains = 0,
        .landing_pads_removed = 0,
        .unreachable_removed = 0,
        .states_merged = 0,
        .identical_merged = 0,
        .prefix_merged = 0,
        .final_deduped = 0,
        .suffix_merged = 0,
        .sat_merged = 0,
        .sat_optimal = 0
    };

    if (original_count <= 1) return 0;

    // Early exit if no optimizations enabled - avoid allocating dead_states
    if (!opts.enable_prune && !opts.enable_epsilon_elim &&
        !opts.enable_final_dedup && !opts.enable_bidirectional && !opts.enable_sat_optimal) {
        VERBOSE_PRINT(premin, "Pre-minimization: No optimizations enabled, skipping\n");
        return 0;
    }

    VERBOSE_PRINT(premin, "Pre-minimizing NFA with %d states\n", original_count);

    // Initialize signature cache for the lifetime of this preminimization run
    sig_cache_init(original_count);

    // Allocate dead state tracking
    // dead_states is dynamic - it can grow when suffix factorization creates new states
    int dead_states_capacity = original_count;
    bool* dead_states = calloc(dead_states_capacity, sizeof(bool));

    // Pass 1: Remove unreachable states first (O(n))
    if (opts.enable_prune) {
        VERBOSE_PRINT(premin, "Removing unreachable states...\n");
        last_stats.unreachable_removed = remove_unreachable(nfa, original_count, dead_states);
        VERBOSE_PRINT(premin, "Removed %d unreachable states\n", last_stats.unreachable_removed);
    }

    // Pass 2: Bypass epsilon pass-through states (O(n))
    if (opts.enable_epsilon_elim) {
        VERBOSE_PRINT(premin, "Bypassing epsilon pass-through states...\n");
        last_stats.epsilon_bypassed = bypass_epsilon_pass_through(nfa, original_count, dead_states);
        VERBOSE_PRINT(premin, "Bypassed %d epsilon pass-through states\n", last_stats.epsilon_bypassed);
    }

    // Pass 4: Deduplicate equivalent final states (O(n log n))
    // This MUST run before bidirectional merging to create longer common suffixes
    if (opts.enable_final_dedup) {
        VERBOSE_PRINT(premin, "Deduplicating final states...\n");
        last_stats.final_deduped = deduplicate_final_states(nfa, original_count, dead_states);
        VERBOSE_PRINT(premin, "Deduplicated %d final states\n", last_stats.final_deduped);
    }

    // Pass 5: Bidirectional incremental merging (O(n log n))
    // This combines prefix and suffix merging in an incremental fixpoint iteration.
    // We alternate between prefix and suffix passes until no more merges happen.
    // Then, if SAT optimal is enabled, we try harder merges on remaining candidates.

    // Track effective state count - this includes newly created intermediate states
    // from suffix factorization (which are created beyond original_count)
    int effective_count = original_count;

    if (opts.enable_bidirectional) {
        VERBOSE_PRINT(premin, "Running bidirectional incremental merging...\n");
        int total_bidir_merged = 0;
        int pass = 1;
        const int max_passes = 20;  // Safety limit

        // Track next available state slot for suffix factorization (persists across passes)
        int next_state = original_count;

        while (pass <= max_passes) {
            VERBOSE_PRINT(premin, "  Bidirectional pass %d...\n", pass);

            // Use next_state as the current state count - it includes any newly created states
            int current_count = next_state;

            // Try prefix merging
            int prefix_merged = merge_common_prefixes(nfa, current_count, dead_states);
            VERBOSE_PRINT(premin, "    Prefix merging: %d states\n", prefix_merged);

            // Try suffix merging
            int suffix_merged = merge_common_suffixes_fast(nfa, current_count, dead_states);
            VERBOSE_PRINT(premin, "    Suffix merging: %d states\n", suffix_merged);

            // Try suffix factorization (creates new intermediate states)
            int suffix_factored = factorize_suffixes(nfa, current_count, &dead_states, &dead_states_capacity, &next_state);
            VERBOSE_PRINT(premin, "    Suffix factorization: %d paths\n", suffix_factored);

            int pass_merged = prefix_merged + suffix_merged + suffix_factored;
            total_bidir_merged += pass_merged;

            // If no merges happened, we've reached fixpoint
            if (pass_merged == 0) {
                VERBOSE_PRINT(premin, "  Fixpoint reached after %d passes\n", pass);
                break;
            }

            VERBOSE_PRINT(premin, "  Pass %d merged %d states (total: %d)\n", pass, pass_merged, total_bidir_merged);
            pass++;
        }

        if (pass > max_passes) {
            VERBOSE_PRINT(premin, "  Warning: Reached max passes limit (%d)\n", max_passes);
        }

        last_stats.prefix_merged = total_bidir_merged;
        VERBOSE_PRINT(premin, "Bidirectional merging eliminated %d states\n", total_bidir_merged);

        // Update effective_count to include any new intermediate states created
        effective_count = next_state;
        VERBOSE_PRINT(premin, "Effective state count after factorization: %d\n", effective_count);

        // Pass 5b: SAT-based optimal merge selection (continuation of bidirectional)
        // After greedy fixpoint, try harder merges on remaining conflicting candidates.
        // This reuses the same NFA state and continues where bidirectional left off.
        if (opts.enable_sat_optimal && nfa_preminimize_optimal_available()) {
            VERBOSE_PRINT(premin, "Continuing with SAT optimal merge selection...\n");
            int max_cand = opts.max_sat_candidates > 0 ? opts.max_sat_candidates : 200;
            last_stats.sat_optimal = nfa_preminimize_optimal_merges(nfa, effective_count, dead_states,
                                                                      max_cand, opts.verbose);
            if (last_stats.sat_optimal > 0) {
                VERBOSE_PRINT(premin, "SAT optimal merged %d additional states\n", last_stats.sat_optimal);
            }
        }
    }

    // Pass 6: Final unreachable cleanup
    if (opts.enable_prune) {
        VERBOSE_PRINT(premin, "Final unreachable cleanup...\n");
        int final_unreachable = remove_unreachable(nfa, effective_count, dead_states);
        last_stats.unreachable_removed += final_unreachable;
        VERBOSE_PRINT(premin, "Removed %d more unreachable states\n", final_unreachable);
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

    // Free signature cache
    sig_cache_free();

    int total_removed = original_count - new_count;
    if (total_removed > 0) {
        VERBOSE_PRINT(premin, "Pre-minimized NFA: %d → %d states (%.1f%% reduction)\n",
                      original_count, new_count,
                      100.0 * total_removed / original_count);
    } else {
        VERBOSE_PRINT(premin, "Pre-minimization: No states removed (NFA already optimal)\n");
    }

    return total_removed;
}
