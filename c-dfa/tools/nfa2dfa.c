#define DFA_ERROR_PROGRAM "nfa2dfa"
#include "../include/dfa_errors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include "../include/dfa_types.h"
#include "../include/dfa_format.h"
#include "../include/multi_target_array.h"
#include "../include/nfa.h"
#include "dfa_minimize.h"
#include "dfa_compress.h"
#include "dfa_layout.h"
#include "nfa_preminimize.h"
#include "nfa2dfa_context.h"

#if MAX_SYMBOLS != 320
#error "MAX_SYMBOLS must be 320"
#endif

// Forward declaration
int find_symbol_id(char c);
void nfa_init(void);

static char pattern_identifier[256] = "";
static bool flag_verbose = false;

#define DEBUG_PRINT(...) do { if (flag_verbose) fprintf(stderr, __VA_ARGS__); } while (0)

// Virtual symbol definitions (must match nfa_builder.c)
#define VSYM_EPS 257
#define VSYM_EOS 258

// Marker type definitions
#define MARKER_TYPE_START 0
#define MARKER_TYPE_END 1

/**
 * Check allocation result and abort on failure
 */
static void* alloc_or_abort(void* ptr, const char* msg) {
    if (ptr == NULL) {
        FATAL("%s", msg);
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Global NFA/DFA storage - use larger static arrays for practical workloads
// For truly astronomical state counts (>32K), a more sophisticated solution would be needed
static nfa_state_t nfa[MAX_STATES];
static build_dfa_state_t* dfa[MAX_STATES];  // Array of pointers (Phase 6: dynamic states)
static alphabet_entry_t alphabet[MAX_SYMBOLS];
static int nfa_state_count = 0;
static int dfa_state_count = 0;
static int alphabet_size = 0;
static int max_states = MAX_STATES;

// ============================================================================
// NFA-TO-DFA CONVERTER STATE DOCUMENTATION
// 
// The following global variables hold the NFA-to-DFA conversion state.
// For a production-quality refactor, these should be encapsulated in a context.
// Current design: CLI tool that runs once and exits - globals are acceptable.
// ============================================================================

// DFA Deduplication Hash Table
#define DFA_HASH_SIZE 32749
static int dfa_hash_table[DFA_HASH_SIZE];
static int dfa_next_in_bucket[MAX_STATES];

void init_hash_table(nfa2dfa_context_t* ctx) {
    (void)ctx; // Context not used with static arrays
    memset(dfa_hash_table, -1, sizeof(dfa_hash_table));
    memset(dfa_next_in_bucket, -1, sizeof(dfa_next_in_bucket));
}

// Phase 3: Marker harvesting system
#define MAX_MARKERS_PER_DFA_TRANSITION 16
#define MAX_DFA_MARKER_LISTS 8192
#define MARKER_SENTINEL 0xFFFFFFFF

// MarkerList is now defined in dfa_minimize.h (shared with SAT minimizer)

static MarkerList* dfa_marker_lists = NULL;
static int marker_list_count = 0;

static void init_marker_lists(void) {
    dfa_marker_lists = alloc_or_abort(malloc(sizeof(MarkerList) * MAX_DFA_MARKER_LISTS), "Failed to allocate marker lists");
    memset(dfa_marker_lists, 0, sizeof(MarkerList) * MAX_DFA_MARKER_LISTS);
}

// Note: No free_marker_lists() needed - CLI tool exits after processing

// Get unique marker list (store if new)
static uint32_t store_marker_list(const uint32_t* markers, int count) {
    if (count == 0) return 0;
    
    // Check if list already exists
    for (int i = 0; i < marker_list_count; i++) {
        if (dfa_marker_lists[i].count == count) {
            bool match = true;
            for (int j = 0; j < count; j++) {
                if (dfa_marker_lists[i].markers[j] != markers[j]) { match = false; break; }
            }
            if (match) return (uint32_t)(i + 1);  // +1 to distinguish from 0 (no markers)
        }
    }
    
    // Store new list
    if (marker_list_count < MAX_DFA_MARKER_LISTS) {
        for (int j = 0; j < count && j < MAX_MARKERS_PER_DFA_TRANSITION; j++) {
            dfa_marker_lists[marker_list_count].markers[j] = markers[j];
        }
        dfa_marker_lists[marker_list_count].count = count;
        return (uint32_t)(marker_list_count++ + 1);
    }
    return 0;
}

// Collect markers from NFA states in an epsilon closure
static void collect_markers_from_states(const int* states, int state_count,
                                        uint32_t* out_markers, int* out_count) {
    int count = *out_count;  // Start with existing marker count
    for (int i = 0; i < state_count && count < MAX_MARKERS_PER_DFA_TRANSITION; i++) {
        int ns = states[i];
        if (ns < 0 || ns >= nfa_state_count) continue;

        // Collect markers from pending_markers array (Phase 2: edge payloads)
        for (int m = 0; m < nfa[ns].pending_marker_count && count < MAX_MARKERS_PER_DFA_TRANSITION; m++) {
            if (nfa[ns].pending_markers[m].active) {
                uint32_t marker = ((uint32_t)nfa[ns].pending_markers[m].pattern_id << 17) |
                                  ((uint32_t)nfa[ns].pending_markers[m].uid << 1) |
                                  (uint32_t)nfa[ns].pending_markers[m].type;
                bool exists = false;
                for (int j = 0; j < count; j++) {
                    if (out_markers[j] == marker) { exists = true; break; }
                }
                if (!exists) out_markers[count++] = marker;
            }
        }
    }
    *out_count = count;
}


// Insertion sort for small-to-medium integer arrays.
// Faster than qsort for typical NFA state set sizes (10-1000 elements)
// due to no function call overhead and better cache behavior.
static void sort_states_canonical(int* states, int count) {
    for (int i = 1; i < count; i++) {
        int key = states[i];
        int j = i - 1;
        while (j >= 0 && states[j] > key) {
            states[j + 1] = states[j];
            j--;
        }
        states[j + 1] = key;
    }
}

// Hash a canonical (sorted) NFA state set
static uint32_t hash_nfa_set(const int* sorted_states, int count, uint8_t mask, uint16_t first_accepting_pattern) {
    uint32_t hash = 2166136261u;
    for (int i = 0; i < count; i++) {
        hash ^= (uint32_t)sorted_states[i];
        hash *= 16777619;
    }
    hash ^= (uint32_t)mask << 24;
    hash ^= (uint32_t)first_accepting_pattern;
    return hash;
}

static int find_dfa_state_hashed(uint32_t hash, const int* sorted_states, int count, uint8_t mask, uint16_t first_accepting_pattern) {
    int idx = dfa_hash_table[hash % DFA_HASH_SIZE];
    while (idx != -1) {
        if (dfa[idx]->nfa_state_count == count) {
            uint8_t existing_mask = (uint8_t)(dfa[idx]->flags >> 8);
            if (existing_mask == mask && dfa[idx]->first_accepting_pattern == first_accepting_pattern) {
                bool match = true;
                for (int j = 0; j < count; j++) {
                    if (dfa[idx]->nfa_states[j] != sorted_states[j]) { match = false; break; }
                }
                if (match) return idx;
            }
        }
        idx = dfa_next_in_bucket[idx];
    }
    return -1;
}

#ifndef NFABUILDER_EXCLUDE_NFA_INIT

void nfa_init(void) {
    for (int i = 0; i < MAX_STATES; i++) {
        nfa[i].category_mask = 0;
        nfa[i].pattern_id = 0;
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            nfa[i].transitions[j] = -1;
        }
        mta_init(&nfa[i].multi_targets);
        nfa[i].is_eos_target = false;
        nfa[i].pending_marker_count = 0;
        for (int j = 0; j < MAX_PENDING_MARKERS; j++) {
            nfa[i].pending_markers[j].active = false;
        }
    }
    nfa_state_count = 0;
    marker_list_count = 0;
}

#endif  // NFABUILDER_EXCLUDE_NFA_INIT

void dfa_init(nfa2dfa_context_t* ctx) {
    (void)ctx; // CLI version uses global state
    memset(dfa_hash_table, -1, sizeof(int) * DFA_HASH_SIZE);
    memset(dfa_next_in_bucket, -1, sizeof(int) * max_states);
    // Free any previously allocated states
    for (int i = 0; i < dfa_state_count; i++) {
        if (dfa[i]) {
            build_dfa_state_destroy(dfa[i]);
            dfa[i] = NULL;
        }
    }
    // Pre-allocate first batch of states
    for (int i = 0; i < max_states; i++) {
        dfa[i] = NULL;  // Will be allocated on demand in dfa_add_state
    }
    dfa_state_count = 0;
}

void epsilon_closure_with_markers(int* states, int* count, int max_states,
                                   uint32_t* markers, int* marker_count, int max_markers) {
    const int epsilon_symbol_id = 257;
    bool* in_set = alloc_or_abort(calloc(max_states, sizeof(bool)), "epsilon_closure in_set");
    int* stack = alloc_or_abort(malloc(max_states * sizeof(int)), "epsilon_closure stack");
    int top = 0;

    for (int i = 0; i < *count; i++) {
        int s = states[i];
        if (s >= 0 && s < nfa_state_count) { stack[top++] = s; in_set[s] = true; }
    }

    while (top > 0) {
        int s = stack[--top];

        // Process EPSILON transitions (257) - use multi_targets only
        int mta_cnt = 0;
        int* mta_targets = mta_get_target_array(&nfa[s].multi_targets, epsilon_symbol_id, &mta_cnt);
        if (mta_targets) {
            for (int i = 0; i < mta_cnt; i++) {
                int target = mta_targets[i];
                if (target >= 0 && target < nfa_state_count && !in_set[target]) {
                    if (*count < max_states) { states[(*count)++] = target; stack[top++] = target; in_set[target] = true; }
                }
            }
        }

        int mta_marker_count = 0;
        transition_marker_t* mta_markers = mta_get_markers(&nfa[s].multi_targets, epsilon_symbol_id, &mta_marker_count);
        if (mta_markers) {
            for (int m = 0; m < mta_marker_count && *marker_count < max_markers; m++) {
                uint32_t marker = ((uint32_t)mta_markers[m].pattern_id << 17) |
                                  ((uint32_t)mta_markers[m].uid << 1) |
                                  (uint32_t)mta_markers[m].type;
                bool exists = false;
                for (int j = 0; j < *marker_count; j++) {
                    if (markers[j] == marker) { exists = true; break; }
                }
                if (!exists) markers[(*marker_count)++] = marker;
            }
        }
    }
}

void epsilon_closure(int* states, int* count, int max_states) {
    int epsilon_sid = -1;
    int epsilon_symbol_id = 257;
    for (int s = 0; s < alphabet_size; s++) {
        if (alphabet[s].symbol_id == 257) { epsilon_sid = s; break; }
    }
    if (epsilon_sid < 0) {
        return;
    }

    bool* in_set = alloc_or_abort(calloc(max_states, sizeof(bool)), "epsilon_closure in_set");
    int* stack = alloc_or_abort(malloc(max_states * sizeof(int)), "epsilon_closure stack");
    int top = 0;
    
    for (int i = 0; i < *count; i++) {
        int s = states[i];
        if (s >= 0 && s < nfa_state_count) { stack[top++] = s; in_set[s] = true; }
    }

    while (top > 0) {
        int s = stack[--top];
        // Process EPSILON transitions (257) - use multi_targets only
        int mta_cnt = 0;
        int* mta_targets = mta_get_target_array(&nfa[s].multi_targets, epsilon_symbol_id, &mta_cnt);
        if (mta_targets) {
            for (int i = 0; i < mta_cnt; i++) {
                int target = mta_targets[i];
                if (target >= 0 && target < nfa_state_count && !in_set[target]) {
                    if (*count < max_states) { states[(*count)++] = target; stack[top++] = target; in_set[target] = true; }
                }
            }
        }
    }
    free(in_set);
    free(stack);
}

// Helper: Collect category mask from ALL accepting states reachable from given NFA states via epsilon
// This is used to fix quantifier category mixing bug where different patterns with shared prefixes
// have fork states that can only reach SOME accepting states, not all
// KEY: We search from ALL starting states TOGETHER to find all reachable accepting states
// CRITICAL FIX: For INITIAL state, collect ALL fork categories unconditionally because
// patterns like "cmd ((abc))*" have fork states that aren't reachable via epsilon from state 0
// (they're after the literal characters), but should still contribute to initial state for empty match
static uint8_t collect_fork_categories(int* states, int count, bool is_initial_state) {
    uint8_t fork_cats = 0;
    
    // Check if there are any fork states in the NFA (is_eos_target with category)
    // A fork state is a state that can match empty (is_eos_target) and has a category
    bool has_fork = false;
    for (int i = 0; i < nfa_state_count; i++) {
        if (nfa[i].is_eos_target && nfa[i].category_mask != 0) {
            has_fork = true;
            break;
        }
    }
    if (!has_fork) return 0;
    
    // For initial state, do epsilon closure from state 0 and collect fork categories
    // that are actually reachable via epsilon transitions
    // This ensures + quantifier (which has NO skip path) doesn't incorrectly match empty
    if (is_initial_state) {
        bool* visited = alloc_or_abort(calloc(nfa_state_count, sizeof(bool)), "collect_fork_categories visited");
        int* stack = alloc_or_abort(malloc(nfa_state_count * sizeof(int)), "collect_fork_categories stack");
        int stack_top = 0;
        
        // Start from state 0 (initial state)
        stack[stack_top++] = 0;
        visited[0] = true;
        
        int epsilon_symbol_id = 257;
        
        while (stack_top > 0) {
            int cur = stack[--stack_top];
            
            // If this is a fork state (is_eos_target with category), collect its category
            if (nfa[cur].is_eos_target && nfa[cur].category_mask != 0) {
                fork_cats |= nfa[cur].category_mask;
            }
            
            // Continue exploring via EPSILON transitions
            int mta_cnt = 0;
            int* mta_targets = mta_get_target_array(&nfa[cur].multi_targets, epsilon_symbol_id, &mta_cnt);
            if (mta_targets) {
                for (int i = 0; i < mta_cnt; i++) {
                    int target = mta_targets[i];
                    if (target >= 0 && target < nfa_state_count && !visited[target]) {
                        visited[target] = true;
                        stack[stack_top++] = target;
                    }
                }
            }
        }
        free(visited);
        free(stack);
        return fork_cats;
    }
    
    // For non-initial states, search from all states via epsilon closure
    bool* visited = alloc_or_abort(calloc(nfa_state_count, sizeof(bool)), "collect_fork_categories visited");
    int* stack = alloc_or_abort(malloc(nfa_state_count * sizeof(int)), "collect_fork_categories stack");
    int stack_top = 0;
    
    // For non-initial states, search from all states
    for (int s = 0; s < count; s++) {
        int start = states[s];
        if (start >= 0 && start < nfa_state_count && !visited[start]) {
            stack[stack_top++] = start;
            visited[start] = true;
        }
    }
    
    int epsilon_symbol_id = 257;
    
    while (stack_top > 0) {
        int cur = stack[--stack_top];
        
        // If this is a fork state (is_eos_target with category), collect its category
        if (nfa[cur].is_eos_target && nfa[cur].category_mask != 0) {
            fork_cats |= nfa[cur].category_mask;
        }
        
        // Continue exploring via EPSILON transitions
        int mta_cnt = 0;
        int* mta_targets = mta_get_target_array(&nfa[cur].multi_targets, epsilon_symbol_id, &mta_cnt);
        if (mta_targets) {
            for (int i = 0; i < mta_cnt; i++) {
                int target = mta_targets[i];
                if (target >= 0 && target < nfa_state_count && !visited[target]) {
                    visited[target] = true;
                    stack[stack_top++] = target;
                }
            }
        }
    }
    
    free(visited);
    free(stack);
    return fork_cats;
}

int dfa_add_state(uint8_t category_mask, int* nfa_states, int nfa_count, uint16_t accepting_pattern_id, uint16_t first_accepting_pattern) {
    // Sort once for hash, lookup, and storage
    int* sorted = alloc_or_abort(malloc(nfa_count * sizeof(int)), "dfa_add_state sorted");
    for (int i = 0; i < nfa_count; i++) {
        sorted[i] = nfa_states[i];
    }
    sort_states_canonical(sorted, nfa_count);

    uint32_t h = hash_nfa_set(sorted, nfa_count, category_mask, first_accepting_pattern);
    int bucket = h % DFA_HASH_SIZE;
    int existing = find_dfa_state_hashed(h, sorted, nfa_count, category_mask, first_accepting_pattern);
    if (existing != -1) {
        return existing;
    }
    if (dfa_state_count >= MAX_STATES) { 
        FATAL("Max DFA states reached (%d states)", MAX_STATES);
        ERROR("  Split patterns into multiple files or simplify complex patterns");
        exit(EXIT_FAILURE); 
    }
    int state = dfa_state_count++;
    // Allocate the state dynamically
    dfa[state] = build_dfa_state_create(MAX_SYMBOLS, nfa_count > 64 ? nfa_count * 2 : 128);
    if (!dfa[state]) {
        FATAL("Failed to allocate DFA state %d", state);
        exit(EXIT_FAILURE);
    }
    dfa[state]->flags = (category_mask << 8);
    if (accepting_pattern_id != 0 || first_accepting_pattern != 0) {
        dfa[state]->flags |= DFA_STATE_ACCEPTING;
    }
    dfa[state]->accepting_pattern_id = accepting_pattern_id;
    dfa[state]->first_accepting_pattern = first_accepting_pattern;
    
    // Store pre-sorted states
    dfa[state]->nfa_state_count = nfa_count;
    if (nfa_count > dfa[state]->nfa_state_capacity) {
        if (!build_dfa_state_grow_nfa(dfa[state], nfa_count - dfa[state]->nfa_state_capacity)) {
            FATAL("Failed to grow NFA state array for DFA state %d", state);
            exit(EXIT_FAILURE);
        }
    }
    for (int i = 0; i < nfa_count; i++) dfa[state]->nfa_states[i] = sorted[i];
    dfa_next_in_bucket[state] = dfa_hash_table[bucket];
    dfa_hash_table[bucket] = state;
    free(sorted);
    return state;
}

void nfa_move(int* states, int* count, int sid, int max_states) {
    int* ns = alloc_or_abort(malloc(max_states * sizeof(int)), "nfa_move ns");
    int nc = 0; 
    bool* is = alloc_or_abort(calloc(max_states, sizeof(bool)), "nfa_move is");
    for (int i = 0; i < *count; i++) {
        int s = states[i]; if (s < 0 || s >= nfa_state_count) continue;

        // Use multi_targets only - transitions[] array is not populated
        int mta_cnt = 0;
        int* targets = mta_get_target_array(&nfa[s].multi_targets, sid, &mta_cnt);
        if (targets) {
            for (int k = 0; k < mta_cnt; k++) {
                int t = targets[k]; if (t >= 0 && t < nfa_state_count && !is[t]) { if (nc < max_states) { ns[nc++] = t; is[t] = true; } }
            }
        }
    }
    for (int i = 0; i < nc; i++) states[i] = ns[i];
    *count = nc;
    free(ns);
    free(is);
}

static void collect_transition_markers(int source_count, int* source_states, int sid,
                                       uint32_t* out_markers, int* out_count, int max_markers) {
    int count = *out_count;
    for (int i = 0; i < source_count && count < max_markers; i++) {
        int s = source_states[i];
        if (s < 0 || s >= nfa_state_count) continue;

        int mta_marker_count = 0;
        transition_marker_t* mta_markers = mta_get_markers(&nfa[s].multi_targets, sid, &mta_marker_count);
        if (mta_markers && mta_marker_count > 0) {
            for (int m = 0; m < mta_marker_count && count < max_markers; m++) {
                uint32_t marker = ((uint32_t)mta_markers[m].pattern_id << 17) |
                                  ((uint32_t)mta_markers[m].uid << 1) |
                                  (uint32_t)mta_markers[m].type;
                bool exists = false;
                for (int j = 0; j < count; j++) {
                    if (out_markers[j] == marker) { exists = true; break; }
                }
                if (!exists) {
                    out_markers[count++] = marker;
                }
            }
        }

        // Collect VSYM_EOS (258) markers ONLY when processing symbol 258
        if (sid == 258) {
            int eos_marker_count = 0;
            int eos_sid = -1;
            for (int as = 0; as < alphabet_size; as++) {
                if (alphabet[as].symbol_id == 258) { eos_sid = as; break; }
            }
            if (eos_sid >= 0) {
                transition_marker_t* eos_markers = mta_get_markers(&nfa[s].multi_targets, eos_sid, &eos_marker_count);
                if (eos_markers && eos_marker_count > 0) {
                    for (int m = 0; m < eos_marker_count && count < max_markers; m++) {
                        uint32_t marker = ((uint32_t)eos_markers[m].pattern_id << 17) |
                                          ((uint32_t)eos_markers[m].uid << 1) |
                                          (uint32_t)eos_markers[m].type;
                        bool exists = false;
                        for (int j = 0; j < count; j++) {
                            if (out_markers[j] == marker) { exists = true; break; }
                        }
                        if (!exists) {
                            out_markers[count++] = marker;
                        }
                    }
                }
            }
        }
    }
    *out_count = count;
}

void nfa_to_dfa(nfa2dfa_context_t* ctx) {
    (void)ctx; // CLI version uses global state
    DEBUG_PRINT("nfa_to_dfa: nfa_state_count=%d, alphabet_size=%d\n", nfa_state_count, alphabet_size);
    dfa_init(NULL);
    init_marker_lists();
    DEBUG_PRINT("after dfa_init\n");

    int* in = alloc_or_abort(calloc(max_states, sizeof(int)), "nfa_to_dfa in");
    int ic = 1;
    DEBUG_PRINT("before epsilon_closure\n");
    int* temp = alloc_or_abort(malloc(max_states * sizeof(int)), "nfa_to_dfa temp");
    memcpy(temp, in, sizeof(int)); 
    int tc = ic;
    uint32_t dummy_markers[MAX_MARKERS_PER_DFA_TRANSITION];
    int dummy_count = 0;
    epsilon_closure_with_markers(temp, &tc, max_states, dummy_markers, &dummy_count, MAX_MARKERS_PER_DFA_TRANSITION);
    DEBUG_PRINT("after epsilon_closure, tc=%d\n", tc);
    DEBUG_PRINT("temp states: ");
    for (int i = 0; i < tc; i++) DEBUG_PRINT("%d ", temp[i]);
    DEBUG_PRINT("\n");
    
    // Compute category mask and find accepting pattern ID
    // Category ONLY from TRUE accepting states (pattern_id != 0 OR is_eos_target)
    // is_eos_target states are reachable via epsilon from intermediate states and have category
    // This prevents category leakage from intermediate states
    // CRITICAL: Never accept from state 0 - it's the bootstrap state that should never be accepting
    // CRITICAL FIX: For the INITIAL DFA state, don't accept based on is_eos_target states
    // is_eos_target states are reached via epsilon without consuming characters, which is
    // correct for patterns like (a)* that allow zero iterations, but should NOT make the
    // initial DFA state accepting for patterns like (a)+ that require at least one character.
    uint8_t im = 0;
    uint16_t accept_pattern = 0;
    uint64_t reachable_accepting_patterns = 0;
    bool is_initial_state = (ic == 1 && in[0] == 0);  // Only state 0 in initial input (before epsilon closure)
    
    for (int i = 0; i < tc; i++) {
        int ns = temp[i];
        // Skip state 0 - it's the bootstrap and should never contribute to acceptance
        if (ns == 0) continue;
        
        // CRITICAL: For initial DFA state, don't use is_eos_target for acceptance
        // This prevents patterns like (a)+ from incorrectly accepting empty when
        // combined with patterns like (x)* in the same NFA
        // BUT include is_eos_target states that have pattern_id set (like (E)? which should match empty)
        
        // CRITICAL: For initial DFA state, don't use is_eos_target for acceptance
        // This prevents patterns like (a)+ from incorrectly accepting empty when
        // combined with patterns like (x)* in the same NFA
        
        // Category from states that are either accepting (pattern_id) or EOS targets
        // BUT for initial state, exclude EOS-only states
        if ((nfa[ns].pattern_id != 0 || (nfa[ns].is_eos_target && !is_initial_state)) && nfa[ns].category_mask != 0) {
            // fprintf(stderr, "DEBUG: adding cat 0x%02x from state %d\n", nfa[ns].category_mask, ns);
            im |= nfa[ns].category_mask;
        }
        // Accept pattern from states with pattern_id (true accepting states)
        if (nfa[ns].pattern_id != 0 && accept_pattern == 0) {
            accept_pattern = nfa[ns].pattern_id - 1;  // Convert back to 0-based
        }
        // Also check EOS target states for non-initial states
        if (!is_initial_state && nfa[ns].is_eos_target && accept_pattern == 0) {
            // Check if this EOS target state has transitions to accepting states
            // Look for EOS transitions (symbol 258) from this state
            int eos_cnt = 0;
            int* eos_targets = mta_get_target_array(&nfa[ns].multi_targets, 258, &eos_cnt);
            if (eos_targets) {
                for (int e = 0; e < eos_cnt; e++) {
                    int eos_t = eos_targets[e];
                    if (nfa[eos_t].pattern_id != 0) {
                        accept_pattern = nfa[eos_t].pattern_id - 1;  // Convert back to 0-based
                        break;
                    }
                }
            }
        }
        
    // Also collect category from EOS target states (fork states can reach accepting states via EOS)
    // This ensures we get categories from patterns that require multiple iterations
    // CRITICAL: For initial DFA state, don't collect from is_eos_target states
    if (!is_initial_state && nfa[ns].is_eos_target && nfa[ns].category_mask == 0) {
            int eos_cnt = 0;
            int* eos_targets = mta_get_target_array(&nfa[ns].multi_targets, 258, &eos_cnt);
            if (eos_targets) {
                for (int e = 0; e < eos_cnt; e++) {
                    int eos_t = eos_targets[e];
                    if (nfa[eos_t].category_mask != 0) {
                        im |= nfa[eos_t].category_mask;
                        break;
                    }
                }
            }
        }
        
        // Track all reachable accepting patterns for state deduplication
        if (nfa[ns].pattern_id != 0) {
            if (nfa[ns].pattern_id <= 64) {
                reachable_accepting_patterns |= (1ULL << (nfa[ns].pattern_id - 1));
            }
        }
    }
    DEBUG_PRINT("before collect_fork_categories, im=0x%02x\n", im);
    // QUANTIFIER FIX: Do NOT collect fork categories for initial state
    // The initial state should NOT get categories from is_eos_target states
    // because patterns with + quantifier should NOT match empty strings
    // This was incorrectly re-adding categories that were excluded at line 597
    uint8_t fork_cats = collect_fork_categories(temp, tc, false);
    DEBUG_PRINT("after collect_fork_categories, fork_cats=0x%02x\n", fork_cats);
    im |= fork_cats;
    DEBUG_PRINT("before dfa_add_state\n");
    int idfa = dfa_add_state(im, temp, tc, accept_pattern, reachable_accepting_patterns);
    if (idfa < 0) {
        ERROR("Failed to add initial DFA state");
        return;
    }

    // Allow empty matching for all patterns - the core fix is in category propagation
    // (not including category from is_eos_target states), which prevents false category matches

    int* q = alloc_or_abort(malloc(max_states * sizeof(int)), "nfa_to_dfa queue");
    int h = 0, t = 1; q[0] = idfa;
    
    // Pre-allocate working arrays for the loop
    int* ms = alloc_or_abort(malloc(max_states * sizeof(int)), "nfa_to_dfa ms");
    int* temp2 = alloc_or_abort(malloc(max_states * sizeof(int)), "nfa_to_dfa temp2");

    while (h < t) {
        int cur = q[h++];
        for (int i = 0; i < alphabet_size; i++) {
            int symbol = alphabet[i].symbol_id;
            if (symbol == 257) continue;

            int mc = dfa[cur]->nfa_state_count;
            for (int j = 0; j < mc; j++) ms[j] = dfa[cur]->nfa_states[j];

            uint32_t markers[MAX_MARKERS_PER_DFA_TRANSITION];
            memset(markers, 0, sizeof(markers));
            int marker_count = 0;
            collect_transition_markers(mc, ms, symbol, markers, &marker_count, MAX_MARKERS_PER_DFA_TRANSITION);

            nfa_move(ms, &mc, symbol, max_states);

            if (mc == 0) {
                int eos_sid = -1;
                for (int as = 0; as < alphabet_size; as++) {
                    if (alphabet[as].symbol_id == 258) { eos_sid = as; break; }
                }
                if (eos_sid >= 0 && symbol == alphabet[eos_sid].symbol_id) {
                    store_marker_list(markers, marker_count);
                }
                continue;
            }
            int tc2 = mc; 
            memcpy(temp2, ms, mc * sizeof(int));
            epsilon_closure_with_markers(temp2, &tc2, max_states, markers, &marker_count, MAX_MARKERS_PER_DFA_TRANSITION);

            // Compute category mask and accepting pattern for target state
            // Category ONLY from TRUE accepting states (pattern_id != 0 OR is_eos_target)
            // is_eos_target states are reachable via epsilon from intermediate states and have category
            // This prevents category leakage from intermediate states
            // QUANTIFIER FIX: Also collect categories from all reachable fork states
            uint8_t mm = 0;
            uint16_t accept_pattern2 = 0;
            uint64_t reachable_accepting_patterns2 = 0;
            
            for (int j = 0; j < tc2; j++) {
                int ns = temp2[j];
                // Category from states that are either accepting (pattern_id) or EOS targets
                if ((nfa[ns].pattern_id != 0 || nfa[ns].is_eos_target) && nfa[ns].category_mask != 0) {
                    mm |= nfa[ns].category_mask;
                }
                
                // Also collect category from EOS target states (fork states can reach accepting states via EOS)
                // This ensures we get categories from patterns that require multiple iterations
                if (nfa[ns].is_eos_target && nfa[ns].category_mask == 0) {
                    int eos_cnt = 0;
                    int* eos_targets = mta_get_target_array(&nfa[ns].multi_targets, 258, &eos_cnt);
                    if (eos_targets) {
                        for (int e = 0; e < eos_cnt; e++) {
                            int eos_t = eos_targets[e];
                            if (nfa[eos_t].category_mask != 0) {
                                mm |= nfa[eos_t].category_mask;
                                break;
                            }
                        }
                    }
                }
                
                // Accept pattern from any state in the closure (epsilon-reached states included)
                if (nfa[ns].pattern_id != 0 && accept_pattern2 == 0) {
                    accept_pattern2 = nfa[ns].pattern_id - 1;  // Convert back to 0-based
                }
                // Track all reachable accepting patterns for state deduplication
                if (nfa[ns].pattern_id != 0) {
                    if (nfa[ns].pattern_id <= 64) {
                        reachable_accepting_patterns2 |= (1ULL << (nfa[ns].pattern_id - 1));
                    }
                }
            }
            
            // QUANTIFIER FIX: Only collect fork categories for INITIAL state
            // For non-initial states, don't collect fork categories as they can cause
            // incorrect matching where patterns like a* and b* match any character
            uint8_t fork_cats = 0;
            if (is_initial_state) {
                fork_cats = collect_fork_categories(temp2, tc2, false);
            }
            mm |= fork_cats;
            // DO NOT inherit from source - that breaks prefix sharing

            collect_markers_from_states(temp2, tc2, markers, &marker_count);
            uint32_t marker_list_offset = store_marker_list(markers, marker_count);

            int target = dfa_add_state(mm, temp2, tc2, accept_pattern2, (uint16_t)reachable_accepting_patterns2);

            // Handle both literal symbols (sid < 256) and virtual symbols (VSYM_ANY=256, VSYM_SPACE=259, VSYM_TAB=260)
            int sid = alphabet[i].symbol_id;
            if (sid < 256 || sid == 256 || sid == 259 || sid == 260) {
                dfa[cur]->transitions[sid] = target;
                dfa[cur]->marker_offsets[sid] = marker_list_offset;
            }

            bool is_new = true; for (int j = 0; j < t; j++) if (q[j] == target) { is_new = false; break; }
            if (is_new && t < MAX_STATES) q[t++] = target;
        }
    }

    // Post-process ALL states to set EOS targets correctly
    // For each DFA state:
    // - If this DFA state contains an accept NFA state (pattern_id != 0):
    //   - Find the DFA state that represents that accept NFA state
    //   - Set eos_target to that DFA state
    // - If not accepting but contains an EOS target NFA state:
    //   - Find the accept DFA state with matching category
    // 
    // NOTE: We allow empty matching for patterns that support it (*, ?, |).
    // The issue was category leakage from is_eos_target states, which we fixed earlier.
    for (int cur = 0; cur < dfa_state_count; cur++) {

        // Find accept NFA state (pattern_id != 0) in this DFA state's set
        int accept_nfa_state = -1;
        for (int j = 0; j < dfa[cur]->nfa_state_count; j++) {
            int nfa_state = dfa[cur]->nfa_states[j];
            if (nfa[nfa_state].pattern_id != 0) {
                accept_nfa_state = nfa_state;
                break;
            }
        }

        if (accept_nfa_state >= 0) {
            // This DFA state contains an accept NFA state - find the DFA state for it
            for (int s = 0; s < dfa_state_count; s++) {
                for (int j = 0; j < dfa[s]->nfa_state_count; j++) {
                    if (dfa[s]->nfa_states[j] == accept_nfa_state) {
                        dfa[cur]->eos_target = s;
                        goto eos_done;
                    }
                }
            }
        }

        // Not accepting - check if it contains an EOS target NFA state
        // IMPORTANT: Only consider states with pattern_id != 0 as valid EOS targets
        // Fork states (like for + quantifier) have is_eos_target but no pattern_id
        // and should NOT allow empty matching
        int eos_nfa_state = -1;
        for (int j = 0; j < dfa[cur]->nfa_state_count; j++) {
            int nfa_state = dfa[cur]->nfa_states[j];
            // Only accept via empty string if the state has an actual pattern_id
            if (nfa[nfa_state].is_eos_target && nfa[nfa_state].pattern_id != 0) {
                eos_nfa_state = nfa_state;
                break;
            }
        }

        // If no direct EOS target found, check EOS target states for EOS transitions
        // This handles + quantifier where fork state leads to accept state via EOS
        if (eos_nfa_state < 0) {
            for (int j = 0; j < dfa[cur]->nfa_state_count; j++) {
                int nfa_state = dfa[cur]->nfa_states[j];
                if (nfa[nfa_state].is_eos_target) {
                    // Check if this EOS target state has transitions to accepting states
                    int eos_cnt = 0;
                    int* eos_targets = mta_get_target_array(&nfa[nfa_state].multi_targets, 258, &eos_cnt);
                    if (eos_targets) {
                        for (int e = 0; e < eos_cnt; e++) {
                            int eos_t = eos_targets[e];
                            if (nfa[eos_t].pattern_id != 0) {
                                // Found accepting state via EOS transition
                                // Find or create DFA state for this accept state
                                for (int s = 0; s < dfa_state_count; s++) {
                                    for (int k = 0; k < dfa[s]->nfa_state_count; k++) {
                                        if (dfa[s]->nfa_states[k] == eos_t) {
                                            dfa[cur]->eos_target = s;
                                            if (dfa[cur]->accepting_pattern_id == 0) {
                                                dfa[cur]->accepting_pattern_id = nfa[eos_t].pattern_id - 1;
                                                dfa[cur]->flags |= DFA_STATE_ACCEPTING;
                                            }
                                            break;
                                        }
                                    }
                                    if (dfa[cur]->eos_target != 0) break;
                                }
                                break;
                            }
                        }
                    }
                }
                if (eos_nfa_state >= 0 || dfa[cur]->eos_target != 0) break;
            }
        }

        if (eos_nfa_state >= 0) {
            // Find the DFA state that contains this exact EOS target NFA state
            for (int s = 0; s < dfa_state_count; s++) {
                for (int j = 0; j < dfa[s]->nfa_state_count; j++) {
                    if (dfa[s]->nfa_states[j] == eos_nfa_state) {
                        dfa[cur]->eos_target = s;
                        // Also set accepting pattern if not already set
                        if (dfa[cur]->accepting_pattern_id == 0 && nfa[eos_nfa_state].pattern_id != 0) {
                            dfa[cur]->accepting_pattern_id = nfa[eos_nfa_state].pattern_id - 1;  // Convert to 0-based
                            dfa[cur]->flags |= DFA_STATE_ACCEPTING;
                        }
                        break;
                    }
                }
                if (dfa[cur]->eos_target != 0) break;
            }
        }

        eos_done:;
    }
    free(q);
    free(ms);
    free(temp2);
    free(in);
    free(temp);
}

void flatten_dfa(nfa2dfa_context_t* ctx) {
    (void)ctx; // CLI version uses global state
    int any_sid = -1;
    int space_sid = -1;
    int tab_sid = -1;

    // Identify virtual symbol IDs
    for (int s = 0; s < alphabet_size; s++) {
        if (alphabet[s].symbol_id == 256) any_sid = s;
        else if (alphabet[s].symbol_id == 259) space_sid = s;
        else if (alphabet[s].symbol_id == 260) tab_sid = s;
    }
    
    for (int s = 0; s < dfa_state_count; s++) {
        int nt[256]; bool any[256]; uint32_t markers[256];
        for (int i = 0; i < 256; i++) { nt[i] = -1; any[i] = false; markers[i] = 0; }

        uint32_t any_marker = (any_sid != -1) ? dfa[s]->marker_offsets[256] : 0;

        // First, set specific symbol transitions
        for (int i = 0; i < alphabet_size; i++) {
            int sid = alphabet[i].symbol_id;
            if (sid < 256 && dfa[s]->transitions[sid] != -1) {
                int t = dfa[s]->transitions[sid];
                nt[sid] = t;
                any[sid] = false;
                markers[sid] = dfa[s]->marker_offsets[sid];
            }
        }

        // Override with space and tab transitions (use symbol IDs directly, not alphabet indices)
        if (space_sid != -1 && dfa[s]->transitions[259] != -1) {
            nt[32] = dfa[s]->transitions[259];
            any[32] = false;
            markers[32] = dfa[s]->marker_offsets[259];
        }

        if (tab_sid != -1 && dfa[s]->transitions[260] != -1) {
            nt[9] = dfa[s]->transitions[260];
            any[9] = false;
            markers[9] = dfa[s]->marker_offsets[260];
        }

        // Finally, override with ANY transition (fills in gaps)
        if (any_sid != -1 && dfa[s]->transitions[any_sid] != -1) {
            int t = dfa[s]->transitions[any_sid];
            for (int i = 0; i < 256; i++) {
                if (nt[i] == -1) {  // Only fill gaps, don't override specific transitions
                    nt[i] = t;
                    any[i] = true;
                    markers[i] = any_marker;
                }
            }
        }

        int rc = 0;
        for (int i = 0; i < 256; i++) {
            if (nt[i] >= dfa_state_count) {
                nt[i] = -1;
            }
            dfa[s]->transitions[i] = nt[i];
            dfa[s]->transitions_from_any[i] = any[i];
            dfa[s]->marker_offsets[i] = markers[i];
            if (nt[i] != -1) rc++;
        }
        for (int i = 256; i < MAX_SYMBOLS; i++) {
            dfa[s]->transitions[i] = -1;
            dfa[s]->marker_offsets[i] = 0;
        }
        dfa[s]->transition_count = rc;
    }
}

typedef struct { uint8_t type, d1, d2, d3; int target_state_index; } intermediate_rule_t;

int compress_state_rules(int sidx, intermediate_rule_t* out) {
    int rc = 0, ct = -1, sc = -1;
    // Compress only literal byte transitions (0-255)
    for (int c = 0; c <= 256; c++) {
        int t = (c < 256) ? dfa[sidx]->transitions[c] : -1;
        if (t != ct) {
            if (ct != -1) {
                out[rc].target_state_index = ct; out[rc].d1 = (uint8_t)sc; out[rc].d2 = (uint8_t)(c - 1); out[rc].d3 = 0;
                out[rc].type = (sc == c - 1) ? DFA_RULE_LITERAL : DFA_RULE_RANGE;
                rc++;
            }
            ct = t; sc = c;
        }
    }
    return rc;
}

void write_dfa_file(nfa2dfa_context_t* ctx, const char* filename) {
    (void)ctx; // CLI version uses global state
    FILE* file = fopen(filename, "wb");
    if (!file) { FATAL_SYS("Cannot open '%s' for writing", filename); exit(EXIT_FAILURE); }
    
#define DFA_CACHE_LINE_SIZE 64
#define DFA_MAX_ALIGNMENT_SLACK 5
    
    /* ====================================================================
     * PHASE 1: PRE-WRITE - collect rules, compute maxima
     * ==================================================================== */
    
    size_t alloc_size = (size_t)dfa_state_count * MAX_SYMBOLS * sizeof(intermediate_rule_t);
    if (dfa_state_count > 0 && alloc_size / sizeof(intermediate_rule_t) / MAX_SYMBOLS != (size_t)dfa_state_count) {
        FATAL("Integer overflow in rule allocation"); exit(EXIT_FAILURE);
    }
    intermediate_rule_t* all_rules = alloc_or_abort(malloc(alloc_size), "Rules");
    
    int* rule_counts = malloc(dfa_state_count * sizeof(int));
    if (!rule_counts) { FATAL("Failed to allocate rule counts"); exit(EXIT_FAILURE); }
    
    uint32_t max_offset = 0;
    uint32_t max_count = 0;
    uint32_t max_pid = 0;
    size_t total_rules = 0;
    
    for (int i = 0; i < dfa_state_count; i++) {
        rule_counts[i] = compress_state_rules(i, &all_rules[i * MAX_SYMBOLS]);
        total_rules += rule_counts[i];
        if ((uint32_t)rule_counts[i] > max_count) max_count = (uint32_t)rule_counts[i];
        if (dfa[i]->accepting_pattern_id != 0xFFFF && dfa[i]->accepting_pattern_id > max_pid)
            max_pid = dfa[i]->accepting_pattern_id;
    }
    size_t id_len = strlen(pattern_identifier);
    
    size_t marker_data_size = 0;
    for (int i = 0; i < dfa_state_count; i++) {
        for (int r = 0; r < rule_counts[i] && r < 256; r++) {
            uint32_t list_idx = dfa[i]->marker_offsets[all_rules[i * MAX_SYMBOLS + r].d1];
            if (list_idx > 0 && list_idx <= (uint32_t)marker_list_count) {
                MarkerList* ml = &dfa_marker_lists[list_idx - 1];
                marker_data_size += (ml->count + 1) * sizeof(uint32_t);
            }
        }
        if (dfa[i]->eos_marker_offset > 0 && dfa[i]->eos_marker_offset <= (uint32_t)marker_list_count) {
            MarkerList* ml = &dfa_marker_lists[dfa[i]->eos_marker_offset - 1];
            marker_data_size += (ml->count + 1) * sizeof(uint32_t);
        }
    }
    
    /* ====================================================================
     * PHASE 2: OPTIMISE LAYOUT - pick encoding, compute sizes
     * ==================================================================== */
    
    // Rough upper bound for offsets
    max_offset = (uint32_t)(DFA_HEADER_FIXED + 2*4 + id_len
                 + (size_t)dfa_state_count * DFA_STATE_SIZE(DFA_W4)
                 + total_rules * DFA_RULE_SIZE(DFA_W4)
                 + marker_data_size);
    
    int enc_ow = dfa_best_ow(max_offset);
    int enc_cw = dfa_best_cw(max_count);
    int enc_pw = dfa_best_pw(max_pid);
    int enc = dfa_make_enc(enc_ow, enc_cw, enc_pw);
    
    int state_size = DFA_STATE_SIZE(enc);
    int rule_size  = DFA_RULE_SIZE(enc);
    size_t header_size = DFA_HEADER_SIZE(enc, (uint8_t)id_len);
    
    // Compute state offsets with cache-line alignment
    size_t* state_offset = malloc(dfa_state_count * sizeof(size_t));
    size_t* rule_offset  = malloc(dfa_state_count * sizeof(size_t));
    
    size_t cur = header_size;
    for (int i = 0; i < dfa_state_count; i++) {
        int mis = cur % DFA_CACHE_LINE_SIZE;
        int pad = mis ? (DFA_CACHE_LINE_SIZE - mis) : 0;
        bool hot = (i == 0 || (dfa[i]->flags & DFA_STATE_ACCEPTING));
        bool align = (mis && (hot ? pad <= DFA_MAX_ALIGNMENT_SLACK*4 : pad <= DFA_MAX_ALIGNMENT_SLACK));
        if (align) cur += pad;
        state_offset[i] = cur;
        cur += state_size;
    }
    for (int i = 0; i < dfa_state_count; i++) {
        rule_offset[i] = cur;
        cur += (size_t)rule_counts[i] * rule_size;
    }
    size_t metadata_offset = cur;
    size_t total_size = metadata_offset + marker_data_size;
    
    /* ====================================================================
     * PHASE 3: WRITE - allocate buffer, write all fields via accessors
     * ==================================================================== */
    
    uint8_t* raw = calloc(1, total_size);
    if (!raw) { FATAL("Failed to allocate DFA buffer (%zu bytes)", total_size); exit(EXIT_FAILURE); }
    
    // Header
    dfa_fmt_set_magic(raw, DFA_MAGIC);
    dfa_fmt_set_version(raw, DFA_VERSION);
    dfa_fmt_set_state_count(raw, (uint16_t)dfa_state_count);
    dfa_fmt_set_encoding(raw, (uint8_t)enc);
    dfa_fmt_set_id_len(raw, (uint8_t)id_len);
    dfa_fmt_set_initial_state(raw, enc, (uint32_t)state_offset[0]);
    dfa_fmt_set_meta_offset(raw, enc, 0);
    memcpy(raw + DFA_HEADER_SIZE(enc, (uint8_t)id_len) - id_len, pattern_identifier, id_len);
    
    // States
    for (int i = 0; i < dfa_state_count; i++) {
        size_t so = state_offset[i];
        dfa_fmt_set_st_tc(raw, so, enc, (uint16_t)rule_counts[i]);
        dfa_fmt_set_st_rules(raw, so, enc, (rule_counts[i] > 0) ? (uint32_t)rule_offset[i] : 0);
        dfa_fmt_set_st_flags(raw, so, enc, dfa[i]->flags);
        dfa_fmt_set_st_pid(raw, so, enc, dfa[i]->accepting_pattern_id);
        dfa_fmt_set_st_eos_m(raw, so, enc, 0);
        dfa_fmt_set_st_eos_t(raw, so, enc,
            dfa[i]->eos_target ? (uint32_t)state_offset[dfa[i]->eos_target] : 0);
        dfa_fmt_set_st_first(raw, so, enc, 0);
    }
    
    // Rules
    for (int i = 0; i < dfa_state_count; i++) {
        for (int r = 0; r < rule_counts[i]; r++) {
            size_t ro = rule_offset[i] + (size_t)r * rule_size;
            dfa_fmt_set_rl_type(raw, ro, all_rules[i * MAX_SYMBOLS + r].type);
            dfa_fmt_set_rl_d1(raw, ro, all_rules[i * MAX_SYMBOLS + r].d1);
            dfa_fmt_set_rl_d2(raw, ro, all_rules[i * MAX_SYMBOLS + r].d2);
            dfa_fmt_set_rl_d3(raw, ro, 0);
            dfa_fmt_set_rl_markers(raw, ro, enc, 0);
            int tidx = all_rules[i * MAX_SYMBOLS + r].target_state_index;
            if (tidx < 0 || tidx >= dfa_state_count) {
                FATAL("State %d rule %d target index %d out of bounds", i, r, tidx);
                exit(EXIT_FAILURE);
            }
            dfa_fmt_set_rl_target(raw, ro, enc, (uint32_t)state_offset[tidx]);
        }
    }
    
    // Markers
    if (marker_list_count > 0) {
        dfa_fmt_set_meta_offset(raw, enc, (uint32_t)metadata_offset);
        uint32_t* mbase = (uint32_t*)(raw + metadata_offset);
        size_t moff = 0;
        for (int i = 0; i < dfa_state_count; i++) {
            for (int r = 0; r < rule_counts[i] && r < 256; r++) {
                size_t ro = rule_offset[i] + (size_t)r * rule_size;
                uint32_t lidx = dfa[i]->marker_offsets[all_rules[i * MAX_SYMBOLS + r].d1];
                if (lidx > 0 && lidx <= (uint32_t)marker_list_count) {
                    MarkerList* ml = &dfa_marker_lists[lidx - 1];
                    dfa_fmt_set_rl_markers(raw, ro, enc, (uint32_t)(metadata_offset + moff * 4));
                    mbase[moff++] = (uint32_t)ml->count;
                    for (int m = 0; m < ml->count; m++) mbase[moff++] = ml->markers[m];
                }
            }
        }
    }
    
    size_t written = fwrite(raw, 1, total_size, file);
    if (written != total_size) {
        FATAL_SYS("Failed to write DFA file '%s' (wrote %zu of %zu bytes)", filename, written, total_size);
    }
    
    if (flag_verbose) {
        int ac = 0, hc = 0;
        for (int i = 0; i < dfa_state_count; i++) {
            if (state_offset[i] % DFA_CACHE_LINE_SIZE == 0) {
                ac++;
                if (i == 0 || (dfa[i]->flags & DFA_STATE_ACCEPTING)) hc++;
            }
        }
        fprintf(stderr, "DFA v%d: %zu bytes, %d states, %zu rules, enc=0x%02X (ow=%d cw=%d pw=%d)\n",
                DFA_VERSION, total_size, dfa_state_count, total_rules, enc, enc_ow, enc_cw, enc_pw);
        fprintf(stderr, "  state_size=%d rule_size=%d header_size=%zu aligned=%d/%d hot=%d\n",
                state_size, rule_size, header_size, ac, dfa_state_count, hc);
    }
    
    fclose(file); free(raw); free(all_rules);
    free(rule_counts); free(state_offset); free(rule_offset);
}

void load_nfa_file(nfa2dfa_context_t* ctx, const char* filename) {
    (void)ctx; // CLI version uses global state
    FILE* file = fopen(filename, "r");
    if (!file) { FATAL_SYS("Cannot open NFA file '%s'", filename); exit(EXIT_FAILURE); }
    char line[1024]; 
    if (!fgets(line, sizeof(line), file)) { FATAL("Empty NFA file"); exit(EXIT_FAILURE); }
    if (!strstr(line, "NFA_ALPHABET")) { FATAL("Invalid NFA header"); exit(EXIT_FAILURE); }
#ifndef NFABUILDER_EXCLUDE_NFA_INIT
    nfa_init();
#endif
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "Identifier:", 11) == 0) sscanf(line + 11, "%s", pattern_identifier);
        else if (strncmp(line, "AlphabetSize:", 13) == 0) {
            sscanf(line + 13, "%d", &alphabet_size);
        } else if (strncmp(line, "States:", 7) == 0) {
            sscanf(line + 7, "%d", &nfa_state_count);

        }
        else if (strncmp(line, "Alphabet:", 9) == 0) {
            for (int i = 0; i < alphabet_size; i++) {
                if (!fgets(line, sizeof(line), file)) break;
                if (line[0] == '\n' || line[0] == '\r') { i--; continue; }
                if (strncmp(line, "State ", 6) == 0) { i--; continue; }
                if (strncmp(line, "Initial:", 8) == 0) { i--; continue; }
                unsigned int sid, start, end;
                if (sscanf(line, " Symbol %u: %u-%u", &sid, &start, &end) >= 3) {
                    alphabet[i].symbol_id = (int)sid; alphabet[i].start_char = (int)start; alphabet[i].end_char = (int)end;
                    alphabet[i].is_special = (strstr(line, "special") != NULL);
                }
            }
        }
        else if (strncmp(line, "State ", 6) == 0) {
            int s_idx; sscanf(line + 6, "%d:", &s_idx);
            // Initialize the state's transitions array to -1 (nfa_init may not have been called)
            for (int j = 0; j < MAX_SYMBOLS; j++) {
                nfa[s_idx].transitions[j] = -1;
            }
            mta_init(&nfa[s_idx].multi_targets);
            while (fgets(line, sizeof(line), file) && line[0] != '\n' && line[0] != '\r') {
                if (strstr(line, "CategoryMask:")) { unsigned int m; sscanf(strstr(line, "0x"), "%x", &m); nfa[s_idx].category_mask = (uint8_t)m; }
                else if (strstr(line, "EosTarget:")) nfa[s_idx].is_eos_target = (strstr(line, "yes") != NULL);
                else if (strstr(line, "PatternId:")) { 
                    unsigned int p; 
                    char* pstr = strstr(line, "PatternId:");
                    if (pstr) {
                        sscanf(pstr + 10, "%u", &p); 
                        nfa[s_idx].pattern_id = (uint16_t)p;
                    }
                }
                // Phase 2: markers are now stored as edge payloads, not on states
                // BUT CaptureEnd needs special handling: END markers attach to the state itself
                // We add them to the state's multi_targets using a special marker transition (VSYM_EOS)
                else if (strncmp(line, "  CaptureEnd:", 12) == 0) {
                    int cap_id;
                    if (sscanf(line + 14, "%d", &cap_id) == 1) {
                        // Add END marker to the state using VSYM_EOS (258)
                        mta_add_marker(&nfa[s_idx].multi_targets, VSYM_EOS, 0, cap_id, MARKER_TYPE_END);
                    }
                }
                else if (strncmp(line, "    Symbol ", 11) == 0) {
                    int sid, target; char* arrow = strstr(line, "->");
                    if (arrow && sscanf(line + 11, "%d", &sid) == 1) {
                        char* p = arrow + 2;
                        while (p && *p != '[') {
                            while (isspace(*p) || *p == ',') p++;
                            if (sscanf(p, "%d", &target) == 1) {
                                mta_add_target(&nfa[s_idx].multi_targets, sid, target);
                            }
                            p = strchr(p, ','); if (p) p++;
                        }
                        char* markers_start = strstr(line, "[Markers:");
                        if (markers_start) {
                            char* m = markers_start + 9;
                            while (*m && *m != ']') {
                                uint32_t marker;
                                while (*m && (isspace(*m) || *m == ',')) m++;
                                if (sscanf(m, "0x%08X", &marker) == 1) {
                                    uint16_t pattern_id = (marker >> 17) & 0xFFFF;
                                    uint16_t uid = (marker >> 1) & 0x7FFF;
                                    uint8_t type = marker & 0x1;
                                    mta_add_marker(&nfa[s_idx].multi_targets, sid, pattern_id, uid, type);
                                    // Advance m past this marker (skip 10 chars for "0xXXXXXXXX")
                                    m += 10;
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    fclose(file);
}

#ifndef NFABUILDER_NO_MAIN
int main(int argc, char* argv[]) {
    bool minimize = true;
    bool compress = true;   // Compression ON by default (greedy algorithm)
    bool compress_sat = false;
    const char* input_file = NULL;
    const char* output_file = "out.dfa";
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "--no-minimize") == 0) minimize = false;
            else if (strcmp(argv[i], "--no-compress") == 0) compress = false;
            else if (strcmp(argv[i], "-v") == 0) flag_verbose = true;
            else if (strcmp(argv[i], "--minimize-hopcroft") == 0) dfa_minimize_set_algorithm(DFA_MIN_HOPCROFT);
            else if (strcmp(argv[i], "--minimize-moore") == 0) dfa_minimize_set_algorithm(DFA_MIN_MOORE);
            else if (strcmp(argv[i], "--minimize-brzozowski") == 0) dfa_minimize_set_algorithm(DFA_MIN_BRZOZOWSKI);
            else if (strcmp(argv[i], "--minimize-sat") == 0) dfa_minimize_set_algorithm(DFA_MIN_SAT);
            else if (strcmp(argv[i], "--compress-sat") == 0) compress_sat = true;
        } else {
            if (input_file == NULL) input_file = argv[i];
            else output_file = argv[i];
        }
    }
    if (input_file == NULL) return 1;
    
    init_hash_table(NULL);
    
    load_nfa_file(NULL, input_file);
    
    // Pre-minimize NFA before subset construction (always on by default)
    nfa_premin_options_t premin_opts = nfa_premin_default_options();
    premin_opts.verbose = flag_verbose;
    
    // Check for SAT optimal flag
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "--sat-optimal") == 0) {
            premin_opts.enable_sat_optimal = true;
        }
    }
    
    nfa_preminimize(nfa, &nfa_state_count, &premin_opts);
    
    nfa_to_dfa(NULL);
    flatten_dfa(NULL);
    
    if (minimize) {
        dfa_min_algo_t algo = dfa_minimize_get_algorithm();
        dfa_state_count = dfa_minimize(dfa, dfa_state_count);
        // Don't re-flatten after Brzozowski - it already produces correct transitions
        if (algo != DFA_MIN_BRZOZOWSKI) {
            flatten_dfa(NULL);  // Re-flatten with new state indices after minimization
        }
        // Apply cache-optimized layout (now separate from minimization)
        layout_options_t layout_opts = get_default_layout_options();
        int* order = optimize_dfa_layout(dfa, dfa_state_count, &layout_opts);
        if (order) free(order);
    }
    
    if (compress) {
        compress_options_t opts = get_default_compress_options();
        opts.verbose = flag_verbose;
        opts.use_sat = compress_sat;  // Enable SAT-based optimal merging if requested
        dfa_compress(dfa, dfa_state_count, &opts);
    }
    
    write_dfa_file(NULL, output_file);
    return 0;
}
#endif  // NFABUILDER_NO_MAIN
