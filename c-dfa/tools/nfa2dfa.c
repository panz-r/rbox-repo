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
#include "../include/pipeline.h"
#include "nfa_builder.h"
#include "dfa_minimize.h"
#include "dfa_compress.h"
#include "dfa_layout.h"
#include "nfa_preminimize.h"
#include "nfa2dfa_context.h"
#include "../include/cdfa_defines.h"

#if MAX_SYMBOLS != 320
#error "MAX_SYMBOLS must be 320"
#endif

#define DEBUG_PRINT(ctx, ...) do { if (CTX_FLAG_VERBOSE(ctx)) fprintf(stderr, __VA_ARGS__); } while (0)

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

// ============================================================================
// CONTEXT ACCESSORS
//
// All functions receive a valid context (ctx != NULL).
// ============================================================================

// Global marker lists pointer for SAT minimizer (uses context when available)
static MarkerList* g_marker_lists = NULL;
static int g_marker_list_count = 0;

MarkerList* dfa_get_marker_lists(int* count) {
    if (count) *count = g_marker_list_count;
    return g_marker_lists;
}

void dfa_set_marker_lists(MarkerList* lists, int count) {
    g_marker_lists = lists;
    g_marker_list_count = count;
}

// Pointer-to-array fields
#define CTX_NFA(ctx)             ((ctx)->nfa)
#define CTX_DFA(ctx)             ((ctx)->dfa)
#define CTX_ALPHABET(ctx)        ((ctx)->alphabet)
#define CTX_HASH_TABLE(ctx)      ((ctx)->dfa_hash_table)
#define CTX_NEXT_BUCKET(ctx)     ((ctx)->dfa_next_in_bucket)
#define CTX_MARKER_LISTS(ctx)    ((ctx)->dfa_marker_lists)

// Scalar fields
#define CTX_NFA_COUNT(ctx)       ((ctx)->nfa_state_count)
#define CTX_DFA_COUNT(ctx)       ((ctx)->dfa_state_count)
#define CTX_ALPHABET_SIZE(ctx)   ((ctx)->alphabet_size)
#define CTX_MAX_STATES(ctx)      ((ctx)->max_states)
#define CTX_MARKER_COUNT(ctx)    ((ctx)->marker_list_count)

// Pointer-to-scalar fields (return address of count)
#define CTX_NFA_COUNT_PTR(ctx, unused)   (&(ctx)->nfa_state_count)
#define CTX_DFA_COUNT_PTR(ctx, unused)   (&(ctx)->dfa_state_count)
#define CTX_ALPHABET_SIZE_PTR(ctx, unused) (&(ctx)->alphabet_size)

// Configuration fields (context-only, ctx guaranteed non-NULL)
#define CTX_FLAG_VERBOSE(ctx)   ((ctx)->flag_verbose)
#define CTX_PATTERN_ID(ctx)     ((ctx)->pattern_identifier)

void init_hash_table(ATTR_UNUSED nfa2dfa_context_t* ctx) {
    memset(CTX_HASH_TABLE(ctx), -1, sizeof(int) * DFA_HASH_SIZE);
    memset(CTX_NEXT_BUCKET(ctx), -1, sizeof(int) * MAX_STATES);
}

#define MAX_MARKERS_PER_DFA_TRANSITION 16
#define MAX_DFA_MARKER_LISTS 8192

// MarkerList is now defined in dfa_minimize.h (shared with SAT minimizer)

static void init_marker_lists(ATTR_UNUSED nfa2dfa_context_t* ctx) {
    ctx->dfa_marker_lists = alloc_or_abort(malloc(sizeof(MarkerList) * MAX_DFA_MARKER_LISTS), "Failed to allocate marker lists");
    memset(ctx->dfa_marker_lists, 0, sizeof(MarkerList) * MAX_DFA_MARKER_LISTS);
    ctx->marker_list_count = 0;
}

// Note: No free_marker_lists() needed - CLI tool exits after processing

// Get unique marker list (store if new)
static uint32_t store_marker_list(ATTR_UNUSED nfa2dfa_context_t* ctx, const uint32_t* markers, int count) {
    if (count == 0) return 0;
    
    MarkerList* lists = CTX_MARKER_LISTS(ctx);
    int count_local = CTX_MARKER_COUNT(ctx);
    
    // Check if list already exists
    for (int i = 0; i < count_local; i++) {
        if (lists[i].count == count) {
            bool match = true;
            for (int j = 0; j < count; j++) {
                if (lists[i].markers[j] != markers[j]) { match = false; break; }
            }
            if (match) return (uint32_t)(i + 1);  // +1 to distinguish from 0 (no markers)
        }
    }
    
    // Store new list
    if (count_local < MAX_DFA_MARKER_LISTS) {
        for (int j = 0; j < count && j < MAX_MARKERS_PER_DFA_TRANSITION; j++) {
            lists[count_local].markers[j] = markers[j];
        }
        lists[count_local].count = count;
        ctx->marker_list_count = count_local + 1;
        return (uint32_t)(count_local + 1);
    }
    return 0;
}

// Collect markers from NFA states in an epsilon closure
static void collect_markers_from_states(ATTR_UNUSED nfa2dfa_context_t* ctx, const int* states, int state_count,
                                        uint32_t* out_markers, int* out_count) {
    nfa_state_t* nfa_arr = CTX_NFA(ctx);
    int nfa_cnt = CTX_NFA_COUNT(ctx);
    int count = *out_count;  // Start with existing marker count
    for (int i = 0; i < state_count && count < MAX_MARKERS_PER_DFA_TRANSITION; i++) {
        int ns = states[i];
        if (ns < 0 || ns >= nfa_cnt) continue;

        // Collect markers from pending_markers array
        for (int m = 0; m < nfa_arr[ns].pending_marker_count && count < MAX_MARKERS_PER_DFA_TRANSITION; m++) {
            if (nfa_arr[ns].pending_markers[m].active) {
                uint32_t marker = ((uint32_t)nfa_arr[ns].pending_markers[m].pattern_id << 17) |
                                  ((uint32_t)nfa_arr[ns].pending_markers[m].uid << 1) |
                                  (uint32_t)nfa_arr[ns].pending_markers[m].type;
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
static void sort_states_canonical(ATTR_UNUSED nfa2dfa_context_t* ctx, int* states, int count) {
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
static uint32_t hash_nfa_set(ATTR_UNUSED nfa2dfa_context_t* ctx, const int* sorted_states, int count, uint8_t mask, uint16_t first_accepting_pattern) {
    (void)ctx;
    uint32_t hash = FNV_OFFSET_BASIS;
    for (int i = 0; i < count; i++) {
        hash ^= (uint32_t)sorted_states[i];
        hash *= FNV_PRIME;
    }
    hash ^= (uint32_t)mask << 24;
    hash ^= (uint32_t)first_accepting_pattern;
    return hash;
}

static int find_dfa_state_hashed(ATTR_UNUSED nfa2dfa_context_t* ctx, uint32_t hash, const int* sorted_states, int count, uint8_t mask, uint16_t first_accepting_pattern) {
    int* dfa_hash = CTX_HASH_TABLE(ctx);
    int* dfa_next = CTX_NEXT_BUCKET(ctx);
    build_dfa_state_t** dfa_arr = CTX_DFA(ctx);
    int idx = dfa_hash[hash % DFA_HASH_SIZE];
    while (idx != -1) {
        if (dfa_arr[idx]->nfa_state_count == count) {
            uint8_t existing_mask = (uint8_t)(dfa_arr[idx]->flags >> 8);
            if (existing_mask == mask && dfa_arr[idx]->first_accepting_pattern == first_accepting_pattern) {
                bool match = true;
                for (int j = 0; j < count; j++) {
                    if (dfa_arr[idx]->nfa_states[j] != sorted_states[j]) { match = false; break; }
                }
                if (match) return idx;
            }
        }
        idx = dfa_next[idx];
    }
    return -1;
}

void dfa_init(ATTR_UNUSED nfa2dfa_context_t* ctx) {
    int* dfa_hash = CTX_HASH_TABLE(ctx);
    int* dfa_next = CTX_NEXT_BUCKET(ctx);
    build_dfa_state_t** dfa_arr = CTX_DFA(ctx);
    int* dfa_count_ptr = CTX_DFA_COUNT_PTR(ctx, dfa_state_count);
    
    memset(dfa_hash, -1, sizeof(int) * DFA_HASH_SIZE);
    memset(dfa_next, -1, sizeof(int) * MAX_STATES);
    // Free any previously allocated states
    for (int i = 0; i < *dfa_count_ptr; i++) {
        if (dfa_arr[i]) {
            build_dfa_state_destroy(dfa_arr[i]);
            dfa_arr[i] = NULL;
        }
    }
    // Pre-allocate first batch of states
    for (int i = 0; i < MAX_STATES; i++) {
        dfa_arr[i] = NULL;  // Will be allocated on demand in dfa_add_state
    }
    *dfa_count_ptr = 0;
}

void epsilon_closure_with_markers(ATTR_UNUSED nfa2dfa_context_t* ctx, int* states, int* count, int max_states,
                                   uint32_t* markers, int* marker_count, int max_markers) {
    nfa_state_t* nfa_arr = CTX_NFA(ctx);
    int nfa_cnt = CTX_NFA_COUNT(ctx);
    const int epsilon_symbol_id = VSYM_EPS;
    bool* in_set = alloc_or_abort(calloc(max_states, sizeof(bool)), "epsilon_closure in_set");
    int* stack = alloc_or_abort(malloc(max_states * sizeof(int)), "epsilon_closure stack");
    int top = 0;

    for (int i = 0; i < *count; i++) {
        int s = states[i];
        if (s >= 0 && s < nfa_cnt) { stack[top++] = s; in_set[s] = true; }
    }

    while (top > 0) {
        int s = stack[--top];

        // Process EPSILON transitions (257) - use multi_targets only
        int mta_cnt = 0;
        int* mta_targets = mta_get_target_array(&nfa_arr[s].multi_targets, epsilon_symbol_id, &mta_cnt);
        if (mta_targets) {
            for (int i = 0; i < mta_cnt; i++) {
                int target = mta_targets[i];
                if (target >= 0 && target < nfa_cnt && !in_set[target]) {
                    if (*count < max_states) { states[(*count)++] = target; stack[top++] = target; in_set[target] = true; }
                }
            }
        }

        int mta_marker_count = 0;
        transition_marker_t* mta_markers = mta_get_markers(&nfa_arr[s].multi_targets, epsilon_symbol_id, &mta_marker_count);
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
    free(in_set);
    free(stack);
}

void epsilon_closure(ATTR_UNUSED nfa2dfa_context_t* ctx, int* states, int* count, int max_states) {
    nfa_state_t* nfa_arr = CTX_NFA(ctx);
    alphabet_entry_t* alphabet_arr = CTX_ALPHABET(ctx);
    int nfa_cnt = CTX_NFA_COUNT(ctx);
    int alphabet_sz = CTX_ALPHABET_SIZE(ctx);
    int epsilon_sid = -1;
    int epsilon_symbol_id = 257;
    for (int s = 0; s < alphabet_sz; s++) {
        if (alphabet_arr[s].symbol_id == VSYM_EPS) { epsilon_sid = s; break; }
    }
    if (epsilon_sid < 0) {
        return;
    }

    bool* in_set = alloc_or_abort(calloc(max_states, sizeof(bool)), "epsilon_closure in_set");
    int* stack = alloc_or_abort(malloc(max_states * sizeof(int)), "epsilon_closure stack");
    int top = 0;
    
    for (int i = 0; i < *count; i++) {
        int s = states[i];
        if (s >= 0 && s < nfa_cnt) { stack[top++] = s; in_set[s] = true; }
    }

    while (top > 0) {
        int s = stack[--top];
        // Process EPSILON transitions (257) - use multi_targets only
        int mta_cnt = 0;
        int* mta_targets = mta_get_target_array(&nfa_arr[s].multi_targets, epsilon_symbol_id, &mta_cnt);
        if (mta_targets) {
            for (int i = 0; i < mta_cnt; i++) {
                int target = mta_targets[i];
                if (target >= 0 && target < nfa_cnt && !in_set[target]) {
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
static uint8_t collect_fork_categories(ATTR_UNUSED nfa2dfa_context_t* ctx, int* states, int count, bool is_initial_state) {
    nfa_state_t* nfa_arr = CTX_NFA(ctx);
    int nfa_cnt = CTX_NFA_COUNT(ctx);
    uint8_t fork_cats = 0;
    
    // Check if there are any fork states in the NFA (is_eos_target with category)
    // A fork state is a state that can match empty (is_eos_target) and has a category
    bool has_fork = false;
    for (int i = 0; i < nfa_cnt; i++) {
        if (nfa_arr[i].is_eos_target && nfa_arr[i].category_mask != 0) {
            has_fork = true;
            break;
        }
    }
    if (!has_fork) return 0;
    
    // For initial state, do epsilon closure from state 0 and collect fork categories
    // that are actually reachable via epsilon transitions
    // This ensures + quantifier (which has NO skip path) doesn't incorrectly match empty
    if (is_initial_state) {
        bool* visited = alloc_or_abort(calloc(nfa_cnt, sizeof(bool)), "collect_fork_categories visited");
        int* stack = alloc_or_abort(malloc(nfa_cnt * sizeof(int)), "collect_fork_categories stack");
        int stack_top = 0;
        
        // Start from state 0 (initial state)
        stack[stack_top++] = 0;
        visited[0] = true;
        
        int epsilon_symbol_id = 257;
        
        while (stack_top > 0) {
            int cur = stack[--stack_top];
            
            // If this is a fork state (is_eos_target with category), collect its category
            if (nfa_arr[cur].is_eos_target && nfa_arr[cur].category_mask != 0) {
                fork_cats |= nfa_arr[cur].category_mask;
            }
            
            // Continue exploring via EPSILON transitions
            int mta_cnt = 0;
            int* mta_targets = mta_get_target_array(&nfa_arr[cur].multi_targets, epsilon_symbol_id, &mta_cnt);
            if (mta_targets) {
                for (int i = 0; i < mta_cnt; i++) {
                    int target = mta_targets[i];
                    if (target >= 0 && target < nfa_cnt && !visited[target]) {
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
    bool* visited = alloc_or_abort(calloc(nfa_cnt, sizeof(bool)), "collect_fork_categories visited");
    int* stack = alloc_or_abort(malloc(nfa_cnt * sizeof(int)), "collect_fork_categories stack");
    int stack_top = 0;
    
    // For non-initial states, search from all states
    for (int s = 0; s < count; s++) {
        int start = states[s];
        if (start >= 0 && start < nfa_cnt && !visited[start]) {
            stack[stack_top++] = start;
            visited[start] = true;
        }
    }
    
    int epsilon_symbol_id = 257;
    
    while (stack_top > 0) {
        int cur = stack[--stack_top];
        
        // If this is a fork state (is_eos_target with category), collect its category
        if (nfa_arr[cur].is_eos_target && nfa_arr[cur].category_mask != 0) {
            fork_cats |= nfa_arr[cur].category_mask;
        }
        
        // Continue exploring via EPSILON transitions
        int mta_cnt = 0;
        int* mta_targets = mta_get_target_array(&nfa_arr[cur].multi_targets, epsilon_symbol_id, &mta_cnt);
        if (mta_targets) {
            for (int i = 0; i < mta_cnt; i++) {
                int target = mta_targets[i];
                if (target >= 0 && target < nfa_cnt && !visited[target]) {
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

int dfa_add_state(ATTR_UNUSED nfa2dfa_context_t* ctx, uint8_t category_mask, int* nfa_states, int nfa_count, uint16_t accepting_pattern_id, uint16_t first_accepting_pattern) {
    build_dfa_state_t** dfa_arr = CTX_DFA(ctx);
    int* dfa_hash = CTX_HASH_TABLE(ctx);
    int* dfa_next = CTX_NEXT_BUCKET(ctx);
    int* dfa_count_ptr = CTX_DFA_COUNT_PTR(ctx, dfa_state_count);
    (void)dfa_hash; (void)dfa_next;
    
    int* sorted = alloc_or_abort(malloc(nfa_count * sizeof(int)), "dfa_add_state sorted");
    for (int i = 0; i < nfa_count; i++) {
        sorted[i] = nfa_states[i];
    }
    sort_states_canonical(ctx, sorted, nfa_count);

    uint32_t h = hash_nfa_set(ctx, sorted, nfa_count, category_mask, first_accepting_pattern);
    int bucket = h % DFA_HASH_SIZE;
    int existing = find_dfa_state_hashed(ctx, h, sorted, nfa_count, category_mask, first_accepting_pattern);
    if (existing != -1) {
        free(sorted);
        return existing;
    }
    if (*dfa_count_ptr >= MAX_STATES) { 
        FATAL("Max DFA states reached (%d states)", MAX_STATES);
        ERROR("  Split patterns into multiple files or simplify complex patterns");
        exit(EXIT_FAILURE); 
    }
    int state = (*dfa_count_ptr)++;
    // Allocate the state dynamically
    dfa_arr[state] = build_dfa_state_create(MAX_SYMBOLS, nfa_count > 64 ? nfa_count * 2 : 128);
    if (!dfa_arr[state]) {
        FATAL("Failed to allocate DFA state %d", state);
        exit(EXIT_FAILURE);
    }
    dfa_arr[state]->flags = (category_mask << 8);
    if (accepting_pattern_id != 0 || first_accepting_pattern != 0) {
        dfa_arr[state]->flags |= DFA_STATE_ACCEPTING;
    }
    dfa_arr[state]->accepting_pattern_id = accepting_pattern_id;
    dfa_arr[state]->first_accepting_pattern = first_accepting_pattern;
    
    // Store pre-sorted states
    dfa_arr[state]->nfa_state_count = nfa_count;
    if (nfa_count > dfa_arr[state]->nfa_state_capacity) {
        if (!build_dfa_state_grow_nfa(dfa_arr[state], nfa_count - dfa_arr[state]->nfa_state_capacity)) {
            FATAL("Failed to grow NFA state array for DFA state %d", state);
            exit(EXIT_FAILURE);
        }
    }
    for (int i = 0; i < nfa_count; i++) dfa_arr[state]->nfa_states[i] = sorted[i];
    dfa_next[state] = dfa_hash[bucket];
    dfa_hash[bucket] = state;
    free(sorted);
    return state;
}

void nfa_move(ATTR_UNUSED nfa2dfa_context_t* ctx, int* states, int* count, int sid, int max_states) {
    nfa_state_t* nfa_arr = CTX_NFA(ctx);
    int nfa_cnt = CTX_NFA_COUNT(ctx);
    int* ns = alloc_or_abort(malloc(max_states * sizeof(int)), "nfa_move ns");
    int nc = 0; 
    bool* is = alloc_or_abort(calloc(max_states, sizeof(bool)), "nfa_move is");
    for (int i = 0; i < *count; i++) {
        int s = states[i]; if (s < 0 || s >= nfa_cnt) continue;

        // Use multi_targets only - transitions[] array is not populated
        int mta_cnt = 0;
        int* targets = mta_get_target_array(&nfa_arr[s].multi_targets, sid, &mta_cnt);
        if (targets) {
            for (int k = 0; k < mta_cnt; k++) {
                int t = targets[k]; if (t >= 0 && t < nfa_cnt && !is[t]) { if (nc < max_states) { ns[nc++] = t; is[t] = true; } }
            }
        }
    }
    for (int i = 0; i < nc; i++) states[i] = ns[i];
    *count = nc;
    free(ns);
    free(is);
}

static void collect_transition_markers(ATTR_UNUSED nfa2dfa_context_t* ctx, int source_count, int* source_states, int sid,
                                       uint32_t* out_markers, int* out_count, int max_markers) {
    nfa_state_t* nfa_arr = CTX_NFA(ctx);
    alphabet_entry_t* alphabet_arr = CTX_ALPHABET(ctx);
    int alphabet_sz = CTX_ALPHABET_SIZE(ctx);
    int nfa_cnt = CTX_NFA_COUNT(ctx);
    int count = *out_count;
    for (int i = 0; i < source_count && count < max_markers; i++) {
        int s = source_states[i];
        if (s < 0 || s >= nfa_cnt) continue;

        // Collect markers from multi_targets
        int mta_marker_count = 0;
        transition_marker_t* mta_markers = mta_get_markers(&nfa_arr[s].multi_targets, sid, &mta_marker_count);
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

        // Also collect from pending_markers (capture markers)
        for (int m = 0; m < nfa_arr[s].pending_marker_count && count < max_markers; m++) {
            if (nfa_arr[s].pending_markers[m].active) {
                uint32_t marker = ((uint32_t)nfa_arr[s].pending_markers[m].pattern_id << 17) |
                                  ((uint32_t)nfa_arr[s].pending_markers[m].uid << 1) |
                                  (uint32_t)nfa_arr[s].pending_markers[m].type;
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
        if (sid == VSYM_EOS) {
            int eos_marker_count = 0;
            int eos_sid = -1;
            for (int as = 0; as < alphabet_sz; as++) {
                if (alphabet_arr[as].symbol_id == VSYM_EOS) { eos_sid = as; break; }
            }
            if (eos_sid >= 0) {
                transition_marker_t* eos_markers = mta_get_markers(&nfa_arr[s].multi_targets, eos_sid, &eos_marker_count);
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

void nfa_to_dfa(ATTR_UNUSED nfa2dfa_context_t* ctx) {
    build_dfa_state_t** dfa_arr = CTX_DFA(ctx);
    nfa_state_t* nfa_arr = CTX_NFA(ctx);
    alphabet_entry_t* alphabet_arr = CTX_ALPHABET(ctx);
    int alphabet_sz = CTX_ALPHABET_SIZE(ctx);
    int nfa_count = CTX_NFA_COUNT(ctx);
    int max_st = CTX_MAX_STATES(ctx);
    int* dfa_count_ptr = CTX_DFA_COUNT_PTR(ctx, dfa_state_count);
    DEBUG_PRINT(ctx, "nfa_to_dfa: nfa_state_count=%d, alphabet_size=%d\n", nfa_count, alphabet_sz);
    dfa_init(ctx);
    init_marker_lists(ctx);
    dfa_set_marker_lists(ctx->dfa_marker_lists, ctx->marker_list_count);
    DEBUG_PRINT(ctx, "after dfa_init\n");

    int* in = alloc_or_abort(calloc(max_st, sizeof(int)), "nfa_to_dfa in");
    int ic = 1;
    DEBUG_PRINT(ctx, "before epsilon_closure\n");
    int* temp = alloc_or_abort(malloc(max_st * sizeof(int)), "nfa_to_dfa temp");
    memcpy(temp, in, sizeof(int)); 
    int tc = ic;
    uint32_t dummy_markers[MAX_MARKERS_PER_DFA_TRANSITION];
    int dummy_count = 0;
    epsilon_closure_with_markers(ctx, temp, &tc, max_st, dummy_markers, &dummy_count, MAX_MARKERS_PER_DFA_TRANSITION);
    DEBUG_PRINT(ctx, "after epsilon_closure, tc=%d\n", tc);
    DEBUG_PRINT(ctx, "temp states: ");
    for (int i = 0; i < tc; i++) DEBUG_PRINT(ctx, "%d ", temp[i]);
    DEBUG_PRINT(ctx, "\n");
    
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
        
        // For initial DFA state: don't use is_eos_target for acceptance
        // (prevents patterns like (a)+ from incorrectly accepting empty when
        // combined with (x)*). Include is_eos_target states that have pattern_id set.
        
        // Category from states that are either accepting (pattern_id) or EOS targets
        if ((nfa_arr[ns].pattern_id != 0 || (nfa_arr[ns].is_eos_target && !is_initial_state)) && nfa_arr[ns].category_mask != 0) {
            im |= nfa_arr[ns].category_mask;
        }
        // Accept pattern from states with pattern_id (true accepting states)
        if (nfa_arr[ns].pattern_id != 0 && accept_pattern == 0) {
            accept_pattern = nfa_arr[ns].pattern_id - 1;  // Convert back to 0-based
        }
        // Also check EOS target states for non-initial states
        if (!is_initial_state && nfa_arr[ns].is_eos_target && accept_pattern == 0) {
            // Check if this EOS target state has transitions to accepting states
            // Look for EOS transitions (symbol 258) from this state
            int eos_cnt = 0;
            int* eos_targets = mta_get_target_array(&nfa_arr[ns].multi_targets, 258, &eos_cnt);
            if (eos_targets) {
                for (int e = 0; e < eos_cnt; e++) {
                    int eos_t = eos_targets[e];
                    if (nfa_arr[eos_t].pattern_id != 0) {
                        accept_pattern = nfa_arr[eos_t].pattern_id - 1;  // Convert back to 0-based
                        break;
                    }
                }
            }
        }
        
    // Also collect category from EOS target states (fork states can reach accepting states via EOS)
    // This ensures we get categories from patterns that require multiple iterations
    // CRITICAL: For initial DFA state, don't collect from is_eos_target states
    if (!is_initial_state && nfa_arr[ns].is_eos_target && nfa_arr[ns].category_mask == 0) {
            int eos_cnt = 0;
            int* eos_targets = mta_get_target_array(&nfa_arr[ns].multi_targets, 258, &eos_cnt);
            if (eos_targets) {
                for (int e = 0; e < eos_cnt; e++) {
                    int eos_t = eos_targets[e];
                    if (nfa_arr[eos_t].category_mask != 0) {
                        im |= nfa_arr[eos_t].category_mask;
                        break;
                    }
                }
            }
        }
        
        // Track all reachable accepting patterns for state deduplication
        if (nfa_arr[ns].pattern_id != 0) {
            if (nfa_arr[ns].pattern_id <= 64) {
                reachable_accepting_patterns |= (1ULL << (nfa_arr[ns].pattern_id - 1));
            }
        }
    }
    DEBUG_PRINT(ctx, "before collect_fork_categories, im=0x%02x\n", im);
    // Don't collect fork categories for initial state - patterns with +
    // quantifier should not match empty strings via fork state categories
    uint8_t fork_cats = collect_fork_categories(ctx, temp, tc, false);
    DEBUG_PRINT(ctx, "after collect_fork_categories, fork_cats=0x%02x\n", fork_cats);
    im |= fork_cats;
    DEBUG_PRINT(ctx, "before dfa_add_state\n");
    int idfa = dfa_add_state(ctx, im, temp, tc, accept_pattern, reachable_accepting_patterns);
    if (idfa < 0) {
        ERROR("Failed to add initial DFA state");
        return;
    }

    // Allow empty matching for all patterns - the core fix is in category propagation
    // (not including category from is_eos_target states), which prevents false category matches

    int* q = alloc_or_abort(malloc(max_st * sizeof(int)), "nfa_to_dfa queue");
    int h = 0, t = 1; q[0] = idfa;
    
    // Pre-allocate working arrays for the loop
    int* ms = alloc_or_abort(malloc(max_st * sizeof(int)), "nfa_to_dfa ms");
    int* temp2 = alloc_or_abort(malloc(max_st * sizeof(int)), "nfa_to_dfa temp2");

    while (h < t) {
        int cur = q[h++];
        for (int i = 0; i < alphabet_sz; i++) {
            int symbol = alphabet_arr[i].symbol_id;
            if (symbol == VSYM_EPS) continue;

            int mc = dfa_arr[cur]->nfa_state_count;
            for (int j = 0; j < mc; j++) ms[j] = dfa_arr[cur]->nfa_states[j];

            uint32_t markers[MAX_MARKERS_PER_DFA_TRANSITION];
            memset(markers, 0, sizeof(markers));
            int marker_count = 0;
            collect_transition_markers(ctx, mc, ms, symbol, markers, &marker_count, MAX_MARKERS_PER_DFA_TRANSITION);

            nfa_move(ctx, ms, &mc, symbol, max_st);

            if (mc == 0) {
                int eos_sid = -1;
                for (int as = 0; as < alphabet_sz; as++) {
                    if (alphabet_arr[as].symbol_id == VSYM_EOS) { eos_sid = as; break; }
                }
                if (eos_sid >= 0 && symbol == alphabet_arr[eos_sid].symbol_id) {
                    store_marker_list(ctx, markers, marker_count);
                }
                continue;
            }
            int tc2 = mc; 
            memcpy(temp2, ms, mc * sizeof(int));
            epsilon_closure_with_markers(ctx, temp2, &tc2, max_st, markers, &marker_count, MAX_MARKERS_PER_DFA_TRANSITION);

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
                if ((nfa_arr[ns].pattern_id != 0 || nfa_arr[ns].is_eos_target) && nfa_arr[ns].category_mask != 0) {
                    mm |= nfa_arr[ns].category_mask;
                }
                
                // Also collect category from EOS target states (fork states can reach accepting states via EOS)
                // This ensures we get categories from patterns that require multiple iterations
                if (nfa_arr[ns].is_eos_target && nfa_arr[ns].category_mask == 0) {
                    int eos_cnt = 0;
                    int* eos_targets = mta_get_target_array(&nfa_arr[ns].multi_targets, 258, &eos_cnt);
                    if (eos_targets) {
                        for (int e = 0; e < eos_cnt; e++) {
                            int eos_t = eos_targets[e];
                            if (nfa_arr[eos_t].category_mask != 0) {
                                mm |= nfa_arr[eos_t].category_mask;
                                break;
                            }
                        }
                    }
                }
                
                // Accept pattern from any state in the closure (epsilon-reached states included)
                if (nfa_arr[ns].pattern_id != 0 && accept_pattern2 == 0) {
                    accept_pattern2 = nfa_arr[ns].pattern_id - 1;  // Convert back to 0-based
                }
                // Track all reachable accepting patterns for state deduplication
                if (nfa_arr[ns].pattern_id != 0) {
                    if (nfa_arr[ns].pattern_id <= 64) {
                        reachable_accepting_patterns2 |= (1ULL << (nfa_arr[ns].pattern_id - 1));
                    }
                }
            }
            
            // QUANTIFIER FIX: Only collect fork categories for INITIAL state
            // For non-initial states, don't collect fork categories as they can cause
            // incorrect matching where patterns like a* and b* match any character
            uint8_t fork_cats = 0;
            if (is_initial_state) {
                fork_cats = collect_fork_categories(ctx, temp2, tc2, false);
            }
            mm |= fork_cats;
            // DO NOT inherit from source - that breaks prefix sharing

            collect_markers_from_states(ctx, temp2, tc2, markers, &marker_count);
            uint32_t marker_list_offset = store_marker_list(ctx, markers, marker_count);

            int target = dfa_add_state(ctx, mm, temp2, tc2, accept_pattern2, (uint16_t)reachable_accepting_patterns2);

            // Handle both literal symbols (sid < BYTE_VALUE_MAX) and virtual symbols (VSYM_BYTE_ANY, VSYM_SPACE, VSYM_TAB)
            int sid = alphabet_arr[i].symbol_id;
            if (sid < BYTE_VALUE_MAX || sid == VSYM_BYTE_ANY || sid == VSYM_SPACE || sid == VSYM_TAB) {
                dfa_arr[cur]->transitions[sid] = target;
                dfa_arr[cur]->marker_offsets[sid] = marker_list_offset;
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
    // NOTE: We allow empty matching for patterns that support it (*, ?, |).
    // The issue was category leakage from is_eos_target states, which we fixed earlier.
    for (int cur = 0; cur < *dfa_count_ptr; cur++) {

        // Find accept NFA state (pattern_id != 0) in this DFA state's set
        int accept_nfa_state = -1;
        for (int j = 0; j < dfa_arr[cur]->nfa_state_count; j++) {
            int nfa_state = dfa_arr[cur]->nfa_states[j];
            if (nfa_arr[nfa_state].pattern_id != 0) {
                accept_nfa_state = nfa_state;
                break;
            }
        }

        if (accept_nfa_state >= 0) {
            // This DFA state contains an accept NFA state - find the DFA state for it
            for (int s = 0; s < *dfa_count_ptr; s++) {
                for (int j = 0; j < dfa_arr[s]->nfa_state_count; j++) {
                    if (dfa_arr[s]->nfa_states[j] == accept_nfa_state) {
                        dfa_arr[cur]->eos_target = s;
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
        for (int j = 0; j < dfa_arr[cur]->nfa_state_count; j++) {
            int nfa_state = dfa_arr[cur]->nfa_states[j];
            // Only accept via empty string if the state has an actual pattern_id
            if (nfa_arr[nfa_state].is_eos_target && nfa_arr[nfa_state].pattern_id != 0) {
                eos_nfa_state = nfa_state;
                break;
            }
        }

        // If no direct EOS target found, check EOS target states for EOS transitions
        // This handles + quantifier where fork state leads to accept state via EOS
        if (eos_nfa_state < 0) {
            for (int j = 0; j < dfa_arr[cur]->nfa_state_count; j++) {
                int nfa_state = dfa_arr[cur]->nfa_states[j];
                if (nfa_arr[nfa_state].is_eos_target) {
                    // Check if this EOS target state has transitions to accepting states
                    int eos_cnt = 0;
                    int* eos_targets = mta_get_target_array(&nfa_arr[nfa_state].multi_targets, 258, &eos_cnt);
                    if (eos_targets) {
                        for (int e = 0; e < eos_cnt; e++) {
                            int eos_t = eos_targets[e];
                            if (nfa_arr[eos_t].pattern_id != 0) {
                                // Found accepting state via EOS transition
                                // Find or create DFA state for this accept state
                                for (int s = 0; s < *dfa_count_ptr; s++) {
                                    for (int k = 0; k < dfa_arr[s]->nfa_state_count; k++) {
                                        if (dfa_arr[s]->nfa_states[k] == eos_t) {
                                            dfa_arr[cur]->eos_target = s;
                                            if (dfa_arr[cur]->accepting_pattern_id == 0) {
                                                dfa_arr[cur]->accepting_pattern_id = nfa_arr[eos_t].pattern_id - 1;
                                                dfa_arr[cur]->flags |= DFA_STATE_ACCEPTING;
                                            }
                                            break;
                                        }
                                    }
                                    if (dfa_arr[cur]->eos_target != 0) break;
                                }
                                break;
                            }
                        }
                    }
                }
                if (eos_nfa_state >= 0 || dfa_arr[cur]->eos_target != 0) break;
            }
        }

        if (eos_nfa_state >= 0) {
            // Find the DFA state that contains this exact EOS target NFA state
            for (int s = 0; s < *dfa_count_ptr; s++) {
                for (int j = 0; j < dfa_arr[s]->nfa_state_count; j++) {
                    if (dfa_arr[s]->nfa_states[j] == eos_nfa_state) {
                        dfa_arr[cur]->eos_target = s;
                        // Also set accepting pattern if not already set
                        if (dfa_arr[cur]->accepting_pattern_id == 0 && nfa_arr[eos_nfa_state].pattern_id != 0) {
                            dfa_arr[cur]->accepting_pattern_id = nfa_arr[eos_nfa_state].pattern_id - 1;  // Convert to 0-based
                            dfa_arr[cur]->flags |= DFA_STATE_ACCEPTING;
                        }
                        break;
                    }
                }
                if (dfa_arr[cur]->eos_target != 0) break;
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

void flatten_dfa(ATTR_UNUSED nfa2dfa_context_t* ctx) {
    build_dfa_state_t** dfa_arr = CTX_DFA(ctx);
    alphabet_entry_t* alphabet_arr = CTX_ALPHABET(ctx);
    int alphabet_sz = CTX_ALPHABET_SIZE(ctx);
    int* dfa_count_ptr = CTX_DFA_COUNT_PTR(ctx, dfa_state_count);
    (void)dfa_arr; (void)alphabet_arr; (void)alphabet_sz; (void)dfa_count_ptr;
    int any_sid = -1;
    int space_sid = -1;
    int tab_sid = -1;

    // Identify virtual symbol IDs
    for (int s = 0; s < alphabet_sz; s++) {
        if (alphabet_arr[s].symbol_id == VSYM_BYTE_ANY) any_sid = s;
        else if (alphabet_arr[s].symbol_id == VSYM_SPACE) space_sid = s;
        else if (alphabet_arr[s].symbol_id == VSYM_TAB) tab_sid = s;
    }
    
    for (int s = 0; s < *dfa_count_ptr; s++) {
        int nt[BYTE_VALUE_MAX]; bool any[BYTE_VALUE_MAX]; uint32_t markers[BYTE_VALUE_MAX];
        for (int i = 0; i < BYTE_VALUE_MAX; i++) { nt[i] = -1; any[i] = false; markers[i] = 0; }

        uint32_t any_marker = (any_sid != -1) ? dfa_arr[s]->marker_offsets[VSYM_BYTE_ANY] : 0;

        // First, set specific symbol transitions
        for (int i = 0; i < alphabet_sz; i++) {
            int sid = alphabet_arr[i].symbol_id;
            if (sid < BYTE_VALUE_MAX && dfa_arr[s]->transitions[sid] != -1) {
                int t = dfa_arr[s]->transitions[sid];
                nt[sid] = t;
                any[sid] = false;
                markers[sid] = dfa_arr[s]->marker_offsets[sid];
            }
        }

        // Override with space and tab transitions (use symbol IDs directly, not alphabet indices)
        if (space_sid != -1 && dfa_arr[s]->transitions[259] != -1) {
            nt[32] = dfa_arr[s]->transitions[259];
            any[32] = false;
            markers[32] = dfa_arr[s]->marker_offsets[259];
        }

        if (tab_sid != -1 && dfa_arr[s]->transitions[260] != -1) {
            nt[9] = dfa_arr[s]->transitions[260];
            any[9] = false;
            markers[9] = dfa_arr[s]->marker_offsets[260];
        }

        // Finally, override with ANY transition (fills in gaps)
        if (any_sid != -1 && dfa_arr[s]->transitions[any_sid] != -1) {
            int t = dfa_arr[s]->transitions[any_sid];
            for (int i = 0; i < BYTE_VALUE_MAX; i++) {
                if (nt[i] == -1) {  // Only fill gaps, don't override specific transitions
                    nt[i] = t;
                    any[i] = true;
                    markers[i] = any_marker;
                }
            }
        }

        int rc = 0;
        for (int i = 0; i < BYTE_VALUE_MAX; i++) {
            if (nt[i] >= *dfa_count_ptr) {
                nt[i] = -1;
            }
            dfa_arr[s]->transitions[i] = nt[i];
            dfa_arr[s]->transitions_from_any[i] = any[i];
            dfa_arr[s]->marker_offsets[i] = markers[i];
            if (nt[i] != -1) rc++;
        }
        for (int i = BYTE_VALUE_MAX; i < MAX_SYMBOLS; i++) {
            dfa_arr[s]->transitions[i] = -1;
            dfa_arr[s]->marker_offsets[i] = 0;
        }
        dfa_arr[s]->transition_count = rc;
    }
}

typedef struct { uint8_t type, d1, d2, d3; int target_state_index; } intermediate_rule_t;

int compress_state_rules(ATTR_UNUSED nfa2dfa_context_t* ctx, int sidx, intermediate_rule_t* out) {
    build_dfa_state_t** dfa_arr = CTX_DFA(ctx);
    int rc = 0, ct = -1, sc = -1;
    // Compress only literal byte transitions (0-255)
    for (int c = 0; c <= BYTE_VALUE_MAX; c++) {
        int t = (c < BYTE_VALUE_MAX) ? dfa_arr[sidx]->transitions[c] : -1;
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

/* ============================================================================
 * Packed encoding helpers
 * ============================================================================ */

#define PACK_MAX_GROUPS 256
typedef struct { int target_idx; uint8_t chars[256]; int nchars; } pack_group_t;
typedef struct { uint8_t start; uint8_t end; int target_idx; bool is_default; } pack_entry_t;

/* Compute packed entries preserving first-match order.
 * 
 * Rules are evaluated first-match. We scan in original order and merge
 * only CONSECUTIVE rules that share the same target into ranges.
 * Rules with different targets between them cannot be merged.
 *
 * DEFAULT rules (wildcards) are emitted as is_default=true entries.
 * These are written as bitmask rules in the binary.
 *
 * Example: a->1, z->2, b->1 → entries: [a->1], [z->2], [b->1]
 *          a->1, b->1, c->1 → entries: [a-c->1] (merged)
 *          DEFAULT->1       → entries: [DEFAULT->1]
 */
static int compute_packed_entries(ATTR_UNUSED nfa2dfa_context_t* ctx, ATTR_UNUSED int state_idx, const intermediate_rule_t* rules, int rule_count,
                                   pack_entry_t* entries, int max_entries) {
    (void)ctx;
    (void)state_idx;
    int ne = 0;
    int cur_target = -1;
    uint8_t range_start = 0, range_end = 0;
    bool cur_is_default = false;
    
    for (int r = 0; r < rule_count && ne < max_entries; r++) {
        int tidx = rules[r].target_state_index;
        uint8_t rtype = rules[r].type;
        uint8_t ch = rules[r].d1;
        uint8_t ch2 = rules[r].d2;
        
        if (rtype == DFA_RULE_DEFAULT) {
            // Emit previous range (if any)
            if (cur_target >= 0) {
                entries[ne].start = range_start;
                entries[ne].end = range_end;
                entries[ne].target_idx = cur_target;
                entries[ne].is_default = cur_is_default;
                ne++;
            }
            // Emit DEFAULT entry
            entries[ne].start = 0;
            entries[ne].end = 0;
            entries[ne].target_idx = tidx;
            entries[ne].is_default = true;
            ne++;
            cur_target = -1;
            cur_is_default = false;
        } else if (rtype == DFA_RULE_RANGE) {
            // RANGE rule: covers d1..d2
            // Emit previous range (if any)
            if (cur_target >= 0) {
                entries[ne].start = range_start;
                entries[ne].end = range_end;
                entries[ne].target_idx = cur_target;
                entries[ne].is_default = cur_is_default;
                ne++;
            }
            // Emit range entry
            if (ne < max_entries) {
                entries[ne].start = ch;
                entries[ne].end = ch2;
                entries[ne].target_idx = tidx;
                entries[ne].is_default = false;
                ne++;
            }
            cur_target = -1;
        } else if (rtype == DFA_RULE_LITERAL_2 || rtype == DFA_RULE_LITERAL_3) {
            // LITERAL_2: matches d1 or d2. LITERAL_3: matches d1, d2, or d3.
            // Emit as separate literal entries preserving order
            if (cur_target >= 0) {
                entries[ne].start = range_start;
                entries[ne].end = range_end;
                entries[ne].target_idx = cur_target;
                entries[ne].is_default = cur_is_default;
                ne++;
            }
            cur_target = -1;
            // Emit d1
            if (ne < max_entries) {
                entries[ne].start = ch; entries[ne].end = ch;
                entries[ne].target_idx = tidx; entries[ne].is_default = false;
                ne++;
            }
            // Emit d2
            if (ne < max_entries) {
                entries[ne].start = ch2; entries[ne].end = ch2;
                entries[ne].target_idx = tidx; entries[ne].is_default = false;
                ne++;
            }
            // Emit d3 (LITERAL_3 only)
            if (rtype == DFA_RULE_LITERAL_3 && ne < max_entries) {
                uint8_t ch3 = rules[r].d3;
                entries[ne].start = ch3; entries[ne].end = ch3;
                entries[ne].target_idx = tidx; entries[ne].is_default = false;
                ne++;
            }
        } else if (rtype == DFA_RULE_RANGE_LITERAL) {
            // RANGE_LITERAL: matches d1..d2 or d3
            if (cur_target >= 0) {
                entries[ne].start = range_start; entries[ne].end = range_end;
                entries[ne].target_idx = cur_target; entries[ne].is_default = cur_is_default;
                ne++;
            }
            cur_target = -1;
            // Emit range d1..d2
            if (ne < max_entries) {
                entries[ne].start = ch; entries[ne].end = ch2;
                entries[ne].target_idx = tidx; entries[ne].is_default = false;
                ne++;
            }
            // Emit literal d3
            if (ne < max_entries) {
                uint8_t ch3 = rules[r].d3;
                entries[ne].start = ch3; entries[ne].end = ch3;
                entries[ne].target_idx = tidx; entries[ne].is_default = false;
                ne++;
            }
        } else if (rtype == DFA_RULE_NOT_LITERAL || rtype == DFA_RULE_NOT_RANGE) {
            // NOT rules: emit as DEFAULT (match anything not covered by other rules)
            if (cur_target >= 0) {
                entries[ne].start = range_start; entries[ne].end = range_end;
                entries[ne].target_idx = cur_target; entries[ne].is_default = cur_is_default;
                ne++;
            }
            cur_target = -1;
            // Emit as DEFAULT-like entry (covers all chars not matched by preceding rules)
            if (ne < max_entries) {
                entries[ne].start = 0; entries[ne].end = 0;
                entries[ne].target_idx = tidx; entries[ne].is_default = true;
                ne++;
            }
        } else if (tidx == cur_target && ch == range_end + 1 && !cur_is_default) {
            // Extend current range with same target
            range_end = ch;
        } else {
            // Emit previous range (if any)
            if (cur_target >= 0) {
                entries[ne].start = range_start;
                entries[ne].end = range_end;
                entries[ne].target_idx = cur_target;
                entries[ne].is_default = cur_is_default;
                ne++;
            }
            // Start new range
            cur_target = tidx;
            range_start = ch;
            range_end = ch;
            cur_is_default = false;
        }
    }
    // Emit final range
    if (cur_target >= 0 && ne < max_entries) {
        entries[ne].start = range_start;
        entries[ne].end = range_end;
        entries[ne].target_idx = cur_target;
        entries[ne].is_default = cur_is_default;
        ne++;
    }
    return ne;
}

void write_dfa_file(ATTR_UNUSED nfa2dfa_context_t* ctx, const char* filename) {
    build_dfa_state_t** dfa_arr = CTX_DFA(ctx);
    int dfa_count = CTX_DFA_COUNT(ctx);
    MarkerList* marker_lists = CTX_MARKER_LISTS(ctx);
    int marker_count = CTX_MARKER_COUNT(ctx);
    (void)dfa_arr; (void)dfa_count; (void)marker_lists; (void)marker_count;
    
    FILE* file = fopen(filename, "wb");
    if (!file) { FATAL_SYS("Cannot open '%s' for writing", filename); exit(EXIT_FAILURE); }
    
#define DFA_CACHE_LINE_SIZE 64
#define DFA_MAX_ALIGNMENT_SLACK 5
    
    /* ====================================================================
     * PHASE 1: PRE-WRITE - collect rules, compute maxima
     * ==================================================================== */
    
    size_t alloc_size = (size_t)dfa_count * MAX_SYMBOLS * sizeof(intermediate_rule_t);
    if (dfa_count > 0 && alloc_size / sizeof(intermediate_rule_t) / MAX_SYMBOLS != (size_t)dfa_count) {
        FATAL("Integer overflow in rule allocation"); exit(EXIT_FAILURE);
    }
    intermediate_rule_t* all_rules = alloc_or_abort(malloc(alloc_size), "Rules");
    
    int* rule_counts = malloc(dfa_count * sizeof(int));
    if (!rule_counts) { FATAL("Failed to allocate rule counts"); exit(EXIT_FAILURE); }
    
    uint32_t max_offset = 0;
    uint32_t max_count = 0;
    uint32_t max_pid = 0;
    size_t total_rules = 0;
    
    for (int i = 0; i < dfa_count; i++) {
        rule_counts[i] = compress_state_rules(ctx, i, &all_rules[i * MAX_SYMBOLS]);
        total_rules += rule_counts[i];
        if ((uint32_t)rule_counts[i] > max_count) max_count = (uint32_t)rule_counts[i];
        if (dfa_arr[i]->accepting_pattern_id != 0xFFFF && dfa_arr[i]->accepting_pattern_id > max_pid)
            max_pid = dfa_arr[i]->accepting_pattern_id;
    }
    size_t id_len = strlen(CTX_PATTERN_ID(ctx));
    
    size_t marker_data_size = 0;
    for (int i = 0; i < dfa_count; i++) {
        for (int r = 0; r < rule_counts[i] && r < 256; r++) {
            uint32_t list_idx = dfa_arr[i]->marker_offsets[all_rules[i * MAX_SYMBOLS + r].d1];
            if (list_idx > 0 && list_idx <= (uint32_t)marker_count) {
                MarkerList* ml = &marker_lists[list_idx - 1];
                marker_data_size += (ml->count + 1) * sizeof(uint32_t);
            }
        }
        if (dfa_arr[i]->eos_marker_offset > 0 && dfa_arr[i]->eos_marker_offset <= (uint32_t)marker_count) {
            MarkerList* ml = &marker_lists[dfa_arr[i]->eos_marker_offset - 1];
            marker_data_size += (ml->count + 1) * sizeof(uint32_t);
        }
    }
    
    /* ====================================================================
     * PHASE 2: OPTIMISE LAYOUT - pick encoding, compute sizes
     * ==================================================================== */
    
    // Rough upper bound for offsets
    max_offset = (uint32_t)(DFA_HEADER_FIXED + 2*4 + id_len
                 + (size_t)dfa_count * DFA_STATE_SIZE(DFA_W4)
                 + total_rules * DFA_RULE_SIZE(DFA_W4)
                 + marker_data_size);
    
    int enc_ow = dfa_best_ow(max_offset);
    int enc_cw = dfa_best_cw(max_count);
    int enc_pw = dfa_best_pw(max_pid);
    int enc = dfa_make_enc(enc_ow, enc_cw, enc_pw);
    
    int state_size = DFA_STATE_SIZE(enc);
    int rule_size  = DFA_RULE_SIZE(enc);
    int lit_size = DFA_PACK_LITERAL_SIZE(enc);
    int rng_size = DFA_PACK_RANGE_SIZE(enc);
    size_t header_size = DFA_HEADER_SIZE(enc, (uint8_t)id_len) + 8;
    
    // Per-state encoding and packed sizes
    int* rule_encoding = calloc(dfa_count, sizeof(int));
    int* n_entries = calloc(dfa_count, sizeof(int));
    size_t* packed_sizes = calloc(dfa_count, sizeof(size_t));
    pack_entry_t* tmp_entries = malloc(MAX_SYMBOLS * sizeof(pack_entry_t));
    
    size_t element_size = (rng_size > lit_size ? rng_size : lit_size);
    size_t packed_data_size = (size_t)dfa_count * MAX_SYMBOLS;
    if (dfa_count > 0 && packed_data_size / dfa_count != MAX_SYMBOLS) {
        FATAL("Integer overflow calculating packed data size");
        exit(EXIT_FAILURE);
    }
    packed_data_size *= element_size;
    uint8_t* packed_data = malloc(packed_data_size);
    size_t* packed_data_offset = malloc((size_t)dfa_count * sizeof(size_t));
size_t packed_data_used = 0;
     
    for (int i = 0; i < dfa_count; i++) {
        if (rule_counts[i] == 0) {
            n_entries[i] = 0;
            packed_sizes[i] = 0;
            packed_data_offset[i] = 0;
            rule_encoding[i] = DFA_RULE_ENC_NORMAL;
            continue;
        }
        // States with markers must use normal encoding (packed format has no marker slot)
        // Check both marker_offsets and eos_marker_offset for markers.
        bool has_markers = false;
        if (dfa_arr[i]->eos_marker_offset != 0) has_markers = true;
        for (int r = 0; r < rule_counts[i] && !has_markers; r++) {
            if (dfa_arr[i]->marker_offsets[all_rules[i * MAX_SYMBOLS + r].d1] != 0)
                has_markers = true;
        }
        rule_encoding[i] = has_markers ? DFA_RULE_ENC_NORMAL : DFA_RULE_ENC_PACKED;
        if (has_markers) {
            // Normal encoding uses fixed-stride rules (rule_size each).
            // Don't compute packed entries — just note normal encoding.
            packed_sizes[i] = 0;
            packed_data_offset[i] = 0;
            n_entries[i] = rule_counts[i];
            continue;
        }
        
        // Count actual transitions (including ranges)
        int actual_transitions = 0;
        for (int r = 0; r < rule_counts[i]; r++) {
            intermediate_rule_t* rule = &all_rules[i * MAX_SYMBOLS + r];
            if (rule->type == DFA_RULE_LITERAL) actual_transitions++;
            else if (rule->type == DFA_RULE_RANGE) actual_transitions += (rule->d2 - rule->d1 + 1);
            else if (rule->type == DFA_RULE_LITERAL_2) actual_transitions += 2;
            else if (rule->type == DFA_RULE_LITERAL_3) actual_transitions += 3;
            else if (rule->type == DFA_RULE_RANGE_LITERAL) actual_transitions += (rule->d2 - rule->d1 + 2);
            else if (rule->type == DFA_RULE_DEFAULT) actual_transitions = 256;
            else if (rule->type == DFA_RULE_NOT_LITERAL) actual_transitions += 255;
            else if (rule->type == DFA_RULE_NOT_RANGE) actual_transitions += (256 - (rule->d2 - rule->d1 + 1));
        }
        
        // Use bitmask encoding for states with many transitions (character classes)
        // Bitmask is 1 + 32 + OW + 4 = ~39 bytes per unique target
        // Packed is ~3-4 bytes per RULE (not per transition - ranges are compact!)
        // So bitmask is only better when we have MANY rules with few unique targets
        int bitmask_rule_size = 1 + 32 + dfa_owb(enc) + 4;
        
        // Group rules by unique target first
        int unique_targets = 0;
        int target_list[MAX_SYMBOLS];
        for (int r = 0; r < rule_counts[i]; r++) {
            int tidx = all_rules[i * MAX_SYMBOLS + r].target_state_index;
            bool found = false;
            for (int t = 0; t < unique_targets; t++) {
                if (target_list[t] == tidx) { found = true; break; }
            }
            if (!found) target_list[unique_targets++] = tidx;
        }
        
        // Calculate packed size based on actual rules (not transitions)
        size_t pbs_actual = 0;
        for (int r = 0; r < rule_counts[i]; r++) {
            intermediate_rule_t* rule = &all_rules[i * MAX_SYMBOLS + r];
            if (rule->type == DFA_RULE_LITERAL || rule->type == DFA_RULE_NOT_LITERAL) {
                pbs_actual += lit_size;
            } else if (rule->type == DFA_RULE_RANGE || rule->type == DFA_RULE_NOT_RANGE) {
                pbs_actual += rng_size;
            } else if (rule->type == DFA_RULE_LITERAL_2) {
                pbs_actual += 2 * lit_size;
            } else if (rule->type == DFA_RULE_LITERAL_3) {
                pbs_actual += 3 * lit_size;
            } else if (rule->type == DFA_RULE_RANGE_LITERAL) {
                pbs_actual += rng_size + lit_size;
            } else if (rule->type == DFA_RULE_DEFAULT) {
                pbs_actual += lit_size;  // Default is one entry
            }
        }
        
        size_t bms = (size_t)unique_targets * bitmask_rule_size;
        
        // Only use bitmask if it's actually smaller than packed
        if (bms < pbs_actual) {
            rule_encoding[i] = DFA_RULE_ENC_BITMASK;
            packed_sizes[i] = 0;
            packed_data_offset[i] = 0;
            n_entries[i] = unique_targets;
            // Store unique target count for bitmask rules
            rule_counts[i] = unique_targets;
            continue;
        }
        int ne = compute_packed_entries(ctx, i, &all_rules[i * MAX_SYMBOLS],
                                         rule_counts[i], tmp_entries, MAX_SYMBOLS);
        // Compute exact byte size matching how entries will be written
        size_t pbs = 0; int actual_ne = 0;
        for (int e = 0; e < ne; e++) {
            if (tmp_entries[e].start == tmp_entries[e].end) {
                pbs += lit_size; actual_ne++;
            } else if (tmp_entries[e].end <= 127) {
                pbs += rng_size; actual_ne++;
            } else if (tmp_entries[e].start <= 127) {
                pbs += rng_size; actual_ne++;
                int extra = tmp_entries[e].end - 127;
                pbs += (size_t)extra * lit_size; actual_ne += extra;
            } else {
                int cnt = tmp_entries[e].end - tmp_entries[e].start + 1;
                pbs += (size_t)cnt * lit_size; actual_ne += cnt;
            }
        }
        n_entries[i] = actual_ne;
        packed_sizes[i] = pbs;
        packed_data_offset[i] = packed_data_used;
        packed_data_used += pbs;
}
     
    // Compute state offsets with cache-line alignment
    size_t* state_offset = malloc(dfa_count * sizeof(size_t));
    size_t* rule_offset  = malloc(dfa_count * sizeof(size_t));
    
    size_t cur = header_size;
    for (int i = 0; i < dfa_count; i++) {
        int mis = cur % DFA_CACHE_LINE_SIZE;
        int pad = mis ? (DFA_CACHE_LINE_SIZE - mis) : 0;
        bool hot = (i == 0 || (dfa_arr[i]->flags & DFA_STATE_ACCEPTING));
        bool align = (mis && (hot ? pad <= DFA_MAX_ALIGNMENT_SLACK*4 : pad <= DFA_MAX_ALIGNMENT_SLACK));
        if (align) cur += pad;
        state_offset[i] = cur;
        cur += (rule_counts[i] == 0) ? DFA_STATE_SIZE_COMPACT(enc) : state_size;
    }
    
    // Write packed data to temp buffer for deduplication comparison
    pack_entry_t* write_entries = malloc(MAX_SYMBOLS * sizeof(pack_entry_t));
    for (int i = 0; i < dfa_count; i++) {
        if (rule_counts[i] == 0 || rule_encoding[i] != DFA_RULE_ENC_PACKED) continue;
        int ne = compute_packed_entries(ctx, i, &all_rules[i * MAX_SYMBOLS],
                                         rule_counts[i], write_entries, MAX_SYMBOLS);
        size_t off = 0;
        for (int e = 0; e < ne; e++) {
            uint32_t target = (uint32_t)state_offset[write_entries[e].target_idx];
            if (write_entries[e].start == write_entries[e].end) {
                dfa_pack_write_literal(packed_data + packed_data_offset[i] + off, write_entries[e].start, enc, target);
                off += lit_size;
            } else if (write_entries[e].end <= 127) {
                dfa_pack_write_range(packed_data + packed_data_offset[i] + off, write_entries[e].start, write_entries[e].end, enc, target);
                off += rng_size;
            } else {
                for (int ch = write_entries[e].start; ch <= write_entries[e].end; ch++) {
                    dfa_pack_write_literal(packed_data + packed_data_offset[i] + off, (uint8_t)ch, enc, target);
                    off += lit_size;
                }
            }
        }
    }
    
    // Rule offsets with deduplication
    for (int i = 0; i < dfa_count; i++) {
        if (rule_counts[i] == 0) {
            rule_offset[i] = cur;
            continue;
        }
        if (rule_encoding[i] == DFA_RULE_ENC_NORMAL) {
            // Normal encoding: fixed-stride rules, space = rule_counts * rule_size
            // No deduplication for normal (different per-state targets)
            rule_offset[i] = cur;
            cur += (size_t)rule_counts[i] * (size_t)rule_size;
            continue;
        }
        if (rule_encoding[i] == DFA_RULE_ENC_BITMASK) {
            // Bitmask encoding: one bitmask rule per target
            int bms = DFA_RULE_BITMASK_SIZE(enc);
            rule_offset[i] = cur;
            cur += (size_t)rule_counts[i] * bms;
            continue;
        }
        if (packed_sizes[i] == 0) {
            rule_offset[i] = cur;
            continue;
        }
        // Check if this state's packed data matches a previous state
        bool found_dup = false;
        for (int j = 0; j < i; j++) {
            if (packed_sizes[j] == packed_sizes[i] && packed_sizes[i] > 0 &&
                memcmp(packed_data + packed_data_offset[j],
                       packed_data + packed_data_offset[i],
                       packed_sizes[i]) == 0) {
                rule_offset[i] = rule_offset[j];
                found_dup = true;
                break;
            }
        }
        if (!found_dup) {
            rule_offset[i] = cur;
            cur += packed_sizes[i];
        }
    }
    
    // Collect Pattern ID data for separate section (V10)
    // Each entry: state_offset + pattern_id
    typedef struct { uint32_t state_off; uint16_t pid; } pid_entry_t;
    pid_entry_t* pid_entries = malloc(dfa_count * sizeof(pid_entry_t));
    int pid_count = 0;
    
    for (int i = 0; i < dfa_count; i++) {
        if (dfa_arr[i]->accepting_pattern_id != 0 && dfa_arr[i]->accepting_pattern_id != UINT16_MAX) {
            pid_entries[pid_count].state_off = (uint32_t)state_offset[i];
            pid_entries[pid_count].pid = dfa_arr[i]->accepting_pattern_id;
            pid_count++;
        }
    }
    
    // Sort Pattern ID entries by state_off
    for (int i = 1; i < pid_count; i++) {
        pid_entry_t tmp = pid_entries[i];
        int j = i - 1;
        while (j >= 0 && pid_entries[j].state_off > tmp.state_off) {
            pid_entries[j + 1] = pid_entries[j];
            j--;
        }
        pid_entries[j + 1] = tmp;
    }
    
    // Collect EOS data for separate EOS section (V9)
    // Each entry: state_offset + target_or_marker
    typedef struct { uint32_t state_off; uint32_t value; } eos_entry_t;
    eos_entry_t* eos_targets = malloc(dfa_count * sizeof(eos_entry_t));
    eos_entry_t* eos_markers = malloc(dfa_count * sizeof(eos_entry_t));
    int eos_target_count = 0;
    int eos_marker_count = 0;
    
    for (int i = 0; i < dfa_count; i++) {
        if (dfa_arr[i]->eos_target > 0 && dfa_arr[i]->eos_target < (uint32_t)dfa_count) {
            eos_targets[eos_target_count].state_off = (uint32_t)state_offset[i];
            eos_targets[eos_target_count].value = (uint32_t)state_offset[dfa_arr[i]->eos_target];
            eos_target_count++;
        }
        if (dfa_arr[i]->eos_marker_offset != 0) {
            eos_markers[eos_marker_count].state_off = (uint32_t)state_offset[i];
            eos_markers[eos_marker_count].value = dfa_arr[i]->eos_marker_offset;
            eos_marker_count++;
        }
    }
    
    // Sort EOS entries by state_off (simple insertion sort - entries are mostly sorted)
    for (int i = 1; i < eos_target_count; i++) {
        eos_entry_t tmp = eos_targets[i];
        int j = i - 1;
        while (j >= 0 && eos_targets[j].state_off > tmp.state_off) {
            eos_targets[j + 1] = eos_targets[j];
            j--;
        }
        eos_targets[j + 1] = tmp;
    }
    for (int i = 1; i < eos_marker_count; i++) {
        eos_entry_t tmp = eos_markers[i];
        int j = i - 1;
        while (j >= 0 && eos_markers[j].state_off > tmp.state_off) {
            eos_markers[j + 1] = eos_markers[j];
            j--;
        }
        eos_markers[j + 1] = tmp;
    }
    
    // Compute section sizes
    size_t pid_section_size = DFA_PID_SECTION_SIZE(pid_count, enc);
    size_t eos_section_size = DFA_EOS_SECTION_SIZE(eos_target_count, eos_marker_count, enc);
    size_t pid_offset = cur;  // Pattern ID section starts after rules
    size_t eos_offset = cur + pid_section_size;  // EOS section after PID section
    
    size_t metadata_offset = cur + pid_section_size + eos_section_size;
    size_t total_size = metadata_offset + marker_data_size;
    
    /* ====================================================================
     * PHASE 3: WRITE - allocate buffer, write all fields via accessors
     * ==================================================================== */
    
    uint8_t* raw = calloc(1, total_size);
    if (!raw) { FATAL("Failed to allocate DFA buffer (%zu bytes)", total_size); exit(EXIT_FAILURE); }
    
    // Header
    dfa_fmt_set_magic(raw, DFA_MAGIC);
    dfa_fmt_set_version(raw, DFA_VERSION);
    dfa_fmt_set_state_count(raw, (uint16_t)dfa_count);
    dfa_fmt_set_encoding(raw, (uint8_t)enc);
    dfa_fmt_set_id_len(raw, (uint8_t)id_len);
    dfa_fmt_set_initial_state(raw, enc, (uint32_t)state_offset[0]);
    dfa_fmt_set_meta_offset(raw, enc, 0);
    dfa_fmt_set_eos_offset(raw, enc, (uint32_t)eos_offset);  // V9: EOS section offset
    dfa_fmt_set_pid_offset(raw, enc, (uint32_t)pid_offset);  // V10: Pattern ID section offset
    memcpy(raw + DFA_HEADER_SIZE(enc, (uint8_t)id_len) - id_len, CTX_PATTERN_ID(ctx), id_len);
    
    // States (compact for empty, full for active)
    for (int i = 0; i < dfa_count; i++) {
        size_t so = state_offset[i];
        dfa_fmt_set_st_tc(raw, so, enc, (uint16_t)rule_counts[i]);
        if (rule_counts[i] > 0) {
            dfa_fmt_set_st_rules(raw, so, enc, (uint32_t)rule_offset[i]);
            uint16_t flags = dfa_arr[i]->flags;
            DFA_SET_RULE_ENC(flags, rule_encoding[i]);
            dfa_fmt_set_st_flags(raw, so, enc, flags);
            dfa_fmt_set_st_first(raw, so, enc, (uint16_t)n_entries[i]);
        } else {
            int cof = dfa_st_off_flags_c(enc);
            dfa_w16(raw, so + cof, dfa_arr[i]->flags);
            dfa_wwp(raw, so + cof + 2, enc, 0);  /* first */
        }
    }
    
    // Rules (packed or normal per state)
    for (int i = 0; i < dfa_count; i++) {
        if (rule_counts[i] == 0) continue;
        if (rule_encoding[i] == DFA_RULE_ENC_PACKED) {
            int ne = compute_packed_entries(ctx, i, &all_rules[i * MAX_SYMBOLS],
                                             rule_counts[i], write_entries, MAX_SYMBOLS);
            size_t off = 0;
            for (int e = 0; e < ne; e++) {
                uint32_t target = (uint32_t)state_offset[write_entries[e].target_idx];
                if (write_entries[e].start == write_entries[e].end) {
                    dfa_pack_write_literal(raw + rule_offset[i] + off, write_entries[e].start, enc, target);
                    off += lit_size;
                } else if (write_entries[e].end <= 127) {
                    dfa_pack_write_range(raw + rule_offset[i] + off, write_entries[e].start, write_entries[e].end, enc, target);
                    off += rng_size;
                } else if (write_entries[e].start <= 127) {
                    dfa_pack_write_range(raw + rule_offset[i] + off, write_entries[e].start, 127, enc, target);
                    off += rng_size;
                    for (int ch = 128; ch <= write_entries[e].end; ch++) {
                        dfa_pack_write_literal(raw + rule_offset[i] + off, (uint8_t)ch, enc, target);
                        off += lit_size;
                    }
                } else {
                    for (int ch = write_entries[e].start; ch <= write_entries[e].end; ch++) {
                        dfa_pack_write_literal(raw + rule_offset[i] + off, (uint8_t)ch, enc, target);
                        off += lit_size;
                    }
                }
            }
        } else if (rule_encoding[i] == DFA_RULE_ENC_BITMASK) {
            // Bitmask encoding: group rules by target, write one bitmask per unique target
            int bms = DFA_RULE_BITMASK_SIZE(enc);
            
            // Collect unique targets and their bitmasks
            int unique_targets = 0;
            int target_list[MAX_SYMBOLS];
            uint8_t target_masks[MAX_SYMBOLS][32];
            memset(target_masks, 0, sizeof(target_masks));
            
            for (int r = 0; r < rule_counts[i]; r++) {
                intermediate_rule_t* rule = &all_rules[i * MAX_SYMBOLS + r];
                int tidx = rule->target_state_index;
                
                // Find or create target entry
                int target_idx = -1;
                for (int t = 0; t < unique_targets; t++) {
                    if (target_list[t] == tidx) { target_idx = t; break; }
                }
                if (target_idx < 0) {
                    target_idx = unique_targets++;
                    target_list[target_idx] = tidx;
                }
                
                // Add characters to bitmask
                uint8_t* mask = target_masks[target_idx];
                if (rule->type == DFA_RULE_LITERAL) {
                    mask[rule->d1 / 8] |= (1 << (rule->d1 % 8));
                } else if (rule->type == DFA_RULE_RANGE) {
                    for (int ch = rule->d1; ch <= rule->d2; ch++) {
                        mask[ch / 8] |= (1 << (ch % 8));
                    }
                } else if (rule->type == DFA_RULE_LITERAL_2) {
                    mask[rule->d1 / 8] |= (1 << (rule->d1 % 8));
                    mask[rule->d2 / 8] |= (1 << (rule->d2 % 8));
                } else if (rule->type == DFA_RULE_LITERAL_3) {
                    mask[rule->d1 / 8] |= (1 << (rule->d1 % 8));
                    mask[rule->d2 / 8] |= (1 << (rule->d2 % 8));
                    mask[rule->d3 / 8] |= (1 << (rule->d3 % 8));
                } else if (rule->type == DFA_RULE_RANGE_LITERAL) {
                    for (int ch = rule->d1; ch <= rule->d2; ch++) {
                        mask[ch / 8] |= (1 << (ch % 8));
                    }
                    mask[rule->d3 / 8] |= (1 << (rule->d3 % 8));
                } else if (rule->type == DFA_RULE_DEFAULT) {
                    memset(mask, 0xFF, 32);
                } else if (rule->type == DFA_RULE_NOT_LITERAL) {
                    memset(mask, 0xFF, 32);
                    mask[rule->d1 / 8] &= ~(1 << (rule->d1 % 8));
                } else if (rule->type == DFA_RULE_NOT_RANGE) {
                    memset(mask, 0xFF, 32);
                    for (int ch = rule->d1; ch <= rule->d2; ch++) {
                        mask[ch / 8] &= ~(1 << (ch % 8));
                    }
                }
            }
            
            // Write bitmask rules
            for (int t = 0; t < unique_targets; t++) {
                size_t ro = rule_offset[i] + (size_t)t * bms;
                int tidx = target_list[t];
                if (tidx < 0 || tidx >= dfa_count) {
                    FATAL("State %d bitmask target %d out of bounds", i, tidx);
                    exit(EXIT_FAILURE);
                }
                
                dfa_fmt_set_rl_type(raw, ro, DFA_RULE_BITMASK);
                memcpy(raw + ro + DFA_BM_OFF_MASK, target_masks[t], 32);
                dfa_wow(raw, ro + DFA_BM_OFF_TARGET, enc, (uint32_t)state_offset[tidx]);
                dfa_w32(raw, ro + DFA_BM_OFF_TARGET + dfa_owb(enc), 0);  // markers = 0
            }
        } else {
            for (int r = 0; r < rule_counts[i]; r++) {
                size_t ro = rule_offset[i] + (size_t)r * rule_size;
                dfa_fmt_set_rl_type(raw, ro, all_rules[i * MAX_SYMBOLS + r].type);
                dfa_fmt_set_rl_d1(raw, ro, all_rules[i * MAX_SYMBOLS + r].d1);
                dfa_fmt_set_rl_d2(raw, ro, all_rules[i * MAX_SYMBOLS + r].d2);
                dfa_fmt_set_rl_d3(raw, ro, 0);
                dfa_fmt_set_rl_markers(raw, ro, enc, 0);
                int tidx = all_rules[i * MAX_SYMBOLS + r].target_state_index;
                if (tidx < 0 || tidx >= dfa_count) {
                    FATAL("State %d rule %d target index %d out of bounds", i, r, tidx);
                    exit(EXIT_FAILURE);
                }
                dfa_fmt_set_rl_target(raw, ro, enc, (uint32_t)state_offset[tidx]);
            }
        }
    }
    free(write_entries);
    
    // Pattern ID Section (V10) - write sparse pattern_id data
    {
        uint8_t* pid_base = raw + pid_offset;
        dfa_fmt_set_pid_count(pid_base, (uint16_t)pid_count);
        
        // Write Pattern ID entries
        uint8_t* pid_ent = pid_base + DFA_PID_HEADER_SIZE;
        for (int i = 0; i < pid_count; i++) {
            dfa_fmt_set_pid_entry(pid_ent, pid_entries[i].state_off, pid_entries[i].pid, enc);
            pid_ent += DFA_PID_ENTRY_SIZE(enc);
        }
    }
    free(pid_entries);
    
    // EOS Section (V9) - write sparse EOS data
    {
        uint8_t* eos_base = raw + eos_offset;
        dfa_fmt_set_eos_target_count(eos_base, (uint16_t)eos_target_count);
        dfa_fmt_set_eos_marker_count(eos_base, (uint16_t)eos_marker_count);
        
        // Write EOS targets
        uint8_t* eos_tgt = eos_base + DFA_EOS_HEADER_SIZE;
        for (int i = 0; i < eos_target_count; i++) {
            dfa_fmt_set_eos_target_entry(eos_tgt, eos_targets[i].state_off, eos_targets[i].value, enc);
            eos_tgt += DFA_EOS_TARGET_ENTRY_SIZE(enc);
        }
        
        // Write EOS markers
        uint8_t* eos_mkr = eos_tgt;
        for (int i = 0; i < eos_marker_count; i++) {
            dfa_fmt_set_eos_marker_entry(eos_mkr, eos_markers[i].state_off, eos_markers[i].value, enc);
            eos_mkr += DFA_EOS_MARKER_ENTRY_SIZE(enc);
        }
    }
    free(eos_targets);
    free(eos_markers);
    
    // Markers
    if (marker_count > 0) {
        dfa_fmt_set_meta_offset(raw, enc, (uint32_t)metadata_offset);
        uint32_t* mbase = (uint32_t*)(raw + metadata_offset);
        size_t moff = 0;
        for (int i = 0; i < dfa_count; i++) {
            if (rule_encoding[i] != DFA_RULE_ENC_NORMAL) continue;  // Skip packed/bitmask states
            for (int r = 0; r < rule_counts[i] && r < 256; r++) {
                size_t ro = rule_offset[i] + (size_t)r * rule_size;
                uint32_t lidx = dfa_arr[i]->marker_offsets[all_rules[i * MAX_SYMBOLS + r].d1];
                if (lidx > 0 && lidx <= (uint32_t)marker_count) {
                    MarkerList* ml = &marker_lists[lidx - 1];
                    dfa_fmt_set_rl_markers(raw, ro, enc, (uint32_t)(metadata_offset + moff * 4));
                    mbase[moff++] = (uint32_t)ml->count;
                    for (int m = 0; m < ml->count; m++) mbase[moff++] = ml->markers[m];
                }
            }
        }
    }
    
    size_t hs = DFA_HEADER_SIZE(enc, (uint8_t)id_len);
    uint8_t hdr_copy[hs + 8];
    memcpy(hdr_copy, raw, hs);
    memset(hdr_copy + hs, 0, 8);
    uint32_t crc = crc32c(hdr_copy, hs);
    uint32_t fnv = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < hs; i++) { fnv ^= hdr_copy[i]; fnv *= FNV_PRIME; }
    dfa_fmt_set_checksum_crc32(raw, crc);
    dfa_fmt_set_checksum_fnv32(raw, fnv);
    
    size_t written = fwrite(raw, 1, total_size, file);
    if (written != total_size) {
        FATAL_SYS("Failed to write DFA file '%s' (wrote %zu of %zu bytes)", filename, written, total_size);
    }
    
    if (CTX_FLAG_VERBOSE(ctx)) {
        int ac = 0, hc = 0;
        for (int i = 0; i < dfa_count; i++) {
            if (state_offset[i] % DFA_CACHE_LINE_SIZE == 0) {
                ac++;
                if (i == 0 || (dfa_arr[i]->flags & DFA_STATE_ACCEPTING)) hc++;
            }
        }
        fprintf(stderr, "DFA v%d: %zu bytes, %d states, %zu rules, enc=0x%02X (ow=%d cw=%d pw=%d)\n",
                DFA_VERSION, total_size, dfa_count, total_rules, enc, enc_ow, enc_cw, enc_pw);
        fprintf(stderr, "  state_size=%d rule_size=%d header_size=%zu aligned=%d/%d hot=%d\n",
                state_size, rule_size, header_size, ac, dfa_count, hc);
    }
    
    fclose(file); free(raw); free(all_rules);
    free(rule_counts); free(state_offset); free(rule_offset);
    free(rule_encoding); free(n_entries); free(packed_sizes); free(tmp_entries);
}

void load_nfa_file(ATTR_UNUSED nfa2dfa_context_t* ctx, const char* filename) {
    nfa_state_t* nfa_arr = CTX_NFA(ctx);
    alphabet_entry_t* alphabet_arr = CTX_ALPHABET(ctx);
    int* nfa_count_ptr = CTX_NFA_COUNT_PTR(ctx, nfa_state_count);
    int* alphabet_size_ptr = CTX_ALPHABET_SIZE_PTR(ctx, alphabet_size);
    (void)nfa_arr; (void)alphabet_arr; (void)nfa_count_ptr; (void)alphabet_size_ptr;
    
    FILE* file = fopen(filename, "r");
    if (!file) { FATAL_SYS("Cannot open NFA file '%s'", filename); exit(EXIT_FAILURE); }
    char line[1024]; 
    if (!fgets(line, sizeof(line), file)) { FATAL("Empty NFA file"); exit(EXIT_FAILURE); }
    if (!strstr(line, "NFA_ALPHABET")) { FATAL("Invalid NFA header"); exit(EXIT_FAILURE); }
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "Identifier:", 11) == 0) sscanf(line + 11, "%255s", CTX_PATTERN_ID(ctx));
        else if (strncmp(line, "AlphabetSize:", 13) == 0) {
            sscanf(line + 13, "%d", alphabet_size_ptr);
        } else if (strncmp(line, "States:", 7) == 0) {
            sscanf(line + 7, "%d", nfa_count_ptr);

        }
        else if (strncmp(line, "Alphabet:", 9) == 0) {
            for (int i = 0; i < *alphabet_size_ptr; i++) {
                if (!fgets(line, sizeof(line), file)) break;
                if (line[0] == '\n' || line[0] == '\r') { i--; continue; }
                if (strncmp(line, "State ", 6) == 0) { i--; continue; }
                if (strncmp(line, "Initial:", 8) == 0) { i--; continue; }
                unsigned int sid, start, end;
                if (sscanf(line, " Symbol %u: %u-%u", &sid, &start, &end) >= 3) {
                    alphabet_arr[i].symbol_id = (int)sid; alphabet_arr[i].start_char = (int)start; alphabet_arr[i].end_char = (int)end;
                    alphabet_arr[i].is_special = (strstr(line, "special") != NULL);
                }
            }
        }
        else if (strncmp(line, "State ", 6) == 0) {
            int s_idx; sscanf(line + 6, "%d:", &s_idx);
            // Initialize the state's transitions array to -1 (nfa_init may not have been called)
            for (int j = 0; j < MAX_SYMBOLS; j++) {
                nfa_arr[s_idx].transitions[j] = -1;
            }
            mta_init(&nfa_arr[s_idx].multi_targets);
            while (fgets(line, sizeof(line), file) && line[0] != '\n' && line[0] != '\r') {
                if (strstr(line, "CategoryMask:")) { unsigned int m; sscanf(strstr(line, "0x"), "%x", &m); nfa_arr[s_idx].category_mask = (uint8_t)m; }
                else if (strstr(line, "EosTarget:")) nfa_arr[s_idx].is_eos_target = (strstr(line, "yes") != NULL);
                else if (strstr(line, "PatternId:")) { 
                    unsigned int p; 
                    char* pstr = strstr(line, "PatternId:");
                    if (pstr) {
                        sscanf(pstr + 10, "%u", &p); 
                        nfa_arr[s_idx].pattern_id = (uint16_t)p;
                    }
                }
                // CaptureEnd and CaptureStart need special handling
                else if (strncmp(line, "  CaptureEnd:", 12) == 0) {
                    int cap_id;
                    if (sscanf(line + 14, "%d", &cap_id) == 1) {
                        mta_add_marker(&nfa_arr[s_idx].multi_targets, VSYM_EOS, 0, cap_id, MARKER_TYPE_END);
                    }
                }
                else if (strncmp(line, "  CaptureStart:", 14) == 0) {
                    int cap_id;
                    if (sscanf(line + 16, "%d", &cap_id) == 1) {
                        // CaptureStart: add START marker to all character transitions
                        // This ensures the marker fires on the first character after the capture start tag
                        for (int sym = 0; sym < 256; sym++) {
                            if (nfa_arr[s_idx].transitions[sym] >= 0) {
                                mta_add_marker(&nfa_arr[s_idx].multi_targets, sym, 0, cap_id, MARKER_TYPE_START);
                            }
                        }
                    }
                }
                else if (strncmp(line, "    Symbol ", 11) == 0) {
                    int sid, target; char* arrow = strstr(line, "->");
                    if (arrow && sscanf(line + 11, "%d", &sid) == 1) {
                        char* p = arrow + 2;
                        while (p && *p != '[') {
                            while (isspace(*p) || *p == ',') p++;
                            if (sscanf(p, "%d", &target) == 1) {
                                mta_add_target(&nfa_arr[s_idx].multi_targets, sid, target);
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
                                    mta_add_marker(&nfa_arr[s_idx].multi_targets, sid, pattern_id, uid, type);
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
static void print_version(void) {
    fprintf(stderr, "nfa2dfa_advanced version %s\n", pipeline_get_version());
}

static void print_usage(const char* progname) {
    fprintf(stderr, "Usage: %s [options] <input.nfa> [output.dfa]\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "Convert NFA to minimized DFA binary.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h, --help           Show this help message\n");
    fprintf(stderr, "  --version            Show version information\n");
    fprintf(stderr, "  -v                   Enable verbose output\n");
    fprintf(stderr, "  -vv                  Enable very verbose debug output\n");
    fprintf(stderr, "  --no-minimize        Skip DFA minimization\n");
    fprintf(stderr, "  --no-compress        Skip DFA compression\n");
    fprintf(stderr, "  --minimize-hopcroft  Use Hopcroft minimization (default)\n");
    fprintf(stderr, "  --minimize-moore     Use Moore minimization\n");
    fprintf(stderr, "  --minimize-brzozowski Use Brzozowski minimization\n");
    fprintf(stderr, "  --minimize-sat       Use SAT-based minimization\n");
    fprintf(stderr, "  --compress-sat       Use SAT-based compression\n");
    fprintf(stderr, "  --sat-optimal        Use SAT-based optimal pre-minimization\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Arguments:\n");
    fprintf(stderr, "  input.nfa            Input NFA file (required)\n");
    fprintf(stderr, "  output.dfa           Output DFA file (default: out.dfa)\n");
}

int main(int argc, char* argv[]) {
    bool minimize = true;
    bool compress = true;
    bool verbose = false;
    int verbosity = 0;
    bool compress_sat = false;
    bool sat_optimal = false;
    const char* input_file = NULL;
    const char* output_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--version") == 0) {
            print_version();
            return 0;
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = true;
            verbosity = 1;
        } else if (strcmp(argv[i], "-vv") == 0) {
            verbose = true;
            verbosity = 2;
        } else if (strcmp(argv[i], "--no-minimize") == 0) {
            minimize = false;
        } else if (strcmp(argv[i], "--no-compress") == 0) {
            compress = false;
        } else if (strcmp(argv[i], "--minimize-hopcroft") == 0) {
            dfa_minimize_set_algorithm(DFA_MIN_HOPCROFT);
        } else if (strcmp(argv[i], "--minimize-moore") == 0) {
            dfa_minimize_set_algorithm(DFA_MIN_MOORE);
        } else if (strcmp(argv[i], "--minimize-brzozowski") == 0) {
            dfa_minimize_set_algorithm(DFA_MIN_BRZOZOWSKI);
        } else if (strcmp(argv[i], "--minimize-sat") == 0) {
            dfa_minimize_set_algorithm(DFA_MIN_SAT);
        } else if (strcmp(argv[i], "--compress-sat") == 0) {
            compress_sat = true;
        } else if (strcmp(argv[i], "--sat-optimal") == 0) {
            sat_optimal = true;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Error: unknown option '%s'\n", argv[i]);
            print_usage(argv[0]);
            return 2;
        } else {
            if (input_file == NULL) {
                input_file = argv[i];
            } else if (output_file == NULL) {
                output_file = argv[i];
            }
        }
    }

    if (input_file == NULL) {
        fprintf(stderr, "Error: no input file specified\n");
        print_usage(argv[0]);
        return 2;
    }

    if (output_file == NULL) {
        output_file = "out.dfa";
    }

    if (verbosity > 0) {
        fprintf(stderr, "nfa2dfa_advanced: input='%s' output='%s' minimize=%d compress=%d\n",
                input_file, output_file, minimize, compress);
    }

    pipeline_config_t config = {
        .minimize_algo = dfa_minimize_get_algorithm(),
        .preminimize = true,
        .compress = compress,
        .optimize_layout = minimize,
        .verbose = verbose,
        .use_sat_compress = compress_sat,
        .enable_sat_optimal_premin = sat_optimal,
    };

    pipeline_t* p = pipeline_create(&config);
    if (!p) {
        fprintf(stderr, "Error: failed to create pipeline\n");
        return 1;
    }

    pipeline_error_t err = pipeline_load_nfa(p, input_file);
    if (err != PIPELINE_OK) {
        const char* err_msg = pipeline_get_last_error(p);
        fprintf(stderr, "Error: failed to load NFA from '%s': %s\n",
                input_file, err_msg ? err_msg : pipeline_error_string(err));
        pipeline_destroy(p);
        return 1;
    }

    if (verbosity > 0) {
        fprintf(stderr, "nfa2dfa: loaded NFA with %d states\n", pipeline_get_nfa_state_count(p));
    }

    err = pipeline_convert_to_dfa(p);
    if (err != PIPELINE_OK) {
        const char* err_msg = pipeline_get_last_error(p);
        fprintf(stderr, "Error: NFA to DFA conversion failed: %s\n",
                err_msg ? err_msg : pipeline_error_string(err));
        pipeline_destroy(p);
        return 1;
    }

    if (verbosity > 0) {
        fprintf(stderr, "nfa2dfa: converted to DFA with %d states\n", pipeline_get_dfa_state_count(p));
    }

    if (minimize) {
        dfa_min_algo_t algo = config.minimize_algo;
        if (verbosity > 0) {
            fprintf(stderr, "nfa2dfa: before minimize, state_count=%d, algo=%d\n",
                    pipeline_get_dfa_state_count(p), algo);
        }
        err = pipeline_minimize_dfa(p, algo);
        if (err != PIPELINE_OK) {
            fprintf(stderr, "Error: minimization failed: %s\n", pipeline_error_string(err));
            pipeline_destroy(p);
            return 1;
        }
        if (verbosity > 0) {
            fprintf(stderr, "nfa2dfa: after minimize, state_count=%d\n",
                    pipeline_get_dfa_state_count(p));
        }
        if (config.optimize_layout) {
            if (verbosity > 0) {
                fprintf(stderr, "nfa2dfa: before layout, state_count=%d\n",
                        pipeline_get_dfa_state_count(p));
            }
            err = pipeline_optimize_layout(p);
            if (err != PIPELINE_OK) {
                fprintf(stderr, "Error: layout optimization failed: %s\n",
                        pipeline_error_string(err));
                pipeline_destroy(p);
                return 1;
            }
            if (verbosity > 0) {
                fprintf(stderr, "nfa2dfa: after layout\n");
            }
        }
    }

    if (compress) {
        if (verbosity > 0) {
            fprintf(stderr, "nfa2dfa: before compress, state_count=%d\n",
                    pipeline_get_dfa_state_count(p));
        }
        err = pipeline_compress(p);
        if (err != PIPELINE_OK) {
            fprintf(stderr, "Error: compression failed: %s\n", pipeline_error_string(err));
            pipeline_destroy(p);
            return 1;
        }
        if (verbosity > 0) {
            fprintf(stderr, "nfa2dfa: after compress\n");
        }
    }

    if (verbosity > 0) {
        fprintf(stderr, "nfa2dfa: before write_dfa_file, state_count=%d\n",
                pipeline_get_dfa_state_count(p));
    }
    err = pipeline_save_binary(p, output_file);
    if (err != PIPELINE_OK) {
        const char* err_msg = pipeline_get_last_error(p);
        fprintf(stderr, "Error: failed to save DFA to '%s': %s\n",
                output_file, err_msg ? err_msg : pipeline_error_string(err));
        pipeline_destroy(p);
        return 1;
    }
    if (verbosity > 0) {
        fprintf(stderr, "nfa2dfa: after write_dfa_file\n");
    }

    if (verbosity > 0) {
        fprintf(stderr, "nfa2dfa: done, output='%s' size=%zu bytes\n",
                output_file, pipeline_get_binary_size(p));
    }

    pipeline_destroy(p);
    return 0;
}
#endif  // NFABUILDER_NO_MAIN
