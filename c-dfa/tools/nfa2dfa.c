#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include "../include/dfa_types.h"
#include "../include/multi_target_array.h"
#include "../include/nfa.h"
#include "dfa_minimize.h"

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
        fprintf(stderr, "FATAL: %s - %s\n", msg, strerror(errno));
        exit(EXIT_FAILURE);
    }
    return ptr;
}

typedef struct {
    int symbol_id;
    int start_char;
    int end_char;
    bool is_special;
} alphabet_entry_t;

// Global NFA/DFA storage - use larger static arrays for practical workloads
// For truly astronomical state counts (>32K), a more sophisticated solution would be needed
static nfa_state_t nfa[MAX_STATES];
static build_dfa_state_t dfa[MAX_STATES];
static alphabet_entry_t alphabet[MAX_SYMBOLS];
static int nfa_state_count = 0;
static int dfa_state_count = 0;
static int alphabet_size = 0;
static int max_states = MAX_STATES;

// DFA Deduplication Hash Table
#define DFA_HASH_SIZE 32749
static int dfa_hash_table[DFA_HASH_SIZE];
static int dfa_next_in_bucket[MAX_STATES];

static void init_hash_table(void) {
    memset(dfa_hash_table, -1, sizeof(dfa_hash_table));
    memset(dfa_next_in_bucket, -1, sizeof(dfa_next_in_bucket));
}

// Phase 3: Marker harvesting system
#define MAX_MARKERS_PER_DFA_TRANSITION 16
#define MAX_DFA_MARKER_LISTS 8192
#define MARKER_SENTINEL 0xFFFFFFFF

typedef struct {
    uint32_t markers[MAX_MARKERS_PER_DFA_TRANSITION];
    int count;
} MarkerList;

static MarkerList* dfa_marker_lists = NULL;
static int marker_list_count = 0;

static void init_marker_lists(void) {
    dfa_marker_lists = alloc_or_abort(malloc(sizeof(MarkerList) * MAX_DFA_MARKER_LISTS), "Failed to allocate marker lists");
    memset(dfa_marker_lists, 0, sizeof(MarkerList) * MAX_DFA_MARKER_LISTS);
}

static void free_marker_lists(void) {
    if (dfa_marker_lists) free(dfa_marker_lists);
    dfa_marker_lists = NULL;
}

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

// Comparator for sorting NFA states (for canonical ordering)
static int compare_ints(const void* a, const void* b) {
    return (*(int*)a - *(int*)b);
}

// Sort states canonically before hashing to enable better state merging
// This ensures that equivalent NFA state sets get the same hash even if
// they were discovered in different orders during NFA-to-DFA conversion
static void sort_states_canonical(int* states, int count) {
    qsort(states, count, sizeof(int), compare_ints);
}

static uint32_t hash_nfa_set(const int* states, int count, uint8_t mask, uint16_t first_accepting_pattern) {
    // Sort states canonically for consistent hashing
    int sorted[MAX_STATES];
    int sorted_count = count;
    for (int i = 0; i < count && i < MAX_STATES; i++) {
        sorted[i] = states[i];
    }
    sort_states_canonical(sorted, sorted_count);
    
    uint32_t hash = 2166136261u;
    for (int i = 0; i < sorted_count; i++) {
        hash ^= (uint32_t)sorted[i];
        hash *= 16777619;
    }
    hash ^= (uint32_t)mask << 24;
    hash ^= (uint32_t)first_accepting_pattern;
    return hash;
}

static int find_dfa_state_hashed(uint32_t hash, const int* states, int count, uint8_t mask, uint16_t first_accepting_pattern) {
    // Sort states canonically for comparison
    int sorted[MAX_STATES];
    int sorted_count = count;
    for (int i = 0; i < count && i < MAX_STATES; i++) {
        sorted[i] = states[i];
    }
    sort_states_canonical(sorted, sorted_count);
    
    int idx = dfa_hash_table[hash % DFA_HASH_SIZE];
    while (idx != -1) {
        if (dfa[idx].nfa_state_count == sorted_count) {
            uint8_t existing_mask = (uint8_t)(dfa[idx].flags >> 8);
            if (existing_mask == mask && dfa[idx].first_accepting_pattern == first_accepting_pattern) {
                bool match = true;
                for (int j = 0; j < sorted_count; j++) {
                    if (dfa[idx].nfa_states[j] != sorted[j]) { match = false; break; }
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

void dfa_init(void) {
    if (dfa_hash_table) {
        memset(dfa_hash_table, -1, sizeof(int) * DFA_HASH_SIZE);
    }
    if (dfa_next_in_bucket && max_states > 0) {
        memset(dfa_next_in_bucket, -1, sizeof(int) * max_states);
    }
    if (dfa && max_states > 0) {
        for (int i = 0; i < max_states; i++) {
            dfa[i].flags = 0;
            dfa[i].transition_count = 0;
            dfa[i].nfa_state_count = 0;
            dfa[i].eos_target = 0;
            for (int j = 0; j < MAX_SYMBOLS; j++) {
                dfa[i].transitions[j] = -1;
                dfa[i].transitions_from_any[j] = false;
            }
        }
    }
    dfa_state_count = 0;
}

void epsilon_closure_with_markers(int* states, int* count, int max_states,
                                  uint32_t* markers, int* marker_count, int max_markers) {
    int epsilon_sid = -1;
    int epsilon_symbol_id = 257;
    for (int s = 0; s < alphabet_size; s++) {
        if (alphabet[s].symbol_id == 257) { epsilon_sid = s; break; }
    }
    if (epsilon_sid < 0) {
        return;
    }

    static bool in_set[MAX_STATES];
    memset(in_set, 0, sizeof(in_set));
    int stack[MAX_STATES], top = 0;

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

    static bool in_set[MAX_STATES];
    memset(in_set, 0, sizeof(in_set));
    int stack[MAX_STATES], top = 0;
    
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
}

// Helper: Collect category mask from ALL accepting states reachable from given NFA states via epsilon
// This is used to fix quantifier category mixing bug where different patterns with shared prefixes
// have fork states that can only reach SOME accepting states, not all
// KEY: We search from ALL starting states TOGETHER to find all reachable accepting states
static uint8_t collect_fork_categories(int* states, int count, bool is_initial_state) {
    uint8_t fork_cats = 0;
    
    // Check if there are any fork states in the NFA (is_eos_target with category but pattern_id=0)
    bool has_fork = false;
    for (int i = 0; i < nfa_state_count; i++) {
        if (nfa[i].is_eos_target && nfa[i].category_mask != 0 && nfa[i].pattern_id == 0) {
            has_fork = true;
            break;
        }
    }
    if (!has_fork) return 0;
    
    // Search from ALL starting states TOGETHER to find all reachable fork states
    static bool visited[MAX_STATES];
    memset(visited, 0, sizeof(visited));
    
    int stack[MAX_STATES];
    int stack_top = 0;
    
    // Add starting states to the stack
    // For initial state, only use state 0 to find fork states that can match empty
    // For non-initial states, search from all states
    if (is_initial_state) {
        // For initial state, only start from state 0
        if (0 >= 0 && 0 < nfa_state_count) {
            stack[stack_top++] = 0;
            visited[0] = true;
        }
    } else {
        // For non-initial states, search from all states
        for (int s = 0; s < count; s++) {
            int start = states[s];
            if (start >= 0 && start < nfa_state_count && !visited[start]) {
                stack[stack_top++] = start;
                visited[start] = true;
            }
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
    
    return fork_cats;
}

int dfa_add_state(uint8_t category_mask, int* nfa_states, int nfa_count, uint16_t accepting_pattern_id, uint16_t first_accepting_pattern) {
    //fprintf(stderr, "DEBUG dfa_add_state: START count=%d, dfa_state_count=%d\n", nfa_count, dfa_state_count);
    uint32_t h = hash_nfa_set(nfa_states, nfa_count, category_mask, first_accepting_pattern);
    //fprintf(stderr, "DEBUG dfa_add_state: hash done\n");
    int bucket = h % DFA_HASH_SIZE;
    //fprintf(stderr, "DEBUG dfa_add_state: bucket=%d\n", bucket);
    int existing = find_dfa_state_hashed(h, nfa_states, nfa_count, category_mask, first_accepting_pattern);
    //fprintf(stderr, "DEBUG dfa_add_state: find done, existing=%d\n", existing);
    if (existing != -1) {
        return existing;
    }
    //fprintf(stderr, "DEBUG dfa_add_state: adding new state\n");
    if (dfa_state_count >= MAX_STATES) { 
        fprintf(stderr, "FATAL: Max DFA states reached (%d states)\n", MAX_STATES);
        fprintf(stderr, "This usually happens when:\n");
        fprintf(stderr, "  1. The pattern file has too many complex patterns\n");
        fprintf(stderr, "  2. Patterns have many alternatives (e.g., large character classes)\n");
        fprintf(stderr, "  3. Patterns use nested quantifiers that cause state explosion\n");
        fprintf(stderr, "\nSuggestions:\n");
        fprintf(stderr, "  - Split patterns into multiple files\n");
        fprintf(stderr, "  - Use fragments instead of large alternations\n");
        fprintf(stderr, "  - Simplify complex patterns\n");
        exit(1); 
    }
    int state = dfa_state_count++;
    memset(&dfa[state], 0, sizeof(build_dfa_state_t));
    for (int i = 0; i < MAX_SYMBOLS; i++) dfa[state].transitions[i] = -1;
    dfa[state].flags = (category_mask << 8);
    // Only mark as accepting if there's an actual accepting pattern
    // Don't mark as accepting just because category_mask is non-zero
    // (category comes from is_eos_target states which include fork states)
    if (accepting_pattern_id != 0 || first_accepting_pattern != 0) {
        dfa[state].flags |= DFA_STATE_ACCEPTING;
    }
    dfa[state].accepting_pattern_id = accepting_pattern_id;
    dfa[state].first_accepting_pattern = first_accepting_pattern;
    
    // Store sorted states for canonical form (helps with later minimization)
    int sorted[MAX_STATES];
    for (int i = 0; i < nfa_count && i < MAX_STATES; i++) {
        sorted[i] = nfa_states[i];
    }
    sort_states_canonical(sorted, nfa_count);
    dfa[state].nfa_state_count = nfa_count;
    for (int i = 0; i < nfa_count && i < 8192; i++) dfa[state].nfa_states[i] = sorted[i];
    dfa_next_in_bucket[state] = dfa_hash_table[bucket];
    dfa_hash_table[bucket] = state;
    return state;
}

void nfa_move(int* states, int* count, int sid, int max_states) {
    int ns[MAX_STATES], nc = 0; static bool is[MAX_STATES];
    memset(is, 0, sizeof(is));
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

void nfa_to_dfa(void) {
    fprintf(stderr, "DEBUG nfa_to_dfa: nfa_state_count=%d, alphabet_size=%d\n", nfa_state_count, alphabet_size);
    dfa_init();
    fprintf(stderr, "DEBUG after dfa_init\n");

    int in[MAX_STATES] = {0}; int ic = 1;
    fprintf(stderr, "DEBUG before epsilon_closure\n");
    int temp[MAX_STATES]; memcpy(temp, in, sizeof(int)); int tc = ic;
    uint32_t dummy_markers[MAX_MARKERS_PER_DFA_TRANSITION];
    int dummy_count = 0;
    epsilon_closure_with_markers(temp, &tc, MAX_STATES, dummy_markers, &dummy_count, MAX_MARKERS_PER_DFA_TRANSITION);
    fprintf(stderr, "DEBUG after epsilon_closure, tc=%d\n", tc);
    fprintf(stderr, "DEBUG temp states: ");
    for (int i = 0; i < tc; i++) fprintf(stderr, "%d ", temp[i]);
    fprintf(stderr, "\n");
    
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
    fprintf(stderr, "DEBUG before collect_fork_categories, im=0x%02x\n", im);
    // QUANTIFIER FIX: Also collect categories from ALL reachable fork states
    uint8_t fork_cats = collect_fork_categories(temp, tc, is_initial_state);
    fprintf(stderr, "DEBUG after collect_fork_categories, fork_cats=0x%02x\n", fork_cats);
    im |= fork_cats;
    fprintf(stderr, "DEBUG before dfa_add_state\n");
    int idfa = dfa_add_state(im, temp, tc, accept_pattern, reachable_accepting_patterns);
    if (idfa < 0) {
        fprintf(stderr, "Error: Failed to add initial DFA state\n");
        return;
    }

    // Allow empty matching for all patterns - the core fix is in category propagation
    // (not including category from is_eos_target states), which prevents false category matches

    int q[MAX_STATES]; int h = 0, t = 1; q[0] = idfa;
    //fprintf(stderr, "DEBUG: Starting main BFS loop, initial dfa_state_count=%d\n", dfa_state_count);

    while (h < t) {
        int cur = q[h++];
        //fprintf(stderr, "DEBUG: Processing DFA state %d (h=%d, t=%d, total_states=%d)\n", cur, h, t, dfa_state_count);
        for (int i = 0; i < alphabet_size; i++) {
            int symbol = alphabet[i].symbol_id;
            if (symbol == 257) continue;

            int ms[MAX_STATES]; int mc = dfa[cur].nfa_state_count;
            for (int j = 0; j < mc; j++) ms[j] = dfa[cur].nfa_states[j];

            uint32_t markers[MAX_MARKERS_PER_DFA_TRANSITION];
            memset(markers, 0, sizeof(markers));
            int marker_count = 0;
            collect_transition_markers(mc, ms, symbol, markers, &marker_count, MAX_MARKERS_PER_DFA_TRANSITION);

            nfa_move(ms, &mc, symbol, MAX_STATES);

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
            int tc2 = mc; int temp2[MAX_STATES]; memcpy(temp2, ms, mc * sizeof(int));
            epsilon_closure_with_markers(temp2, &tc2, MAX_STATES, markers, &marker_count, MAX_MARKERS_PER_DFA_TRANSITION);

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
            
            // QUANTIFIER FIX: Also collect categories from ALL reachable fork states
            // This ensures patterns with shared prefixes but different categories are all considered
            uint8_t fork_cats = collect_fork_categories(temp2, tc2, false);
            mm |= fork_cats;
            // DO NOT inherit from source - that breaks prefix sharing

            collect_markers_from_states(temp2, tc2, markers, &marker_count);
            uint32_t marker_list_offset = store_marker_list(markers, marker_count);

            int target = dfa_add_state(mm, temp2, tc2, accept_pattern2, (uint16_t)reachable_accepting_patterns2);

            // Handle both literal symbols (sid < 256) and virtual symbols (VSYM_ANY=256, VSYM_SPACE=259, VSYM_TAB=260)
            int sid = alphabet[i].symbol_id;
            if (sid < 256 || sid == 256 || sid == 259 || sid == 260) {
                dfa[cur].transitions[sid] = target;
                dfa[cur].marker_offsets[sid] = marker_list_offset;
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
        for (int j = 0; j < dfa[cur].nfa_state_count; j++) {
            int nfa_state = dfa[cur].nfa_states[j];
            if (nfa[nfa_state].pattern_id != 0) {
                accept_nfa_state = nfa_state;
                break;
            }
        }

        if (accept_nfa_state >= 0) {
            // This DFA state contains an accept NFA state - find the DFA state for it
            for (int s = 0; s < dfa_state_count; s++) {
                for (int j = 0; j < dfa[s].nfa_state_count; j++) {
                    if (dfa[s].nfa_states[j] == accept_nfa_state) {
                        dfa[cur].eos_target = s;
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
        for (int j = 0; j < dfa[cur].nfa_state_count; j++) {
            int nfa_state = dfa[cur].nfa_states[j];
            // Only accept via empty string if the state has an actual pattern_id
            if (nfa[nfa_state].is_eos_target && nfa[nfa_state].pattern_id != 0) {
                eos_nfa_state = nfa_state;
                break;
            }
        }

        // If no direct EOS target found, check EOS target states for EOS transitions
        // This handles + quantifier where fork state leads to accept state via EOS
        if (eos_nfa_state < 0) {
            for (int j = 0; j < dfa[cur].nfa_state_count; j++) {
                int nfa_state = dfa[cur].nfa_states[j];
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
                                    for (int k = 0; k < dfa[s].nfa_state_count; k++) {
                                        if (dfa[s].nfa_states[k] == eos_t) {
                                            dfa[cur].eos_target = s;
                                            if (dfa[cur].accepting_pattern_id == 0) {
                                                dfa[cur].accepting_pattern_id = nfa[eos_t].pattern_id - 1;
                                                dfa[cur].flags |= DFA_STATE_ACCEPTING;
                                            }
                                            break;
                                        }
                                    }
                                    if (dfa[cur].eos_target != 0) break;
                                }
                                break;
                            }
                        }
                    }
                }
                if (eos_nfa_state >= 0 || dfa[cur].eos_target != 0) break;
            }
        }

        if (eos_nfa_state >= 0) {
            // Find the DFA state that contains this exact EOS target NFA state
            for (int s = 0; s < dfa_state_count; s++) {
                for (int j = 0; j < dfa[s].nfa_state_count; j++) {
                    if (dfa[s].nfa_states[j] == eos_nfa_state) {
                        dfa[cur].eos_target = s;
                        // Also set accepting pattern if not already set
                        if (dfa[cur].accepting_pattern_id == 0 && nfa[eos_nfa_state].pattern_id != 0) {
                            dfa[cur].accepting_pattern_id = nfa[eos_nfa_state].pattern_id - 1;  // Convert to 0-based
                            dfa[cur].flags |= DFA_STATE_ACCEPTING;
                        }
                        break;
                    }
                }
                if (dfa[cur].eos_target != 0) break;
            }
        }

        eos_done:;
    }
    //fprintf(stderr, "DEBUG nfa_to_dfa: COMPLETED, dfa_state_count=%d\n", dfa_state_count);
}

void flatten_dfa(void) {
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

        uint32_t any_marker = (any_sid != -1) ? dfa[s].marker_offsets[256] : 0;

        // First, set specific symbol transitions
        for (int i = 0; i < alphabet_size; i++) {
            int sid = alphabet[i].symbol_id;
            if (sid < 256 && dfa[s].transitions[sid] != -1) {
                int t = dfa[s].transitions[sid];
                nt[sid] = t;
                any[sid] = false;
                markers[sid] = dfa[s].marker_offsets[sid];
            }
        }

        // Override with space and tab transitions (use symbol IDs directly, not alphabet indices)
        if (space_sid != -1 && dfa[s].transitions[259] != -1) {
            nt[32] = dfa[s].transitions[259];
            any[32] = false;
            markers[32] = dfa[s].marker_offsets[259];
        }

        if (tab_sid != -1 && dfa[s].transitions[260] != -1) {
            nt[9] = dfa[s].transitions[260];
            any[9] = false;
            markers[9] = dfa[s].marker_offsets[260];
        }

        // Finally, override with ANY transition (fills in gaps)
        if (any_sid != -1 && dfa[s].transitions[any_sid] != -1) {
            int t = dfa[s].transitions[any_sid];
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
            dfa[s].transitions[i] = nt[i];
            dfa[s].transitions_from_any[i] = any[i];
            dfa[s].marker_offsets[i] = markers[i];
            if (nt[i] != -1) rc++;
        }
        for (int i = 256; i < MAX_SYMBOLS; i++) {
            dfa[s].transitions[i] = -1;
            dfa[s].marker_offsets[i] = 0;
        }
        dfa[s].transition_count = rc;
    }
}

typedef struct { uint8_t type, d1, d2, d3; int target_state_index; } intermediate_rule_t;

int compress_state_rules(int sidx, intermediate_rule_t* out) {
    int rc = 0, ct = -1, sc = -1;
    // Compress only literal byte transitions (0-255)
    for (int c = 0; c <= 256; c++) {
        int t = (c < 256) ? dfa[sidx].transitions[c] : -1;
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

void write_dfa_file(const char* filename) {
    FILE* file = fopen(filename, "wb");
    if (!file) { fprintf(stderr, "FATAL: Cannot open %s for writing\n", filename); exit(1); }
    intermediate_rule_t* all_rules = alloc_or_abort(malloc(dfa_state_count * MAX_SYMBOLS * sizeof(intermediate_rule_t)), "Rules");
    size_t total_rules = 0;
    for (int i = 0; i < dfa_state_count; i++) total_rules += compress_state_rules(i, &all_rules[i * MAX_SYMBOLS]);
    size_t id_len = strlen(pattern_identifier);

    size_t marker_data_size = 0;
    for (int i = 0; i < dfa_state_count; i++) {
        int rule_count = compress_state_rules(i, &all_rules[i * MAX_SYMBOLS]);
        for (int r = 0; r < rule_count && r < 256; r++) {
            uint32_t list_idx = dfa[i].marker_offsets[all_rules[i * MAX_SYMBOLS + r].d1];
            if (list_idx > 0 && list_idx <= (uint32_t)marker_list_count) {
                MarkerList* ml = &dfa_marker_lists[list_idx - 1];
                marker_data_size += (ml->count + 1) * sizeof(uint32_t);
            }
        }
        if (dfa[i].eos_marker_offset > 0 && dfa[i].eos_marker_offset <= (uint32_t)marker_list_count) {
            MarkerList* ml = &dfa_marker_lists[dfa[i].eos_marker_offset - 1];
            marker_data_size += (ml->count + 1) * sizeof(uint32_t);
        }
    }

    size_t dfa_size = 23 + id_len + dfa_state_count * sizeof(dfa_state_t) + total_rules * sizeof(dfa_rule_t);
    dfa_t* ds = calloc(1, dfa_size + marker_data_size);
    if (!ds) { fprintf(stderr, "FATAL: Failed to allocate DFA buffer (%zu + %zu bytes)\n", dfa_size, marker_data_size); exit(1); }
    ds->magic = DFA_MAGIC; ds->version = DFA_VERSION;
    ds->state_count = dfa_state_count; ds->initial_state = 23 + id_len;  // Header is 23 bytes total (magic=4, ver=2, cnt=2, init=4, mask=4, flags=2, id_len=1, meta=4 = 23), identifier starts at offset 23
    ds->metadata_offset = 0;  // Will be set after states are written if needed

    uint32_t accepting_mask = 0;
    for (int i = 0; i < dfa_state_count; i++) {
        if (dfa[i].flags & DFA_STATE_ACCEPTING) {
            accepting_mask |= (1 << i);
        }
    }
    ds->accepting_mask = accepting_mask;

    ds->identifier_length = (uint8_t)id_len;
    memcpy(ds->identifier, pattern_identifier, id_len);

    dfa_state_t* sarr = (dfa_state_t*)((char*)ds + ds->initial_state);
    dfa_rule_t* rarr = (dfa_rule_t*)((char*)sarr + dfa_state_count * sizeof(dfa_state_t));
    size_t cro = ds->initial_state + dfa_state_count * sizeof(dfa_state_t);
    size_t gri = 0;
    for (int i = 0; i < dfa_state_count; i++) {
        int rc = compress_state_rules(i, &all_rules[i * MAX_SYMBOLS]);
        if (rc > 256) rc = 256;
        sarr[i].transition_count = (uint16_t)rc; sarr[i].transitions_offset = (rc > 0) ? (uint32_t)cro : 0;
        sarr[i].flags = dfa[i].flags;
        sarr[i].accepting_pattern_id = dfa[i].accepting_pattern_id;
        sarr[i].eos_marker_offset = 0;
        if (dfa[i].eos_target != 0) {
            uint32_t eos_offset = (uint32_t)(ds->initial_state + (size_t)dfa[i].eos_target * sizeof(dfa_state_t));
            sarr[i].eos_target = eos_offset;
        } else {
            sarr[i].eos_target = 0;
        }
        for (int r = 0; r < rc; r++) {
            dfa_rule_t* dst = &rarr[gri++];
            dst->type = all_rules[i * MAX_SYMBOLS + r].type; dst->data1 = all_rules[i * MAX_SYMBOLS + r].d1;
            dst->data2 = all_rules[i * MAX_SYMBOLS + r].d2; dst->data3 = 0;
            dst->marker_offset = 0;
            int tidx = all_rules[i * MAX_SYMBOLS + r].target_state_index;
            if (tidx < 0 || tidx >= dfa_state_count) {
                fprintf(stderr, "FATAL: State %d rule %d target index %d out of bounds (max %d)\n",
                        i, r, tidx, dfa_state_count - 1);
                exit(1);
            }
            uint32_t calculated_target = (uint32_t)(ds->initial_state + (size_t)tidx * sizeof(dfa_state_t));
            dst->target = calculated_target;
        }
        cro += rc * sizeof(dfa_rule_t);
    }

    size_t metadata_offset = cro;
    if (marker_list_count > 0) {
        ds->metadata_offset = (uint32_t)metadata_offset;

        uint32_t* marker_base = (uint32_t*)((char*)ds + metadata_offset);
        size_t moffset = 0;

        for (int i = 0; i < dfa_state_count; i++) {
            int rule_count = compress_state_rules(i, &all_rules[i * MAX_SYMBOLS]);
            size_t rule_offset = sarr[i].transitions_offset;
            for (int r = 0; r < rule_count && r < 256; r++) {
                dfa_rule_t* dst = (dfa_rule_t*)((char*)ds + rule_offset + r * sizeof(dfa_rule_t));
                uint32_t list_idx = dfa[i].marker_offsets[all_rules[i * MAX_SYMBOLS + r].d1];
                if (list_idx > 0 && list_idx <= (uint32_t)marker_list_count) {
                    MarkerList* ml = &dfa_marker_lists[list_idx - 1];
                    // Set dst->marker_offset BEFORE writing markers
                    dst->marker_offset = (uint32_t)(metadata_offset + moffset * sizeof(uint32_t));
                    for (int k = 0; k < ml->count; k++) {
                        uint32_t val = ml->markers[k];
                        // Write byte-by-byte to avoid endianness issues
                        ((uint8_t*)marker_base)[moffset * 4 + 0] = (val >> 0) & 0xFF;
                        ((uint8_t*)marker_base)[moffset * 4 + 1] = (val >> 8) & 0xFF;
                        ((uint8_t*)marker_base)[moffset * 4 + 2] = (val >> 16) & 0xFF;
                        ((uint8_t*)marker_base)[moffset * 4 + 3] = (val >> 24) & 0xFF;
                        moffset++;
                    }
                    uint32_t sentinel = MARKER_SENTINEL;
                    ((uint8_t*)marker_base)[moffset * 4 + 0] = (sentinel >> 0) & 0xFF;
                    ((uint8_t*)marker_base)[moffset * 4 + 1] = (sentinel >> 8) & 0xFF;
                    ((uint8_t*)marker_base)[moffset * 4 + 2] = (sentinel >> 16) & 0xFF;
                    ((uint8_t*)marker_base)[moffset * 4 + 3] = (sentinel >> 24) & 0xFF;
                    moffset++;
                }
            }
            if (dfa[i].eos_marker_offset > 0 && dfa[i].eos_marker_offset < (uint32_t)marker_list_count) {
                MarkerList* ml = &dfa_marker_lists[dfa[i].eos_marker_offset - 1];
                sarr[i].eos_marker_offset = (uint32_t)(metadata_offset + moffset * sizeof(uint32_t));
                for (int k = 0; k < ml->count; k++) marker_base[moffset++] = ml->markers[k];
                marker_base[moffset++] = MARKER_SENTINEL;
            }
        }
    }

    size_t total_size = dfa_size + marker_data_size;
    if (fwrite(ds, 1, total_size, file) != total_size) exit(1);
    fclose(file); free(ds); free(all_rules);
}

void load_nfa_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) { fprintf(stderr, "FATAL: Cannot open NFA file %s\n", filename); exit(1); }
    char line[1024]; 
    if (!fgets(line, sizeof(line), file)) { fprintf(stderr, "FATAL: Empty NFA file\n"); exit(1); }
    if (!strstr(line, "NFA_ALPHABET")) { fprintf(stderr, "FATAL: Invalid NFA header\n"); exit(1); }
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

int main(int argc, char* argv[]) {
    bool minimize = true;
    const char* input_file = NULL;
    const char* output_file = "out.dfa";
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "--no-minimize") == 0) minimize = false;
            else if (strcmp(argv[i], "-v") == 0) flag_verbose = true;
            else if (strcmp(argv[i], "--minimize-hopcroft") == 0) dfa_minimize_set_algorithm(DFA_MIN_HOPCROFT);
            else if (strcmp(argv[i], "--minimize-moore") == 0) dfa_minimize_set_algorithm(DFA_MIN_MOORE);
            else if (strcmp(argv[i], "--minimize-brzozowski") == 0) dfa_minimize_set_algorithm(DFA_MIN_BRZOZOWSKI);
            else if (strcmp(argv[i], "--minimize-sat") == 0) dfa_minimize_set_algorithm(DFA_MIN_SAT);
        } else {
            if (input_file == NULL) input_file = argv[i];
            else output_file = argv[i];
        }
    }
    if (input_file == NULL) return 1;
    
    init_hash_table();
    
    load_nfa_file(input_file);
    nfa_to_dfa();
    flatten_dfa();
    
    if (minimize) {
        dfa_min_algo_t algo = dfa_minimize_get_algorithm();
        dfa_state_count = dfa_minimize(dfa, dfa_state_count);
        // Don't re-flatten after Brzozowski - it already produces correct transitions
        if (algo != DFA_MIN_BRZOZOWSKI) {
            flatten_dfa();  // Re-flatten with new state indices after minimization
        }
    }
    write_dfa_file(output_file);
    return 0;
}
