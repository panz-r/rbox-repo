/**
 * DFA Minimization Implementation - Brzozowski's Algorithm
 * 
 * Brzozowski's algorithm achieves the unique minimal DFA by:
 * 1. Reversing the DFA transitions to create an NFA.
 * 2. Determinizing the NFA (subset construction) to produce a DFA.
 * 3. Reversing the resulting DFA transitions to create another NFA.
 * 4. Determinizing the second NFA to produce the final minimal DFA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include "../include/dfa_types.h"
#include "dfa_minimize.h"

// Limits for Brzozowski intermediate structures
#define BRZ_MAX_STATES 16384
#define BRZ_HASH_SIZE 32768

// Virtual symbol IDs
#define SYM_EOS 0
#define SYM_LITERAL(c) ((uint16_t)(c) + 1)
#define SYM_ANY(c) ((uint16_t)(c) + 257)
#define TOTAL_VIRTUAL_SYMBOLS 513

// ============================================================================
// Internal NFA Structure
// ============================================================================

typedef struct {
    int target;
    uint16_t symbol;
} brz_edge_t;

typedef struct {
    brz_edge_t* edges;
    int* offsets;
    int* counts;
    int total_edges;
    int state_count;
    
    // DFA properties associated with each state
    uint16_t* flags;
    int8_t* cap_start;
    int8_t* cap_end;
    int8_t* cap_defer;
    uint32_t* eos_target;
} brz_nfa_t;

static void free_brz_nfa(brz_nfa_t* nfa) {
    if (nfa) {
        free(nfa->edges); free(nfa->offsets); free(nfa->counts);
        free(nfa->flags); free(nfa->cap_start); free(nfa->cap_end);
        free(nfa->cap_defer); free(nfa->eos_target);
    }
}

static bool build_reversed_nfa(const build_dfa_state_t* dfa, int state_count, brz_nfa_t* nfa) {
    memset(nfa, 0, sizeof(brz_nfa_t));
    nfa->state_count = state_count;
    nfa->counts = calloc(state_count, sizeof(int));
    nfa->offsets = calloc(state_count, sizeof(int));
    nfa->flags = malloc(state_count * sizeof(uint16_t));
    nfa->cap_start = malloc(state_count * sizeof(int8_t));
    nfa->cap_end = malloc(state_count * sizeof(int8_t));
    nfa->cap_defer = malloc(state_count * sizeof(int8_t));
    nfa->eos_target = malloc(state_count * sizeof(uint32_t));

    if (!nfa->counts || !nfa->offsets || !nfa->flags) return false;

    for (int s = 0; s < state_count; s++) {
        nfa->flags[s] = dfa[s].flags;
        nfa->cap_start[s] = dfa[s].capture_start_id;
        nfa->cap_end[s] = dfa[s].capture_end_id;
        nfa->cap_defer[s] = dfa[s].capture_defer_id;
        nfa->eos_target[s] = dfa[s].eos_target;

        for (int c = 0; c < 256; c++) {
            int t = dfa[s].transitions[c];
            if (t >= 0 && t < state_count) { nfa->counts[t]++; nfa->total_edges++; }
        }
        if (dfa[s].eos_target != 0 && dfa[s].eos_target < (uint32_t)state_count) {
            nfa->counts[dfa[s].eos_target]++; nfa->total_edges++;
        }
    }

    nfa->edges = malloc((nfa->total_edges + 1) * sizeof(brz_edge_t));
    if (!nfa->edges) return false;

    int current_offset = 0;
    for (int s = 0; s < state_count; s++) {
        nfa->offsets[s] = current_offset;
        current_offset += nfa->counts[s];
        nfa->counts[s] = 0;
    }

    for (int s = 0; s < state_count; s++) {
        for (int c = 0; c < 256; c++) {
            int t = dfa[s].transitions[c];
            if (t >= 0 && t < state_count) {
                int idx = nfa->offsets[t] + nfa->counts[t]++;
                nfa->edges[idx].target = s;
                nfa->edges[idx].symbol = dfa[s].transitions_from_any[c] ? SYM_ANY(c) : SYM_LITERAL(c);
            }
        }
        if (dfa[s].eos_target != 0 && dfa[s].eos_target < (uint32_t)state_count) {
            int t = (int)dfa[s].eos_target;
            int idx = nfa->offsets[t] + nfa->counts[t]++;
            nfa->edges[idx].target = s;
            nfa->edges[idx].symbol = SYM_EOS;
        }
    }
    return true;
}

// ============================================================================
// Subset Construction
// ============================================================================

typedef struct {
    int* states;
    int count;
    uint32_t hash;
} brz_subset_t;

typedef struct {
    brz_subset_t subsets[BRZ_MAX_STATES];
    int count;
    int hash_table[BRZ_HASH_SIZE];
    int next_in_hash[BRZ_MAX_STATES];
} brz_subset_mgr_t;

static uint32_t hash_ints(const int* data, int count) {
    uint32_t hash = 2166136261u;
    for (int i = 0; i < count; i++) {
        hash ^= (uint32_t)data[i];
        hash *= 16777619;
    }
    return hash;
}

static int compare_ints(const void* a, const void* b) {
    return (*(const int*)a - *(const int*)b);
}

static int get_or_create_subset(brz_subset_mgr_t* mgr, int* states, int count) {
    if (count == 0) return -1;
    qsort(states, count, sizeof(int), compare_ints);
    uint32_t h = hash_ints(states, count);
    int bucket = h % BRZ_HASH_SIZE;
    int curr = mgr->hash_table[bucket];
    while (curr != -1) {
        if (mgr->subsets[curr].count == count && mgr->subsets[curr].hash == h) {
            bool match = true;
            for (int i = 0; i < count; i++) if (mgr->subsets[curr].states[i] != states[i]) { match = false; break; }
            if (match) return curr;
        }
        curr = mgr->next_in_hash[curr];
    }
    if (mgr->count >= BRZ_MAX_STATES) return -2;
    int idx = mgr->count++;
    mgr->subsets[idx].count = count;
    mgr->subsets[idx].hash = h;
    mgr->subsets[idx].states = malloc(count * sizeof(int));
    memcpy(mgr->subsets[idx].states, states, count * sizeof(int));
    mgr->next_in_hash[idx] = mgr->hash_table[bucket];
    mgr->hash_table[bucket] = idx;
    return idx;
}

/**
 * Determinize an NFA into a DFA. 
 * Returns boolean array indicating which DFA states contain the target NFA state.
 */
static int brz_determinize(
    const brz_nfa_t* nfa,
    const int* start_set, int start_count,
    int target_nfa_state,
    build_dfa_state_t* out_dfa,
    bool* contains_target_out
) {
    brz_subset_mgr_t* mgr = calloc(1, sizeof(brz_subset_mgr_t));
    if (!mgr) return 0;
    memset(mgr->hash_table, -1, sizeof(mgr->hash_table));

    int temp[BRZ_MAX_STATES];
    memcpy(temp, start_set, start_count * sizeof(int));
    int init_idx = get_or_create_subset(mgr, temp, start_count);
    if (init_idx < 0) { free(mgr); return 0; }

    int head = 0;
    while (head < mgr->count) {
        int curr_idx = head++;
        brz_subset_t* curr = &mgr->subsets[curr_idx];

        uint16_t f = 0; int8_t cs = -1, ce = -1, cd = -1; bool has_target = false;
        for (int i = 0; i < curr->count; i++) {
            int s = curr->states[i];
            f |= nfa->flags[s];
            if (nfa->cap_start[s] >= 0) cs = nfa->cap_start[s];
            if (nfa->cap_end[s] >= 0) ce = nfa->cap_end[s];
            if (nfa->cap_defer[s] >= 0) cd = nfa->cap_defer[s];
            if (s == target_nfa_state) has_target = true;
        }

        memset(&out_dfa[curr_idx], 0, sizeof(build_dfa_state_t));
        out_dfa[curr_idx].flags = f;
        out_dfa[curr_idx].capture_start_id = cs;
        out_dfa[curr_idx].capture_end_id = ce;
        out_dfa[curr_idx].capture_defer_id = cd;
        if (contains_target_out) contains_target_out[curr_idx] = has_target;
        for (int i = 0; i < 256; i++) out_dfa[curr_idx].transitions[i] = -1;

        for (int sym = 0; sym < TOTAL_VIRTUAL_SYMBOLS; sym++) {
            int next_count = 0;
            for (int i = 0; i < curr->count; i++) {
                int s = curr->states[i];
                int off = nfa->offsets[s], cnt = nfa->counts[s];
                for (int k = 0; k < cnt; k++) if (nfa->edges[off + k].symbol == sym) {
                    int t = nfa->edges[off + k].target;
                    bool found = false;
                    for (int m = 0; m < next_count; m++) if (temp[m] == t) { found = true; break; }
                    if (!found) temp[next_count++] = t;
                }
            }
            if (next_count > 0) {
                int tidx = get_or_create_subset(mgr, temp, next_count);
                if (tidx >= 0) {
                    if (sym == SYM_EOS) out_dfa[curr_idx].eos_target = (uint32_t)tidx;
                    else if (sym <= 256) {
                        out_dfa[curr_idx].transitions[sym - 1] = tidx;
                        out_dfa[curr_idx].transitions_from_any[sym - 1] = false;
                    } else {
                        out_dfa[curr_idx].transitions[sym - 257] = tidx;
                        out_dfa[curr_idx].transitions_from_any[sym - 257] = true;
                    }
                }
            }
        }
    }

    int res = mgr->count;
    for (int i = 0; i < res; i++) free(mgr->subsets[i].states);
    free(mgr);
    return res;
}

// ============================================================================
// Public API
// ============================================================================

int dfa_minimize_brzozowski(build_dfa_state_t* dfa, int state_count) {
    if (state_count <= 1) return state_count;

    fprintf(stderr, "[MINIMIZE] Brzozowski Extreme Minimization pass 1...\n");

    // Pass 1: D1 = determinize(reverse(D_orig))
    brz_nfa_t n1;
    if (!build_reversed_nfa(dfa, state_count, &n1)) return state_count;

    int init1[8192], c1 = 0;
    for (int i = 0; i < state_count; i++) if (dfa[i].flags & 0xFF00) init1[c1++] = i;
    if (c1 == 0) { free_brz_nfa(&n1); return state_count; }

    build_dfa_state_t* d1 = malloc(BRZ_MAX_STATES * sizeof(build_dfa_state_t));
    bool* contains_start1 = malloc(BRZ_MAX_STATES * sizeof(bool));
    int s1 = brz_determinize(&n1, init1, c1, 0, d1, contains_start1);
    free_brz_nfa(&n1);

    fprintf(stderr, "[MINIMIZE] Brzozowski Pass 1 complete: %d intermediate states\n", s1);
    fprintf(stderr, "[MINIMIZE] Brzozowski Extreme Minimization pass 2...\n");

    // Pass 2: D_min = determinize(reverse(D1))
    brz_nfa_t n2;
    if (!build_reversed_nfa(d1, s1, &n2)) { free(d1); free(contains_start1); return state_count; }

    int init2[BRZ_MAX_STATES], c2 = 0;
    for (int i = 0; i < s1; i++) if (contains_start1[i]) init2[c2++] = i;
    free(contains_start1);

    build_dfa_state_t* d2 = malloc(BRZ_MAX_STATES * sizeof(build_dfa_state_t));
    int s2 = brz_determinize(&n2, init2, c2, -1, d2, NULL); // Final pass doesn't need contains_start
    free_brz_nfa(&n2); free(d1);

    fprintf(stderr, "[MINIMIZE] Brzozowski Pass 2 complete: %d minimal states\n", s2);

    // Copy result back
    memcpy(dfa, d2, s2 * sizeof(build_dfa_state_t));
    free(d2);

    return s2; 
}
