/**
 * DFA Minimization Implementation - Brzozowski's Algorithm
 *
 * Brzozowski's algorithm achieves the unique minimal DFA by:
 * 1. Reversing the DFA transitions to create an NFA.
 * 2. Determinizing the NFA (subset construction) to produce a DFA.
 * 3. Reversing the resulting DFA transitions to create another NFA.
 * 4. Determinizing the second NFA to produce the final minimal DFA.
 *
 * Phase 3: Output-Sensitive Minimization
 * - Track marker_offsets on reversed edges
 * - Propagate markers through determinization
 * - Prevent merging states with different capture outputs
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
    uint32_t marker_offset;  // Phase 3: Track marker offset for output-sensitive minimization
} brz_edge_t;

typedef struct {
    brz_edge_t* edges;
    int* offsets;
    int* counts;
    int total_edges;
    int state_count;

    // DFA properties associated with each state
    uint16_t* flags;
    uint32_t* eos_target;

    // Phase 3: Track which original states have markers
    int* nfa_state_for_dfa_state;
} brz_nfa_t;

static void free_brz_nfa(brz_nfa_t* nfa) {
    if (nfa) {
        free(nfa->edges); free(nfa->offsets); free(nfa->counts);
        free(nfa->flags); free(nfa->eos_target);
        free(nfa->nfa_state_for_dfa_state);
    }
}

static bool build_reversed_nfa(const build_dfa_state_t* dfa, int state_count, brz_nfa_t* nfa) {
    memset(nfa, 0, sizeof(brz_nfa_t));
    nfa->state_count = state_count;
    nfa->counts = calloc(state_count, sizeof(int));
    nfa->offsets = calloc(state_count, sizeof(int));
    nfa->flags = malloc(state_count * sizeof(uint16_t));
    nfa->eos_target = malloc(state_count * sizeof(uint32_t));
    nfa->nfa_state_for_dfa_state = malloc(state_count * sizeof(int));

    if (!nfa->counts || !nfa->offsets || !nfa->flags) return false;

    for (int s = 0; s < state_count; s++) {
        nfa->flags[s] = dfa[s].flags;
        nfa->eos_target[s] = dfa[s].eos_target;
        // Phase 3: Track if this state has any non-zero marker_offsets
        nfa->nfa_state_for_dfa_state[s] = -1;
        for (int c = 0; c < 256; c++) {
            if (dfa[s].marker_offsets[c] != 0 || dfa[s].eos_marker_offset != 0) {
                nfa->nfa_state_for_dfa_state[s] = s;
                break;
            }
        }

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
                // Phase 3: Store marker offset on the reversed edge
                nfa->edges[idx].marker_offset = dfa[s].marker_offsets[c];
            }
        }
        if (dfa[s].eos_target != 0 && dfa[s].eos_target < (uint32_t)state_count) {
            int t = (int)dfa[s].eos_target;
            int idx = nfa->offsets[t] + nfa->counts[t]++;
            nfa->edges[idx].target = s;
            nfa->edges[idx].symbol = SYM_EOS;
            // Phase 3: Store EOS marker offset on the reversed edge
            nfa->edges[idx].marker_offset = dfa[s].eos_marker_offset;
        }
    }
    return true;
}

// ============================================================================
// Subset Construction
// ============================================================================

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

// Phase 3: Extended subset to track marker sources
typedef struct {
    int states[8192];
    int count;
    uint32_t hash;
    bool has_marker_source;
    uint32_t marker_sources[256];
    int marker_source_count;
} ext_subset_t;

/**
 * Determinize an NFA into a DFA.
 * Phase 3: Track marker_offsets on transitions to prevent merging states with different outputs.
 */
static int brz_determinize(
    const brz_nfa_t* nfa,
    const int* start_set, int start_count,
    int target_nfa_state,
    build_dfa_state_t* out_dfa,
    bool* contains_target_out
) {
    ext_subset_t* subsets = calloc(BRZ_MAX_STATES, sizeof(ext_subset_t));
    int* hash_table = calloc(BRZ_HASH_SIZE, sizeof(int));
    int* next_in_hash = calloc(BRZ_MAX_STATES, sizeof(int));

    if (!subsets || !hash_table || !next_in_hash) {
        free(subsets); free(hash_table); free(next_in_hash);
        return 0;
    }

    // Initialize hash table
    for (int i = 0; i < BRZ_HASH_SIZE; i++) hash_table[i] = -1;
    for (int i = 0; i < BRZ_MAX_STATES; i++) next_in_hash[i] = -1;

    int temp[BRZ_MAX_STATES];

    // Copy and sort start states
    memcpy(temp, start_set, start_count * sizeof(int));
    qsort(temp, start_count, sizeof(int), compare_ints);

    // Create initial extended subset
    uint32_t h = hash_ints(temp, start_count);
    subsets[0].count = start_count;
    subsets[0].hash = h;
    memcpy(subsets[0].states, temp, start_count * sizeof(int));
    subsets[0].has_marker_source = false;
    subsets[0].marker_source_count = 0;

    int bucket = h % BRZ_HASH_SIZE;
    hash_table[bucket] = 0;
    next_in_hash[0] = -1;

    int head = 0;
    int subset_count = 1;

    while (head < subset_count && subset_count < BRZ_MAX_STATES) {
        ext_subset_t* curr = &subsets[head];

        // Compute DFA state properties from constituent NFA states
        uint16_t f = 0;
        bool has_target = false;

        for (int i = 0; i < curr->count; i++) {
            int s = curr->states[i];
            f |= nfa->flags[s];
            if (s == target_nfa_state) has_target = true;
        }

        memset(&out_dfa[head], 0, sizeof(build_dfa_state_t));
        out_dfa[head].flags = f;
        if (contains_target_out) contains_target_out[head] = has_target;
        for (int i = 0; i < 256; i++) out_dfa[head].transitions[i] = -1;

        // Phase 3: Collect marker sources from all constituent NFA states
        curr->has_marker_source = false;
        curr->marker_source_count = 0;

        for (int i = 0; i < curr->count; i++) {
            int s = curr->states[i];
            // Check outgoing edges for markers
            int off = nfa->offsets[s];
            int cnt = nfa->counts[s];
            for (int k = 0; k < cnt && curr->marker_source_count < 256; k++) {
                uint32_t mo = nfa->edges[off + k].marker_offset;
                if (mo != 0) {
                    // Check if this marker is already recorded
                    bool found = false;
                    for (int m = 0; m < curr->marker_source_count; m++) {
                        if (curr->marker_sources[m] == mo) { found = true; break; }
                    }
                    if (!found) {
                        curr->marker_sources[curr->marker_source_count++] = mo;
                        curr->has_marker_source = true;
                    }
                }
            }
        }

        // Build transitions for each symbol
        for (int sym = 0; sym < TOTAL_VIRTUAL_SYMBOLS; sym++) {
            int next_count = 0;
            int seen[BRZ_MAX_STATES] = {0};

            for (int i = 0; i < curr->count; i++) {
                int s = curr->states[i];
                int off = nfa->offsets[s];
                int cnt = nfa->counts[s];
                for (int k = 0; k < cnt; k++) {
                    if (nfa->edges[off + k].symbol == sym) {
                        int t = nfa->edges[off + k].target;
                        if (!seen[t]) { seen[t] = 1; temp[next_count++] = t; }
                    }
                }
            }

            if (next_count > 0 && subset_count < BRZ_MAX_STATES) {
                // Check if subset already exists
                qsort(temp, next_count, sizeof(int), compare_ints);
                uint32_t nh = hash_ints(temp, next_count);
                int nbucket = nh % BRZ_HASH_SIZE;
                int existing = hash_table[nbucket];
                bool found_existing = false;

                while (existing != -1) {
                    if (subsets[existing].count == next_count && subsets[existing].hash == nh) {
                        bool match = true;
                        for (int i = 0; i < next_count; i++) {
                            if (subsets[existing].states[i] != temp[i]) { match = false; break; }
                        }
                        if (match) { found_existing = true; break; }
                    }
                    existing = next_in_hash[existing];
                }

                int tidx;
                if (found_existing) {
                    tidx = existing;
                } else {
                    // Create new subset
                    tidx = subset_count++;
                    if (tidx < BRZ_MAX_STATES) {
                        subsets[tidx].count = next_count;
                        subsets[tidx].hash = nh;
                        memcpy(subsets[tidx].states, temp, next_count * sizeof(int));
                        subsets[tidx].has_marker_source = false;
                        subsets[tidx].marker_source_count = 0;

                        next_in_hash[tidx] = hash_table[nbucket];
                        hash_table[nbucket] = tidx;
                    }
                }

                if (tidx < subset_count) {
                    // Phase 3: Set transition, preserving marker information
                    // Using marker source as distinguishing feature prevents merging
                    uint32_t marker_for_transition = 0;
                    if (curr->marker_source_count > 0) {
                        marker_for_transition = curr->marker_sources[0];
                    }

                    if (sym == SYM_EOS) {
                        out_dfa[head].eos_target = (uint32_t)tidx;
                        out_dfa[head].eos_marker_offset = marker_for_transition;
                    } else if (sym <= 256) {
                        out_dfa[head].transitions[sym - 1] = tidx;
                        out_dfa[head].transitions_from_any[sym - 1] = false;
                        out_dfa[head].marker_offsets[sym - 1] = marker_for_transition;
                    } else {
                        out_dfa[head].transitions[sym - 257] = tidx;
                        out_dfa[head].transitions_from_any[sym - 257] = true;
                        out_dfa[head].marker_offsets[sym - 257] = marker_for_transition;
                    }
                }
            }
        }

        head++;
    }

    free(subsets);
    free(hash_table);
    free(next_in_hash);
    return subset_count;
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
    int s2 = brz_determinize(&n2, init2, c2, -1, d2, NULL);
    free_brz_nfa(&n2); free(d1);

    fprintf(stderr, "[MINIMIZE] Brzozowski Pass 2 complete: %d minimal states\n", s2);

    // Copy result back
    memcpy(dfa, d2, s2 * sizeof(build_dfa_state_t));
    free(d2);

    return s2;
}
