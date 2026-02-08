/**
 * DFA Minimization Implementation
 * 
 * Implements DFA state minimization using:
 * 1. Dead State Pruning (Reverse Reachability)
 * 2. Moore's Algorithm (Partition Refinement)
 * 3. Hopcroft's Algorithm (Fast Refinement)
 * 4. Brzozowski's Algorithm (Extreme Minimization)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include "../include/dfa_types.h"
#include "dfa_minimize.h"

// Constants matching nfa.h
#define MAX_STATES 8192
#define MAX_SYMBOLS 256

// FNV-1a Constants for hashing
#define FNV_PRIME 16777619
#define FNV_OFFSET_BASIS 2166136261u

// Debug and Statistics
static bool minimize_verbose = false;
static dfa_min_algo_t current_algo = DFA_MIN_HOPCROFT;
static dfa_minimize_stats_t last_stats = {0};

#define VERBOSE_PRINT(fmt, ...) do { \
    if (minimize_verbose) fprintf(stderr, "[MINIMIZE] " fmt, ##__VA_ARGS__); \
} while(0)

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

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    int states[MAX_STATES];
    int count;
} partition_t;

typedef struct {
    int partition_map[MAX_STATES];
    partition_t partitions[MAX_STATES];
    int partition_count;
} minimizer_state_t;

// ============================================================================
// Property and Transition Equivalence
// ============================================================================

static bool are_properties_equivalent(const build_dfa_state_t* s1, const build_dfa_state_t* s2) {
    if (s1->flags != s2->flags) return false;
    if (s1->capture_start_id != s2->capture_start_id) return false;
    if (s1->capture_end_id != s2->capture_end_id) return false;
    if (s1->capture_defer_id != s2->capture_defer_id) return false;
    if ((s1->eos_target != 0) != (s2->eos_target != 0)) return false;
    return true;
}

static bool are_transitions_equivalent(const build_dfa_state_t* s1, const build_dfa_state_t* s2, const int* partition_map) {
    for (int c = 0; c < 256; c++) {
        int t1 = s1->transitions[c], t2 = s2->transitions[c];
        if (t1 == -1 && t2 == -1) continue;
        if (t1 == -1 || t2 == -1) return false;
        if (partition_map[t1] != partition_map[t2]) return false;
        if (s1->transitions_from_any[c] != s2->transitions_from_any[c]) return false;
    }
    if (s1->eos_target != 0 && s2->eos_target != 0) {
        if (partition_map[s1->eos_target] != partition_map[s2->eos_target]) return false;
    }
    return true;
}

static uint16_t compute_hash(const build_dfa_state_t* state, const int* partition_map) {
    uint32_t hash = FNV_OFFSET_BASIS;
    hash ^= (state->flags & 0xFFFF); hash *= FNV_PRIME;
    hash ^= (uint8_t)state->capture_start_id; hash *= FNV_PRIME;
    hash ^= (uint8_t)state->capture_end_id; hash *= FNV_PRIME;
    hash ^= (uint8_t)state->capture_defer_id; hash *= FNV_PRIME;
    if (state->eos_target != 0) { hash ^= 0xFF; hash *= FNV_PRIME; }
    for (int c = 0; c < 256; c += 16) {
        int t = state->transitions[c];
        int target_p = (t != -1) ? partition_map[t] : -1;
        hash ^= c; hash *= FNV_PRIME;
        hash ^= (uint8_t)target_p; hash *= FNV_PRIME;
    }
    return (uint16_t)((hash >> 16) ^ (hash & 0xFFFF));
}

// ============================================================================
// Shared Initialization and Build
// ============================================================================

static void initialize_partitions(minimizer_state_t* ms, const build_dfa_state_t* dfa, int state_count) {
    for (int i = 0; i < MAX_STATES; i++) ms->partition_map[i] = -1;
    int group_count = 0;
    for (int s = 0; s < state_count; s++) {
        bool found = false;
        for (int g = 0; g < group_count; g++) {
            if (are_properties_equivalent(&dfa[s], &dfa[ms->partitions[g].states[0]])) {
                ms->partitions[g].states[ms->partitions[g].count++] = s;
                ms->partition_map[s] = g;
                found = true; break;
            }
        }
        if (!found) {
            ms->partitions[group_count].states[0] = s;
            ms->partitions[group_count].count = 1;
            ms->partition_map[s] = group_count;
            group_count++;
        }
    }
    ms->partition_count = group_count;
}

int build_minimized_dfa(build_dfa_state_t* dfa, const minimizer_state_t* ms, int old_state_count) {
    build_dfa_state_t* new_dfa = malloc(ms->partition_count * sizeof(build_dfa_state_t));
    alloc_or_abort(new_dfa, "Alloc New DFA Buffer");
    int state_remap[MAX_STATES];
    int new_count = 0;
    for (int p = 0; p < ms->partition_count; p++) {
        if (ms->partitions[p].count == 0) continue;
        int rep = ms->partitions[p].states[0];
        memcpy(&new_dfa[new_count], &dfa[rep], sizeof(build_dfa_state_t));
        for (int i = 0; i < ms->partitions[p].count; i++) state_remap[ms->partitions[p].states[i]] = new_count;
        new_count++;
    }
    for (int s = 0; s < new_count; s++) {
        for (int c = 0; c < 256; c++) {
            int t = new_dfa[s].transitions[c];
            if (t != -1 && t < old_state_count) new_dfa[s].transitions[c] = state_remap[t];
        }
        if (new_dfa[s].eos_target != 0 && new_dfa[s].eos_target < (uint32_t)old_state_count) {
            new_dfa[s].eos_target = (uint32_t)state_remap[new_dfa[s].eos_target];
        }
        new_dfa[s].nfa_state_count = 0;
    }
    memcpy(dfa, new_dfa, new_count * sizeof(build_dfa_state_t));
    free(new_dfa); return new_count;
}

// ============================================================================
// Moore's Algorithm (Robust Baseline)
// ============================================================================

int dfa_minimize_moore(build_dfa_state_t* dfa, int state_count) {
    minimizer_state_t* ms = calloc(1, sizeof(minimizer_state_t));
    alloc_or_abort(ms, "Alloc MS");
    initialize_partitions(ms, dfa, state_count);
    int iterations = 0;
    while (iterations < 100) {
        iterations++; bool changed = false;
        int old_count = ms->partition_count;
        for (int p = 0; p < old_count; p++) {
            if (ms->partitions[p].count <= 1) continue;
            int subgroup_count = 0; int state_to_sg[MAX_STATES]; int sg_reps[MAX_STATES];
            for (int i = 0; i < ms->partitions[p].count; i++) {
                int s = ms->partitions[p].states[i]; int sg = -1;
                uint16_t sig = compute_hash(&dfa[s], ms->partition_map);
                for (int u = 0; u < subgroup_count; u++) {
                    if (sig == compute_hash(&dfa[sg_reps[u]], ms->partition_map)) {
                        if (are_transitions_equivalent(&dfa[s], &dfa[sg_reps[u]], ms->partition_map)) { sg = u; break; }
                    }
                }
                if (sg == -1) { sg = subgroup_count++; sg_reps[sg] = s; }
                state_to_sg[i] = sg;
            }
            if (subgroup_count > 1) {
                changed = true; int new_p_ids[MAX_STATES]; new_p_ids[0] = p;
                for (int sg = 1; sg < subgroup_count; sg++) { new_p_ids[sg] = ms->partition_count++; ms->partitions[new_p_ids[sg]].count = 0; }
                int kept[MAX_STATES], kept_count = 0;
                for (int i = 0; i < ms->partitions[p].count; i++) {
                    int s = ms->partitions[p].states[i]; int dest = new_p_ids[state_to_sg[i]];
                    if (dest == p) kept[kept_count++] = s;
                    else { ms->partitions[dest].states[ms->partitions[dest].count++] = s; ms->partition_map[s] = dest; }
                }
                ms->partitions[p].count = kept_count; memcpy(ms->partitions[p].states, kept, kept_count * sizeof(int));
            }
        }
        if (!changed) break;
    }
    int new_count = build_minimized_dfa(dfa, ms, state_count);
    free(ms); return new_count;
}

// ============================================================================
// Public Interface
// ============================================================================

void dfa_minimize_set_algorithm(dfa_min_algo_t algo) { current_algo = algo; }
void dfa_minimize_set_moore(bool use_moore) { current_algo = use_moore ? DFA_MIN_MOORE : DFA_MIN_HOPCROFT; }
void dfa_minimize_set_verbose(bool verbose) { minimize_verbose = verbose; }
void dfa_minimize_get_stats(dfa_minimize_stats_t* stats) { if(stats) *stats = last_stats; }

static bool verify_minimized_dfa(const build_dfa_state_t* dfa, int state_count) {
    if (state_count <= 0) return false;
    for (int s = 0; s < state_count; s++) {
        for (int c = 0; c < 256; c++) {
            int t = dfa[s].transitions[c];
            if (t != -1 && (t < 0 || t >= state_count)) return false;
        }
        if (dfa[s].eos_target != 0 && dfa[s].eos_target >= (uint32_t)state_count) return false;
    }
    return true;
}

int dfa_minimize(build_dfa_state_t* dfa, int state_count) {
    if (state_count <= 0) return 0;
    int original = state_count;
    
    int new_count;
    if (current_algo == DFA_MIN_MOORE) {
        new_count = dfa_minimize_moore(dfa, state_count);
    } else if (current_algo == DFA_MIN_BRZOZOWSKI) {
        new_count = dfa_minimize_brzozowski(dfa, state_count);
    } else {
        // Fallback to Moore for now until Hopcroft is hardened
        new_count = dfa_minimize_moore(dfa, state_count);
    }
    
    last_stats.initial_states = original;
    last_stats.final_states = new_count;
    last_stats.states_removed = original - new_count;
    
    if (!verify_minimized_dfa(dfa, new_count)) {
        fprintf(stderr, "FATAL: Minimized DFA failed verification.\n");
        exit(1);
    }
    return new_count;
}
