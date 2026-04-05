/**
 * DFA Minimization - Header File
 */

#ifndef DFA_MINIMIZE_H
#define DFA_MINIMIZE_H

#include <stdbool.h>
#include <stdint.h>
#include "../include/nfa.h"
#include "../include/dfa_types.h"

// Arena allocator for DFA states - single allocation, bulk free
// Enables scalable state counts beyond MAX_STATES
typedef struct {
    build_dfa_state_t** states;  // Array of pointers to dynamically allocated states
    int capacity;               // Total allocated capacity
    int count;                  // Number of states currently used
} dfa_state_arena_t;

dfa_state_arena_t* dfa_arena_create(int initial_capacity);
void dfa_arena_destroy(dfa_state_arena_t* arena);
build_dfa_state_t* dfa_arena_alloc(dfa_state_arena_t* arena);  // Returns next state, grows if needed
void dfa_arena_reset(dfa_state_arena_t* arena);  // Reset count to 0, keep memory

// Marker list access for SAT minimizer
typedef struct {
    uint32_t markers[16]; // MAX_MARKERS_PER_DFA_TRANSITION
    int count;
} MarkerList;

MarkerList* dfa_get_marker_lists(int* count);

/**
 * Minimization algorithm selection
 */
typedef enum {
    DFA_MIN_MOORE,
    DFA_MIN_HOPCROFT,
    DFA_MIN_BRZOZOWSKI,
    DFA_MIN_SAT
} dfa_min_algo_t;

/**
 * Minimize a DFA in-place.
 * Note: Thread-safe when called with algo parameter; avoid dfa_minimize_set_algorithm().
 */
int dfa_minimize(build_dfa_state_t** dfa, int state_count, dfa_min_algo_t algo);

/**
 * Enable/disable debug output for minimization
 */
void dfa_minimize_set_verbose(bool verbose);

/**
 * Get statistics about the last minimization
 */
typedef struct {
    int initial_states;
    int final_states;
    int states_removed;
    int iterations;
} dfa_minimize_stats_t;

void dfa_minimize_get_stats(dfa_minimize_stats_t* stats);

/**
 * Select minimization algorithm (not thread-safe - use dfa_minimize with algo param)
 */
void dfa_minimize_set_algorithm(dfa_min_algo_t algo);

/**
 * Get current minimization algorithm
 */
dfa_min_algo_t dfa_minimize_get_algorithm(void);

/**
 * Hopcroft's Algorithm
 */
int dfa_minimize_hopcroft(build_dfa_state_t** dfa, int state_count);

/**
 * Moore's Algorithm
 */
int dfa_minimize_moore(build_dfa_state_t** dfa, int state_count);

/**
 * Brzozowski's Algorithm - Extreme minimization
 */
int dfa_minimize_brzozowski(build_dfa_state_t** dfa, int state_count);

/**
 * SAT-based Algorithm - Provably optimal minimization using CaDiCaL solver
 */
int dfa_minimize_sat(build_dfa_state_t** dfa, int state_count);

#endif // DFA_MINIMIZE_H
