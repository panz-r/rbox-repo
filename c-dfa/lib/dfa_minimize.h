/**
 * DFA Minimization - Header File
 */

#ifndef DFA_MINIMIZE_H
#define DFA_MINIMIZE_H

#include <stdbool.h>
#include <stdint.h>
#include "../include/nfa.h"
#include "../include/dfa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

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

/**
 * Minimization algorithm selection (see dfa_types.h for dfa_minimize_algo_t)
 */

/**
 * Minimize a DFA in-place.
 * Note: Thread-safe when called with algo parameter; avoid dfa_minimize_set_algorithm().
 * @param dfa Pointer to DFA state array
 * @param state_count Number of states
 * @param algo Minimization algorithm (MOORE, HOPCROFT, BRZOZOWSKI, SAT)
 * @param verbose If true, print minimization progress to stderr
 * @param marker_lists Array of marker lists for SAT minimizer (can be NULL if algo != SAT)
 * @param marker_list_count Number of marker lists
 */
int dfa_minimize(build_dfa_state_t** dfa, int state_count, dfa_minimize_algo_t algo, bool verbose,
                 MarkerList* marker_lists, int marker_list_count);

/**
 * Enable/disable debug output for minimization
 */
void dfa_minimize_set_verbose(bool verbose);

/**
 * Get statistics about the last minimization.
 * dfa_minimize_stats_t is defined in dfa_types.h.
 */
void dfa_minimize_get_stats(dfa_minimize_stats_t* stats);

/**
 * Set iterations count for the last minimization
 */
void dfa_minimize_set_iterations(int iterations);

/**
 * Select minimization algorithm (not thread-safe - use dfa_minimize with algo param)
 */
void dfa_minimize_set_algorithm(dfa_minimize_algo_t algo);

/**
 * Get current minimization algorithm
 */
dfa_minimize_algo_t dfa_minimize_get_algorithm(void);

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
 * @param marker_lists Array of marker lists for transition markers (can be NULL)
 * @param marker_list_count Number of marker lists
 */
int dfa_minimize_sat(build_dfa_state_t** dfa, int state_count, MarkerList* marker_lists, int marker_list_count);

#ifdef __cplusplus
}
#endif

#endif // DFA_MINIMIZE_H
