/**
 * DFA Minimization - Header File
 * 
 * Implements DFA state minimization using a variant of Hopcroft's algorithm.
 * Minimizes the build_dfa_state_t array before binary serialization.
 * 
 * Usage:
 *   After nfa_to_dfa() and flatten_dfa() complete:
 *     int new_count = dfa_minimize(dfa, dfa_state_count);
 *     dfa_state_count = new_count;
 *   Then call write_dfa_file() as normal.
 */

#ifndef DFA_MINIMIZE_H
#define DFA_MINIMIZE_H

#include <stdbool.h>
#include <stdint.h>

// Structure definition - shared between nfa2dfa.c and dfa_minimize.c
// This defines the in-memory DFA state before binary serialization
typedef struct build_dfa_state {
    uint32_t transitions_offset;
    uint16_t transition_count;
    uint16_t flags;
    int transitions[256];
    bool transitions_from_any[256];
    int nfa_states[8192];  // MAX_STATES from nfa.h
    int nfa_state_count;
    int8_t capture_start_id;
    int8_t capture_end_id;
    int8_t capture_defer_id;
    uint32_t eos_target;
} build_dfa_state_t;

/**
 * Minimize a DFA in-place.
 * 
 * Takes an array of build_dfa_state_t and collapses equivalent states.
 * After minimization, states are compacted (no gaps in the array).
 * 
 * @param dfa Array of DFA states (will be modified in-place)
 * @param state_count Number of valid states in the array
 * @return New number of states after minimization
 */
int dfa_minimize(build_dfa_state_t* dfa, int state_count);

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

#endif // DFA_MINIMIZE_H
