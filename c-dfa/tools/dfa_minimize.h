/**
 * DFA Minimization - Header File
 */

#ifndef DFA_MINIMIZE_H
#define DFA_MINIMIZE_H

#include <stdbool.h>
#include <stdint.h>
#include "../include/nfa.h"

// Structure definition - shared between nfa2dfa.c and dfa_minimize.c
typedef struct build_dfa_state {
    uint32_t transitions_offset;
    uint16_t transition_count;
    uint16_t flags;
    int transitions[MAX_SYMBOLS];
    bool transitions_from_any[MAX_SYMBOLS];
    int nfa_states[8192];  // MAX_STATES from nfa.h
    int nfa_state_count;
    int8_t capture_start_id;
    int8_t capture_end_id;
    int8_t capture_defer_id;
    uint32_t eos_target;
} build_dfa_state_t;

/**
 * Minimize a DFA in-place.
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

typedef enum {
    DFA_MIN_MOORE,
    DFA_MIN_HOPCROFT,
    DFA_MIN_BRZOZOWSKI
} dfa_min_algo_t;

/**
 * Select minimization algorithm
 */
void dfa_minimize_set_algorithm(dfa_min_algo_t algo);

/**
 * Hopcroft's Algorithm
 */
int dfa_minimize_hopcroft(build_dfa_state_t* dfa, int state_count);

/**
 * Moore's Algorithm
 */
int dfa_minimize_moore(build_dfa_state_t* dfa, int state_count);

/**
 * Brzozowski's Algorithm - Extreme minimization
 */
int dfa_minimize_brzozowski(build_dfa_state_t* dfa, int state_count);

#endif // DFA_MINIMIZE_H
