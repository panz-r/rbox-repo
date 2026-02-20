/**
 * Stub for windowed SAT optimization when CaDiCaL is not available.
 */

#include <stdbool.h>
#include "nfa_preminimize.h"
#include "../include/nfa.h"

/**
 * Windowed SAT-based NFA pre-minimization (stub).
 */
int nfa_preminimize_windowed_sat(nfa_state_t* nfa, int state_count, bool* dead_states,
                                  int window_size, int window_overlap, bool verbose) {
    (void)nfa;
    (void)state_count;
    (void)dead_states;
    (void)window_size;
    (void)window_overlap;
    (void)verbose;
    return 0;  // No merges when SAT not available
}

/**
 * Check if windowed SAT optimization is available (stub).
 */
bool nfa_preminimize_windowed_sat_available(void) {
    return false;
}
