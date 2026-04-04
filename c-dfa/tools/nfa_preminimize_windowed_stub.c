/**
 * Stub for windowed SAT optimization when CaDiCaL is not available.
 */

#include <stdbool.h>
#include "nfa_preminimize.h"
#include "../include/nfa.h"
#include "../include/cdfa_defines.h"

/**
 * Windowed SAT-based NFA pre-minimization (stub).
 */
int nfa_preminimize_windowed_sat(ATTR_UNUSED nfa_state_t* nfa, ATTR_UNUSED int state_count, ATTR_UNUSED bool* dead_states,
                                  ATTR_UNUSED int window_size, ATTR_UNUSED int window_overlap, ATTR_UNUSED bool verbose) {
    return 0;  // No merges when SAT not available
}

/**
 * Check if windowed SAT optimization is available (stub).
 */
bool nfa_preminimize_windowed_sat_available(void) {
    return false;
}
