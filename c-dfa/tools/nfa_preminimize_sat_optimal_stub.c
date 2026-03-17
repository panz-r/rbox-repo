/**
 * NFA Pre-minimize SAT Optimal Stub - Used when CaDiCaL is not available
 * Marked as weak so real implementation can override when linking SAT modules.
 */

#include <stdbool.h>
#include "../include/dfa_types.h"
#include "nfa_preminimize.h"

__attribute__((weak))
bool nfa_preminimize_optimal_available(void) {
    return false;
}

__attribute__((weak))
int nfa_preminimize_optimal_merges(nfa_state_t* nfa, int state_count, bool* dead_states,
                                    int max_candidates, bool verbose) {
    (void)nfa;
    (void)state_count;
    (void)dead_states;
    (void)max_candidates;
    (void)verbose;
    return 0;
}
