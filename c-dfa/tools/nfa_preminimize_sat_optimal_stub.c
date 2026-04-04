/**
 * NFA Pre-minimize SAT Optimal Stub - Used when CaDiCaL is not available
 * Marked as weak so real implementation can override when linking SAT modules.
 */

#include <stdbool.h>
#include "../include/dfa_types.h"
#include "nfa_preminimize.h"
#include "../include/cdfa_defines.h"

__attribute__((weak))
bool nfa_preminimize_optimal_available(void) {
    return false;
}

__attribute__((weak))
int nfa_preminimize_optimal_merges(ATTR_UNUSED nfa_state_t* nfa, ATTR_UNUSED int state_count, ATTR_UNUSED bool* dead_states,
                                    ATTR_UNUSED int max_candidates, ATTR_UNUSED bool verbose) {
    return 0;
}
