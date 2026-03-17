/**
 * SAT Compression Stub - Used when CaDiCaL is not available
 * Marked as weak so real implementation can override when linking SAT modules.
 */

#include <stdio.h>
#include "../include/dfa_types.h"
#include "dfa_compress.h"

__attribute__((weak))
int sat_merge_rules_for_state(build_dfa_state_t* state, int max_group_size) {
    (void)state;
    (void)max_group_size;
    // Fall back to greedy merge (already called by dfa_compress when use_sat=false)
    return 0;
}
