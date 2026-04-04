/**
 * SAT Compression Stub - Used when CaDiCaL is not available
 * Marked as weak so real implementation can override when linking SAT modules.
 */

#include <stdio.h>
#include "../include/dfa_types.h"
#include "dfa_compress.h"
#include "../include/cdfa_defines.h"

__attribute__((weak))
int sat_merge_rules_for_state(ATTR_UNUSED build_dfa_state_t* state, ATTR_UNUSED int max_group_size) {
    return 0;
}
