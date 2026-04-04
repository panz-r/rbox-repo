/**
 * Stub for SAT-based layout optimization
 * Used when CaDiCaL is not available
 */

#include "dfa_layout_sat.h"
#include "../include/cdfa_defines.h"

__attribute__((weak))
int* sat_optimize_condensation_order(
    ATTR_UNUSED int** cond, ATTR_UNUSED int scc_count,
    ATTR_UNUSED const int* greedy_order, ATTR_UNUSED long long greedy_cost
) {
    return 0; // NULL
}

__attribute__((weak))
int sat_layout_available(void) {
    return 0;
}
