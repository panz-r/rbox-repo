/**
 * Stub for SAT-based layout optimization
 * Used when CaDiCaL is not available
 */

#include "dfa_layout_sat.h"

__attribute__((weak))
int* sat_optimize_condensation_order(
    int** cond, int scc_count,
    const int* greedy_order, long long greedy_cost
) {
    (void)cond; (void)scc_count; (void)greedy_order; (void)greedy_cost;
    return 0; // NULL
}

__attribute__((weak))
int sat_layout_available(void) {
    return 0;
}
