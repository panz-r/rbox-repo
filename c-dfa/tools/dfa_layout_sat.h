/**
 * SAT-Based DFA Layout Optimization
 */

#ifndef DFA_LAYOUT_SAT_H
#define DFA_LAYOUT_SAT_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Find optimal SCC ordering using bounded SAT.
 * Returns refined ordering (position -> SCC), or NULL if no improvement.
 * Caller must free the returned array.
 */
int* sat_optimize_condensation_order(
    int** cond,              // condensation graph [scc_count][scc_count]
    int scc_count,           // number of SCCs
    const int* greedy_order, // greedy ordering (position -> SCC)
    long long greedy_cost    // cost of greedy ordering
);

/**
 * Check if SAT-based layout is available (1=yes, 0=no)
 */
int sat_layout_available(void);

#ifdef __cplusplus
}
#endif

#endif // DFA_LAYOUT_SAT_H
