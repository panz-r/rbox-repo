/**
 * SAT-Based Condensation DAG Ordering for Cache Locality
 * 
 * Bounded SAT encoding to find optimal SCC ordering that minimizes
 * Σ cond[i][j] × |pos[i] - pos[j]|
 * 
 * Encoding strategy:
 *   - Position: x[i][p] = SCC i at position p (one-hot, k² vars)
 *   - All-different: row + column constraints (O(k³) clauses)
 *   - Topological: ¬x[i][p] ∨ ¬x[j][q] for edge i→j where p ≥ q
 *   - Distance: d_{i,j,t} = (|pos[i]-pos[j]| ≥ t) for t=1..k-1
 *   - Cost = Σ cond[i][j] × Σ_t d_{i,j,t}
 *   - Bound: sequential counter ≤ greedy_cost-1, then binary search
 * 
 * Complexity: O(k²) vars, O(k³) clauses for structure, O(k⁴) for distances
 * For k ≤ 20: ~400 vars, ~16000 clauses - easily solvable
 */

#ifdef USE_CADICAL

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <climits>
#include <vector>
#include "cadical.hpp"
#include "../include/cdfa_defines.h"

// ============================================================================
// CNF Builder with Incremental Solving
// ============================================================================

struct BoundedSAT {
    CaDiCaL::Solver solver;
    int num_vars;
    
    BoundedSAT() : num_vars(0) {}
    
    int new_var() {
        num_vars++;
        solver.resize(num_vars);
        return num_vars;
    }
    
    void clause(const std::vector<int>& lits) {
        for (int l : lits) solver.add(l);
        solver.add(0);
    }
    
    // Exactly one of vars is true (pairwise all-different)
    void exactly_one(const std::vector<int>& vars) {
        clause(vars); // At least one
        for (size_t i = 0; i < vars.size(); i++)
            for (size_t j = i+1; j < vars.size(); j++)
                clause({-vars[i], -vars[j]}); // At most one pairs
    }
    
    // Sequential counter: at most N of vars are true
    // Returns the auxiliary variables for the counter (for use with assumptions)
    // The final constraint is: s[n][N+1] must be false
    std::vector<std::vector<int>> sequential_counter(const std::vector<int>& vars, int bound) {
        int n = (int)vars.size();
        std::vector<std::vector<int>> s(n+1, std::vector<int>(bound+2, 0));
        
        for (int i = 0; i <= n; i++)
            for (int j = 0; j <= bound+1; j++)
                s[i][j] = new_var();
        
        clause({s[0][0]}); // s[0][0] = true
        for (int j = 1; j <= bound+1; j++)
            clause({-s[0][j]}); // s[0][j] = false
        
        for (int i = 1; i <= n; i++) {
            clause({s[i][0]}); // s[i][0] = true
            for (int j = 1; j <= bound+1; j++) {
                // s[i][j] = s[i-1][j] ∨ (vars[i-1] ∧ s[i-1][j-1])
                clause({-s[i][j], s[i-1][j], vars[i-1]});
                clause({-s[i][j], s[i-1][j], s[i-1][j-1]});
                clause({-s[i-1][j], s[i][j]});
                clause({-vars[i-1], -s[i-1][j-1], s[i][j]});
            }
        }
        
        return s;
    }
    
    // Solve with assumption that at most N cost variables are true
    // (using the sequential counter's terminal variable)
    int solve_with_bound(int terminal_var) {
        solver.assume(-terminal_var); // Force at most N to be true
        return solver.solve();
    }
    
    int get_var(int var) { return solver.val(var) > 0 ? 1 : 0; }
};

// ============================================================================
// Condensation DAG Ordering via Bounded SAT
// ============================================================================

extern "C" {

int* sat_optimize_condensation_order(
    int** cond,
    int scc_count,
    ATTR_UNUSED const int* greedy_order,
    long long greedy_cost
) {
    if (scc_count <= 3 || scc_count > 20) return nullptr;
    if (greedy_cost <= 0) return nullptr;
    
    int k = scc_count;
    
    BoundedSAT sat;
    
    // === Position variables: x[i][p] = SCC i at position p ===
    std::vector<std::vector<int>> x(k, std::vector<int>(k, 0));
    for (int i = 0; i < k; i++)
        for (int p = 0; p < k; p++)
            x[i][p] = sat.new_var();
    
    // All-different: each SCC at one position
    for (int i = 0; i < k; i++)
        sat.exactly_one(x[i]);
    
    // All-different: each position has one SCC
    for (int p = 0; p < k; p++) {
        std::vector<int> col(k);
        for (int i = 0; i < k; i++) col[i] = x[i][p];
        sat.exactly_one(col);
    }
    
    // === Topological ordering constraints ===
    // If edge i→j exists, pos[i] < pos[j]
    // For p ≥ q: ¬x[i][p] ∨ ¬x[j][q]
    for (int i = 0; i < k; i++) {
        for (int j = 0; j < k; j++) {
            if (cond[i][j] > 0) {
                for (int p = 0; p < k; p++)
                    for (int q = 0; q <= p; q++)
                        sat.clause({-x[i][p], -x[j][q]});
            }
        }
    }
    
    // === Distance indicator variables ===
    // t_{i,j,d} = (|pos[i] - pos[j]| >= d) for d = 1..k-1
    // Encoding: t_{i,j,d} = ∨_p (x[i][p] ∧ ∨_{q: |p-q|>=d} x[j][q])
    //
    // Forward implication (positions -> distance):
    //   For each p, q with |p-q| >= d:
    //     x[i][p] ∧ x[j][q] → t_{i,j,d}
    //     CNF: ¬x[i][p] ∨ ¬x[j][q] ∨ t_{i,j,d}
    //
    // Reverse implication (distance -> positions):
    //   t_{i,j,d} → ∨_{p,q:|p-q|>=d} (x[i][p] ∧ x[j][q])
    //   This is expensive to encode directly. Instead we note that:
    //   1. t_{i,j,d} → t_{i,j,d-1} (monotonic: if |p-q| >= d, then >= d-1)
    //   2. At least one t_{i,j,d} is true (positions always have some distance)
    //   3. The forward implications ensure correctness
    
    struct ThresholdVar { int i, j, d, var; };
    std::vector<ThresholdVar> thresh_vars;
    
    // Only create distance vars for pairs with edges
    for (int i = 0; i < k; i++) {
        for (int j = i+1; j < k; j++) {
            bool has_edge = (cond[i][j] > 0 || cond[j][i] > 0);
            if (!has_edge) continue;
            
            std::vector<int> pair_thresh_vars;
            
            for (int d = 1; d < k; d++) {
                int var = sat.new_var();
                thresh_vars.push_back({i, j, d, var});
                pair_thresh_vars.push_back(var);
                
                // Forward: positions -> threshold
                for (int p = 0; p < k; p++) {
                    for (int q = 0; q < k; q++) {
                        if (abs(p - q) >= d) {
                            sat.clause({-x[i][p], -x[j][q], var});
                        }
                    }
                }
            }
            
            // Monotonicity: t_{i,j,d} → t_{i,j,d-1}
            for (int d = 2; d < k; d++) {
                int var_d = pair_thresh_vars[d-1];
                int var_dm1 = pair_thresh_vars[d-2];
                sat.clause({-var_d, var_dm1});
            }
            
            // At least one threshold must be true
            // (positions always differ by at least 1, since i != j and all-different)
            sat.clause(pair_thresh_vars);
            
            // At most k-1 thresholds can be true (trivially satisfied by monotonicity,
            // but helps the solver)
            // Actually, monotonicity ensures exactly the thresholds from 1 to |p-q| are true
        }
    }
    
    // === Cost variables ===
    // Cost = Σ_{i,j} cond[i][j] × Σ_d t_{i,j,d}
    // Because: Σ_d [|p-q| >= d] = |p-q|
    //
    // We expand: cost_var_count = Σ cond[i][j] × (k-1) 
    // For each threshold variable with weight w, add it w times
    
    std::vector<int> cost_vars;
    for (const auto& tv : thresh_vars) {
        int w = cond[tv.i][tv.j] + cond[tv.j][tv.i];
        if (w <= 0) continue;
        // Add this threshold variable w times to the cost pool
        for (int c = 0; c < w; c++) {
            cost_vars.push_back(tv.var);
        }
    }
    
    if (cost_vars.empty()) return nullptr;
    
    // === Sequential counter for cost bound ===
    // counter_terminal = s[n][bound+1]
    // When we assume ¬counter_terminal, we enforce at most `bound` cost vars true
    
    // Start with greedy_cost - 1 as initial bound
    int best_bound = (int)(greedy_cost - 1);
    if (best_bound <= 0) return nullptr;
    
    // Build sequential counter for max possible bound
    int max_bound = (int)cost_vars.size();
    auto counter = sat.sequential_counter(cost_vars, max_bound);
    
    // Binary search for optimal bound
    int lb = 0;
    int ub = best_bound;
    int* best_order = nullptr;
    
    while (lb <= ub) {
        int mid = (lb + ub) / 2;
        
        // Add constraint: at most mid cost vars true
        // We use the counter's terminal variable with assumption
        // For binary search, we need different bounds, so we rebuild counter each time
        // (Alternatively, we could use incremental cardinality constraints)
        
        // For now, rebuild counter for this specific bound
        BoundedSAT search_sat;
        
        // Re-encode position variables
        std::vector<std::vector<int>> sx(k, std::vector<int>(k, 0));
        for (int i = 0; i < k; i++)
            for (int p = 0; p < k; p++)
                sx[i][p] = search_sat.new_var();
        
        for (int i = 0; i < k; i++)
            search_sat.exactly_one(sx[i]);
        
        for (int p = 0; p < k; p++) {
            std::vector<int> col(k);
            for (int i = 0; i < k; i++) col[i] = sx[i][p];
            search_sat.exactly_one(col);
        }
        
        for (int i = 0; i < k; i++) {
            for (int j = 0; j < k; j++) {
                if (cond[i][j] > 0) {
                    for (int p = 0; p < k; p++)
                        for (int q = 0; q <= p; q++)
                            search_sat.clause({-sx[i][p], -sx[j][q]});
                }
            }
        }
        
        // Re-encode threshold variables
        std::vector<int> search_cost_vars;
        for (int i = 0; i < k; i++) {
            for (int j = i+1; j < k; j++) {
                bool has_edge = (cond[i][j] > 0 || cond[j][i] > 0);
                if (!has_edge) continue;
                
                std::vector<int> pair_thresh;
                for (int d = 1; d < k; d++) {
                    int var = search_sat.new_var();
                    pair_thresh.push_back(var);
                    
                    int w = cond[i][j] + cond[j][i];
                    for (int c = 0; c < w; c++)
                        search_cost_vars.push_back(var);
                    
                    for (int p = 0; p < k; p++)
                        for (int q = 0; q < k; q++)
                            if (abs(p - q) >= d)
                                search_sat.clause({-sx[i][p], -sx[j][q], var});
                }
                
                for (size_t d = 1; d < pair_thresh.size(); d++)
                    search_sat.clause({-pair_thresh[d], pair_thresh[d-1]});
                
                search_sat.clause(pair_thresh);
            }
        }
        
        // Add cardinality constraint: at most mid cost vars true
        auto sc = search_sat.sequential_counter(search_cost_vars, mid);
        int sterm = sc[(int)search_cost_vars.size()][mid + 1];
        search_sat.clause({-sterm}); // Enforce at most mid
        
        int result = search_sat.solver.solve();
        
        if (result == 10) { // SAT
            // Found a solution with cost <= mid
            // Extract ordering
            if (best_order) free(best_order);
            best_order = (int*)malloc(k * sizeof(int));
            
            // Map position -> SCC
            std::vector<int> pos_to_scc(k, -1);
            for (int i = 0; i < k; i++) {
                for (int p = 0; p < k; p++) {
                    if (search_sat.get_var(sx[i][p]) > 0) {
                        pos_to_scc[p] = i;
                        break;
                    }
                }
            }
            
            for (int p = 0; p < k; p++) {
                best_order[p] = pos_to_scc[p];
            }
            
            ub = mid - 1; // Try to find even better
        } else {
            lb = mid + 1; // Bound too tight, relax
        }
    }
    
    return best_order;
}

int sat_layout_available(void) { return 1; }

} // extern "C"

#else // !USE_CADICAL

extern "C" {

int* sat_optimize_condensation_order(
    int** cond, int scc_count,
    const int* greedy_order, long long greedy_cost
) {
    (void)cond; (void)scc_count; (void)greedy_order; (void)greedy_cost;
    return nullptr;
}

int sat_layout_available(void) { return 0; }

} // extern "C"

#endif
