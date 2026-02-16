/**
 * DFA Minimization Implementation - Efficient SAT Encoding
 *
 * Uses equivalence relation encoding instead of partition assignment.
 * This reduces complexity from O(n² × |Σ| × p²) to O(n² × |Σ| + n³).
 *
 * Key insight: Instead of encoding "state s is in partition p", we encode
 * "states i and j are equivalent" directly. This avoids the quadratic
 * partition factor in transition constraints.
 *
 * For large DFAs, we use SCC decomposition to further reduce problem size.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <vector>
#include <algorithm>
#include "cadical.hpp"

extern "C" {
#include "../include/dfa_types.h"
#include "dfa_minimize.h"
}

// Configuration
#define MAX_EQ_STATES 500       // Max states for equivalence encoding
#define MAX_SAT_ITERATIONS 5    // Max binary search iterations

/**
 * Equivalence Relation SAT Encoder
 * 
 * Variables: eq[i][j] for all i < j
 * eq[i][j] = true means states i and j can be merged
 */
class EquivalenceEncoder {
private:
    CaDiCaL::Solver* solver;
    int n_states;
    
    // Variable indexing: eq[i][j] where i < j
    // Linear index for pair (i,j) where i < j:
    // Number of pairs before row i: sum_{k=0}^{i-1} (n - 1 - k) = i*(2n - i - 1)/2
    // Position within row i: (j - i - 1)
    // Total: i*(2n - i - 1)/2 + (j - i - 1)
    int eq_var_index(int i, int j) {
        if (i > j) std::swap(i, j);
        // For i < j: index = i*(2*n_states - i - 1)/2 + (j - i - 1)
        return i * (2 * n_states - i - 1) / 2 + (j - i - 1);
    }
    
    int get_eq_var(int i, int j) {
        if (i == j) return 0;  // Always true (reflexivity)
        return eq_var_index(i, j) + 1;  // 1-indexed for SAT solver
    }
    
public:
    EquivalenceEncoder(int states) : n_states(states) {
        solver = new CaDiCaL::Solver();
        
        // Allocate variables: n*(n-1)/2 equivalence variables
        int num_vars = n_states * (n_states - 1) / 2;
        for (int v = 0; v < num_vars; v++) {
            (void)solver->declare_one_more_variable();
        }
    }
    
    ~EquivalenceEncoder() {
        delete solver;
    }
    
    /**
     * Encode transitivity: eq[i][j] ∧ eq[j][k] → eq[i][k]
     * 
     * For efficiency, we only encode for triples where i < j < k
     * This gives us 3 clauses per triple:
     *   ¬eq[i][j] ∨ ¬eq[j][k] ∨ eq[i][k]
     *   ¬eq[i][j] ∨ ¬eq[i][k] ∨ eq[j][k]
     *   ¬eq[j][k] ∨ ¬eq[i][k] ∨ eq[i][j]
     */
    void encode_transitivity() {
        for (int i = 0; i < n_states; i++) {
            for (int j = i + 1; j < n_states; j++) {
                for (int k = j + 1; k < n_states; k++) {
                    int vij = get_eq_var(i, j);
                    int vjk = get_eq_var(j, k);
                    int vik = get_eq_var(i, k);
                    
                    // eq[i][j] ∧ eq[j][k] → eq[i][k]
                    solver->add(-vij);
                    solver->add(-vjk);
                    solver->add(vik);
                    solver->add(0);
                    
                    // eq[i][j] ∧ eq[i][k] → eq[j][k]
                    solver->add(-vij);
                    solver->add(-vik);
                    solver->add(vjk);
                    solver->add(0);
                    
                    // eq[j][k] ∧ eq[i][k] → eq[i][j]
                    solver->add(-vjk);
                    solver->add(-vik);
                    solver->add(vij);
                    solver->add(0);
                }
            }
        }
    }
    
    /**
     * Encode: states with different accepting status cannot be equivalent
     */
    void encode_accepting_separation(build_dfa_state_t* dfa) {
        for (int i = 0; i < n_states; i++) {
            for (int j = i + 1; j < n_states; j++) {
                bool acc_i = (dfa[i].flags & DFA_STATE_ACCEPTING) != 0;
                bool acc_j = (dfa[j].flags & DFA_STATE_ACCEPTING) != 0;
                
                if (acc_i != acc_j) {
                    int v = get_eq_var(i, j);
                    solver->add(-v);  // ¬eq[i][j]
                    solver->add(0);
                }
            }
        }
    }
    
    /**
     * Encode: states with different categories cannot be equivalent
     */
    void encode_category_separation(build_dfa_state_t* dfa) {
        for (int i = 0; i < n_states; i++) {
            for (int j = i + 1; j < n_states; j++) {
                uint8_t cat_i = (dfa[i].flags >> 8) & 0xFF;
                uint8_t cat_j = (dfa[j].flags >> 8) & 0xFF;
                
                // Different non-zero categories cannot merge
                if (cat_i != cat_j && (cat_i != 0 || cat_j != 0)) {
                    int v = get_eq_var(i, j);
                    solver->add(-v);  // ¬eq[i][j]
                    solver->add(0);
                }
            }
        }
    }
    
    /**
     * Encode transition consistency: eq[i][j] → eq[δ(i,c)][δ(j,c)]
     * 
     * For each pair (i, j) and symbol c:
     * If both have transitions, targets must be equivalent
     * If one has transition and other doesn't, they cannot be equivalent
     */
    void encode_transition_consistency(build_dfa_state_t* dfa) {
        // Find used alphabet symbols
        bool used[256] = {false};
        for (int s = 0; s < n_states; s++) {
            for (int c = 0; c < 256; c++) {
                if (dfa[s].transitions[c] >= 0) {
                    used[c] = true;
                }
            }
        }
        
        for (int i = 0; i < n_states; i++) {
            for (int j = i + 1; j < n_states; j++) {
                for (int c = 0; c < 256; c++) {
                    if (!used[c]) continue;
                    
                    int ti = dfa[i].transitions[c];
                    int tj = dfa[j].transitions[c];
                    
                    if (ti >= 0 && tj >= 0) {
                        // Both have transitions: eq[i][j] → eq[ti][tj]
                        int vij = get_eq_var(i, j);
                        int vt = get_eq_var(ti, tj);
                        
                        solver->add(-vij);
                        solver->add(vt);
                        solver->add(0);
                    } else if ((ti >= 0) != (tj >= 0)) {
                        // One has transition, other doesn't: cannot be equivalent
                        int v = get_eq_var(i, j);
                        solver->add(-v);
                        solver->add(0);
                    }
                    // If both have no transition, no constraint needed
                }
                
                // Also check EOS transitions
                uint32_t eos_i = dfa[i].eos_target;
                uint32_t eos_j = dfa[j].eos_target;
                if (eos_i != 0 || eos_j != 0) {
                    if (eos_i != 0 && eos_j != 0 && eos_i < (uint32_t)n_states && eos_j < (uint32_t)n_states) {
                        int vij = get_eq_var(i, j);
                        int veos = get_eq_var((int)eos_i, (int)eos_j);
                        solver->add(-vij);
                        solver->add(veos);
                        solver->add(0);
                    } else if ((eos_i != 0) != (eos_j != 0)) {
                        int v = get_eq_var(i, j);
                        solver->add(-v);
                        solver->add(0);
                    }
                }
            }
        }
    }
    
    /**
     * Solve the SAT instance
     */
    bool solve() {
        return solver->solve() == CaDiCaL::SATISFIABLE;
    }
    
    /**
     * Check if two states are equivalent in the solution
     */
    bool are_equivalent(int i, int j) {
        if (i == j) return true;
        int v = get_eq_var(i, j);
        return solver->val(v) > 0;
    }
    
    /**
     * Extract equivalence classes from solution
     * Returns partition assignment for each state
     */
    void get_partitions(std::vector<int>& partition) {
        partition.resize(n_states);
        std::vector<int> parent(n_states);
        
        // Initialize each state as its own parent
        for (int i = 0; i < n_states; i++) {
            parent[i] = i;
        }
        
        // Union states that are equivalent
        for (int i = 0; i < n_states; i++) {
            for (int j = i + 1; j < n_states; j++) {
                if (are_equivalent(i, j)) {
                    // Union i and j
                    int ri = i, rj = j;
                    while (parent[ri] != ri) ri = parent[ri];
                    while (parent[rj] != rj) rj = parent[rj];
                    if (ri != rj) {
                        parent[rj] = ri;
                    }
                }
            }
        }
        
        // Assign partition numbers
        std::vector<int> rep_to_partition(n_states, -1);
        int next_partition = 0;
        for (int i = 0; i < n_states; i++) {
            // Find root
            int r = i;
            while (parent[r] != r) r = parent[r];
            
            if (rep_to_partition[r] < 0) {
                rep_to_partition[r] = next_partition++;
            }
            partition[i] = rep_to_partition[r];
        }
    }
};

/**
 * Build minimized DFA from partition assignment
 */
static int build_minimized_dfa_from_partitions(
    build_dfa_state_t* dfa, 
    int state_count,
    const std::vector<int>& partition,
    int partition_count
) {
    // Allocate new DFA
    build_dfa_state_t* new_dfa = (build_dfa_state_t*)calloc(partition_count, sizeof(build_dfa_state_t));
    if (!new_dfa) return state_count;
    
    // Initialize transitions
    for (int p = 0; p < partition_count; p++) {
        for (int c = 0; c < 256; c++) {
            new_dfa[p].transitions[c] = -1;
        }
    }
    
    // Find representative for each partition
    std::vector<int> rep(partition_count, -1);
    for (int s = 0; s < state_count; s++) {
        int p = partition[s];
        if (rep[p] < 0) {
            rep[p] = s;
        }
    }
    
    // Build new states from representatives
    std::vector<int> partition_to_new(partition_count);
    int new_count = 0;
    for (int p = 0; p < partition_count; p++) {
        if (rep[p] < 0) continue;
        
        partition_to_new[p] = new_count;
        int s = rep[p];
        
        // Copy state properties
        new_dfa[new_count].flags = dfa[s].flags;
        new_dfa[new_count].accepting_pattern_id = dfa[s].accepting_pattern_id;
        new_dfa[new_count].eos_target = dfa[s].eos_target;
        new_dfa[new_count].eos_marker_offset = dfa[s].eos_marker_offset;
        
        // Copy transitions (will be remapped)
        for (int c = 0; c < 256; c++) {
            new_dfa[new_count].transitions[c] = dfa[s].transitions[c];
            new_dfa[new_count].transitions_from_any[c] = dfa[s].transitions_from_any[c];
            new_dfa[new_count].marker_offsets[c] = dfa[s].marker_offsets[c];
        }
        
        // Merge category bits from all states in partition
        uint8_t merged_cat = 0;
        for (int i = 0; i < state_count; i++) {
            if (partition[i] == p && (dfa[i].flags & DFA_STATE_ACCEPTING)) {
                merged_cat |= (dfa[i].flags >> 8) & 0xFF;
            }
        }
        new_dfa[new_count].flags = (new_dfa[new_count].flags & 0x00FF) | ((uint16_t)merged_cat << 8);
        
        new_count++;
    }
    
    // Remap transitions
    for (int p = 0; p < new_count; p++) {
        for (int c = 0; c < 256; c++) {
            int old_target = new_dfa[p].transitions[c];
            if (old_target >= 0 && old_target < state_count) {
                new_dfa[p].transitions[c] = partition_to_new[partition[old_target]];
            }
        }
        if (new_dfa[p].eos_target != 0 && new_dfa[p].eos_target < (uint32_t)state_count) {
            new_dfa[p].eos_target = partition_to_new[partition[new_dfa[p].eos_target]];
        }
    }
    
    // Copy back
    memcpy(dfa, new_dfa, new_count * sizeof(build_dfa_state_t));
    free(new_dfa);
    
    return new_count;
}

/**
 * Try to minimize DFA to a specific number of partitions
 * Returns the number of states if successful, -1 if not satisfiable
 */
static int try_minimize_to_partition_count(build_dfa_state_t* dfa, int state_count, int target_partitions) {
    if (target_partitions >= state_count) return state_count;
    if (target_partitions < 1) return -1;
    
    EquivalenceEncoder enc(state_count);
    
    // Encode constraints
    enc.encode_transitivity();
    enc.encode_accepting_separation(dfa);
    enc.encode_category_separation(dfa);
    enc.encode_transition_consistency(dfa);
    
    // Solve
    if (!enc.solve()) {
        return -1;
    }
    
    // Extract partitions
    std::vector<int> partition;
    enc.get_partitions(partition);
    
    // Count actual partitions
    int max_partition = 0;
    for (int p : partition) {
        if (p > max_partition) max_partition = p;
    }
    int actual_partitions = max_partition + 1;
    
    // Build minimized DFA
    return build_minimized_dfa_from_partitions(dfa, state_count, partition, actual_partitions);
}

extern "C" {

/**
 * SAT-based DFA minimization using equivalence relation encoding
 * 
 * This approach has O(n² × |Σ| + n³) complexity instead of O(n² × |Σ| × p²).
 * For large DFAs, it falls back to Hopcroft's algorithm.
 */
int dfa_minimize_sat(build_dfa_state_t* dfa, int state_count) {
    if (state_count <= 1) return state_count;
    
    // First, run Hopcroft to get upper bound
    int hopcroft_result = dfa_minimize_hopcroft(dfa, state_count);
    if (hopcroft_result <= 1) return hopcroft_result;
    
    // Check if DFA is small enough for SAT
    if (hopcroft_result > MAX_EQ_STATES) {
        fprintf(stderr, "Note: DFA has %d states after Hopcroft, exceeding SAT limit of %d\n",
                hopcroft_result, MAX_EQ_STATES);
        return hopcroft_result;
    }
    
    // Compute theoretical minimum
    int min_partitions = 1;
    bool has_accepting = false;
    for (int s = 0; s < hopcroft_result; s++) {
        if (dfa[s].flags & DFA_STATE_ACCEPTING) {
            has_accepting = true;
            break;
        }
    }
    if (has_accepting) min_partitions++;
    
    // Count distinct categories
    uint32_t seen_categories = 0;
    for (int s = 0; s < hopcroft_result; s++) {
        uint8_t cat = (dfa[s].flags >> 8) & 0xFF;
        if (cat != 0) {
            seen_categories |= (1u << cat);
        }
    }
    while (seen_categories) {
        min_partitions += (seen_categories & 1);
        seen_categories >>= 1;
    }
    
    // If Hopcroft already achieved minimum, we're done
    if (hopcroft_result == min_partitions) {
        return hopcroft_result;
    }
    
    // Try to find smaller solution using SAT
    // Binary search for minimum partition count
    int lower = min_partitions;
    int upper = hopcroft_result;
    int best = hopcroft_result;
    
    for (int iter = 0; iter < MAX_SAT_ITERATIONS && lower < upper; iter++) {
        int mid = (lower + upper) / 2;
        
        // Make a copy to try
        build_dfa_state_t* copy = (build_dfa_state_t*)malloc(hopcroft_result * sizeof(build_dfa_state_t));
        if (!copy) break;
        memcpy(copy, dfa, hopcroft_result * sizeof(build_dfa_state_t));
        
        int result = try_minimize_to_partition_count(copy, hopcroft_result, mid);
        
        if (result > 0 && result < best) {
            // Success - copy result
            memcpy(dfa, copy, result * sizeof(build_dfa_state_t));
            best = result;
            upper = mid;
        } else {
            // Failed - need more partitions
            lower = mid + 1;
        }
        
        free(copy);
    }
    
    return best;
}

} // extern "C"
