/**
 * NFA Pre-Minimization: SAT-Based Optimal Merge Selection
 * 
 * This module implements SAT-based optimization for NFA state merging.
 * Unlike the previous approach which used SAT for bisimulation verification,
 * this uses SAT for OPTIMAL SELECTION from pre-filtered candidates.
 * 
 * Key Design Principles:
 * 1. Polynomial-time pre-filtering generates safe merge candidates
 * 2. SAT finds the maximum set of non-conflicting merges
 * 3. Complexity is bounded by limiting the number of candidates
 * 
 * Algorithm:
 * 1. Collect merge candidates from prefix/suffix analysis (O(n log n))
 * 2. Build conflict graph between candidates (O(m²))
 * 3. Encode as MaxSAT and solve
 * 4. Apply optimal merge set
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <vector>
#include <algorithm>
#include <set>
#include <map>

extern "C" {
#include "nfa_preminimize.h"
#include "../include/nfa.h"
#include "../include/multi_target_array.h"
}

#ifdef USE_CADICAL
#include <functional>
#include "cadical.hpp"
#endif

// Configuration
#define MAX_CANDIDATES 500        // Maximum merge candidates for SAT
#define MAX_SAT_TIME_MS 10000     // Timeout for SAT solver

// Verbose output
static bool sat_opt_verbose = false;

#define VERBOSE_PRINT(...) do { \
    if (sat_opt_verbose) fprintf(stderr, "[SAT-OPT] " __VA_ARGS__); \
} while(0)

// Epsilon symbol
#define VSYM_EPS 257

// ============================================================================
// CANDIDATE STRUCTURE
// ============================================================================

/**
 * A merge candidate represents two states that can potentially be merged.
 * Each candidate has a type (prefix, suffix, or final) and safety properties.
 */
typedef enum {
    MERGE_TYPE_PREFIX,    // Same incoming (source, symbol)
    MERGE_TYPE_SUFFIX,    // Same outgoing (target, symbol)
    MERGE_TYPE_FINAL      // Equivalent final states
} merge_type_t;

typedef struct {
    int state1;           // First state (lower index)
    int state2;           // Second state (higher index)
    merge_type_t type;    // Type of merge
    uint64_t signature;   // Hash of properties for quick comparison
    int priority;         // Higher priority = prefer this merge
} merge_candidate_t;

// ============================================================================
// HELPER FUNCTIONS (reused from nfa_preminimize.c)
// ============================================================================

/**
 * Get all successor states for a given state and symbol.
 */
static std::vector<int> get_successors(const nfa_state_t* nfa, int state_idx, int symbol) {
    std::vector<int> successors;
    const nfa_state_t* state = &nfa[state_idx];
    
    // Check fast-path single targets
    if (state->multi_targets.has_first_target[symbol]) {
        successors.push_back(state->multi_targets.first_targets[symbol]);
    }
    
    // Check multi-targets
    int count;
    int* targets = mta_get_target_array((multi_target_array_t*)&state->multi_targets, symbol, &count);
    if (targets && count > 0) {
        for (int i = 0; i < count; i++) {
            bool found = false;
            for (int s : successors) {
                if (s == targets[i]) { found = true; break; }
            }
            if (!found) successors.push_back(targets[i]);
        }
    }
    
    // Also check legacy transitions[] array
    if (state->transitions[symbol] >= 0) {
        bool found = false;
        for (int s : successors) {
            if (s == state->transitions[symbol]) { found = true; break; }
        }
        if (!found) successors.push_back(state->transitions[symbol]);
    }
    
    std::sort(successors.begin(), successors.end());
    return successors;
}

/**
 * Check if two states have identical outgoing transitions.
 */
static bool states_outgoing_match(const nfa_state_t* nfa, int s1, int s2) {
    const nfa_state_t* state1 = &nfa[s1];
    const nfa_state_t* state2 = &nfa[s2];
    
    // Check fast-path single targets
    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
        bool has1 = state1->multi_targets.has_first_target[sym];
        bool has2 = state2->multi_targets.has_first_target[sym];
        if (has1 != has2) return false;
        if (has1 && state1->multi_targets.first_targets[sym] != state2->multi_targets.first_targets[sym]) {
            return false;
        }
    }
    
    // Check multi-targets
    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
        std::vector<int> succ1 = get_successors(nfa, s1, sym);
        std::vector<int> succ2 = get_successors(nfa, s2, sym);
        if (succ1.size() != succ2.size()) return false;
        for (size_t i = 0; i < succ1.size(); i++) {
            if (succ1[i] != succ2[i]) return false;
        }
    }
    
    // Check legacy transitions
    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
        if (state1->transitions[sym] != state2->transitions[sym]) return false;
    }
    
    return true;
}

/**
 * Compute signature for a state's accepting properties.
 */
static uint64_t compute_accepting_signature(const nfa_state_t* state) {
    uint64_t hash = 14695981039346656037ULL;
    
    hash ^= state->category_mask;
    hash *= 1099511628211ULL;
    hash ^= state->pattern_id;
    hash *= 1099511628211ULL;
    hash ^= state->is_eos_target ? 1 : 0;
    hash *= 1099511628211ULL;
    hash ^= state->pending_marker_count;
    hash *= 1099511628211ULL;
    
    for (int i = 0; i < state->pending_marker_count; i++) {
        hash ^= state->pending_markers[i].pattern_id;
        hash *= 1099511628211ULL;
        hash ^= state->pending_markers[i].uid;
        hash *= 1099511628211ULL;
        hash ^= state->pending_markers[i].type;
        hash *= 1099511628211ULL;
    }
    
    return hash;
}

/**
 * Compute signature for a state's category only (ignoring pattern_id).
 * This allows merging accepting states from different patterns with same category.
 */
static uint64_t compute_category_signature(const nfa_state_t* state) {
    uint64_t hash = 14695981039346656037ULL;
    
    // Only include category_mask and is_eos_target
    // This allows merging accepting states from different patterns
    hash ^= state->category_mask;
    hash *= 1099511628211ULL;
    hash ^= state->is_eos_target ? 1 : 0;
    hash *= 1099511628211ULL;
    
    // Include pending markers but without pattern_id
    hash ^= state->pending_marker_count;
    hash *= 1099511628211ULL;
    
    for (int i = 0; i < state->pending_marker_count; i++) {
        hash ^= state->pending_markers[i].uid;
        hash *= 1099511628211ULL;
        hash ^= state->pending_markers[i].type;
        hash *= 1099511628211ULL;
    }
    
    return hash;
}

// ============================================================================
// CANDIDATE GENERATION
// ============================================================================

// ============================================================================
// CONFLICT ANALYSIS
// ============================================================================

/**
 * Check if two merge candidates conflict.
 *
 * Two candidates conflict if they share ANY state.
 * (a1, b1) and (a2, b2) conflict when {a1, b1} ∩ {a2, b2} ≠ ∅.
 * A state can only participate in one merge (it either survives
 * as the representative, or gets marked dead).
 */
static bool candidates_conflict(
    const merge_candidate_t& c1,
    const merge_candidate_t& c2
) {
    int a1 = c1.state1, b1 = c1.state2;
    int a2 = c2.state1, b2 = c2.state2;

    if (a1 == a2 && b1 == b2) return false;  // Same pair

    return (a1 == a2 || a1 == b2 || b1 == a2 || b1 == b2);
}

/**
 * Build conflict graph between candidates.
 * Returns a map from candidate index to set of conflicting candidate indices.
 */
static std::map<int, std::set<int>> build_conflict_graph(
    const std::vector<merge_candidate_t>& candidates
) {
    std::map<int, std::set<int>> conflicts;

    for (size_t i = 0; i < candidates.size(); i++) {
        for (size_t j = i + 1; j < candidates.size(); j++) {
            if (candidates_conflict(candidates[i], candidates[j])) {
                conflicts[i].insert(j);
                conflicts[j].insert(i);
            }
        }
    }

    return conflicts;
}

// ============================================================================
// SAT ENCODING AND SOLVING
// ============================================================================

#ifdef USE_CADICAL

/**
 * Greedy selection for maximal set of non-conflicting merges.
 * This is a fallback when SAT solving fails.
 */
static std::set<int> solve_optimal_merges_greedy(
    const std::vector<merge_candidate_t>& candidates,
    const std::map<int, std::set<int>>& conflicts
) {
    std::set<int> result;
    
    if (candidates.empty()) return result;
    
    int n = candidates.size();
    
    // Track which states have been merged
    std::set<int> merged_states;
    
    // Sort candidates by priority (higher first)
    std::vector<int> order(n);
    for (int i = 0; i < n; i++) order[i] = i;
    std::sort(order.begin(), order.end(), [&](int a, int b) {
        return candidates[a].priority > candidates[b].priority;
    });
    
    // Greedily select non-conflicting candidates
    for (int idx : order) {
        const merge_candidate_t& cand = candidates[idx];
        
        // Check if either state is already merged
        if (merged_states.count(cand.state1) || merged_states.count(cand.state2)) {
            continue;
        }
        
        // Check for conflicts with already selected candidates
        bool has_conflict = false;
        auto it = conflicts.find(idx);
        if (it != conflicts.end()) {
            for (int conflict_idx : it->second) {
                if (result.count(conflict_idx)) {
                    has_conflict = true;
                    break;
                }
            }
        }
        
        if (!has_conflict) {
            result.insert(idx);
            merged_states.insert(cand.state1);
            merged_states.insert(cand.state2);
        }
    }
    
    VERBOSE_PRINT("Greedy selection selected %zu merges\n", result.size());
    
    return result;
}

// ============================================================================
// TOTALIZER ENCODING FOR CARDINALITY CONSTRAINTS
// ============================================================================

/**
 * Totalizer tree node. Represents a binary tree over the n input variables.
 * Leaves are the inputs; internal nodes represent merged sub-counts.
 *
 * For each internal node u with children L, R and subtree size s_u:
 *   bits[u][k] = true iff at least (k+1) of the subtree inputs are selected,
 *                for k in [0, s_u-1].
 *
 * The single forward encoding rule (per k, a, b with a+b = k):
 *   ¬bits[L][a] ∨ ¬bits[R][b] ∨ bits[u][k]
 *
 * This is the Bailleux-Boufkhad totalizer (2006): O(n log n) aux vars and
 * O(n log n) clauses. For n=200: ~1,200 aux vars, ~3,000 aux clauses.
 */
struct TotNode {
    bool is_leaf;
    int input_idx;                        // Only for leaves: candidate index
    int left;                             // Left child node index (-1 for leaves)
    int right;                            // Right child node index (-1 for leaves)
    int subtree_size;                     // Number of leaves in subtree
    std::vector<int> bits;                // bits[k] = literal for "count >= k+1"
    // bits[0] is implicit true, stored as 0 (unused slot for convenience)
};

/**
 * Build a balanced binary totalizer tree over n input variables.
 *
 * Tree structure: 2n-1 total nodes. Leaves 0..n-1, internals n..2n-2.
 * Root is at index 2n-2. Built bottom-up layer by layer.
 *
 * @param n       Number of input variables
 * @param cand_var  Maps candidate index → SAT literal
 * @param next_var  Running counter for fresh aux variable allocation (modified)
 * @return        Vector of all tree nodes
 */
static std::vector<TotNode> build_totalizer_tree(
    int n,
    std::function<int(int)> cand_var,
    int& next_var
) {
    int total_nodes = 2 * n - 1;
    std::vector<TotNode> tree(total_nodes);

    // Initialize leaves (indices 0 .. n-1)
    for (int i = 0; i < n; i++) {
        tree[i].is_leaf = true;
        tree[i].input_idx = i;
        tree[i].left = -1;
        tree[i].right = -1;
        tree[i].subtree_size = 1;
        // bits[0] is implicit (always true). bits[1] = literal x_i.
        tree[i].bits.resize(2, 0);
        tree[i].bits[1] = cand_var(i);
    }

    // Build internal nodes bottom-up by levels
    // Level 0: leaves are at node indices 0..n-1, count = n
    // Each level halves the count, pairing adjacent nodes
    std::vector<int> current_level(2 * n);
    int current_count = 0;
    for (int i = 0; i < n; i++) current_level[current_count++] = i;

    int next_node = n;  // next free node index

    while (current_count > 1) {
        int next_count = 0;
        std::vector<int> next_level(2 * n);

        for (int i = 0; i + 1 < current_count; i += 2) {
            int left_idx = current_level[i];
            int right_idx = current_level[i + 1];
            int u = next_node++;

            tree[u].is_leaf = false;
            tree[u].left = left_idx;
            tree[u].right = right_idx;
            tree[u].subtree_size = tree[left_idx].subtree_size + tree[right_idx].subtree_size;

            // Allocate auxiliary variables for bits[1 .. subtree_size-1]
            // bits[0] is implicit true (stored as 0)
            tree[u].bits.resize(tree[u].subtree_size, 0);
            for (int k = 1; k < tree[u].subtree_size; k++) {
                tree[u].bits[k] = next_var++;
            }

            next_level[next_count++] = u;
        }

        // If odd count, carry last node to next level
        if (current_count % 2 == 1) {
            next_level[next_count++] = current_level[current_count - 1];
        }

        for (int i = 0; i < next_count; i++) current_level[i] = next_level[i];
        current_count = next_count;
    }

    return tree;
}

/**
 * Add the totalizer clauses for node u.
 *
 * Two sets of clauses per internal node (Bailleux-Boufkhad 2006):
 *
 * 1. Merging (forward):  ¬L[a] ∨ ¬R[b] ∨ U[k]    for each k = a+b
 *    "If left has ≥a+1 and right has ≥b+1, then U has ≥k+1"
 *
 * 2. Decomposition (backward):
 *    a) ¬U[k] ∨ L[k]     "If U has ≥k+1, left has ≥k+1"
 *    b) ¬U[k] ∨ R[k]     "If U has ≥k+1, right has ≥k+1"
 *    Only emitted for k values each child actually supports (k < subtree_size).
 *
 * bits[][0] is implicit true, so those terms are omitted from clauses.
 */
static void add_totalizer_clauses(CaDiCaL::Solver& solver, const std::vector<TotNode>& tree, int u) {
    const TotNode& node = tree[u];
    if (node.is_leaf) return;

    const TotNode& L = tree[node.left];
    const TotNode& R = tree[node.right];

    // Merging clauses
    for (int k = 1; k < node.subtree_size; k++) {
        int a_lo = std::max(0, k - (R.subtree_size - 1));
        int a_hi = std::min(k, L.subtree_size - 1);

        for (int a = a_lo; a <= a_hi; a++) {
            int b = k - a;

            int terms[3];
            int nt = 0;
            if (a > 0) terms[nt++] = -L.bits[a];
            if (b > 0) terms[nt++] = -R.bits[b];
            terms[nt++] = node.bits[k];

            for (int t = 0; t < nt; t++) solver.add(terms[t]);
            solver.add(0);
        }
    }

    // Decomposition clauses: U[k] → L[k]  and  U[k] → R[k]
    for (int k = 1; k < node.subtree_size; k++) {
        // ¬U[k] ∨ L[k]   (only if left subtree can represent count k+1)
        if (k < L.subtree_size) {
            solver.add(-node.bits[k]);
            solver.add(L.bits[k]);
            solver.add(0);
        }

        // ¬U[k] ∨ R[k]   (only if right subtree can represent count k+1)
        if (k < R.subtree_size) {
            solver.add(-node.bits[k]);
            solver.add(R.bits[k]);
            solver.add(0);
        }
    }
}

// ============================================================================
// BOUNDED SAT MAXIMUM INDEPENDENT SET SOLVER
// ============================================================================

/**
 * Bounded MaxIS SAT solver using totalizer cardinality encoding.
 *
 * Finds the maximum independent set in the conflict graph via iterative
 * cardinality-bounded SAT with a single solver instance and incremental
 * tightening.
 *
 * Bounded complexity for n ≤ MAX_CANDIDATES (200):
 *   Totalizer structure:  O(n log n) aux vars  ≈ 1,200
 *   Totalizer clauses:    O(n log n) aux cls   ≈ 3,000
 *   Conflict clauses:     O(m) edges           ≤ 19,900
 *   Card-tightening:      1 blocking clause per iteration
 *   Iterations:           typically 1–5
 *
 * @param candidates  Merge candidates
 * @param conflicts   Conflict graph (candidate index → set of conflicting indices)
 * @return            Set of selected candidate indices (optimal or best found)
 */
static std::set<int> solve_optimal_merges_sat(
    const std::vector<merge_candidate_t>& candidates,
    const std::map<int, std::set<int>>& conflicts
) {
    int n = (int)candidates.size();
    if (n == 0) return {};

    // Greedy lower bound
    std::set<int> greedy_result = solve_optimal_merges_greedy(candidates, conflicts);
    int greedy_size = (int)greedy_result.size();

    if (greedy_size == n) return greedy_result;
    if (greedy_size == 0) return greedy_result;

    // Count conflict edges for verbose
    int total_conflicts = 0;
    for (const auto& entry : conflicts) {
        total_conflicts += (int)entry.second.size();
    }
    total_conflicts /= 2;

    VERBOSE_PRINT("Bounded SAT MaxIS (totalizer): %d candidates, %d conflict edges, greedy lower bound = %d\n",
                  n, total_conflicts, greedy_size);

    // --- Build ONE solver instance ---
    CaDiCaL::Solver solver;
    solver.set("quiet", 1);

    // Candidate variables: x_i → variable i+1 (1-indexed)
    auto cand_var = [](int i) -> int { return i + 1; };
    int next_var = n + 1;  // first aux variable after candidates

    // Build totalizer tree (computes all aux variable IDs)
    std::vector<TotNode> tree = build_totalizer_tree(n, cand_var, next_var);

    // Pre-declare all variables before adding clauses
    // CaDiCaL in factorcheck mode requires explicit variable declaration
    solver.resize(next_var);

    // Add totalizer clauses
    for (int u = n; u < (int)tree.size(); u++) {
        add_totalizer_clauses(solver, tree, u);
    }

    int root = (int)tree.size() - 1;

    // Conflict clauses: for each edge (i,j), (¬x_i ∨ ¬x_j)
    for (const auto& entry : conflicts) {
        int i = entry.first;
        for (int j : entry.second) {
            if (j > i) {
                solver.add(-cand_var(i));
                solver.add(-cand_var(j));
                solver.add(0);
            }
        }
    }

    std::set<int> best_result = greedy_result;
    int best_size = greedy_size;

    // --- Find maximum via iterative assumption-based solve ---
    //
    // Totalizer root bits[j] means "count >= j+1".
    // For each target t from greedy_size+1 to n:
    //   Assume root.bits[t] (force count >= t+1)
    //   Solve — SAT means a model of size t+1 exists
    //   Record the model and try t+1
    //   UNSAT means no model of size t+1 exists → current best is optimal
    //
    // Assumptions are lightweight (incremental, no clause modification).
    for (int t = greedy_size; t < n; t++) {
        // Ask: can we find an independent set of size >= t+1?
        solver.assume(tree[root].bits[t]);

        int res = solver.solve();

        if (res != 10) {
            VERBOSE_PRINT("  UNSAT at count >= %d (optimal size = %d)\n", t + 1, best_size);
            break;
        }

        std::set<int> selected;
        for (int i = 0; i < n; i++) {
            if (solver.val(cand_var(i)) > 0) {
                selected.insert(i);
            }
        }

        best_result = selected;
        best_size = (int)selected.size();

        VERBOSE_PRINT("  SAT at count >= %d (found %d merges)\n", t + 1, best_size);
    }

    if (best_size > greedy_size) {
        VERBOSE_PRINT("  SAT improved: %d → %d merges\n", greedy_size, best_size);
    } else {
        VERBOSE_PRINT("  Greedy was optimal (%d merges)\n", greedy_size);
    }

    VERBOSE_PRINT("Bounded SAT result: %d merges (greedy was %d)\n", best_size, greedy_size);

    return best_result;
}

#endif // USE_CADICAL

// ============================================================================
// MERGE APPLICATION
// ============================================================================

/**
 * Apply a single merge: redirect all transitions from state2 to state1.
 */
static void apply_merge(nfa_state_t* nfa, int state_count, bool* dead_states, int state1, int state2) {
    if (dead_states[state1] || dead_states[state2]) return;
    if (state1 == state2) return;
    
    VERBOSE_PRINT("  Merging state %d into %d\n", state2, state1);
    
    // Redirect all transitions pointing to state2 to state1
    for (int s = 0; s < state_count; s++) {
        if (dead_states[s]) continue;
        
        nfa_state_t* state = &nfa[s];
        
        // Redirect fast-path single targets
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            if (state->multi_targets.has_first_target[sym] && 
                state->multi_targets.first_targets[sym] == state2) {
                state->multi_targets.first_targets[sym] = state1;
            }
        }
        
        // Redirect multi-targets
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int count;
            int* targets = mta_get_target_array(&state->multi_targets, sym, &count);
            if (targets && count > 0) {
                for (int i = 0; i < count; i++) {
                    if (targets[i] == state2) {
                        targets[i] = state1;
                    }
                }
            }
        }
        
        // Redirect legacy transitions
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            if (state->transitions[sym] == state2) {
                state->transitions[sym] = state1;
            }
        }
    }
    
    // Combine accepting properties
    nfa[state1].category_mask |= nfa[state2].category_mask;
    
    // Combine pending markers
    if (nfa[state2].pending_marker_count > 0) {
        for (int i = 0; i < nfa[state2].pending_marker_count && 
                        nfa[state1].pending_marker_count < MAX_PENDING_MARKERS; i++) {
            bool exists = false;
            for (int j = 0; j < nfa[state1].pending_marker_count && !exists; j++) {
                if (nfa[state1].pending_markers[j].uid == nfa[state2].pending_markers[i].uid &&
                    nfa[state1].pending_markers[j].type == nfa[state2].pending_markers[i].type) {
                    exists = true;
                }
            }
            if (!exists) {
                nfa[state1].pending_markers[nfa[state1].pending_marker_count++] = nfa[state2].pending_markers[i];
            }
        }
    }
    
    // Mark state2 as dead
    dead_states[state2] = true;
}

/**
 * Apply all selected merges.
 */
static int apply_selected_merges(
    nfa_state_t* nfa,
    int state_count,
    bool* dead_states,
    const std::vector<merge_candidate_t>& candidates,
    const std::set<int>& selected
) {
    int merged = 0;
    
    // Sort selected by type (FINAL first, then SUFFIX, then PREFIX)
    // This ensures we merge final states first, creating longer suffixes
    std::vector<int> sorted_selected(selected.begin(), selected.end());
    std::sort(sorted_selected.begin(), sorted_selected.end(), [&](int a, int b) {
        return candidates[a].type > candidates[b].type;  // FINAL=2 > SUFFIX=1 > PREFIX=0
    });
    
    for (int idx : sorted_selected) {
        const merge_candidate_t& cand = candidates[idx];
        
        if (dead_states[cand.state1] || dead_states[cand.state2]) {
            VERBOSE_PRINT("  Skipping merge %d: state already dead\n", idx);
            continue;
        }
        
        apply_merge(nfa, state_count, dead_states, cand.state1, cand.state2);
        merged++;
    }
    
    return merged;
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

// Forward declarations
static std::set<int> solve_optimal_merges_greedy(
    const std::vector<merge_candidate_t>& candidates,
    const std::map<int, std::set<int>>& conflicts
);

#ifdef USE_CADICAL
static std::set<int> solve_optimal_merges_sat(
    const std::vector<merge_candidate_t>& candidates,
    const std::map<int, std::set<int>>& conflicts
);
#endif

/**
 * Collect candidates within a state range [start_state, end_state).
 * This enables windowed processing for O(n) total complexity.
 */
static int collect_candidates_in_window(
    const nfa_state_t* nfa,
    int state_count,
    const bool* dead_states,
    std::vector<merge_candidate_t>& candidates,
    int start_state,
    int end_state
) {
    int count = 0;
    
    // Collect prefix candidates where source is in window
    typedef std::pair<int, int> source_symbol_t;
    std::map<source_symbol_t, std::vector<int>> incoming_map;
    
    for (int s = start_state; s < end_state && s < state_count; s++) {
        if (dead_states[s]) continue;
        
        const nfa_state_t* state = &nfa[s];
        
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            if (state->multi_targets.has_first_target[sym]) {
                int target = state->multi_targets.first_targets[sym];
                if (target >= 0 && !dead_states[target] && target != 0 && nfa[target].category_mask == 0) {
                    incoming_map[{s, sym}].push_back(target);
                }
            }
            
            int cnt;
            int* targets = mta_get_target_array((multi_target_array_t*)&state->multi_targets, sym, &cnt);
            if (targets && cnt > 0) {
                for (int i = 0; i < cnt; i++) {
                    if (targets[i] >= 0 && !dead_states[targets[i]] && targets[i] != 0 && nfa[targets[i]].category_mask == 0) {
                        incoming_map[{s, sym}].push_back(targets[i]);
                    }
                }
            }
        }
    }
    
    // Group by (source, symbol, signature)
    std::map<std::tuple<int, int, uint64_t>, std::vector<int>> prefix_groups;
    for (const auto& entry : incoming_map) {
        int source = entry.first.first;
        int symbol = entry.first.second;
        const std::vector<int>& targets = entry.second;
        
        for (int target : targets) {
            uint64_t sig = compute_accepting_signature(&nfa[target]);
            prefix_groups[{source, symbol, sig}].push_back(target);
        }
    }
    
    // Generate prefix candidates
    for (auto& group : prefix_groups) {
        std::vector<int>& states = group.second;
        if (states.size() < 2) continue;
        
        std::sort(states.begin(), states.end());
        states.erase(std::unique(states.begin(), states.end()), states.end());
        
        if (states.size() < 2) continue;
        
        for (size_t i = 0; i < states.size() && (int)candidates.size() < MAX_CANDIDATES; i++) {
            for (size_t j = i + 1; j < states.size() && (int)candidates.size() < MAX_CANDIDATES; j++) {
                if (states_outgoing_match(nfa, states[i], states[j])) {
                    merge_candidate_t cand;
                    cand.state1 = std::min(states[i], states[j]);
                    cand.state2 = std::max(states[i], states[j]);
                    cand.type = MERGE_TYPE_PREFIX;
                    cand.signature = std::get<2>(group.first);
                    cand.priority = 1;
                    candidates.push_back(cand);
                    count++;
                }
            }
        }
    }
    
    // Collect suffix candidates where state is in window
    // Group by (target_category_sig, symbol, source_sig) to enable 3-to-2 merging
    std::map<std::tuple<uint64_t, int, uint64_t>, std::vector<int>> suffix_groups;
    
    for (int s = start_state; s < end_state && s < state_count; s++) {
        if (dead_states[s]) continue;
        if (s == 0) continue;
        
        const nfa_state_t* state = &nfa[s];
        
        std::vector<std::pair<int, int>> outgoing;
        
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            if (state->multi_targets.has_first_target[sym]) {
                outgoing.push_back({sym, state->multi_targets.first_targets[sym]});
            }
            
            int cnt;
            int* targets = mta_get_target_array((multi_target_array_t*)&state->multi_targets, sym, &cnt);
            if (targets && cnt > 0) {
                for (int i = 0; i < cnt; i++) {
                    outgoing.push_back({sym, targets[i]});
                }
            }
        }
        
        uint64_t sig = compute_accepting_signature(state);
        for (const auto& out : outgoing) {
            int symbol = out.first;
            int target = out.second;
            
            if (target >= 0 && !dead_states[target]) {
                // Use category signature of target to enable merging states
                // that point to different accepting states with same category
                uint64_t target_sig = compute_category_signature(&nfa[target]);
                suffix_groups[{target_sig, symbol, sig}].push_back(s);
            }
        }
    }
    
    // Generate suffix candidates
    for (auto& group : suffix_groups) {
        std::vector<int>& states = group.second;
        if (states.size() < 2) continue;
        
        std::sort(states.begin(), states.end());
        states.erase(std::unique(states.begin(), states.end()), states.end());
        
        if (states.size() < 2) continue;
        
        for (size_t i = 0; i < states.size() && (int)candidates.size() < MAX_CANDIDATES; i++) {
            for (size_t j = i + 1; j < states.size() && (int)candidates.size() < MAX_CANDIDATES; j++) {
                // CRITICAL: Verify states have matching outgoing transitions
                // Without this check, we could merge states with different futures
                if (states_outgoing_match(nfa, states[i], states[j])) {
                    merge_candidate_t cand;
                    cand.state1 = std::min(states[i], states[j]);
                    cand.state2 = std::max(states[i], states[j]);
                    cand.type = MERGE_TYPE_SUFFIX;
                    cand.signature = std::get<2>(group.first);
                    cand.priority = 1;
                    candidates.push_back(cand);
                    count++;
                }
            }
        }
    }
    
    // Collect final state candidates (accepting states with same category, no pending markers)
    // This enables 3-to-2 merging by first merging accepting states
    std::map<uint64_t, std::vector<int>> final_groups;
    
    for (int s = start_state; s < end_state && s < state_count; s++) {
        if (dead_states[s]) continue;
        if (nfa[s].category_mask == 0) continue;  // Only accepting states
        if (nfa[s].pending_marker_count > 0) continue;  // Skip states with capture markers
        
        // Use category signature to allow merging across patterns
        uint64_t sig = compute_category_signature(&nfa[s]);
        final_groups[sig].push_back(s);
    }
    
    // Generate final state candidates
    for (auto& group : final_groups) {
        std::vector<int>& states = group.second;
        if (states.size() < 2) continue;
        
        std::sort(states.begin(), states.end());
        states.erase(std::unique(states.begin(), states.end()), states.end());
        
        if (states.size() < 2) continue;
        
        for (size_t i = 0; i < states.size() && (int)candidates.size() < MAX_CANDIDATES; i++) {
            for (size_t j = i + 1; j < states.size() && (int)candidates.size() < MAX_CANDIDATES; j++) {
                // Verify outgoing transitions match (both should have none)
                if (states_outgoing_match(nfa, states[i], states[j])) {
                    merge_candidate_t cand;
                    cand.state1 = std::min(states[i], states[j]);
                    cand.state2 = std::max(states[i], states[j]);
                    cand.type = MERGE_TYPE_FINAL;
                    cand.signature = group.first;
                    cand.priority = 2;  // Higher priority for final states
                    candidates.push_back(cand);
                    count++;
                }
            }
        }
    }
    
    return count;
}

/**
 * Process a single window: collect candidates, build conflicts, solve, apply.
 */
static int process_window(
    nfa_state_t* nfa,
    int state_count,
    bool* dead_states,
    int start_state,
    int end_state,
    int max_candidates
) {
    std::vector<merge_candidate_t> candidates;
    
    collect_candidates_in_window(nfa, state_count, dead_states, candidates, start_state, end_state);
    
    if (candidates.empty()) return 0;
    
    if ((int)candidates.size() > max_candidates) {
        candidates.resize(max_candidates);
    }
    
    // Build conflict graph
    std::map<int, std::set<int>> conflicts = build_conflict_graph(candidates);
    
    int total_conflicts = 0;
    for (const auto& entry : conflicts) {
        total_conflicts += entry.second.size();
    }
    total_conflicts /= 2;
    
    if (total_conflicts == 0) {
        // No conflicts - apply all candidates
        std::set<int> all;
        for (size_t i = 0; i < candidates.size(); i++) all.insert(i);
        return apply_selected_merges(nfa, state_count, dead_states, candidates, all);
    }
    
    // Solve with bounded SAT (falls back to greedy if CaDiCaL unavailable)
#ifdef USE_CADICAL
    std::set<int> selected = solve_optimal_merges_sat(candidates, conflicts);
#else
    std::set<int> selected = solve_optimal_merges_greedy(candidates, conflicts);
#endif
    
    if (selected.empty()) return 0;
    
    return apply_selected_merges(nfa, state_count, dead_states, candidates, selected);
}

/**
 * Iterative windowed SAT-based optimal merge selection.
 * 
 * Slides a window over the state space, processing each window independently.
 * This achieves O(n) total complexity while finding more merges than single-shot.
 * 
 * @param nfa NFA state array
 * @param state_count Number of states
 * @param dead_states Array marking dead states (updated in-place)
 * @param max_candidates Maximum candidates per window
 * @param verbose Enable verbose output
 * @return Number of states merged
 */
extern "C" int nfa_preminimize_optimal_merges(
    nfa_state_t* nfa,
    int state_count,
    bool* dead_states,
    int max_candidates,
    bool verbose
) {
    sat_opt_verbose = verbose;
    
    if (max_candidates <= 0) max_candidates = MAX_CANDIDATES;
    
    VERBOSE_PRINT("Starting iterative windowed optimal merge selection\n");
    VERBOSE_PRINT("NFA has %d states, window size ~%d states\n", state_count, max_candidates / 4);
    
    int total_merged = 0;
    int window_size = max_candidates / 4;  // States per window
    if (window_size < 10) window_size = 10;
    if (window_size > 100) window_size = 100;
    
    int window_stride = window_size * 2 / 3;  // Overlap windows for better coverage
    
    int start = 0;
    int iteration = 0;
    const int max_iterations = (state_count / window_stride) + 2;
    
    while (start < state_count && iteration < max_iterations) {
        int end = start + window_size;
        if (end > state_count) end = state_count;
        
        VERBOSE_PRINT("  Window %d: states [%d, %d)\n", iteration, start, end);
        
        int merged = process_window(nfa, state_count, dead_states, start, end, max_candidates);
        
        if (merged > 0) {
            VERBOSE_PRINT("    Merged %d states in window\n", merged);
            total_merged += merged;
        }
        
        start += window_stride;
        iteration++;
    }
    
    VERBOSE_PRINT("Iterative windowed merge complete: %d states merged in %d windows\n", total_merged, iteration);
    
    return total_merged;
}

/**
 * Check if SAT-based optimal merging is available.
 */
extern "C" bool nfa_preminimize_optimal_available(void) {
#ifdef USE_CADICAL
    return true;
#else
    return false;
#endif
}
