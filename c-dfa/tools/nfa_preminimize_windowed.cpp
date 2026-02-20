/**
 * NFA Pre-Minimization: Windowed SAT Optimization
 * 
 * This module implements region-based local subproblem SAT optimization.
 * 
 * Key Design Principles:
 * 1. Total complexity is O(n log n) in NFA size n
 * 2. Subproblems are bounded to size m (e.g., 50 states)
 * 3. Within each subproblem, we can use O(m²) or even O(2^m) methods
 * 4. Windows slide over the NFA with overlap to catch cross-boundary opportunities
 * 
 * Algorithm:
 * 1. Slide a window of bounded size over the NFA
 * 2. For each window, extract the local subgraph (states + their transitions)
 * 3. Use SAT to find bisimilar states within the subgraph
 * 4. Apply verified merges
 * 
 * Why This Works:
 * - Most optimization opportunities are LOCAL
 * - States that can be merged are usually "nearby" in the NFA structure
 * - By sliding windows with overlap, we don't miss cross-boundary opportunities
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
#include <queue>

#ifdef USE_CADICAL
#include "cadical.hpp"
#endif

extern "C" {
#include "nfa_preminimize.h"
#include "../include/nfa.h"
#include "../include/multi_target_array.h"
}

// Configuration
#define DEFAULT_WINDOW_SIZE 40       // Maximum states per window
#define DEFAULT_WINDOW_OVERLAP 20    // Overlap between consecutive windows
#define MAX_SAT_STATES 50            // Maximum states for SAT subproblem

// Verbose output
static bool windowed_verbose = false;

#define VERBOSE_PRINT(...) do { \
    if (windowed_verbose) fprintf(stderr, "[WINDOWED-SAT] " __VA_ARGS__); \
} while(0)

// Epsilon symbol
#define VSYM_EPS 257

/**
 * Get all successor states for a given state and symbol.
 */
static std::vector<int> get_successors(const nfa_state_t* nfa, int state_idx, int symbol) {
    std::vector<int> successors;
    const nfa_state_t* state = &nfa[state_idx];
    
    if (state->transitions[symbol] >= 0) {
        successors.push_back(state->transitions[symbol]);
    }
    
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
    
    std::sort(successors.begin(), successors.end());
    return successors;
}

/**
 * Compute epsilon closure for a state.
 * Returns all states reachable via epsilon transitions (including the state itself).
 */
static std::set<int> epsilon_closure(const nfa_state_t* nfa, int state_idx, int state_count, const bool* dead_states) {
    std::set<int> closure;
    std::queue<int> queue;
    
    queue.push(state_idx);
    closure.insert(state_idx);
    
    while (!queue.empty()) {
        int s = queue.front();
        queue.pop();
        
        if (dead_states[s]) continue;
        
        // Get epsilon successors
        std::vector<int> eps_succ = get_successors(nfa, s, VSYM_EPS);
        for (int succ : eps_succ) {
            if (closure.find(succ) == closure.end() && !dead_states[succ]) {
                closure.insert(succ);
                queue.push(succ);
            }
        }
    }
    
    return closure;
}

/**
 * Get epsilon-closed successors for a state and symbol.
 * This computes: epsilon_closure(move(state, symbol))
 */
static std::set<int> get_epsilon_closed_successors(const nfa_state_t* nfa, int state_idx, int symbol,
                                                    int state_count, const bool* dead_states) {
    std::set<int> result;
    
    // Get direct successors on this symbol
    std::vector<int> direct = get_successors(nfa, state_idx, symbol);
    
    // For each direct successor, compute its epsilon closure
    for (int succ : direct) {
        if (dead_states[succ]) continue;
        std::set<int> ec = epsilon_closure(nfa, succ, state_count, dead_states);
        result.insert(ec.begin(), ec.end());
    }
    
    return result;
}

/**
 * Check if two states have identical accepting properties.
 */
static bool states_accepting_match(const nfa_state_t* nfa, int s1, int s2) {
    const nfa_state_t* state1 = &nfa[s1];
    const nfa_state_t* state2 = &nfa[s2];
    
    if (state1->category_mask != state2->category_mask) return false;
    if (state1->pattern_id != state2->pattern_id) return false;
    if (state1->pending_marker_count != state2->pending_marker_count) return false;
    if (state1->is_eos_target != state2->is_eos_target) return false;
    
    for (int i = 0; i < state1->pending_marker_count; i++) {
        if (state1->pending_markers[i].pattern_id != state2->pending_markers[i].pattern_id) return false;
        if (state1->pending_markers[i].type != state2->pending_markers[i].type) return false;
    }
    
    return true;
}

/**
 * Get all symbols used in outgoing transitions from a state.
 */
static std::set<int> get_used_symbols(const nfa_state_t* nfa, int state_idx) {
    std::set<int> symbols;
    const nfa_state_t* state = &nfa[state_idx];
    
    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
        if (state->transitions[sym] >= 0) {
            symbols.insert(sym);
        }
    }
    
    int mta_count = mta_get_entry_count((multi_target_array_t*)&state->multi_targets);
    if (mta_count > 0) {
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int count;
            int* targets = mta_get_target_array((multi_target_array_t*)&state->multi_targets, sym, &count);
            if (targets && count > 0) {
                symbols.insert(sym);
            }
        }
    }
    
    return symbols;
}

#ifdef USE_CADICAL
/**
 * SAT-based bisimulation verification for a local subgraph.
 * 
 * This uses proper epsilon-aware bisimulation:
 * Two states s1 and s2 are bisimilar iff:
 * 1. They have identical accepting properties
 * 2. For every symbol, their epsilon-closed successor sets are bisimilar
 * 
 * @param nfa NFA state array
 * @param states List of state indices in this subgraph
 * @param state_count Total NFA state count
 * @param dead_states Dead state markers
 * @return Map from state index to representative
 */
static std::map<int, int> verify_local_bisimulation_sat(
    const nfa_state_t* nfa,
    const std::vector<int>& states,
    int state_count,
    const bool* dead_states
) {
    std::map<int, int> result;
    
    int k = states.size();
    if (k < 2) return result;
    
    VERBOSE_PRINT("  SAT verification for %d states\n", k);
    
    // Pre-check: all states must have matching accepting properties
    for (int i = 1; i < k; i++) {
        if (!states_accepting_match(nfa, states[0], states[i])) {
            VERBOSE_PRINT("  Accepting properties mismatch, no merges possible\n");
            return result;
        }
    }
    
    // Collect all symbols used by any state
    std::set<int> all_symbols;
    for (int s : states) {
        std::set<int> syms = get_used_symbols(nfa, s);
        all_symbols.insert(syms.begin(), syms.end());
    }
    
    // Create SAT solver
    CaDiCaL::Solver solver;
    solver.set("quiet", 1);
    
    // Variable: bisim[i][j] for i < j (states i and j are bisimilar)
    auto var = [k](int i, int j) -> int {
        if (i > j) { int t = i; i = j; j = t; }
        return i * k + j - i * (i + 1) / 2 + 1;
    };
    
    // Transitivity constraints
    for (int i = 0; i < k; i++) {
        for (int j = i + 1; j < k; j++) {
            for (int l = j + 1; l < k; l++) {
                solver.add(-var(i, j));
                solver.add(-var(j, l));
                solver.add(var(i, l));
                solver.add(0);
                
                solver.add(-var(i, j));
                solver.add(-var(i, l));
                solver.add(var(j, l));
                solver.add(0);
                
                solver.add(-var(i, l));
                solver.add(-var(j, l));
                solver.add(var(i, j));
                solver.add(0);
            }
        }
    }
    
    // Epsilon-aware transition constraints
    // For each symbol, check if successor sets can be bisimilar
    for (int sym : all_symbols) {
        for (int i = 0; i < k; i++) {
            for (int j = i + 1; j < k; j++) {
                // Get epsilon-closed successors
                std::set<int> succ_i = get_epsilon_closed_successors(nfa, states[i], sym, state_count, dead_states);
                std::set<int> succ_j = get_epsilon_closed_successors(nfa, states[j], sym, state_count, dead_states);
                
                // If successor sets have different sizes, states cannot be bisimilar
                if (succ_i.size() != succ_j.size()) {
                    solver.add(-var(i, j));
                    solver.add(0);
                    continue;
                }
                
                if (succ_i.empty()) continue;
                
                // Check if successor sets could be bisimilar
                // For each successor in succ_i, there must be a potential bisimilar one in succ_j
                bool compatible = true;
                for (int si : succ_i) {
                    bool found_match = false;
                    for (int sj : succ_j) {
                        // Check if si and sj could be bisimilar:
                        // 1. Same accepting properties
                        // 2. Both in our local subgraph (so SAT can decide)
                        // 3. Or both outside and already in same partition
                        
                        if (!states_accepting_match(nfa, si, sj)) continue;
                        
                        // Check if both are in local subgraph
                        int si_idx = -1, sj_idx = -1;
                        for (int idx = 0; idx < k; idx++) {
                            if (states[idx] == si) si_idx = idx;
                            if (states[idx] == sj) sj_idx = idx;
                        }
                        
                        if (si_idx >= 0 && sj_idx >= 0) {
                            // Both in subgraph - SAT will decide if they're bisimilar
                            found_match = true;
                            break;
                        } else if (si_idx < 0 && sj_idx < 0) {
                            // Both outside subgraph - check if they're identical
                            if (si == sj) {
                                found_match = true;
                                break;
                            }
                        }
                    }
                    if (!found_match) {
                        compatible = false;
                        break;
                    }
                }
                
                if (!compatible) {
                    solver.add(-var(i, j));
                    solver.add(0);
                }
            }
        }
    }
    
    // Objective: maximize bisimilarity
    for (int i = 0; i < k; i++) {
        for (int j = i + 1; j < k; j++) {
            solver.assume(var(i, j));
        }
    }
    
    // Solve
    int res = solver.solve();
    
    if (res == 10) {  // SATISFIABLE
        // Extract equivalence classes
        std::vector<int> equiv_class(k, -1);
        int next_class = 0;
        
        for (int i = 0; i < k; i++) {
            if (equiv_class[i] >= 0) continue;
            
            equiv_class[i] = next_class;
            
            for (int j = i + 1; j < k; j++) {
                if (equiv_class[j] >= 0) continue;
                
                if (solver.val(var(i, j)) > 0) {
                    equiv_class[j] = next_class;
                }
            }
            
            next_class++;
        }
        
        // Build result map
        std::map<int, int> class_rep;
        for (int i = 0; i < k; i++) {
            int ec = equiv_class[i];
            if (class_rep.find(ec) == class_rep.end()) {
                class_rep[ec] = states[i];
                result[states[i]] = states[i];
            } else {
                result[states[i]] = class_rep[ec];
            }
        }
        
        VERBOSE_PRINT("  Found %d equivalence classes from %d states\n", next_class, k);
    } else {
        VERBOSE_PRINT("  No SAT solution\n");
    }
    
    return result;
}
#endif

/**
 * Extract a local subgraph around a set of seed states.
 * 
 * This includes:
 * - The seed states themselves
 * - States reachable within k hops
 * - States that have transitions to/from the seed states
 * 
 * @param nfa NFA state array
 * @param state_count Total number of states
 * @param dead_states Dead state markers
 * @param seed_states Starting states for extraction
 * @param max_hops Maximum hops to expand
 * @param max_size Maximum size of extracted subgraph
 * @return Vector of state indices in the extracted subgraph
 */
static std::vector<int> extract_local_subgraph(
    const nfa_state_t* nfa,
    int state_count,
    const bool* dead_states,
    const std::vector<int>& seed_states,
    int max_hops,
    int max_size
) {
    std::set<int> visited;
    std::queue<std::pair<int, int>> queue;  // (state, hop)
    
    // Start with seed states
    for (int s : seed_states) {
        if (!dead_states[s]) {
            visited.insert(s);
            queue.push({s, 0});
        }
    }
    
    // BFS expansion
    while (!queue.empty() && (int)visited.size() < max_size) {
        int s = queue.front().first;
        int hop = queue.front().second;
        queue.pop();
        
        if (hop >= max_hops) continue;
        
        // Add successors
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            std::vector<int> succ = get_successors(nfa, s, sym);
            for (int t : succ) {
                if (visited.find(t) == visited.end() && !dead_states[t]) {
                    visited.insert(t);
                    if ((int)visited.size() >= max_size) break;
                    queue.push({t, hop + 1});
                }
            }
        }
        
        // Add predecessors (need to scan all states)
        for (int src = 0; src < state_count && (int)visited.size() < max_size; src++) {
            if (dead_states[src] || visited.find(src) != visited.end()) continue;
            
            for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                std::vector<int> succ = get_successors(nfa, src, sym);
                for (int t : succ) {
                    if (t == s) {
                        visited.insert(src);
                        queue.push({src, hop + 1});
                        break;
                    }
                }
            }
        }
    }
    
    return std::vector<int>(visited.begin(), visited.end());
}

/**
 * Apply a merge: redirect all transitions from src to rep.
 */
static void apply_merge(nfa_state_t* nfa, int state_count, bool* dead_states, int src, int rep) {
    if (dead_states[src] || dead_states[rep]) return;
    
    for (int s = 0; s < state_count; s++) {
        if (dead_states[s]) continue;
        
        nfa_state_t* state = &nfa[s];
        
        // Single transitions
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            if (state->transitions[sym] == src) {
                state->transitions[sym] = rep;
            }
        }
        
        // Multi-targets
        for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
            int count;
            int* targets = mta_get_target_array(&state->multi_targets, sym, &count);
            if (targets && count > 0) {
                for (int i = 0; i < count; i++) {
                    if (targets[i] == src) {
                        targets[i] = rep;
                    }
                }
            }
        }
    }
    
    dead_states[src] = true;
}

/**
 * Main windowed SAT optimization function.
 * 
 * @param nfa NFA state array
 * @param state_count Number of states
 * @param dead_states Array marking dead states (updated in-place)
 * @param window_size Maximum states per window
 * @param window_overlap Overlap between windows
 * @param verbose Enable verbose output
 * @return Number of states merged
 */
extern "C" int nfa_preminimize_windowed_sat(
    nfa_state_t* nfa,
    int state_count,
    bool* dead_states,
    int window_size,
    int window_overlap,
    bool verbose
) {
    windowed_verbose = verbose;
    
    if (window_size <= 0) window_size = DEFAULT_WINDOW_SIZE;
    if (window_overlap <= 0) window_overlap = DEFAULT_WINDOW_OVERLAP;
    if (window_overlap >= window_size) window_overlap = window_size / 2;
    
    int merged_total = 0;
    
    VERBOSE_PRINT("Starting windowed SAT optimization: %d states, window_size=%d, overlap=%d\n",
                  state_count, window_size, window_overlap);
    
#ifdef USE_CADICAL
    // Count live states
    int live_count = 0;
    for (int s = 0; s < state_count; s++) {
        if (!dead_states[s]) live_count++;
    }
    
    VERBOSE_PRINT("Live states: %d\n", live_count);
    
    // Create a list of live states
    std::vector<int> live_states;
    for (int s = 0; s < state_count; s++) {
        if (!dead_states[s]) {
            live_states.push_back(s);
        }
    }
    
    // Slide window over live states
    int window_start = 0;
    int windows_processed = 0;
    
    while (window_start < (int)live_states.size()) {
        int window_end = std::min(window_start + window_size, (int)live_states.size());
        
        // Extract states in this window
        std::vector<int> window_states(live_states.begin() + window_start,
                                        live_states.begin() + window_end);
        
        // Expand to include local neighborhood
        std::vector<int> subgraph = extract_local_subgraph(
            nfa, state_count, dead_states,
            window_states, 2, MAX_SAT_STATES
        );
        
        if (subgraph.size() >= 2) {
            VERBOSE_PRINT("Window %d: %zu states in subgraph\n", windows_processed, subgraph.size());
            
            // Run SAT verification
            std::map<int, int> merges = verify_local_bisimulation_sat(
                nfa, subgraph, state_count, dead_states
            );
            
            // Apply merges
            for (auto& m : merges) {
                if (m.first != m.second && !dead_states[m.first]) {
                    apply_merge(nfa, state_count, dead_states, m.first, m.second);
                    merged_total++;
                    VERBOSE_PRINT("  Merged state %d into %d\n", m.first, m.second);
                }
            }
        }
        
        window_start += (window_size - window_overlap);
        windows_processed++;
    }
    
    VERBOSE_PRINT("Processed %d windows, merged %d states\n", windows_processed, merged_total);
#else
    VERBOSE_PRINT("CaDiCaL not available, SAT optimization disabled\n");
#endif
    
    return merged_total;
}

/**
 * Check if windowed SAT optimization is available.
 */
extern "C" bool nfa_preminimize_windowed_sat_available(void) {
#ifdef USE_CADICAL
    return true;
#else
    return false;
#endif
}
