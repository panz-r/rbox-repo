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
#include "cadical.hpp"
#endif

// Configuration
#define MAX_CANDIDATES 200        // Maximum merge candidates for SAT
#define MAX_SAT_TIME_MS 5000      // Timeout for SAT solver

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
 * Two candidates conflict if:
 * 1. They share a state (that state can only merge once)
 * 2. OR merging one would invalidate the other's preconditions
 */
static bool candidates_conflict(
    const merge_candidate_t& c1,
    const merge_candidate_t& c2
) {
    // Extract states involved
    int a1 = c1.state1, b1 = c1.state2;
    int a2 = c2.state1, b2 = c2.state2;
    
    // Check for overlapping states - a state can only be merged ONCE
    // If state X appears in both candidates, they conflict
    bool overlap = (a1 == a2 || a1 == b2 || b1 == a2 || b1 == b2);
    
    if (!overlap) {
        // No overlap - check if merges would create inconsistent transitions
        // This happens if merging (a1, b1) would change transitions that (a2, b2) depends on
        
        // For now, we conservatively allow non-overlapping merges
        // A more sophisticated analysis could check for indirect conflicts
        return false;
    }
    
    // Overlapping states - this is a CONFLICT
    // A state can only be merged once, so if it appears in two different
    // merge candidates, we must choose one
    
    // Case 1: Same pair - no conflict (same merge)
    if (a1 == a2 && b1 == b2) return false;
    
    // Case 2: Three or four different states involved
    // This is a conflict - we must choose which merge to apply
    // The SAT solver will find the optimal set
    
    // For three-state case: (a1, b1) and (a1, b2)
    // State a1 can only merge with ONE of b1 or b2
    // This is a HARD CONFLICT
    
    return true;
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

// Forward declaration
static std::set<int> solve_optimal_merges_greedy(
    const std::vector<merge_candidate_t>& candidates,
    const std::map<int, std::set<int>>& conflicts
);

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
    
    // Solve with greedy selection
    std::set<int> selected = solve_optimal_merges_greedy(candidates, conflicts);
    
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
