/**
 * NFA Pre-Minimization
 * 
 * Reduces NFA states before subset construction to minimize DFA blowup.
 * Focuses on:
 * 1. Epsilon elimination - bypass states connected only by epsilon
 * 2. Bidirectional incremental merging - O(n log n) prefix/suffix merging
 * 3. Unreachable state pruning
 * 4. Final state deduplication
 */

#ifndef NFA_PREMINIMIZE_H
#define NFA_PREMINIMIZE_H

#include <stdint.h>
#include <stdbool.h>
#include "../include/nfa.h"

/**
 * Statistics from pre-minimization
 */
typedef struct {
    int original_states;      // NFA states before minimization
    int minimized_states;     // NFA states after minimization
    int epsilon_bypassed;     // States bypassed by epsilon elimination
    int epsilon_chains;       // Epsilon chains compressed
    int landing_pads_removed; // Landing-pad states removed
    int unreachable_removed;  // Unreachable states removed
    int states_merged;        // States eliminated by merging
    int identical_merged;     // States merged by identical state detection
    int prefix_merged;        // States merged by bidirectional merging
    int final_deduped;        // Final states deduplicated
    int suffix_merged;        // States merged by suffix merging
    int sat_merged;           // States merged via SAT verification
    int sat_optimal;          // States merged via SAT optimal selection
} nfa_premin_stats_t;

/**
 * Options for pre-minimization
 * 
 * All optimizations are O(n) or O(n log n) and safe (preserve language equivalence):
 *   - enable_prune: Remove unreachable states (O(n))
 *   - enable_epsilon_elim: Bypass single epsilon pass-through states (O(n))
 *   - enable_final_dedup: Deduplicate equivalent final/accepting states (O(n log n))
 *   - enable_bidirectional: Bidirectional incremental merging (O(n log n))
 *   - enable_sat_optimal: SAT-based optimal merge selection (bounded complexity)
 */
typedef struct {
    bool enable_epsilon_elim;   // Enable epsilon pass-through bypass (default: true)
    bool enable_prune;          // Enable unreachable state pruning (default: true)
    bool enable_final_dedup;    // Enable final state deduplication (default: true)
    bool enable_bidirectional;  // Enable bidirectional incremental merging (default: true)
    bool enable_sat_optimal;    // Enable SAT-based optimal merge selection (default: true)
    int max_sat_candidates;     // Maximum candidates for SAT optimal (default: 200)
    bool verbose;               // Print progress information
} nfa_premin_options_t;

/**
 * Get default pre-minimization options
 */
nfa_premin_options_t nfa_premin_default_options(void);

/**
 * Pre-minimize an NFA.
 * 
 * @param nfa NFA state array
 * @param state_count Pointer to number of states (updated in-place)
 * @param options Pre-minimization options (NULL for defaults)
 * @return Number of states eliminated
 */
int nfa_preminimize(nfa_state_t* nfa, int* state_count, const nfa_premin_options_t* options);

/**
 * Get statistics from last pre-minimization run
 */
void nfa_premin_get_stats(nfa_premin_stats_t* stats);

/**
 * Compute a signature hash for an NFA state.
 * States with identical signatures are merge candidates.
 * 
 * @param nfa NFA state array
 * @param state_idx State to compute signature for
 * @return 64-bit signature hash
 */
uint64_t nfa_compute_state_signature(const nfa_state_t* nfa, int state_idx);

/**
 * SAT-based NFA pre-minimization.
 * Uses CaDiCaL SAT solver to verify bisimulation before merging.
 * 
 * @param nfa NFA state array
 * @param state_count Number of states
 * @param dead_states Array marking dead states (updated in-place)
 * @param verbose Enable verbose output
 * @return Number of states merged
 */
int nfa_preminimize_sat(nfa_state_t* nfa, int state_count, bool* dead_states, bool verbose);

/**
 * Check if SAT-based pre-minimization is available.
 * 
 * @return true if CaDiCaL is compiled and available
 */
bool nfa_preminimize_sat_available(void);

/**
 * Windowed SAT-based NFA pre-minimization.
 * 
 * Uses a sliding window approach to apply SAT optimization on bounded subproblems.
 * Total complexity is O(n log n) in NFA size n, with O(m²) or O(2^m) within each
 * window of size m (bounded).
 * 
 * @param nfa NFA state array
 * @param state_count Number of states
 * @param dead_states Array marking dead states (updated in-place)
 * @param window_size Maximum states per window (0 for default)
 * @param window_overlap Overlap between windows (0 for default)
 * @param verbose Enable verbose output
 * @return Number of states merged
 */
int nfa_preminimize_windowed_sat(nfa_state_t* nfa, int state_count, bool* dead_states,
                                  int window_size, int window_overlap, bool verbose);

/**
 * Check if windowed SAT optimization is available.
 * 
 * @return true if CaDiCaL is compiled and available
 */
bool nfa_preminimize_windowed_sat_available(void);

/**
 * SAT-based optimal merge selection.
 * 
 * Uses SAT to find the maximum set of non-conflicting merges from
 * pre-filtered candidates. This is an optimization approach rather
 * than verification - SAT finds the optimal combination.
 * 
 * Algorithm:
 * 1. Collect merge candidates from prefix/suffix analysis (O(n log n))
 * 2. Build conflict graph between candidates (O(m²))
 * 3. Encode as SAT and solve for maximum merges
 * 4. Apply optimal merge set
 * 
 * @param nfa NFA state array
 * @param state_count Number of states
 * @param dead_states Array marking dead states (updated in-place)
 * @param max_candidates Maximum candidates for SAT (0 for default)
 * @param verbose Enable verbose output
 * @return Number of states merged
 */
int nfa_preminimize_optimal_merges(nfa_state_t* nfa, int state_count, bool* dead_states,
                                    int max_candidates, bool verbose);

/**
 * Check if optimal SAT merging is available.
 * 
 * @return true if CaDiCaL is compiled and available
 */
bool nfa_preminimize_optimal_available(void);

#endif // NFA_PREMINIMIZE_H
