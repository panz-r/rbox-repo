/**
 * NFA Pre-Minimization
 * 
 * Reduces NFA states before subset construction to minimize DFA blowup.
 * Focuses on:
 * 1. Epsilon elimination - bypass states connected only by epsilon
 * 2. Landing-pad removal - remove intermediate states from RDP parser
 * 3. Unreachable state pruning
 * 4. SAT-based bisimulation verification for safe state merging
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
    int landing_pads_removed; // Landing-pad states removed
    int unreachable_removed;  // Unreachable states removed
    int states_merged;        // States eliminated by merging
    int sat_merged;           // States merged via SAT verification
} nfa_premin_stats_t;

/**
 * Options for pre-minimization
 */
typedef struct {
    bool enable_epsilon_elim; // Enable epsilon elimination (default: true)
    bool enable_landing_pad;  // Enable landing-pad removal (default: true)
    bool enable_prune;        // Enable unreachable state pruning (default: true)
    bool enable_merge;        // Enable state merging (default: true)
    bool enable_sat;          // Enable SAT-based bisimulation verification (default: true)
    bool verbose;             // Print progress information
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

#endif // NFA_PREMINIMIZE_H
