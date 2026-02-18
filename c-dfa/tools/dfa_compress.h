/**
 * DFA Transition Table Compression
 * 
 * Uses SAT solver to find optimal compression of DFA transition tables.
 * Three strategies:
 * 1. Rule Merging: Combine LITERAL rules into LITERAL_2/LITERAL_3
 * 2. Range Optimization: Merge adjacent literals into ranges
 * 3. Default State Sharing: Share common default transition tables
 */

#ifndef DFA_COMPRESS_H
#define DFA_COMPRESS_H

#include <stdint.h>
#include <stdbool.h>
#include "dfa_types.h"
#include "dfa_minimize.h"  // For build_dfa_state_t

/**
 * Compression statistics
 */
typedef struct {
    int original_rules;         // Total rules before compression
    int compressed_rules;       // Total rules after compression
    int original_bytes;         // Estimated bytes before compression
    int compressed_bytes;       // Estimated bytes after compression
    float compression_ratio;    // compressed_bytes / original_bytes
    
    // Per-strategy stats
    int rules_merged;           // Rules saved by merging
    int ranges_created;         // New range rules created
    int defaults_shared;        // States sharing default tables
} compression_stats_t;

/**
 * Compression options
 */
typedef struct {
    bool enable_rule_merging;       // Combine LITERAL rules
    bool enable_range_optimization; // Merge adjacent literals into ranges
    bool enable_default_sharing;    // Share default transition tables
    int max_group_size;             // Max rules per merged group (default: 3)
    bool use_sat;                   // Use SAT solver for optimal merging (slower but optimal)
    bool verbose;                   // Print compression details
} compress_options_t;

/**
 * Get default compression options (all optimizations enabled)
 */
compress_options_t get_default_compress_options(void);

/**
 * Compress DFA transition tables using SAT optimization.
 * 
 * @param dfa DFA state array
 * @param state_count Number of states
 * @param options Compression options (NULL for defaults)
 * @return New state count (may change due to default sharing)
 */
int dfa_compress(build_dfa_state_t* dfa, int state_count, const compress_options_t* options);

/**
 * Get compression statistics from last run.
 */
void dfa_get_compression_stats(compression_stats_t* stats);

/**
 * SAT-based optimal rule merging for a single state.
 * Implemented in dfa_compress_sat.cpp.
 *
 * @param state DFA state to optimize
 * @param max_group_size Maximum characters per group (typically 3)
 * @return Number of rules saved by optimal grouping
 */
int sat_merge_rules_for_state(build_dfa_state_t* state, int max_group_size);

/**
 * SAT-based compression for all states in a DFA.
 * Implemented in dfa_compress_sat.cpp.
 *
 * @param dfa Array of DFA states
 * @param state_count Number of states
 * @param max_group_size Maximum characters per group (typically 3)
 * @return Total number of rules saved
 */
int sat_compress_dfa(build_dfa_state_t* dfa, int state_count, int max_group_size);

/**
 * Greedy rule merging for a single state.
 * Used as preprocessing for SAT compression.
 *
 * @param state DFA state to optimize
 * @param max_group_size Maximum characters per group (typically 3)
 * @return Number of rules saved by greedy grouping
 */
int merge_rules_for_state(build_dfa_state_t* state, int max_group_size);

/**
 * Estimate compression ratio without modifying DFA.
 * 
 * @param dfa DFA state array
 * @param state_count Number of states
 * @param options Compression options
 * @return Estimated compression ratio (0.0-1.0)
 */
float dfa_estimate_compression(const build_dfa_state_t* dfa, int state_count, const compress_options_t* options);

#endif // DFA_COMPRESS_H
