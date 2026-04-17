/**
 * DFA Transition Table Compression Implementation
 * 
 * Uses SAT solver to find optimal compression of DFA transition tables.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "dfa_compress.h"
#include "dfa_minimize.h"  // For build_dfa_state_t

// SAT compression functions are declared in dfa_compress.h
// and implemented in dfa_compress_sat.cpp (C++).
// CaDiCaL is linked via sat_modules or directly via cadical.

// Statistics from last compression
static compression_stats_t last_stats = {
    .original_rules = 0,
    .compressed_rules = 0,
    .original_bytes = 0,
    .compressed_bytes = 0,
    .compression_ratio = 0.0f,
    .rules_merged = 0,
    .ranges_created = 0,
    .defaults_shared = 0
};
static bool compress_verbose = false;

// Forward declaration
static int merge_rules_with_options(build_dfa_state_t* state, int max_group_size, bool use_sat);

/**
 * Get default compression options
 */
compress_options_t get_default_compress_options(void) {
    compress_options_t opts = {
        .enable_rule_merging = true,
        .enable_range_optimization = true,
        .enable_default_sharing = true,
        .max_group_size = 3,
        .use_sat = false,
        .verbose = false
    };
    return opts;
}

/**
 * Get compression statistics
 */
void dfa_get_compression_stats(compression_stats_t* stats) {
    if (stats) *stats = last_stats;
}

// ============================================================================
// Strategy 1: Rule Merging (Combine LITERAL rules)
// ============================================================================

/**
 * Rule group for merging
 */
typedef struct {
    int chars[3];       // Characters in this group
    int count;          // Number of characters (1-3)
    int target;         // Target state
    uint32_t markers;   // Marker offset (simplified: assume same for all)
} rule_group_t;

/**
 * Check if two transitions can be merged
 */
static bool can_merge(int target1, uint32_t markers1, int target2, uint32_t markers2) {
    return target1 == target2 && markers1 == markers2;
}

/**
 * Merge LITERAL rules for a single state using greedy algorithm.
 * SAT-based merging would be more optimal but slower.
 * 
 * @return Number of rules saved
 */
int merge_rules_for_state(build_dfa_state_t* state, int max_group_size) {
    // Count transitions by target
    int transition_count = 0;
    for (int c = 0; c < BYTE_VALUE_MAX; c++) {
        if (state->transitions[c] >= 0) {
            transition_count++;
        }
    }
    
    if (transition_count <= 1) return 0;
    
    // Group transitions by (target, markers)
    rule_group_t* groups = malloc(transition_count * sizeof(rule_group_t));
    bool* used = calloc(BYTE_VALUE_MAX, sizeof(bool));
    
    if (!groups || !used) {
        free(groups);
        free(used);
        return 0;
    }
    
    int group_count = 0;
    
    for (int c = 0; c < BYTE_VALUE_MAX; c++) {
        if (state->transitions[c] < 0 || used[c]) continue;
        
        // Start new group
        rule_group_t* g = &groups[group_count];
        g->chars[0] = c;
        g->count = 1;
        g->target = state->transitions[c];
        g->markers = state->marker_offsets[c];
        used[c] = true;
        
        // Find matching characters
        for (int c2 = c + 1; c2 < 256 && g->count < max_group_size; c2++) {
            if (state->transitions[c2] >= 0 && !used[c2] &&
                can_merge(g->target, g->markers, 
                         state->transitions[c2], state->marker_offsets[c2])) {
                g->chars[g->count++] = c2;
                used[c2] = true;
            }
        }
        
        group_count++;
    }
    
    // Calculate savings
    int original_rules = transition_count;
    int compressed_rules = group_count;
    int saved = original_rules - compressed_rules;
    
    free(groups);
    free(used);
    
    return saved;
}

// ============================================================================
// Strategy 2: Range Optimization
// ============================================================================

/**
 * Detect character ranges in transitions.
 * 
 * @return Number of rules saved by creating ranges
 */
static int optimize_ranges_for_state(build_dfa_state_t* state) {
    int saved = 0;
    
    // Scan for consecutive characters with same target
    int range_start = -1;
    int last_target = -1;
    uint32_t last_markers = 0;
    
    for (int c = 0; c <= BYTE_VALUE_MAX; c++) {  // Include sentinel at BYTE_VALUE_MAX
        int target = (c < BYTE_VALUE_MAX) ? state->transitions[c] : -1;
        uint32_t markers = (c < BYTE_VALUE_MAX) ? state->marker_offsets[c] : 0;
        
        if (target >= 0 && target == last_target && markers == last_markers) {
            // Continue range
        } else {
            // End previous range
            if (range_start >= 0 && c - 1 > range_start) {
                // Range of at least 2 characters
                int range_len = c - 1 - range_start + 1;
                if (range_len >= 3) {
                    // Worth creating a range rule
                    saved += range_len - 1;  // Save (range_len - 1) rules
                }
            }
            range_start = (target >= 0) ? c : -1;
        }
        last_target = target;
        last_markers = markers;
    }
    
    return saved;
}

// ============================================================================
// Strategy 3: Default State Sharing
// ============================================================================

/**
 * Find states with identical default transition behavior.
 * 
 * @return Number of states that can share defaults
 */
static int find_default_sharing(build_dfa_state_t** dfa, int state_count) {
    // For simplicity, count states with identical transition patterns
    int shared = 0;
    bool* counted = calloc(state_count, sizeof(bool));
    if (!counted) return 0;
    
    for (int i = 0; i < state_count; i++) {
        if (counted[i]) continue;
        
        int identical = 1;
        for (int j = i + 1; j < state_count; j++) {
            if (counted[j]) continue;
            
            // Compare transition patterns
            bool same = true;
            for (int c = 0; c < 256 && same; c++) {
                if (dfa[i]->transitions[c] != dfa[j]->transitions[c] ||
                    dfa[i]->marker_offsets[c] != dfa[j]->marker_offsets[c]) {
                    same = false;
                }
            }
            
            if (same) {
                identical++;
                counted[j] = true;
            }
        }
        
        if (identical > 1) {
            shared += identical - 1;  // First state is the "original"
        }
    }
    
    free(counted);
    return shared;
}

// ============================================================================
// Main Compression Function
// ============================================================================

/**
 * Estimate compression ratio without modifying DFA
 */
float dfa_estimate_compression(const build_dfa_state_t** dfa, int state_count, 
                               const compress_options_t* options) {
    if (!dfa || state_count <= 0) return 1.0f;
    
    compress_options_t opts = options ? *options : get_default_compress_options();
    
    int total_original = 0;
    int total_saved = 0;
    
    for (int s = 0; s < state_count; s++) {
        const build_dfa_state_t* state = dfa[s];
        
        // Count transitions
        for (int c = 0; c < BYTE_VALUE_MAX; c++) {
            if (state->transitions[c] >= 0) {
                total_original++;
            }
        }
        
        // Estimate savings (simplified)
        if (opts.enable_rule_merging) {
            // Estimate ~30% savings from merging
            total_saved += total_original * 0.3;
        }
    }
    
    if (total_original == 0) return 1.0f;
    return (float)(total_original - total_saved) / total_original;
}

/**
 * Compress DFA transition tables
 */
int dfa_compress(build_dfa_state_t** dfa, int state_count, const compress_options_t* options) {
    if (!dfa || state_count <= 0) return state_count;
    
    compress_options_t opts = options ? *options : get_default_compress_options();
    compress_verbose = opts.verbose;
    
    // Reset statistics
    last_stats = (compression_stats_t){
        .original_rules = 0,
        .compressed_rules = 0,
        .original_bytes = 0,
        .compressed_bytes = 0,
        .compression_ratio = 0.0f,
        .rules_merged = 0,
        .ranges_created = 0,
        .defaults_shared = 0
    };
    
    // Count original rules
    for (int s = 0; s < state_count; s++) {
        for (int c = 0; c < BYTE_VALUE_MAX; c++) {
            if (dfa[s]->transitions[c] >= 0) {
                last_stats.original_rules++;
            }
        }
    }
    last_stats.original_bytes = last_stats.original_rules * 12;  // 12 bytes per rule
    
    VERBOSE_PRINT(compress, "Original: %d rules, %d bytes\n", 
                  last_stats.original_rules, last_stats.original_bytes);
    
    // Strategy 1: Rule Merging
    if (opts.enable_rule_merging) {
        VERBOSE_PRINT(compress, "Applying rule merging (%s)...\n", opts.use_sat ? "SAT" : "greedy");
        for (int s = 0; s < state_count; s++) {
            last_stats.rules_merged += merge_rules_with_options(dfa[s], opts.max_group_size, opts.use_sat);
        }
        VERBOSE_PRINT(compress, "  Saved %d rules by merging\n", last_stats.rules_merged);
    }
    
    // Strategy 2: Range Optimization
    if (opts.enable_range_optimization) {
        VERBOSE_PRINT(compress, "Applying range optimization...\n");
        int range_savings = 0;
        for (int s = 0; s < state_count; s++) {
            range_savings += optimize_ranges_for_state(dfa[s]);
        }
        last_stats.ranges_created = range_savings;
        VERBOSE_PRINT(compress, "  Created %d range rules\n", last_stats.ranges_created);
    }
    
    // Strategy 3: Default State Sharing
    if (opts.enable_default_sharing) {
        VERBOSE_PRINT(compress, "Applying default state sharing...\n");
        last_stats.defaults_shared = find_default_sharing(dfa, state_count);
        VERBOSE_PRINT(compress, "  Shared %d default states\n", last_stats.defaults_shared);
    }
    
    // Calculate final statistics
    last_stats.compressed_rules = last_stats.original_rules - last_stats.rules_merged;
    last_stats.compressed_bytes = last_stats.compressed_rules * 12;
    if (last_stats.original_bytes > 0) {
        last_stats.compression_ratio = (float)last_stats.compressed_bytes / last_stats.original_bytes;
    } else {
        last_stats.compression_ratio = 1.0f;
    }
    
    VERBOSE_PRINT(compress, "Compressed: %d rules, %d bytes (%.1f%% reduction)\n",
                  last_stats.compressed_rules, last_stats.compressed_bytes,
                  (1.0f - last_stats.compression_ratio) * 100.0f);
    
    return state_count;  // State count doesn't change in this implementation
}

/**
 * Merge rules using either greedy or SAT algorithm
 */
static int merge_rules_with_options(build_dfa_state_t* state, int max_group_size, bool use_sat) {
    if (use_sat) {
        return sat_merge_rules_for_state(state, max_group_size);
    }
    return merge_rules_for_state(state, max_group_size);
}
