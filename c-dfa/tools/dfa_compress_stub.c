/**
 * DFA Compression Stub - Used when CaDiCaL is not available
 */

#include "dfa_compress.h"
#include "dfa_minimize.h"
#include "../include/cdfa_defines.h"

// Statistics from last compression
static compression_stats_t last_stats = {0};

compress_options_t get_default_compress_options(void) {
    compress_options_t opts = {
        .enable_rule_merging = true,
        .enable_range_optimization = true,
        .enable_default_sharing = true,
        .max_group_size = 3,
        .verbose = false
    };
    return opts;
}

void dfa_get_compression_stats(compression_stats_t* stats) {
    if (stats) *stats = last_stats;
}

float dfa_estimate_compression(ATTR_UNUSED const build_dfa_state_t** dfa, ATTR_UNUSED int state_count,
                               ATTR_UNUSED const compress_options_t* options) {
    return 1.0f;  // No compression in stub
}

int dfa_compress(ATTR_UNUSED build_dfa_state_t** dfa, int state_count, ATTR_UNUSED const compress_options_t* options) {
    return state_count;
}
