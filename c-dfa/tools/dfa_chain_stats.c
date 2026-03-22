/**
 * dfa_chain_stats.c - Analyze DFA for chain encoding opportunities
 *
 * Scans a DFA binary and reports statistics on chains of states with
 * single transitions that could potentially be merged.
 *
 * Usage: dfa_chain_stats <dfa_file> [--verbose]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "dfa_types.h"
#include "dfa_format.h"

typedef struct {
    int state_count;
    int chain_count;           /* Number of chains found */
    int chain_states;          /* Total states in all chains */
    int removable_states;      /* States that could be removed (chain_states - chain_count) */
    int longest_chain;         /* Longest chain length */
    int chain_by_length[32];   /* Histogram: chains[i] = chains of length i */
    int branching_chains;      /* Chains that start from a state with multiple outgoing transitions */
    int single_outgoing;       /* States with exactly 1 outgoing transition */
    int zero_outgoing;         /* States with 0 outgoing transitions (dead/accepting) */
    int multi_outgoing;        /* States with 2+ outgoing transitions */
} chain_stats_t;

typedef struct {
    int target;
    uint8_t char_taken;
} transition_t;

/**
 * Count outgoing literal transitions (0-255) for a state
 */
static int count_outgoing(const uint8_t* d, size_t sz, int enc, size_t so) {
    int count = 0;
    uint16_t tc = dfa_fmt_st_tc(d, so, enc);
    
    if (tc == 0) {
        /* Compact state - check if it has any transitions via rules_offset */
        return 0;
    }
    
    uint32_t rl = dfa_fmt_st_rules(d, so, enc);
    uint16_t flags = dfa_fmt_st_flags_tc(d, so, enc, tc);
    int renc = DFA_GET_RULE_ENC(flags);
    
    if (renc == DFA_RULE_ENC_PACKED) {
        /* Packed encoding - count literals and ranges */
        uint16_t n_ent = dfa_fmt_st_first_tc(d, so, enc, tc);
        const uint8_t* entry = d + rl;
        for (uint16_t i = 0; i < n_ent; i++) {
            if ((size_t)(entry - d) >= sz) break;
            if (dfa_pack_is_literal(entry)) {
                count++;
                entry += DFA_PACK_LITERAL_SIZE(enc);
            } else {
                uint8_t start = dfa_pack_range_start(entry);
                uint8_t end = dfa_pack_range_end(entry);
                count += (end - start + 1);
                entry += DFA_PACK_RANGE_SIZE(enc);
            }
        }
    } else {
        /* Normal encoding - count rules */
        int rs = DFA_RULE_SIZE(enc);
        for (uint16_t i = 0; i < tc; i++) {
            size_t ro = rl + (size_t)i * rs;
            if ((size_t)ro + (size_t)rs > sz) break;
            uint8_t rt = dfa_fmt_rl_type(d, ro);
            switch (rt) {
                case DFA_RULE_LITERAL:       count++; break;
                case DFA_RULE_RANGE: {
                    uint8_t r1 = dfa_fmt_rl_d1(d, ro);
                    uint8_t r2 = dfa_fmt_rl_d2(d, ro);
                    count += (r2 - r1 + 1);
                    break;
                }
                case DFA_RULE_LITERAL_2:     count += 2; break;
                case DFA_RULE_LITERAL_3:     count += 3; break;
                case DFA_RULE_RANGE_LITERAL: {
                    uint8_t r1 = dfa_fmt_rl_d1(d, ro);
                    uint8_t r2 = dfa_fmt_rl_d2(d, ro);
                    count += (r2 - r1 + 2);  /* range + 1 literal */
                    break;
                }
                case DFA_RULE_DEFAULT:       count += 256; break;  /* Matches everything */
                case DFA_RULE_NOT_LITERAL:   count += 255; break;
                case DFA_RULE_NOT_RANGE: {
                    uint8_t r1 = dfa_fmt_rl_d1(d, ro);
                    uint8_t r2 = dfa_fmt_rl_d2(d, ro);
                    count += (256 - (r2 - r1 + 1));
                    break;
                }
            }
        }
    }
    return count;
}

/**
 * Get the single outgoing transition target for a state with exactly 1 outgoing transition
 * Returns -1 if state doesn't have exactly 1 outgoing transition
 */
static int get_single_target(const uint8_t* d, size_t sz, int enc, size_t so, uint8_t* out_char) {
    uint16_t tc = dfa_fmt_st_tc(d, so, enc);
    if (tc == 0) return -1;
    
    uint32_t rl = dfa_fmt_st_rules(d, so, enc);
    uint16_t flags = dfa_fmt_st_flags_tc(d, so, enc, tc);
    int renc = DFA_GET_RULE_ENC(flags);
    
    if (renc == DFA_RULE_ENC_PACKED) {
        uint16_t n_ent = dfa_fmt_st_first_tc(d, so, enc, tc);
        if (n_ent != 1) return -1;  /* Must have exactly 1 entry */
        
        const uint8_t* entry = d + rl;
        if (dfa_pack_is_literal(entry)) {
            if (out_char) *out_char = dfa_pack_lit_char(entry);
            return (int)dfa_pack_lit_target(entry, enc);
        }
        /* Range with single char is effectively a literal */
        if (dfa_pack_is_range(entry)) {
            uint8_t start = dfa_pack_range_start(entry);
            uint8_t end = dfa_pack_range_end(entry);
            if (start == end) {
                if (out_char) *out_char = start;
                return (int)dfa_pack_range_target(entry, enc);
            }
        }
        return -1;
    } else {
        if (tc != 1) return -1;  /* Must have exactly 1 rule */
        
        int rs = DFA_RULE_SIZE(enc);
        size_t ro = rl;
        if ((size_t)ro + (size_t)rs > sz) return -1;
        
        uint8_t rt = dfa_fmt_rl_type(d, ro);
        if (rt == DFA_RULE_LITERAL) {
            if (out_char) *out_char = dfa_fmt_rl_d1(d, ro);
            return (int)dfa_fmt_rl_target(d, ro, enc);
        }
        if (rt == DFA_RULE_RANGE) {
            uint8_t r1 = dfa_fmt_rl_d1(d, ro);
            uint8_t r2 = dfa_fmt_rl_d2(d, ro);
            if (r1 == r2) {
                if (out_char) *out_char = r1;
                return (int)dfa_fmt_rl_target(d, ro, enc);
            }
        }
        return -1;
    }
}

/**
 * Check if a state is accepting (has category or pattern_id)
 */
static bool is_accepting(const uint8_t* d, size_t sz, int enc, size_t so, uint16_t tc) {
    (void)sz; (void)tc;
    uint16_t flags = dfa_fmt_st_flags_tc(d, so, enc, tc);
    uint8_t cat = DFA_GET_CATEGORY_MASK(flags);
    if (cat != 0) return true;
    
    /* Look up pattern_id from Pattern ID section (V10) */
    uint32_t pid_off = dfa_fmt_pid_offset(d);
    if (pid_off > 0 && pid_off < sz) {
        const uint8_t* pid = d + pid_off;
        uint16_t pattern_id = dfa_fmt_pid_lookup(pid, enc, (uint32_t)so);
        if (pattern_id != 0 && pattern_id != UINT16_MAX) return true;
    }
    
    return false;
}

/**
 * Check if a state has an EOS target (V9: uses EOS section)
 */
static bool has_eos_target(const uint8_t* d, size_t sz, int enc, size_t so, uint16_t tc) {
    (void)sz; (void)tc;
    uint32_t eos_off = dfa_fmt_eos_offset(d);
    if (eos_off == 0 || eos_off >= sz) return false;
    const uint8_t* eos = d + eos_off;
    return dfa_fmt_eos_lookup_target(eos, enc, (uint32_t)so) != 0;
}

/**
 * Analyze a DFA for chain encoding opportunities
 */
static void analyze_dfa(const uint8_t* d, size_t sz, chain_stats_t* stats, bool verbose) {
    memset(stats, 0, sizeof(*stats));
    
    if (sz < DFA_HEADER_FIXED) return;
    if (dfa_fmt_magic(d) != DFA_MAGIC) return;
    if (dfa_fmt_version(d) != DFA_VERSION) return;
    
    int enc = dfa_fmt_encoding(d);
    uint16_t state_count = dfa_fmt_state_count(d);
    stats->state_count = state_count;
    
    /* Build state offset table */
    size_t* state_offsets = malloc(state_count * sizeof(size_t));
    if (!state_offsets) return;
    
    /* Scan for state offsets by walking from initial state */
    uint32_t init = dfa_fmt_initial_state(d);
    size_t hs = DFA_HEADER_SIZE(enc, dfa_fmt_id_len(d));
    
    /* Simple scan: states are laid out sequentially after header */
    /* We need to account for packed encoding which has variable-size rules */
    size_t cur = hs;
    for (int i = 0; i < state_count && cur < sz; i++) {
        /* Align to cache line boundary if needed */
        /* States might have padding for alignment */
        state_offsets[i] = cur;
        
        uint16_t tc = dfa_fmt_st_tc(d, cur, enc);
        if (tc == 0) {
            cur += DFA_STATE_SIZE_COMPACT(enc);
        } else {
            cur += DFA_STATE_SIZE(enc);
        }
    }
    
    /* Classify states and find chains */
    bool* visited = calloc(state_count, sizeof(bool));
    int* chain_lengths = calloc(state_count, sizeof(int));  /* Length of chain starting at each state */
    
    for (int i = 0; i < state_count; i++) {
        size_t so = state_offsets[i];
        if (so >= sz) continue;
        
        int outgoing = count_outgoing(d, sz, enc, so);
        
        if (outgoing == 0) {
            stats->zero_outgoing++;
        } else if (outgoing == 1) {
            stats->single_outgoing++;
        } else {
            stats->multi_outgoing++;
        }
    }
    
    /* Find chains: start from states with 2+ outgoing transitions,
     * follow paths of single-transition states */
    for (int i = 0; i < state_count; i++) {
        size_t so = state_offsets[i];
        if (so >= sz) continue;
        
        int outgoing = count_outgoing(d, sz, enc, so);
        if (outgoing < 2) continue;  /* Chain starts only from branching states */
        
        /* For each outgoing transition, try to follow a chain */
        /* For simplicity, we check the single-transition followers */
        uint16_t tc = dfa_fmt_st_tc(d, so, enc);
        if (tc == 0) continue;
        
        uint32_t rl = dfa_fmt_st_rules(d, so, enc);
        int rs = DFA_RULE_SIZE(enc);
        uint16_t flags = dfa_fmt_st_flags_tc(d, so, enc, tc);
        int renc = DFA_GET_RULE_ENC(flags);
        
        if (renc == DFA_RULE_ENC_PACKED) {
            /* Packed encoding - iterate entries */
            uint16_t n_ent = dfa_fmt_st_first_tc(d, so, enc, tc);
            const uint8_t* entry = d + rl;
            
            for (uint16_t e = 0; e < n_ent; e++) {
                if ((size_t)(entry - d) >= sz) break;
                
                int target = -1;
                if (dfa_pack_is_literal(entry)) {
                    target = (int)dfa_pack_lit_target(entry, enc);
                    entry += DFA_PACK_LITERAL_SIZE(enc);
                } else if (dfa_pack_is_range(entry)) {
                    /* For ranges, only consider single-char ranges */
                    uint8_t start = dfa_pack_range_start(entry);
                    uint8_t end = dfa_pack_range_end(entry);
                    if (start == end) {
                        target = (int)dfa_pack_range_target(entry, enc);
                    }
                    entry += DFA_PACK_RANGE_SIZE(enc);
                } else {
                    continue;
                }
                
                if (target < 0 || target >= state_count) continue;
                
                /* Follow chain from this target */
                int chain_len = 1;  /* Count the first transition */
                int cur_state = target;
                
                while (true) {
                    size_t cur_so = state_offsets[cur_state];
                    if (cur_so >= sz) break;
                    
                    uint16_t cur_tc = dfa_fmt_st_tc(d, cur_so, enc);
                    
                    /* Stop chain at accepting states or states with EOS */
                    if (is_accepting(d, sz, enc, cur_so, cur_tc)) break;
                    if (has_eos_target(d, sz, enc, cur_so, cur_tc)) break;
                    
                    uint8_t next_char;
                    int next_target = get_single_target(d, sz, enc, cur_so, &next_char);
                    
                    if (next_target < 0) break;  /* Not a single transition */
                    
                    chain_len++;
                    cur_state = next_target;
                    
                    if (chain_len >= 64) break;  /* Max chain length */
                }
                
                if (chain_len >= 2) {
                    stats->chain_count++;
                    stats->chain_states += chain_len;
                    stats->removable_states += (chain_len - 1);
                    if (chain_len > stats->longest_chain) {
                        stats->longest_chain = chain_len;
                    }
                    if (chain_len < 32) {
                        stats->chain_by_length[chain_len]++;
                    }
                    stats->branching_chains++;
                    
                    if (verbose) {
                        printf("  Chain from state %d: length %d\n", i, chain_len);
                    }
                }
            }
        } else {
            /* Normal encoding - iterate rules */
            for (uint16_t r = 0; r < tc; r++) {
                size_t ro = rl + (size_t)r * rs;
                if ((size_t)ro + (size_t)rs > sz) break;
                
                uint8_t rt = dfa_fmt_rl_type(d, ro);
                if (rt != DFA_RULE_LITERAL && rt != DFA_RULE_RANGE) continue;
                
                int target = (int)dfa_fmt_rl_target(d, ro, enc);
                if (target < 0 || target >= state_count) continue;
                
                /* For range rules, only consider single-char ranges */
                if (rt == DFA_RULE_RANGE) {
                    uint8_t r1 = dfa_fmt_rl_d1(d, ro);
                    uint8_t r2 = dfa_fmt_rl_d2(d, ro);
                    if (r1 != r2) continue;
                }
                
                /* Follow chain from this target */
                int chain_len = 1;
                int cur_state = target;
                
                while (true) {
                    size_t cur_so = state_offsets[cur_state];
                    if (cur_so >= sz) break;
                    
                    uint16_t cur_tc = dfa_fmt_st_tc(d, cur_so, enc);
                    
                    if (is_accepting(d, sz, enc, cur_so, cur_tc)) break;
                    if (has_eos_target(d, sz, enc, cur_so, cur_tc)) break;
                    
                    uint8_t next_char;
                    int next_target = get_single_target(d, sz, enc, cur_so, &next_char);
                    
                    if (next_target < 0) break;
                    
                    chain_len++;
                    cur_state = next_target;
                    
                    if (chain_len >= 64) break;
                }
                
                if (chain_len >= 2) {
                    stats->chain_count++;
                    stats->chain_states += chain_len;
                    stats->removable_states += (chain_len - 1);
                    if (chain_len > stats->longest_chain) {
                        stats->longest_chain = chain_len;
                    }
                    if (chain_len < 32) {
                        stats->chain_by_length[chain_len]++;
                    }
                    stats->branching_chains++;
                    
                    if (verbose) {
                        printf("  Chain from state %d rule %d: length %d\n", i, r, chain_len);
                    }
                }
            }
        }
    }
    
    free(visited);
    free(chain_lengths);
    free(state_offsets);
}

static void print_stats(const char* filename, const chain_stats_t* stats) {
    printf("DFA: %s\n", filename);
    printf("  States:              %d\n", stats->state_count);
    printf("  Single outgoing:     %d (%.1f%%)\n", 
           stats->single_outgoing, 
           100.0 * stats->single_outgoing / (stats->state_count ? stats->state_count : 1));
    printf("  Multi outgoing:      %d (%.1f%%)\n", 
           stats->multi_outgoing,
           100.0 * stats->multi_outgoing / (stats->state_count ? stats->state_count : 1));
    printf("  Zero outgoing:       %d\n", stats->zero_outgoing);
    printf("  ---\n");
    printf("  Chains found:        %d\n", stats->chain_count);
    printf("  States in chains:    %d\n", stats->chain_states);
    printf("  Removable states:    %d (%.1f%% of total)\n", 
           stats->removable_states,
           100.0 * stats->removable_states / (stats->state_count ? stats->state_count : 1));
    printf("  Longest chain:       %d\n", stats->longest_chain);
    printf("  ---\n");
    printf("  Chain length histogram:\n");
    for (int i = 2; i < 32 && i <= stats->longest_chain; i++) {
        if (stats->chain_by_length[i] > 0) {
            printf("    len %2d: %d chains\n", i, stats->chain_by_length[i]);
        }
    }
    
    /* Estimate savings */
    int state_header_size = 13;  /* Approximate: CW(1) + OW(2) + flags(2) + PW(1) + OW(2) + markers(4) + first(1) */
    int chain_entry_overhead = 8;  /* len(2) + target(2) + markers(4) */
    int bytes_per_removed_state = state_header_size;
    int extra_chain_bytes = stats->chain_count * chain_entry_overhead;
    int estimated_savings = stats->removable_states * bytes_per_removed_state - extra_chain_bytes;
    
    printf("  ---\n");
    printf("  Estimated savings:   %d bytes (remove %d states @ %dB, add %dB chain overhead)\n",
           estimated_savings, stats->removable_states, 
           stats->removable_states * bytes_per_removed_state,
           extra_chain_bytes);
}

int main(int argc, char* argv[]) {
    bool verbose = false;
    const char* filename = NULL;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (argv[i][0] != '-') {
            filename = argv[i];
        }
    }
    
    if (!filename) {
        fprintf(stderr, "Usage: %s <dfa_file> [--verbose]\n", argv[0]);
        return 1;
    }
    
    FILE* f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open '%s'\n", filename);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t* d = malloc(sz);
    if (!d) { fclose(f); return 1; }
    
    if (fread(d, 1, sz, f) != sz) {
        fclose(f); free(d);
        return 1;
    }
    fclose(f);
    
    chain_stats_t stats;
    analyze_dfa(d, sz, &stats, verbose);
    print_stats(filename, &stats);
    
    free(d);
    return 0;
}
