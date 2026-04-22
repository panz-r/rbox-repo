/**
 * nfa_builder_lib.c - Library components from nfa_builder
 *
 * Contains context lifecycle and legacy compatibility functions
 * needed by the library (pipeline.c) and nfa2dfa.
 *
 * Compiled with -DNFABUILDER_NO_MAIN to exclude CLI code.
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "nfa_builder.h"
#include "../include/multi_target_array.h"
#include "../include/nfa.h"

// ============================================================================
// Context Lifecycle
// ============================================================================

nfa_builder_context_t* nfa_builder_context_create(void) {
    // Context struct is ~25MB; use calloc for zero-initialization
    nfa_builder_context_t* ctx = calloc(1, sizeof(nfa_builder_context_t));
    if (!ctx) return NULL;

    // Zero-init via calloc handles most initialization
    // Set non-zero defaults
    ctx->current_pattern_index = -1;
    ctx->current_pattern_cat_mask = 0x01;
    ctx->nfa_state_count = 0;
    ctx->pattern_count = 0;
    ctx->alphabet_size = 0;
    ctx->fragment_count = 0;
    ctx->capture_count = 0;
    ctx->capture_stack_depth = 0;
    ctx->pending_marker_count = 0;
    ctx->last_element_sid = -1;
    ctx->pending_capture_defer_id = -1;
    ctx->prev_frag_exit = -1;
    ctx->current_fragment.exit_state = -1;
    ctx->current_fragment.anchor_state = -1;
    ctx->current_fragment.loop_entry_state = -1;
    ctx->dynamic_category_count = 0;
    ctx->categories_defined = false;
    ctx->category_mapping_count = 0;
    ctx->has_fragment_error = false;

    return ctx;
}

void nfa_builder_context_destroy(nfa_builder_context_t* ctx) {
    if (!ctx) return;
    // Free signature table linked lists
    for (int i = 0; i < SIGNATURE_TABLE_SIZE; i++) {
        state_signature_t* entry = ctx->signature_table[i];
        while (entry) {
            state_signature_t* next = entry->next;
            free(entry);
            entry = next;
        }
    }
    // Free NFA state tags
    for (int i = 0; i < ctx->nfa_state_count; i++) {
        for (int j = 0; j < ctx->nfa[i].tag_count; j++) {
            free(ctx->nfa[i].tags[j]);
        }
        mta_free(&ctx->nfa[i].multi_targets);
    }
    free(ctx);
}

// ============================================================================
// nfa_graph lifecycle - finalizing NFA for conversion to DFA
// ============================================================================

nfa_graph_t* nfa_graph_create(nfa_state_t* states, int state_count,
                               alphabet_entry_t* alphabet, int alphabet_size) {
    if (!states || state_count <= 0) return NULL;
    
    nfa_graph_t* graph = calloc(1, sizeof(nfa_graph_t));
    if (!graph) return NULL;
    
    graph->states = states;
    graph->state_count = state_count;
    graph->alphabet_size = alphabet_size;
    graph->owns_data = true;
    
    if (alphabet && alphabet_size > 0) {
        graph->alphabet = calloc((size_t)alphabet_size, sizeof(alphabet_entry_t));
        if (!graph->alphabet) {
            free(graph);
            return NULL;
        }
        memcpy(graph->alphabet, alphabet, (size_t)alphabet_size * sizeof(alphabet_entry_t));
    } else {
        graph->alphabet = NULL;
    }
    
    return graph;
}

void nfa_graph_free(nfa_graph_t* graph) {
    if (!graph) return;
    if (graph->owns_data) {
        free(graph->states);
        free(graph->alphabet);
    }
    free(graph);
}

nfa_graph_t* nfa_builder_finalize(nfa_builder_context_t* ctx, 
                                   const nfa_premin_options_t* premin_opts,
                                   nfa_premin_stats_t* out_premin_stats) {
    if (!ctx || ctx->nfa_state_count <= 0) return NULL;
    
    nfa_state_t* states = calloc(MAX_STATES, sizeof(nfa_state_t));
    if (!states) return NULL;
    
    int final_state_count = ctx->nfa_state_count;
    
    for (int i = 0; i < ctx->nfa_state_count && i < MAX_STATES; i++) {
        nfa_builder_state_t* src = &ctx->nfa[i];
        nfa_state_t* dst = &states[i];
        
        dst->category_mask = src->category_mask;
        dst->pattern_id = (uint16_t)src->pattern_id;
        dst->is_eos_target = src->is_eos_target;
        dst->pending_marker_count = 0;
        
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            if (src->multi_targets.has_first_target[j]) {
                dst->multi_targets.first_targets[j] = src->multi_targets.first_targets[j];
                dst->multi_targets.has_first_target[j] = true;
            }
        }
        
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            mta_entry_t* src_entry = src->multi_targets.symbol_map[j];
            if (src_entry != NULL) {
                mta_entry_t* new_entry = malloc(sizeof(mta_entry_t));
                if (!new_entry) continue;
                    
                new_entry->symbol_id = src_entry->symbol_id;
                new_entry->target_count = src_entry->target_count;
                new_entry->target_capacity = src_entry->target_capacity;
                new_entry->dirty = src_entry->dirty;
                new_entry->cached_csv = NULL;
                new_entry->marker_count = src_entry->marker_count;
                
                size_t targets_size = (size_t)src_entry->target_capacity * sizeof(int);
                new_entry->targets = malloc(targets_size);
                if (!new_entry->targets) {
                    free(new_entry);
                    continue;
                }
                memcpy(new_entry->targets, src_entry->targets, 
                       (size_t)src_entry->target_count * sizeof(int));
                
                for (int k = 0; k < src_entry->marker_count; k++) {
                    new_entry->markers[k] = src_entry->markers[k];
                }
                
                dst->multi_targets.symbol_map[j] = new_entry;
            }
        }
        
        dst->multi_targets.entry_count = 0;
        dst->multi_targets.entry_capacity = 0;
        dst->multi_targets.active_entries = NULL;
        
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            if (dst->multi_targets.symbol_map[j] != NULL) {
                if (dst->multi_targets.entry_count >= dst->multi_targets.entry_capacity) {
                    int new_cap = dst->multi_targets.entry_capacity == 0 ? 8 : dst->multi_targets.entry_capacity * 2;
                    mta_entry_t** new_active = realloc(dst->multi_targets.active_entries, 
                                                      (size_t)new_cap * sizeof(mta_entry_t*));
                    if (!new_active) {
                        free(dst->multi_targets.active_entries);
                        continue;
                    }
                    dst->multi_targets.active_entries = new_active;
                    dst->multi_targets.entry_capacity = new_cap;
                }
                if (dst->multi_targets.entry_count < dst->multi_targets.entry_capacity) {
                    dst->multi_targets.active_entries[dst->multi_targets.entry_count++] = 
                        dst->multi_targets.symbol_map[j];
                }
            }
        }
    }
    
    if (premin_opts) {
        nfa_preminimize(states, &final_state_count, premin_opts);
    }
    
    alphabet_entry_t* alphabet = NULL;
    int alphabet_size = 0;
    if (ctx->alphabet_size > 0) {
        alphabet = calloc((size_t)ctx->alphabet_size, sizeof(alphabet_entry_t));
        if (!alphabet) {
            for (int i = 0; i < final_state_count; i++) {
                mta_free(&states[i].multi_targets);
            }
            free(states);
            return NULL;
        }
        for (int i = 0; i < ctx->alphabet_size; i++) {
            alphabet[i].symbol_id = ctx->alphabet[i].symbol_id;
            alphabet[i].start_char = ctx->alphabet[i].start_char;
            alphabet[i].end_char = ctx->alphabet[i].end_char;
            alphabet[i].is_special = ctx->alphabet[i].is_special;
        }
        alphabet_size = ctx->alphabet_size;
    }
    
    nfa_graph_t* result = nfa_graph_create(states, final_state_count, alphabet, alphabet_size);
    if (!result) {
        for (int i = 0; i < final_state_count; i++) {
            mta_free(&states[i].multi_targets);
        }
        free(states);
        free(alphabet);
        return NULL;
    }
    
    if (out_premin_stats) {
        nfa_premin_stats_t premin_stats;
        nfa_premin_get_stats(&premin_stats);
        out_premin_stats->original_states = ctx->nfa_state_count;
        out_premin_stats->minimized_states = final_state_count;
        out_premin_stats->epsilon_bypassed = premin_stats.epsilon_bypassed;
        out_premin_stats->epsilon_chains = premin_stats.epsilon_chains;
        out_premin_stats->landing_pads_removed = premin_stats.landing_pads_removed;
        out_premin_stats->unreachable_removed = premin_stats.unreachable_removed;
        out_premin_stats->states_merged = premin_stats.states_merged;
        out_premin_stats->identical_merged = premin_stats.identical_merged;
        out_premin_stats->prefix_merged = premin_stats.prefix_merged;
        out_premin_stats->final_deduped = premin_stats.final_deduped;
        out_premin_stats->suffix_merged = premin_stats.suffix_merged;
        out_premin_stats->sat_merged = premin_stats.sat_merged;
        out_premin_stats->sat_optimal = premin_stats.sat_optimal;
    }
    
    return result;
}

// ============================================================================
// Legacy compatibility (used by nfa2dfa.c)
// ============================================================================

int find_symbol_id(unsigned char c) {
    return (int)c;
}
