/**
 * nfa2dfa_context.c - Implementation of NFA-to-DFA context management
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dfa_types.h"
#include "nfa.h"
#include "nfa2dfa_context.h"
#include "nfa_builder.h"
#include "multi_target_array.h"

static void* checked_malloc(size_t size) {
    if (size == 0) return NULL;
    if (size > SIZE_MAX) return NULL;
    void* ptr = malloc(size);
    return ptr;
}

nfa2dfa_context_t* nfa2dfa_context_create(void) {
    nfa2dfa_context_t* ctx = calloc(1, sizeof(nfa2dfa_context_t));
    if (!ctx) return NULL;

    // Allocate NFA array with overflow check
    size_t nfa_size;
    if (CKD_MUL(&nfa_size, (size_t)MAX_STATES, sizeof(nfa_state_t))) {
        free(ctx);
        return NULL;
    }
    ctx->nfa = calloc(1, nfa_size);
    if (!ctx->nfa) {
        free(ctx);
        return NULL;
    }
    ctx->nfa_state_count = 0;
    
    // Allocate DFA state pointer array with overflow check
    size_t dfa_size;
    if (CKD_MUL(&dfa_size, (size_t)MAX_STATES, sizeof(build_dfa_state_t*))) {
        free(ctx->nfa);
        free(ctx);
        return NULL;
    }
    ctx->dfa = calloc(1, dfa_size);
    if (!ctx->dfa) {
        free(ctx->nfa);
        free(ctx);
        return NULL;
    }
    ctx->dfa_state_count = 0;
    ctx->dfa_state_capacity = MAX_STATES;
    ctx->max_states = MAX_STATES;
    
    // Allocate alphabet array with overflow check
    size_t alphabet_alloc_size;
    if (CKD_MUL(&alphabet_alloc_size, (size_t)MAX_SYMBOLS, sizeof(alphabet_entry_t))) {
        free(ctx->dfa);
        free(ctx->nfa);
        free(ctx);
        return NULL;
    }
    ctx->alphabet = calloc(1, alphabet_alloc_size);
    if (!ctx->alphabet) {
        free(ctx->dfa);
        free(ctx->nfa);
        free(ctx);
        return NULL;
    }
    ctx->alphabet_size = 0;
    
    // Allocate hash table with overflow check
    size_t hash_size, next_size;
    if (CKD_MUL(&hash_size, (size_t)DFA_HASH_SIZE, sizeof(int)) ||
        CKD_MUL(&next_size, (size_t)MAX_STATES, sizeof(int))) {
        free(ctx->alphabet);
        free(ctx->dfa);
        free(ctx->nfa);
        free(ctx);
        return NULL;
    }
    ctx->dfa_hash_table = calloc(DFA_HASH_SIZE, sizeof(int));
    ctx->dfa_next_in_bucket = calloc(MAX_STATES, sizeof(int));
    if (!ctx->dfa_hash_table || !ctx->dfa_next_in_bucket) {
        free(ctx->alphabet);
        free(ctx->dfa);
        free(ctx->nfa);
        free(ctx->dfa_hash_table);
        free(ctx->dfa_next_in_bucket);
        free(ctx);
        return NULL;
    }
    
    ctx->dfa_marker_lists = NULL;
    ctx->marker_list_count = 0;
    ctx->pattern_identifier[0] = '\0';
    ctx->flag_verbose = false;

    return ctx;
}

int nfa2dfa_context_set_nfa(nfa2dfa_context_t* ctx, nfa_builder_context_t* builder_ctx) {
    if (!ctx || !builder_ctx) return -1;

    // Initialize all NFA states to -1 and init multi_targets
    for (int i = 0; i < MAX_STATES; i++) {
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            ctx->nfa[i].transitions[j] = -1;
        }
        mta_init(&ctx->nfa[i].multi_targets);
    }
    
    // Copy NFA states from builder to nfa2dfa context
    for (int i = 0; i < builder_ctx->nfa_state_count && i < MAX_STATES; i++) {
        nfa_builder_state_t* src = &builder_ctx->nfa[i];
        nfa_state_t* dst = &ctx->nfa[i];
        
        // Copy simple fields
        dst->category_mask = src->category_mask;
        dst->pattern_id = (uint16_t)src->pattern_id;
        dst->is_eos_target = src->is_eos_target;
        dst->pending_marker_count = 0;
        
        // Copy transitions array
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            dst->transitions[j] = src->transitions[j];
        }
        
        // Deep copy multi_targets - first free any existing
        mta_free(&dst->multi_targets);
        
        // Copy first_targets if used
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            if (src->multi_targets.has_first_target[j]) {
                dst->multi_targets.first_targets[j] = src->multi_targets.first_targets[j];
                dst->multi_targets.has_first_target[j] = true;
            }
        }
        
        // Copy symbol_map entries (these are the multi-target entries)
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            mta_entry_t* src_entry = src->multi_targets.symbol_map[j];
            if (src_entry != NULL) {
                // Create new entry in destination
                mta_entry_t* new_entry = checked_malloc(sizeof(mta_entry_t));
                if (new_entry == NULL) continue;
                    
                new_entry->symbol_id = src_entry->symbol_id;
                new_entry->target_count = src_entry->target_count;
                new_entry->target_capacity = src_entry->target_capacity;
                new_entry->dirty = src_entry->dirty;
                new_entry->cached_csv = NULL;  // Will be regenerated as needed
                new_entry->marker_count = src_entry->marker_count;
                
                // Copy targets
                size_t targets_size = (size_t)src_entry->target_capacity * sizeof(int);
                new_entry->targets = checked_malloc(targets_size);
                if (new_entry->targets == NULL) {
                    free(new_entry);
                    continue;
                }
                memcpy(new_entry->targets, src_entry->targets, 
                       (size_t)src_entry->target_count * sizeof(int));
                
                // Copy markers
                for (int k = 0; k < src_entry->marker_count; k++) {
                    new_entry->markers[k] = src_entry->markers[k];
                }
                
                dst->multi_targets.symbol_map[j] = new_entry;
            }
        }
        
        // Copy active_entries count and array (need to rebuild pointer list)
        // Actually, let's rebuild active_entries from symbol_map
        dst->multi_targets.entry_count = 0;
        dst->multi_targets.entry_capacity = 0;
        free(dst->multi_targets.active_entries);
        dst->multi_targets.active_entries = NULL;
        
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            if (dst->multi_targets.symbol_map[j] != NULL) {
                // Grow active_entries if needed
                if (dst->multi_targets.entry_count >= dst->multi_targets.entry_capacity) {
                    int new_cap = dst->multi_targets.entry_capacity == 0 ? 8 : dst->multi_targets.entry_capacity * 2;
                    mta_entry_t** new_active = realloc(dst->multi_targets.active_entries, 
                                                      (size_t)new_cap * sizeof(mta_entry_t*));
                    if (new_active == NULL) {
                        // realloc failed - entry remains in symbol_map, will be freed by mta_free
                        // We just can't add it to active_entries right now
                        continue;
                    }
                    // Success - update pointers
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
    ctx->nfa_state_count = builder_ctx->nfa_state_count;
    
    // Copy alphabet
    ctx->alphabet_size = builder_ctx->alphabet_size;
    for (int i = 0; i < builder_ctx->alphabet_size && i < MAX_SYMBOLS; i++) {
        ctx->alphabet[i].symbol_id = builder_ctx->alphabet[i].symbol_id;
        ctx->alphabet[i].start_char = builder_ctx->alphabet[i].start_char;
        ctx->alphabet[i].end_char = builder_ctx->alphabet[i].end_char;
        ctx->alphabet[i].is_special = builder_ctx->alphabet[i].is_special;
    }
    
    return ctx->nfa_state_count;
}

void nfa2dfa_context_destroy(nfa2dfa_context_t* ctx) {
    if (!ctx) return;

    // Free each DFA state
    if (ctx->dfa) {
        for (int i = 0; i < ctx->dfa_state_count; i++) {
            if (ctx->dfa[i]) {
                build_dfa_state_destroy(ctx->dfa[i]);
            }
        }
        free(ctx->dfa);
    }

    // Free NFA states' multi-target arrays (array has MAX_STATES entries)
    if (ctx->nfa) {
        for (int i = 0; i < MAX_STATES; i++) {
            mta_free(&ctx->nfa[i].multi_targets);
        }
        free(ctx->nfa);
    }

    free(ctx->dfa_hash_table);
    free(ctx->dfa_next_in_bucket);
    free(ctx->dfa_marker_lists);
    free(ctx->alphabet);
    free(ctx);
}