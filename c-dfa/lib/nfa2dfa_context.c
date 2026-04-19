/**
 * nfa2dfa_context.c - Implementation of NFA-to-DFA context management
 */

#include <stdlib.h>
#include <string.h>
#include "dfa_types.h"
#include "nfa.h"
#include "nfa2dfa_context.h"

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

    free(ctx->dfa_hash_table);
    free(ctx->dfa_next_in_bucket);
    free(ctx->dfa_marker_lists);
    free(ctx->nfa);
    free(ctx->alphabet);
    free(ctx);
}