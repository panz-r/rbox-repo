/**
 * nfa2dfa_context.c - Implementation of NFA-to-DFA context management
 */

#include <stdlib.h>
#include <string.h>
#include "../include/dfa_types.h"
#include "../include/nfa.h"
#include "../tools/nfa2dfa_context.h"

#define DFA_HASH_SIZE 32749

nfa2dfa_context_t* nfa2dfa_context_create(void) {
    nfa2dfa_context_t* ctx = calloc(1, sizeof(nfa2dfa_context_t));
    if (!ctx) return NULL;

    // Allocate NFA array
    ctx->nfa = calloc(32768, sizeof(nfa_state_t));  // MAX_STATES
    if (!ctx->nfa) {
        free(ctx);
        return NULL;
    }
    ctx->nfa_state_count = 0;
    
    // Allocate DFA state pointer array
    ctx->dfa = calloc(32768, sizeof(build_dfa_state_t*));  // MAX_STATES
    if (!ctx->dfa) {
        free(ctx->nfa);
        free(ctx);
        return NULL;
    }
    ctx->dfa_state_count = 0;
    ctx->dfa_state_capacity = 32768;
    ctx->max_states = 32768;
    
    // Allocate alphabet array
    ctx->alphabet = calloc(320, sizeof(alphabet_entry_t));  // MAX_SYMBOLS
    if (!ctx->alphabet) {
        free(ctx->dfa);
        free(ctx->nfa);
        free(ctx);
        return NULL;
    }
    ctx->alphabet_size = 0;
    
    // Allocate hash table
    ctx->dfa_hash_table = calloc(32749, sizeof(int));  // DFA_HASH_SIZE
    ctx->dfa_next_in_bucket = calloc(32768, sizeof(int));  // MAX_STATES
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