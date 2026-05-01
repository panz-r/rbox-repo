/**
 * nfa2dfa_context.h - Pipeline context for NFA-to-DFA conversion
 *
 * Encapsulates all conversion state to eliminate global variables,
 * enabling library usage, unit testing, and thread safety.
 */

#ifndef NFA2DFA_CONTEXT_H
#define NFA2DFA_CONTEXT_H

#include <stdbool.h>
#include <stdint.h>
#include "../include/nfa.h"
#include "../include/nfa_dsl.h"
#include "dfa_minimize.h"
#include "nfa_builder.h"
#include <draugr/ht.h>

/* alphabet_entry_t is defined in include/nfa_dsl.h */

typedef struct {
    // NFA storage
    nfa_state_t* nfa;
    int nfa_state_count;

    // DFA storage (dynamic array of pointers)
    build_dfa_state_t** dfa;
    int dfa_state_count;
    int dfa_state_capacity;
    int max_states;

    // Alphabet
    alphabet_entry_t* alphabet;
    int alphabet_size;

    // Bare hash table for DFA dedup (hash → DFA state index)
    ht_bare_t* dfa_dedup;

    // Marker harvesting
    MarkerList* dfa_marker_lists;
    int marker_list_count;

    // Configuration
    char pattern_identifier[256];
    bool flag_verbose;
} nfa2dfa_context_t;

/**
 * Allocate and initialize a new context with default buffer sizes.
 * Returns NULL on allocation failure.
 */
nfa2dfa_context_t* nfa2dfa_context_create(void);

/**
 * Free all memory associated with the context.
 */
void nfa2dfa_context_destroy(nfa2dfa_context_t* ctx);

/**
 * Transfer NFA from builder context directly to nfa2dfa context.
 * This eliminates the need for temp file serialization.
 * Returns number of states transferred, or -1 on error.
 */
int nfa2dfa_context_set_nfa(nfa2dfa_context_t* ctx, nfa_builder_context_t* builder_ctx);

#endif // NFA2DFA_CONTEXT_H
