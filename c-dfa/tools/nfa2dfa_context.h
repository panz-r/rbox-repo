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
#include "dfa_minimize.h"

#define DFA_HASH_SIZE 32749

typedef struct {
    int symbol_id;
    int start_char;
    int end_char;
    bool is_special;
} alphabet_entry_t;

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

    // Hash table for DFA dedup
    int* dfa_hash_table;
    int* dfa_next_in_bucket;

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

#endif // NFA2DFA_CONTEXT_H
