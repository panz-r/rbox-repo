/**
 * Shared NFA/DFA build-time constants and type definitions
 * Used by nfa_builder.c and nfa2dfa.c
 */

#ifndef NFA_H
#define NFA_H

#include <stdbool.h>
#include <stdint.h>
#include "cdfa_defines.h"

#define BYTE_VALUE_MAX 256
#define MAX_PATTERNS 2048
#define MAX_TAGS 16
#define SIGNATURE_TABLE_SIZE 4096
#define MAX_PENDING_MARKERS 8

#include "multi_target_array.h"

/* Pending marker for tracking markers that need to be attached to transitions */
typedef struct {
    uint16_t pattern_id;
    uint32_t uid;
    uint8_t type;  /* 0 = START, 1 = END */
    bool active;
} pending_marker_t;

/* Shared NFA state structure for both nfa_builder and nfa2dfa */
typedef struct {
    uint8_t category_mask;
    uint16_t pattern_id;    // Pattern ID for this state (0 = none)
    int transitions[MAX_SYMBOLS];
    multi_target_array_t multi_targets;
    bool is_eos_target;
    /* Pending markers to attach to outgoing transitions */
    pending_marker_t pending_markers[MAX_PENDING_MARKERS];
    int pending_marker_count;
} nfa_state_t;

/* Alphabet entry for character class mapping */
typedef struct {
    int symbol_id;
    int start_char;
    int end_char;
    bool is_special;
} alphabet_entry_t;

/* Finalized NFA graph - read-only representation for conversion to DFA */
typedef struct {
    nfa_state_t* states;       // NFA state array (owned by this struct)
    int state_count;            // Number of states
    alphabet_entry_t* alphabet; // Alphabet (or NULL if not needed)
    int alphabet_size;          // Alphabet size
} nfa_graph_t;

/**
 * Create an nfa_graph_t from a state array.
 * Takes ownership of the provided states buffer - caller must NOT free it.
 * Returns newly allocated nfa_graph_t that caller owns.
 */
nfa_graph_t* nfa_graph_create(nfa_state_t* states, int state_count,
                               alphabet_entry_t* alphabet, int alphabet_size);

/**
 * Free an nfa_graph_t and all its owned memory.
 */
void nfa_graph_free(nfa_graph_t* graph);

#endif // NFA_H
