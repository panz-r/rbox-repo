/**
 * Shared NFA/DFA build-time constants and type definitions
 * Used by nfa_builder.c and nfa2dfa.c
 */

#ifndef NFA_H
#define NFA_H

#include <stdbool.h>
#include <stdint.h>

#define MAX_STATES 8192
#define MAX_SYMBOLS 320
#define MAX_CHARS 256
#define MAX_PATTERNS 2048
#define MAX_LINE_LENGTH 2048
#define MAX_TAGS 16
#define SIGNATURE_TABLE_SIZE 4096
#define MAX_PENDING_MARKERS 8
#define MAX_TRANSITION_MARKERS 65536

/* Category bitmask constants (8 categories, one bit each) */
#define CAT_MASK_SAFE       0x01
#define CAT_MASK_CAUTION    0x02
#define CAT_MASK_MODIFYING  0x04
#define CAT_MASK_DANGEROUS  0x08
#define CAT_MASK_NETWORK    0x10
#define CAT_MASK_ADMIN      0x20
#define CAT_MASK_BUILD      0x40
#define CAT_MASK_CONTAINER  0x80

#include "multi_target_array.h"

/* Pending marker for tracking markers that need to be attached to transitions */
typedef struct {
    uint16_t pattern_id;
    uint32_t uid;
    uint8_t type;  /* 0 = START, 1 = END */
    bool active;
} pending_marker_t;

/* Transition marker storage - attached to specific NFA transitions */
typedef struct {
    uint32_t markers[MAX_PENDING_MARKERS];
    int marker_count;
} transition_marker_entry_t;

/* Accessor for transition markers - defined in nfa_builder.c */
transition_marker_entry_t* get_transition_marker_entry(int from_state, int symbol_id);

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

#endif // NFA_H
