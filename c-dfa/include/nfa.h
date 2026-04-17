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

#endif // NFA_H
