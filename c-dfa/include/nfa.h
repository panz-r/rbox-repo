/**
 * Shared NFA/DFA build-time constants and type definitions
 * Used by nfa_builder.c and nfa2dfa.c
 */

#ifndef NFA_H
#define NFA_H

#include <stdbool.h>
#include <stdint.h>

#define MAX_STATES 8192
#define MAX_SYMBOLS 256
#define MAX_CHARS 256
#define MAX_PATTERNS 2048
#define MAX_LINE_LENGTH 2048
#define MAX_TAGS 16
#define SIGNATURE_TABLE_SIZE 4096

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

/* Shared NFA state structure for both nfa_builder and nfa2dfa */
typedef struct {
    uint8_t category_mask;
    int transitions[MAX_SYMBOLS];
    multi_target_array_t multi_targets;
    int8_t capture_start_id;
    int8_t capture_end_id;
    int8_t capture_defer_id;
    bool is_eos_target;
} nfa_state_t;

#endif // NFA_H
