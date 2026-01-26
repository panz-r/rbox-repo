#ifndef DFA_TYPES_H
#define DFA_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * DFA State - represents a single state in the DFA
 *
 * The DFA is stored as a compact binary structure with the following layout:
 * - States are stored in a contiguous array
 * - Transitions use offsets from the start of the structure
 * - This allows direct memory mapping without deserialization
 *
 * Flags field encoding (16 bits):
 * - Bits 0-7: State flags (DFA_STATE_*)
 * - Bits 8-15: Category mask (8-way parallel acceptance)
 */
typedef struct {
    /**
     * Transition table for this state.
     * Array of (character, next_state_offset) pairs.
     * Terminated by a special marker (character = 0, next_state_offset = 0).
     */
    uint32_t transitions_offset;  // Offset to transition table
    uint16_t transition_count;    // Number of transitions
    uint16_t flags;               // State flags (lower 8 bits) | category_mask (upper 8 bits)
} dfa_state_t;

/**
 * Transition entry - maps a character to a next state
 */
typedef struct __attribute__((packed)) {
    char character;              // Input character (0 = end marker)
    uint32_t next_state_offset;  // Offset to next state (0 = no transition)
} dfa_transition_t;

/**
 * Complete DFA structure - can be memory-mapped directly
 *
 * Version 3 layout:
 * - Header (24 bytes)
 * - States array
 * - Transition tables follow after states
 *
 * Transitions are stored as compact 5-byte entries:
 * - 1 byte character (0 = end marker)
 * - 4 bytes next_state_offset (absolute file offset)
 */
typedef struct {
    uint32_t magic;              // Magic number: 0xDFA1DFA1
    uint16_t version;            // Version: 3 (character-based, no alphabet_map)
    uint16_t state_count;        // Total number of states
    uint32_t initial_state;      // Offset to initial state
    uint32_t accepting_mask;     // Bitmask of accepting states
    uint16_t flags;              // DFA flags
    uint16_t reserved;           // Reserved for future use
    dfa_state_t states[];        // Flexible array of states
    // Transition tables follow after states
} dfa_t;

/**
 * DFA State Flags
 */
#define DFA_STATE_ACCEPTING  0x0001  // This is an accepting state
#define DFA_STATE_ERROR      0x0002  // This is an error state
#define DFA_STATE_DEAD       0x0004  // No transitions from this state

/**
 * Category mask extraction from flags
 */
#define DFA_GET_CATEGORY_MASK(flags) ((flags) >> 8)
#define DFA_SET_CATEGORY_MASK(flags, mask) ((flags) = ((flags) & 0x00FF) | ((mask) << 8))

/**
 * Magic number for DFA validation
 */
#define DFA_MAGIC 0xDFA1DFA1

/**
 * Current DFA version
 */
#define DFA_VERSION 4  // Version 4: character-based transitions with capture support

/**
 * Maximum number of states in a single DFA
 */
#define DFA_MAX_STATES 65535

/**
 * Maximum number of transitions per state
 */
#define DFA_MAX_TRANSITIONS 256

/**
 * Special character values
 * Note: Capture markers use high values (>= 0xF0) to avoid conflicts with normal characters
 */
#define DFA_CHAR_ANY 0x00               // Wildcard (matches any character)
#define DFA_CHAR_EPSILON 0x01           // Epsilon transition
#define DFA_CHAR_END 0x02               // End of transition table marker (NOT the same as ANY!)
#define DFA_CHAR_WHITESPACE 0x03        // Matches any whitespace character (space, tab, newline)
#define DFA_CHAR_VERBATIM_SPACE 0x04    // Matches exactly one space character
#define DFA_CHAR_NORMALIZING_SPACE 0xFE // Matches one or more space/tab characters (normalizing)
#define DFA_CHAR_EOS 0x05               // End of String marker (used for accepting) - matches alphabet symbol 1
#define DFA_CHAR_CAPTURE_START 0xF0     // Capture start marker (next byte is kind, 0xF0-0xFF)
#define DFA_CHAR_CAPTURE_END 0xF1       // Capture end marker (next byte is kind, 0xF0-0xFF)

#define DFA_MAX_CAPTURES 16             // Maximum number of concurrent captures

/**
 * Single capture result
 */
typedef struct {
    size_t start;              // Start position in input (0 = not started)
    size_t end;                // End position in input
    char name[32];             // Capture name (for debugging/API)
    bool active;               // Is capture currently in progress?
    bool completed;            // Was capture successfully completed?
} dfa_capture_t;

/**
 * Category bitmask constants (8 categories, one bit each)
 * These match the values used during NFA/DFA construction
 */
#define CAT_MASK_SAFE       0x01
#define CAT_MASK_CAUTION    0x02
#define CAT_MASK_MODIFYING  0x04
#define CAT_MASK_DANGEROUS  0x08
#define CAT_MASK_NETWORK    0x10
#define CAT_MASK_ADMIN      0x20
#define CAT_MASK_BUILD      0x40
#define CAT_MASK_CONTAINER  0x80

/**
 * Command categories for accepting states
 */
typedef enum {
    DFA_CMD_UNKNOWN = 0,      // Unknown command
    DFA_CMD_READONLY_SAFE,    // Read-only, 100% safe
    DFA_CMD_READONLY_CAUTION, // Read-only but needs caution
    DFA_CMD_MODIFYING,        // Modifies filesystem
    DFA_CMD_DANGEROUS,        // Potentially dangerous
    DFA_CMD_NETWORK,          // Network operations
    DFA_CMD_ADMIN,            // Requires admin privileges
} dfa_command_category_t;

/**
 * Result of DFA evaluation
 */
typedef struct {
    dfa_command_category_t category;   // Command category (legacy enum, derived from mask)
    uint8_t category_mask;             // 8-bit category mask for parallel acceptance
    uint32_t final_state;              // Final state offset
    bool matched;                      // Whether the input matched completely
    size_t matched_length;             // Number of characters matched
    dfa_capture_t captures[DFA_MAX_CAPTURES];  // Capture results
    int capture_count;                 // Number of captures found
} dfa_result_t;

#endif // DFA_TYPES_H