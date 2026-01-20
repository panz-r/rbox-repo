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
 */
typedef struct {
    /**
     * Transition table for this state.
     * Array of (character, next_state_offset) pairs.
     * Terminated by a special marker (character = 0, next_state_offset = 0).
     */
    uint32_t transitions_offset;  // Offset to transition table
    uint16_t transition_count;    // Number of transitions
    uint16_t flags;               // State flags (accepting, error, etc.)
} dfa_state_t;

/**
 * Transition entry - maps a character to a next state
 */
typedef struct {
    char character;              // Input character (0 = end marker)
    uint32_t next_state_offset;  // Offset to next state (0 = no transition)
} dfa_transition_t;

/**
 * Complete DFA structure - can be memory-mapped directly
 */
typedef struct {
    uint32_t magic;              // Magic number: 0xDFA1DFA1
    uint16_t version;            // Version: 2 (with alphabet support)
    uint16_t state_count;        // Total number of states
    uint32_t initial_state;      // Offset to initial state
    uint32_t accepting_mask;     // Bitmask of accepting states
    uint16_t alphabet_size;      // Number of symbols in alphabet (version 2+)
    uint16_t reserved;           // Reserved for future use
    // Alphabet mapping follows (version 2+):
    // char alphabet_map[256];   // Maps character to symbol ID
    // Then states and transitions follow
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
 * Magic number for DFA validation
 */
#define DFA_MAGIC 0xDFA1DFA1

/**
 * Current DFA version
 */
#define DFA_VERSION 2  // Version 2 adds alphabet support

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
 */
#define DFA_CHAR_ANY 0x00               // Wildcard (matches any character)
#define DFA_CHAR_EPSILON 0x01           // Epsilon transition
#define DFA_CHAR_END 0x00               // End of transition table marker
#define DFA_CHAR_WHITESPACE 0x02        // Matches any whitespace character (space, tab, newline)
#define DFA_CHAR_VERBATIM_SPACE 0x03    // Matches exactly one space character
#define DFA_CHAR_NORMALIZING_SPACE 0x04 // Matches one or more space/tab characters (normalizing)

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
    dfa_command_category_t category;  // Command category
    uint32_t final_state;             // Final state offset
    bool matched;                     // Whether the input matched completely
    size_t matched_length;            // Number of characters matched
} dfa_result_t;

#endif // DFA_TYPES_H