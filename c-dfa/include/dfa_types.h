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
 *
 * Version 6 layout (with capture markers):
 * - Header (dfa_t)
 * - Identifier
 * - Name Table (metadata block)
 * - States array (dfa_state_t)
 * - Rules array (dfa_rule_t)
 * - Marker Block
 */
typedef struct __attribute__((packed)) {
    uint32_t transitions_offset;      // Offset to rule table (absolute, from DFA base, 0 = no rules)
    uint16_t transition_count;        // Number of rules
    uint16_t flags;                   // State flags (accepting, capture markers, etc.)
    int8_t capture_start_id;          // Capture ID for CAPTURE_START (-1 = none)
    int8_t capture_end_id;            // Capture ID for CAPTURE_END (-1 = none)
    int8_t capture_defer_id;          // Capture ID for deferred CAPTURE_END (-1 = none)
    uint16_t accepting_pattern_id;     // Pattern ID for accepting state (0 = not accepting, >0 = accepting with pattern)
    uint32_t eos_target;              // Offset to EOS target state (absolute, 0 = no EOS transition)
    uint32_t eos_marker_offset;       // Offset to EOS marker list (absolute, 0 = no markers)
} dfa_state_t;

/**
 * Complete DFA structure - can be memory-mapped directly
 *
 * Version 6 layout (with capture markers):
 * - Header (dfa_t): magic(4) + version(2) + state_count(2) + initial_state(4) +
 *                   accepting_mask(4) + flags(2) + identifier_length(1) + metadata_offset(4) = 23 bytes
 * - identifier (0-255 bytes, not null-terminated)
 * - Name Table (metadata_offset): [entry_count(4)][Entry1: pattern_id(2), name_len(2), name_data...][Entry2...]
 * - States array (dfa_state_t)
 * - Rules array (dfa_rule_t)
 * - Marker Block: Variable-length marker lists, each terminated by 0xFFFFFFFF sentinel
 */
typedef struct __attribute__((packed)) {
    uint32_t magic;                   // Magic number: 0xDFA1DFA1
    uint16_t version;                 // Version: 6
    uint16_t state_count;             // Total number of states
    uint32_t initial_state;           // Offset to initial state (absolute, from DFA base)
    uint32_t accepting_mask;          // Bitmask of accepting states
    uint16_t flags;                   // DFA flags
    uint8_t identifier_length;        // Length of identifier (0-255)
    uint32_t metadata_offset;          // Offset to name table (absolute, from DFA base)
    uint8_t identifier[];            // Identifier string (not null-terminated)
} dfa_t;

/**
 * DFA State Flags
 */
#define DFA_STATE_ACCEPTING      0x0001  // This is an accepting state
#define DFA_STATE_ERROR          0x0002  // This is an error state
#define DFA_STATE_DEAD           0x0004  // No transitions from this state
#define DFA_STATE_CAPTURE_START  0x0008  // State has CAPTURE_START marker
#define DFA_STATE_CAPTURE_END    0x0010  // State has CAPTURE_END marker
#define DFA_STATE_CAPTURE_DEFER  0x0020  // Defer CAPTURE_END until leaving this state

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
#define DFA_VERSION 6  // Version 6: Capture markers and scalable metadata

/**
 * Maximum number of states in a single DFA
 */
#define DFA_MAX_STATES 65535

/**
 * Maximum number of transitions per state
 */
#define DFA_MAX_TRANSITIONS 256

/**
 * Rule types for V5 format
 */
#define DFA_RULE_LITERAL        0  // Match data1
#define DFA_RULE_RANGE          1  // Match data1..data2
#define DFA_RULE_LITERAL_2      2  // Match data1 or data2
#define DFA_RULE_LITERAL_3      3  // Match data1 or data2 or data3
#define DFA_RULE_RANGE_LITERAL  4  // Match data1..data2 or data3
#define DFA_RULE_DEFAULT        5  // Match anything
#define DFA_RULE_NOT_LITERAL    6  // Match anything NOT data1
#define DFA_RULE_NOT_RANGE      7  // Match anything NOT in data1..data2

/**
 * Compact Rule entry (12 bytes on 32-bit systems, may vary)
 *
 * Marker encoding in marker_offset lists:
 * - Each marker is packed into a uint32_t: [16-bit PatternID][15-bit UID][1-bit Type]
 * - Type: 0 = CAPTURE_START, 1 = CAPTURE_END
 * - UID: Unique identifier for the capture point
 * - PatternID: Which pattern this capture belongs to
 * - Lists are terminated by 0xFFFFFFFF sentinel
 */
typedef struct __attribute__((packed)) {
    uint8_t type;                // Rule type (DFA_RULE_*)
    uint8_t data1;               // Generic payload byte 1
    uint8_t data2;               // Generic payload byte 2
    uint8_t data3;               // Generic payload byte 3 (for LITERAL_3, RANGE_LITERAL)
    uint32_t target;             // Next state offset (absolute file offset)
    uint32_t marker_offset;      // Offset to marker list (absolute, from DFA base, 0 = no markers)
} dfa_rule_t;

/**
 * Special character values
 */
#define DFA_CHAR_ANY 0x00               // Wildcard
#define DFA_CHAR_EPSILON 0x01           // Epsilon
#define DFA_CHAR_END 0x02               // End marker
#define DFA_CHAR_WHITESPACE 0x03        // Whitespace
#define DFA_CHAR_VERBATIM_SPACE 0x04    // Literal space
#define DFA_CHAR_NORMALIZING_SPACE 0xFE // Matches one or more spaces
#define DFA_CHAR_INSTANT 0xFF           // Non-consuming transition
#define DFA_CHAR_EOS 0x05               // End of String

#define DFA_MAX_CAPTURES 16             // Maximum captures

/**
 * Single capture result
 */
typedef struct {
    size_t start;              // Start position in input
    size_t end;                // End position in input
    char name[32];             // Capture name
    bool active;               // In progress
    bool completed;            // Finished
    int capture_id;            // Lookup ID
} dfa_capture_t;

/**
 * Category bitmask constants
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
 * Command categories
 */
typedef enum {
    DFA_CMD_UNKNOWN = 0,
    DFA_CMD_READONLY_SAFE,
    DFA_CMD_READONLY_CAUTION,
    DFA_CMD_MODIFYING,
    DFA_CMD_DANGEROUS,
    DFA_CMD_NETWORK,
    DFA_CMD_ADMIN,
} dfa_command_category_t;

/**
 * Result of DFA evaluation
 */
typedef struct {
    dfa_command_category_t category;
    uint8_t category_mask;
    uint32_t final_state;
    bool matched;
    size_t matched_length;
    dfa_capture_t captures[DFA_MAX_CAPTURES];
    int capture_count;
} dfa_result_t;

/**
 * Marker Block Constants
 */
#define MARKER_SENTINEL 0xFFFFFFFF
#define MARKER_TYPE_START 0
#define MARKER_TYPE_END 1

/**
 * Marker encoding macros
 * Marker format: [16-bit PatternID][15-bit UID][1-bit Type]
 */
#define MARKER_PACK(pattern_id, uid, type) \
    ((((uint32_t)(pattern_id)) << 17) | (((uint32_t)(uid)) << 1) | (uint32_t)(type))

#define MARKER_GET_PATTERN_ID(marker) ((uint16_t)((marker) >> 17))
#define MARKER_GET_UID(marker) ((uint16_t)(((marker) >> 1) & 0x7FFF))
#define MARKER_GET_TYPE(marker) ((marker) & 0x01)

/**
 * Name Table Entry (variable length)
 * Stored at metadata_offset:
 * - entry_count (4 bytes): Number of entries
 * - Followed by variable-length entries
 */
typedef struct {
    uint16_t pattern_id;      // Pattern identifier
    uint16_t name_length;     // Length of capture name (excluding null terminator)
    char name_data[];         // Capture name (not null-terminated)
} dfa_name_entry_t;

/**
 * Marker List Entry (fixed 4 bytes per marker)
 * Each rule/state can point to a list of markers.
 * Lists are terminated by MARKER_SENTINEL (0xFFFFFFFF).
 */
typedef uint32_t dfa_marker_t;

#endif // DFA_TYPES_H
