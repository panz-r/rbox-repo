#ifndef DFA_COMPACT_H
#define DFA_COMPACT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * Compact DFA State - optimized for size while maintaining direct usability
 *
 * Key improvements:
 * - Variable-length encoding for offsets (1-4 bytes based on DFA size)
 * - Range-based transitions for character classes
 * - Default transitions to reduce table size
 * - Bit-packed flags and counts
 */
typedef struct {
    /**
     * Transition data using variable-length encoding.
     * Format: [transition_type][data...]
     * Where transition_type determines the encoding format.
     */
    uint8_t transitions[]; // Variable-length transition data
} dfa_compact_state_t;

/**
 * Compact DFA Header - smaller and more flexible
 */
typedef struct {
    uint32_t magic;              // Magic number: 0xDFA2DFA2 (new version)
    uint8_t version;             // Version: 2
    uint8_t flags;               // DFA flags
    uint16_t state_count;        // Total number of states
    uint32_t initial_state;      // Offset to initial state (variable-length encoded)
    uint8_t offset_size;         // Size of offsets in bytes (1, 2, or 4)
    uint8_t reserved[3];         // Padding for alignment
    // States follow immediately after header
} dfa_compact_t;

/**
 * Transition Types (first byte of transition data)
 */
#define DFA_TRANS_DEFAULT  0x00    // Default transition (single next state)
#define DFA_TRANS_RANGE    0x01    // Character range transition
#define DFA_TRANS_SPARSE   0x02    // Sparse character transitions
#define DFA_TRANS_END      0xFF    // End of transition table

/**
 * Compact DFA Magic Number
 */
#define DFA_COMPACT_MAGIC 0xDFA2DFA2

/**
 * Compact DFA Version
 */
#define DFA_COMPACT_VERSION 2

/**
 * Maximum offset size (4 bytes = 4GB address space)
 */
#define DFA_MAX_OFFSET_SIZE 4

#endif // DFA_COMPACT_H