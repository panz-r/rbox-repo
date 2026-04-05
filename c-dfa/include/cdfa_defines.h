/**
 * cdfa_defines.h - Compiler and platform attribute macros and shared constants
 *
 * Single source of truth for:
 *   - Compiler attribute macros (ATTR_*)
 *   - DFA magic number and version
 *   - State flags (DFA_STATE_*)
 *   - Rule types (DFA_RULE_*)
 *   - Rule encoding types (DFA_RULE_ENC_*)
 *   - Size limits (MAX_STATES, DFA_HASH_SIZE)
 */

#ifndef CDFA_DEFINES_H
#define CDFA_DEFINES_H

/* ============================================================================
 * Compiler attribute macros
 * ============================================================================ */

#if defined(__GNUC__) || defined(__clang__)
#define ATTR_UNUSED __attribute__((unused))
#define ATTR_NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))
#define ATTR_NONNULL_ALL __attribute__((nonnull))

#else
#define ATTR_UNUSED
#define ATTR_NONNULL(...)
#define ATTR_NONNULL_ALL
#endif

/* ============================================================================
 * Size limits
 * ============================================================================ */

#ifndef MAX_STATES
#define MAX_STATES 32768
#endif

#ifndef DFA_HASH_SIZE
#define DFA_HASH_SIZE 32749
#endif

#ifndef MAX_SYMBOLS
#define MAX_SYMBOLS 320
#endif

/* ============================================================================
 * DFA binary format constants
 * ============================================================================ */

/**
 * Magic number for DFA validation
 */
#define DFA_MAGIC 0xDFA1DFA1

/**
 * Current DFA version
 */
#define DFA_VERSION 10

/**
 * State flags
 */
#define DFA_STATE_ACCEPTING      0x0001  // This is an accepting state
#define DFA_STATE_ERROR          0x0002  // This is an error state
#define DFA_STATE_DEAD           0x0004  // No transitions from this state
#define DFA_STATE_CAPTURE_START  0x0008  // State has CAPTURE_START marker
#define DFA_STATE_CAPTURE_END    0x0010  // State has CAPTURE_END marker
#define DFA_STATE_CAPTURE_DEFER  0x0020  // Defer CAPTURE_END until leaving this state

/**
 * State flag helpers
 */
#define DFA_STATE_CATEGORY_MASK  0xFF00  // bits 8-15: 8-bit category mask
#define DFA_STATE_RULE_ENC_MASK  0x00C0  // bits 6-7: rule encoding selector
#define DFA_STATE_RULE_ENC_SHIFT 6

/**
 * Rule types
 */
#define DFA_RULE_LITERAL        0  // Match data1
#define DFA_RULE_RANGE           1  // Match data1..data2
#define DFA_RULE_LITERAL_2      2  // Match data1 or data2
#define DFA_RULE_LITERAL_3      3  // Match data1 or data2 or data3
#define DFA_RULE_RANGE_LITERAL   4  // Match data1..data2 or data3
#define DFA_RULE_DEFAULT         5  // Match anything
#define DFA_RULE_NOT_LITERAL     6  // Match anything NOT data1
#define DFA_RULE_NOT_RANGE       7  // Match anything NOT in data1..data2
#define DFA_RULE_BITMASK         8  // Match bytes in mask → target
#define DFA_RULE_NOT_BITMASK     9  // Match bytes NOT in mask → target
#define DFA_RULE_CHAIN          10  // Match chain of bytes → target

/**
 * Rule encoding types
 */
#define DFA_RULE_ENC_NORMAL   0  // Fixed-stride rules
#define DFA_RULE_ENC_BITMASK 1  // Bitmask rules (one per target)
#define DFA_RULE_ENC_PACKED  2  // Variable-stride packed entries (no markers)
#define DFA_RULE_ENC_CHAIN   3  // Multi-character literal chains

#endif // CDFA_DEFINES_H
