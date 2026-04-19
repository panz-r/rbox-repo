/**
 * cdfa_defines.h - Compiler and platform attribute macros and shared constants
 *
 * Single source of truth for:
 *   - Compiler attribute macros (ATTR_*)
 *   - DFA magic number and version
 *   - State flags (DFA_STATE_*)
 *   - Rule types (DFA_RULE_*)
 *   - Rule encoding types (DFA_RULE_ENC_*)
 *   - Size limits (MAX_STATES, DFA_HASH_SIZE, MAX_SYMBOLS)
 *   - Overflow-safe arithmetic macros (CKD_*)
 *   - FNV hash constants
 *   - Build-time NFA constants
 */

#ifndef CDFA_DEFINES_H
#define CDFA_DEFINES_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

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
 * C11 Checked Arithmetic Macros
 *
 * These macros detect integer overflow in multiplication and addition.
 * Returns true if overflow would occur.
 *
 * Example: if (CKD_MUL(&result, a, b)) { handle overflow; }
 * ============================================================================ */

#if __STDC_VERSION__ >= 202311L
#include <stdckdint.h>
#endif

#ifndef CKD_MUL
#define CKD_MUL(result, a, b) __builtin_mul_overflow((a), (b), (result))
#endif
#ifndef CKD_ADD
#define CKD_ADD(result, a, b) __builtin_add_overflow((a), (b), (result))
#endif
#ifndef CKD_SUB
#define CKD_SUB(result, a, b) __builtin_sub_overflow((a), (b), (result))
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

/**
 * Maximum line length for text-based formats (pattern files, NFA/DFA text formats)
 */
#ifndef MAX_LINE_LENGTH
#define MAX_LINE_LENGTH 2048
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
#define DFA_VERSION 11

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

/* ============================================================================
 * FNV-1a Hash Constants
 * ============================================================================ */

#define FNV_OFFSET_BASIS 2166136261u
#define FNV_PRIME        16777619u

/**
 * CRC32-C (Castagnoli) polynomial for checksum
 */
#define CRC32C_POLY 0x82F63B78u

/**
 * Compute CRC32-C checksum over buffer
 */
static inline uint32_t crc32c(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (CRC32C_POLY & -(crc & 1u));
        }
    }
    return ~crc;
}

/* ============================================================================
 * NFA Build-Time Constants
 * ============================================================================ */

#define INITIAL_NFA_CAPACITY 64
#define NFA_GROWTH_FACTOR 2

#endif // CDFA_DEFINES_H
