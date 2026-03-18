/**
 * dfa_format.h - DFA Binary Format Definition
 *
 * This is the SINGLE SOURCE OF TRUTH for the DFA binary format.
 * Both the writer (nfa2dfa.c) and reader (dfa_eval.c, dfa_loader.c)
 * must use these definitions. Never hardcode offsets elsewhere.
 *
 * Format version 6 (with capture markers).
 */

#ifndef DFA_FORMAT_H
#define DFA_FORMAT_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Header offsets (fixed byte positions)
 * ============================================================================ */
#define DFA_HEADER_SIZE          23

#define DFA_OFF_MAGIC             0   /* uint32_t: 0xDFA1DFA1 */
#define DFA_OFF_VERSION           4   /* uint16_t: 5 or 6 */
#define DFA_OFF_STATE_COUNT       6   /* uint16_t */
#define DFA_OFF_INITIAL_STATE     8   /* uint32_t: byte offset to state 0 */
#define DFA_OFF_ACCEPT_MASK      12   /* uint32_t: bitmask of accepting states (0-31) */
#define DFA_OFF_FLAGS            16   /* uint16_t */
#define DFA_OFF_ID_LEN           18   /* uint8_t: length of identifier */
#define DFA_OFF_META             19   /* uint32_t: byte offset to metadata/name table */

/* Identifier starts right after header */
#define DFA_OFF_IDENTIFIER       DFA_HEADER_SIZE

/* ============================================================================
 * State header size (dfa_state_t in binary)
 * ============================================================================ */
#define DFA_STATE_SIZE           20

#define DFA_ST_OFF_TC             0   /* uint16_t: transition rule count */
#define DFA_ST_OFF_RULES          2   /* uint32_t: byte offset to rules */
#define DFA_ST_OFF_FLAGS          6   /* uint16_t */
#define DFA_ST_OFF_PATTERN_ID     8   /* uint16_t */
#define DFA_ST_OFF_EOS_TARGET    10   /* uint32_t: byte offset to EOS target state */
#define DFA_ST_OFF_EOS_MARKERS   14   /* uint32_t: byte offset to EOS marker list */
#define DFA_ST_OFF_FIRST_PAT     18   /* uint16_t */

/* ============================================================================
 * Rule size (dfa_rule_t in binary)
 * ============================================================================ */
#define DFA_RULE_SIZE            12

#define DFA_RL_OFF_TYPE           0   /* uint8_t */
#define DFA_RL_OFF_DATA1          1   /* uint8_t */
#define DFA_RL_OFF_DATA2          2   /* uint8_t */
#define DFA_RL_OFF_DATA3          3   /* uint8_t */
#define DFA_RL_OFF_TARGET         4   /* uint32_t: byte offset to target state */
#define DFA_RL_OFF_MARKERS        8   /* uint32_t: byte offset to marker list */

/* ============================================================================
 * Constants
 * ============================================================================ */
#define DFA_MAGIC          0xDFA1DFA1
#define DFA_MIN_VERSION    5
#define DFA_MAX_VERSION    6

/* Rule types */
#define DFA_RULE_LITERAL   0
#define DFA_RULE_RANGE     1
#define DFA_RULE_ANY       2

/* State flags */
#define DFA_STATE_ACCEPTING  0x0001
#define DFA_STATE_CATEGORY_MASK  0xFF00

/* Marker sentinel */
#define MARKER_SENTINEL    0xFFFFFFFF

/* ============================================================================
 * Little-endian read helpers
 * ============================================================================ */

static inline uint32_t dfa_fmt_read_u32(const uint8_t* data, size_t offset) {
    return (uint32_t)data[offset]
         | ((uint32_t)data[offset+1] << 8)
         | ((uint32_t)data[offset+2] << 16)
         | ((uint32_t)data[offset+3] << 24);
}

static inline uint16_t dfa_fmt_read_u16(const uint8_t* data, size_t offset) {
    return (uint16_t)data[offset]
         | ((uint16_t)data[offset+1] << 8);
}

static inline uint8_t dfa_fmt_read_u8(const uint8_t* data, size_t offset) {
    return data[offset];
}

/* ============================================================================
 * Little-endian write helpers
 * ============================================================================ */

static inline void dfa_fmt_write_u32(uint8_t* data, size_t offset, uint32_t val) {
    data[offset]   = (uint8_t)(val);
    data[offset+1] = (uint8_t)(val >> 8);
    data[offset+2] = (uint8_t)(val >> 16);
    data[offset+3] = (uint8_t)(val >> 24);
}

static inline void dfa_fmt_write_u16(uint8_t* data, size_t offset, uint16_t val) {
    data[offset]   = (uint8_t)(val);
    data[offset+1] = (uint8_t)(val >> 8);
}

static inline void dfa_fmt_write_u8(uint8_t* data, size_t offset, uint8_t val) {
    data[offset] = val;
}

/* ============================================================================
 * Header accessors - read fields from binary DFA data
 * ============================================================================ */

static inline uint32_t dfa_fmt_magic(const uint8_t* d)        { return dfa_fmt_read_u32(d, DFA_OFF_MAGIC); }
static inline uint16_t dfa_fmt_version(const uint8_t* d)      { return dfa_fmt_read_u16(d, DFA_OFF_VERSION); }
static inline uint16_t dfa_fmt_state_count(const uint8_t* d)  { return dfa_fmt_read_u16(d, DFA_OFF_STATE_COUNT); }
static inline uint32_t dfa_fmt_initial_state(const uint8_t* d){ return dfa_fmt_read_u32(d, DFA_OFF_INITIAL_STATE); }
static inline uint32_t dfa_fmt_accept_mask(const uint8_t* d)  { return dfa_fmt_read_u32(d, DFA_OFF_ACCEPT_MASK); }
static inline uint16_t dfa_fmt_flags(const uint8_t* d)        { return dfa_fmt_read_u16(d, DFA_OFF_FLAGS); }
static inline uint8_t  dfa_fmt_id_len(const uint8_t* d)       { return dfa_fmt_read_u8(d, DFA_OFF_ID_LEN); }
static inline uint32_t dfa_fmt_meta_offset(const uint8_t* d)  { return dfa_fmt_read_u32(d, DFA_OFF_META); }
static inline const uint8_t* dfa_fmt_identifier(const uint8_t* d) { return d + DFA_OFF_IDENTIFIER; }

/* ============================================================================
 * State accessors - read fields from a state at byte offset
 * ============================================================================ */

static inline uint16_t dfa_fmt_st_tc(const uint8_t* d, size_t off)         { return dfa_fmt_read_u16(d, off + DFA_ST_OFF_TC); }
static inline uint32_t dfa_fmt_st_rules(const uint8_t* d, size_t off)      { return dfa_fmt_read_u32(d, off + DFA_ST_OFF_RULES); }
static inline uint16_t dfa_fmt_st_flags(const uint8_t* d, size_t off)      { return dfa_fmt_read_u16(d, off + DFA_ST_OFF_FLAGS); }
static inline uint16_t dfa_fmt_st_pattern_id(const uint8_t* d, size_t off) { return dfa_fmt_read_u16(d, off + DFA_ST_OFF_PATTERN_ID); }
static inline uint32_t dfa_fmt_st_eos_target(const uint8_t* d, size_t off) { return dfa_fmt_read_u32(d, off + DFA_ST_OFF_EOS_TARGET); }
static inline uint32_t dfa_fmt_st_eos_markers(const uint8_t* d, size_t off){ return dfa_fmt_read_u32(d, off + DFA_ST_OFF_EOS_MARKERS); }

/* ============================================================================
 * Rule accessors - read fields from a rule at byte offset
 * ============================================================================ */

static inline uint8_t  dfa_fmt_rl_type(const uint8_t* d, size_t off)    { return dfa_fmt_read_u8(d, off + DFA_RL_OFF_TYPE); }
static inline uint8_t  dfa_fmt_rl_data1(const uint8_t* d, size_t off)   { return dfa_fmt_read_u8(d, off + DFA_RL_OFF_DATA1); }
static inline uint8_t  dfa_fmt_rl_data2(const uint8_t* d, size_t off)   { return dfa_fmt_read_u8(d, off + DFA_RL_OFF_DATA2); }
static inline uint32_t dfa_fmt_rl_target(const uint8_t* d, size_t off)  { return dfa_fmt_read_u32(d, off + DFA_RL_OFF_TARGET); }
static inline uint32_t dfa_fmt_rl_markers(const uint8_t* d, size_t off) { return dfa_fmt_read_u32(d, off + DFA_RL_OFF_MARKERS); }

#ifdef __cplusplus
}
#endif

#endif /* DFA_FORMAT_H */
