/**
 * dfa_format.h - DFA Binary Format Definition (v10, separate PID section)
 *
 * SINGLE SOURCE OF TRUTH for the DFA binary format.
 * Writer (nfa2dfa.c) and reader (dfa_eval.c, dfa_loader.c) both use these.
 * Never hardcode offsets elsewhere.
 *
 * V9: separate EOS section - reduces state header size by 6 bytes
 * V10: separate Pattern ID section - reduces state header by 1 byte
 */

#ifndef DFA_FORMAT_H
#define DFA_FORMAT_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "cdfa_defines.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Encoding byte layout (offset 8 in header)
 *
 * Bits 1:0 - offset width code:  0=2B, 1=3B, 2=4B
 * Bits 3:2 - count width code:   0=1B, 1=2B
 * Bits 5:4 - pid width code:     0=1B, 1=2B
 * ============================================================================ */

#define DFA_ENC_OFF_W(enc)       ((enc) & 0x03)
#define DFA_ENC_CNT_W(enc)       (((enc) >> 2) & 0x03)
#define DFA_ENC_PID_W(enc)       (((enc) >> 4) & 0x03)

#define DFA_W2  0
#define DFA_W3  1
#define DFA_W4  2

/* ============================================================================
 * Width code to byte count (MUST come before macros/functions that use them)
 * ============================================================================ */

static inline int dfa_owb(int enc) {
    int c = DFA_ENC_OFF_W(enc);
    return (c == 0) ? 2 : (c == 1) ? 3 : 4;
}
static inline int dfa_cwb(int enc) {
    return (DFA_ENC_CNT_W(enc) == 0) ? 1 : 2;
}
static inline int dfa_pwb(int enc) {
    return (DFA_ENC_PID_W(enc) == 0) ? 1 : 2;
}

/* Best width code for a max value */
static inline int dfa_best_ow(uint32_t max_val) {
    if (max_val < 0x10000)   return DFA_W2;
    if (max_val < 0x1000000) return DFA_W3;
    return DFA_W4;
}
static inline int dfa_best_cw(uint32_t max_val) {
    return (max_val < 0x100) ? 0 : 1;
}
static inline int dfa_best_pw(uint32_t max_val) {
    return (max_val < 0x100) ? 0 : 1;
}
static inline uint8_t dfa_make_enc(int ow, int cw, int pw) {
    return (uint8_t)((ow & 3) | ((cw & 3) << 2) | ((pw & 3) << 4));
}

/* ============================================================================
 * Header layout (v10)
 *
 *  0: magic          (4B)
 *  4: version        (2B)
 *  6: state_count    (2B)
 *  8: encoding       (1B)
 *  9: id_len         (1B)
 * 10: initial_state  (OW bytes)
 * 10+OW: meta_offset (OW bytes)
 * 10+2*OW: eos_offset (OW bytes) - V9: offset to EOS section
 * 10+3*OW: pid_offset (OW bytes) - V10: offset to Pattern ID section
 * 10+4*OW: identifier (id_len bytes)
 * ============================================================================ */

#define DFA_OFF_MAGIC          0
#define DFA_OFF_VERSION        4
#define DFA_OFF_STATE_COUNT    6
#define DFA_OFF_ENCODING       8
#define DFA_OFF_ID_LEN         9
#define DFA_OFF_INIT_STATE    10
#define DFA_HEADER_FIXED      10

#define DFA_HEADER_SIZE(enc, id_len) \
    (DFA_HEADER_FIXED + 4 * dfa_owb(enc) + (id_len))

/* ============================================================================
 * Constants
 * ============================================================================ */

#define DFA_MAGIC          0xDFA1DFA1
#define DFA_VERSION        10

#define DFA_RULE_LITERAL       0
#define DFA_RULE_RANGE         1
#define DFA_RULE_LITERAL_2     2
#define DFA_RULE_LITERAL_3     3
#define DFA_RULE_RANGE_LITERAL 4
#define DFA_RULE_DEFAULT       5
#define DFA_RULE_NOT_LITERAL   6
#define DFA_RULE_NOT_RANGE     7
#define DFA_RULE_BITMASK       8   /* match bytes in mask → target */
#define DFA_RULE_NOT_BITMASK   9   /* match bytes NOT in mask → target */
#define DFA_RULE_CHAIN         10  /* match chain of bytes → target */

/* Bitmask rule size: type(1) + mask(32) + target(OW) + markers(4) */
#define DFA_RULE_BITMASK_SIZE(enc) (1 + 32 + dfa_owb(enc) + 4)

/* Bitmask rule field offsets */
#define DFA_BM_OFF_MASK     1      /* 32 bytes */
#define DFA_BM_OFF_TARGET  33      /* OW bytes */

/* ============================================================================
 * Chain encoding (DFA_RULE_ENC_CHAIN = 3)
 *
 * Encodes multi-character literal sequences as single transitions.
 * Useful when a state has multiple outgoing literal paths that form
 * fixed strings (e.g., "log" vs "status").
 *
 * State header: same as normal, but tc = number of chains, first = n_chains
 * Rules area:
 *   [chain_0][chain_1]...[chain_{n-1}][default_target: OW]
 *
 * Each chain entry:
 *   [chain_len: 2][bytes: chain_len][target: OW][markers: 4]
 *
 * Default target (after all chains, OW bytes):
 *   Where to go if no chain matches (0 = no match, fail)
 *
 * Chain evaluation: for each chain, check if input[pos..pos+chain_len-1]
 * matches chain_bytes. If match, advance pos by chain_len and go to target.
 * If no chain matches, go to default_target.
 * ============================================================================ */

/* Chain entry size (excluding the variable-length bytes) */
#define DFA_CHAIN_HEADER_SIZE    (2)  /* chain_len field */
#define DFA_CHAIN_TRAILER_SIZE(enc) (dfa_owb(enc) + 4)  /* target + markers */
#define DFA_CHAIN_DEFAULT_SIZE(enc) (dfa_owb(enc))  /* default target */

/* Compute chain entry size given chain_len */
#define DFA_CHAIN_ENTRY_SIZE(enc, chain_len) \
    (DFA_CHAIN_HEADER_SIZE + (chain_len) + DFA_CHAIN_TRAILER_SIZE(enc))

/* Chain field offsets within a chain entry */
#define DFA_CHAIN_OFF_LEN      0   /* 2 bytes: length of byte sequence */
/* bytes at offset 2 */
/* target at offset 2 + chain_len */
/* markers at offset 2 + chain_len + OW */

/* ============================================================================
 * EOS Section Format (V9)
 *
 * EOS (end-of-string) data is stored in a separate section to reduce
 * state header size. Since EOS is checked only once per evaluation,
 * separating it reduces memory bandwidth during DFA traversal.
 *
 * Layout (sorted by state_offset for binary search):
 *   [eos_target_count: 2 bytes]
 *   [eos_target_entries: count × (state_offset: OW + target: OW)]
 *   [eos_marker_count: 2 bytes]  
 *   [eos_marker_entries: count × (state_offset: OW + marker: 4)]
 *
 * Uses byte offsets (not state indices) for direct lookup during evaluation.
 * ============================================================================ */

#define DFA_EOS_OFF_TARGET_COUNT   0   /* 2 bytes: number of target entries */
#define DFA_EOS_OFF_MARKER_COUNT   2   /* 2 bytes: number of marker entries */
#define DFA_EOS_HEADER_SIZE        4   /* Total header size */

/* Entry sizes - use byte offsets for direct lookup */
#define DFA_EOS_TARGET_ENTRY_SIZE(enc) (dfa_owb(enc) + dfa_owb(enc))  /* state_offset + target */
#define DFA_EOS_MARKER_ENTRY_SIZE(enc) (dfa_owb(enc) + 4)             /* state_offset + marker */

/* Compute EOS section size */
#define DFA_EOS_SECTION_SIZE(n_targets, n_markers, enc) \
    (DFA_EOS_HEADER_SIZE + \
     (n_targets) * DFA_EOS_TARGET_ENTRY_SIZE(enc) + \
     (n_markers) * DFA_EOS_MARKER_ENTRY_SIZE(enc))

/* ============================================================================
 * Pattern ID Section Format (V10)
 *
 * Pattern IDs are stored in a separate section to reduce state header size.
 * Pattern IDs are only needed when a match is found, not during traversal.
 *
 * Layout (sorted by state_offset for binary search):
 *   [pid_count: 2 bytes]
 *   [pid_entries: count × (state_offset: OW + pattern_id: PW)]
 * ============================================================================ */

#define DFA_PID_OFF_COUNT          0   /* 2 bytes: number of entries */
#define DFA_PID_HEADER_SIZE        2   /* Total header size */

/* Entry size: state_offset + pattern_id */
#define DFA_PID_ENTRY_SIZE(enc)    (dfa_owb(enc) + dfa_pwb(enc))

/* Compute Pattern ID section size */
#define DFA_PID_SECTION_SIZE(n_entries, enc) \
    (DFA_PID_HEADER_SIZE + (n_entries) * DFA_PID_ENTRY_SIZE(enc))

/* ============================================================================
 * Packed encoding (DFA_RULE_ENC_PACKED = 2)
 *
 * Variable-stride entries WITHOUT marker slots.
 *
 * Literal: [0b0LLLLLLL][target(OW)]  = 1+OW bytes
 * Range:   [0b1SSSSSSS][end(1)][target(OW)] = 2+OW bytes
 *
 * Savings vs normal (10 bytes/rule): 3 bytes per literal, N*10-8 per range
 * ============================================================================ */

#define DFA_PACK_LITERAL       0x00  /* high bit clear = literal */
#define DFA_PACK_RANGE         0x80  /* high bit set = range */
#define DFA_PACK_TYPE_MASK     0x80
#define DFA_PACK_CHAR_MASK     0x7F

/* Packed entry sizes (no markers) */
#define DFA_PACK_LITERAL_SIZE(enc) (1 + dfa_owb(enc))
#define DFA_PACK_RANGE_SIZE(enc)   (2 + dfa_owb(enc))

/* Bitmask rule field accessors */
static inline int dfa_bm_off_target(ATTR_UNUSED int enc)  { return 33; }
static inline int dfa_bm_off_markers(int enc) { return 33 + dfa_owb(enc); }

#define DFA_STATE_ACCEPTING      0x0001
#define DFA_STATE_CATEGORY_MASK  0xFF00  /* bits 8-15: 8-bit category mask */
#define DFA_STATE_RULE_ENC_MASK  0x00C0  /* bits 6-7: rule encoding selector */
#define DFA_STATE_RULE_ENC_SHIFT 6

/* Rule encoding values (in bits 6-7 of state flags)
 *
 * NORMAL:  fixed-stride rules [type(1) d1(1) d2(1) d3(1) target(OW) markers(4)]
 * BITMASK: 32-byte bitmask per target [type(1) mask(32) target(OW) markers(4)]
 * PACKED:  variable-stride entries [literal: 0b0LLLLLLL target(OW)]
 *                                    [range:   0b1SSSSSSS end(1) target(OW)]
 * CHAIN:   multi-character literal chains [len(2) bytes... target(OW) markers(4)]
 *          followed by [default_target(OW)]
 */
#define DFA_RULE_ENC_NORMAL    0  /* Fixed-stride rules */
#define DFA_RULE_ENC_BITMASK   1  /* Bitmask rules (one per target) */
#define DFA_RULE_ENC_PACKED    2  /* Variable-stride packed entries (no markers) */
#define DFA_RULE_ENC_CHAIN     3  /* Multi-character literal chains */

#define DFA_GET_CATEGORY_MASK(flags) ((uint8_t)(((flags) >> 8) & 0xFF))
#define DFA_SET_CATEGORY_MASK(flags, mask) \
    ((flags) = ((flags) & ~DFA_STATE_CATEGORY_MASK) | ((uint16_t)(mask) << 8))

#define DFA_GET_RULE_ENC(flags) (((flags) & DFA_STATE_RULE_ENC_MASK) >> DFA_STATE_RULE_ENC_SHIFT)
#define DFA_SET_RULE_ENC(flags, enc) \
    ((flags) = ((flags) & ~DFA_STATE_RULE_ENC_MASK) | ((uint16_t)((enc) & 3) << DFA_STATE_RULE_ENC_SHIFT))

#define MARKER_SENTINEL    0xFFFFFFFF

/* ============================================================================
 * State layout size and field offsets
 *
 * Full (tc>0):
 * State layout (V9 - EOS data moved to separate section):
 *
 * Full (tc > 0, has rules):
 *   [tc: CW] [rules: OW] [flags: 2] [first: PW]
 *
 * Compact (tc=0, no rules):
 *   [tc: CW] [flags: 2] [first: PW]
 *
 * Pattern ID and EOS data are stored in separate sections.
 * ============================================================================ */

#define DFA_STATE_SIZE(enc) \
    (dfa_cwb(enc) + dfa_owb(enc) + 2 + dfa_pwb(enc))

/* Compact state: skip rules_offset (saves OW bytes per empty state) */
#define DFA_STATE_SIZE_COMPACT(enc) \
    (dfa_cwb(enc) + 2 + dfa_pwb(enc))

/* State size based on whether it has rules */
#define DFA_STATE_SIZE_TC(enc, tc) \
    ((tc) == 0 ? DFA_STATE_SIZE_COMPACT(enc) : DFA_STATE_SIZE(enc))

/* Full state field offsets (tc > 0) */
static inline int dfa_st_off_rules(int enc) { return dfa_cwb(enc); }
static inline int dfa_st_off_flags(int enc) { return dfa_cwb(enc) + dfa_owb(enc); }

/* Compact state field offsets (tc == 0, no rules_offset) */
static inline int dfa_st_off_flags_c(int enc) { return dfa_cwb(enc); }
/* pattern_id removed from state header in V10 - now in Pattern ID section */
/* eos_target and eos_marker removed from state header in V9 - now in EOS section */
static inline int dfa_st_off_first(int enc) { return dfa_cwb(enc) + dfa_owb(enc) + 2; }

/* ============================================================================
 * Rule layout size and field offsets
 *
 *  [type:1] [d1:1] [d2:1] [d3:1] [target: OW] [markers: 4]
 * ============================================================================ */

#define DFA_RULE_SIZE(enc)  (8 + dfa_owb(enc))

#define DFA_RL_OFF_TYPE    0
#define DFA_RL_OFF_DATA1   1
#define DFA_RL_OFF_DATA2   2
#define DFA_RL_OFF_DATA3   3

static inline int dfa_rl_off_target(ATTR_UNUSED int enc)  { return 4; }
static inline int dfa_rl_off_markers(int enc) { return 4 + dfa_owb(enc); }

/* ============================================================================
 * Fixed-width read helpers (little-endian)
 * ============================================================================ */

static inline uint32_t dfa_r32(const uint8_t* d, size_t o) {
    return (uint32_t)d[o] | ((uint32_t)d[o+1]<<8) | ((uint32_t)d[o+2]<<16) | ((uint32_t)d[o+3]<<24);
}
static inline uint16_t dfa_r16(const uint8_t* d, size_t o) {
    return (uint16_t)d[o] | ((uint16_t)d[o+1]<<8);
}
static inline uint8_t dfa_r8(const uint8_t* d, size_t o) {
    return d[o];
}
static inline uint32_t dfa_r24(const uint8_t* d, size_t o) {
    return (uint32_t)d[o] | ((uint32_t)d[o+1]<<8) | ((uint32_t)d[o+2]<<16);
}

/* ============================================================================
 * Fixed-width write helpers (little-endian)
 * ============================================================================ */

static inline void dfa_w32(uint8_t* d, size_t o, uint32_t v) {
    d[o]=(uint8_t)v; d[o+1]=(uint8_t)(v>>8); d[o+2]=(uint8_t)(v>>16); d[o+3]=(uint8_t)(v>>24);
}
static inline void dfa_w16(uint8_t* d, size_t o, uint16_t v) {
    d[o]=(uint8_t)v; d[o+1]=(uint8_t)(v>>8);
}
static inline void dfa_w8(uint8_t* d, size_t o, uint8_t v) {
    d[o]=v;
}
static inline void dfa_w24(uint8_t* d, size_t o, uint32_t v) {
    d[o]=(uint8_t)v; d[o+1]=(uint8_t)(v>>8); d[o+2]=(uint8_t)(v>>16);
}

/* ============================================================================
 * Variable-width read helpers
 * ============================================================================ */

static inline uint32_t dfa_row(const uint8_t* d, size_t o, int enc) {
    int w = DFA_ENC_OFF_W(enc);
    return (w==0) ? dfa_r16(d,o) : (w==1) ? dfa_r24(d,o) : dfa_r32(d,o);
}
static inline uint16_t dfa_rcw(const uint8_t* d, size_t o, int enc) {
    return (DFA_ENC_CNT_W(enc)==0) ? dfa_r8(d,o) : dfa_r16(d,o);
}
static inline uint16_t dfa_rpw(const uint8_t* d, size_t o, int enc) {
    return (DFA_ENC_PID_W(enc)==0) ? dfa_r8(d,o) : dfa_r16(d,o);
}

/* ============================================================================
 * Variable-width write helpers
 * ============================================================================ */

static inline void dfa_wow(uint8_t* d, size_t o, int enc, uint32_t v) {
    int w = DFA_ENC_OFF_W(enc);
    if (w==0) dfa_w16(d,o,(uint16_t)v);
    else if (w==1) dfa_w24(d,o,v);
    else dfa_w32(d,o,v);
}
static inline void dfa_wwc(uint8_t* d, size_t o, int enc, uint16_t v) {
    if (DFA_ENC_CNT_W(enc)==0) dfa_w8(d,o,(uint8_t)v);
    else dfa_w16(d,o,v);
}
static inline void dfa_wwp(uint8_t* d, size_t o, int enc, uint16_t v) {
    if (DFA_ENC_PID_W(enc)==0) dfa_w8(d,o,(uint8_t)v);
    else dfa_w16(d,o,v);
}

/* ============================================================================
 * Header accessors (read)
 * ============================================================================ */

static inline uint32_t dfa_fmt_magic(const uint8_t* d)         { return dfa_r32(d, DFA_OFF_MAGIC); }
static inline uint16_t dfa_fmt_version(const uint8_t* d)       { return dfa_r16(d, DFA_OFF_VERSION); }
static inline uint16_t dfa_fmt_state_count(const uint8_t* d)   { return dfa_r16(d, DFA_OFF_STATE_COUNT); }
static inline uint8_t  dfa_fmt_encoding(const uint8_t* d)      { return dfa_r8(d, DFA_OFF_ENCODING); }
static inline uint8_t  dfa_fmt_id_len(const uint8_t* d)        { return dfa_r8(d, DFA_OFF_ID_LEN); }

static inline uint32_t dfa_fmt_initial_state(const uint8_t* d) {
    return dfa_row(d, DFA_OFF_INIT_STATE, dfa_fmt_encoding(d));
}
static inline uint32_t dfa_fmt_meta_offset(const uint8_t* d) {
    int e = dfa_fmt_encoding(d);
    return dfa_row(d, DFA_OFF_INIT_STATE + dfa_owb(e), e);
}
static inline uint32_t dfa_fmt_eos_offset(const uint8_t* d) {
    int e = dfa_fmt_encoding(d);
    return dfa_row(d, DFA_OFF_INIT_STATE + 2 * dfa_owb(e), e);
}
static inline uint32_t dfa_fmt_pid_offset(const uint8_t* d) {
    int e = dfa_fmt_encoding(d);
    return dfa_row(d, DFA_OFF_INIT_STATE + 3 * dfa_owb(e), e);
}
static inline const uint8_t* dfa_fmt_identifier(const uint8_t* d) {
    return d + DFA_OFF_INIT_STATE + 4 * dfa_owb(dfa_fmt_encoding(d));
}

/* ============================================================================
 * Header accessors (write)
 * ============================================================================ */

static inline void dfa_fmt_set_magic(uint8_t* d, uint32_t v)       { dfa_w32(d, DFA_OFF_MAGIC, v); }
static inline void dfa_fmt_set_version(uint8_t* d, uint16_t v)     { dfa_w16(d, DFA_OFF_VERSION, v); }
static inline void dfa_fmt_set_state_count(uint8_t* d, uint16_t v) { dfa_w16(d, DFA_OFF_STATE_COUNT, v); }
static inline void dfa_fmt_set_encoding(uint8_t* d, uint8_t v)     { dfa_w8(d, DFA_OFF_ENCODING, v); }
static inline void dfa_fmt_set_id_len(uint8_t* d, uint8_t v)       { dfa_w8(d, DFA_OFF_ID_LEN, v); }
static inline void dfa_fmt_set_initial_state(uint8_t* d, int enc, uint32_t v) {
    dfa_wow(d, DFA_OFF_INIT_STATE, enc, v);
}
static inline void dfa_fmt_set_meta_offset(uint8_t* d, int enc, uint32_t v) {
    dfa_wow(d, DFA_OFF_INIT_STATE + dfa_owb(enc), enc, v);
}
static inline void dfa_fmt_set_eos_offset(uint8_t* d, int enc, uint32_t v) {
    dfa_wow(d, DFA_OFF_INIT_STATE + 2 * dfa_owb(enc), enc, v);
}
static inline void dfa_fmt_set_pid_offset(uint8_t* d, int enc, uint32_t v) {
    dfa_wow(d, DFA_OFF_INIT_STATE + 3 * dfa_owb(enc), enc, v);
}

/* ============================================================================
 * State accessors (read)
 * ============================================================================ */

static inline uint16_t dfa_fmt_st_tc(const uint8_t* d, size_t so, int enc)    { return dfa_rcw(d, so, enc); }
static inline uint32_t dfa_fmt_st_rules(const uint8_t* d, size_t so, int enc) { return dfa_row(d, so + dfa_st_off_rules(enc), enc); }
static inline uint16_t dfa_fmt_st_flags(const uint8_t* d, size_t so, int enc) { return dfa_r16(d, so + dfa_st_off_flags(enc)); }
/* pattern_id moved to separate Pattern ID section in V10 */
/* eos_target and eos_marker moved to separate EOS section in V9 */
static inline uint16_t dfa_fmt_st_first(const uint8_t* d, size_t so, int enc) { return dfa_rpw(d, so + dfa_st_off_first(enc), enc); }

/* TC-aware state field offsets: handle compact (tc=0) vs full (tc>0) */
static inline int dfa_st_foff_flags(int enc, uint16_t tc) {
    return dfa_cwb(enc) + (tc > 0 ? dfa_owb(enc) : 0);
}
/* pattern_id removed from state header in V10 - now in Pattern ID section */
/* eos_target and eos_marker removed from state header in V9 - now in EOS section */
static inline int dfa_st_foff_first(int enc, uint16_t tc) {
    return dfa_st_foff_flags(enc, tc) + 2;
}

/* TC-aware state readers: automatically use compact or full layout */
static inline uint16_t dfa_fmt_st_flags_tc(const uint8_t* d, size_t so, int enc, uint16_t tc) {
    return dfa_r16(d, so + dfa_st_foff_flags(enc, tc));
}
/* pattern_id moved to Pattern ID section in V10 */
/* eos_target and eos_marker moved to EOS section in V9 */
static inline uint16_t dfa_fmt_st_first_tc(const uint8_t* d, size_t so, int enc, uint16_t tc) {
    return dfa_rpw(d, so + dfa_st_foff_first(enc, tc), enc);
}

/* ============================================================================
 * Pattern ID Section accessors (V10)
 * ============================================================================ */

/* Read Pattern ID section header */
static inline uint16_t dfa_fmt_pid_count(const uint8_t* pid) { return dfa_r16(pid, DFA_PID_OFF_COUNT); }

/* Get pointer to Pattern ID entries */
static inline const uint8_t* dfa_fmt_pid_entries(const uint8_t* pid) { return pid + DFA_PID_HEADER_SIZE; }

/* Read Pattern ID entry - uses byte offsets */
static inline uint32_t dfa_fmt_pid_entry_state_off(const uint8_t* entry, int enc) { return dfa_row(entry, 0, enc); }
static inline uint16_t dfa_fmt_pid_entry_pid(const uint8_t* entry, int enc) { return dfa_rpw(entry, dfa_owb(enc), enc); }

/* Write Pattern ID section header */
static inline void dfa_fmt_set_pid_count(uint8_t* pid, uint16_t v) { dfa_w16(pid, DFA_PID_OFF_COUNT, v); }

/* Write Pattern ID entry */
static inline void dfa_fmt_set_pid_entry(uint8_t* entry, uint32_t state_off, uint16_t pid, int enc) {
    dfa_wow(entry, 0, enc, state_off);
    dfa_wwp(entry, dfa_owb(enc), enc, pid);
}

/* Pattern ID lookup - binary search for state byte offset */
static inline uint16_t dfa_fmt_pid_lookup(const uint8_t* pid, int enc, uint32_t state_off) {
    if (!pid) return 0;
    uint16_t count = dfa_fmt_pid_count(pid);
    if (count == 0) return 0;
    
    const uint8_t* entries = dfa_fmt_pid_entries(pid);
    int entry_size = DFA_PID_ENTRY_SIZE(enc);
    
    /* Binary search */
    int lo = 0, hi = count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        const uint8_t* entry = entries + mid * entry_size;
        uint32_t off = dfa_fmt_pid_entry_state_off(entry, enc);
        if (off == state_off) return dfa_fmt_pid_entry_pid(entry, enc);
        if (off < state_off) lo = mid + 1;
        else hi = mid - 1;
    }
    return 0;
}

/* ============================================================================
 * State accessors (write)
 * ============================================================================ */

static inline void dfa_fmt_set_st_tc(uint8_t* d, size_t so, int enc, uint16_t v)    { dfa_wwc(d, so, enc, v); }
static inline void dfa_fmt_set_st_rules(uint8_t* d, size_t so, int enc, uint32_t v) { dfa_wow(d, so + dfa_st_off_rules(enc), enc, v); }
static inline void dfa_fmt_set_st_flags(uint8_t* d, size_t so, int enc, uint16_t v) { dfa_w16(d, so + dfa_st_off_flags(enc), v); }
/* pattern_id moved to Pattern ID section in V10 */
/* eos_target and eos_marker moved to EOS section in V9 */
static inline void dfa_fmt_set_st_first(uint8_t* d, size_t so, int enc, uint16_t v) { dfa_wwp(d, so + dfa_st_off_first(enc), enc, v); }

/* ============================================================================
 * EOS Section accessors (V9)
 * ============================================================================ */

/* Read EOS section header */
static inline uint16_t dfa_fmt_eos_target_count(const uint8_t* eos) { return dfa_r16(eos, DFA_EOS_OFF_TARGET_COUNT); }
static inline uint16_t dfa_fmt_eos_marker_count(const uint8_t* eos) { return dfa_r16(eos, DFA_EOS_OFF_MARKER_COUNT); }

/* Get pointer to EOS target entries */
static inline const uint8_t* dfa_fmt_eos_targets(const uint8_t* eos) { return eos + DFA_EOS_HEADER_SIZE; }

/* Get pointer to EOS marker entries */
static inline const uint8_t* dfa_fmt_eos_markers(const uint8_t* eos, int enc) {
    return eos + DFA_EOS_HEADER_SIZE + 
           dfa_fmt_eos_target_count(eos) * DFA_EOS_TARGET_ENTRY_SIZE(enc);
}

/* Read EOS target entry - uses byte offsets */
static inline uint32_t dfa_fmt_eos_target_state_off(const uint8_t* entry, int enc) { return dfa_row(entry, 0, enc); }
static inline uint32_t dfa_fmt_eos_target_value(const uint8_t* entry, int enc) { return dfa_row(entry, dfa_owb(enc), enc); }

/* Read EOS marker entry - uses byte offsets */
static inline uint32_t dfa_fmt_eos_marker_state_off(const uint8_t* entry, int enc) { return dfa_row(entry, 0, enc); }
static inline uint32_t dfa_fmt_eos_marker_value(const uint8_t* entry, int enc) { return dfa_r32(entry, dfa_owb(enc)); }

/* Write EOS section header */
static inline void dfa_fmt_set_eos_target_count(uint8_t* eos, uint16_t v) { dfa_w16(eos, DFA_EOS_OFF_TARGET_COUNT, v); }
static inline void dfa_fmt_set_eos_marker_count(uint8_t* eos, uint16_t v) { dfa_w16(eos, DFA_EOS_OFF_MARKER_COUNT, v); }

/* Write EOS target entry - uses byte offsets */
static inline void dfa_fmt_set_eos_target_entry(uint8_t* entry, uint32_t state_off, uint32_t target, int enc) {
    dfa_wow(entry, 0, enc, state_off);
    dfa_wow(entry, dfa_owb(enc), enc, target);
}

/* Write EOS marker entry - uses byte offsets */
static inline void dfa_fmt_set_eos_marker_entry(uint8_t* entry, uint32_t state_off, uint32_t marker, int enc) {
    dfa_wow(entry, 0, enc, state_off);
    dfa_w32(entry, dfa_owb(enc), marker);
}

/* EOS lookup helpers - binary search for state byte offset */
static inline uint32_t dfa_fmt_eos_lookup_target(const uint8_t* eos, int enc, uint32_t state_off) {
    if (!eos) return 0;
    uint16_t count = dfa_fmt_eos_target_count(eos);
    if (count == 0) return 0;
    
    const uint8_t* entries = dfa_fmt_eos_targets(eos);
    int entry_size = DFA_EOS_TARGET_ENTRY_SIZE(enc);
    
    /* Binary search */
    int lo = 0, hi = count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        const uint8_t* entry = entries + mid * entry_size;
        uint32_t off = dfa_fmt_eos_target_state_off(entry, enc);
        if (off == state_off) return dfa_fmt_eos_target_value(entry, enc);
        if (off < state_off) lo = mid + 1;
        else hi = mid - 1;
    }
    return 0;
}

static inline uint32_t dfa_fmt_eos_lookup_marker(const uint8_t* eos, int enc, uint32_t state_off) {
    if (!eos) return 0;
    uint16_t count = dfa_fmt_eos_marker_count(eos);
    if (count == 0) return 0;
    
    const uint8_t* entries = dfa_fmt_eos_markers(eos, enc);
    int entry_size = DFA_EOS_MARKER_ENTRY_SIZE(enc);
    
    /* Binary search */
    int lo = 0, hi = count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        const uint8_t* entry = entries + mid * entry_size;
        uint32_t off = dfa_fmt_eos_marker_state_off(entry, enc);
        if (off == state_off) return dfa_fmt_eos_marker_value(entry, enc);
        if (off < state_off) lo = mid + 1;
        else hi = mid - 1;
    }
    return 0;
}

/* ============================================================================
 * Rule accessors (read)
 * ============================================================================ */

static inline uint8_t  dfa_fmt_rl_type(const uint8_t* d, size_t ro)             { return dfa_r8(d, ro + DFA_RL_OFF_TYPE); }
static inline uint8_t  dfa_fmt_rl_d1(const uint8_t* d, size_t ro)               { return dfa_r8(d, ro + DFA_RL_OFF_DATA1); }
static inline uint8_t  dfa_fmt_rl_d2(const uint8_t* d, size_t ro)               { return dfa_r8(d, ro + DFA_RL_OFF_DATA2); }
static inline uint8_t  dfa_fmt_rl_d3(const uint8_t* d, size_t ro)               { return dfa_r8(d, ro + DFA_RL_OFF_DATA3); }
static inline uint32_t dfa_fmt_rl_target(const uint8_t* d, size_t ro, int enc)  { return dfa_row(d, ro + dfa_rl_off_target(enc), enc); }
static inline uint32_t dfa_fmt_rl_markers(const uint8_t* d, size_t ro, int enc) { return dfa_r32(d, ro + dfa_rl_off_markers(enc)); }

/* ============================================================================
 * Rule accessors (write)
 * ============================================================================ */

static inline void dfa_fmt_set_rl_type(uint8_t* d, size_t ro, uint8_t v)               { dfa_w8(d, ro + DFA_RL_OFF_TYPE, v); }
static inline void dfa_fmt_set_rl_d1(uint8_t* d, size_t ro, uint8_t v)                 { dfa_w8(d, ro + DFA_RL_OFF_DATA1, v); }
static inline void dfa_fmt_set_rl_d2(uint8_t* d, size_t ro, uint8_t v)                 { dfa_w8(d, ro + DFA_RL_OFF_DATA2, v); }
static inline void dfa_fmt_set_rl_d3(uint8_t* d, size_t ro, uint8_t v)                 { dfa_w8(d, ro + DFA_RL_OFF_DATA3, v); }
static inline void dfa_fmt_set_rl_target(uint8_t* d, size_t ro, int enc, uint32_t v)   { dfa_wow(d, ro + dfa_rl_off_target(enc), enc, v); }
static inline void dfa_fmt_set_rl_markers(uint8_t* d, size_t ro, int enc, uint32_t v)  { dfa_w32(d, ro + dfa_rl_off_markers(enc), v); }

/* ============================================================================
 * Packed encoding read/write helpers (require dfa_row/dfa_wow from above)
 * ============================================================================ */

/* Encode */
static inline void dfa_pack_write_literal(uint8_t* dst, uint8_t ch, int enc, uint32_t target) {
    dst[0] = (uint8_t)(ch & DFA_PACK_CHAR_MASK);
    dfa_wow(dst, 1, enc, target);
}
static inline void dfa_pack_write_range(uint8_t* dst, uint8_t start, uint8_t end, int enc, uint32_t target) {
    dst[0] = (uint8_t)(DFA_PACK_RANGE | (start & DFA_PACK_CHAR_MASK));
    dst[1] = end & DFA_PACK_CHAR_MASK;
    dfa_wow(dst, 2, enc, target);
}

/* Decode */
static inline int dfa_pack_is_literal(const uint8_t* e) { return (e[0] & DFA_PACK_TYPE_MASK) == DFA_PACK_LITERAL; }
static inline int dfa_pack_is_range(const uint8_t* e)   { return (e[0] & DFA_PACK_TYPE_MASK) == DFA_PACK_RANGE; }
static inline uint8_t dfa_pack_lit_char(const uint8_t* e)     { return e[0] & DFA_PACK_CHAR_MASK; }
static inline uint32_t dfa_pack_lit_target(const uint8_t* e, int enc)  { return dfa_row(e, 1, enc); }
static inline uint8_t dfa_pack_range_start(const uint8_t* e)   { return e[0] & DFA_PACK_CHAR_MASK; }
static inline uint8_t dfa_pack_range_end(const uint8_t* e)     { return e[1]; }
static inline uint32_t dfa_pack_range_target(const uint8_t* e, int enc) { return dfa_row(e, 2, enc); }

/* Step to next entry */
static inline const uint8_t* dfa_pack_next(const uint8_t* e, int enc) {
    return e + (dfa_pack_is_literal(e) ? DFA_PACK_LITERAL_SIZE(enc) : DFA_PACK_RANGE_SIZE(enc));
}

/* ============================================================================
 * Chain encoding helpers (DFA_RULE_ENC_CHAIN = 3)
 * ============================================================================ */

/* Read chain length from chain entry */
static inline uint16_t dfa_chain_len(const uint8_t* e) {
    return dfa_r16(e, DFA_CHAIN_OFF_LEN);
}

/* Get pointer to chain bytes */
static inline const uint8_t* dfa_chain_bytes(const uint8_t* e) {
    return e + DFA_CHAIN_HEADER_SIZE;
}

/* Read target from chain entry (variable offset based on chain_len) */
static inline uint32_t dfa_chain_target(const uint8_t* e, int enc) {
    uint16_t clen = dfa_chain_len(e);
    return dfa_row(e, DFA_CHAIN_HEADER_SIZE + clen, enc);
}

/* Read markers from chain entry */
static inline uint32_t dfa_chain_markers(const uint8_t* e, int enc) {
    uint16_t clen = dfa_chain_len(e);
    return dfa_r32(e, DFA_CHAIN_HEADER_SIZE + clen + dfa_owb(enc));
}

/* Compute total size of a chain entry */
static inline size_t dfa_chain_entry_size(const uint8_t* e, int enc) {
    return DFA_CHAIN_HEADER_SIZE + dfa_chain_len(e) + DFA_CHAIN_TRAILER_SIZE(enc);
}

/* Step to next chain entry */
static inline const uint8_t* dfa_chain_next(const uint8_t* e, int enc) {
    return e + dfa_chain_entry_size(e, enc);
}

/* Read default target after all chains */
static inline uint32_t dfa_chain_default_target(const uint8_t* chains_end, int enc) {
    return dfa_row(chains_end, 0, enc);
}

/* Write a chain entry */
static inline void dfa_chain_write(uint8_t* dst, const uint8_t* bytes, uint16_t len,
                                    int enc, uint32_t target, uint32_t markers) {
    dfa_w16(dst, DFA_CHAIN_OFF_LEN, len);
    memcpy(dst + DFA_CHAIN_HEADER_SIZE, bytes, len);
    dfa_wow(dst, DFA_CHAIN_HEADER_SIZE + len, enc, target);
    dfa_w32(dst, DFA_CHAIN_HEADER_SIZE + len + dfa_owb(enc), markers);
}

/* Write default target after all chains */
static inline void dfa_chain_write_default(uint8_t* dst, int enc, uint32_t target) {
    dfa_wow(dst, 0, enc, target);
}

#ifdef __cplusplus
}
#endif

#endif /* DFA_FORMAT_H */
