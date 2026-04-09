#include "dfa_types.h"
#include "dfa_format.h"
#include "dfa_errors.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

/**
 * DFA Evaluator - adaptive-width reader
 * All reads via dfa_fmt_* with runtime encoding. No struct casts.
 */

#define MAX_TRACE    16384
#define MAX_CAP_STK  32

typedef struct { int id; size_t start; size_t end; } cap_t;

bool dfa_eval_with_limit(const void* data, size_t sz, const char* in, size_t len, dfa_result_t* res, int mc);

const char* dfa_category_string(dfa_command_category_t cat) {
    static const char* n[] = {"Unknown","Read-only (Safe)","Read-only (Caution)",
        "Modifying","Dangerous","Network","Admin","Build","Container"};
    int i = (int)cat;
    return (i >= 0 && i <= 8) ? n[i] : "Invalid";
}

static void add_cap(dfa_result_t* r, int id, size_t s, size_t e, int max_caps) {
    if (r->capture_count >= max_caps) return;
    dfa_capture_t* c = &r->captures[r->capture_count++];
    c->start = s; c->end = e; c->capture_id = id;
    snprintf(c->name, sizeof(c->name), "(unnamed)");
    c->active = false; c->completed = true;
}

static void proc_markers(const uint8_t* d, size_t sz, uint32_t moff, size_t pos,
    uint16_t wpid, uint8_t cmask, cap_t* stk, int* sd, dfa_result_t* r, int max_caps)
{
    if (!moff || moff >= sz) return;
    bool filt = (cmask && wpid != UINT16_MAX);
    size_t max_markers = (sz - moff) / 4;
    for (size_t i = 0; i < max_markers; i++) {
        size_t off = (size_t)moff + (size_t)i * 4;
        if (off + 4 > sz) break;
        uint32_t mk = dfa_r32(d, off);
        if (mk == MARKER_SENTINEL) break;
        uint16_t pid = MARKER_GET_PATTERN_ID(mk);
        uint16_t uid = MARKER_GET_UID(mk);
        uint8_t  typ = MARKER_GET_TYPE(mk);
        if (filt && pid != wpid) continue;
        if (typ == MARKER_TYPE_START) {
            if (*sd < MAX_CAP_STK) { stk[*sd].id=uid; stk[*sd].start=pos; stk[*sd].end=0; (*sd)++; }
        } else if (typ == MARKER_TYPE_END) {
            if (*sd > 0) {
                for (int j=*sd-1; j>=0; j--) {
                    if (stk[j].id==uid && !stk[j].end) { stk[j].end=pos; add_cap(r,uid,stk[j].start,pos,max_caps); break; }
                }
            }
        }
    }
}

bool dfa_eval(const void* data, size_t sz, const char* in, size_t len, dfa_result_t* res) {
    return dfa_eval_with_limit(data, sz, in, len, res, DFA_MAX_CAPTURES);
}

bool dfa_eval_with_limit(const void* vd, size_t sz, const char* in, size_t len, dfa_result_t* res, int mc) {
    if (mc <= 0) mc = DFA_MAX_CAPTURES;
    if (mc > DFA_MAX_CAPTURES) mc = DFA_MAX_CAPTURES;
    const uint8_t* d = (const uint8_t*)vd;
    if (sz < DFA_HEADER_FIXED) return false;

    memset(res, 0, sizeof(*res));
    res->category = DFA_CMD_UNKNOWN;

    if (dfa_fmt_magic(d) != DFA_MAGIC) return false;
    uint16_t ver = dfa_fmt_version(d);
    if (ver != DFA_VERSION) return false;

    int enc = dfa_fmt_encoding(d);
    int rs = DFA_RULE_SIZE(enc);
    uint8_t idl = dfa_fmt_id_len(d);
    size_t hs = DFA_HEADER_SIZE(enc, idl);

    if (sz < hs + 8) return false;  // need at least header + 2 checksums

    uint32_t stored_crc = dfa_fmt_checksum_crc32(d);
    uint32_t stored_fnv = dfa_fmt_checksum_fnv32(d);
    uint8_t hdr_copy[hs + 8];
    memcpy(hdr_copy, d, hs);
    memset(hdr_copy + hs, 0, 8);
    uint32_t computed_crc = crc32c(hdr_copy, hs);
    uint32_t computed_fnv = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < hs; i++) { computed_fnv ^= hdr_copy[i]; computed_fnv *= FNV_PRIME; }
    if (stored_crc != computed_crc || stored_fnv != computed_fnv) {
        ERROR("DFA checksum mismatch (corrupted header)");
        return false;
    }

    uint32_t init = dfa_fmt_initial_state(d);
    if ((size_t)init + DFA_STATE_SIZE_TC(enc, 0) > sz) return false;  // min state size

    /* Get EOS section pointer - validate section header and size are within bounds */
    uint32_t eos_off = dfa_fmt_eos_offset(d);
    const uint8_t* eos_section = NULL;
    if (eos_off > 0 && eos_off <= sz && (size_t)eos_off + DFA_EOS_HEADER_SIZE <= sz) {
        uint16_t target_count = dfa_fmt_eos_target_count(d + eos_off);
        uint16_t marker_count = dfa_fmt_eos_marker_count(d + eos_off);
        size_t eos_data_size = DFA_EOS_HEADER_SIZE +
            (size_t)target_count * DFA_EOS_TARGET_ENTRY_SIZE(enc) +
            (size_t)marker_count * DFA_EOS_MARKER_ENTRY_SIZE(enc);
        if ((size_t)eos_off + eos_data_size <= sz) {
            eos_section = d + eos_off;
        }
    }

    /* Get Pattern ID section pointer - validate section header and size are within bounds */
    uint32_t pid_off = dfa_fmt_pid_offset(d);
    const uint8_t* pid_section = NULL;
    if (pid_off > 0 && pid_off <= sz && (size_t)pid_off + DFA_PID_HEADER_SIZE <= sz) {
        uint16_t pid_count = dfa_fmt_pid_count(d + pid_off);
        size_t pid_data_size = DFA_PID_HEADER_SIZE + (size_t)pid_count * DFA_PID_ENTRY_SIZE(enc);
        if ((size_t)pid_off + pid_data_size <= sz) {
            pid_section = d + pid_off;
        }
    }

    /* Empty input: check initial state and EOS */
    if (!len) {
        uint16_t tc0 = dfa_fmt_st_tc(d, init, enc);
        uint16_t fl = dfa_fmt_st_flags_tc(d, init, enc, tc0);
        uint8_t cat = DFA_GET_CATEGORY_MASK(fl);
        /* Look up EOS target from EOS section */
        uint16_t init_state_idx = 0;  /* Initial state is state 0 */
        uint32_t eos = dfa_fmt_eos_lookup_target(eos_section, enc, init_state_idx);
        if (eos && (size_t)eos + DFA_STATE_SIZE_TC(enc, 0) <= sz) {
            uint16_t eosc = dfa_fmt_st_tc(d, eos, enc);
            if ((size_t)eos + DFA_STATE_SIZE_TC(enc, eosc) <= sz) {
                uint16_t eos_flags = dfa_fmt_st_flags_tc(d, eos, enc, eosc);
                cat |= DFA_GET_CATEGORY_MASK(eos_flags);
            }
        }
        if (cat) {
            res->matched = true; res->matched_length = 0; res->category_mask = cat;
            for (int i=0;i<8;i++) if (cat&(1<<i)) { res->category=(dfa_command_category_t)(i+1); break; }
        }
        return res->matched;
    }

    /* Walk states */
    uint32_t cur = init;
    uint32_t tr[MAX_TRACE]; int td = 0;
    if (td < MAX_TRACE) tr[td++] = cur; /* else: trace overflow - captures may be incomplete */
    size_t pos = 0;

    while (pos < len) {
        unsigned char c = (unsigned char)in[pos];
        
        /* First validate cur is within minimal bounds to read tc */
        if ((size_t)cur < hs || (size_t)cur + DFA_STATE_SIZE_TC(enc, 0) > sz) return false;
        
        /* Now read state data - tc must be readable since cur passed minimal bounds check */
        uint16_t tc = dfa_fmt_st_tc(d, cur, enc);
        uint32_t rl = dfa_fmt_st_rules(d, cur, enc);
        uint16_t flags = dfa_fmt_st_flags_tc(d, cur, enc, tc);
        
        /* Full bounds check with actual tc value */
        if ((size_t)cur + DFA_STATE_SIZE_TC(enc, tc) > sz) return false;
        
        int renc = DFA_GET_RULE_ENC(flags);
        uint32_t nxt = 0; bool found = false;

        if (renc == DFA_RULE_ENC_PACKED) {
            // Packed encoding: iterate variable-stride entries
            uint16_t n_ent = dfa_fmt_st_first_tc(d, cur, enc, tc);
            const uint8_t* entry = d + rl;
            int lit_size = DFA_PACK_LITERAL_SIZE(enc);
            int rng_size = DFA_PACK_RANGE_SIZE(enc);
            for (uint16_t i = 0; i < n_ent && !found; i++) {
                size_t entry_off = (size_t)(entry - d);
                if (entry_off >= sz) break;
                if (entry_off + 1 > sz) break;
                if (dfa_pack_is_literal(entry)) {
                    if (entry_off + lit_size > sz) break;
                    if (c == dfa_pack_lit_char(entry)) {
                        uint32_t tgt = dfa_pack_lit_target(entry, enc);
                        if (tgt >= sz) return false;
                        nxt = tgt; found = true;
                    }
                    entry += lit_size;
                } else {
                    if (entry_off + rng_size > sz) break;
                    uint8_t start = dfa_pack_range_start(entry);
                    uint8_t end = dfa_pack_range_end(entry);
                    if (c >= start && c <= end) {
                        uint32_t tgt = dfa_pack_range_target(entry, enc);
                        if (tgt >= sz) return false;
                        nxt = tgt; found = true;
                    }
                    entry += rng_size;
                }
            }
        } else if (renc == DFA_RULE_ENC_BITMASK) {
            // Bitmask rules: check each bitmask rule for character match
            int bms = DFA_RULE_BITMASK_SIZE(enc);
            for (uint16_t i = 0; i < tc; i++) {
                if (bms == 0) break;
                if (i > 0 && (size_t)i > SIZE_MAX / (size_t)bms) break;
                size_t ioff = (size_t)i * (size_t)bms;
                if (ioff > sz || rl > sz - ioff) break;
                size_t ro = rl + ioff;
                if (ro >= sz || ro + (size_t)bms > sz) break;
                uint8_t rt = dfa_fmt_rl_type(d, ro);
                if (rt != DFA_RULE_BITMASK && rt != DFA_RULE_NOT_BITMASK) break;
                // Check bitmask
                const uint8_t* mask = d + ro + DFA_BM_OFF_MASK;
                bool bit = (mask[c / 8] >> (c % 8)) & 1;
                bool m = (rt == DFA_RULE_BITMASK) ? bit : !bit;
                if (m) {
                    uint32_t tgt = dfa_row(d, ro + dfa_bm_off_target(enc), enc);
                    if (tgt >= sz) return false;
                    nxt = tgt; found = true; break;
                }
            }
        } else {
            // Normal fixed-stride rules
            for (uint16_t i = 0; i < tc; i++) {
                size_t ro = rl + (size_t)i * rs;
                if (rs == 0 || ro >= sz || ro + rs > sz) break;
                uint8_t rt = dfa_fmt_rl_type(d, ro);
                uint8_t r1 = dfa_fmt_rl_d1(d, ro);
                uint8_t r2 = dfa_fmt_rl_d2(d, ro);
                uint32_t tgt = dfa_fmt_rl_target(d, ro, enc);
                bool m = false;
                switch (rt) {
                    case DFA_RULE_LITERAL:       m=(c==r1); break;
                    case DFA_RULE_RANGE:         m=(c>=r1&&c<=r2); break;
                    case DFA_RULE_LITERAL_2:     m=(c==r1||c==r2); break;
                    case DFA_RULE_LITERAL_3:     { uint8_t r3=dfa_fmt_rl_d3(d,ro); m=(c==r1||c==r2||c==r3); break; }
                    case DFA_RULE_RANGE_LITERAL: { uint8_t r3=dfa_fmt_rl_d3(d,ro); m=((c>=r1&&c<=r2)||c==r3); break; }
                    case DFA_RULE_DEFAULT:       m=true; break;
                    case DFA_RULE_NOT_LITERAL:   m=(c!=r1); break;
                    case DFA_RULE_NOT_RANGE:     m=(c<r1||c>r2); break;
                }
                if (m) { if (tgt>=sz) return false; nxt=tgt; found=true; break; }
            }
        }
        if (!found) return false;
        pos++; cur = nxt; if (td < MAX_TRACE) tr[td++] = cur;
    }

    /* Determine category */
    uint16_t cur_tc = dfa_fmt_st_tc(d, cur, enc);
    uint16_t src_fl = dfa_fmt_st_flags_tc(d, cur, enc, cur_tc);
    uint8_t src_cat = DFA_GET_CATEGORY_MASK(src_fl);
    /* Look up pattern_id from Pattern ID section */
    uint16_t wpid = dfa_fmt_pid_lookup(pid_section, enc, cur);

    /* Look up EOS target from EOS section */
    uint32_t eos = dfa_fmt_eos_lookup_target(eos_section, enc, cur);
    if (eos) {
        /* Validate eos before accessing */
        if ((size_t)eos + DFA_STATE_SIZE_TC(enc, 0) <= sz) {
            uint16_t eosc = dfa_fmt_st_tc(d, eos, enc);
            if ((size_t)eos + DFA_STATE_SIZE_TC(enc, eosc) <= sz) {
                cur = eos; cur_tc = eosc;
                if (td < MAX_TRACE) tr[td++] = cur;
                /* Look up pattern_id for new state */
                wpid = dfa_fmt_pid_lookup(pid_section, enc, cur);
            }
        }
    }

    uint8_t cat = src_cat ? src_cat : DFA_GET_CATEGORY_MASK(dfa_fmt_st_flags_tc(d, cur, enc, cur_tc));
    if (cat || (wpid && wpid != UINT16_MAX)) {
        res->matched = true; res->matched_length = pos; res->category_mask = cat;
        res->final_state = cur;
        for (int i=0;i<8;i++) if (cat&(1<<i)) { res->category=(dfa_command_category_t)(i+1); break; }

        /* Captures */
        if (wpid && wpid != UINT16_MAX) {
            cap_t stk[MAX_CAP_STK]; int sd = 0;
            uint32_t meta = dfa_fmt_meta_offset(d);
            int lit_size = DFA_PACK_LITERAL_SIZE(enc);
            int rng_size = DFA_PACK_RANGE_SIZE(enc);
            for (int t = 1; t < td && (size_t)t <= pos; t++) {
                uint32_t fo = tr[t-1], to = tr[t];
                uint16_t ftc = dfa_fmt_st_tc(d, fo, enc);
                uint32_t frl = dfa_fmt_st_rules(d, fo, enc);
                uint16_t fflags = dfa_fmt_st_flags_tc(d, fo, enc, ftc);
                int frenc = DFA_GET_RULE_ENC(fflags);

                if (frenc == DFA_RULE_ENC_PACKED) {
                    // Packed encoding: iterate variable-stride entries
                    uint16_t n_ent = dfa_fmt_st_first_tc(d, fo, enc, ftc);
                    const uint8_t* entry = d + frl;
                    for (uint16_t i = 0; i < n_ent; i++) {
                        size_t entry_off = (size_t)(entry - d);
                        if (entry_off >= sz) break;
                        if (entry_off + 1 > sz) break;
                        bool matched = false;
                        if (dfa_pack_is_literal(entry)) {
                            if (entry_off + lit_size > sz) break;
                            if (dfa_pack_lit_target(entry, enc) == to) matched = true;
                            entry += lit_size;
                        } else {
                            if (entry_off + rng_size > sz) break;
                            if (dfa_pack_range_target(entry, enc) == to) matched = true;
                            entry += rng_size;
                        }
                        if (matched) {
                            size_t marker_off = (size_t)frl + dfa_rl_off_markers(enc);
                            if (marker_off + 4 <= sz) {
                                uint32_t mk = dfa_r32(d, marker_off);
                                if (mk && meta && mk+4 <= sz)
                                    proc_markers(d, sz, mk, t-1, wpid, cat, stk, &sd, res, mc);
                            }
                            break;
                        }
                    }
                } else {
                    // Normal encoding: iterate fixed-stride rules
                    for (uint16_t i = 0; i < ftc; i++) {
                        size_t ro = frl + (size_t)i * rs;
                        if (dfa_fmt_rl_target(d, ro, enc) == to) {
                            uint32_t mk = dfa_fmt_rl_markers(d, ro, enc);
                            if (mk && meta && mk+4 <= sz)
                                proc_markers(d, sz, mk, t-1, wpid, cat, stk, &sd, res, mc);
                            break;
                        }
                    }
                }
            }
            /* Look up EOS marker from EOS section */
            uint32_t em = dfa_fmt_eos_lookup_marker(eos_section, enc, cur);
            if (em && meta && em+4 <= sz)
                proc_markers(d, sz, em, pos, wpid, cat, stk, &sd, res, mc);
        }
    }
    return res->matched;
}

/* Capture access */
int dfa_result_get_capture(const dfa_result_t* r, int i, const char** s, size_t* l) {
    if (i<0||i>=r->capture_count) return -1;
    if (s) { *s=NULL; }
    if (l) { *l=r->captures[i].end-r->captures[i].start; }
    return r->captures[i].capture_id;
}
const char* dfa_result_get_capture_name(const dfa_result_t* r, int i) {
    return (i>=0&&i<r->capture_count) ? r->captures[i].name : NULL;
}
int dfa_result_get_capture_count(const dfa_result_t* r) { return r->capture_count; }
bool dfa_result_get_capture_by_index(const dfa_result_t* r, int i, size_t* s, size_t* l) {
    if (i<0||i>=r->capture_count) return false;
    if (s) { *s=r->captures[i].start; }
    if (l) { *l=r->captures[i].end-r->captures[i].start; }
    return true;
}
bool dfa_result_get_capture_string(const dfa_result_t* r, int i,
    ATTR_UNUSED const void* dd, ATTR_UNUSED size_t ds, const char* in, const char** s, size_t* l, const char** nm)
{
    if (i<0||i>=r->capture_count) return false;
    const dfa_capture_t* c = &r->captures[i];
    if (s) { *s=in+c->start; }
    if (l) { *l=c->end-c->start; }
    if (nm) *nm=c->name;
    return true;
}

/* Identifier validation */
bool dfa_eval_validate_id(const void* vd, size_t sz, const char* eid) {
    const uint8_t* d = (const uint8_t*)vd;
    if (sz < DFA_HEADER_FIXED) return false;
    if (dfa_fmt_magic(d) != DFA_MAGIC) return false;
    int enc = dfa_fmt_encoding(d);
    uint8_t il = dfa_fmt_id_len(d);
    if ((size_t)DFA_HEADER_SIZE(enc, il) > sz) return false;
    if ((size_t)DFA_HEADER_SIZE(enc, il) + il > sz) return false;
    size_t el = strlen(eid);
    if (il != el) return false;
    return !memcmp(dfa_fmt_identifier(d), eid, el);
}
