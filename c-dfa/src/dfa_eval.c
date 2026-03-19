#include "dfa_types.h"
#include "dfa_format.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

/**
 * DFA Evaluator - v7 adaptive-width reader
 * All reads via dfa_fmt_* with runtime encoding. No struct casts.
 */

#ifndef DFA_EVAL_DEBUG
#define DFA_EVAL_DEBUG 0
#endif

#if DFA_EVAL_DEBUG
#define DBG(fmt, ...) fprintf(stderr, "[EVAL] " fmt, ##__VA_ARGS__)
#else
#define DBG(...) ((void)0)
#endif

#define MAX_EVAL_LEN 16384
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

static void add_cap(dfa_result_t* r, int id, size_t s, size_t e) {
    if (r->capture_count >= DFA_MAX_CAPTURES) return;
    dfa_capture_t* c = &r->captures[r->capture_count++];
    c->start = s; c->end = e; c->capture_id = id;
    c->name[0] = '\0'; c->active = false; c->completed = true;
}

static void proc_markers(const uint8_t* d, size_t sz, uint32_t moff, size_t pos,
    uint16_t wpid, uint8_t cmask, cap_t* stk, int* sd, dfa_result_t* r)
{
    if (!moff || moff >= sz) return;
    bool filt = (cmask && wpid != UINT16_MAX);
    for (size_t i = 0; i < 1024; i++) {
        if (moff + i*4 + 4 > sz) break;
        uint32_t mk = dfa_r32(d, moff + i*4);
        if (mk == MARKER_SENTINEL) break;
        uint16_t pid = MARKER_GET_PATTERN_ID(mk);
        uint16_t uid = MARKER_GET_UID(mk);
        uint8_t  typ = MARKER_GET_TYPE(mk);
        if (filt && pid != wpid) continue;
        if (typ == MARKER_TYPE_START) {
            if (*sd < MAX_CAP_STK) { stk[*sd].id=uid; stk[*sd].start=pos; stk[*sd].end=0; (*sd)++; }
        } else if (typ == MARKER_TYPE_END) {
            for (int j=*sd-1; j>=0; j--) {
                if (stk[j].id==uid && !stk[j].end) { stk[j].end=pos; add_cap(r,uid,stk[j].start,pos); break; }
            }
        }
    }
}

bool dfa_eval(const void* data, size_t sz, const char* in, size_t len, dfa_result_t* res) {
    return dfa_eval_with_limit(data, sz, in, len, res, DFA_MAX_CAPTURES);
}

bool dfa_eval_with_limit(const void* vd, size_t sz, const char* in, size_t len, dfa_result_t* res, int mc) {
    (void)mc;
    const uint8_t* d = (const uint8_t*)vd;
    if (!d || !in || !res) return false;
    if (sz < DFA_HEADER_FIXED) return false;

    DBG("input='%.*s' len=%zu\n", (int)len, in, len);
    memset(res, 0, sizeof(*res));
    res->category = DFA_CMD_UNKNOWN;

    if (dfa_fmt_magic(d) != DFA_MAGIC) return false;
    uint16_t ver = dfa_fmt_version(d);
    if (ver != DFA_VERSION) return false;

    int enc = dfa_fmt_encoding(d);
    int ss = DFA_STATE_SIZE(enc);
    int rs = DFA_RULE_SIZE(enc);
    uint8_t idl = dfa_fmt_id_len(d);
    size_t hs = DFA_HEADER_SIZE(enc, idl);

    uint32_t init = dfa_fmt_initial_state(d);
    if ((size_t)init + (size_t)ss > sz) return false;

    /* Empty input: check initial state and EOS */
    if (!len) {
        uint16_t fl = dfa_fmt_st_flags(d, init, enc);
        uint8_t cat = DFA_GET_CATEGORY_MASK(fl);
        uint32_t eos = dfa_fmt_st_eos_t(d, init, enc);
        if (eos && (size_t)eos + (size_t)ss <= sz)
            cat |= DFA_GET_CATEGORY_MASK(dfa_fmt_st_flags(d, eos, enc));
        if (cat) {
            res->matched = true; res->matched_length = 0; res->category_mask = cat;
            for (int i=0;i<8;i++) if (cat&(1<<i)) { res->category=(dfa_command_category_t)(i+1); break; }
        }
        return res->matched;
    }

    /* Walk states */
    uint32_t cur = init;
    uint32_t tr[MAX_TRACE]; int td = 0; tr[td++] = cur;
    size_t pos = 0;

    while (pos < len && pos < MAX_EVAL_LEN) {
        unsigned char c = (unsigned char)in[pos];
        uint16_t tc = dfa_fmt_st_tc(d, cur, enc);
        uint32_t rl = dfa_fmt_st_rules(d, cur, enc);
        DBG("pos=%zu c='%c' st=%u tc=%u rl=%u\n", pos, c, cur, tc, rl);

        if ((size_t)cur < hs || (size_t)cur + (size_t)ss > sz) return false;

        uint32_t nxt = 0; bool found = false;
        for (uint16_t i = 0; i < tc; i++) {
            size_t ro = rl + (size_t)i * rs;
            if ((size_t)ro + (size_t)rs > sz) break;
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
        if (!found) return false;
        pos++; cur = nxt; if (td < MAX_TRACE) tr[td++] = cur;
    }

    /* Determine category */
    uint16_t src_fl = dfa_fmt_st_flags(d, cur, enc);
    uint8_t src_cat = DFA_GET_CATEGORY_MASK(src_fl);
    uint16_t wpid = dfa_fmt_st_pid(d, cur, enc);

    uint32_t eos = dfa_fmt_st_eos_t(d, cur, enc);
    if (eos && (size_t)eos + (size_t)ss <= sz) {
        cur = eos; if (td < MAX_TRACE) tr[td++] = cur;
        wpid = dfa_fmt_st_pid(d, cur, enc);
    }

    uint8_t cat = src_cat ? src_cat : DFA_GET_CATEGORY_MASK(dfa_fmt_st_flags(d, cur, enc));
    if (cat || (wpid && wpid != UINT16_MAX)) {
        res->matched = true; res->matched_length = pos; res->category_mask = cat;
        res->final_state = cur;
        for (int i=0;i<8;i++) if (cat&(1<<i)) { res->category=(dfa_command_category_t)(i+1); break; }

        /* Captures (v7+) */
        if (wpid && wpid != UINT16_MAX) {
            cap_t stk[MAX_CAP_STK]; int sd = 0;
            uint32_t meta = dfa_fmt_meta_offset(d);
            for (int t = 1; t < td && (size_t)t <= pos; t++) {
                uint32_t fo = tr[t-1], to = tr[t];
                uint16_t ftc = dfa_fmt_st_tc(d, fo, enc);
                uint32_t frl = dfa_fmt_st_rules(d, fo, enc);
                for (uint16_t i = 0; i < ftc; i++) {
                    size_t ro = frl + (size_t)i * rs;
                    if (dfa_fmt_rl_target(d, ro, enc) == to) {
                        uint32_t mk = dfa_fmt_rl_markers(d, ro, enc);
                        if (mk && meta && mk+4 <= sz)
                            proc_markers(d, sz, mk, t-1, wpid, cat, stk, &sd, res);
                        break;
                    }
                }
            }
            uint32_t em = dfa_fmt_st_eos_m(d, cur, enc);
            if (em && meta && em+4 <= sz)
                proc_markers(d, sz, em, pos, wpid, cat, stk, &sd, res);
        }
    }
    return res->matched;
}

/* Capture access */
int dfa_result_get_capture(const dfa_result_t* r, int i, const char** s, size_t* l) {
    if (!r||i<0||i>=r->capture_count) return -1;
    if (s) *s=NULL; if (l) *l=r->captures[i].end-r->captures[i].start;
    return r->captures[i].capture_id;
}
const char* dfa_result_get_capture_name(const dfa_result_t* r, int i) {
    return (r&&i>=0&&i<r->capture_count) ? r->captures[i].name : NULL;
}
int dfa_result_get_capture_count(const dfa_result_t* r) { return r ? r->capture_count : 0; }
bool dfa_result_get_capture_by_index(const dfa_result_t* r, int i, size_t* s, size_t* l) {
    if (!r||i<0||i>=r->capture_count) return false;
    if (s) *s=r->captures[i].start; if (l) *l=r->captures[i].end-r->captures[i].start;
    return true;
}
bool dfa_result_get_capture_string(const dfa_result_t* r, int i,
    const void* dd, size_t ds, const char* in, const char** s, size_t* l, const char** nm)
{
    (void)dd; (void)ds;
    if (!r||i<0||i>=r->capture_count) return false;
    dfa_capture_t* c = (dfa_capture_t*)&r->captures[i];
    if (s) *s=in+c->start; if (l) *l=c->end-c->start;
    if (nm) { if (!c->name[0]) snprintf(c->name,sizeof(c->name),"capture_%d",c->capture_id); *nm=c->name; }
    return true;
}

/* Identifier validation */
bool dfa_eval_validate_id(const void* vd, size_t sz, const char* eid) {
    const uint8_t* d = (const uint8_t*)vd;
    if (!d||sz<DFA_HEADER_FIXED||!eid) return false;
    if (dfa_fmt_magic(d) != DFA_MAGIC) return false;
    int enc = dfa_fmt_encoding(d);
    uint8_t il = dfa_fmt_id_len(d);
    if (DFA_HEADER_SIZE(enc, il) > sz) return false;
    size_t el = strlen(eid);
    return il == el && !memcmp(dfa_fmt_identifier(d), eid, el);
}
