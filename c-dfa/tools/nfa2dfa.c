#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include "../include/dfa_types.h"
#include "multi_target_array.h"
#include "../include/nfa.h"
#include "dfa_minimize.h"

#if MAX_SYMBOLS != 320
#error "MAX_SYMBOLS must be 320"
#endif

// Forward declaration
int find_symbol_id(char c);
void nfa_init(void);

static char pattern_identifier[256] = "";
static bool flag_verbose = false;

#define DEBUG_PRINT(...) do { if (flag_verbose) fprintf(stderr, __VA_ARGS__); } while (0)

// Virtual symbol definitions (must match nfa_builder.c)
#define VSYM_EPS 257
#define VSYM_EOS 258

// Marker type definitions
#define MARKER_TYPE_START 0
#define MARKER_TYPE_END 1

/**
 * Check allocation result and abort on failure
 */
static void* alloc_or_abort(void* ptr, const char* msg) {
    if (ptr == NULL) {
        fprintf(stderr, "FATAL: %s - %s\n", msg, strerror(errno));
        exit(EXIT_FAILURE);
    }
    return ptr;
}

typedef struct {
    int symbol_id;
    int start_char;
    int end_char;
    bool is_special;
} alphabet_entry_t;

// Global NFA/DFA storage
static nfa_state_t nfa[MAX_STATES];
static build_dfa_state_t dfa[MAX_STATES];
static alphabet_entry_t alphabet[MAX_SYMBOLS];
static int nfa_state_count = 0;
static int dfa_state_count = 0;
static int alphabet_size = 0;

// Phase 3: Marker harvesting system
#define MAX_MARKERS_PER_DFA_TRANSITION 16
#define MAX_DFA_MARKER_LISTS 8192
#define MARKER_SENTINEL 0xFFFFFFFF

typedef struct {
    uint32_t markers[MAX_MARKERS_PER_DFA_TRANSITION];
    int count;
} MarkerList;

static MarkerList dfa_marker_lists[MAX_DFA_MARKER_LISTS];
static int marker_list_count = 0;

// Get unique marker list (store if new)
static uint32_t store_marker_list(const uint32_t* markers, int count) {
    if (count == 0) return 0;
    
    // Check if list already exists
    for (int i = 0; i < marker_list_count; i++) {
        if (dfa_marker_lists[i].count == count) {
            bool match = true;
            for (int j = 0; j < count; j++) {
                if (dfa_marker_lists[i].markers[j] != markers[j]) { match = false; break; }
            }
            if (match) return (uint32_t)(i + 1);  // +1 to distinguish from 0 (no markers)
        }
    }
    
    // Store new list
    if (marker_list_count < MAX_DFA_MARKER_LISTS) {
        for (int j = 0; j < count && j < MAX_MARKERS_PER_DFA_TRANSITION; j++) {
            dfa_marker_lists[marker_list_count].markers[j] = markers[j];
        }
        dfa_marker_lists[marker_list_count].count = count;
        return (uint32_t)(marker_list_count++ + 1);
    }
    return 0;
}

// Collect markers from NFA states in an epsilon closure
static void collect_markers_from_states(const int* states, int state_count,
                                        uint32_t* out_markers, int* out_count) {
    int count = *out_count;  // Start with existing marker count
    for (int i = 0; i < state_count && count < MAX_MARKERS_PER_DFA_TRANSITION; i++) {
        int ns = states[i];
        if (ns < 0 || ns >= nfa_state_count) continue;

        // Collect markers from pending_markers array (Phase 2: edge payloads)
        for (int m = 0; m < nfa[ns].pending_marker_count && count < MAX_MARKERS_PER_DFA_TRANSITION; m++) {
            if (nfa[ns].pending_markers[m].active) {
                uint32_t marker = ((uint32_t)nfa[ns].pending_markers[m].pattern_id << 17) |
                                  ((uint32_t)nfa[ns].pending_markers[m].uid << 1) |
                                  (uint32_t)nfa[ns].pending_markers[m].type;
                bool exists = false;
                for (int j = 0; j < count; j++) {
                    if (out_markers[j] == marker) { exists = true; break; }
                }
                if (!exists) out_markers[count++] = marker;
            }
        }
    }
    *out_count = count;
}

// DFA Deduplication Hash Table
#define DFA_HASH_SIZE 32749
static int dfa_hash_table[DFA_HASH_SIZE];
static int dfa_next_in_bucket[MAX_STATES];

static uint32_t hash_nfa_set(const int* states, int count, uint8_t mask) {
    uint32_t hash = 2166136261u;
    for (int i = 0; i < count; i++) {
        hash ^= (uint32_t)states[i];
        hash *= 16777619;
    }
    hash ^= (uint32_t)mask << 24;
    return hash;
}

static int find_dfa_state_hashed(uint32_t hash, const int* states, int count, uint8_t mask) {
    int idx = dfa_hash_table[hash % DFA_HASH_SIZE];
    while (idx != -1) {
        if (dfa[idx].nfa_state_count == count) {
            uint8_t existing_mask = (uint8_t)(dfa[idx].flags >> 8);
            if (existing_mask == mask) {
                bool match = true;
                for (int j = 0; j < count; j++) {
                    if (dfa[idx].nfa_states[j] != states[j]) { match = false; break; }
                }
                if (match) return idx;
            }
        }
        idx = dfa_next_in_bucket[idx];
    }
    return -1;
}

#ifndef NFABUILDER_EXCLUDE_NFA_INIT

void nfa_init(void) {
    for (int i = 0; i < MAX_STATES; i++) {
        nfa[i].category_mask = 0;
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            nfa[i].transitions[j] = -1;
        }
        mta_init(&nfa[i].multi_targets);
        nfa[i].is_eos_target = false;
        nfa[i].pending_marker_count = 0;
        for (int j = 0; j < MAX_PENDING_MARKERS; j++) {
            nfa[i].pending_markers[j].active = false;
        }
    }
    nfa_state_count = 0;
    marker_list_count = 0;
}

#endif  // NFABUILDER_EXCLUDE_NFA_INIT

void dfa_init(void) {
    memset(dfa_hash_table, -1, sizeof(dfa_hash_table));
    for (int i = 0; i < MAX_STATES; i++) {
        dfa_next_in_bucket[i] = -1;
        dfa[i].flags = 0;
        dfa[i].transition_count = 0;
        dfa[i].nfa_state_count = 0;
        dfa[i].eos_target = 0;
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            dfa[i].transitions[j] = -1;
            dfa[i].transitions_from_any[j] = false;
        }
    }
    dfa_state_count = 0;
}

void epsilon_closure_with_markers(int* states, int* count, int max_states,
                                  uint32_t* markers, int* marker_count, int max_markers) {
    int epsilon_sid = -1;
    int eos_sid = -1;
    for (int s = 0; s < alphabet_size; s++) {
        if (alphabet[s].symbol_id == 257) { epsilon_sid = s; }
        if (alphabet[s].symbol_id == 258) { eos_sid = s; }
    }
    if (epsilon_sid < 0 && eos_sid < 0) {
        return;
    }

    static bool in_set[MAX_STATES];
    memset(in_set, 0, sizeof(in_set));
    int stack[MAX_STATES], top = 0;

    for (int i = 0; i < *count; i++) {
        int s = states[i];
        if (s >= 0 && s < nfa_state_count) { stack[top++] = s; in_set[s] = true; }
    }

    while (top > 0) {
        int s = stack[--top];

        // Process EPSILON transitions (257)
        if (epsilon_sid >= 0) {
            int t = nfa[s].transitions[epsilon_sid];
            if (t != -1 && t < nfa_state_count && !in_set[t]) {
                if (*count < max_states) { states[(*count)++] = t; stack[top++] = t; in_set[t] = true; }
            }
            int mta_cnt = 0;
            int* mta_targets = mta_get_target_array(&nfa[s].multi_targets, epsilon_sid, &mta_cnt);
            if (mta_targets) {
                for (int i = 0; i < mta_cnt; i++) {
                    int target = mta_targets[i];
                    if (target >= 0 && target < nfa_state_count && !in_set[target]) {
                        if (*count < max_states) { states[(*count)++] = target; stack[top++] = target; in_set[target] = true; }
                    }
                }
            }

            int mta_marker_count = 0;
            transition_marker_t* mta_markers = mta_get_markers(&nfa[s].multi_targets, epsilon_sid, &mta_marker_count);
            if (mta_markers) {
                for (int m = 0; m < mta_marker_count && *marker_count < max_markers; m++) {
                    uint32_t marker = ((uint32_t)mta_markers[m].pattern_id << 17) |
                                      ((uint32_t)mta_markers[m].uid << 1) |
                                      (uint32_t)mta_markers[m].type;
                    bool exists = false;
                    for (int j = 0; j < *marker_count; j++) {
                        if (markers[j] == marker) { exists = true; break; }
                    }
                    if (!exists) markers[(*marker_count)++] = marker;
                }
            }
        }

        // Process EOS transitions (258) - follow them and harvest END markers
        if (eos_sid >= 0) {
            // First, harvest markers from EOS transitions on this state
            int mta_marker_count = 0;
            transition_marker_t* mta_markers = mta_get_markers(&nfa[s].multi_targets, eos_sid, &mta_marker_count);
            if (mta_markers) {
                for (int m = 0; m < mta_marker_count && *marker_count < max_markers; m++) {
                    uint32_t marker = ((uint32_t)mta_markers[m].pattern_id << 17) |
                                      ((uint32_t)mta_markers[m].uid << 1) |
                                      (uint32_t)mta_markers[m].type;
                    bool exists = false;
                    for (int j = 0; j < *marker_count; j++) {
                        if (markers[j] == marker) { exists = true; break; }
                    }
                    if (!exists) markers[(*marker_count)++] = marker;
                }
            }

            // Then, traverse EOS transitions to discover more states
            int mta_cnt = 0;
            int* eos_targets = mta_get_target_array(&nfa[s].multi_targets, eos_sid, &mta_cnt);
            if (eos_targets) {
                for (int i = 0; i < mta_cnt; i++) {
                    int target = eos_targets[i];
                    if (target >= 0 && target < nfa_state_count && !in_set[target]) {
                        if (*count < max_states) { states[(*count)++] = target; stack[top++] = target; in_set[target] = true; }
                    }
                }
            }
        }
    }
}

void epsilon_closure(int* states, int* count, int max_states) {
    int epsilon_sid = -1;
    for (int s = 0; s < alphabet_size; s++) {
        if (alphabet[s].symbol_id == 257) { epsilon_sid = s; break; }
    }
    if (epsilon_sid < 0) {
        return;
    }

    static bool in_set[MAX_STATES];
    memset(in_set, 0, sizeof(in_set));
    int stack[MAX_STATES], top = 0;
    
    for (int i = 0; i < *count; i++) {
        int s = states[i];
        if (s >= 0 && s < nfa_state_count) { stack[top++] = s; in_set[s] = true; }
    }

    while (top > 0) {
        int s = stack[--top];
        int t = nfa[s].transitions[epsilon_sid];
        if (t != -1 && t < nfa_state_count && !in_set[t]) {
            if (*count < max_states) { states[(*count)++] = t; stack[top++] = t; in_set[t] = true; }
        }
        int mta_cnt = 0;
        int* mta_targets = mta_get_target_array(&nfa[s].multi_targets, epsilon_sid, &mta_cnt);
        if (mta_targets) {
            for (int i = 0; i < mta_cnt; i++) {
                int target = mta_targets[i];
                if (target >= 0 && target < nfa_state_count && !in_set[target]) {
                    if (*count < max_states) { states[(*count)++] = target; stack[top++] = target; in_set[target] = true; }
                }
            }
        }
    }
}

int dfa_add_state(uint8_t category_mask, int* nfa_states, int nfa_count, uint16_t accepting_pattern_id) {
    uint32_t h = hash_nfa_set(nfa_states, nfa_count, category_mask);
    int existing = find_dfa_state_hashed(h, nfa_states, nfa_count, category_mask);
    if (existing != -1) return existing;
    if (dfa_state_count >= MAX_STATES) { fprintf(stderr, "FATAL: Max DFA states reached\n"); exit(1); }
    int state = dfa_state_count++;
    memset(&dfa[state], 0, sizeof(build_dfa_state_t));
    for (int i = 0; i < 256; i++) dfa[state].transitions[i] = -1;
    dfa[state].flags = (category_mask << 8);
    if (category_mask != 0) dfa[state].flags |= DFA_STATE_ACCEPTING;
    dfa[state].accepting_pattern_id = accepting_pattern_id;
    dfa[state].nfa_state_count = nfa_count;
    for (int i = 0; i < nfa_count && i < 8192; i++) dfa[state].nfa_states[i] = nfa_states[i];
    int bucket = h % DFA_HASH_SIZE;
    dfa_next_in_bucket[state] = dfa_hash_table[bucket];
    dfa_hash_table[bucket] = state;
    return state;
}

void nfa_move(int* states, int* count, int sid, int max_states) {
    int ns[MAX_STATES], nc = 0; static bool is[MAX_STATES];
    memset(is, 0, sizeof(is));
    for (int i = 0; i < *count; i++) {
        int s = states[i]; if (s < 0 || s >= nfa_state_count) continue;

        // Check both single target and multi-target transitions
        int t_single = nfa[s].transitions[sid];
        if (t_single != -1 && t_single < nfa_state_count && !is[t_single]) {
            if (nc < max_states) { ns[nc++] = t_single; is[t_single] = true; }
        }

        int mta_cnt = 0;
        int* targets = mta_get_target_array(&nfa[s].multi_targets, sid, &mta_cnt);
        if (targets) {
            for (int k = 0; k < mta_cnt; k++) {
                int t = targets[k]; if (t >= 0 && t < nfa_state_count && !is[t]) { if (nc < max_states) { ns[nc++] = t; is[t] = true; } }
            }
        }
    }
    for (int i = 0; i < nc; i++) states[i] = ns[i];
    *count = nc;
}

static void collect_transition_markers(int source_count, int* source_states, int sid,
                                       uint32_t* out_markers, int* out_count, int max_markers) {
    int count = *out_count;
    for (int i = 0; i < source_count && count < max_markers; i++) {
        int s = source_states[i];
        if (s < 0 || s >= nfa_state_count) continue;

        int mta_marker_count = 0;
        transition_marker_t* mta_markers = mta_get_markers(&nfa[s].multi_targets, sid, &mta_marker_count);
        if (mta_markers && mta_marker_count > 0) {
            for (int m = 0; m < mta_marker_count && count < max_markers; m++) {
                uint32_t marker = ((uint32_t)mta_markers[m].pattern_id << 17) |
                                  ((uint32_t)mta_markers[m].uid << 1) |
                                  (uint32_t)mta_markers[m].type;
                bool exists = false;
                for (int j = 0; j < count; j++) {
                    if (out_markers[j] == marker) { exists = true; break; }
                }
                if (!exists) {
                    out_markers[count++] = marker;
                }
            }
        }

        // Also collect VSYM_EOS (258) markers - these are END markers attached to states
        // that should be harvested whenever we visit those states
        int eos_marker_count = 0;
        int eos_sid = -1;
        for (int as = 0; as < alphabet_size; as++) {
            if (alphabet[as].symbol_id == 258) { eos_sid = as; break; }
        }
        if (eos_sid >= 0) {
            transition_marker_t* eos_markers = mta_get_markers(&nfa[s].multi_targets, eos_sid, &eos_marker_count);
            if (eos_markers && eos_marker_count > 0) {
                for (int m = 0; m < eos_marker_count && count < max_markers; m++) {
                    uint32_t marker = ((uint32_t)eos_markers[m].pattern_id << 17) |
                                      ((uint32_t)eos_markers[m].uid << 1) |
                                      (uint32_t)eos_markers[m].type;
                    bool exists = false;
                    for (int j = 0; j < count; j++) {
                        if (out_markers[j] == marker) { exists = true; break; }
                    }
                    if (!exists) {
                        out_markers[count++] = marker;
                    }
                }
            }
        }
    }
    *out_count = count;
}

void nfa_to_dfa(void) {
    dfa_init();

    int in[MAX_STATES] = {0}; int ic = 1;
    int temp[MAX_STATES]; memcpy(temp, in, sizeof(int)); int tc = ic;
    uint32_t dummy_markers[MAX_MARKERS_PER_DFA_TRANSITION];
    int dummy_count = 0;
    epsilon_closure_with_markers(temp, &tc, MAX_STATES, dummy_markers, &dummy_count, MAX_MARKERS_PER_DFA_TRANSITION);
    uint8_t im = 0; for (int i = 0; i < tc; i++) { im |= nfa[temp[i]].category_mask; }
    int idfa = dfa_add_state(im, temp, tc, 0);
    int q[MAX_STATES]; int h = 0, t = 1; q[0] = idfa;
    while (h < t) {
        int cur = q[h++];
        for (int i = 0; i < alphabet_size; i++) {
            int symbol = alphabet[i].symbol_id;
            if (symbol == 257) continue;

            int ms[MAX_STATES]; int mc = dfa[cur].nfa_state_count;
            for (int j = 0; j < mc; j++) ms[j] = dfa[cur].nfa_states[j];

            uint32_t markers[MAX_MARKERS_PER_DFA_TRANSITION];
            int marker_count = 0;
            collect_transition_markers(mc, ms, symbol, markers, &marker_count, MAX_MARKERS_PER_DFA_TRANSITION);

            nfa_move(ms, &mc, symbol, MAX_STATES);
            if (mc == 0) {
                int eos_sid = -1;
                for (int as = 0; as < alphabet_size; as++) {
                    if (alphabet[as].symbol_id == 258) { eos_sid = as; break; }
                }
                if (eos_sid >= 0 && symbol == alphabet[eos_sid].symbol_id) {
                    uint32_t eos_offset = store_marker_list(markers, marker_count);
                }
                continue;
            }
            int tc2 = mc; int temp2[MAX_STATES]; memcpy(temp2, ms, mc * sizeof(int));
            epsilon_closure_with_markers(temp2, &tc2, MAX_STATES, markers, &marker_count, MAX_MARKERS_PER_DFA_TRANSITION);
            uint8_t mm = 0; for (int j = 0; j < tc2; j++) mm |= nfa[temp2[j]].category_mask;

            collect_markers_from_states(temp2, tc2, markers, &marker_count);
            if (marker_count > 0) {
                fprintf(stderr, "[DEBUG MARKER] tc2=%d, collected %d markers\n", tc2, marker_count);
                for (int m = 0; m < marker_count; m++) {
                    fprintf(stderr, "  marker[%d] = 0x%08X\n", m, markers[m]);
                }
            }
            uint32_t marker_list_offset = store_marker_list(markers, marker_count);
            if (marker_list_offset > 0) {
                fprintf(stderr, "[DEBUG MARKER] Stored at offset %u (count=%d)\n", marker_list_offset, marker_count);
            }

            int target = dfa_add_state(mm, temp2, tc2, 0);
            int sid = alphabet[i].symbol_id;
            if (sid < 256) {
                dfa[cur].transitions[sid] = target;
                dfa[cur].marker_offsets[sid] = marker_list_offset;
                if (sid == 103) {
                    fprintf(stderr, "[DEBUG] nfa_to_dfa: DFA state %d, 'g'(103) -> %d\n", cur, target);
                }
            }

            if (alphabet[i].symbol_id == 258) {
                dfa[cur].eos_target = target;
                dfa[cur].eos_marker_offset = marker_list_offset;
            }

            bool is_new = true; for (int j = 0; j < t; j++) if (q[j] == target) { is_new = false; break; }
            if (is_new && t < MAX_STATES) q[t++] = target;
        }
    }
}

void flatten_dfa(void) {
    int any_sid = -1;
    int space_sid = -1;
    int tab_sid = -1;

    // Identify virtual symbol IDs
    for (int s = 0; s < alphabet_size; s++) {
        if (alphabet[s].symbol_id == 256) any_sid = s;
        else if (alphabet[s].symbol_id == 259) space_sid = s;
        else if (alphabet[s].symbol_id == 260) tab_sid = s;
    }
    
    for (int s = 0; s < dfa_state_count; s++) {
        int nt[256]; bool any[256]; uint32_t markers[256];
        for (int i = 0; i < 256; i++) { nt[i] = -1; any[i] = false; markers[i] = 0; }

        uint32_t any_marker = (any_sid != -1) ? dfa[s].marker_offsets[any_sid] : 0;

        // First, set specific symbol transitions
        for (int i = 0; i < alphabet_size; i++) {
            int sid = alphabet[i].symbol_id;
            if (sid < 256 && dfa[s].transitions[sid] != -1) {
                int t = dfa[s].transitions[sid];
                nt[sid] = t;
                any[sid] = false;
                markers[sid] = dfa[s].marker_offsets[sid];
            }
        }

        // Override with space and tab transitions
        if (space_sid != -1 && dfa[s].transitions[space_sid] != -1) {
            nt[32] = dfa[s].transitions[space_sid];
            any[32] = false;
            markers[32] = dfa[s].marker_offsets[space_sid];
        }

        if (tab_sid != -1 && dfa[s].transitions[tab_sid] != -1) {
            nt[9] = dfa[s].transitions[tab_sid];
            any[9] = false;
            markers[9] = dfa[s].marker_offsets[tab_sid];
        }

        // Finally, override with ANY transition (fills in gaps)
        if (any_sid != -1 && dfa[s].transitions[any_sid] != -1) {
            int t = dfa[s].transitions[any_sid];
            for (int i = 0; i < 256; i++) {
                if (nt[i] == -1) {  // Only fill gaps, don't override specific transitions
                    nt[i] = t;
                    any[i] = true;
                    markers[i] = any_marker;
                }
            }
        }

        int rc = 0;
        for (int i = 0; i < 256; i++) {
            if (nt[i] >= dfa_state_count) {
                nt[i] = -1;
            }
            dfa[s].transitions[i] = nt[i];
            dfa[s].transitions_from_any[i] = any[i];
            dfa[s].marker_offsets[i] = markers[i];
            if (nt[i] != -1) rc++;
        }
        for (int i = 256; i < MAX_SYMBOLS; i++) {
            dfa[s].transitions[i] = -1;
            dfa[s].marker_offsets[i] = 0;
        }
        dfa[s].transition_count = rc;
    }
}

typedef struct { uint8_t type, d1, d2, d3; int target_state_index; } intermediate_rule_t;

int compress_state_rules(int sidx, intermediate_rule_t* out) {
    int rc = 0, ct = -1, sc = -1;
    // Compress only literal byte transitions (0-255)
    for (int c = 0; c <= 256; c++) {
        int t = (c < 256) ? dfa[sidx].transitions[c] : -1;
        if (t != ct) {
            if (ct != -1) {
                out[rc].target_state_index = ct; out[rc].d1 = (uint8_t)sc; out[rc].d2 = (uint8_t)(c - 1); out[rc].d3 = 0;
                out[rc].type = (sc == c - 1) ? DFA_RULE_LITERAL : DFA_RULE_RANGE;
                rc++;
            }
            ct = t; sc = c;
        }
    }
    return rc;
}

void write_dfa_file(const char* filename) {
    FILE* file = fopen(filename, "wb");
    if (!file) { fprintf(stderr, "FATAL: Cannot open %s for writing\n", filename); exit(1); }
    intermediate_rule_t* all_rules = alloc_or_abort(malloc(dfa_state_count * MAX_SYMBOLS * sizeof(intermediate_rule_t)), "Rules");
    size_t total_rules = 0;
    for (int i = 0; i < dfa_state_count; i++) total_rules += compress_state_rules(i, &all_rules[i * MAX_SYMBOLS]);
    size_t id_len = strlen(pattern_identifier);

    size_t marker_data_size = 0;
    for (int i = 0; i < dfa_state_count; i++) {
        int rule_count = compress_state_rules(i, &all_rules[i * MAX_SYMBOLS]);
        for (int r = 0; r < rule_count && r < 256; r++) {
            uint32_t list_idx = dfa[i].marker_offsets[all_rules[i * MAX_SYMBOLS + r].d1];
            if (list_idx > 0 && list_idx <= (uint32_t)marker_list_count) {
                MarkerList* ml = &dfa_marker_lists[list_idx - 1];
                marker_data_size += (ml->count + 1) * sizeof(uint32_t);
            }
        }
        if (dfa[i].eos_marker_offset > 0 && dfa[i].eos_marker_offset <= (uint32_t)marker_list_count) {
            MarkerList* ml = &dfa_marker_lists[dfa[i].eos_marker_offset - 1];
            marker_data_size += (ml->count + 1) * sizeof(uint32_t);
        }
    }

    size_t dfa_size = 23 + id_len + dfa_state_count * sizeof(dfa_state_t) + total_rules * sizeof(dfa_rule_t);
    dfa_t* ds = calloc(1, dfa_size + marker_data_size);
    if (!ds) { fprintf(stderr, "FATAL: Failed to allocate DFA buffer (%zu + %zu bytes)\n", dfa_size, marker_data_size); exit(1); }
    ds->magic = DFA_MAGIC; ds->version = DFA_VERSION;
    ds->state_count = dfa_state_count; ds->initial_state = 23 + id_len;  // Header is 23 bytes total (magic=4, ver=2, cnt=2, init=4, mask=4, flags=2, id_len=1, meta=4 = 23), identifier starts at offset 23
    ds->metadata_offset = 0;  // Will be set after states are written if needed

    uint32_t accepting_mask = 0;
    for (int i = 0; i < dfa_state_count; i++) {
        if (dfa[i].flags & DFA_STATE_ACCEPTING) {
            accepting_mask |= (1 << i);
        }
    }
    ds->accepting_mask = accepting_mask;

    ds->identifier_length = (uint8_t)id_len; 
    fprintf(stderr, "[DEBUG ID] ds at %p\n", (void*)ds);
    fprintf(stderr, "[DEBUG ID] id_len at offset %zu = %d\n", offsetof(dfa_t, identifier_length), ds->identifier_length);
    fprintf(stderr, "[DEBUG ID] identifier at offset %zu\n", offsetof(dfa_t, identifier));
    memcpy(ds->identifier, pattern_identifier, id_len);
    fprintf(stderr, "[DEBUG ID] After memcpy, bytes at ds[18..26]: %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
            ((unsigned char*)ds)[18], ((unsigned char*)ds)[19],
            ((unsigned char*)ds)[20], ((unsigned char*)ds)[21],
            ((unsigned char*)ds)[22], ((unsigned char*)ds)[23],
            ((unsigned char*)ds)[24], ((unsigned char*)ds)[25],
            ((unsigned char*)ds)[26]);

    dfa_state_t* sarr = (dfa_state_t*)((char*)ds + ds->initial_state);
    dfa_rule_t* rarr = (dfa_rule_t*)((char*)sarr + dfa_state_count * sizeof(dfa_state_t));
    size_t cro = ds->initial_state + dfa_state_count * sizeof(dfa_state_t);
    size_t gri = 0;
    for (int i = 0; i < dfa_state_count; i++) {
        int rc = compress_state_rules(i, &all_rules[i * MAX_SYMBOLS]);
        if (rc > 256) rc = 256;
        sarr[i].transition_count = (uint16_t)rc; sarr[i].transitions_offset = (rc > 0) ? (uint32_t)cro : 0;
        sarr[i].flags = dfa[i].flags;
        sarr[i].accepting_pattern_id = dfa[i].accepting_pattern_id;
        sarr[i].eos_marker_offset = 0;
        if (dfa[i].eos_target != 0) sarr[i].eos_target = (uint32_t)(ds->initial_state + (size_t)dfa[i].eos_target * sizeof(dfa_state_t));
        for (int r = 0; r < rc; r++) {
            dfa_rule_t* dst = &rarr[gri++];
            dst->type = all_rules[i * MAX_SYMBOLS + r].type; dst->data1 = all_rules[i * MAX_SYMBOLS + r].d1;
            dst->data2 = all_rules[i * MAX_SYMBOLS + r].d2; dst->data3 = 0;
            dst->marker_offset = 0;
            int tidx = all_rules[i * MAX_SYMBOLS + r].target_state_index;
            if (tidx < 0 || tidx >= dfa_state_count) {
                fprintf(stderr, "FATAL: State %d rule %d target index %d out of bounds (max %d)\n",
                        i, r, tidx, dfa_state_count - 1);
                exit(1);
            }
            dst->target = (uint32_t)(ds->initial_state + (size_t)tidx * sizeof(dfa_state_t));
        }
        cro += rc * sizeof(dfa_rule_t);
    }

    size_t metadata_offset = cro;
    fprintf(stderr, "[DEBUG WRITE] id_len=%zu, initial_state=%u, cro=%zu, marker_list_count=%d\n",
            id_len, ds->initial_state, cro, marker_list_count);
    if (marker_list_count > 0) {
        fprintf(stderr, "[DEBUG WRITE] Setting metadata_offset=%zu\n", metadata_offset);
        ds->metadata_offset = (uint32_t)metadata_offset;
        fprintf(stderr, "[DEBUG WRITE] ds->metadata_offset = %u (0x%X)\n",
                ds->metadata_offset, ds->metadata_offset);

        uint32_t* marker_base = (uint32_t*)((char*)ds + metadata_offset);
        fprintf(stderr, "[DEBUG WRITE] marker_base at %p\n", (void*)marker_base);
        size_t moffset = 0;

        for (int i = 0; i < dfa_state_count; i++) {
            int rule_count = compress_state_rules(i, &all_rules[i * MAX_SYMBOLS]);
            size_t rule_offset = sarr[i].transitions_offset;
            for (int r = 0; r < rule_count && r < 256; r++) {
                dfa_rule_t* dst = (dfa_rule_t*)((char*)ds + rule_offset + r * sizeof(dfa_rule_t));
                uint32_t list_idx = dfa[i].marker_offsets[all_rules[i * MAX_SYMBOLS + r].d1];
                fprintf(stderr, "[DEBUG MARKER WRITE] State %d, rule %d, list_idx=%u\n", i, r, list_idx);
                if (list_idx > 0 && list_idx <= (uint32_t)marker_list_count) {
                    MarkerList* ml = &dfa_marker_lists[list_idx - 1];
                    fprintf(stderr, "[DEBUG MARKER WRITE] Writing %d markers from list %d\n", ml->count, list_idx - 1);
                    // Set dst->marker_offset BEFORE writing markers
                    dst->marker_offset = (uint32_t)(metadata_offset + moffset * sizeof(uint32_t));
                    for (int k = 0; k < ml->count; k++) {
                        uint32_t val = ml->markers[k];
                        // Write byte-by-byte to avoid endianness issues
                        ((uint8_t*)marker_base)[moffset * 4 + 0] = (val >> 0) & 0xFF;
                        ((uint8_t*)marker_base)[moffset * 4 + 1] = (val >> 8) & 0xFF;
                        ((uint8_t*)marker_base)[moffset * 4 + 2] = (val >> 16) & 0xFF;
                        ((uint8_t*)marker_base)[moffset * 4 + 3] = (val >> 24) & 0xFF;
                        fprintf(stderr, "  marker[%zu] = 0x%08X\n", moffset, ml->markers[k]);
                        moffset++;
                    }
                    uint32_t sentinel = MARKER_SENTINEL;
                    ((uint8_t*)marker_base)[moffset * 4 + 0] = (sentinel >> 0) & 0xFF;
                    ((uint8_t*)marker_base)[moffset * 4 + 1] = (sentinel >> 8) & 0xFF;
                    ((uint8_t*)marker_base)[moffset * 4 + 2] = (sentinel >> 16) & 0xFF;
                    ((uint8_t*)marker_base)[moffset * 4 + 3] = (sentinel >> 24) & 0xFF;
                    moffset++;
                }
            }
            if (dfa[i].eos_marker_offset > 0 && dfa[i].eos_marker_offset < (uint32_t)marker_list_count) {
                MarkerList* ml = &dfa_marker_lists[dfa[i].eos_marker_offset - 1];
                sarr[i].eos_marker_offset = (uint32_t)(metadata_offset + moffset * sizeof(uint32_t));
                for (int k = 0; k < ml->count; k++) marker_base[moffset++] = ml->markers[k];
                marker_base[moffset++] = MARKER_SENTINEL;
            }
        }
        fprintf(stderr, "[DEBUG WRITE] Total markers written: %zu\n", moffset);
    } else {
        fprintf(stderr, "[DEBUG WRITE] No markers to write\n");
    }

    size_t total_size = dfa_size + marker_data_size;
    fprintf(stderr, "[DEBUG WRITE] total_size=%zu, dfa_size=%zu, marker_data_size=%zu\n",
            total_size, dfa_size, marker_data_size);
    if (fwrite(ds, 1, total_size, file) != total_size) exit(1);
    fclose(file); free(ds); free(all_rules);
}

void load_nfa_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) { fprintf(stderr, "FATAL: Cannot open NFA file %s\n", filename); exit(1); }
    char line[1024]; 
    if (!fgets(line, sizeof(line), file)) { fprintf(stderr, "FATAL: Empty NFA file\n"); exit(1); }
    if (!strstr(line, "NFA_ALPHABET")) { fprintf(stderr, "FATAL: Invalid NFA header\n"); exit(1); }
#ifndef NFABUILDER_EXCLUDE_NFA_INIT
    nfa_init();
#endif
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "Identifier:", 11) == 0) sscanf(line + 11, "%s", pattern_identifier);
        else if (strncmp(line, "AlphabetSize:", 13) == 0) {
            sscanf(line + 13, "%d", &alphabet_size);
        } else if (strncmp(line, "States:", 7) == 0) {
            sscanf(line + 7, "%d", &nfa_state_count);

        }
        else if (strncmp(line, "Alphabet:", 9) == 0) {
            for (int i = 0; i < alphabet_size; i++) {
                if (!fgets(line, sizeof(line), file)) break;
                if (line[0] == '\n' || line[0] == '\r') { i--; continue; }
                if (strncmp(line, "State ", 6) == 0) { i--; continue; }
                if (strncmp(line, "Initial:", 8) == 0) { i--; continue; }
                unsigned int sid, start, end;
                if (sscanf(line, " Symbol %u: %u-%u", &sid, &start, &end) >= 3) {
                    alphabet[i].symbol_id = (int)sid; alphabet[i].start_char = (int)start; alphabet[i].end_char = (int)end;
                    alphabet[i].is_special = (strstr(line, "special") != NULL);
                }
            }
        }
        else if (strncmp(line, "State ", 6) == 0) {
            int s_idx; sscanf(line + 6, "%d:", &s_idx);
            while (fgets(line, sizeof(line), file) && line[0] != '\n' && line[0] != '\r') {
                if (strstr(line, "CategoryMask:")) { unsigned int m; sscanf(strstr(line, "0x"), "%x", &m); nfa[s_idx].category_mask = (uint8_t)m; }
                else if (strstr(line, "EosTarget:")) nfa[s_idx].is_eos_target = (strstr(line, "yes") != NULL);
                // Phase 2: markers are now stored as edge payloads, not on states
                // BUT CaptureEnd needs special handling: END markers attach to the state itself
                // We add them to the state's multi_targets using a special marker transition (VSYM_EOS)
                else if (strncmp(line, "  CaptureEnd:", 12) == 0) {
                    int cap_id;
                    if (sscanf(line + 14, "%d", &cap_id) == 1) {
                        // Add END marker to the state using VSYM_EOS (258)
                        mta_add_marker(&nfa[s_idx].multi_targets, VSYM_EOS, 0, cap_id, MARKER_TYPE_END);
                    }
                }
                else if (strncmp(line, "    Symbol ", 11) == 0) {
                    int sid, target; char* arrow = strstr(line, "->");
                    if (arrow && sscanf(line + 11, "%d", &sid) == 1) {
                        char* p = arrow + 2;
                        while (p && *p != '[') {
                            while (isspace(*p) || *p == ',') p++;
                            if (sscanf(p, "%d", &target) == 1) {
                                mta_add_target(&nfa[s_idx].multi_targets, sid, target);
                            }
                            p = strchr(p, ','); if (p) p++;
                        }
                        char* markers_start = strstr(line, "[Markers:");
                        if (markers_start) {
                            char* m = markers_start + 9;
                            while (*m && *m != ']') {
                                uint32_t marker;
                                while (*m && (isspace(*m) || *m == ',')) m++;
                                if (sscanf(m, "0x%08X", &marker) == 1) {
                                    uint16_t pattern_id = (marker >> 17) & 0xFFFF;
                                    uint16_t uid = (marker >> 1) & 0x7FFF;
                                    uint8_t type = marker & 0x1;
                                    mta_add_marker(&nfa[s_idx].multi_targets, sid, pattern_id, uid, type);
                                    // Advance m past this marker (skip 10 chars for "0xXXXXXXXX")
                                    m += 10;
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    fclose(file);
}

int main(int argc, char* argv[]) {
    bool minimize = true;
    const char* input_file = NULL;
    const char* output_file = "out.dfa";
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "--no-minimize") == 0) minimize = false;
            else if (strcmp(argv[i], "-v") == 0) flag_verbose = true;
            else if (strcmp(argv[i], "--minimize-moore") == 0) dfa_minimize_set_algorithm(DFA_MIN_MOORE);
            else if (strcmp(argv[i], "--minimize-brzozowski") == 0) dfa_minimize_set_algorithm(DFA_MIN_BRZOZOWSKI);
        } else {
            if (input_file == NULL) input_file = argv[i];
            else output_file = argv[i];
        }
    }
    if (input_file == NULL) return 1;
    load_nfa_file(input_file);
    nfa_to_dfa();
    flatten_dfa();
    if (minimize) dfa_state_count = dfa_minimize(dfa, dfa_state_count);
    write_dfa_file(output_file);
    return 0;
}
