/**
 * nfa_dsl_utils.c - DSL utilities for NFA testing
 *
 * Implements helper functions for verifying NFA structure
 * by inspecting serialized DSL output.
 */

#define _DEFAULT_SOURCE
#include "nfa_dsl_utils.h"
#include "nfa_dsl.h"
#include "cdfa_defines.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * DSL NFA Query Helpers
 * ============================================================================ */

bool dsl_has_transition(const dsl_nfa_t *nfa, int from, int sym, int to) {
    if (!nfa || from < 0 || from >= nfa->state_count) return false;
    const dsl_state_t *s = &nfa->states[from];
    for (int i = 0; i < s->transition_count; i++) {
        const dsl_transition_t *t = &s->transitions[i];
        if (t->symbol_id != sym) continue;
        for (int j = 0; j < t->target_count; j++) {
            if (t->targets[j] == to) return true;
        }
    }
    return false;
}

bool dsl_state_is_accepting(const dsl_nfa_t *nfa, int state, uint8_t mask) {
    if (!nfa || state < 0 || state >= nfa->state_count) return false;
    const dsl_state_t *s = &nfa->states[state];
    if (!s->is_accept) return false;
    if (mask != 0 && s->category_mask != mask) return false;
    return true;
}

bool dsl_has_marker(const dsl_nfa_t *nfa, int from, int sym, uint32_t marker) {
    if (!nfa || from < 0 || from >= nfa->state_count) return false;
    const dsl_state_t *s = &nfa->states[from];
    for (int i = 0; i < s->transition_count; i++) {
        const dsl_transition_t *t = &s->transitions[i];
        if (t->symbol_id != sym) continue;
        for (int j = 0; j < t->marker_count; j++) {
            if (t->markers[j].value == marker) return true;
        }
    }
    return false;
}

static bool dsl_has_path_bfs(const dsl_nfa_t *nfa, int from, int to, const int *seq, int len) {
    if (len == 0) return from == to;
    if (from < 0 || from >= nfa->state_count) return false;
    const dsl_state_t *s = &nfa->states[from];
    for (int i = 0; i < s->transition_count; i++) {
        const dsl_transition_t *t = &s->transitions[i];
        if (t->symbol_id != seq[0]) continue;
        for (int j = 0; j < t->target_count; j++) {
            if (dsl_has_path_bfs(nfa, t->targets[j], to, seq + 1, len - 1))
                return true;
        }
    }
    return false;
}

bool dsl_has_path(const dsl_nfa_t *nfa, int from, int to, const int *seq, int len) {
    if (len == 0) return from == to;
    return dsl_has_path_bfs(nfa, from, to, seq, len);
}

int dsl_extract_symbol_sequence(const char *dsl, int *symbols, int max_syms, bool skip_eps) {
    int count = 0;
    const char *p = dsl;
    while (*p && count < max_syms) {
        const char *arrow = strstr(p, "->");
        if (!arrow) break;

        const char *line_start = arrow;
        while (line_start > dsl && *(line_start-1) != '\n') line_start--;

        /* Find symbol: look backward from arrow for last non-space before -> */
        const char *sym_end = arrow;
        while (sym_end > line_start && isspace(*(sym_end-1))) sym_end--;
        const char *sym_start = sym_end;
        while (sym_start > line_start && !isspace(*(sym_start-1))) sym_start--;

        int sym_len = sym_end - sym_start;
        if (sym_len > 0 && sym_len < 31) {
            char sym_name[32];
            strncpy(sym_name, sym_start, sym_len);
            sym_name[sym_len] = '\0';

            int sym_id = -1;
            if (strcmp(sym_name, "EPS") == 0) {
                /* Epsilon transitions are intentionally skipped when skip_eps=true */
                if (!skip_eps) sym_id = VSYM_EPS;
            } else if (strcmp(sym_name, "ANY") == 0) {
                sym_id = VSYM_BYTE_ANY;
            } else if (strcmp(sym_name, "EOS") == 0) {
                /* End-of-string marker */
                sym_id = VSYM_EOS;
            } else if (strcmp(sym_name, "SPACE") == 0 || strcmp(sym_name, "TAB") == 0) {
                /* Skip whitespace normalization transitions (loops, not single chars) */
            } else if (sym_name[0] == '\'' && sym_name[sym_len-1] == '\'') {
                /* Literal character like 'a' or ' ' or escaped sequences like '\n' */
                if (sym_len >= 3 && sym_name[1] == '\\') {
                    /* Handle escaped sequences: \n, \t, \r, \\, \', \xHH */
                    char esc = sym_name[2];
                    switch (esc) {
                        case 'n':  sym_id = '\n'; break;
                        case 't':  sym_id = '\t'; break;
                        case 'r':  sym_id = '\r'; break;
                        case '\\': sym_id = '\\'; break;
                        case '\'': sym_id = '\''; break;
                        case 'x': {
                            /* \xHH hex escape - requires at least 5 chars: '\xHH\'' */
                            if (sym_len >= 5 && sym_name[4] == '\'') {
                                char hex[3] = {sym_name[3], sym_name[4] == '\'' ? sym_name[5] : '0', 0};
                                if (sym_name[4] == '\'') {
                                    hex[0] = sym_name[3];
                                    hex[1] = sym_name[4];
                                } else {
                                    hex[0] = sym_name[3];
                                    hex[1] = 0;
                                }
                                sym_id = (int)strtol(hex, NULL, 16);
                            }
                            break;
                        }
                        default: sym_id = -1;
                    }
                } else {
                    sym_id = (unsigned char)sym_name[1];
                }
            } else if (strncmp(sym_name, "\\x", 2) == 0 && sym_len >= 4) {
                /* Hex escape like \x41 for 'A' (unquoted) */
                char hex[3] = {sym_name[2], sym_len >= 4 ? sym_name[3] : '0', 0};
                sym_id = (int)strtol(hex, NULL, 16);
            }

            if (sym_id >= 0) {
                symbols[count++] = sym_id;
            }
        }
        p = arrow + 2;
    }
    return count;
}

bool nfa_assert_symbol_sequence(const nfa_graph_t *graph,
                                 const int *expected_symbols,
                                 int expected_count,
                                 bool skip_eps) {
    char *dsl = nfa_graph_dsl_to_string(graph);
    if (!dsl) {
        fprintf(stderr, "FAIL: could not generate DSL string\n");
        return false;
    }

    int actual[256];
    int actual_count = dsl_extract_symbol_sequence(dsl, actual, 256, skip_eps);
    free(dsl);

    if (actual_count != expected_count) {
        fprintf(stderr, "FAIL: symbol count mismatch: expected %d, got %d\n",
                expected_count, actual_count);
        return false;
    }

    for (int i = 0; i < actual_count; i++) {
        if (actual[i] != expected_symbols[i]) {
            fprintf(stderr, "FAIL: symbol %d mismatch: expected '%c' (0x%02X), got '%c' (0x%02X)\n",
                    i, expected_symbols[i], expected_symbols[i],
                    actual[i], actual[i]);
            return false;
        }
    }
    return true;
}

/* ============================================================================
 * DSL DFA Query Helpers
 *
 * These functions work with dsl_dfa_t (parsed from DFA DSL) to verify
 * transition structure without needing the full build_dfa_state_t array.
 * ============================================================================ */

/**
 * Get the number of states in a parsed DFA.
 */
int dfa_dsl_get_state_count(const dsl_dfa_t *dfa) {
    if (!dfa) return 0;
    return dfa->state_count;
}

/**
 * Get the number of transitions in a state.
 */
int dfa_dsl_get_transition_count(const dsl_dfa_t *dfa, int state_id) {
    if (!dfa || state_id < 0 || state_id >= dfa->state_count) return 0;
    const dsl_dfa_state_t *s = &dfa->states[state_id];
    return s->symbol_transition_count;
}

/**
 * Check if a state has a transition on the given symbol.
 */
bool dfa_dsl_has_transition(const dsl_dfa_t *dfa, int state_id, int symbol) {
    if (!dfa || state_id < 0 || state_id >= dfa->state_count) return false;
    const dsl_dfa_state_t *s = &dfa->states[state_id];
    for (int i = 0; i < s->symbol_transition_count; i++) {
        if (s->symbol_transitions[i].symbol_id == symbol) return true;
    }
    return false;
}

/**
 * Get the target state for a transition on a given symbol.
 * Returns -1 if no such transition exists.
 */
int dfa_dsl_get_target(const dsl_dfa_t *dfa, int state_id, int symbol) {
    if (!dfa || state_id < 0 || state_id >= dfa->state_count) return -1;
    const dsl_dfa_state_t *s = &dfa->states[state_id];
    for (int i = 0; i < s->symbol_transition_count; i++) {
        if (s->symbol_transitions[i].symbol_id == symbol) {
            if (s->symbol_transitions[i].target_count > 0) {
                return s->symbol_transitions[i].targets[0];
            }
        }
    }
    return -1;
}

/**
 * Check if a state is accepting.
 */
bool dfa_dsl_is_accepting(const dsl_dfa_t *dfa, int state_id) {
    if (!dfa || state_id < 0 || state_id >= dfa->state_count) return false;
    return dfa->states[state_id].is_accept;
}

/**
 * Check if a state is the start state.
 */
bool dfa_dsl_is_start(const dsl_dfa_t *dfa, int state_id) {
    if (!dfa || state_id < 0 || state_id >= dfa->state_count) return false;
    return dfa->states[state_id].is_start;
}

/**
 * Get the category mask for a state.
 * Returns 0 if state doesn't exist or has no category.
 */
uint8_t dfa_dsl_get_category(const dsl_dfa_t *dfa, int state_id) {
    if (!dfa || state_id < 0 || state_id >= dfa->state_count) return 0;
    return dfa->states[state_id].category_mask;
}

/**
 * Check if a transition has a marker with the given value.
 */
bool dfa_dsl_transition_has_marker(const dsl_dfa_t *dfa, int state_id,
                                   int symbol, uint32_t marker_value) {
    if (!dfa || state_id < 0 || state_id >= dfa->state_count) return false;
    const dsl_dfa_state_t *s = &dfa->states[state_id];
    for (int i = 0; i < s->symbol_transition_count; i++) {
        if (s->symbol_transitions[i].symbol_id == symbol) {
            for (int m = 0; m < s->symbol_transitions[i].marker_count; m++) {
                if (s->symbol_transitions[i].markers[m].value == marker_value) {
                    return true;
                }
            }
        }
    }
    return false;
}

/**
 * Check if a state has the EOS (end-of-sequence) flag.
 */
bool dfa_dsl_state_has_eos(const dsl_dfa_t *dfa, int state_id) {
    if (!dfa || state_id < 0 || state_id >= dfa->state_count) return false;
    return dfa->states[state_id].is_eos_target;
}

/**
 * Get the EOS target for a state.
 * Returns -1 if no EOS target.
 */
int dfa_dsl_get_eos_target(const dsl_dfa_t *dfa, int state_id) {
    if (!dfa || state_id < 0 || state_id >= dfa->state_count) return -1;
    return dfa->states[state_id].eos_target;
}

/**
 * Find states that are reachable from the start state via BFS.
 * Fills the provided array with state IDs (max count elements).
 * Returns the actual number of states found.
 */
int dfa_dsl_find_reachable_states(const dsl_dfa_t *dfa, int *out_states, int max_count) {
    if (!dfa || !out_states || max_count <= 0) return 0;
    
    bool *visited = calloc((size_t)dfa->state_count, sizeof(bool));
    if (!visited) return 0;
    
    int queue[256];
    int queue_head = 0, queue_tail = 0;
    int count = 0;
    
    queue[queue_tail++] = dfa->start_state;
    visited[dfa->start_state] = true;
    
    while (queue_head < queue_tail && count < max_count) {
        int curr = queue[queue_head++];
        out_states[count++] = curr;
        
        const dsl_dfa_state_t *s = &dfa->states[curr];
        
        for (int i = 0; i < s->symbol_transition_count && queue_tail < 256; i++) {
            for (int t = 0; t < s->symbol_transitions[i].target_count; t++) {
                int target = s->symbol_transitions[i].targets[t];
                if (!visited[target]) {
                    visited[target] = true;
                    queue[queue_tail++] = target;
                }
            }
        }
        
        if (s->is_eos_target && s->eos_target >= 0 && !visited[s->eos_target]) {
            visited[s->eos_target] = true;
            if (queue_tail < 256) queue[queue_tail++] = s->eos_target;
        }
    }
    
    free(visited);
    return count;
}

/**
 * Check if two DFAs are structurally isomorphic (same shape, different state IDs).
 * Uses canonical BFS numbering to determine isomorphism.
 * Returns true if isomorphic.
 */
bool dfa_dsl_is_isomorphic(const dsl_dfa_t *a, const dsl_dfa_t *b) {
    if (!a || !b) return false;
    if (a->state_count != b->state_count) return false;
    if (a->alphabet_size != b->alphabet_size) return false;
    
    char *a_str = dfa_dsl_to_string_filtered(a, (dfa_dsl_filter_t){-1, -1, -1});
    char *b_str = dfa_dsl_to_string_filtered(b, (dfa_dsl_filter_t){-1, -1, -1});
    
    if (!a_str || !b_str) {
        free(a_str); free(b_str);
        return false;
    }
    
    bool result = (strcmp(a_str, b_str) == 0);
    free(a_str); free(b_str);
    return result;
}
