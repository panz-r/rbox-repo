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
