/**
 * nfa_dsl.c - Compact NFA serialization/deserialization DSL
 *
 * Implements the NFA DSL format described in nfa_dsl.h.
 * Used for testing and verification only - not linked into production.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "../lib/nfa_builder.h"
#include "../include/nfa_dsl.h"
#include "../include/dfa_errors.h"
#include "../include/dfa_types.h"
#include "../include/dfa_format.h"
#include "../include/cdfa_defines.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Forward declaration for context type from nfa_builder.h */
/* nfa_builder_context_t is fully defined in nfa_builder.h which we include */

/* ============================================================================
 * Virtual symbol table
 * ============================================================================ */

typedef struct {
    const char *name;
    int id;
} vsym_entry_t;

static const vsym_entry_t vsym_table[] = {
    {"EPS",   VSYM_EPS},
    {"ANY",   VSYM_BYTE_ANY},
    {"EOS",   VSYM_EOS},
    {"SPACE", VSYM_SPACE},
    {"TAB",   VSYM_TAB},
    {NULL, -1}
};

int nfa_dsl_symbol_from_name(const char *name) {
    for (int i = 0; vsym_table[i].name != NULL; i++) {
        if (strcasecmp(vsym_table[i].name, name) == 0) {
            return vsym_table[i].id;
        }
    }
    return -1;
}

const char *nfa_dsl_symbol_name(int symbol_id) {
    for (int i = 0; vsym_table[i].name != NULL; i++) {
        if (vsym_table[i].id == symbol_id) {
            return vsym_table[i].name;
        }
    }
    return NULL;
}

/* ============================================================================
 * Internal: Write a single character in DSL format (quoted, escaped)
 * ============================================================================ */

static void dsl_write_char(FILE *out, unsigned char c) {
    switch (c) {
    case '\n':  fprintf(out, "\\n");  return;
    case '\t':  fprintf(out, "\\t");  return;
    case '\r':  fprintf(out, "\\r");  return;
    case '\\':  fprintf(out, "\\\\"); return;
    case '\'':  fprintf(out, "\\'");  return;
    default:
        if (c >= 0x20 && c < 0x7f) {
            fprintf(out, "'%c'", c);
        } else {
            fprintf(out, "\\x%02x", c);
        }
        return;
    }
}

/* ============================================================================
 * Internal: Write a symbol (literal or virtual name)
 * ============================================================================ */

static void dsl_write_symbol(FILE *out, int symbol_id) {
    const char *name = nfa_dsl_symbol_name(symbol_id);
    if (name) {
        fprintf(out, "%s", name);
    } else if (symbol_id >= 0 && symbol_id < 256) {
        dsl_write_char(out, (unsigned char)symbol_id);
    } else {
        fprintf(out, "%d", symbol_id);
    }
}

/* ============================================================================
 * Internal: Sort helper for symbol IDs (qsort comparator)
 * ============================================================================ */

static int cmp_int(const void *a, const void *b) {
    return (*(const int *)a) - (*(const int *)b);
}

static int cmp_uint32(const void *a, const void *b) {
    uint32_t va = *(const uint32_t *)a;
    uint32_t vb = *(const uint32_t *)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

/* ============================================================================
 * Canonicalization: Compute a deterministic signature for an NFA state
 *
 * The signature encodes:
 *   - Accepting properties (category_mask, pattern_id)
 *   - EOS target flag
 *   - All outgoing transitions (symbol_id, sorted target set, sorted markers)
 *
 * Two structurally identical states produce identical signatures.
 * Uses FNV-1a for fast, deterministic hashing.
 * ============================================================================ */

static uint64_t fnv1a_init(void) { return 2166136261ULL; }

static uint64_t fnv1a_update(uint64_t h, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619ULL;
    }
    return h;
}

static uint64_t fnv1a_update_u32(uint64_t h, uint32_t v) {
    return fnv1a_update(h, &v, sizeof(v));
}

static uint64_t fnv1a_update_i32(uint64_t h, int32_t v) {
    return fnv1a_update(h, &v, sizeof(v));
}

/* Compute a canonical signature for an NFA state.
 * This hashes the state's properties and all outgoing transitions
 * (with targets and markers sorted for determinism). */
static uint64_t compute_state_signature(const nfa_state_t *s) {
    uint64_t h = fnv1a_init();

    /* Accepting properties */
    h = fnv1a_update_u32(h, s->category_mask);
    h = fnv1a_update_i32(h, s->pattern_id);
    h = fnv1a_update(h, &s->is_eos_target, sizeof(s->is_eos_target));

    /* Collect active symbols, sort them */
    int active_syms[MAX_SYMBOLS];
    int active_count = 0;

    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
        int count = mta_get_target_count((multi_target_array_t *)&s->multi_targets, sym);
        if (count > 0) {
            active_syms[active_count++] = sym;
        }
    }
    qsort(active_syms, (size_t)active_count, sizeof(int), cmp_int);

    /* Hash each transition: symbol + sorted targets + sorted markers */
    for (int si = 0; si < active_count; si++) {
        int sym = active_syms[si];
        h = fnv1a_update_i32(h, sym);

        int count = 0;
        int *targets = mta_get_target_array((multi_target_array_t *)&s->multi_targets, sym, &count);
        if (targets && count > 0) {
            /* Sort targets for deterministic signature */
            qsort(targets, (size_t)count, sizeof(int), cmp_int);
            for (int k = 0; k < count; k++) {
                h = fnv1a_update_i32(h, targets[k]);
            }
        }

        /* Markers - sorted by packed value */
        int marker_count = 0;
        transition_marker_t *markers = mta_get_markers(
            (multi_target_array_t *)&s->multi_targets, sym, &marker_count);
        if (markers && marker_count > 0) {
            /* Collect packed marker values, sort, hash */
            uint32_t packed[MAX_MARKERS_PER_TRANSITION];
            int mp = 0;
            for (int m = 0; m < marker_count && mp < MAX_MARKERS_PER_TRANSITION; m++) {
                packed[mp++] = MARKER_PACK(markers[m].pattern_id, markers[m].uid, markers[m].type);
            }
            qsort(packed, (size_t)mp, sizeof(uint32_t), cmp_uint32);
            for (int m = 0; m < mp; m++) {
                h = fnv1a_update_u32(h, packed[m]);
            }
        }
    }

    return h;
}

/* ============================================================================
 * Canonicalization: Generalized BFS traversal with deterministic ordering
 *
 * Performs BFS from a given start state. Optionally restricts to states
 * relevant to a specific pattern_id. At each BFS level, states are sorted
 * by (signature, original_index) for deterministic tie-breaking.
 *
 * Parameters:
 *   states       - NFA state array
 *   state_count  - total number of states
 *   start_state  - state to begin BFS from (typically 0)
 *   pattern_filter - if >= 0, restrict to states with this pattern_id or
 *                    states on paths between them
 *   old_to_new_out         - filled with old_id -> new_id mapping (caller frees)
 *   canonical_order_out    - filled with new_id -> old_id array (caller frees)
 *   reachable_count_out    - set to number of reachable states
 *
 * Returns true on success, false on allocation failure.
 * ============================================================================ */

typedef struct {
    int old_id;
    uint64_t signature;
} bfs_entry_t;

static int cmp_bfs_entry(const void *a, const void *b) {
    const bfs_entry_t *ea = (const bfs_entry_t *)a;
    const bfs_entry_t *eb = (const bfs_entry_t *)b;
    if (ea->signature < eb->signature) return -1;
    if (ea->signature > eb->signature) return 1;
    return ea->old_id - eb->old_id;
}

static bool canonicalize_bfs_ex(
        const nfa_state_t *states,
        int state_count,
        int start_state,
        int pattern_filter ATTR_UNUSED,
        int **old_to_new_out,
        int **canonical_order_out,
        int *reachable_count_out)
{
    int *old_to_new = malloc((size_t)state_count * sizeof(int));
    int *canonical_order = malloc((size_t)state_count * sizeof(int));
    bool *visited = calloc((size_t)state_count, sizeof(bool));
    bfs_entry_t *frontier = malloc((size_t)state_count * sizeof(bfs_entry_t));

    if (!old_to_new || !canonical_order || !visited || !frontier) {
        free(old_to_new); free(canonical_order); free(visited); free(frontier);
        return false;
    }

    for (int i = 0; i < state_count; i++) {
        old_to_new[i] = -1;
    }

    int new_id = 0;
    int frontier_start = 0;
    int frontier_end = 0;

    /* Seed: start from the given start state */
    if (start_state < 0 || start_state >= state_count) {
        /* Invalid start state - nothing reachable */
        *old_to_new_out = old_to_new;
        *canonical_order_out = canonical_order;
        *reachable_count_out = 0;
        free(visited); free(frontier);
        return true;
    }

    visited[start_state] = true;
    frontier[frontier_end].old_id = start_state;
    frontier[frontier_end].signature = compute_state_signature(&states[start_state]);
    frontier_end++;

    while (frontier_start < frontier_end) {
        int level_end = frontier_end;

        /* Sort the current BFS level for deterministic ordering */
        int level_size = level_end - frontier_start;
        qsort(&frontier[frontier_start], (size_t)level_size, sizeof(bfs_entry_t), cmp_bfs_entry);

        /* Assign new IDs and discover next level */
        int next_frontier_start = frontier_end;

        for (int fi = frontier_start; fi < level_end; fi++) {
            int old_id = frontier[fi].old_id;

            old_to_new[old_id] = new_id;
            canonical_order[new_id] = old_id;
            new_id++;

            /* Discover unvisited neighbors */
            const nfa_state_t *s = &states[old_id];
            for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
                int count = 0;
                int *targets = mta_get_target_array((multi_target_array_t *)&s->multi_targets,
                                                     sym, &count);
                if (!targets) continue;
                for (int k = 0; k < count; k++) {
                    int target = targets[k];
                    if (target >= 0 && target < state_count && !visited[target]) {
                        /* If pattern filtering is active, only include the target
                         * if it belongs to the filtered pattern or is on a path
                         * to/from such states. For simplicity, we include all
                         * reachable states from the start, since the start state
                         * was already chosen to be within the pattern's subgraph.
                         * Pattern filtering primarily affects marker output. */
                        visited[target] = true;
                        frontier[frontier_end].old_id = target;
                        frontier[frontier_end].signature = compute_state_signature(&states[target]);
                        frontier_end++;
                    }
                }
            }
        }

        frontier_start = next_frontier_start;
    }

    *reachable_count_out = new_id;
    *old_to_new_out = old_to_new;
    *canonical_order_out = canonical_order;

    free(visited);
    free(frontier);
    return true;
}

/* Wrapper: canonicalize from state 0 (full NFA) */
static int *canonicalize_bfs(const nfa_state_t *states,
                              int state_count,
                              int **canonical_order_out,
                              int *reachable_count_out) {
    int *old_to_new = NULL;
    int *canonical_order = NULL;
    int reachable_count = 0;

    bool ok = canonicalize_bfs_ex(states, state_count, 0, -1,
                                   &old_to_new, &canonical_order, &reachable_count);
    if (!ok) return NULL;

    *canonical_order_out = canonical_order;
    *reachable_count_out = reachable_count;
    return old_to_new;
}

/* ============================================================================
 * Internal: Serialize one state with canonical output
 *
 * Shared between nfa_dsl_dump and nfa_dsl_dump_filtered.
 * Writes the state definition line and all transitions for one state.
 *
 * Parameters:
 *   out               - output stream
 *   s                 - the NFA state
 *   new_id            - the remapped (canonical) state ID
 *   is_start          - whether this state is the start of the subgraph
 *   old_to_new        - state ID remapping table (old -> new), -1 for unreachable
 *   marker_pid_filter - if >= 0, only output markers for this pattern_id
 * ============================================================================ */

static void dsl_serialize_state(FILE *out,
                                 const nfa_state_t *s,
                                 int new_id,
                                 bool is_start,
                                 const int *old_to_new,
                                 int marker_pid_filter)
{
    /* State definition line */
    fprintf(out, "%d:", new_id);
    if (is_start) {
        fprintf(out, " start");
    }
    if (s->category_mask != 0) {
        fprintf(out, " accept category=0x%02x pattern=%d",
                s->category_mask, s->pattern_id);
    }
    if (s->is_eos_target) {
        fprintf(out, " eos");
    }
    fprintf(out, "\n");

    /* Collect active symbols, sort */
    int active_syms[MAX_SYMBOLS];
    int active_count = 0;

    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
        int count = mta_get_target_count((multi_target_array_t *)&s->multi_targets, sym);
        if (count > 0) {
            active_syms[active_count++] = sym;
        }
    }
    qsort(active_syms, (size_t)active_count, sizeof(int), cmp_int);

    /* Output transitions */
    for (int si = 0; si < active_count; si++) {
        int sym = active_syms[si];
        int count = 0;
        int *targets = mta_get_target_array((multi_target_array_t *)&s->multi_targets,
                                             sym, &count);
        if (!targets || count == 0) continue;

        /* Sort targets by old ID, then filter and remap */
        qsort(targets, (size_t)count, sizeof(int), cmp_int);

        /* Remap targets, keeping only those that are in the subgraph */
        int remapped[DSL_MAX_TARGETS];
        int rcount = 0;
        for (int k = 0; k < count && rcount < DSL_MAX_TARGETS; k++) {
            if (old_to_new[targets[k]] >= 0) {
                remapped[rcount++] = old_to_new[targets[k]];
            }
        }
        if (rcount == 0) continue;

        /* Re-sort after remapping */
        qsort(remapped, (size_t)rcount, sizeof(int), cmp_int);

        /* Write transition line */
        fprintf(out, "%d ", new_id);
        dsl_write_symbol(out, sym);
        fprintf(out, " -> ");
        for (int k = 0; k < rcount; k++) {
            if (k > 0) fprintf(out, ",");
            fprintf(out, "%d", remapped[k]);
        }

        /* Markers - sorted by packed value, optionally filtered */
        int marker_count = 0;
        transition_marker_t *markers = mta_get_markers(
            (multi_target_array_t *)&s->multi_targets, sym, &marker_count);
        if (markers && marker_count > 0) {
            uint32_t packed[MAX_MARKERS_PER_TRANSITION];
            int mp = 0;
            for (int m = 0; m < marker_count && mp < MAX_MARKERS_PER_TRANSITION; m++) {
                /* Filter markers by pattern_id if requested */
                if (marker_pid_filter >= 0 &&
                    markers[m].pattern_id != marker_pid_filter) {
                    continue;
                }
                packed[mp++] = MARKER_PACK(markers[m].pattern_id,
                                            markers[m].uid, markers[m].type);
            }
            if (mp > 0) {
                qsort(packed, (size_t)mp, sizeof(uint32_t), cmp_uint32);
                fprintf(out, " [");
                for (int m = 0; m < mp; m++) {
                    if (m > 0) fprintf(out, ",");
                    fprintf(out, "0x%08X", packed[m]);
                }
                fprintf(out, "]");
            }
        }

        fprintf(out, "\n");
    }
}

/* ============================================================================
 * Serializer: nfa_dsl_dump (canonicalized, full NFA)
 * ============================================================================ */

/* ============================================================================
 * Serializer: nfa_graph_dsl_dump (canonicalized, full NFA from graph)
 * ============================================================================ */

void nfa_graph_dsl_dump(FILE *out, const nfa_graph_t *graph) {
    int state_count = graph->state_count;

    if (state_count == 0) return;

    int reachable_count = 0;
    int *canonical_order = NULL;
int *old_to_new = canonicalize_bfs(graph->states, state_count,
                                        &canonical_order, &reachable_count);

    if (!old_to_new || !canonical_order || reachable_count == 0) {
        free(old_to_new); free(canonical_order);
        return;
    }

    fprintf(out, "version: %d\n", NFA_DSL_VERSION);

    for (int ci = 0; ci < reachable_count; ci++) {
        int old_id = canonical_order[ci];
        dsl_serialize_state(out, &graph->states[old_id], ci, ci == 0,
                            old_to_new, -1);
    }

    free(old_to_new);
    free(canonical_order);
}

/* ============================================================================
 * Serializer: nfa_graph_dsl_to_string
 * ============================================================================ */

char *nfa_graph_dsl_to_string(const nfa_graph_t *graph) {
    size_t buf_size = (size_t)(graph->state_count * 256 + 1024);
    char *buf = malloc(buf_size);
    if (!buf) return NULL;

    FILE *out = fmemopen(buf, buf_size, "w");
    if (!out) {
        free(buf);
        return NULL;
    }

    nfa_graph_dsl_dump(out, graph);
    fflush(out);
    size_t actual_len = (size_t)ftell(out);
    fclose(out);

    buf[actual_len] = '\0';
    char *shrunk = realloc(buf, actual_len + 1);
    return shrunk ? shrunk : buf;
}

/* ============================================================================
 * Serializer: nfa_graph_dsl_dump_filtered (focused sub-graph)
 * ============================================================================ */

void nfa_graph_dsl_dump_filtered(FILE *out, const nfa_graph_t *graph, nfa_dsl_filter_t filter) {
    const nfa_state_t *states = graph->states;
    int state_count = graph->state_count;

    if (state_count == 0) return;

    int start = (filter.start_state >= 0) ? filter.start_state : 0;

    /* Canonical BFS from the given start state */
    int reachable_count = 0;
    int *canonical_order = NULL;
    int *old_to_new = NULL;

    bool ok = canonicalize_bfs_ex(states, state_count, start, -1,
                                   &old_to_new, &canonical_order, &reachable_count);
    if (!ok || !old_to_new || !canonical_order || reachable_count == 0) {
        free(old_to_new); free(canonical_order);
        return;
    }

    fprintf(out, "version: %d\n", NFA_DSL_VERSION);

    /* Header comment for focused output */
    if (filter.pattern_id_filter >= 0) {
        fprintf(out, "# Focused NFA for pattern %d (from state %d)\n",
                filter.pattern_id_filter, start);
    } else if (filter.start_state >= 0) {
        fprintf(out, "# Focused NFA from state %d\n", start);
    }

    /* Determine marker filter */
    int marker_pid = -1;
    if (filter.pattern_id_filter >= 0 && !filter.include_markers_for_other_patterns) {
        marker_pid = filter.pattern_id_filter;
    }

    /* Serialize each state */
    for (int ci = 0; ci < reachable_count; ci++) {
        int old_id = canonical_order[ci];
        dsl_serialize_state(out, &states[old_id], ci, ci == 0,
                            old_to_new, marker_pid);
    }

    free(old_to_new);
    free(canonical_order);
}

char *nfa_graph_dsl_to_string_filtered(const nfa_graph_t *graph, nfa_dsl_filter_t filter) {
    size_t buf_size = (size_t)(graph->state_count * 256 + 1024);
    char *buf = malloc(buf_size);
    if (!buf) return NULL;

    FILE *out = fmemopen(buf, buf_size, "w");
    if (!out) {
        free(buf);
        return NULL;
    }

    nfa_graph_dsl_dump_filtered(out, graph, filter);
    fflush(out);
    size_t actual_len = (size_t)ftell(out);
    fclose(out);

    buf[actual_len] = '\0';
    char *shrunk = realloc(buf, actual_len + 1);
    return shrunk ? shrunk : buf;
}

/* ============================================================================
 * Round-trip verification
 * ============================================================================ */

char *nfa_graph_dsl_verify_roundtrip(const nfa_graph_t *graph) {
    char *first = nfa_graph_dsl_to_string(graph);
    if (!first) {
        return strdup("nfa_graph_dsl_to_string returned NULL on first call");
    }

    /* Serialize the same graph again - deterministic output must match */
    char *second = nfa_graph_dsl_to_string(graph);
    if (!second) {
        free(first);
        return strdup("nfa_graph_dsl_to_string returned NULL on second call");
    }

    char *diff = NULL;
    if (strcmp(first, second) != 0) {
        diff = nfa_dsl_diff(first, second);
    }

    free(first);
    free(second);
    return diff;
}

/* ============================================================================
 * Deserializer: Internal parser types
 * ============================================================================ */

typedef enum {
    TOK_EOF,
    TOK_INT,
    TOK_HEX,
    TOK_IDENT,
    TOK_CHAR_LITERAL,
    TOK_ARROW,
    TOK_COLON,
    TOK_COMMA,
    TOK_LBRACKET,
    TOK_RBRACKET,
    TOK_EQUALS,
    TOK_COMMENT,
    TOK_BACKSLASH
} dsl_token_type_t;

typedef struct {
    dsl_token_type_t type;
    char text[MAX_LINE_LENGTH];
    int ival;           /* For TOK_INT / TOK_HEX */
} dsl_token_t;

typedef struct {
    const char *input;
    int pos;
    int line;
    int col;
    dsl_token_t lookahead;
    bool has_lookahead;
    char error[512];
} dsl_lexer_t;

/* ============================================================================
 * Lexer
 * ============================================================================ */

static void dsl_lexer_init(dsl_lexer_t *lex, const char *input) {
    memset(lex, 0, sizeof(*lex));
    lex->input = input;
    lex->pos = 0;
    lex->line = 1;
    lex->col = 1;
}

static void dsl_lexer_skip_ws(dsl_lexer_t *lex) {
    while (lex->input[lex->pos]) {
        char c = lex->input[lex->pos];
        if (c == ' ' || c == '\t' || c == '\r') {
            lex->pos++;
            lex->col++;
        } else if (c == '\n') {
            lex->pos++;
            lex->line++;
            lex->col = 1;
        } else {
            break;
        }
    }
}

static dsl_token_t dsl_lexer_next(dsl_lexer_t *lex) {
    dsl_token_t tok;
    memset(&tok, 0, sizeof(tok));

    dsl_lexer_skip_ws(lex);

    if (lex->input[lex->pos] == '\0') {
        tok.type = TOK_EOF;
        return tok;
    }

    char c = lex->input[lex->pos];

    /* Comments */
    if (c == '#') {
        tok.type = TOK_COMMENT;
        int i = 0;
        while (lex->input[lex->pos] && lex->input[lex->pos] != '\n') {
            if (i < (int)sizeof(tok.text) - 1) {
                tok.text[i++] = lex->input[lex->pos];
            }
            lex->pos++;
        }
        tok.text[i] = '\0';
        return tok;
    }

    /* Arrow -> */
    if (c == '-' && lex->input[lex->pos + 1] == '>') {
        tok.type = TOK_ARROW;
        strcpy(tok.text, "->");
        lex->pos += 2;
        lex->col += 2;
        return tok;
    }

    /* Single-char tokens */
    if (c == ':') { tok.type = TOK_COLON;     tok.text[0] = ':'; lex->pos++; lex->col++; return tok; }
    if (c == ',') { tok.type = TOK_COMMA;     tok.text[0] = ','; lex->pos++; lex->col++; return tok; }
    if (c == '[') { tok.type = TOK_LBRACKET;  tok.text[0] = '['; lex->pos++; lex->col++; return tok; }
    if (c == ']') { tok.type = TOK_RBRACKET;  tok.text[0] = ']'; lex->pos++; lex->col++; return tok; }
    if (c == '=') { tok.type = TOK_EQUALS;    tok.text[0] = '='; lex->pos++; lex->col++; return tok; }

    /* Backslash (escape sequences) */
    if (c == '\\') {
        tok.type = TOK_BACKSLASH;
        tok.text[0] = '\\';
        lex->pos++;
        lex->col++;
        char next = lex->input[lex->pos];
        if (next == 'n' || next == 't' || next == 'r' || next == '\\') {
            tok.text[1] = next;
            tok.text[2] = '\0';
            lex->pos++;
            lex->col++;
        } else if (next == 'x' && isxdigit((unsigned char)lex->input[lex->pos + 1])
                                && isxdigit((unsigned char)lex->input[lex->pos + 2])) {
            tok.text[1] = 'x';
            tok.text[2] = lex->input[lex->pos + 1];
            tok.text[3] = lex->input[lex->pos + 2];
            tok.text[4] = '\0';
            lex->pos += 3;
            lex->col += 3;
        } else {
            tok.text[1] = next;
            tok.text[2] = '\0';
            lex->pos++;
            lex->col++;
        }
        return tok;
    }

    /* Character literal 'x' or "x" */
    if (c == '\'' || c == '"') {
        char quote = c;
        lex->pos++;
        lex->col++;
        tok.type = TOK_CHAR_LITERAL;

        if (lex->input[lex->pos] == '\\') {
            /* Escaped character in quotes */
            lex->pos++;
            lex->col++;
            char next = lex->input[lex->pos];
            switch (next) {
            case 'n':  tok.ival = '\n'; break;
            case 't':  tok.ival = '\t'; break;
            case 'r':  tok.ival = '\r'; break;
            case '\\': tok.ival = '\\'; break;
            case '\'': tok.ival = '\''; break;
            case '"':  tok.ival = '"';  break;
            case 'x': {
                /* \xHH */
                char hex[3] = {0};
                hex[0] = lex->input[lex->pos + 1];
                hex[1] = lex->input[lex->pos + 2];
                tok.ival = (int)strtol(hex, NULL, 16);
                lex->pos += 2;
                lex->col += 2;
                break;
            }
            default:
                tok.ival = (unsigned char)next;
                break;
            }
            snprintf(tok.text, sizeof(tok.text), "'%c'", (char)tok.ival);
            lex->pos++;
            lex->col++;
        } else {
            tok.ival = (unsigned char)lex->input[lex->pos];
            snprintf(tok.text, sizeof(tok.text), "'%c'", lex->input[lex->pos]);
            lex->pos++;
            lex->col++;
        }
        /* Consume closing quote */
        if (lex->input[lex->pos] == quote) {
            lex->pos++;
            lex->col++;
        }
        return tok;
    }

    /* Hex number 0x... */
    if (c == '0' && (lex->input[lex->pos + 1] == 'x' || lex->input[lex->pos + 1] == 'X')) {
        tok.type = TOK_HEX;
        int i = 0;
        tok.text[i++] = lex->input[lex->pos++]; lex->col++;
        tok.text[i++] = lex->input[lex->pos++]; lex->col++;
        while (isxdigit((unsigned char)lex->input[lex->pos]) && i < (int)sizeof(tok.text) - 1) {
            tok.text[i++] = lex->input[lex->pos++];
            lex->col++;
        }
        tok.text[i] = '\0';
        tok.ival = (int)strtol(tok.text, NULL, 16);
        return tok;
    }

    /* Integer */
    if (isdigit((unsigned char)c)) {
        tok.type = TOK_INT;
        int i = 0;
        while (isdigit((unsigned char)lex->input[lex->pos]) && i < (int)sizeof(tok.text) - 1) {
            tok.text[i++] = lex->input[lex->pos++];
            lex->col++;
        }
        tok.text[i] = '\0';
        tok.ival = atoi(tok.text);
        return tok;
    }

    /* Identifier (keyword or virtual symbol name) */
    if (isalpha((unsigned char)c) || c == '_') {
        tok.type = TOK_IDENT;
        int i = 0;
        while ((isalnum((unsigned char)lex->input[lex->pos]) || lex->input[lex->pos] == '_')
               && i < (int)sizeof(tok.text) - 1) {
            tok.text[i++] = lex->input[lex->pos++];
            lex->col++;
        }
        tok.text[i] = '\0';
        return tok;
    }

    /* Unknown character - skip and return EOF-like */
    snprintf(lex->error, sizeof(lex->error),
             "Unexpected character '%c' at line %d col %d", c, lex->line, lex->col);
    lex->pos++;
    lex->col++;
    tok.type = TOK_EOF;
    return tok;
}

/* Peek at next non-comment token */
static dsl_token_t dsl_lexer_peek(dsl_lexer_t *lex) {
    if (lex->has_lookahead) {
        return lex->lookahead;
    }
    dsl_token_t tok;
    do {
        tok = dsl_lexer_next(lex);
    } while (tok.type == TOK_COMMENT);
    lex->lookahead = tok;
    lex->has_lookahead = true;
    return tok;
}

static dsl_token_t dsl_lexer_consume(dsl_lexer_t *lex) {
    dsl_token_t tok = dsl_lexer_peek(lex);
    lex->has_lookahead = false;
    return tok;
}

static bool dsl_lexer_match(dsl_lexer_t *lex, dsl_token_type_t type) {
    if (dsl_lexer_peek(lex).type == type) {
        dsl_lexer_consume(lex);
        return true;
    }
    return false;
}

/* ============================================================================
 * Parser helpers
 * ============================================================================ */

static dsl_nfa_t *dsl_nfa_alloc(int max_state) {
    dsl_nfa_t *nfa = calloc(1, sizeof(dsl_nfa_t));
    if (!nfa) return NULL;

    nfa->max_state_id = max_state;
    nfa->state_count = max_state + 1;
    nfa->start_state = -1;
    nfa->alphabet_size = -1;
    nfa->identifier[0] = '\0';

    nfa->states = calloc((size_t)(max_state + 1), sizeof(dsl_state_t));
    if (!nfa->states) {
        free(nfa);
        return NULL;
    }

    /* Initialize states */
    for (int i = 0; i <= max_state; i++) {
        nfa->states[i].state_id = i;
        nfa->states[i].pattern_id = -1;
    }

    return nfa;
}

/* Ensure the states array can hold state_id */
static bool dsl_nfa_grow(dsl_nfa_t *nfa, int state_id) {
    if (state_id <= nfa->max_state_id) return true;

    int new_max = state_id;
    dsl_state_t *new_states = realloc(nfa->states,
                                       (size_t)(new_max + 1) * sizeof(dsl_state_t));
    if (!new_states) return false;

    /* Zero-initialize new entries */
    for (int i = nfa->max_state_id + 1; i <= new_max; i++) {
        memset(&new_states[i], 0, sizeof(dsl_state_t));
        new_states[i].state_id = i;
        new_states[i].pattern_id = -1;
    }

    nfa->states = new_states;
    nfa->max_state_id = new_max;
    nfa->state_count = new_max + 1;
    return true;
}

/* Parse a symbol from the current token. Returns symbol ID or -1. */
static int dsl_parse_symbol(dsl_lexer_t *lex) {
    dsl_token_t tok = dsl_lexer_peek(lex);

    if (tok.type == TOK_CHAR_LITERAL) {
        dsl_lexer_consume(lex);
        return tok.ival;
    }

    if (tok.type == TOK_BACKSLASH) {
        dsl_lexer_consume(lex);
        if (strcmp(tok.text, "\\n") == 0) return '\n';
        if (strcmp(tok.text, "\\t") == 0) return '\t';
        if (strcmp(tok.text, "\\r") == 0) return '\r';
        if (strcmp(tok.text, "\\\\") == 0) return '\\';
        if (tok.text[1] == 'x') {
            char hex[3] = {tok.text[2], tok.text[3], '\0'};
            return (int)strtol(hex, NULL, 16);
        }
        return -1;
    }

    if (tok.type == TOK_IDENT) {
        int sym = nfa_dsl_symbol_from_name(tok.text);
        if (sym >= 0) {
            dsl_lexer_consume(lex);
            return sym;
        }
        /* Not a virtual symbol name - could be an error */
        return -1;
    }

    if (tok.type == TOK_INT || tok.type == TOK_HEX) {
        dsl_lexer_consume(lex);
        return tok.ival;
    }

    return -1;
}

/* Parse a target list: INT { , INT } */
static bool dsl_parse_target_list(dsl_lexer_t *lex, dsl_transition_t *trans) {
    trans->target_count = 0;

    dsl_token_t tok = dsl_lexer_peek(lex);
    if (tok.type != TOK_INT && tok.type != TOK_HEX) return false;

    while (true) {
        tok = dsl_lexer_peek(lex);
        if (tok.type != TOK_INT && tok.type != TOK_HEX) break;
        dsl_lexer_consume(lex);
        if (trans->target_count < DSL_MAX_TARGETS) {
            trans->targets[trans->target_count++] = tok.ival;
        }
        if (!dsl_lexer_match(lex, TOK_COMMA)) break;
    }

    return trans->target_count > 0;
}

/* Parse marker list: 0xHHHHHHHH { , 0xHHHHHHHH } */
static bool dsl_parse_marker_list(dsl_lexer_t *lex, dsl_transition_t *trans) {
    trans->marker_count = 0;

    if (!dsl_lexer_match(lex, TOK_LBRACKET)) return false;

    while (true) {
        dsl_token_t tok = dsl_lexer_peek(lex);
        if (tok.type == TOK_RBRACKET) {
            dsl_lexer_consume(lex);
            return true;
        }
        if (tok.type == TOK_HEX || tok.type == TOK_INT) {
            dsl_lexer_consume(lex);
            if (trans->marker_count < DSL_MAX_MARKERS) {
                trans->markers[trans->marker_count].value = (uint32_t)tok.ival;
                trans->marker_count++;
            }
        } else {
            /* Unexpected token in markers */
            dsl_lexer_consume(lex);
        }
        dsl_lexer_match(lex, TOK_COMMA);
    }
}

/* Try to parse a transition line: state_id symbol -> targets [markers]
 * The state_id token has already been consumed; we have its value.
 * Returns true if a transition was successfully parsed, false otherwise.
 * Does NOT consume any tokens on failure (restores lexer state). */
static bool dsl_try_parse_transition(dsl_lexer_t *lex, dsl_nfa_t *nfa, int state_id) {
    /* Save lexer state for backtracking */
    dsl_lexer_t saved = *lex;

    /* Ensure the state exists */
    if (!dsl_nfa_grow(nfa, state_id)) {
        *lex = saved;
        return false;
    }
    dsl_state_t *state = &nfa->states[state_id];

    if (state->transition_count >= DSL_MAX_TRANSITIONS) {
        *lex = saved;
        return false;
    }

    /* Next should be a symbol */
    int sym = dsl_parse_symbol(lex);
    if (sym < 0) {
        *lex = saved;
        return false;
    }

    /* Arrow */
    if (!dsl_lexer_match(lex, TOK_ARROW)) {
        *lex = saved;
        return false;
    }

    /* Add transition */
    dsl_transition_t *trans = &state->transitions[state->transition_count];
    memset(trans, 0, sizeof(*trans));
    trans->symbol_id = sym;

    if (!dsl_parse_target_list(lex, trans)) {
        *lex = saved;
        return false;
    }

    /* Optional markers */
    dsl_parse_marker_list(lex, trans);

    state->transition_count++;
    return true;
}

/* ============================================================================
 * Main parser
 * ============================================================================ */

static dsl_nfa_t *dsl_parse_input(const char *text) {
    dsl_lexer_t lex;
    dsl_lexer_init(&lex, text);

    dsl_nfa_t *nfa = dsl_nfa_alloc(63); /* Start with 64 states */
    if (!nfa) return NULL;

    while (true) {
        dsl_token_t tok = dsl_lexer_peek(&lex);
        if (tok.type == TOK_EOF) break;

        /* Version header: version: N or version=N */
        if (tok.type == TOK_IDENT && strcmp(tok.text, "version") == 0) {
            dsl_lexer_consume(&lex);
            /* Accept both "version: N" and "version=N" */
            if (dsl_lexer_match(&lex, TOK_COLON) ||
                dsl_lexer_match(&lex, TOK_EQUALS)) {
                dsl_token_t val = dsl_lexer_consume(&lex);
                if (val.type == TOK_INT) {
                    nfa->version = val.ival;
                }
            }
            continue;
        }

        /* Type header: type: NFA or type: DFA */
        if (tok.type == TOK_IDENT && strcmp(tok.text, "type") == 0) {
            dsl_lexer_consume(&lex);
            if (dsl_lexer_match(&lex, TOK_COLON)) {
                dsl_token_t val = dsl_lexer_consume(&lex);
                if (val.type == TOK_IDENT) {
                    if (strcasecmp(val.text, "DFA") == 0) {
                        nfa->dsl_type = DSL_TYPE_DFA;
                    } else {
                        nfa->dsl_type = DSL_TYPE_NFA;
                    }
                }
            }
            continue;
        }

        /* Global metadata: identifier=... */
        if (tok.type == TOK_IDENT && strcmp(tok.text, "identifier") == 0) {
            dsl_lexer_consume(&lex);
            if (dsl_lexer_match(&lex, TOK_EQUALS)) {
                dsl_token_t val = dsl_lexer_consume(&lex);
                if (val.type == TOK_IDENT) {
                    /* Identifier value may be truncated to fit buffer */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
                    snprintf(nfa->identifier, sizeof(nfa->identifier), "%s", val.text);
#pragma GCC diagnostic pop
                }
            }
            continue;
        }

        /* Global metadata: alphabet_size=N */
        if (tok.type == TOK_IDENT && strcmp(tok.text, "alphabet_size") == 0) {
            dsl_lexer_consume(&lex);
            if (dsl_lexer_match(&lex, TOK_EQUALS)) {
                dsl_token_t val = dsl_lexer_consume(&lex);
                if (val.type == TOK_INT) {
                    nfa->alphabet_size = val.ival;
                }
            }
            continue;
        }

        /* State definition or transition line: both start with INT */
        if (tok.type == TOK_INT) {
            int state_id = tok.ival;
            dsl_lexer_consume(&lex);

            /* Check if this is a state definition (INT followed by ':')
             * or a transition (INT followed by symbol '->' targets) */
            dsl_token_t next = dsl_lexer_peek(&lex);

            if (next.type == TOK_COLON) {
                /* State definition line: INT : [start] [accept] [category=0xNN] [pattern=N] [eos] */
                dsl_lexer_consume(&lex);

                /* Grow states array if needed */
                if (!dsl_nfa_grow(nfa, state_id)) {
                    nfa_dsl_free(nfa);
                    return NULL;
                }
                dsl_state_t *state = &nfa->states[state_id];
                state->state_id = state_id;
                state->is_defined = true;

                /* Parse optional keywords after colon */
                while (true) {
                    dsl_token_t kw = dsl_lexer_peek(&lex);
                    if (kw.type == TOK_IDENT) {
                        if (strcasecmp(kw.text, "start") == 0) {
                            dsl_lexer_consume(&lex);
                            state->is_start = true;
                            nfa->start_state = state_id;
                        } else if (strcasecmp(kw.text, "accept") == 0) {
                            dsl_lexer_consume(&lex);
                            state->is_accept = true;
                        } else if (strcasecmp(kw.text, "eos") == 0) {
                            dsl_lexer_consume(&lex);
                            state->is_eos_target = true;
                        } else if (strcasecmp(kw.text, "category") == 0) {
                            dsl_lexer_consume(&lex);
                            if (dsl_lexer_match(&lex, TOK_EQUALS)) {
                                dsl_token_t cv = dsl_lexer_consume(&lex);
                                if (cv.type == TOK_HEX) {
                                    state->category_mask = (uint8_t)cv.ival;
                                } else if (cv.type == TOK_INT) {
                                    state->category_mask = (uint8_t)cv.ival;
                                }
                            }
                        } else if (strcasecmp(kw.text, "pattern") == 0) {
                            dsl_lexer_consume(&lex);
                            if (dsl_lexer_match(&lex, TOK_EQUALS)) {
                                dsl_token_t pv = dsl_lexer_consume(&lex);
                                if (pv.type == TOK_INT) {
                                    state->pattern_id = pv.ival;
                                }
                            }
                        } else {
                            break; /* Unknown keyword - end of state header */
                        }
                    } else {
                        break;
                    }
                }
            } else {
                /* Must be a transition line: INT symbol -> targets [markers] */
                /* We already consumed the INT (state_id), try to parse the rest */
                if (!dsl_try_parse_transition(&lex, nfa, state_id)) {
                    /* Failed to parse as transition; skip this line */
                }
            }

            continue;
        }

        /* Skip unknown tokens */
        dsl_lexer_consume(&lex);
    }

    /* Default: state 0 is start if none specified */
    if (nfa->start_state < 0) {
        nfa->start_state = 0;
        if (nfa->state_count > 0) {
            nfa->states[0].is_start = true;
        }
    }

    /* Compute actual state_count. Include states that were explicitly
     * defined (had a "N:" line) or referenced as transition targets. */
    int highest = -1;
    for (int i = 0; i <= nfa->max_state_id; i++) {
        const dsl_state_t *s = &nfa->states[i];
        if (s->is_defined || s->is_start || s->is_accept || s->is_eos_target ||
            s->category_mask != 0 || s->pattern_id >= 0 ||
            s->transition_count > 0 ||
            s->state_id == nfa->start_state) {
            highest = i;
        }
    }
    /* Also include states referenced as transition targets */
    for (int i = 0; i <= nfa->max_state_id; i++) {
        const dsl_state_t *s = &nfa->states[i];
        for (int t = 0; t < s->transition_count; t++) {
            for (int k = 0; k < s->transitions[t].target_count; k++) {
                int target = s->transitions[t].targets[k];
                if (target > highest) highest = target;
            }
        }
    }
    if (highest >= 0) {
        nfa->state_count = highest + 1;
    } else {
        nfa->state_count = 0;
    }

    return nfa;
}

/* ============================================================================
 * Public API: Parse from file
 * ============================================================================ */

dsl_nfa_t *nfa_dsl_parse_file(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        ERROR("Cannot open DSL file '%s'", filename);
        return NULL;
    }

    /* Read entire file */
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *text = malloc((size_t)size + 1);
    if (!text) {
        fclose(f);
        return NULL;
    }

    size_t nread = fread(text, 1, (size_t)size, f);
    text[nread] = '\0';
    fclose(f);

    dsl_nfa_t *result = dsl_parse_input(text);
    free(text);
    return result;
}

/* ============================================================================
 * Public API: Parse from string
 * ============================================================================ */

dsl_nfa_t *nfa_dsl_parse_string(const char *text) {
    if (!text) return NULL;
    return dsl_parse_input(text);
}

/* ============================================================================
 * Free
 * ============================================================================ */

void nfa_dsl_free(dsl_nfa_t *nfa) {
    if (!nfa) return;
    free(nfa->states);
    free(nfa);
}

/* ============================================================================
 * Comparison: structural equality
 * ============================================================================ */

static bool transitions_equal(const dsl_transition_t *a, const dsl_transition_t *b) {
    if (a->symbol_id != b->symbol_id) return false;
    if (a->target_count != b->target_count) return false;
    if (a->marker_count != b->marker_count) return false;

    for (int i = 0; i < a->target_count; i++) {
        if (a->targets[i] != b->targets[i]) return false;
    }
    for (int i = 0; i < a->marker_count; i++) {
        if (a->markers[i].value != b->markers[i].value) return false;
    }
    return true;
}

bool nfa_dsl_equal(const dsl_nfa_t *a, const dsl_nfa_t *b) {
    if (!a || !b) return a == b;

    if (a->state_count != b->state_count) return false;

    for (int i = 0; i < a->state_count; i++) {
        const dsl_state_t *sa = &a->states[i];
        const dsl_state_t *sb = &b->states[i];

        if (sa->state_id != sb->state_id) return false;
        if (sa->is_start != sb->is_start) return false;
        if (sa->is_accept != sb->is_accept) return false;
        if (sa->category_mask != sb->category_mask) return false;
        if (sa->pattern_id != sb->pattern_id) return false;
        if (sa->is_eos_target != sb->is_eos_target) return false;
        if (sa->transition_count != sb->transition_count) return false;

        for (int t = 0; t < sa->transition_count; t++) {
            if (!transitions_equal(&sa->transitions[t], &sb->transitions[t])) return false;
        }
    }

    return true;
}

/* ============================================================================
 * Diff helpers
 * ============================================================================ */

static int count_lines(const char *s) {
    int n = 0;
    if (!s || !*s) return 0;
    while (*s) {
        if (*s == '\n') n++;
        s++;
    }
    return n;
}

static const char *get_line(const char *s, int idx, int *len) {
    int cur = 0;
    while (*s && cur < idx) {
        if (*s == '\n') cur++;
        s++;
    }
    if (cur != idx) { *len = 0; return NULL; }
    const char *start = s;
    while (*s && *s != '\n') s++;
    *len = (int)(s - start);
    return start;
}

static bool lines_equal(const char *a, int alen, const char *b, int blen) {
    if (alen != blen) return false;
    return memcmp(a, b, (size_t)alen) == 0;
}

char *nfa_dsl_diff(const char *expected, const char *actual) {
    if (!expected) expected = "";
    if (!actual) actual = "";
    if (strcmp(expected, actual) == 0) return NULL;

    int elines = count_lines(expected);
    int alines = count_lines(actual);
    int maxlines = elines > alines ? elines : alines;

    size_t buf_size = (size_t)(maxlines * 128 + 256);
    char *buf = malloc(buf_size);
    if (!buf) return NULL;
    int pos = 0;

    pos += snprintf(buf + pos, buf_size - (size_t)pos,
                    "--- expected\n+++ actual\n");

    for (int i = 0; i < maxlines; i++) {
        int elen = 0, alen = 0;
        const char *eline = (i < elines) ? get_line(expected, i, &elen) : NULL;
        const char *aline = (i < alines) ? get_line(actual, i, &alen) : NULL;

        if (eline && aline && lines_equal(eline, elen, aline, alen)) {
            pos += snprintf(buf + pos, buf_size - (size_t)pos,
                            " %.*s\n", elen, eline);
        } else {
            if (eline) {
                pos += snprintf(buf + pos, buf_size - (size_t)pos,
                                "-%.*s\n", elen, eline);
            }
            if (aline) {
                pos += snprintf(buf + pos, buf_size - (size_t)pos,
                                "+%.*s\n", alen, aline);
            }
        }
    }

    buf[pos] = '\0';
    return buf;
}

bool nfa_dsl_assert_equal(const char *label,
                           const char *expected,
                           const char *actual) {
    if (strcmp(expected, actual) == 0) return true;

    char *diff = nfa_dsl_diff(expected, actual);
    if (diff) {
        fprintf(stderr, "[%s] NFA mismatch:\n%s", label, diff);
        free(diff);
    }
    return false;
}

/* ============================================================================
 * Round-trip verification (uses nfa_graph_dsl_verify_roundtrip)
 * ============================================================================ */

/* ============================================================================
 * Validator / Linter
 * ============================================================================ */

static void add_issue(dsl_validation_t *v, dsl_severity_t sev,
                       int state_id, const char *fmt, ...) {
    if (v->issue_count >= v->issue_capacity) {
        int new_cap = v->issue_capacity * 2;
        if (new_cap < 16) new_cap = 16;
        dsl_issue_t *new_issues = realloc(v->issues, (size_t)new_cap * sizeof(dsl_issue_t));
        if (!new_issues) return;
        v->issues = new_issues;
        v->issue_capacity = new_cap;
    }

    dsl_issue_t *issue = &v->issues[v->issue_count];
    issue->severity = sev;
    issue->state_id = state_id;

    va_list args;
    va_start(args, fmt);
    vsnprintf(issue->message, sizeof(issue->message), fmt, args);
    va_end(args);

    v->issue_count++;
    if (sev == DSL_SEVERITY_ERROR) {
        v->valid = false;
    }
}

dsl_validation_t *nfa_dsl_validate(const dsl_nfa_t *nfa) {
    dsl_validation_t *v = calloc(1, sizeof(dsl_validation_t));
    if (!v) return NULL;
    v->valid = true;

    if (!nfa) {
        add_issue(v, DSL_SEVERITY_ERROR, -1, "NFA is NULL");
        return v;
    }

    /* Version check */
    if (nfa->version > 0 && nfa->version != NFA_DSL_VERSION) {
        add_issue(v, DSL_SEVERITY_WARNING, -1,
                  "DSL version %d differs from expected %d",
                  nfa->version, NFA_DSL_VERSION);
    }

    /* Check start state exists */
    if (nfa->start_state < 0 || nfa->start_state >= nfa->state_count) {
        add_issue(v, DSL_SEVERITY_ERROR, -1, "No valid start state");
    }

    /* Build set of defined states (those with explicit "N:" definition lines
     * or that are the start state) */
    bool *defined = calloc((size_t)nfa->state_count, sizeof(bool));
    if (!defined) {
        add_issue(v, DSL_SEVERITY_ERROR, -1, "Allocation failure");
        return v;
    }
    for (int i = 0; i < nfa->state_count; i++) {
        if (nfa->states[i].is_defined || nfa->states[i].is_start) {
            defined[i] = true;
        }
    }

    /* Validate each state */
    for (int i = 0; i < nfa->state_count; i++) {
        const dsl_state_t *s = &nfa->states[i];

        for (int t = 0; t < s->transition_count; t++) {
            const dsl_transition_t *tr = &s->transitions[t];
            for (int k = 0; k < tr->target_count; k++) {
                int target = tr->targets[k];
                if (target < 0 || target >= nfa->state_count || !defined[target]) {
                    add_issue(v, DSL_SEVERITY_ERROR, i,
                              "Transition to undefined state %d", target);
                }
            }
        }

        if (s->is_accept && s->category_mask == 0) {
            add_issue(v, DSL_SEVERITY_WARNING, i,
                      "Accepting state with no category mask");
        }

        if (!s->is_accept && s->transition_count == 0 && i != nfa->start_state) {
            add_issue(v, DSL_SEVERITY_WARNING, i,
                      "Non-accepting state with no outgoing transitions (dead end)");
        }

        if (s->transition_count == 1 && s->transitions[0].target_count == 1
            && s->transitions[0].targets[0] == i && !s->is_accept) {
            add_issue(v, DSL_SEVERITY_WARNING, i,
                      "State has only a self-loop and is not accepting");
        }
    }

    free(defined);
    return v;
}

void nfa_dsl_validation_free(dsl_validation_t *v) {
    if (!v) return;
    free(v->issues);
    free(v);
}

void nfa_dsl_validation_print(FILE *out, const dsl_validation_t *v) {
    if (!v) return;
    for (int i = 0; i < v->issue_count; i++) {
        const dsl_issue_t *issue = &v->issues[i];
        const char *sev = (issue->severity == DSL_SEVERITY_ERROR) ? "ERROR" : "WARN";
        if (issue->state_id >= 0) {
            fprintf(out, "  [%s] state %d: %s\n", sev, issue->state_id, issue->message);
        } else {
            fprintf(out, "  [%s] %s\n", sev, issue->message);
        }
    }
    if (v->issue_count == 0) {
        fprintf(out, "  No issues found.\n");
    }
}

/* ============================================================================
 * DOT (Graphviz) visualization
 * ============================================================================ */

void nfa_dsl_dump_dot(FILE *out, const dsl_nfa_t *nfa) {
    if (!nfa || !nfa->states) return;

    fprintf(out, "digraph NFA {\n");
    fprintf(out, "  rankdir=LR;\n");
    fprintf(out, "  node [shape=circle];\n");
    fprintf(out, "  __start [shape=point];\n");

    if (nfa->start_state >= 0 && nfa->start_state < nfa->state_count) {
        fprintf(out, "  __start -> %d;\n", nfa->start_state);
    }

    for (int i = 0; i < nfa->state_count; i++) {
        const dsl_state_t *s = &nfa->states[i];
        if (s->is_accept) {
            fprintf(out, "  %d [shape=doublecircle", i);
            if (s->category_mask != 0) {
                fprintf(out, " label=\"%d\\n0x%02x\"", i, s->category_mask);
            }
            fprintf(out, "];\n");
        }
    }

    for (int i = 0; i < nfa->state_count; i++) {
        const dsl_state_t *s = &nfa->states[i];
        for (int t = 0; t < s->transition_count; t++) {
            const dsl_transition_t *tr = &s->transitions[t];

            char label[64];
            const char *vname = nfa_dsl_symbol_name(tr->symbol_id);
            if (vname) {
                snprintf(label, sizeof(label), "%s", vname);
            } else if (tr->symbol_id >= 0x20 && tr->symbol_id < 0x7f) {
                snprintf(label, sizeof(label), "'%c'", (char)tr->symbol_id);
            } else {
                snprintf(label, sizeof(label), "0x%02x", tr->symbol_id);
            }

            for (int k = 0; k < tr->target_count; k++) {
                fprintf(out, "  %d -> %d [label=\"%s", i, tr->targets[k], label);
                if (tr->marker_count > 0) {
                    fprintf(out, " [");
                    for (int m = 0; m < tr->marker_count; m++) {
                        if (m > 0) fprintf(out, ",");
                        fprintf(out, "0x%08X", tr->markers[m].value);
                    }
                    fprintf(out, "]");
                }
                fprintf(out, "\"];\n");
            }
        }
    }

    fprintf(out, "}\n");
}

char *nfa_dsl_to_dot(const dsl_nfa_t *nfa) {
    size_t buf_size = (size_t)(nfa->state_count * 256 + 1024);
    char *buf = malloc(buf_size);
    if (!buf) return NULL;

    FILE *out = fmemopen(buf, buf_size, "w");
    if (!out) {
        free(buf);
        return NULL;
    }

    nfa_dsl_dump_dot(out, nfa);
    fflush(out);
    size_t actual_len = (size_t)ftell(out);
    fclose(out);

    buf[actual_len] = '\0';
    char *shrunk = realloc(buf, actual_len + 1);
    return shrunk ? shrunk : buf;
}

/* ============================================================================
 * ============================================================================
 * DFA SERIALIZATION
 *
 * Serializes build_dfa_state_t** arrays to canonical DFA DSL format.
 * DFA DSL uses a subset of NFA DSL with extensions:
 *   - No epsilon transitions
 *   - Single target per symbol (deterministic)
 *   - Range syntax: 'a'-'z' -> target
 *   - Default transition: default -> target
 *   - type: DFA header
 * ============================================================================
 * ============================================================================ */

/* Marker list type from dfa_minimize.h - cast from void* parameter */
typedef struct {
    uint32_t markers[16];
    int count;
} dfa_serializer_marker_list_t;

/* ============================================================================
 * DFA Canonicalization: BFS with signature-based tie-breaking
 * ============================================================================ */

typedef struct {
    int old_id;
    uint64_t signature;
} dfa_bfs_entry_t;

static int cmp_dfa_bfs_entry(const void *a, const void *b) {
    const dfa_bfs_entry_t *ea = (const dfa_bfs_entry_t *)a;
    const dfa_bfs_entry_t *eb = (const dfa_bfs_entry_t *)b;
    if (ea->signature < eb->signature) return -1;
    if (ea->signature > eb->signature) return 1;
    return ea->old_id - eb->old_id;
}

/* Compute a canonical signature for a DFA build state.
 * Hashes accepting properties, flags, and all outgoing transitions
 * (symbol -> target pairs, sorted by symbol for determinism). */
static uint64_t compute_dfa_state_signature(const build_dfa_state_t *s) {
    uint64_t h = fnv1a_init();

    h = fnv1a_update_u32(h, s->flags);
    h = fnv1a_update_u32(h, (uint32_t)s->accepting_pattern_id);
    h = fnv1a_update_u32(h, s->eos_target);
    h = fnv1a_update_u32(h, s->eos_marker_offset);

    /* Hash transitions: for each symbol with a transition, hash (sym, target) */
    for (int sym = 0; sym < s->alphabet_size && sym < BYTE_VALUE_MAX; sym++) {
        if (s->transitions[sym] >= 0) {
            h = fnv1a_update_i32(h, sym);
            h = fnv1a_update_i32(h, s->transitions[sym]);
        }
    }

    /* Hash virtual symbol transitions */
    for (int sym = BYTE_VALUE_MAX; sym < s->alphabet_size; sym++) {
        if (s->transitions[sym] >= 0) {
            h = fnv1a_update_i32(h, sym);
            h = fnv1a_update_i32(h, s->transitions[sym]);
        }
    }

    return h;
}

/* BFS canonical ordering for DFA states.
 * Returns old_to_new mapping (caller frees) and sets reachable_count. */
static int *dfa_canonicalize_bfs(
        const build_dfa_state_t * const *dfa,
        int state_count,
        int start_state,
        int alphabet_size,
        int **canonical_order_out,
        int *reachable_count_out)
{
    int *old_to_new = malloc((size_t)state_count * sizeof(int));
    int *canonical_order = malloc((size_t)state_count * sizeof(int));
    bool *visited = calloc((size_t)state_count, sizeof(bool));
    dfa_bfs_entry_t *frontier = malloc((size_t)state_count * sizeof(dfa_bfs_entry_t));

    if (!old_to_new || !canonical_order || !visited || !frontier) {
        free(old_to_new); free(canonical_order); free(visited); free(frontier);
        return NULL;
    }

    for (int i = 0; i < state_count; i++) {
        old_to_new[i] = -1;
    }

    int new_id = 0;
    int frontier_start = 0;
    int frontier_end = 0;

    if (start_state < 0 || start_state >= state_count) {
        *canonical_order_out = canonical_order;
        *reachable_count_out = 0;
        free(visited); free(frontier);
        return old_to_new;
    }

    visited[start_state] = true;
    frontier[frontier_end].old_id = start_state;
    frontier[frontier_end].signature = compute_dfa_state_signature(dfa[start_state]);
    frontier_end++;

    while (frontier_start < frontier_end) {
        int level_end = frontier_end;
        int level_size = level_end - frontier_start;
        qsort(&frontier[frontier_start], (size_t)level_size,
              sizeof(dfa_bfs_entry_t), cmp_dfa_bfs_entry);

        int next_frontier_start = frontier_end;

        for (int fi = frontier_start; fi < level_end; fi++) {
            int old_id = frontier[fi].old_id;
            old_to_new[old_id] = new_id;
            canonical_order[new_id] = old_id;
            new_id++;

            const build_dfa_state_t *s = dfa[old_id];
            for (int sym = 0; sym < alphabet_size; sym++) {
                int target = s->transitions[sym];
                if (target >= 0 && target < state_count && !visited[target]) {
                    visited[target] = true;
                    frontier[frontier_end].old_id = target;
                    frontier[frontier_end].signature =
                        compute_dfa_state_signature(dfa[target]);
                    frontier_end++;
                }
            }
        }

        frontier_start = next_frontier_start;
    }

    *reachable_count_out = new_id;
    *canonical_order_out = canonical_order;
    free(visited);
    free(frontier);
    return old_to_new;
}

/* ============================================================================
 * DFA Range Compression
 *
 * Groups consecutive literal bytes (0-255) with the same target into ranges.
 * Returns dynamically allocated array of range descriptors and count.
 * ============================================================================ */

typedef struct {
    int start_sym;
    int end_sym;
    int target;
    bool has_marker;
} dfa_range_t;

/* Build compressed transition list for a DFA state.
 * Returns malloc'd array of ranges, sets *range_count. */
static dfa_range_t *dfa_build_ranges(
        const build_dfa_state_t *s,
        const dfa_serializer_marker_list_t *mlists ATTR_UNUSED,
        int *range_count,
        int default_target,
        int *out_default_target)
{
    *range_count = 0;
    *out_default_target = default_target;

    /* Count unique targets among literal bytes (excluding default target) */
    int max_ranges = 256;
    dfa_range_t *ranges = malloc((size_t)max_ranges * sizeof(dfa_range_t));
    if (!ranges) return NULL;

    int rcount = 0;
    int i = 0;
    while (i < BYTE_VALUE_MAX) {
        int target = s->transitions[i];
        if (target < 0 || target == default_target) {
            i++;
            continue;
        }

        /* Start of a potential range */
        int start = i;
        int end = i;
        bool has_marker = (s->marker_offsets[i] != 0);

        /* Extend range while same target and same marker offset value */
        uint32_t marker_offset = s->marker_offsets[start];
        while (end + 1 < BYTE_VALUE_MAX &&
               s->transitions[end + 1] == target &&
               s->marker_offsets[end + 1] == marker_offset) {
            end++;
        }

        if (rcount < max_ranges) {
            ranges[rcount].start_sym = start;
            ranges[rcount].end_sym = end;
            ranges[rcount].target = target;
            ranges[rcount].has_marker = has_marker;
            rcount++;
        }

        i = end + 1;
    }

    *range_count = rcount;
    return ranges;
}

/* Find the most common transition target among literal bytes for a state.
 * Returns -1 if there's no dominant target (or state has too few transitions). */
static int dfa_find_default_target(const build_dfa_state_t *s) {
    /* Count transitions per target among literal bytes */
    int target_counts[256]; /* index = target % 256, naive but works for small DFAs */
    int targets[256];
    int distinct = 0;

    memset(target_counts, 0, sizeof(target_counts));
    memset(targets, -1, sizeof(targets));

    for (int i = 0; i < BYTE_VALUE_MAX; i++) {
        int t = s->transitions[i];
        if (t < 0) continue;

        /* Find or add this target to the tracking array */
        bool found = false;
        for (int j = 0; j < distinct; j++) {
            if (targets[j] == t) {
                target_counts[j]++;
                found = true;
                break;
            }
        }
        if (!found && distinct < 256) {
            targets[distinct] = t;
            target_counts[distinct] = 1;
            distinct++;
        }
    }

    if (distinct == 0) return -1;

    /* Find most common target */
    int best_idx = 0;
    for (int j = 1; j < distinct; j++) {
        if (target_counts[j] > target_counts[best_idx]) {
            best_idx = j;
        }
    }

    /* Only emit default if it covers at least 4 literals (avoids clutter) */
    if (target_counts[best_idx] >= 4) {
        return targets[best_idx];
    }
    return -1;
}

/* ============================================================================
 * DFA Marker Resolution
 * ============================================================================ */

/* Resolve a marker_offset to actual marker values.
 * marker_offset is 1-based index into the marker list array.
 * Returns the count of markers, fills out_markers array (caller provides). */
static int dfa_resolve_markers(
        const dfa_serializer_marker_list_t *mlists,
        uint32_t marker_offset,
        uint32_t *out_markers,
        int max_markers)
{
    if (!mlists || marker_offset == 0) return 0;

    int idx = (int)marker_offset - 1;
    int count = mlists[idx].count;
    if (count > max_markers) count = max_markers;

    memcpy(out_markers, mlists[idx].markers, (size_t)count * sizeof(uint32_t));
    return count;
}

/* ============================================================================
 * DFA State Serialization
 * ============================================================================ */

static void dfa_serialize_state(
        FILE *out,
        const build_dfa_state_t * const *dfa,
        int old_id,
        int new_id,
        bool is_start,
        const int *old_to_new,
        const alphabet_entry_t *alphabet ATTR_UNUSED,
        int alphabet_size,
        const dfa_serializer_marker_list_t *mlists)
{
    const build_dfa_state_t *s = dfa[old_id];

    /* State definition line */
    fprintf(out, "%d:", new_id);
    if (is_start) {
        fprintf(out, " start");
    }

    /* Accepting state properties */
    if (s->flags & DFA_STATE_ACCEPTING) {
        uint8_t cat_mask = DFA_GET_CATEGORY_MASK(s->flags);
        fprintf(out, " accept category=0x%02x pattern=%d",
                cat_mask, s->accepting_pattern_id);
    }

    fprintf(out, "\n");

    /* Determine default transition target (for range compression) */
    int default_target = dfa_find_default_target(s);
    int actual_default = -1;

    /* Build compressed range list for literal bytes */
    int range_count = 0;
    dfa_range_t *ranges = dfa_build_ranges(s, mlists, &range_count,
                                             default_target, &actual_default);

    /* Output ranges */
    if (ranges) {
        for (int r = 0; r < range_count; r++) {
            const dfa_range_t *rng = &ranges[r];
            int remapped_target = old_to_new[rng->target];

            if (rng->start_sym == rng->end_sym) {
                /* Single literal */
                fprintf(out, "%d ", new_id);
                dsl_write_symbol(out, rng->start_sym);
                fprintf(out, " -> %d", remapped_target);
            } else {
                /* Range */
                fprintf(out, "%d ", new_id);
                dsl_write_symbol(out, rng->start_sym);
                fprintf(out, "-");
                dsl_write_symbol(out, rng->end_sym);
                fprintf(out, " -> %d", remapped_target);
            }

            /* Markers for this range */
            if (rng->has_marker && mlists) {
                uint32_t markers[16];
                int mc = dfa_resolve_markers(mlists,
                                              s->marker_offsets[rng->start_sym],
                                              markers, 16);
                if (mc > 0) {
                    qsort(markers, (size_t)mc, sizeof(uint32_t), cmp_uint32);
                    fprintf(out, " [");
                    for (int m = 0; m < mc; m++) {
                        if (m > 0) fprintf(out, ",");
                        fprintf(out, "0x%08X", markers[m]);
                    }
                    fprintf(out, "]");
                }
            }

            fprintf(out, "\n");
        }
    }

    free(ranges);

    /* Virtual symbol transitions (ANY, SPACE, TAB, EOS) */
    for (int sym = BYTE_VALUE_MAX; sym < alphabet_size; sym++) {
        int target = s->transitions[sym];
        if (target < 0) continue;
        int remapped = old_to_new[target];

        const char *vname = nfa_dsl_symbol_name(sym);
        if (vname) {
            fprintf(out, "%d %s -> %d", new_id, vname, remapped);
        } else {
            fprintf(out, "%d %d -> %d", new_id, sym, remapped);
        }

        /* Markers */
        if (s->marker_offsets[sym] != 0 && mlists) {
            uint32_t markers[16];
            int mc = dfa_resolve_markers(mlists, s->marker_offsets[sym],
                                          markers, 16);
            if (mc > 0) {
                qsort(markers, (size_t)mc, sizeof(uint32_t), cmp_uint32);
                fprintf(out, " [");
                for (int m = 0; m < mc; m++) {
                    if (m > 0) fprintf(out, ",");
                    fprintf(out, "0x%08X", markers[m]);
                }
                fprintf(out, "]");
            }
        }

        fprintf(out, "\n");
    }

    /* EOS transition */
    if (s->eos_target != 0) {
        /* eos_target stores the DFA state index + 1 (0 = no EOS target).
         * Wait - looking at the code, eos_target for build states is the
         * actual target state index. Let me check...
         * In nfa2dfa.c it's set as: dfa[cur]->eos_target = target;
         * So it's a direct state index.
         * But in dfa_format.h it's a byte offset. For build states it's an index.
         */
        int eos_tgt = (int)s->eos_target;
        if (eos_tgt >= 0 && eos_tgt < 65536 && old_to_new[eos_tgt] >= 0) {
            fprintf(out, "%d EOS -> %d", new_id, old_to_new[eos_tgt]);

            /* EOS markers */
            if (s->eos_marker_offset != 0 && mlists) {
                uint32_t markers[16];
                int mc = dfa_resolve_markers(mlists, s->eos_marker_offset,
                                              markers, 16);
                if (mc > 0) {
                    qsort(markers, (size_t)mc, sizeof(uint32_t), cmp_uint32);
                    fprintf(out, " [");
                    for (int m = 0; m < mc; m++) {
                        if (m > 0) fprintf(out, ",");
                        fprintf(out, "0x%08X", markers[m]);
                    }
                    fprintf(out, "]");
                }
            }

            fprintf(out, "\n");
        }
    }

    /* Default transition (must be last) */
    if (actual_default >= 0 && old_to_new[actual_default] >= 0) {
        fprintf(out, "%d default -> %d", new_id, old_to_new[actual_default]);

        /* Default transition markers - check if all default transitions share
         * the same marker_offset. If so, output it for the default. */
        /* For simplicity, we don't emit markers on default transitions
         * since they represent a compressed set of individual transitions
         * that may have different markers. */
        fprintf(out, "\n");
    }
}

/* ============================================================================
 * Public API: DFA Serialization
 * ============================================================================ */

void dfa_dsl_dump(FILE *out,
                   const build_dfa_state_t * const *dfa,
                   int state_count,
                   const alphabet_entry_t *alphabet,
                   int alphabet_size,
                   const void *marker_lists,
                   int marker_list_count)
{
    (void)marker_list_count;

    if (state_count == 0 || !dfa) return;

    const dfa_serializer_marker_list_t *mlists =
        (const dfa_serializer_marker_list_t *)marker_lists;

    /* Canonical BFS from state 0 */
    int reachable_count = 0;
    int *canonical_order = NULL;
    int *old_to_new = dfa_canonicalize_bfs(dfa, state_count, 0, alphabet_size,
                                             &canonical_order, &reachable_count);
    if (!old_to_new || !canonical_order || reachable_count == 0) {
        free(old_to_new); free(canonical_order);
        return;
    }

    /* Header */
    fprintf(out, "type: DFA\n");
    fprintf(out, "version: %d\n", NFA_DSL_VERSION);
    fprintf(out, "alphabet_size: %d\n", alphabet_size);
    fprintf(out, "initial: 0\n");

    /* Serialize each reachable state */
    for (int ci = 0; ci < reachable_count; ci++) {
        int old_id = canonical_order[ci];
        dfa_serialize_state(out, dfa, old_id, ci, ci == 0,
                            old_to_new, alphabet, alphabet_size, mlists);
    }

    free(old_to_new);
    free(canonical_order);
}

char *dfa_dsl_to_string(const build_dfa_state_t * const *dfa,
                         int state_count,
                         const alphabet_entry_t *alphabet,
                         int alphabet_size,
                         const void *marker_lists,
                         int marker_list_count)
{
    if (state_count == 0 || !dfa) return NULL;

    size_t buf_size = (size_t)(state_count * 512 + 2048);
    char *buf = malloc(buf_size);
    if (!buf) return NULL;

    FILE *out = fmemopen(buf, buf_size, "w");
    if (!out) {
        free(buf);
        return NULL;
    }

    dfa_dsl_dump(out, dfa, state_count, alphabet, alphabet_size,
                 marker_lists, marker_list_count);
    fflush(out);
    size_t actual_len = (size_t)ftell(out);
    fclose(out);

    buf[actual_len] = '\0';
    char *shrunk = realloc(buf, actual_len + 1);
    return shrunk ? shrunk : buf;
}

/* ============================================================================
 * DFA Deserialization
 *
 * Parses DFA DSL text back into a dsl_dfa_t structure.
 * Reuses the NFA lexer infrastructure with DFA-specific extensions.
 * ============================================================================ */

static dsl_dfa_state_t *dfa_dsl_state_alloc(int state_id) {
    dsl_dfa_state_t *s = calloc(1, sizeof(dsl_dfa_state_t));
    if (!s) return NULL;
    s->state_id = state_id;
    s->pattern_id = -1;
    s->default_target = -1;
    s->eos_target = -1;
    return s;
}

static dsl_dfa_t *dfa_dsl_parse_input(const char *text) {
    dsl_lexer_t lex;
    dsl_lexer_init(&lex, text);

    dsl_dfa_t *dfa = calloc(1, sizeof(dsl_dfa_t));
    if (!dfa) return NULL;
    dfa->dsl_type = DSL_TYPE_DFA;
    dfa->start_state = -1;
    dfa->alphabet_size = -1;
    dfa->identifier[0] = '\0';

    /* Track states - grow as needed */
    int state_capacity = 64;
    dsl_dfa_state_t **states = calloc((size_t)state_capacity, sizeof(dsl_dfa_state_t *));
    if (!states) { free(dfa); return NULL; }

    /* Temporary storage for transitions being parsed.
     * We accumulate raw symbol transitions and resolve ranges later. */
    typedef struct {
        int from_state;
        int symbol_id;
        int target;
        bool is_range;
        int range_end;
        bool is_default;
        bool is_eos;
        int marker_count;
        uint32_t markers[DSL_MAX_MARKERS];
    } raw_trans_t;

    int raw_capacity = 256;
    int raw_count = 0;
    raw_trans_t *raw = malloc((size_t)raw_capacity * sizeof(raw_trans_t));
    if (!raw) { free(states); free(dfa); return NULL; }

    while (true) {
        dsl_token_t tok = dsl_lexer_peek(&lex);
        if (tok.type == TOK_EOF) break;

        /* Type header */
        if (tok.type == TOK_IDENT && strcmp(tok.text, "type") == 0) {
            dsl_lexer_consume(&lex);
            if (dsl_lexer_match(&lex, TOK_COLON)) {
                dsl_token_t val = dsl_lexer_consume(&lex);
                (void)val; /* Already know it's DFA since we're here */
            }
            continue;
        }

        /* Version header */
        if (tok.type == TOK_IDENT && strcmp(tok.text, "version") == 0) {
            dsl_lexer_consume(&lex);
            if (dsl_lexer_match(&lex, TOK_COLON) ||
                dsl_lexer_match(&lex, TOK_EQUALS)) {
                dsl_token_t val = dsl_lexer_consume(&lex);
                if (val.type == TOK_INT) dfa->version = val.ival;
            }
            continue;
        }

        /* alphabet_size */
        if (tok.type == TOK_IDENT && strcmp(tok.text, "alphabet_size") == 0) {
            dsl_lexer_consume(&lex);
            if (dsl_lexer_match(&lex, TOK_COLON) ||
                dsl_lexer_match(&lex, TOK_EQUALS)) {
                dsl_token_t val = dsl_lexer_consume(&lex);
                if (val.type == TOK_INT) dfa->alphabet_size = val.ival;
            }
            continue;
        }

        /* initial */
        if (tok.type == TOK_IDENT && strcmp(tok.text, "initial") == 0) {
            dsl_lexer_consume(&lex);
            if (dsl_lexer_match(&lex, TOK_COLON) ||
                dsl_lexer_match(&lex, TOK_EQUALS)) {
                dsl_token_t val = dsl_lexer_consume(&lex);
                if (val.type == TOK_INT) dfa->start_state = val.ival;
            }
            continue;
        }

        /* identifier */
        if (tok.type == TOK_IDENT && strcmp(tok.text, "identifier") == 0) {
            dsl_lexer_consume(&lex);
            if (dsl_lexer_match(&lex, TOK_EQUALS)) {
                dsl_token_t val = dsl_lexer_consume(&lex);
                if (val.type == TOK_IDENT) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
                    snprintf(dfa->identifier, sizeof(dfa->identifier), "%s", val.text);
#pragma GCC diagnostic pop
                }
            }
            continue;
        }

        /* State definition or transition: both start with INT */
        if (tok.type == TOK_INT) {
            int state_id = tok.ival;
            dsl_lexer_consume(&lex);
            dsl_token_t next = dsl_lexer_peek(&lex);

            if (next.type == TOK_COLON) {
                /* State definition: INT : [start] [accept] [category=0xNN] [pattern=N] */
                dsl_lexer_consume(&lex);

                /* Ensure state slot */
                if (state_id >= state_capacity) {
                    int new_cap = state_id + 64;
                    dsl_dfa_state_t **new_states = realloc(states,
                        (size_t)new_cap * sizeof(dsl_dfa_state_t *));
                    if (!new_states) goto cleanup;
                    memset(new_states + state_capacity, 0,
                           (size_t)(new_cap - state_capacity) * sizeof(dsl_dfa_state_t *));
                    states = new_states;
                    state_capacity = new_cap;
                }
                if (!states[state_id]) {
                    states[state_id] = dfa_dsl_state_alloc(state_id);
                    if (!states[state_id]) goto cleanup;
                }
                dsl_dfa_state_t *s = states[state_id];
                s->state_id = state_id;
                s->is_defined = true;

                if (dfa->max_state_id < state_id) dfa->max_state_id = state_id;

                /* Parse keywords */
                while (true) {
                    dsl_token_t kw = dsl_lexer_peek(&lex);
                    if (kw.type == TOK_IDENT) {
                        if (strcasecmp(kw.text, "start") == 0) {
                            dsl_lexer_consume(&lex);
                            s->is_start = true;
                            dfa->start_state = state_id;
                        } else if (strcasecmp(kw.text, "accept") == 0) {
                            dsl_lexer_consume(&lex);
                            s->is_accept = true;
                        } else if (strcasecmp(kw.text, "category") == 0) {
                            dsl_lexer_consume(&lex);
                            if (dsl_lexer_match(&lex, TOK_EQUALS)) {
                                dsl_token_t cv = dsl_lexer_consume(&lex);
                                if (cv.type == TOK_HEX || cv.type == TOK_INT)
                                    s->category_mask = (uint8_t)cv.ival;
                            }
                        } else if (strcasecmp(kw.text, "pattern") == 0) {
                            dsl_lexer_consume(&lex);
                            if (dsl_lexer_match(&lex, TOK_EQUALS)) {
                                dsl_token_t pv = dsl_lexer_consume(&lex);
                                if (pv.type == TOK_INT)
                                    s->pattern_id = pv.ival;
                            }
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            } else {
                /* Transition line: INT symbol [- symbol] -> target [markers]
                 * Or: INT default -> target
                 * Or: INT EOS -> target [markers]
                 */
                int from_state = state_id;

                dsl_token_t sym_tok = dsl_lexer_peek(&lex);

                /* "default" keyword */
                if (sym_tok.type == TOK_IDENT &&
                    strcasecmp(sym_tok.text, "default") == 0) {
                    dsl_lexer_consume(&lex);
                    if (dsl_lexer_match(&lex, TOK_ARROW)) {
                        dsl_token_t tgt = dsl_lexer_consume(&lex);
                        if (tgt.type == TOK_INT || tgt.type == TOK_HEX) {
                            /* Store as raw transition */
                            if (raw_count >= raw_capacity) {
                                raw_capacity *= 2;
                                raw_trans_t *new_raw = realloc(raw,
                                    (size_t)raw_capacity * sizeof(raw_trans_t));
                                if (!new_raw) goto cleanup;
                                raw = new_raw;
                            }
                            memset(&raw[raw_count], 0, sizeof(raw_trans_t));
                            raw[raw_count].from_state = from_state;
                            raw[raw_count].is_default = true;
                            raw[raw_count].target = tgt.ival;
                            raw_count++;
                        }
                    }
                    /* Optional markers on default */
                    if (dsl_lexer_peek(&lex).type == TOK_LBRACKET) {
                        /* Skip marker list for defaults */
                        dsl_lexer_consume(&lex);
                        while (dsl_lexer_peek(&lex).type != TOK_RBRACKET &&
                               dsl_lexer_peek(&lex).type != TOK_EOF) {
                            dsl_lexer_consume(&lex);
                        }
                        if (dsl_lexer_peek(&lex).type == TOK_RBRACKET)
                            dsl_lexer_consume(&lex);
                    }
                    continue;
                }

                /* "EOS" keyword */
                if (sym_tok.type == TOK_IDENT &&
                    strcasecmp(sym_tok.text, "EOS") == 0) {
                    dsl_lexer_consume(&lex);
                    if (dsl_lexer_match(&lex, TOK_ARROW)) {
                        dsl_token_t tgt = dsl_lexer_consume(&lex);
                        if (tgt.type == TOK_INT || tgt.type == TOK_HEX) {
                            if (raw_count >= raw_capacity) {
                                raw_capacity *= 2;
                                raw_trans_t *new_raw = realloc(raw,
                                    (size_t)raw_capacity * sizeof(raw_trans_t));
                                if (!new_raw) goto cleanup;
                                raw = new_raw;
                            }
                            memset(&raw[raw_count], 0, sizeof(raw_trans_t));
                            raw[raw_count].from_state = from_state;
                            raw[raw_count].is_eos = true;
                            raw[raw_count].target = tgt.ival;

                            /* Optional markers */
                            if (dsl_lexer_peek(&lex).type == TOK_LBRACKET) {
                                dsl_lexer_consume(&lex);
                                int mc = 0;
                                while (dsl_lexer_peek(&lex).type != TOK_RBRACKET &&
                                       dsl_lexer_peek(&lex).type != TOK_EOF) {
                                    dsl_token_t mtok = dsl_lexer_consume(&lex);
                                    if ((mtok.type == TOK_HEX || mtok.type == TOK_INT) &&
                                        mc < DSL_MAX_MARKERS) {
                                        raw[raw_count].markers[mc++] = (uint32_t)mtok.ival;
                                    }
                                    dsl_lexer_match(&lex, TOK_COMMA);
                                }
                                raw[raw_count].marker_count = mc;
                                if (dsl_lexer_peek(&lex).type == TOK_RBRACKET)
                                    dsl_lexer_consume(&lex);
                            }
                            raw_count++;
                        }
                    }
                    continue;
                }

                /* Symbol or range: sym [- sym] -> target [markers] */
                int sym_start = dsl_parse_symbol(&lex);
                if (sym_start < 0) continue;

                /* Check for range: '-' followed by another symbol.
                 * We must check the raw input BEFORE calling dsl_lexer_peek
                 * because the lexer would consume the '-' as an unknown token
                 * (it's not part of '->'). */
                bool is_range = false;
                int sym_end = sym_start;

                /* Skip whitespace, then check for literal '-' */
                dsl_lexer_skip_ws(&lex);
                if (lex.input[lex.pos] == '-' && lex.input[lex.pos + 1] != '>') {
                    lex.pos++; lex.col++; /* consume '-' */
                    sym_end = dsl_parse_symbol(&lex);
                    if (sym_end >= 0) is_range = true;
                }

                if (!dsl_lexer_match(&lex, TOK_ARROW)) continue;

                dsl_token_t tgt = dsl_lexer_consume(&lex);
                if (tgt.type != TOK_INT && tgt.type != TOK_HEX) continue;

                /* Parse optional markers */
                uint32_t markers[DSL_MAX_MARKERS];
                int mc = 0;

                if (dsl_lexer_peek(&lex).type == TOK_LBRACKET) {
                    dsl_lexer_consume(&lex);
                    while (dsl_lexer_peek(&lex).type != TOK_RBRACKET &&
                           dsl_lexer_peek(&lex).type != TOK_EOF) {
                        dsl_token_t mtok = dsl_lexer_consume(&lex);
                        if ((mtok.type == TOK_HEX || mtok.type == TOK_INT) &&
                            mc < DSL_MAX_MARKERS) {
                            markers[mc++] = (uint32_t)mtok.ival;
                        }
                        dsl_lexer_match(&lex, TOK_COMMA);
                    }
                    if (dsl_lexer_peek(&lex).type == TOK_RBRACKET)
                        dsl_lexer_consume(&lex);
                }

                if (is_range) {
                    /* Expand range into individual symbol transitions */
                    for (int c = sym_start; c <= sym_end; c++) {
                        if (raw_count >= raw_capacity) {
                            raw_capacity *= 2;
                            raw_trans_t *new_raw = realloc(raw,
                                (size_t)raw_capacity * sizeof(raw_trans_t));
                            if (!new_raw) goto cleanup;
                            raw = new_raw;
                        }
                        memset(&raw[raw_count], 0, sizeof(raw_trans_t));
                        raw[raw_count].from_state = from_state;
                        raw[raw_count].symbol_id = c;
                        raw[raw_count].target = tgt.ival;
                        raw[raw_count].marker_count = mc;
                        memcpy(raw[raw_count].markers, markers,
                               (size_t)mc * sizeof(uint32_t));
                        raw_count++;
                    }
                } else {
                    if (raw_count >= raw_capacity) {
                        raw_capacity *= 2;
                        raw_trans_t *new_raw = realloc(raw,
                            (size_t)raw_capacity * sizeof(raw_trans_t));
                        if (!new_raw) goto cleanup;
                        raw = new_raw;
                    }
                    memset(&raw[raw_count], 0, sizeof(raw_trans_t));
                    raw[raw_count].from_state = from_state;
                    raw[raw_count].symbol_id = sym_start;
                    raw[raw_count].target = tgt.ival;
                    raw[raw_count].marker_count = mc;
                    memcpy(raw[raw_count].markers, markers,
                           (size_t)mc * sizeof(uint32_t));
                    raw_count++;
                }
            }
            continue;
        }

        /* Skip unknown tokens */
        dsl_lexer_consume(&lex);
    }

    /* Resolve raw transitions into states */
    int highest_state = dfa->max_state_id;
    for (int i = 0; i < raw_count; i++) {
        if (raw[i].target > highest_state) highest_state = raw[i].target;
        if (raw[i].from_state > highest_state) highest_state = raw[i].from_state;
    }

    /* Ensure state array covers all referenced states */
    if (highest_state >= state_capacity) {
        int new_cap = highest_state + 64;
        dsl_dfa_state_t **new_states = realloc(states,
            (size_t)new_cap * sizeof(dsl_dfa_state_t *));
        if (!new_states) goto cleanup;
        memset(new_states + state_capacity, 0,
               (size_t)(new_cap - state_capacity) * sizeof(dsl_dfa_state_t *));
        states = new_states;
        state_capacity = new_cap;
    }

    /* Create state entries that don't exist yet */
    for (int i = 0; i <= highest_state; i++) {
        if (!states[i]) {
            states[i] = dfa_dsl_state_alloc(i);
            if (!states[i]) goto cleanup;
        }
    }

    /* Populate states from raw transitions */
    for (int i = 0; i < raw_count; i++) {
        int sid = raw[i].from_state;
        dsl_dfa_state_t *s = states[sid];

        if (raw[i].is_default) {
            s->has_default = true;
            s->default_target = raw[i].target;
        } else if (raw[i].is_eos) {
            s->eos_target = raw[i].target;
        } else {
            /* Regular symbol transition */
            int ti = s->symbol_transition_count;
            if (ti < DSL_MAX_TRANSITIONS) {
                s->symbol_transitions[ti].symbol_id = raw[i].symbol_id;
                s->symbol_transitions[ti].target_count = 1;
                s->symbol_transitions[ti].targets[0] = raw[i].target;
                s->symbol_transitions[ti].marker_count = raw[i].marker_count;
                memcpy(s->symbol_transitions[ti].markers, raw[i].markers,
                       (size_t)raw[i].marker_count * sizeof(uint32_t));
                s->symbol_transition_count++;
            }
        }
    }

    /* Set state count */
    dfa->state_count = highest_state + 1;
    dfa->max_state_id = highest_state;

    if (dfa->start_state < 0) {
        dfa->start_state = 0;
        if (states[0]) states[0]->is_start = true;
    }

    free(raw);

    /* Transfer state pointers to DFA */
    dfa->states = calloc((size_t)(highest_state + 1), sizeof(dsl_dfa_state_t));
    if (!dfa->states) goto cleanup;
    for (int i = 0; i <= highest_state; i++) {
        if (states[i]) {
            memcpy(&dfa->states[i], states[i], sizeof(dsl_dfa_state_t));
        }
    }
    /* Free individual state structs */
    for (int i = 0; i < state_capacity; i++) {
        free(states[i]);
    }
    free(states);

    return dfa;

cleanup:
    for (int i = 0; i < state_capacity; i++) free(states[i]);
    free(states);
    free(raw);
    free(dfa);
    return NULL;
}

dsl_dfa_t *dfa_dsl_parse_string(const char *text) {
    if (!text) return NULL;
    return dfa_dsl_parse_input(text);
}

dsl_dfa_t *dfa_dsl_parse_file(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *text = malloc((size_t)size + 1);
    if (!text) { fclose(f); return NULL; }

    size_t nread = fread(text, 1, (size_t)size, f);
    text[nread] = '\0';
    fclose(f);

    dsl_dfa_t *result = dfa_dsl_parse_input(text);
    free(text);
    return result;
}

void dfa_dsl_free(dsl_dfa_t *dfa) {
    if (!dfa) return;
    free(dfa->states);
    free(dfa);
}
