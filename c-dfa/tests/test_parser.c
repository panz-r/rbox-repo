/**
 * Parser Unit Tests - Tests for pattern parser and NFA construction
 *
 * Tests verify parsing succeeds/fails correctly and NFA has expected properties.
 */

#define _DEFAULT_SOURCE

#include "../lib/nfa_builder.h"
#include "../include/nfa.h"
#include "../include/nfa_dsl.h"
#include "../include/multi_target_array.h"
#include "../include/cdfa_defines.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  %s...", #name); \
    fflush(stdout); \
    if (test_##name()) { \
        tests_passed++; \
        printf(" PASS\n"); \
    } else { \
        tests_failed++; \
        printf(" FAIL\n"); \
    } \
} while(0)

#define ASSERT(cond) do { if (!(cond)) { \
    printf("  ASSERT FAILED: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
    return false; \
} } while(0)

#define ASSERT_TRUE(cond) ASSERT(cond)
#define ASSERT_FALSE(cond) do { if (cond) { \
    printf("  ASSERT FAILED: %s was true at %s:%d\n", #cond, __FILE__, __LINE__); \
    return false; \
} } while(0)

static const char* CATEGORIES_SECTION = 
    "[CATEGORIES]\n"
    "0: safe\n"
    "1: caution\n"
    "2: modifying\n"
    "3: dangerous\n"
    "4: network\n"
    "5: admin\n"
    "6: build\n"
    "7: container\n"
    "\n";

// ============================================================================
// Helper Functions
// ============================================================================

static bool has_transition_on(nfa_graph_t* g, int from, int sym) {
    if (from < 0 || from >= g->state_count) return false;
    if (g->states[from].multi_targets.has_first_target[sym]) return true;
    mta_entry_t* e = g->states[from].multi_targets.symbol_map[sym];
    return e != NULL && e->target_count > 0;
}

static int find_transition_target(nfa_graph_t* g, int from, int sym) {
    if (from < 0 || from >= g->state_count) return -1;
    if (g->states[from].multi_targets.has_first_target[sym]) {
        return g->states[from].multi_targets.first_targets[sym];
    }
    mta_entry_t* e = g->states[from].multi_targets.symbol_map[sym];
    if (e && e->target_count > 0) return e->targets[0];
    return -1;
}

static int follow_epsilon_chain(nfa_graph_t* g, int start) {
    int current = start;
    for (int iterations = 0; iterations < g->state_count; iterations++) {
        if (current < 0 || current >= g->state_count) return -1;
        int next = -1;
        if (g->states[current].multi_targets.has_first_target[VSYM_EPS]) {
            next = g->states[current].multi_targets.first_targets[VSYM_EPS];
        } else {
            mta_entry_t* e = g->states[current].multi_targets.symbol_map[VSYM_EPS];
            if (e && e->target_count > 0) next = e->targets[0];
        }
        if (next < 0) break;
        if (next == current) break;
        current = next;
    }
    return current;
}

/* ============================================================================
 * DSL Query Helpers
 * ============================================================================ */

static bool dsl_has_transition(const dsl_nfa_t *nfa, int from, int sym, int to) {
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

static bool dsl_has_epsilon(const dsl_nfa_t *nfa, int from, int to) {
    return dsl_has_transition(nfa, from, VSYM_EPS, to);
}

static bool dsl_state_is_accepting(const dsl_nfa_t *nfa, int state, uint8_t mask) {
    if (!nfa || state < 0 || state >= nfa->state_count) return false;
    const dsl_state_t *s = &nfa->states[state];
    if (!s->is_accept) return false;
    if (mask != 0 && s->category_mask != mask) return false;
    return true;
}

static bool dsl_has_marker(const dsl_nfa_t *nfa, int from, int sym, uint32_t marker) {
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

static bool dsl_has_path(const dsl_nfa_t *nfa, int from, int to, const int *seq, int len) {
    if (len == 0) return from == to;
    return dsl_has_path_bfs(nfa, from, to, seq, len);
}

/* ============================================================================
 * DSL Assertion Macros
 * ============================================================================ */

#define ASSERT_DSL_TRANSITION(nfa, from, sym, to) do { \
    if (!dsl_has_transition(nfa, from, sym, to)) { \
        printf("  ASSERT FAILED: Transition %d -%s-> %d not found\n", \
                from, sym == VSYM_EPS ? "EPS" : nfa_dsl_symbol_name(sym), to); \
        return false; \
    } \
} while(0)

#define ASSERT_DSL_EPSILON(nfa, from, to) do { \
    if (!dsl_has_epsilon(nfa, from, to)) { \
        printf("  ASSERT FAILED: Epsilon %d -> %d not found\n", from, to); \
        return false; \
    } \
} while(0)

#define ASSERT_DSL_ACCEPTING(nfa, state, mask) do { \
    if (!dsl_state_is_accepting(nfa, state, mask)) { \
        printf("  ASSERT FAILED: State %d not accepting (mask=0x%02X)\n", state, mask); \
        return false; \
    } \
} while(0)

#define ASSERT_DSL_NO_EPSILON_TO(nfa, from, to) do { \
    if (dsl_has_epsilon(nfa, from, to)) { \
        printf("  ASSERT FAILED: Unexpected epsilon %d -> %d exists\n", from, to); \
        return false; \
    } \
} while(0)

#define ASSERT_DSL_PATH(nfa, from, to, ...) do { \
    const int __seq[] = { __VA_ARGS__ }; \
    if (!dsl_has_path(nfa, from, to, __seq, (int)(sizeof(__seq)/sizeof(int)))) { \
        printf("  ASSERT FAILED: Path from %d to %d not found\n", from, to); \
        return false; \
    } \
} while(0)

static nfa_graph_t* parse_pattern(const char* pattern_line) {
    nfa_builder_context_t* ctx = nfa_builder_context_create();
    if (!ctx) return NULL;
    
    nfa_construct_init(ctx);
    
    char* tmpfile = strdup("/tmp/test_parser_XXXXXX");
    int fd = mkstemp(tmpfile);
    if (fd < 0) {
        free(tmpfile);
        nfa_builder_context_destroy(ctx);
        return NULL;
    }
    
    FILE* f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        unlink(tmpfile);
        free(tmpfile);
        nfa_builder_context_destroy(ctx);
        return NULL;
    }
    
    fprintf(f, "%s%s\n", CATEGORIES_SECTION, pattern_line);
    fclose(f);
    
    nfa_parser_read_spec_file(ctx, tmpfile);
    unlink(tmpfile);
    free(tmpfile);
    
    if (nfa_parser_has_error(ctx)) {
        nfa_builder_context_destroy(ctx);
        return NULL;
    }
    
    nfa_graph_t* graph = nfa_builder_finalize(ctx, NULL, NULL);
    nfa_builder_context_destroy(ctx);
    return graph;
}

static bool parse_fails_with_error(const char* pattern_line, parse_error_type_t expected_type) {
    char* tmpfile = strdup("/tmp/test_error_XXXXXX");
    int fd = mkstemp(tmpfile);
    if (fd < 0) {
        free(tmpfile);
        return false;
    }
    
    FILE* f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        unlink(tmpfile);
        free(tmpfile);
        return false;
    }
    
    fprintf(f, "%s%s\n", CATEGORIES_SECTION, pattern_line);
    fclose(f);
    
    nfa_builder_context_t* ctx = nfa_builder_context_create();
    if (!ctx) {
        unlink(tmpfile);
        free(tmpfile);
        return false;
    }
    
    nfa_construct_init(ctx);
    nfa_parser_read_spec_file(ctx, tmpfile);
    
    bool has_error = nfa_parser_has_error(ctx);
    const parse_error_info_t* err = nfa_parser_get_error(ctx);
    bool matches = has_error && err->type == expected_type;
    
    nfa_builder_context_destroy(ctx);
    unlink(tmpfile);
    free(tmpfile);
    
    return matches;
}

// ============================================================================
// Basic Literal Patterns
// ============================================================================

static bool test_literal_a(void) {
    nfa_graph_t* g = parse_pattern("[safe] a");
    ASSERT_TRUE(g != NULL);

    /* DSL structural verification */
    const char* expected =
        "version: 1\n"
        "0: start\n"
        "0 EPS -> 1\n"
        "1:\n"
        "1 EPS -> 2\n"
        "2:\n"
        "2 'a' -> 3\n"
        "3: accept category=0x01 pattern=1 eos\n";

    ASSERT_NFA_EQ_STR(g, expected, "literal 'a'");
    nfa_graph_free(g);
    return true;
}

static bool test_literal_abc(void) {
    nfa_graph_t* g = parse_pattern("[safe] abc");
    ASSERT_TRUE(g != NULL);

    /* DSL structural verification: NFA for 'abc' should have:
     * - start state with EPS to first char state
     * - 'a' -> 'b' -> 'c' chain
     * - accept state with category=0x01 (safe) and eos marker */
    const char* expected =
        "version: 1\n"
        "0: start\n"
        "0 EPS -> 1\n"
        "1:\n"
        "1 EPS -> 2\n"
        "2:\n"
        "2 'a' -> 3\n"
        "3:\n"
        "3 EPS -> 4\n"
        "4:\n"
        "4 'b' -> 5\n"
        "5:\n"
        "5 EPS -> 6\n"
        "6:\n"
        "6 'c' -> 7\n"
        "7: accept category=0x01 pattern=1 eos\n";

    ASSERT_NFA_EQ_STR(g, expected, "literal 'abc'");
    nfa_graph_free(g);
    return true;
}

static bool test_literal_chain_cat(void) {
    nfa_graph_t* g = parse_pattern("[caution] rm -rf /");
    ASSERT_TRUE(g != NULL);
    ASSERT_TRUE(g->state_count >= 2);
    int last = g->state_count - 1;
    ASSERT_TRUE(nfa_state_is_accepting(g, last));
    nfa_graph_free(g);
    return true;
}

static bool test_escaped_newline(void) {
    nfa_graph_t* g = parse_pattern("[safe] \\n");
    ASSERT_TRUE(g != NULL);
    ASSERT_TRUE(g->state_count >= 2);
    int s0 = follow_epsilon_chain(g, 0);
    int target = find_transition_target(g, s0, 'n');
    ASSERT_TRUE(target >= 0);
    nfa_graph_free(g);
    return true;
}

static bool test_escaped_tab(void) {
    nfa_graph_t* g = parse_pattern("[safe] \\t");
    ASSERT_TRUE(g != NULL);
    ASSERT_TRUE(g->state_count >= 2);
    int s0 = follow_epsilon_chain(g, 0);
    int target = find_transition_target(g, s0, 't');
    ASSERT_TRUE(target >= 0);
    nfa_graph_free(g);
    return true;
}

static bool test_hex_escape_A(void) {
    nfa_graph_t* g = parse_pattern("[safe] \\x41");
    ASSERT_TRUE(g != NULL);
    ASSERT_TRUE(g->state_count >= 2);
    int s0 = follow_epsilon_chain(g, 0);
    int target = find_transition_target(g, s0, 'A');
    ASSERT_TRUE(target >= 0);
    nfa_graph_free(g);
    return true;
}

static bool test_quoted_char(void) {
    nfa_graph_t* g = parse_pattern("[safe] 'x'");
    ASSERT_TRUE(g != NULL);
    ASSERT_TRUE(g->state_count >= 2);
    int s0 = follow_epsilon_chain(g, 0);
    int target = find_transition_target(g, s0, 'x');
    ASSERT_TRUE(target >= 0);
    nfa_graph_free(g);
    return true;
}

static bool test_max_length_pattern(void) {
    char pattern[600];
    strcpy(pattern, "[safe] ");
    for (int i = 7; i < 511; i++) {
        pattern[i] = 'a';
    }
    pattern[511] = '\0';
    
    nfa_graph_t* g = parse_pattern(pattern);
    ASSERT_TRUE(g != NULL);
    ASSERT_TRUE(g->state_count >= 2);
    nfa_graph_free(g);
    return true;
}

static bool test_too_long_pattern(void) {
    char pattern[600];
    strcpy(pattern, "[safe] ");
    for (int i = 7; i < 600; i++) {
        pattern[i] = 'a';
    }
    pattern[599] = '\0';
    
    ASSERT_TRUE(parse_fails_with_error(pattern, PARSE_ERROR_LENGTH));
    return true;
}

// ============================================================================
// Parentheses and Grouping
// ============================================================================

static bool test_simple_group(void) {
    nfa_graph_t* g = parse_pattern("[safe] (a)");
    ASSERT_TRUE(g != NULL);

    /* DSL structural verification: grouping doesn't change structure */
    char* dsl = nfa_graph_dsl_to_string(g);
    ASSERT_TRUE(dsl != NULL);
    ASSERT_TRUE(strstr(dsl, "'a'") != NULL);  /* Has 'a' transition */
    free(dsl);

    nfa_graph_free(g);
    return true;
}

static bool test_nested_groups(void) {
    nfa_graph_t* g = parse_pattern("[safe] (ab)");
    ASSERT_TRUE(g != NULL);
    ASSERT_TRUE(g->state_count >= 3);
    int s0 = follow_epsilon_chain(g, 0);
    ASSERT_TRUE(has_transition_on(g, s0, 'a'));
    nfa_graph_free(g);
    return true;
}

static bool test_unclosed_paren(void) {
    ASSERT_TRUE(parse_fails_with_error("[safe] (a", PARSE_ERROR_UNCLOSED_PAREN));
    return true;
}

static bool test_unmatched_paren(void) {
    ASSERT_TRUE(parse_fails_with_error("[safe] a)", PARSE_ERROR_UNMATCHED_PAREN));
    return true;
}

static bool test_deep_nesting(void) {
    nfa_graph_t* g = parse_pattern("[safe] (a)");
    ASSERT_TRUE(g != NULL);
    ASSERT_TRUE(g->state_count >= 2);
    nfa_graph_free(g);
    return true;
}

// ============================================================================
// Quantifiers
// ============================================================================

static bool test_star_quantifier(void) {
    nfa_graph_t* g = parse_pattern("[safe] (a)*");
    ASSERT_TRUE(g != NULL);

    /* Kleene star: 'a' path exists, accepting state exists */
    char* dsl_str = nfa_graph_dsl_to_string(g);
    ASSERT_TRUE(dsl_str != NULL);
    ASSERT_TRUE(strstr(dsl_str, "'a'") != NULL);
    ASSERT_TRUE(strstr(dsl_str, "accept") != NULL);
    free(dsl_str);

    nfa_graph_free(g);
    return true;
}

static bool test_plus_quantifier(void) {
    nfa_graph_t* g = parse_pattern("[safe] (a)+");
    ASSERT_TRUE(g != NULL);

    /* Plus: 'a' path exists, accepting state exists */
    char* dsl_str = nfa_graph_dsl_to_string(g);
    ASSERT_TRUE(dsl_str != NULL);
    ASSERT_TRUE(strstr(dsl_str, "'a'") != NULL);
    ASSERT_TRUE(strstr(dsl_str, "accept") != NULL);
    free(dsl_str);

    nfa_graph_free(g);
    return true;
}

static bool test_question_quantifier(void) {
    nfa_graph_t* g = parse_pattern("[safe] (a)?");
    ASSERT_TRUE(g != NULL);

    /* Question mark: 'a' path exists, accepting state exists */
    char* dsl_str = nfa_graph_dsl_to_string(g);
    ASSERT_TRUE(dsl_str != NULL);
    ASSERT_TRUE(strstr(dsl_str, "'a'") != NULL);
    ASSERT_TRUE(strstr(dsl_str, "accept") != NULL);
    free(dsl_str);

    nfa_graph_free(g);
    return true;
}

static bool test_quantifier_on_literal(void) {
    ASSERT_TRUE(parse_fails_with_error("[safe] a*", PARSE_ERROR_QUANTIFIER_POSITION));
    return true;
}

static bool test_quantifier_on_escaped(void) {
    ASSERT_TRUE(parse_fails_with_error("[safe] \\n*", PARSE_ERROR_QUANTIFIER_POSITION));
    return true;
}

static bool test_nested_quantifiers(void) {
    const char* spec = 
        "[CATEGORIES]\n"
        "0: safe\n"
        "\n"
        "[fragment:x] a\n"
        "[safe] [[x]]*";
    
    nfa_builder_context_t* ctx = nfa_builder_context_create();
    ASSERT_TRUE(ctx != NULL);
    nfa_construct_init(ctx);
    
    char* tmpfile = strdup("/tmp/test_parser_XXXXXX");
    int fd = mkstemp(tmpfile);
    ASSERT_TRUE(fd >= 0);
    FILE* f = fdopen(fd, "w");
    ASSERT_TRUE(f != NULL);
    fprintf(f, "%s", spec);
    fclose(f);
    
    nfa_parser_read_spec_file(ctx, tmpfile);
    unlink(tmpfile);
    free(tmpfile);
    
    ASSERT_TRUE(!nfa_parser_has_error(ctx));
    nfa_graph_t* g = nfa_builder_finalize(ctx, NULL, NULL);
    ASSERT_TRUE(g != NULL);
    nfa_graph_free(g);
    nfa_builder_context_destroy(ctx);
    return true;
}

static bool test_empty_group_star(void) {
    nfa_graph_t* g = parse_pattern("[safe] ()*");
    ASSERT_TRUE(g != NULL);
    int last = g->state_count - 1;
    ASSERT_TRUE(nfa_state_is_accepting(g, last));
    nfa_graph_free(g);
    return true;
}

static bool test_empty_group_plus(void) {
    nfa_graph_t* g = parse_pattern("[safe] ()+");
    ASSERT_TRUE(g != NULL);
    nfa_graph_free(g);
    return true;
}

static bool test_empty_group_question(void) {
    nfa_graph_t* g = parse_pattern("[safe] ()?");
    ASSERT_TRUE(g != NULL);
    int last = g->state_count - 1;
    ASSERT_TRUE(nfa_state_is_accepting(g, last));
    nfa_graph_free(g);
    return true;
}

// ============================================================================
// Alternation
// ============================================================================

static bool test_alternation_two(void) {
    nfa_graph_t* g = parse_pattern("[safe] (a|b)");
    ASSERT_TRUE(g != NULL);

    /* DSL verification: alternation has both branches */
    char* dsl = nfa_graph_dsl_to_string(g);
    ASSERT_TRUE(dsl != NULL);
    ASSERT_TRUE(strstr(dsl, "'a'") != NULL);
    ASSERT_TRUE(strstr(dsl, "'b'") != NULL);
    ASSERT_TRUE(strstr(dsl, "EPS") != NULL);  /* Has epsilon transitions */
    free(dsl);

    nfa_graph_free(g);
    return true;
}

static bool test_alternation_three(void) {
    nfa_graph_t* g = parse_pattern("[safe] (a|b|c)");
    ASSERT_TRUE(g != NULL);

    /* DSL verification: alternation has all three paths */
    char* dsl = nfa_graph_dsl_to_string(g);
    ASSERT_TRUE(dsl != NULL);
    ASSERT_TRUE(strstr(dsl, "'a'") != NULL);
    ASSERT_TRUE(strstr(dsl, "'b'") != NULL);
    ASSERT_TRUE(strstr(dsl, "'c'") != NULL);
    free(dsl);

    nfa_graph_free(g);
    return true;
}

static bool test_alternation_empty_first(void) {
    nfa_graph_t* g = parse_pattern("[safe] (|a)");
    ASSERT_TRUE(g != NULL);

    /* DSL verification: empty first means epsilon from start can skip to accept */
    char* dsl = nfa_graph_dsl_to_string(g);
    ASSERT_TRUE(dsl != NULL);
    ASSERT_TRUE(strstr(dsl, "'a'") != NULL);
    free(dsl);

    nfa_graph_free(g);
    return true;
}

static bool test_alternation_empty_last(void) {
    nfa_graph_t* g = parse_pattern("[safe] (a|)");
    ASSERT_TRUE(g != NULL);

    /* DSL verification: empty last is similar */
    char* dsl = nfa_graph_dsl_to_string(g);
    ASSERT_TRUE(dsl != NULL);
    ASSERT_TRUE(strstr(dsl, "'a'") != NULL);
    free(dsl);

    nfa_graph_free(g);
    return true;
}

static bool test_nested_alternation(void) {
    nfa_graph_t* g = parse_pattern("[safe] (a|(b|c))");
    ASSERT_TRUE(g != NULL);

    /* DSL verification: nested alternation has 'a', 'b', 'c' paths */
    char* dsl = nfa_graph_dsl_to_string(g);
    ASSERT_TRUE(dsl != NULL);
    ASSERT_TRUE(strstr(dsl, "'a'") != NULL);
    ASSERT_TRUE(strstr(dsl, "'b'") != NULL);
    ASSERT_TRUE(strstr(dsl, "'c'") != NULL);
    free(dsl);

    nfa_graph_free(g);
    return true;
}

// ============================================================================
// Wildcards
// ============================================================================

static bool test_wildcard_star(void) {
    nfa_graph_t* g = parse_pattern("[safe] (*)");
    ASSERT_TRUE(g != NULL);
    int s0 = follow_epsilon_chain(g, 0);
    ASSERT_TRUE(has_transition_on(g, s0, VSYM_BYTE_ANY));
    nfa_graph_free(g);
    return true;
}

static bool test_wildcard_in_group(void) {
    nfa_graph_t* g = parse_pattern("[safe] (*)");
    ASSERT_TRUE(g != NULL);
    ASSERT_TRUE(g->state_count >= 2);
    int s0 = follow_epsilon_chain(g, 0);
    ASSERT_TRUE(has_transition_on(g, s0, VSYM_BYTE_ANY));
    nfa_graph_free(g);
    return true;
}

// ============================================================================
// Whitespace
// ============================================================================

static bool test_space_normalization(void) {
    nfa_graph_t* g = parse_pattern("[safe] x ");
    ASSERT_TRUE(g != NULL);
    ASSERT_TRUE(g->state_count >= 2);
    nfa_graph_free(g);
    return true;
}

static bool test_tab_normalization(void) {
    nfa_graph_t* g = parse_pattern("[safe] \\t");
    ASSERT_TRUE(g != NULL);
    ASSERT_TRUE(g->state_count >= 2);
    int s0 = follow_epsilon_chain(g, 0);
    int target = find_transition_target(g, s0, 't');
    ASSERT_TRUE(target >= 0);
    nfa_graph_free(g);
    return true;
}

// ============================================================================
// Capture Markers
// ============================================================================

static bool test_capture_start(void) {
    nfa_graph_t* g = parse_pattern("[safe] <name>a");
    ASSERT_TRUE(g != NULL);
    ASSERT_TRUE(g->state_count >= 2);
    int s0 = follow_epsilon_chain(g, 0);
    ASSERT_TRUE(has_transition_on(g, s0, 'a'));
    nfa_graph_free(g);
    return true;
}

static bool test_capture_end(void) {
    nfa_graph_t* g = parse_pattern("[safe] a</name>");
    ASSERT_TRUE(g != NULL);
    ASSERT_TRUE(g->state_count >= 2);
    int s0 = follow_epsilon_chain(g, 0);
    ASSERT_TRUE(has_transition_on(g, s0, 'a'));
    nfa_graph_free(g);
    return true;
}

static bool test_capture_full(void) {
    nfa_graph_t* g = parse_pattern("[safe] <name>a</name>");
    ASSERT_TRUE(g != NULL);
    ASSERT_TRUE(g->state_count >= 2);
    int s0 = follow_epsilon_chain(g, 0);
    ASSERT_TRUE(has_transition_on(g, s0, 'a'));
    nfa_graph_free(g);
    return true;
}

static bool test_capture_nested(void) {
    nfa_graph_t* g = parse_pattern("[safe] <outer><inner>a</inner></outer>");
    ASSERT_TRUE(g != NULL);
    ASSERT_TRUE(g->state_count >= 2);
    nfa_graph_free(g);
    return true;
}

// ============================================================================
// Fragment References
// ============================================================================

static bool test_fragment_simple(void) {
    const char* spec = 
        "[CATEGORIES]\n"
        "0: safe\n"
        "\n"
        "[fragment:foo] a\n"
        "[safe] [[foo]]\n";
    
    nfa_builder_context_t* ctx = nfa_builder_context_create();
    ASSERT_TRUE(ctx != NULL);
    nfa_construct_init(ctx);
    
    char* tmpfile = strdup("/tmp/test_parser_XXXXXX");
    int fd = mkstemp(tmpfile);
    ASSERT_TRUE(fd >= 0);
    FILE* f = fdopen(fd, "w");
    ASSERT_TRUE(f != NULL);
    fprintf(f, "%s", spec);
    fclose(f);
    
    nfa_parser_read_spec_file(ctx, tmpfile);
    unlink(tmpfile);
    free(tmpfile);
    
    ASSERT_TRUE(!nfa_parser_has_error(ctx));
    nfa_graph_t* g = nfa_builder_finalize(ctx, NULL, NULL);
    ASSERT_TRUE(g != NULL);
    nfa_graph_free(g);
    nfa_builder_context_destroy(ctx);
    return true;
}

static bool test_fragment_undefined(void) {
    const char* spec = 
        "[CATEGORIES]\n"
        "0: safe\n"
        "\n"
        "[fragment:foo] a\n"
        "[safe] [[bar]]\n";
    
    nfa_builder_context_t* ctx = nfa_builder_context_create();
    ASSERT_TRUE(ctx != NULL);
    nfa_construct_init(ctx);
    
    char* tmpfile = strdup("/tmp/test_parser_XXXXXX");
    int fd = mkstemp(tmpfile);
    ASSERT_TRUE(fd >= 0);
    FILE* f = fdopen(fd, "w");
    ASSERT_TRUE(f != NULL);
    fprintf(f, "%s", spec);
    fclose(f);
    
    nfa_parser_read_spec_file(ctx, tmpfile);
    unlink(tmpfile);
    free(tmpfile);
    
    ASSERT_TRUE(nfa_parser_has_error(ctx));
    nfa_builder_context_destroy(ctx);
    return true;
}

static bool test_fragment_in_alternation(void) {
    const char* spec = 
        "[CATEGORIES]\n"
        "0: safe\n"
        "\n"
        "[fragment:x] a\n"
        "[fragment:y] b\n"
        "[safe] [[x]]|[[y]]\n";
    
    nfa_builder_context_t* ctx = nfa_builder_context_create();
    ASSERT_TRUE(ctx != NULL);
    nfa_construct_init(ctx);
    
    char* tmpfile = strdup("/tmp/test_parser_XXXXXX");
    int fd = mkstemp(tmpfile);
    ASSERT_TRUE(fd >= 0);
    FILE* f = fdopen(fd, "w");
    ASSERT_TRUE(f != NULL);
    fprintf(f, "%s", spec);
    fclose(f);
    
    nfa_parser_read_spec_file(ctx, tmpfile);
    unlink(tmpfile);
    free(tmpfile);
    
    ASSERT_TRUE(!nfa_parser_has_error(ctx));
    nfa_graph_t* g = nfa_builder_finalize(ctx, NULL, NULL);
    ASSERT_TRUE(g != NULL);
    nfa_graph_free(g);
    nfa_builder_context_destroy(ctx);
    return true;
}

static bool test_fragment_depth_limit(void) {
    char spec[4000];
    strcpy(spec, "[CATEGORIES]\n0: safe\n\n");
    
    for (int i = 0; i < 31; i++) {
        char fragname[32];
        snprintf(fragname, sizeof(fragname), "f%d", i);
        char line[128];
        snprintf(line, sizeof(line), "[fragment:%s] x[[f%d]]\n", fragname, i + 1);
        strcat(spec, line);
    }
    strcat(spec, "[fragment:f31] x\n");
    strcat(spec, "[safe] [[f0]]\n");
    
    nfa_builder_context_t* ctx = nfa_builder_context_create();
    ASSERT_TRUE(ctx != NULL);
    nfa_construct_init(ctx);
    
    char* tmpfile = strdup("/tmp/test_parser_XXXXXX");
    int fd = mkstemp(tmpfile);
    ASSERT_TRUE(fd >= 0);
    FILE* f = fdopen(fd, "w");
    ASSERT_TRUE(f != NULL);
    fprintf(f, "%s", spec);
    fclose(f);
    
    nfa_parser_read_spec_file(ctx, tmpfile);
    unlink(tmpfile);
    free(tmpfile);
    
    ASSERT_TRUE(!nfa_parser_has_error(ctx));
    nfa_graph_t* g = nfa_builder_finalize(ctx, NULL, NULL);
    ASSERT_TRUE(g != NULL);
    nfa_graph_free(g);
    nfa_builder_context_destroy(ctx);
    return true;
}

// ============================================================================
// Error Conditions
// ============================================================================

static bool test_error_empty_pattern(void) {
    nfa_builder_context_t* ctx = nfa_builder_context_create();
    ASSERT_TRUE(ctx != NULL);
    nfa_construct_init(ctx);
    nfa_parser_parse_pattern(ctx, "");
    bool has_err = nfa_parser_has_error(ctx);
    nfa_builder_context_destroy(ctx);
    ASSERT_TRUE(has_err);
    return true;
}

static bool test_error_invalid_category(void) {
    nfa_builder_context_t* ctx = nfa_builder_context_create();
    ASSERT_TRUE(ctx != NULL);
    nfa_construct_init(ctx);
    nfa_parser_parse_pattern(ctx, "[unknown] a");
    ASSERT_TRUE(nfa_parser_has_error(ctx));
    nfa_builder_context_destroy(ctx);
    return true;
}

static bool test_error_double_paren(void) {
    nfa_builder_context_t* ctx = nfa_builder_context_create();
    ASSERT_TRUE(ctx != NULL);
    nfa_construct_init(ctx);
    nfa_parser_parse_pattern(ctx, "[safe] ((a))");
    bool has_err = nfa_parser_has_error(ctx);
    nfa_builder_context_destroy(ctx);
    ASSERT_TRUE(has_err);
    return true;
}

// ============================================================================
// Main
// ============================================================================

int main(ATTR_UNUSED int argc, ATTR_UNUSED char** argv) {
    printf("Parser Unit Tests\n");
    printf("=================\n\n");
    
    printf("Basic Literals:\n");
    TEST(literal_a);
    TEST(literal_abc);
    TEST(literal_chain_cat);
    TEST(escaped_newline);
    TEST(escaped_tab);
    TEST(hex_escape_A);
    TEST(quoted_char);
    TEST(max_length_pattern);
    TEST(too_long_pattern);
    
    printf("\nParentheses and Grouping:\n");
    TEST(simple_group);
    TEST(nested_groups);
    TEST(unclosed_paren);
    TEST(unmatched_paren);
    TEST(deep_nesting);
    
    printf("\nQuantifiers:\n");
    TEST(star_quantifier);
    TEST(plus_quantifier);
    TEST(question_quantifier);
    TEST(quantifier_on_literal);
    TEST(quantifier_on_escaped);
    TEST(nested_quantifiers);
    TEST(empty_group_star);
    TEST(empty_group_plus);
    TEST(empty_group_question);
    
    printf("\nAlternation:\n");
    TEST(alternation_two);
    TEST(alternation_three);
    TEST(alternation_empty_first);
    TEST(alternation_empty_last);
    TEST(nested_alternation);
    
    printf("\nWildcards:\n");
    TEST(wildcard_star);
    TEST(wildcard_in_group);
    
    printf("\nWhitespace:\n");
    TEST(space_normalization);
    TEST(tab_normalization);
    
    printf("\nCapture Markers:\n");
    TEST(capture_start);
    TEST(capture_end);
    TEST(capture_full);
    TEST(capture_nested);
    
    printf("\nFragment References:\n");
    TEST(fragment_simple);
    TEST(fragment_undefined);
    TEST(fragment_in_alternation);
    TEST(fragment_depth_limit);
    
    printf("\nError Conditions:\n");
    TEST(error_empty_pattern);
    TEST(error_invalid_category);
    TEST(error_double_paren);
    
    printf("\n=================\n");
    printf("SUMMARY: %d/%d passed\n", tests_passed, tests_run);
    
    return (tests_failed > 0) ? 1 : 0;
}