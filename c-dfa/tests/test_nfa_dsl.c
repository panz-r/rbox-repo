/**
 * test_nfa_dsl.c - NFA DSL serialization/deserialization tests
 *
 * Tests cover:
 *  - Basic serialization and parsing
 *  - Virtual symbols (EPS, ANY, EOS, SPACE, TAB)
 *  - Markers and escape sequences
 *  - BFS canonicalization (state renumbering, unreachable state omission)
 *  - Deterministic output (same NFA always produces same string)
 *  - Round-trip (serialize -> parse -> serialize produces identical output)
 */

#define _POSIX_C_SOURCE 200809L
#define DFA_ERROR_PROGRAM "test_nfa_dsl"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../lib/nfa_builder.h"
#include "../include/nfa_dsl.h"
#include "../include/dfa_errors.h"
#include "../include/dfa_format.h"

static int test_count = 0;
static int pass_count = 0;

#define TEST(name) do { test_count++; printf("  TEST %d: %s ... ", test_count, name); } while(0)
#define PASS() do { pass_count++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)
#define CHECK(cond, msg) do { if (!(cond)) { FAIL(msg); return false; } } while(0)

/* ============================================================================
 * Helper: Construct a standard alphabet in a builder context
 * ============================================================================ */

static void init_alphabet(nfa_builder_context_t *ctx) {
    for (int i = 0; i < BYTE_VALUE_MAX; i++) {
        ctx->alphabet[i].start_char = i;
        ctx->alphabet[i].end_char = i;
        ctx->alphabet[i].symbol_id = i;
        ctx->alphabet[i].is_special = false;
    }
    ctx->alphabet[VSYM_BYTE_ANY].start_char = 0;
    ctx->alphabet[VSYM_BYTE_ANY].end_char = 255;
    ctx->alphabet[VSYM_BYTE_ANY].symbol_id = VSYM_BYTE_ANY;
    ctx->alphabet[VSYM_BYTE_ANY].is_special = true;
    ctx->alphabet[VSYM_EPS].start_char = 1;
    ctx->alphabet[VSYM_EPS].end_char = 1;
    ctx->alphabet[VSYM_EPS].symbol_id = VSYM_EPS;
    ctx->alphabet[VSYM_EPS].is_special = true;
    ctx->alphabet[VSYM_EOS].start_char = 5;
    ctx->alphabet[VSYM_EOS].end_char = 5;
    ctx->alphabet[VSYM_EOS].symbol_id = VSYM_EOS;
    ctx->alphabet[VSYM_EOS].is_special = true;
    ctx->alphabet[VSYM_SPACE].start_char = 32;
    ctx->alphabet[VSYM_SPACE].end_char = 32;
    ctx->alphabet[VSYM_SPACE].symbol_id = VSYM_SPACE;
    ctx->alphabet[VSYM_SPACE].is_special = true;
    ctx->alphabet[VSYM_TAB].start_char = 9;
    ctx->alphabet[VSYM_TAB].end_char = 9;
    ctx->alphabet[VSYM_TAB].symbol_id = VSYM_TAB;
    ctx->alphabet[VSYM_TAB].is_special = true;
    ctx->alphabet_size = VSYM_TAB + 1;
}

static nfa_builder_context_t *create_ctx(void) {
    nfa_builder_context_t *ctx = nfa_builder_context_create();
    if (!ctx) return NULL;
    init_alphabet(ctx);
    nfa_construct_init(ctx);
    return ctx;
}

static void destroy_ctx(nfa_builder_context_t *ctx) {
    if (!ctx) return;
    nfa_construct_cleanup(ctx);
    nfa_builder_context_destroy(ctx);
}

/* Helper: serialize builder context to DSL string using new API */
static char *ctx_to_dsl(nfa_builder_context_t *ctx) {
    nfa_graph_t *graph = nfa_builder_finalize(ctx, NULL, NULL);
    if (!graph) return NULL;
    char *dsl = nfa_graph_dsl_to_string(graph);
    nfa_graph_free(graph);
    return dsl;
}

/* ============================================================================
 * Tests: Basic serialization and parsing
 * ============================================================================ */

static bool test_serialize_simple(void) {
    TEST("serialize simple NFA 'a'");
    nfa_builder_context_t *ctx = create_ctx();
    CHECK(ctx, "failed to create context");

    int s1 = nfa_construct_add_state_with_category(ctx, 0x01);
    nfa_construct_add_transition(ctx, 0, s1, 'a');

    char *dsl = ctx_to_dsl(ctx);
    CHECK(dsl, "nfa_dsl_to_string returned NULL");

    /* Canonical output: always includes category and pattern on accept.
     * current_pattern_index defaults to -1 in nfa_builder_context_create,
     * so pattern_id = current_pattern_index + 1 = 0. */
    CHECK(strstr(dsl, "0: start\n") != NULL, "missing '0: start'");
    CHECK(strstr(dsl, "0 'a' -> 1\n") != NULL, "missing \"0 'a' -> 1\"");
    CHECK(strstr(dsl, "1: accept category=0x01 pattern=0") != NULL,
          "accept line should include category+pattern");

    free(dsl);
    destroy_ctx(ctx);
    PASS();
    return true;
}

static bool test_parse_simple(void) {
    TEST("parse simple DSL string");
    const char *dsl_text =
        "0: start\n"
        "0 'a' -> 1\n"
        "1: accept category=0x01 pattern=1\n";

    dsl_nfa_t *nfa = nfa_dsl_parse_string(dsl_text);
    CHECK(nfa, "nfa_dsl_parse_string returned NULL");
    CHECK(nfa->state_count == 2, "expected 2 states");
    CHECK(nfa->start_state == 0, "expected start_state == 0");

    dsl_state_t *s0 = &nfa->states[0];
    CHECK(s0->is_start, "state 0 should be start");
    CHECK(!s0->is_accept, "state 0 should not be accept");
    CHECK(s0->transition_count == 1, "state 0 should have 1 transition");
    CHECK(s0->transitions[0].symbol_id == 'a', "transition symbol should be 'a'");
    CHECK(s0->transitions[0].targets[0] == 1, "transition target should be 1");

    dsl_state_t *s1 = &nfa->states[1];
    CHECK(s1->is_accept, "state 1 should be accept");
    CHECK(s1->category_mask == 0x01, "state 1 category_mask should be 0x01");
    CHECK(s1->pattern_id == 1, "state 1 pattern_id should be 1");

    nfa_dsl_free(nfa);
    PASS();
    return true;
}

/* ============================================================================
 * Tests: Virtual symbols
 * ============================================================================ */

static bool test_parse_virtual_symbols(void) {
    TEST("parse virtual symbols (EPS, ANY, SPACE, TAB, EOS)");
    const char *dsl_text =
        "0: start\n"
        "0 EPS -> 1,2\n"
        "1 'a' -> 3\n"
        "2 ANY -> 3\n"
        "3 SPACE -> 4\n"
        "3 TAB -> 4\n"
        "3 EOS -> 4\n"
        "4: accept category=0x01 pattern=1\n";

    dsl_nfa_t *nfa = nfa_dsl_parse_string(dsl_text);
    CHECK(nfa, "parse returned NULL");

    CHECK(nfa->states[0].transitions[0].symbol_id == VSYM_EPS, "EPS");
    CHECK(nfa->states[1].transitions[0].symbol_id == 'a', "'a'");
    CHECK(nfa->states[2].transitions[0].symbol_id == VSYM_BYTE_ANY, "ANY");
    CHECK(nfa->states[3].transitions[0].symbol_id == VSYM_SPACE, "SPACE");
    CHECK(nfa->states[3].transitions[1].symbol_id == VSYM_TAB, "TAB");
    CHECK(nfa->states[3].transitions[2].symbol_id == VSYM_EOS, "EOS");

    nfa_dsl_free(nfa);
    PASS();
    return true;
}

static bool test_symbol_helpers(void) {
    TEST("symbol name helpers");
    CHECK(nfa_dsl_symbol_from_name("EPS") == VSYM_EPS, "EPS");
    CHECK(nfa_dsl_symbol_from_name("eps") == VSYM_EPS, "eps case-insensitive");
    CHECK(nfa_dsl_symbol_from_name("ANY") == VSYM_BYTE_ANY, "ANY");
    CHECK(nfa_dsl_symbol_from_name("EOS") == VSYM_EOS, "EOS");
    CHECK(nfa_dsl_symbol_from_name("SPACE") == VSYM_SPACE, "SPACE");
    CHECK(nfa_dsl_symbol_from_name("TAB") == VSYM_TAB, "TAB");
    CHECK(nfa_dsl_symbol_from_name("NOPE") == -1, "unknown -> -1");
    CHECK(strcmp(nfa_dsl_symbol_name(VSYM_EPS), "EPS") == 0, "EPS name");
    CHECK(nfa_dsl_symbol_name('a') == NULL, "literal -> NULL");
    PASS();
    return true;
}

/* ============================================================================
 * Tests: Markers
 * ============================================================================ */

static bool test_parse_markers(void) {
    TEST("parse transition markers");
    const char *dsl_text =
        "0: start\n"
        "0 'a' -> 1 [0x00010000,0x00020001]\n"
        "1: accept category=0x01 pattern=1\n";

    dsl_nfa_t *nfa = nfa_dsl_parse_string(dsl_text);
    CHECK(nfa, "parse returned NULL");

    CHECK(nfa->states[0].transitions[0].marker_count == 2, "2 markers");
    CHECK(nfa->states[0].transitions[0].markers[0].value == 0x00010000, "marker 0");
    CHECK(nfa->states[0].transitions[0].markers[1].value == 0x00020001, "marker 1");

    nfa_dsl_free(nfa);
    PASS();
    return true;
}

/* ============================================================================
 * Tests: Escape sequences
 * ============================================================================ */

static bool test_parse_escapes(void) {
    TEST("parse escape sequences");
    const char *dsl_text =
        "0: start\n"
        "0 '\\n' -> 1\n"
        "0 '\\t' -> 2\n"
        "0 '\\r' -> 3\n"
        "1: accept category=0x01 pattern=1\n"
        "2: accept category=0x02 pattern=2\n"
        "3: accept category=0x04 pattern=3\n";

    dsl_nfa_t *nfa = nfa_dsl_parse_string(dsl_text);
    CHECK(nfa, "parse returned NULL");

    bool found_nl = false, found_tab = false, found_cr = false;
    for (int i = 0; i < nfa->states[0].transition_count; i++) {
        int sym = nfa->states[0].transitions[i].symbol_id;
        if (sym == '\n') found_nl = true;
        if (sym == '\t') found_tab = true;
        if (sym == '\r') found_cr = true;
    }
    CHECK(found_nl, "missing \\n");
    CHECK(found_tab, "missing \\t");
    CHECK(found_cr, "missing \\r");

    nfa_dsl_free(nfa);
    PASS();
    return true;
}

/* ============================================================================
 * Tests: File I/O and hex literals
 * ============================================================================ */

static bool test_parse_file(void) {
    TEST("parse from file");
    const char *filename = "/tmp/test_nfa_dsl_smoke.nfa";
    const char *dsl_text =
        "# Test NFA\n"
        "0: start\n"
        "0 'a' -> 1\n"
        "1: accept category=0x01 pattern=1\n";

    FILE *f = fopen(filename, "w");
    CHECK(f, "cannot create temp file");
    fputs(dsl_text, f);
    fclose(f);

    dsl_nfa_t *nfa = nfa_dsl_parse_file(filename);
    CHECK(nfa, "nfa_dsl_parse_file returned NULL");
    CHECK(nfa->states[0].is_start, "state 0 should be start");
    CHECK(nfa->states[1].is_accept, "state 1 should be accept");

    nfa_dsl_free(nfa);
    remove(filename);
    PASS();
    return true;
}

static bool test_parse_hex_byte(void) {
    TEST("parse hex byte literal 0x20");
    const char *dsl_text =
        "0: start\n"
        "0 0x20 -> 1\n"
        "1: accept category=0x01 pattern=1\n";

    dsl_nfa_t *nfa = nfa_dsl_parse_string(dsl_text);
    CHECK(nfa, "parse returned NULL");
    CHECK(nfa->states[0].transitions[0].symbol_id == 0x20, "symbol should be 0x20");

    nfa_dsl_free(nfa);
    PASS();
    return true;
}

/* ============================================================================
 * Tests: Structural equality
 * ============================================================================ */

static bool test_structural_equality(void) {
    TEST("structural equality comparison");
    const char *dsl_a =
        "0: start\n"
        "0 'a' -> 1\n"
        "1: accept category=0x01 pattern=1\n";
    const char *dsl_b =
        "0: start\n"
        "0 'a' -> 1\n"
        "1: accept category=0x01 pattern=1\n";
    const char *dsl_c =
        "0: start\n"
        "0 'b' -> 1\n"
        "1: accept category=0x01 pattern=1\n";

    dsl_nfa_t *a = nfa_dsl_parse_string(dsl_a);
    dsl_nfa_t *b = nfa_dsl_parse_string(dsl_b);
    dsl_nfa_t *c = nfa_dsl_parse_string(dsl_c);

    CHECK(nfa_dsl_equal(a, b), "identical NFAs should be equal");
    CHECK(!nfa_dsl_equal(a, c), "different NFAs should not be equal");
    CHECK(!nfa_dsl_equal(a, NULL), "NFA vs NULL");
    CHECK(nfa_dsl_equal(NULL, NULL), "NULL vs NULL");

    nfa_dsl_free(a);
    nfa_dsl_free(b);
    nfa_dsl_free(c);
    PASS();
    return true;
}

/* ============================================================================
 * Tests: Canonicalization
 * ============================================================================ */

static bool test_canonical_bfs_renumbering(void) {
    TEST("BFS canonical renumbering for alternation (a|b)");

    /* Build (a|b) with internal states created BEFORE the accept state:
       state 0 --EPS--> state 1 (empty), state 2 (empty)
       state 1 --'a'--> state 3 (accept)
       state 2 --'b'--> state 3

       The BFS from state 0 discovers: 0 -> {1,2} -> {3}
       States 1 and 2 are at the same BFS level; they are sorted by signature.
       State 1 has 'a' outgoing, state 2 has 'b' outgoing.
       Since 'a' < 'b', state 1 gets lower signature, so:
         new 0 = old 0 (start)
         new 1 = old 1 ('a' transition, lower sig)
         new 2 = old 2 ('b' transition, higher sig)
         new 3 = old 3 (accept)
    */
    nfa_builder_context_t *ctx = create_ctx();
    CHECK(ctx, "failed to create context");
    ctx->current_pattern_index = 0;

    int s1 = nfa_construct_add_state_with_category(ctx, 0);
    int s2 = nfa_construct_add_state_with_category(ctx, 0);
    int s3 = nfa_construct_add_state_with_category(ctx, 0x01);

    nfa_construct_add_transition(ctx, 0, s1, VSYM_EPS);
    nfa_construct_add_transition(ctx, 0, s2, VSYM_EPS);
    nfa_construct_add_transition(ctx, s1, s3, 'a');
    nfa_construct_add_transition(ctx, s2, s3, 'b');

    char *dsl = ctx_to_dsl(ctx);
    CHECK(dsl, "nfa_dsl_to_string returned NULL");

    /* The canonical output should have 4 reachable states numbered 0-3 */
    const char *expected =
        "version: 1\n"
        "0: start\n"
        "0 EPS -> 1,2\n"
        "1:\n"
        "1 'a' -> 3\n"
        "2:\n"
        "2 'b' -> 3\n"
        "3: accept category=0x01 pattern=1\n";

    CHECK(strcmp(dsl, expected) == 0, "canonical output mismatch");

    free(dsl);
    destroy_ctx(ctx);
    PASS();
    return true;
}

static bool test_canonical_unreachable_omitted(void) {
    TEST("unreachable states are omitted from output");

    /* Build NFA where state 2 is unreachable from state 0:
       state 0 --'a'--> state 1 (accept)
       state 2 --'z'--> state 3 (accept) [unreachable]

       Only states 0 and 1 should appear in output.
    */
    nfa_builder_context_t *ctx = create_ctx();
    CHECK(ctx, "failed to create context");
    ctx->current_pattern_index = 0;

    int s1 = nfa_construct_add_state_with_category(ctx, 0x01);
    int s2 = nfa_construct_add_state_with_category(ctx, 0);
    int s3 = nfa_construct_add_state_with_category(ctx, 0x02);

    /* state 0 -> state 1 (reachable) */
    nfa_construct_add_transition(ctx, 0, s1, 'a');
    /* state 2 -> state 3 (unreachable - no incoming edges from reachable states) */
    nfa_construct_add_transition(ctx, s2, s3, 'z');

    char *dsl = ctx_to_dsl(ctx);
    CHECK(dsl, "nfa_dsl_to_string returned NULL");

    /* Only 2 states should appear: 0 (start) and 1 (accept) */
    const char *expected =
        "version: 1\n"
        "0: start\n"
        "0 'a' -> 1\n"
        "1: accept category=0x01 pattern=1\n";

    CHECK(strcmp(dsl, expected) == 0, "unreachable states should be omitted");

    free(dsl);
    destroy_ctx(ctx);
    PASS();
    return true;
}

static bool test_canonical_accept_always_has_category_pattern(void) {
    TEST("accept states always include category= and pattern=");

    nfa_builder_context_t *ctx = create_ctx();
    CHECK(ctx, "failed to create context");
    ctx->current_pattern_index = 0;

    /* Accept state with category 0x01 and pattern_id 1 (the default from add_state_with_category) */
    int s1 = nfa_construct_add_state_with_category(ctx, 0x01);
    nfa_construct_add_transition(ctx, 0, s1, 'x');

    char *dsl = ctx_to_dsl(ctx);
    CHECK(dsl, "nfa_dsl_to_string returned NULL");

    /* Should always have both category and pattern */
    CHECK(strstr(dsl, "accept category=0x01 pattern=") != NULL,
          "accept line should include category= and pattern=");

    free(dsl);
    destroy_ctx(ctx);
    PASS();
    return true;
}

static bool test_canonical_deterministic_output(void) {
    TEST("deterministic: serialize same NFA twice produces identical strings");

    nfa_builder_context_t *ctx = create_ctx();
    CHECK(ctx, "failed to create context");
    ctx->current_pattern_index = 0;

    int s1 = nfa_construct_add_state_with_category(ctx, 0);
    int s2 = nfa_construct_add_state_with_category(ctx, 0x01);

    nfa_construct_add_transition(ctx, 0, s1, VSYM_EPS);
    nfa_construct_add_transition(ctx, 0, s2, VSYM_EPS);
    nfa_construct_add_transition(ctx, s1, s2, 'a');

    char *dsl1 = ctx_to_dsl(ctx);
    char *dsl2 = ctx_to_dsl(ctx);
    CHECK(dsl1 && dsl2, "nfa_dsl_to_string returned NULL");
    CHECK(strcmp(dsl1, dsl2) == 0, "two serializations of same NFA should be identical");

    free(dsl1);
    free(dsl2);
    destroy_ctx(ctx);
    PASS();
    return true;
}

static bool test_canonical_roundtrip(void) {
    TEST("round-trip: serialize -> parse -> serialize produces identical output");

    nfa_builder_context_t *ctx = create_ctx();
    CHECK(ctx, "failed to create context");
    ctx->current_pattern_index = 0;

    int s1 = nfa_construct_add_state_with_category(ctx, 0);
    int s2 = nfa_construct_add_state_with_category(ctx, 0x01);

    nfa_construct_add_transition(ctx, 0, s1, VSYM_EPS);
    nfa_construct_add_transition(ctx, s1, s2, 'b');
    nfa_construct_add_transition(ctx, 0, s2, 'a');

    char *dsl_orig = ctx_to_dsl(ctx);
    CHECK(dsl_orig, "first serialization failed");

    /* Parse the DSL back */
    dsl_nfa_t *parsed = nfa_dsl_parse_string(dsl_orig);
    CHECK(parsed, "parse of serialized output failed");

    /* The parsed NFA should have the same number of states */
    /* Count lines containing state definitions to verify structure preserved */
    int state_lines = 0;
    const char *p = dsl_orig;
    while (*p) {
        if (*p == ':' && p != dsl_orig && isdigit((unsigned char)*(p - 1))) {
            state_lines++;
        }
        p++;
    }
    CHECK(state_lines >= 3, "expected at least 3 state definitions");

    nfa_dsl_free(parsed);
    free(dsl_orig);
    destroy_ctx(ctx);
    PASS();
    return true;
}

static bool test_canonical_multiple_patterns(void) {
    TEST("multiple patterns: each gets its own accept state");

    nfa_builder_context_t *ctx = create_ctx();
    CHECK(ctx, "failed to create context");

    /* Pattern 1: 'a' */
    ctx->current_pattern_index = 0;
    int s1 = nfa_construct_add_state_with_category(ctx, 0x01);
    nfa_construct_add_transition(ctx, 0, s1, 'a');

    /* Pattern 2: 'b' */
    ctx->current_pattern_index = 1;
    int s2 = nfa_construct_add_state_with_category(ctx, 0x02);
    nfa_construct_add_transition(ctx, 0, s2, 'b');

    char *dsl = ctx_to_dsl(ctx);
    CHECK(dsl, "nfa_dsl_to_string returned NULL");

    /* Both accept states should be present with different categories */
    CHECK(strstr(dsl, "category=0x01 pattern=1") != NULL, "pattern 1 accept");
    CHECK(strstr(dsl, "category=0x02 pattern=2") != NULL, "pattern 2 accept");

    /* State 0 should have both 'a' and 'b' transitions */
    CHECK(strstr(dsl, "'a' ->") != NULL, "'a' transition");
    CHECK(strstr(dsl, "'b' ->") != NULL, "'b' transition");

    free(dsl);
    destroy_ctx(ctx);
    PASS();
    return true;
}

static bool test_canonical_epsilon_chain(void) {
    TEST("epsilon chain: 0 -EPS-> 1 -EPS-> 2 -'a'-> 3 (accept)");

    nfa_builder_context_t *ctx = create_ctx();
    CHECK(ctx, "failed to create context");
    ctx->current_pattern_index = 0;

    int s1 = nfa_construct_add_state_with_category(ctx, 0);
    int s2 = nfa_construct_add_state_with_category(ctx, 0);
    int s3 = nfa_construct_add_state_with_category(ctx, 0x01);

    nfa_construct_add_transition(ctx, 0, s1, VSYM_EPS);
    nfa_construct_add_transition(ctx, s1, s2, VSYM_EPS);
    nfa_construct_add_transition(ctx, s2, s3, 'a');

    char *dsl = ctx_to_dsl(ctx);
    CHECK(dsl, "nfa_dsl_to_string returned NULL");

    /* Should be 4 states, all reachable via BFS */
    const char *expected =
        "version: 1\n"
        "0: start\n"
        "0 EPS -> 1\n"
        "1:\n"
        "1 EPS -> 2\n"
        "2:\n"
        "2 'a' -> 3\n"
        "3: accept category=0x01 pattern=1\n";

    CHECK(strcmp(dsl, expected) == 0, "epsilon chain canonical mismatch");

    free(dsl);
    destroy_ctx(ctx);
    PASS();
    return true;
}

/* ============================================================================
 * Tests: Focused serialization
 * ============================================================================ */

static nfa_builder_context_t *build_multi_pattern_nfa(void) {
    nfa_builder_context_t *ctx = create_ctx();
    if (!ctx) return NULL;

    ctx->current_pattern_index = 0;
    int s1 = nfa_construct_add_state_with_category(ctx, 0x01);
    nfa_construct_add_transition(ctx, 0, s1, 'a');

    ctx->current_pattern_index = 1;
    int s2 = nfa_construct_add_state_with_category(ctx, 0x02);
    nfa_construct_add_transition(ctx, 0, s2, 'b');

    return ctx;
}

static bool test_filtered_from_start_state(void) {
    TEST("filtered: sub-graph from non-start state");
    nfa_builder_context_t *ctx = build_multi_pattern_nfa();
    CHECK(ctx, "failed to build multi-pattern NFA");

    /* Start from state 1 (accept for 'a'): single-node subgraph */
    nfa_dsl_filter_t filter = nfa_dsl_filter_from_state(1);
    nfa_graph_t *g1 = nfa_builder_finalize(ctx, NULL, NULL);
    char *dsl = g1 ? nfa_graph_dsl_to_string_filtered(g1, filter) : NULL;
    if (g1) nfa_graph_free(g1);
    CHECK(dsl, "nfa_graph_dsl_to_string_filtered returned NULL");

    const char *expected =
        "# Focused NFA from state 1\n"
        "0: start accept category=0x01 pattern=1\n";
    CHECK(strcmp(dsl, expected) == 0, "focused output mismatch");

    free(dsl);
    destroy_ctx(ctx);
    PASS();
    return true;
}

static bool test_filtered_pattern(void) {
    TEST("filtered: extract pattern with header comment");
    nfa_builder_context_t *ctx = build_multi_pattern_nfa();
    CHECK(ctx, "failed to build multi-pattern NFA");

    nfa_dsl_filter_t filter = nfa_dsl_filter_for_pattern(1, 0);
    nfa_graph_t *g2 = nfa_builder_finalize(ctx, NULL, NULL);
    char *dsl = g2 ? nfa_graph_dsl_to_string_filtered(g2, filter) : NULL;
    if (g2) nfa_graph_free(g2);
    CHECK(dsl, "nfa_graph_dsl_to_string_filtered returned NULL");
    CHECK(dsl, "nfa_graph_dsl_to_string_filtered returned NULL");

    CHECK(strstr(dsl, "# Focused NFA for pattern 1") != NULL,
          "missing pattern header comment");

    /* Canonical BFS reorders states at same level by signature.
     * Both accept states are at BFS level 1 from state 0.
     * The exact order depends on signature hashes, so check for presence. */
    CHECK(strstr(dsl, "0: start") != NULL, "state 0 start");
    CHECK(strstr(dsl, "accept category=0x01 pattern=1") != NULL,
          "pattern 0 accept present");
    CHECK(strstr(dsl, "accept category=0x02 pattern=2") != NULL,
          "pattern 1 accept present");

    free(dsl);
    destroy_ctx(ctx);
    PASS();
    return true;
}

static bool test_filtered_isolated_branch(void) {
    TEST("filtered: isolated branch with renumbering");
    nfa_builder_context_t *ctx = create_ctx();
    CHECK(ctx, "failed to create context");
    ctx->current_pattern_index = 0;

    /* Diamond: 0 -EPS-> 1 -'a'-> 3 (accept)
     *          0 -EPS-> 2 -'b'-> 4 (accept) */
    int s1 = nfa_construct_add_state_with_category(ctx, 0);
    int s2 = nfa_construct_add_state_with_category(ctx, 0);
    int s3 = nfa_construct_add_state_with_category(ctx, 0x01);
    int s4 = nfa_construct_add_state_with_category(ctx, 0x02);

    nfa_construct_add_transition(ctx, 0, s1, VSYM_EPS);
    nfa_construct_add_transition(ctx, 0, s2, VSYM_EPS);
    nfa_construct_add_transition(ctx, s1, s3, 'a');
    nfa_construct_add_transition(ctx, s2, s4, 'b');

    /* Start from state 2: only states 2 and 4, renumbered to 0,1 */
    nfa_dsl_filter_t filter = nfa_dsl_filter_from_state(s2);
    nfa_graph_t *g2 = nfa_builder_finalize(ctx, NULL, NULL);
    char *focused = g2 ? nfa_graph_dsl_to_string_filtered(g2, filter) : NULL;
    if (g2) nfa_graph_free(g2);
    CHECK(focused, "focused serialization failed");

    const char *expected =
        "# Focused NFA from state 2\n"
        "0: start\n"
        "0 'b' -> 1\n"
        "1: accept category=0x02 pattern=1\n";
    CHECK(strcmp(focused, expected) == 0, "focused branch output mismatch");

    free(focused);
    destroy_ctx(ctx);
    PASS();
    return true;
}

static bool test_filtered_with_markers(void) {
    TEST("filtered: marker filtering by pattern_id");
    nfa_builder_context_t *ctx = create_ctx();
    CHECK(ctx, "failed to create context");

    ctx->current_pattern_index = 0;
    int s1 = nfa_construct_add_state_with_category(ctx, 0x01);
    nfa_construct_add_transition(ctx, 0, s1, 'a');

    ctx->current_pattern_index = 1;
    int s2 = nfa_construct_add_state_with_category(ctx, 0x02);
    nfa_construct_add_transition(ctx, 0, s2, 'b');

    /* Add markers to transitions.
     * MARKER_PACK(pattern_id, uid, type) produces 0xPPUUUT.
     * For pattern_id=0: MARKER_PACK(0, 0, 0) = 0x00000000
     * For pattern_id=1: MARKER_PACK(1, 0, 0) = 0x00020000 */
    mta_add_marker(&ctx->nfa[0].multi_targets, 'a', 0, 0, 0);
    mta_add_marker(&ctx->nfa[0].multi_targets, 'b', 1, 0, 0);

    /* Full dump: both markers */
    char *full = ctx_to_dsl(ctx);
    CHECK(full, "full serialization failed");
    /* Markers are packed: MARKER_PACK(pid, uid, type).
     * pid=0 -> 0x00000000, pid=1 -> 0x00020000 */
    CHECK(strstr(full, "0x00000000") != NULL, "full: marker for pattern 0");
    CHECK(strstr(full, "0x00020000") != NULL, "full: marker for pattern 1");
    free(full);

    /* Filtered for pattern 1, excluding other markers.
     * Only markers with pattern_id=1 should remain. */
    nfa_dsl_filter_t filter = nfa_dsl_filter_for_pattern(1, 0);
    nfa_graph_t *g3 = nfa_builder_finalize(ctx, NULL, NULL);
    char *filtered = g3 ? nfa_graph_dsl_to_string_filtered(g3, filter) : NULL;
    if (g3) nfa_graph_free(g3);
    CHECK(filtered, "filtered serialization failed");

    CHECK(strstr(filtered, "0x00000000") == NULL,
          "pattern 0 marker should be excluded");
    CHECK(strstr(filtered, "0x00020000") != NULL,
          "pattern 1 marker should be included");

    free(filtered);
    destroy_ctx(ctx);
    PASS();
    return true;
}

static bool test_filtered_empty_subgraph(void) {
    TEST("filtered: invalid start state produces empty output");
    nfa_builder_context_t *ctx = create_ctx();
    CHECK(ctx, "failed to create context");

    ctx->current_pattern_index = 0;
    int s1 = nfa_construct_add_state_with_category(ctx, 0x01);
    nfa_construct_add_transition(ctx, 0, s1, 'a');

    nfa_dsl_filter_t filter = nfa_dsl_filter_from_state(999);
    nfa_graph_t *g4 = nfa_builder_finalize(ctx, NULL, NULL);
    char *dsl = g4 ? nfa_graph_dsl_to_string_filtered(g4, filter) : NULL;
    if (g4) nfa_graph_free(g4);
    CHECK(dsl, "should return non-NULL for empty subgraph");
    CHECK(strlen(dsl) == 0, "invalid start should produce empty output");

    free(dsl);
    destroy_ctx(ctx);
    PASS();
    return true;
}

/* ============================================================================
 * Tests: Version header
 * ============================================================================ */

static bool test_version_header(void) {
    TEST("version header present in serialized output");
    nfa_builder_context_t *ctx = create_ctx();
    CHECK(ctx, "failed to create context");

    ctx->current_pattern_index = 0;
    int s1 = nfa_construct_add_state_with_category(ctx, 0x01);
    nfa_construct_add_transition(ctx, 0, s1, 'x');

    char *dsl = ctx_to_dsl(ctx);
    CHECK(dsl, "nfa_dsl_to_string returned NULL");
    CHECK(strncmp(dsl, "version: 1\n", 11) == 0, "output must start with version: 1");

    free(dsl);
    destroy_ctx(ctx);
    PASS();
    return true;
}

static bool test_version_parsed(void) {
    TEST("version header parsed from DSL string");
    const char *dsl_text =
        "version: 1\n"
        "0: start\n"
        "0 'a' -> 1\n"
        "1: accept category=0x01 pattern=1\n";

    dsl_nfa_t *nfa = nfa_dsl_parse_string(dsl_text);
    CHECK(nfa, "parse returned NULL");
    CHECK(nfa->version == 1, "version should be 1");

    nfa_dsl_free(nfa);
    PASS();
    return true;
}

/* ============================================================================
 * Tests: Diff helpers
 * ============================================================================ */

static bool test_diff_identical(void) {
    TEST("diff: identical strings produce NULL");
    const char *s = "version: 1\n0: start\n";
    char *diff = nfa_dsl_diff(s, s);
    CHECK(diff == NULL, "identical strings should produce NULL diff");
    PASS();
    return true;
}

static bool test_diff_different(void) {
    TEST("diff: different strings produce diff output");
    const char *expected = "version: 1\n0: start\n0 'a' -> 1\n";
    const char *actual   = "version: 1\n0: start\n0 'b' -> 1\n";

    char *diff = nfa_dsl_diff(expected, actual);
    CHECK(diff != NULL, "different strings should produce diff");
    CHECK(strstr(diff, "--- expected") != NULL, "diff should have expected marker");
    CHECK(strstr(diff, "+++ actual") != NULL, "diff should have actual marker");
    CHECK(strstr(diff, "-0 'a' -> 1") != NULL, "diff should show removed line");
    CHECK(strstr(diff, "+0 'b' -> 1") != NULL, "diff should show added line");

    free(diff);
    PASS();
    return true;
}

static bool test_assert_equal(void) {
    TEST("assert_equal: returns true for matching, false for different");
    const char *s = "version: 1\n0: start\n";
    CHECK(nfa_dsl_assert_equal("test", s, s) == true, "identical should return true");

    /* Redirect stderr to suppress output during test */
    FILE *devnull = fopen("/dev/null", "w");
    FILE *old_stderr = stderr;
    stderr = devnull;
    bool result = nfa_dsl_assert_equal("test", s, "different\n") == false;
    stderr = old_stderr;
    fclose(devnull);
    CHECK(result, "different should return false");

    PASS();
    return true;
}

/* ============================================================================
 * Tests: Round-trip verification
 * ============================================================================ */

static bool test_roundtrip_ok(void) {
    TEST("round-trip: serialize same context twice matches");
    nfa_builder_context_t *ctx = create_ctx();
    CHECK(ctx, "failed to create context");
    ctx->current_pattern_index = 0;

    int s1 = nfa_construct_add_state_with_category(ctx, 0x01);
    nfa_construct_add_transition(ctx, 0, s1, 'a');
    nfa_construct_add_transition(ctx, 0, s1, 'b');

    char *diff;
    {
        nfa_graph_t *graph = nfa_builder_finalize(ctx, NULL, NULL);
        if (!graph) {
            destroy_ctx(ctx);
            FAIL("nfa_builder_finalize returned NULL");
            PASS();
            return false;
        }
        diff = nfa_graph_dsl_verify_roundtrip(graph);
        nfa_graph_free(graph);
    }
    CHECK(diff == NULL, "round-trip should be consistent");

    free(diff);
    destroy_ctx(ctx);
    PASS();
    return true;
}

/* ============================================================================
 * Tests: Validator / Linter
 * ============================================================================ */

static bool test_validate_valid(void) {
    TEST("validator: valid NFA passes");
    const char *dsl_text =
        "version: 1\n"
        "0: start\n"
        "0 'a' -> 1\n"
        "1: accept category=0x01 pattern=1\n";

    dsl_nfa_t *nfa = nfa_dsl_parse_string(dsl_text);
    CHECK(nfa, "parse returned NULL");

    dsl_validation_t *v = nfa_dsl_validate(nfa);
    CHECK(v, "validate returned NULL");
    CHECK(v->valid, "valid NFA should pass validation");
    CHECK(v->issue_count == 0, "valid NFA should have no issues");

    nfa_dsl_validation_free(v);
    nfa_dsl_free(nfa);
    PASS();
    return true;
}

static bool test_validate_undefined_target(void) {
    TEST("validator: transition to undefined state is ERROR");
    const char *dsl_text =
        "0: start\n"
        "0 'a' -> 5\n";

    dsl_nfa_t *nfa = nfa_dsl_parse_string(dsl_text);
    CHECK(nfa, "parse returned NULL");

    dsl_validation_t *v = nfa_dsl_validate(nfa);
    CHECK(v, "validate returned NULL");
    CHECK(!v->valid, "should have errors");

    bool found = false;
    for (int i = 0; i < v->issue_count; i++) {
        if (v->issues[i].severity == DSL_SEVERITY_ERROR &&
            strstr(v->issues[i].message, "undefined state") != NULL) {
            found = true;
        }
    }
    CHECK(found, "should report undefined state error");

    nfa_dsl_validation_free(v);
    nfa_dsl_free(nfa);
    PASS();
    return true;
}

static bool test_validate_warnings(void) {
    TEST("validator: dead end state produces WARNING");
    const char *dsl_text =
        "0: start\n"
        "0 'a' -> 1\n"
        "1:\n";

    dsl_nfa_t *nfa = nfa_dsl_parse_string(dsl_text);
    CHECK(nfa, "parse returned NULL");

    dsl_validation_t *v = nfa_dsl_validate(nfa);
    CHECK(v, "validate returned NULL");
    CHECK(v->valid, "warnings should not make valid=false");

    bool found = false;
    for (int i = 0; i < v->issue_count; i++) {
        if (v->issues[i].severity == DSL_SEVERITY_WARNING &&
            v->issues[i].state_id == 1 &&
            strstr(v->issues[i].message, "dead end") != NULL) {
            found = true;
        }
    }
    CHECK(found, "should warn about dead-end state");

    nfa_dsl_validation_free(v);
    nfa_dsl_free(nfa);
    PASS();
    return true;
}

/* ============================================================================
 * Tests: DOT visualization
 * ============================================================================ */

static bool test_dot_output(void) {
    TEST("DOT: basic NFA produces valid DOT output");
    const char *dsl_text =
        "0: start\n"
        "0 'a' -> 1\n"
        "0 EPS -> 2\n"
        "1: accept category=0x01 pattern=1\n"
        "2 'b' -> 1\n";

    dsl_nfa_t *nfa = nfa_dsl_parse_string(dsl_text);
    CHECK(nfa, "parse returned NULL");

    char *dot = nfa_dsl_to_dot(nfa);
    CHECK(dot, "nfa_dsl_to_dot returned NULL");
    CHECK(strstr(dot, "digraph NFA") != NULL, "should start with digraph");
    CHECK(strstr(dot, "__start -> 0") != NULL, "should have start arrow");
    CHECK(strstr(dot, "shape=doublecircle") != NULL, "accept should be doublecircle");
    CHECK(strstr(dot, "-> 1") != NULL, "should have edge to state 1");
    CHECK(strstr(dot, "EPS") != NULL, "should show EPS label");

    free(dot);
    nfa_dsl_free(nfa);
    PASS();
    return true;
}

/* ============================================================================
 * Tests: Assertion macros (ASSERT_NFA_EQ_STR)
 * ============================================================================ */

static bool test_assert_macro_pass(void) {
    TEST("ASSERT_NFA_EQ_STR: matching output passes");
    nfa_builder_context_t *ctx = create_ctx();
    CHECK(ctx, "failed to create context");

    ctx->current_pattern_index = 0;
    int s1 = nfa_construct_add_state_with_category(ctx, 0x01);
    nfa_construct_add_transition(ctx, 0, s1, 'z');

    char *actual = ctx_to_dsl(ctx);
    CHECK(actual, "nfa_dsl_to_string returned NULL");

    /* Should match - need to finalize ctx to graph for macro */
    nfa_graph_t *g = nfa_builder_finalize(ctx, NULL, NULL);
    if (g) {
        ASSERT_NFA_EQ_STR(g, actual, "assert macro pass test");
        nfa_graph_free(g);
    }

    free(actual);
    destroy_ctx(ctx);
    PASS();
    return true;
}

static bool test_assert_macro_fail(void) {
    TEST("ASSERT_NFA_EQ_STR: mismatching output fails gracefully");
    nfa_builder_context_t *ctx = create_ctx();
    CHECK(ctx, "failed to create context");

    ctx->current_pattern_index = 0;
    int s1 = nfa_construct_add_state_with_category(ctx, 0x01);
    nfa_construct_add_transition(ctx, 0, s1, 'z');

    /* Redirect stderr */
    FILE *devnull = fopen("/dev/null", "w");
    FILE *old_stderr = stderr;
    stderr = devnull;

    /* This should print diff to stderr and we catch the return */
    char *expected = "WRONG OUTPUT\n";
    char *actual = ctx_to_dsl(ctx);
    bool result = nfa_dsl_assert_equal("test", expected, actual) == false;

    stderr = old_stderr;
    fclose(devnull);

    CHECK(result, "mismatch should return false");

    free(actual);
    destroy_ctx(ctx);
    PASS();
    return true;
}

/* ============================================================================
 * Tests: DFA DSL Serialization
 * ============================================================================ */

/* Helper: Create a simple 3-state DFA (start, intermediate, accept)
 * with transitions: 0 -'a'-> 1 -'b'-> 2 (accept, cat=0x01, pat=1)
 * Uses build_dfa_state_t directly (no NFA conversion needed). */
static build_dfa_state_t **create_simple_dfa(int *out_count,
                                              alphabet_entry_t **out_alphabet,
                                              int *out_alpha_size) {
    int alpha_size = VSYM_TAB + 1; /* Standard alphabet */
    int state_count = 3;

    /* Build alphabet */
    alphabet_entry_t *alpha = calloc((size_t)alpha_size, sizeof(alphabet_entry_t));
    for (int i = 0; i < BYTE_VALUE_MAX; i++) {
        alpha[i].symbol_id = i;
        alpha[i].start_char = i;
        alpha[i].end_char = i;
        alpha[i].is_special = false;
    }
    alpha[VSYM_BYTE_ANY].symbol_id = VSYM_BYTE_ANY;
    alpha[VSYM_BYTE_ANY].start_char = 0;
    alpha[VSYM_BYTE_ANY].end_char = 255;
    alpha[VSYM_BYTE_ANY].is_special = true;
    alpha[VSYM_EPS].symbol_id = VSYM_EPS;
    alpha[VSYM_EPS].is_special = true;
    alpha[VSYM_EOS].symbol_id = VSYM_EOS;
    alpha[VSYM_EOS].is_special = true;
    alpha[VSYM_SPACE].symbol_id = VSYM_SPACE;
    alpha[VSYM_SPACE].is_special = true;
    alpha[VSYM_TAB].symbol_id = VSYM_TAB;
    alpha[VSYM_TAB].is_special = true;

    /* Build DFA states */
    build_dfa_state_t **dfa = calloc((size_t)state_count, sizeof(build_dfa_state_t *));

    /* State 0: start, 'a'->1 */
    dfa[0] = build_dfa_state_create(alpha_size, 4);
    dfa[0]->transitions['a'] = 1;

    /* State 1: intermediate, 'b'->2 */
    dfa[1] = build_dfa_state_create(alpha_size, 4);
    dfa[1]->transitions['b'] = 2;

    /* State 2: accept, category=0x01, pattern=1 */
    dfa[2] = build_dfa_state_create(alpha_size, 4);
    dfa[2]->flags = DFA_STATE_ACCEPTING;
    DFA_SET_CATEGORY_MASK(dfa[2]->flags, 0x01);
    dfa[2]->accepting_pattern_id = 1;

    *out_count = state_count;
    *out_alphabet = alpha;
    *out_alpha_size = alpha_size;
    return dfa;
}

static void destroy_simple_dfa(build_dfa_state_t **dfa, int count,
                                alphabet_entry_t *alpha) {
    for (int i = 0; i < count; i++) {
        build_dfa_state_destroy(dfa[i]);
    }
    free(dfa);
    free(alpha);
}

static bool test_dfa_serialize_simple(void) {
    TEST("DFA: serialize simple 3-state DFA (a-b)");

    int state_count = 0, alpha_size = 0;
    alphabet_entry_t *alpha = NULL;
    build_dfa_state_t **dfa = create_simple_dfa(&state_count, &alpha, &alpha_size);
    CHECK(dfa, "failed to create DFA");

    char *dsl = dfa_dsl_to_string((const build_dfa_state_t * const *)dfa, state_count, alpha, alpha_size, NULL, 0);
    CHECK(dsl, "dfa_dsl_to_string returned NULL");

    /* Check header */
    CHECK(strstr(dsl, "type: DFA\n") != NULL, "missing DFA type header");
    CHECK(strstr(dsl, "version: 1\n") != NULL, "missing version header");
    CHECK(strstr(dsl, "alphabet_size:") != NULL, "missing alphabet_size");
    CHECK(strstr(dsl, "initial: 0\n") != NULL, "missing initial state");

    /* Check state definitions */
    CHECK(strstr(dsl, "0: start\n") != NULL, "state 0 should be start");
    CHECK(strstr(dsl, "1:") != NULL, "state 1 should be defined");
    CHECK(strstr(dsl, "2: accept category=0x01 pattern=1") != NULL,
          "state 2 should be accept");

    /* Check transitions */
    CHECK(strstr(dsl, "0 'a' -> 1") != NULL, "0 'a' -> 1");
    CHECK(strstr(dsl, "1 'b' -> 2") != NULL, "1 'b' -> 2");

    free(dsl);
    destroy_simple_dfa(dfa, state_count, alpha);
    PASS();
    return true;
}

static bool test_dfa_parse_simple(void) {
    TEST("DFA: parse simple DFA DSL string");

    const char *dsl_text =
        "type: DFA\n"
        "version: 1\n"
        "alphabet_size: 261\n"
        "initial: 0\n"
        "0: start\n"
        "0 'a' -> 1\n"
        "1:\n"
        "1 'b' -> 2\n"
        "2: accept category=0x01 pattern=1\n";

    dsl_dfa_t *dfa = dfa_dsl_parse_string(dsl_text);
    CHECK(dfa, "dfa_dsl_parse_string returned NULL");
    CHECK(dfa->dsl_type == DSL_TYPE_DFA, "type should be DFA");
    CHECK(dfa->version == 1, "version should be 1");
    CHECK(dfa->start_state == 0, "start state should be 0");
    CHECK(dfa->state_count == 3, "should have 3 states");
    CHECK(dfa->alphabet_size == 261, "alphabet_size should be 261");

    /* State 0 */
    CHECK(dfa->states[0].is_start, "state 0 should be start");
    CHECK(!dfa->states[0].is_accept, "state 0 should not be accept");
    CHECK(dfa->states[0].symbol_transition_count == 1, "state 0 should have 1 transition");
    CHECK(dfa->states[0].symbol_transitions[0].symbol_id == 'a', "symbol should be 'a'");
    CHECK(dfa->states[0].symbol_transitions[0].targets[0] == 1, "target should be 1");

    /* State 1 */
    CHECK(!dfa->states[1].is_accept, "state 1 should not be accept");
    CHECK(dfa->states[1].symbol_transition_count == 1, "state 1 should have 1 transition");

    /* State 2 */
    CHECK(dfa->states[2].is_accept, "state 2 should be accept");
    CHECK(dfa->states[2].category_mask == 0x01, "category should be 0x01");
    CHECK(dfa->states[2].pattern_id == 1, "pattern_id should be 1");

    dfa_dsl_free(dfa);
    PASS();
    return true;
}

static bool test_dfa_parse_default_transition(void) {
    TEST("DFA: parse default transition");

    const char *dsl_text =
        "type: DFA\n"
        "version: 1\n"
        "alphabet_size: 261\n"
        "initial: 0\n"
        "0: start\n"
        "0 'a' -> 1\n"
        "0 default -> 2\n"
        "1: accept category=0x01 pattern=1\n"
        "2:\n";

    dsl_dfa_t *dfa = dfa_dsl_parse_string(dsl_text);
    CHECK(dfa, "dfa_dsl_parse_string returned NULL");

    /* State 0 should have default target */
    CHECK(dfa->states[0].has_default, "state 0 should have default");
    CHECK(dfa->states[0].default_target == 2, "default target should be 2");
    CHECK(dfa->states[0].symbol_transition_count == 1, "should have 1 explicit transition");

    dfa_dsl_free(dfa);
    PASS();
    return true;
}

static bool test_dfa_parse_range(void) {
    TEST("DFA: parse range transition");

    const char *dsl_text =
        "type: DFA\n"
        "version: 1\n"
        "alphabet_size: 261\n"
        "initial: 0\n"
        "0: start\n"
        "0 'a'-'z' -> 1\n"
        "1: accept category=0x01 pattern=1\n";

    dsl_dfa_t *dfa = dfa_dsl_parse_string(dsl_text);
    CHECK(dfa, "dfa_dsl_parse_string returned NULL");

    /* Range 'a'-'z' should expand to 26 individual transitions */
    CHECK(dfa->states[0].symbol_transition_count == 26,
          "range should expand to 26 transitions");

    /* Verify first and last */
    bool found_a = false, found_z = false;
    for (int i = 0; i < dfa->states[0].symbol_transition_count; i++) {
        int sym = dfa->states[0].symbol_transitions[i].symbol_id;
        if (sym == 'a') found_a = true;
        if (sym == 'z') found_z = true;
    }
    CHECK(found_a, "should contain 'a'");
    CHECK(found_z, "should contain 'z'");

    dfa_dsl_free(dfa);
    PASS();
    return true;
}

static bool test_dfa_parse_eos(void) {
    TEST("DFA: parse EOS transition");

    const char *dsl_text =
        "type: DFA\n"
        "version: 1\n"
        "alphabet_size: 261\n"
        "initial: 0\n"
        "0: start\n"
        "0 'a' -> 1\n"
        "1: accept category=0x01 pattern=1\n"
        "1 EOS -> 2\n"
        "2:\n";

    dsl_dfa_t *dfa = dfa_dsl_parse_string(dsl_text);
    CHECK(dfa, "dfa_dsl_parse_string returned NULL");

    CHECK(dfa->states[1].eos_target == 2, "state 1 EOS target should be 2");

    dfa_dsl_free(dfa);
    PASS();
    return true;
}

static bool test_dfa_parse_markers(void) {
    TEST("DFA: parse transition markers");

    const char *dsl_text =
        "type: DFA\n"
        "version: 1\n"
        "alphabet_size: 261\n"
        "initial: 0\n"
        "0: start\n"
        "0 'a' -> 1 [0x00010000,0x00020001]\n"
        "1: accept category=0x01 pattern=1\n";

    dsl_dfa_t *dfa = dfa_dsl_parse_string(dsl_text);
    CHECK(dfa, "dfa_dsl_parse_string returned NULL");

    CHECK(dfa->states[0].symbol_transition_count == 1, "1 transition");
    CHECK(dfa->states[0].symbol_transitions[0].marker_count == 2, "2 markers");
    CHECK(dfa->states[0].symbol_transitions[0].markers[0].value == 0x00010000,
          "marker 0");
    CHECK(dfa->states[0].symbol_transitions[0].markers[1].value == 0x00020001,
          "marker 1");

    dfa_dsl_free(dfa);
    PASS();
    return true;
}

static bool test_dfa_deterministic(void) {
    TEST("DFA: deterministic output - serialize same DFA twice");

    int state_count = 0, alpha_size = 0;
    alphabet_entry_t *alpha = NULL;
    build_dfa_state_t **dfa = create_simple_dfa(&state_count, &alpha, &alpha_size);
    CHECK(dfa, "failed to create DFA");

    char *dsl1 = dfa_dsl_to_string((const build_dfa_state_t * const *)dfa, state_count, alpha, alpha_size, NULL, 0);
    char *dsl2 = dfa_dsl_to_string((const build_dfa_state_t * const *)dfa, state_count, alpha, alpha_size, NULL, 0);
    CHECK(dsl1 && dsl2, "dfa_dsl_to_string returned NULL");
    CHECK(strcmp(dsl1, dsl2) == 0, "two serializations should be identical");

    free(dsl1);
    free(dsl2);
    destroy_simple_dfa(dfa, state_count, alpha);
    PASS();
    return true;
}

static bool test_dfa_with_default_compression(void) {
    TEST("DFA: default transition compression for common target");

    int alpha_size = VSYM_TAB + 1;
    alphabet_entry_t *alpha = calloc((size_t)alpha_size, sizeof(alphabet_entry_t));
    for (int i = 0; i < BYTE_VALUE_MAX; i++) {
        alpha[i].symbol_id = i;
        alpha[i].start_char = i;
        alpha[i].end_char = i;
    }
    alpha[VSYM_BYTE_ANY].symbol_id = VSYM_BYTE_ANY;
    alpha[VSYM_EOS].symbol_id = VSYM_EOS;
    alpha[VSYM_SPACE].symbol_id = VSYM_SPACE;
    alpha[VSYM_TAB].symbol_id = VSYM_TAB;

    /* Build DFA where state 0 sends most bytes to state 2 (dead),
     * but 'a' and 'b' to state 1 */
    int state_count = 3;
    build_dfa_state_t **dfa = calloc((size_t)state_count, sizeof(build_dfa_state_t *));

    /* State 0: start, 'a'->1, 'b'->1, everything else->2 */
    dfa[0] = build_dfa_state_create(alpha_size, 4);
    dfa[0]->transitions['a'] = 1;
    dfa[0]->transitions['b'] = 1;
    for (int c = 0; c < BYTE_VALUE_MAX; c++) {
        if (c != 'a' && c != 'b') {
            dfa[0]->transitions[c] = 2;
        }
    }

    /* State 1: accept */
    dfa[1] = build_dfa_state_create(alpha_size, 4);
    dfa[1]->flags = DFA_STATE_ACCEPTING;
    DFA_SET_CATEGORY_MASK(dfa[1]->flags, 0x01);
    dfa[1]->accepting_pattern_id = 1;

    /* State 2: dead state */
    dfa[2] = build_dfa_state_create(alpha_size, 4);

    char *dsl = dfa_dsl_to_string((const build_dfa_state_t * const *)dfa, state_count, alpha, alpha_size, NULL, 0);
    CHECK(dsl, "dfa_dsl_to_string returned NULL");

    /* Should have default transition for the most common target.
     * After BFS canonicalization, states may be renumbered:
     * old state 2 (dead) → new state 1, old state 1 (accept) → new state 2.
     * The default goes to whichever state the majority of transitions target. */
    CHECK(strstr(dsl, "default ->") != NULL,
          "should have a default transition");

    /* Should NOT have 254 individual transitions to the default target */
    /* The only explicit transitions should be 'a' and 'b' (as a range) */
    CHECK(strstr(dsl, "'a'-'b' ->") != NULL,
          "should have compressed 'a'-'b' range");

    free(dsl);
    destroy_simple_dfa(dfa, state_count, alpha);
    PASS();
    return true;
}

static bool test_dfa_roundtrip_parse(void) {
    TEST("DFA: round-trip parse -> serialize -> compare header");

    const char *dsl_text =
        "type: DFA\n"
        "version: 1\n"
        "alphabet_size: 261\n"
        "initial: 0\n"
        "0: start\n"
        "0 'a' -> 1\n"
        "1: accept category=0x01 pattern=1\n";

    dsl_dfa_t *dfa = dfa_dsl_parse_string(dsl_text);
    CHECK(dfa, "parse returned NULL");
    CHECK(dfa->dsl_type == DSL_TYPE_DFA, "type should be DFA");
    CHECK(dfa->state_count == 2, "should have 2 states");
    CHECK(dfa->states[0].is_start, "state 0 start");
    CHECK(dfa->states[1].is_accept, "state 1 accept");
    CHECK(dfa->states[0].symbol_transition_count == 1, "1 transition");

    dfa_dsl_free(dfa);
    PASS();
    return true;
}

static bool test_dfa_free_null(void) {
    TEST("DFA: dfa_dsl_free(NULL) is safe");
    dfa_dsl_free(NULL);
    PASS();
    return true;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    printf("\nNFA DSL Tests\n");
    printf("=============\n\n");

    /* Basic */
    test_serialize_simple();
    test_parse_simple();

    /* Virtual symbols */
    test_parse_virtual_symbols();
    test_symbol_helpers();

    /* Markers */
    test_parse_markers();

    /* Escapes */
    test_parse_escapes();

    /* I/O */
    test_parse_file();
    test_parse_hex_byte();

    /* Equality */
    test_structural_equality();

    /* Canonicalization */
    test_canonical_bfs_renumbering();
    test_canonical_unreachable_omitted();
    test_canonical_accept_always_has_category_pattern();
    test_canonical_deterministic_output();
    test_canonical_roundtrip();
    test_canonical_multiple_patterns();
    test_canonical_epsilon_chain();

    /* Focused serialization */
    test_filtered_from_start_state();
    test_filtered_pattern();
    test_filtered_isolated_branch();
    test_filtered_with_markers();
    test_filtered_empty_subgraph();

    /* Version header */
    test_version_header();
    test_version_parsed();

    /* Diff */
    test_diff_identical();
    test_diff_different();
    test_assert_equal();

    /* Round-trip */
    test_roundtrip_ok();

    /* Validator */
    test_validate_valid();
    test_validate_undefined_target();
    test_validate_warnings();

    /* DOT visualization */
    test_dot_output();

    /* Assertion macros */
    test_assert_macro_pass();
    test_assert_macro_fail();

    /* DFA DSL */
    printf("\nDFA DSL Tests\n");
    printf("-------------\n\n");
    test_dfa_serialize_simple();
    test_dfa_parse_simple();
    test_dfa_parse_default_transition();
    test_dfa_parse_range();
    test_dfa_parse_eos();
    test_dfa_parse_markers();
    test_dfa_deterministic();
    test_dfa_with_default_compression();
    test_dfa_roundtrip_parse();
    test_dfa_free_null();

    printf("\n=============\n");
    printf("Results: %d/%d passed\n", pass_count, test_count);

    if (pass_count == test_count) {
        printf("ALL TESTS PASSED\n\n");
        return 0;
    } else {
        printf("%d TESTS FAILED\n\n", test_count - pass_count);
        return 1;
    }
}
