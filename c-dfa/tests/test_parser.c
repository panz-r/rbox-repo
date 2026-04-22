/**
 * Parser Unit Tests - Tests for pattern parser and NFA construction
 *
 * Tests cover:
 * - Basic literal patterns
 * - Parentheses and grouping
 * - Quantifiers (*, +, ?)
 * - Alternation (|)
 * - Capture markers
 * - Fragment references
 * - Error detection
 */

#define _DEFAULT_SOURCE

#include "../lib/nfa_builder.h"
#include "../include/nfa.h"
#include "../include/multi_target_array.h"
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

#define ASSERT(cond) do { if (!(cond)) return false; } while(0)
#define ASSERT_EQUAL(exp, act) do { if ((exp) != (act)) { return false; } } while(0)
#define ASSERT_TRUE(cond) ASSERT(cond)
#define ASSERT_FALSE(cond) ASSERT(!(cond))

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

static nfa_graph_t* parse_pattern_line(const char* pattern_line) {
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

static bool parse_fails_with_error_type(const char* pattern_line, parse_error_type_t expected_type) {
    nfa_builder_context_t* ctx = nfa_builder_context_create();
    if (!ctx) return false;
    
    nfa_construct_init(ctx);
    
    char* tmpfile = strdup("/tmp/test_parser_XXXXXX");
    int fd = mkstemp(tmpfile);
    if (fd < 0) {
        free(tmpfile);
        nfa_builder_context_destroy(ctx);
        return false;
    }
    
    FILE* f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        unlink(tmpfile);
        free(tmpfile);
        nfa_builder_context_destroy(ctx);
        return false;
    }
    
    fprintf(f, "%s%s\n", CATEGORIES_SECTION, pattern_line);
    fclose(f);
    
    nfa_parser_read_spec_file(ctx, tmpfile);
    unlink(tmpfile);
    free(tmpfile);
    
    bool has_error = nfa_parser_has_error(ctx);
    const parse_error_info_t* err = nfa_parser_get_error(ctx);
    bool matches = has_error && err->type == expected_type;
    
    nfa_builder_context_destroy(ctx);
    return matches;
}

// ============================================================================
// Basic Literal Patterns
// ============================================================================

static bool test_literal_a(void) {
    nfa_graph_t* graph = parse_pattern_line("[safe] a");
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 2);
    ASSERT_TRUE(nfa_state_is_accepting(graph, graph->state_count - 1));
    
    nfa_graph_free(graph);
    return true;
}

static bool test_literal_chain(void) {
    nfa_graph_t* graph = parse_pattern_line("[safe] abc");
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 4);
    
    nfa_graph_free(graph);
    return true;
}

static bool test_literal_with_category(void) {
    nfa_graph_t* graph = parse_pattern_line("[caution] rm -rf /");
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 2);
    
    nfa_graph_free(graph);
    return true;
}

static bool test_max_length_pattern(void) {
    char pattern[600];
    strcpy(pattern, "[safe] ");
    for (int i = 7; i < 511; i++) {
        pattern[i] = 'a';
    }
    pattern[511] = '\0';
    
    nfa_graph_t* graph = parse_pattern_line(pattern);
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 2);
    
    nfa_graph_free(graph);
    return true;
}

static bool test_too_long_pattern(void) {
    char pattern[600];
    strcpy(pattern, "[safe] ");
    for (int i = 7; i < 600; i++) {
        pattern[i] = 'a';
    }
    pattern[600] = '\0';
    
    bool result = parse_fails_with_error_type(pattern, PARSE_ERROR_LENGTH);
    return result;
}

// ============================================================================
// Parentheses and Grouping
// ============================================================================

static bool test_simple_group(void) {
    nfa_graph_t* graph = parse_pattern_line("[safe] (a)");
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 2);
    
    nfa_graph_free(graph);
    return true;
}

static bool test_nested_groups(void) {
    nfa_graph_t* graph = parse_pattern_line("[safe] ((a))");
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 2);
    
    nfa_graph_free(graph);
    return true;
}

static bool test_unclosed_paren(void) {
    bool result = parse_fails_with_error_type("[safe] (a", PARSE_ERROR_UNCLOSED_PAREN);
    return result;
}

static bool test_unmatched_paren(void) {
    bool result = parse_fails_with_error_type("[safe] a)", PARSE_ERROR_UNMATCHED_PAREN);
    return result;
}

// ============================================================================
// Quantifiers
// ============================================================================

static bool test_star_quantifier(void) {
    nfa_graph_t* graph = parse_pattern_line("[safe] (a)*");
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 2);
    
    nfa_graph_free(graph);
    return true;
}

static bool test_plus_quantifier(void) {
    nfa_graph_t* graph = parse_pattern_line("[safe] (a)+");
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 2);
    
    nfa_graph_free(graph);
    return true;
}

static bool test_question_quantifier(void) {
    nfa_graph_t* graph = parse_pattern_line("[safe] (a)?");
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 2);
    
    nfa_graph_free(graph);
    return true;
}

static bool test_quantifier_on_literal(void) {
    bool result = parse_fails_with_error_type("[safe] a*", PARSE_ERROR_QUANTIFIER_POSITION);
    return result;
}

static bool test_nested_quantifiers(void) {
    nfa_graph_t* graph = parse_pattern_line("[safe] ((a)*)+");
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 2);
    
    nfa_graph_free(graph);
    return true;
}

// ============================================================================
// Alternation
// ============================================================================

static bool test_alternation_two(void) {
    nfa_graph_t* graph = parse_pattern_line("[safe] (a|b)");
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 3);
    
    nfa_graph_free(graph);
    return true;
}

static bool test_alternation_three(void) {
    nfa_graph_t* graph = parse_pattern_line("[safe] (a|b|c)");
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 4);
    
    nfa_graph_free(graph);
    return true;
}

static bool test_alternation_empty_first(void) {
    nfa_graph_t* graph = parse_pattern_line("[safe] (|a)");
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 2);
    
    nfa_graph_free(graph);
    return true;
}

static bool test_alternation_empty_last(void) {
    nfa_graph_t* graph = parse_pattern_line("[safe] (a|)");
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 2);
    
    nfa_graph_free(graph);
    return true;
}

// ============================================================================
// Capture Markers
// ============================================================================

static bool test_capture_start(void) {
    nfa_graph_t* graph = parse_pattern_line("[safe] <name>a");
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 2);
    
    nfa_graph_free(graph);
    return true;
}

static bool test_capture_end(void) {
    nfa_graph_t* graph = parse_pattern_line("[safe] a</name>");
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 2);
    
    nfa_graph_free(graph);
    return true;
}

static bool test_capture_full(void) {
    nfa_graph_t* graph = parse_pattern_line("[safe] <name>a</name>");
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 2);
    
    nfa_graph_free(graph);
    return true;
}

static bool test_capture_nested(void) {
    nfa_graph_t* graph = parse_pattern_line("[safe] <outer><inner>a</inner></outer>");
    if (!graph) return false;
    
    ASSERT_TRUE(graph->state_count >= 2);
    
    nfa_graph_free(graph);
    return true;
}

// ============================================================================
// Fragment References
// ============================================================================

static bool parse_spec(const char* spec_content) {
    nfa_builder_context_t* ctx = nfa_builder_context_create();
    if (!ctx) return false;
    
    nfa_construct_init(ctx);
    
    char* tmpfile = strdup("/tmp/test_parser_XXXXXX");
    int fd = mkstemp(tmpfile);
    if (fd < 0) {
        free(tmpfile);
        nfa_builder_context_destroy(ctx);
        return false;
    }
    
    FILE* f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        unlink(tmpfile);
        free(tmpfile);
        nfa_builder_context_destroy(ctx);
        return false;
    }
    
    fprintf(f, "%s", spec_content);
    fclose(f);
    
    nfa_parser_read_spec_file(ctx, tmpfile);
    unlink(tmpfile);
    free(tmpfile);
    
    bool has_error = nfa_parser_has_error(ctx);
    nfa_builder_context_destroy(ctx);
    return !has_error;
}

static bool test_fragment_simple(void) {
    const char* spec = 
        "[CATEGORIES]\n"
        "0: safe\n"
        "\n"
        "[fragment:foo] a\n"
        "[safe] ((foo))\n";
    
    return parse_spec(spec);
}

static bool test_fragment_undefined(void) {
    const char* spec = 
        "[CATEGORIES]\n"
        "0: safe\n"
        "\n"
        "[safe] ((missing))\n";
    
    return parse_spec(spec);
}

static bool test_fragment_in_alternation(void) {
    const char* spec = 
        "[CATEGORIES]\n"
        "0: safe\n"
        "\n"
        "[fragment:x] a\n"
        "[fragment:y] b\n"
        "[safe] (((x))|((y)))\n";
    
    return parse_spec(spec);
}

// ============================================================================
// Error Conditions
// ============================================================================

static bool test_error_empty_pattern(void) {
    nfa_builder_context_t* ctx = nfa_builder_context_create();
    if (!ctx) return false;
    
    nfa_construct_init(ctx);
    nfa_parser_parse_pattern(ctx, "");
    
    bool has_error = nfa_parser_has_error(ctx);
    
    nfa_builder_context_destroy(ctx);
    return has_error;
}

static bool test_error_invalid_category(void) {
    bool result = parse_fails_with_error_type("[unknown] a", PARSE_ERROR_CATEGORY);
    return result;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    printf("Parser Unit Tests\n");
    printf("=================\n\n");
    
    printf("Basic Literals:\n");
    TEST(literal_a);
    TEST(literal_chain);
    TEST(literal_with_category);
    TEST(max_length_pattern);
    TEST(too_long_pattern);
    
    printf("\nParentheses and Grouping:\n");
    TEST(simple_group);
    TEST(nested_groups);
    TEST(unclosed_paren);
    TEST(unmatched_paren);
    
    printf("\nQuantifiers:\n");
    TEST(star_quantifier);
    TEST(plus_quantifier);
    TEST(question_quantifier);
    TEST(quantifier_on_literal);
    TEST(nested_quantifiers);
    
    printf("\nAlternation:\n");
    TEST(alternation_two);
    TEST(alternation_three);
    TEST(alternation_empty_first);
    TEST(alternation_empty_last);
    
    printf("\nCapture Markers:\n");
    TEST(capture_start);
    TEST(capture_end);
    TEST(capture_full);
    TEST(capture_nested);
    
    printf("\nFragment References:\n");
    TEST(fragment_simple);
    TEST(fragment_undefined);
    TEST(fragment_in_alternation);
    
    printf("\nError Conditions:\n");
    TEST(error_empty_pattern);
    TEST(error_invalid_category);
    
    printf("\n=================\n");
    printf("SUMMARY: %d/%d passed\n", tests_passed, tests_run);
    
    return (tests_failed > 0) ? 1 : 0;
}