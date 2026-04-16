/*
 * test_token_types.c – Unit tests for the wildcard lattice and token classification.
 *
 * Tests all 12+1 types, the join table, and the compatibility table.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "rbox_policy_learner.h"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  %-45s ", #name); \
    if (name()) { \
        tests_passed++; \
        printf("PASS\n"); \
    } else { \
        tests_failed++; \
        printf("FAIL\n"); \
    } \
} while(0)

#define ASSERT(cond) do { if (!(cond)) { printf("  Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__); return 0; } } while(0)
#define ASSERT_TYPE(token, expected) do { \
    cpl_token_type_t t = cpl_classify_token(token); \
    if (t != expected) { \
        printf("  classify('%s') = %s, expected %s at %s:%d\n", \
               token, cpl_type_symbol[t], cpl_type_symbol[expected], \
               __FILE__, __LINE__); \
        return 0; \
    } \
} while(0)

/* ============================================================
 * TYPE CLASSIFICATION
 * ============================================================ */

/* --- #h: Hex hash (8+ hex chars) --- */

static int test_classify_hexhash_lowercase(void)
{
    ASSERT_TYPE("deadbeef", CPL_TYPE_HEXHASH);
    return 1;
}

static int test_classify_hexhash_mixed(void)
{
    ASSERT_TYPE("a1B2c3D4e5F6", CPL_TYPE_HEXHASH);
    return 1;
}

static int test_classify_hexhash_long(void)
{
    ASSERT_TYPE("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", CPL_TYPE_HEXHASH);
    return 1;
}

static int test_classify_hexhash_too_short(void)
{
    /* 7 hex chars is too short for #h - falls through to LITERAL */
    ASSERT_TYPE("deadbee", CPL_TYPE_LITERAL);
    return 1;
}

/* --- #n: Number --- */

static int test_classify_number_decimal(void)
{
    ASSERT_TYPE("42", CPL_TYPE_NUMBER);
    return 1;
}

static int test_classify_number_negative(void)
{
    ASSERT_TYPE("-100", CPL_TYPE_NUMBER);
    return 1;
}

static int test_classify_number_hex_prefix(void)
{
    ASSERT_TYPE("0xff", CPL_TYPE_NUMBER);
    return 1;
}

static int test_classify_number_octal(void)
{
    ASSERT_TYPE("0755", CPL_TYPE_NUMBER);
    return 1;
}

static int test_classify_number_zero(void)
{
    ASSERT_TYPE("0", CPL_TYPE_NUMBER);
    return 1;
}

/* --- #i: IPv4 --- */

static int test_classify_ipv4_standard(void)
{
    ASSERT_TYPE("192.168.1.1", CPL_TYPE_IPV4);
    return 1;
}

static int test_classify_ipv4_localhost(void)
{
    ASSERT_TYPE("127.0.0.1", CPL_TYPE_IPV4);
    return 1;
}

static int test_classify_ipv4_all_zeros(void)
{
    ASSERT_TYPE("0.0.0.0", CPL_TYPE_IPV4);
    return 1;
}

/* --- #w: Word --- */

static int test_classify_word_simple(void)
{
    /* Words are LITERAL by default - they could be command names */
    ASSERT_TYPE("nginx", CPL_TYPE_LITERAL);
    return 1;
}

static int test_classify_word_underscore(void)
{
    ASSERT_TYPE("my_var", CPL_TYPE_LITERAL);
    return 1;
}

static int test_classify_word_uppercase(void)
{
    ASSERT_TYPE("PATH", CPL_TYPE_LITERAL);
    return 1;
}

static int test_classify_word_with_digits(void)
{
    ASSERT_TYPE("var123", CPL_TYPE_LITERAL);
    return 1;
}

static int test_classify_word_underscore_start(void)
{
    ASSERT_TYPE("_private", CPL_TYPE_LITERAL);
    return 1;
}

/* --- #f: Filename (has dot, no slash) --- */

static int test_classify_filename_with_ext(void)
{
    ASSERT_TYPE("output.txt", CPL_TYPE_FILENAME);
    return 1;
}

static int test_classify_filename_c_source(void)
{
    ASSERT_TYPE("main.c", CPL_TYPE_FILENAME);
    return 1;
}

static int test_classify_filename_multiple_dots(void)
{
    ASSERT_TYPE("archive.tar.gz", CPL_TYPE_FILENAME);
    return 1;
}

static int test_classify_filename_hidden(void)
{
    ASSERT_TYPE(".gitignore", CPL_TYPE_FILENAME);
    return 1;
}

/* --- #r: Relative path --- */

static int test_classify_relpath_with_slash(void)
{
    ASSERT_TYPE("src/main.c", CPL_TYPE_REL_PATH);
    return 1;
}

static int test_classify_relpath_dotdot(void)
{
    ASSERT_TYPE("../lib/foo", CPL_TYPE_REL_PATH);
    return 1;
}

static int test_classify_relpath_dot(void)
{
    ASSERT_TYPE("./configure", CPL_TYPE_REL_PATH);
    return 1;
}

static int test_classify_relpath_deep(void)
{
    ASSERT_TYPE("src/utils/helpers.c", CPL_TYPE_REL_PATH);
    return 1;
}

/* --- #p: Absolute path --- */

static int test_classify_abspath_simple(void)
{
    ASSERT_TYPE("/etc/passwd", CPL_TYPE_ABS_PATH);
    return 1;
}

static int test_classify_abspath_root(void)
{
    ASSERT_TYPE("/tmp", CPL_TYPE_ABS_PATH);
    return 1;
}

static int test_classify_abspath_deep(void)
{
    ASSERT_TYPE("/usr/local/bin/gcc", CPL_TYPE_ABS_PATH);
    return 1;
}

/* --- #u: URL --- */

static int test_classify_url_https(void)
{
    ASSERT_TYPE("https://example.com", CPL_TYPE_URL);
    return 1;
}

static int test_classify_url_http(void)
{
    ASSERT_TYPE("http://localhost:8080", CPL_TYPE_URL);
    return 1;
}

static int test_classify_url_git(void)
{
    ASSERT_TYPE("git://github.com/user/repo", CPL_TYPE_URL);
    return 1;
}

static int test_classify_url_ftp(void)
{
    ASSERT_TYPE("ftp://files.example.com/pub", CPL_TYPE_URL);
    return 1;
}

/* --- #q: Quoted string (no space) --- */

static int test_classify_quoted_nospace(void)
{
    /* Bare words without context are LITERAL */
    ASSERT_TYPE("hello", CPL_TYPE_LITERAL);
    return 1;
}

static int test_classify_quoted_single_word(void)
{
    ASSERT_TYPE("msg", CPL_TYPE_LITERAL);
    return 1;
}

/* --- #qs: Quoted string with space --- */

static int test_classify_quoted_with_space(void)
{
    ASSERT_TYPE("hello world", CPL_TYPE_QUOTED_SPACE);
    return 1;
}

static int test_classify_quoted_sentence(void)
{
    ASSERT_TYPE("some test string", CPL_TYPE_QUOTED_SPACE);
    return 1;
}

/* --- Ambiguous / edge cases --- */

static int test_classify_literal_dash(void)
{
    ASSERT_TYPE("-", CPL_TYPE_LITERAL);
    return 1;
}

static int test_classify_literal_special_chars(void)
{
    ASSERT_TYPE("foo@bar", CPL_TYPE_LITERAL);
    return 1;
}

static int test_classify_literal_percent(void)
{
    ASSERT_TYPE("%PATH%", CPL_TYPE_LITERAL);
    return 1;
}

/* ============================================================
 * JOIN TABLE
 * ============================================================ */

static int test_join_reflexive(void)
{
    /* a ∨ a = a for all types */
    for (int t = 0; t < CPL_TYPE_COUNT; t++) {
        ASSERT(cpl_join((cpl_token_type_t)t, (cpl_token_type_t)t) == (cpl_token_type_t)t);
    }
    return 1;
}

static int test_join_symmetric(void)
{
    /* a ∨ b = b ∨ a */
    for (int a = 0; a < CPL_TYPE_COUNT; a++) {
        for (int b = 0; b < CPL_TYPE_COUNT; b++) {
            ASSERT(cpl_join((cpl_token_type_t)a, (cpl_token_type_t)b) ==
                   cpl_join((cpl_token_type_t)b, (cpl_token_type_t)a));
        }
    }
    return 1;
}

static int test_join_any_is_top(void)
{
    /* a ∨ * = * for all a */
    for (int t = 0; t < CPL_TYPE_COUNT; t++) {
        ASSERT(cpl_join((cpl_token_type_t)t, CPL_TYPE_ANY) == CPL_TYPE_ANY);
        ASSERT(cpl_join(CPL_TYPE_ANY, (cpl_token_type_t)t) == CPL_TYPE_ANY);
    }
    return 1;
}

static int test_join_hex_number(void)
{
    /* #h ∨ #n = #n (hex hash is a kind of number) */
    ASSERT(cpl_join(CPL_TYPE_HEXHASH, CPL_TYPE_NUMBER) == CPL_TYPE_NUMBER);
    return 1;
}

static int test_join_number_word(void)
{
    /* #n ∨ #w = #val */
    ASSERT(cpl_join(CPL_TYPE_NUMBER, CPL_TYPE_WORD) == CPL_TYPE_VALUE);
    /* #w ∨ #n = #val (symmetric) */
    ASSERT(cpl_join(CPL_TYPE_WORD, CPL_TYPE_NUMBER) == CPL_TYPE_VALUE);
    return 1;
}

static int test_join_path_types(void)
{
    /* #p ∨ #r = #path */
    ASSERT(cpl_join(CPL_TYPE_ABS_PATH, CPL_TYPE_REL_PATH) == CPL_TYPE_PATH);
    /* #p ∨ #f = #path */
    ASSERT(cpl_join(CPL_TYPE_ABS_PATH, CPL_TYPE_FILENAME) == CPL_TYPE_PATH);
    /* #r ∨ #f = #r (filename is a degenerate relative path) */
    ASSERT(cpl_join(CPL_TYPE_REL_PATH, CPL_TYPE_FILENAME) == CPL_TYPE_REL_PATH);
    /* #f ∨ #r = #r (symmetric) */
    ASSERT(cpl_join(CPL_TYPE_FILENAME, CPL_TYPE_REL_PATH) == CPL_TYPE_REL_PATH);
    return 1;
}

static int test_join_quoted_types(void)
{
    /* #q ∨ #qs = #qs */
    ASSERT(cpl_join(CPL_TYPE_QUOTED, CPL_TYPE_QUOTED_SPACE) == CPL_TYPE_QUOTED_SPACE);
    return 1;
}

static int test_join_cross_domain(void)
{
    /* #n ∨ #p = * (number and path are unrelated) */
    ASSERT(cpl_join(CPL_TYPE_NUMBER, CPL_TYPE_ABS_PATH) == CPL_TYPE_ANY);
    /* #w ∨ #u = * (word and URL are unrelated) */
    ASSERT(cpl_join(CPL_TYPE_WORD, CPL_TYPE_URL) == CPL_TYPE_ANY);
    /* #p ∨ #n = * (symmetric) */
    ASSERT(cpl_join(CPL_TYPE_ABS_PATH, CPL_TYPE_NUMBER) == CPL_TYPE_ANY);
    return 1;
}

static int test_join_val_with_path(void)
{
    /* #val ∨ #path = * */
    ASSERT(cpl_join(CPL_TYPE_VALUE, CPL_TYPE_PATH) == CPL_TYPE_ANY);
    /* #path ∨ #val = * (symmetric) */
    ASSERT(cpl_join(CPL_TYPE_PATH, CPL_TYPE_VALUE) == CPL_TYPE_ANY);
    return 1;
}

/* ============================================================
 * COMPATIBILITY TABLE
 * ============================================================ */

static int test_compat_reflexive(void)
{
    for (int t = 0; t < CPL_TYPE_COUNT; t++) {
        ASSERT(cpl_is_compatible((cpl_token_type_t)t, (cpl_token_type_t)t));
    }
    return 1;
}

static int test_compat_literal_only_self(void)
{
    /* Literal matches literal and * (ANY) */
    ASSERT(cpl_is_compatible(CPL_TYPE_LITERAL, CPL_TYPE_LITERAL));
    ASSERT(cpl_is_compatible(CPL_TYPE_LITERAL, CPL_TYPE_ANY));
    for (int t = 1; t < CPL_TYPE_COUNT - 1; t++) {
        ASSERT(!cpl_is_compatible(CPL_TYPE_LITERAL, (cpl_token_type_t)t));
    }
    return 1;
}

static int test_compat_any_matches_all(void)
{
    /* * (CPL_TYPE_ANY) matches any command token type */
    for (int t = 0; t < CPL_TYPE_COUNT; t++) {
        ASSERT(cpl_is_compatible((cpl_token_type_t)t, CPL_TYPE_ANY));
    }
    return 1;
}

static int test_compat_hex_to_number(void)
{
    /* #h ≤ #n */
    ASSERT(cpl_is_compatible(CPL_TYPE_HEXHASH, CPL_TYPE_NUMBER));
    /* #h ≤ #val */
    ASSERT(cpl_is_compatible(CPL_TYPE_HEXHASH, CPL_TYPE_VALUE));
    /* #n ≤ #val */
    ASSERT(cpl_is_compatible(CPL_TYPE_NUMBER, CPL_TYPE_VALUE));
    return 1;
}

static int test_compat_path_hierarchy(void)
{
    /* #f ≤ #r */
    ASSERT(cpl_is_compatible(CPL_TYPE_FILENAME, CPL_TYPE_REL_PATH));
    /* #f ≤ #path */
    ASSERT(cpl_is_compatible(CPL_TYPE_FILENAME, CPL_TYPE_PATH));
    /* #r ≤ #path */
    ASSERT(cpl_is_compatible(CPL_TYPE_REL_PATH, CPL_TYPE_PATH));
    /* #p ≤ #path */
    ASSERT(cpl_is_compatible(CPL_TYPE_ABS_PATH, CPL_TYPE_PATH));
    return 1;
}

static int test_compat_quoted_hierarchy(void)
{
    /* #q ≤ #qs */
    ASSERT(cpl_is_compatible(CPL_TYPE_QUOTED, CPL_TYPE_QUOTED_SPACE));
    /* #q ≤ #val */
    ASSERT(cpl_is_compatible(CPL_TYPE_QUOTED, CPL_TYPE_VALUE));
    /* #qs ≤ #val */
    ASSERT(cpl_is_compatible(CPL_TYPE_QUOTED_SPACE, CPL_TYPE_VALUE));
    return 1;
}

static int test_compat_cross_domain_denied(void)
{
    /* #n does NOT match #p */
    ASSERT(!cpl_is_compatible(CPL_TYPE_NUMBER, CPL_TYPE_ABS_PATH));
    /* #w does NOT match #path */
    ASSERT(!cpl_is_compatible(CPL_TYPE_WORD, CPL_TYPE_PATH));
    /* #p does NOT match #val */
    ASSERT(!cpl_is_compatible(CPL_TYPE_ABS_PATH, CPL_TYPE_VALUE));
    /* #val does NOT match #path */
    ASSERT(!cpl_is_compatible(CPL_TYPE_VALUE, CPL_TYPE_PATH));
    return 1;
}

/* ============================================================
 * TYPED NORMALISATION
 * ============================================================ */

static int test_normalize_typed_simple(void)
{
    cpl_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    cpl_error_t err = cpl_normalize_typed("ls -la", &arr);
    ASSERT(err == CPL_OK);
    ASSERT(arr.count == 2);
    ASSERT(arr.tokens[0].type == CPL_TYPE_LITERAL);
    ASSERT(strcmp(arr.tokens[0].text, "ls") == 0);
    ASSERT(arr.tokens[1].type == CPL_TYPE_LITERAL);
    cpl_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_path(void)
{
    cpl_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    cpl_error_t err = cpl_normalize_typed("cat /etc/passwd", &arr);
    ASSERT(err == CPL_OK);
    ASSERT(arr.count == 2);
    ASSERT(arr.tokens[0].type == CPL_TYPE_LITERAL);
    ASSERT(arr.tokens[1].type == CPL_TYPE_ABS_PATH);
    cpl_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_number(void)
{
    cpl_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    cpl_error_t err = cpl_normalize_typed("head -n 42", &arr);
    ASSERT(err == CPL_OK);
    ASSERT(arr.count == 3);
    ASSERT(arr.tokens[2].type == CPL_TYPE_NUMBER);
    cpl_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_hexhash(void)
{
    cpl_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    cpl_error_t err = cpl_normalize_typed("git show deadbeef12345678", &arr);
    ASSERT(err == CPL_OK);
    ASSERT(arr.count == 3);
    ASSERT(arr.tokens[2].type == CPL_TYPE_HEXHASH);
    cpl_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_ipv4(void)
{
    cpl_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    cpl_error_t err = cpl_normalize_typed("ping 192.168.1.1", &arr);
    ASSERT(err == CPL_OK);
    ASSERT(arr.count == 2);
    ASSERT(arr.tokens[1].type == CPL_TYPE_IPV4);
    cpl_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_url(void)
{
    cpl_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    cpl_error_t err = cpl_normalize_typed("curl https://example.com", &arr);
    ASSERT(err == CPL_OK);
    ASSERT(arr.count == 2);
    ASSERT(arr.tokens[1].type == CPL_TYPE_URL);
    cpl_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_filename(void)
{
    cpl_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    cpl_error_t err = cpl_normalize_typed("gcc main.c", &arr);
    ASSERT(err == CPL_OK);
    ASSERT(arr.count == 2);
    ASSERT(arr.tokens[1].type == CPL_TYPE_FILENAME);
    cpl_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_relpath(void)
{
    cpl_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    cpl_error_t err = cpl_normalize_typed("cat src/main.c", &arr);
    ASSERT(err == CPL_OK);
    ASSERT(arr.count == 2);
    ASSERT(arr.tokens[1].type == CPL_TYPE_REL_PATH);
    cpl_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_long_flag_value(void)
{
    cpl_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    cpl_error_t err = cpl_normalize_typed("git commit --message hello", &arr);
    ASSERT(err == CPL_OK);
    ASSERT(arr.count == 4);
    ASSERT(arr.tokens[0].type == CPL_TYPE_LITERAL); /* git */
    ASSERT(arr.tokens[1].type == CPL_TYPE_LITERAL); /* commit */
    ASSERT(arr.tokens[2].type == CPL_TYPE_LITERAL); /* --message */
    ASSERT(arr.tokens[3].type == CPL_TYPE_LITERAL); /* hello (word, not in a variable context) */
    cpl_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_long_flag_number(void)
{
    cpl_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    cpl_error_t err = cpl_normalize_typed("gcc --optimization 2", &arr);
    ASSERT(err == CPL_OK);
    ASSERT(arr.count == 3);
    ASSERT(arr.tokens[2].type == CPL_TYPE_NUMBER);
    cpl_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_redirection_path(void)
{
    cpl_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    cpl_error_t err = cpl_normalize_typed("ls > /tmp/out.txt", &arr);
    ASSERT(err == CPL_OK);
    ASSERT(arr.count == 3);
    ASSERT(arr.tokens[1].type == CPL_TYPE_LITERAL); /* > */
    ASSERT(arr.tokens[2].type == CPL_TYPE_ABS_PATH);
    cpl_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_pipeline(void)
{
    cpl_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    cpl_error_t err = cpl_normalize_typed("cat file.txt | grep ERROR", &arr);
    ASSERT(err == CPL_OK);
    ASSERT(arr.count == 5);
    ASSERT(arr.tokens[0].type == CPL_TYPE_LITERAL);  /* cat */
    ASSERT(arr.tokens[1].type == CPL_TYPE_FILENAME); /* file.txt */
    ASSERT(arr.tokens[2].type == CPL_TYPE_LITERAL);  /* | */
    ASSERT(arr.tokens[3].type == CPL_TYPE_LITERAL);  /* grep */
    ASSERT(arr.tokens[4].type == CPL_TYPE_LITERAL);  /* ERROR */
    cpl_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_quoted_with_space(void)
{
    cpl_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    cpl_error_t err = cpl_normalize_typed("echo \"hello world\"", &arr);
    ASSERT(err == CPL_OK);
    ASSERT(arr.count == 2);
    ASSERT(arr.tokens[0].type == CPL_TYPE_LITERAL);    /* echo */
    ASSERT(arr.tokens[1].type == CPL_TYPE_QUOTED_SPACE);
    cpl_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_env_assignment(void)
{
    cpl_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    cpl_error_t err = cpl_normalize_typed("export PATH=/usr/bin", &arr);
    ASSERT(err == CPL_OK);
    /* export is a word (LITERAL), PATH=/usr/bin is split into PATH= + /usr/bin */
    ASSERT(arr.count == 3);
    ASSERT(arr.tokens[0].type == CPL_TYPE_LITERAL); /* export */
    ASSERT(arr.tokens[1].type == CPL_TYPE_LITERAL); /* PATH= */
    ASSERT(arr.tokens[2].type == CPL_TYPE_ABS_PATH); /* /usr/bin */
    cpl_free_token_array(&arr);
    return 1;
}

/* ============================================================
 * LEGACY STRING NORMALISATION (backward compat)
 * ============================================================ */

static int test_normalize_string_uses_type_symbols(void)
{
    char **tokens = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_normalize("cat /etc/passwd", &tokens, &count);
    ASSERT(err == CPL_OK);
    ASSERT(count == 2);
    ASSERT(strcmp(tokens[0], "cat") == 0);
    ASSERT(strcmp(tokens[1], "#p") == 0);
    cpl_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_string_number(void)
{
    char **tokens = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_normalize("head -n 42", &tokens, &count);
    ASSERT(err == CPL_OK);
    ASSERT(count == 3);
    ASSERT(strcmp(tokens[2], "#n") == 0);
    cpl_free_tokens(tokens, count);
    return 1;
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void)
{
    printf("Running token type tests...\n\n");

    printf("Classification - Hex hash (#h):\n");
    TEST(test_classify_hexhash_lowercase);
    TEST(test_classify_hexhash_mixed);
    TEST(test_classify_hexhash_long);
    TEST(test_classify_hexhash_too_short);

    printf("\nClassification - Number (#n):\n");
    TEST(test_classify_number_decimal);
    TEST(test_classify_number_negative);
    TEST(test_classify_number_hex_prefix);
    TEST(test_classify_number_octal);
    TEST(test_classify_number_zero);

    printf("\nClassification - IPv4 (#i):\n");
    TEST(test_classify_ipv4_standard);
    TEST(test_classify_ipv4_localhost);
    TEST(test_classify_ipv4_all_zeros);

    printf("\nClassification - Word (#w):\n");
    TEST(test_classify_word_simple);
    TEST(test_classify_word_underscore);
    TEST(test_classify_word_uppercase);
    TEST(test_classify_word_with_digits);
    TEST(test_classify_word_underscore_start);

    printf("\nClassification - Filename (#f):\n");
    TEST(test_classify_filename_with_ext);
    TEST(test_classify_filename_c_source);
    TEST(test_classify_filename_multiple_dots);
    TEST(test_classify_filename_hidden);

    printf("\nClassification - Relative path (#r):\n");
    TEST(test_classify_relpath_with_slash);
    TEST(test_classify_relpath_dotdot);
    TEST(test_classify_relpath_dot);
    TEST(test_classify_relpath_deep);

    printf("\nClassification - Absolute path (#p):\n");
    TEST(test_classify_abspath_simple);
    TEST(test_classify_abspath_root);
    TEST(test_classify_abspath_deep);

    printf("\nClassification - URL (#u):\n");
    TEST(test_classify_url_https);
    TEST(test_classify_url_http);
    TEST(test_classify_url_git);
    TEST(test_classify_url_ftp);

    printf("\nClassification - Quoted (#q, #qs):\n");
    TEST(test_classify_quoted_nospace);
    TEST(test_classify_quoted_single_word);
    TEST(test_classify_quoted_with_space);
    TEST(test_classify_quoted_sentence);

    printf("\nClassification - Edge cases:\n");
    TEST(test_classify_literal_dash);
    TEST(test_classify_literal_special_chars);
    TEST(test_classify_literal_percent);

    printf("\nJoin table:\n");
    TEST(test_join_reflexive);
    TEST(test_join_symmetric);
    TEST(test_join_any_is_top);
    TEST(test_join_hex_number);
    TEST(test_join_number_word);
    TEST(test_join_path_types);
    TEST(test_join_quoted_types);
    TEST(test_join_cross_domain);
    TEST(test_join_val_with_path);

    printf("\nCompatibility table:\n");
    TEST(test_compat_reflexive);
    TEST(test_compat_literal_only_self);
    TEST(test_compat_any_matches_all);
    TEST(test_compat_hex_to_number);
    TEST(test_compat_path_hierarchy);
    TEST(test_compat_quoted_hierarchy);
    TEST(test_compat_cross_domain_denied);

    printf("\nTyped normalisation:\n");
    TEST(test_normalize_typed_simple);
    TEST(test_normalize_typed_path);
    TEST(test_normalize_typed_number);
    TEST(test_normalize_typed_hexhash);
    TEST(test_normalize_typed_ipv4);
    TEST(test_normalize_typed_url);
    TEST(test_normalize_typed_filename);
    TEST(test_normalize_typed_relpath);
    TEST(test_normalize_typed_long_flag_value);
    TEST(test_normalize_typed_long_flag_number);
    TEST(test_normalize_typed_redirection_path);
    TEST(test_normalize_typed_pipeline);
    TEST(test_normalize_typed_quoted_with_space);
    TEST(test_normalize_typed_env_assignment);

    printf("\nLegacy string normalisation:\n");
    TEST(test_normalize_string_uses_type_symbols);
    TEST(test_normalize_string_number);

    printf("\n========================================\n");
    printf("Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
