#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

static int total_tests_run = 0;
static int total_tests_passed = 0;
static const char* build_dir = "build_test";

typedef struct {
    const char* input;
    bool should_match;
    size_t expected_len;
    uint8_t expected_category;
    const char* description;
} TestCase;

static void print_separator(void) {
    printf("\n");
}

static void build_dfa(const char* patterns_file, const char* dfa_file) {
    const char* filename = strrchr(dfa_file, '/');
    filename = filename ? filename + 1 : dfa_file;

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "mkdir -p %s && "
        "./tools/nfa_builder %s %s/test.nfa && "
        "./tools/nfa2dfa_advanced --minimize-moore %s/test.nfa %s",
        build_dir, patterns_file, build_dir, build_dir, dfa_file);
    system(cmd);
}

static void run_test_group(const char* group_name, const char* patterns_file, const char* dfa_file,
                          const TestCase* cases, int count) {
    build_dfa(patterns_file, dfa_file);

    printf("\n=== %s ===\n", group_name);
    printf("Patterns: %s\n", patterns_file);

    size_t size;
    void* data = load_dfa_from_file(dfa_file, &size);
    if (!data) {
        printf("  [ERROR] Failed to load DFA: %s\n", dfa_file);
        return;
    }

    if (!dfa_init(data, size)) {
        printf("  [ERROR] Failed to init DFA\n");
        free(data);
        return;
    }

    int group_run = 0;
    int group_passed = 0;

    for (int i = 0; i < count; i++) {
        dfa_result_t result;
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match && cases[i].expected_len > 0) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        if (passed && cases[i].expected_category != 0) {
            passed = ((result.category_mask & cases[i].expected_category) != 0);
        }

        group_run++;
        total_tests_run++;

        if (passed) {
            group_passed++;
            total_tests_passed++;
            printf("  [PASS] %s\n", cases[i].description);
        } else {
            printf("  [FAIL] %s - got '%s' (len=%zu, cat=0x%02x)\n",
                   cases[i].description,
                   result.matched ? "MATCH" : "NO MATCH",
                   result.matched_length,
                   result.category_mask);
        }
    }

    printf("  Result: %d/%d passed\n", group_passed, group_run);
    dfa_reset();
    free(data);
}

static void run_core_tests(void) {
    TestCase cases[] = {
        {"git status", true, 0, 0, "git status matches"},
        {"git log --oneline", true, 0, 0, "git log --oneline matches"},
        {"git branch -a", true, 0, 0, "git branch -a matches"},
        {"git log -n 10", true, 0, 0, "git log -n 10 matches"},
        {"git log -n 12345", true, 0, 0, "git log -n 12345 matches"},
        {"cat test.txt", true, 0, 0, "cat test.txt matches"},
        {"ls -la", true, 0, 0, "ls -la matches"},
        {"head -n 5 file.txt", true, 0, 0, "head -n 5 file.txt matches"},
        {"tail -n 10 file.txt", true, 0, 0, "tail -n 10 file.txt matches"},
        {"which socat", true, 0, 0, "which socat matches"},
        {"rm -rf /", false, 0, 0, "rm -rf / should NOT match"},
        {"git push", false, 0, 0, "git push should NOT match"},
        {"chmod 777 file", false, 0, 0, "chmod 777 file should NOT match"},
    };

    run_test_group("CORE TESTS", "patterns_safe_commands.txt",
                   "build_test/readonlybox.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_quantifier_tests(void) {
    TestCase cases[] = {
        // Pattern: (a)+ - matches one or more 'a's
        {"a", true, 1, CAT_MASK_SAFE, "(a)+ matches 'a'"},
        {"aa", true, 2, CAT_MASK_SAFE, "(a)+ matches 'aa'"},
        {"aaa", true, 3, CAT_MASK_SAFE, "(a)+ matches 'aaa'"},
        {"", false, 0, 0, "(a)+ should NOT match empty"},
        {"b", false, 0, 0, "(a)+ should NOT match 'b'"},
        {"ab", false, 0, 0, "(a)+ should NOT match 'ab'"},
        // Pattern: a((b))+ - matches 'a' followed by one or more 'b's
        {"ab", true, 2, CAT_MASK_SAFE, "a((b))+ matches 'ab'"},
        {"abb", true, 3, CAT_MASK_SAFE, "a((b))+ matches 'abb'"},
        {"abbb", true, 4, CAT_MASK_SAFE, "a((b))+ matches 'abbb'"},
        {"a", false, 0, 0, "a((b))+ should NOT match 'a'"},
        // Pattern: abc((b))+ - matches 'abc' followed by one or more 'b's
        {"abcb", true, 4, CAT_MASK_SAFE, "abc((b))+ matches 'abcb'"},
        // Pattern: (a)* - matches zero or more 'a's
        {"", true, 0, CAT_MASK_SAFE, "(a)* matches empty"},
        {"a", true, 1, CAT_MASK_SAFE, "(a)* matches 'a'"},
        // Pattern: (a)? - matches zero or one 'a'
        {"", true, 0, CAT_MASK_SAFE, "(a)? matches empty"},
        {"a", true, 1, CAT_MASK_SAFE, "(a)? matches 'a'"},
    };

    run_test_group("QUANTIFIER TESTS", "patterns_quantifier_comprehensive.txt",
                   "build_test/quantifier.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_fragment_tests(void) {
    TestCase cases[] = {
        {"alpha beta", true, 11, CAT_MASK_SAFE, "alpha beta matches"},
        {"outer inner", true, 12, CAT_MASK_SAFE, "outer inner matches"},
        {"inner", false, 0, 0, "inner alone should NOT match"},
        {"outer", false, 0, 0, "outer alone should NOT match"},
        {"xyz", true, 3, CAT_MASK_SAFE, "((xyz))+ matches 'xyz'"},
        {"xyzxyz", true, 6, CAT_MASK_SAFE, "((xyz))+ matches 'xyzxyz'"},
    };

    run_test_group("FRAGMENT TESTS", "patterns_frag_quant.txt",
                   "build_test/fragment.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_alternation_tests(void) {
    TestCase cases[] = {
        {"a", true, 1, CAT_MASK_SAFE, "(a|b) matches 'a'"},
        {"b", true, 1, CAT_MASK_SAFE, "(a|b) matches 'b'"},
        {"a", true, 1, CAT_MASK_SAFE, "(a|b)+ matches 'a'"},
        {"ab", true, 2, CAT_MASK_SAFE, "(a|b)+ matches 'ab'"},
        {"aba", true, 3, CAT_MASK_SAFE, "(a|b)+ matches 'aba'"},
        {"", false, 0, 0, "(a|b)+ should NOT match empty"},
        {"c", false, 0, 0, "(a|b)+ should NOT match 'c'"},
        {"ABC", true, 3, CAT_MASK_SAFE, "(ABC|DEF) matches 'ABC'"},
    };

    run_test_group("ALTERNATION TESTS", "patterns_focused.txt",
                   "build_test/alternation.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_boundary_tests(void) {
    TestCase cases[] = {
        {"", true, 0, CAT_MASK_SAFE, "empty matches empty"},
        {"abc", true, 3, CAT_MASK_SAFE, "abc matches 'abc'"},
        {"abcdef", true, 6, CAT_MASK_SAFE, "abcdef matches"},
        {"abcde", false, 0, 0, "abcde should NOT match"},
        {"abcdefg", false, 0, 0, "abcdefg should NOT match"},
    };

    run_test_group("BOUNDARY TESTS", "patterns_simple.txt",
                   "build_test/boundary.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_category_tests(void) {
    TestCase cases[] = {
        {"SAFE_CMD arg1", true, 11, 0x01, "SAFE_CMD matches with cat 0x01"},
        {"CAUTION_CMD arg1", true, 13, 0x02, "CAUTION_CMD matches with cat 0x02"},
        {"SAFE_CMD arg1", false, 0, 0x02, "SAFE_CMD should NOT have cat 0x02"},
        {"CAUTION_CMD arg1", false, 0, 0x01, "CAUTION_CMD should NOT have cat 0x01"},
    };

    run_test_group("CATEGORY TESTS", "patterns_acceptance_category_test.txt",
                   "build_test/category.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_tripled_quantifier_depth(void) {
    TestCase cases[] = {
        {"ab", true, 2, CAT_MASK_SAFE, "a((b))+ matches 'ab'"},
        {"abb", true, 3, CAT_MASK_SAFE, "a((b))+ matches 'abb'"},
        {"abbb", true, 4, CAT_MASK_SAFE, "a((b))+ matches 'abbb'"},
        {"a", false, 0, 0, "a((b))+ should NOT match 'a'"},
        {"a", true, 1, CAT_MASK_SAFE, "((a))+ matches 'a'"},
        {"aa", true, 2, CAT_MASK_SAFE, "((a))+ matches 'aa'"},
        {"aaa", true, 3, CAT_MASK_SAFE, "((a))+ matches 'aaa'"},
        {"aa", true, 2, CAT_MASK_SAFE, "(((a)))+ matches 'aa'"},
        {"aaaa", true, 4, CAT_MASK_SAFE, "(((a)))+ matches 'aaaa'"},
        {"a", true, 1, CAT_MASK_SAFE, "(a|b)+ matches 'a'"},
        {"ab", true, 2, CAT_MASK_SAFE, "(a|b)+ matches 'ab'"},
        {"ababa", true, 5, CAT_MASK_SAFE, "(a|b)+ matches 'ababa'"},
        {"a", true, 1, CAT_MASK_SAFE, "((a|b))+ matches 'a'"},
        {"ab", true, 2, CAT_MASK_SAFE, "((a|b))+ matches 'ab'"},
        {"abab", true, 4, CAT_MASK_SAFE, "((a|b))+ matches 'abab'"},
        {"", true, 0, CAT_MASK_SAFE, "(a*)+ matches empty"},
        {"a", true, 1, CAT_MASK_SAFE, "(a*)+ matches 'a'"},
        {"a", true, 1, CAT_MASK_SAFE, "(a+)+ matches 'a'"},
        {"aaa", true, 3, CAT_MASK_SAFE, "(a+)+ matches 'aaa'"},
    };

    run_test_group("TRIPLED QUANTIFIER DEPTH", "patterns_quantifier_comprehensive.txt",
                   "build_test/tripled_quant.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_tripled_fragment_interactions(void) {
    TestCase cases[] = {
        {"alpha beta", true, 11, CAT_MASK_SAFE, "alpha beta matches"},
        {"outer inner", true, 12, CAT_MASK_SAFE, "outer inner matches"},
        {"xyz", true, 3, CAT_MASK_SAFE, "((xyz))+ matches 'xyz'"},
        {"xyzxyz", true, 6, CAT_MASK_SAFE, "((xyz))+ matches 'xyzxyz'"},
        {"ABC ABC ABC", true, 11, CAT_MASK_SAFE, "ABC repeated 3x matches"},
        {"AB", true, 2, CAT_MASK_SAFE, "(AB)+ matches 'AB'"},
        {"ABAB", true, 4, CAT_MASK_SAFE, "(AB)+ matches 'ABAB'"},
    };

    run_test_group("TRIPLED FRAGMENT INTERACTIONS", "patterns_frag_plus.txt",
                   "build_test/tripled_frag.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_tripled_boundary(void) {
    TestCase cases[] = {
        {"a", true, 1, CAT_MASK_SAFE, "single 'a' matches"},
        {"aa", true, 2, CAT_MASK_SAFE, "two 'a's match"},
        {"aaa", true, 3, CAT_MASK_SAFE, "three 'a's match"},
        {"ababababab", true, 10, CAT_MASK_SAFE, "10 'ab' pattern matches"},
        {"abababababa", false, 0, 0, "11 'ab' should NOT match"},
        {"xyxyxyxyxy", true, 10, CAT_MASK_SAFE, "10 'xy' pattern matches"},
        {"", true, 0, CAT_MASK_SAFE, "empty matches empty"},
        {"testtesttesttesttest", true, 20, CAT_MASK_SAFE, "5 'test' repetitions match"},
    };

    run_test_group("TRIPLED BOUNDARY CONDITIONS", "patterns_simple.txt",
                   "build_test/tripled_bound.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_tripled_hard_edges(void) {
    TestCase cases[] = {
        {"X123Y", true, 5, CAT_MASK_SAFE, "X+3digits+Y matches"},
        {"X1234Y", true, 6, CAT_MASK_SAFE, "X+4digits+Y matches"},
        {"X1Y", true, 3, CAT_MASK_SAFE, "X+1digit+Y matches"},
        {"XY", false, 0, 0, "X+0digits+Y should NOT match"},
        {"X12345Y", false, 0, 0, "X+5digits+Y should NOT match"},
        {"X001Y", true, 5, CAT_MASK_SAFE, "X+leading zeros+Y matches"},
        {"X999Y", true, 5, CAT_MASK_SAFE, "X+999+Y matches"},
    };

    run_test_group("TRIPLED HARD EDGE CASES", "patterns_digit_test.txt",
                   "build_test/tripled_hard.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_tripled_syntax(void) {
    TestCase cases[] = {
        {"cmd arg1", true, 8, CAT_MASK_SAFE, "cmd with 1 arg matches"},
        {"cmd arg1 arg2", true, 12, CAT_MASK_SAFE, "cmd with 2 args matches"},
        {"cmd arg1 arg2 arg3", true, 16, CAT_MASK_SAFE, "cmd with 3 args matches"},
        {"cmd", true, 3, CAT_MASK_SAFE, "cmd alone matches"},
        {"CMD VAR", true, 7, CAT_MASK_SAFE, "PAT VAR matches"},
        {"CMD VAR1 VAR2", true, 11, CAT_MASK_SAFE, "PAT VAR VAR matches"},
        {"XYZ", true, 3, CAT_MASK_SAFE, "XYZ matches"},
        {"XYZ XYZ", true, 7, CAT_MASK_SAFE, "XYZ XYZ matches"},
    };

    run_test_group("TRIPLED SYNTAX INTERACTIONS", "patterns_space_test.txt",
                   "build_test/tripled_syntax.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_tripled_category_isolation(void) {
    TestCase cases[] = {
        {"SAFE_CMD alpha", true, 12, 0x01, "SAFE_CMD+alpha has cat 0x01"},
        {"SAFE_CMD beta", true, 11, 0x01, "SAFE_CMD+beta has cat 0x01"},
        {"CAUTION_CMD alpha", true, 14, 0x02, "CAUTION_CMD+alpha has cat 0x02"},
        {"CAUTION_CMD beta", true, 13, 0x02, "CAUTION_CMD+beta has cat 0x02"},
        {"SAFE_CMD alpha", false, 0, 0x02, "SAFE_CMD should NOT have cat 0x02"},
        {"CAUTION_CMD alpha", false, 0, 0x01, "CAUTION_CMD should NOT have cat 0x01"},
        {"SAFE_CMD PAT1", true, 10, 0x01, "SAFE_CMD+PAT1 matches"},
        {"CAUTION_CMD PAT2", true, 12, 0x02, "CAUTION_CMD+PAT2 matches"},
    };

    run_test_group("TRIPLED CATEGORY ISOLATION", "patterns_acceptance_category_test.txt",
                   "build_test/tripled_cat.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_tripled_quantifier_interactions(void) {
    TestCase cases[] = {
        {"ab", true, 2, CAT_MASK_SAFE, "a((b))+ matches 'ab'"},
        {"abbb", true, 4, CAT_MASK_SAFE, "a((b))+ matches 'abbb'"},
        {"", true, 0, CAT_MASK_SAFE, "a((b))* matches empty"},
        {"a", true, 1, CAT_MASK_SAFE, "a((b))* matches 'a'"},
        {"abb", true, 3, CAT_MASK_SAFE, "a((b))* matches 'abb'"},
        {"a", true, 1, CAT_MASK_SAFE, "a((b))? matches 'a'"},
        {"ab", true, 2, CAT_MASK_SAFE, "a((b))? matches 'ab'"},
        {"abcd", true, 4, CAT_MASK_SAFE, "abc((d))+ matches 'abcd'"},
        {"xy", true, 2, CAT_MASK_SAFE, "((x)y)+ matches 'xy'"},
        {"xyxy", true, 4, CAT_MASK_SAFE, "((x)y)+ matches 'xyxy'"},
        {"", true, 0, CAT_MASK_SAFE, "((x)y)* matches empty"},
        {"xy", true, 2, CAT_MASK_SAFE, "((x)y)* matches 'xy'"},
    };

    run_test_group("TRIPLED QUANTIFIER INTERACTIONS", "patterns_quantifier_test.txt",
                   "build_test/tripled_quant_int.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

    static void run_expanded_quantifier_tests(void) {
    TestCase cases[] = {
        {"a", true, 1, CAT_MASK_SAFE, "a+ matches 'a'"},
        {"aa", true, 2, CAT_MASK_SAFE, "a+ matches 'aa'"},
        {"aaa", true, 3, CAT_MASK_SAFE, "a+ matches 'aaa'"},
        {"aaaaaa", true, 6, CAT_MASK_SAFE, "a+ matches 6 'a's"},
        {"", false, 0, 0, "a+ should NOT match empty"},
        {"b", false, 0, 0, "a+ should NOT match 'b'"},
        {"ab", false, 0, 0, "a+ should NOT match 'ab'"},
        // Pattern is ab(c)+, so "abc" matches with length 3 (ab + one c)
        {"abc", true, 3, CAT_MASK_SAFE, "ab(c)+ matches 'abc'"},
        {"abcc", true, 4, CAT_MASK_SAFE, "ab(c)+ matches 'abcc'"},
        // Pattern is (a)?, so test inputs are "a" and "" (not "a?")
        {"a", true, 1, CAT_MASK_SAFE, "(a)? matches 'a'"},
        {"", true, 0, CAT_MASK_SAFE, "(a)? matches empty"},
    };

    run_test_group("EXPANDED QUANTIFIER EDGE CASES", "patterns_expanded_quantifier.txt",
                   "build_test/expanded_quantifier.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_expanded_alternation_tests(void) {
    TestCase cases[] = {
        {"a", true, 1, CAT_MASK_SAFE, "(a|b)+ matches 'a'"},
        {"b", true, 1, CAT_MASK_SAFE, "(a|b)+ matches 'b'"},
        {"aa", true, 2, CAT_MASK_SAFE, "(a|b)+ matches 'aa'"},
        {"ab", true, 2, CAT_MASK_SAFE, "(a|b)+ matches 'ab'"},
        {"ba", true, 2, CAT_MASK_SAFE, "(a|b)+ matches 'ba'"},
        {"abc", true, 1, CAT_MASK_SAFE, "(a|b|c)+ matches 'a'"},
        {"c", true, 1, CAT_MASK_SAFE, "(a|b|c)+ matches 'c'"},
        {"abc", true, 3, CAT_MASK_SAFE, "(a|b|c)+ matches 'abc'"},
        {"ac", true, 2, CAT_MASK_SAFE, "(a|b)?c matches 'ac'"},
        {"bc", true, 2, CAT_MASK_SAFE, "(a|b)?c matches 'bc'"},
        {"c", true, 1, CAT_MASK_SAFE, "(a|b)?c matches 'c' (optional not present)"},
    };

    run_test_group("EXPANDED ALTERNATION TESTS", "patterns_expanded_alternation.txt",
                   "build_test/expanded_alternation.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_expanded_nested_tests(void) {
    TestCase cases[] = {
        {"a", true, 1, CAT_MASK_SAFE, "((a))+ matches 'a'"},
        {"aa", true, 2, CAT_MASK_SAFE, "((a))+ matches 'aa'"},
        {"aaa", true, 3, CAT_MASK_SAFE, "((a))+ matches 'aaa'"},
        {"a", true, 1, CAT_MASK_SAFE, "(((a)))+ matches 'a'"},
        {"aaa", true, 3, CAT_MASK_SAFE, "(((a)))+ matches 'aaa'"},
        {"a", true, 1, CAT_MASK_SAFE, "((a)+)+ matches 'a'"},
        {"aa", true, 2, CAT_MASK_SAFE, "((a)+)+ matches 'aa'"},
        {"aaa", true, 3, CAT_MASK_SAFE, "((a)+)+ matches 'aaa'"},
        {"", true, 0, CAT_MASK_SAFE, "(a*)+ matches empty"},
        {"a", true, 1, CAT_MASK_SAFE, "(a*)+ matches 'a'"},
        {"aa", true, 2, CAT_MASK_SAFE, "(a*)+ matches 'aa'"},
        {"", true, 0, CAT_MASK_SAFE, "(a+)* matches empty"},
        {"a", true, 1, CAT_MASK_SAFE, "(a+)* matches 'a'"},
        {"aa", true, 2, CAT_MASK_SAFE, "(a+)* matches 'aa'"},
    };

    run_test_group("EXPANDED NESTED QUANTIFIER TESTS", "patterns_expanded_nested.txt",
                   "build_test/expanded_nested.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_expanded_fragment_tests(void) {
    TestCase cases[] = {
        {"xy", true, 2, CAT_MASK_SAFE, "x+ y+ matches 'xy'"},
        {"xxy", true, 3, CAT_MASK_SAFE, "x+ y+ matches 'xxy'"},
        {"xyy", true, 3, CAT_MASK_SAFE, "x+ y+ matches 'xyy'"},
        {"xxyy", true, 4, CAT_MASK_SAFE, "x+ y+ matches 'xxyy'"},
        {"abcdef", true, 6, CAT_MASK_SAFE, "abc def+ matches 'abcdef'"},
        {"abcdefdef", true, 9, CAT_MASK_SAFE, "abc def+ matches 'abcdefdef'"},
        {"abcdefdefdef", true, 12, CAT_MASK_SAFE, "abc def+ matches 'abcdefdefdef'"},
        {"a", true, 1, CAT_MASK_SAFE, "nested single char matches 'a'"},
        {"aaa", true, 3, CAT_MASK_SAFE, "nested single char matches 'aaa'"},
        {"ac", true, 2, CAT_MASK_SAFE, "a+|c+ matches 'ac'"},
        {"ad", true, 2, CAT_MASK_SAFE, "a+|c+ matches 'ad'"},
        {"bc", true, 2, CAT_MASK_SAFE, "b+|d+ matches 'bc'"},
    };

    run_test_group("EXPANDED FRAGMENT INTERACTION TESTS", "patterns_expanded_fragment.txt",
                   "build_test/expanded_fragment.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_expanded_boundary_tests(void) {
    TestCase cases[] = {
        {"", true, 0, CAT_MASK_SAFE, "empty pattern matches empty string"},
        {"abc", true, 3, CAT_MASK_SAFE, "abc matches 'abc'"},
        {"abcdef", true, 6, CAT_MASK_SAFE, "abcdef matches full pattern"},
        {"abcde", false, 0, 0, "abcde should NOT match (needs 'f')"},
        {"abcdefg", false, 0, 0, "abcdefg should NOT match"},
        {"aa", true, 2, CAT_MASK_SAFE, "a++ matches 'aa'"},
        {"aaa", true, 3, CAT_MASK_SAFE, "a+++ matches 'aaa'"},
        {"ab", true, 2, CAT_MASK_SAFE, "a?b+ matches 'ab'"},
        {"b", true, 1, CAT_MASK_SAFE, "a?b+ matches 'b' (a optional)"},
        {"abb", true, 3, CAT_MASK_SAFE, "a?b+ matches 'abb'"},
        {"a", true, 1, CAT_MASK_SAFE, "a+b? matches 'a' (b optional)"},
        {"ab", true, 2, CAT_MASK_SAFE, "a+b? matches 'ab'"},
        {"", true, 0, CAT_MASK_SAFE, "a?b?c? matches empty (all optional)"},
        {"a", true, 1, CAT_MASK_SAFE, "a?b?c? matches 'a'"},
        {"ab", true, 2, CAT_MASK_SAFE, "a?b?c? matches 'ab'"},
        {"abc", true, 3, CAT_MASK_SAFE, "a?b?c? matches 'abc'"},
    };

    run_test_group("EXPANDED BOUNDARY CONDITION TESTS", "patterns_expanded_boundary.txt",
                   "build_test/expanded_boundary.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_expanded_interaction_tests(void) {
    TestCase cases[] = {
        {"a", true, 1, CAT_MASK_SAFE, "a+b* matches 'a'"},
        {"ab", true, 2, CAT_MASK_SAFE, "a+b* matches 'ab'"},
        {"abb", true, 3, CAT_MASK_SAFE, "a+b* matches 'abb'"},
        {"aa", true, 2, CAT_MASK_SAFE, "a+b* matches 'aa'"},
        {"aab", true, 3, CAT_MASK_SAFE, "a+b* matches 'aab'"},
        {"b", true, 0, CAT_MASK_SAFE, "a+b* matches 'b' (b*)"},
        {"a", true, 1, CAT_MASK_SAFE, "a*b+ matches 'a'"},
        {"ab", true, 2, CAT_MASK_SAFE, "a*b+ matches 'ab'"},
        {"aa", true, 2, CAT_MASK_SAFE, "a*b+ matches 'aa'"},
        {"b", true, 1, CAT_MASK_SAFE, "a*b+ matches 'b' (zero a's)"},
        {"b", true, 1, CAT_MASK_SAFE, "a?b+ matches 'b' (a optional)"},
        {"ab", true, 2, CAT_MASK_SAFE, "a?b+ matches 'ab'"},
        {"a", true, 1, CAT_MASK_SAFE, "a+b? matches 'a' (b optional)"},
        {"ab", true, 2, CAT_MASK_SAFE, "a+b? matches 'ab'"},
    };

    run_test_group("EXPANDED QUANTIFIER INTERACTION TESTS", "patterns_expanded_interactions.txt",
                   "build_test/expanded_interactions.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_expanded_mixed_tests(void) {
    TestCase cases[] = {
        {"xy", true, 2, CAT_MASK_SAFE, "x y matches 'xy'"},
        {"xyy", true, 3, CAT_MASK_SAFE, "x y+ matches 'xyy'"},
        {"xyyy", true, 4, CAT_MASK_SAFE, "x y+ matches 'xyyy'"},
        {"xy", true, 2, CAT_MASK_SAFE, "x+ y matches 'xy'"},
        {"xxy", true, 3, CAT_MASK_SAFE, "x+ y matches 'xxy'"},
        {"xxxy", true, 4, CAT_MASK_SAFE, "x+ y matches 'xxxy'"},
        {"abcde", true, 5, CAT_MASK_SAFE, "ab c de matches 'abcde'"},
        {"abcde", true, 5, CAT_MASK_SAFE, "ab c+ de matches 'abcde'"},
        {"abccde", true, 6, CAT_MASK_SAFE, "ab c+ de matches 'abccde'"},
        {"startmidend", true, 10, CAT_MASK_SAFE, "start mid+ end matches 'startmidend'"},
        {"startmiddend", true, 13, CAT_MASK_SAFE, "start mid+ end matches 'startmiddend'"},
    };

    run_test_group("EXPANDED MIXED LITERAL/FRAGMENT TESTS", "patterns_expanded_mixed.txt",
                   "build_test/expanded_mixed.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_expanded_hard_tests(void) {
    TestCase cases[] = {
        {"aab", true, 3, CAT_MASK_SAFE, "(a+a+)+b matches 'aab'"},
        {"aaaab", true, 5, CAT_MASK_SAFE, "(a+a+)+b matches 'aaaab'"},
        {"a", true, 1, CAT_MASK_SAFE, "a+ a+ matches 'a' (both fragments same char)"},
        {"aa", true, 2, CAT_MASK_SAFE, "a+ a+ matches 'aa'"},
        {"aaa", true, 3, CAT_MASK_SAFE, "a+ a+ matches 'aaa'"},
        {"ab", true, 2, CAT_MASK_SAFE, "(ab)+ matches 'ab'"},
        {"abab", true, 4, CAT_MASK_SAFE, "(ab)+ matches 'abab'"},
        {"ababab", true, 6, CAT_MASK_SAFE, "(ab)+ matches 'ababab'"},
        {"a", true, 1, CAT_MASK_SAFE, "(a|aa)+ matches 'a'"},
        {"aa", true, 2, CAT_MASK_SAFE, "(a|aa)+ matches 'aa'"},
        {"aaa", true, 3, CAT_MASK_SAFE, "(a|aa)+ matches 'aaa'"},
        {"aaaa", true, 4, CAT_MASK_SAFE, "(a|aa)+ matches 'aaaa'"},
        {"a", true, 1, CAT_MASK_SAFE, "[a|b|c]+ matches 'a'"},
        {"b", true, 1, CAT_MASK_SAFE, "[a|b|c]+ matches 'b'"},
        {"c", true, 1, CAT_MASK_SAFE, "[a|b|c]+ matches 'c'"},
        {"abc", true, 3, CAT_MASK_SAFE, "[a|b|c]+ matches 'abc'"},
    };

    run_test_group("EXPANDED HARD EDGE CASE TESTS", "patterns_expanded_hard.txt",
                   "build_test/expanded_hard.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_expanded_perf_tests(void) {
    TestCase cases[] = {
        {"a", true, 1, CAT_MASK_SAFE, "single 'a' matches a+"},
        {"aa", true, 2, CAT_MASK_SAFE, "two 'a's match a+"},
        {"aaa", true, 3, CAT_MASK_SAFE, "three 'a's match a+"},
        {"aaaaaaaaaa", true, 10, CAT_MASK_SAFE, "ten 'a's match a+"},
        {"aaaaaaaaaaaaaaaaaaaaaaaaaa", true, 26, CAT_MASK_SAFE, "26 'a's match a+"},
        {"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", false, 0, 0, "50 b's should NOT match a+"},
        {"", false, 0, 0, "empty should NOT match a+"},
        {"ababababab", true, 10, CAT_MASK_SAFE, "'ab' pattern matches"},
        {"abababababa", false, 0, 0, "odd length 'ab' should NOT match"},
        {"testtesttesttesttest", true, 20, CAT_MASK_SAFE, "5 'test' repetitions match"},
    };

    run_test_group("EXPANDED PERFORMANCE STRESS TESTS", "patterns_expanded_perf.txt",
                   "build_test/expanded_perf.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_admin_command_tests(void) {
    TestCase cases[] = {
        {"sudo command", true, 0, CAT_MASK_ADMIN, "sudo command matches"},
        {"sudo -i", true, 0, CAT_MASK_ADMIN, "sudo -i matches"},
        {"sudo su", true, 0, CAT_MASK_ADMIN, "sudo su matches"},
        {"useradd username", true, 0, CAT_MASK_ADMIN, "useradd matches"},
        {"groupadd groupname", true, 0, CAT_MASK_ADMIN, "groupadd matches"},
        {"apt-get update", true, 0, CAT_MASK_ADMIN, "apt-get update matches"},
        {"cat file.txt", false, 0, CAT_MASK_ADMIN, "regular command should NOT match admin"},
    };

    run_test_group("ADMIN COMMAND TESTS", "patterns_admin_commands.txt",
                   "build_test/admin_commands.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_caution_command_tests(void) {
    TestCase cases[] = {
        {"cat /etc/passwd", true, 0, CAT_MASK_CAUTION, "cat /etc/passwd matches"},
        {"cat /etc/shadow", true, 0, CAT_MASK_CAUTION, "cat /etc/shadow matches"},
        {"find / -name \"*.conf\"", true, 0, CAT_MASK_CAUTION, "find / matches"},
        {"netstat -tuln", true, 0, CAT_MASK_CAUTION, "netstat matches"},
        {"ifconfig -a", true, 0, CAT_MASK_CAUTION, "ifconfig matches"},
        {"ps aux | grep root", true, 0, CAT_MASK_CAUTION, "ps aux grep matches"},
        {"git status", false, 0, CAT_MASK_CAUTION, "safe command should NOT match caution"},
    };

    run_test_group("CAUTION COMMAND TESTS", "patterns_caution_commands.txt",
                   "build_test/caution_commands.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_modifying_command_tests(void) {
    TestCase cases[] = {
        {"rm file.txt", true, 0, CAT_MASK_MODIFYING, "rm file matches"},
        {"rm -rf /", true, 0, CAT_MASK_MODIFYING, "rm -rf / matches"},
        {"touch newfile.txt", true, 0, CAT_MASK_MODIFYING, "touch matches"},
        {"mkdir dir", true, 0, CAT_MASK_MODIFYING, "mkdir matches"},
        {"cp file1.txt file2.txt", true, 0, CAT_MASK_MODIFYING, "cp matches"},
        {"chmod 755 file.txt", true, 0, CAT_MASK_MODIFYING, "chmod matches"},
        {"git status", false, 0, CAT_MASK_MODIFYING, "safe command should NOT match modifying"},
    };

    run_test_group("MODIFYING COMMAND TESTS", "patterns_modifying_commands.txt",
                   "build_test/modifying_commands.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_dangerous_command_tests(void) {
    TestCase cases[] = {
        {"reboot", true, 0, CAT_MASK_DANGEROUS, "reboot matches"},
        {"shutdown", true, 0, CAT_MASK_DANGEROUS, "shutdown matches"},
        {"dd if=/dev/zero of=/dev/sda", true, 0, CAT_MASK_DANGEROUS, "dd destructive matches"},
        {"mkfs.ext4 /dev/sda1", true, 0, CAT_MASK_DANGEROUS, "mkfs matches"},
        {":(){ :|:& };:", true, 0, CAT_MASK_DANGEROUS, "fork bomb matches"},
        {"git status", false, 0, CAT_MASK_DANGEROUS, "safe command should NOT match dangerous"},
    };

    run_test_group("DANGEROUS COMMAND TESTS", "patterns_dangerous_commands.txt",
                   "build_test/dangerous_commands.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_network_command_tests(void) {
    TestCase cases[] = {
        {"ping google.com", true, 0, CAT_MASK_NETWORK, "ping matches"},
        {"curl http://example.com", true, 0, CAT_MASK_NETWORK, "curl HTTP matches"},
        {"wget https://example.com", true, 0, CAT_MASK_NETWORK, "wget HTTPS matches"},
        {"ssh user@host", true, 0, CAT_MASK_NETWORK, "ssh matches"},
        {"nmap host", true, 0, CAT_MASK_NETWORK, "nmap matches"},
        {"nc host port", true, 0, CAT_MASK_NETWORK, "netcat matches"},
        {"git status", false, 0, CAT_MASK_NETWORK, "safe command should NOT match network"},
    };

    run_test_group("NETWORK COMMAND TESTS", "patterns_network_commands.txt",
                   "build_test/network_commands.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_combined_tests(void) {
    TestCase cases[] = {
        {"cat file.txt", true, 0, CAT_MASK_SAFE, "cat file matches safe"},
        {"grep pattern file.txt", true, 0, CAT_MASK_SAFE, "grep matches safe"},
        {"git status", true, 0, CAT_MASK_SAFE, "git status matches safe"},
        {"git log --oneline", true, 0, CAT_MASK_SAFE, "git log matches safe"},
        {"find . -name \"*.txt\"", true, 0, CAT_MASK_SAFE, "find matches safe"},
        {"ps aux", true, 0, CAT_MASK_SAFE, "ps matches safe"},
        {"rm file.txt", false, 0, CAT_MASK_SAFE, "rm should NOT match safe"},
    };

    run_test_group("COMBINED PATTERN TESTS", "patterns_combined.txt",
                   "build_test/combined.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_minimal_tests(void) {
    TestCase cases[] = {
        {"cat file.txt", true, 12, CAT_MASK_SAFE, "cat file.txt matches"},
        {"ls -la", true, 6, CAT_MASK_SAFE, "ls -la matches"},
        {"rm file.txt", true, 11, CAT_MASK_MODIFYING, "rm file.txt matches"},
        {"reboot", true, 6, CAT_MASK_DANGEROUS, "reboot matches"},
        {"cat", false, 0, 0, "cat alone should NOT match"},
        {"rm", false, 0, 0, "rm alone should NOT match"},
    };

    run_test_group("MINIMAL PATTERN TESTS", "patterns_minimal.txt",
                   "build_test/minimal.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_simple_quantifier_tests(void) {
    TestCase cases[] = {
        {"a", false, 0, 0, "a(B)+ should NOT match 'a' (needs at least one B)"},
        {"aB", true, 2, CAT_MASK_SAFE, "a(B)+ matches 'aB'"},
        {"aBB", true, 3, CAT_MASK_SAFE, "a(B)+ matches 'aBB'"},
        {"aBBB", true, 4, CAT_MASK_SAFE, "a(B)+ matches 'aBBB'"},
        {"", false, 0, 0, "a(B)+ should NOT match empty"},
        {"ab", false, 0, 0, "a(B)+ should NOT match 'ab' (lowercase b)"},
    };

    run_test_group("SIMPLE QUANTIFIER TESTS", "patterns_quantifier_simple.txt",
                   "build_test/simple_quant.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_step_tests(void) {
    TestCase cases[] = {
        {"a", true, 1, CAT_MASK_SAFE, "step1 matches 'a'"},
        {"ab", true, 2, CAT_MASK_SAFE, "step2 matches 'ab'"},
        {"abc", true, 3, CAT_MASK_SAFE, "step3 matches 'abc'"},
        {"", false, 0, 0, "empty should NOT match step patterns"},
    };

    run_test_group("STEP PATTERN TESTS", "patterns_step1.txt",
                   "build_test/step1.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_test_pattern_tests(void) {
    TestCase cases[] = {
        {"test arg1", true, 0, CAT_MASK_SAFE, "test pattern matches"},
        {"TEST uppercase", true, 0, CAT_MASK_SAFE, "TEST uppercase matches"},
        {"test1", true, 0, CAT_MASK_SAFE, "test1 matches"},
        {"", false, 0, 0, "empty should NOT match test pattern"},
    };

    run_test_group("TEST PATTERN TESTS", "patterns_test.txt",
                   "build_test/test_patterns.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_debug_tests(void) {
    TestCase cases[] = {
        {"debug arg1", true, 0, CAT_MASK_SAFE, "debug pattern matches"},
        {"DEBUG UPPERCASE", true, 0, CAT_MASK_SAFE, "DEBUG uppercase matches"},
        {"", false, 0, 0, "empty should NOT match debug pattern"},
    };

    run_test_group("DEBUG PATTERN TESTS", "patterns_debug.txt",
                   "build_test/debug_patterns.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_with_captures_tests(void) {
    TestCase cases[] = {
        {"cp src.txt dst.txt", true, 0, CAT_MASK_SAFE, "cp with captures matches"},
        {"mv old.txt new.txt", true, 0, CAT_MASK_SAFE, "mv with captures matches"},
        {"rsync -avz src/ dest/", true, 0, CAT_MASK_SAFE, "rsync with captures matches"},
        {"echo hello world", true, 0, CAT_MASK_SAFE, "echo with captures matches"},
    };

    run_test_group("WITH CAPTURES TESTS", "patterns_with_captures.txt",
                   "build_test/with_captures.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_capture_simple_tests(void) {
    TestCase cases[] = {
        {"cat file.txt", true, 0, CAT_MASK_SAFE, "cat simple capture matches"},
        {"head -n 10 file.txt", true, 0, CAT_MASK_SAFE, "head capture matches"},
        {"tail -n 5 file.txt", true, 0, CAT_MASK_SAFE, "tail capture matches"},
        {"grep pattern file.txt", true, 0, CAT_MASK_SAFE, "grep capture matches"},
    };

    run_test_group("CAPTURE SIMPLE TESTS", "patterns_capture_simple.txt",
                   "build_test/capture_simple.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_capture_test_tests(void) {
    TestCase cases[] = {
        {"GET /api/users HTTP/1.1", true, 0, CAT_MASK_SAFE, "HTTP request capture matches"},
        {"POST /api/data HTTP/1.1", true, 0, CAT_MASK_SAFE, "POST request capture matches"},
        {"curl -X GET http://api.example.com", true, 0, CAT_MASK_SAFE, "curl with method capture matches"},
    };

    run_test_group("CAPTURE TEST TESTS", "patterns_capture_test.txt",
                   "build_test/capture_test.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

int main(int argc, char* argv[]) {
    printf("=================================================\n");
    printf("DFA TEST RUNNER\n");
    printf("=================================================\n");
    printf("Pattern -> NFA -> DFA -> eval chain per test group\n\n");

    total_tests_run = 0;
    total_tests_passed = 0;

    run_core_tests();
    run_quantifier_tests();
    run_fragment_tests();
    run_alternation_tests();
    run_boundary_tests();
    run_category_tests();
    run_tripled_quantifier_depth();
    run_tripled_fragment_interactions();
    run_tripled_boundary();
    run_tripled_hard_edges();
    run_tripled_syntax();
    run_tripled_category_isolation();
    run_tripled_quantifier_interactions();

    run_expanded_quantifier_tests();
    run_expanded_alternation_tests();
    run_expanded_nested_tests();
    run_expanded_fragment_tests();
    run_expanded_boundary_tests();
    run_expanded_interaction_tests();
    run_expanded_mixed_tests();
    run_expanded_hard_tests();
    run_expanded_perf_tests();

    run_admin_command_tests();
    run_caution_command_tests();
    run_modifying_command_tests();
    run_dangerous_command_tests();
    run_network_command_tests();
    run_combined_tests();
    run_minimal_tests();
    run_simple_quantifier_tests();
    run_step_tests();
    run_test_pattern_tests();
    run_debug_tests();
    run_with_captures_tests();
    run_capture_simple_tests();
    run_capture_test_tests();

    print_separator();
    printf("=================================================\n");
    printf("SUMMARY: %d/%d passed\n", total_tests_passed, total_tests_run);
    printf("=================================================\n");

    return 0;
}
