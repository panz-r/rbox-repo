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
        "mkdir -p %s && cd %s && "
        "../tools/nfa_builder --alphabet ../alphabet_per_char.map ../%s test.nfa 2>/dev/null && "
        "../tools/nfa2dfa_advanced test.nfa %s 2>/dev/null",
        build_dir, build_dir, patterns_file, filename);
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
        {"a+", true, 1, CAT_MASK_SAFE, "a+ matches 'a'"},
        {"aa", true, 2, CAT_MASK_SAFE, "aa matches 'aa'"},
        {"aaa", true, 3, CAT_MASK_SAFE, "aaa matches 'aaa'"},
        {"", false, 0, 0, "a+ should NOT match empty"},
        {"b", false, 0, 0, "a+ should NOT match 'b'"},
        {"ab", false, 0, 0, "a+ should NOT match 'ab'"},
        {"a((b))+", true, 2, CAT_MASK_SAFE, "a((b))+ matches 'ab'"},
        {"a((b))+", true, 3, CAT_MASK_SAFE, "a((b))+ matches 'abb'"},
        {"a((b))+", true, 4, CAT_MASK_SAFE, "a((b))+ matches 'abbb'"},
        {"a((b))+", false, 0, 0, "a((b))+ should NOT match 'a'"},
        {"abc((b))+", true, 4, CAT_MASK_SAFE, "abc((b))+ matches 'abcb'"},
        {"a*", true, 0, CAT_MASK_SAFE, "a* matches empty"},
        {"a", true, 1, CAT_MASK_SAFE, "a* matches 'a'"},
        {"a?", true, 0, CAT_MASK_SAFE, "a? matches empty"},
        {"a?", true, 1, CAT_MASK_SAFE, "a? matches 'a'"},
    };

    run_test_group("QUANTIFIER TESTS", "patterns_quantifier_comprehensive.txt",
                   "build_test/quantifier.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_fragment_tests(void) {
    TestCase cases[] = {
        {"alpha", true, 5, CAT_MASK_SAFE, "alpha matches 'alpha'"},
        {"beta", true, 4, CAT_MASK_SAFE, "beta matches 'beta'"},
        {"alpha beta", true, 11, CAT_MASK_SAFE, "alpha beta matches"},
        {"outer inner", true, 12, CAT_MASK_SAFE, "outer inner matches"},
        {"inner", false, 0, 0, "inner alone should NOT match"},
        {"outer", false, 0, 0, "outer alone should NOT match"},
        {"((xyz))+", true, 3, CAT_MASK_SAFE, "((xyz))+ matches 'xyz'"},
        {"((xyz))+", true, 6, CAT_MASK_SAFE, "((xyz))+ matches 'xyzxyz'"},
    };

    run_test_group("FRAGMENT TESTS", "patterns_frag_quant.txt",
                   "build_test/fragment.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_alternation_tests(void) {
    TestCase cases[] = {
        {"(a|b)", true, 1, CAT_MASK_SAFE, "(a|b) matches 'a'"},
        {"(a|b)", true, 1, CAT_MASK_SAFE, "(a|b) matches 'b'"},
        {"(a|b)+", true, 1, CAT_MASK_SAFE, "(a|b)+ matches 'a'"},
        {"(a|b)+", true, 2, CAT_MASK_SAFE, "(a|b)+ matches 'ab'"},
        {"(a|b)+", true, 3, CAT_MASK_SAFE, "(a|b)+ matches 'aba'"},
        {"", false, 0, 0, "(a|b)+ should NOT match empty"},
        {"c", false, 0, 0, "(a|b)+ should NOT match 'c'"},
        {"(ABC|DEF)", true, 3, CAT_MASK_SAFE, "(ABC|DEF) matches 'ABC'"},
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
        {"a((b))+", true, 2, CAT_MASK_SAFE, "a((b))+ matches 'ab'"},
        {"a((b))+", true, 3, CAT_MASK_SAFE, "a((b))+ matches 'abb'"},
        {"a((b))+", true, 4, CAT_MASK_SAFE, "a((b))+ matches 'abbb'"},
        {"a((b))+", false, 0, 0, "a((b))+ should NOT match 'a'"},
        {"((a))+", true, 1, CAT_MASK_SAFE, "((a))+ matches 'a'"},
        {"((a))+", true, 2, CAT_MASK_SAFE, "((a))+ matches 'aa'"},
        {"((a))+", true, 3, CAT_MASK_SAFE, "((a))+ matches 'aaa'"},
        {"(((a)))+", true, 2, CAT_MASK_SAFE, "(((a)))+ matches 'aa'"},
        {"(((a)))+", true, 4, CAT_MASK_SAFE, "(((a)))+ matches 'aaaa'"},
        {"(a|b)+", true, 1, CAT_MASK_SAFE, "(a|b)+ matches 'a'"},
        {"(a|b)+", true, 2, CAT_MASK_SAFE, "(a|b)+ matches 'ab'"},
        {"(a|b)+", true, 5, CAT_MASK_SAFE, "(a|b)+ matches 'ababa'"},
        {"((a|b))+", true, 1, CAT_MASK_SAFE, "((a|b))+ matches 'a'"},
        {"((a|b))+", true, 2, CAT_MASK_SAFE, "((a|b))+ matches 'ab'"},
        {"((a|b))+", true, 4, CAT_MASK_SAFE, "((a|b))+ matches 'abab'"},
        {"(a*)+", true, 0, CAT_MASK_SAFE, "(a*)+ matches empty"},
        {"(a*)+", true, 1, CAT_MASK_SAFE, "(a*)+ matches 'a'"},
        {"(a+)+", true, 1, CAT_MASK_SAFE, "(a+)+ matches 'a'"},
        {"(a+)+", true, 3, CAT_MASK_SAFE, "(a+)+ matches 'aaa'"},
    };

    run_test_group("TRIPLED QUANTIFIER DEPTH", "patterns_quantifier_comprehensive.txt",
                   "build_test/tripled_quant.dfa", cases, sizeof(cases)/sizeof(cases[0]));
}

static void run_tripled_fragment_interactions(void) {
    TestCase cases[] = {
        {"alpha", true, 5, CAT_MASK_SAFE, "alpha matches 'alpha'"},
        {"beta", true, 4, CAT_MASK_SAFE, "beta matches 'beta'"},
        {"alpha beta", true, 11, CAT_MASK_SAFE, "alpha beta matches"},
        {"outer inner", true, 12, CAT_MASK_SAFE, "outer inner matches"},
        {"((xyz))+", true, 3, CAT_MASK_SAFE, "((xyz))+ matches 'xyz'"},
        {"((xyz))+", true, 6, CAT_MASK_SAFE, "((xyz))+ matches 'xyzxyz'"},
        {"ABC ABC ABC", true, 11, CAT_MASK_SAFE, "ABC repeated 3x matches"},
        {"(AB)+", true, 2, CAT_MASK_SAFE, "(AB)+ matches 'AB'"},
        {"(AB)+", true, 4, CAT_MASK_SAFE, "(AB)+ matches 'ABAB'"},
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
        {"a((b))+", true, 2, CAT_MASK_SAFE, "a+(b)+ matches 'ab'"},
        {"a((b))+", true, 4, CAT_MASK_SAFE, "a+(b)+ matches 'abbb'"},
        {"a((b))*", true, 0, CAT_MASK_SAFE, "a+(b)* matches empty"},
        {"a((b))*", true, 1, CAT_MASK_SAFE, "a+(b)* matches 'a'"},
        {"a((b))*", true, 3, CAT_MASK_SAFE, "a+(b)* matches 'abb'"},
        {"a((b))?", true, 1, CAT_MASK_SAFE, "a+(b)? matches 'a'"},
        {"a((b))?", true, 2, CAT_MASK_SAFE, "a+(b)? matches 'ab'"},
        {"abc((d))+", true, 4, CAT_MASK_SAFE, "abc+(d)+ matches 'abcd'"},
        {"((x)y)+", true, 2, CAT_MASK_SAFE, "((x)y)+ matches 'xy'"},
        {"((x)y)+", true, 4, CAT_MASK_SAFE, "((x)y)+ matches 'xyxy'"},
        {"((x)y)*", true, 0, CAT_MASK_SAFE, "((x)y)* matches empty"},
        {"((x)y)*", true, 2, CAT_MASK_SAFE, "((x)y)* matches 'xy'"},
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
        {"abc", true, 1, CAT_MASK_SAFE, "abc+ matches 'abc'"},
        {"abcc", true, 4, CAT_MASK_SAFE, "abc+ matches 'abcc'"},
        {"a?", true, 1, CAT_MASK_SAFE, "a? matches 'a'"},
        {"", true, 0, CAT_MASK_SAFE, "a? matches empty"},
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

    print_separator();
    printf("=================================================\n");
    printf("SUMMARY: %d/%d passed\n", total_tests_passed, total_tests_run);
    printf("=================================================\n");

    return 0;
}
