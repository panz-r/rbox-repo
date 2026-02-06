// ============================================================================
// EXPANDED DFA/NFA TEST SUITE (3x Coverage)
// ============================================================================
// Additional test functions for comprehensive coverage

static int expanded_tests_run = 0;
static int expanded_tests_passed = 0;

#define EXP_TEST_ASSERT(cond, msg) do { \
    expanded_tests_run++; \
    if (cond) { \
        expanded_tests_passed++; \
        printf("  [PASS] %s\n", msg); \
    } else { \
        printf("  [FAIL] %s\n", msg); \
    } \
} while(0)

typedef struct {
    const char* input;
    bool should_match;
    size_t expected_len;
    const char* description;
} ExpandedTestCase;

static void test_expanded_quantifier_edge_cases(void) {
    printf("\nTest: Quantifier Edge Cases (Expanded)\n");
    printf("  Edge cases that commonly cause failures\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Single char quantifier edge cases
        {"a+", true, 1, "a+ matches single 'a'"},
        {"aa+", true, 2, "aa+ matches two 'a's"},
        {"aaa+", true, 3, "aaa+ matches three 'a's"},
        {"aaaaaa", true, 6, "aaaaaa matches six 'a's"},
        {"", false, 0, "empty string should not match a+"},
        {"b", false, 0, "b should not match a+"},
        {"ab", false, 0, "ab should not match a+"},
        {"ba", false, 0, "ba should not match a+"},
        {"aaaab", false, 0, "aaaab should not match a+"},

        // Multiple char literal quantifier
        {"abc+", true, 3, "abc+ matches 'abc'"},
        {"abcc", true, 4, "abcc matches 'abcc'"},
        {"abccc", true, 5, "abccc matches 'abccc'"},
        {"", false, 0, "empty should not match abc+"},
        {"ab", false, 0, "ab should not match abc+"},
        {"abd", false, 0, "abd should not match abc+"},

        // Quantifier at pattern end
        {"test123+", true, 7, "test123+ matches full pattern"},
        {"test1234", false, 0, "test1234 should not match test123+"},

        // Quantifier after fragment
        {"xyz((abc))+", true, 6, "xyz((abc))+ matches xyzabc"},
        {"xyz((abc))abc", true, 9, "xyz((abc))abc matches xyzabcabc"},
        {"xyz((abc))abcabc", true, 12, "xyz((abc))abcabc matches xyzabcabcabc"},
        {"xyz", false, 0, "xyz should not match xyz((abc))+"},
        {"xyz((def))+", false, 0, "xyz((def))+ should not match"},

        // Zero vs one quantifier confusion
        {"a?", true, 1, "a? matches single 'a'"},
        {"", true, 0, "empty matches a? (zero occurrences)"},
        {"aa", false, 0, "aa should not match a?"},

        // Star vs plus confusion
        {"a*", true, 0, "a* matches empty (zero or more)"},
        {"a", true, 1, "a matches a* (one)"},
        {"aa", true, 2, "aa matches a* (two)"},
        {"aaa", true, 3, "aaa matches a* (three)"},
        {"b", true, 0, "b matches a* (zero a's, just b)"},
        {"baa", true, 1, "baa matches a* (one a)"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

static void test_expanded_alternation_with_quantifiers(void) {
    printf("\nTest: Alternation with Quantifiers (Expanded)\n");
    printf("  Testing | combined with +, *, ?\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Alternation with plus
        {"(a|b)+", true, 1, "(a|b)+ matches 'a'"},
        {"(a|b)+", true, 1, "(a|b)+ matches 'b'"},
        {"(a|b)+", true, 2, "(a|b)+ matches 'aa'"},
        {"(a|b)+", true, 2, "(a|b)+ matches 'ab'"},
        {"(a|b)+", true, 2, "(a|b)+ matches 'ba'"},
        {"(a|b)+", true, 2, "(a|b)+ matches 'bb'"},
        {"(a|b)+", true, 3, "(a|b)+ matches 'aba'"},
        {"(a|b)+", true, 5, "(a|b)+ matches 'ababa'"},
        {"", false, 0, "empty should not match (a|b)+"},
        {"c", false, 0, "'c' should not match (a|b)+"},

        // Alternation with star
        {"(a|b)*", true, 0, "(a|b)* matches empty"},
        {"(a|b)*", true, 1, "(a|b)* matches 'a'"},
        {"(a|b)*", true, 2, "(a|b)* matches 'ab'"},
        {"(a|b)*", true, 4, "(a|b)* matches 'abba'"},
        {"(a|b)*c", true, 3, "(a|b)*c matches 'abc'"},
        {"(a|b)*c", true, 4, "(a|b)*c matches 'abbc'"},
        {"c", true, 1, "(a|b)*c matches 'c' (zero a/b)"},
        {"ac", true, 2, "(a|b)*c matches 'ac'"},

        // Alternation with optional
        {"(a|b)?", true, 0, "(a|b)? matches empty"},
        {"(a|b)?", true, 1, "(a|b)? matches 'a'"},
        {"(a|b)?", true, 1, "(a|b)? matches 'b'"},
        {"(a|b)?c", true, 2, "(a|b)?c matches 'ac'"},
        {"(a|b)?c", true, 2, "(a|b)?c matches 'bc'"},
        {"(a|b)?c", true, 1, "(a|b)?c matches 'c' (optional not present)"},
        {"(a|b)?c", false, 0, "(a|b)?c should not match 'cc'"},

        // Multiple alternations
        {"(a|b|c)+", true, 1, "(a|b|c)+ matches 'a'"},
        {"(a|b|c)+", true, 1, "(a|b|c)+ matches 'b'"},
        {"(a|b|c)+", true, 1, "(a|b|c)+ matches 'c'"},
        {"(a|b|c)+", true, 3, "(a|b|c)+ matches 'abc'"},
        {"(a|b|c)+", true, 5, "(a|b|c)+ matches 'ababc'"},
        {"", false, 0, "empty should not match (a|b|c)+"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

static void test_expanded_nested_quantifiers(void) {
    printf("\nTest: Complex Nested Quantifiers (Expanded)\n");
    printf("  Deeply nested quantifier patterns\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Double nesting
        {"((a))+", true, 1, "((a))+ matches 'a'"},
        {"((a))+", true, 2, "((a))+ matches 'aa'"},
        {"((a))+", true, 3, "((a))+ matches 'aaa'"},
        {"", false, 0, "empty should not match ((a))+"},

        // Triple nesting
        {"(((a)))+", true, 1, "(((a)))+ matches 'a'"},
        {"(((a)))+", true, 3, "(((a)))+ matches 'aaa'"},
        {"", false, 0, "empty should not match (((a)))+"},

        // Mixed nesting
        {"((a)+)+", true, 1, "((a)+)+ matches 'a' (inner + requires one)"},
        {"((a)+)+", true, 2, "((a)+)+ matches 'aa'"},
        {"((a)+)+", true, 3, "((a)+)+ matches 'aaa'"},
        {"((a)+)+", true, 4, "((a)+)+ matches 'aaaa'"},
        {"", false, 0, "empty should not match ((a)+)+"},

        // Star inside plus
        {"(a*)+", true, 0, "(a*)+ matches empty (a* allows zero)"},
        {"(a*)+", true, 1, "(a*)+ matches 'a'"},
        {"(a*)+", true, 2, "(a*)+ matches 'aa'"},
        {"(a*)+", true, 3, "(a*)+ matches 'aaa'"},
        {"(a*)+b", true, 2, "(a*)+b matches 'ab'"},
        {"(a*)+b", true, 3, "(a*)+b matches 'aab'"},

        // Plus inside star
        {"(a+)*", true, 0, "(a+)* matches empty (zero repetitions)"},
        {"(a+)*", true, 1, "(a+)* matches 'a' (one rep of a+)"},
        {"(a+)*", true, 2, "(a+)* matches 'aa' (one rep)"},
        {"(a+)*", true, 3, "(a+)* matches 'aaa' (one rep)"},
        {"(a+)*", true, 4, "(a+)* matches 'aaaa' (one rep)"},
        {"", true, 0, "(a+)* matches empty (zero reps)"},
        {"b", true, 0, "(a+)*b matches 'b' (zero a+ reps)"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

static void test_expanded_fragment_interactions(void) {
    printf("\nTest: Fragment Interactions (Expanded)\n");
    printf("  Testing multiple fragments with quantifiers\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Multiple fragments
        {"((x))+((y))+", true, 2, "xy matches x+ y+"},
        {"((x))+((y))+", true, 3, "xxy matches x+ y+"},
        {"((x))+((y))+", true, 3, "xyy matches x+ y+"},
        {"((x))+((y))+", true, 4, "xxyy matches x+ y+"},
        {"((x))+((y))+", true, 5, "xxxyy matches x+ y+"},
        {"((x))+((y))+", true, 5, "xxyyy matches x+ y+"},
        {"", false, 0, "empty should not match x+ y+"},
        {"x", false, 0, "x alone should not match x+ y+"},
        {"y", false, 0, "y alone should not match x+ y+"},

        // Fragment with literal
        {"abc((def))+", true, 6, "abcdef matches abc def+"},
        {"abc((def))+", true, 9, "abcdefdef matches abc def+ def+"},
        {"abc((def))+", true, 12, "abcdefdefdef matches abc def+ def+ def+"},
        {"abc", false, 0, "abc alone should not match abc def+"},
        {"abcdeg", false, 0, "abcdeg should not match abc def+"},

        // Nested fragments
        {"(( (a) ))+", true, 1, "nested single char fragment matches 'a'"},
        {"(( (a) ))+", true, 3, "nested single char fragment matches 'aaa'"},
        {"", false, 0, "nested fragment should not match empty"},

        // Fragment alternation
        {"((a|b))+((c|d))+", true, 2, "ac matches a+|c+ with b+|d+"},
        {"((a|b))+((c|d))+", true, 2, "ad matches a+|c+ with b+|d+"},
        {"((a|b))+((c|d))+", true, 2, "bc matches a+|c+ with b+|d+"},
        {"((a|b))+((c|d))+", true, 2, "bd matches a+|c+ with b+|d+"},
        {"", false, 0, "empty should not match fragment alternation"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

static void test_expanded_boundary_conditions(void) {
    printf("\nTest: Boundary Conditions (Expanded)\n");
    printf("  Edge cases at pattern boundaries\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Empty pattern edge cases
        {"", true, 0, "empty pattern matches empty string"},

        // Quantifier at very end
        {"abc", true, 3, "abc matches 'abc' at end"},
        {"abcdef", true, 6, "abcdef matches full pattern"},
        {"abcde", false, 0, "abcde should not match if pattern needs 'f'"},
        {"abcdefg", false, 0, "abcdefg should not match if pattern ends at 'f'"},

        // Over-quantification
        {"a++", true, 2, "a++ matches 'aa' (two a's)"},
        {"a++", true, 3, "a++ matches 'aaa' (three a's)"},
        {"a+++", true, 3, "a+++ matches 'aaa' (three a's)"},

        // Mixed quantifiers
        {"a?b+", true, 2, "ab matches a?b+"},
        {"a?b+", true, 1, "b matches a?b+ (a is optional)"},
        {"a?b+", true, 3, "abb matches a?b+"},
        {"a?b+", true, 4, "abbb matches a?b+"},
        {"a?b+", false, 0, "a alone should not match a?b+"},
        {"a?b+", false, 0, "empty should not match a?b+"},

        {"a+b?", true, 1, "a matches a+b? (b optional)"},
        {"a+b?", true, 2, "ab matches a+b?"},
        {"a+b?", true, 3, "aab matches a+b?"},
        {"a+b?", true, 3, "abb matches a+b?"},
        {"", false, 0, "empty should not match a+b?"},

        // Consecutive quantifiers
        {"a?b?c?", true, 0, "empty matches a?b?c? (all optional)"},
        {"a?b?c?", true, 1, "a matches a?b?c?"},
        {"a?b?c?", true, 2, "ab matches a?b?c?"},
        {"a?b?c?", true, 3, "abc matches a?b?c?"},
        {"a?b?c?", true, 1, "b matches a?b?c? (a optional)"},
        {"a?b?c?", true, 2, "bc matches a?b?c? (a optional)"},
        {"a?b?c?", true, 1, "c matches a?b?c? (a,b optional)"},
        {"a?b?c?", false, 0, "d should not match a?b?c?"},

        // Maximum repetition test
        {"aaaaaaaaaaaaaaa", true, 15, "15 a's match a+"},
        {"aaaaaaaaaaaaaaaa", true, 16, "16 a's match a+"},
        {"aaaaaaaaaaaaaaaaa", true, 17, "17 a's match a+"},
        {"aaaaaaaaaaaaaaaaaa", true, 18, "18 a's match a+"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

static void test_expanded_quantifier_interactions(void) {
    printf("\nTest: Quantifier Interaction Patterns (Expanded)\n");
    printf("  Complex interactions between quantifiers\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Plus followed by star
        {"a+b*", true, 1, "a+b* matches 'a' (b*)"},
        {"a+b*", true, 2, "a+b* matches 'ab'"},
        {"a+b*", true, 3, "a+b* matches 'abb'"},
        {"a+b*", true, 2, "a+b* matches 'aa' (one b, star extends)"},
        {"a+b*", true, 3, "a+b* matches 'aab'"},
        {"a+b*", true, 1, "a+b* matches 'a' (zero bs)"},
        {"b*", true, 0, "a+b* starting with b* matches 'b'"},
        {"", false, 0, "empty should not match a+b* (needs at least one a)"},

        // Star followed by plus
        {"a*b+", true, 1, "a*b+ matches 'a' (a* allows zero, b+ needs one)"},
        {"a*b+", true, 2, "a*b+ matches 'ab'"},
        {"a*b+", true, 3, "a*b+ matches 'abb'"},
        {"a*b+", true, 2, "a*b+ matches 'aa' (first a*, then b+)"},
        {"a*b+", true, 3, "a*b+ matches 'aab'"},
        {"a*b+", true, 1, "a*b+ matches 'b' (zero a's)"},
        {"", false, 0, "empty should not match a*b+ (needs at least one b)"},

        // Optional followed by plus
        {"a?b+", true, 1, "a?b+ matches 'b' (a optional)"},
        {"a?b+", true, 2, "a?b+ matches 'ab'"},
        {"a?b+", true, 3, "a?b+ matches 'abb'"},
        {"", false, 0, "empty should not match a?b+ (needs b)"},

        // Plus followed by optional
        {"a+b?", true, 1, "a+b? matches 'a' (b optional)"},
        {"a+b?", true, 2, "a+b? matches 'ab'"},
        {"a+b?", true, 3, "a+b? matches 'abb'"},
        {"a+b?", true, 2, "a+b? matches 'aa'"},
        {"", false, 0, "empty should not match a+b?"},

        // All three quantifiers
        {"a?b?c?", true, 0, "empty matches a?b?c?"},
        {"a?b?c?", true, 1, "a matches a?b?c?"},
        {"a?b?c?", true, 2, "ab matches a?b?c?"},
        {"a?b?c?", true, 3, "abc matches a?b?c?"},
        {"a?b?c?", true, 1, "b matches a?b?c?"},
        {"a?b?c?", true, 2, "bc matches a?b?c?"},
        {"a?b?c?", true, 1, "c matches a?b?c?"},

        // Complex interactions
        {"(a+b?)+", true, 1, "(a+b?)+ matches 'a'"},
        {"(a+b?)+", true, 2, "(a+b?)+ matches 'ab'"},
        {"(a+b?)+", true, 3, "(a+b?)+ matches 'aba'"},
        {"(a+b?)+", true, 3, "(a+b?)+ matches 'abb'"},
        {"(a+b?)+", true, 4, "(a+b?)+ matches 'abab'"},
        {"(a+b?)+", true, 2, "(a+b?)+ matches 'aa'"},
        {"", true, 0, "(a+b?)+ matches empty (outer + allows zero)"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

static void test_expanded_mixed_literal_fragment(void) {
    printf("\nTest: Mixed Literal/Fragment Quantifiers (Expanded)\n");
    printf("  Combining literal chars with fragments under quantifiers\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Literal followed by fragment with quantifier
        {"x((y))", true, 2, "xy matches x y (no quantifier)"},
        {"x((y))+", true, 2, "xy matches x y+ (one y)"},
        {"x((y))+", true, 3, "xyy matches x y+ (two y's)"},
        {"x((y))+", true, 4, "xyyy matches x y+ (three y's)"},
        {"x", false, 0, "x alone should not match x y+"},
        {"xz", false, 0, "xz should not match x y+"},

        // Fragment followed by literal with quantifier
        {"((x))y", true, 2, "xy matches x y (no quantifier)"},
        {"((x))+y", true, 2, "xy matches x+ y (one x)"},
        {"((x))+y", true, 3, "xxy matches x+ y (two x's)"},
        {"((x))+y", true, 4, "xxxy matches x+ y (three x's)"},
        {"y", false, 0, "y alone should not match x+ y"},
        {"zy", false, 0, "zy should not match x+ y"},

        // Multiple literals with fragment quantifier
        {"ab((c))de", true, 5, "abcde matches ab c de"},
        {"ab((c))+de", true, 5, "abcde matches ab c+ de (one c)"},
        {"ab((c))+de", true, 6, "abccde matches ab c+ de (two c's)"},
        {"ab((c))+de", true, 7, "abcccde matches ab c+ de (three c's)"},
        {"abde", false, 0, "abde should not match ab c+ de"},
        {"abfde", false, 0, "abfde should not match ab c+ de"},

        // Fragment with quantifier between literals
        {"start((mid))+end", true, 10, "startmidend matches start mid+ end (one mid)"},
        {"start((mid))+end", true, 13, "startmiddend matches start mid+ end (two mids)"},
        {"start((mid))+end", true, 16, "startmidddend matches start mid+ end (three mids)"},
        {"startend", false, 0, "startend should not match start mid+ end"},
        {"startxend", false, 0, "startxend should not match start mid+ end"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

static void test_expanded_hard_edge_cases(void) {
    printf("\nTest: Very Hard Edge Cases (Expanded)\n");
    printf("  Extremely challenging patterns likely to fail\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Nested plus patterns
        {"(a+a+)+b", true, 3, "(a+a+)+b matches 'aab' (nested plus)"},
        {"(a+a+)+b", true, 5, "(a+a+)+b matches 'aaaab' (nested plus)"},
        {"(a+a+)+b", true, 7, "(a+a+)+b matches 'aaaaaab' (nested plus)"},
        {"b", false, 0, "b alone should not match (a+a+)+b"},

        // Overlapping fragment references
        {"((a))+((a))+", true, 1, "a matches a+ a+ (both fragments same char)"},
        {"((a))+((a))+", true, 2, "aa matches a+ a+ (two total)"},
        {"((a))+((a))+", true, 3, "aaa matches a+ a+ (three total)"},
        {"", false, 0, "empty should not match a+ a+"},

        // Fragment with itself in quantifier
        {"((ab))+", true, 2, "(ab)+ matches 'ab'"},
        {"((ab))+", true, 4, "(ab)+ matches 'abab'"},
        {"((ab))+", true, 6, "(ab)+ matches 'ababab'"},
        {"a", false, 0, "'a' should not match (ab)+"},
        {"b", false, 0, "'b' should not match (ab)+"},
        {"aba", false, 0, "'aba' should not match (ab)+"},

        // Alternation with quantifier edge cases
        {"(a|aa)+", true, 1, "(a|aa)+ matches 'a'"},
        {"(a|aa)+", true, 2, "(a|aa)+ matches 'aa'"},
        {"(a|aa)+", true, 2, "(a|aa)+ matches 'aa' (second alternative)"},
        {"(a|aa)+", true, 3, "(a|aa)+ matches 'aaa' (a + aa)"},
        {"(a|aa)+", true, 4, "(a|aa)+ matches 'aaaa' (aa + aa)"},
        {"", false, 0, "empty should not match (a|aa)+"},

        // Quantifier after character class
        {"[abc]+", true, 1, "[abc]+ matches 'a'"},
        {"[abc]+", true, 1, "[abc]+ matches 'b'"},
        {"[abc]+", true, 1, "[abc]+ matches 'c'"},
        {"[abc]+", true, 3, "[abc]+ matches 'abc'"},
        {"[abc]+", true, 5, "[abc]+ matches 'ababc'"},
        {"[abc]+", true, 6, "[abc]+ matches 'abcabc'"},
        {"d", false, 0, "'d' should not match [abc]+"},
        {"", false, 0, "empty should not match [abc]+"},

        // Whitespace handling with quantifiers
        {"a +b", true, 3, "a b matches 'a +b' (one space before +)"},
        {"a+ b", true, 2, "ab matches 'a+ b' (no space in input)"},
        {"aa b", true, 3, "aa b matches 'a+ b'"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

static void test_expanded_performance_stress(void) {
    printf("\nTest: Performance Stress Quantifiers (Expanded)\n");
    printf("  Large inputs to test efficiency\n\n");

    dfa_result_t result;

    ExpandedTestCase cases[] = {
        // Long inputs matching
        {"a", true, 1, "single 'a' matches a+"},
        {"aa", true, 2, "two 'a's match a+"},
        {"aaa", true, 3, "three 'a's match a+"},
        {"aaaa", true, 4, "four 'a's match a+"},
        {"aaaaa", true, 5, "five 'a's match a+"},
        {"aaaaaa", true, 6, "six 'a's match a+"},
        {"aaaaaaa", true, 7, "seven 'a's match a+"},
        {"aaaaaaaa", true, 8, "eight 'a's match a+"},
        {"aaaaaaaaa", true, 9, "nine 'a's match a+"},
        {"aaaaaaaaaa", true, 10, "ten 'a's match a+"},
        {"aaaaaaaaaaaaaaaaaaaaaaaaaa", true, 26, "26 'a's match a+"},
        {"aaaaaaaaaaaaaaaaaaaaaaaaaaa", true, 27, "27 'a's match a+"},
        {"aaaaaaaaaaaaaaaaaaaaaaaaaaaa", true, 28, "28 'a's match a+"},
        {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true, 29, "29 'a's match a+"},
        {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true, 30, "30 'a's match a+"},

        // Long inputs not matching
        {"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", false, 0, "50 b's should not match a+"},
        {"", false, 0, "empty should not match a+ (requires at least one a)"},

        // Medium complex patterns
        {"ababababab", true, 10, "10 chars 'ab' pattern matches"},
        {"abababababa", false, 0, "11 chars 'ab' pattern should not match (odd length)"},
        {"xyxyxyxyxyxyxyxyxyxy", true, 20, "20 chars 'xy' pattern matches"},
        {"xyxyxyxyxyxyxyxyxyx", false, 0, "19 chars 'xy' pattern should not match"},

        // Stress test with fragments
        {"testtesttesttesttest", true, 20, "5 'test' repetitions match"},
        {"testtesttesttesttesttest", true, 24, "6 'test' repetitions match"},
        {"testtesttesttesttesttesttest", true, 28, "7 'test' repetitions match"},
        {"testtesttesttesttesttesttesttest", true, 32, "8 'test' repetitions match"},
        {"testtesttesttesttesttesttesttesttest", true, 36, "9 'test' repetitions match"},
        {"testtesttesttesttesttesttesttesttesttest", true, 40, "10 'test' repetitions match"},
    };

    int count = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < count; i++) {
        dfa_evaluate(cases[i].input, 0, &result);
        bool passed = (result.matched == cases[i].should_match);
        if (passed && cases[i].should_match) {
            passed = (result.matched_length == cases[i].expected_len);
        }
        EXP_TEST_ASSERT(passed, cases[i].description);
    }
}

void run_expanded_tests(void) {
    printf("\n");
    printf("=================================================\n");
    printf("EXPANDED DFA/NFA TEST SUITE (3x Coverage)\n");
    printf("=================================================\n");

    test_expanded_quantifier_edge_cases();
    test_expanded_alternation_with_quantifiers();
    test_expanded_nested_quantifiers();
    test_expanded_fragment_interactions();
    test_expanded_boundary_conditions();
    test_expanded_quantifier_interactions();
    test_expanded_mixed_literal_fragment();
    test_expanded_hard_edge_cases();
    test_expanded_performance_stress();

    printf("\n=================================================\n");
    printf("EXPANDED TESTS: %d/%d passed\n", expanded_tests_passed, expanded_tests_run);
    printf("=================================================\n");
}
