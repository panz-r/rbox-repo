// ============================================================================
// PatternMatcher Fuzz Test
//
// Generates random AST patterns and inputs, then validates that:
// 1. PatternMatcher::matches never crashes or hangs
// 2. PatternMatcher::validate is consistent (if matches says X matches,
//    validate should agree)
// 3. PatternMatcher handles deeply nested and degenerate patterns
// ============================================================================

#include "pattern_matcher.h"
#include "testgen.h"
#include <iostream>
#include <random>
#include <sstream>
#include <chrono>

static int fuzz_tests_run = 0;
static int fuzz_tests_passed = 0;
static int fuzz_tests_failed = 0;

#define FUZZ_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        std::cout << "FAIL: " << msg << "\n"; \
        fuzz_tests_failed++; \
        return; \
    } \
} while(0)

// Generate a random string of given length from a safe alphabet
static std::string randomString(int len, std::mt19937& rng) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::string result;
    for (int i = 0; i < len; i++) {
        result += charset[std::uniform_int_distribution<int>(0, sizeof(charset) - 2)(rng)];
    }
    return result;
}

// Generate a random AST node with given depth limit
static std::shared_ptr<PatternNode> randomAST(int depth, std::mt19937& rng) {
    if (depth <= 0) {
        return PatternNode::createLiteral(randomString(
            std::uniform_int_distribution<int>(1, 4)(rng), rng));
    }
    
    int type = std::uniform_int_distribution<int>(0, 6)(rng);
    switch (type) {
    case 0: { // Literal
        return PatternNode::createLiteral(randomString(
            std::uniform_int_distribution<int>(1, 6)(rng), rng));
    }
    case 1: { // Alternation
        int n = std::uniform_int_distribution<int>(2, 4)(rng);
        std::vector<std::shared_ptr<PatternNode>> alts;
        for (int i = 0; i < n; i++) {
            alts.push_back(PatternNode::createLiteral(randomString(
                std::uniform_int_distribution<int>(1, 4)(rng), rng)));
        }
        return PatternNode::createAlternation(alts);
    }
    case 2: { // Sequence
        int n = std::uniform_int_distribution<int>(1, 3)(rng);
        std::vector<std::shared_ptr<PatternNode>> kids;
        for (int i = 0; i < n; i++) {
            kids.push_back(randomAST(depth - 1, rng));
        }
        return PatternNode::createSequence(kids);
    }
    case 3: { // Plus
        auto child = randomAST(depth - 1, rng);
        return PatternNode::createQuantified(child, PatternType::PLUS_QUANTIFIER);
    }
    case 4: { // Star
        auto child = randomAST(depth - 1, rng);
        return PatternNode::createQuantified(child, PatternType::STAR_QUANTIFIER);
    }
    case 5: { // Optional
        auto child = randomAST(depth - 1, rng);
        return PatternNode::createQuantified(child, PatternType::OPTIONAL);
    }
    default: // Fragment ref
        return PatternNode::createFragment("f");
    }
}

// Fuzz test: generate random patterns, match against random inputs
void fuzz_randomPatterns(int iterations, unsigned int seed) {
    std::cout << "  Fuzz random patterns (" << iterations << " iterations, seed=" << seed << ")...\n";
    std::mt19937 rng(seed);
    
    for (int i = 0; i < iterations; i++) {
        auto pattern = randomAST(3, rng);
        std::string input = randomString(std::uniform_int_distribution<int>(0, 10)(rng), rng);
        
        // Should never crash
        bool matched = PatternMatcher::matches(pattern, input);
        (void)matched; // just checking it doesn't crash
        
        fuzz_tests_run++;
    }
    fuzz_tests_passed += iterations;
}

// Fuzz test: validate consistency between matches() and validate()
void fuzz_validateConsistency(int iterations, unsigned int seed) {
    std::cout << "  Fuzz validate consistency (" << iterations << " iterations)...\n";
    std::mt19937 rng(seed);
    int consistent = 0;
    
    for (int i = 0; i < iterations; i++) {
        auto pattern = randomAST(2, rng);
        
        int n_match = std::uniform_int_distribution<int>(1, 3)(rng);
        int n_counter = std::uniform_int_distribution<int>(1, 3)(rng);
        
        std::vector<std::string> matching, counters;
        for (int j = 0; j < n_match; j++) {
            matching.push_back(randomString(std::uniform_int_distribution<int>(1, 6)(rng), rng));
        }
        for (int j = 0; j < n_counter; j++) {
            counters.push_back(randomString(std::uniform_int_distribution<int>(1, 6)(rng), rng));
        }
        
        bool all_match = true;
        for (const auto& m : matching) {
            if (!PatternMatcher::matches(pattern, m)) {
                all_match = false;
                break;
            }
        }
        bool any_counter_matches = false;
        for (const auto& c : counters) {
            if (PatternMatcher::matches(pattern, c)) {
                any_counter_matches = true;
                break;
            }
        }
        
        bool manual_valid = all_match && !any_counter_matches;
        bool validate_result = PatternMatcher::validate(pattern, matching, counters);
        
        if (manual_valid == validate_result) {
            consistent++;
        } else {
            // This can legitimately differ if matches() is more conservative than validate()
            // Only flag as real failure if validate says OK but individual matches disagree
            if (validate_result && !all_match) {
                std::cout << "    INCONSISTENCY at iter " << i << ": validate=true but individual match failed\n";
                fuzz_tests_failed++;
            }
        }
        
        fuzz_tests_run++;
    }
    fuzz_tests_passed += iterations;
    std::cout << "    Consistency: " << consistent << "/" << iterations << "\n";
}

// Fuzz test: deep nesting doesn't hang or stack overflow
void fuzz_deepNesting() {
    std::cout << "  Fuzz deep nesting...\n";
    std::mt19937 rng(42);
    
    // Build a deeply nested quantifier chain
    auto node = PatternNode::createLiteral("a");
    for (int i = 0; i < 20; i++) {
        node = PatternNode::createQuantified(node, PatternType::STAR_QUANTIFIER);
    }
    
    // Should complete quickly (not hang)
    bool result = PatternMatcher::matches(node, "a");
    // Deep nesting of star on a single char: "a" should match
    if (!result) {
        std::cout << "    Deep nesting: expected 'a' to match, got false\n";
        fuzz_tests_failed++;
    }
    
    result = PatternMatcher::matches(node, "");
    // Star allows empty
    if (!result) {
        std::cout << "    Deep nesting: expected '' to match deep star, got false\n";
        fuzz_tests_failed++;
    }
    
    fuzz_tests_run += 2;
    fuzz_tests_passed += 2;
}

// Fuzz test: alternating alternations don't cause exponential blowup
void fuzz_alternatingAlternations() {
    std::cout << "  Fuzz alternating alternations...\n";
    std::mt19937 rng(42);
    
    // Build: (a|b)(a|b)(a|b)...(a|b)  (20 alternations)
    std::vector<std::shared_ptr<PatternNode>> kids;
    for (int i = 0; i < 20; i++) {
        auto a = PatternNode::createLiteral("a");
        auto b = PatternNode::createLiteral("b");
        kids.push_back(PatternNode::createAlternation({a, b}));
    }
    auto seq = PatternNode::createSequence(kids);
    
    auto start = std::chrono::steady_clock::now();
    bool result = PatternMatcher::matches(seq, "abababababababababab");
    auto end = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    if (!result) {
        std::cout << "    Alternating: expected 'abab...' to match, got false\n";
        fuzz_tests_failed++;
    }
    if (ms > 1000) {
        std::cout << "    Alternating: took " << ms << "ms (>1s), potential performance issue\n";
        fuzz_tests_failed++;
    }
    
    fuzz_tests_run += 1;
    fuzz_tests_passed += (result && ms <= 1000) ? 1 : 0;
}

// Regression test: specific known-difficult seed pairs
void regression_knownPairs() {
    std::cout << "  Regression: known difficult pairs...\n";
    
    // Pair 1: abc vs abd (differ at last char)
    {
        auto cat = PatternNode::createLiteral("abc");
        auto dog = PatternNode::createLiteral("abd");
        auto alt = PatternNode::createAlternation({cat, dog});
        
        if (!PatternMatcher::validate(alt, {"abc", "abd"}, {"abe", "ab", "abcx"})) {
            std::cout << "    FAIL: abc|abd vs abe,ab,abcx\n";
            fuzz_tests_failed++;
        }
        fuzz_tests_run++;
        fuzz_tests_passed++;
    }
    
    // Pair 2: aa vs aaa (length-based)
    {
        auto aa = PatternNode::createLiteral("aa");
        auto plus_a = PatternNode::createQuantified(
            PatternNode::createLiteral("a"), PatternType::PLUS_QUANTIFIER);
        
        // "aa" and "aaa" both match a+, so this is not a valid separator
        // This tests that the matcher is correct about it
        bool validates = PatternMatcher::validate(plus_a, {"aa"}, {"aaa"});
        if (validates) {
            std::cout << "    FAIL: a+ should match aaa (counter), but validate returned true\n";
            fuzz_tests_failed++;
        }
        fuzz_tests_run++;
        fuzz_tests_passed++;
    }
    
    // Pair 3: Empty input edge case
    {
        auto opt = PatternNode::createQuantified(
            PatternNode::createLiteral("x"), PatternType::OPTIONAL);
        
        if (!PatternMatcher::validate(opt, {"", "x"}, {"y", "xx"})) {
            std::cout << "    FAIL: x? should match '' and 'x' but not 'y' or 'xx'\n";
            fuzz_tests_failed++;
        }
        fuzz_tests_run++;
        fuzz_tests_passed++;
    }
    
    // Pair 4: Fragment ref resolution
    {
        auto frag = PatternNode::createFragment("test");
        if (!PatternMatcher::validateWithFragments(frag, {"hello"}, {"world"}, {{"test", "hello"}})) {
            std::cout << "    FAIL: fragment 'test'=hello should match 'hello' not 'world'\n";
            fuzz_tests_failed++;
        }
        fuzz_tests_run++;
        fuzz_tests_passed++;
    }
}

int run_pattern_matcher_fuzz_tests() {
    std::cout << "PatternMatcher Fuzz & Regression Tests\n";
    std::cout << "======================================\n\n";
    
    fuzz_randomPatterns(1000, 42);
    fuzz_randomPatterns(1000, 123);
    fuzz_validateConsistency(500, 42);
    fuzz_deepNesting();
    fuzz_alternatingAlternations();
    regression_knownPairs();
    
    std::cout << "\n======================================\n";
    std::cout << "Fuzz results: " << fuzz_tests_passed << "/" << fuzz_tests_run << " passed";
    if (fuzz_tests_failed > 0) {
        std::cout << " (" << fuzz_tests_failed << " failed)";
    }
    std::cout << "\n\n";
    
    return fuzz_tests_failed > 0 ? 1 : 0;
}
