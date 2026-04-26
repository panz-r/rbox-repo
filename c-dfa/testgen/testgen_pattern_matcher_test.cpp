// ============================================================================
// PatternMatcher Unit Tests
// ============================================================================

#include "pattern_matcher.h"
#include "testgen.h"
#include <iostream>
#include <cassert>
#include <sstream>

static int pm_tests_run = 0;
static int pm_tests_passed = 0;

#define PM_TEST(name) void pm_test_##name()
#define RUN_PM_TEST(name) do { \
    std::cout << "  " << #name << " ... "; \
    pm_tests_run++; \
    try { \
        pm_test_##name(); \
        std::cout << "PASS\n"; \
        pm_tests_passed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAIL: " << e.what() << "\n"; \
    } \
} while(0)

#define PM_ASSERT_TRUE(x) do { \
    if (!(x)) { \
        throw std::runtime_error("Assertion failed: " #x " is false"); \
    } \
} while(0)

#define PM_ASSERT_FALSE(x) do { \
    if (x) { \
        throw std::runtime_error("Assertion failed: " #x " is true"); \
    } \
} while(0)

#define PM_ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        std::ostringstream oss; \
        oss << "Assertion failed: " << (a) << " != " << (b); \
        throw std::runtime_error(oss.str()); \
    } \
} while(0)

using namespace std;

// ============================================================================
// Literal matching
// ============================================================================

PM_TEST(literal_exactMatch) {
    auto node = PatternNode::createLiteral("abc");
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "abc"));
}

PM_TEST(literal_noMatch) {
    auto node = PatternNode::createLiteral("abc");
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "abd"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "ab"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "abcd"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, ""));
}

PM_TEST(literal_emptyLiteral) {
    auto node = PatternNode::createLiteral("");
    PM_ASSERT_TRUE(PatternMatcher::matches(node, ""));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "a"));
}

PM_TEST(literal_singleChar) {
    auto node = PatternNode::createLiteral("x");
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "x"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "y"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "xy"));
}

// ============================================================================
// Alternation matching
// ============================================================================

PM_TEST(alternation_basic) {
    auto a = PatternNode::createLiteral("cat");
    auto b = PatternNode::createLiteral("dog");
    auto node = PatternNode::createAlternation({a, b});
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "cat"));
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "dog"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "bird"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, ""));
}

PM_TEST(alternation_threeOptions) {
    auto a = PatternNode::createLiteral("a");
    auto b = PatternNode::createLiteral("b");
    auto c = PatternNode::createLiteral("c");
    auto node = PatternNode::createAlternation({a, b, c});
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "a"));
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "b"));
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "c"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "d"));
}

PM_TEST(alternation_emptyFails) {
    auto node = PatternNode::createAlternation({});
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "a"));
}

// ============================================================================
// Sequence matching
// ============================================================================

PM_TEST(sequence_twoLiterals) {
    auto a = PatternNode::createLiteral("ab");
    auto b = PatternNode::createLiteral("cd");
    auto node = PatternNode::createSequence({a, b});
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "abcd"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "ab"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "cd"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "abcde"));
}

PM_TEST(sequence_threeLiterals) {
    auto a = PatternNode::createLiteral("x");
    auto b = PatternNode::createLiteral("y");
    auto c = PatternNode::createLiteral("z");
    auto node = PatternNode::createSequence({a, b, c});
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "xyz"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "xy"));
}

PM_TEST(sequence_emptySequence) {
    auto node = PatternNode::createSequence({});
    PM_ASSERT_TRUE(PatternMatcher::matches(node, ""));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "a"));
}

// ============================================================================
// Optional matching X?
// ============================================================================

PM_TEST(optional_matchesPresent) {
    auto child = PatternNode::createLiteral("ab");
    auto node = PatternNode::createQuantified(child, PatternType::OPTIONAL);
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "ab"));
}

PM_TEST(optional_matchesEmpty) {
    auto child = PatternNode::createLiteral("ab");
    auto node = PatternNode::createQuantified(child, PatternType::OPTIONAL);
    PM_ASSERT_TRUE(PatternMatcher::matches(node, ""));
}

PM_TEST(optional_noMatchPartial) {
    auto child = PatternNode::createLiteral("ab");
    auto node = PatternNode::createQuantified(child, PatternType::OPTIONAL);
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "a"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "abc"));
}

// ============================================================================
// Plus quantifier X+
// ============================================================================

PM_TEST(plus_matchesOne) {
    auto child = PatternNode::createLiteral("ab");
    auto node = PatternNode::createQuantified(child, PatternType::PLUS_QUANTIFIER);
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "ab"));
}

PM_TEST(plus_matchesMultiple) {
    auto child = PatternNode::createLiteral("ab");
    auto node = PatternNode::createQuantified(child, PatternType::PLUS_QUANTIFIER);
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "abab"));
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "ababab"));
}

PM_TEST(plus_noMatchEmpty) {
    auto child = PatternNode::createLiteral("ab");
    auto node = PatternNode::createQuantified(child, PatternType::PLUS_QUANTIFIER);
    PM_ASSERT_FALSE(PatternMatcher::matches(node, ""));
}

PM_TEST(plus_noMatchPartial) {
    auto child = PatternNode::createLiteral("ab");
    auto node = PatternNode::createQuantified(child, PatternType::PLUS_QUANTIFIER);
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "a"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "aba"));
}

PM_TEST(plus_alternationChild) {
    auto a = PatternNode::createLiteral("a");
    auto b = PatternNode::createLiteral("b");
    auto alt = PatternNode::createAlternation({a, b});
    auto node = PatternNode::createQuantified(alt, PatternType::PLUS_QUANTIFIER);
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "a"));
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "b"));
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "ab"));
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "ba"));
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "aba"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, ""));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "c"));
}

// ============================================================================
// Star quantifier X*
// ============================================================================

PM_TEST(star_matchesEmpty) {
    auto child = PatternNode::createLiteral("ab");
    auto node = PatternNode::createQuantified(child, PatternType::STAR_QUANTIFIER);
    PM_ASSERT_TRUE(PatternMatcher::matches(node, ""));
}

PM_TEST(star_matchesOne) {
    auto child = PatternNode::createLiteral("ab");
    auto node = PatternNode::createQuantified(child, PatternType::STAR_QUANTIFIER);
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "ab"));
}

PM_TEST(star_matchesMultiple) {
    auto child = PatternNode::createLiteral("ab");
    auto node = PatternNode::createQuantified(child, PatternType::STAR_QUANTIFIER);
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "ababab"));
}

PM_TEST(star_noMatchPartial) {
    auto child = PatternNode::createLiteral("ab");
    auto node = PatternNode::createQuantified(child, PatternType::STAR_QUANTIFIER);
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "a"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "aba"));
}

// ============================================================================
// Nested patterns
// ============================================================================

PM_TEST(sequenceWithQuantifier) {
    // Pattern: "prefix" ( "ab" )+ "suffix"
    auto prefix = PatternNode::createLiteral("prefix");
    auto ab = PatternNode::createLiteral("ab");
    auto plus_ab = PatternNode::createQuantified(ab, PatternType::PLUS_QUANTIFIER);
    auto suffix = PatternNode::createLiteral("suffix");
    auto node = PatternNode::createSequence({prefix, plus_ab, suffix});

    PM_ASSERT_TRUE(PatternMatcher::matches(node, "prefixabsuffix"));
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "prefixababsuffix"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "prefixsuffix"));  // + needs at least one
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "prefixasuffix"));
}

PM_TEST(nestedQuantifiers) {
    // Pattern: ( "a" )+ where each "a" can repeat -> should match "a", "aa", "aaa"
    auto a = PatternNode::createLiteral("a");
    auto plus_a = PatternNode::createQuantified(a, PatternType::PLUS_QUANTIFIER);
    PM_ASSERT_TRUE(PatternMatcher::matches(plus_a, "a"));
    PM_ASSERT_TRUE(PatternMatcher::matches(plus_a, "aaa"));
}

PM_TEST(alternationInSequence) {
    // Pattern: "x" ( "a" | "b" ) "y"
    auto x = PatternNode::createLiteral("x");
    auto a = PatternNode::createLiteral("a");
    auto b = PatternNode::createLiteral("b");
    auto alt = PatternNode::createAlternation({a, b});
    auto y = PatternNode::createLiteral("y");
    auto node = PatternNode::createSequence({x, alt, y});

    PM_ASSERT_TRUE(PatternMatcher::matches(node, "xay"));
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "xby"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "xcy"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "xy"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "xaby"));
}

PM_TEST(sequenceInAlternation) {
    // Pattern: ( "ab" | "cd" )
    auto ab = PatternNode::createSequence({PatternNode::createLiteral("a"), PatternNode::createLiteral("b")});
    auto cd = PatternNode::createSequence({PatternNode::createLiteral("c"), PatternNode::createLiteral("d")});
    auto node = PatternNode::createAlternation({ab, cd});

    PM_ASSERT_TRUE(PatternMatcher::matches(node, "ab"));
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "cd"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "ac"));
}

// ============================================================================
// Fragment references
// ============================================================================

PM_TEST(fragmentRef_basic) {
    // Fragment "f" defined as "hello"
    auto frag_ref = PatternNode::createFragment("f");
    std::map<std::string, std::string> fragments = {{"f", "hello"}};

    PM_ASSERT_TRUE(PatternMatcher::validateWithFragments(frag_ref, {"hello"}, {"world"}, fragments));
}

PM_TEST(fragmentRef_inSequence) {
    // Pattern: "pre" [[f]]+ "post"  where f = "ab"
    auto pre = PatternNode::createLiteral("pre");
    auto frag_ref = PatternNode::createFragment("f");
    auto plus_frag = PatternNode::createQuantified(frag_ref, PatternType::PLUS_QUANTIFIER);
    auto post = PatternNode::createLiteral("post");
    auto node = PatternNode::createSequence({pre, plus_frag, post});
    std::map<std::string, std::string> fragments = {{"f", "ab"}};

    PM_ASSERT_TRUE(PatternMatcher::validateWithFragments(
        node, {"preabpost", "preababpost"}, {"prepost", "preapost"}, fragments));
}

PM_TEST(fragmentRef_unknownFails) {
    auto frag_ref = PatternNode::createFragment("missing");
    PM_ASSERT_FALSE(PatternMatcher::matches(frag_ref, "anything"));
}

// ============================================================================
// validate() and explainFailure()
// ============================================================================

PM_TEST(validate_correctPattern) {
    // Pattern: "cat" | "dog"
    auto cat = PatternNode::createLiteral("cat");
    auto dog = PatternNode::createLiteral("dog");
    auto node = PatternNode::createAlternation({cat, dog});

    PM_ASSERT_TRUE(PatternMatcher::validate(node, {"cat", "dog"}, {"bird", "fish"}));
}

PM_TEST(validate_matchingInputFails) {
    auto node = PatternNode::createLiteral("abc");
    // "abc" should match but "xyz" won't match "abc"
    PM_ASSERT_FALSE(PatternMatcher::validate(node, {"xyz"}, {}));
}

PM_TEST(validate_counterMatches) {
    auto cat = PatternNode::createLiteral("cat");
    auto dog = PatternNode::createLiteral("dog");
    auto node = PatternNode::createAlternation({cat, dog});
    // "cat" is a counter but matches the pattern -> validation fails
    PM_ASSERT_FALSE(PatternMatcher::validate(node, {"cat"}, {"cat"}));
}

PM_TEST(explainFailure_matchingFail) {
    auto node = PatternNode::createLiteral("abc");
    auto reason = PatternMatcher::explainFailure(node, {"xyz"}, {});
    PM_ASSERT_TRUE(!reason.empty());
    PM_ASSERT_TRUE(reason.find("xyz") != string::npos);
}

PM_TEST(explainFailure_counterFail) {
    auto node = PatternNode::createLiteral("abc");
    auto reason = PatternMatcher::explainFailure(node, {"abc"}, {"abc"});
    PM_ASSERT_TRUE(!reason.empty());
    PM_ASSERT_TRUE(reason.find("abc") != string::npos);
}

PM_TEST(explainFailure_success) {
    auto node = PatternNode::createLiteral("abc");
    auto reason = PatternMatcher::explainFailure(node, {"abc"}, {"xyz"});
    PM_ASSERT_TRUE(reason.empty());
}

PM_TEST(validate_nullPattern) {
    PM_ASSERT_FALSE(PatternMatcher::validate(nullptr, {"a"}, {}));
}

// ============================================================================
// Edge cases
// ============================================================================

PM_TEST(nullNode) {
    PM_ASSERT_FALSE(PatternMatcher::matches(nullptr, "abc"));
}

PM_TEST(emptyInput) {
    auto node = PatternNode::createLiteral("abc");
    PM_ASSERT_FALSE(PatternMatcher::matches(node, ""));
}

PM_TEST(complexNestedPattern) {
    // Pattern: ( ( "a" | "b" )+ "c" )*
    auto a = PatternNode::createLiteral("a");
    auto b = PatternNode::createLiteral("b");
    auto alt = PatternNode::createAlternation({a, b});
    auto plus_alt = PatternNode::createQuantified(alt, PatternType::PLUS_QUANTIFIER);
    auto c = PatternNode::createLiteral("c");
    auto inner = PatternNode::createSequence({plus_alt, c});
    auto star = PatternNode::createQuantified(inner, PatternType::STAR_QUANTIFIER);

    PM_ASSERT_TRUE(PatternMatcher::matches(star, ""));        // empty
    PM_ASSERT_TRUE(PatternMatcher::matches(star, "ac"));      // one group
    PM_ASSERT_TRUE(PatternMatcher::matches(star, "bc"));      // one group
    PM_ASSERT_TRUE(PatternMatcher::matches(star, "abc"));     // one group
    PM_ASSERT_TRUE(PatternMatcher::matches(star, "acbc"));    // two groups
    PM_ASSERT_TRUE(PatternMatcher::matches(star, "acbcac"));  // three groups
    PM_ASSERT_FALSE(PatternMatcher::matches(star, "a"));      // no trailing c
    PM_ASSERT_FALSE(PatternMatcher::matches(star, "ab"));     // no trailing c
    PM_ASSERT_FALSE(PatternMatcher::matches(star, "dc"));     // d not in alternation
}

PM_TEST(optionalInSequence) {
    // "pre" ( "mid" )? "post"
    auto pre = PatternNode::createLiteral("pre");
    auto mid = PatternNode::createLiteral("mid");
    auto opt = PatternNode::createQuantified(mid, PatternType::OPTIONAL);
    auto post = PatternNode::createLiteral("post");
    auto node = PatternNode::createSequence({pre, opt, post});

    PM_ASSERT_TRUE(PatternMatcher::matches(node, "premidpost"));
    PM_ASSERT_TRUE(PatternMatcher::matches(node, "prepost"));
    PM_ASSERT_FALSE(PatternMatcher::matches(node, "premipost"));
}

// ============================================================================
// Main
// ============================================================================

// Forward declaration for brute-force cross-validation test (defined after this function)
void pm_test_bruteForce_crossValidate();

int run_pattern_matcher_tests() {
    std::cout << "PatternMatcher Unit Tests\n";
    std::cout << "=========================\n\n";

    std::cout << "Literal matching:\n";
    RUN_PM_TEST(literal_exactMatch);
    RUN_PM_TEST(literal_noMatch);
    RUN_PM_TEST(literal_emptyLiteral);
    RUN_PM_TEST(literal_singleChar);

    std::cout << "\nAlternation matching:\n";
    RUN_PM_TEST(alternation_basic);
    RUN_PM_TEST(alternation_threeOptions);
    RUN_PM_TEST(alternation_emptyFails);

    std::cout << "\nSequence matching:\n";
    RUN_PM_TEST(sequence_twoLiterals);
    RUN_PM_TEST(sequence_threeLiterals);
    RUN_PM_TEST(sequence_emptySequence);

    std::cout << "\nOptional matching:\n";
    RUN_PM_TEST(optional_matchesPresent);
    RUN_PM_TEST(optional_matchesEmpty);
    RUN_PM_TEST(optional_noMatchPartial);

    std::cout << "\nPlus quantifier:\n";
    RUN_PM_TEST(plus_matchesOne);
    RUN_PM_TEST(plus_matchesMultiple);
    RUN_PM_TEST(plus_noMatchEmpty);
    RUN_PM_TEST(plus_noMatchPartial);
    RUN_PM_TEST(plus_alternationChild);

    std::cout << "\nStar quantifier:\n";
    RUN_PM_TEST(star_matchesEmpty);
    RUN_PM_TEST(star_matchesOne);
    RUN_PM_TEST(star_matchesMultiple);
    RUN_PM_TEST(star_noMatchPartial);

    std::cout << "\nNested patterns:\n";
    RUN_PM_TEST(sequenceWithQuantifier);
    RUN_PM_TEST(nestedQuantifiers);
    RUN_PM_TEST(alternationInSequence);
    RUN_PM_TEST(sequenceInAlternation);

    std::cout << "\nFragment references:\n";
    RUN_PM_TEST(fragmentRef_basic);
    RUN_PM_TEST(fragmentRef_inSequence);
    RUN_PM_TEST(fragmentRef_unknownFails);

    std::cout << "\nValidate and explain:\n";
    RUN_PM_TEST(validate_correctPattern);
    RUN_PM_TEST(validate_matchingInputFails);
    RUN_PM_TEST(validate_counterMatches);
    RUN_PM_TEST(explainFailure_matchingFail);
    RUN_PM_TEST(explainFailure_counterFail);
    RUN_PM_TEST(explainFailure_success);
    RUN_PM_TEST(validate_nullPattern);

    std::cout << "\nEdge cases:\n";
    RUN_PM_TEST(nullNode);
    RUN_PM_TEST(emptyInput);
    RUN_PM_TEST(complexNestedPattern);
    RUN_PM_TEST(optionalInSequence);

    std::cout << "\nBrute-force cross-validation:\n";
    RUN_PM_TEST(bruteForce_crossValidate);

    std::cout << "\n=========================\n";
    std::cout << "Results: " << pm_tests_passed << "/" << pm_tests_run << " tests passed\n\n";

    return (pm_tests_passed == pm_tests_run) ? 0 : 1;
}

// Brute-force match: try to match input[pos:] against node.
// Returns true if there exists a full match (pos == input.size() at end).
static bool bruteForceMatch(const std::shared_ptr<PatternNode>& node,
                            const std::string& input, size_t pos, int depth_limit) {
    if (depth_limit <= 0 || !node) return false;
    
    switch (node->type) {
        case PatternType::LITERAL:
            if (input.substr(pos, node->value.size()) == node->value &&
                pos + node->value.size() <= input.size()) {
                return pos + node->value.size() == input.size();
            }
            return false;
            
        case PatternType::ALTERNATION:
            for (const auto& child : node->children) {
                if (bruteForceMatch(child, input, pos, depth_limit - 1)) return true;
            }
            return false;
            
        case PatternType::SEQUENCE:
            if (node->children.empty()) return pos == input.size();
            // Match children sequentially
            {
                std::function<bool(size_t, size_t)> matchSeq;
                matchSeq = [&](size_t child_idx, size_t p) -> bool {
                    if (child_idx >= node->children.size()) return p == input.size();
                    // Try to match child at position p, then recurse
                    const auto& child = node->children[child_idx];
                    // For literal children, we can do exact matching
                    if (child->type == PatternType::LITERAL) {
                        if (input.substr(p, child->value.size()) == child->value &&
                            p + child->value.size() <= input.size()) {
                            return matchSeq(child_idx + 1, p + child->value.size());
                        }
                        return false;
                    }
                    // For non-literal, we need to try all possible consumption lengths
                    // Since we only have small strings, try all positions
                    for (size_t end = p; end <= input.size(); end++) {
                        // Check if child matches input[p:end]
                        std::string sub = input.substr(p, end - p);
                        // Build a temporary match: child should consume exactly (end-p) chars
                        if (bruteForceMatch(child, sub, 0, depth_limit - 1)) {
                            if (matchSeq(child_idx + 1, end)) return true;
                        }
                    }
                    return false;
                };
                return matchSeq(0, pos);
            }
            
        case PatternType::PLUS_QUANTIFIER:
            if (!node->quantified) return false;
            // One or more: must match at least once
            for (size_t end = pos + 1; end <= input.size(); end++) {
                std::string sub = input.substr(pos, end - pos);
                if (bruteForceMatch(node->quantified, sub, 0, depth_limit - 1)) {
                    // Check if remaining also matches the plus (recursively) or is empty
                    if (end == input.size()) return true;
                    // Try matching more repetitions
                    std::string remaining = input.substr(end);
                    // Build a new match for the remaining as same PLUS pattern
                    auto plus_copy = PatternNode::createQuantified(node->quantified, PatternType::PLUS_QUANTIFIER);
                    if (bruteForceMatch(plus_copy, remaining, 0, depth_limit - 1)) return true;
                    // Also try just one more match then done
                    if (bruteForceMatch(node->quantified, remaining, 0, depth_limit - 1)) return true;
                }
            }
            return false;
            
        case PatternType::STAR_QUANTIFIER:
            if (pos == input.size()) return true;  // empty match
            if (!node->quantified) return pos == input.size();
            // Try one or more matches
            {
                auto plus_node = PatternNode::createQuantified(node->quantified, PatternType::PLUS_QUANTIFIER);
                return bruteForceMatch(plus_node, input, pos, depth_limit - 1);
            }
            
        case PatternType::OPTIONAL:
            if (pos == input.size()) return true;  // skip
            if (!node->quantified) return true;
            return bruteForceMatch(node->quantified, input, pos, depth_limit - 1);
            
        case PatternType::FRAGMENT_REF:
            // Can't resolve fragments in brute-force; skip these test cases
            return false;
            
        default:
            return false;
    }
}

// Generate a simple random pattern AST
static std::shared_ptr<PatternNode> generateSimplePattern(std::mt19937& rng, int depth) {
    static const char chars[] = "abc";
    std::uniform_int_distribution<int> char_dist(0, 2);
    std::uniform_int_distribution<int> type_dist(0, 4);
    
    if (depth <= 0) {
        // Must be a literal
        int len = 1 + std::uniform_int_distribution<int>(0, 1)(rng);
        std::string val;
        for (int i = 0; i < len; i++) val += chars[char_dist(rng)];
        return PatternNode::createLiteral(val);
    }
    
    int t = type_dist(rng);
    if (t == 0) {
        // Literal
        int len = 1 + std::uniform_int_distribution<int>(0, 2)(rng);
        std::string val;
        for (int i = 0; i < len; i++) val += chars[char_dist(rng)];
        return PatternNode::createLiteral(val);
    } else if (t == 1) {
        // Alternation of 2-3 literals
        int n = 2 + std::uniform_int_distribution<int>(0, 1)(rng);
        std::vector<std::shared_ptr<PatternNode>> alts;
        for (int i = 0; i < n; i++) {
            std::string val;
            val += chars[char_dist(rng)];
            alts.push_back(PatternNode::createLiteral(val));
        }
        return PatternNode::createAlternation(alts);
    } else if (t == 2) {
        // Sequence of 2 literals
        auto a = generateSimplePattern(rng, 0);
        auto b = generateSimplePattern(rng, 0);
        return PatternNode::createSequence({a, b});
    } else if (t == 3) {
        // Optional
        auto inner = generateSimplePattern(rng, depth - 1);
        return PatternNode::createQuantified(inner, PatternType::OPTIONAL);
    } else {
        // Plus
        auto inner = generateSimplePattern(rng, 0);
        return PatternNode::createQuantified(inner, PatternType::PLUS_QUANTIFIER);
    }
}

// Generate random test strings
static std::vector<std::string> generateTestStrings(std::mt19937& rng, int count) {
    static const char chars[] = "abc";
    std::uniform_int_distribution<int> char_dist(0, 2);
    std::uniform_int_distribution<int> len_dist(0, 4);
    
    std::vector<std::string> result;
    for (int i = 0; i < count; i++) {
        int len = len_dist(rng);
        std::string s;
        for (int j = 0; j < len; j++) s += chars[char_dist(rng)];
        result.push_back(s);
    }
    return result;
}

PM_TEST(bruteForce_crossValidate) {
    // Compare PatternMatcher::matches against brute-force on 3000 random pattern×string pairs.
    // Limited to small alphabet (abc) and short strings (≤4 chars) for tractability.
    std::mt19937 rng(12345);
    const int iterations = 500;
    const int strings_per_pattern = 6;
    int mismatches = 0;
    
    for (int i = 0; i < iterations; i++) {
        auto pattern = generateSimplePattern(rng, 2);
        auto strings = generateTestStrings(rng, strings_per_pattern);
        
        for (const auto& s : strings) {
            bool pm_result = PatternMatcher::matches(pattern, s);
            bool bf_result = bruteForceMatch(pattern, s, 0, 10);
            
            if (pm_result != bf_result) {
                mismatches++;
                // Only report first few to avoid spam
                if (mismatches <= 3) {
                    std::cerr << "  MISMATCH: input='" << s << "' PM=" << pm_result
                              << " BF=" << bf_result << "\n";
                }
            }
        }
    }
    
    PM_ASSERT_TRUE(mismatches == 0);
}
