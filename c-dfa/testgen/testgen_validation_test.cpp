// ============================================================================
// ValidationHelpers Unit Tests
// ============================================================================

#include "testgen.h"
#include "pattern_strategies.h"
#include <iostream>
#include <cassert>
#include <sstream>
#include <random>

int vh_tests_run = 0;
int vh_tests_passed = 0;

#define VH_TEST(name) void vh_test_##name()
#define RUN_VH_TEST(name) do { \
    std::cout << "  " << #name << " ... "; \
    vh_tests_run++; \
    try { \
        vh_test_##name(); \
        std::cout << "PASS\n"; \
        vh_tests_passed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAIL: " << e.what() << "\n"; \
    } \
} while(0)

#define VH_ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        std::ostringstream oss; \
        oss << "Assertion failed: " << (a) << " != " << (b); \
        throw std::runtime_error(oss.str()); \
    } \
} while(0)

#define VH_ASSERT_TRUE(x) do { \
    if (!(x)) { \
        throw std::runtime_error("Assertion failed: " #x " is false"); \
    } \
} while(0)

#define VH_ASSERT_FALSE(x) do { \
    if (x) { \
        throw std::runtime_error("Assertion failed: " #x " is true"); \
    } \
} while(0)

// ============================================================================
// Tests for patternMatchesLiteral
// ============================================================================

VH_TEST(patternMatchesLiteral_exactMatch) {
    VH_ASSERT_TRUE(patternMatchesLiteral("hello", "hello"));
    VH_ASSERT_TRUE(patternMatchesLiteral("", ""));
    VH_ASSERT_TRUE(patternMatchesLiteral("a", "a"));
}

VH_TEST(patternMatchesLiteral_noMatch) {
    VH_ASSERT_FALSE(patternMatchesLiteral("hello", "world"));
    VH_ASSERT_FALSE(patternMatchesLiteral("hello", "Hello"));
    VH_ASSERT_FALSE(patternMatchesLiteral("hello", "hell"));
}

VH_TEST(patternMatchesLiteral_emptyString) {
    VH_ASSERT_FALSE(patternMatchesLiteral("", "nonempty"));
}

// ============================================================================
// Tests for patternMatchesOptional
// ============================================================================

VH_TEST(patternMatchesOptional_emptyContentMatchesEmpty) {
    VH_ASSERT_TRUE(patternMatchesOptional("abc", ""));
}

VH_TEST(patternMatchesOptional_contentMatches) {
    VH_ASSERT_TRUE(patternMatchesOptional("abc", "abc"));
}

VH_TEST(patternMatchesOptional_noMatch) {
    VH_ASSERT_FALSE(patternMatchesOptional("abc", "abcd"));
    VH_ASSERT_FALSE(patternMatchesOptional("abc", "ab"));
}

VH_TEST(patternMatchesOptional_partialMatch) {
    VH_ASSERT_FALSE(patternMatchesOptional("hello", "hell"));
}

// ============================================================================
// Tests for patternMatchesPlus
// ============================================================================

VH_TEST(patternMatchesPlus_exactRepeats) {
    VH_ASSERT_TRUE(patternMatchesPlus("ab", "ababab"));
    VH_ASSERT_TRUE(patternMatchesPlus("a", "aaa"));
    VH_ASSERT_TRUE(patternMatchesPlus("abc", "abcabcabc"));
    VH_ASSERT_TRUE(patternMatchesPlus("x", "xxxx"));
}

VH_TEST(patternMatchesPlus_noMatch) {
    VH_ASSERT_FALSE(patternMatchesPlus("ab", "ababa"));  // odd length
    VH_ASSERT_FALSE(patternMatchesPlus("ab", "ababc"));  // wrong char
    VH_ASSERT_FALSE(patternMatchesPlus("ab", ""));        // empty
}

VH_TEST(patternMatchesPlus_emptyContent) {
    VH_ASSERT_FALSE(patternMatchesPlus("", "anything"));
    VH_ASSERT_FALSE(patternMatchesPlus("", ""));
}

// ============================================================================
// Tests for patternMatchesStar
// ============================================================================

VH_TEST(patternMatchesStar_emptyString) {
    VH_ASSERT_TRUE(patternMatchesStar("ab", ""));
    VH_ASSERT_TRUE(patternMatchesStar("anything", ""));
}

VH_TEST(patternMatchesStar_validRepeats) {
    VH_ASSERT_TRUE(patternMatchesStar("ab", "ababab"));
    VH_ASSERT_TRUE(patternMatchesStar("a", "aaa"));
    VH_ASSERT_TRUE(patternMatchesStar("ab", "ab"));
}

VH_TEST(patternMatchesStar_invalidRepeats) {
    VH_ASSERT_FALSE(patternMatchesStar("ab", "ababa"));  // odd length
    VH_ASSERT_FALSE(patternMatchesStar("ab", "ababc"));  // wrong char
}

VH_TEST(patternMatchesStar_emptyContentMatchesEmpty) {
    VH_ASSERT_TRUE(patternMatchesStar("", ""));
    VH_ASSERT_FALSE(patternMatchesStar("", "abc"));  // empty content shouldn't match non-empty
}

// ============================================================================
// Tests for patternMatchesCharClass
// ============================================================================

VH_TEST(patternMatchesCharClass_singleChar) {
    VH_ASSERT_TRUE(patternMatchesCharClass("a|b|c", "a"));
    VH_ASSERT_TRUE(patternMatchesCharClass("a|b|c", "b"));
    VH_ASSERT_TRUE(patternMatchesCharClass("a|b|c", "c"));
}

VH_TEST(patternMatchesCharClass_multipleChars) {
    VH_ASSERT_TRUE(patternMatchesCharClass("a|b|c", "abc"));
    VH_ASSERT_TRUE(patternMatchesCharClass("a|b|c", "cab"));
    VH_ASSERT_TRUE(patternMatchesCharClass("a|b|c", "abcabc"));
    VH_ASSERT_TRUE(patternMatchesCharClass("a|b|c", "aaa"));
}

VH_TEST(patternMatchesCharClass_noMatch) {
    VH_ASSERT_FALSE(patternMatchesCharClass("a|b|c", "d"));
    VH_ASSERT_FALSE(patternMatchesCharClass("a|b|c", "abx"));
    VH_ASSERT_FALSE(patternMatchesCharClass("x|y|z", "w"));
}

VH_TEST(patternMatchesCharClass_emptyString) {
    VH_ASSERT_FALSE(patternMatchesCharClass("a|b|c", ""));
}

VH_TEST(patternMatchesCharClass_singleCharClass) {
    VH_ASSERT_TRUE(patternMatchesCharClass("x", "xxx"));
    VH_ASSERT_TRUE(patternMatchesCharClass("x", "x"));
    VH_ASSERT_FALSE(patternMatchesCharClass("x", "y"));
}

// ============================================================================
// Tests for createQuantifiedAlternation
// ============================================================================

VH_TEST(createQuantifiedAlternation_basic) {
    std::vector<std::string> alts = {"a", "b", "c"};
    std::vector<std::string> seeds = {"seed1", "seed2", "seed3"};
    auto node = createQuantifiedAlternation(alts, PatternType::PLUS_QUANTIFIER, seeds);
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->type == PatternType::PLUS_QUANTIFIER);
    VH_ASSERT_TRUE(node->children.size() == 3);
}

VH_TEST(createQuantifiedAlternation_singleAlt) {
    std::vector<std::string> alts = {"only"};
    std::vector<std::string> seeds = {"seed"};
    auto node = createQuantifiedAlternation(alts, PatternType::PLUS_QUANTIFIER, seeds);
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->children.size() == 1);
}

VH_TEST(createQuantifiedAlternation_emptyAlts) {
    std::vector<std::string> alts;
    std::vector<std::string> seeds;
    auto node = createQuantifiedAlternation(alts, PatternType::PLUS_QUANTIFIER, seeds);
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->children.empty());
}

// ============================================================================
// Tests for createQuantifiedLiteral
// ============================================================================

VH_TEST(createQuantifiedLiteral_plus) {
    auto node = createQuantifiedLiteral("test", PatternType::PLUS_QUANTIFIER, {"seed"});
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->type == PatternType::PLUS_QUANTIFIER);
    VH_ASSERT_TRUE(node->value == "test");
    VH_ASSERT_TRUE(node->quantified != nullptr);
}

VH_TEST(createQuantifiedLiteral_star) {
    auto node = createQuantifiedLiteral("test", PatternType::STAR_QUANTIFIER, {"seed"});
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->type == PatternType::STAR_QUANTIFIER);
}

VH_TEST(createQuantifiedLiteral_optional) {
    auto node = createQuantifiedLiteral("test", PatternType::OPTIONAL, {"seed"});
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->type == PatternType::OPTIONAL);
}

// ============================================================================
// Tests for createQuantifiedFragment
// ============================================================================

VH_TEST(createQuantifiedFragment_plus) {
    auto node = createQuantifiedFragment("frag1", PatternType::PLUS_QUANTIFIER, {"seed"});
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->type == PatternType::PLUS_QUANTIFIER);
    VH_ASSERT_TRUE(node->fragment_name == "frag1");
}

VH_TEST(createQuantifiedFragment_star) {
    auto node = createQuantifiedFragment("frag2", PatternType::STAR_QUANTIFIER, {"seed"});
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->type == PatternType::STAR_QUANTIFIER);
}

// ============================================================================
// Tests for createAlternationPlus/Star/Optional
// ============================================================================

VH_TEST(createAlternationPlus_basic) {
    std::vector<std::string> alts = {"x", "y"};
    auto node = createAlternationPlus(alts, {"s1", "s2"});
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->type == PatternType::PLUS_QUANTIFIER);
}

VH_TEST(createAlternationStar_basic) {
    std::vector<std::string> alts = {"x", "y"};
    auto node = createAlternationStar(alts, {"s1", "s2"});
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->type == PatternType::STAR_QUANTIFIER);
}

VH_TEST(createAlternationOptional_basic) {
    std::vector<std::string> alts = {"x", "y"};
    auto node = createAlternationOptional(alts, {"s1", "s2"});
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->type == PatternType::OPTIONAL);
}

// ============================================================================
// Tests for createLiteralPlus/Star/Optional
// ============================================================================

VH_TEST(createLiteralPlus_basic) {
    auto node = createLiteralPlus("abc", {"seed"});
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->type == PatternType::PLUS_QUANTIFIER);
    VH_ASSERT_TRUE(node->value == "abc");
}

VH_TEST(createLiteralStar_basic) {
    auto node = createLiteralStar("abc", {"seed"});
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->type == PatternType::STAR_QUANTIFIER);
}

VH_TEST(createLiteralOptional_basic) {
    auto node = createLiteralOptional("abc", {"seed"});
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->type == PatternType::OPTIONAL);
}

// ============================================================================
// Tests for createFragmentPlus/Star
// ============================================================================

VH_TEST(createFragmentPlus_basic) {
    auto node = createFragmentPlus("frag", {"seed"});
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->type == PatternType::PLUS_QUANTIFIER);
    VH_ASSERT_TRUE(node->fragment_name == "frag");
}

VH_TEST(createFragmentStar_basic) {
    auto node = createFragmentStar("frag", {"seed"});
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->type == PatternType::STAR_QUANTIFIER);
    VH_ASSERT_TRUE(node->fragment_name == "frag");
}

// ============================================================================
// Tests for wrapWithCaptureTags
// ============================================================================

VH_TEST(wrapWithCaptureTags_basic) {
    auto inner = PatternNode::createLiteral("test", {"seed"}, {});
    auto wrapped = wrapWithCaptureTags(inner, "mytag");
    
    VH_ASSERT_TRUE(wrapped != nullptr);
    VH_ASSERT_EQ(wrapped->capture_tag, "mytag");
}

VH_TEST(wrapWithCaptureTags_null) {
    VH_ASSERT_TRUE(wrapWithCaptureTags(nullptr, "tag") == nullptr);
}

VH_TEST(wrapWithCaptureTags_preservesInner) {
    auto inner = PatternNode::createLiteral("test", {"seed"}, {});
    auto wrapped = wrapWithCaptureTags(inner, "mytag");
    
    VH_ASSERT_EQ(wrapped->value, "test");
    VH_ASSERT_TRUE(wrapped->type == PatternType::LITERAL);
}

// ============================================================================
// Tests for createCharClass
// ============================================================================

VH_TEST(createCharClass_basic) {
    auto node = createCharClass("abc", {"seed"});
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->type == PatternType::LITERAL);
    VH_ASSERT_EQ(node->value, "[abc]");
}

VH_TEST(createCharClass_withSeeds) {
    auto node = createCharClass("xyz", {"seed1", "seed2"});
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->matched_seeds.size() == 2);
}

// ============================================================================
// Tests for createCharClassPlus
// ============================================================================

VH_TEST(createCharClassPlus_basic) {
    auto node = createCharClassPlus("xyz", {"seed"});
    
    VH_ASSERT_TRUE(node != nullptr);
    VH_ASSERT_TRUE(node->type == PatternType::PLUS_QUANTIFIER);
    VH_ASSERT_TRUE(node->quantified != nullptr);
}

// ============================================================================
// Tests for createSequenceNode
// ============================================================================

VH_TEST(createSequenceNode_basic) {
    auto child1 = PatternNode::createLiteral("a", {"s1"}, {});
    auto child2 = PatternNode::createLiteral("b", {"s2"}, {});
    auto seq = createSequenceNode({child1, child2}, {"s1", "s2"});
    
    VH_ASSERT_TRUE(seq != nullptr);
    VH_ASSERT_TRUE(seq->type == PatternType::SEQUENCE);
    VH_ASSERT_TRUE(seq->children.size() == 2);
}

VH_TEST(createSequenceNode_singleChild) {
    auto child = PatternNode::createLiteral("a", {"s1"}, {});
    auto seq = createSequenceNode({child}, {"s1"});
    
    VH_ASSERT_TRUE(seq != nullptr);
    VH_ASSERT_TRUE(seq->children.size() == 1);
}

VH_TEST(createSequenceNode_empty) {
    auto seq = createSequenceNode({}, {});
    
    VH_ASSERT_TRUE(seq != nullptr);
    VH_ASSERT_TRUE(seq->children.empty());
}

// ============================================================================
// Tests for extractFragment
// ============================================================================

VH_TEST(extractFragment_deterministicOutput) {
    std::mt19937 rng(12345);  // fixed seed for deterministic output
    std::map<std::string, std::string> fragments;
    
    auto result = extractFragment("abc", fragments, rng, true);
    
    VH_ASSERT_TRUE(!result.empty());
    VH_ASSERT_TRUE(result.find("[[") != std::string::npos);
    VH_ASSERT_TRUE(result.find("]]+") != std::string::npos);
    VH_ASSERT_TRUE(!fragments.empty());
}

VH_TEST(extractFragment_withNamespace) {
    std::mt19937 rng(12345);
    std::map<std::string, std::string> fragments;
    
    // Use force_simple=true to avoid namespace
    auto result = extractFragment("xyz", fragments, rng, true);
    
    VH_ASSERT_TRUE(!result.empty());
    // When force_simple=true, should not contain ::
    VH_ASSERT_TRUE(result.find("::") == std::string::npos);
}

VH_TEST(extractFragment_emptyCharClass) {
    std::mt19937 rng(42);
    std::map<std::string, std::string> fragments;
    
    auto result = extractFragment("", fragments, rng, true);
    
    VH_ASSERT_TRUE(!result.empty());
    VH_ASSERT_TRUE(!fragments.empty());
}

VH_TEST(extractFragment_multipleCallsDifferent) {
    std::mt19937 rng(99999);
    std::map<std::string, std::string> fragments1, fragments2;
    
    auto result1 = extractFragment("abc", fragments1, rng, true);
    auto result2 = extractFragment("abc", fragments2, rng, true);
    
    // Results should be different (different fragment names)
    VH_ASSERT_TRUE(result1 != result2);
}

// ============================================================================
// Run all tests
// ============================================================================

int run_validation_helpers_tests() {
    std::cout << "ValidationHelpers Unit Tests\n";
    std::cout << "============================\n\n";
    
    std::cout << "patternMatchesLiteral:\n";
    RUN_VH_TEST(patternMatchesLiteral_exactMatch);
    RUN_VH_TEST(patternMatchesLiteral_noMatch);
    RUN_VH_TEST(patternMatchesLiteral_emptyString);
    
    std::cout << "\npatternMatchesOptional:\n";
    RUN_VH_TEST(patternMatchesOptional_emptyContentMatchesEmpty);
    RUN_VH_TEST(patternMatchesOptional_contentMatches);
    RUN_VH_TEST(patternMatchesOptional_noMatch);
    RUN_VH_TEST(patternMatchesOptional_partialMatch);
    
    std::cout << "\npatternMatchesPlus:\n";
    RUN_VH_TEST(patternMatchesPlus_exactRepeats);
    RUN_VH_TEST(patternMatchesPlus_noMatch);
    RUN_VH_TEST(patternMatchesPlus_emptyContent);
    
    std::cout << "\npatternMatchesStar:\n";
    RUN_VH_TEST(patternMatchesStar_emptyString);
    RUN_VH_TEST(patternMatchesStar_validRepeats);
    RUN_VH_TEST(patternMatchesStar_invalidRepeats);
    RUN_VH_TEST(patternMatchesStar_emptyContentMatchesEmpty);
    
    std::cout << "\npatternMatchesCharClass:\n";
    RUN_VH_TEST(patternMatchesCharClass_singleChar);
    RUN_VH_TEST(patternMatchesCharClass_multipleChars);
    RUN_VH_TEST(patternMatchesCharClass_noMatch);
    RUN_VH_TEST(patternMatchesCharClass_emptyString);
    RUN_VH_TEST(patternMatchesCharClass_singleCharClass);
    
    std::cout << "\ncreateQuantifiedAlternation:\n";
    RUN_VH_TEST(createQuantifiedAlternation_basic);
    RUN_VH_TEST(createQuantifiedAlternation_singleAlt);
    RUN_VH_TEST(createQuantifiedAlternation_emptyAlts);
    
    std::cout << "\ncreateQuantifiedLiteral:\n";
    RUN_VH_TEST(createQuantifiedLiteral_plus);
    RUN_VH_TEST(createQuantifiedLiteral_star);
    RUN_VH_TEST(createQuantifiedLiteral_optional);
    
    std::cout << "\ncreateQuantifiedFragment:\n";
    RUN_VH_TEST(createQuantifiedFragment_plus);
    RUN_VH_TEST(createQuantifiedFragment_star);
    
    std::cout << "\ncreateAlternationPlus/Star/Optional:\n";
    RUN_VH_TEST(createAlternationPlus_basic);
    RUN_VH_TEST(createAlternationStar_basic);
    RUN_VH_TEST(createAlternationOptional_basic);
    
    std::cout << "\ncreateLiteralPlus/Star/Optional:\n";
    RUN_VH_TEST(createLiteralPlus_basic);
    RUN_VH_TEST(createLiteralStar_basic);
    RUN_VH_TEST(createLiteralOptional_basic);
    
    std::cout << "\ncreateFragmentPlus/Star:\n";
    RUN_VH_TEST(createFragmentPlus_basic);
    RUN_VH_TEST(createFragmentStar_basic);
    
    std::cout << "\nwrapWithCaptureTags:\n";
    RUN_VH_TEST(wrapWithCaptureTags_basic);
    RUN_VH_TEST(wrapWithCaptureTags_null);
    RUN_VH_TEST(wrapWithCaptureTags_preservesInner);
    
    std::cout << "\ncreateCharClass:\n";
    RUN_VH_TEST(createCharClass_basic);
    RUN_VH_TEST(createCharClass_withSeeds);
    
    std::cout << "\ncreateCharClassPlus:\n";
    RUN_VH_TEST(createCharClassPlus_basic);
    
    std::cout << "\ncreateSequenceNode:\n";
    RUN_VH_TEST(createSequenceNode_basic);
    RUN_VH_TEST(createSequenceNode_singleChild);
    RUN_VH_TEST(createSequenceNode_empty);
    
    std::cout << "\nextractFragment:\n";
    RUN_VH_TEST(extractFragment_deterministicOutput);
    RUN_VH_TEST(extractFragment_withNamespace);
    RUN_VH_TEST(extractFragment_emptyCharClass);
    RUN_VH_TEST(extractFragment_multipleCallsDifferent);
    
    std::cout << "\n============================\n";
    std::cout << "Results: " << vh_tests_passed << "/" << vh_tests_run << " tests passed\n";
    
    return vh_tests_passed == vh_tests_run ? 0 : 1;
}
