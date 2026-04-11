// ============================================================================
// PatternFactorization Unit Tests
// ============================================================================

#include "testgen.h"
#include "pattern_strategies.h"
#include "pattern_factorization.h"
#include <iostream>
#include <cassert>
#include <sstream>
#include <random>

int pf_tests_run = 0;
int pf_tests_passed = 0;

#define PF_TEST(name) void pf_test_##name()
#define RUN_PF_TEST(name) do { \
    std::cout << "  " << #name << " ... "; \
    pf_tests_run++; \
    try { \
        pf_test_##name(); \
        std::cout << "PASS\n"; \
        pf_tests_passed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAIL: " << e.what() << "\n"; \
    } \
} while(0)

#define PF_ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        std::ostringstream oss; \
        oss << "Assertion failed: " << (a) << " != " << (b); \
        throw std::runtime_error(oss.str()); \
    } \
} while(0)

#define PF_ASSERT_TRUE(x) do { \
    if (!(x)) { \
        throw std::runtime_error("Assertion failed: " #x " is false"); \
    } \
} while(0)

#define PF_ASSERT_FALSE(x) do { \
    if (x) { \
        throw std::runtime_error("Assertion failed: " #x " is true"); \
    } \
} while(0)

// ============================================================================
// Tests for findCommonPrefix
// ============================================================================

PF_TEST(findCommonPrefix_empty) {
    std::vector<std::string> empty;
    std::string result = PatternFactorization::findCommonPrefix(empty);
    PF_ASSERT_EQ(result, "");
}

PF_TEST(findCommonPrefix_single) {
    std::vector<std::string> single = {"hello"};
    std::string result = PatternFactorization::findCommonPrefix(single);
    PF_ASSERT_EQ(result, "hello");
}

PF_TEST(findCommonPrefix_all_same) {
    std::vector<std::string> same = {"hello", "hello", "hello"};
    std::string result = PatternFactorization::findCommonPrefix(same);
    PF_ASSERT_EQ(result, "hello");
}

PF_TEST(findCommonPrefix_common_prefix) {
    std::vector<std::string> common = {"prefix_abc", "prefix_def", "prefix_ghi"};
    std::string result = PatternFactorization::findCommonPrefix(common);
    PF_ASSERT_EQ(result, "prefix_");
}

PF_TEST(findCommonPrefix_no_common) {
    std::vector<std::string> no_common = {"abc", "def", "ghi"};
    std::string result = PatternFactorization::findCommonPrefix(no_common);
    PF_ASSERT_EQ(result, "");
}

// ============================================================================
// Tests for findCommonSuffix
// ============================================================================

PF_TEST(findCommonSuffix_empty) {
    std::vector<std::string> empty;
    std::string result = PatternFactorization::findCommonSuffix(empty);
    PF_ASSERT_EQ(result, "");
}

PF_TEST(findCommonSuffix_single) {
    std::vector<std::string> single = {"hello"};
    std::string result = PatternFactorization::findCommonSuffix(single);
    PF_ASSERT_EQ(result, "hello");
}

PF_TEST(findCommonSuffix_common_suffix) {
    std::vector<std::string> common = {"abc_suffix", "def_suffix", "ghi_suffix"};
    std::string result = PatternFactorization::findCommonSuffix(common);
    PF_ASSERT_EQ(result, "_suffix");
}

PF_TEST(findCommonSuffix_no_common) {
    std::vector<std::string> no_common = {"abc", "def", "ghi"};
    std::string result = PatternFactorization::findCommonSuffix(no_common);
    PF_ASSERT_EQ(result, "");
}

// ============================================================================
// Tests for copyPatternNode
// ============================================================================

PF_TEST(copyPatternNode_literal) {
    auto original = PatternNode::createLiteral("test", {"seed1"}, {"counter1"});
    auto copy = PatternFactorization::copyPatternNode(original);
    
    PF_ASSERT_TRUE(copy != nullptr);
    PF_ASSERT_EQ(copy->value, "test");
    PF_ASSERT_EQ(copy->matched_seeds.size(), 1u);
    PF_ASSERT_EQ(copy->counter_seeds.size(), 1u);
    
    copy->value = "modified";
    PF_ASSERT_EQ(original->value, "test");
}

PF_TEST(copyPatternNode_sequence) {
    auto child1 = PatternNode::createLiteral("a", {"a"}, {});
    auto child2 = PatternNode::createLiteral("b", {"b"}, {});
    auto original = PatternNode::createSequence({child1, child2}, {"ab"}, {"xy"});
    auto copy = PatternFactorization::copyPatternNode(original);
    
    PF_ASSERT_TRUE(copy != nullptr);
    PF_ASSERT_EQ(copy->children.size(), 2u);
    PF_ASSERT_TRUE(copy->children[0] != child1);
}

PF_TEST(copyPatternNode_alternation) {
    auto child1 = PatternNode::createLiteral("a", {"a"}, {});
    auto child2 = PatternNode::createLiteral("b", {"b"}, {});
    auto original = PatternNode::createAlternation({child1, child2}, {"a", "b"}, {"x", "y"});
    auto copy = PatternFactorization::copyPatternNode(original);
    
    PF_ASSERT_TRUE(copy != nullptr);
    PF_ASSERT_EQ(copy->children.size(), 2u);
    PF_ASSERT_EQ(copy->matched_seeds.size(), 2u);
    PF_ASSERT_EQ(copy->counter_seeds.size(), 2u);
}

// ============================================================================
// Tests for factorPattern
// ============================================================================

PF_TEST(factorPattern_null) {
    auto result = PatternFactorization::factorPattern(nullptr, 0, nullptr);
    PF_ASSERT_TRUE(result == nullptr);
}

PF_TEST(factorPattern_literal) {
    auto node = PatternNode::createLiteral("test", {"test"}, {});
    auto result = PatternFactorization::factorPattern(node, 0, nullptr);
    PF_ASSERT_TRUE(result != nullptr);
    PF_ASSERT_EQ(result->value, "test");
}

// ============================================================================
// Tests for applyFactorization
// ============================================================================

PF_TEST(applyFactorization_null) {
    std::mt19937 rng(42);
    auto result = PatternFactorization::applyFactorization(nullptr, rng, nullptr);
    PF_ASSERT_TRUE(result == nullptr);
}

PF_TEST(applyFactorization_literal) {
    auto node = PatternNode::createLiteral("abc", {"abc"}, {});
    std::mt19937 rng(42);
    auto result = PatternFactorization::applyFactorization(node, rng, nullptr);
    PF_ASSERT_TRUE(result != nullptr);
}

PF_TEST(applyFactorization_simple_alternation) {
    auto child1 = PatternNode::createLiteral("abc", {"abc"}, {});
    auto child2 = PatternNode::createLiteral("abd", {"abd"}, {});
    auto child3 = PatternNode::createLiteral("abf", {"abf"}, {});
    auto node = PatternNode::createAlternation({child1, child2, child3}, {"abc", "abd", "abf"}, {});
    
    std::mt19937 rng(42);
    auto result = PatternFactorization::applyFactorization(node, rng, nullptr);
    PF_ASSERT_TRUE(result != nullptr);
}

// ============================================================================
// Tests for applyRandomStars
// ============================================================================

PF_TEST(applyRandomStars_literal) {
    auto node = PatternNode::createLiteral("abc", {"abc"}, {});
    std::mt19937 rng(42);
    auto result = PatternFactorization::applyRandomStars(node, rng);
    PF_ASSERT_TRUE(result != nullptr);
}

// ============================================================================
// Tests for detectStarInsertions
// ============================================================================

PF_TEST(detectStarInsertions_null_before) {
    auto after = PatternNode::createLiteral("abc", {"abc"}, {});
    std::string result = PatternFactorization::detectStarInsertions(nullptr, after, "context");
    PF_ASSERT_EQ(result, "");
}

PF_TEST(detectStarInsertions_null_after) {
    auto before = PatternNode::createLiteral("abc", {"abc"}, {});
    std::string result = PatternFactorization::detectStarInsertions(before, nullptr, "context");
    PF_ASSERT_EQ(result, "");
}

// ============================================================================
// Run all tests
// ============================================================================

int run_factorization_tests() {
    std::cout << "PatternFactorization Unit Tests\n";
    std::cout << "==============================\n\n";
    
    std::cout << "findCommonPrefix tests:\n";
    RUN_PF_TEST(findCommonPrefix_empty);
    RUN_PF_TEST(findCommonPrefix_single);
    RUN_PF_TEST(findCommonPrefix_all_same);
    RUN_PF_TEST(findCommonPrefix_common_prefix);
    RUN_PF_TEST(findCommonPrefix_no_common);
    
    std::cout << "\nfindCommonSuffix tests:\n";
    RUN_PF_TEST(findCommonSuffix_empty);
    RUN_PF_TEST(findCommonSuffix_single);
    RUN_PF_TEST(findCommonSuffix_common_suffix);
    RUN_PF_TEST(findCommonSuffix_no_common);
    
    std::cout << "\ncopyPatternNode tests:\n";
    RUN_PF_TEST(copyPatternNode_literal);
    RUN_PF_TEST(copyPatternNode_sequence);
    RUN_PF_TEST(copyPatternNode_alternation);
    
    std::cout << "\nfactorPattern tests:\n";
    RUN_PF_TEST(factorPattern_null);
    RUN_PF_TEST(factorPattern_literal);
    
    std::cout << "\napplyFactorization tests:\n";
    RUN_PF_TEST(applyFactorization_null);
    RUN_PF_TEST(applyFactorization_literal);
    RUN_PF_TEST(applyFactorization_simple_alternation);
    
    std::cout << "\napplyRandomStars tests:\n";
    RUN_PF_TEST(applyRandomStars_literal);
    
    std::cout << "\ndetectStarInsertions tests:\n";
    RUN_PF_TEST(detectStarInsertions_null_before);
    RUN_PF_TEST(detectStarInsertions_null_after);
    
    std::cout << "\n==============================\n";
    std::cout << "Results: " << pf_tests_passed << "/" << pf_tests_run << " tests passed\n";
    
    return pf_tests_passed == pf_tests_run ? 0 : 1;
}