// ============================================================================
// ExpectationGen Unit Tests
// ============================================================================

#include "testgen.h"
#include "expectation_gen.h"
#include <iostream>
#include <cassert>
#include <sstream>
#include <random>

int eg_tests_run = 0;
int eg_tests_passed = 0;

#define EG_TEST(name) void eg_test_##name()
#define RUN_EG_TEST(name) do { \
    std::cout << "  " << #name << " ... "; \
    eg_tests_run++; \
    try { \
        eg_test_##name(); \
        std::cout << "PASS\n"; \
        eg_tests_passed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAIL: " << e.what() << "\n"; \
    } \
} while(0)

#define EG_ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        std::ostringstream oss; \
        oss << "Assertion failed: " << (a) << " != " << (b); \
        throw std::runtime_error(oss.str()); \
    } \
} while(0)

#define EG_ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        std::ostringstream oss; \
        oss << "Assertion failed: " << (a) << " != " << (b); \
        throw std::runtime_error(oss.str()); \
    } \
} while(0)

#define EG_ASSERT_TRUE(x) do { \
    if (!(x)) { \
        throw std::runtime_error("Assertion failed: " #x " is false"); \
    } \
} while(0)

#define EG_ASSERT_FALSE(x) do { \
    if (x) { \
        throw std::runtime_error("Assertion failed: " #x " is true"); \
    } \
} while(0)

// ============================================================================
// Tests for expectationTypeToString
// ============================================================================

EG_TEST(expectationTypeToString_matchExact) {
    EG_ASSERT_EQ(expectationTypeToString(ExpectationType::MATCH_EXACT), "MATCH_EXACT");
}

EG_TEST(expectationTypeToString_noMatch) {
    EG_ASSERT_EQ(expectationTypeToString(ExpectationType::NO_MATCH), "NO_MATCH");
}

EG_TEST(expectationTypeToString_fragmentMatch) {
    EG_ASSERT_EQ(expectationTypeToString(ExpectationType::FRAGMENT_MATCH), "FRAGMENT_MATCH");
}

EG_TEST(expectationTypeToString_unknown) {
    EG_ASSERT_EQ(expectationTypeToString(static_cast<ExpectationType>(999)), "UNKNOWN");
}

// ============================================================================
// Tests for hasFragment
// ============================================================================

EG_TEST(hasFragment_true) {
    EG_ASSERT_TRUE(hasFragment("((frag))+"));
    EG_ASSERT_TRUE(hasFragment("((test::x))"));
}

EG_TEST(hasFragment_false) {
    EG_ASSERT_FALSE(hasFragment("abc"));
    EG_ASSERT_FALSE(hasFragment("(a|b|c)"));
}

// ============================================================================
// Tests for hasQuantifier
// ============================================================================

EG_TEST(hasQuantifier_star) {
    EG_ASSERT_TRUE(hasQuantifier("a*", '*'));
    EG_ASSERT_TRUE(hasQuantifier("(ab)*", '*'));
}

EG_TEST(hasQuantifier_plus) {
    EG_ASSERT_TRUE(hasQuantifier("a+", '+'));
    EG_ASSERT_TRUE(hasQuantifier("(ab)+", '+'));
}

EG_TEST(hasQuantifier_question) {
    EG_ASSERT_TRUE(hasQuantifier("a?", '?'));
    EG_ASSERT_TRUE(hasQuantifier("(ab)?", '?'));
}

EG_TEST(hasQuantifier_notPresent) {
    EG_ASSERT_FALSE(hasQuantifier("abc", '*'));
    EG_ASSERT_FALSE(hasQuantifier("(a|b|c)", '+'));
}

// ============================================================================
// Tests for hasStarQuantifier
// ============================================================================

EG_TEST(hasStarQuantifier_true) {
    EG_ASSERT_TRUE(hasStarQuantifier("a*"));
    EG_ASSERT_TRUE(hasStarQuantifier("(ab)*"));
}

EG_TEST(hasStarQuantifier_false) {
    EG_ASSERT_FALSE(hasStarQuantifier("a+"));
    EG_ASSERT_FALSE(hasStarQuantifier("abc"));
}

// ============================================================================
// Tests for hasPlusQuantifier
// ============================================================================

EG_TEST(hasPlusQuantifier_true) {
    EG_ASSERT_TRUE(hasPlusQuantifier("a+"));
    EG_ASSERT_TRUE(hasPlusQuantifier("(ab)+"));
}

EG_TEST(hasPlusQuantifier_false) {
    EG_ASSERT_FALSE(hasPlusQuantifier("a*"));
    EG_ASSERT_FALSE(hasPlusQuantifier("abc"));
}

// ============================================================================
// Tests for hasOptional
// ============================================================================

EG_TEST(hasOptional_true) {
    EG_ASSERT_TRUE(hasOptional("a?"));
    EG_ASSERT_TRUE(hasOptional("(ab)?"));
}

EG_TEST(hasOptional_false) {
    EG_ASSERT_FALSE(hasOptional("a+"));
    EG_ASSERT_FALSE(hasOptional("abc"));
}

// ============================================================================
// Tests for hasAlternation
// ============================================================================

EG_TEST(hasAlternation_true) {
    EG_ASSERT_TRUE(hasAlternation("(a|b|c)"));
    EG_ASSERT_TRUE(hasAlternation("a|b|c"));
}

EG_TEST(hasAlternation_false) {
    EG_ASSERT_FALSE(hasAlternation("abc"));
    EG_ASSERT_FALSE(hasAlternation("(abc)"));
}

// ============================================================================
// Tests for hasCaptureTags
// ============================================================================

EG_TEST(hasCaptureTags_true) {
    EG_ASSERT_TRUE(hasCaptureTags("<tag>content</tag>"));
    EG_ASSERT_TRUE(hasCaptureTags("<x>abc</x>"));
}

EG_TEST(hasCaptureTags_false) {
    EG_ASSERT_FALSE(hasCaptureTags("<tag>content"));  // only opening tag
    EG_ASSERT_FALSE(hasCaptureTags("abc"));
    EG_ASSERT_FALSE(hasCaptureTags("<tag>"));  // no closing tag
}

// ============================================================================
// Tests for extractAlternatives
// ============================================================================

EG_TEST(extractAlternatives_basic) {
    EG_ASSERT_EQ(extractAlternatives("(a|b|c)"), "a|b|c");
}

EG_TEST(extractAlternatives_noParens) {
    EG_ASSERT_EQ(extractAlternatives("abc"), "");
}

EG_TEST(extractAlternatives_nested) {
    EG_ASSERT_EQ(extractAlternatives("(a|(b|c))"), "a|(b|c)");
}

// ============================================================================
// Tests for splitAlternatives
// ============================================================================

EG_TEST(splitAlternatives_basic) {
    auto result = splitAlternatives("a|b|c");
    EG_ASSERT_TRUE(result.size() == 3);
    EG_ASSERT_EQ(result[0], "a");
    EG_ASSERT_EQ(result[1], "b");
    EG_ASSERT_EQ(result[2], "c");
}

EG_TEST(splitAlternatives_empty) {
    auto result = splitAlternatives("");
    EG_ASSERT_TRUE(result.empty());
}

EG_TEST(splitAlternatives_single) {
    auto result = splitAlternatives("abc");
    EG_ASSERT_TRUE(result.size() == 1);
    EG_ASSERT_EQ(result[0], "abc");
}

EG_TEST(splitAlternatives_nested) {
    auto result = splitAlternatives("a|(b|c)");
    EG_ASSERT_TRUE(result.size() == 2);
    EG_ASSERT_EQ(result[0], "a");
    EG_ASSERT_EQ(result[1], "(b|c)");
}

// ============================================================================
// Run all tests
// ============================================================================

int run_expectation_gen_tests() {
    std::cout << "ExpectationGen Unit Tests\n";
    std::cout << "=========================\n\n";
    
    std::cout << "expectationTypeToString:\n";
    RUN_EG_TEST(expectationTypeToString_matchExact);
    RUN_EG_TEST(expectationTypeToString_noMatch);
    RUN_EG_TEST(expectationTypeToString_fragmentMatch);
    RUN_EG_TEST(expectationTypeToString_unknown);
    
    std::cout << "\nhasFragment:\n";
    RUN_EG_TEST(hasFragment_true);
    RUN_EG_TEST(hasFragment_false);
    
    std::cout << "\nhasQuantifier:\n";
    RUN_EG_TEST(hasQuantifier_star);
    RUN_EG_TEST(hasQuantifier_plus);
    RUN_EG_TEST(hasQuantifier_question);
    RUN_EG_TEST(hasQuantifier_notPresent);
    
    std::cout << "\nhasStarQuantifier:\n";
    RUN_EG_TEST(hasStarQuantifier_true);
    RUN_EG_TEST(hasStarQuantifier_false);
    
    std::cout << "\nhasPlusQuantifier:\n";
    RUN_EG_TEST(hasPlusQuantifier_true);
    RUN_EG_TEST(hasPlusQuantifier_false);
    
    std::cout << "\nhasOptional:\n";
    RUN_EG_TEST(hasOptional_true);
    RUN_EG_TEST(hasOptional_false);
    
    std::cout << "\nhasAlternation:\n";
    RUN_EG_TEST(hasAlternation_true);
    RUN_EG_TEST(hasAlternation_false);
    
    std::cout << "\nhasCaptureTags:\n";
    RUN_EG_TEST(hasCaptureTags_true);
    RUN_EG_TEST(hasCaptureTags_false);
    
    std::cout << "\nextractAlternatives:\n";
    RUN_EG_TEST(extractAlternatives_basic);
    RUN_EG_TEST(extractAlternatives_noParens);
    RUN_EG_TEST(extractAlternatives_nested);
    
    std::cout << "\nsplitAlternatives:\n";
    RUN_EG_TEST(splitAlternatives_basic);
    RUN_EG_TEST(splitAlternatives_empty);
    RUN_EG_TEST(splitAlternatives_single);
    RUN_EG_TEST(splitAlternatives_nested);
    
    std::cout << "\n=========================\n";
    std::cout << "Results: " << eg_tests_passed << "/" << eg_tests_run << " tests passed\n";
    
    return eg_tests_passed == eg_tests_run ? 0 : 1;
}
