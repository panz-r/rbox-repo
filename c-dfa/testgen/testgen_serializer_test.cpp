// ============================================================================
// PatternSerializer Unit Tests
// ============================================================================

#include "testgen.h"
#include "pattern_serializer.h"
#include <iostream>
#include <cassert>
#include <sstream>

int ser_tests_run = 0;
int ser_tests_passed = 0;

#define SER_TEST(name) void ser_test_##name()
#define RUN_SER_TEST(name) do { \
    std::cout << "  " << #name << " ... "; \
    ser_tests_run++; \
    try { \
        ser_test_##name(); \
        std::cout << "PASS\n"; \
        ser_tests_passed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAIL: " << e.what() << "\n"; \
    } \
} while(0)

#define SER_ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        std::ostringstream oss; \
        oss << "Assertion failed: '" << (a) << "' != '" << (b) << "'"; \
        throw std::runtime_error(oss.str()); \
    } \
} while(0)

#define SER_ASSERT_TRUE(x) do { \
    if (!(x)) { \
        throw std::runtime_error("Assertion failed: " #x " is false"); \
    } \
} while(0)

// ============================================================================
// Tests for serializePattern - Literal patterns
// ============================================================================

SER_TEST(serializePattern_null) {
    SER_ASSERT_EQ(serializePattern(nullptr), "");
}

SER_TEST(serializePattern_literalSimple) {
    auto node = PatternNode::createLiteral("hello", {"seed"}, {});
    SER_ASSERT_EQ(serializePattern(node), "hello");
}

SER_TEST(serializePattern_literalWithSpecialChars) {
    auto node = PatternNode::createLiteral("hello(world)", {"seed"}, {});
    SER_ASSERT_EQ(serializePattern(node), "hello\\(world\\)");
}

SER_TEST(serializePattern_literalWithRegexMetachars) {
    auto node = PatternNode::createLiteral("a+b*c?", {"seed"}, {});
    SER_ASSERT_EQ(serializePattern(node), "a\\+b\\*c\\?");
}

SER_TEST(serializePattern_literalEmpty) {
    auto node = PatternNode::createLiteral("", {"seed"}, {});
    SER_ASSERT_EQ(serializePattern(node), "");
}

// ============================================================================
// Tests for serializePattern - Quantified patterns
// ============================================================================

SER_TEST(serializePattern_plusQuantifier) {
    auto node = PatternNode::createLiteral("abc", {"seed"}, {});
    node->type = PatternType::PLUS_QUANTIFIER;
    node->quantified = PatternNode::createLiteral("abc", {"seed"}, {});
    SER_ASSERT_EQ(serializePattern(node), "(abc)+");
}

SER_TEST(serializePattern_starQuantifier) {
    auto node = PatternNode::createLiteral("x", {"seed"}, {});
    node->type = PatternType::STAR_QUANTIFIER;
    node->quantified = PatternNode::createLiteral("x", {"seed"}, {});
    SER_ASSERT_EQ(serializePattern(node), "(x)*");
}

SER_TEST(serializePattern_optionalQuantifier) {
    auto node = PatternNode::createLiteral("y", {"seed"}, {});
    node->type = PatternType::OPTIONAL;
    node->quantified = PatternNode::createLiteral("y", {"seed"}, {});
    SER_ASSERT_EQ(serializePattern(node), "(y)?");
}

// ============================================================================
// Tests for serializePattern - Fragment patterns
// ============================================================================

SER_TEST(serializePattern_fragmentRef) {
    auto node = PatternNode::createFragment("frag1", {"seed"}, {});
    node->type = PatternType::FRAGMENT_REF;
    
    SER_ASSERT_EQ(serializePattern(node), "((frag1))+");
}

SER_TEST(serializePattern_fragmentInQuantifier) {
    auto frag_node = PatternNode::createFragment("myfrag", {"seed"}, {});
    frag_node->type = PatternType::FRAGMENT_REF;
    
    auto node = std::make_shared<PatternNode>();
    node->type = PatternType::PLUS_QUANTIFIER;
    node->quantified = frag_node;
    
    SER_ASSERT_EQ(serializePattern(node), "(((myfrag))+)+");
}

// ============================================================================
// Tests for serializePattern - Alternation patterns
// ============================================================================

SER_TEST(serializePattern_alternationSimple) {
    auto child1 = PatternNode::createLiteral("a", {"seed"}, {});
    auto child2 = PatternNode::createLiteral("b", {"seed"}, {});
    
    auto node = PatternNode::createAlternation({child1, child2}, {"seed"});
    
    SER_ASSERT_EQ(serializePattern(node), "(a|b)");
}

SER_TEST(serializePattern_alternationThree) {
    auto child1 = PatternNode::createLiteral("x", {"seed"}, {});
    auto child2 = PatternNode::createLiteral("y", {"seed"}, {});
    auto child3 = PatternNode::createLiteral("z", {"seed"}, {});
    
    auto node = PatternNode::createAlternation({child1, child2, child3}, {"seed"});
    
    SER_ASSERT_EQ(serializePattern(node), "(x|y|z)");
}

SER_TEST(serializePattern_alternationQuantified) {
    auto child1 = PatternNode::createLiteral("a", {"seed"}, {});
    auto child2 = PatternNode::createLiteral("b", {"seed"}, {});
    
    auto inner = PatternNode::createAlternation({child1, child2}, {"seed"});
    auto node = std::make_shared<PatternNode>();
    node->type = PatternType::PLUS_QUANTIFIER;
    node->quantified = inner;
    
    SER_ASSERT_EQ(serializePattern(node), "((a|b))+");
}

SER_TEST(serializePattern_alternationSingle) {
    auto child = PatternNode::createLiteral("only", {"seed"}, {});
    auto node = PatternNode::createAlternation({child}, {"seed"});
    
    SER_ASSERT_EQ(serializePattern(node), "(only)");
}

// ============================================================================
// Tests for serializePattern - Sequence patterns
// ============================================================================

SER_TEST(serializePattern_sequenceTwo) {
    auto child1 = PatternNode::createLiteral("a", {"seed"}, {});
    auto child2 = PatternNode::createLiteral("b", {"seed"}, {});
    
    auto node = PatternNode::createSequence({child1, child2}, {"seed"});
    
    SER_ASSERT_EQ(serializePattern(node), "ab");
}

SER_TEST(serializePattern_sequenceThree) {
    auto child1 = PatternNode::createLiteral("a", {"seed"}, {});
    auto child2 = PatternNode::createLiteral("b", {"seed"}, {});
    auto child3 = PatternNode::createLiteral("c", {"seed"}, {});
    
    auto node = PatternNode::createSequence({child1, child2, child3}, {"seed"});
    
    SER_ASSERT_EQ(serializePattern(node), "abc");
}

SER_TEST(serializePattern_sequenceEmpty) {
    auto node = PatternNode::createSequence({}, {"seed"});
    SER_ASSERT_EQ(serializePattern(node), "");
}

// ============================================================================
// Tests for serializePattern - Capture tags
// ============================================================================

SER_TEST(serializePattern_withCaptureTag) {
    auto node = PatternNode::createLiteral("content", {"seed"}, {});
    node->capture_tag = "mytag";
    
    SER_ASSERT_EQ(serializePattern(node), "<mytag>content</mytag>");
}

SER_TEST(serializePattern_captureTagWithQuantifier) {
    auto inner = PatternNode::createLiteral("abc", {"seed"}, {});
    
    auto node = PatternNode::createLiteral("abc", {"seed"}, {});
    node->capture_tag = "tag1";
    node->type = PatternType::PLUS_QUANTIFIER;
    node->quantified = inner;
    
    SER_ASSERT_EQ(serializePattern(node), "<tag1>(abc)+</tag1>");
}

// ============================================================================
// Tests for serializePattern - Complex nested patterns
// ============================================================================

SER_TEST(serializePattern_nestedAlternationInSequence) {
    auto alt = PatternNode::createAlternation({
        PatternNode::createLiteral("a", {"seed"}, {}),
        PatternNode::createLiteral("b", {"seed"}, {})
    }, {"seed"});
    
    auto seq = PatternNode::createSequence({
        alt,
        PatternNode::createLiteral("c", {"seed"}, {})
    }, {"seed"});
    
    SER_ASSERT_EQ(serializePattern(seq), "(a|b)c");
}

SER_TEST(serializePattern_nestedQuantifiers) {
    auto inner = PatternNode::createLiteral("x", {"seed"}, {});
    
    auto node = std::make_shared<PatternNode>();
    node->type = PatternType::PLUS_QUANTIFIER;
    node->quantified = inner;
    
    SER_ASSERT_EQ(serializePattern(node), "(x)+");
}

// ============================================================================
// Run all tests
// ============================================================================

int run_pattern_serializer_tests() {
    std::cout << "PatternSerializer Unit Tests\n";
    std::cout << "============================\n\n";
    
    std::cout << "Literal patterns:\n";
    RUN_SER_TEST(serializePattern_null);
    RUN_SER_TEST(serializePattern_literalSimple);
    RUN_SER_TEST(serializePattern_literalWithSpecialChars);
    RUN_SER_TEST(serializePattern_literalWithRegexMetachars);
    RUN_SER_TEST(serializePattern_literalEmpty);
    
    std::cout << "\nQuantified patterns:\n";
    RUN_SER_TEST(serializePattern_plusQuantifier);
    RUN_SER_TEST(serializePattern_starQuantifier);
    RUN_SER_TEST(serializePattern_optionalQuantifier);
    
    std::cout << "\nFragment patterns:\n";
    RUN_SER_TEST(serializePattern_fragmentRef);
    RUN_SER_TEST(serializePattern_fragmentInQuantifier);
    
    std::cout << "\nAlternation patterns:\n";
    RUN_SER_TEST(serializePattern_alternationSimple);
    RUN_SER_TEST(serializePattern_alternationThree);
    RUN_SER_TEST(serializePattern_alternationQuantified);
    RUN_SER_TEST(serializePattern_alternationSingle);
    
    std::cout << "\nSequence patterns:\n";
    RUN_SER_TEST(serializePattern_sequenceTwo);
    RUN_SER_TEST(serializePattern_sequenceThree);
    RUN_SER_TEST(serializePattern_sequenceEmpty);
    
    std::cout << "\nCapture tags:\n";
    RUN_SER_TEST(serializePattern_withCaptureTag);
    RUN_SER_TEST(serializePattern_captureTagWithQuantifier);
    
    std::cout << "\nComplex nested patterns:\n";
    RUN_SER_TEST(serializePattern_nestedAlternationInSequence);
    RUN_SER_TEST(serializePattern_nestedQuantifiers);
    
    std::cout << "\n============================\n";
    std::cout << "Results: " << ser_tests_passed << "/" << ser_tests_run << " tests passed\n";
    
    return ser_tests_passed == ser_tests_run ? 0 : 1;
}
