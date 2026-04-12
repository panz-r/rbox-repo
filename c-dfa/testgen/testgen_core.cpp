#include "testgen_core.h"
#include "pattern_serializer.h"

namespace TestGen {

std::string TestCaseCore::pattern() const {
    if (ast) {
        return serializePattern(ast);
    }
    return "";
}

TestCaseCore TestCaseCore::fromOldTestCase(const TestCase& tc) {
    TestCaseCore result;
    result.id = "tc_" + std::to_string(tc.test_id);
    result.fragments = tc.fragments;
    result.proof = tc.proof;
    
    if (!tc.pattern.empty()) {
        result.ast = parsePatternToAST(tc.pattern);
    }
    
    for (const auto& inp : tc.matching_inputs) {
        result.inputs.add(inp, {"matching"});
    }
    for (const auto& inp : tc.counter_inputs) {
        result.inputs.add(inp, {"counter"});
    }
    
    for (const auto& e : tc.expectations) {
        result.expectations.add(e);
    }
    
    return result;
}

TestCase TestCaseCore::toOldTestCase(int test_id) const {
    TestCase tc;
    tc.test_id = test_id;
    tc.pattern = pattern();
    tc.fragments = fragments;
    tc.proof = proof;
    tc.expectations = expectations.all();
    tc.complexity = Complexity::MEDIUM;
    tc.category = Category::SAFE;
    tc.counter_category = Category::UNKNOWN;
    
    for (const auto& node : inputs.nodes) {
        if (node.categories.count("matching")) {
            tc.matching_inputs.push_back(node.value);
        } else if (node.categories.count("counter")) {
            tc.counter_inputs.push_back(node.value);
        }
    }
    
    return tc;
}

} // namespace TestGen