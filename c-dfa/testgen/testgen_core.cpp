#include "testgen_core.h"
#include "pattern_serializer.h"
#include <set>

namespace TestGen {

std::string TestCaseCore::pattern() const {
    if (ast) {
        std::string result = serializePattern(ast);
        if (result.find("fNag") != std::string::npos) {
            fprintf(stderr, "DEBUG PATTERN: serialize produced fNag in: %s\n", result.c_str());
        }
        return result;
    }
    return "";
}

// Collect all FRAGMENT_REF names from an AST node
static void collectFragmentNames(std::shared_ptr<PatternNode> node, std::set<std::string>& names) {
    if (!node) return;
    if (node->type == PatternType::FRAGMENT_REF) {
        names.insert(node->fragment_name);
    }
    if (node->quantified) {
        collectFragmentNames(node->quantified, names);
    }
    for (auto& child : node->children) {
        collectFragmentNames(child, names);
    }
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
    
    // DEFENSIVE FIX: Ensure all FRAGMENT_REF nodes in AST have definitions
    // This catches issues where mutations create FRAGMENT_REF nodes without definitions
    if (ast) {
        std::set<std::string> ast_frags;
        collectFragmentNames(ast, ast_frags);
        for (const auto& frag_name : ast_frags) {
            if (tc.fragments.find(frag_name) == tc.fragments.end()) {
                fprintf(stderr, "WARNING: Fragment '%s' in mutated AST but has no definition, adding placeholder\n",
                        frag_name.c_str());
                tc.fragments[frag_name] = ".";
            }
        }
    }
    
    return tc;
}

} // namespace TestGen