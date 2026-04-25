#include "testgen_core.h"
#include "pattern_serializer.h"
#include <set>

namespace TestGen {

std::string TestCaseCore::pattern() const {
    if (ast) {
        return serializePattern(ast);
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
    
    // DEFENSIVE FIX: Ensure all FRAGMENT_REF nodes in AST have definitions.
    // Only produces sound definitions when all matched_seeds are identical.
    // When seeds differ or are absent, clears the pattern to skip this test case.
    if (ast) {
        std::set<std::string> ast_frags;
        collectFragmentNames(ast, ast_frags);
        for (const auto& frag_name : ast_frags) {
            if (tc.fragments.find(frag_name) == tc.fragments.end()) {
                std::function<std::vector<std::string>(std::shared_ptr<PatternNode>)> findSeeds;
                findSeeds = [&](std::shared_ptr<PatternNode> n) -> std::vector<std::string> {
                    if (!n) return std::vector<std::string>();
                    if (n->type == PatternType::FRAGMENT_REF && n->fragment_name == frag_name) {
                        return n->matched_seeds;
                    }
                    for (auto& child : n->children) {
                        auto s = findSeeds(child);
                        if (!s.empty()) return s;
                    }
                    if (n->quantified) return findSeeds(n->quantified);
                    return std::vector<std::string>();
                };
                auto seeds = findSeeds(ast);
                if (!seeds.empty()) {
                    bool all_same = true;
                    for (const auto& s : seeds) {
                        if (s != seeds[0]) { all_same = false; break; }
                    }
                    if (all_same) {
                        tc.fragments[frag_name] = seeds[0];
                    } else {
                        // Seeds differ — no sound definition; skip this test case
                        tc.pattern = "";
                        return tc;
                    }
                } else {
                    // No seeds — skip this test case
                    tc.pattern = "";
                    return tc;
                }
            }
        }
    }
    
    return tc;
}

} // namespace TestGen