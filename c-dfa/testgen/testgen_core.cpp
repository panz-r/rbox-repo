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
    
    // DEFENSIVE FIX: Ensure all FRAGMENT_REF nodes in AST have definitions
    // Derives actual definitions from the AST node's matched_seeds when possible
    if (ast) {
        std::set<std::string> ast_frags;
        collectFragmentNames(ast, ast_frags);
        for (const auto& frag_name : ast_frags) {
            if (tc.fragments.find(frag_name) == tc.fragments.end()) {
                // Search the AST for this fragment ref to get its matched_seeds
                std::function<std::vector<std::string>(std::shared_ptr<PatternNode>)> findSeeds;
                findSeeds = [&](std::shared_ptr<PatternNode> n) -> std::vector<std::string> {
                    if (!n) return {};
                    if (n->type == PatternType::FRAGMENT_REF && n->fragment_name == frag_name) {
                        return n->matched_seeds;
                    }
                    for (auto& child : n->children) {
                        auto s = findSeeds(child);
                        if (!s.empty()) return s;
                    }
                    if (n->quantified) return findSeeds(n->quantified);
                    return {};
                };
                auto seeds = findSeeds(ast);
                if (!seeds.empty()) {
                    // All seeds the same -> use as literal definition
                    bool all_same = true;
                    for (const auto& s : seeds) {
                        if (s != seeds[0]) { all_same = false; break; }
                    }
                    tc.fragments[frag_name] = all_same ? seeds[0] : std::string(1, seeds[0].empty() ? 'Z' : seeds[0][0]);
                } else {
                    tc.fragments[frag_name] = "Z";
                }
            }
        }
    }
    
    return tc;
}

} // namespace TestGen