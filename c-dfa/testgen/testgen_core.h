#ifndef TESTGEN_CORE_H
#define TESTGEN_CORE_H

#include "testgen.h"
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <functional>

namespace TestGen {

// ============================================================================
// InputGraph - tracks inputs and their relationships
// ============================================================================

struct InputNode {
    std::string id;
    std::string value;
    std::set<std::string> categories;
    std::map<std::string, std::string> meta;
};

struct DependencyEdge {
    std::string from;
    std::string to;
    enum class Type {
        DIFFERS_AT,
        SHARES_STRUCTURE,
        USES_FRAGMENT,
        NUMERICAL_RELATION,
        SAME_CATEGORY
    };
    Type type;
    std::map<std::string, std::string> meta;
    
    static std::string typeToString(Type t) {
        switch (t) {
            case Type::DIFFERS_AT: return "DIFFERS_AT";
            case Type::SHARES_STRUCTURE: return "SHARES_STRUCTURE";
            case Type::USES_FRAGMENT: return "USES_FRAGMENT";
            case Type::NUMERICAL_RELATION: return "NUMERICAL_RELATION";
            case Type::SAME_CATEGORY: return "SAME_CATEGORY";
            default: return "UNKNOWN";
        }
    }
};

struct InputGraph {
    std::vector<InputNode> nodes;
    std::vector<DependencyEdge> edges;
    
    InputNode& add(const std::string& value, const std::set<std::string>& cats = {}) {
        InputNode node;
        node.id = "input_" + std::to_string(nodes.size());
        node.value = value;
        node.categories = cats;
        nodes.push_back(std::move(node));
        return nodes.back();
    }
    
    void link(const DependencyEdge& edge) {
        edges.push_back(edge);
    }
    
    std::vector<InputNode*> query(std::function<bool(const InputNode&)> filter) {
        std::vector<InputNode*> result;
        for (auto& node : nodes) {
            if (filter(node)) {
                result.push_back(&node);
            }
        }
        return result;
    }
    
    std::vector<InputNode*> byCategory(const std::string& cat) {
        return query([&cat](const InputNode& n) {
            return n.categories.count(cat) > 0;
        });
    }
    
    InputNode* getById(const std::string& id) {
        for (auto& node : nodes) {
            if (node.id == id) return &node;
        }
        return nullptr;
    }
    
    std::vector<DependencyEdge> getEdgesFrom(const std::string& node_id) {
        std::vector<DependencyEdge> result;
        for (auto& e : edges) {
            if (e.from == node_id) result.push_back(e);
        }
        return result;
    }
    
    std::vector<DependencyEdge> getEdgesTo(const std::string& node_id) {
        std::vector<DependencyEdge> result;
        for (auto& e : edges) {
            if (e.to == node_id) result.push_back(e);
        }
        return result;
    }
};

// ============================================================================
// GenerationContext - state carrier through pipeline
// ============================================================================

struct FragmentBuildState {
    std::string name;
    std::string current_definition;
    bool complete = false;
    int build_step = 0;
};

struct GenerationContext {
    InputGraph graph;
    std::map<std::string, int> counters;
    std::mt19937 rng;
    std::vector<FragmentBuildState> fragment_builds;
    
    int getAndIncrement(const std::string& counter) {
        int val = counters[counter];
        counters[counter] = val + 1;
        return val;
    }
    
    void setCounter(const std::string& counter, int value) {
        counters[counter] = value;
    }
    
    int peek(const std::string& counter) const {
        auto it = counters.find(counter);
        return it != counters.end() ? it->second : 0;
    }
    
    FragmentBuildState* startFragment(const std::string& name) {
        for (auto& f : fragment_builds) {
            if (f.name == name) return &f;
        }
        FragmentBuildState f;
        f.name = name;
        fragment_builds.push_back(std::move(f));
        return &fragment_builds.back();
    }
    
    void completeFragment(const std::string& name) {
        for (auto& f : fragment_builds) {
            if (f.name == name) {
                f.complete = true;
                return;
            }
        }
    }
};

// ============================================================================
// ExpectationSet - structured expectations
// ============================================================================

struct ExpectationSet {
    std::vector<Expectation> match;
    std::vector<Expectation> no_match;
    std::vector<Expectation> fragment;
    std::vector<Expectation> quantifier;
    std::vector<Expectation> structure;
    
    void add(const Expectation& e) {
        switch (e.type) {
            case ExpectationType::MATCH_EXACT:
                match.push_back(e);
                break;
            case ExpectationType::NO_MATCH:
                no_match.push_back(e);
                break;
            case ExpectationType::FRAGMENT_MATCH:
            case ExpectationType::FRAGMENT_NESTED:
                fragment.push_back(e);
                break;
            case ExpectationType::QUANTIFIER_STAR_EMPTY:
            case ExpectationType::QUANTIFIER_PLUS_MINONE:
            case ExpectationType::REPETITION_MIN_COUNT:
                quantifier.push_back(e);
                break;
            default:
                structure.push_back(e);
                break;
        }
    }
    
    size_t total() const {
        return match.size() + no_match.size() + fragment.size() +
               quantifier.size() + structure.size();
    }
    
    std::vector<Expectation> all() const {
        std::vector<Expectation> result;
        result.insert(result.end(), match.begin(), match.end());
        result.insert(result.end(), no_match.begin(), no_match.end());
        result.insert(result.end(), fragment.begin(), fragment.end());
        result.insert(result.end(), quantifier.begin(), quantifier.end());
        result.insert(result.end(), structure.begin(), structure.end());
        return result;
    }
};

// ============================================================================
// TestCaseCore - new TestCase that uses InputGraph
// ============================================================================

struct TestCaseCore {
    std::string id;
    std::shared_ptr<PatternNode> ast;
    InputGraph inputs;
    std::map<std::string, std::string> fragments;
    ExpectationSet expectations;
    std::string proof;
    double score = 0.0;
    
    std::string pattern() const;
    
    static TestCaseCore fromOldTestCase(const TestCase& tc);
    TestCase toOldTestCase(int test_id) const;
};

} // namespace TestGen

#endif // TESTGEN_CORE_H