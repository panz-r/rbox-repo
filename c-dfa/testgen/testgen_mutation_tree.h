#ifndef TESTGEN_MUTATION_TREE_H
#define TESTGEN_MUTATION_TREE_H

#include "testgen_core.h"
#include "testgen_operators.h"
#include <vector>
#include <map>
#include <functional>

namespace TestGen {

struct MutationTreeNode {
    TestCaseCore tc = {};
    double score = 0.0;
    MutationTreeNode* parent = nullptr;
    std::vector<MutationTreeNode*> children = {};
    int depth = 0;
    std::string operator_name = {};
    
    MutationTreeNode(const TestCaseCore& tc_, MutationTreeNode* parent_ = nullptr)
        : tc(tc_), score(0.0), parent(parent_), depth(parent_ ? parent_->depth + 1 : 0) {}
    
    ~MutationTreeNode() {
        for (auto child : children) delete child;
    }
};

class DFACoverageTracker {
public:
    struct CoverageData {
        std::set<int> covered_lines = {};
        std::set<std::pair<int,int>> covered_edges = {};
        
        bool operator==(const CoverageData& other) const {
            return covered_lines == other.covered_lines && 
                   covered_edges == other.covered_edges;
        }
        
        size_t totalCoverage() const {
            return covered_lines.size() + covered_edges.size();
        }
    };
    
    void recordCoverage(const std::string& test_id, const CoverageData& data) {
        coverage_map[test_id] = data;
        // Merge into global coverage
        for (int line : data.covered_lines) global_covered_lines.insert(line);
        for (const auto& edge : data.covered_edges) global_covered_edges.insert(edge);
        // Track coverage history for plateau detection
        coverage_history.push_back(global_covered_lines.size() + global_covered_edges.size());
    }
    
    // Estimate coverage gain for a test case based on its AST complexity.
    // More complex patterns (more alternatives, quantifiers, fragments) are
    // likely to exercise more DFA states. This is a heuristic — the real
    // coverage is recorded via recordCoverage after pipeline execution.
    double coverageGain(const TestCaseCore& tc) const {
        if (!tc.ast) return 0.0;
        
        // Estimate new state coverage from AST complexity
        double estimated_new = 0.0;
        
        // Count AST features that correspond to DFA states
        int features = countFeatures(tc.ast);
        
        // Estimate: each feature might touch ~2-3 new states
        // Discount by what we've already covered
        double coverage_ratio = 0.0;
        size_t total = global_covered_lines.size() + global_covered_edges.size();
        if (total > 0) {
            // Simple decay: more coverage = diminishing returns
            coverage_ratio = 1.0 / (1.0 + total * 0.01);
        } else {
            coverage_ratio = 1.0;
        }
        
        estimated_new = features * coverage_ratio;
        return estimated_new;
    }
    
    std::vector<std::string> uncoveredStates() const {
        // This would require DFA introspection which isn't available
        // Return empty for now — placeholder for future pipeline integration
        return {};
    }
    
    bool plateaued() const {
        // Plateau = last N recordings added no new coverage
        const size_t window = 5;
        if (coverage_history.size() < window) return false;
        
        size_t latest = coverage_history.back();
        size_t oldest_in_window = coverage_history[coverage_history.size() - window];
        return latest == oldest_in_window;
    }
    
    CoverageData baseline() const {
        CoverageData b;
        b.covered_lines = global_covered_lines;
        b.covered_edges = global_covered_edges;
        return b;
    }
    
    void reset() {
        coverage_map.clear();
        global_covered_lines.clear();
        global_covered_edges.clear();
        coverage_history.clear();
    }

private:
    std::map<std::string, CoverageData> coverage_map;
    std::set<int> global_covered_lines;
    std::set<std::pair<int,int>> global_covered_edges;
    std::vector<size_t> coverage_history;
    
    // Count AST features that map to DFA state complexity
    static int countFeatures(std::shared_ptr<PatternNode> node) {
        if (!node) return 0;
        int count = 0;
        switch (node->type) {
            case PatternType::ALTERNATION:
                count = (int)node->children.size();
                break;
            case PatternType::PLUS_QUANTIFIER:
            case PatternType::STAR_QUANTIFIER:
            case PatternType::OPTIONAL:
                count = 2;  // quantifier adds loop states
                break;
            case PatternType::FRAGMENT_REF:
                count = 3;  // fragment expansion adds states
                break;
            default:
                count = 1;
                break;
        }
        if (node->quantified) count += countFeatures(node->quantified);
        for (auto& child : node->children) count += countFeatures(child);
        return count;
    }
};

class MutationTree {
public:
    MutationTree();
    
    void setSeed(const TestCaseCore& seed);
    void setCoverageTracker(DFACoverageTracker* tracker);
    
    void grow(
        MutationTreeNode* from,
        size_t branching_factor,
        std::mt19937& rng
    );
    
    void prune(
        MutationTreeNode* at,
        size_t keep,
        std::function<double(const TestCaseCore&)> score_fn
    );
    
    void iterate(
        size_t max_depth,
        size_t branching_factor,
        size_t keep_per_level,
        std::mt19937& rng
    );
    
    std::vector<TestCaseCore> getFrontier() const;
    std::vector<TestCaseCore> getAll() const;
    
    MutationTreeNode* root() const { return root_; }
    
private:
    MutationTreeNode* root_;
    DFACoverageTracker* coverage;
    CoordinatedMutationEngine coordinated_engine;
    
    std::vector<TestCaseCore> scoreAndRank(
        const std::vector<TestCaseCore>& candidates,
        std::mt19937& rng
    );
};

double defaultScoreFunction(const TestCaseCore& tc);

} // namespace TestGen

#endif // TESTGEN_MUTATION_TREE_H