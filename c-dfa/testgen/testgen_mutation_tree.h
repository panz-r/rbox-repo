#ifndef TESTGEN_MUTATION_TREE_H
#define TESTGEN_MUTATION_TREE_H

#include "testgen_core.h"
#include "testgen_operators.h"
#include <vector>
#include <map>
#include <functional>

namespace TestGen {

struct MutationTreeNode {
    TestCaseCore tc;
    double score;
    MutationTreeNode* parent;
    std::vector<MutationTreeNode*> children;
    int depth;
    std::string operator_name;
    
    MutationTreeNode(const TestCaseCore& tc_, MutationTreeNode* parent_ = nullptr)
        : tc(tc_), score(0.0), parent(parent_), depth(parent_ ? parent_->depth + 1 : 0) {}
    
    ~MutationTreeNode() {
        for (auto child : children) delete child;
    }
};

class DFACoverageTracker {
public:
    struct CoverageData {
        std::set<int> covered_lines;
        std::set<std::pair<int,int>> covered_edges;
        
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
    }
    
    double coverageGain(const TestCaseCore& tc) const {
        return 0.0;
    }
    
    std::vector<std::string> uncoveredStates() const {
        return {};
    }
    
    bool plateaued() const {
        return false;
    }
    
    CoverageData baseline() const {
        return CoverageData{};
    }
    
private:
    std::map<std::string, CoverageData> coverage_map;
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