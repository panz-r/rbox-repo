#include "testgen_mutation_tree.h"
#include "pattern_serializer.h"
#include <algorithm>
#include <cmath>

namespace TestGen {

static size_t countAlternatives(std::shared_ptr<PatternNode> node) {
    if (!node) return 0;
    if (node->type == PatternType::ALTERNATION) return node->children.size();
    size_t count = 0;
    if (node->quantified) count += countAlternatives(node->quantified);
    for (auto& child : node->children) count += countAlternatives(child);
    return count;
}

static size_t countQuantifiers(std::shared_ptr<PatternNode> node) {
    if (!node) return 0;
    size_t count = 0;
    if (node->type == PatternType::PLUS_QUANTIFIER ||
        node->type == PatternType::STAR_QUANTIFIER ||
        node->type == PatternType::OPTIONAL) {
        count = 1;
    }
    if (node->quantified) count += countQuantifiers(node->quantified);
    for (auto& child : node->children) count += countQuantifiers(child);
    return count;
}

static size_t countFragments(std::shared_ptr<PatternNode> node) {
    if (!node) return 0;
    size_t count = 0;
    if (node->type == PatternType::FRAGMENT_REF) count = 1;
    if (node->quantified) count += countFragments(node->quantified);
    for (auto& child : node->children) count += countFragments(child);
    return count;
}

static bool hasNestedQuantifiers(std::shared_ptr<PatternNode> node) {
    if (!node) return false;
    if ((node->type == PatternType::PLUS_QUANTIFIER ||
         node->type == PatternType::STAR_QUANTIFIER) &&
        node->quantified &&
        (node->quantified->type == PatternType::PLUS_QUANTIFIER ||
         node->quantified->type == PatternType::STAR_QUANTIFIER ||
         node->quantified->type == PatternType::OPTIONAL)) {
        return true;
    }
    if (node->quantified && hasNestedQuantifiers(node->quantified)) return true;
    for (auto& child : node->children) {
        if (hasNestedQuantifiers(child)) return true;
    }
    return false;
}

double defaultScoreFunction(const TestCaseCore& tc) {
    double score = 0.0;
    
    if (tc.ast) {
        score += countAlternatives(tc.ast) * 2.0;
        score += countQuantifiers(tc.ast) * 1.5;
        score += countFragments(tc.ast) * 3.0;
        if (hasNestedQuantifiers(tc.ast)) score += 10.0;
    }
    
    score += tc.expectations.total() * 0.5;
    
    return score;
}

MutationTree::MutationTree() : root_(nullptr), coverage(nullptr) {}

void MutationTree::setSeed(const TestCaseCore& seed) {
    if (root_) delete root_;
    root_ = new MutationTreeNode(seed);
}

void MutationTree::setCoverageTracker(DFACoverageTracker* tracker) {
    coverage = tracker;
}

std::vector<TestCaseCore> MutationTree::scoreAndRank(
    const std::vector<TestCaseCore>& candidates,
    std::mt19937& rng
) {
    std::vector<std::pair<TestCaseCore, double>> scored;
    for (const auto& tc : candidates) {
        double s = defaultScoreFunction(tc);
        if (coverage) {
            s += coverage->coverageGain(tc) * 100.0;
        }
        scored.push_back({tc, s});
    }
    
    std::sort(scored.begin(), scored.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    std::vector<TestCaseCore> result;
    for (auto& p : scored) result.push_back(p.first);
    return result;
}

void MutationTree::grow(
    MutationTreeNode* from,
    size_t branching_factor,
    std::mt19937& rng
) {
    if (!from || from->depth >= 10) return;
    
    std::vector<TestCaseCore> candidates;
    
    auto mutations = mutation_engine.mutate(from->tc.ast, branching_factor, rng);
    for (auto& m : mutations) {
        if (m.success) {
            TestCaseCore child = from->tc;
            child.ast = m.ast;
            child.proof += " | " + m.description;
            candidates.push_back(child);
        }
    }
    
    auto generations = generation_engine.generate(from->tc.ast, branching_factor, rng);
    for (auto& g : generations) {
        if (g.success) {
            TestCaseCore child = from->tc;
            child.ast = g.ast;
            child.fragments.insert(g.new_fragments.begin(), g.new_fragments.end());
            child.proof += " | " + g.description;
            candidates.push_back(child);
        }
    }
    
    auto ranked = scoreAndRank(candidates, rng);
    
    size_t to_add = std::min(branching_factor, ranked.size());
    for (size_t i = 0; i < to_add; ++i) {
        auto* child_node = new MutationTreeNode(ranked[i], from);
        from->children.push_back(child_node);
    }
}

void MutationTree::prune(
    MutationTreeNode* at,
    size_t keep,
    std::function<double(const TestCaseCore&)> score_fn
) {
    if (!at) return;
    
    std::vector<std::pair<MutationTreeNode*, double>> scored;
    for (auto* child : at->children) {
        double s = score_fn(child->tc);
        if (coverage) {
            s += coverage->coverageGain(child->tc) * 100.0;
        }
        child->score = s;
        scored.push_back({child, s});
    }
    
    std::sort(scored.begin(), scored.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    std::vector<MutationTreeNode*> kept;
    for (size_t i = 0; i < keep && i < scored.size(); ++i) {
        kept.push_back(scored[i].first);
    }
    
    for (auto* child : at->children) {
        if (std::find(kept.begin(), kept.end(), child) == kept.end()) {
            delete child;
        }
    }
    
    at->children = kept;
}

void MutationTree::iterate(
    size_t max_depth,
    size_t branching_factor,
    size_t keep_per_level,
    std::mt19937& rng
) {
    if (!root_) return;
    
    std::vector<MutationTreeNode*> frontier = {root_};
    
    for (int depth = 0; depth < (int)max_depth && !frontier.empty(); ++depth) {
        std::vector<MutationTreeNode*> new_frontier;
        
        for (auto* node : frontier) {
            grow(node, branching_factor, rng);
        }
        
        for (auto* node : frontier) {
            if (!node->children.empty()) {
                prune(node, keep_per_level, defaultScoreFunction);
                for (auto* child : node->children) {
                    new_frontier.push_back(child);
                }
            }
        }
        
        frontier = new_frontier;
        
        if (coverage && coverage->plateaued()) {
            break;
        }
    }
}

std::vector<TestCaseCore> MutationTree::getFrontier() const {
    std::vector<TestCaseCore> result;
    if (!root_) return result;
    
    std::function<void(MutationTreeNode*)> collect = [&](MutationTreeNode* node) {
        if (node->children.empty()) {
            result.push_back(node->tc);
        } else {
            for (auto* child : node->children) {
                collect(child);
            }
        }
    };
    
    collect(root_);
    return result;
}

std::vector<TestCaseCore> MutationTree::getAll() const {
    std::vector<TestCaseCore> result;
    if (!root_) return result;
    
    std::function<void(MutationTreeNode*)> collect = [&](MutationTreeNode* node) {
        result.push_back(node->tc);
        for (auto* child : node->children) {
            collect(child);
        }
    };
    
    collect(root_);
    return result;
}

} // namespace TestGen