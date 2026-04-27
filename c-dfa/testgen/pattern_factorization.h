#ifndef PATTERN_FACTORIZATION_H
#define PATTERN_FACTORIZATION_H

#include "testgen.h"

namespace PatternFactorization {
    // Fragment name generator - uses incrementing counter to avoid collisions
    std::string nextFragName();

    std::string findCommonPrefix(const std::vector<std::string>& strings);
    std::string findCommonSuffix(const std::vector<std::string>& strings);
    std::map<std::string, std::vector<std::string>> groupByPrefix(const std::vector<std::string>& alternatives, size_t prefix_len);
    std::map<std::string, std::vector<std::string>> groupBySuffix(const std::vector<std::string>& alternatives, size_t suffix_len);
    std::shared_ptr<PatternNode> factorPattern(std::shared_ptr<PatternNode> node, int depth, FactorizationProof* proof_out = nullptr);
    std::shared_ptr<PatternNode> applyFactorization(std::shared_ptr<PatternNode> root, std::mt19937& rng, FactorizationProof* proof_out = nullptr);
    std::shared_ptr<PatternNode> applyRandomStars(std::shared_ptr<PatternNode> root, std::mt19937& rng);
    std::pair<std::shared_ptr<PatternNode>, std::map<std::string, std::string>> applyComplexRewrites(std::shared_ptr<PatternNode> root, std::mt19937& rng, std::string& proof_out);
    std::shared_ptr<PatternNode> copyPatternNode(std::shared_ptr<PatternNode> node);
    std::string detectStarInsertions(std::shared_ptr<PatternNode> before, std::shared_ptr<PatternNode> after, const std::string& context);
}

#endif // PATTERN_FACTORIZATION_H