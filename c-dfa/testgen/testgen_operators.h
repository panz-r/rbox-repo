#ifndef TESTGEN_OPERATORS_H
#define TESTGEN_OPERATORS_H

#include "testgen_core.h"
#include <random>
#include <vector>
#include <functional>

namespace TestGen {

// ============================================================================
// Coordinated Mutation Operators - ONE atomic planned change
//
// Each operator plans the COMPLETE mutation as ONE atomic transformation:
// - pattern_change + input_changes + counter_changes + expectation_changes
// - All must be planned TOGETHER to produce a passing test case
// - Reject (return invalid) if a coherent passing plan can't be produced
//
// The mutation IS the plan - reasoning is part of the mutation
// ============================================================================

enum class CoordinatedMutationType {
    CHAR_SUBSTITUTE,
    ADD_ALTERNATIVE,
    NEST_QUANTIFIER,
    EXTEND_SEQUENCE,
    DEEPEN_NESTING,
    SPLIT_ALTERNATION,
};

struct CoordinatedMutationResult {
    TestCaseCore mutated_tc;
    std::string proof;
    bool valid;
};

class CoordinatedMutationOperator {
public:
    virtual ~CoordinatedMutationOperator() = default;
    
    virtual CoordinatedMutationType type() const = 0;
    virtual std::string name() const = 0;
    virtual CoordinatedMutationResult apply(
        const TestCaseCore& original,
        std::mt19937& rng
    ) const = 0;
    virtual bool isGeneralizing() const = 0;
};

class CharSubstituteCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::CHAR_SUBSTITUTE; }
    std::string name() const override { return "CHAR_SUBSTITUTE_COORD"; }
    bool isGeneralizing() const override { return false; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

class AddAlternativeCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::ADD_ALTERNATIVE; }
    std::string name() const override { return "ADD_ALTERNATIVE_COORD"; }
    bool isGeneralizing() const override { return true; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

class NestQuantifierCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::NEST_QUANTIFIER; }
    std::string name() const override { return "NEST_QUANTIFIER_COORD"; }
    bool isGeneralizing() const override { return true; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

class ExtendSequenceCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::EXTEND_SEQUENCE; }
    std::string name() const override { return "EXTEND_SEQUENCE_COORD"; }
    bool isGeneralizing() const override { return false; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

class DeepenNestingCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::DEEPEN_NESTING; }
    std::string name() const override { return "DEEPEN_NESTING_COORD"; }
    bool isGeneralizing() const override { return true; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

class SplitAlternationCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::SPLIT_ALTERNATION; }
    std::string name() const override { return "SPLIT_ALTERNATION_COORD"; }
    bool isGeneralizing() const override { return true; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

class CutBasedCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::EXTEND_SEQUENCE; }
    std::string name() const override { return "CUT_BASED_COORD"; }
    bool isGeneralizing() const override { return false; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

class CoordinatedMutationEngine {
public:
    CoordinatedMutationEngine();
    
    std::vector<CoordinatedMutationResult> mutate(
        const TestCaseCore& tc,
        size_t max_results,
        std::mt19937& rng
    ) const;
    
    static std::vector<std::unique_ptr<CoordinatedMutationOperator>> allOperators();
    
private:
    std::vector<std::unique_ptr<CoordinatedMutationOperator>> operators;
};

} // namespace TestGen

#endif // TESTGEN_OPERATORS_H