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
    EXTEND_ALTERNATION,
    REMOVE_QUANTIFIER,
    ALTER_ALTERNATIVE,
    FLATTEN_QUANTIFIED_ALT,
    UNWRAP_FRAGMENT_REF,
    SEQUENCE_TO_ALTERNATION,
    INLINE_FRAGMENT,
    SWAP_SEQUENCE_CHILDREN,
};

struct CoordinatedMutationResult {
    TestCaseCore mutated_tc = {};
    std::string proof = {};
    bool valid = false;
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

class ExtendAlternationCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::EXTEND_ALTERNATION; }
    std::string name() const override { return "EXTEND_ALTERNATION_COORD"; }
    bool isGeneralizing() const override { return true; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

class RemoveQuantifierCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::REMOVE_QUANTIFIER; }
    std::string name() const override { return "REMOVE_QUANTIFIER_COORD"; }
    bool isGeneralizing() const override { return false; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

class AlterAlternativeCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::ALTER_ALTERNATIVE; }
    std::string name() const override { return "ALTER_ALTERNATIVE_COORD"; }
    bool isGeneralizing() const override { return false; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

class FlattenQuantifiedAltCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::FLATTEN_QUANTIFIED_ALT; }
    std::string name() const override { return "FLATTEN_QUANTIFIED_ALT_COORD"; }
    bool isGeneralizing() const override { return true; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

class UnwrapFragmentRefCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::UNWRAP_FRAGMENT_REF; }
    std::string name() const override { return "UNWRAP_FRAGMENT_REF_COORD"; }
    bool isGeneralizing() const override { return false; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

class SequenceToAlternationCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::SEQUENCE_TO_ALTERNATION; }
    std::string name() const override { return "SEQUENCE_TO_ALTERNATION_COORD"; }
    bool isGeneralizing() const override { return true; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

class QuantifyAlternationCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::NEST_QUANTIFIER; }
    std::string name() const override { return "QUANTIFY_ALTERNATION_COORD"; }
    bool isGeneralizing() const override { return true; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

class PrefixSuffixAlternationCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::EXTEND_SEQUENCE; }
    std::string name() const override { return "PREFIX_SUFFIX_ALT_COORD"; }
    bool isGeneralizing() const override { return true; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

// Extract a substring from a literal into a fragment reference.
// E.g., literal "abcde" -> sequence "ab" + fragment_ref("fgX") + "de"
// with fragment fgX = "c". Preserves semantics but tests fragment handling.
class ExtractFragmentCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::UNWRAP_FRAGMENT_REF; }
    std::string name() const override { return "EXTRACT_FRAGMENT_COORD"; }
    bool isGeneralizing() const override { return false; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

// Insert redundant grouping around a sub-expression.
// E.g., "abc" -> "(abc)". Preserves matching semantics.
class RedundantGroupCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::DEEPEN_NESTING; }
    std::string name() const override { return "REDUNDANT_GROUP_COORD"; }
    bool isGeneralizing() const override { return false; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

// Swap order of alternatives in an alternation.
// E.g., (a|b|c) -> (c|a|b). Preserves matching semantics.
class SwapAlternativesCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::ALTER_ALTERNATIVE; }
    std::string name() const override { return "SWAP_ALTERNATIVES_COORD"; }
    bool isGeneralizing() const override { return false; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

// Replace a [[fragment]] reference with its literal definition.
// E.g., if fragX = a|b|c, then [[fragX]] becomes (a|b|c).
// Preserves matching semantics (fragment ref is equivalent to its definition).
class InlineFragmentCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::INLINE_FRAGMENT; }
    std::string name() const override { return "INLINE_FRAGMENT"; }
    bool isGeneralizing() const override { return false; }
    CoordinatedMutationResult apply(const TestCaseCore& original, std::mt19937& rng) const override;
};

// Swap two adjacent children in a SEQUENCE node.
// E.g., (A B C) -> (A C B). The pipeline must handle permuted concatenation order.
// Matching inputs are re-checked via PatternMatcher; reject if fewer than 1 survives.
class SwapSequenceChildrenCoordOp : public CoordinatedMutationOperator {
public:
    CoordinatedMutationType type() const override { return CoordinatedMutationType::SWAP_SEQUENCE_CHILDREN; }
    std::string name() const override { return "SWAP_SEQUENCE_CHILDREN"; }
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