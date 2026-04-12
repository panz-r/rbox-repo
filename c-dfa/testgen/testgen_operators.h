#ifndef TESTGEN_OPERATORS_H
#define TESTGEN_OPERATORS_H

#include "testgen_core.h"
#include <random>
#include <vector>
#include <functional>

namespace TestGen {

// ============================================================================
// Mutation Operators - Local changes to existing patterns
// ============================================================================

enum class MutationType {
    CHAR_SUBSTITUTE,
    CHAR_INSERT,
    CHAR_DELETE,
    CLASS_EXPAND,
    CLASS_REDUCE,
    QUANTIFIER_GREEDY_LAZY,
    OPTIONAL_INSERT,
    GROUP_INSERT,
    GROUP_REMOVE,
    ESCAPE_INSERT,
    ESCAPE_REMOVE,
};

struct MutationResult {
    std::shared_ptr<PatternNode> ast;
    std::string description;
    bool success;
};

class MutationOperator {
public:
    virtual ~MutationOperator() = default;
    
    virtual MutationType type() const = 0;
    virtual MutationResult apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const = 0;
    virtual std::string name() const = 0;
};

class CharSubstituteOp : public MutationOperator {
public:
    MutationType type() const override { return MutationType::CHAR_SUBSTITUTE; }
    MutationResult apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "CHAR_SUBSTITUTE"; }
};

class CharInsertOp : public MutationOperator {
public:
    MutationType type() const override { return MutationType::CHAR_INSERT; }
    MutationResult apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "CHAR_INSERT"; }
};

class CharDeleteOp : public MutationOperator {
public:
    MutationType type() const override { return MutationType::CHAR_DELETE; }
    MutationResult apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "CHAR_DELETE"; }
};

class ClassExpandOp : public MutationOperator {
public:
    MutationType type() const override { return MutationType::CLASS_EXPAND; }
    MutationResult apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "CLASS_EXPAND"; }
};

class ClassReduceOp : public MutationOperator {
public:
    MutationType type() const override { return MutationType::CLASS_REDUCE; }
    MutationResult apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "CLASS_REDUCE"; }
};

class QuantifierGreedyLazyOp : public MutationOperator {
public:
    MutationType type() const override { return MutationType::QUANTIFIER_GREEDY_LAZY; }
    MutationResult apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "QUANTIFIER_GREEDY_LAZY"; }
};

class OptionalInsertOp : public MutationOperator {
public:
    MutationType type() const override { return MutationType::OPTIONAL_INSERT; }
    MutationResult apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "OPTIONAL_INSERT"; }
};

class GroupInsertOp : public MutationOperator {
public:
    MutationType type() const override { return MutationType::GROUP_INSERT; }
    MutationResult apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "GROUP_INSERT"; }
};

class GroupRemoveOp : public MutationOperator {
public:
    MutationType type() const override { return MutationType::GROUP_REMOVE; }
    MutationResult apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "GROUP_REMOVE"; }
};

class EscapeInsertOp : public MutationOperator {
public:
    MutationType type() const override { return MutationType::ESCAPE_INSERT; }
    MutationResult apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "ESCAPE_INSERT"; }
};

class EscapeRemoveOp : public MutationOperator {
public:
    MutationType type() const override { return MutationType::ESCAPE_REMOVE; }
    MutationResult apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "ESCAPE_REMOVE"; }
};

class MutationEngine {
public:
    MutationEngine();
    
    std::vector<MutationResult> mutate(
        std::shared_ptr<PatternNode> ast,
        size_t max_mutations,
        std::mt19937& rng
    ) const;
    
    static std::vector<std::unique_ptr<MutationOperator>> allOperators();
    
private:
    std::vector<std::unique_ptr<MutationOperator>> operators;
};

// ============================================================================
// Generation Operators - Adds elements, grows patterns
// ============================================================================

enum class GenerationType {
    ADD_ALTERNATIVE,
    EXTEND_SEQUENCE,
    NEST_QUANTIFIER,
    ADD_PREFIX,
    ADD_SUFFIX,
    LITERAL_TO_FRAGMENT,
    SPLIT_ALTERNATION,
    DEEPEN_NESTING,
};

struct GenerationResult {
    std::shared_ptr<PatternNode> ast;
    std::map<std::string, std::string> new_fragments;
    std::string description;
    bool success;
};

class GenerationOperator {
public:
    virtual ~GenerationOperator() = default;
    
    virtual GenerationType type() const = 0;
    virtual GenerationResult generate(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const = 0;
    virtual std::string name() const = 0;
};

class AddAlternativeOp : public GenerationOperator {
public:
    GenerationType type() const override { return GenerationType::ADD_ALTERNATIVE; }
    GenerationResult generate(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "ADD_ALTERNATIVE"; }
};

class ExtendSequenceOp : public GenerationOperator {
public:
    GenerationType type() const override { return GenerationType::EXTEND_SEQUENCE; }
    GenerationResult generate(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "EXTEND_SEQUENCE"; }
};

class NestQuantifierOp : public GenerationOperator {
public:
    GenerationType type() const override { return GenerationType::NEST_QUANTIFIER; }
    GenerationResult generate(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "NEST_QUANTIFIER"; }
};

class AddPrefixOp : public GenerationOperator {
public:
    GenerationType type() const override { return GenerationType::ADD_PREFIX; }
    GenerationResult generate(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "ADD_PREFIX"; }
};

class AddSuffixOp : public GenerationOperator {
public:
    GenerationType type() const override { return GenerationType::ADD_SUFFIX; }
    GenerationResult generate(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "ADD_SUFFIX"; }
};

class LiteralToFragmentOp : public GenerationOperator {
public:
    GenerationType type() const override { return GenerationType::LITERAL_TO_FRAGMENT; }
    GenerationResult generate(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "LITERAL_TO_FRAGMENT"; }
};

class SplitAlternationOp : public GenerationOperator {
public:
    GenerationType type() const override { return GenerationType::SPLIT_ALTERNATION; }
    GenerationResult generate(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "SPLIT_ALTERNATION"; }
};

class DeepenNestingOp : public GenerationOperator {
public:
    GenerationType type() const override { return GenerationType::DEEPEN_NESTING; }
    GenerationResult generate(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const override;
    std::string name() const override { return "DEEPEN_NESTING"; }
};

class GenerationEngine {
public:
    GenerationEngine();
    
    std::vector<GenerationResult> generate(
        std::shared_ptr<PatternNode> ast,
        size_t max_variants,
        std::mt19937& rng
    ) const;
    
    static std::vector<std::unique_ptr<GenerationOperator>> allOperators();
    
private:
    std::vector<std::unique_ptr<GenerationOperator>> operators;
};

} // namespace TestGen

#endif // TESTGEN_OPERATORS_H