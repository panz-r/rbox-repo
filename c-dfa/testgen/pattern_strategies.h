#ifndef PATTERN_STRATEGIES_H
#define PATTERN_STRATEGIES_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <random>

// Forward declarations
struct PatternNode;
struct Expectation;
enum class PatternType;
enum class ExpectationType;

// ============================================================================
// Pattern Result - Return type for all pattern generation strategies
// ============================================================================

struct PatternResult {
    std::string pattern;
    std::map<std::string, std::string> fragments;
    std::string proof;
    std::vector<Expectation> expectations;
    std::shared_ptr<PatternNode> ast;
};

// ============================================================================
// Pattern Strategies - 30 pattern generation strategies
// ============================================================================

// Strategy 1: Literal (exact match)
PatternResult tryLiteral(const std::vector<std::string>& matching,
                       const std::vector<std::string>& counters,
                       std::mt19937& rng);

// Strategy 2: Alternation of all
PatternResult tryAlternation(const std::vector<std::string>& matching,
                           const std::vector<std::string>& counters,
                           std::mt19937& rng);

// Strategy 3: Repetition pattern
PatternResult tryRepetition(const std::vector<std::string>& matching,
                           const std::vector<std::string>& counters,
                           std::mt19937& rng);

// Strategy 4: Prefix plus fragment
PatternResult tryPrefixPlusFragment(const std::vector<std::string>& matching,
                                  const std::vector<std::string>& counters,
                                  std::mt19937& rng);

// Strategy 5: Suffix plus fragment
PatternResult trySuffixPlusFragment(const std::vector<std::string>& matching,
                                  const std::vector<std::string>& counters,
                                  std::mt19937& rng);

// Strategy 6: Two-part fragment
PatternResult tryTwoPartFragment(const std::vector<std::string>& matching,
                               const std::vector<std::string>& counters,
                               std::mt19937& rng);

// Strategy 7: Fragment-only
PatternResult tryFragmentOnly(const std::vector<std::string>& matching,
                            const std::vector<std::string>& counters,
                            std::mt19937& rng);

// Strategy 8: Optional quantifier
PatternResult tryOptionalQuantifier(const std::vector<std::string>& matching,
                                  const std::vector<std::string>& counters,
                                  std::mt19937& rng);

// Strategy 9: Empty alternative
PatternResult tryEmptyAlternative(const std::vector<std::string>& matching,
                                 const std::vector<std::string>& counters,
                                 std::mt19937& rng);

// Strategy 10: Nested group
PatternResult tryNestedGroup(const std::vector<std::string>& matching,
                           const std::vector<std::string>& counters,
                           std::mt19937& rng,
                           const std::string& prefix = "");

// Strategy 11: Multi-char fragment
PatternResult tryMultiCharFragment(const std::vector<std::string>& matching,
                                 const std::vector<std::string>& counters,
                                 std::mt19937& rng);

// Strategy 12: Alternation with quantifier
PatternResult tryAlternationWithQuantifier(const std::vector<std::string>& matching,
                                         const std::vector<std::string>& counters,
                                         std::mt19937& rng);

// Strategy 13: Sequence with quantifier
PatternResult trySequenceWithQuantifier(const std::vector<std::string>& matching,
                                      const std::vector<std::string>& counters,
                                      std::mt19937& rng);

// Strategy 14: Optional sequence
PatternResult tryOptionalSequence(const std::vector<std::string>& matching,
                                const std::vector<std::string>& counters,
                                std::mt19937& rng);

// Strategy 15: Nested quantifiers
PatternResult tryNestedQuantifiers(const std::vector<std::string>& matching,
                                 const std::vector<std::string>& counters,
                                 std::mt19937& rng);

// Strategy 16: Char class sequence
PatternResult tryCharClassSequence(const std::vector<std::string>& matching,
                                 const std::vector<std::string>& counters,
                                 std::mt19937& rng);

// Strategy 17: Star quantifier
PatternResult tryStarQuantifier(const std::vector<std::string>& matching,
                               const std::vector<std::string>& counters,
                               std::mt19937& rng);

// Strategy 18: Char class plus
PatternResult tryCharClassPlus(const std::vector<std::string>& matching,
                              const std::vector<std::string>& counters,
                              std::mt19937& rng);

// Strategy 19: Mixed quantifiers
PatternResult tryMixedQuantifiers(const std::vector<std::string>& matching,
                                const std::vector<std::string>& counters,
                                std::mt19937& rng);

// Strategy 20: Fragment chaining
PatternResult tryFragmentChaining(const std::vector<std::string>& matching,
                                 const std::vector<std::string>& counters,
                                 std::mt19937& rng);

// Strategy 21: Deep nesting
PatternResult tryDeepNesting(const std::vector<std::string>& matching,
                           const std::vector<std::string>& counters,
                           std::mt19937& rng);

// Strategy 22: Multi fragment combo
PatternResult tryMultiFragmentCombo(const std::vector<std::string>& matching,
                                  const std::vector<std::string>& counters,
                                  std::mt19937& rng);

// Strategy 23: Nested alternation
PatternResult tryNestedAlternation(const std::vector<std::string>& matching,
                                 const std::vector<std::string>& counters,
                                 std::mt19937& rng);

// Strategy 24: Quantifier stack
PatternResult tryQuantifierStack(const std::vector<std::string>& matching,
                               const std::vector<std::string>& counters,
                               std::mt19937& rng);

// Strategy 25: Long alternation
PatternResult tryLongAlternation(const std::vector<std::string>& matching,
                               const std::vector<std::string>& counters,
                               std::mt19937& rng);

// Strategy 26: Alternation with affix
PatternResult tryAltWithAffix(const std::vector<std::string>& matching,
                             const std::vector<std::string>& counters,
                             std::mt19937& rng);

// Strategy 27: Triple quantifier
PatternResult tryTripleQuant(const std::vector<std::string>& matching,
                           const std::vector<std::string>& counters,
                           std::mt19937& rng);

// Strategy 28: Complex alternation
PatternResult tryComplexAlternation(const std::vector<std::string>& matching,
                                  const std::vector<std::string>& counters,
                                  std::mt19937& rng);

// Strategy 29: Capture tags
PatternResult tryCaptureTags(const std::vector<std::string>& matching,
                           const std::vector<std::string>& counters,
                           std::mt19937& rng);

// Strategy 30: Single char fragment
PatternResult trySingleCharFragment(const std::vector<std::string>& matching,
                                  const std::vector<std::string>& counters,
                                  std::mt19937& rng);

// Post-processing: Apply edge cases with probability
PatternResult applyEdgeCases(const PatternResult& base,
                           const std::vector<std::string>& matching,
                           const std::vector<std::string>& counters,
                           std::mt19937& rng);

#endif // PATTERN_STRATEGIES_H