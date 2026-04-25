// ============================================================================
// PatternMatcher - Fast in-memory pattern matching using NFA simulation
//
// Matches PatternNode ASTs against input strings. Uses NFA-style set-of-
// positions tracking: each match step produces the set of reachable input
// positions. A full match is when any position equals input.size().
//
// Handles: LITERAL, ALTERNATION, SEQUENCE, PLUS/STAR/OPTIONAL, FRAGMENT_REF.
// ============================================================================

#ifndef PATTERN_MATCHER_H
#define PATTERN_MATCHER_H

#include <string>
#include <memory>
#include <vector>
#include <set>
#include <map>

struct PatternNode;

/**
 * Fast AST-based pattern matcher for test case validation.
 */
class PatternMatcher {
public:
    /**
     * Check if a pattern AST fully matches an input string.
     * Full match = the entire input is consumed.
     */
    static bool matches(const std::shared_ptr<PatternNode>& pattern, const std::string& input);

    /**
     * Validate a pattern against sets of matching and counter inputs.
     * @return true if ALL matching_inputs match AND NO counter_inputs match.
     */
    static bool validate(const std::shared_ptr<PatternNode>& pattern,
                        const std::vector<std::string>& matching_inputs,
                        const std::vector<std::string>& counter_inputs);

    /**
     * Validate with fragment definitions. Fragment refs are resolved
     * by looking up their definition in the fragments map, parsing it,
     * and matching against that sub-pattern.
     */
    static bool validateWithFragments(
        const std::shared_ptr<PatternNode>& pattern,
        const std::vector<std::string>& matching_inputs,
        const std::vector<std::string>& counter_inputs,
        const std::map<std::string, std::string>& fragments);

    /**
     * Diagnostic: explain why validation failed.
     * Returns empty string on success.
     */
    static std::string explainFailure(
        const std::shared_ptr<PatternNode>& pattern,
        const std::vector<std::string>& matching_inputs,
        const std::vector<std::string>& counter_inputs,
        const std::map<std::string, std::string>& fragments = {});
};

#endif // PATTERN_MATCHER_H
