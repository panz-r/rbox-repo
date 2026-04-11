#ifndef INDUCTIVE_BUILDER_H
#define INDUCTIVE_BUILDER_H

#include <string>
#include <vector>
#include <memory>
#include <random>

// Forward declarations
struct PatternNode;

// ============================================================================
// InductiveBuilder - Constraint-Propagating Pattern AST Construction
// ============================================================================

namespace InductiveBuilder {

struct InputState {
    std::string full_input;
    std::string remaining;
    bool is_matching;
    
    InputState(const std::string& input, bool matching);
};

struct BuildResult {
    std::shared_ptr<PatternNode> ast;
    std::string proof;
    bool success;
    
    BuildResult();
    BuildResult(std::shared_ptr<PatternNode> a, const std::string& p, bool s);
};

std::string commonPrefix(const std::vector<std::string>& strings);
std::string findDistinguishingPrefix(const std::vector<InputState>& matching_states,
                                      const std::vector<InputState>& counter_states);

BuildResult makeAlternation(const std::vector<InputState>& matching_states,
                            const std::vector<InputState>& counter_states);

BuildResult buildRecursive(std::vector<InputState> matching_states,
                          std::vector<InputState> counter_states,
                          int depth,
                          std::mt19937& rng);

BuildResult buildInductive(const std::vector<std::string>& matching,
                          const std::vector<std::string>& counters,
                          std::mt19937& rng);

} // namespace InductiveBuilder

#endif // INDUCTIVE_BUILDER_H