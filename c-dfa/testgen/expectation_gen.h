#ifndef EXPECTATION_GEN_H
#define EXPECTATION_GEN_H

#include <string>
#include <vector>
#include <map>
#include <memory>

// Forward declarations
struct PatternNode;
enum class ExpectationType;
struct Expectation;

// ============================================================================
// Expectation Generation - Deep Semantic Verification
// ============================================================================

std::string expectationTypeToString(ExpectationType type);

bool hasFragment(const std::string& pattern);
bool hasQuantifier(const std::string& pattern, char quant);
bool hasStarQuantifier(const std::string& pattern);
bool hasPlusQuantifier(const std::string& pattern);
bool hasOptional(const std::string& pattern);
bool hasAlternation(const std::string& pattern);
bool hasCaptureTags(const std::string& pattern);
std::string extractAlternatives(const std::string& pattern);
std::vector<std::string> splitAlternatives(const std::string& alternation);

std::vector<Expectation> generateFragmentExpectations(const std::string& pattern,
                                                     const std::map<std::string, std::string>& fragments,
                                                     const std::vector<std::string>& matching,
                                                     const std::vector<std::string>& counters);

std::vector<Expectation> generateQuantifierExpectations(const std::string& pattern,
                                                       const std::vector<std::string>& matching,
                                                       const std::vector<std::string>& counters);

std::vector<Expectation> generateAlternationExpectations(const std::string& pattern,
                                                         const std::vector<std::string>& matching,
                                                         const std::vector<std::string>& counters);

std::vector<Expectation> generateCaptureTagExpectations(const std::string& pattern,
                                                       const std::vector<std::string>& matching,
                                                       const std::vector<std::string>& counters);

std::vector<Expectation> generateCharClassExpectations(const std::string& pattern,
                                                       const std::vector<std::string>& matching,
                                                       const std::vector<std::string>& counters);

void collectExpectationsFromNode(std::shared_ptr<PatternNode> node,
                                std::vector<Expectation>& expectations,
                                const std::string& prefix,
                                int depth);

std::vector<Expectation> generateExpectationsFromAST(std::shared_ptr<PatternNode> ast,
                                                     const std::map<std::string, std::string>& fragments,
                                                     const std::vector<std::string>& matching,
                                                     const std::vector<std::string>& counters);

std::vector<Expectation> generateAllExpectations(const std::string& pattern,
                                                  const std::map<std::string, std::string>& fragments,
                                                  const std::vector<std::string>& matching,
                                                  const std::vector<std::string>& counters);

#endif // EXPECTATION_GEN_H