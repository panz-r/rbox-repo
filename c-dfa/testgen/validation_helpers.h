#ifndef VALIDATION_HELPERS_H
#define VALIDATION_HELPERS_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <random>

struct PatternNode;
enum class PatternType;
enum class ExpectationType;
struct Expectation;

struct PatternResult {
    std::string pattern;
    std::map<std::string, std::string> fragments;
    std::string proof;
    std::vector<Expectation> expectations;
    std::shared_ptr<PatternNode> ast;
};

bool patternMatchesLiteral(const std::string& literal, const std::string& str);
bool patternMatchesOptional(const std::string& content, const std::string& str);
bool patternMatchesPlus(const std::string& content, const std::string& str);
bool patternMatchesStar(const std::string& content, const std::string& str);
bool patternMatchesCharClass(const std::string& char_class, const std::string& str);

std::shared_ptr<PatternNode> createQuantifiedAlternation(
    const std::vector<std::string>& alts, PatternType type, const std::vector<std::string>& seeds);
std::shared_ptr<PatternNode> createQuantifiedLiteral(
    const std::string& literal, PatternType type, const std::vector<std::string>& seeds);
std::shared_ptr<PatternNode> createQuantifiedFragment(
    const std::string& frag_name, PatternType type, const std::vector<std::string>& seeds);
std::shared_ptr<PatternNode> createAlternationPlus(const std::vector<std::string>& alts, const std::vector<std::string>& seeds);
std::shared_ptr<PatternNode> createAlternationStar(const std::vector<std::string>& alts, const std::vector<std::string>& seeds);
std::shared_ptr<PatternNode> createAlternationOptional(const std::vector<std::string>& alts, const std::vector<std::string>& seeds);
std::shared_ptr<PatternNode> createLiteralPlus(const std::string& literal, const std::vector<std::string>& seeds);
std::shared_ptr<PatternNode> createLiteralStar(const std::string& literal, const std::vector<std::string>& seeds);
std::shared_ptr<PatternNode> createLiteralOptional(const std::string& literal, const std::vector<std::string>& seeds);
std::shared_ptr<PatternNode> createFragmentPlus(const std::string& frag_name, const std::vector<std::string>& seeds);
std::shared_ptr<PatternNode> createFragmentStar(const std::string& frag_name, const std::vector<std::string>& seeds);
std::shared_ptr<PatternNode> wrapWithCaptureTags(std::shared_ptr<PatternNode> node, const std::string& tag_name);
std::shared_ptr<PatternNode> createCharClass(const std::string& chars, const std::vector<std::string>& seeds);
std::shared_ptr<PatternNode> createCharClassPlus(const std::string& chars, const std::vector<std::string>& seeds);
std::shared_ptr<PatternNode> createSequenceNode(const std::vector<std::shared_ptr<PatternNode>>& nodes, const std::vector<std::string>& seeds);

std::string extractFragment(const std::string& char_class, 
                          std::map<std::string, std::string>& fragments,
                          std::mt19937& rng,
                          bool force_simple = false);

#endif // VALIDATION_HELPERS_H
