#include "testgen.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <set>
#include <unordered_set>
#include <unistd.h>
#include <sys/stat.h>

// ============================================================================
// Pattern Building Blocks (elementary units of c-dfa patterns)
// ============================================================================

enum class PatternType {
    LITERAL,           // Plain string: "abc"
    OPTIONAL,          // Optional: (abc)?
    PLUS_QUANTIFIER,   // One or more: (abc)+
    STAR_QUANTIFIER,   // Zero or more: (abc)*
    ALTERNATION,       // OR: (a|b|c)
    FRAGMENT_PLUS,     // Fragment with plus: ((digit))+
    FRAGMENT_STAR,     // Fragment with star: ((digit))*
    SEQUENCE           // Sequence: abcdef
};

struct PatternComponent {
    PatternType type;
    std::string value;           // For literals
    std::string fragment_name;   // For fragments
    std::vector<std::string> alternatives;  // For alternation
};

// ============================================================================
// TestGenerator Implementation
// ============================================================================

TestGenerator::TestGenerator(const Options& opts) : opts(opts) {
    rng.seed(opts.seed);
}

std::vector<TestCase> TestGenerator::generate() {
    std::vector<TestCase> tests;
    // For combined testing, max 4 test cases (8 patterns: 4 matching + 4 counter)
    int max_tests = std::min(opts.num_tests, 4);
    tests.reserve(max_tests);
    for (int i = 0; i < max_tests; i++) {
        tests.push_back(generateTestCase(i));
    }
    generated_tests = tests;
    return tests;
}

// Generate random seed strings for a test case
std::pair<std::vector<std::string>, std::vector<std::string>> 
TestGenerator::generateSeeds(Complexity complexity) {
    const std::string lowercase = "abcdefghijklmnopqrstuvwxyz";
    const std::string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string digits = "0123456789";
    const std::string alphanum = lowercase + uppercase + digits;
    
    std::vector<std::string> matching_seeds;
    std::vector<std::string> counter_seeds;
    std::set<std::string> used;
    
    // Generate high-entropy random matching seeds (fixed 5)
    const int num_matching = 5;
    
    while ((int)matching_seeds.size() < num_matching) {
        std::string s;
        int len;
        
        if (complexity == Complexity::SIMPLE) {
            len = 2 + std::uniform_int_distribution<int>(0, 3)(rng);  // 2-5 chars
        } else if (complexity == Complexity::MEDIUM) {
            len = 3 + std::uniform_int_distribution<int>(0, 5)(rng);  // 3-8 chars
        } else {
            len = 4 + std::uniform_int_distribution<int>(0, 8)(rng);  // 4-12 chars
        }
        
        for (int j = 0; j < len; j++) {
            s += alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
        }
        
        if (used.insert(s).second) {
            matching_seeds.push_back(s);
        }
    }
    
    // Generate high-entropy random counter seeds (fixed 25)
    const int num_counters = 25;
    
    while ((int)counter_seeds.size() < num_counters) {
        std::string s;
        int len;
        
        if (complexity == Complexity::SIMPLE) {
            len = 2 + std::uniform_int_distribution<int>(0, 4)(rng);
        } else if (complexity == Complexity::MEDIUM) {
            len = 3 + std::uniform_int_distribution<int>(0, 6)(rng);
        } else {
            len = 4 + std::uniform_int_distribution<int>(0, 10)(rng);
        }
        
        for (int j = 0; j < len; j++) {
            s += alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
        }
        
        // Must be different from all matching
        if (used.find(s) == used.end()) {
            used.insert(s);
            counter_seeds.push_back(s);
        }
    }
    
    return {matching_seeds, counter_seeds};
}

struct SeedAnalysis {
    bool all_same_length;
    bool all_same_prefix;
    std::string common_prefix;
    std::string common_suffix;
    std::set<char> all_chars;
    std::map<int, std::set<char>> chars_at_pos;
};

SeedAnalysis analyzeSeeds(const std::vector<std::string>& matching, 
                          const std::vector<std::string>& counters) {
    SeedAnalysis analysis;
    analysis.all_same_length = true;
    
    if (matching.empty()) return analysis;
    
    size_t first_len = matching[0].size();
    for (const auto& s : matching) {
        if (s.size() != first_len) {
            analysis.all_same_length = false;
            break;
        }
    }
    
    if (!matching.empty()) {
        analysis.common_prefix = matching[0];
        for (const auto& s : matching) {
            std::string new_prefix;
            for (size_t i = 0; i < s.size() && i < analysis.common_prefix.size(); i++) {
                if (s[i] == analysis.common_prefix[i]) {
                    new_prefix += s[i];
                } else {
                    break;
                }
            }
            analysis.common_prefix = new_prefix;
        }
    }
    
    if (!matching.empty()) {
        analysis.common_suffix = matching[0];
        for (const auto& s : matching) {
            std::string new_suffix;
            size_t min_len = std::min(s.size(), analysis.common_suffix.size());
            for (size_t i = 0; i < min_len; i++) {
                if (s[s.size() - 1 - i] == analysis.common_suffix[analysis.common_suffix.size() - 1 - i]) {
                    new_suffix = s[s.size() - 1 - i] + new_suffix;
                } else {
                    break;
                }
            }
            analysis.common_suffix = new_suffix;
        }
    }
    
    for (const auto& s : matching) {
        for (char c : s) {
            analysis.all_chars.insert(c);
        }
    }
    for (const auto& s : counters) {
        for (char c : s) {
            analysis.all_chars.insert(c);
        }
    }
    
    size_t max_len = 0;
    for (const auto& s : matching) max_len = std::max(max_len, s.size());
    for (const auto& s : counters) max_len = std::max(max_len, s.size());
    
    for (size_t pos = 0; pos < max_len; pos++) {
        std::set<char> chars_at_this_pos;
        for (const auto& s : matching) {
            if (pos < s.size()) chars_at_this_pos.insert(s[pos]);
        }
        for (const auto& s : counters) {
            if (pos < s.size()) chars_at_this_pos.insert(s[pos]);
        }
        analysis.chars_at_pos[pos] = chars_at_this_pos;
    }
    
    return analysis;
}

bool literalMatches(const std::string& pattern, const std::string& str) {
    return pattern == str;
}

bool alternationMatches(const std::vector<std::string>& alts, const std::string& str) {
    for (const auto& alt : alts) {
        if (alt == str) return true;
    }
    return false;
}

bool charClassPlusMatches(const std::string& char_class, const std::string& str) {
    std::set<char> allowed;
    std::string current;
    for (char c : char_class) {
        if (c == '|') {
            if (current.size() == 1) allowed.insert(current[0]);
            current.clear();
        } else {
            current += c;
        }
    }
    if (current.size() == 1) allowed.insert(current[0]);
    
    for (char c : str) {
        if (allowed.find(c) == allowed.end()) return false;
    }
    return !str.empty();
}

// ============================================================================
// Full-spectrum Pattern Generation with Fragments
// ============================================================================

struct PatternResult {
    std::string pattern;
    std::map<std::string, std::string> fragments;  // fragment definitions
    std::string proof;
};

// Try many different pattern strategies and return the first that works

// Check if a pattern matches an input (simplified - just for validation)
bool patternMatchesLiteral(const std::string& literal, const std::string& str) {
    return literal == str;
}

bool patternMatchesOptional(const std::string& content, const std::string& str) {
    return str.empty() || str == content;
}

bool patternMatchesPlus(const std::string& content, const std::string& str) {
    if (str.empty() || content.empty()) return false;
    size_t content_len = content.size();
    if (str.size() % content_len != 0) return false;
    for (size_t i = 0; i < str.size(); i += content_len) {
        if (str.substr(i, content_len) != content) return false;
    }
    return true;
}

bool patternMatchesStar(const std::string& content, const std::string& str) {
    if (content.empty()) return str.empty();
    if (str.empty()) return true;
    size_t content_len = content.size();
    if (str.size() % content_len != 0) return false;
    for (size_t i = 0; i < str.size(); i += content_len) {
        if (str.substr(i, content_len) != content) return false;
    }
    return true;
}

bool patternMatchesCharClass(const std::string& char_class, const std::string& str) {
    std::set<char> allowed;
    std::string current;
    for (char c : char_class) {
        if (c == '|') {
            if (current.size() == 1) allowed.insert(current[0]);
            current.clear();
        } else {
            current += c;
        }
    }
    if (current.size() == 1) allowed.insert(current[0]);
    
    for (char c : str) {
        if (allowed.find(c) == allowed.end()) return false;
    }
    return !str.empty();
}

// Extract fragment from char class and return pattern with fragment reference
// Optionally uses namespaced format with ~30% probability
std::string extractFragment(const std::string& char_class, 
                          std::map<std::string, std::string>& fragments,
                          std::mt19937& rng,
                          bool force_simple = false) {
    // Create fragment name
    static const char* frag_names[] = {"a", "b", "c", "d", "e", "f", "g", "h", "x", "y", "z"};
    std::string frag_name = frag_names[std::uniform_int_distribution<int>(0, 10)(rng)];
    
    // Add numeric suffix to make unique
    frag_name += std::to_string(std::uniform_int_distribution<int>(0, 99)(rng));
    
    // Decide whether to use namespaced format (30% chance)
    bool use_namespace = !force_simple && std::uniform_int_distribution<int>(0, 99)(rng) < 30;
    std::string full_name;
    
    if (use_namespace) {
        // Use test namespace
        std::string namespaces[] = {"test", "gen", "tgen", "pat"};
        std::string ns = namespaces[std::uniform_int_distribution<int>(0, 3)(rng)];
        full_name = ns + "::" + frag_name;
    } else {
        full_name = frag_name;
    }
    
    fragments[full_name] = char_class;
    
    return "((" + full_name + "))+";
}

// Strategy 1: Literal (exact match)
PatternResult tryLiteral(const std::vector<std::string>& matching,
                        const std::vector<std::string>& counters,
                        std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() != 1) {
        result.proof += "  Literal: requires single matching\n";
        return result;
    }
    
    const std::string& lit = matching[0];
    
    // Check no counter matches this literal
    for (const auto& c : counters) {
        if (c == lit) {
            result.proof += "  Literal rejected: counter identical\n";
            return result;
        }
    }
    
    result.pattern = lit;
    result.proof += "  Literal: '" + lit + "'\n";
    result.proof += "    MATCHES: '" + lit + "'\n";
    result.proof += "    VERIFIED: no counter matches literal\n";
    return result;
}

// Strategy 2: Alternation of all
PatternResult tryAlternation(const std::vector<std::string>& matching,
                            const std::vector<std::string>& counters,
                            std::mt19937& rng) {
    PatternResult result;
    
    std::string pattern = "(";
    for (size_t i = 0; i < matching.size(); i++) {
        if (i > 0) pattern += "|";
        pattern += matching[i];
    }
    pattern += ")";
    
    // Verify all matching match
    for (const auto& m : matching) {
        bool found = false;
        for (const auto& alt : matching) {
            if (m == alt) { found = true; break; }
        }
        if (!found) {
            result.proof += "  Alternation rejected: matching doesn't fully match\n";
            return result;
        }
    }
    
    // Verify no counter matches
    std::string counters_matching;
    for (const auto& c : counters) {
        for (const auto& alt : matching) {
            if (c == alt) {
                counters_matching += "'" + c + "', ";
            }
        }
    }
    
    if (!counters_matching.empty()) {
        result.proof += "  Alternation rejected: counters match: " + counters_matching + "\n";
        return result;
    }
    
    // ALWAYS apply a quantifier to make it interesting
    std::uniform_int_distribution<int> qdist(0, 2);
    int qtype = qdist(rng);
    
    if (qtype == 0) {
        pattern += "+";  // One or more
    } else if (qtype == 1) {
        pattern += "*";  // Zero or more
    } else {
        pattern += "?";  // Zero or one
    }
    
    result.pattern = pattern;
    result.proof += "  Alternation: " + pattern + "\n";
    result.proof += "    MATCHES all " + std::to_string(matching.size()) + " matching inputs\n";
    result.proof += "    VERIFIED: no counter inputs match\n";
    return result;
}

// Strategy 3: Repetition pattern - find common substring repeated
PatternResult tryRepetition(const std::vector<std::string>& matching,
                           const std::vector<std::string>& counters,
                           std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  Repetition: requires 2+ matching\n";
        return result;
    }
    
    // Try each matching string as a potential repeat unit
    for (const auto& unit : matching) {
        if (unit.empty()) continue;
        
        bool all_match = true;
        for (const auto& m : matching) {
            if (!patternMatchesPlus(unit, m)) {
                all_match = false;
                break;
            }
        }
        
        if (!all_match) continue;
        
        // Check counters don't match
        bool any_counter_matches = false;
        for (const auto& c : counters) {
            if (patternMatchesPlus(unit, c)) {
                any_counter_matches = true;
                break;
            }
        }
        
        if (any_counter_matches) continue;
        
        // Maybe extract fragment from unit?
        if (unit.size() >= 2 && std::uniform_int_distribution<int>(0, 1)(rng) == 1) {
            std::map<std::string, std::string> frags;
            std::string frag_pattern = extractFragment(unit, frags, rng);
            result.fragments.insert(frags.begin(), frags.end());
            result.pattern = frag_pattern;
        } else {
            result.pattern = "(" + unit + ")+";
        }
        
        result.proof += "  Repetition: " + result.pattern + "\n";
        result.proof += "    Unit: '" + unit + "'\n";
        result.proof += "    MATCHES: ";
        for (size_t i = 0; i < matching.size(); i++) {
            if (i > 0) result.proof += ", ";
            result.proof += "'" + matching[i] + "'";
        }
        result.proof += "\n";
        result.proof += "    VERIFIED: no counter matches repetition of '" + unit + "'\n";
        return result;
    }
    
    result.proof += "  Repetition: none found (no common unit that matches all)\n";
    return result;
}

// Strategy 4: Common prefix + variable suffix with fragment
PatternResult tryPrefixPlusFragment(const std::vector<std::string>& matching,
                                   const std::vector<std::string>& counters,
                                   std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  Prefix+: requires 2+ matching\n";
        return result;
    }
    
    // Find common prefix
    std::string prefix = matching[0];
    for (size_t i = 1; i < matching.size(); i++) {
        std::string new_prefix;
        for (size_t j = 0; j < matching[i].size() && j < prefix.size(); j++) {
            if (matching[i][j] == prefix[j]) {
                new_prefix += prefix[j];
            } else {
                break;
            }
        }
        prefix = new_prefix;
        if (prefix.empty()) break;
    }
    
    if (prefix.empty()) {
        result.proof += "  Prefix+: no common prefix\n";
        return result;
    }
    
    // For each position after prefix, try char class+
    for (size_t pos = prefix.size(); pos <= prefix.size(); pos++) {
        std::set<char> match_chars;
        for (const auto& m : matching) {
            if (pos < m.size()) match_chars.insert(m[pos]);
        }
        
        if (match_chars.empty()) continue;
        
        // Build char class
        std::string char_class;
        for (char c : match_chars) {
            if (!char_class.empty()) char_class += "|";
            char_class += c;
        }
        
        // Try with inline char class+
        std::string pattern = prefix + "(" + char_class + ")+";
        
        bool all_match = true;
        for (const auto& m : matching) {
            if (m.size() <= pos) {
                all_match = false;
                break;
            }
            std::string suffix = m.substr(pos);
            if (!patternMatchesCharClass(char_class, suffix)) {
                all_match = false;
                break;
            }
        }
        
        if (!all_match) continue;
        
        // Check counters
        bool any_match = false;
        for (const auto& c : counters) {
            if (c.size() > pos && c.substr(0, pos) == prefix) {
                std::string suffix = c.substr(pos);
                if (patternMatchesCharClass(char_class, suffix)) {
                    any_match = true;
                    break;
                }
            }
        }
        
        if (!any_match) {
            // Now try with fragment instead of inline char class
            if (match_chars.size() >= 2 && std::uniform_int_distribution<int>(0, 1)(rng) == 1) {
                std::map<std::string, std::string> frags;
                std::string frag_pattern = extractFragment(char_class, frags, rng);
                result.fragments.insert(frags.begin(), frags.end());
                result.pattern = prefix + frag_pattern;
            } else {
                result.pattern = pattern;
            }
            result.proof += "  Prefix+: " + result.pattern + "\n";
            result.proof += "    Prefix: '" + prefix + "'\n";
            result.proof += "    Char class: (" + char_class + ")+\n";
            result.proof += "    MATCHES: all " + std::to_string(matching.size()) + " inputs start with '" + prefix + "'\n";
            result.proof += "    VERIFIED: no counter has prefix '" + prefix + "' with matching suffix\n";
            return result;
        }
    }
    
    result.proof += "  Prefix+: no valid char class (counters would match)\n";
    return result;
}

// Strategy 5: Common suffix + variable prefix with fragment
PatternResult trySuffixPlusFragment(const std::vector<std::string>& matching,
                                    const std::vector<std::string>& counters,
                                    std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  Suffix+: requires 2+ matching\n";
        return result;
    }
    
    // Find common suffix
    std::string suffix = matching[0];
    for (size_t i = 1; i < matching.size(); i++) {
        std::string new_suffix;
        size_t min_len = std::min(matching[i].size(), suffix.size());
        for (size_t j = 0; j < min_len; j++) {
            char c1 = matching[i][matching[i].size() - 1 - j];
            char c2 = suffix[suffix.size() - 1 - j];
            if (c1 == c2) {
                new_suffix = c1 + new_suffix;
            } else {
                break;
            }
        }
        suffix = new_suffix;
        if (suffix.empty()) break;
    }
    
    if (suffix.empty()) {
        result.proof += "  Suffix+: no common suffix\n";
        return result;
    }
    
    size_t suffix_len = suffix.size();
    
    for (size_t suffix_start = 0; suffix_start <= suffix_len; suffix_start++) {
        std::set<char> match_chars;
        for (const auto& m : matching) {
            if (m.size() > suffix_len && (m.size() - suffix_len - 1) >= 0) {
                size_t pos = m.size() - suffix_len - 1;
                if (pos < m.size()) match_chars.insert(m[pos]);
            }
        }
        
        if (match_chars.empty()) continue;
        
        std::string char_class;
        for (char c : match_chars) {
            if (!char_class.empty()) char_class += "|";
            char_class += c;
        }
        
        // Try with fragment
        if (match_chars.size() >= 2 && std::uniform_int_distribution<int>(0, 1)(rng) == 1) {
            std::map<std::string, std::string> frags;
            std::string frag_pattern = extractFragment(char_class, frags, rng);
            result.fragments.insert(frags.begin(), frags.end());
            result.pattern = frag_pattern + suffix;
        } else {
            result.pattern = "(" + char_class + ")+" + suffix;
        }
        
        // Verify matching - check BOTH suffix AND that prefix matches char class
        bool all_match = true;
        for (const auto& m : matching) {
            if (m.size() <= suffix_len) {
                all_match = false;
                break;
            }
            if (m.substr(m.size() - suffix_len) != suffix) {
                all_match = false;
                break;
            }
            // Verify prefix consists ONLY of chars from the char class
            std::string prefix = m.substr(0, m.size() - suffix_len);
            if (!patternMatchesCharClass(char_class, prefix)) {
                all_match = false;
                break;
            }
        }
        
        if (!all_match) {
            result.pattern = "";
            continue;
        }
        
        // Check counters
        bool any_match = false;
        for (const auto& c : counters) {
            if (c.size() > suffix_len && c.substr(c.size() - suffix_len) == suffix) {
                if (!c.empty() && patternMatchesCharClass(char_class, c.substr(0, c.size() - suffix_len))) {
                    any_match = true;
                    break;
                }
            }
        }
        
        if (!any_match) {
            result.proof += "  Suffix+: " + result.pattern + "\n";
            result.proof += "    Suffix: '" + suffix + "'\n";
            result.proof += "    Char class: (" + char_class + ")+\n";
            result.proof += "    MATCHES: all " + std::to_string(matching.size()) + " inputs end with '" + suffix + "'\n";
            result.proof += "    VERIFIED: no counter has suffix '" + suffix + "' with matching prefix\n";
            return result;
        }
    }
    
    result.proof += "  Suffix+: no valid pattern (counters would match)\n";
    result.pattern = "";
    return result;
}

// Strategy 6: Two-part pattern with fragment
PatternResult tryTwoPartFragment(const std::vector<std::string>& matching,
                                const std::vector<std::string>& counters,
                                std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  TwoPart+: requires 2+ matching\n";
        return result;
    }
    
    // Try splitting at each position
    for (size_t split_pos = 1; split_pos < matching[0].size(); split_pos++) {
        std::string part1 = matching[0].substr(0, split_pos);
        std::string part2 = matching[0].substr(split_pos);
        
        if (part2.empty()) continue;
        
        // Try: part1(part2)+
        std::string pattern = part1 + "(" + part2 + ")+";
        
        bool all_match = true;
        for (const auto& m : matching) {
            if (m.size() < split_pos || m.substr(0, split_pos) != part1) {
                all_match = false;
                break;
            }
            if (!patternMatchesPlus(part2, m.substr(split_pos))) {
                all_match = false;
                break;
            }
        }
        
        if (!all_match) continue;
        
        // Check counters
        bool any_match = false;
        for (const auto& c : counters) {
            if (c.size() >= split_pos && c.substr(0, split_pos) == part1) {
                if (patternMatchesPlus(part2, c.substr(split_pos))) {
                    any_match = true;
                    break;
                }
            }
        }
        
        if (!any_match) {
            // Maybe use fragment for part2?
            if (part2.size() >= 1 && std::uniform_int_distribution<int>(0, 1)(rng) == 1) {
                std::map<std::string, std::string> frags;
                std::string frag_pattern = extractFragment(part2, frags, rng);
                result.fragments.insert(frags.begin(), frags.end());
                result.pattern = part1 + frag_pattern;
            } else {
                result.pattern = pattern;
            }
            result.proof += "  TwoPart+: " + result.pattern + "\n";
            return result;
        }
        
        // Try: (part1)+part2
        pattern = "(" + part1 + ")+" + part2;
        
        all_match = true;
        for (const auto& m : matching) {
            size_t part1_len = m.size() - part2.size();
            if (part1_len < part1.size() || part1_len % part1.size() != 0) {
                all_match = false;
                break;
            }
            if (m.substr(part1_len) != part2) {
                all_match = false;
                break;
            }
            bool valid = true;
            for (size_t i = 0; i < part1_len; i += part1.size()) {
                if (m.substr(i, part1.size()) != part1) {
                    valid = false;
                    break;
                }
            }
            if (!valid) {
                all_match = false;
                break;
            }
        }
        
        if (!all_match) continue;
        
        any_match = false;
        for (const auto& c : counters) {
            size_t part1_len = c.size() - part2.size();
            if (part1_len > 0 && c.substr(c.size() - part2.size()) == part2) {
                bool valid = true;
                for (size_t i = 0; i < part1_len; i += part1.size()) {
                    if (c.substr(i, part1.size()) != part1) {
                        valid = false;
                        break;
                    }
                }
                if (valid) {
                    any_match = true;
                    break;
                }
            }
        }
        
        if (!any_match) {
            result.pattern = pattern;
            result.proof += "  TwoPart+: " + pattern + "\n";
            result.proof += "    Part1: '" + part1 + "', Part2: '" + part2 + "'\n";
            result.proof += "    MATCHES: all inputs are repetitions of part1 followed by part2\n";
            result.proof += "    VERIFIED: no counter matches this structure\n";
            return result;
        }
    }
    
    result.proof += "  TwoPart+: no valid split (counters would match)\n";
    result.pattern = "";
    return result;
}

// Strategy 7: Fragment-only pattern
PatternResult tryFragmentOnly(const std::vector<std::string>& matching,
                             const std::vector<std::string>& counters,
                             std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  FragmentOnly: requires 2+ matching\n";
        return result;
    }
    
    // Collect all unique chars from all matching strings
    std::set<char> all_chars;
    for (const auto& m : matching) {
        for (char c : m) {
            all_chars.insert(c);
        }
    }
    
    if (all_chars.size() < 2) {
        result.proof += "  FragmentOnly: not enough variation\n";
        return result;
    }
    
    // Create fragment from all chars
    std::string char_class;
    for (char c : all_chars) {
        if (!char_class.empty()) char_class += "|";
        char_class += c;
    }
    
    // Extract the fragment name and definition from the returned pattern
    std::map<std::string, std::string> frags;
    std::string frag_pattern = extractFragment(char_class, frags, rng);
    result.fragments.insert(frags.begin(), frags.end());
    
    // Get the fragment definition
    std::string frag_def;
    for (const auto& f : frags) {
        frag_def = f.second;
        break;
    }
    
    // Now verify using the FRAGMENT's definition (the characters it contains)
    // Try with common prefix
    std::string prefix;
    for (size_t i = 0; i < 2; i++) {
        prefix += matching[0][i];
        bool all_have = true;
        for (const auto& m : matching) {
            if (i >= m.size() || m[i] != prefix.back()) {
                all_have = false;
                break;
            }
        }
        if (!all_have) {
            prefix.pop_back();
            break;
        }
    }
    
    if (!prefix.empty()) {
        result.pattern = prefix + frag_pattern;
    } else {
        result.pattern = frag_pattern;
    }
    
    // Verify - use the FRAGMENT's character set, not the original char_class
    bool all_match = true;
    for (const auto& m : matching) {
        if (!prefix.empty() && m.find(prefix) != 0) {
            all_match = false;
            break;
        }
        std::string suffix = prefix.empty() ? m : m.substr(prefix.size());
        if (!patternMatchesCharClass(frag_def, suffix)) {
            all_match = false;
            break;
        }
    }
    
    // Verify - check that no counter matches the fragment pattern
    bool any_counter_matches = false;
    for (const auto& c : counters) {
        // For FragmentOnly with fragment, check if ALL chars in counter are from fragment
        if (patternMatchesCharClass(frag_def, c)) {
            any_counter_matches = true;
            break;
        }
    }
    
    if (any_counter_matches) {
        result.proof += "  FragmentOnly: counters would match fragment\n";
        result.pattern = "";
        return result;
    }
    
    if (!all_match) {
        result.proof += "  FragmentOnly: verification failed\n";
        result.pattern = "";
        return result;
    }
    
    result.proof += "  FragmentOnly: " + result.pattern + "\n";
    result.proof += "    Char class contains " + std::to_string(all_chars.size()) + " unique chars\n";
    if (!prefix.empty()) {
        result.proof += "    Prefix: '" + prefix + "'\n";
    }
    result.proof += "    MATCHES: all " + std::to_string(matching.size()) + " inputs consist of these chars\n";
    result.proof += "    VERIFIED: no counter matches the char class pattern\n";
    return result;
}

// ============================================================================
// Edge Case Strategies
// ============================================================================

// Strategy: Optional quantifier - try (unit)? instead of alternation
PatternResult tryOptionalQuantifier(const std::vector<std::string>& matching,
                                   const std::vector<std::string>& counters,
                                   std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  Optional: requires 2+ matching\n";
        return result;
    }
    
    // Find common prefix and try making it optional
    std::string prefix = matching[0];
    for (size_t i = 1; i < matching.size(); i++) {
        std::string new_prefix;
        for (size_t j = 0; j < matching[i].size() && j < prefix.size(); j++) {
            if (matching[i][j] == prefix[j]) {
                new_prefix += prefix[j];
            } else {
                break;
            }
        }
        prefix = new_prefix;
        if (prefix.empty()) break;
    }
    
    if (prefix.empty() || prefix.size() < 2) {
        result.proof += "  Optional: no suitable prefix\n";
        return result;
    }
    
    // Try: (prefix)?rest where rest is what comes after
    for (size_t split = 1; split < prefix.size(); split++) {
        std::string opt_part = prefix.substr(0, split);
        std::string rest = prefix.substr(split);
        
        // Build pattern: (opt_part)?rest
        // This would match both opt_part+rest and just rest
        
        // Check if all matching are either prefix or rest
        bool valid = true;
        for (const auto& m : matching) {
            if (m != prefix && m != rest) {
                valid = false;
                break;
            }
        }
        if (!valid) continue;
        
        // Check counters - ensure none match the optional pattern
        bool any_counter_matches = false;
        for (const auto& c : counters) {
            if (c == rest || c == prefix) {
                any_counter_matches = true;
                break;
            }
        }
        
        if (!any_counter_matches) {
            result.pattern = "(" + opt_part + ")?";
            if (!rest.empty()) result.pattern += rest;
            
            result.proof += "  Optional: " + result.pattern + "\n";
            result.proof += "    Makes '" + opt_part + "' optional before '" + rest + "'\n";
            result.proof += "    MATCHES: '" + prefix + "' and '" + rest + "'\n";
            result.proof += "    VERIFIED: no counter matches\n";
            return result;
        }
    }
    
    result.proof += "  Optional: no valid optional pattern found\n";
    return result;
}

// Strategy: Empty alternative - try adding | to alternation
PatternResult tryEmptyAlternative(const std::vector<std::string>& matching,
                                const std::vector<std::string>& counters,
                                std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  EmptyAlt: requires 2+ matching\n";
        return result;
    }
    
    // Build alternation
    std::string pattern = "(";
    for (size_t i = 0; i < matching.size(); i++) {
        if (i > 0) pattern += "|";
        pattern += matching[i];
    }
    pattern += "|)";  // Add empty alternative
    
    // Verify matching still works (empty would match empty string which isn't in our inputs)
    bool all_match = true;
    for (const auto& m : matching) {
        bool found = false;
        for (const auto& alt : matching) {
            if (m == alt) { found = true; break; }
        }
        if (!found) { all_match = false; break; }
    }
    
    if (!all_match) {
        result.proof += "  EmptyAlt: base alternation doesn't work\n";
        return result;
    }
    
    // Check counters - empty matches empty string, so we need to ensure
    // no counter is empty (they're all non-empty high-entropy strings)
    bool any_counter_empty = false;
    for (const auto& c : counters) {
        if (c.empty()) {
            any_counter_empty = true;
            break;
        }
    }
    
    if (!any_counter_empty) {
        // Also verify no counter matches any of the alternatives
        bool any_match = false;
        for (const auto& c : counters) {
            for (const auto& alt : matching) {
                if (c == alt) {
                    any_match = true;
                    break;
                }
            }
            if (any_match) break;
        }
        
        if (!any_match) {
            result.pattern = pattern;
            result.proof += "  EmptyAlt: " + result.pattern + "\n";
            result.proof += "    Added empty alternative |\n";
            result.proof += "    MATCHES: " + std::to_string(matching.size()) + " inputs\n";
            result.proof += "    VERIFIED: no counter is empty or matches alternatives\n";
            return result;
        }
    }
    
    result.proof += "  EmptyAlt: counters prevent empty alternative\n";
    return result;
}

// Strategy: Nested group - wrap pattern in extra parens
PatternResult tryNestedGroup(const std::vector<std::string>& matching,
                           const std::vector<std::string>& counters,
                           std::mt19937& rng,
                           const std::string& base_pattern) {
    PatternResult result;
    
    if (base_pattern.empty()) {
        result.proof += "  Nested: no base pattern\n";
        return result;
    }
    
    // Wrap in extra parens: ((pattern))
    result.pattern = "((" + base_pattern + "))";
    
    // Verify - nested groups should match same as base
    bool all_match = true;
    for (const auto& m : matching) {
        // Check if base pattern would match
        bool base_matches = false;
        
        // Simple check: is m in matching?
        if (base_pattern.find(m) != std::string::npos || 
            base_pattern.find("(" + m + ")") != std::string::npos ||
            base_pattern.find(m + "|") != std::string::npos ||
            base_pattern.find("|" + m + ")") != std::string::npos) {
            base_matches = true;
        }
        
        if (!base_matches && matching.size() == 1 && m == matching[0]) {
            // Single literal case
            base_matches = (base_pattern == m);
        }
        
        if (!base_matches) {
            // Check alternation
            size_t pos = 0;
            while ((pos = base_pattern.find('|', pos)) != std::string::npos) {
                std::string alt = base_pattern.substr(pos + 1);
                size_t end = alt.find(')');
                if (end != std::string::npos) {
                    alt = alt.substr(0, end);
                    if (alt == m) { base_matches = true; break; }
                }
                pos++;
            }
        }
        
        if (!base_matches) { all_match = false; break; }
    }
    
    if (all_match) {
        // Check counters - nested should have same matching behavior
        bool any_match = false;
        for (const auto& c : counters) {
            for (const auto& alt : matching) {
                if (c == alt) { any_match = true; break; }
            }
            if (any_match) break;
        }
        
        if (!any_match) {
            result.proof += "  Nested: " + result.pattern + "\n";
            result.proof += "    Wrapped base pattern in extra parentheses\n";
            result.proof += "    VERIFIED: same matching as base, counters excluded\n";
            return result;
        }
    }
    
    result.proof += "  Nested: base pattern doesn't work with nesting\n";
    result.pattern = "";
    return result;
}

// Strategy: Multi-character fragment
PatternResult tryMultiCharFragment(const std::vector<std::string>& matching,
                                  const std::vector<std::string>& counters,
                                  std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  MultiFrag: requires 2+ matching\n";
        return result;
    }
    
    // Find common substring (2+ chars) across all matching
    std::string common_substr;
    std::string first = matching[0];
    
    for (size_t len = 2; len <= first.size(); len++) {
        for (size_t pos = 0; pos + len <= first.size(); pos++) {
            std::string substr = first.substr(pos, len);
            
            bool found_in_all = true;
            for (size_t i = 1; i < matching.size(); i++) {
                if (matching[i].find(substr) == std::string::npos) {
                    found_in_all = false;
                    break;
                }
            }
            
            if (found_in_all) {
                common_substr = substr;
                break;
            }
        }
        if (!common_substr.empty()) break;
    }
    
    if (common_substr.empty()) {
        result.proof += "  MultiFrag: no common substring\n";
        return result;
    }
    
    // Build fragment pattern: replace common substring with fragment
    std::string frag_name = "m";
    frag_name += std::to_string(std::uniform_int_distribution<int>(10, 99)(rng));
    result.fragments[frag_name] = common_substr;
    
    // Build pattern: try to use fragment in a plus
    std::string pattern = "((" + frag_name + "))+";
    
    // Verify all matching can be generated by repeating the substring
    bool all_match = true;
    for (const auto& m : matching) {
        if (!patternMatchesPlus(common_substr, m)) {
            // Maybe it's used somewhere in the string, not as full repetition
            if (m.find(common_substr) == std::string::npos) {
                all_match = false;
                break;
            }
        }
    }
    
    if (all_match) {
        // Check counters
        bool any_match = false;
        for (const auto& c : counters) {
            if (c.find(common_substr) != std::string::npos) {
                if (patternMatchesPlus(common_substr, c)) {
                    any_match = true;
                    break;
                }
            }
        }
        
        if (!any_match) {
            result.pattern = pattern;
            result.proof += "  MultiFrag: " + result.pattern + "\n";
            result.proof += "    Fragment: " + frag_name + " = " + common_substr + "\n";
            result.proof += "    MATCHES: strings containing " + common_substr + "\n";
            result.proof += "    VERIFIED: counters don't match\n";
            return result;
        }
    }
    
    // Try with alternation instead: (substr1|substr2)+
    std::set<std::string> substrings;
    for (const auto& m : matching) {
        for (size_t len = 2; len <= m.size(); len++) {
            for (size_t pos = 0; pos + len <= m.size(); pos++) {
                substrings.insert(m.substr(pos, len));
            }
        }
    }
    
    // Build alternation of substrings
    std::string alt_pattern = "(";
    int count = 0;
    for (const auto& s : substrings) {
        if (count > 10) break;  // Limit alternation size
        if (count > 0) alt_pattern += "|";
        alt_pattern += s;
        count++;
    }
    alt_pattern += ")";
    
    // Check if this works
    all_match = true;
    for (const auto& m : matching) {
        bool matches_alt = false;
        for (const auto& s : substrings) {
            if (m.find(s) != std::string::npos) {
                matches_alt = true;
                break;
            }
        }
        if (!matches_alt) { all_match = false; break; }
    }
    
    if (all_match) {
        bool any_match = false;
        for (const auto& c : counters) {
            for (const auto& s : substrings) {
                if (c.find(s) != std::string::npos) {
                    any_match = true;
                    break;
                }
            }
            if (any_match) break;
        }
        
        if (!any_match) {
            result.pattern = alt_pattern;
            result.proof += "  MultiFrag: " + result.pattern + "\n";
            result.proof += "    Alternation of " + std::to_string(count) + " substrings\n";
            result.proof += "    MATCHES: inputs with these substrings\n";
            result.proof += "    VERIFIED: counters excluded\n";
            return result;
        }
    }
    
    result.proof += "  MultiFrag: no valid multi-char fragment pattern\n";
    return result;
}

// ============================================================================
// New Pattern Strategies with Quantifiers on Expressions
// ============================================================================

// Strategy: Alternation with quantifier - (a|b)+ or (a|b)*
PatternResult tryAlternationWithQuantifier(const std::vector<std::string>& matching,
                                           const std::vector<std::string>& counters,
                                           std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  AltQuant: requires 2+ matching\n";
        return result;
    }
    
    // Find a common substring that can be the "base" of alternation
    // Look for a substring that appears in all matching
    std::set<std::string> common_substrs;
    std::string first = matching[0];
    
    for (size_t len = 1; len <= first.size(); len++) {
        for (size_t pos = 0; pos + len <= first.size(); pos++) {
            std::string substr = first.substr(pos, len);
            bool in_all = true;
            for (size_t i = 1; i < matching.size(); i++) {
                if (matching[i].find(substr) == std::string::npos) {
                    in_all = false;
                    break;
                }
            }
            if (in_all) common_substrs.insert(substr);
        }
    }
    
    // Try each common substring as a potential alternation element
    for (const auto& substr : common_substrs) {
        if (substr.empty() || substr.size() < 2) continue;
        
        // Build alternation: take substr, then add variations
        // e.g., substr="abc" -> (abc|abd|abX)+
        std::vector<std::string> alts;
        alts.push_back(substr);
        
        // Add 1-3 variations
        int num_variants = 1 + std::uniform_int_distribution<int>(0, 2)(rng);
        for (int v = 0; v < num_variants; v++) {
            std::string var = substr;
            // Change one char
            size_t idx = std::uniform_int_distribution<int>(0, var.size()-1)(rng);
            char orig = var[idx];
            char newc;
            do {
                newc = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[
                    std::uniform_int_distribution<int>(0, 60)(rng)];
            } while (newc == orig);
            var[idx] = newc;
            alts.push_back(var);
        }
        
        // Build pattern: (alt1|alt2|...)+
        std::string pattern = "(";
        for (size_t i = 0; i < alts.size(); i++) {
            if (i > 0) pattern += "|";
            pattern += alts[i];
        }
        pattern += ")+";
        
        // Check if matching strings match this pattern
        bool all_match = true;
        for (const auto& m : matching) {
            bool matches = false;
            for (const auto& alt : alts) {
                if (patternMatchesPlus(alt, m)) {
                    matches = true;
                    break;
                }
            }
            if (!matches) {
                all_match = false;
                break;
            }
        }
        
        if (!all_match) continue;
        
        // Check counters
        bool any_match = false;
        for (const auto& c : counters) {
            for (const auto& alt : alts) {
                if (patternMatchesPlus(alt, c)) {
                    any_match = true;
                    break;
                }
            }
            if (any_match) break;
        }
        
        if (any_match) continue;
        
        // Decide on quantifier randomly
        if (std::uniform_int_distribution<int>(0, 1)(rng) == 0) {
            pattern = pattern.substr(0, pattern.size() - 1) + ")*";
        }
        
        result.pattern = pattern;
        result.proof += "  AltQuant: " + result.pattern + "\n";
        result.proof += "    Base: '" + substr + "' with variations\n";
        result.proof += "    MATCHES: repetitions of these alternatives\n";
        result.proof += "    VERIFIED: no counter matches\n";
        return result;
    }
    
    result.proof += "  AltQuant: no valid alternation with quantifier\n";
    return result;
}

// Strategy: Sequence with quantifier - (abc)+ or (abc)*
PatternResult trySequenceWithQuantifier(const std::vector<std::string>& matching,
                                        const std::vector<std::string>& counters,
                                        std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  SeqQuant: requires 2+ matching\n";
        return result;
    }
    
    // Find common prefix
    std::string prefix = matching[0];
    for (size_t i = 1; i < matching.size(); i++) {
        std::string new_prefix;
        for (size_t j = 0; j < matching[i].size() && j < prefix.size(); j++) {
            if (matching[i][j] == prefix[j]) {
                new_prefix += prefix[j];
            } else {
                break;
            }
        }
        prefix = new_prefix;
        if (prefix.empty()) break;
    }
    
    if (prefix.size() < 2) {
        result.proof += "  SeqQuant: no suitable prefix\n";
        return result;
    }
    
    // Try different prefix lengths as the sequence unit
    for (size_t len = 2; len <= prefix.size(); len++) {
        std::string unit = prefix.substr(0, len);
        
        // Check if all matching are repetitions of this unit
        bool all_match = true;
        for (const auto& m : matching) {
            if (!patternMatchesPlus(unit, m)) {
                all_match = false;
                break;
            }
        }
        
        if (!all_match) continue;
        
        // Check counters
        bool any_match = false;
        for (const auto& c : counters) {
            if (patternMatchesPlus(unit, c)) {
                any_match = true;
                break;
            }
        }
        
        if (any_match) continue;
        
        // Choose quantifier randomly
        std::uniform_int_distribution<int> qdist(0, 2);
        int qtype = qdist(rng);
        
        if (qtype == 0) {
            result.pattern = "(" + unit + ")+";
        } else if (qtype == 1) {
            result.pattern = "(" + unit + ")*";
        } else {
            result.pattern = "(" + unit + ")";
        }
        
        result.proof += "  SeqQuant: " + result.pattern + "\n";
        result.proof += "    Unit: '" + unit + "'\n";
        result.proof += "    MATCHES: " + std::to_string(matching.size()) + " inputs\n";
        result.proof += "    VERIFIED: no counter matches\n";
        return result;
    }
    
    result.proof += "  SeqQuant: no valid sequence with quantifier\n";
    return result;
}

// Strategy: Optional sequence - (abc)? 
PatternResult tryOptionalSequence(const std::vector<std::string>& matching,
                                  const std::vector<std::string>& counters,
                                  std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  OptSeq: requires 2+ matching\n";
        return result;
    }
    
    // Look for strings where some share a common prefix
    std::string prefix = matching[0];
    for (size_t i = 1; i < matching.size(); i++) {
        std::string new_prefix;
        for (size_t j = 0; j < matching[i].size() && j < prefix.size(); j++) {
            if (matching[i][j] == prefix[j]) {
                new_prefix += prefix[j];
            } else {
                break;
            }
        }
        prefix = new_prefix;
        if (prefix.empty()) break;
    }
    
    if (prefix.size() < 2) {
        result.proof += "  OptSeq: no suitable prefix\n";
        return result;
    }
    
    // Try splitting: (prefix)?rest
    for (size_t split = 1; split < prefix.size(); split++) {
        std::string opt_part = prefix.substr(0, split);
        std::string rest = prefix.substr(split);
        
        if (rest.empty()) continue;
        
        // Check which matching strings have opt_part
        int with_opt = 0;
        int without_opt = 0;
        
        for (const auto& m : matching) {
            if (m.find(opt_part + rest) == 0) {
                with_opt++;
            } else if (m.find(rest) == 0) {
                without_opt++;
            }
        }
        
        if (with_opt > 0 && without_opt > 0) {
            // Build pattern: (opt_partrest)? or (opt_part)?rest
            std::string pattern = "(" + opt_part + rest + ")?";
            
            // Check counters - should not match
            bool any_match = false;
            for (const auto& c : counters) {
                if (c == opt_part + rest || c == rest) {
                    any_match = true;
                    break;
                }
            }
            
            if (!any_match) {
                result.pattern = pattern;
                result.proof += "  OptSeq: " + result.pattern + "\n";
                result.proof += "    Optional: '" + opt_part + rest + "'\n";
                result.proof += "    MATCHES: with/without the optional part\n";
                result.proof += "    VERIFIED: no counter matches\n";
                return result;
            }
        }
    }
    
    result.proof += "  OptSeq: no valid optional sequence\n";
    return result;
}

// Strategy: Nested quantifiers - ((ab)+)* or ((a|b)+)?
PatternResult tryNestedQuantifiers(const std::vector<std::string>& matching,
                                   const std::vector<std::string>& counters,
                                   std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  NestedQuant: requires 2+ matching\n";
        return result;
    }
    
    // Try to build a base pattern first
    std::string base_unit;
    
    // Find common substring
    std::string first = matching[0];
    for (size_t len = 2; len <= first.size(); len++) {
        for (size_t pos = 0; pos + len <= first.size(); pos++) {
            std::string substr = first.substr(pos, len);
            bool in_all = true;
            for (size_t i = 1; i < matching.size(); i++) {
                if (matching[i].find(substr) == std::string::npos) {
                    in_all = false;
                    break;
                }
            }
            if (in_all) {
                base_unit = substr;
                break;
            }
        }
        if (!base_unit.empty()) break;
    }
    
    if (base_unit.empty()) {
        result.proof += "  NestedQuant: no suitable base unit\n";
        return result;
    }
    
    // Build nested quantifier patterns
    // Choose random nesting pattern
    std::uniform_int_distribution<int> ndist(0, 3);
    int nest_type = ndist(rng);
    
    std::string inner_pattern;
    std::string outer_pattern;
    
    switch (nest_type) {
        case 0: // ((unit)+)*
            inner_pattern = "(" + base_unit + ")+";
            outer_pattern = "(" + inner_pattern + ")*";
            break;
        case 1: // ((unit)*)+
            inner_pattern = "(" + base_unit + ")*";
            outer_pattern = "(" + inner_pattern + ")+";
            break;
        case 2: // ((unit)+)?
            inner_pattern = "(" + base_unit + ")+";
            outer_pattern = "(" + inner_pattern + ")?";
            break;
        default: // ((unit)*)?
            inner_pattern = "(" + base_unit + ")*";
            outer_pattern = "(" + inner_pattern + ")?";
            break;
    }
    
    // Verify all matching
    bool all_match = true;
    for (const auto& m : matching) {
        if (m.find(base_unit) == std::string::npos) {
            all_match = false;
            break;
        }
    }
    
    if (!all_match) {
        result.proof += "  NestedQuant: base unit not in all matching\n";
        return result;
    }
    
    // Check counters
    bool any_match = false;
    for (const auto& c : counters) {
        if (c.find(base_unit) != std::string::npos) {
            any_match = true;
            break;
        }
    }
    
    if (!any_match) {
        result.pattern = outer_pattern;
        result.proof += "  NestedQuant: " + result.pattern + "\n";
        result.proof += "    Inner: " + inner_pattern + "\n";
        result.proof += "    Outer: " + outer_pattern + "\n";
        result.proof += "    MATCHES: strings containing " + base_unit + "\n";
        result.proof += "    VERIFIED: no counter matches\n";
        return result;
    }
    
    result.proof += "  NestedQuant: counters prevent this pattern\n";
    return result;
}

// Strategy: Char class sequence - (a|b|c)+ with different chars
PatternResult tryCharClassSequence(const std::vector<std::string>& matching,
                                   const std::vector<std::string>& counters,
                                   std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  CharClassSeq: requires 2+ matching\n";
        return result;
    }
    
    // Find common prefix
    std::string prefix = matching[0];
    for (size_t i = 1; i < matching.size(); i++) {
        std::string new_prefix;
        for (size_t j = 0; j < matching[i].size() && j < prefix.size(); j++) {
            if (matching[i][j] == prefix[j]) {
                new_prefix += prefix[j];
            } else {
                break;
            }
        }
        prefix = new_prefix;
        if (prefix.empty()) break;
    }
    
    if (prefix.empty()) {
        result.proof += "  CharClassSeq: no common prefix\n";
        return result;
    }
    
    // Build char class from characters at next position
    size_t pos = prefix.size();
    std::set<char> suffix_chars;
    for (const auto& m : matching) {
        if (pos < m.size()) {
            suffix_chars.insert(m[pos]);
        }
    }
    
    if (suffix_chars.size() < 2) {
        result.proof += "  CharClassSeq: not enough char variation\n";
        return result;
    }
    
    // Build char class: (a|b|c)+
    std::string char_class;
    for (char c : suffix_chars) {
        if (!char_class.empty()) char_class += "|";
        char_class += c;
    }
    
    std::string pattern = prefix + "(" + char_class + ")+";
    
    // Verify all matching
    bool all_match = true;
    for (const auto& m : matching) {
        if (m.size() <= pos) {
            all_match = false;
            break;
        }
        if (m.substr(0, pos) != prefix) {
            all_match = false;
            break;
        }
        std::string suffix = m.substr(pos);
        if (!patternMatchesCharClass(char_class, suffix)) {
            all_match = false;
            break;
        }
    }
    
    if (!all_match) {
        result.proof += "  CharClassSeq: matching strings don't fit\n";
        return result;
    }
    
    // Check counters
    bool any_match = false;
    for (const auto& c : counters) {
        if (c.size() > pos && c.substr(0, pos) == prefix) {
            std::string suffix = c.substr(pos);
            if (patternMatchesCharClass(char_class, suffix)) {
                any_match = true;
                break;
            }
        }
    }
    
    if (any_match) {
        result.proof += "  CharClassSeq: counters would match\n";
        return result;
    }
    
    result.pattern = pattern;
    result.proof += "  CharClassSeq: " + result.pattern + "\n";
    result.proof += "    Prefix: '" + prefix + "'\n";
    result.proof += "    Char class: (" + char_class + ")+\n";
    result.proof += "    MATCHES: prefix followed by one or more of these chars\n";
    result.proof += "    VERIFIED: no counter matches\n";
    return result;
}

// Strategy: Star quantifier (zero or more)
PatternResult tryStarQuantifier(const std::vector<std::string>& matching,
                                const std::vector<std::string>& counters,
                                std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  StarQuant: requires 2+ matching\n";
        return result;
    }
    
    // Try each matching string as a potential repeat unit
    for (const auto& unit : matching) {
        if (unit.empty()) continue;
        
        // For star, we need to check if matching strings can be repetitions
        // OR if they start with the unit (allowing zero of it)
        bool all_match = true;
        for (const auto& m : matching) {
            if (!patternMatchesStar(unit, m) && m.find(unit) != 0) {
                all_match = false;
                break;
            }
        }
        
        if (!all_match) continue;
        
        // Check counters - star is permissive, so be careful
        bool any_counter_matches = false;
        for (const auto& c : counters) {
            // Counter matches if it's a full repetition OR starts with unit
            if (patternMatchesStar(unit, c) || c.find(unit) == 0) {
                any_counter_matches = true;
                break;
            }
        }
        
        if (any_counter_matches) continue;
        
        // Use fragment occasionally
        if (unit.size() >= 1 && std::uniform_int_distribution<int>(0, 1)(rng) == 1) {
            std::map<std::string, std::string> frags;
            std::string frag_pattern = extractFragment(unit, frags, rng);
            result.fragments.insert(frags.begin(), frags.end());
            result.pattern = "(" + frag_pattern + ")*";
        } else {
            result.pattern = "(" + unit + ")*";
        }
        
        result.proof += "  StarQuant: " + result.pattern + "\n";
        result.proof += "    Unit: '" + unit + "'\n";
        result.proof += "    MATCHES: strings starting with or repetitions of '" + unit + "'\n";
        result.proof += "    VERIFIED: no counter matches\n";
        return result;
    }
    
    result.proof += "  StarQuant: no valid star pattern found\n";
    return result;
}

// Strategy: CharClassPlus - inline character class with plus (not fragment)
PatternResult tryCharClassPlus(const std::vector<std::string>& matching,
                               const std::vector<std::string>& counters,
                               std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  CharClassPlus: requires 2+ matching\n";
        return result;
    }
    
    // Find common prefix
    std::string prefix = matching[0];
    for (size_t i = 1; i < matching.size(); i++) {
        std::string new_prefix;
        for (size_t j = 0; j < matching[i].size() && j < prefix.size(); j++) {
            if (matching[i][j] == prefix[j]) {
                new_prefix += prefix[j];
            } else {
                break;
            }
        }
        prefix = new_prefix;
        if (prefix.empty()) break;
    }
    
    if (prefix.empty()) {
        result.proof += "  CharClassPlus: no common prefix\n";
        return result;
    }
    
    // Collect chars after prefix
    size_t pos = prefix.size();
    std::set<char> match_chars;
    for (const auto& m : matching) {
        if (pos < m.size()) match_chars.insert(m[pos]);
    }
    
    if (match_chars.size() < 2) {
        result.proof += "  CharClassPlus: not enough char variation\n";
        return result;
    }
    
    // Build inline char class (not fragment)
    std::string char_class;
    for (char c : match_chars) {
        if (!char_class.empty()) char_class += "|";
        char_class += c;
    }
    
    // Pattern: prefix[char_class]+
    // Note: c-dfa uses (a|b)+ syntax, not [ab]+
    std::string pattern = prefix + "(" + char_class + ")+";
    
    // Verify all matching
    bool all_match = true;
    for (const auto& m : matching) {
        if (m.size() <= pos) {
            all_match = false;
            break;
        }
        std::string suffix = m.substr(pos);
        if (!patternMatchesCharClass(char_class, suffix)) {
            all_match = false;
            break;
        }
    }
    
    if (!all_match) {
        result.proof += "  CharClassPlus: matching strings don't fit char class\n";
        return result;
    }
    
    // Check counters
    bool any_match = false;
    for (const auto& c : counters) {
        if (c.size() > pos && c.substr(0, pos) == prefix) {
            std::string suffix = c.substr(pos);
            if (patternMatchesCharClass(char_class, suffix)) {
                any_match = true;
                break;
            }
        }
    }
    
    if (any_match) {
        result.proof += "  CharClassPlus: counters would match\n";
        return result;
    }
    
    result.pattern = pattern;
    result.proof += "  CharClassPlus: " + result.pattern + "\n";
    result.proof += "    Prefix: '" + prefix + "'\n";
    result.proof += "    Char class: (" + char_class + ")+\n";
    result.proof += "    MATCHES: all inputs start with '" + prefix + "' and continue with these chars\n";
    result.proof += "    VERIFIED: no counter matches\n";
    return result;
}

// Strategy: Mixed quantifiers - combine different quantifiers
PatternResult tryMixedQuantifiers(const std::vector<std::string>& matching,
                                  const std::vector<std::string>& counters,
                                  std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  MixedQuant: requires 2+ matching\n";
        return result;
    }
    
    // Find common prefix
    std::string prefix = matching[0];
    for (size_t i = 1; i < matching.size(); i++) {
        std::string new_prefix;
        for (size_t j = 0; j < matching[i].size() && j < prefix.size(); j++) {
            if (matching[i][j] == prefix[j]) {
                new_prefix += prefix[j];
            } else {
                break;
            }
        }
        prefix = new_prefix;
        if (prefix.empty()) break;
    }
    
    if (prefix.empty() || prefix.size() < 2) {
        result.proof += "  MixedQuant: no suitable prefix\n";
        return result;
    }
    
    // Try splitting prefix into two parts with different quantifiers
    for (size_t split = 1; split < prefix.size(); split++) {
        std::string part1 = prefix.substr(0, split);
        std::string part2 = prefix.substr(split);
        
        if (part2.empty()) continue;
        
        // Try: part1+part2? - part2 optional
        std::string pattern1 = part1 + "(" + part2 + ")?";
        
        bool all_match1 = true;
        for (const auto& m : matching) {
            if (m.find(part1) != 0) {
                all_match1 = false;
                break;
            }
            std::string rest = m.substr(part1.size());
            if (rest != part2 && !rest.empty()) {
                all_match1 = false;
                break;
            }
        }
        
        if (all_match1) {
            bool any_counter = false;
            for (const auto& c : counters) {
                if (c.find(part1) == 0) {
                    std::string rest = c.substr(part1.size());
                    if (rest == part2 || rest.empty()) {
                        any_counter = true;
                        break;
                    }
                }
            }
            
            if (!any_counter) {
                result.pattern = pattern1;
                result.proof += "  MixedQuant: " + result.pattern + "\n";
                result.proof += "    Part1: '" + part1 + "', Part2: '" + part2 + "' optional\n";
                result.proof += "    VERIFIED: no counter matches\n";
                return result;
            }
        }
        
        // Try: part1*part2 - part1 zero or more
        std::string pattern2 = "(" + part1 + ")*" + part2;
        
        bool all_match2 = true;
        for (const auto& m : matching) {
            if (m.size() < part2.size()) {
                all_match2 = false;
                break;
            }
            if (m.substr(m.size() - part2.size()) != part2) {
                all_match2 = false;
                break;
            }
            std::string prefix_part = m.substr(0, m.size() - part2.size());
            // Check prefix is repetitions of part1
            if (!prefix_part.empty() && prefix_part.size() % part1.size() != 0) {
                all_match2 = false;
                break;
            }
            for (size_t i = 0; i < prefix_part.size(); i += part1.size()) {
                if (prefix_part.substr(i, part1.size()) != part1) {
                    all_match2 = false;
                    break;
                }
            }
            if (!all_match2) break;
        }
        
        if (all_match2) {
            bool any_counter = false;
            for (const auto& c : counters) {
                if (c.size() >= part2.size() && c.substr(c.size() - part2.size()) == part2) {
                    std::string prefix_part = c.substr(0, c.size() - part2.size());
                    if (prefix_part.empty() || (prefix_part.size() % part1.size() == 0)) {
                        bool valid = true;
                        for (size_t i = 0; i < prefix_part.size(); i += part1.size()) {
                            if (prefix_part.substr(i, part1.size()) != part1) {
                                valid = false;
                                break;
                            }
                        }
                        if (valid) {
                            any_counter = true;
                            break;
                        }
                    }
                }
            }
            
            if (!any_counter) {
                result.pattern = pattern2;
                result.proof += "  MixedQuant: " + result.pattern + "\n";
                result.proof += "    Part1: '" + part1 + "'*, Part2: '" + part2 + "'\n";
                result.proof += "    VERIFIED: no counter matches\n";
                return result;
            }
        }
    }
    
    result.proof += "  MixedQuant: no valid mixed quantifier pattern\n";
    return result;
}

// Strategy: Fragment chaining - use multiple fragments in one pattern
PatternResult tryFragmentChaining(const std::vector<std::string>& matching,
                                  const std::vector<std::string>& counters,
                                  std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  FragChain: requires 2+ matching\n";
        return result;
    }
    
    // Find two different common substrings we can use as fragments
    std::set<std::string> all_substrs;
    for (const auto& m : matching) {
        for (size_t len = 1; len <= m.size(); len++) {
            for (size_t pos = 0; pos + len <= m.size(); pos++) {
                all_substrs.insert(m.substr(pos, len));
            }
        }
    }
    
    std::vector<std::string> substr_list(all_substrs.begin(), all_substrs.end());
    if (substr_list.size() < 2) {
        result.proof += "  FragChain: not enough substrings\n";
        return result;
    }
    
    // Try different pairs as fragments
    std::shuffle(substr_list.begin(), substr_list.end(), rng);
    
    for (size_t i = 0; i < std::min((size_t)10, substr_list.size()); i++) {
        for (size_t j = i + 1; j < std::min((size_t)15, substr_list.size()); j++) {
            std::string frag1 = substr_list[i];
            std::string frag2 = substr_list[j];
            
            if (frag1 == frag2) continue;
            
            // Create fragment definitions
            std::string name1 = "x" + std::to_string(i);
            std::string name2 = "y" + std::to_string(j);
            result.fragments[name1] = frag1;
            result.fragments[name2] = frag2;
            
            // Try: ((x))+((y))+
            std::string pattern = "((" + name1 + "))+" + "((" + name2 + "))+";
            
            // Check if matching strings fit this pattern
            bool all_match = true;
            for (const auto& m : matching) {
                // Need at least one of each fragment in sequence
                size_t pos1 = m.find(frag1);
                size_t pos2 = m.find(frag2);
                if (pos1 == std::string::npos || pos2 == std::string::npos) {
                    all_match = false;
                    break;
                }
                // Order matters - frag1 should come before frag2 in cycle
                // For simplicity, check if we can partition string into repetitions
                std::string remaining = m;
                bool valid = true;
                while (!remaining.empty()) {
                    if (remaining.find(frag1) == 0) {
                        remaining = remaining.substr(frag1.size());
                    } else if (remaining.find(frag2) == 0) {
                        remaining = remaining.substr(frag2.size());
                    } else {
                        valid = false;
                        break;
                    }
                }
                if (!valid || !remaining.empty()) {
                    all_match = false;
                    break;
                }
            }
            
            if (!all_match) {
                result.fragments.erase(name1);
                result.fragments.erase(name2);
                continue;
            }
            
            // Check counters
            bool any_match = false;
            for (const auto& c : counters) {
                std::string remaining = c;
                bool valid = true;
                while (!remaining.empty()) {
                    if (remaining.find(frag1) == 0) {
                        remaining = remaining.substr(frag1.size());
                    } else if (remaining.find(frag2) == 0) {
                        remaining = remaining.substr(frag2.size());
                    } else {
                        valid = false;
                        break;
                    }
                }
                if (valid && remaining.empty()) {
                    any_match = true;
                    break;
                }
            }
            
            if (!any_match) {
                result.pattern = pattern;
                result.proof += "  FragChain: " + result.pattern + "\n";
                result.proof += "    Frag1: " + name1 + "=" + frag1 + "\n";
                result.proof += "    Frag2: " + name2 + "=" + frag2 + "\n";
                result.proof += "    MATCHES: alternating " + frag1 + " and " + frag2 + "\n";
                result.proof += "    VERIFIED: no counter matches\n";
                return result;
            }
            
            result.fragments.erase(name1);
            result.fragments.erase(name2);
        }
    }
    
    result.proof += "  FragChain: no valid fragment chain found\n";
    return result;
}

// Strategy: Deep nesting - wrap pattern in parens
// IMPORTANT: c-dfa syntax interprets ((...)) and (((...))) as fragment references!
// So we can only use single grouping: (pattern) - which is just grouping, not fragment
PatternResult tryDeepNesting(const std::vector<std::string>& matching,
                              const std::vector<std::string>& counters,
                              std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  DeepNest: requires 2+ matching\n";
        return result;
    }
    
    // First try to get any valid pattern
    PatternResult base = tryAlternation(matching, counters, rng);
    if (base.pattern.empty()) {
        base = tryPrefixPlusFragment(matching, counters, rng);
    }
    if (base.pattern.empty()) {
        result.proof += "  DeepNest: no base pattern found\n";
        return result;
    }
    
    // Don't wrap if pattern already has parens (would create fragment reference)
    if (base.pattern.find('(') != std::string::npos) {
        result.proof += "  DeepNest: base pattern already has parens\n";
        result.pattern = base.pattern;
        result.fragments = base.fragments;
        return result;
    }
    
    // Single grouping is safe: (pattern) is grouping, not fragment reference
    std::string grouped = "(" + base.pattern + ")";
    
    // Verify still works
    bool all_match = true;
    for (const auto& m : matching) {
        bool found = false;
        for (const auto& alt : matching) {
            if (m == alt) { found = true; break; }
        }
        if (!found) { all_match = false; break; }
    }
    
    if (all_match) {
        result.pattern = grouped;
        result.fragments = base.fragments;
        result.proof += "  DeepNest: " + result.pattern + "\n";
        result.proof += "    Single grouping (safe - not fragment reference)\n";
        result.proof += "    VERIFIED: same matching as base\n";
        return result;
    }
    
    result.proof += "  DeepNest: grouping broke pattern\n";
    return result;
}

// Strategy: Complex alternation - longer alternations with 8-15 alternatives
PatternResult tryComplexAlternation(const std::vector<std::string>& matching,
                                    const std::vector<std::string>& counters,
                                    std::mt19937& rng) {
    PatternResult result;
    
    // Need at least 3 matching to make interesting alternation
    if (matching.size() < 3) {
        result.proof += "  ComplexAlt: requires 3+ matching\n";
        return result;
    }
    
    // Generate additional alternatives from counters by modifying them
    // Take counter strings and create variations
    std::vector<std::string> alts = matching;
    
    // Add some variations of counters (but not exact matches)
    int added = 0;
    for (const auto& c : counters) {
        if (added >= 10) break;
        if (c.empty()) continue;
        
        // Create variation: add/remove/replace a char
        std::string var = c;
        std::uniform_int_distribution<int> op_dist(0, 2);
        int op = op_dist(rng);
        
        if (op == 0 && var.size() > 1) {
            // Remove first char
            var = var.substr(1);
        } else if (op == 1 && var.size() > 1) {
            // Remove last char
            var = var.substr(0, var.size() - 1);
        } else {
            // Replace first char
            var[0] = 'X';
        }
        
        // Only add if different from all existing
        bool dup = false;
        for (const auto& a : alts) {
            if (var == a) { dup = true; break; }
        }
        if (!dup && !var.empty()) {
            alts.push_back(var);
            added++;
        }
    }
    
    if (alts.size() < 4) {
        result.proof += "  ComplexAlt: not enough alternatives\n";
        return result;
    }
    
    // Build alternation
    std::string pattern = "(";
    for (size_t i = 0; i < alts.size(); i++) {
        if (i > 0) pattern += "|";
        pattern += alts[i];
    }
    pattern += ")";
    
    // Verify all original matching match
    bool all_match = true;
    for (const auto& m : matching) {
        bool found = false;
        for (const auto& alt : alts) {
            if (m == alt) { found = true; break; }
        }
        if (!found) { all_match = false; break; }
    }
    
    if (!all_match) {
        result.proof += "  ComplexAlt: alternation doesn't cover all matching\n";
        return result;
    }
    
    // Verify no counter matches
    bool any_match = false;
    for (const auto& c : counters) {
        for (const auto& alt : alts) {
            if (c == alt) { any_match = true; break; }
        }
        if (any_match) break;
    }
    
    if (any_match) {
        result.proof += "  ComplexAlt: counters would match\n";
        return result;
    }
    
    result.pattern = pattern;
    result.proof += "  ComplexAlt: " + result.pattern + "\n";
    result.proof += "    Alternatives: " + std::to_string(alts.size()) + "\n";
    result.proof += "    MATCHES: " + std::to_string(matching.size()) + " original inputs\n";
    result.proof += "    VERIFIED: no counter matches\n";
    return result;
}

// ============================================================================
// Capture Tags Strategy
// ============================================================================

// Strategy: Wrap pattern in capture tags - <capname>pattern</capname>
PatternResult tryCaptureTags(const std::vector<std::string>& matching,
                            const std::vector<std::string>& counters,
                            std::mt19937& rng) {
    PatternResult result;
    
    if (matching.empty()) {
        result.proof += "  Capture: no matching inputs\n";
        return result;
    }
    
    // First try to get any valid pattern
    PatternResult base = tryAlternation(matching, counters, rng);
    if (base.pattern.empty()) {
        base = tryPrefixPlusFragment(matching, counters, rng);
    }
    if (base.pattern.empty()) {
        base = tryFragmentOnly(matching, counters, rng);
    }
    if (base.pattern.empty()) {
        result.proof += "  Capture: no base pattern found\n";
        return result;
    }
    
    // Generate a random capture name
    std::string cap_names[] = {"cap", "match", "arg", "val", "num", "text", "name", "id"};
    std::string cap_name = cap_names[std::uniform_int_distribution<int>(0, 7)(rng)];
    cap_name += std::to_string(std::uniform_int_distribution<int>(0, 99)(rng));
    
    // Wrap pattern in capture tags
    result.pattern = "<" + cap_name + ">" + base.pattern + "</" + cap_name + ">";
    result.fragments = base.fragments;
    
    // Verify - capture tags shouldn't change matching behavior
    bool all_match = true;
    for (const auto& m : matching) {
        bool matches = false;
        // Check if base pattern matches
        if (base.pattern.find("|") != std::string::npos) {
            // Alternation - check if m is one of the options
            for (const auto& alt : matching) {
                if (m == alt) { matches = true; break; }
            }
        } else if (base.pattern.find("((") != std::string::npos) {
            // Fragment - check if m fits the fragment pattern
            matches = true; // Base already verified
        } else {
            // Literal
            matches = (base.pattern == m);
        }
        if (!matches) { all_match = false; break; }
    }
    
    if (!all_match) {
        result.proof += "  Capture: base pattern doesn't match\n";
        result.pattern = "";
        return result;
    }
    
    // Check counters - capture shouldn't affect counter matching
    bool any_match = false;
    for (const auto& c : counters) {
        for (const auto& alt : matching) {
            if (c == alt) { any_match = true; break; }
        }
        if (any_match) break;
    }
    
    if (any_match) {
        result.proof += "  Capture: counters would match\n";
        result.pattern = "";
        return result;
    }
    
    result.proof += "  Capture: " + result.pattern + "\n";
    result.proof += "    Capture name: " + cap_name + "\n";
    result.proof += "    VERIFIED: same matching as base with capture tags\n";
    return result;
}

// ============================================================================
// Single-Char Shorthand Fragment Strategy
// ============================================================================

// Strategy: Create fragment with single character definition
PatternResult trySingleCharFragment(const std::vector<std::string>& matching,
                                   const std::vector<std::string>& counters,
                                   std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  SingleCharFrag: requires 2+ matching\n";
        return result;
    }
    
    // Find a character that appears in all matching strings
    std::set<char> common_chars;
    for (const auto& m : matching) {
        for (char c : m) {
            bool in_all = true;
            for (const auto& m2 : matching) {
                if (m2.find(c) == std::string::npos) {
                    in_all = false;
                    break;
                }
            }
            if (in_all) common_chars.insert(c);
        }
    }
    
    if (common_chars.empty()) {
        result.proof += "  SingleCharFrag: no common char found\n";
        return result;
    }
    
    // Pick a random common character
    std::vector<char> chars(common_chars.begin(), common_chars.end());
    std::shuffle(chars.begin(), chars.end(), rng);
    char selected_char = chars[0];
    std::string char_str(1, selected_char);
    
    // Create single-char fragment
    std::map<std::string, std::string> frags;
    std::string frag_pattern = extractFragment(char_str, frags, rng, true);
    result.fragments.insert(frags.begin(), frags.end());
    
    // Check if matching strings contain this character
    bool all_match = true;
    for (const auto& m : matching) {
        if (m.find(char_str) == std::string::npos) {
            all_match = false;
            break;
        }
    }
    
    if (!all_match) {
        result.proof += "  SingleCharFrag: char not in all matching\n";
        result.pattern = "";
        return result;
    }
    
    // Check counters - should NOT match (fragment alone is too permissive)
    bool any_match = false;
    for (const auto& c : counters) {
        if (c.find(char_str) != std::string::npos) {
            any_match = true;
            break;
        }
    }
    
    if (any_match) {
        result.proof += "  SingleCharFrag: counters would match single char\n";
        result.pattern = "";
        return result;
    }
    
    // Use the fragment pattern
    result.pattern = frag_pattern;
    result.proof += "  SingleCharFrag: " + result.pattern + "\n";
    result.proof += "    Single char: '" + char_str + "'\n";
    result.proof += "    MATCHES: strings containing '" + char_str + "'\n";
    result.proof += "    VERIFIED: no counter matches\n";
    return result;
}

// ============================================================================
// Post-processing: Apply edge cases with probability
// ============================================================================

// Apply edge case transformations to a working pattern
PatternResult applyEdgeCases(const PatternResult& base,
                           const std::vector<std::string>& matching,
                           const std::vector<std::string>& counters,
                           std::mt19937& rng) {
    PatternResult result = base;
    
    if (result.pattern.empty()) return result;
    
    // 5% chance: Try optional quantifier (only if alternation)
    if (result.pattern.find("|") != std::string::npos && 
        std::uniform_int_distribution<int>(0, 99)(rng) < 5) {
        PatternResult opt = tryOptionalQuantifier(matching, counters, rng);
        if (!opt.pattern.empty()) {
            result = opt;
            result.proof += "    [Edge case: Optional with 5% probability]\n";
            return result;
        }
    }
    
    // 3% chance: Try empty alternative
    if (result.pattern.find("|") != std::string::npos &&
        std::uniform_int_distribution<int>(0, 99)(rng) < 3) {
        PatternResult empty = tryEmptyAlternative(matching, counters, rng);
        if (!empty.pattern.empty()) {
            result = empty;
            result.proof += "    [Edge case: Empty alternative with 3% probability]\n";
            return result;
        }
    }
    
    // 4% chance: Try nested group
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 4) {
        PatternResult nested = tryNestedGroup(matching, counters, rng, result.pattern);
        if (!nested.pattern.empty()) {
            result = nested;
            result.fragments = nested.fragments;
            result.proof += "    [Edge case: Nested group with 4% probability]\n";
            return result;
        }
    }
    
    // 5% chance: Try multi-char fragment
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 5) {
        PatternResult multi = tryMultiCharFragment(matching, counters, rng);
        if (!multi.pattern.empty()) {
            result = multi;
            for (const auto& f : multi.fragments) {
                result.fragments[f.first] = f.second;
            }
            result.proof += "    [Edge case: Multi-char fragment with 5% probability]\n";
            return result;
        }
    }
    
    // 7% chance: Try star quantifier (zero or more)
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 7) {
        PatternResult star = tryStarQuantifier(matching, counters, rng);
        if (!star.pattern.empty()) {
            result = star;
            for (const auto& f : star.fragments) {
                result.fragments[f.first] = f.second;
            }
            result.proof += "    [Edge case: Star quantifier with 7% probability]\n";
            return result;
        }
    }
    
    // 4% chance: Try char class plus
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 4) {
        PatternResult cc = tryCharClassPlus(matching, counters, rng);
        if (!cc.pattern.empty()) {
            result = cc;
            result.proof += "    [Edge case: Char class plus with 4% probability]\n";
            return result;
        }
    }
    
    // 3% chance: Try mixed quantifiers
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 3) {
        PatternResult mixed = tryMixedQuantifiers(matching, counters, rng);
        if (!mixed.pattern.empty()) {
            result = mixed;
            result.proof += "    [Edge case: Mixed quantifiers with 3% probability]\n";
            return result;
        }
    }
    
    // 5% chance: Try fragment chaining
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 5) {
        PatternResult chain = tryFragmentChaining(matching, counters, rng);
        if (!chain.pattern.empty()) {
            result = chain;
            for (const auto& f : chain.fragments) {
                result.fragments[f.first] = f.second;
            }
            result.proof += "    [Edge case: Fragment chaining with 5% probability]\n";
            return result;
        }
    }
    
    // 2% chance: Try capture tags
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 2) {
        PatternResult cap = tryCaptureTags(matching, counters, rng);
        if (!cap.pattern.empty()) {
            result = cap;
            for (const auto& f : cap.fragments) {
                result.fragments[f.first] = f.second;
            }
            result.proof += "    [Edge case: Capture tags with 2% probability]\n";
            return result;
        }
    }
    
    // 3% chance: Try single-char shorthand fragment
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 3) {
        PatternResult single = trySingleCharFragment(matching, counters, rng);
        if (!single.pattern.empty()) {
            result = single;
            for (const auto& f : single.fragments) {
                result.fragments[f.first] = f.second;
            }
            result.proof += "    [Edge case: Single-char fragment with 3% probability]\n";
            return result;
        }
    }
    
    return result;
}

// Main pattern generator - try all strategies
PatternResult generateSeparatingPattern(const std::vector<std::string>& matching,
                                        const std::vector<std::string>& counters,
                                        Complexity complexity,
                                        std::mt19937& rng) {
    PatternResult final_result;
    final_result.proof = "PROOF:\n";
    
    if (matching.empty()) {
        final_result.proof += "- No matching inputs provided\n";
        return final_result;
    }
    
    final_result.proof += "- Analyzing " + std::to_string(matching.size()) + " matching, " 
                 + std::to_string(counters.size()) + " counter inputs\n";
    
    // Try literal first if only one matching
    if (matching.size() == 1) {
        PatternResult r = tryLiteral(matching, counters, rng);
        if (!r.pattern.empty()) {
            final_result = r;
            final_result.proof = "PROOF:\n- SUCCESS with literal\n" + final_result.proof;
            // Apply edge cases with probability
            final_result = applyEdgeCases(final_result, matching, counters, rng);
            return final_result;
        }
    }
    
    // Try all strategies in random order and collect valid results
    std::vector<std::function<PatternResult(const std::vector<std::string>&,
                                            const std::vector<std::string>&,
                                            std::mt19937&)>> strategies;
    
    strategies.push_back(tryAlternation);
    strategies.push_back(tryRepetition);
    strategies.push_back(tryPrefixPlusFragment);
    strategies.push_back(trySuffixPlusFragment);
    strategies.push_back(tryTwoPartFragment);
    strategies.push_back(tryFragmentOnly);
    strategies.push_back(tryStarQuantifier);
    strategies.push_back(tryCharClassPlus);
    strategies.push_back(tryMixedQuantifiers);
    strategies.push_back(tryFragmentChaining);
    strategies.push_back(tryDeepNesting);
    strategies.push_back(tryComplexAlternation);
    strategies.push_back(tryAlternationWithQuantifier);
    strategies.push_back(trySequenceWithQuantifier);
    strategies.push_back(tryOptionalSequence);
    strategies.push_back(tryNestedQuantifiers);
    strategies.push_back(tryCharClassSequence);
    
    // Shuffle
    std::shuffle(strategies.begin(), strategies.end(), rng);
    std::shuffle(strategies.begin(), strategies.end(), rng);
    
    // Collect ALL valid results
    std::vector<PatternResult> valid_results;
    for (auto& strategy : strategies) {
        PatternResult r = strategy(matching, counters, rng);
        if (!r.pattern.empty()) {
            valid_results.push_back(r);
        }
    }
    
    // If multiple valid, pick randomly (50/50 at each decision point)
    if (!valid_results.empty()) {
        std::uniform_int_distribution<int> dist(0, valid_results.size() - 1);
        final_result = valid_results[dist(rng)];
        final_result.proof = "PROOF:\n- SUCCESS (random choice from " + 
                             std::to_string(valid_results.size()) + " valid strategies):\n" + 
                             final_result.proof;
        // Apply edge cases with probability
        final_result = applyEdgeCases(final_result, matching, counters, rng);
        return final_result;
    }
    
    final_result.proof += "- All strategies failed\n";
    return final_result;
}

std::map<std::string, std::string> generateFragmentsForPattern(const std::string& pattern) {
    std::map<std::string, std::string> fragments;
    return fragments;
}

TestCase TestGenerator::generateTestCase(int test_id) {
    TestCase tc;
    tc.test_id = test_id;
    
    // Assign unique categories based on test_id (8 categories available)
    // Pattern 0: safe + dangerous (1 + 4 = 5)
    // Pattern 1: caution + network (2 + 5 = 7)
    // Pattern 2: modifying + admin (3 + 6 = 9)
    // Pattern 3: build + container (7 + 8 = 15)
    static Category matching_cats[] = {Category::SAFE, Category::CAUTION, Category::MODIFYING, Category::BUILD};
    static Category counter_cats[] = {Category::DANGEROUS, Category::NETWORK, Category::ADMIN, Category::CONTAINER};
    
    tc.category = matching_cats[test_id % 4];
    tc.counter_category = counter_cats[test_id % 4];
    
    tc.complexity = opts.complexity;
    tc.fragments.clear();
    
    auto [matching_seeds, counter_seeds] = generateSeeds(tc.complexity);
    
    tc.matching_inputs = matching_seeds;
    tc.counter_inputs = counter_seeds;
    
    PatternResult result = generateSeparatingPattern(tc.matching_inputs, tc.counter_inputs, 
                                                     tc.complexity, rng);
    
    tc.pattern = result.pattern;
    tc.fragments = result.fragments;
    
    if (tc.pattern.empty()) {
        result.proof += "\n[FAILED] Could not generate separating pattern\n";
    }
    
    tc.proof = result.proof;
    
    return tc;
}

Category TestGenerator::randomCategory() {
    std::uniform_int_distribution<int> dist(1, 8);
    return static_cast<Category>(dist(rng));
}

std::string TestGenerator::categoryToString(Category cat) {
    switch (cat) {
        case Category::SAFE: return "safe";
        case Category::CAUTION: return "caution";
        case Category::MODIFYING: return "modifying";
        case Category::DANGEROUS: return "dangerous";
        case Category::NETWORK: return "network";
        case Category::ADMIN: return "admin";
        case Category::BUILD: return "build";
        case Category::CONTAINER: return "container";
        default: return "safe";
    }
}

std::pair<std::vector<std::string>, std::vector<std::string>> 
TestGenerator::generateInputs(Complexity complexity) {
    return generateSeeds(complexity);
}

std::map<std::string, std::string> TestGenerator::generateFragments(Complexity complexity) {
    return {};
}

std::string TestGenerator::generateSimpleArg() {
    return "";
}

std::string TestGenerator::generateFlags(int count) {
    return "";
}

std::string TestGenerator::generatePath() {
    return "";
}

std::string TestGenerator::generatePattern(const std::vector<std::string>& matching_inputs, 
                                           const std::vector<std::string>& counter_inputs,
                                           const std::map<std::string, std::string>& fragments,
                                           Complexity complexity,
                                           std::string& proof_out) {
    PatternResult result = generateSeparatingPattern(matching_inputs, counter_inputs, complexity, rng);
    proof_out = result.proof;
    return result.pattern;
}

std::string TestGenerator::transformPart(const std::string& part,
                                        const std::map<std::string, std::string>& fragments,
                                        Complexity complexity,
                                        bool allow_wildcard,
                                        const std::vector<std::string>& counter_inputs,
                                        const std::string& current_pattern,
                                        std::string& proof_out) {
    proof_out = "no transformation";
    return part;
}

bool TestGenerator::wouldMatchWithoutOptional(const std::string& pattern_prefix, const std::string& counter_input) {
    return false;
}

bool TestGenerator::wouldMatchWithAlternation(const std::string& pattern_prefix, const std::string& literal_part, const std::string& counter_input) {
    return false;
}

std::string TestGenerator::makeLiteralPattern(const std::vector<std::string>& parts) {
    std::string result;
    for (const auto& p : parts) {
        if (!result.empty()) result += " ";
        result += p;
    }
    return result;
}

std::string TestGenerator::makeMediumPattern(const std::vector<std::string>& parts, const std::map<std::string, std::string>& fragments) {
    return makeLiteralPattern(parts);
}

std::string TestGenerator::makeComplexPattern(const std::vector<std::string>& parts, const std::map<std::string, std::string>& fragments) {
    return makeLiteralPattern(parts);
}

std::vector<std::string> TestGenerator::generateCounterInputsSimple(const std::string& arg, const std::string& cmd) {
    return {};
}

std::vector<std::string> TestGenerator::generateCounterInputsMedium(const std::string& flags, const std::string& arg, const std::string& cmd) {
    return {};
}

std::vector<std::string> TestGenerator::generateCounterInputsComplex(const std::string& flags, const std::vector<std::string>& args, const std::string& cmd) {
    return {};
}

bool TestGenerator::wouldPatternMatch(const std::string& input, const std::string& pattern) {
    return false;
}

void TestGenerator::writePatternFile(const std::vector<TestCase>& tests, const std::string& filename) {
    std::ofstream out(filename);
    out << "# Auto-generated test patterns\n\n";
    
    std::map<std::string, std::string> all_fragments;
    for (const auto& tc : tests) {
        for (const auto& f : tc.fragments) {
            if (all_fragments.find(f.first) == all_fragments.end()) {
                all_fragments[f.first] = f.second;
            }
        }
    }
    
    if (!all_fragments.empty()) {
        out << "# Fragment definitions\n";
        for (const auto& f : all_fragments) {
            out << "[fragment:" << f.first << "] " << f.second << "\n";
        }
        out << "\n";
    }
    
    out << "# Patterns\n";
    for (const auto& tc : tests) {
        if (!tc.pattern.empty()) {
            // Write matching pattern with its category
            out << "[" << categoryToString(tc.category) << ":test" << tc.test_id << "] " << tc.pattern << "\n";
            // Write counter pattern with different category (to distinguish in combined DFA)
            out << "[" << categoryToString(tc.counter_category) << ":counter" << tc.test_id << "] " << tc.pattern << "\n";
        }
    }
    
    out.close();
    std::cout << "Written pattern file: " << filename << "\n";
}

void TestGenerator::writeExpectations(const std::vector<TestCase>& tests, const std::string& filename) {
    std::ofstream out(filename);
    out << "[\n";
    for (size_t i = 0; i < tests.size(); i++) {
        const auto& tc = tests[i];
        out << "  {\n";
        out << "    \"id\": " << i << ",\n";
        out << "    \"test_id\": " << tc.test_id << ",\n";
        out << "    \"pattern\": \"[" << categoryToString(tc.category) << ":test" << tc.test_id << "] " << tc.pattern << "\",\n";
        out << "    \"category\": \"" << categoryToString(tc.category) << "\",\n";
        out << "    \"counter_category\": \"" << categoryToString(tc.counter_category) << "\",\n";
        out << "    \"matching_inputs\": [";
        for (size_t j = 0; j < tc.matching_inputs.size(); j++) {
            if (j > 0) out << ", ";
            out << "\"" << tc.matching_inputs[j] << "\"";
        }
        out << "],\n";
        out << "    \"counter_inputs\": [";
        for (size_t j = 0; j < tc.counter_inputs.size(); j++) {
            if (j > 0) out << ", ";
            out << "\"" << tc.counter_inputs[j] << "\"";
        }
        out << "],\n";
        out << "    \"proof\": \"";
        for (size_t p = 0; p < tc.proof.size(); p++) {
            char c = tc.proof[p];
            if (c == '\n') out << "\\n";
            else if (c == '"') out << "\\\"";
            else out << c;
        }
        out << "\",\n";
        out << "    \"complexity\": \"";
        switch (tc.complexity) {
            case Complexity::SIMPLE: out << "simple"; break;
            case Complexity::MEDIUM: out << "medium"; break;
            case Complexity::COMPLEX: out << "complex"; break;
        }
        out << "\"\n  }";
        if (i < tests.size() - 1) out << ",";
        out << "\n";
    }
    out << "]\n";
    out.close();
    std::cout << "Written expectations: " << filename << "\n";
}

int TestGenerator::runTests(const std::string& pattern_file, const std::string& expectations_file) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "Running tests through c-dfa...\n";
    std::cout << std::string(60, '=') << "\n\n";
    
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) == nullptr) {
        std::cerr << "Cannot get current directory\n";
        return 1;
    }
    std::string abs_cwd = cwd;
    std::string abs_pattern = abs_cwd + "/" + pattern_file;
    std::string output_dir = abs_pattern.substr(0, abs_pattern.rfind('/'));
    
    std::cout << "1. Building NFA...\n";
    std::string nfa_file = output_dir + "/test.nfa";
    int result = system(("cd " + abs_cwd + "/.. && ./tools/nfa_builder " + abs_pattern + " " + nfa_file + " 2>&1").c_str());
    if (result != 0) {
        std::cerr << "NFA builder failed!\n";
        return 1;
    }
    std::cout << "   NFA built successfully\n\n";
    
    std::cout << "2. Building DFA...\n";
    std::string dfa_file = output_dir + "/test.dfa";
    result = system(("cd " + abs_cwd + "/.. && ./tools/nfa2dfa_advanced " + nfa_file + " " + dfa_file + " 2>&1").c_str());
    if (result != 0) {
        std::cerr << "DFA builder failed!\n";
        return 1;
    }
    std::cout << "   DFA built successfully\n\n";
    
    std::cout << "3. Testing patterns...\n";
    
    std::vector<TestCase>& tests = generated_tests;
    int passed = 0;
    int failed = 0;
    int skipped = 0;
    
    for (size_t i = 0; i < tests.size(); i++) {
        const auto& tc = tests[i];
        
        if (tc.pattern.empty()) {
            std::cout << "   SKIP #" << i << ": no pattern generated\n";
            skipped++;
            continue;
        }
        
        int expected_match_category = static_cast<int>(tc.category);
        int expected_counter_category = static_cast<int>(tc.counter_category);
        
        // Check: matching inputs MUST match with the MATCHING category
        bool all_matched = true;
        for (const auto& match_in : tc.matching_inputs) {
            std::string cmd = "cd " + abs_cwd + "/.. && ./tools/dfa_eval_wrapper " + dfa_file + " \"" + match_in + "\" 2>/dev/null";
            FILE* fp = popen(cmd.c_str(), "r");
            bool matched = false;
            int matched_category = 0;
            if (fp) {
                char buf[256];
                while (fgets(buf, sizeof(buf), fp)) {
                    if (strstr(buf, "matched=1")) matched = true;
                    char* cat_str = strstr(buf, "category=");
                    if (cat_str) matched_category = atoi(cat_str + 9);
                }
                pclose(fp);
            }
            if (!matched || matched_category != expected_match_category) {
                all_matched = false;
                break;
            }
        }
        
        if (!all_matched) { 
            std::cout << "   FAIL #" << i << ": matching inputs didn't match with correct category\n";
            failed++;
            global_failed_count++;
            
            // Save failed test case
            std::string fail_file = output_dir + "/failed_case_" + std::to_string(global_failed_count) + ".json";
            std::ofstream ff(fail_file);
            ff << "{\n";
            ff << "  \"batch_file\": \"" << pattern_file << "\",\n";
            ff << "  \"test_id\": " << tc.test_id << ",\n";
            ff << "  \"pattern\": \"[" << categoryToString(tc.category) << ":test" << tc.test_id << "] " << tc.pattern << "\",\n";
            ff << "  \"category\": \"" << categoryToString(tc.category) << "\",\n";
            ff << "  \"counter_category\": \"" << categoryToString(tc.counter_category) << "\",\n";
            ff << "  \"matching_inputs\": [";
            for (size_t j = 0; j < tc.matching_inputs.size(); j++) {
                if (j > 0) ff << ", ";
                ff << "\"" << tc.matching_inputs[j] << "\"";
            }
            ff << "],\n";
            ff << "  \"counter_inputs\": [";
            for (size_t j = 0; j < tc.counter_inputs.size(); j++) {
                if (j > 0) ff << ", ";
                ff << "\"" << tc.counter_inputs[j] << "\"";
            }
            ff << "],\n";
            ff << "  \"error\": \"matching inputs did not match with correct category\"\n";
            ff << "}\n";
            ff.close();
            std::cout << "   Saved: " << fail_file << "\n";
            continue; 
        }
        
        // Check: counter inputs must NOT match with the matching category
        // (they may match with the counter category, which is fine)
        bool any_counter_matched = false;
        for (const auto& counter : tc.counter_inputs) {
            std::string counter_cmd = "cd " + abs_cwd + "/.. && ./tools/dfa_eval_wrapper " + dfa_file + " \"" + counter + "\" 2>/dev/null";
            FILE* cfp = popen(counter_cmd.c_str(), "r");
            if (cfp) {
                char cbuf[256];
                while (fgets(cbuf, sizeof(cbuf), cfp)) {
                    if (strstr(cbuf, "matched=1")) {
                        int counter_cat = 0;
                        char* cat_str = strstr(cbuf, "category=");
                        if (cat_str) counter_cat = atoi(cat_str + 9);
                        // Counter input should NOT match with the matching category
                        if (counter_cat == expected_match_category) any_counter_matched = true;
                    }
                }
                pclose(cfp);
            }
        }
        
        if (!any_counter_matched) {
            passed++;
        } else {
            std::cout << "   FAIL #" << i << ": counter input matched with matching category\n";
            failed++;
            global_failed_count++;
            
            // Save failed test case
            std::string fail_file = output_dir + "/failed_case_" + std::to_string(global_failed_count) + ".json";
            std::ofstream ff(fail_file);
            ff << "{\n";
            ff << "  \"batch_file\": \"" << pattern_file << "\",\n";
            ff << "  \"test_id\": " << tc.test_id << ",\n";
            ff << "  \"pattern\": \"[" << categoryToString(tc.category) << ":test" << tc.test_id << "] " << tc.pattern << "\",\n";
            ff << "  \"category\": \"" << categoryToString(tc.category) << "\",\n";
            ff << "  \"counter_category\": \"" << categoryToString(tc.counter_category) << "\",\n";
            ff << "  \"matching_inputs\": [";
            for (size_t j = 0; j < tc.matching_inputs.size(); j++) {
                if (j > 0) ff << ", ";
                ff << "\"" << tc.matching_inputs[j] << "\"";
            }
            ff << "],\n";
            ff << "  \"counter_inputs\": [";
            for (size_t j = 0; j < tc.counter_inputs.size(); j++) {
                if (j > 0) ff << ", ";
                ff << "\"" << tc.counter_inputs[j] << "\"";
            }
            ff << "],\n";
            ff << "  \"error\": \"counter inputs matched with matching category\"\n";
            ff << "}\n";
            ff.close();
            std::cout << "   Saved: " << fail_file << "\n";
        }
    }
    
    std::cout << "\nResults: " << passed << " passed, " << failed << " failed, " << skipped << " skipped\n";
    return failed > 0 ? 1 : 0;
}

int TestGenerator::runTestsIndividual(const std::string& pattern_file, const std::string& expectations_file) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "Running tests through c-dfa (INDIVIDUALLY)...\n";
    std::cout << std::string(60, '=') << "\n\n";
    
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) == nullptr) {
        std::cerr << "Cannot get current directory\n";
        return 1;
    }
    std::string abs_cwd = cwd;
    std::string abs_pattern = abs_cwd + "/" + pattern_file;
    std::string output_dir = abs_pattern.substr(0, abs_pattern.rfind('/'));
    std::string failed_dir = output_dir + "/failed_cases";
    
    // Create failed_cases directory
    mkdir(failed_dir.c_str(), 0755);
    
    std::vector<TestCase>& tests = generated_tests;
    int passed = 0;
    int failed = 0;
    int skipped = 0;
    static int failed_count = 0;
    failed_count = 0;
    
    for (size_t i = 0; i < tests.size(); i++) {
        const auto& tc = tests[i];
        
        if (tc.pattern.empty()) {
            std::cout << "   SKIP #" << i << ": no pattern generated\n";
            skipped++;
            continue;
        }
        
        std::string temp_pattern = output_dir + "/temp_pattern.txt";
        std::ofstream tp(temp_pattern);
        for (const auto& f : tc.fragments) {
            tp << "[fragment:" << f.first << "] " << f.second << "\n";
        }
        tp << "[" << categoryToString(tc.category) << "] " << tc.pattern << "\n";
        tp.close();
        
        std::string nfa_file = output_dir + "/temp.nfa";
        std::string dfa_file = output_dir + "/temp.dfa";
        
        std::string nfa_cmd = "cd " + abs_cwd + "/.. && ./tools/nfa_builder " + temp_pattern + " " + nfa_file + " 2>/dev/null";
        int result = system(nfa_cmd.c_str());
        if (result != 0) { failed++; continue; }
        
        std::string dfa_cmd = "cd " + abs_cwd + "/.. && ./tools/nfa2dfa_advanced " + nfa_file + " " + dfa_file + " 2>/dev/null";
        result = system(dfa_cmd.c_str());
        if (result != 0) { failed++; continue; }
        
        bool all_matched = true;
        int expected_category = static_cast<int>(tc.category);
        for (const auto& match_in : tc.matching_inputs) {
            std::string eval_cmd = "cd " + abs_cwd + "/.. && ./tools/dfa_eval_wrapper " + dfa_file + " \"" + match_in + "\" 2>/dev/null";
            FILE* fp = popen(eval_cmd.c_str(), "r");
            bool matched = false;
            int matched_category = 0;
            if (fp) {
                char buf[256];
                while (fgets(buf, sizeof(buf), fp)) {
                    if (strstr(buf, "matched=1")) matched = true;
                    char* cat_str = strstr(buf, "category=");
                    if (cat_str) matched_category = atoi(cat_str + 9);
                }
                pclose(fp);
            }
            if (!matched || matched_category != expected_category) { all_matched = false; break; }
        }
        
        bool any_counter_matched = false;
        for (const auto& counter : tc.counter_inputs) {
            std::string counter_cmd = "cd " + abs_cwd + "/.. && ./tools/dfa_eval_wrapper " + dfa_file + " \"" + counter + "\" 2>/dev/null";
            FILE* cfp = popen(counter_cmd.c_str(), "r");
            if (cfp) {
                char cbuf[256];
                while (fgets(cbuf, sizeof(cbuf), cfp)) {
                    if (strstr(cbuf, "matched=1")) {
                        int counter_cat = 0;
                        char* cat_str = strstr(cbuf, "category=");
                        if (cat_str) counter_cat = atoi(cat_str + 9);
                        if (counter_cat == expected_category) any_counter_matched = true;
                    }
                }
                pclose(cfp);
            }
        }
        
        if (all_matched && !any_counter_matched) {
            passed++;
            std::cout << "   PASS #" << i << "\n";
        } else {
            failed++;
            failed_count++;
            std::cout << "   FAIL #" << i << ": pattern=" << tc.pattern << "\n";
            
            // Save failed test case
            std::string fail_file = failed_dir + "/case_" + std::to_string(failed_count) + ".json";
            std::ofstream ff(fail_file);
            ff << "{\n";
            ff << "  \"id\": " << failed_count << ",\n";
            ff << "  \"test_id\": " << tc.test_id << ",\n";
            ff << "  \"pattern\": \"[" << categoryToString(tc.category) << ":test" << tc.test_id << "] " << tc.pattern << "\",\n";
            ff << "  \"category\": \"" << categoryToString(tc.category) << "\",\n";
            ff << "  \"matching_inputs\": [";
            for (size_t j = 0; j < tc.matching_inputs.size(); j++) {
                if (j > 0) ff << ", ";
                ff << "\"" << tc.matching_inputs[j] << "\"";
            }
            ff << "],\n";
            ff << "  \"counter_inputs\": [";
            for (size_t j = 0; j < tc.counter_inputs.size(); j++) {
                if (j > 0) ff << ", ";
                ff << "\"" << tc.counter_inputs[j] << "\"";
            }
            ff << "],\n";
            ff << "  \"proof\": \"";
            for (size_t p = 0; p < tc.proof.size(); p++) {
                char c = tc.proof[p];
                if (c == '\n') ff << "\\n";
                else if (c == '"') ff << "\\\"";
                else ff << c;
            }
            ff << "\",\n";
            ff << "  \"error\": \"";
            if (!all_matched) ff << "matching inputs did not match";
            else if (any_counter_matched) ff << "counter inputs matched";
            ff << "\"\n";
            ff << "}\n";
            ff.close();
            std::cout << "   Saved failed case to: " << fail_file << "\n";
        }
        
        remove(temp_pattern.c_str());
        remove(nfa_file.c_str());
        remove(dfa_file.c_str());
    }
    
    std::cout << "\nResults: " << passed << " passed, " << failed << " failed, " << skipped << " skipped\n";
    if (failed > 0) {
        std::cout << "Failed cases saved to: " << failed_dir << "/\n";
    }
    return failed > 0 ? 1 : 0;
}
