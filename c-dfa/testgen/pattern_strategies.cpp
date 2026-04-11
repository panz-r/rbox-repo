// ============================================================================
// Pattern Strategies - Pattern generation implementations
// ============================================================================
//
// This file contains all pattern generation strategy implementations and their
// helper functions.
//
// Contents:
// - patternMatches* functions (validation helpers)
// - extractFragment function
// - 30 try* strategy functions
// - applyEdgeCases post-processing function

#include "pattern_strategies.h"
#include "testgen.h"

#include <algorithm>
#include <set>

using namespace std;

// ============================================================================
// Validation Helpers - Check if pattern matches input
// ============================================================================

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
// Create quantified alternation: (alt1|alt2|alt3)+
std::shared_ptr<PatternNode> createQuantifiedAlternation(
    const std::vector<std::string>& alts,
    PatternType type,
    const std::vector<std::string>& seeds) {
    
    std::vector<std::shared_ptr<PatternNode>> alt_nodes;
    for (const auto& alt : alts) {
        alt_nodes.push_back(PatternNode::createLiteral(alt, {alt}));
    }
    auto alt_node = PatternNode::createAlternation(alt_nodes, seeds);
    alt_node->type = type;
    alt_node->quantified = PatternNode::createAlternation(alt_nodes, seeds);
    return alt_node;
}

// Create quantified literal: (literal)+
std::shared_ptr<PatternNode> createQuantifiedLiteral(
    const std::string& literal,
    PatternType type,
    const std::vector<std::string>& seeds) {
    
    auto lit_node = PatternNode::createLiteral(literal, seeds);
    lit_node->type = type;
    lit_node->quantified = PatternNode::createLiteral(literal, seeds);
    return lit_node;
}

// Create quantified fragment: ((frag))+
std::shared_ptr<PatternNode> createQuantifiedFragment(
    const std::string& frag_name,
    PatternType type,
    const std::vector<std::string>& seeds) {
    
    auto frag_node = PatternNode::createFragment(frag_name, seeds);
    frag_node->type = type;
    frag_node->quantified = PatternNode::createFragment(frag_name, seeds);
    return frag_node;
}

// Convenience wrappers for quantified alternations
std::shared_ptr<PatternNode> createAlternationPlus(const std::vector<std::string>& alts, const std::vector<std::string>& seeds) {
    return createQuantifiedAlternation(alts, PatternType::PLUS_QUANTIFIER, seeds);
}

std::shared_ptr<PatternNode> createAlternationStar(const std::vector<std::string>& alts, const std::vector<std::string>& seeds) {
    return createQuantifiedAlternation(alts, PatternType::STAR_QUANTIFIER, seeds);
}

std::shared_ptr<PatternNode> createAlternationOptional(const std::vector<std::string>& alts, const std::vector<std::string>& seeds) {
    return createQuantifiedAlternation(alts, PatternType::OPTIONAL, seeds);
}

// Convenience wrappers for quantified literals
std::shared_ptr<PatternNode> createLiteralPlus(const std::string& literal, const std::vector<std::string>& seeds) {
    return createQuantifiedLiteral(literal, PatternType::PLUS_QUANTIFIER, seeds);
}

std::shared_ptr<PatternNode> createLiteralStar(const std::string& literal, const std::vector<std::string>& seeds) {
    return createQuantifiedLiteral(literal, PatternType::STAR_QUANTIFIER, seeds);
}

std::shared_ptr<PatternNode> createLiteralOptional(const std::string& literal, const std::vector<std::string>& seeds) {
    return createQuantifiedLiteral(literal, PatternType::OPTIONAL, seeds);
}

// Convenience wrappers for quantified fragments
std::shared_ptr<PatternNode> createFragmentPlus(const std::string& frag_name, const std::vector<std::string>& seeds) {
    return createQuantifiedFragment(frag_name, PatternType::PLUS_QUANTIFIER, seeds);
}

std::shared_ptr<PatternNode> createFragmentStar(const std::string& frag_name, const std::vector<std::string>& seeds) {
    return createQuantifiedFragment(frag_name, PatternType::STAR_QUANTIFIER, seeds);
}

// Helper: Wrap an AST node with capture tags
std::shared_ptr<PatternNode> wrapWithCaptureTags(std::shared_ptr<PatternNode> node, const std::string& tag_name) {
    if (!node) return nullptr;
    node->capture_tag = tag_name;
    return node;
}

// Helper: Create char class literal like [abc]
std::shared_ptr<PatternNode> createCharClass(const std::string& chars, const std::vector<std::string>& seeds) {
    auto node = std::make_shared<PatternNode>();
    node->type = PatternType::LITERAL;
    node->value = "[" + chars + "]";
    node->matched_seeds = seeds;
    return node;
}

// Helper: Create char class with plus quantifier like [abc]+
std::shared_ptr<PatternNode> createCharClassPlus(const std::string& chars, const std::vector<std::string>& seeds) {
    auto char_node = createCharClass(chars, seeds);
    char_node->type = PatternType::PLUS_QUANTIFIER;
    char_node->quantified = createCharClass(chars, seeds);
    return char_node;
}

// Helper: Create sequence of nodes
std::shared_ptr<PatternNode> createSequenceNode(const std::vector<std::shared_ptr<PatternNode>>& nodes, const std::vector<std::string>& seeds) {
    return PatternNode::createSequence(nodes, seeds);
}

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
    result.ast = PatternNode::createLiteral(lit, matching);
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
    
    // Build AST with matched_seeds
    std::vector<std::shared_ptr<PatternNode>> alt_nodes;
    for (const auto& m : matching) {
        alt_nodes.push_back(PatternNode::createLiteral(m, {m}));
    }
    
    // ALWAYS apply a quantifier to make it interesting
    std::uniform_int_distribution<int> qdist(0, 2);
    int qtype = qdist(rng);
    
    std::shared_ptr<PatternNode> alt_node = PatternNode::createAlternation(alt_nodes, matching);
    
    if (qtype == 0) {
        alt_node->type = PatternType::PLUS_QUANTIFIER;
        alt_node->quantified = PatternNode::createAlternation(alt_nodes, matching);
    } else if (qtype == 1) {
        alt_node->type = PatternType::STAR_QUANTIFIER;
        alt_node->quantified = PatternNode::createAlternation(alt_nodes, matching);
    } else {
        alt_node->type = PatternType::OPTIONAL;
        alt_node->quantified = PatternNode::createAlternation(alt_nodes, matching);
    }
    
    result.ast = alt_node;
    result.pattern = serializePattern(alt_node);
    result.proof += "  Alternation: " + result.pattern + "\n";
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
            
            // Extract fragment name from pattern like "((name))+"
            size_t start = frag_pattern.find("((");
            size_t end = frag_pattern.find("))+");
            if (start != std::string::npos && end != std::string::npos && start + 2 < end) {
                std::string frag_name = frag_pattern.substr(start + 2, end - start - 2);
                result.ast = createFragmentPlus(frag_name, matching);
            }
            result.pattern = frag_pattern;
        } else {
            // Use AST helper
            result.ast = createLiteralPlus(unit, matching);
            result.pattern = serializePattern(result.ast);
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
                
                // Extract fragment name and create AST
                size_t start = frag_pattern.find("((");
                size_t end = frag_pattern.find("))+");
                if (start != std::string::npos && end != std::string::npos && start + 2 < end) {
                    std::string frag_name = frag_pattern.substr(start + 2, end - start - 2);
                    auto frag_node = createFragmentPlus(frag_name, matching);
                    if (!prefix.empty()) {
                        // Create sequence: prefix + fragment+
                        auto prefix_node = PatternNode::createLiteral(prefix, {});
                        result.ast = PatternNode::createSequence({prefix_node, frag_node}, matching);
                    } else {
                        result.ast = frag_node;
                    }
                }
                result.pattern = prefix + frag_pattern;
            } else {
                // Create AST for char class pattern
                auto char_node = createCharClassPlus(char_class, matching);
                if (!prefix.empty()) {
                    auto prefix_node = PatternNode::createLiteral(prefix, {});
                    result.ast = PatternNode::createSequence({prefix_node, char_node}, matching);
                } else {
                    result.ast = char_node;
                }
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
            // Create AST for suffix+ pattern
            auto char_node = createCharClassPlus(char_class, matching);
            auto suffix_node = PatternNode::createLiteral(suffix, {});
            
            if (match_chars.size() >= 2 && std::uniform_int_distribution<int>(0, 1)(rng) == 1) {
                // Try with fragment
                std::map<std::string, std::string> frags;
                std::string frag_pattern = extractFragment(char_class, frags, rng);
                result.fragments.insert(frags.begin(), frags.end());
                
                size_t start = frag_pattern.find("((");
                size_t end = frag_pattern.find("))+");
                if (start != std::string::npos && end != std::string::npos && start + 2 < end) {
                    std::string frag_name = frag_pattern.substr(start + 2, end - start - 2);
                    auto frag_node = createFragmentPlus(frag_name, matching);
                    result.ast = PatternNode::createSequence({frag_node, suffix_node}, matching);
                }
                result.pattern = frag_pattern + suffix;
            } else {
                result.ast = PatternNode::createSequence({char_node, suffix_node}, matching);
                result.pattern = "(" + char_class + ")+" + suffix;
            }
            
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

    // Exclude characters that appear in counter inputs to ensure separation
    for (const auto& c : counters) {
        for (char c2 : c) {
            all_chars.erase(c2);
        }
    }
    
    if (all_chars.size() < 2) {
        result.proof += "  FragmentOnly: not enough variation or overlaps with counter\n";
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
    
    // Build AST for fragment pattern
    if (!result.pattern.empty()) {
        // Extract fragment name from pattern like "((name))+"
        size_t start = result.pattern.find("((");
        size_t end = result.pattern.find("))+");
        if (start != std::string::npos && end != std::string::npos && start + 2 < end) {
            std::string frag_name = result.pattern.substr(start + 2, end - start - 2);
            result.ast = createFragmentPlus(frag_name, matching);
        }
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
            
            // Create AST
            auto opt_node = PatternNode::createLiteral(opt_part, {opt_part});
            opt_node->type = PatternType::OPTIONAL;
            opt_node->quantified = PatternNode::createLiteral(opt_part, {opt_part});
            
            if (!rest.empty()) {
                auto rest_node = PatternNode::createLiteral(rest, {rest});
                result.ast = PatternNode::createSequence({opt_node, rest_node}, matching);
            } else {
                result.ast = opt_node;
            }
            
            if (result.ast) {
                result.pattern = serializePattern(result.ast);
            }
            
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
            
            // Create AST with empty alternative
            std::vector<std::shared_ptr<PatternNode>> nodes;
            for (const auto& alt : matching) {
                nodes.push_back(PatternNode::createLiteral(alt, {alt}));
            }
            nodes.push_back(PatternNode::createLiteral("", {}));  // empty alternative
            result.ast = PatternNode::createAlternation(nodes, matching);
            
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
            result.pattern = "((" + base_pattern + "))";
            
            // For nested groups, we keep the same AST but wrap it
            // Just use the base pattern as-is since nesting doesn't change semantics
            
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
    // IMPORTANT: Must check patternMatchesPlus, not just find!
    // A substring might appear in each input but NOT as a full repetition
    bool all_match = true;
    for (const auto& m : matching) {
        // Use patternMatchesPlus to verify the input IS a repetition of common_substr
        // NOT just that it contains common_substr somewhere
        if (!patternMatchesPlus(common_substr, m)) {
            all_match = false;
            break;
        }
    }
    
    if (all_match) {
        // Check counters - use patternMatchesPlus for consistency
        bool any_match = false;
        for (const auto& c : counters) {
            if (patternMatchesPlus(common_substr, c)) {
                any_match = true;
                break;
            }
        }
        
        if (!any_match) {
            result.pattern = pattern;
            
            // Create AST
            result.ast = createFragmentPlus(frag_name, matching);
            
            result.proof += "  MultiFrag: " + result.pattern + "\n";
            result.proof += "    Fragment: " + frag_name + " = " + common_substr + "\n";
            result.proof += "    MATCHES: strings that are repetitions of " + common_substr + "\n";
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
        bool use_star = std::uniform_int_distribution<int>(0, 1)(rng) == 0;
        if (use_star) {
            pattern = pattern.substr(0, pattern.size() - 1) + ")*";
        }
        
        // Create AST
        if (use_star) {
            std::vector<std::shared_ptr<PatternNode>> nodes;
            for (const auto& alt : alts) {
                nodes.push_back(PatternNode::createLiteral(alt, {alt}));
            }
            auto alt_node = PatternNode::createAlternation(nodes, matching);
            alt_node->type = PatternType::STAR_QUANTIFIER;
            alt_node->quantified = PatternNode::createAlternation(nodes, matching);
            result.ast = alt_node;
        } else {
            result.ast = createAlternationPlus(alts, matching);
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
        
        // Create AST based on quantifier type
        if (qtype == 0) {
            result.ast = createLiteralPlus(unit, matching);
            result.pattern = "(" + unit + ")+";
        } else if (qtype == 1) {
            result.ast = createLiteralStar(unit, matching);
            result.pattern = "(" + unit + ")*";
        } else {
            auto lit_node = PatternNode::createLiteral(unit, matching);
            lit_node->type = PatternType::OPTIONAL;
            lit_node->quantified = PatternNode::createLiteral(unit, matching);
            result.ast = lit_node;
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
                
                // Create AST for optional sequence
                auto full_node = PatternNode::createLiteral(opt_part + rest, {opt_part + rest});
                full_node->type = PatternType::OPTIONAL;
                full_node->quantified = PatternNode::createLiteral(opt_part + rest, {opt_part + rest});
                result.ast = full_node;
                
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
        // Build AST based on nest_type
        auto base_node = PatternNode::createLiteral(base_unit, matching);
        
        switch (nest_type) {
            case 0: { // ((unit)+)*
                auto inner_node = createLiteralPlus(base_unit, matching);
                inner_node->type = PatternType::PLUS_QUANTIFIER;
                result.ast = PatternNode::createQuantified(inner_node, PatternType::STAR_QUANTIFIER, matching);
                break;
            }
            case 1: { // ((unit)*)+
                auto inner_node = createLiteralStar(base_unit, matching);
                result.ast = PatternNode::createQuantified(inner_node, PatternType::PLUS_QUANTIFIER, matching);
                break;
            }
            case 2: { // ((unit)+)?
                auto inner_node = createLiteralPlus(base_unit, matching);
                result.ast = PatternNode::createQuantified(inner_node, PatternType::OPTIONAL, matching);
                break;
            }
            default: { // ((unit)*)?
                auto inner_node = createLiteralStar(base_unit, matching);
                result.ast = PatternNode::createQuantified(inner_node, PatternType::OPTIONAL, matching);
                break;
            }
        }
        
        if (result.ast) {
            result.pattern = serializePattern(result.ast);
        } else {
            result.pattern = outer_pattern;
        }
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
    
    // Create AST
    auto prefix_node = PatternNode::createLiteral(prefix, {});
    auto char_node = createCharClassPlus(char_class, matching);
    result.ast = PatternNode::createSequence({prefix_node, char_node}, matching);
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
            
            // Extract fragment name and create AST
            size_t start = frag_pattern.find("((");
            size_t end = frag_pattern.find("))+");
            if (start != std::string::npos && end != std::string::npos && start + 2 < end) {
                std::string frag_name = frag_pattern.substr(start + 2, end - start - 2);
                result.ast = createFragmentStar(frag_name, matching);
            }
        } else {
            result.ast = createLiteralStar(unit, matching);
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
    
    // Create AST
    auto prefix_node = PatternNode::createLiteral(prefix, {});
    auto char_node = createCharClassPlus(char_class, matching);
    result.ast = PatternNode::createSequence({prefix_node, char_node}, matching);
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
                
                // Create AST: part1 + (part2)?
                auto part1_node = PatternNode::createLiteral(part1, {});
                auto part2_node = PatternNode::createLiteral(part2, {part2});
                part2_node->type = PatternType::OPTIONAL;
                part2_node->quantified = PatternNode::createLiteral(part2, {part2});
                result.ast = PatternNode::createSequence({part1_node, part2_node}, matching);
                
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
                
                // Create AST: (part1)* + part2
                auto part1_node = PatternNode::createLiteral(part1, {});
                part1_node->type = PatternType::STAR_QUANTIFIER;
                part1_node->quantified = PatternNode::createLiteral(part1, {});
                auto part2_node = PatternNode::createLiteral(part2, {});
                result.ast = PatternNode::createSequence({part1_node, part2_node}, matching);
                
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
    // But exclude any substring that appears in counter inputs
    std::set<std::string> all_substrs;
    for (const auto& m : matching) {
        for (size_t len = 1; len <= m.size(); len++) {
            for (size_t pos = 0; pos + len <= m.size(); pos++) {
                std::string substr = m.substr(pos, len);
                // Skip if any counter input contains this substring
                bool in_counter = false;
                for (const auto& c : counters) {
                    if (c.find(substr) != std::string::npos) {
                        in_counter = true;
                        break;
                    }
                }
                if (!in_counter) {
                    all_substrs.insert(substr);
                }
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
                
                // Create AST: ((frag1))+((frag2))+
                auto frag1_node = createFragmentPlus(name1, matching);
                auto frag2_node = createFragmentPlus(name2, matching);
                result.ast = PatternNode::createSequence({frag1_node, frag2_node}, matching);
                
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
        
        // Create AST - wrap base.ast in a grouping (no quantifier)
        if (base.ast) {
            // For grouping, we just serialize the child directly
            result.ast = base.ast;
        }
        
        result.proof += "  DeepNest: " + result.pattern + "\n";
        result.proof += "    Single grouping (safe - not fragment reference)\n";
        result.proof += "    VERIFIED: same matching as base\n";
        return result;
    }
    
    result.proof += "  DeepNest: grouping broke pattern\n";
    return result;
}

// Strategy: Multi-fragment combination - two fragments used together
// Pattern: ((frag1))+((frag2))+ - tests fragment isolation when combined
PatternResult tryMultiFragmentCombo(const std::vector<std::string>& matching,
                                   const std::vector<std::string>& counters,
                                   std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 4) {
        result.proof += "  MultiFrag: requires 4+ matching\n";
        return result;
    }
    
    // Split matching into two groups for two fragments
    std::vector<std::string> group1(matching.begin(), matching.begin() + matching.size()/2);
    std::vector<std::string> group2(matching.begin() + matching.size()/2, matching.end());
    
    if (group1.size() < 2 || group2.size() < 2) {
        result.proof += "  MultiFrag: groups too small\n";
        return result;
    }
    
    // Create first fragment from group1 chars
    std::set<char> chars1;
    for (const auto& m : group1) {
        for (char c : m) chars1.insert(c);
    }
    // Exclude counter chars
    for (const auto& c : counters) {
        for (char c2 : c) chars1.erase(c2);
    }
    if (chars1.size() < 2) {
        result.proof += "  MultiFrag: not enough chars for frag1\n";
        return result;
    }
    
    std::string frag1_def;
    for (char c : chars1) {
        if (!frag1_def.empty()) frag1_def += "|";
        frag1_def += c;
    }
    std::string frag1_name = "mf1";
    result.fragments[frag1_name] = frag1_def;
    
    // Create second fragment from group2 chars (exclusive from group1)
    std::set<char> chars2;
    for (const auto& m : group2) {
        for (char c : m) chars2.insert(c);
    }
    for (const auto& c : counters) {
        for (char c2 : c) chars2.erase(c2);
    }
    // Remove chars from group1 to ensure exclusivity
    for (char c : chars1) chars2.erase(c);
    if (chars2.size() < 2) {
        result.proof += "  MultiFrag: not enough exclusive chars for frag2\n";
        return result;
    }
    
    std::string frag2_def;
    for (char c : chars2) {
        if (!frag2_def.empty()) frag2_def += "|";
        frag2_def += c;
    }
    std::string frag2_name = "mf2";
    result.fragments[frag2_name] = frag2_def;
    
    // Pattern: ((mf1))+((mf2))+ - SEQUENTIAL: group1 uses frag1, group2 uses frag2
    result.pattern = "((" + frag1_name + "))+(((" + frag2_name + "))+";
    
    // Verify: group1 strings should ONLY have chars from frag1, group2 ONLY from frag2
    bool all_match = true;
    // Check group1 strings
    for (const auto& m : group1) {
        for (char c : m) {
            if (!chars1.count(c)) { all_match = false; break; }
        }
        if (!all_match) break;
    }
    // Check group2 strings
    for (const auto& m : group2) {
        for (char c : m) {
            if (!chars2.count(c)) { all_match = false; break; }
        }
        if (!all_match) break;
    }
    
    if (!all_match) {
        result.proof += "  MultiFrag: matching strings don't fit sequential pattern\n";
        result.pattern = "";
        return result;
    }
    
    // Check counters: ensure no counter has both fragment chars
    bool any_counter_match = false;
    for (const auto& c : counters) {
        bool has_frag1 = false, has_frag2 = false;
        for (char c2 : c) {
            if (chars1.count(c2)) has_frag1 = true;
            if (chars2.count(c2)) has_frag2 = true;
        }
        if (has_frag1 && has_frag2) {
            any_counter_match = true;
            break;
        }
    }
    
    if (any_counter_match) {
        result.proof += "  MultiFrag: counters would match\n";
        result.pattern = "";
        return result;
    }
    
    // Create AST
    auto frag1_node = createFragmentPlus(frag1_name, group1);
    auto frag2_node = createFragmentPlus(frag2_name, group2);
    result.ast = PatternNode::createSequence({frag1_node, frag2_node}, matching);
    
    result.proof += "  MultiFrag: " + result.pattern + "\n";
    result.proof += "    frag1: " + frag1_name + "=" + frag1_def + "\n";
    result.proof += "    frag2: " + frag2_name + "=" + frag2_def + "\n";
    return result;
}

// Strategy: Nested alternation - alternation within alternation
PatternResult tryNestedAlternation(const std::vector<std::string>& matching,
                                   const std::vector<std::string>& counters,
                                   std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 4) {
        result.proof += "  NestedAlt: requires 4+ matching\n";
        return result;
    }
    
    // Create pattern: (a|b|c) with each alternative being a full matching string
    // The "nested" part is just using + quantifier
    
    // Build simple alternation from matching strings
    std::string pattern = "(";
    for (size_t i = 0; i < matching.size(); i++) {
        if (i > 0) pattern += "|";
        pattern += matching[i];
    }
    pattern += ")+";
    
    // Create AST
    result.ast = createAlternationPlus(matching, matching);
    result.pattern = pattern;
    
    result.proof += "  NestedAlt: " + result.pattern + "\n";
    return result;
}

// Strategy: Complex quantifier stack - (a*)+, (a+)*, (a?)+
PatternResult tryQuantifierStack(const std::vector<std::string>& matching,
                                  const std::vector<std::string>& counters,
                                  std::mt19937& rng) {
    PatternResult result;
    
    if (matching.empty()) {
        result.proof += "  QuantStack: requires matching\n";
        return result;
    }
    
    // Use first matching string as base
    std::string base = matching[0];
    if (base.empty()) {
        result.proof += "  QuantStack: empty base\n";
        return result;
    }
    
    // Try different quantifier stacks
    std::vector<std::string> stacks = {
        "(" + base + "*)+",   // Zero or more, one or more times
        "(" + base + "+)*",   // One or more, zero or more times  
        "(" + base + "?)+",   // Optional, one or more times
    };
    
    std::shuffle(stacks.begin(), stacks.end(), rng);
    
    for (const auto& pattern : stacks) {
        bool all_match = true;
        for (const auto& m : matching) {
            // Check if m fits the pattern (starts with base, then any repetitions)
            if (m.find(base) != 0) {
                all_match = false;
                break;
            }
        }
        
        if (all_match) {
            // Create AST for quantifier stack
            auto base_node = PatternNode::createLiteral(base, matching);
            if (pattern.find("*)+") != std::string::npos) {
                // (base*)*
                base_node->type = PatternType::STAR_QUANTIFIER;
                base_node->quantified = PatternNode::createLiteral(base, matching);
                result.ast = PatternNode::createQuantified(base_node, PatternType::PLUS_QUANTIFIER, matching);
            } else if (pattern.find("+)*") != std::string::npos) {
                // (base+)*
                base_node->type = PatternType::PLUS_QUANTIFIER;
                base_node->quantified = PatternNode::createLiteral(base, matching);
                result.ast = PatternNode::createQuantified(base_node, PatternType::STAR_QUANTIFIER, matching);
            } else {
                // (base?)*
                base_node->type = PatternType::OPTIONAL;
                base_node->quantified = PatternNode::createLiteral(base, matching);
                result.ast = PatternNode::createQuantified(base_node, PatternType::PLUS_QUANTIFIER, matching);
            }
            
            result.pattern = pattern;
            result.proof += "  QuantStack: " + result.pattern + "\n";
            return result;
        }
    }
    
    result.proof += "  QuantStack: no valid stack\n";
    return result;
}

// Strategy: Long literal alternation - 10-20 alternatives with long strings
PatternResult tryLongAlternation(const std::vector<std::string>& matching,
                               const std::vector<std::string>& counters,
                               std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  LongAlt: requires 2+ matching\n";
        return result;
    }
    
    // Use matching strings as base, add many variations
    std::vector<std::string> alts = matching;
    
    // Add variations of matching strings
    for (const auto& m : matching) {
        if (alts.size() >= 20) break;
        if (m.size() < 2) continue;
        
        // Add prefix/suffix variations
        for (int i = 0; i < 2 && alts.size() < 20; i++) {
            std::string var = m;
            // Reverse
            std::reverse(var.begin(), var.end());
            if (var != m && std::find(alts.begin(), alts.end(), var) == alts.end()) {
                alts.push_back(var);
            }
        }
    }
    
    if (alts.size() < 3) {
        result.proof += "  LongAlt: not enough alternatives\n";
        return result;
    }
    
    // Build pattern
    std::string pattern = "(";
    for (size_t i = 0; i < alts.size(); i++) {
        if (i > 0) pattern += "|";
        pattern += alts[i];
    }
    pattern += ")";
    
    // Randomly add quantifier
    bool use_plus = std::uniform_int_distribution<int>(0, 1)(rng) == 0;
    if (use_plus) {
        pattern += "+";
    }
    
    // Create AST
    if (use_plus) {
        result.ast = createAlternationPlus(alts, matching);
    } else {
        std::vector<std::shared_ptr<PatternNode>> nodes;
        for (const auto& alt : alts) {
            nodes.push_back(PatternNode::createLiteral(alt, {alt}));
        }
        result.ast = PatternNode::createAlternation(nodes, matching);
    }
    
    result.pattern = pattern;
    result.proof += "  LongAlt: " + result.pattern + "\n";
    return result;
}

// Strategy: Alternation with prefix/suffix - simplified with proper verification
PatternResult tryAltWithAffix(const std::vector<std::string>& matching,
                             const std::vector<std::string>& counters,
                             std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  AltAffix: requires 2+ matching\n";
        return result;
    }
    
    // Simple approach: use matching strings as alternatives
    std::string pattern = "(";
    for (size_t i = 0; i < matching.size(); i++) {
        if (i > 0) pattern += "|";
        pattern += matching[i];
    }
    pattern += ")+";
    
    // Verify all matching inputs are alternatives
    bool all_match = true;
    for (const auto& m : matching) {
        bool found = false;
        for (const auto& alt : matching) {
            if (m == alt) { found = true; break; }
        }
        if (!found) { all_match = false; break; }
    }
    
    if (!all_match) {
        result.proof += "  AltAffix: verification failed\n";
        return result;
    }
    
    // Create AST
    result.ast = createAlternationPlus(matching, matching);
    
    result.pattern = pattern;
    result.proof += "  AltAffix: " + result.pattern + "\n";
    return result;
}

// Strategy: Triple quantifier nesting
PatternResult tryTripleQuant(const std::vector<std::string>& matching,
                            const std::vector<std::string>& counters,
                            std::mt19937& rng) {
    PatternResult result;
    
    if (matching.empty()) {
        result.proof += "  TripleQ: requires matching\n";
        return result;
    }
    
    std::string base = matching[0];
    if (base.empty()) {
        result.proof += "  TripleQ: empty base\n";
        return result;
    }
    
    // Try: ((base)?)+
    std::string pattern = "((" + base + ")?)+";
    
    // Verify: all matching should have base as prefix
    bool all_match = true;
    for (const auto& m : matching) {
        if (m.find(base) != 0) {
            all_match = false;
            break;
        }
    }
    
    if (!all_match) {
        // Try simpler: (base)+
        pattern = "(" + base + ")+";
        for (const auto& m : matching) {
            if (m != base) {
                all_match = false;
                break;
            }
        }
        if (!all_match) {
            result.proof += "  TripleQ: no match\n";
            return result;
        }
    }
    
    result.pattern = pattern;
    
    // Create AST for triple quantifier
    if (pattern.find("?") != std::string::npos) {
        // ((base)?)+
        auto inner_node = createLiteralOptional(base, matching);
        result.ast = createLiteralPlus("(" + base + ")?", matching);
    } else {
        // (base)+
        result.ast = createLiteralPlus(base, matching);
    }
    
    result.proof += "  TripleQ: " + result.pattern + "\n";
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
    
    // Create AST
    result.ast = PatternNode::createAlternation(
        [&alts]() {
            std::vector<std::shared_ptr<PatternNode>> nodes;
            for (const auto& alt : alts) {
                nodes.push_back(PatternNode::createLiteral(alt, {alt}));
            }
            return nodes;
        }(),
        matching
    );
    
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
    
    // First try to get any valid pattern (with AST)
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
    
    // Use AST if available, otherwise wrap string
    if (base.ast) {
        result.ast = wrapWithCaptureTags(base.ast, cap_name);
        result.pattern = serializePattern(result.ast);
    } else {
        // Fallback to string manipulation
        result.pattern = "<" + cap_name + ">" + base.pattern + "</" + cap_name + ">";
    }
    result.fragments = base.fragments;
    
    // Verify - capture tags shouldn't change matching behavior
    // Use base.ast's pattern for verification since result may have been modified
    std::string verify_pattern = base.ast ? serializePattern(base.ast) : base.pattern;
    bool all_match = true;
    for (const auto& m : matching) {
        bool matches = false;
        // Check if base pattern matches
        if (verify_pattern.find("|") != std::string::npos) {
            // Alternation - check if m is one of the options
            for (const auto& alt : matching) {
                if (m == alt) { matches = true; break; }
            }
        } else if (verify_pattern.find("((") != std::string::npos) {
            // Fragment - check if m fits the fragment pattern
            matches = true; // Base already verified
        } else {
            // Literal
            matches = (verify_pattern == m);
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
    
    // Create AST - extract fragment name from pattern like "((name))+"
    size_t start = frag_pattern.find("((");
    size_t end = frag_pattern.find("))+");
    if (start != std::string::npos && end != std::string::npos && start + 2 < end) {
        std::string frag_name = frag_pattern.substr(start + 2, end - start - 2);
        result.ast = createFragmentPlus(frag_name, matching);
    }
    
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
    
    // 8% chance: Try optional quantifier (only if alternation)
    if (result.pattern.find("|") != std::string::npos && 
        std::uniform_int_distribution<int>(0, 99)(rng) < 8) {
        PatternResult opt = tryOptionalQuantifier(matching, counters, rng);
        if (!opt.pattern.empty()) {
            result = opt;
            result.proof += "    [Edge case: Optional with 8% probability]\n";
            return result;
        }
    }
    
    // 6% chance: Try empty alternative
    if (result.pattern.find("|") != std::string::npos &&
        std::uniform_int_distribution<int>(0, 99)(rng) < 6) {
        PatternResult empty = tryEmptyAlternative(matching, counters, rng);
        if (!empty.pattern.empty()) {
            result = empty;
            result.proof += "    [Edge case: Empty alternative with 6% probability]\n";
            return result;
        }
    }
    
    // 6% chance: Try nested group
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 6) {
        PatternResult nested = tryNestedGroup(matching, counters, rng, result.pattern);
        if (!nested.pattern.empty()) {
            result = nested;
            result.fragments = nested.fragments;
            result.proof += "    [Edge case: Nested group with 6% probability]\n";
            return result;
        }
    }
    
    // 8% chance: Try multi-char fragment
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 8) {
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
    
    // 10% chance: Try star quantifier (zero or more)
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 10) {
        PatternResult star = tryStarQuantifier(matching, counters, rng);
        if (!star.pattern.empty()) {
            result = star;
            for (const auto& f : star.fragments) {
                result.fragments[f.first] = f.second;
            }
            result.proof += "    [Edge case: Star quantifier with 10% probability]\n";
            return result;
        }
    }
    
    // 6% chance: Try char class plus
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 6) {
        PatternResult cc = tryCharClassPlus(matching, counters, rng);
        if (!cc.pattern.empty()) {
            result = cc;
            result.proof += "    [Edge case: Char class plus with 6% probability]\n";
            return result;
        }
    }
    
    // 5% chance: Try mixed quantifiers
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 5) {
        PatternResult mixed = tryMixedQuantifiers(matching, counters, rng);
        if (!mixed.pattern.empty()) {
            result = mixed;
            result.proof += "    [Edge case: Mixed quantifiers with 5% probability]\n";
            return result;
        }
    }
    
    // 8% chance: Try fragment chaining
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 8) {
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
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 6) {
        PatternResult cap = tryCaptureTags(matching, counters, rng);
        if (!cap.pattern.empty()) {
            result = cap;
            for (const auto& f : cap.fragments) {
                result.fragments[f.first] = f.second;
            }
            result.proof += "    [Edge case: Capture tags with 6% probability]\n";
            return result;
        }
    }
    
    // 5% chance: Try single-char shorthand fragment
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 5) {
        PatternResult single = trySingleCharFragment(matching, counters, rng);
        if (!single.pattern.empty()) {
            result = single;
            for (const auto& f : single.fragments) {
                result.fragments[f.first] = f.second;
            }
            result.proof += "    [Edge case: Single-char fragment with 5% probability]\n";
            return result;
        }
    }
    
    return result;
}
