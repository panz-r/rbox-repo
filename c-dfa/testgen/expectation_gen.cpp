// ============================================================================
// Expectation Generation - Deep Semantic Verification
// ============================================================================

#include "expectation_gen.h"
#include "testgen.h"
#include "pattern_strategies.h"

#include <set>

using namespace std;std::string expectationTypeToString(ExpectationType type) {
    switch (type) {
        case ExpectationType::MATCH_EXACT: return "MATCH_EXACT";
        case ExpectationType::NO_MATCH: return "NO_MATCH";
        case ExpectationType::FRAGMENT_MATCH: return "FRAGMENT_MATCH";
        case ExpectationType::QUANTIFIER_STAR_EMPTY: return "QUANTIFIER_STAR_EMPTY";
        case ExpectationType::QUANTIFIER_PLUS_MINONE: return "QUANTIFIER_PLUS_MINONE";
        case ExpectationType::ALTERNATION_INDIVIDUAL: return "ALTERNATION_INDIVIDUAL";
        case ExpectationType::CAPTURE_TAG_MATCH: return "CAPTURE_TAG_MATCH";
        case ExpectationType::PREFIX_MATCH: return "PREFIX_MATCH";
        case ExpectationType::SUFFIX_MATCH: return "SUFFIX_MATCH";
        case ExpectationType::CHAR_CLASS_MATCH: return "CHAR_CLASS_MATCH";
        case ExpectationType::REPETITION_MIN_COUNT: return "REPETITION_MIN_COUNT";
        case ExpectationType::FRAGMENT_NESTED: return "FRAGMENT_NESTED";
        default: return "UNKNOWN";
    }
}

bool hasFragment(const std::string& pattern) {
    return pattern.find("((") != std::string::npos;
}

bool hasQuantifier(const std::string& pattern, char quant) {
    size_t pos = pattern.find(quant);
    while (pos != std::string::npos) {
        if (pos == 0 || pattern[pos-1] != '\\') {
            return true;
        }
        pos = pattern.find(quant, pos + 1);
    }
    return false;
}

bool hasStarQuantifier(const std::string& pattern) {
    return hasQuantifier(pattern, '*');
}

bool hasPlusQuantifier(const std::string& pattern) {
    return hasQuantifier(pattern, '+');
}

bool hasOptional(const std::string& pattern) {
    return hasQuantifier(pattern, '?');
}

bool hasAlternation(const std::string& pattern) {
    return pattern.find("|") != std::string::npos;
}

bool hasCaptureTags(const std::string& pattern) {
    return pattern.find("<") != std::string::npos && pattern.find("</") != std::string::npos;
}

std::string extractAlternatives(const std::string& pattern) {
    size_t start = pattern.find('(');
    size_t end = pattern.rfind(')');
    if (start == std::string::npos || end == std::string::npos || end <= start) {
        return "";
    }
    return pattern.substr(start + 1, end - start - 1);
}

std::vector<std::string> splitAlternatives(const std::string& alternation) {
    std::vector<std::string> result;
    std::string current;
    int depth = 0;
    for (char c : alternation) {
        if (c == '(') depth++;
        else if (c == ')') depth--;
        else if (c == '|' && depth == 0) {
            if (!current.empty()) {
                result.push_back(current);
                current.clear();
            }
            continue;
        }
        current += c;
    }
    if (!current.empty()) {
        result.push_back(current);
    }
    return result;
}

std::string extractCharClass(const std::string& pattern) {
    size_t pos = pattern.find('[');
    if (pos == std::string::npos) return "";
    size_t end = pattern.find(']', pos);
    if (end == std::string::npos) return "";
    return pattern.substr(pos, end - pos + 1);
}

std::map<std::string, std::string> extractFragmentDefs(const std::string& pattern) {
    std::map<std::string, std::string> frags;
    size_t pos = 0;
    while ((pos = pattern.find("((", pos)) != std::string::npos) {
        size_t name_start = pos + 2;
        size_t name_end = pattern.find("))", name_start);
        if (name_end != std::string::npos) {
            std::string name = pattern.substr(name_start, name_end - name_start);
            size_t def_start = name_end + 2;
            size_t def_end = pattern.find("))", def_start);
            if (def_end != std::string::npos) {
                std::string def = pattern.substr(def_start, def_end - def_start);
                frags[name] = def;
            }
        }
        pos++;
    }
    return frags;
}

std::vector<Expectation> generateFragmentExpectations(const std::string& pattern,
                                                       const std::map<std::string, std::string>& fragment_defs,
                                                       const std::vector<std::string>& matching,
                                                       const std::vector<std::string>& counters) {
    std::vector<Expectation> expectations;
    
    if (fragment_defs.empty()) return expectations;
    
    for (const auto& frag : fragment_defs) {
        std::string frag_name = frag.first;
        std::string frag_def = frag.second;
        
        Expectation exp;
        exp.type = ExpectationType::FRAGMENT_MATCH;
        exp.input = "[[FRAGMENT:" + frag_name + "]]";
        exp.expected_match = "yes";
        exp.description = "Fragment '" + frag_name + "' definition must match pattern reference";
        exp.meta["fragment_name"] = frag_name;
        exp.meta["fragment_definition"] = frag_def;
        
        std::string frag_ref = "((" + frag_name + "))";
        if (pattern.find(frag_ref) != std::string::npos) {
            exp.meta["pattern_has_reference"] = "yes";
        }
        
        expectations.push_back(exp);
        
        if (frag_def.find("+") != std::string::npos) {
            Expectation exp_plus;
            exp_plus.type = ExpectationType::QUANTIFIER_PLUS_MINONE;
            exp_plus.input = "[[FRAGMENT:" + frag_name + ":EMPTY]]";
            exp_plus.expected_match = "no";
            exp_plus.description = "Fragment '" + frag_name + "' with + quantifier must require at least one character";
            exp_plus.meta["fragment_name"] = frag_name;
            exp_plus.meta["quantifier"] = "+";
            expectations.push_back(exp_plus);
        }
        
        if (frag_def.find("*") != std::string::npos) {
            Expectation exp_star;
            exp_star.type = ExpectationType::QUANTIFIER_STAR_EMPTY;
            exp_star.input = "[[FRAGMENT:" + frag_name + ":EMPTY]]";
            exp_star.expected_match = "yes";
            exp_star.description = "Fragment '" + frag_name + "' with * quantifier must match empty string";
            exp_star.meta["fragment_name"] = frag_name;
            exp_star.meta["quantifier"] = "*";
            expectations.push_back(exp_star);
        }
    }
    
    return expectations;
}

std::vector<Expectation> generateQuantifierExpectations(const std::string& pattern,
                                                         const std::vector<std::string>& matching,
                                                         const std::vector<std::string>& counters) {
    std::vector<Expectation> expectations;
    
    if (hasStarQuantifier(pattern)) {
        Expectation exp;
        exp.type = ExpectationType::QUANTIFIER_STAR_EMPTY;
        exp.input = "";
        exp.expected_match = "yes";
        exp.description = "Pattern with * quantifier must match empty string";
        exp.meta["quantifier"] = "*";
        exp.meta["pattern"] = pattern;
        expectations.push_back(exp);
    }
    
    if (hasPlusQuantifier(pattern)) {
        // Only verify that the original matching inputs still match
        // Don't create synthetic test cases that might not match the quantifier
        for (const auto& match : matching) {
            Expectation exp;
            exp.type = ExpectationType::QUANTIFIER_PLUS_MINONE;
            exp.input = match;
            exp.expected_match = "yes";
            exp.description = "Pattern with + quantifier must match original input '" + match + "'";
            exp.meta["quantifier"] = "+";
            exp.meta["pattern"] = pattern;
            expectations.push_back(exp);
        }
    }
    
    return expectations;
}

// Extract prefix before an alternation, e.g., "a(b|c)" -> "a"
// Returns empty string if no prefix
std::string extractPrefixBeforeAlternation(const std::string& pattern) {
    size_t paren_start = pattern.find('(');
    if (paren_start == std::string::npos || paren_start == 0) return "";
    
    // Check if there's a | inside the parentheses
    size_t paren_end = pattern.find(')', paren_start);
    if (paren_end == std::string::npos) return "";
    
    std::string inside = pattern.substr(paren_start + 1, paren_end - paren_start - 1);
    if (inside.find('|') == std::string::npos) return "";
    
    // Return the prefix (everything before the opening paren)
    return pattern.substr(0, paren_start);
}

std::vector<Expectation> generateAlternationExpectations(const std::string& pattern,
                                                           const std::vector<std::string>& matching,
                                                           const std::vector<std::string>& counters) {
    std::vector<Expectation> expectations;
    
    if (!hasAlternation(pattern)) return expectations;
    
    std::string alt_str = extractAlternatives(pattern);
    if (alt_str.empty()) return expectations;
    
    std::vector<std::string> alternatives = splitAlternatives(alt_str);
    if (alternatives.size() < 2) return expectations;
    
    // Check for prefix before alternation (e.g., "a(b|c)" has prefix "a")
    std::string prefix = extractPrefixBeforeAlternation(pattern);
    
    for (size_t i = 0; i < alternatives.size() && i < 5; i++) {
        std::string alt = alternatives[i];
        
        // For prefix+alternation patterns, the full match is prefix+alternative
        std::string full_alt = prefix + alt;
        
        bool is_matching_alt = false;
        for (const auto& m : matching) {
            // Check if this alternative (with prefix) is part of a matching input
            if (m.find(full_alt) != std::string::npos || full_alt.find(m) != std::string::npos) {
                is_matching_alt = true;
                break;
            }
        }
        
        if (is_matching_alt) {
            Expectation exp;
            exp.type = ExpectationType::ALTERNATION_INDIVIDUAL;
            // Use the full alternative (with prefix) as the expected input
            exp.input = full_alt;
            exp.expected_match = "yes";
            exp.description = "Alternative '" + full_alt + "' in alternation must match individually";
            exp.meta["alternative"] = alt;
            exp.meta["full_alternative"] = full_alt;
            exp.meta["alternation"] = alt_str;
            if (!prefix.empty()) {
                exp.meta["prefix"] = prefix;
            }
            expectations.push_back(exp);
        }
    }
    
    return expectations;
}

std::vector<Expectation> generateCaptureTagExpectations(const std::string& pattern,
                                                          const std::vector<std::string>& matching,
                                                          const std::vector<std::string>& counters) {
    std::vector<Expectation> expectations;
    
    if (!hasCaptureTags(pattern)) return expectations;
    
    size_t tag_start = pattern.find('<');
    size_t tag_end = pattern.find('>');
    if (tag_start == std::string::npos || tag_end == std::string::npos) return expectations;
    
    std::string capture_name = pattern.substr(tag_start + 1, tag_end - tag_start - 1);
    
    Expectation exp;
    exp.type = ExpectationType::CAPTURE_TAG_MATCH;
    exp.input = "[[CAPTURE_TEST]]";
    exp.expected_match = "yes";
    exp.description = "Capture tag '" + capture_name + "' should not change matching behavior";
    exp.meta["capture_name"] = capture_name;
    exp.meta["original_pattern"] = pattern;
    
    size_t close_start = pattern.find("</");
    if (close_start != std::string::npos) {
        size_t close_end = pattern.find(">", close_start);
        if (close_end != std::string::npos) {
            std::string close_name = pattern.substr(close_start + 2, close_end - close_start - 2);
            exp.meta["close_tag"] = close_name;
            if (close_name != capture_name) {
                exp.description += " (MISMATCHED TAGS - this is a BUG in c-dfa if accepted)";
            }
        }
    }
    
    expectations.push_back(exp);
    
    return expectations;
}

std::vector<Expectation> generateCharClassExpectations(const std::string& pattern,
                                                        const std::vector<std::string>& matching,
                                                        const std::vector<std::string>& counters) {
    std::vector<Expectation> expectations;
    
    std::string char_class = extractCharClass(pattern);
    if (char_class.empty()) return expectations;
    
    std::set<char> allowed_chars;
    for (size_t i = 1; i < char_class.size() - 1; i++) {
        if (char_class[i] != '|') {
            allowed_chars.insert(char_class[i]);
        }
    }
    
    for (char c : allowed_chars) {
        std::string single(1, c);
        Expectation exp;
        exp.type = ExpectationType::CHAR_CLASS_MATCH;
        exp.input = single;
        exp.expected_match = "yes";
        exp.description = "Character '" + single + "' must match character class " + char_class;
        exp.meta["char_class"] = char_class;
        exp.meta["character"] = single;
        expectations.push_back(exp);
    }
    
    const std::string other_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (char c : other_chars) {
        if (allowed_chars.find(c) == allowed_chars.end()) {
            std::string single(1, c);
            Expectation exp;
            exp.type = ExpectationType::CHAR_CLASS_MATCH;
            exp.input = single;
            exp.expected_match = "no";
            exp.description = "Character '" + single + "' must NOT match character class " + char_class;
            exp.meta["char_class"] = char_class;
            exp.meta["character"] = single;
            expectations.push_back(exp);
            break;
        }
    }
    
    return expectations;
}

// ============================================================================
// AST-based Expectation Generation - Uses matched_seeds annotations
// ============================================================================

// Recursively collect expectations from AST nodes
// Uses matched_seeds from each node to determine what inputs should match
void collectExpectationsFromNode(std::shared_ptr<PatternNode> node,
                                   std::vector<Expectation>& expectations,
                                   const std::string& prefix,
                                   int depth) {
    if (!node || depth > 20) return;
    
    switch (node->type) {
        case PatternType::LITERAL: {
            // For literals in sequences (depth > 0 with prefix), don't generate MATCH_EXACT
            // The full pattern match is verified at the sequence/alternation level
            // Only generate MATCH_EXACT for top-level literals (depth == 0 or no prefix)
            if (prefix.empty() && depth == 0) {
                std::string full_pattern = prefix + node->value;
                for (const auto& seed : node->matched_seeds) {
                    Expectation exp;
                    exp.type = ExpectationType::MATCH_EXACT;
                    exp.input = seed;
                    exp.expected_match = "yes";
                    exp.description = "Input '" + seed + "' must match pattern '" + full_pattern + "'";
                    exp.meta["pattern"] = full_pattern;
                    exp.meta["node_value"] = node->value;
                    expectations.push_back(exp);
                }
            }
            break;
        }
        
        case PatternType::ALTERNATION: {
            // For alternations, collect from each alternative
            // Also add ALTERNATION_INDIVIDUAL expectations for each alternative's seeds
            std::string alt_prefix = prefix;  // No additional prefix for alternation itself
            
            for (const auto& child : node->children) {
                // Recursively collect from each alternative
                collectExpectationsFromNode(child, expectations, alt_prefix, depth + 1);
            }
            
            // Add ALTERNATION_INDIVIDUAL expectations only for top-level (depth 0)
            // For factored patterns, the individual alternative verification is handled
            // by the sequence-level full pattern matching
            if (depth == 0) {
                for (const auto& child : node->children) {
                    if (child->type == PatternType::LITERAL) {
                        for (const auto& seed : child->matched_seeds) {
                            Expectation exp;
                            exp.type = ExpectationType::ALTERNATION_INDIVIDUAL;
                            exp.input = seed;
                            exp.expected_match = "yes";
                            exp.description = "Alternative must match input '" + seed + "'";
                            exp.meta["alternative_value"] = child->value;
                            exp.meta["full_input"] = seed;
                            expectations.push_back(exp);
                        }
                    }
                }
            }
            break;
        }
        
        case PatternType::SEQUENCE: {
            // For sequences, accumulate prefix from first child, then recurse
            if (node->children.size() >= 2) {
                // First child is typically the prefix literal
                std::string new_prefix = prefix;
                if (node->children[0]->type == PatternType::LITERAL) {
                    new_prefix += node->children[0]->value;
                }
                // Recurse on remaining children
                for (size_t i = 1; i < node->children.size(); i++) {
                    collectExpectationsFromNode(node->children[i], expectations, new_prefix, depth + 1);
                }
                
                // If this is a top-level sequence (depth 0) with matched_seeds, 
                // generate MATCH_EXACT expectations for the full pattern
                if (depth == 0 && !node->matched_seeds.empty()) {
                    std::string full_pattern = new_prefix;
                    // Add remaining children's values to get full pattern
                    for (size_t i = 1; i < node->children.size(); i++) {
                        if (node->children[i]->type == PatternType::LITERAL) {
                            full_pattern += node->children[i]->value;
                        } else if (node->children[i]->type == PatternType::ALTERNATION) {
                            // For alternation, use its serialized form
                            full_pattern += serializePattern(node->children[i]);
                        }
                    }
                    for (const auto& seed : node->matched_seeds) {
                        Expectation exp;
                        exp.type = ExpectationType::MATCH_EXACT;
                        exp.input = seed;
                        exp.expected_match = "yes";
                        exp.description = "Input '" + seed + "' must match pattern '" + full_pattern + "'";
                        exp.meta["pattern"] = full_pattern;
                        expectations.push_back(exp);
                    }
                }
            } else if (node->children.size() == 1) {
                collectExpectationsFromNode(node->children[0], expectations, prefix, depth + 1);
            }
            break;
        }
        
        case PatternType::PLUS_QUANTIFIER:
        case PatternType::STAR_QUANTIFIER: {
            if (node->quantified) {
                collectExpectationsFromNode(node->quantified, expectations, prefix, depth + 1);
            }
            
            // Don't generate synthetic quantifier expectations here
            // The expectations from matched_seeds at higher levels will verify correctness
            break;
        }
        
        case PatternType::OPTIONAL: {
            // For optional groups, we need special handling
            // The quantified node should be verified, but also we need to track
            // that inputs may or may not match through it
            if (node->quantified) {
                collectExpectationsFromNode(node->quantified, expectations, prefix, depth + 1);
            }
            
            // Add expectations for the OPTIONAL node itself
            // All seeds at this node should be able to match (either with or without content)
            for (const auto& seed : node->matched_seeds) {
                Expectation exp;
                exp.type = ExpectationType::MATCH_EXACT;
                exp.input = seed;
                exp.expected_match = "yes";
                exp.description = "Input '" + seed + "' must match optional pattern at depth " + std::to_string(depth);
                exp.meta["optional_depth"] = std::to_string(depth);
                expectations.push_back(exp);
            }
            break;
        }
        
        case PatternType::FRAGMENT_REF:
            // Fragment references don't generate expectations directly
            // The fragment definition is tested separately
            break;
            
        default:
            break;
    }
}

// Main entry point for AST-based expectation generation
std::vector<Expectation> generateExpectationsFromAST(
    std::shared_ptr<PatternNode> ast,
    const std::map<std::string, std::string>& fragment_defs,
    const std::vector<std::string>& matching,
    const std::vector<std::string>& counters) {
    
    std::vector<Expectation> expectations;
    
    // Collect expectations by traversing AST
    collectExpectationsFromNode(ast, expectations, "", 0);
    
    // Also add fragment expectations if any
    if (!fragment_defs.empty()) {
        for (const auto& frag : fragment_defs) {
            Expectation exp;
            exp.type = ExpectationType::FRAGMENT_MATCH;
            exp.input = "[[FRAGMENT:" + frag.first + "]]";
            exp.expected_match = "yes";
            exp.description = "Fragment '" + frag.first + "' definition";
            exp.meta["fragment_name"] = frag.first;
            exp.meta["fragment_definition"] = frag.second;
            expectations.push_back(exp);
        }
    }
    
    return expectations;
}

std::vector<Expectation> generateAllExpectations(const std::string& pattern,
                                                 const std::map<std::string, std::string>& fragment_defs,
                                                 const std::vector<std::string>& matching,
                                                 const std::vector<std::string>& counters) {
    std::vector<Expectation> expectations;
    
    auto frag_exps = generateFragmentExpectations(pattern, fragment_defs, matching, counters);
    expectations.insert(expectations.end(), frag_exps.begin(), frag_exps.end());
    
    auto quant_exps = generateQuantifierExpectations(pattern, matching, counters);
    expectations.insert(expectations.end(), quant_exps.begin(), quant_exps.end());
    
    auto alt_exps = generateAlternationExpectations(pattern, matching, counters);
    expectations.insert(expectations.end(), alt_exps.begin(), alt_exps.end());
    
    auto cap_exps = generateCaptureTagExpectations(pattern, matching, counters);
    expectations.insert(expectations.end(), cap_exps.begin(), cap_exps.end());
    
    auto char_exps = generateCharClassExpectations(pattern, matching, counters);
    expectations.insert(expectations.end(), char_exps.begin(), char_exps.end());
    
    return expectations;
}
