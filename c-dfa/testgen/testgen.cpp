#include "testgen.h"
#include "pattern_strategies.h"
#include "pattern_serializer.h"
#include "command_utils.h"
#include "expectation_gen.h"
#include "inductive_builder.h"
#include "edge_case_gen.h"
#include "testgen_mutation_tree.h"
#include "pattern_matcher.h"
#include "pipeline.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <optional>
#include <tuple>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <libgen.h>

// ============================================================================
// Pattern AST Implementation
// ============================================================================

std::shared_ptr<PatternNode> PatternNode::createLiteral(const std::string& val, 
    const std::vector<std::string>& seeds,
    const std::vector<std::string>& counters) {
    auto node = std::make_shared<PatternNode>();
    node->type = PatternType::LITERAL;
    node->value = val;
    node->matched_seeds = seeds;
    node->counter_seeds = counters;
    return node;
}

std::shared_ptr<PatternNode> PatternNode::createFragment(const std::string& name, 
    const std::vector<std::string>& seeds,
    const std::vector<std::string>& counters) {
    auto node = std::make_shared<PatternNode>();
    node->type = PatternType::FRAGMENT_REF;
    node->fragment_name = name;
    node->matched_seeds = seeds;
    node->counter_seeds = counters;
    return node;
}

std::shared_ptr<PatternNode> PatternNode::createSequence(const std::vector<std::shared_ptr<PatternNode>>& kids, 
    const std::vector<std::string>& seeds,
    const std::vector<std::string>& counters) {
    auto node = std::make_shared<PatternNode>();
    node->type = PatternType::SEQUENCE;
    node->children = kids;
    node->matched_seeds = seeds;
    node->counter_seeds = counters;
    return node;
}

std::shared_ptr<PatternNode> PatternNode::createAlternation(const std::vector<std::shared_ptr<PatternNode>>& alts, 
    const std::vector<std::string>& seeds,
    const std::vector<std::string>& counters) {
    auto node = std::make_shared<PatternNode>();
    node->type = PatternType::ALTERNATION;
    node->children = alts;
    node->matched_seeds = seeds;
    node->counter_seeds = counters;
    return node;
}

std::shared_ptr<PatternNode> PatternNode::createQuantified(std::shared_ptr<PatternNode> child, 
    PatternType quant_type, 
    const std::vector<std::string>& seeds,
    const std::vector<std::string>& counters) {
    auto node = std::make_shared<PatternNode>();
    node->type = quant_type;
    node->quantified = child;
    node->matched_seeds = seeds;
    node->counter_seeds = counters;
    return node;
}

// ============================================================================
// Pattern Factory - Consolidated Quantified Node Creation
// ============================================================================
//
// These functions create quantified pattern nodes. The pattern is:
// 1. Create a child node (alternation, literal, or fragment)
// 2. Set the parent's type to the quantifier type
// 3. Set the parent's quantified field to the child
// 4. Assign matched_seeds to track which inputs should match
//
// Generalized factory functions handle all quantifier types. Convenience
// wrappers are provided for backward compatibility.
// Conservative pattern matching check - returns true only if input clearly matches
// the pattern structure. Used to filter matching_inputs after factorization.
bool wouldInputMatchPattern(const std::string& input, const std::string& pattern) {
    // Extract just the pattern part (after category tag if present)
    std::string pattern_only = pattern;
    size_t bracket_end = pattern.find("] ");
    if (bracket_end != std::string::npos) {
        pattern_only = pattern.substr(bracket_end + 2);
    }
    
    // Remove capture tags from pattern_only
    std::string clean_pattern;
    size_t i = 0;
    while (i < pattern_only.size()) {
        if (pattern_only[i] == '<') {
            size_t tag_end = pattern_only.find('>', i);
            if (tag_end != std::string::npos) {
                if (i + 1 < pattern_only.size() && pattern_only[i + 1] == '/') {
                    i = tag_end + 1;
                } else {
                    std::string tag_name = pattern_only.substr(i + 1, tag_end - i - 1);
                    size_t close_tag = pattern_only.find("</" + tag_name + ">", tag_end);
                    if (close_tag != std::string::npos) {
                        clean_pattern += pattern_only.substr(tag_end + 1, close_tag - tag_end - 1);
                        i = close_tag + tag_name.size() + 3;
                    } else {
                        i = tag_end + 1;
                    }
                }
            } else {
                clean_pattern += pattern_only[i++];
            }
        } else {
            clean_pattern += pattern_only[i++];
        }
    }
    
    // For simple patterns (no alternations), do direct comparison
    if (clean_pattern.find('(') == std::string::npos && 
        clean_pattern.find('|') == std::string::npos) {
        return input == clean_pattern;
    }
    
    // For patterns with alternations, we need to be careful
    // Check if input could match any top-level alternative
    
    // Extract top-level alternatives (not nested)
    // Handle the case where pattern is wrapped in outer parens: (a|b|c)
    std::string pattern_to_parse = clean_pattern;
    
    // If pattern starts with ( and ends with matching ), remove outer parens
    if (!pattern_to_parse.empty() && pattern_to_parse.front() == '(') {
        size_t end = pattern_to_parse.size() - 1;
        int depth = 1;
        size_t i = 1;
        while (i < end && depth > 0) {
            if (pattern_to_parse[i] == '(') depth++;
            else if (pattern_to_parse[i] == ')') depth--;
            i++;
        }
        // If we found matching closing paren at the end, strip outer parens
        if (depth == 0 && i - 1 == end) {
            pattern_to_parse = pattern_to_parse.substr(1, end - 1);
        }
    }
    
    std::vector<std::string> top_alts;
    size_t start = 0;
    int depth = 0;
    for (size_t j = 0; j < pattern_to_parse.size(); j++) {
        if (pattern_to_parse[j] == '(') depth++;
        else if (pattern_to_parse[j] == ')') depth--;
        else if (pattern_to_parse[j] == '|' && depth == 0) {
            top_alts.push_back(pattern_to_parse.substr(start, j - start));
            start = j + 1;
        }
    }
    top_alts.push_back(pattern_to_parse.substr(start));
    
    // Check each top-level alternative
    for (const auto& alt : top_alts) {
        // Remove surrounding parentheses if present
        std::string clean_alt = alt;
        if (clean_alt.size() >= 2 && clean_alt.front() == '(' && clean_alt.back() == ')') {
            clean_alt = clean_alt.substr(1, clean_alt.size() - 2);
        }
        
        // If alternative has no nested structure, do direct comparison
        if (clean_alt.find('|') == std::string::npos && 
            clean_alt.find('(') == std::string::npos) {
            if (input == clean_alt) return true;
            continue;
        }
        
        // Alternative has nested structure - check if it has a simple prefix+suffix pattern
        // Pattern: prefix + (alt1|alt2|...)
        size_t paren_pos = clean_alt.find('(');
        if (paren_pos != std::string::npos) {
            std::string prefix = clean_alt.substr(0, paren_pos);
            
            // Find matching closing paren (handle nesting)
            size_t close = paren_pos + 1;
            int depth = 1;
            while (close < clean_alt.size() && depth > 0) {
                if (clean_alt[close] == '(') depth++;
                else if (clean_alt[close] == ')') depth--;
                close++;
            }
            close--; // Now points to the matching ')'
            
            if (close > paren_pos) {
                std::string nested = clean_alt.substr(paren_pos + 1, close - paren_pos - 1);
                
                // Check for quantifiers after the closing paren
                char quant = '\0';
                size_t after_close = close + 1;
                if (after_close < clean_alt.size()) {
                    quant = clean_alt[after_close];
                }
                
                // If input starts with prefix, check remainder against nested alternatives
                if (input.size() >= prefix.size() && 
                    input.substr(0, prefix.size()) == prefix) {
                    std::string remainder = input.substr(prefix.size());
                    
                    // Split nested by | at depth 0 (respecting nested parens)
                    std::vector<std::string> nested_alts;
                    size_t ns = 0;
                    int nested_depth = 0;
                    for (size_t i = 0; i < nested.size(); i++) {
                        if (nested[i] == '(') nested_depth++;
                        else if (nested[i] == ')') nested_depth--;
                        else if (nested[i] == '|' && nested_depth == 0) {
                            nested_alts.push_back(nested.substr(ns, i - ns));
                            ns = i + 1;
                        }
                    }
                    nested_alts.push_back(nested.substr(ns));
                    
                    // Check if remainder matches any nested alternative
                    for (const auto& na : nested_alts) {
                        std::string clean_na = na;
                        // Remove surrounding parens from nested alt if present
                        if (clean_na.size() >= 2 && clean_na.front() == '(' && clean_na.back() == ')') {
                            clean_na = clean_na.substr(1, clean_na.size() - 2);
                        }
                        
                        // Check for quantifiers at the end
                        if (!clean_na.empty() && clean_na.back() == '?') {
                            // Optional: X? matches empty or X
                            std::string base = clean_na.substr(0, clean_na.size() - 1);
                            if (remainder == base || remainder.empty()) return true;
                        } else if (!clean_na.empty() && clean_na.back() == '*') {
                            // Star: X* matches empty, X, XX, XXX, etc.
                            std::string base = clean_na.substr(0, clean_na.size() - 1);
                            if (base.empty()) continue;
                            bool valid = true;
                            size_t pos = 0;
                            while (pos < remainder.size()) {
                                if (remainder.substr(pos, base.size()) == base) {
                                    pos += base.size();
                                } else {
                                    valid = false;
                                    break;
                                }
                            }
                            if (valid) return true;
                        } else if (!clean_na.empty() && clean_na.back() == '+') {
                            // Plus: X+ matches X, XX, XXX, etc. (at least one)
                            std::string base = clean_na.substr(0, clean_na.size() - 1);
                            if (base.empty()) continue;
                            bool valid = true;
                            size_t pos = 0;
                            while (pos < remainder.size()) {
                                if (remainder.substr(pos, base.size()) == base) {
                                    pos += base.size();
                                } else {
                                    valid = false;
                                    break;
                                }
                            }
                            if (valid && pos > 0) return true;
                        } else if (remainder == clean_na) {
                            return true;
                        }
                    }
                    
                    // Check if the group itself is optional and remainder is empty
                    if (quant == '?' && remainder.empty()) return true;
                }
            }
        }
    }
    
    // Handle character classes: [abc]+ or [abc]
    // If pattern contains '[' it may be a character class
    size_t char_class_start = clean_pattern.find('[');
    if (char_class_start != std::string::npos) {
        // Extract character class definition
        size_t char_class_end = clean_pattern.find(']', char_class_start);
        if (char_class_end != std::string::npos && char_class_end > char_class_start) {
            std::string char_class = clean_pattern.substr(char_class_start + 1, char_class_end - char_class_start - 1);
            
            // Check if it's a simple character class (no nested [] or complex regex)
            bool is_simple_class = true;
            for (char c : char_class) {
                if (c == '[' || c == ']' || c == '-' || c == '^') {
                    is_simple_class = false;
                    break;
                }
            }
            
            if (is_simple_class) {
                // Parse simple character class
                std::set<char> allowed;
                for (char c : char_class) {
                    allowed.insert(c);
                }
                
                // Check if quantifier follows
                bool is_plus = false;
                bool is_star = false;
                bool is_optional = false;
                size_t quant_pos = char_class_end + 1;
                if (quant_pos < clean_pattern.size()) {
                    if (clean_pattern[quant_pos] == '+') is_plus = true;
                    else if (clean_pattern[quant_pos] == '*') is_star = true;
                    else if (clean_pattern[quant_pos] == '?') is_optional = true;
                }
                
                // Check if entire pattern is just the char class (possibly with quantifier)
                std::string before_class = clean_pattern.substr(0, char_class_start);
                std::string after_class = quant_pos < clean_pattern.size() ? 
                    clean_pattern.substr(quant_pos + 1) : "";
                
                // If there's content before the char class, check prefix first
                if (!before_class.empty()) {
                    if (input.size() < before_class.size() || 
                        input.substr(0, before_class.size()) != before_class) {
                        return false;
                    }
                }
                
                // Extract the part after the prefix
                std::string remainder = before_class.empty() ? input : input.substr(before_class.size());
                
                // Handle quantifiers
                if (is_optional) {
                    // [abc]? matches empty or single char
                    if (remainder.empty() || (remainder.size() == 1 && allowed.count(remainder[0]))) {
                        if (after_class.empty() || remainder.size() < input.size()) {
                            return remainder.empty() || allowed.count(remainder[0]);
                        }
                        return after_class.empty() ? true : false;
                    }
                }
                
                if (is_plus) {
                    // [abc]+ matches one or more of the characters
                    if (remainder.empty()) return false;
                    for (char c : remainder) {
                        if (allowed.count(c) == 0) return false;
                    }
                    // Check suffix if any
                    if (!after_class.empty()) {
                        return remainder.size() < input.size() && 
                               input.substr(remainder.size()) == after_class;
                    }
                    return true;
                }
                
                if (is_star) {
                    // [abc]* matches zero or more
                    if (remainder.empty()) return true;
                    for (char c : remainder) {
                        if (allowed.count(c) == 0) return false;
                    }
                    if (!after_class.empty()) {
                        return remainder.size() < input.size() && 
                               input.substr(remainder.size()) == after_class;
                    }
                    return true;
                }
                
                // No quantifier - must match exactly the character class (single char)
                if (remainder.size() == 1 && allowed.count(remainder[0])) {
                    if (!after_class.empty()) {
                        return remainder.size() + before_class.size() < input.size() &&
                               input.substr(remainder.size() + before_class.size()) == after_class;
                    }
                    return before_class.empty() || remainder.size() + before_class.size() == input.size();
                }
            }
        }
    }
    
    // If we get here, the input doesn't match any alternative we could parse
    return false;
}

// Validate pattern against inputs using in-process pipeline API.
// Returns: (all_matching_match, all_counters_dont_match)
// Much faster than forking cdfatool for each input.
std::pair<bool, bool> validatePatternWithPipeline(const std::string& pattern,
                                                   const std::vector<std::string>& matching,
                                                   const std::vector<std::string>& counters,
                                                   const std::map<std::string, std::string>& fragments) {
    bool all_matching_match = true;
    bool all_counters_dont_match = true;
    
    // Write a temporary pattern file
    char tmp_pat[] = "/tmp/testgen_val_XXXXXX.txt";
    int fd = mkstemp(tmp_pat);
    if (fd < 0) return {false, false};
    
    FILE* fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        unlink(tmp_pat);
        return {false, false};
    }
    
    for (const auto& [name, def] : fragments) {
        fprintf(fp, "fragment %s = %s\n", name.c_str(), def.c_str());
    }
    fprintf(fp, "[1] %s\n", pattern.c_str());
    fclose(fp);
    
    // Build DFA in-process
    pipeline_config_t config;
    memset(&config, 0, sizeof(config));
    config.minimize_algo = (dfa_minimize_algo_t)0; // MOORE
    config.verbose = false;
    config.compress = true;
    config.optimize_layout = true;
    
    pipeline_t* p = pipeline_create(&config);
    if (!p) {
        unlink(tmp_pat);
        return {false, false};
    }
    
    pipeline_error_t err = pipeline_run(p, tmp_pat);
    if (err != PIPELINE_OK) {
        pipeline_destroy(p);
        unlink(tmp_pat);
        return {false, false};
    }
    
    size_t binary_size = 0;
    const uint8_t* binary = pipeline_get_binary(p, &binary_size);
    if (!binary || binary_size == 0) {
        pipeline_destroy(p);
        unlink(tmp_pat);
        return {false, false};
    }
    
    // Create evaluator from in-memory binary
    dfa_evaluator_t* eval = dfa_eval_create(binary, binary_size);
    if (!eval) {
        pipeline_destroy(p);
        unlink(tmp_pat);
        return {false, false};
    }
    
    // Evaluate matching inputs
    for (const auto& input : matching) {
        dfa_result_t result = dfa_eval_evaluate(eval, input.c_str());
        if (!result.matched) {
            all_matching_match = false;
            break;
        }
    }
    
    // Evaluate counter inputs
    if (all_matching_match) {
        for (const auto& input : counters) {
            dfa_result_t result = dfa_eval_evaluate(eval, input.c_str());
            if (result.matched) {
                all_counters_dont_match = false;
                break;
            }
        }
    }
    
    dfa_eval_destroy(eval);
    pipeline_destroy(p);
    unlink(tmp_pat);
    
    return {all_matching_match, all_counters_dont_match};
}

// Legacy wrapper kept for compatibility; now uses in-process pipeline
std::pair<bool, bool> validatePatternWithDSL(const std::string& pattern,
                                              const std::vector<std::string>& matching,
                                              const std::vector<std::string>& counters,
                                              const std::map<std::string, std::string>& fragments,
                                              const std::string& /* tools_dir */) {
    return validatePatternWithPipeline(pattern, matching, counters, fragments);
}

// Serialize PatternNode to string with capture tags

// ============================================================================
// Pattern Validation Cache
// ============================================================================
// Caches PatternMatcher::validate results keyed by serialized pattern + inputs.
// Avoids redundant NFA simulation for repeated validation of the same pattern.

static std::unordered_map<std::string, bool> g_validation_cache;
static const size_t MAX_CACHE_SIZE = 1024;

static std::string makeValidationKey(
    const std::shared_ptr<PatternNode>& ast,
    const std::vector<std::string>& matching,
    const std::vector<std::string>& counters,
    const std::map<std::string, std::string>& fragments) {
    std::string key;
    key.reserve(256);
    if (ast) key += serializePattern(ast);
    key += "|M:";
    for (const auto& m : matching) { key += m; key += ","; }
    key += "|C:";
    for (const auto& c : counters) { key += c; key += ","; }
    key += "|F:";
    for (const auto& [k, v] : fragments) { key += k; key += "="; key += v; key += ","; }
    return key;
}

static bool cachedValidate(
    const std::shared_ptr<PatternNode>& ast,
    const std::vector<std::string>& matching,
    const std::vector<std::string>& counters,
    const std::map<std::string, std::string>& fragments) {
    std::string key = makeValidationKey(ast, matching, counters, fragments);
    auto it = g_validation_cache.find(key);
    if (it != g_validation_cache.end()) return it->second;
    
    bool result = PatternMatcher::validateWithFragments(ast, matching, counters, fragments);
    
    if (g_validation_cache.size() >= MAX_CACHE_SIZE) {
        g_validation_cache.clear();
    }
    g_validation_cache[key] = result;
    return result;
}

// Collect all FRAGMENT_REF names from an AST
static void collectFragmentNames(std::shared_ptr<PatternNode> node, std::set<std::string>& names) {
    if (!node) return;
    if (node->type == PatternType::FRAGMENT_REF) {
        names.insert(node->fragment_name);
    }
    if (node->quantified) {
        collectFragmentNames(node->quantified, names);
    }
    for (auto& child : node->children) {
        collectFragmentNames(child, names);
    }
}



// Parse pattern string to AST (simple parser for basic patterns)
std::shared_ptr<PatternNode> parsePatternToAST(const std::string& pattern) {
    if (pattern.empty()) return nullptr;
    
    // Handle FRAGMENT_REF pattern: [[fragment_name]]+ or [[fragment_name]]+suffix
    // This must be checked BEFORE general parenthesized patterns
    if (pattern.size() >= 6 && pattern.substr(0, 2) == "[[") {
        size_t closing = pattern.find("]]");
        if (closing == std::string::npos) return nullptr;
        
        std::string rest = pattern.substr(closing + 2);
        // Must start with + for valid FRAGMENT_REF (quantifier)
        if (rest.empty() || (rest[0] != '+' && rest[0] != '*' && rest[0] != '?')) return nullptr;
        
        std::string frag_name = pattern.substr(2, closing - 2);
        if (!frag_name.empty()) {
            auto node = PatternNode::createFragment(frag_name, {}, {});
            
            // Handle quantifier if present
            if (rest[0] == '+') {
                node->type = PatternType::PLUS_QUANTIFIER;
                node->quantified = PatternNode::createFragment(frag_name, {}, {});
            } else if (rest[0] == '*') {
                node->type = PatternType::STAR_QUANTIFIER;
                node->quantified = PatternNode::createFragment(frag_name, {}, {});
            } else if (rest[0] == '?') {
                node->type = PatternType::OPTIONAL;
                node->quantified = PatternNode::createFragment(frag_name, {}, {});
            }
            
            // If there's more pattern after the FRAGMENT_REF quantifier, parse recursively
            std::string remaining = rest.substr(1);
            if (!remaining.empty()) {
                // Create a SEQUENCE node: FRAGMENT_REF followed by the rest
                auto rest_node = parsePatternToAST(remaining);
                if (rest_node) {
                    return PatternNode::createSequence({node, rest_node}, {});
                }
            }
            
            return node;
        }
    }
    
    // Find the closing paren for a parenthesized group, respecting nested parens
    // Note: FRAGMENT_REF now uses [[...]] syntax, not nested parens
    auto findClosingParen = [](const std::string& s, size_t start) -> size_t {
        int depth = 1;
        for (size_t i = start; i < s.size(); i++) {
            // Check for nested paren groups (but not [[ which is fragment ref)
            if (s[i] == '(' && (i + 1 >= s.size() || s[i+1] != '[')) {
                depth++;
            } else if (s[i] == ')' && (i + 1 >= s.size() || s[i+1] != ']')) {
                depth--;
                if (depth == 0) return i;
            }
        }
        return std::string::npos;
    };
    
    // Handle alternation with quantifier: (a|b|c)+
    // The quantifier is AFTER the closing paren, not inside
    if (pattern.size() >= 3 && pattern[0] == '(') {
        size_t close_paren = findClosingParen(pattern, 1);
        if (close_paren != std::string::npos) {
            std::string inner = pattern.substr(1, close_paren - 1);
            std::vector<std::shared_ptr<PatternNode>> alts;
            
            // Check if inner contains | at depth 0
            auto splitAlternation = [](const std::string& s) -> std::vector<std::string> {
                std::vector<std::string> result;
                int depth = 0;
                size_t start = 0;
                for (size_t i = 0; i <= s.size(); i++) {
                    if (i < s.size() && s[i] == '[' && i + 1 < s.size() && s[i+1] == '[') {
                        // Skip FRAGMENT_REF [[...]]
                        size_t frag_end = s.find("]]", i + 2);
                        if (frag_end != std::string::npos) {
                            i = frag_end + 1;
                            continue;
                        }
                    }
                    if (i < s.size() && s[i] == '(') depth++;
                    else if (i < s.size() && s[i] == ')') depth--;
                    else if (i == s.size() || (s[i] == '|' && depth == 0)) {
                        std::string alt = s.substr(start, i - start);
                        if (!alt.empty()) result.push_back(alt);
                        start = i + 1;
                    }
                }
                return result;
            };
            
            std::vector<std::string> alt_strings = splitAlternation(inner);
            if (alt_strings.size() >= 2) {
                for (const auto& alt : alt_strings) {
                    alts.push_back(parsePatternToAST(alt));
                }
                
                // Check what comes after the closing paren
                std::string after = pattern.substr(close_paren + 1);
                std::shared_ptr<PatternNode> alt_node = PatternNode::createAlternation(alts, {});
                
                if (after == "+") {
                    alt_node->type = PatternType::PLUS_QUANTIFIER;
                    alt_node->quantified = PatternNode::createAlternation(alts, {});
                } else if (after == "*") {
                    alt_node->type = PatternType::STAR_QUANTIFIER;
                    alt_node->quantified = PatternNode::createAlternation(alts, {});
                } else if (after == "?") {
                    alt_node->type = PatternType::OPTIONAL;
                    alt_node->quantified = PatternNode::createAlternation(alts, {});
                }
                // If nothing after, it's just a grouped alternation, return as-is
                return alt_node;
            } else if (alt_strings.size() == 1) {
                // Single alternative - recurse to handle FRAGMENT_REF inside
                return parsePatternToAST(alt_strings[0]);
            }
        }
    }
    
    // Handle simple pattern without alternation: (xxx)+
    if (pattern.size() >= 4 && pattern[0] == '(') {
        size_t close_paren = findClosingParen(pattern, 1);
        if (close_paren != std::string::npos) {
            std::string inner = pattern.substr(1, close_paren - 1);
            std::string after = pattern.substr(close_paren + 1);
            
            // No alternation, just a literal with quantifier
            if (!inner.empty() && (after == "+" || after == "*" || after == "?")) {
                std::shared_ptr<PatternNode> node = PatternNode::createLiteral(inner, {});
                if (after == "+") {
                    node->type = PatternType::PLUS_QUANTIFIER;
                    node->quantified = PatternNode::createLiteral(inner, {});
                } else if (after == "*") {
                    node->type = PatternType::STAR_QUANTIFIER;
                    node->quantified = PatternNode::createLiteral(inner, {});
                } else if (after == "?") {
                    node->type = PatternType::OPTIONAL;
                    node->quantified = PatternNode::createLiteral(inner, {});
                }
                return node;
            }
        }
    }
    
    // Simple literal
    return PatternNode::createLiteral(pattern, {});
}

// Add capture tags to AST nodes
void addCaptureTags(std::shared_ptr<PatternNode> node, std::mt19937& rng) {
    if (!node) return;
    
    std::vector<std::string> all_seeds = node->matched_seeds;
    
    std::function<void(std::shared_ptr<PatternNode>)> collect = [&](std::shared_ptr<PatternNode> n) {
        if (!n) return;
        for (const auto& s : n->matched_seeds) {
            all_seeds.push_back(s);
        }
        if (n->quantified) collect(n->quantified);
        for (const auto& c : n->children) collect(c);
    };
    collect(node);
    
    std::sort(all_seeds.begin(), all_seeds.end());
    all_seeds.erase(std::unique(all_seeds.begin(), all_seeds.end()), all_seeds.end());
    
    if (all_seeds.empty()) return;
    
    // Strategy 1: Capture entire alternation
    if (node->type == PatternType::ALTERNATION && node->children.size() >= 2) {
        bool all_single = true;
        for (const auto& child : node->children) {
            if (child->matched_seeds.size() != 1) {
                all_single = false; break;
            }
        }
        if (all_single) {
            node->capture_tag = "c" + std::to_string(std::uniform_int_distribution<int>(0, 99)(rng));
            return;
        }
    }
    
    // Strategy 2: Capture entire quantified node
    if ((node->type == PatternType::PLUS_QUANTIFIER || 
         node->type == PatternType::STAR_QUANTIFIER ||
         node->type == PatternType::OPTIONAL) && 
        node->quantified && 
        !node->quantified->matched_seeds.empty()) {
        node->capture_tag = "c" + std::to_string(std::uniform_int_distribution<int>(0, 99)(rng));
        return;
    }
    
    // Recurse
    for (auto& child : node->children) {
        addCaptureTags(child, rng);
    }
    if (node->quantified) {
        addCaptureTags(node->quantified, rng);
    }
}

// Collect all seeds from captured nodes
std::vector<std::string> collectCaptureSeeds(std::shared_ptr<PatternNode> node) {
    std::vector<std::string> seeds;
    if (!node) return seeds;
    
    if (!node->capture_tag.empty()) {
        seeds.insert(seeds.end(), node->matched_seeds.begin(), node->matched_seeds.end());
    }
    
    for (const auto& c : node->children) {
        auto child_seeds = collectCaptureSeeds(c);
        seeds.insert(seeds.end(), child_seeds.begin(), child_seeds.end());
    }
    if (node->quantified) {
        auto quant_seeds = collectCaptureSeeds(node->quantified);
        seeds.insert(seeds.end(), quant_seeds.begin(), quant_seeds.end());
    }
    
    std::sort(seeds.begin(), seeds.end());
    seeds.erase(std::unique(seeds.begin(), seeds.end()), seeds.end());
    return seeds;
}

// ============================================================================
// Pattern Rewriting - Keeps matching set constant, complicates expression
// ============================================================================

void rewritePattern(std::shared_ptr<PatternNode> node, std::mt19937& rng) {
    if (!node) return;
    
    // Much lower probability to avoid creating invalid patterns
    std::uniform_int_distribution<int> apply_dist(0, 99);
    std::uniform_int_distribution<int> char_dist(0, 61);
    
    // Collect all seed values
    std::set<std::string> all_seeds;
    std::function<void(std::shared_ptr<PatternNode>)> collect = [&](std::shared_ptr<PatternNode> n) {
        if (!n) return;
        for (const auto& s : n->matched_seeds) {
            all_seeds.insert(s);
        }
        if (n->quantified) collect(n->quantified);
        for (const auto& c : n->children) collect(c);
    };
    collect(node);
    
    // Strategy 1: Reorder alternation alternatives (very rare)
    if (node->type == PatternType::ALTERNATION && node->children.size() > 1) {
        if (apply_dist(rng) < 2) {  // 2% chance
            std::shuffle(node->children.begin(), node->children.end(), rng);
        }
    }
    
    // Strategy 2: Add random non-matching alternatives (very rare)
    if (node->type == PatternType::ALTERNATION && !all_seeds.empty() && apply_dist(rng) < 2) {
        int num_new = 1;
        for (int i = 0; i < num_new; i++) {
            int len = std::uniform_int_distribution<int>(3, 6)(rng);
            static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            std::string new_alt;
            for (int j = 0; j < len; j++) {
                new_alt += charset[char_dist(rng)];
            }
            if (all_seeds.find(new_alt) == all_seeds.end()) {
                node->children.push_back(PatternNode::createLiteral(new_alt, {}));
            }
        }
    }
    
    // Strategy 3: Add empty alternative (ε) - makes pattern optional
    // Creates: (a|b|"") which means (a|b)? - matches empty OR a OR b
    if (node->type == PatternType::ALTERNATION && !all_seeds.empty() && apply_dist(rng) < 3) {
        bool has_empty = false;
        for (const auto& child : node->children) {
            if (child->type == PatternType::LITERAL && child->value.empty()) {
                has_empty = true; break;
            }
        }
        if (!has_empty) {
            // Add empty literal with empty seed (meaning "matches empty")
            auto empty_lit = PatternNode::createLiteral("", {}, {});
            empty_lit->matched_seeds = {};  // Empty matches empty
            node->children.push_back(empty_lit);
            // Note: matched_seeds will be updated by parent to track which inputs match
        }
    }
    
    // Strategy 4: Duplicate alternatives (very rare)
    if (node->type == PatternType::ALTERNATION && node->children.size() >= 2 && apply_dist(rng) < 2) {
        size_t idx = std::uniform_int_distribution<int>(0, node->children.size() - 1)(rng);
        auto& child = node->children[idx];
        if (child->type == PatternType::LITERAL && !child->value.empty() && child->fragment_name.empty()) {
            node->children.push_back(PatternNode::createLiteral(child->value, {}));
        }
    }
    
    // Strategy 5: Wrap literal in parens - DISABLED (causes nesting issues)
    // if (node->type == PatternType::LITERAL && !node->value.empty() && node->fragment_name.empty()) {
    //     if (apply_dist(rng) == 0) {
    //         node->type = PatternType::ALTERNATION;
    //         node->children.push_back(PatternNode::createLiteral(node->value, node->matched_seeds));
    //         node->value.clear();
    //     }
    // }
    
    // Strategy 6: Unmatched capture begin tag - DISABLED (creates invalid patterns)
    // if (node->capture_tag.empty() && node->capture_begin_only.empty() && node->capture_end_only.empty()) {
    //     if (apply_dist(rng) == 0 && std::uniform_int_distribution<int>(0, 9)(rng) == 0) {
    //         node->capture_begin_only = "u" + std::to_string(std::uniform_int_distribution<int>(0, 99)(rng));
    //     }
    // }
    
    // Strategy 7: Unmatched capture end tag - DISABLED (creates invalid patterns)
    // if (node->capture_tag.empty() && node->capture_begin_only.empty() && node->capture_end_only.empty()) {
    //     if (apply_dist(rng) == 0 && std::uniform_int_distribution<int>(0, 9)(rng) == 0) {
    //         node->capture_end_only = "u" + std::to_string(std::uniform_int_distribution<int>(0, 99)(rng));
    //     }
    // }
    
    // Strategy 8: Quantifier manipulation - DISABLED (changes matching semantics)
    // if (node->quantified) {
    //     if (apply_dist(rng) == 0) {
    //         ...
    //     }
    // }
    
    // Strategy 9: Case variation - DISABLED (changes matching semantics)
    // if (node->type == PatternType::LITERAL && !node->value.empty() && node->fragment_name.empty()) {
    //     ...
    // }
    
    // Strategy 10: Character class conversion - DISABLED (changes matching semantics)
    // if (node->type == PatternType::LITERAL && node->value.size() == 1 && node->fragment_name.empty()) {
    //     ...
    // }
    
    // Strategy 11: Split literal into prefix alternation - DISABLED (changes matching semantics)
    // if (node->type == PatternType::LITERAL && node->value.size() >= 3 && node->fragment_name.empty()) {
    //     ...
    // }
    
    // Strategy 12: Interleave wildcard between characters - DISABLED (changes matching semantics)
    // if (node->type == PatternType::LITERAL && node->value.size() >= 2 && node->fragment_name.empty()) {
    //     ...
    // }
    
    // Strategy 13: Wrap in nested capture group - DISABLED (creates invalid patterns)
    // if (node->type == PatternType::LITERAL && !node->value.empty() && node->capture_tag.empty() && node->fragment_name.empty()) {
    //     if (apply_dist(rng) < 3) {  // 3% chance
    //         node->capture_tag = "c" + std::to_string(std::uniform_int_distribution<int>(0, 99)(rng));
    //     }
    // }
    
    // Strategy 14: Add optional suffix - DISABLED (changes matching semantics)
    // if (node->type == PatternType::LITERAL && !node->value.empty() && node->fragment_name.empty()) {
    //     ...
    // }
    
    // Recurse
    if (node->quantified) {
        rewritePattern(node->quantified, rng);
    }
    for (auto& child : node->children) {
        rewritePattern(child, rng);
    }
}

// ============================================================================
// TestGenerator Implementation
// ============================================================================

TestGenerator::TestGenerator(const Options& opts) : opts(opts) {
    rng.seed(opts.seed);
}

std::vector<TestCase> TestGenerator::generate() {
    std::vector<TestCase> tests;
    int max_tests = std::min(opts.num_tests, 4);
    tests.reserve(max_tests * (1 + opts.mutations_per_test));
    
    std::set<std::string> all_used_inputs;
    int total_mutations = 0;
    int total_attempts = 0;
    
    for (int i = 0; i < max_tests; i++) {
        std::cout << "  Generating test case " << (i + 1) << "/" << max_tests << "..." << std::flush;
        
        TestCase base_tc = generateTestCase(i, all_used_inputs);
        
        for (const auto& inp : base_tc.matching_inputs) {
            all_used_inputs.insert(inp);
        }
        for (const auto& inp : base_tc.counter_inputs) {
            all_used_inputs.insert(inp);
        }
        
        tests.push_back(base_tc);
        
        TestGen::CoordinatedMutationEngine coord_engine;
        TestGen::TestCaseCore current_core = TestGen::TestCaseCore::fromOldTestCase(base_tc);
        std::string proof_chain = base_tc.proof;
        
        int mutations_applied = 0;
        int mutation_attempts = 0;
        const int max_attempts = opts.mutations_per_test * 2;
        
        while (mutations_applied < opts.mutations_per_test && mutation_attempts < max_attempts) {
            mutation_attempts++;
            total_attempts++;
            
            auto mutations = coord_engine.mutate(current_core, 5, rng);
            if (mutations.empty()) break;
            
            TestGen::TestCaseCore next_core;
            std::string mut_proof;
            bool found_valid = false;
            
            for (auto& mut_result : mutations) {
                if (mut_result.valid) {
                    next_core = mut_result.mutated_tc;
                    mut_proof = mut_result.proof;
                    found_valid = true;
                    break;
                }
            }
            
            if (!found_valid) continue;
            
            TestCase mutated_tc = next_core.toOldTestCase(tests.size());
            mutated_tc.category = base_tc.category;
            mutated_tc.counter_category = base_tc.counter_category;
            mutated_tc.proof = proof_chain + " -> " + mut_proof;
            
            // Mutations share inputs with their parent by design - no collision check needed
            tests.push_back(mutated_tc);
            proof_chain = mutated_tc.proof;
            current_core = next_core;
            mutations_applied++;
            total_mutations++;
        }
        
        std::cout << " " << mutations_applied << " mutations (" << mutation_attempts
                  << " attempts)" << std::endl;
    }
    
    if (total_attempts > 0) {
        std::cout << "  Mutation success rate: " << total_mutations << "/" << total_attempts
                  << " (" << std::fixed << std::setprecision(0)
                  << (100.0 * total_mutations / total_attempts) << "%)" << std::endl;
    }
    
    return tests;
}

// Generate random seed strings for a test case
std::pair<std::vector<std::string>, std::vector<std::string>> 
TestGenerator::generateSeeds(Complexity complexity, std::set<std::string>& used_inputs) {
    // Only use safe characters that don't need escaping in regex patterns
    const std::string lowercase = "abcdefghijklmnopqrstuvwxyz";
    const std::string uppercase = "ABCDEFGHIJKLMQRSTUVWXYZ";
    const std::string digits = "0123456789";
    const std::string alphanum = lowercase + uppercase + digits;
    
    std::vector<std::string> matching_seeds;
    std::vector<std::string> counter_seeds;
    std::set<std::string> used = used_inputs;
    
    // Generate correlation-based seeds with structure
    // Auto-correlation: 5 elements, each randomly initialized to [0.02, 0.34]
    // Cross-correlation: controls how much inputs influence each other
    std::vector<double> autocorr(5);
    for (int i = 0; i < 5; i++) {
        autocorr[i] = 0.02 + std::uniform_real_distribution<double>(0.0, 0.32)(rng);
    }
    double crosscorr = 0.3;
    
    // Determine base parameters from complexity
    int num_matching = 5;
    int num_counters = 25;
    int min_len, max_len;
    
    if (complexity == Complexity::SIMPLE) {
        min_len = 3;
        max_len = 6;
    } else if (complexity == Complexity::MEDIUM) {
        min_len = 4;
        max_len = 10;
    } else {
        min_len = 6;
        max_len = 16;
    }
    
    // Generate base pattern: a repeating unit that will be mutated
    // This creates correlation within and between strings
    std::string base_unit;
    int unit_len = 2 + std::uniform_int_distribution<int>(0, 2)(rng);
    for (int i = 0; i < unit_len; i++) {
        base_unit += alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
    }
    
    // Generate matching seeds with correlation
    std::vector<std::string> base_matching;
    for (int i = 0; i < num_matching; i++) {
        // Length varies around base unit length
        int target_len = min_len + std::uniform_int_distribution<int>(0, max_len - min_len)(rng);
        
        // Determine how to build this string:
        // 0 = pure random, 1 = repeat base_unit, 2 = repeat prefix, 3 = prefix + repeat
        int build_type = std::uniform_int_distribution<int>(0, 3)(rng);
        
        std::string s;
        if (build_type == 0) {
            // Pure random (add some entropy)
            for (int j = 0; j < target_len; j++) {
                s += alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
            }
        } else if (build_type == 1) {
            // Repeat base unit
            while ((int)s.size() < target_len) {
                s += base_unit;
            }
            s = s.substr(0, target_len);
        } else if (build_type == 2) {
            // Repeat a prefix of base_unit
            std::string prefix = base_unit.substr(0, 1 + std::uniform_int_distribution<int>(0, base_unit.size()-1)(rng));
            while ((int)s.size() < target_len) {
                s += prefix;
            }
            s = s.substr(0, target_len);
        } else {
            // Prefix + variation: start with some chars from base, then vary
            int prefix_len = std::uniform_int_distribution<int>(1, std::min(3, target_len-1))(rng);
            s = base_unit.substr(0, prefix_len);
            // Add correlated continuation using 5-element autocorrelation vector
            while ((int)s.size() < target_len) {
                double r = std::uniform_real_distribution<double>(0.0, 1.0)(rng);
                bool used_autocorr = false;
                
                // Check each autocorrelation element
                double cumulative = 0.0;
                for (int i = 0; i < (int)autocorr.size() && i + 1 < (int)s.size(); i++) {
                    cumulative += autocorr[i];
                    if (r < cumulative) {
                        // Repeat the character at position (i+1) back from end
                        s += s[s.size() - (i + 1)];
                        used_autocorr = true;
                        break;
                    }
                }
                
                if (!used_autocorr) {
                    // Random char
                    s += alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
                }
            }
        }
        
        if (used.insert(s).second) {
            matching_seeds.push_back(s);
            base_matching.push_back(s);
        }
    }
    
    // Ensure we have enough matching seeds
    while ((int)matching_seeds.size() < num_matching) {
        std::string s;
        int len = min_len + std::uniform_int_distribution<int>(0, max_len - min_len)(rng);
        
        // Use cross-correlation: build from existing matching seeds
        if (!base_matching.empty() && std::uniform_real_distribution<double>(0.0, 1.0)(rng) < crosscorr) {
            // Take a prefix from one matching seed and suffix from another
            const std::string& src1 = base_matching[std::uniform_int_distribution<int>(0, base_matching.size()-1)(rng)];
            const std::string& src2 = base_matching[std::uniform_int_distribution<int>(0, base_matching.size()-1)(rng)];
            int split = std::uniform_int_distribution<int>(1, std::min((int)src1.size()-1, len-1))(rng);
            s = src1.substr(0, split) + src2.substr(0, std::min((int)src2.size(), len - split));
        } else {
            // Random
            for (int j = 0; j < len; j++) {
                s += alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
            }
        }
        
        if (used.insert(s).second) {
            matching_seeds.push_back(s);
            base_matching.push_back(s);
        }
    }
    
    // Generate counter seeds that are different from matching
    // They should NOT follow the same patterns
    while ((int)counter_seeds.size() < num_counters) {
        std::string s;
        int len = min_len + std::uniform_int_distribution<int>(0, max_len - min_len)(rng);
        
        // For counters, use completely different approach:
        // Use a different character set or reverse patterns
        int counter_type = std::uniform_int_distribution<int>(0, 2)(rng);
        
        if (counter_type == 0) {
            // Different character set (e.g., only lowercase when matching uses mixed)
            std::string diff_chars = lowercase;
            for (int j = 0; j < len; j++) {
                s += diff_chars[std::uniform_int_distribution<int>(0, diff_chars.size()-1)(rng)];
            }
        } else if (counter_type == 1) {
            // Reverse or modify a matching seed to create near-miss
            if (!matching_seeds.empty()) {
                const std::string& src = matching_seeds[std::uniform_int_distribution<int>(0, matching_seeds.size()-1)(rng)];
                if (!src.empty()) {
                    // Take a different length
                    len = std::uniform_int_distribution<int>(1, (int)src.size())(rng);
                    s = src.substr(0, len);
                    // Change one character
                    if (!s.empty() && len > 1) {
                        int pos = std::uniform_int_distribution<int>(0, len-1)(rng);
                        char replacement = alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
                        while (replacement == s[pos]) {
                            replacement = alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
                        }
                        s[pos] = replacement;
                    }
                }
            } else {
                for (int j = 0; j < len; j++) {
                    s += alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
                }
            }
        } else {
            // Pure random (high entropy - opposite of matching)
            for (int j = 0; j < len; j++) {
                s += alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
            }
        }
        
        // Must be different from all matching and existing counters
        if (used.find(s) == used.end()) {
            bool invalid = false;
            for (const auto& m : matching_seeds) {
                // Reject if too similar to a matching seed
                if (s.size() == m.size()) {
                    int diff = 0;
                    for (size_t k = 0; k < s.size(); k++) {
                        if (s[k] != m[k]) diff++;
                    }
                    if (diff <= 1) {  // Too similar
                        invalid = true;
                        break;
                    }
                }
                // Reject if one is a prefix of another
                if (s.find(m) == 0 || m.find(s) == 0) {
                    invalid = true;
                    break;
                }
            }
            if (!invalid) {
                used.insert(s);
                counter_seeds.push_back(s);
            }
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
// ============================================================================
// InductiveBuilder - Constraint-Propagating Pattern AST Construction
// ============================================================================
// At each step, we track:
//   already matched part , remaining to match
//   For matching input: aas, ttt
//   For counter-input:  aaa, geeew
// We add to pattern something that matches SOME of 'ttt' but NOT all of 'geeew'.
// The pattern matches part of ttt while matching as little as possible of constraints.
// Division strategy:
//   Input:    asfalkjsfha
//   Counter:  asdggeeeeha
//   Split into subproblems:
//     1: asf (input), asdgge (counter) - with extra constraint
//     2: alkjsfha (input), eeeha (counter)
//   The extra constraint on subproblem 1 ensures that we can concatenate the patterns





// ============================================================================
// PatternFactorization - Rewrite alternations to factor out common prefixes/suffixes
// ============================================================================
// Prefix Example: d(7q7q7q|ddd|7qq8q|7qxd7qxd|7qNN7N)
//   -> d(ddd|(7q7q7q|7qq8q|7qxd7qxd|7qNN7N))
//   -> d(ddd|7(q7q7q|qq8q|qxd7qxd|qNN7N))
//   -> d(ddd|7q(7q7q|q8q|xd7qxd|NN7N))
// Suffix Example: (abc7q|bbc7q|cbc7q)
//   -> ((abc|bbc|cbc)7q)
//   -> (((ab|bb|cb)bc)7q)
//   -> (((a|b|c)bc)7q)
// This recursively factors common prefixes AND suffixes outside alternations.
// (Namespace definition continues from forward declaration above)

#include "pattern_factorization.h"

// Main pattern generator - try all strategies
PatternResult generateSeparatingPattern(const std::vector<std::string>& matching,
                                        const std::vector<std::string>& counters,
                                        [[maybe_unused]] Complexity complexity,
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
    strategies.push_back(tryMultiFragmentCombo);
    strategies.push_back(tryNestedAlternation);
    strategies.push_back(tryQuantifierStack);
    strategies.push_back(tryLongAlternation);
    strategies.push_back(tryAltWithAffix);
    strategies.push_back(tryTripleQuant);
    
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

std::map<std::string, std::string> generateFragmentsForPattern([[maybe_unused]] const std::string& pattern) {
    std::map<std::string, std::string> fragments;
    return fragments;
}

TestCase TestGenerator::generateTestCase(int test_id, std::set<std::string>& used_inputs) {
    TestCase tc;
    tc.test_id = test_id;
    
    // First test in batch? Clear the tracking sets
    if (test_id == 0) {
        batch_used_matching_.clear();
        batch_used_counter_.clear();
        batch_used_inputs_.clear();
    }
    
    // Select a unique matching category not used in this batch
    do {
        tc.category = randomCategory();
    } while (batch_used_matching_.count(tc.category) > 0);
    batch_used_matching_.insert(tc.category);
    
    // Select a counter category not equal to any matching category in this batch
    // and not already used as a counter category
    do {
        tc.counter_category = randomCategory();
    } while (tc.counter_category == tc.category || 
             batch_used_matching_.count(tc.counter_category) > 0 ||
             batch_used_counter_.count(tc.counter_category) > 0);
    batch_used_counter_.insert(tc.counter_category);
    
    tc.complexity = opts.complexity;
    tc.fragments.clear();
    
    // 5% chance to use edge-case coordinated seeding
    bool use_edge_case = (std::uniform_int_distribution<int>(0, 99)(rng) < 5);
    std::shared_ptr<PatternNode> edge_ast = nullptr;
    EdgeCaseResult edge;  // Declare outside to use in fragment handling
    
    if (use_edge_case) {
        // Randomly select an edge case type (skip NESTED_QUANTIFIER for now - creates conflicting expectations)
        std::uniform_int_distribution<int> edge_type_dist(0, 3);
        EdgeCaseType edge_types[] = {
            EdgeCaseType::RANGE_BOUNDARY,
            EdgeCaseType::PARTIAL_MATCH_FAIL,
            EdgeCaseType::QUANTIFIER_EDGE,
            EdgeCaseType::ALTERNATION_EDGE
        };
        EdgeCaseType selected_type = edge_types[edge_type_dist(rng)];
        
        edge = generateEdgeCase(selected_type, rng);
        
        // Use edge-case seeds
        tc.matching_inputs = edge.matching_seeds;
        tc.counter_inputs = edge.counter_seeds;
        edge_ast = edge.initial_ast;
        
        tc.proof += "\n=== EDGE CASE GENERATION ===\n";
        tc.proof += edge.proof;
        tc.proof += "\n";
    } else {
        // Normal random seeding
        auto [matching_seeds, counter_seeds] = generateSeeds(tc.complexity, used_inputs);
        tc.matching_inputs = matching_seeds;
        tc.counter_inputs = counter_seeds;
    }
    
    // Track seeds in batch_used_inputs_ for global uniqueness
    for (const auto& s : tc.matching_inputs) {
        batch_used_inputs_.insert(s);
    }
    for (const auto& s : tc.counter_inputs) {
        batch_used_inputs_.insert(s);
    }
    
    PatternResult result;
    bool pattern_valid = false;
    int max_retries = 5;
    
    // Retry loop for pattern generation
    for (int retry = 0; retry < max_retries && !pattern_valid; retry++) {
        result = PatternResult();
        result.proof = "Retry " + std::to_string(retry + 1) + ":\n";
        
        std::map<std::string, std::string> edge_fragments;
        if (use_edge_case && edge_ast) {
            // Use edge-case AST directly
            result.ast = edge_ast;
            // Add fragment definitions from edge case
            for (const auto& frag : edge.fragments) {
                result.fragments[frag.first] = frag.second;
            }
        } else {
            // Use InductiveBuilder as primary approach
            InductiveBuilder::BuildResult ib_result = InductiveBuilder::buildInductive(
                tc.matching_inputs, tc.counter_inputs, rng);
            
            if (ib_result.success && ib_result.ast) {
                result.ast = ib_result.ast;
                result.fragments = ib_result.fragments;
                result.pattern = serializePattern(ib_result.ast);
                result.proof += ib_result.proof;
            } else {
                // Fallback to old approach if InductiveBuilder fails
                PatternResult fallback = generateSeparatingPattern(tc.matching_inputs, tc.counter_inputs, tc.complexity, rng);
                result = fallback;
                result.proof += fallback.proof;
                // CRITICAL FIX: Strategies set result.pattern but NOT result.ast
                // Parse the pattern string to AST so transformations can work on it
                if (!result.pattern.empty() && !result.ast) {
                    result.ast = parsePatternToAST(result.pattern);
                }
            }
        }
        
        // Validate: check if all matched seeds match and no counter matches
        // Uses the NFA-based PatternMatcher for accurate AST-level validation
        if (!result.pattern.empty() && result.ast) {
            bool pattern_validates = cachedValidate(
                result.ast, tc.matching_inputs, tc.counter_inputs, tc.fragments);
            
            if (pattern_validates) {
                pattern_valid = true;
                result.proof += "  [PASS] Pattern validation passed (NFA matcher)\n";
            } else {
                // Get detailed failure explanation
                std::string failure = PatternMatcher::explainFailure(
                    result.ast, tc.matching_inputs, tc.counter_inputs, tc.fragments);
                result.proof += "  " + failure;
                if (retry < max_retries - 1) {
                    result.proof += "  [RETRY] Pattern invalid, regenerating...\n";
                    // Regenerate seeds for next attempt
                    auto [new_matching, new_counters] = generateSeeds(tc.complexity, used_inputs);
                    tc.matching_inputs = new_matching;
                    tc.counter_inputs = new_counters;
                    // Update batch tracking
                    for (const auto& s : new_matching) {
                        batch_used_inputs_.insert(s);
                    }
                    for (const auto& s : new_counters) {
                        batch_used_inputs_.insert(s);
                    }
                }
            }
        }
    }
    
    // If all retries failed, create trivial alternation as last resort
    if (!pattern_valid) {
        result.proof += "\n  [FALLBACK] All retries failed, creating trivial alternation\n";
        std::vector<std::shared_ptr<PatternNode>> alts;
        std::vector<std::string> all_counters;
        std::vector<std::string> filtered_matching;
        for (const auto& c : tc.counter_inputs) {
            all_counters.push_back(c);
        }
        for (const auto& m : tc.matching_inputs) {
            if (m.empty()) continue;  // Empty strings can't be serialized as alternatives
            filtered_matching.push_back(m);
            alts.push_back(PatternNode::createLiteral(m, {m}, all_counters));
        }
        if (!alts.empty()) {
            if (alts.size() == 1) {
                result.ast = alts[0];
            } else {
                result.ast = PatternNode::createAlternation(alts, filtered_matching, all_counters);
            }
            result.pattern = serializePattern(result.ast);
            result.fragments.clear();
            pattern_valid = true;
            tc.matching_inputs = filtered_matching;  // Update to filtered set
        }
    }

    // Skip rewritePattern for now
    
    tc.pattern = result.pattern;
    tc.fragments = result.fragments;
    
    // Apply factorization to create more compact patterns
    if (!use_edge_case || !edge_ast) {
        std::string before = serializePattern(result.ast);
        int before_match = result.ast ? result.ast->matched_seeds.size() : 0;
        int before_counters = result.ast ? result.ast->counter_seeds.size() : 0;
        
        result.proof += "  [Pre-transformation]\n";
        result.proof += "    Pattern: " + before + "\n";
        result.proof += "    Constraint: must-match(" + std::to_string(before_match) + "), must-not-match(" + std::to_string(before_counters) + ")\n";
        
        // Save AST before factorization in case we need to revert
        auto pre_factor_ast = result.ast ? PatternFactorization::copyPatternNode(result.ast) : nullptr;
        bool factorization_failed = false;
        
        // Apply factorization with detailed proof generation
        FactorizationProof factor_proof;
        factor_proof.before = before;
        
        result.ast = PatternFactorization::applyFactorization(result.ast, rng, &factor_proof);
        std::string after_factor = serializePattern(result.ast);
        int after_match = result.ast ? result.ast->matched_seeds.size() : 0;
        int after_counters = result.ast ? result.ast->counter_seeds.size() : 0;
        
        if (before != after_factor) {
            result.proof += "  [Factorization]\n";
            result.proof += "    Before: " + before + "\n";
            result.proof += "    After:  " + after_factor + "\n";
            result.proof += "    Constraint: must-match(" + std::to_string(after_match) + "), must-not-match(" + std::to_string(after_counters) + ")\n";
            
            // Generate detailed per-input derivation proof
            result.proof += "\n    DERIVATION (per input):\n";
            
            // Parse the before pattern to understand structure
            std::vector<std::string> before_alts;
            std::string before_clean = before;
            if (before_clean.size() >= 2 && before_clean.front() == '(' && before_clean.back() == ')') {
                before_clean = before_clean.substr(1, before_clean.size() - 2);
            }
            
            // Split by | at depth 0
            size_t start = 0;
            int depth = 0;
            for (size_t i = 0; i < before_clean.size(); i++) {
                if (before_clean[i] == '(') depth++;
                else if (before_clean[i] == ')') depth--;
                else if (before_clean[i] == '|' && depth == 0) {
                    before_alts.push_back(before_clean.substr(start, i - start));
                    start = i + 1;
                }
            }
            before_alts.push_back(before_clean.substr(start));
            
            // For each matching input, trace how it maps through factorization
            int valid_count = 0;
            int invalid_count = 0;
            
            for (const auto& input : result.ast->matched_seeds) {
                // Find which original alternative this input came from
                std::string original_alt;
                for (const auto& alt : before_alts) {
                    if (input == alt) {
                        original_alt = alt;
                        break;
                    }
                }
                
                if (original_alt.empty()) {
                    result.proof += "      ? '" + input + "': Cannot trace to original alternative\n";
                    invalid_count++;
                    continue;
                }
                
                // Use NFA-based matcher for accurate pattern matching
                bool found_match = PatternMatcher::matches(result.ast, input);
                
                if (found_match) {
                    result.proof += "      ✓ '" + input + "': matches pattern\n";
                    valid_count++;
                } else {
                    result.proof += "      ✗ '" + input + "': does NOT match pattern\n";
                    result.proof += "        Original: '" + original_alt + "'\n";
                    invalid_count++;
                }
            }
            
            result.proof += "\n    VALIDATION: " + std::to_string(valid_count) + "/" + 
                          std::to_string(after_match) + " inputs valid\n";
            
            if (invalid_count > 0) {
                result.proof += "    STATUS: FACTORIZATION BUG DETECTED - " + 
                              std::to_string(invalid_count) + " input(s) don't match factored pattern\n";
                factorization_failed = true;
            } else {
                result.proof += "    STATUS: All inputs verified to match\n";
            }
        }
        
        // If factorization failed, revert to pre-factorization AST and skip rewrites
        if (factorization_failed && pre_factor_ast) {
            result.proof += "  [REVERT] Factization produced invalid pattern, using pre-factorization version\n";
            result.ast = pre_factor_ast;
            // Ensure fragments from result.fragments are in tc.fragments
            // (they may have been set by the strategy before factorization)
            for (const auto& [name, def] : result.fragments) {
                tc.fragments[name] = def;
            }
        } else {
            // Apply complex rewrites (char classes, optional groups, nested quantifiers)
            std::string pre_complex = serializePattern(result.ast);
            auto [rewritten_ast, fragment_defs] = PatternFactorization::applyComplexRewrites(
                result.ast, rng, result.proof);
            result.ast = rewritten_ast;
            // Add any fragment definitions to BOTH result and tc
            for (const auto& [name, def] : fragment_defs) {
                result.fragments[name] = def;
                tc.fragments[name] = def;  // Also add to tc for pattern file output
            }
            // Also ensure any pre-existing fragments from result.fragments are in tc.fragments
            // (these may have been set by strategy before applyComplexRewrites)
            for (const auto& [name, def] : result.fragments) {
                tc.fragments[name] = def;
            }
            std::string after_complex = serializePattern(result.ast);
        
            // Apply random star quantifier insertion (20% chance to trigger)
            // DEEP COPY the AST before star insertion for comparison
            std::string pre_star_pattern = serializePattern(result.ast);
            std::shared_ptr<PatternNode> pre_star_ast = PatternFactorization::copyPatternNode(result.ast);  // Deep copy!
        
            result.ast = PatternFactorization::applyRandomStars(result.ast, rng);
            std::string after_stars = serializePattern(result.ast);
        
            if (pre_star_pattern != after_stars) {
                // Use AST comparison to detect specific star insertions
                std::string star_details = PatternFactorization::detectStarInsertions(
                    pre_star_ast, result.ast, "root");
            
                result.proof += "  [Star insertion]\n";
                result.proof += "    Pattern: " + pre_star_pattern + " -> " + after_stars + "\n";
                if (!star_details.empty()) {
                    result.proof += star_details;
                } else {
                    result.proof += "    (Star transformations detected but structure differed)\n";
                }
            }
        
            tc.pattern = after_stars;
        }
    }
    
    // Use the AST's matched_seeds which contains all inputs that validly match
    if (result.ast && !result.ast->matched_seeds.empty()) {
        tc.matching_inputs = result.ast->matched_seeds;
    }
    
    // Generate expectations from the AST (uses matched_seeds annotations)
    tc.expectations = generateExpectationsFromAST(result.ast, tc.fragments,
                                                   tc.matching_inputs, tc.counter_inputs);
    
    if (tc.pattern.empty()) {
        result.proof += "\n[FAILED] Could not generate separating pattern\n";
    }
    
    tc.proof = result.proof;
    
    // COMPREHENSIVE FIX: Ensure all FRAGMENT_REF nodes in AST have definitions
    // Derives actual definitions from the AST node's matched_seeds when possible
    if (result.ast && !tc.pattern.empty()) {
        std::set<std::string> ast_frags;
        collectFragmentNames(result.ast, ast_frags);
        for (const auto& frag_name : ast_frags) {
            if (tc.fragments.find(frag_name) == tc.fragments.end()) {
                // Search the AST for this fragment ref to get its matched_seeds
                std::function<std::vector<std::string>(std::shared_ptr<PatternNode>)> findSeeds;
                findSeeds = [&](std::shared_ptr<PatternNode> n) -> std::vector<std::string> {
                    if (!n) return {};
                    if (n->type == PatternType::FRAGMENT_REF && n->fragment_name == frag_name) {
                        return n->matched_seeds;
                    }
                    for (auto& child : n->children) {
                        auto s = findSeeds(child);
                        if (!s.empty()) return s;
                    }
                    if (n->quantified) return findSeeds(n->quantified);
                    return {};
                };
                auto seeds = findSeeds(result.ast);
                if (!seeds.empty()) {
                    bool all_same = true;
                    for (const auto& s : seeds) {
                        if (s != seeds[0]) { all_same = false; break; }
                    }
                    tc.fragments[frag_name] = all_same ? seeds[0] : std::string(1, seeds[0].empty() ? 'Z' : seeds[0][0]);
                } else {
                    tc.fragments[frag_name] = "Z";
                }
            }
        }
    }
    
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
    std::set<std::string> empty_set;
    return generateSeeds(complexity, empty_set);
}

std::map<std::string, std::string> TestGenerator::generateFragments([[maybe_unused]] Complexity complexity) {
    return {};
}

std::string TestGenerator::generateSimpleArg() {
    return "";
}

std::string TestGenerator::generateFlags([[maybe_unused]] int count) {
    return "";
}

std::string TestGenerator::generatePath() {
    return "";
}

std::string TestGenerator::generatePattern(const std::vector<std::string>& matching_inputs, 
                                           const std::vector<std::string>& counter_inputs,
                                           [[maybe_unused]] const std::map<std::string, std::string>& fragments,
                                           Complexity complexity,
                                           std::string& proof_out) {
    PatternResult result = generateSeparatingPattern(matching_inputs, counter_inputs, complexity, rng);
    proof_out = result.proof;
    return result.pattern;
}

std::string TestGenerator::transformPart(const std::string& part,
                                        [[maybe_unused]] const std::map<std::string, std::string>& fragments,
                                        [[maybe_unused]] Complexity complexity,
                                        [[maybe_unused]] bool allow_wildcard,
                                        [[maybe_unused]] const std::vector<std::string>& counter_inputs,
                                        [[maybe_unused]] const std::string& current_pattern,
                                        std::string& proof_out) {
    proof_out = "no transformation";
    return part;
}

bool TestGenerator::wouldMatchWithoutOptional([[maybe_unused]] const std::string& pattern_prefix, [[maybe_unused]] const std::string& counter_input) {
    return false;
}

bool TestGenerator::wouldMatchWithAlternation([[maybe_unused]] const std::string& pattern_prefix, [[maybe_unused]] const std::string& literal_part, [[maybe_unused]] const std::string& counter_input) {
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

std::string TestGenerator::makeMediumPattern(const std::vector<std::string>& parts, [[maybe_unused]] const std::map<std::string, std::string>& fragments) {
    return makeLiteralPattern(parts);
}

std::string TestGenerator::makeComplexPattern(const std::vector<std::string>& parts, [[maybe_unused]] const std::map<std::string, std::string>& fragments) {
    return makeLiteralPattern(parts);
}

std::vector<std::string> TestGenerator::generateCounterInputsSimple([[maybe_unused]] const std::string& arg, [[maybe_unused]] const std::string& cmd) {
    return {};
}

std::vector<std::string> TestGenerator::generateCounterInputsMedium([[maybe_unused]] const std::string& flags, [[maybe_unused]] const std::string& arg, [[maybe_unused]] const std::string& cmd) {
    return {};
}

std::vector<std::string> TestGenerator::generateCounterInputsComplex([[maybe_unused]] const std::string& flags, [[maybe_unused]] const std::vector<std::string>& args, [[maybe_unused]] const std::string& cmd) {
    return {};
}

bool TestGenerator::wouldPatternMatch([[maybe_unused]] const std::string& input, [[maybe_unused]] const std::string& pattern) {
    return false;
}

// Extract fragment references from a pattern string
// FRAGMENT_REF format: [[name]]+ where name can contain namespace like "test::name"
// FRAGMENT_REF is: [[ name ]] + where + is the quantifier
static std::vector<std::string> extractFragmentRefsFromPattern(const std::string& pattern) {
    std::vector<std::string> refs;
    size_t pos = 0;
    while (pos < pattern.size()) {
        if (pos + 2 < pattern.size() && pattern[pos] == '[' && pattern[pos+1] == '[') {
            size_t start = pos + 2;
            size_t end = start;
            while (end < pattern.size() && !(end + 1 < pattern.size() && pattern[end] == ']' && pattern[end+1] == ']')) {
                end++;
            }
            if (end + 1 < pattern.size() && pattern[end] == ']' && pattern[end+1] == ']') {
                std::string frag_name = pattern.substr(start, end - start);
                // After ]] there might be a quantifier, skip it
                size_t after_end = end + 2;
                if (after_end < pattern.size() && (pattern[after_end] == '+' || pattern[after_end] == '*' || pattern[after_end] == '?')) {
                    after_end++;
                }
                // Validate: fragment name should be alphanumeric + underscore + hyphen + ::
                bool valid = !frag_name.empty();
                for (char c : frag_name) {
                    if (!isalnum(c) && c != '_' && c != '-' && c != ':' && c != '/') {
                        valid = false;
                        break;
                    }
                }
                if (valid) {
                    refs.push_back(frag_name);
                }
                pos = after_end;
                continue;
            }
        }
        pos++;
    }
    return refs;
}

void TestGenerator::writePatternFile(const std::vector<TestCase>& tests, const std::string& filename) {
    std::ofstream out(filename);
    out << "# Auto-generated test patterns\n\n";
    
    // Collect all fragment definitions and validate references
    std::map<std::string, std::string> all_fragments;
    for (const auto& tc : tests) {
        for (const auto& f : tc.fragments) {
            if (all_fragments.find(f.first) == all_fragments.end()) {
                all_fragments[f.first] = f.second;
            }
        }
    }
    
    // Validate: ensure every FRAGMENT_REF in patterns has a definition
    for (const auto& tc : tests) {
        auto refs = extractFragmentRefsFromPattern(tc.pattern);
        for (const auto& ref : refs) {
            if (all_fragments.find(ref) == all_fragments.end()) {
                fprintf(stderr, "ERROR: Pattern references undefined fragment '%s' in test %d - this is a bug in testgen\n", 
                        ref.c_str(), tc.test_id);
                std::string pattern_short = tc.pattern.substr(0, 50);
                fprintf(stderr, "ERROR: Pattern (first 50 chars): %s\n", pattern_short.c_str());
                fprintf(stderr, "ERROR: Available fragments (%zu total):\n", all_fragments.size());
                for (const auto& f : all_fragments) {
                    fprintf(stderr, "ERROR:   '%s' -> '%s'\n", f.first.c_str(), f.second.c_str());
                    if (all_fragments.size() > 10) break;
                }
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
    
    // Write [CATEGORIES] section (0-indexed)
    out << "[CATEGORIES]\n";
    out << "0: safe\n";
    out << "1: caution\n";
    out << "2: modifying\n";
    out << "3: dangerous\n";
    out << "4: network\n";
    out << "5: admin\n";
    out << "6: build\n";
    out << "7: container\n";
    out << "\n";
    
    out << "# Patterns\n";
    for (const auto& tc : tests) {
        if (!tc.pattern.empty()) {
            // Write pattern with its category
            out << "[" << categoryToString(tc.category) << ":test" << tc.test_id << "] " << tc.pattern << "\n";
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
        out << "\",\n";
        out << "    \"fragments\": {";
        bool first_frag = true;
        for (const auto& f : tc.fragments) {
            if (!first_frag) out << ", ";
            out << "\"" << f.first << "\": \"" << f.second << "\"";
            first_frag = false;
        }
        out << "},\n";
        out << "    \"expectations\": [\n";
        for (size_t e = 0; e < tc.expectations.size(); e++) {
            const auto& exp = tc.expectations[e];
            out << "      {\n";
            out << "        \"type\": \"" << expectationTypeToString(exp.type) << "\",\n";
            out << "        \"input\": \"";
            for (size_t p = 0; p < exp.input.size(); p++) {
                char c = exp.input[p];
                if (c == '"') out << "\\\"";
                else out << c;
            }
            out << "\",\n";
            out << "        \"expected_match\": \"" << exp.expected_match << "\",\n";
            out << "        \"description\": \"";
            for (size_t p = 0; p < exp.description.size(); p++) {
                char c = exp.description[p];
                if (c == '"') out << "\\\"";
                else out << c;
            }
            out << "\",\n";
            out << "        \"meta\": {";
            bool first_meta = true;
            for (const auto& m : exp.meta) {
                if (!first_meta) out << ", ";
                out << "\"" << m.first << "\": \"";
                for (size_t p = 0; p < m.second.size(); p++) {
                    char c = m.second[p];
                    if (c == '"') out << "\\\"";
                    else out << c;
                }
                out << "\"";
                first_meta = false;
            }
            out << "}\n";
            out << "      }";
            if (e < tc.expectations.size() - 1) out << ",";
            out << "\n";
        }
        out << "    ]\n";
        out << "  }";
        if (i < tests.size() - 1) out << ",";
        out << "\n";
    }
    out << "]\n";
    out.close();
    std::cout << "Written expectations: " << filename << "\n";
}

int TestGenerator::runTests(const std::vector<TestCase>& tests, const std::string& cwd, const std::string& tools_dir, const std::string& pattern_file, [[maybe_unused]] const std::string& expectations_file, int* passed_out, int* failed_out, int* skipped_out) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "Running tests through c-dfa...\n";
    std::cout << std::string(60, '=') << "\n\n";
    
    std::string abs_pattern = cwd + "/" + pattern_file;
    std::string output_dir = abs_pattern.substr(0, abs_pattern.rfind('/'));
    
    std::cout << "1. Building DFA...\n";
    std::string dfa_file = output_dir + "/test.dfa";
    // Remove existing DFA file to avoid "already exists" error
    unlink(dfa_file.c_str());
    std::string dfa_cmd = tools_dir + "/cdfatool compile " + abs_pattern + " -o " + dfa_file + " 2>&1";
    int result = system(dfa_cmd.c_str());
    if (result != 0) {
        std::cerr << "cdfatool compile failed!\n";
        return 1;
    }
    std::cout << "   DFA built successfully\n\n";
    
    std::cout << "2. Testing patterns...\n";
    
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
        
        int expected_match_category = static_cast<int>(tc.category) - 1;
        
        // Check: matching inputs MUST match with the MATCHING category
        bool all_matched = true;
        std::string match_fail_reason;
        for (const auto& match_in : tc.matching_inputs) {
            std::string cmd = tools_dir + "/cdfatool eval " + dfa_file + " <<< \"" + match_in + "\"";
            CommandResult res = runCommand(cmd);
            
            if (res.exit_code != 0) {
                all_matched = false;
                match_fail_reason = "exit_code=" + std::to_string(res.exit_code);
                break;
            }
            
            bool matched = false;
            int category_mask = 0;
            
            // Parse stdout for matched, category, and category_mask
            if (res.stdout.empty()) {
                all_matched = false;
                match_fail_reason = "stdout was empty";
                break;
            }
            
            size_t match_pos = res.stdout.find("matched=1");
            if (match_pos != std::string::npos) {
                matched = true;
            }
            
            // Parse reported category (1-indexed: 1=SAFE, 2=CAUTION, etc.)
            int reported_category = 0;
            size_t cat_pos = res.stdout.find("category=");
            if (cat_pos != std::string::npos) {
                std::string cat_str = res.stdout.substr(cat_pos + 9);
                size_t end_pos = cat_str.find(' ');
                if (end_pos == std::string::npos) end_pos = cat_str.find('(');
                if (end_pos != std::string::npos) cat_str = cat_str.substr(0, end_pos);
                reported_category = atoi(cat_str.c_str());
            }
            
            // Parse category_mask
            size_t mask_pos = res.stdout.find("category_mask=0x");
            if (mask_pos != std::string::npos) {
                std::string mask_str = res.stdout.substr(mask_pos + 16);  // "category_mask=0x" is 16 chars
                // Extract hex value up to space or end
                size_t end_pos = mask_str.find(' ');
                if (end_pos != std::string::npos) {
                    mask_str = mask_str.substr(0, end_pos);
                }
                category_mask = (int)strtol(mask_str.c_str(), nullptr, 16);
            }
            

            
            int category_bit = (1 << expected_match_category);
            bool mask_has_expected = (category_mask & category_bit);
            bool category_matches = (reported_category == (expected_match_category + 1));
            
            // Count bits in mask to detect multiple matches
            int mask_bits = __builtin_popcount((unsigned int)category_mask);
            
            // Check consistency between category and category_mask
            bool consistent = true;
            if (matched && reported_category > 0) {
                // Category value should correspond to a bit in the mask
                if (reported_category >= 1 && reported_category <= 8) {
                    int expected_bit = reported_category - 1;
                    if ((category_mask & (1 << expected_bit)) == 0) {
                        consistent = false;
                    }
                } else {
                    consistent = false;  // Invalid category value
                }
            }
            
            // FAIL if: not matched, or expected bit not in mask
            if (!matched || !mask_has_expected) {
                all_matched = false;
                char mask_hex[16];
                snprintf(mask_hex, sizeof(mask_hex), "0x%02x", category_mask);
                match_fail_reason = "matched=" + std::to_string(matched) + 
                    ", category=" + std::to_string(reported_category) + 
                    ", category_mask=" + std::string(mask_hex);
                break;
            }
            
            // If multiple patterns can match (multiple bits in mask), don't fail on category mismatch
            // The expected category is in the mask, which is sufficient for multi-match cases
            if (mask_bits > 1 && !category_matches && mask_has_expected) {
                // Multiple patterns match - this is valid, just log a note
                // Don't fail - the expected bit IS in the mask
            } else if (!category_matches) {
                all_matched = false;
                char mask_hex[16];
                snprintf(mask_hex, sizeof(mask_hex), "0x%02x", category_mask);
                match_fail_reason = "INCONSISTENCY: category=" + std::to_string(reported_category) + 
                    " but mask has bit for " + std::to_string(expected_match_category + 1) +
                    " (mask=" + std::string(mask_hex) + ")";
                break;
            }
            
            // Also fail if category and mask are inconsistent
            if (!consistent) {
                all_matched = false;
                char mask_hex[16];
                snprintf(mask_hex, sizeof(mask_hex), "0x%02x", category_mask);
                match_fail_reason = "INCONSISTENCY: category=" + std::to_string(reported_category) + 
                    " but mask=0x" + std::string(mask_hex);
                break;
            }
        }
        
        if (!all_matched) { 
            std::cout << "   FAIL #" << i << ": matching inputs didn't match with correct category";
            if (!match_fail_reason.empty()) {
                std::cout << " (" << match_fail_reason << ")";
            }
            std::cout << "\n";
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
        std::string counter_fail_reason;
        for (const auto& counter : tc.counter_inputs) {
            std::string counter_cmd = tools_dir + "/cdfatool eval " + dfa_file + " <<< \"" + counter + "\"";
            CommandResult res = runCommand(counter_cmd);
            
            if (res.exit_code != 0) {
                any_counter_matched = true;  // Treat as failure
                counter_fail_reason = "exit_code=" + std::to_string(res.exit_code);
                break;
            }
            
            int last_counter_cat = 0;
            size_t cat_pos = res.stdout.find("category=");
            if (cat_pos != std::string::npos) {
                std::string cat_str = res.stdout.substr(cat_pos + 9);
                // Extract number up to space or parenthesis
                size_t end_pos = cat_str.find(' ');
                if (end_pos == std::string::npos) end_pos = cat_str.find('(');
                if (end_pos != std::string::npos) {
                    cat_str = cat_str.substr(0, end_pos);
                }
                last_counter_cat = atoi(cat_str.c_str());
            }
            // Counter input should NOT match with the matching category
            // Note: last_counter_cat is 1-indexed (from DFA), expected_match_category is 0-indexed
            if (last_counter_cat == expected_match_category + 1) any_counter_matched = true;
        }
        
        if (!any_counter_matched) {
            // Verify deep semantic expectations
            bool expectations_passed = true;
            std::string expectation_fail_reason;
            
            for (const auto& exp : tc.expectations) {
                std::string test_input = exp.input;
                
                if (exp.input.find("[[FRAGMENT:") != std::string::npos) {
                    continue;
                }
                if (exp.input == "[[CAPTURE_TEST]]") {
                    if (!tc.matching_inputs.empty()) {
                        test_input = tc.matching_inputs[0];
                    } else {
                        continue;
                    }
                }
                
                std::string cmd = tools_dir + "/cdfatool eval " + dfa_file + " <<< \"" + test_input + "\"";
                CommandResult res = runCommand(cmd);
                
                // Check for errors (ignore LOADING DFA debug messages)
                if (res.exit_code != 0) {
                    expectations_passed = false;
                    expectation_fail_reason = "exit_code=" + std::to_string(res.exit_code) + ", stderr=" + res.stderr;
                    break;
                }
                bool matched = false;
                int matched_category = 0;
                
                // Parse stdout
                if (res.stdout.find("matched=1") != std::string::npos) {
                    matched = true;
                }
                size_t cat_pos = res.stdout.find("category=");
                if (cat_pos != std::string::npos) {
                    std::string cat_str = res.stdout.substr(cat_pos + 9);
                    size_t end_pos = cat_str.find(' ');
                    if (end_pos == std::string::npos) end_pos = cat_str.find('(');
                    if (end_pos != std::string::npos) {
                        cat_str = cat_str.substr(0, end_pos);
                    }
                    matched_category = atoi(cat_str.c_str());
                }
                
                bool expected_match = (exp.expected_match == "yes");
                
                // For quantifier expectations, check if it matches any valid category
                // Not just the specific pattern's category (since other patterns may also match)
                if (exp.type == ExpectationType::QUANTIFIER_STAR_EMPTY || 
                    exp.type == ExpectationType::QUANTIFIER_PLUS_MINONE) {
                    // For STAR_EMPTY: empty string should match if ANY * pattern exists
                    // For PLUS_MINONE: empty should NOT match the + pattern
                    if (exp.type == ExpectationType::QUANTIFIER_STAR_EMPTY) {
                        // Empty string should match with SOME category (any * pattern)
                        if (expected_match && !matched) {
                            expectations_passed = false;
                            expectation_fail_reason = "Expectation failed: type=" + expectationTypeToString(exp.type) + 
                                ", input='" + test_input + "', expected=" + exp.expected_match + 
                                ", got no match, desc=" + exp.description;
                            break;
                        }
                    } else {
                        // PLUS_MINONE: empty should NOT match with THIS pattern's category
                        // Note: matched_category is 1-indexed from DFA, tc.category is also 1-indexed
                        int exp_cat = static_cast<int>(tc.category);
                        bool matched_this_category = matched && (matched_category == exp_cat);
                        
                        if (expected_match && !matched_this_category) {
                            expectations_passed = false;
                            expectation_fail_reason = "Expectation failed: type=" + expectationTypeToString(exp.type) + 
                                ", input='" + test_input + "', expected=" + exp.expected_match + 
                                ", got category=" + std::to_string(matched_category) + 
                                ", desc=" + exp.description;
                            break;
                        } else if (!expected_match && matched_this_category) {
                            expectations_passed = false;
                            expectation_fail_reason = "Expectation failed: type=" + expectationTypeToString(exp.type) + 
                                ", input='" + test_input + "', expected=" + exp.expected_match + 
                                ", got category=" + std::to_string(matched_category) + 
                                ", desc=" + exp.description;
                            break;
                        }
                    }
                } else {
                    // Original logic for other expectation types
                    if (matched != expected_match) {
                        expectations_passed = false;
                        expectation_fail_reason = "Expectation failed: type=" + expectationTypeToString(exp.type) + 
                            ", input='" + test_input + "', expected=" + exp.expected_match + 
                            ", got=" + (matched ? "yes" : "no") + ", desc=" + exp.description;
                        break;
                    }
                }
            }
            
            if (!expectations_passed) {
                std::cout << "   FAIL #" << i << ": " << expectation_fail_reason << "\n";
                failed++;
                global_failed_count++;
                
                std::string fail_file = output_dir + "/failed_case_" + std::to_string(global_failed_count) + ".json";
                std::ofstream ff(fail_file);
                ff << "{\n";
                ff << "  \"batch_file\": \"" << pattern_file << "\",\n";
                ff << "  \"test_id\": " << tc.test_id << ",\n";
                ff << "  \"pattern\": \"" << tc.pattern << "\",\n";
                ff << "  \"category\": \"" << categoryToString(tc.category) << "\",\n";
                ff << "  \"error\": \"" << expectation_fail_reason << "\",\n";
                ff << "  \"expectations\": [\n";
                for (size_t e = 0; e < tc.expectations.size(); e++) {
                    const auto& exp = tc.expectations[e];
                    ff << "    {\"type\": \"" << expectationTypeToString(exp.type) << "\", ";
                    ff << "\"input\": \"" << exp.input << "\", ";
                    ff << "\"expected\": \"" << exp.expected_match << "\"}\n";
                }
                ff << "  ]\n";
                ff << "}\n";
                ff.close();
                std::cout << "   Saved: " << fail_file << "\n";
            } else {
                passed++;
            }
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
    if (passed_out) *passed_out = passed;
    if (failed_out) *failed_out = failed;
    if (skipped_out) *skipped_out = skipped;
    return failed > 0 ? 1 : 0;
}

int TestGenerator::runTestsIndividual(const std::vector<TestCase>& tests, const std::string& cwd, const std::string& tools_dir, const std::string& pattern_file, [[maybe_unused]] const std::string& expectations_file, int* passed_out, int* failed_out, int* skipped_out) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "Running tests through c-dfa (INDIVIDUALLY)...\n";
    std::cout << std::string(60, '=') << "\n\n";
    
    std::string abs_pattern = cwd + "/" + pattern_file;
    std::string output_dir = abs_pattern.substr(0, abs_pattern.rfind('/'));
    std::string failed_dir = output_dir + "/failed_cases";
    
    // Create failed_cases directory
    mkdir(failed_dir.c_str(), 0755);
    
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
        
        CommandResult compile_res = runCommand(tools_dir + "/cdfatool compile " + temp_pattern + " -o " + dfa_file);
        if (compile_res.exit_code != 0 || !compile_res.stderr.empty()) { 
            std::cout << "   FAIL #" << i << ": cdfatool compile failed (exit=" << compile_res.exit_code << ")\n";
            failed++; 
            continue; 
        }
        
        bool all_matched = true;
        int expected_category_0idx = static_cast<int>(tc.category) - 1;  // Convert 1-indexed to 0-indexed
        for (const auto& match_in : tc.matching_inputs) {
            CommandResult res = runCommand(tools_dir + "/cdfatool eval " + dfa_file + " <<< \"" + match_in + "\"");
            
            // Check for errors (ignore LOADING DFA debug messages)
            if (res.exit_code != 0) {
                std::cout << "   FAIL #" << i << ": cdfatool eval error (exit=" << res.exit_code << ")\n";
                all_matched = false;
                break;
            }
            
            bool matched = false;
            int matched_category = 0;
            int category_mask = 0;
            
            // Parse stdout
            if (res.stdout.find("matched=1") != std::string::npos) {
                matched = true;
            }
            
            // Parse reported category (1-indexed from DFA)
            size_t cat_pos = res.stdout.find("category=");
            if (cat_pos != std::string::npos) {
                std::string cat_str = res.stdout.substr(cat_pos + 9);
                size_t end_pos = cat_str.find(' ');
                if (end_pos == std::string::npos) end_pos = cat_str.find('(');
                if (end_pos != std::string::npos) {
                    cat_str = cat_str.substr(0, end_pos);
                }
                matched_category = atoi(cat_str.c_str());
            }
            
            // Parse category_mask
            size_t mask_pos = res.stdout.find("category_mask=0x");
            if (mask_pos != std::string::npos) {
                std::string mask_str = res.stdout.substr(mask_pos + 16);
                size_t end_pos = mask_str.find(' ');
                if (end_pos != std::string::npos) mask_str = mask_str.substr(0, end_pos);
                category_mask = (int)strtol(mask_str.c_str(), nullptr, 16);
            }
            
            // Dual-verification: check both mask and category consistency
            int category_bit = (1 << expected_category_0idx);
            bool mask_has_expected = (category_mask & category_bit);
            bool category_matches = (matched_category == static_cast<int>(tc.category));
            
            // Count bits in mask to detect multiple matches
            int mask_bits = __builtin_popcount((unsigned int)category_mask);
            
            // Check consistency
            bool consistent = true;
            if (matched && matched_category > 0) {
                if (matched_category >= 1 && matched_category <= 8) {
                    int expected_bit = matched_category - 1;
                    if ((category_mask & (1 << expected_bit)) == 0) {
                        consistent = false;
                    }
                } else {
                    consistent = false;
                }
            }
            
            if (!matched || !mask_has_expected) {
                std::cout << "   FAIL #" << i << ": matched=" << matched << ", category=" << matched_category << ", category_mask=0x" << std::hex << category_mask << std::dec << "\n";
                all_matched = false;
                break;
            }
            
            // If multiple patterns can match (multiple bits in mask), don't fail on category mismatch
            if (mask_bits > 1 && !category_matches && mask_has_expected) {
                // Multiple patterns match - this is valid
            } else if (!category_matches || !consistent) {
                std::cout << "   FAIL #" << i << ": INCONSISTENCY - category=" << matched_category << " but expected " << static_cast<int>(tc.category) << " (mask=0x" << std::hex << category_mask << std::dec << ")\n";
                all_matched = false;
                break;
            }
        }
        
        bool any_counter_matched = false;
        for (const auto& counter : tc.counter_inputs) {
            CommandResult res = runCommand(tools_dir + "/cdfatool eval " + dfa_file + " <<< \"" + counter + "\"");
            
            // Check for errors (ignore LOADING DFA debug messages)
            bool is_debug_only = (res.stderr.find("LOADING DFA:") != std::string::npos);
            if (res.exit_code != 0 || (!is_debug_only && !res.stderr.empty())) {
                any_counter_matched = true;  // Treat error as failure
                break;
            }
            
            int counter_cat = 0;
            size_t ccat_pos = res.stdout.find("category=");
            if (ccat_pos != std::string::npos) {
                std::string cat_str = res.stdout.substr(ccat_pos + 9);
                size_t end_pos = cat_str.find(' ');
                if (end_pos == std::string::npos) end_pos = cat_str.find('(');
                if (end_pos != std::string::npos) {
                    cat_str = cat_str.substr(0, end_pos);
                }
                counter_cat = atoi(cat_str.c_str()) - 1;  // Convert to 0-indexed
                if (counter_cat == expected_category_0idx) any_counter_matched = true;
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
    if (passed_out) *passed_out = passed;
    if (failed_out) *failed_out = failed;
    if (skipped_out) *skipped_out = skipped;
    if (failed > 0) {
        std::cout << "Failed cases saved to: " << failed_dir << "/\n";
    }
    return failed > 0 ? 1 : 0;
}
