#include "edge_case_gen.h"
#include <algorithm>
#include <random>
#include <set>

static std::string randomAlphaEdge(int len, std::mt19937& rng) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::uniform_int_distribution<int> dist(0, sizeof(charset) - 2);
    std::string result;
    for (int i = 0; i < len; i++) {
        result += charset[dist(rng)];
    }
    return result;
}

static EdgeCaseResult createRangeBoundaryEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::RANGE_BOUNDARY;
    
    std::uniform_int_distribution<int> range_dist(0, 2);
    int range_type = range_dist(rng);
    
    std::string range_name;
    std::vector<char> chars;
    
    if (range_type == 0) {
        range_name = "lower";
        for (char c = 'a'; c <= 'z'; c++) chars.push_back(c);
    } else if (range_type == 1) {
        range_name = "upper";
        for (char c = 'A'; c <= 'Z'; c++) chars.push_back(c);
    } else {
        range_name = "digit";
        for (char c = '0'; c <= '9'; c++) chars.push_back(c);
    }
    
    std::string frag_def;
    std::vector<std::string> frag_chars;
    std::uniform_int_distribution<int> char_idx(0, (int)chars.size() - 1);
    
    int num_chars = 5 + std::uniform_int_distribution<int>(0, 5)(rng);
    std::set<char> selected;
    for (int i = 0; i < num_chars; i++) {
        selected.insert(chars[char_idx(rng)]);
    }
    for (char c : selected) {
        std::string s(1, c);
        frag_def += s + "|";
        frag_chars.push_back(s);
    }
    if (!frag_def.empty()) frag_def.pop_back();
    
    std::string frag_name = "range_" + range_name;
    
    auto frag_node = PatternNode::createFragment(frag_name, frag_chars);
    frag_node->type = PatternType::PLUS_QUANTIFIER;
    frag_node->quantified = PatternNode::createFragment(frag_name, frag_chars);
    result.initial_ast = frag_node;
    
    result.fragments[frag_name] = frag_def;
    
    result.proof = "EDGE_CASE: RANGE_BOUNDARY\n";
    result.proof += "  Fragment: " + frag_name + " = " + frag_def + "\n";
    result.proof += "  Pattern: [[" + frag_name + "]]+\n";
    
    for (char c : selected) {
        result.matching_seeds.push_back(std::string(1, c));
    }
    std::vector<char> selected_vec(selected.begin(), selected.end());
    if (selected_vec.size() >= 2) {
        result.matching_seeds.push_back(std::string(1, selected_vec.front()) + std::string(1, selected_vec.front()));
        result.matching_seeds.push_back(std::string(1, selected_vec.back()) + std::string(1, selected_vec.back()));
    }
    
    static const char non_range[] = "!@#$%^&*()[]{}|;':\",./<>?";
    std::uniform_int_distribution<int> non_dist(0, sizeof(non_range) - 2);
    for (int i = 0; i < 10; i++) {
        std::string s(1, non_range[non_dist(rng)]);
        result.counter_seeds.push_back(s);
    }
    
    result.proof += "  Matching: ";
    for (auto& s : result.matching_seeds) result.proof += s + " ";
    result.proof += "\n  Counters: ";
    for (auto& s : result.counter_seeds) result.proof += s + " ";
    result.proof += "\n  Rationale: Tests range boundaries - matching uses edge chars from range, counters use non-range chars\n";
    
    return result;
}

static EdgeCaseResult createPartialMatchEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::PARTIAL_MATCH_FAIL;
    
    std::string prefix = randomAlphaEdge(2, rng);
    
    auto node = PatternNode::createLiteral(prefix, {prefix});
    node->type = PatternType::PLUS_QUANTIFIER;
    node->quantified = PatternNode::createLiteral(prefix, {prefix});
    result.initial_ast = node;
    
    result.matching_seeds.push_back(prefix);
    result.matching_seeds.push_back(prefix + prefix);
    result.matching_seeds.push_back(prefix + prefix + prefix);
    
    static const char extras[] = "xyzXYZ012!@#%^&*()";
    std::uniform_int_distribution<int> extra_dist(0, sizeof(extras) - 2);
    for (int i = 0; i < 8; i++) {
        result.counter_seeds.push_back(prefix + extras[extra_dist(rng)]);
    }
    
    result.proof = "EDGE_CASE: PARTIAL_MATCH_FAIL\n";
    result.proof += "  Pattern: (" + prefix + ")+\n";
    result.proof += "  Matching: ";
    for (auto& s : result.matching_seeds) result.proof += s + " ";
    result.proof += "\n  Counters: ";
    for (auto& s : result.counter_seeds) result.proof += s + " ";
    result.proof += "\n  Rationale: Counters share prefix with pattern but have unexpected continuation\n";
    
    return result;
}

static EdgeCaseResult createQuantifierEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::QUANTIFIER_EDGE;
    
    std::uniform_int_distribution<int> qtype(0, 2);
    int qt = qtype(rng);
    
    std::string base = randomAlphaEdge(1, rng);
    
    PatternType quant_type;
    std::string quant_str;
    if (qt == 0) {
        quant_type = PatternType::PLUS_QUANTIFIER;
        quant_str = "+";
    } else if (qt == 1) {
        quant_type = PatternType::STAR_QUANTIFIER;
        quant_str = "*";
    } else {
        quant_type = PatternType::OPTIONAL;
        quant_str = "?";
    }
    
    auto node = PatternNode::createLiteral(base, {base});
    node->type = quant_type;
    node->quantified = PatternNode::createLiteral(base, {base});
    result.initial_ast = node;
    
    if (qt == 0) {
        result.matching_seeds.push_back(base);
        result.matching_seeds.push_back(base + base);
        result.matching_seeds.push_back(base + base + base);
    } else if (qt == 1) {
        result.matching_seeds.push_back("");
        result.matching_seeds.push_back(base);
        result.matching_seeds.push_back(base + base + base);
    } else {
        result.matching_seeds.push_back("");
        result.matching_seeds.push_back(base);
    }
    
    std::string diff(1, base[0] + 1);
    if (diff[0] > 'z') diff[0] = 'a';
    result.counter_seeds.push_back(diff);
    result.counter_seeds.push_back(diff + diff);
    
    result.proof = "EDGE_CASE: QUANTIFIER_EDGE\n";
    result.proof += "  Pattern: (" + base + ")" + quant_str + "\n";
    result.proof += "  Matching: ";
    for (auto& s : result.matching_seeds) result.proof += (s.empty() ? "<empty>, " : s + ", ");
    result.proof += "\n  Counters: ";
    for (auto& s : result.counter_seeds) result.proof += s + " ";
    result.proof += "\n  Rationale: Tests quantifier " + quant_str + " edge cases (empty, single, multiple)\n";
    
    return result;
}

static EdgeCaseResult createAlternationEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::ALTERNATION_EDGE;
    
    int num_alts = 3 + std::uniform_int_distribution<int>(0, 2)(rng);
    std::vector<std::string> alts;
    std::set<char> used_chars;
    
    for (int i = 0; i < num_alts; i++) {
        std::string alt;
        do {
            alt = randomAlphaEdge(1 + std::uniform_int_distribution<int>(0, 1)(rng), rng);
        } while (used_chars.count(alt[0]));
        used_chars.insert(alt[0]);
        alts.push_back(alt);
    }
    
    std::vector<std::shared_ptr<PatternNode>> alt_nodes;
    for (auto& alt : alts) {
        alt_nodes.push_back(PatternNode::createLiteral(alt, {alt}));
    }
    auto node = PatternNode::createAlternation(alt_nodes, alts);
    node->type = PatternType::PLUS_QUANTIFIER;
    node->quantified = PatternNode::createAlternation(alt_nodes, alts);
    result.initial_ast = node;
    
    for (auto& alt : alts) {
        result.matching_seeds.push_back(alt);
    }
    result.matching_seeds.push_back(alts[0] + alts[1]);
    
    char counter_char = '!';
    while (used_chars.count(counter_char)) counter_char++;
    result.counter_seeds.push_back(std::string(1, counter_char));
    result.counter_seeds.push_back(std::string(1, counter_char) + std::string(1, counter_char));
    result.counter_seeds.push_back(alts[0] + counter_char);
    
    result.proof = "EDGE_CASE: ALTERNATION_EDGE\n";
    result.proof += "  Pattern: (";
    for (size_t i = 0; i < alts.size(); i++) {
        if (i > 0) result.proof += "|";
        result.proof += alts[i];
    }
    result.proof += ")+\n";
    result.proof += "  Matching: ";
    for (auto& s : result.matching_seeds) result.proof += s + " ";
    result.proof += "\n  Counters: ";
    for (auto& s : result.counter_seeds) result.proof += s + " ";
    result.proof += "\n  Rationale: Tests alternation - some alts match, counters fail at different points\n";
    
    return result;
}

static EdgeCaseResult createNestedQuantifierEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::NESTED_QUANTIFIER;
    
    std::string inner = randomAlphaEdge(2, rng);
    
    auto inner_node = PatternNode::createLiteral(inner, {inner});
    inner_node->type = PatternType::PLUS_QUANTIFIER;
    inner_node->quantified = PatternNode::createLiteral(inner, {inner});
    
    auto node = PatternNode::createQuantified(inner_node, PatternType::STAR_QUANTIFIER, {inner});
    result.initial_ast = node;
    
    result.matching_seeds.push_back(inner);
    result.matching_seeds.push_back(inner + inner);
    result.matching_seeds.push_back(inner + inner + inner);
    
    static const char extras[] = "xyzXYZ012!@#";
    std::uniform_int_distribution<int> extra_dist(0, sizeof(extras) - 2);
    for (int i = 0; i < 6; i++) {
        result.counter_seeds.push_back(inner + extras[extra_dist(rng)]);
    }
    
    result.proof = "EDGE_CASE: NESTED_QUANTIFIER\n";
    result.proof += "  Pattern: (" + inner + "+)*\n";
    result.proof += "  Matching: ";
    for (auto& s : result.matching_seeds) result.proof += s + " ";
    result.proof += "\n  Counters: ";
    for (auto& s : result.counter_seeds) result.proof += s + " ";
    result.proof += "\n  Rationale: Tests nested quantifiers - inner + should match, partial should fail\n";
    
    return result;
}

static EdgeCaseResult createEmptyAlternationEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::EMPTY_ALTERNATION;

    // Pattern: (a|b|) which matches "a", "b", or empty string
    std::string a = std::string(1, 'a' + std::uniform_int_distribution<int>(0, 25)(rng));
    std::string b = std::string(1, 'a' + std::uniform_int_distribution<int>(0, 25)(rng));
    while (b == a) b = std::string(1, 'a' + std::uniform_int_distribution<int>(0, 25)(rng));

    auto lit_a = PatternNode::createLiteral(a, {a});
    auto lit_b = PatternNode::createLiteral(b, {b});
    auto empty_lit = PatternNode::createLiteral("", {""});
    auto alt_node = PatternNode::createAlternation({lit_a, lit_b, empty_lit}, {a, b, ""});
    result.initial_ast = alt_node;

    result.matching_seeds = {a, b, ""};
    
    // Counter: strings that are neither a nor b nor empty
    char c = 'a' + std::uniform_int_distribution<int>(0, 25)(rng);
    while (std::string(1, c) == a || std::string(1, c) == b) {
        c = 'a' + std::uniform_int_distribution<int>(0, 25)(rng);
    }
    result.counter_seeds = {std::string(1, c), a + b, b + a, "xyz"};

    result.proof = "EDGE_CASE: EMPTY_ALTERNATION\n";
    result.proof += "  Pattern: (" + a + "|" + b + "|)\n";
    result.proof += "  Matching: " + a + ", " + b + ", <empty>\n";
    result.proof += "  Rationale: Tests empty alternative (|) - matches empty or a or b\n";
    return result;
}

static EdgeCaseResult createDeepNestingEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::DEEP_NESTING;

    // Build deeply nested pattern: ((((((ab)+)*)
    std::string inner = randomAlphaEdge(2, rng);
    int depth = 6 + std::uniform_int_distribution<int>(0, 4)(rng);  // 6-10 levels

    auto node = PatternNode::createLiteral(inner, {inner});
    node->type = PatternType::PLUS_QUANTIFIER;
    node->quantified = PatternNode::createLiteral(inner, {inner});

    for (int i = 0; i < depth; i++) {
        auto wrapped = PatternNode::createQuantified(node, PatternType::STAR_QUANTIFIER, {inner});
        node = wrapped;
    }
    result.initial_ast = node;

    result.matching_seeds = {inner, inner + inner, inner + inner + inner};
    result.counter_seeds = {inner + "x", "x" + inner, "x"};

    result.proof = "EDGE_CASE: DEEP_NESTING\n";
    result.proof += "  Depth: " + std::to_string(depth) + "\n";
    result.proof += "  Inner: " + inner + "\n";
    result.proof += "  Rationale: Tests deeply nested quantifiers\n";
    return result;
}

static EdgeCaseResult createEmptyGroupQuantEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::EMPTY_GROUP_QUANT;

    // Pattern: (a|b)+ where the plus quantifier is applied to a simple alternation
    // Tests that quantifiers on groups work correctly
    std::string a = randomAlphaEdge(1, rng);
    std::string b = randomAlphaEdge(1, rng);
    while (b == a) b = randomAlphaEdge(1, rng);

    auto lit_a = PatternNode::createLiteral(a, {a});
    auto lit_b = PatternNode::createLiteral(b, {b});
    auto alt_node = PatternNode::createAlternation({lit_a, lit_b}, {a, b});
    
    // Wrap in quantifier
    auto quant_node = PatternNode::createQuantified(alt_node, PatternType::PLUS_QUANTIFIER, {a, b, a+b, b+a});
    result.initial_ast = quant_node;

    result.matching_seeds = {a, b, a + b, b + a, a + a, b + b};
    result.counter_seeds = {"", "x", a + "x", "x" + a};

    result.proof = "EDGE_CASE: EMPTY_GROUP_QUANT\n";
    result.proof += "  Pattern: (" + a + "|" + b + ")+\n";
    result.proof += "  Rationale: Tests quantified group with alternation\n";
    return result;
}

static EdgeCaseResult createLongAlternationEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::LONG_ALTERNATION;

    int num_alts = 12 + std::uniform_int_distribution<int>(0, 8)(rng);  // 12-20 alternatives
    std::vector<std::shared_ptr<PatternNode>> alt_nodes;
    std::vector<std::string> alts;
    std::set<char> used_chars;

    for (int i = 0; i < num_alts; i++) {
        std::string alt;
        do {
            alt = randomAlphaEdge(1 + std::uniform_int_distribution<int>(0, 2)(rng), rng);
        } while (!alt.empty() && used_chars.count(alt[0]));
        if (!alt.empty()) used_chars.insert(alt[0]);
        alts.push_back(alt);
        alt_nodes.push_back(PatternNode::createLiteral(alt, {alt}));
    }

    auto node = PatternNode::createAlternation(alt_nodes, alts);
    result.initial_ast = node;

    for (auto& alt : alts) {
        result.matching_seeds.push_back(alt);
    }

    // Generate counters that don't match any alternative
    for (int i = 0; i < 10; i++) {
        std::string counter = randomAlphaEdge(3, rng);
        bool matches_any = false;
        for (auto& alt : alts) {
            if (counter == alt) { matches_any = true; break; }
        }
        if (!matches_any) {
            result.counter_seeds.push_back(counter);
        }
    }

    result.proof = "EDGE_CASE: LONG_ALTERNATION\n";
    result.proof += "  Num alternatives: " + std::to_string(num_alts) + "\n";
    result.proof += "  Rationale: Tests alternation with many alternatives (>10)\n";
    return result;
}

static EdgeCaseResult createFragmentCycleEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::FRAGMENT_CYCLE;

    // Create two fragments that reference different patterns
    // (actual cycles would hang the parser, so we test near-cycle patterns)
    std::string base_a = randomAlphaEdge(2, rng);
    std::string base_b = randomAlphaEdge(2, rng);
    while (base_b == base_a) base_b = randomAlphaEdge(2, rng);

    std::string frag_a_name = "cycA";
    std::string frag_b_name = "cycB";

    result.fragments[frag_a_name] = base_a;
    result.fragments[frag_b_name] = base_b;

    // Pattern: [[cycA]][[cycB]]+ (sequence of fragment refs)
    auto frag_a_node = PatternNode::createFragment(frag_a_name, {base_a});
    auto frag_b_node = PatternNode::createFragment(frag_b_name, {base_b});
    frag_b_node->type = PatternType::PLUS_QUANTIFIER;
    frag_b_node->quantified = PatternNode::createFragment(frag_b_name, {base_b});

    auto seq_node = PatternNode::createSequence({frag_a_node, frag_b_node}, {base_a + base_b});
    result.initial_ast = seq_node;

    result.matching_seeds = {base_a + base_b, base_a + base_b + base_b};
    result.counter_seeds = {base_b, base_a, base_b + base_a, "x"};

    result.proof = "EDGE_CASE: FRAGMENT_CYCLE\n";
    result.proof += "  Fragments: " + frag_a_name + "=" + base_a + ", " + frag_b_name + "=" + base_b + "\n";
    result.proof += "  Pattern: [[" + frag_a_name + "]][[" + frag_b_name + "]]+\n";
    result.proof += "  Rationale: Tests multiple fragment references in sequence (near-cycle stress)\n";
    return result;
}

static EdgeCaseResult createOverlappingAlternationEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::OVERLAPPING_ALTERNATION;
    
    // Generate a product structure: prefixes × suffixes
    // Example: {ab, cd} × {X, Y, Z} = {abX, abY, abZ, cdX, cdY, cdZ}
    // The inductive builder should discover (ab|cd)(X|Y|Z) via prefix/suffix split.
    std::vector<std::string> prefixes;
    std::vector<std::string> suffixes;
    
    // 2-3 distinct prefixes
    int num_prefixes = 2 + std::uniform_int_distribution<int>(0, 1)(rng);
    // 2-3 distinct suffixes
    int num_suffixes = 2 + std::uniform_int_distribution<int>(0, 1)(rng);
    
    // Generate unique prefixes
    std::set<std::string> seen_prefixes;
    while ((int)prefixes.size() < num_prefixes) {
        std::string p = randomAlphaEdge(2, rng);
        if (seen_prefixes.insert(p).second) {
            prefixes.push_back(p);
        }
    }
    
    // Generate unique suffixes
    std::set<std::string> seen_suffixes;
    while ((int)suffixes.size() < num_suffixes) {
        std::string s = randomAlphaEdge(2, rng);
        if (seen_suffixes.insert(s).second) {
            suffixes.push_back(s);
        }
    }
    
    // Generate matching seeds as the product
    for (const auto& p : prefixes) {
        for (const auto& s : suffixes) {
            result.matching_seeds.push_back(p + s);
        }
    }
    
    // Generate counters:
    // 1. Wrong suffix for known prefix (e.g., "abW" where only abX, abY, abZ exist)
    if (!prefixes.empty() && !suffixes.empty()) {
        std::string wrong_suffix = randomAlphaEdge(2, rng);
        while (std::find(suffixes.begin(), suffixes.end(), wrong_suffix) != suffixes.end()) {
            wrong_suffix = randomAlphaEdge(2, rng);
        }
        result.counter_seeds.push_back(prefixes[0] + wrong_suffix);
    }
    
    // 2. Wrong prefix for known suffix (e.g., "efX" where only abX, cdX exist)
    if (!prefixes.empty() && !suffixes.empty()) {
        std::string wrong_prefix = randomAlphaEdge(2, rng);
        while (std::find(prefixes.begin(), prefixes.end(), wrong_prefix) != prefixes.end()) {
            wrong_prefix = randomAlphaEdge(2, rng);
        }
        result.counter_seeds.push_back(wrong_prefix + suffixes[0]);
    }
    
    // 3. Mix of valid prefix and suffix but product not in set (longer string)
    if (!prefixes.empty() && !suffixes.empty()) {
        result.counter_seeds.push_back(prefixes[0] + randomAlphaEdge(3, rng));
    }
    
    // 4. Random counters of varying lengths
    for (int i = 0; i < 3; i++) {
        std::string c = randomAlphaEdge(3 + std::uniform_int_distribution<int>(0, 2)(rng), rng);
        result.counter_seeds.push_back(c);
    }
    
    result.proof = "EDGE_CASE: OVERLAPPING_ALTERNATION\n";
    result.proof += "  Prefixes: {";
    for (size_t i = 0; i < prefixes.size(); i++) {
        if (i > 0) result.proof += ", ";
        result.proof += prefixes[i];
    }
    result.proof += "}  Suffixes: {";
    for (size_t i = 0; i < suffixes.size(); i++) {
        if (i > 0) result.proof += ", ";
        result.proof += suffixes[i];
    }
    result.proof += "}\n";
    result.proof += "  Matching seeds: " + std::to_string(result.matching_seeds.size()) + " products\n";
    result.proof += "  Rationale: Tests prefix/suffix factorization — builder should find (prefix1|prefix2)(suffix1|suffix2)\n";
    return result;
}

static EdgeCaseResult createFragmentChainEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::FRAGMENT_CHAIN;
    
    // Create a chain of 3 fragments: fa=value, fb=[[fa]]+suffix, fc=[[fb]]+suffix2
    // Pattern: [[fc]]+ → expands to (value+suffix+suffix2)+
    // Tests the pipeline's fragment expansion depth limit.
    
    std::string base = randomAlphaEdge(2, rng);
    std::string suf_b = randomAlphaEdge(1, rng);
    std::string suf_c = randomAlphaEdge(1, rng);
    
    // Ensure suffixes are different from base to avoid ambiguity
    while (suf_b == base.substr(0, 1)) suf_b = randomAlphaEdge(1, rng);
    while (suf_c == suf_b || suf_c == base.substr(0, 1)) suf_c = randomAlphaEdge(1, rng);
    
    std::string fa_name = "chainA";
    std::string fb_name = "chainB";
    std::string fc_name = "chainC";
    
    std::string expanded_b = base + suf_b;
    std::string expanded_c = expanded_b + suf_c;
    
    result.fragments[fa_name] = base;
    result.fragments[fb_name] = "[[chainA]]" + suf_b;
    result.fragments[fc_name] = "[[chainB]]" + suf_c;
    
    // Build AST: [[fc]]+
    auto fa_ref = PatternNode::createFragment(fc_name, {expanded_c});
    auto plus_node = PatternNode::createQuantified(fa_ref, PatternType::PLUS_QUANTIFIER);
    result.initial_ast = plus_node;
    
    // Matching: one repetition and two repetitions
    result.matching_seeds = {expanded_c, expanded_c + expanded_c};
    
    // Counters: partial chains, wrong order, base alone
    result.counter_seeds = {
        base,                    // only fa
        expanded_b,              // only fb (missing suffix_c)
        suf_c,                   // just the suffix
        base + suf_c,            // skip middle
        expanded_c + expanded_b, // second rep is wrong
        randomAlphaEdge(3, rng)
    };
    
    result.proof = "EDGE_CASE: FRAGMENT_CHAIN\n";
    result.proof += "  Fragments: " + fa_name + "=" + base + ", " +
                   fb_name + "=[[" + fa_name + "]]" + suf_b + ", " +
                   fc_name + "=[[" + fb_name + "]]" + suf_c + "\n";
    result.proof += "  Pattern: [[" + fc_name + "]]+\n";
    result.proof += "  Expanded: (" + expanded_c + ")+\n";
    result.proof += "  Rationale: Tests depth-limited recursive fragment expansion\n";
    return result;
}

static EdgeCaseResult createVariedLengthAlternationEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::VARIED_LENGTH_ALT;
    
    // Generate an alternation where alternatives have different lengths:
    // e.g., "a", "ab", "abc", "abcd"
    // Stresses the alternation merging and length-partitioning logic.
    
    // Pick a base character
    char base_char = 'a' + std::uniform_int_distribution<int>(0, 25)(rng);
    // Pick 3-5 alternatives of increasing length
    int num_alts = 3 + std::uniform_int_distribution<int>(0, 2)(rng);
    
    std::vector<std::string> alternatives;
    std::string current;
    for (int i = 0; i < num_alts; i++) {
        current += static_cast<char>('a' + std::uniform_int_distribution<int>(0, 25)(rng));
        alternatives.push_back(current);
    }
    
    // Ensure all alternatives are unique (they are by construction since each adds a char)
    
    result.matching_seeds = alternatives;
    
    // Generate counters: strings of the same lengths but different content
    for (int i = 0; i < num_alts; i++) {
        std::string counter;
        for (int j = 0; j <= i; j++) {
            char c;
            do {
                c = 'a' + std::uniform_int_distribution<int>(0, 25)(rng);
            } while (c == alternatives[i][j] && j == 0);  // at least first char differs
            counter += c;
        }
        // Ensure not accidentally equal to any matching seed
        bool is_match = false;
        for (const auto& m : result.matching_seeds) {
            if (counter == m) { is_match = true; break; }
        }
        if (!is_match) {
            result.counter_seeds.push_back(counter);
        }
    }
    
    // Add some more random counters
    for (int i = 0; i < 3; i++) {
        result.counter_seeds.push_back(randomAlphaEdge(
            1 + std::uniform_int_distribution<int>(0, num_alts)(rng), rng));
    }
    
    result.proof = "EDGE_CASE: VARIED_LENGTH_ALT\n";
    result.proof += "  Alternatives: ";
    for (size_t i = 0; i < alternatives.size(); i++) {
        if (i > 0) result.proof += "|";
        result.proof += alternatives[i];
    }
    result.proof += "\n";
    result.proof += "  Rationale: Tests alternation merging with different-length alternatives\n";
    return result;
}

static EdgeCaseResult createMismatchedCaptureEdge(std::mt19937& rng);

EdgeCaseResult generateEdgeCase(EdgeCaseType type, std::mt19937& rng) {
    switch (type) {
        case EdgeCaseType::RANGE_BOUNDARY:
            return createRangeBoundaryEdge(rng);
        case EdgeCaseType::PARTIAL_MATCH_FAIL:
            return createPartialMatchEdge(rng);
        case EdgeCaseType::QUANTIFIER_EDGE:
            return createQuantifierEdge(rng);
        case EdgeCaseType::ALTERNATION_EDGE:
            return createAlternationEdge(rng);
        case EdgeCaseType::NESTED_QUANTIFIER:
            return createNestedQuantifierEdge(rng);
        case EdgeCaseType::EMPTY_ALTERNATION:
            return createEmptyAlternationEdge(rng);
        case EdgeCaseType::DEEP_NESTING:
            return createDeepNestingEdge(rng);
        case EdgeCaseType::EMPTY_GROUP_QUANT:
            return createEmptyGroupQuantEdge(rng);
        case EdgeCaseType::LONG_ALTERNATION:
            return createLongAlternationEdge(rng);
        case EdgeCaseType::FRAGMENT_CYCLE:
            return createFragmentCycleEdge(rng);
        case EdgeCaseType::OVERLAPPING_ALTERNATION:
            return createOverlappingAlternationEdge(rng);
        case EdgeCaseType::FRAGMENT_CHAIN:
            return createFragmentChainEdge(rng);
        case EdgeCaseType::VARIED_LENGTH_ALT:
            return createVariedLengthAlternationEdge(rng);
        case EdgeCaseType::MISMATCHED_CAPTURE:
            return createMismatchedCaptureEdge(rng);
        default:
            return createPartialMatchEdge(rng);
    }
}

static EdgeCaseResult createMismatchedCaptureEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::MISMATCHED_CAPTURE;
    
    // Generate a pattern with malformed capture tags.
    // Tests error handling: the pipeline should reject these patterns or treat them
    // as non-matching since the tags are syntactically invalid.
    
    std::string inner = randomAlphaEdge(3, rng);
    std::string tag_name = "t" + std::to_string(std::uniform_int_distribution<int>(0, 99)(rng));
    std::string tag_name2 = "t" + std::to_string(std::uniform_int_distribution<int>(0, 99)(rng));
    while (tag_name2 == tag_name) tag_name2 = "t" + std::to_string(std::uniform_int_distribution<int>(0, 99)(rng));
    
    int variant = std::uniform_int_distribution<int>(0, 2)(rng);
    
    std::shared_ptr<PatternNode> ast;
    
    if (variant == 0) {
        // Opening tag with no closing tag: <tag>inner
        ast = PatternNode::createLiteral(inner);
        ast->capture_begin_only = tag_name;
        result.proof = "EDGE_CASE: MISMATCHED_CAPTURE (unmatched begin)\n";
        result.proof += "  Pattern: <" + tag_name + ">" + inner + "\n";
    } else if (variant == 1) {
        // Closing tag with no opening tag: inner</tag>
        ast = PatternNode::createLiteral(inner);
        ast->capture_end_only = tag_name;
        result.proof = "EDGE_CASE: MISMATCHED_CAPTURE (unmatched end)\n";
        result.proof += "  Pattern: " + inner + "</" + tag_name + ">\n";
    } else {
        // Mismatched tags: <a>inner</b>
        ast = PatternNode::createLiteral(inner);
        ast->capture_begin_only = tag_name;
        ast->capture_end_only = tag_name2;
        result.proof = "EDGE_CASE: MISMATCHED_CAPTURE (mismatched)\n";
        result.proof += "  Pattern: <" + tag_name + ">" + inner + "</" + tag_name2 + ">\n";
    }
    
    result.initial_ast = ast;
    
    // Since the tags are malformed, nothing should match through them.
    // All inputs become counters (the pattern should not accept any input).
    result.counter_seeds = {inner, inner + inner, randomAlphaEdge(4, rng), ""};
    result.matching_seeds = {};  // No inputs should match a malformed pattern
    
    result.proof += "  Rationale: Tests pipeline error handling for malformed capture tags\n";
    return result;
}