// ============================================================================
// Pattern Serializer - PatternNode to string conversion
// ============================================================================

#include "pattern_serializer.h"
#include "testgen.h"

#include <string>

static std::string escapeRegexSpecial(const std::string& s) {
    std::string result;
    for (char c : s) {
        switch (c) {
            case '*':
            case '+':
            case '?':
            case '{':
            case '}':
            case '[':
            case ']':
            case '^':
            case '$':
            case '.':
            case '\\':
                result += '\\';
                result += c;
                break;
            default:
                result += c;
        }
    }
    return result;
}

std::string serializePattern(std::shared_ptr<PatternNode> node) {
    if (!node) return "";

    std::string capture_prefix = node->capture_tag.empty() ? "" : "<" + node->capture_tag + ">";
    std::string capture_suffix = node->capture_tag.empty() ? "" : "</" + node->capture_tag + ">";
    std::string begin_only = node->capture_begin_only.empty() ? "" : "<" + node->capture_begin_only + ">";
    std::string end_only = node->capture_end_only.empty() ? "" : "</" + node->capture_end_only + ">";

    switch (node->type) {
        case PatternType::LITERAL:
            return begin_only + capture_prefix + escapeRegexSpecial(node->value) + capture_suffix + end_only;

        case PatternType::OPTIONAL:
            if (node->quantified) {
                return "(" + serializePattern(node->quantified) + ")?";
            }
            return "(.)?";

        case PatternType::PLUS_QUANTIFIER:
            if (node->quantified) {
                return begin_only + capture_prefix + "(" + serializePattern(node->quantified) + ")+" + capture_suffix + end_only;
            }
            return "(.)+";

        case PatternType::STAR_QUANTIFIER:
            if (node->quantified) {
                return begin_only + capture_prefix + "(" + serializePattern(node->quantified) + ")*" + capture_suffix + end_only;
            }
            return "(.)*";

        case PatternType::ALTERNATION: {
            if (node->quantified) {
                std::string inner = "(";
                for (size_t i = 0; i < node->children.size(); i++) {
                    if (i > 0) inner += "|";
                    inner += serializePattern(node->children[i]);
                }
                inner += ")";

                PatternType actual_type = node->type;

                if (actual_type == PatternType::PLUS_QUANTIFIER) {
                    return begin_only + capture_prefix + inner + "+" + capture_suffix + end_only;
                } else if (actual_type == PatternType::STAR_QUANTIFIER) {
                    return begin_only + capture_prefix + inner + "*" + capture_suffix + end_only;
                } else if (actual_type == PatternType::OPTIONAL) {
                    return begin_only + capture_prefix + inner + "?" + capture_suffix + end_only;
                }
            }

            std::string result = "(";
            for (size_t i = 0; i < node->children.size(); i++) {
                if (i > 0) result += "|";
                result += serializePattern(node->children[i]);
            }
            result += ")";
            return result;
        }

        case PatternType::SEQUENCE: {
            std::string result;
            for (const auto& child : node->children) {
                result += serializePattern(child);
            }
            return result;
        }

        case PatternType::FRAGMENT_REF:
            if (node->fragment_name.find("fNag") != std::string::npos) {
                fprintf(stderr, "DEBUG SERIAL: FRAGMENT_REF node->fragment_name='%s'\n", node->fragment_name.c_str());
            }
            return "((" + node->fragment_name + "))+";

        default:
            return node->value;
    }
}