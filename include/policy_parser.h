/**
 * @file policy_parser.h
 * @brief Text-based policy file parser and serializer for the Rule Engine.
 */

#ifndef POLICY_PARSER_H
#define POLICY_PARSER_H

#include "rule_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Parse a policy ruleset from a text buffer.
 *
 * Supports layered rules, macro definitions, and comments.
 * Lines beginning with '#' are comments.
 *
 * Macro definition syntax:
 *   [IDENTIFIER] /path/pattern
 *
 * Layer declaration syntax:
 *   @N PRECEDENCE
 *   @N SPECIFICITY[:MASK]
 *
 * Rule syntax:
 *   [@N] PATTERN -> MODE [OP] [subject:REGEX] [recursive]
 *
 * @param rs           Target ruleset (must be allocated).
 * @param text         Input text buffer.
 * @param line_number  Output: line number of first error (NULL to ignore).
 * @param error_msg    Output: error message string (NULL to ignore).
 *                     Message is static, do not free.
 * @return 0 on success, -1 on parse error.
 */
int soft_ruleset_parse_text(soft_ruleset_t *rs, const char *text,
                            int *line_number, const char **error_msg);

/**
 * Parse a policy ruleset from a file.
 *
 * @param rs           Target ruleset (must be allocated).
 * @param path         Input file path.
 * @param line_number  Output: line number of first error (NULL to ignore).
 * @param error_msg    Output: error message string (NULL to ignore).
 * @return 0 on success, -1 on parse error.
 */
int soft_ruleset_parse_file(soft_ruleset_t *rs, const char *path,
                            int *line_number, const char **error_msg);

/**
 * Serialize a ruleset to a text buffer.
 *
 * Layer declarations are emitted before rules belonging to that layer.
 * If the ruleset has no layers (flat), rules are written without prefixes.
 *
 * The caller must free the returned string.
 *
 * @param rs       Source ruleset.
 * @param out_text Output: allocated string containing policy text.
 * @return 0 on success, -1 on allocation error.
 */
int soft_ruleset_write_text(const soft_ruleset_t *rs, char **out_text);

/**
 * Write a ruleset to a policy file.
 *
 * @param rs   Source ruleset.
 * @param path Output file path.
 * @return 0 on success, -1 on error.
 */
int soft_ruleset_write_file(const soft_ruleset_t *rs, const char *path);

#ifdef __cplusplus
}
#endif

#endif /* POLICY_PARSER_H */
