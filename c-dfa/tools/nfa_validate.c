/**
 * nfa_validate.c - Pattern file validation
 *
 * Performs syntax validation on pattern files before NFA construction.
 * Checks for malformed fragments, unbalanced parentheses, and other issues.
 */

#include "nfa_builder.h"
#include "../include/dfa_errors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

bool nfa_validate_pattern_file(nfa_builder_context_t* ctx, const char* spec_file, bool verbose) {
    if (verbose) {
        fprintf(stderr, "\n=== Validation Phase ===\n");
        fprintf(stderr, "Validating: %s\n", spec_file);
    }

    FILE* file = fopen(spec_file, "r");
    if (!file) {
        ERROR("Cannot open spec file '%s'", spec_file);
        return false;
    }

    char line[MAX_LINE_LENGTH];
    int line_num = 0;
    int errors = 0;
    int patterns_seen = 0;

    while (fgets(line, sizeof(line), file)) {
        line_num++;

        if (line[0] == '\0' || line[0] == '\n' || line[0] == '\r' || line[0] == '#') {
            continue;
        }

        line[strcspn(line, "\r\n")] = 0;

        // Check for fragment definition [fragment:name] value
        if (strncmp(line, "[fragment:", 10) == 0) {
            char* name_start = line + 10;
            char* bracket = strchr(name_start, ']');
            if (!bracket) {
                ERROR("Malformed fragment definition at line %d: %s", line_num, line);
                errors++;
                continue;
            }

            size_t name_len = bracket - name_start;
            char frag_name[64];
            if (name_len >= sizeof(frag_name)) {
                ERROR("Fragment name too long at line %d", line_num);
                errors++;
                continue;
            }
            strncpy(frag_name, name_start, name_len);
            frag_name[name_len] = '\0';

            const char* value_start = bracket + 1;
            while (*value_start == ' ' || *value_start == '\t') value_start++;
            if (*value_start == '\0' || *value_start == '\n' || *value_start == '#') {
                ERROR("Fragment '%s' has empty value at line %d", frag_name, line_num);
                errors++;
                continue;
            }

            if (verbose) {
                fprintf(stderr, "  Line %d: Fragment '%s' = '%s'\n", line_num, frag_name, value_start);
            }
            continue;
        }

        // Check for character set definition
        if (strncmp(line, "[characterset:", 15) == 0) {
            if (verbose) {
                fprintf(stderr, "  Line %d: Character set definition\n", line_num);
            }
            continue;
        }

        // Check for [CATEGORIES] section
        if (strcmp(line, "[CATEGORIES]") == 0) {
            if (verbose) {
                fprintf(stderr, "  Line %d: Categories section\n", line_num);
            }
            continue;
        }

        // Check for category definition line (N: name format)
        if (line[0] >= '0' && line[0] <= '7' && line[1] == ':') {
            if (verbose) {
                fprintf(stderr, "  Line %d: Category definition: %s\n", line_num, line);
            }
            const char* name_start = line + 2;
            while (*name_start == ' ' || *name_start == '\t') name_start++;
            if (*name_start != '\0') {
                for (const char* p = name_start; *p && *p != ' ' && *p != '\t' && *p != '#'; p++) {
                    if (!isalnum(*p) && *p != '_' && *p != '-') {
                        ERROR("Invalid character in category name at line %d: %s", line_num, line);
                        errors++;
                        break;
                    }
                }
            }
            continue;
        }

        // Check for ACCEPTANCE_MAPPING directive
        if (strncmp(line, "ACCEPTANCE_MAPPING", 18) == 0) {
            if (verbose) {
                fprintf(stderr, "  Line %d: Acceptance mapping\n", line_num);
            }
            continue;
        }

        // Check for IDENTIFIER directive
        if (strncmp(line, "IDENTIFIER", 10) == 0 && (line[10] == ' ' || line[10] == '"')) {
            char* id_start = line + 11;
            while (*id_start == ' ' || *id_start == '\t') id_start++;

            if (*id_start != '"') {
                ERROR("IDENTIFIER must be a quoted string at line %d", line_num);
                errors++;
                continue;
            }
            id_start++;

            char* id_end = strchr(id_start, '"');
            if (!id_end) {
                ERROR("Unclosed IDENTIFIER string at line %d", line_num);
                errors++;
                continue;
            }

            size_t id_len = id_end - id_start;
            if (id_len >= sizeof(ctx->pattern_identifier)) {
                ERROR("IDENTIFIER too long at line %d", line_num);
                errors++;
                continue;
            }

            strncpy(ctx->pattern_identifier, id_start, id_len);
            ctx->pattern_identifier[id_len] = '\0';

            if (verbose) {
                fprintf(stderr, "  Line %d: Identifier = \"%s\"\n", line_num, ctx->pattern_identifier);
            }
            continue;
        }

        // Check for category pattern [category:subcategory:operations] pattern
        if (line[0] == '[') {
            char* bracket = strchr(line, ']');
            if (!bracket) {
                ERROR("Malformed pattern at line %d: %s", line_num, line);
                errors++;
                continue;
            }

            char* pattern_start = bracket + 1;
            while (*pattern_start == ' ' || *pattern_start == '\t') pattern_start++;

            if (*pattern_start == '\0' || *pattern_start == '\n' || *pattern_start == '\r') {
                continue;
            }

            // Basic validation - count parentheses
            int open_parens = 0, close_parens = 0;
            bool in_escape = false;
            bool in_quote = false;
            for (char* p = pattern_start; *p; p++) {
                if (in_escape) { in_escape = false; continue; }
                if (*p == '\\') { in_escape = true; continue; }
                if (*p == '"') { in_quote = !in_quote; continue; }
                // Skip quoted content for parenthesis counting only
                if (in_quote) continue;
                if (*p == '(') open_parens++;
                else if (*p == ')') close_parens++;
            }

            // Quantifier check - always applies (even inside quotes)
            // Quotes do NOT protect quantifiers - use \* for literal asterisk
            for (char* p = pattern_start; *p; p++) {
                if (*(p - 1) == '\\' && p > pattern_start) continue;  // escaped
                if (*p == '*' || *p == '+' || *p == '?') {
                    char* q = p - 1;
                    while (q >= pattern_start && (*q == ' ' || *q == '\t')) q--;
                    if (q < pattern_start || *q != ')') {
                        ERROR("'%c' quantifier must follow ')' at line %d - use \\%c for literal", *p, line_num, *p);
                        errors++;
                    }
                }
            }

            if (open_parens != close_parens) {
                ERROR("Unmatched parentheses at line %d: %s", line_num, line);
                errors++;
            }

            if (*pattern_start != '\0' &&
                strchr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789*?[]()-+.:\\<", *pattern_start) == NULL) {
                ERROR("Invalid pattern start at line %d: %s", line_num, line);
                errors++;
            }

            patterns_seen++;
            continue;
        }
    }

    fclose(file);

    if (verbose) {
        fprintf(stderr, "  Total patterns found: %d\n", patterns_seen);
        fprintf(stderr, "  Validation errors: %d\n", errors);
    }

    if (errors > 0) {
        fprintf(stderr, "\nValidation FAILED: %d error(s) found\n", errors);
        return false;
    }

    if (patterns_seen == 0) {
        fprintf(stderr, "\nWarning: No patterns found in spec file\n");
    }

    if (verbose) {
        fprintf(stderr, "\nValidation PASSED: No errors found\n");
    }

    return true;
}

bool nfa_validate_pattern_input(const char* line, size_t len) {
    if (line == NULL || len == 0) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        if (line[i] == '\0') {
            return false;
        }
    }

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)line[i];
        if (c == 0xFF) {
            return false;
        }
    }

    if (len == 1) {
        char c = line[0];
        if (c == '$' || c == '*' || c == '[' || c == ']' || c == '+' || c == '?') {
            return false;
        }
    }

    int bracket_depth = 0;
    int paren_depth = 0;
    for (size_t i = 0; i < len; i++) {
        // Skip escaped characters
        if (line[i] == '\\' && i + 1 < len) {
            i++;  // skip next char
            continue;
        }
        if (line[i] == '[') bracket_depth++;
        if (line[i] == ']') bracket_depth--;
        if (line[i] == '(') paren_depth++;
        if (line[i] == ')') paren_depth--;
        if (bracket_depth < 0 || paren_depth < 0) {
            return false;
        }

        // Quantifiers (*, +, ?) must follow ')'
        if (line[i] == '*' || line[i] == '+' || line[i] == '?') {
            // Scan backward for previous non-whitespace char
            int p = (int)i - 1;
            while (p >= 0 && (line[p] == ' ' || line[p] == '\t')) p--;
            if (p < 0 || line[p] != ')') {
                return false;
            }
        }
    }

    if (bracket_depth != 0 || paren_depth != 0) {
        return false;
    }

    return true;
}
