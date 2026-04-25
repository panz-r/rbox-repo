/**
 * nfa_parser.c - Recursive descent pattern parser
 *
 * Implements the recursive descent parser for command patterns,
 * pattern file reading, and NFA construction from patterns.
 */

#define _DEFAULT_SOURCE
#include "nfa_builder.h"
#include "../include/dfa_errors.h"
#include "../include/cdfa_defines.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../include/compat_strl.h"
#include <stdarg.h>

// ============================================================================
// Debug/Verbose helpers (use context flags instead of globals)
// ============================================================================

#define VP(ctx, ...) do { if ((ctx)->flag_verbose) fprintf(stderr, __VA_ARGS__); } while (0)
#define DNP(ctx, ...) do { if ((ctx)->flag_verbose_nfa) fprintf(stderr, __VA_ARGS__); } while (0)

// ============================================================================
// Fragment utilities
// ============================================================================

static const char* find_fragment(nfa_builder_context_t* ctx, const char* name) {
    for (int i = 0; i < ctx->fragment_count; i++) {
        if (strcmp(ctx->fragments[i].name, name) == 0) {
            return ctx->fragments[i].value;
        }
    }
    return NULL;
}

static void normalize_fragment_name(char* name) {
    if (strstr(name, "::") != NULL) {
        return;
    }
    for (int i = 0; name[i] != '\0'; i++) {
        if (name[i] == ':' && name[i + 1] != ':') {
            int len = strlen(name);
            if (len + 1 < MAX_FRAGMENT_NAME) {
                for (int k = len; k > i; k--) {
                    name[k] = name[k - 1];
                }
                name[i] = ':';
                name[i + 1] = ':';
            }
            break;
        }
    }
}

// ============================================================================
// Pattern state management
// ============================================================================

static void reset_pattern_state(nfa_builder_context_t* ctx) {
    ctx->pending_marker_count = 0;
    ctx->capture_stack_depth = 0;
    ctx->pending_capture_defer_id = -1;
    ctx->last_element_sid = -1;
    ctx->prev_frag_exit = -1;
    nfa_parser_clear_error(ctx);
}

// ============================================================================
// Error handling
// ============================================================================

void nfa_parser_set_error(nfa_builder_context_t* ctx, parse_error_type_t type,
                          int position, const char* fmt, ...) {
    ctx->last_error.has_error = true;
    ctx->last_error.type = type;
    ctx->last_error.position = position;
    
    va_list args;
    va_start(args, fmt);
    vsnprintf(ctx->last_error.message, sizeof(ctx->last_error.message), fmt, args);
    va_end(args);
    
    ERROR("%s", ctx->last_error.message);
}

void nfa_parser_clear_error(nfa_builder_context_t* ctx) {
    ctx->last_error.has_error = false;
    ctx->last_error.type = PARSE_ERROR_NONE;
    ctx->last_error.position = -1;
    ctx->last_error.message[0] = '\0';
}

bool nfa_parser_has_error(const nfa_builder_context_t* ctx) {
    return ctx->last_error.has_error;
}

const parse_error_info_t* nfa_parser_get_error(const nfa_builder_context_t* ctx) {
    return &ctx->last_error;
}

// ============================================================================
// Forward declarations for RDP functions
// ============================================================================

static int parse_rdp_element(nfa_builder_context_t* ctx, const char* pattern, int* pos, int start_state);
static int parse_rdp_class(nfa_builder_context_t* ctx, const char* pattern, int* pos, int start_state);
static fragment_result_t parse_rdp_fragment(nfa_builder_context_t* ctx, const char* pattern, int* pos, int start_state);
static int parse_rdp_postfix(nfa_builder_context_t* ctx, const char* pattern, int* pos, int start_state);
static int parse_rdp_sequence(nfa_builder_context_t* ctx, const char* pattern, int* pos, int start_state);
static int parse_rdp_alternation_internal(nfa_builder_context_t* ctx, const char* pattern, int* pos, int start_state);

// ============================================================================
// RDP: Fragment reference parser
// ============================================================================

static fragment_result_t parse_rdp_fragment(nfa_builder_context_t* ctx, const char* pattern, int* pos, int start_state) {
    fragment_result_t result = {
        .anchor_state = -1,
        .loop_entry_state = -1,
        .exit_state = -1,
        .is_single_char = false,
        .loop_char = '\0',
        .capture_defer_id = -1,
        .has_capture = false,
        .capture_name = {0},
        .fragment_entry_state = 0,
        .loop_first_char = '\0'
    };

    if (pattern[*pos] != '[' || pattern[*pos + 1] != '[') {
        result.exit_state = start_state;
        return result;
    }

    if (ctx->fragment_depth >= MAX_FRAGMENT_DEPTH) {
        WARNING("Maximum fragment nesting depth (%d) exceeded", MAX_FRAGMENT_DEPTH);
        result.exit_state = start_state;
        return result;
    }

    size_t j = *pos + 2;
    
    // Find the closing ]] for this fragment
    // For [[f]]|[[g]], stop at the first ]] (before the |)
    // For [[f]], stop at the ]]
    while (pattern[j] != '\0') {
        if (pattern[j] == ']' && pattern[j + 1] == ']') {
            // Check if this ]] is the end of this fragment
            // It's the end if NOT followed by alternation pattern ]]
            bool is_alternation = (pattern[j + 2] == ']' && pattern[j + 3] == '[');
            if (!is_alternation) {
                // This is the closing ]] of this fragment
                break;
            }
            // This ]] is followed by alternation, continue scanning
        }
        j++;
    }

    if (pattern[j] != ']' || pattern[j + 1] != ']') {
        WARNING("Malformed fragment reference at position %d", *pos);
        result.exit_state = start_state;
        return result;
    }

    char frag_name[MAX_FRAGMENT_NAME];
    size_t name_len = j - (*pos + 2);
    if (name_len >= sizeof(frag_name)) {
        WARNING("Fragment name too long at position %d", *pos);
        *pos = j + 2;
        result.exit_state = start_state;
        return result;
    }

    strncpy(frag_name, &pattern[*pos + 2], name_len);
    frag_name[name_len] = '\0';
    normalize_fragment_name(frag_name);

    const char* frag_value = find_fragment(ctx, frag_name);
    if (frag_value == NULL) {
        nfa_parser_set_error(ctx, PARSE_ERROR_UNDEFINED_FRAGMENT, *pos, "Fragment '%s' not found", frag_name);
        *pos = j + 2;
        result.exit_state = -1;
        return result;
    }

    bool is_single_char = (frag_value[0] != '\0' && frag_value[1] == '\0');

    int frag_pos = 0;
    bool saved_parsing_fragment = ctx->parsing_fragment_value;
    ctx->parsing_fragment_value = true;

    ctx->fragment_depth++;
    int frag_end = parse_rdp_alternation_internal(ctx, frag_value, &frag_pos, start_state);
    ctx->fragment_depth--;

    ctx->parsing_fragment_value = saved_parsing_fragment;

    result.anchor_state = start_state;
    result.exit_state = frag_end;

    if (is_single_char) {
        result.is_single_char = true;
        result.loop_char = frag_value[0];
        result.loop_entry_state = start_state;
    } else {
        result.is_single_char = false;
        result.loop_char = '\0';
        result.loop_entry_state = start_state;
        result.fragment_entry_state = start_state;
        result.loop_first_char = frag_value[0];
    }

    *pos = j + 2;
    return result;
}

// ============================================================================
// RDP: Character class (not supported - returns error)
// ============================================================================

static int parse_rdp_class(ATTR_UNUSED nfa_builder_context_t* ctx, ATTR_UNUSED const char* pattern, ATTR_UNUSED int* pos, ATTR_UNUSED int start_state) {
    ERROR("Character class syntax [abc] is not supported");
    ERROR("  Use (a|b|c) for alternatives, escape '\\[' for literal bracket");
    return -1;
}

// ============================================================================
// RDP: Element parser (char, escaped, quoted, class, group, capture, fragment)
// ============================================================================

static int parse_rdp_element(nfa_builder_context_t* ctx, const char* pattern, int* pos, int start_state) {
    if (pattern == NULL || *pos < 0 || (size_t)*pos >= strlen(pattern)) {
        nfa_parser_set_error(ctx, PARSE_ERROR_SYNTAX, *pos, "Unexpected end of pattern at position %d", *pos);
        return -1;
    }

    char c = pattern[*pos];

    // Check for capture start tag <name>
    char cap_name[MAX_CAPTURE_NAME];
    if (nfa_capture_is_start(pattern, *pos, cap_name)) {
        return nfa_capture_parse_start(ctx, pattern, pos, start_state);
    }

    // Check for capture end tag </name>
    if (nfa_capture_is_end(pattern, *pos, cap_name)) {
        return nfa_capture_parse_end(ctx, pattern, pos, start_state);
    }

    switch (c) {
        case '\\': {
            // Escaped character
            if (pattern[*pos + 1] != '\0') {
                char ec = pattern[*pos + 1];

                // Hex escape \xHH
                if (ec == 'x' && pattern[*pos + 2] != '\0' && pattern[*pos + 3] != '\0') {
                    char hex[3] = {pattern[*pos + 2], pattern[*pos + 3], 0};
                    int hex_val = (int)strtol(hex, NULL, 16);
                    if (hex_val > 0 && hex_val < 256) {
                        int sid = nfa_alphabet_find_symbol_id((unsigned char)hex_val);
                        if (sid != -1) {
                            int anchor = start_state;
                            if (anchor == 0) {
                                anchor = nfa_construct_add_state_with_minimization(ctx, false);
                                nfa_construct_add_transition(ctx, 0, anchor, VSYM_EPS);
                            }
                            int new_state = nfa_construct_add_state_with_minimization(ctx, false);
                            nfa_construct_add_transition(ctx, anchor, new_state, sid);
                            int finalized = nfa_construct_finalize_state(ctx, new_state);

                            memset(&ctx->current_fragment, 0, sizeof(ctx->current_fragment));
                            ctx->current_fragment.anchor_state = anchor;
                            ctx->current_fragment.is_single_char = true;
                            ctx->current_fragment.loop_char = (char)hex_val;
                            ctx->current_fragment.loop_entry_state = finalized;
                            ctx->current_fragment.exit_state = finalized;
                            ctx->current_is_char_class = false;
                            *pos += 4;
                            return finalized;
                        }
                    }
                }

                int sid = nfa_alphabet_find_symbol_id((unsigned char)ec);
                if (sid != -1) {
                    int anchor = start_state;
                    if (anchor == 0) {
                        anchor = nfa_construct_add_state_with_minimization(ctx, false);
                        nfa_construct_add_transition(ctx, 0, anchor, VSYM_EPS);
                    }
                    int new_state = nfa_construct_add_state_with_minimization(ctx, false);
                    nfa_construct_add_transition(ctx, anchor, new_state, sid);
                    int finalized = nfa_construct_finalize_state(ctx, new_state);

                    memset(&ctx->current_fragment, 0, sizeof(ctx->current_fragment));
                    ctx->current_fragment.anchor_state = anchor;
                    ctx->current_fragment.is_single_char = true;
                    ctx->current_fragment.loop_char = ec;
                    ctx->current_fragment.loop_entry_state = finalized;
                    ctx->current_fragment.exit_state = finalized;
                    ctx->current_is_char_class = false;
                    *pos += 2;
                    return finalized;
                }
                *pos += 2;
            } else {
                (*pos)++;
            }
            break;
        }

        case '\'': {
            // Quoted character
            (*pos)++;
            if (pattern[*pos] != '\0' && pattern[*pos] != '\'') {
                char qc = pattern[*pos];
                int sid = nfa_alphabet_find_symbol_id((unsigned char)qc);
                if (sid != -1) {
                    int anchor = start_state;
                    if (anchor == 0) {
                        anchor = nfa_construct_add_state_with_minimization(ctx, false);
                        nfa_construct_add_transition(ctx, 0, anchor, VSYM_EPS);
                    }
                    int new_state = nfa_construct_add_state_with_minimization(ctx, false);
                    nfa_construct_add_transition(ctx, anchor, new_state, sid);
                    int finalized = nfa_construct_finalize_state(ctx, new_state);

                    memset(&ctx->current_fragment, 0, sizeof(ctx->current_fragment));
                    ctx->current_fragment.anchor_state = anchor;
                    ctx->current_fragment.is_single_char = true;
                    ctx->current_fragment.loop_char = qc;
                    ctx->current_fragment.loop_entry_state = finalized;
                    ctx->current_fragment.exit_state = finalized;
                    ctx->current_is_char_class = false;
                    (*pos)++;
                    return finalized;
                }
                (*pos)++;
            } else if (pattern[*pos] == '\'') {
                (*pos)++;
            }
            break;
        }

        case '[': {
            // Check for fragment reference [[name]]
            if (pattern[*pos + 1] == '[') {
                size_t j = *pos + 2;
                while (pattern[j] != '\0' && !(pattern[j] == ']' && pattern[j + 1] == ']')) {
                    j++;
                }
                if (pattern[j] == ']' && pattern[j + 1] == ']') {
                    char frag_name[MAX_FRAGMENT_NAME];
                    size_t name_len = j - (*pos + 2);
                    if (name_len > 0 && name_len < sizeof(frag_name)) {
                        strncpy(frag_name, &pattern[*pos + 2], name_len);
                        frag_name[name_len] = '\0';
                        normalize_fragment_name(frag_name);
                        const char* frag_value = find_fragment(ctx, frag_name);
                        if (frag_value != NULL) {
                            fragment_result_t frag_result = parse_rdp_fragment(ctx, pattern, pos, start_state);
                            ctx->current_fragment = frag_result;

                            if (ctx->prev_frag_exit >= 0) {
                                int epsilon_sid = VSYM_EPS;
                                if (epsilon_sid != -1) {
                                    nfa_construct_add_transition(ctx, ctx->prev_frag_exit, frag_result.anchor_state, epsilon_sid);
                                }
                            }

                            ctx->prev_frag_exit = frag_result.exit_state;
                            return frag_result.exit_state;
                        }
                        int word_chars = 0;
                        for (int ci = 0; frag_name[ci] != '\0'; ci++) {
                            if (isalnum((unsigned char)frag_name[ci]) || frag_name[ci] == '_') {
                                word_chars++;
                            }
                        }
                        if (word_chars > (int)name_len / 3) {
                            nfa_parser_set_error(ctx, PARSE_ERROR_UNDEFINED_FRAGMENT, *pos, "Fragment '%s' not found", frag_name);
                            return -1;
                        }
                    }
                }
                // Not a valid fragment reference, fall through to bracket handling
            }
            int result = parse_rdp_class(ctx, pattern, pos, start_state);
            if (result < 0) {
                return start_state;
            }
            return result;
        }

        case '(': {
            // Check for (*) explicit wildcard syntax
            if (pattern[*pos + 1] == '*' && pattern[*pos + 2] == ')') {
                int any_sid = VSYM_BYTE_ANY;
                int anchor = start_state;
                if (anchor == 0) {
                    anchor = nfa_construct_add_state_with_minimization(ctx, false);
                    nfa_construct_add_transition(ctx, 0, anchor, VSYM_EPS);
                }

                int star_state = nfa_construct_add_state_with_minimization(ctx, false);
                nfa_construct_add_transition(ctx, anchor, star_state, VSYM_EPS);
                nfa_construct_add_transition(ctx, anchor, star_state, any_sid);
                nfa_construct_add_transition(ctx, star_state, star_state, any_sid);
                int finalized_star = nfa_construct_finalize_state(ctx, star_state);

                memset(&ctx->current_fragment, 0, sizeof(ctx->current_fragment));
                ctx->current_fragment.anchor_state = anchor;
                ctx->current_fragment.is_single_char = false;
                ctx->current_fragment.exit_state = finalized_star;

                *pos += 3;
                return finalized_star;
            }

            // Check for fragment reference [[name::subname]]
            // Note: double parentheses ((...)) are allowed for nested grouping.
            // Fragment references use [[name]] syntax which is checked below.
            if (pattern[*pos + 1] == '[') {
                size_t j = *pos + 2;
                while (pattern[j] != '\0' && !(pattern[j] == ']' && pattern[j + 1] == ']')) {
                    j++;
                }
                if (pattern[j] == ']' && pattern[j + 1] == ']') {
                    char frag_name[MAX_FRAGMENT_NAME];
                    size_t name_len = j - (*pos + 2);
                    if (name_len > 0 && name_len < sizeof(frag_name)) {
                        strncpy(frag_name, &pattern[*pos + 2], name_len);
                        frag_name[name_len] = '\0';
                        normalize_fragment_name(frag_name);
                        const char* frag_value = find_fragment(ctx, frag_name);
                        if (frag_value != NULL) {
                            fragment_result_t frag_result = parse_rdp_fragment(ctx, pattern, pos, start_state);
                            ctx->current_fragment = frag_result;

                            if (ctx->prev_frag_exit >= 0) {
                                int epsilon_sid = VSYM_EPS;
                                if (epsilon_sid != -1) {
                                    nfa_construct_add_transition(ctx, ctx->prev_frag_exit, frag_result.anchor_state, epsilon_sid);
                                }
                            }

                            ctx->prev_frag_exit = frag_result.exit_state;
                            return frag_result.exit_state;
                        }
                        int word_chars = 0;
                        for (int ci = 0; frag_name[ci] != '\0'; ci++) {
                            if (isalnum((unsigned char)frag_name[ci]) || frag_name[ci] == '_') {
                                word_chars++;
                            }
                        }
                        if (word_chars > (int)name_len / 3) {
                            nfa_parser_set_error(ctx, PARSE_ERROR_UNDEFINED_FRAGMENT, *pos, "Fragment '%s' not found", frag_name);
                            return -1;
                        }
                    }
                }
                // Not a valid fragment reference, treat as nested group
            }
            // Regular grouping
            (*pos)++;
            return parse_rdp_alternation_internal(ctx, pattern, pos, start_state);
        }

        default: {
            if (c == '*') {
                int any_sid = VSYM_BYTE_ANY;
                int anchor = start_state;
                if (anchor == 0) {
                    anchor = nfa_construct_add_state_with_minimization(ctx, false);
                    nfa_construct_add_transition(ctx, 0, anchor, VSYM_EPS);
                }

                int star_state = nfa_construct_add_state_with_minimization(ctx, false);
                nfa_construct_add_transition(ctx, anchor, star_state, any_sid);
                nfa_construct_add_transition(ctx, star_state, star_state, any_sid);
                int finalized_star = nfa_construct_finalize_state(ctx, star_state);
                (*pos)++;

                memset(&ctx->current_fragment, 0, sizeof(ctx->current_fragment));
                ctx->current_fragment.anchor_state = anchor;
                ctx->current_fragment.is_single_char = false;
                ctx->current_fragment.exit_state = finalized_star;

                return finalized_star;
            }

            if (c == ' ' || c == '\t') {
                // Space normalizes to [ \t]+ (one or more whitespace)
                int space_sid = VSYM_SPACE;
                int tab_sid = VSYM_TAB;
                int sid = (c == ' ') ? space_sid : tab_sid;
                if (sid != -1) {
                    int anchor = start_state;
                    if (anchor == 0) {
                        anchor = nfa_construct_add_state_with_minimization(ctx, false);
                        nfa_construct_add_transition(ctx, 0, anchor, VSYM_EPS);
                    }

                    int loop_state = nfa_construct_add_state_with_minimization(ctx, false);
                    int exit_state = nfa_construct_add_state_with_minimization(ctx, false);

                    nfa_construct_add_transition(ctx, loop_state, loop_state, space_sid);
                    nfa_construct_add_transition(ctx, loop_state, loop_state, tab_sid);
                    nfa_construct_add_transition(ctx, anchor, loop_state, space_sid);
                    nfa_construct_add_transition(ctx, anchor, loop_state, tab_sid);
                    nfa_construct_add_transition(ctx, loop_state, exit_state, VSYM_EPS);

                    nfa_construct_finalize_state(ctx, exit_state);
                    memset(&ctx->current_fragment, 0, sizeof(ctx->current_fragment));
                    ctx->current_fragment.anchor_state = anchor;
                    ctx->current_fragment.is_single_char = true;
                    ctx->current_fragment.loop_char = c;
                    ctx->current_fragment.loop_entry_state = loop_state;
                    ctx->current_fragment.exit_state = exit_state;
                    ctx->current_is_char_class = false;
                    (*pos)++;
                    return exit_state;
                }
                (*pos)++;
                break;
            }

            if (c != '\0') {
                if (c == '*' || c == '+' || c == '?') {
                    return start_state;
                }
                int sid = nfa_alphabet_find_symbol_id((unsigned char)c);
                if (sid != -1) {
                    int anchor = start_state;
                    if (anchor == 0) {
                        anchor = 0;  // Use state 0 directly as anchor for root
                    } else {
                        anchor = nfa_construct_add_state_with_minimization(ctx, false);
                        nfa_construct_add_transition(ctx, start_state, anchor, VSYM_EPS);
                    }

                    int new_state = nfa_construct_add_state_with_minimization(ctx, false);
                    nfa_construct_add_transition(ctx, anchor, new_state, sid);
                    int finalized = nfa_construct_finalize_state(ctx, new_state);
                    memset(&ctx->current_fragment, 0, sizeof(ctx->current_fragment));
                    ctx->current_fragment.anchor_state = anchor;
                    ctx->current_fragment.is_single_char = true;
                    ctx->current_fragment.loop_char = c;
                    ctx->current_fragment.loop_entry_state = anchor;
                    ctx->current_fragment.exit_state = finalized;
                    ctx->current_is_char_class = false;
                    (*pos)++;
                    return finalized;
                }
            }
            (*pos)++;
            break;
        }
    }

    return start_state;
}

// ============================================================================
// RDP: Postfix quantifier handler (* + ?)
// ============================================================================

// Check if a quantifier at the given position is valid.
// Quantifiers (*, +, ?) must follow a closing parenthesis ')' or ']' (fragment reference]).
// This prevents the common misunderstanding that * is a wildcard.
static bool quantifier_is_valid(const char* pattern, int quant_pos, ATTR_UNUSED nfa_builder_context_t* ctx) {
    int quotes = 0;
    bool in_esc = false;
    for (int i = 0; i < quant_pos; i++) {
        if (in_esc) { in_esc = false; continue; }
        if (pattern[i] == '\\') { in_esc = true; continue; }
        if (pattern[i] == '"') quotes++;
    }
    if (quotes % 2 == 1) return false;  // Inside quotes - treat as literal, reject as quantifier

    int p = quant_pos - 1;
    while (p >= 0) {
        if (pattern[p] == '\\' && p > 0) {
            p -= 2;  // Skip backslash and escaped character
            continue;
        }
        if (pattern[p] == ' ' || pattern[p] == '\t') {
            p--;
            continue;
        }
        break;
    }
    if (p < 0) return false;
    return pattern[p] == ')' || pattern[p] == ']';
}

static int parse_rdp_postfix(nfa_builder_context_t* ctx, const char* pattern, int* pos, int start_state) {
    int current;
    bool current_fragment_valid = (ctx->current_fragment.exit_state >= 0 && ctx->has_pending_quantifier);
    if (current_fragment_valid) {
        current = ctx->current_fragment.exit_state;
    } else if (!ctx->has_pending_quantifier && ctx->current_fragment.exit_state != -1) {
        current = ctx->current_fragment.exit_state;
    } else {
        current = parse_rdp_element(ctx, pattern, pos, start_state);
        if (current < 0) return -1;
    }

    while (pattern[*pos] != '\0') {
        char op = pattern[*pos];
        int epsilon_sid = VSYM_EPS;
        if (epsilon_sid == -1) break;

        if (op == '*') {
            if (*pos > 0 && pattern[*pos - 1] == '(') {
                break;
            }
            if (!quantifier_is_valid(pattern, *pos, ctx)) {
                nfa_parser_set_error(ctx, PARSE_ERROR_QUANTIFIER_POSITION, *pos,
                    "'*' quantifier must follow ')' - use (expr)* for zero-or-more");
                return -1;
            }
            (*pos)++;

            int exit_state = nfa_construct_add_state_with_minimization(ctx, false);
            int element_entry = ctx->current_fragment.anchor_state;
            if (element_entry < 0) element_entry = start_state;

            int skip_origin = element_entry;
            nfa_construct_add_transition(ctx, skip_origin, exit_state, epsilon_sid);

            if (ctx->current_fragment.exit_state != -1) {
                nfa_construct_add_transition(ctx, ctx->current_fragment.exit_state, element_entry, epsilon_sid);
                nfa_construct_add_transition(ctx, ctx->current_fragment.exit_state, exit_state, epsilon_sid);
            }

            nfa_construct_finalize_state(ctx, exit_state);
            current = exit_state;

            ctx->current_fragment.anchor_state = skip_origin;
            ctx->current_fragment.exit_state = exit_state;

        } else if (op == '+') {
            if (!quantifier_is_valid(pattern, *pos, ctx)) {
                nfa_parser_set_error(ctx, PARSE_ERROR_QUANTIFIER_POSITION, *pos,
                    "'+' quantifier must follow ')' - use (expr)+ for one-or-more");
                return -1;
            }
            (*pos)++;

            int exit_state = nfa_construct_add_state_with_minimization(ctx, false);
            int element_entry = ctx->current_fragment.anchor_state;
            if (element_entry < 0) element_entry = start_state;

            if (ctx->current_fragment.exit_state != -1) {
                nfa_construct_add_transition(ctx, ctx->current_fragment.exit_state, element_entry, epsilon_sid);
                nfa_construct_add_transition(ctx, ctx->current_fragment.exit_state, exit_state, epsilon_sid);
            }

            nfa_construct_finalize_state(ctx, exit_state);
            current = exit_state;
            ctx->current_fragment.exit_state = exit_state;

        } else if (op == '?') {
            if (!quantifier_is_valid(pattern, *pos, ctx)) {
                nfa_parser_set_error(ctx, PARSE_ERROR_QUANTIFIER_POSITION, *pos,
                    "'?' quantifier must follow ')' - use (expr)? for optional");
                return -1;
            }
            (*pos)++;

            int exit_state = nfa_construct_add_state_with_minimization(ctx, false);
            int element_entry = ctx->current_fragment.anchor_state;
            if (element_entry < 0) element_entry = start_state;

            int skip_origin = element_entry;
            nfa_construct_add_transition(ctx, skip_origin, exit_state, epsilon_sid);

            if (ctx->current_fragment.exit_state != -1) {
                nfa_construct_add_transition(ctx, ctx->current_fragment.exit_state, exit_state, epsilon_sid);
            }

            nfa_construct_finalize_state(ctx, exit_state);
            current = exit_state;

            ctx->current_fragment.anchor_state = skip_origin;
            ctx->current_fragment.exit_state = exit_state;

        } else {
            break;
        }
    }

    return current;
}

// ============================================================================
// RDP: Sequence parser (concatenation)
// ============================================================================

static int parse_rdp_sequence(nfa_builder_context_t* ctx, const char* pattern, int* pos, int start_state) {
    int current = start_state;
    int pattern_len = strlen(pattern);

    while (*pos < pattern_len && pattern[*pos] != ')' && pattern[*pos] != '|') {
        char next_char = pattern[*pos];
        if (next_char == '+' || next_char == '*' || next_char == '?') {
            break;
        }
        current = parse_rdp_element(ctx, pattern, pos, current);
        if (current < 0) return -1;

        if (pattern[*pos] == '+' || pattern[*pos] == '*' || pattern[*pos] == '?') {
            ctx->has_pending_quantifier = true;
            current = parse_rdp_postfix(ctx, pattern, pos, current);
            ctx->has_pending_quantifier = false;
            if (current < 0) return -1;
        }
    }

    return current;
}

// ============================================================================
// RDP: Alternation parser (sequence ('|' sequence)*)
// ============================================================================

static int parse_rdp_alternation_internal(nfa_builder_context_t* ctx, const char* pattern, int* pos, int start_state) {
    reset_pattern_state(ctx);

    // Create Anchor State
    int anchor_state;
    int epsilon_sid = VSYM_EPS;
    if (start_state == 0) {
        anchor_state = nfa_construct_add_state_with_minimization(ctx, false);
        nfa_construct_add_transition(ctx, 0, anchor_state, VSYM_EPS);
    } else {
        anchor_state = nfa_construct_add_state_with_minimization(ctx, false);
        if (epsilon_sid != -1) {
            nfa_construct_add_transition(ctx, start_state, anchor_state, epsilon_sid);
        } else {
            anchor_state = start_state;
        }
    }

    bool was_in_group = ctx->current_is_in_group;
    ctx->current_is_in_group = true;

    int first_end = parse_rdp_sequence(ctx, pattern, pos, anchor_state);

    ctx->current_is_in_group = was_in_group;

    if (pattern[*pos] == '|') {
        int merge_state = nfa_construct_add_state_with_minimization(ctx, false);

        if (epsilon_sid != -1) {
            nfa_construct_add_transition(ctx, first_end, merge_state, epsilon_sid);
        }

        int last_branch_end = first_end;
        bool has_empty_alternative = false;
        while (pattern[*pos] == '|') {
            (*pos)++;

            if (pattern[*pos] == ')' || pattern[*pos] == '\0') {
                if (epsilon_sid != -1) {
                    nfa_construct_add_transition(ctx, anchor_state, merge_state, epsilon_sid);
                }
                has_empty_alternative = true;
                continue;
            }

            int branch_end = parse_rdp_sequence(ctx, pattern, pos, anchor_state);

            if (epsilon_sid != -1) {
                nfa_construct_add_transition(ctx, branch_end, merge_state, epsilon_sid);
            }
            last_branch_end = branch_end;
        }

        if (last_branch_end != merge_state && epsilon_sid != -1) {
            nfa_construct_add_transition(ctx, merge_state, last_branch_end, epsilon_sid);
        }

        // Mark merge_state as accepting if appropriate
        if (ctx->current_pattern_index >= 0 && !ctx->parsing_fragment_value) {
            int check_pos = *pos;
            while (pattern[check_pos] == ')') check_pos++;
            char next_char = pattern[check_pos];
            bool end_of_pattern = (next_char == '\0');

            if (has_empty_alternative || end_of_pattern) {
                ctx->nfa[merge_state].category_mask = ctx->current_pattern_cat_mask;
                ctx->nfa[merge_state].is_eos_target = true;
                ctx->nfa[merge_state].pattern_id = ctx->current_pattern_index + 1;
            }
        }

        if (pattern[*pos] == ')') {
            (*pos)++;
            memset(&ctx->current_fragment, 0, sizeof(ctx->current_fragment));
            ctx->current_fragment.is_single_char = false;
            ctx->current_fragment.anchor_state = anchor_state;
            ctx->current_fragment.exit_state = merge_state;
            ctx->current_fragment.fragment_entry_state = start_state;
            for (int s = 0; s < MAX_SYMBOLS && s < ctx->alphabet_size; s++) {
                if (ctx->nfa[start_state].multi_targets.has_first_target[s] ||
                    ctx->nfa[start_state].multi_targets.symbol_map[s] != NULL) {
                    ctx->current_fragment.loop_first_char = ctx->alphabet[s].start_char;
                    break;
                }
            }
        }

        if (ctx->current_fragment.anchor_state < 0) {
            ctx->current_fragment.anchor_state = anchor_state;
        }
        if (ctx->current_fragment.exit_state < 0) {
            ctx->current_fragment.exit_state = merge_state;
        }

        int postfix_result = parse_rdp_postfix(ctx, pattern, pos, merge_state);
        if (postfix_result < 0) return -1;
        nfa_construct_finalize_state(ctx, merge_state);
        return postfix_result;
    }

    // No alternation - handle closing paren and postfix quantifiers
    if (pattern[*pos] == ')') {
        (*pos)++;
        bool preserved_is_single_char = ctx->current_fragment.is_single_char;
        int preserved_loop_entry_state = ctx->current_fragment.loop_entry_state;

        memset(&ctx->current_fragment, 0, sizeof(ctx->current_fragment));
        ctx->current_fragment.anchor_state = anchor_state;
        ctx->current_fragment.is_single_char = preserved_is_single_char;
        ctx->current_fragment.loop_entry_state = preserved_loop_entry_state;
        ctx->current_fragment.exit_state = first_end;
        ctx->current_fragment.fragment_entry_state = start_state;
        if (!preserved_is_single_char) {
            for (int s = 0; s < MAX_SYMBOLS && s < ctx->alphabet_size; s++) {
                if (ctx->nfa[start_state].multi_targets.has_first_target[s] ||
                    ctx->nfa[start_state].multi_targets.symbol_map[s] != NULL) {
                    ctx->current_fragment.loop_first_char = ctx->alphabet[s].start_char;
                    break;
                }
            }
        }
    }

    bool saved_in_group = ctx->current_is_in_group;
    ctx->current_is_in_group = true;
    int postfix_result = parse_rdp_postfix(ctx, pattern, pos, first_end);
    ctx->current_is_in_group = saved_in_group;

    if (postfix_result < 0) return -1;
    return nfa_construct_finalize_state(ctx, postfix_result);
}

// Public wrapper for RDP alternation (called by nfa_capture.c for fragment parsing)
int nfa_parser_rdp_alternation(nfa_builder_context_t* ctx, const char* pattern, int* pos, int start_state) {
    return parse_rdp_alternation_internal(ctx, pattern, pos, start_state);
}

// ============================================================================
// Pattern input validation
// ============================================================================

static bool validate_pattern_input_local(nfa_builder_context_t* ctx, const char* line, size_t len) {
    if (line == NULL || len == 0) {
        nfa_parser_set_error(ctx, PARSE_ERROR_SYNTAX, 0, "Pattern is empty or null");
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        if (line[i] == '\0') {
            nfa_parser_set_error(ctx, PARSE_ERROR_SYNTAX, (int)i, "Pattern contains null byte at position %zu", i);
            return false;
        }
    }

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)line[i];
        if (c == 0xFF) {
            nfa_parser_set_error(ctx, PARSE_ERROR_SYNTAX, (int)i, "Pattern contains invalid byte 0xFF at position %zu", i);
            return false;
        }
    }

    if (len == 1) {
        char c = line[0];
        if (c == '$' || c == '*' || c == '[' || c == ']' || c == '+' || c == '?') {
            nfa_parser_set_error(ctx, PARSE_ERROR_SYNTAX, 0, "Invalid single-character pattern: '%c' (0x%02x) - requires proper context", c, (unsigned char)c);
            return false;
        }
    }

    int bracket_depth = 0;
    int paren_depth = 0;
    for (size_t i = 0; i < len; i++) {
        if (line[i] == '[') bracket_depth++;
        if (line[i] == ']') bracket_depth--;
        if (line[i] == '(') paren_depth++;
        if (line[i] == ')') paren_depth--;
        if (bracket_depth < 0 || paren_depth < 0) {
            break;
        }
    }

    if (bracket_depth > 0) {
        nfa_parser_set_error(ctx, PARSE_ERROR_UNCLOSED_BRACKET, 0, "Unclosed '[' in pattern - not supported");
        return false;
    }
    if (bracket_depth < 0) {
        nfa_parser_set_error(ctx, PARSE_ERROR_UNMATCHED_BRACKET, 0, "Unmatched ']' in pattern");
        return false;
    }
    if (paren_depth > 0) {
        nfa_parser_set_error(ctx, PARSE_ERROR_UNCLOSED_PAREN, 0, "Unclosed '(' in pattern");
        return false;
    }
    if (paren_depth < 0) {
        nfa_parser_set_error(ctx, PARSE_ERROR_UNMATCHED_PAREN, 0, "Unmatched ')' in pattern");
        return false;
    }

    return true;
}

// ============================================================================
// Full pattern builder: parse pattern and construct NFA states
// ============================================================================

static void parse_pattern_full(nfa_builder_context_t* ctx, const char* pattern,
                                const char* category, const char* subcategory,
                                const char* operations, const char* action) {
    if (pattern == NULL || pattern[0] == '\0') {
        return;
    }

    // Clear per-pattern state
    ctx->last_element_sid = -1;
    ctx->pending_capture_defer_id = -1;
    memset(&ctx->current_fragment, 0, sizeof(ctx->current_fragment));
    ctx->current_fragment.exit_state = -1;
    ctx->current_is_char_class = false;
    ctx->has_pending_quantifier = false;

    // Find entry state - try to share prefix with existing patterns
    int start_state;
    int pattern_start_pos = 0;

    unsigned char first_byte = (unsigned char)pattern[0];
    int first_char_sid = nfa_alphabet_find_symbol_id(first_byte);
    if (first_char_sid < 0 || first_char_sid >= MAX_SYMBOLS) {
        first_char_sid = -1;
    }

    if (ctx->nfa_state_count > 1 && pattern[0] != '\0') {
        if (first_char_sid < 0 || first_char_sid >= MAX_SYMBOLS) {
            first_char_sid = -1;
        }

        bool is_safe_first = (strchr("()[]*+?|\\'\"<>", pattern[0]) == NULL) &&
                              (pattern[1] != '*' && pattern[1] != '+' && pattern[1] != '?');

        if (is_safe_first && first_char_sid != -1) {
            start_state = nfa_construct_add_state_with_minimization(ctx, false);
            nfa_construct_add_transition(ctx, 0, start_state, first_char_sid);
            pattern_start_pos = 1;
        } else {
            start_state = 0;
            pattern_start_pos = 0;
        }
    } else {
        start_state = 0;
    }

    // Parse the remaining pattern
    size_t remaining_len = strlen(pattern + pattern_start_pos);
    if (remaining_len >= 512) {
        nfa_parser_set_error(ctx, PARSE_ERROR_LENGTH, 0, "Pattern too long (max 511 chars)");
        return;
    }
    char remaining[512];
    strncpy(remaining, pattern + pattern_start_pos, sizeof(remaining) - 1);
    remaining[sizeof(remaining) - 1] = '\0';

    if (pattern_start_pos == 1 && remaining[0] != '\0') {
        char first_char = pattern[0];
        int first_sid = nfa_alphabet_find_symbol_id((unsigned char)first_char);
        if (first_sid != -1) {
            ctx->last_element_sid = first_sid;
        }
    }

    // Determine acceptance category
    int acceptance_cat = nfa_category_lookup(ctx, category, subcategory, operations);
    if (acceptance_cat < 0) {
        nfa_parser_set_error(ctx, PARSE_ERROR_CATEGORY, 0, "Category '%s' used in pattern but not defined in ACCEPTANCE_MAPPING", category);
    }
    uint8_t cat_mask = (1 << acceptance_cat);
    ctx->current_pattern_cat_mask = cat_mask;

    int parse_pos = 0;
    int end_state;

    if (remaining[0] != '\0') {
        if (start_state == 0) {
            int real_start = nfa_construct_add_state_with_minimization(ctx, false);
            nfa_construct_add_transition(ctx, 0, real_start, VSYM_EPS);

            bool has_alternation = false;
            for (int i = 0; remaining[i] != '\0'; i++) {
                if (remaining[i] == '|' && i > 0 && remaining[i-1] != '\\') {
                    has_alternation = true;
                    break;
                }
            }

            if (has_alternation) {
                end_state = parse_rdp_alternation_internal(ctx, remaining, &parse_pos, real_start);
            } else {
                end_state = parse_rdp_sequence(ctx, remaining, &parse_pos, real_start);
            }
            if (end_state < 0) {
                ERROR("Pattern parse failed for: %s", pattern);
                return;
            }
        } else {
            end_state = parse_rdp_alternation_internal(ctx, remaining, &parse_pos, start_state);
        }
    } else {
        end_state = start_state;
    }

    // Add EOS transition to accepting state
    int eos_sid = VSYM_EOS;
    if (eos_sid != -1) {
        int eos_target_state = end_state;

        if (end_state == 0) {
            eos_target_state = nfa_construct_add_state_with_minimization(ctx, false);
            nfa_construct_add_transition(ctx, 0, eos_target_state, VSYM_EPS);
        }

        // Check if end_state has outgoing transitions (excluding self-loops)
        // Note: Only mta_is_multi is checked because transitions[] was never set in NFA builder.
        // The has_first_target fast-path is not checked to maintain original behavior.
        bool has_outgoing = false;
        for (int s = 0; s < MAX_SYMBOLS; s++) {
            if (mta_is_multi(&ctx->nfa[end_state].multi_targets, s)) {
                int cnt = 0;
                int* targets = mta_get_target_array(&ctx->nfa[end_state].multi_targets, s, &cnt);
                for (int i = 0; i < cnt; i++) {
                    if (targets[i] != end_state) {
                        has_outgoing = true;
                        break;
                    }
                }
                if (has_outgoing) break;
            }
        }

        if (!has_outgoing && mta_is_multi(&ctx->nfa[end_state].multi_targets, VSYM_EPS)) {
            int eps_cnt = 0;
            int* eps_targets = mta_get_target_array(&ctx->nfa[end_state].multi_targets, VSYM_EPS, &eps_cnt);
            for (int i = 0; i < eps_cnt; i++) {
                if (eps_targets[i] != end_state) {
                    has_outgoing = true;
                    break;
                }
            }
        }

        if (ctx->nfa[end_state].category_mask != 0) {
            has_outgoing = true;
        }

        if (has_outgoing) {
            eos_target_state = nfa_construct_add_state_with_minimization(ctx, false);
            ctx->nfa[eos_target_state].is_eos_target = true;
            ctx->nfa[eos_target_state].category_mask = cat_mask;
            nfa_construct_add_transition(ctx, end_state, eos_target_state, eos_sid);
            nfa_construct_finalize_state(ctx, end_state);

            // Create accepting state
            int accepting = ctx->nfa_state_count;
            ctx->nfa_state_count++;
            ctx->nfa[accepting].category_mask = cat_mask;
            ctx->nfa[accepting].pattern_id = (ctx->current_pattern_index >= 0) ?
                (uint16_t)(ctx->current_pattern_index + 1) : 0;
            ctx->nfa[accepting].is_eos_target = true;
            ctx->nfa[accepting].tag_count = 0;
            for (int j = 0; j < MAX_TAGS; j++) ctx->nfa[accepting].tags[j] = NULL;
            mta_init(&ctx->nfa[accepting].multi_targets);
            nfa_construct_add_transition(ctx, eos_target_state, accepting, eos_sid);
        }

        if (!has_outgoing) {
            ctx->nfa[eos_target_state].is_eos_target = true;
            ctx->nfa[eos_target_state].category_mask = cat_mask;
            ctx->nfa[eos_target_state].pattern_id = (ctx->current_pattern_index >= 0) ?
                (uint16_t)(ctx->current_pattern_index + 1) : 0;
        }

        nfa_construct_add_tag(ctx, eos_target_state, category);
        if (subcategory[0] != '\0') nfa_construct_add_tag(ctx, eos_target_state, subcategory);
        if (operations[0] != '\0') nfa_construct_add_tag(ctx, eos_target_state, operations);
        nfa_construct_add_tag(ctx, eos_target_state, action);

        nfa_construct_finalize_state(ctx, eos_target_state);
    }
}

// ============================================================================
// Parse advanced pattern line
// ============================================================================

static void parse_advanced_pattern(nfa_builder_context_t* ctx, const char* line) {
    // Skip IDENTIFIER directive
    if (strncmp(line, "IDENTIFIER", 10) == 0 && (line[10] == ' ' || line[10] == '"')) {
        return;
    }

    // Parse ACCEPTANCE_MAPPING directive
    if (strncmp(line, "ACCEPTANCE_MAPPING", 18) == 0) {
        nfa_category_parse_mapping(ctx, line);
        return;
    }

    // Skip CATEGORIES directive
    if (strncmp(line, "CATEGORIES", 10) == 0) {
        return;
    }

    // Validate input
    size_t line_len = strlen(line);
    if (!validate_pattern_input_local(ctx, line, line_len)) {
        return;
    }

    char category[64] = "safe";
    char subcategory[64] = "";
    char operations[256] = "";
    char action[32] = "allow";
    char pattern[MAX_LINE_LENGTH] = "";

    // Skip leading whitespace
    while (*line == ' ' || *line == '\t') line++;

    // Check for old format patterns
    if (*line != '[' && *line != '#') {
        if (*line == ':' ||
            (line[0] == 'a' && line[1] == '(') ||
            (strstr(line, " :one") != NULL) ||
            (strstr(line, " :cat") != NULL) ||
            (strstr(line, " :ops") != NULL) ||
            (strstr(line, " :fragment") != NULL) ||
            (strstr(line, " :allow") != NULL) ||
            (strstr(line, " :block") != NULL)) {
            ERROR("Detected OLD FORMAT pattern. Use: [category:subcategory:ops] pattern -> action");
            ERROR("  Found: %s", line);
            ERROR("  File: %s", ctx->current_input_file ? ctx->current_input_file : "(unknown)");
            exit(EXIT_FAILURE);
        }
    }

    // Check for [CATEGORIES] section
    if (strcmp(line, "[CATEGORIES]") == 0) {
        return;
    }

    // Check for category definition line (N: name format)
    if (line[0] >= '0' && line[0] <= '7' && line[1] == ':') {
        nfa_category_parse_definition(ctx, line);
        return;
    }

    // Check for fragment or character set definition
    if (strncmp(line, "[fragment:", 10) == 0 || strncmp(line, "[characterset:", 14) == 0) {
        int prefix_len = (line[1] == 'f') ? 10 : 14;
        const char* name_start = line + prefix_len;
        const char* name_end = strchr(name_start, ']');
        if (name_end != NULL && ctx->fragment_count < MAX_FRAGMENTS) {
            size_t name_len = name_end - name_start;
            if (name_len < MAX_FRAGMENT_NAME) {
                strncpy(ctx->fragments[ctx->fragment_count].name, name_start, name_len);
                ctx->fragments[ctx->fragment_count].name[name_len] = '\0';

                // Normalize separator
                if (strstr(ctx->fragments[ctx->fragment_count].name, "::") == NULL) {
                    for (int i = 0; ctx->fragments[ctx->fragment_count].name[i]; i++) {
                        if (ctx->fragments[ctx->fragment_count].name[i] == ':') {
                            int len = strlen(ctx->fragments[ctx->fragment_count].name);
                            for (int k = len; k > i; k--) {
                                ctx->fragments[ctx->fragment_count].name[k] =
                                    ctx->fragments[ctx->fragment_count].name[k - 1];
                            }
                            ctx->fragments[ctx->fragment_count].name[i] = ':';
                            ctx->fragments[ctx->fragment_count].name[i + 1] = ':';
                            break;
                        }
                    }
                }

                const char* value_start = name_end + 1;
                while (*value_start == ' ' || *value_start == '\t') value_start++;
                if (*value_start == '\0' || *value_start == '\n' || *value_start == '#') {
                    nfa_parser_set_error(ctx, PARSE_ERROR_FRAGMENT, 0, "Fragment '%s' has empty value", ctx->fragments[ctx->fragment_count].name);
                    ctx->has_fragment_error = true;
                    return;
                }

                // Check for duplicate
                for (int i = 0; i < ctx->fragment_count; i++) {
                    if (strcmp(ctx->fragments[i].name, ctx->fragments[ctx->fragment_count].name) == 0) {
                        nfa_parser_set_error(ctx, PARSE_ERROR_FRAGMENT, 0, "Duplicate fragment name '%s'", ctx->fragments[ctx->fragment_count].name);
                        ctx->has_fragment_error = true;
                        return;
                    }
                }

                strncpy(ctx->fragments[ctx->fragment_count].value, value_start, MAX_FRAGMENT_VALUE - 1);
                ctx->fragments[ctx->fragment_count].value[MAX_FRAGMENT_VALUE - 1] = '\0';
                ctx->fragment_count++;
            }
        }
        return;
    }

    // Parse category section
    if (*line == '[') {
        line++;
        char* end = strchr(line, ']');
        if (end != NULL) {
            char category_section[256];
            size_t cat_sec_len = end - line;
            if (cat_sec_len >= sizeof(category_section)) cat_sec_len = sizeof(category_section) - 1;
            strncpy(category_section, line, cat_sec_len);
            category_section[cat_sec_len] = '\0';

            char* tok = strtok(category_section, ":");
            if (tok != NULL) {
                strncpy(category, tok, sizeof(category) - 1);
                category[sizeof(category) - 1] = '\0';
            }
            tok = strtok(NULL, ":");
            if (tok != NULL) {
                strncpy(subcategory, tok, sizeof(subcategory) - 1);
                subcategory[sizeof(subcategory) - 1] = '\0';
            }
            tok = strtok(NULL, ":");
            if (tok != NULL) {
                strncpy(operations, tok, sizeof(operations) - 1);
                operations[sizeof(operations) - 1] = '\0';
            }
            line = end + 1;
        }
    }

    while (*line == ' ' || *line == '\t') line++;

    // Parse pattern
    char* arrow = strstr(line, "->");
    if (arrow != NULL) {
        strncpy(pattern, line, arrow - line);
        pattern[arrow - line] = '\0';

        char* end = pattern + strlen(pattern) - 1;
        while (end >= pattern && (*end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }

        arrow += 2;
        while (*arrow == ' ' || *arrow == '\t') arrow++;
        strncpy(action, arrow, sizeof(action) - 1);
        action[sizeof(action) - 1] = '\0';

        end = action + strlen(action) - 1;
        while (end >= action && (*end == ' ' || *end == '\t' || *end == '\n')) {
            *end = '\0';
            end--;
        }
    } else {
        strncpy(pattern, line, sizeof(pattern) - 1);
    }

    if (pattern[0] == '\0') {
        return;
    }

    // Store pattern
    if (ctx->pattern_count < MAX_PATTERNS) {
        strlcpy(ctx->patterns[ctx->pattern_count].pattern, pattern, sizeof(ctx->patterns[ctx->pattern_count].pattern));
        strlcpy(ctx->patterns[ctx->pattern_count].category, category, sizeof(ctx->patterns[ctx->pattern_count].category));
        strlcpy(ctx->patterns[ctx->pattern_count].subcategory, subcategory, sizeof(ctx->patterns[ctx->pattern_count].subcategory));
        strlcpy(ctx->patterns[ctx->pattern_count].operations, operations, sizeof(ctx->patterns[ctx->pattern_count].operations));
        strlcpy(ctx->patterns[ctx->pattern_count].action, action, sizeof(ctx->patterns[ctx->pattern_count].action));
        ctx->patterns[ctx->pattern_count].category_id = nfa_category_parse(ctx, category);
        ctx->current_pattern_index = ctx->pattern_count;
        ctx->pattern_count++;
    }

    ctx->pending_marker_count = 0;
    parse_pattern_full(ctx, pattern, category, subcategory, operations, action);
}

// ============================================================================
// Read spec file
// ============================================================================

void nfa_parser_read_spec_file(nfa_builder_context_t* ctx, const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        FATAL_SYS("Cannot open file '%s'", filename);
        exit(EXIT_FAILURE);
    }

    char line[MAX_LINE_LENGTH];
    bool in_categories_section = false;

    nfa_construct_init(ctx);
    nfa_category_init_defaults(ctx);
    ctx->current_input_file = filename;

    while (fgets(line, sizeof(line), file)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }

        if (line[0] == '\0') {
            continue;
        }

        const char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') continue;

        if (strncmp(p, "#ACCEPTANCE_MAPPING", 19) == 0 || strncmp(p, "ACCEPTANCE_MAPPING", 18) == 0) {
            nfa_category_parse_mapping(ctx, p);
            continue;
        }

        if (line[0] == '#') {
            continue;
        }

        if (strcmp(p, "[CATEGORIES]") == 0) {
            in_categories_section = true;
            continue;
        }

        if (in_categories_section && p[0] == '[' && strncmp(p, "[CATEGORIES]", 12) != 0) {
            in_categories_section = false;
        }

        if (in_categories_section && p[0] >= '0' && p[0] <= '7' && p[1] == ':') {
            nfa_category_parse_definition(ctx, p);
            continue;
        }

        parse_advanced_pattern(ctx, line);
    }

    fclose(file);

    VP(ctx, "Read %d patterns from %s\n", ctx->pattern_count, filename);
}

// ============================================================================
// Public API
// ============================================================================

void nfa_parser_parse_pattern(nfa_builder_context_t* ctx, const char* line) {
    parse_advanced_pattern(ctx, line);
}
