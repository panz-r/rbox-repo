/**
 * nfa_capture.c - Capture marker system
 *
 * Manages capture name-to-ID mapping, capture tag detection,
 * and capture marker queuing for transitions.
 */

#define _DEFAULT_SOURCE
#include "nfa_builder.h"
#include "../include/dfa_errors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../include/compat_strl.h"

int nfa_capture_get_id(nfa_builder_context_t* ctx, const char* name) {
    for (int i = 0; i < ctx->capture_count; i++) {
        if (strcmp(ctx->capture_map[i].name, name) == 0) {
            return ctx->capture_map[i].id;
        }
    }

    if (ctx->capture_count >= MAX_CAPTURES) {
        ERROR("Maximum captures (%d) reached", MAX_CAPTURES);
        return -1;
    }

    strlcpy(ctx->capture_map[ctx->capture_count].name, name, MAX_CAPTURE_NAME);
    ctx->capture_map[ctx->capture_count].id = ctx->capture_count;
    ctx->capture_map[ctx->capture_count].used = true;

    return ctx->capture_count++;
}

const char* nfa_capture_get_name(nfa_builder_context_t* ctx, int id) {
    for (int i = 0; i < ctx->capture_count; i++) {
        if (ctx->capture_map[i].id == id) {
            return ctx->capture_map[i].name;
        }
    }
    return NULL;
}

bool nfa_capture_is_start(const char* pattern, int pos, char* cap_name) {
    if (pattern[pos] != '<') {
        return false;
    }
    if (pattern[pos + 1] == '/') {
        return false;
    }

    int j = pos + 1;
    while (pattern[j] != '\0' && pattern[j] != '>') {
        j++;
    }

    if (pattern[j] != '>') {
        return false;
    }

    int name_len = j - (pos + 1);
    if (name_len >= MAX_CAPTURE_NAME) {
        return false;
    }

    strncpy(cap_name, &pattern[pos + 1], name_len);
    cap_name[name_len] = '\0';

    return true;
}

bool nfa_capture_is_end(const char* pattern, int pos, char* cap_name) {
    if (pattern[pos] != '<' || pattern[pos + 1] != '/') {
        return false;
    }

    int j = pos + 2;
    while (pattern[j] != '\0' && pattern[j] != '>') {
        j++;
    }

    if (pattern[j] != '>') {
        return false;
    }

    int name_len = j - (pos + 2);
    if (name_len >= MAX_CAPTURE_NAME) {
        return false;
    }

    strncpy(cap_name, &pattern[pos + 2], name_len);
    cap_name[name_len] = '\0';

    return true;
}

int nfa_capture_parse_start(nfa_builder_context_t* ctx, const char* pattern, int* pos, int start_state) {
    char cap_name[MAX_CAPTURE_NAME];
    if (!nfa_capture_is_start(pattern, *pos, cap_name)) {
        return start_state;
    }

    int cap_id = nfa_capture_get_id(ctx, cap_name);
    if (cap_id < 0) {
        return start_state;
    }

    // Skip past the opening tag <name>
    while (pattern[*pos] != '\0' && pattern[*pos] != '>') {
        (*pos)++;
    }
    if (pattern[*pos] == '>') {
        (*pos)++;
    }

    // Queue START marker for the next character transition
    if (ctx->pending_marker_count < MAX_PENDING_MARKERS) {
        ctx->pending_markers[ctx->pending_marker_count].pattern_id = (uint16_t)ctx->current_pattern_index;
        ctx->pending_markers[ctx->pending_marker_count].uid = (uint32_t)cap_id;
        ctx->pending_markers[ctx->pending_marker_count].type = MARKER_TYPE_START;
        ctx->pending_markers[ctx->pending_marker_count].active = true;
        ctx->pending_marker_count++;
    }

    // Push capture ID onto stack
    ctx->capture_stack[ctx->capture_stack_depth++] = cap_id;
    ctx->pending_capture_defer_id = cap_id;

    return start_state;
}

int nfa_capture_parse_end(nfa_builder_context_t* ctx, const char* pattern, int* pos, int start_state) {
    char cap_name[MAX_CAPTURE_NAME];
    if (!nfa_capture_is_end(pattern, *pos, cap_name)) {
        return start_state;
    }

    int cap_id = nfa_capture_get_id(ctx, cap_name);
    if (cap_id < 0) {
        return start_state;
    }

    // Skip past the closing tag </name>
    while (pattern[*pos] != '\0' && pattern[*pos] != '>') {
        (*pos)++;
    }
    if (pattern[*pos] == '>') {
        (*pos)++;
    }

    // Check if this is the end of the pattern (no more content after </name>)
    int after_tag_pos = *pos;
    while (pattern[after_tag_pos] != '\0' && isspace(pattern[after_tag_pos])) after_tag_pos++;
    bool is_pattern_end = (pattern[after_tag_pos] == '\0' ||
                           pattern[after_tag_pos] == '[' ||
                           pattern[after_tag_pos] == '<');

    if (is_pattern_end) {
        // Capture ends at pattern boundary - set capture_end_id on state
        ctx->nfa[start_state].capture_end_id = (int8_t)cap_id;
        ctx->nfa[start_state].pattern_id = (uint16_t)ctx->current_pattern_index;
    } else {
        // Intermediate capture - queue END marker for next character transition
        if (ctx->pending_marker_count < MAX_PENDING_MARKERS) {
            ctx->pending_markers[ctx->pending_marker_count].pattern_id = (uint16_t)ctx->current_pattern_index;
            ctx->pending_markers[ctx->pending_marker_count].uid = (uint32_t)cap_id;
            ctx->pending_markers[ctx->pending_marker_count].type = MARKER_TYPE_END;
            ctx->pending_markers[ctx->pending_marker_count].active = true;
            ctx->pending_marker_count++;
        }
    }

    // Pop capture ID from stack
    if (ctx->capture_stack_depth > 0) {
        ctx->capture_stack_depth--;
    }

    return start_state;
}
