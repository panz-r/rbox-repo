#include "dfa_types.h"
#include "dfa_format.h"
#include <string.h>

// Forward declarations
bool dfa_eval_with_limit(const void* dfa_void, size_t dfa_size, const char* input, size_t length, dfa_result_t* result, int max_caps);
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

/**
 * DFA Evaluator - State-passing evaluator with capture extraction
 *
 * All functions take an explicit dfa_machine_t* parameter.
 * No global state - supports multiple concurrent evaluators.
 */

#ifndef DFA_EVAL_DEBUG
#define DFA_EVAL_DEBUG 0
#endif

#if DFA_EVAL_DEBUG
#define EVAL_DEBUG_PRINT(fmt, ...) fprintf(stderr, "[EVAL] " fmt, ##__VA_ARGS__)
#define EVAL_DEBUG_FLUSH() fflush(stderr)
#else
#define EVAL_DEBUG_PRINT(fmt, ...) ((void)0)
#define EVAL_DEBUG_FLUSH() ((void)0)
#endif

#define MAX_MARKER_LIST_SIZE 1024
#define MAX_EVAL_LENGTH 16384
#define MAX_TRACE_LENGTH 16384
#define MAX_CAPTURE_STACK 32

typedef struct {
    int capture_id;
    size_t start_pos;
    size_t end_pos;
} capture_range_t;

// ============================================================================
// Machine lifecycle
// ============================================================================

// ============================================================================
// Category string
// ============================================================================

const char* dfa_category_string(dfa_command_category_t cat) {
    static const char* names[] = {"Unknown", "Read-only (Safe)", "Read-only (Caution)",
                                 "Modifying", "Dangerous", "Network", "Admin", "Build", "Container"};
    int idx = (int)cat;
    return (idx >= 0 && idx <= 8) ? names[idx] : "Invalid";
}

// ============================================================================
// Internal helpers (machine-aware)
// ============================================================================

static bool get_capture_name_from_table(const dfa_t* dfa, size_t dfa_size, int capture_id, int pattern_id, char* buffer, size_t buffer_size) {
    (void)capture_id; // Used in loop below, but compiler doesn't see it
    (void)pattern_id;
    if (!dfa || dfa->metadata_offset == 0 || !buffer || buffer_size == 0) return false;

    const char* base = (const char*)dfa;
    if (dfa->metadata_offset >= dfa_size ||
        dfa->metadata_offset + 4 > dfa_size) {
        return false;
    }
    uint32_t entry_count = *(const uint32_t*)(base + dfa->metadata_offset);

    const char* p = base + dfa->metadata_offset + 4;
    const char* end = base + dfa_size;

    for (uint32_t i = 0; i < entry_count; i++) {
        if (p + 4 > end) {
            return false;
        }

        uint16_t entry_pattern_id = *(const uint16_t*)p;
        uint16_t name_len = *(const uint16_t*)(p + 2);

        if (p + 4 + name_len > end) {
            return false;
        }

        if (entry_pattern_id == (uint16_t)pattern_id) {
            snprintf(buffer, buffer_size, "%.*s", name_len, p + 4);
            return true;
        }

        p += 4 + name_len;
    }
    return false;
}

static void add_capture(dfa_result_t* result, int capture_id, size_t start, size_t end, uint16_t pattern_id) {
    if (result->capture_count >= DFA_MAX_CAPTURES) return;
    dfa_capture_t* cap = &result->captures[result->capture_count++];
    cap->start = start;
    cap->end = end;
    cap->capture_id = capture_id;
    cap->name[0] = '\0';  // Name resolved lazily via dfa_result_get_capture_string()
    cap->active = false;
    cap->completed = true;
}

static void process_marker_list(const dfa_t* dfa, size_t dfa_size, const uint32_t* marker_base, size_t pos,
                                 uint16_t winning_pattern_id, uint8_t category_mask,
                                 capture_range_t* capture_stack, int* stack_depth,
                                 dfa_result_t* result, size_t marker_max_count,
                                 size_t marker_data_size) {
    if (!marker_base) return;

    bool filter_by_pattern = (category_mask != 0 && winning_pattern_id != UINT16_MAX);

    for (size_t i = 0; i < marker_max_count && (i + 1) * sizeof(uint32_t) <= marker_data_size && marker_base[i] != MARKER_SENTINEL; i++) {
        uint32_t mk = marker_base[i];
        uint16_t pattern_id = MARKER_GET_PATTERN_ID(mk);
        uint16_t capture_id = MARKER_GET_UID(mk);
        uint8_t type = MARKER_GET_TYPE(mk);

        if (filter_by_pattern && pattern_id != winning_pattern_id) {
            continue;
        }

        if (type == MARKER_TYPE_START) {
            if (*stack_depth < MAX_CAPTURE_STACK) {
                capture_stack[*stack_depth].capture_id = capture_id;
                capture_stack[*stack_depth].start_pos = pos;
                capture_stack[*stack_depth].end_pos = 0;
                (*stack_depth)++;
            }
        } else if (type == MARKER_TYPE_END) {
            if (*stack_depth > 0) {
                for (int j = *stack_depth - 1; j >= 0; j--) {
                    if (capture_stack[j].capture_id == capture_id && capture_stack[j].end_pos == 0) {
                        capture_stack[j].end_pos = pos;
                        add_capture(result, capture_id, capture_stack[j].start_pos, pos, pattern_id);
                        break;
                    }
                }
            }
        }
    }
}

// ============================================================================
// Evaluation
// ============================================================================

// Direct API - dfa_data and size passed directly, no struct
bool dfa_eval(const void* dfa_data, size_t dfa_size, const char* input, size_t length, dfa_result_t* result) {
    return dfa_eval_with_limit(dfa_data, dfa_size, input, length, result, DFA_MAX_CAPTURES);
}


bool dfa_eval_with_limit(const void* dfa_void, size_t dfa_size, const char* input, size_t length, dfa_result_t* result, int max_caps) {
    (void)max_caps;

    const dfa_t* dfa = (const dfa_t*)dfa_void;
    if (!dfa || !input || !result) {
        return false;
    }

#if DFA_EVAL_DEBUG
    fprintf(stderr, "EVAL: Starting evaluation of '%s', length=%zu\n", input, length);
#endif

    memset(result, 0, sizeof(dfa_result_t));
    result->category = DFA_CMD_UNKNOWN;

    if (dfa->magic != DFA_MAGIC || dfa->version < 5 || dfa->version > 6) {
        fprintf(stderr, "ERROR: Invalid DFA state in evaluator\n");
        return false;
    }

    if (length == 0) {
        const char* raw_base = (const char*)dfa;
        const dfa_state_t* initial = (const dfa_state_t*)(raw_base + dfa->initial_state);
        uint8_t initial_cat = (uint8_t)DFA_GET_CATEGORY_MASK(initial->flags);

        uint8_t cat = initial_cat;

        if (initial->eos_target != 0 && initial->eos_target + sizeof(dfa_state_t) <= dfa_size) {
            const dfa_state_t* eos_state = (const dfa_state_t*)(raw_base + initial->eos_target);
            uint8_t eos_cat = (uint8_t)DFA_GET_CATEGORY_MASK(eos_state->flags);
            cat |= eos_cat;
        }

        if (cat != 0) {
            result->matched = true;
            result->matched_length = 0;
            result->category_mask = cat;
            for (int i = 0; i < 8; i++) if (cat & (1 << i)) { result->category = (dfa_command_category_t)(i + 1); break; }
        }
        return result->matched;
    }

    const char* raw_base = (const char*)dfa;
    const dfa_state_t* curr = (const dfa_state_t*)(raw_base + dfa->initial_state);

    EVAL_DEBUG_PRINT("DFA LOADED: initial_state=%u, first_state_offset=%u\n",
                     dfa->initial_state, (unsigned int)((const char*)curr - raw_base));
    EVAL_DEBUG_PRINT("State 0: tc=%u, to=%u, flags=0x%04X\n",
                     curr->transition_count, curr->transitions_offset, curr->flags);

    if ((const char*)curr - raw_base != dfa->initial_state) {
        fprintf(stderr, "ERROR: Initial state offset mismatch (expected %u, got %zu)\n",
                dfa->initial_state, (const char*)curr - raw_base);
        return false;
    }

    const uint8_t* marker_base = NULL;
    if (dfa->metadata_offset != 0 && dfa->version >= 6) {
        marker_base = (const uint8_t*)dfa + dfa->metadata_offset;
    }

    uint32_t trace_buffer[MAX_TRACE_LENGTH];
    int trace_depth = 0;
    size_t marker_data_size = 0;

    if (trace_depth < MAX_TRACE_LENGTH) {
        trace_buffer[trace_depth++] = (uint32_t)((const char*)curr - raw_base);
    }

    size_t pos = 0;
    size_t dfa_total_size = dfa_size;  // Use actual file size, not computed (accounts for alignment padding)
    size_t rules_start = dfa->initial_state;  // Rules can start anywhere after header

    while (pos < length && pos < MAX_EVAL_LENGTH) {
        unsigned char c = (unsigned char)input[pos];
        const dfa_state_t* next = NULL;

        EVAL_DEBUG_PRINT("Pos %zu: char='%c'(0x%02X), state_offset=%u, tc=%u\n",
                         pos, c, c, (unsigned int)((const char*)curr - raw_base), curr->transition_count);

        size_t curr_offset = (const char*)curr - raw_base;
        if (curr_offset < dfa->initial_state || curr_offset >= dfa_total_size) {
            fprintf(stderr, "ERROR: Current state offset %zu is out of bounds [%u, %zu)\n",
                    curr_offset, dfa->initial_state, dfa_total_size);
            return false;
        }

        if (curr->transition_count > 0) {
            if (curr->transitions_offset >= rules_start && curr->transitions_offset < dfa_size) {
                const dfa_rule_t* r = (const dfa_rule_t*)(raw_base + curr->transitions_offset);
                for (uint16_t i = 0; i < curr->transition_count; i++, r++) {
                    if (r->target < dfa->initial_state || r->target >= dfa_total_size) {
                        fprintf(stderr, "ERROR: Rule target %u is out of bounds [%u, %zu)\n",
                                r->target, dfa->initial_state, dfa_total_size);
                        return false;
                    }
                    bool match = false;
                    switch (r->type) {
                        case DFA_RULE_LITERAL: match = (c == r->data1); break;
                        case DFA_RULE_RANGE:   match = (c >= r->data1 && c <= r->data2); break;
                        case DFA_RULE_LITERAL_2: match = (c == r->data1 || c == r->data2); break;
                        case DFA_RULE_LITERAL_3: match = (c == r->data1 || c == r->data2 || c == r->data3); break;
                        case DFA_RULE_RANGE_LITERAL: match = ((c >= r->data1 && c <= r->data2) || c == r->data3); break;
                        case DFA_RULE_DEFAULT: match = true; break;
                        case DFA_RULE_NOT_LITERAL: match = (c != r->data1); break;
                        case DFA_RULE_NOT_RANGE:   match = (c < r->data1 || c > r->data2); break;
                    }
                    if (match) {
                        EVAL_DEBUG_PRINT("  Rule %u: type=%u matched, target=%u\n", i, r->type, r->target);
                        if (r->target >= 1000000) {
                            fprintf(stderr, "FATAL: Evaluator encountered corrupt target offset %u\n", r->target);
                            return false;
                        }
                        next = (const dfa_state_t*)(raw_base + r->target);
                        break;
                    }
                }
            } else {
                fprintf(stderr, "ERROR: transitions_offset %u is out of bounds [%zu, %zu)\n",
                        curr->transitions_offset, rules_start, dfa_size);
                return false;
            }
        }

        if (!next) {
            return false;
        }

        pos++;
        curr = next;
        if (trace_depth < MAX_TRACE_LENGTH) {
            trace_buffer[trace_depth++] = (uint32_t)((const char*)curr - raw_base);
        }
    }

    uint16_t winning_pattern_id = UINT16_MAX;
    EVAL_DEBUG_PRINT("POST-LOOP: curr_offset=%u, eos_target=%u, trace_depth=%d\n",
                     (unsigned int)((const char*)curr - raw_base), curr->eos_target, trace_depth);

    uint8_t source_category = (uint8_t)DFA_GET_CATEGORY_MASK(curr->flags);
    uint16_t source_accepting = curr->accepting_pattern_id;

    if (curr->eos_target != 0 && curr->eos_target + sizeof(dfa_state_t) <= dfa_size) {
        const dfa_state_t* eos = (const dfa_state_t*)(raw_base + curr->eos_target);
        curr = eos;
        EVAL_DEBUG_PRINT("EOS: jumped to offset %u\n", (unsigned int)((const char*)curr - raw_base));
        if (trace_depth < MAX_TRACE_LENGTH) {
            trace_buffer[trace_depth++] = (uint32_t)((const char*)curr - raw_base);
        }
        winning_pattern_id = source_accepting;
    } else {
        EVAL_DEBUG_PRINT("NO EOS: staying at offset %u\n", (unsigned int)((const char*)curr - raw_base));
        winning_pattern_id = curr->accepting_pattern_id;
    }

    uint8_t mask = source_category ? source_category : (uint8_t)DFA_GET_CATEGORY_MASK(curr->flags);
    EVAL_DEBUG_PRINT("CATEGORY: final_offset=%u, flags=0x%04X, mask=0x%02X, winning_pattern_id=%u\n",
                     (unsigned int)((const char*)curr - raw_base), curr->flags, mask, winning_pattern_id);

    bool has_valid_accept = (mask != 0) || (winning_pattern_id != 0 && winning_pattern_id != UINT16_MAX);
    if (has_valid_accept) {
        result->matched = true;
        result->matched_length = pos;
        result->category_mask = mask;
        result->final_state = (uint32_t)((const char*)curr - raw_base);
        EVAL_DEBUG_PRINT("RESULT: matched=%d, len=%zu, cat=0x%02X, final_state=%u\n",
                         result->matched, pos, mask, result->final_state);
        for (int i = 0; i < 8; i++) if (mask & (1 << i)) {
            result->category = (dfa_command_category_t)(i + 1);
            break;
        }

        if (dfa->version >= 6 && winning_pattern_id != 0 && winning_pattern_id != UINT16_MAX) {
            capture_range_t capture_stack[MAX_CAPTURE_STACK];
            int stack_depth = 0;

            for (int t = 1; t < trace_depth && (size_t)t <= pos; t++) {
                uint32_t from_state_offset = trace_buffer[t - 1];
                uint32_t to_state_offset = trace_buffer[t];

                const dfa_state_t* from_state = (const dfa_state_t*)(raw_base + from_state_offset);

                if (from_state->transition_count == 0 || from_state->transitions_offset == 0) {
                    continue;
                }

                const dfa_rule_t* r = (const dfa_rule_t*)(raw_base + from_state->transitions_offset);
                const uint32_t* transition_markers = NULL;

                for (uint16_t i = 0; i < from_state->transition_count; i++, r++) {
                    if (r->target == to_state_offset) {
                        if (r->marker_offset != 0 && marker_base &&
                            r->marker_offset + sizeof(uint32_t) <= dfa_size) {
                            transition_markers = (const uint32_t*)((const uint8_t*)dfa + r->marker_offset);
                            marker_data_size = dfa_size - r->marker_offset;
                        }
                        break;
                    }
                }

                if (transition_markers) {
                    process_marker_list(dfa, dfa_size, transition_markers, t - 1, winning_pattern_id, mask,
                                       capture_stack, &stack_depth, result, MAX_MARKER_LIST_SIZE, marker_data_size);
                }
            }

            if (curr->eos_marker_offset != 0 && marker_base &&
                curr->eos_marker_offset + sizeof(uint32_t) <= dfa_size) {
                const uint32_t* eos_markers = (const uint32_t*)((const uint8_t*)dfa + curr->eos_marker_offset);
                marker_data_size = dfa_size - curr->eos_marker_offset;
                process_marker_list(dfa, dfa_size, eos_markers, pos, winning_pattern_id, mask,
                                   capture_stack, &stack_depth, result, MAX_MARKER_LIST_SIZE, marker_data_size);
            }
        }
    }

    return result->matched;
}

// ============================================================================
// Capture access (operate on result, no machine needed)
// ============================================================================

int dfa_result_get_capture(const dfa_result_t* result, int index, const char** out_start, size_t* out_length) {
    if (!result || index < 0 || index >= result->capture_count) return -1;
    const dfa_capture_t* cap = &result->captures[index];
    if (out_start) *out_start = NULL;  // Positions only, no string pointer in stateless eval
    if (out_length) *out_length = cap->end - cap->start;
    return cap->capture_id;
}

const char* dfa_result_get_capture_name(const dfa_result_t* result, int index) {
    if (!result || index < 0 || index >= result->capture_count) return NULL;
    return result->captures[index].name;
}

int dfa_result_get_capture_count(const dfa_result_t* result) {
    return result ? result->capture_count : 0;
}

bool dfa_result_get_capture_by_index(const dfa_result_t* result, int index, size_t* out_start, size_t* out_length) {
    if (!result || index < 0 || index >= result->capture_count) return false;
    const dfa_capture_t* cap = &result->captures[index];
    if (out_start) *out_start = cap->start;
    if (out_length) *out_length = cap->end - cap->start;
    return true;
}

/**
 * Get capture string. Resolves name from DFA metadata on first call.
 * Returns pointer into original input buffer (no copy).
 *
 * @param result    Result from a prior dfa_eval() call
 * @param index     Capture index (0..capture_count-1)
 * @param dfa_data  Binary DFA data (same pointer passed to dfa_eval)
 * @param dfa_size  DFA data size
 * @param input     Original input string (same pointer passed to dfa_eval)
 * @param out_start Output: pointer to captured substring in input
 * @param out_len   Output: length of captured substring
 * @param out_name  Output: capture name (from DFA metadata), or NULL to skip
 * @return true on success
 */
bool dfa_result_get_capture_string(const dfa_result_t* result, int index,
                                    const void* dfa_data, size_t dfa_size,
                                    const char* input,
                                    const char** out_start, size_t* out_len,
                                    const char** out_name) {
    if (!result || index < 0 || index >= result->capture_count) return false;
    dfa_capture_t* cap = (dfa_capture_t*)&result->captures[index];  // mutable for name cache

    // Return captured substring (pointer into original input, zero copy)
    if (out_start) *out_start = input + cap->start;
    if (out_len) *out_len = cap->end - cap->start;

    // Resolve name lazily on first access
    if (out_name) {
        if (cap->name[0] == '\0' && dfa_data) {
            // Need pattern_id to look up name - stored in capture_id high bits or separate field
            // For now, use capture_id as lookup key
            get_capture_name_from_table((const dfa_t*)dfa_data, dfa_size,
                                        cap->capture_id, 0, cap->name, sizeof(cap->name));
            if (cap->name[0] == '\0') {
                snprintf(cap->name, sizeof(cap->name), "capture_%d", cap->capture_id);
            }
        }
        *out_name = cap->name;
    }

    return true;
}

/**
 * One-time DFA identifier check. Verifies the loaded binary matches expected identifier.
 * Call once after loading, before any eval calls.
 *
 * Uses dfa_format.h for all binary offset definitions.
 *
 * @param dfa_data    Binary DFA data
 * @param dfa_size    Size of DFA data
 * @param expected_id Identifier string embedded in the DFA binary
 * @return true if identifiers match, false if mismatch or invalid data
 */
bool dfa_eval_validate_id(const void* dfa_data, size_t dfa_size, const char* expected_id) {
    if (!dfa_data || dfa_size < DFA_HEADER_SIZE || !expected_id) return false;

    const uint8_t* data = (const uint8_t*)dfa_data;

    // Check magic at fixed offset
    if (dfa_fmt_magic(data) != DFA_MAGIC) return false;

    // Read identifier length from fixed offset
    uint8_t id_len = dfa_fmt_id_len(data);
    if (DFA_OFF_IDENTIFIER + id_len > dfa_size) return false;

    size_t expected_len = strlen(expected_id);
    if (id_len != expected_len) return false;

    return memcmp(dfa_fmt_identifier(data), expected_id, expected_len) == 0;
}
