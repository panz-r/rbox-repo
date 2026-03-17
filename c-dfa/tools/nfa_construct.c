/**
 * nfa_construct.c - NFA state machine construction
 *
 * Handles NFA state creation, transitions, tags, signatures,
 * file I/O, and cleanup. All state is stored in the context struct.
 */

#include "nfa_builder.h"
#include "../include/dfa_errors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Internal helpers
// ============================================================================

static char* my_strdup(const char* str) {
    if (str == NULL) return NULL;
    size_t len = strlen(str) + 1;
    char* copy = malloc(len);
    if (copy == NULL) {
        FATAL("Failed to allocate %zu bytes for string duplication", len);
        exit(EXIT_FAILURE);
    }
    memcpy(copy, str, len);
    return copy;
}

static unsigned int hash_signature(uint64_t signature) {
    return (unsigned int)(signature % SIGNATURE_TABLE_SIZE);
}

static uint64_t compute_state_signature(nfa_builder_context_t* ctx, int state) {
    uint64_t signature = 0;
    nfa_builder_state_t* s = &ctx->nfa[state];

    signature = signature * 31 + ctx->current_pattern_index;

    if (s->category_mask != 0) {
        signature |= 0x8000000000000000ULL;
        signature = signature * 31 + s->category_mask;
    }

    for (int i = 0; i < s->tag_count; i++) {
        if (s->tags[i] != NULL) {
            const char* tag = s->tags[i];
            while (*tag) {
                signature = signature * 31 + *tag;
                tag++;
            }
        }
    }

    for (int sym = 0; sym < MAX_SYMBOLS; sym++) {
        if (s->transitions[sym] != -1) {
            signature = signature * 31 + sym;
            signature = signature * 31 + s->transitions[sym];
        }
    }

    return signature;
}

static void add_state_to_signature_table(nfa_builder_context_t* ctx, int state, uint64_t signature) {
    unsigned int hash = hash_signature(signature);

    StateSignature* new_entry = malloc(sizeof(StateSignature));
    if (new_entry == NULL) {
        FATAL("Failed to allocate StateSignature for signature table");
        exit(EXIT_FAILURE);
    }

    new_entry->signature = signature;
    new_entry->state_index = state;
    new_entry->next = ctx->signature_table[hash];
    ctx->signature_table[hash] = new_entry;
}

// ============================================================================
// Public API
// ============================================================================

void nfa_construct_init(nfa_builder_context_t* ctx) {
    for (int i = 0; i < MAX_STATES; i++) {
        ctx->nfa[i].category_mask = 0;
        ctx->nfa[i].is_eos_target = false;
        ctx->nfa[i].tag_count = 0;
        for (int j = 0; j < MAX_TAGS; j++) {
            ctx->nfa[i].tags[j] = NULL;
        }
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            ctx->nfa[i].transitions[j] = -1;
        }
        mta_free(&ctx->nfa[i].multi_targets);
        mta_init(&ctx->nfa[i].multi_targets);
        ctx->nfa[i].transition_count = 0;
        ctx->nfa[i].capture_start_id = -1;
        ctx->nfa[i].capture_end_id = -1;
    }
    ctx->nfa_state_count = 1; // State 0 is initial state
    ctx->fragment_count = 0;
    ctx->capture_count = 0;
    ctx->capture_stack_depth = 0;
}

int nfa_construct_add_state_with_category(nfa_builder_context_t* ctx, uint8_t category_mask) {
    if (ctx->nfa_state_count >= MAX_STATES) {
        ERROR("NFA state limit exceeded (max %d states)", MAX_STATES);
        ERROR("  Pattern may be too complex or cause exponential state growth");
        return -1;
    }

    int new_state = ctx->nfa_state_count;
    ctx->nfa[new_state].category_mask = category_mask;
    ctx->nfa[new_state].pattern_id = (category_mask != 0) ?
        (uint16_t)(ctx->current_pattern_index + 1) : 0;
    ctx->nfa[new_state].tag_count = 0;
    for (int j = 0; j < MAX_TAGS; j++) {
        ctx->nfa[new_state].tags[j] = NULL;
    }
    for (int j = 0; j < MAX_SYMBOLS; j++) {
        ctx->nfa[new_state].transitions[j] = -1;
    }
    ctx->nfa[new_state].transition_count = 0;
    mta_init(&ctx->nfa[new_state].multi_targets);
    ctx->nfa_state_count++;

    return new_state;
}

int nfa_construct_add_state_with_minimization(nfa_builder_context_t* ctx, bool accepting) {
    return nfa_construct_add_state_with_category(ctx, accepting ? 0x01 : 0);
}

int nfa_construct_finalize_state(nfa_builder_context_t* ctx, int state) {
    uint64_t signature = compute_state_signature(ctx, state);
    add_state_to_signature_table(ctx, state, signature);
    return state;
}

void nfa_construct_add_tag(nfa_builder_context_t* ctx, int state, const char* tag) {
    if (state < 0 || state >= ctx->nfa_state_count) {
        return;
    }
    if (tag == NULL) {
        ERROR("Attempting to add NULL tag to state %d", state);
        return;
    }
    if (ctx->nfa[state].tag_count >= MAX_TAGS) {
        ERROR("Maximum tags (%d) reached for state %d", MAX_TAGS, state);
        return;
    }

    ctx->nfa[state].tags[ctx->nfa[state].tag_count] = my_strdup(tag);
    ctx->nfa[state].tag_count++;
}

void nfa_construct_add_transition(nfa_builder_context_t* ctx, int from, int to, int symbol_id) {
    if (from < 0 || from >= ctx->nfa_state_count || to < 0 || to >= ctx->nfa_state_count) {
        FATAL("Invalid state index (from=%d, to=%d, state_count=%d)", from, to, ctx->nfa_state_count);
        exit(EXIT_FAILURE);
    }

    if (symbol_id < 0 || symbol_id >= MAX_SYMBOLS) {
        FATAL("Invalid symbol ID %d", symbol_id);
        exit(EXIT_FAILURE);
    }

    bool added = mta_add_target(&ctx->nfa[from].multi_targets, symbol_id, to);
    if (added) {
        ctx->nfa[from].transition_count++;
    }

    // Transfer pending capture markers to character transitions (not EPSILON/EOS)
    if (ctx->pending_marker_count > 0 && symbol_id < 256) {
        multi_target_array_t* mta = &ctx->nfa[from].multi_targets;
        for (int m = 0; m < ctx->pending_marker_count; m++) {
            pending_marker_t* marker = &ctx->pending_markers[m];
            if (marker->pattern_id == (uint16_t)ctx->current_pattern_index) {
                mta_add_marker(mta, symbol_id, marker->pattern_id, marker->uid, marker->type);
            }
        }
        ctx->pending_marker_count = 0;
    }
}

void nfa_construct_write_file(nfa_builder_context_t* ctx, const char* filename) {
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        FATAL_SYS("Cannot create file '%s'", filename);
        return;
    }

    // Write header
    fprintf(file, "NFA_ALPHABET\n");
    fprintf(file, "Identifier: %s\n",
            ctx->pattern_identifier[0] ? ctx->pattern_identifier : "(none)");
    fprintf(file, "AlphabetSize: %d\n", ctx->alphabet_size);
    fprintf(file, "States: %d\n", ctx->nfa_state_count);
    fprintf(file, "Initial: 0\n\n");

    // Write alphabet mapping
    fprintf(file, "Alphabet:\n");
    for (int i = 0; i < ctx->alphabet_size; i++) {
        fprintf(file, "  Symbol %d: %d-%d",
                ctx->alphabet[i].symbol_id,
                (int)ctx->alphabet[i].start_char,
                (int)ctx->alphabet[i].end_char);
        if (ctx->alphabet[i].is_special) {
            fprintf(file, " (special)");
        }
        fprintf(file, "\n");
    }
    fprintf(file, "\n");

    // Write states
    for (int i = 0; i < ctx->nfa_state_count; i++) {
        fprintf(file, "State %d:\n", i);
        fprintf(file, "  CategoryMask: 0x%02x\n", ctx->nfa[i].category_mask);
        fprintf(file, "  PatternId: %d\n", ctx->nfa[i].pattern_id);
        fprintf(file, "  EosTarget: %s\n", ctx->nfa[i].is_eos_target ? "yes" : "no");

        // Write capture markers
        if (ctx->nfa[i].capture_start_id >= 0) {
            const char* cap_name = nfa_capture_get_name(ctx, ctx->nfa[i].capture_start_id);
            if (cap_name) {
                fprintf(file, "  CaptureStart: %d %s\n", ctx->nfa[i].capture_start_id, cap_name);
            } else {
                fprintf(file, "  CaptureStart: %d\n", ctx->nfa[i].capture_start_id);
            }
        }
        if (ctx->nfa[i].capture_end_id >= 0) {
            const char* cap_name = nfa_capture_get_name(ctx, ctx->nfa[i].capture_end_id);
            if (cap_name) {
                fprintf(file, "  CaptureEnd: %d %s\n", ctx->nfa[i].capture_end_id, cap_name);
            } else {
                fprintf(file, "  CaptureEnd: %d\n", ctx->nfa[i].capture_end_id);
            }
        }

        if (ctx->nfa[i].tag_count > 0) {
            fprintf(file, "  Tags:");
            for (int j = 0; j < ctx->nfa[i].tag_count; j++) {
                fprintf(file, " %s", ctx->nfa[i].tags[j]);
            }
            fprintf(file, "\n");
        }

        fprintf(file, "  Transitions: %d\n", ctx->nfa[i].transition_count);

        for (int s = 0; s < MAX_SYMBOLS; s++) {
            int count = mta_get_target_count(&ctx->nfa[i].multi_targets, s);
            if (count > 0) {
                int* targets = mta_get_target_array(&ctx->nfa[i].multi_targets, s, &count);
                if (targets && count > 0) {
                    fprintf(file, "    Symbol %d -> ", s);
                    for (int k = 0; k < count; k++) {
                        fprintf(file, "%d%s", targets[k], (k < count - 1) ? "," : "");
                    }
                    // Write markers attached to this transition
                    int marker_count = 0;
                    transition_marker_t* markers = mta_get_markers(&ctx->nfa[i].multi_targets, s, &marker_count);
                    if (markers && marker_count > 0) {
                        fprintf(file, " [Markers:");
                        for (int m = 0; m < marker_count; m++) {
                            uint32_t full_marker = MARKER_PACK(markers[m].pattern_id, markers[m].uid, markers[m].type);
                            fprintf(file, " 0x%08X", full_marker);
                        }
                        fprintf(file, "]");
                    }
                    fprintf(file, "\n");
                }
            }
        }

        fprintf(file, "\n");
    }

    fclose(file);
    if (ctx->flag_verbose) {
        fprintf(stderr, "Wrote NFA with %d states and %d symbols to %s\n",
                ctx->nfa_state_count, ctx->alphabet_size, filename);
    }
}

void nfa_construct_cleanup(nfa_builder_context_t* ctx) {
    for (int i = 0; i < ctx->nfa_state_count; i++) {
        for (int j = 0; j < ctx->nfa[i].tag_count; j++) {
            free(ctx->nfa[i].tags[j]);
            ctx->nfa[i].tags[j] = NULL;
        }
        mta_free(&ctx->nfa[i].multi_targets);
    }

    for (int i = 0; i < SIGNATURE_TABLE_SIZE; i++) {
        StateSignature* entry = ctx->signature_table[i];
        while (entry != NULL) {
            StateSignature* next = entry->next;
            free(entry);
            entry = next;
        }
        ctx->signature_table[i] = NULL;
    }
}
