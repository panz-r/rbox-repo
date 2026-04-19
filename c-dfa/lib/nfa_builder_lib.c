/**
 * nfa_builder_lib.c - Library components from nfa_builder
 *
 * Contains context lifecycle and legacy compatibility functions
 * needed by the library (pipeline.c) and nfa2dfa.
 *
 * Compiled with -DNFABUILDER_NO_MAIN to exclude CLI code.
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "nfa_builder.h"
#include "../include/multi_target_array.h"

// ============================================================================
// Context Lifecycle
// ============================================================================

nfa_builder_context_t* nfa_builder_context_create(void) {
    // Context struct is ~25MB; use calloc for zero-initialization
    nfa_builder_context_t* ctx = calloc(1, sizeof(nfa_builder_context_t));
    if (!ctx) return NULL;

    // Zero-init via calloc handles most initialization
    // Set non-zero defaults
    ctx->current_pattern_index = -1;
    ctx->current_pattern_cat_mask = 0x01;
    ctx->nfa_state_count = 0;
    ctx->pattern_count = 0;
    ctx->alphabet_size = 0;
    ctx->fragment_count = 0;
    ctx->capture_count = 0;
    ctx->capture_stack_depth = 0;
    ctx->pending_marker_count = 0;
    ctx->last_element_sid = -1;
    ctx->pending_capture_defer_id = -1;
    ctx->prev_frag_exit = -1;
    ctx->current_fragment.exit_state = -1;
    ctx->current_fragment.anchor_state = -1;
    ctx->current_fragment.loop_entry_state = -1;
    ctx->dynamic_category_count = 0;
    ctx->categories_defined = false;
    ctx->category_mapping_count = 0;
    ctx->has_fragment_error = false;

    return ctx;
}

void nfa_builder_context_destroy(nfa_builder_context_t* ctx) {
    if (!ctx) return;
    // Free signature table linked lists
    for (int i = 0; i < SIGNATURE_TABLE_SIZE; i++) {
        state_signature_t* entry = ctx->signature_table[i];
        while (entry) {
            state_signature_t* next = entry->next;
            free(entry);
            entry = next;
        }
    }
    // Free NFA state tags
    for (int i = 0; i < ctx->nfa_state_count; i++) {
        for (int j = 0; j < ctx->nfa[i].tag_count; j++) {
            free(ctx->nfa[i].tags[j]);
        }
        mta_free(&ctx->nfa[i].multi_targets);
    }
    free(ctx);
}

// ============================================================================
// Legacy compatibility (used by nfa2dfa.c)
// ============================================================================

int find_symbol_id(unsigned char c) {
    return (int)c;
}
