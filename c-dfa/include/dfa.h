#ifndef DFA_H
#define DFA_H

/**
 * dfa.h - Public DFA Evaluation API
 *
 * FOR: Eval-only users who load pre-built binary DFAs and evaluate strings.
 * NOT FOR: Building or modifying DFAs (see dfa_internal.h and pipeline.h).
 *
 * Zero allocation. Pass pre-loaded binary DFA data and size directly.
 * No structs, no heap, no setup. Just eval.
 *
 * Usage:
 *   void* dfa_data = ...;  // Load DFA binary however appropriate
 *   size_t dfa_size = ...;
 *   dfa_result_t result;
 *   if (dfa_eval(dfa_data, dfa_size, input, strlen(input), &result)) {
 *       // matched - use result.category, result.captures, etc.
 *   }
 *   free(dfa_data);
 *
 * For building DFAs from pattern sets, see pipeline.h.
 */

#include "dfa_types.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Direct evaluation - pass binary DFA pointer and size
bool dfa_eval(const void* dfa_data, size_t dfa_size, const char* input, size_t length, dfa_result_t* result) __attribute__((nonnull));
bool dfa_eval_with_limit(const void* dfa_data, size_t dfa_size, const char* input, size_t length, dfa_result_t* result, int max_captures) __attribute__((nonnull));

// Result accessors (no machine state needed)
int dfa_result_get_capture(const dfa_result_t* result, int index, const char** out_start, size_t* out_length) __attribute__((nonnull));
const char* dfa_result_get_capture_name(const dfa_result_t* result, int index) __attribute__((nonnull));
int dfa_result_get_capture_count(const dfa_result_t* result) __attribute__((nonnull));
bool dfa_result_get_capture_by_index(const dfa_result_t* result, int index, size_t* out_start, size_t* out_length) ATTR_NONNULL(1);

// Post-eval capture resolution: needs dfa_data + input from eval call
bool dfa_result_get_capture_string(const dfa_result_t* result, int index,
                                    const void* dfa_data, size_t dfa_size,
                                    const char* input,
                                    const char** out_start, size_t* out_len,
                                    const char** out_name) ATTR_NONNULL(1, 3, 5);

// One-time DFA identifier check: verifies correct binary is loaded
// expected_id: the identifier string embedded in the DFA binary
// Returns true if match, false if mismatch or invalid
bool dfa_eval_validate_id(const void* dfa_data, size_t dfa_size, const char* expected_id) ATTR_NONNULL(1, 3);

// Free DFA data loaded via load_dfa_from_file()
void unload_dfa(void* data);

const char* dfa_category_string(dfa_command_category_t category);

#ifdef __cplusplus
}
#endif

#endif // DFA_H
