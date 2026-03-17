#ifndef DFA_INTERNAL_H
#define DFA_INTERNAL_H

/**
 * dfa_internal.h - State-passing DFA evaluation API
 *
 * All functions take an explicit dfa_machine_t* instead of using globals.
 * This enables multiple concurrent evaluators in the same process.
 */

#include "dfa_types.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Machine lifecycle
bool dfa_machine_init(dfa_machine_t* m, const void* dfa_data, size_t size);
bool dfa_machine_init_with_id(dfa_machine_t* m, const void* dfa_data, size_t size, const char* expected_id);
void dfa_machine_reset(dfa_machine_t* m);
bool dfa_machine_is_valid(const dfa_machine_t* m);

// Machine state queries
const dfa_t* dfa_machine_get_dfa(const dfa_machine_t* m);
const char* dfa_machine_get_identifier(const dfa_machine_t* m);
uint16_t dfa_machine_get_version(const dfa_machine_t* m);
uint16_t dfa_machine_get_state_count(const dfa_machine_t* m);

// Evaluation
bool dfa_machine_evaluate(const dfa_machine_t* m, const char* input, size_t length, dfa_result_t* result);
bool dfa_machine_evaluate_with_limit(const dfa_machine_t* m, const char* input, size_t length, dfa_result_t* result, int max_captures);

// Capture access (operate on result, no machine state needed)
int dfa_result_get_capture(const dfa_result_t* result, int index, const char** out_start, size_t* out_length);
const char* dfa_result_get_capture_name(const dfa_result_t* result, int index);
int dfa_result_get_capture_count(const dfa_result_t* result);
bool dfa_result_get_capture_by_index(const dfa_result_t* result, int index, size_t* out_start, size_t* out_length);

// Category string
const char* dfa_category_string(dfa_command_category_t category);

// File I/O (unchanged)
void* load_dfa_from_file(const char* filename, size_t* size);
bool save_dfa_to_file(const char* filename, const void* data, size_t size);
const char* get_dfa_identifier(const char* filename);

#ifdef __cplusplus
}
#endif

#endif // DFA_INTERNAL_H
