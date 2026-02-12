#ifndef DFA_H
#define DFA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "dfa_types.h"

bool dfa_init(const void* dfa_data, size_t size);
bool dfa_init_with_identifier(const void* dfa_data, size_t size, const char* expected_identifier);
bool dfa_evaluate(const char* input, size_t length, dfa_result_t* result);
bool dfa_evaluate_with_limit(const char* input, size_t length, dfa_result_t* result, int max_captures);
const dfa_t* dfa_get_current(void);
const char* dfa_category_string(dfa_command_category_t category);
bool dfa_is_valid(void);
const char* dfa_get_identifier(void);
uint16_t dfa_get_version(void);
uint16_t dfa_get_state_count(void);
bool dfa_reset(void);
int dfa_get_capture(const dfa_result_t* result, int index, const char** out_start, size_t* out_length);
const char* dfa_get_capture_name(const dfa_result_t* result, int index);
int dfa_get_capture_count(const dfa_result_t* result);
bool dfa_get_capture_by_index(const dfa_result_t* result, int index, size_t* out_start, size_t* out_length);
void* load_dfa_from_file(const char* filename, size_t* size);
const char* get_dfa_identifier(const char* filename);
bool save_dfa_to_file(const char* filename, const void* data, size_t size);
const char* lookup_capture_name(const void* dfa_data, uint16_t uid);

#ifdef __cplusplus
}
#endif

#endif // DFA_H
