#ifndef DFA_H
#define DFA_H

#include "dfa_types.h"

bool dfa_init(const void* dfa_data, size_t size);
bool dfa_evaluate(const char* input, size_t length, dfa_result_t* result);
const dfa_t* dfa_get_current(void);
const char* dfa_category_string(dfa_command_category_t category);
bool dfa_is_valid(void);
uint16_t dfa_get_version(void);
uint16_t dfa_get_state_count(void);
bool dfa_reset(void);
int dfa_get_capture(const dfa_result_t* result, int index, const char** out_start, size_t* out_length);
const char* dfa_get_capture_name(const dfa_result_t* result, int index);

#endif // DFA_H
