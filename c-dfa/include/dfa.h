#ifndef DFA_H
#define DFA_H

#include "dfa_types.h"
#include <stddef.h>

/**
 * Initialize the DFA evaluator
 *
 * @param dfa_data Pointer to DFA binary data
 * @param size Size of DFA data in bytes
 * @return true if DFA is valid, false otherwise
 */
bool dfa_init(const void* dfa_data, size_t size);

/**
 * Evaluate a string against the DFA
 *
 * @param input String to evaluate
 * @param length Length of string (0 for null-terminated)
 * @param result Pointer to store evaluation result
 * @return true if evaluation succeeded, false on error
 */
bool dfa_evaluate(const char* input, size_t length, dfa_result_t* result);

/**
 * Get the current DFA structure
 *
 * @return Pointer to current DFA, or NULL if not initialized
 */
const dfa_t* dfa_get_current(void);

/**
 * Get human-readable description of command category
 *
 * @param category Command category
 * @return String description
 */
const char* dfa_category_string(dfa_command_category_t category);

/**
 * Check if DFA is valid
 *
 * @return true if DFA is valid and initialized
 */
bool dfa_is_valid(void);

/**
 * Get DFA version
 *
 * @return DFA version number
 */
uint16_t dfa_get_version(void);

/**
 * Get number of states in DFA
 *
 * @return Number of states, or 0 if not initialized
 */
uint16_t dfa_get_state_count(void);

/**
 * Reset the DFA evaluator
 *
 * @return true if reset succeeded
 */
bool dfa_reset(void);

#endif // DFA_H