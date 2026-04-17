#ifndef DFA_INTERNAL_H
#define DFA_INTERNAL_H

/**
 * dfa_internal.h - DFA Machine Lifecycle and State Management
 *
 * FOR: Machine builders / library internal code that manages DFA lifecycle.
 * FOR: Applications that need multiple concurrent DFA evaluators.
 * NOT FOR: Eval-only users (see dfa.h for the simple eval API).
 *
 * This header provides the dfa_machine_t struct for applications that need
 * to hold DFA state (validation, identifier checking, concurrent evaluators).
 * For simple eval-only use, prefer dfa_eval() from dfa.h which needs no struct.
 *
 * Usage:
 *   dfa_machine_t machine;
 *   if (dfa_machine_init(&machine, dfa_data, dfa_size)) {
 *       dfa_result_t result;
 *       dfa_machine_evaluate(&machine, input, strlen(input), &result);
 *   }
 *
 * For building DFAs from pattern sets, see pipeline.h.
 */

#include "dfa.h"
#include "dfa_format.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Machine lifecycle
bool dfa_machine_init(dfa_machine_t* m, const void* dfa_data, size_t size) ATTR_NONNULL(1, 2);
bool dfa_machine_init_with_id(dfa_machine_t* m, const void* dfa_data, size_t size, const char* expected_id) ATTR_NONNULL(1, 2);
void dfa_machine_reset(dfa_machine_t* m) ATTR_NONNULL(1);
bool dfa_machine_is_valid(const dfa_machine_t* m) ATTR_NONNULL(1);

// Machine state queries
const dfa_t* dfa_machine_get_dfa(const dfa_machine_t* m) ATTR_NONNULL(1);
const char* dfa_machine_get_identifier(const dfa_machine_t* m) ATTR_NONNULL(1);
uint16_t dfa_machine_get_version(const dfa_machine_t* m) ATTR_NONNULL(1);
uint16_t dfa_machine_get_state_count(const dfa_machine_t* m) ATTR_NONNULL(1);

// Builder file I/O (not in eval library)
void* load_dfa_from_file(const char* filename, size_t* size) ATTR_NONNULL(1);

#ifdef __cplusplus
}
#endif

#endif // DFA_INTERNAL_H
