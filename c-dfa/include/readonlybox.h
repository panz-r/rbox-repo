#ifndef READONLYBOX_H
#define READONLYBOX_H

#include "dfa.h"
#include "shell_tokenizer.h"
#include "shell_processor.h"
#include "shell_transform.h"
#include <stdbool.h>

/**
 * ReadOnlyBox - Complete read-only command validation system
 *
 * This system combines:
 * 1. Shell command tokenizer (splits complex commands into individual commands)
 * 2. DFA-based command validation (fast pattern matching)
 * 3. Semantic analysis (detailed command validation)
 */

/**
 * Command validation result
 */
typedef enum {
    RO_CMD_SAFE,           // Command is safe and read-only
    RO_CMD_CAUTION,        // Command is read-only but needs caution
    RO_CMD_MODIFYING,      // Command modifies filesystem
    RO_CMD_DANGEROUS,      // Command is potentially dangerous
    RO_CMD_NETWORK,        // Command involves network operations
    RO_CMD_ADMIN,          // Command requires admin privileges
    RO_CMD_UNKNOWN,        // Command status unknown
    RO_CMD_ERROR           // Error in validation
} ro_command_result_t;

/**
 * Command validation context
 */
typedef struct {
    const dfa_t* dfa;              // DFA for fast validation
    bool use_semantic_analysis;    // Enable detailed semantic analysis
    bool allow_network;            // Allow network commands
    bool allow_admin;              // Allow admin commands
} ro_validation_context_t;

/**
 * Initialize validation context
 */
void ro_init_context(ro_validation_context_t* ctx, const dfa_t* dfa);

/**
 * Validate a complete shell command line
 *
 * This function:
 * 1. Tokenizes the command line into individual commands
 * 2. Validates each command using DFA
 * 3. Performs semantic analysis if needed
 * 4. Returns the overall safety level
 */
ro_command_result_t ro_validate_command_line(
    ro_validation_context_t* ctx,
    const char* command_line
);

/**
 * Validate individual command (after tokenization)
 */
ro_command_result_t ro_validate_command(
    ro_validation_context_t* ctx,
    const char* command
);

/**
 * Get human-readable result name
 */
const char* ro_result_string(ro_command_result_t result);

/**
 * Validate command line and get detailed breakdown
 */
bool ro_validate_detailed(
    ro_validation_context_t* ctx,
    const char* command_line,
    ro_command_result_t* overall_result,
    ro_command_result_t** individual_results,
    size_t* individual_count
);

/**
 * Free detailed validation results
 */
void ro_free_detailed_results(ro_command_result_t* results);

#endif // READONLYBOX_H