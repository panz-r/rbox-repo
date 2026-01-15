#include "readonlybox.h"
#include "dfa.h"
#include "shell_tokenizer.h"
#include <string.h>
#include <stdlib.h>

// Initialize validation context
void ro_init_context(ro_validation_context_t* ctx, const dfa_t* dfa) {
    if (ctx == NULL) return;

    ctx->dfa = dfa;
    ctx->use_semantic_analysis = true;
    ctx->allow_network = false;
    ctx->allow_admin = false;
}

// Convert DFA result to RO result
static ro_command_result_t dfa_to_ro_result(dfa_command_category_t category) {
    switch (category) {
        case DFA_CMD_READONLY_SAFE: return RO_CMD_SAFE;
        case DFA_CMD_READONLY_CAUTION: return RO_CMD_CAUTION;
        case DFA_CMD_MODIFYING: return RO_CMD_MODIFYING;
        case DFA_CMD_DANGEROUS: return RO_CMD_DANGEROUS;
        case DFA_CMD_NETWORK: return RO_CMD_NETWORK;
        case DFA_CMD_ADMIN: return RO_CMD_ADMIN;
        default: return RO_CMD_UNKNOWN;
    }
}

// Validate individual command using DFA
ro_command_result_t ro_validate_command(
    ro_validation_context_t* ctx,
    const char* command
) {
    if (ctx == NULL || command == NULL || ctx->dfa == NULL) {
        return RO_CMD_ERROR;
    }

    dfa_result_t dfa_result;
    if (!dfa_evaluate(command, 0, &dfa_result)) {
        return RO_CMD_ERROR;
    }

    if (!dfa_result.matched) {
        // Command not recognized by DFA - need semantic analysis
        if (ctx->use_semantic_analysis) {
            // TODO: Implement semantic analysis
            // For now, be conservative and mark as unknown
            return RO_CMD_UNKNOWN;
        }
        return RO_CMD_UNKNOWN;
    }

    return dfa_to_ro_result(dfa_result.category);
}

// Validate complete command line with shell-to-semantic transformation and fallback
ro_command_result_t ro_validate_command_line(
    ro_validation_context_t* ctx,
    const char* command_line
) {
    if (ctx == NULL || command_line == NULL) {
        return RO_CMD_ERROR;
    }

    // Try enhanced validation with transformation
    transformed_command_t** transformed_cmds = NULL;
    size_t transformed_count = 0;

    if (shell_transform_command_line(command_line, &transformed_cmds, &transformed_count)) {
        if (transformed_count == 0) {
            // Empty command is safe
            shell_free_transformed_commands(transformed_cmds, transformed_count);
            return RO_CMD_SAFE;
        }

        // Validate each transformed command (semantic equivalents)
        ro_command_result_t overall_result = RO_CMD_SAFE;

        for (size_t i = 0; i < transformed_count; i++) {
            const char* dfa_input = shell_get_dfa_input(transformed_cmds[i]);

            // Validate the transformed command
            ro_command_result_t result = ro_validate_command(ctx, dfa_input);

            // Update overall result (take the most severe)
            if (result > overall_result) {
                overall_result = result;
            }

            // Early exit for dangerous commands
            if (overall_result == RO_CMD_DANGEROUS) {
                break;
            }
        }

        // Free transformed commands
        shell_free_transformed_commands(transformed_cmds, transformed_count);
        return overall_result;
    }

    // Enhanced validation failed - try shell processor fallback
    const char** clean_commands = NULL;
    size_t command_count = 0;
    bool has_shell_features = false;

    if (shell_extract_dfa_inputs(command_line, &clean_commands, &command_count, &has_shell_features)) {
        if (command_count == 0) {
            // Empty command is safe
            if (clean_commands) free(clean_commands);
            return RO_CMD_SAFE;
        }

        // Validate clean commands (no transformation)
        ro_command_result_t overall_result = RO_CMD_SAFE;

        for (size_t i = 0; i < command_count; i++) {
            ro_command_result_t result = ro_validate_command(ctx, clean_commands[i]);

            if (result > overall_result) {
                overall_result = result;
            }

            if (overall_result == RO_CMD_DANGEROUS) {
                break;
            }
        }

        // Free clean command strings
        for (size_t i = 0; i < command_count; i++) {
            free((void*)clean_commands[i]);
        }
        free(clean_commands);

        return overall_result;
    }

    // Shell processor failed - try direct DFA validation as last resort
    return ro_validate_command(ctx, command_line);
}

// Validate with detailed breakdown
bool ro_validate_detailed(
    ro_validation_context_t* ctx,
    const char* command_line,
    ro_command_result_t* overall_result,
    ro_command_result_t** individual_results,
    size_t* individual_count
) {
    if (ctx == NULL || command_line == NULL || overall_result == NULL) {
        return false;
    }

    // Tokenize the command line
    shell_command_t* commands;
    size_t command_count;

    if (!shell_tokenize_commands(command_line, &commands, &command_count)) {
        return false;
    }

    if (command_count == 0) {
        if (individual_results != NULL) *individual_results = NULL;
        if (individual_count != NULL) *individual_count = 0;
        *overall_result = RO_CMD_SAFE;
        return true;
    }

    // Allocate results array
    ro_command_result_t* results = NULL;
    if (individual_results != NULL) {
        results = malloc(command_count * sizeof(ro_command_result_t));
        if (results == NULL) {
            shell_free_commands(commands, command_count);
            return false;
        }
    }

    // Validate each command
    ro_command_result_t overall = RO_CMD_SAFE;

    for (size_t i = 0; i < command_count; i++) {
        size_t length = commands[i].end_pos - commands[i].start_pos;
        const char* command_text = command_line + commands[i].start_pos;

        ro_command_result_t result = ro_validate_command(ctx, command_text);

        if (results != NULL) {
            results[i] = result;
        }

        if (result > overall) {
            overall = result;
        }
    }

    *overall_result = overall;
    if (individual_results != NULL) *individual_results = results;
    if (individual_count != NULL) *individual_count = command_count;

    shell_free_commands(commands, command_count);
    return true;
}

// Free detailed results
void ro_free_detailed_results(ro_command_result_t* results) {
    if (results != NULL) {
        free(results);
    }
}

// Get human-readable result name
const char* ro_result_string(ro_command_result_t result) {
    switch (result) {
        case RO_CMD_SAFE: return "Safe (Read-only)";
        case RO_CMD_CAUTION: return "Caution (Read-only)";
        case RO_CMD_MODIFYING: return "Modifying";
        case RO_CMD_DANGEROUS: return "Dangerous";
        case RO_CMD_NETWORK: return "Network";
        case RO_CMD_ADMIN: return "Admin";
        case RO_CMD_UNKNOWN: return "Unknown";
        case RO_CMD_ERROR: return "Error";
        default: return "Invalid";
    }
}