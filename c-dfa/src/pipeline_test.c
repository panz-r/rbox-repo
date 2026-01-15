#include "shell_processor.h"
#include "readonlybox.h"
#include <stdio.h>

int main() {
    printf("Pipeline Command Extraction Test\n");
    printf("==================================\n\n");

    const char* test_commands[] = {
        "cat file.txt | grep pattern",
        "echo hello | cat | tail -5",
        "./target/release/cppr /tmp/test_tiny.c | tail -20",
        "ls -la | grep '.txt' | head -10"
    };

    size_t num_commands = sizeof(test_commands) / sizeof(test_commands[0]);

    for (size_t i = 0; i < num_commands; i++) {
        printf("Test %zu: %s\n", i + 1, test_commands[i]);
        printf("\n");

        const char** dfa_inputs;
        size_t dfa_input_count;
        bool has_shell_features;

        if (shell_extract_dfa_inputs(test_commands[i], &dfa_inputs, &dfa_input_count, &has_shell_features)) {
            printf("Extracted %zu individual command(s):\n", dfa_input_count);

            for (size_t j = 0; j < dfa_input_count; j++) {
                printf("  Command %zu: '%s'\n", j + 1, dfa_inputs[j]);
            }

            printf("Shell features detected: %s\n", has_shell_features ? "yes" : "no");

            // Free allocated strings
            for (size_t j = 0; j < dfa_input_count; j++) {
                free((void*)dfa_inputs[j]);
            }
            free(dfa_inputs);
        } else {
            printf("Failed to extract commands\n");
        }
        printf("\n");
    }

    // Test the specific example from the user
    printf("Specific Example Test\n");
    printf("====================\n\n");

    const char* specific_command = "./target/release/cppr /tmp/test_tiny.c | tail -20";
    printf("Command: %s\n\n", specific_command);

    if (shell_extract_dfa_inputs(specific_command, &dfa_inputs, &dfa_input_count, &has_shell_features)) {
        printf("This pipeline contains %zu commands:\n", dfa_input_count);
        for (size_t j = 0; j < dfa_input_count; j++) {
            printf("  %zu: '%s'\n", j + 1, dfa_inputs[j]);
        }

        printf("\nDFA will validate each command separately:\n");
        for (size_t j = 0; j < dfa_input_count; j++) {
            printf("  Validating: '%s'\n", dfa_inputs[j]);
        }

        // Free allocated strings
        for (size_t j = 0; j < dfa_input_count; j++) {
            free((void*)dfa_inputs[j]);
        }
        free(dfa_inputs);
    } else {
        printf("Failed to extract commands\n");
    }

    printf("\nTest complete!\n");
    return 0;
}