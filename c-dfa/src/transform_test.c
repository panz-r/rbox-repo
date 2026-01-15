#include "shell_transform.h"
#include "readonlybox.h"
#include <stdio.h>

int main() {
    printf("Shell-to-Semantic Transformation Test\n");
    printf("======================================\n\n");

    const char* test_commands[] = {
        "cat $FILE",
        "grep $PATTERN *.log",
        "cat $(find .)",
        "process $(cmd1) | filter $(cmd2)"
    };

    size_t num_commands = sizeof(test_commands) / sizeof(test_commands[0]);

    for (size_t i = 0; i < num_commands; i++) {
        printf("Test %zu: %s\n", i + 1, test_commands[i]);
        printf("\n");

        transformed_command_t** transformed_cmds;
        size_t transformed_count;

        if (shell_transform_command_line(test_commands[i], &transformed_cmds, &transformed_count)) {
            printf("Transformed into %zu command(s):\n", transformed_count);

            for (size_t j = 0; j < transformed_count; j++) {
                transformed_command_t* cmd = transformed_cmds[j];
                printf("\nCommand %zu.%zu:\n", i + 1, j + 1);
                printf("  Original:      '%s'\n", cmd->original_command);
                printf("  For DFA:       '%s'\n", cmd->transformed_command);
                printf("  Transformations: %s\n",
                       cmd->has_transformations ? "yes" : "no");
                printf("  Shell syntax:    %s\n",
                       cmd->has_shell_syntax ? "yes" : "no");

                if (cmd->token_count > 0) {
                    printf("  Token transformations:\n");
                    for (size_t k = 0; k < cmd->token_count; k++) {
                        transformed_token_t* token = &cmd->tokens[k];
                        printf("    '%.*s' → '%s' (%s)\n",
                               (int)(token->original - cmd->original_command),
                               token->original,
                               token->transformed,
                               extended_shell_token_type_name(token->type));
                    }
                }
            }
            printf("\n");

            // Show what DFA would see
            printf("DFA Validation Inputs:\n");
            for (size_t j = 0; j < transformed_count; j++) {
                const char* dfa_input = shell_get_dfa_input(transformed_cmds[j]);
                printf("  %zu: '%s'\n", j + 1, dfa_input);
            }
            printf("\n");

            shell_free_transformed_commands(transformed_cmds, transformed_count);
        } else {
            printf("Failed to transform command\n\n");
        }
    }

    // Demonstrate the semantic transformation philosophy
    printf("Transformation Philosophy\n");
    printf("========================\n\n");

    printf("Instead of making DFA understand shell syntax:\n");
    printf("  grep $PATTERN *.log  (complex for DFA)\n\n");

    printf("We transform to semantic equivalents:\n");
    printf("  grep VAR_VALUE FILE_PATTERN  (simple for DFA)\n\n");

    printf("Where:\n");
    printf("  $PATTERN      → VAR_VALUE      (variable becomes placeholder)\n");
    printf("  *.log         → FILE_PATTERN   (glob becomes file pattern)\n");
    printf("  $(find .)     → TEMP_FILE      (subshell becomes temp file)\n");
    printf("  |             → (handled by shell layer)\n\n");

    printf("Benefits:\n");
    printf("  ✅ DFA focuses on command semantics, not shell syntax\n");
    printf("  ✅ Shell layer handles shell constructs properly\n");
    printf("  ✅ Clean separation of concerns\n");
    printf("  ✅ Matches real shell execution model\n");
    printf("  ✅ Better security through proper layering\n\n");

    printf("Test complete!\n");
    return 0;
}