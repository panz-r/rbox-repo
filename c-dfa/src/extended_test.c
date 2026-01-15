#include "shell_tokenizer_ext.h"
#include <stdio.h>

int main() {
    printf("Extended Shell Tokenizer Test\n");
    printf("==============================\n\n");

    const char* test_commands[] = {
        "cat $FILE",
        "echo ${USER}",
        "ls *.txt",
        "grep $PATTERN *.log",
        "cat $(find .)",
        "process `ls`",
        "echo $1 $# $?",
        "rm file?.log",
        "find [a-z]*.txt"
    };

    size_t num_commands = sizeof(test_commands) / sizeof(test_commands[0]);

    for (size_t i = 0; i < num_commands; i++) {
        printf("Command %zu: %s\n", i + 1, test_commands[i]);
        printf("Tokens:\n");

        extended_shell_command_t* commands;
        size_t command_count;

        if (extended_shell_tokenize_commands(test_commands[i], &commands, &command_count)) {
            for (size_t j = 0; j < command_count; j++) {
                printf("  Command %zu.%zu:\n", i + 1, j + 1);

                for (size_t k = 0; k < commands[j].token_count; k++) {
                    extended_shell_token_t* token = &commands[j].tokens[k];
                    printf("    [%zu-%zu] %s: '%.*s'%s%s\n",
                           token->position, token->position + token->length - 1,
                           extended_shell_token_type_name(token->type),
                           (int)token->length, token->start,
                           token->is_quoted ? " (quoted)" : "",
                           token->is_escaped ? " (escaped)" : "");
                }

                printf("    Features: %s%s%s%s\n",
                       commands[j].has_variables ? "variables " : "",
                       commands[j].has_globs ? "globs " : "",
                       commands[j].has_subshells ? "subshells " : "",
                       commands[j].has_arithmetic ? "arithmetic " : "");
            }
            printf("\n");

            extended_shell_free_commands(commands, command_count);
        } else {
            printf("    Failed to tokenize\n\n");
        }
    }

    // Performance test
    printf("Performance Test\n");
    printf("================\n");

    const char* perf_command = "grep $PATTERN *.log | cat $(find .) > output.txt";
    printf("Command: %s\n", perf_command);

    for (int i = 0; i < 5; i++) {
        extended_shell_command_t* commands;
        size_t command_count;

        // Warm-up and timing would go here in real benchmark
        if (extended_shell_tokenize_commands(perf_command, &commands, &command_count)) {
            printf("Run %d: %zu commands, %zu total tokens\n",
                   i + 1, command_count,
                   commands[0].token_count + (command_count > 1 ? commands[1].token_count : 0));
            extended_shell_free_commands(commands, command_count);
        }
    }

    printf("\nTest complete!\n");
    return 0;
}