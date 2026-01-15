#include "readonlybox.h"
#include "shell_tokenizer.h"
#include <stdio.h>

int main() {
    printf("Specific Command Validation Test\n");
    printf("================================\n\n");

    const char* command = "cat file.txt | grep pattern > out.txt 2>&1";
    printf("Command: %s\n\n", command);

    // Initialize validation context (no DFA for this demo)
    ro_validation_context_t ctx;
    ro_init_context(&ctx, NULL);

    // Tokenize the command
    printf("1. TOKENIZATION PHASE\n");
    printf("---------------------\n");

    shell_command_t* commands;
    size_t command_count;

    if (!shell_tokenize_commands(command, &commands, &command_count)) {
        printf("Failed to tokenize command\n");
        return 1;
    }

    printf("Found %zu command(s):\n\n", command_count);

    for (size_t i = 0; i < command_count; i++) {
        printf("Command %zu:\n", i + 1);

        for (size_t j = 0; j < commands[i].token_count; j++) {
            shell_token_t* token = &commands[i].tokens[j];
            printf("  [%zu-%zu] %s: '%.*s'\n",
                   token->position, token->position + token->length - 1,
                   shell_token_type_name(token->type),
                   (int)token->length, token->start);
        }

        // Extract command text
        size_t length = commands[i].end_pos - commands[i].start_pos;
        printf("  Extracted command: '%.*s'\n",
               (int)length, command + commands[i].start_pos);
        printf("\n");
    }

    // Show individual commands for DFA validation
    printf("2. INDIVIDUAL COMMAND EXTRACTION\n");
    printf("--------------------------------\n");

    for (size_t i = 0; i < command_count; i++) {
        size_t length = commands[i].end_pos - commands[i].start_pos;
        printf("Command %zu for DFA: '%.*s'\n",
               i + 1, (int)length, command + commands[i].start_pos);
    }
    printf("\n");

    // Simulate DFA validation (mock results since we don't have DFA loaded)
    printf("3. DFA VALIDATION PHASE (simulated)\n");
    printf("------------------------------------\n");

    printf("Command 1 'cat file.txt':\n");
    printf("  DFA path: start -> 'c' -> 'ca' -> 'cat' (accepting)\n");
    printf("  Result: RO_CMD_SAFE (cat is read-only)\n\n");

    printf("Command 2 'grep pattern > out.txt 2>&1':\n");
    printf("  DFA path: start -> 'g' -> 'gr' -> 'gre' -> 'grep' (accepting)\n");
    printf("  Redirections: > (output), 2>&1 (error to output)\n");
    printf("  Result: RO_CMD_SAFE (grep is read-only, redirections don't change safety)\n\n");

    // Overall result
    printf("4. OVERALL RESULT\n");
    printf("----------------\n");
    printf("Most severe result: RO_CMD_SAFE\n");
    printf("Final decision: COMMAND IS SAFE\n\n");

    // Cleanup
    shell_free_commands(commands, command_count);

    printf("Test complete!\n");
    return 0;
}