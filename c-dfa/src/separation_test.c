#include "shell_processor.h"
#include "readonlybox.h"
#include <stdio.h>

int main() {
    printf("Shell-Command Separation Test\n");
    printf("==============================\n\n");

    const char* command = "cat file.txt | grep pattern > out.txt 2>&1";
    printf("Original command: %s\n\n", command);

    // Process with proper separation
    printf("1. SHELL PROCESSING PHASE\n");
    printf("--------------------------\n");

    shell_command_info_t* infos;
    size_t count;

    if (!shell_process_command(command, &infos, &count)) {
        printf("Failed to process command\n");
        return 1;
    }

    printf("Found %zu command(s) with proper separation:\n\n", count);

    for (size_t i = 0; i < count; i++) {
        printf("Command %zu:\n", i + 1);
        printf("  Original: '%s'\n", infos[i].original_command);
        printf("  Clean for DFA: '%s'\n", infos[i].clean_command);
        printf("  Shell features: %s\n",
               infos[i].has_redirections ? "redirections" : "none");
        printf("  Tokens: %zu command, %zu shell\n",
               infos[i].command_token_count, infos[i].shell_token_count);
        printf("\n");
    }

    // Extract DFA inputs
    printf("2. DFA INPUT EXTRACTION\n");
    printf("-----------------------\n");

    const char** dfa_inputs;
    size_t dfa_count;
    bool has_features;

    if (!shell_extract_dfa_inputs(command, &dfa_inputs, &dfa_count, &has_features)) {
        printf("Failed to extract DFA inputs\n");
        shell_free_command_infos(infos, count);
        return 1;
    }

    printf("DFA will validate %zu clean command(s):\n", dfa_count);
    for (size_t i = 0; i < dfa_count; i++) {
        printf("  %zu: '%s'\n", i + 1, dfa_inputs[i]);
    }
    printf("Shell features present: %s\n\n", has_features ? "yes" : "no");

    // Validate with ReadOnlyBox
    printf("3. READONLYBOX VALIDATION\n");
    printf("-------------------------\n");

    ro_validation_context_t ctx;
    ro_init_context(&ctx, NULL); // No DFA for demo

    printf("Validation process:\n");
    printf("  1. Shell processor separates shell logic from commands\n");
    printf("  2. DFA receives clean commands without shell syntax\n");
    printf("  3. Shell layer handles pipes and redirections\n");
    printf("  4. Overall safety determined by most severe command\n\n");

    printf("For our example:\n");
    printf("  Command 1 for DFA: 'cat file.txt' (no shell syntax)\n");
    printf("  Command 2 for DFA: 'grep pattern' (no shell syntax)\n");
    printf("  Shell layer handles: | > 2>&1\n");
    printf("  DFA focuses on: cat and grep semantics only\n\n");

    // Cleanup
    for (size_t i = 0; i < dfa_count; i++) {
        free((void*)dfa_inputs[i]);
    }
    free(dfa_inputs);
    shell_free_command_infos(infos, count);

    // Show the architectural benefit
    printf("4. ARCHITECTURAL BENEFITS\n");
    printf("-------------------------\n");
    printf("✅ Shell syntax handled by shell layer (tokenizer/processor)\n");
    printf("✅ Command semantics handled by DFA layer\n");
    printf("✅ Clear separation of concerns\n");
    printf("✅ Matches real shell execution model\n");
    printf("✅ DFA focuses on what it does best: command validation\n");
    printf("✅ Shell layer handles what it does best: shell syntax\n\n");

    printf("Test complete!\n");
    return 0;
}