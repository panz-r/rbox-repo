#include "readonlybox.h"
#include "dfa.h"
#include "shell_tokenizer.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    printf("ReadOnlyBox Comprehensive Test\n");
    printf("==============================\n\n");

    // Test 1: Shell Tokenizer
    printf("TEST 1: Shell Tokenizer\n");
    printf("-----------------------\n");

    const char* test_command = "cat xx | less -G > rsr";
    printf("Command: %s\n\n", test_command);

    shell_command_t* commands;
    size_t command_count;

    if (shell_tokenize_commands(test_command, &commands, &command_count)) {
        printf("Tokenized into %zu command(s):\n", command_count);

        for (size_t i = 0; i < command_count; i++) {
            printf("\nCommand %zu:\n", i + 1);
            for (size_t j = 0; j < commands[i].token_count; j++) {
                shell_token_t* token = &commands[i].tokens[j];
                printf("  [%zu-%zu] %s: '%.*s'\n",
                       token->position, token->position + token->length - 1,
                       shell_token_type_name(token->type),
                       (int)token->length, token->start);
            }
        }

        printf("\nIndividual commands for DFA validation:\n");
        for (size_t i = 0; i < command_count; i++) {
            size_t length = commands[i].end_pos - commands[i].start_pos;
            printf("Command %zu: '%.*s'\n", i + 1, (int)length, test_command + commands[i].start_pos);
        }
        printf("\n");

        shell_free_commands(commands, command_count);
    } else {
        printf("Failed to tokenize command\n\n");
    }

    // Test 2: DFA Validation (if DFA is available)
    printf("TEST 2: DFA Validation\n");
    printf("----------------------\n");

    // Try to load a DFA if available
    const dfa_t* test_dfa = NULL;
    size_t dfa_size;
    void* dfa_data = load_dfa_from_file("readonlybox.dfa", &dfa_size);

    if (dfa_data != NULL && dfa_init(dfa_data, dfa_size)) {
        test_dfa = dfa_get_current();
        printf("Loaded DFA with %u states\n\n", dfa_get_state_count());
    } else {
        printf("No DFA available - real DFA evaluation required\n\n");
        printf("TEST 2: DFA Validation - SKIPPED (no DFA file available)\n");
        printf("--------------------------------------------------------\n\n");

        // Skip to Test 3
        goto test3;
    }

    // Test individual commands
    const char* test_commands[] = {
        "cat file.txt",
        "grep pattern *",
        "rm -rf /",
        "git log --oneline",
        "find . -name *.txt"
    };

    ro_validation_context_t ctx;
    ro_init_context(&ctx, test_dfa);

    for (size_t i = 0; i < sizeof(test_commands) / sizeof(test_commands[0]); i++) {
        ro_command_result_t result = ro_validate_command(&ctx, test_commands[i]);
        printf("Command: '%s' -> %s\n", test_commands[i], ro_result_string(result));
    }

    printf("\n");

    // Cleanup DFA
    if (dfa_data != NULL) {
        free(dfa_data);
        dfa_reset();
        dfa_data = NULL;
    }

    // Test 3: Complete Command Line Validation
    test3:
    printf("TEST 3: Complete Command Line Validation\n");
    printf("---------------------------------------\n");

    const char* complex_commands[] = {
        "cat file.txt | grep pattern",
        "git log --oneline | head -10 > output.txt",
        "rm -rf / && echo 'done'",
        "find . -name *.txt | xargs cat"
    };

    for (size_t i = 0; i < sizeof(complex_commands) / sizeof(complex_commands[0]); i++) {
        ro_command_result_t result = ro_validate_command_line(&ctx, complex_commands[i]);
        printf("Command: '%s'\n", complex_commands[i]);
        printf("Overall: %s\n", ro_result_string(result));

        // Detailed breakdown
        ro_command_result_t* individual_results = NULL;
        size_t individual_count = 0;

        if (ro_validate_detailed(&ctx, complex_commands[i], &result, &individual_results, &individual_count)) {
            printf("Individual commands:\n");
            for (size_t j = 0; j < individual_count; j++) {
                printf("  %zu: %s\n", j + 1, ro_result_string(individual_results[j]));
            }
            ro_free_detailed_results(individual_results);
        }
        printf("\n");
    }

    // Cleanup
    if (dfa_data != NULL) {
        free(dfa_data);
        dfa_reset();
    }

    return 0;

    printf("TEST COMPLETE\n");
    return 0;
}