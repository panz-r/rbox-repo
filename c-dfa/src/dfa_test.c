#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <dfa_file> [command...]\n", argv[0]);
        return 1;
    }

    const char* dfa_file = argv[1];

    // Load DFA
    FILE* file = fopen(dfa_file, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot open %s\n", dfa_file);
        return 1;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Read DFA data
    void* dfa_data = malloc(size);
    if (dfa_data == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(file);
        return 1;
    }

    fread(dfa_data, 1, size, file);
    fclose(file);

    // Initialize DFA
    if (!dfa_init(dfa_data, size)) {
        fprintf(stderr, "Error: Invalid DFA file\n");
        free(dfa_data);
        return 1;
    }

    printf("Loaded DFA with %d states (version %d)\n\n",
           dfa_get_state_count(), dfa_get_version());

    // Test commands
    if (argc < 3) {
        // Interactive mode
        printf("Enter commands to test (Ctrl+D to exit):\n");
        char line[1024];
        while (fgets(line, sizeof(line), stdin)) {
            // Remove newline
            size_t len = strlen(line);
            if (len > 0 && line[len-1] == '\n') {
                line[len-1] = '\0';
            }

            if (line[0] == '\0') continue;

            // Evaluate command
            dfa_result_t result;
            if (dfa_evaluate(line, 0, &result)) {
                printf("Command: %s\n", line);
                printf("  Category: %s\n", dfa_category_string(result.category));
                printf("  Matched: %s\n", result.matched ? "yes" : "no");
                printf("  Length: %zu\n\n", result.matched_length);
            }
        }
    } else {
        // Batch mode
        for (int i = 2; i < argc; i++) {
            dfa_result_t result;
            if (dfa_evaluate(argv[i], 0, &result)) {
                printf("Command: %s\n", argv[i]);
                printf("  Category: %s\n", dfa_category_string(result.category));
                printf("  Matched: %s\n", result.matched ? "yes" : "no");
                printf("  Length: %zu\n\n", result.matched_length);
            }
        }
    }

    // Cleanup
    dfa_reset();
    free(dfa_data);

    return 0;
}
