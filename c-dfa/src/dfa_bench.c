#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

// Simple benchmarking function
double get_time_in_seconds() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <dfa_file> <iterations>\n", argv[0]);
        return 1;
    }

    const char* dfa_file = argv[1];
    int iterations = atoi(argv[2]);

    // Load DFA
    size_t dfa_size;
    void* dfa_data = load_dfa_from_file(dfa_file, &dfa_size);
    if (dfa_data == NULL) {
        printf("Failed to load DFA from %s\n", dfa_file);
        return 1;
    }

    // Initialize DFA
    if (!dfa_init(dfa_data, dfa_size)) {
        printf("Failed to initialize DFA\n");
        free(dfa_data);
        return 1;
    }

    // Test commands
    const char* test_commands[] = {
        "cat file.txt",
        "ls -la",
        "grep pattern file.txt",
        "find . -name *.txt",
        "ps aux",
        "df -h",
        "du -sh /home",
        "git log --oneline",
        "git show HEAD",
        "git status",
        "rm -rf /",
        "sudo rm -rf /",
        "dd if=/dev/sda of=/dev/null",
        "chmod 777 file.txt",
        "chown user:group file.txt"
    };
    int num_commands = sizeof(test_commands) / sizeof(test_commands[0]);

    printf("Running DFA benchmark with %d iterations...\n", iterations);
    printf("Testing %d commands\n", num_commands);

    double start_time = get_time_in_seconds();

    for (int i = 0; i < iterations; i++) {
        for (int j = 0; j < num_commands; j++) {
            dfa_result_t result;
            dfa_evaluate(test_commands[j], 0, &result);
        }
    }

    double end_time = get_time_in_seconds();
    double total_time = end_time - start_time;

    int total_evaluations = iterations * num_commands;
    double time_per_evaluation = total_time / total_evaluations * 1e6; // microseconds
    double evaluations_per_second = total_evaluations / total_time;

    printf("\nBenchmark Results:\n");
    printf("Total time: %.3f seconds\n", total_time);
    printf("Total evaluations: %d\n", total_evaluations);
    printf("Time per evaluation: %.3f μs\n", time_per_evaluation);
    printf("Evaluations per second: %.0f\n", evaluations_per_second);

    // Print some sample results
    printf("\nSample results:\n");
    for (int j = 0; j < 5 && j < num_commands; j++) {
        dfa_result_t result;
        dfa_evaluate(test_commands[j], 0, &result);
        printf("%s -> %s (%s)\n", test_commands[j],
               result.matched ? "MATCHED" : "NO MATCH",
               dfa_category_string(result.category));
    }

    // Cleanup
    dfa_reset();
    free(dfa_data);

    return 0;
}