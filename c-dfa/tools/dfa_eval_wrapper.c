// DFA Eval Wrapper - Standalone binary for fuzzing subprocess execution
// This wrapper evaluates a command string against the DFA and exits with status:
//   0 = success (matched or no match, no errors)
//   1 = validation error (DFA sanity check failed - indicates a bug)
//   2 = initialization error (could not load DFA)
//   127 = exec/setup error

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <errno.h>

#include "../include/dfa_internal.h"
#include "../include/dfa_types.h"

// Resource limits (can be overridden via environment)
#define DEFAULT_MEMORY_LIMIT (2ULL * 1024 * 1024 * 1024)  // 2GB
#define DEFAULT_CPU_LIMIT 5  // 5 seconds

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s <dfa_file> <command_string>\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Evaluates a command string against the DFA.\n");
    fprintf(stderr, "Exit codes:\n");
    fprintf(stderr, "  0 = success (DFA evaluation completed)\n");
    fprintf(stderr, "  1 = validation error (DFA bug detected)\n");
    fprintf(stderr, "  2 = initialization error\n");
    fprintf(stderr, "  127 = setup error\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Environment:\n");
    fprintf(stderr, "  DFA_EVAL_MEMORY_LIMIT - Memory limit in bytes (default: 2GB)\n");
    fprintf(stderr, "  DFA_EVAL_CPU_LIMIT - CPU time limit in seconds (default: 5)\n");
}

static bool set_resource_limits(void) {
    struct rlimit rl;
    const char* mem_env = getenv("DFA_EVAL_MEMORY_LIMIT");
    const char* cpu_env = getenv("DFA_EVAL_CPU_LIMIT");

    rlim_t memory_limit = mem_env ? (rlim_t)atoll(mem_env) : DEFAULT_MEMORY_LIMIT;
    rlim_t cpu_limit = cpu_env ? (rlim_t)atoi(cpu_env) : DEFAULT_CPU_LIMIT;

    // Set memory limit
    rl.rlim_cur = rl.rlim_max = memory_limit;
    if (setrlimit(RLIMIT_AS, &rl) != 0) {
        fprintf(stderr, "ERROR: Failed to set memory limit: %s\n", strerror(errno));
        return false;
    }

    // Set CPU time limit
    rl.rlim_cur = rl.rlim_max = cpu_limit;
    if (setrlimit(RLIMIT_CPU, &rl) != 0) {
        fprintf(stderr, "ERROR: Failed to set CPU limit: %s\n", strerror(errno));
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        print_usage(argv[0]);
        return 127;
    }

    const char* dfa_file = argv[1];
    const char* command = argv[2];

    // Set resource limits
    if (!set_resource_limits()) {
        return 127;
    }

    // Load DFA from file
    size_t dfa_size = 0;
    void* dfa_data = load_dfa_from_file(dfa_file, &dfa_size);
    if (!dfa_data) {
        fprintf(stderr, "ERROR: Could not load DFA from %s\n", dfa_file);
        return 2;
    }

    // Initialize DFA machine (no globals)
    dfa_machine_t machine;
    if (!dfa_machine_init(&machine, dfa_data, dfa_size)) {
        fprintf(stderr, "ERROR: DFA initialization failed\n");
        free(dfa_data);
        return 2;
    }

    // Evaluate the command
    dfa_result_t result;
    bool ok = dfa_machine_evaluate_with_limit(&machine, command, strlen(command), &result, DFA_MAX_CAPTURES);

    int exit_code = 0;  // Success by default

    if (ok) {
        // Sanity checks - these should NEVER trigger if DFA is correct

        // Capture count should fit in array
        if (result.capture_count > DFA_MAX_CAPTURES) {
            fprintf(stderr, "ERROR: capture_count=%d exceeds MAX_CAPTURES=%d\n",
                    result.capture_count, DFA_MAX_CAPTURES);
            exit_code = 1;  // Validation error
        }

        // Captures should be in bounds
        size_t len = strlen(command);
        for (int i = 0; i < result.capture_count && exit_code == 0; i++) {
            if (result.captures[i].start > len || result.captures[i].end > len) {
                fprintf(stderr, "ERROR: capture %d out of bounds: start=%zu end=%zu size=%zu\n",
                        i, result.captures[i].start, result.captures[i].end, len);
                exit_code = 1;
            }
            if (result.captures[i].start > result.captures[i].end && exit_code == 0) {
                fprintf(stderr, "ERROR: capture %d start > end: %zu > %zu\n",
                        i, result.captures[i].start, result.captures[i].end);
                exit_code = 1;
            }
        }

        // Category should be valid (fixed: now checks up to CONTAINER)
        if (exit_code == 0 && (result.category < DFA_CMD_UNKNOWN || result.category > DFA_CMD_CONTAINER)) {
            fprintf(stderr, "ERROR: invalid category: %d\n", result.category);
            exit_code = 1;
        }

        // Output result for debugging (to stdout, so it can be captured if needed)
        printf("matched=%d category=%d (%s) category_mask=0x%02x captures=%d",
               result.matched,
               result.category,
               dfa_category_string(result.category),
               result.category_mask,
               result.capture_count);
        
        // Output capture details if present
        for (int i = 0; i < result.capture_count; i++) {
            size_t start = result.captures[i].start;
            size_t end = result.captures[i].end;
            // Extract captured substring if valid
            if (start < strlen(command) && end <= strlen(command) && start < end) {
                size_t cap_len = end - start;
                char* captured = malloc(cap_len + 1);
                if (captured) {
                    strncpy(captured, command + start, cap_len);
                    captured[cap_len] = '\0';
                    printf(" capture[%d]=%zu-%zu=%s", i, start, end, captured);
                    free(captured);
                } else {
                    printf(" capture[%d]=%zu-%zu=?", i, start, end);
                }
            } else {
                printf(" capture[%d]=%zu-%zu=?", i, start, end);
            }
        }
        printf("\n");
    } else {
        // No match - this is valid, just report it
        printf("matched=0 category=0 (Unknown)\n");
    }

    dfa_machine_reset(&machine);
    free(dfa_data);
    return exit_code;
}
