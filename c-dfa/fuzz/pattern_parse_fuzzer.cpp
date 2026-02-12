// LibFuzzer harness for pattern parser
// Fuzzes nfa_builder's pattern validation by running it as a separate process

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>  // For O_WRONLY

// Path to nfa_builder binary (relative to fuzzer location)
static const char* NFL_BUILDER_PATH = "../tools/nfa_builder";

// Maximum size of pattern input to write to temp file
static const size_t MAX_PATTERN_SIZE = 8192;

// Resource limits for child process
static const rlim_t MAX_MEMORY = 100 * 1024 * 1024; // 100 MB
static const rlim_t MAX_CPU_TIME = 1; // 1 second CPU time

// LLVMFuzzerInitialize - called once at startup
extern "C" void LLVMFuzzerInitialize(void) {
    // Nothing to initialize
}

// Write data to a temporary file, return filename (must be freed)
static char* write_temp_file(const uint8_t* data, size_t size) {
    char tmpl[] = "/tmp/pattern_parse_fuzzer_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        perror("mkstemp");
        return NULL;
    }

    // Write data
    ssize_t written = write(fd, data, size);
    if (written < 0 || (size_t)written != size) {
        perror("write");
        close(fd);
        unlink(tmpl);
        return NULL;
    }
    close(fd);

    // Return a copy of the filename (caller must free)
    char* filename = strdup(tmpl);
    if (!filename) {
        unlink(tmpl);
        return NULL;
    }
    return filename;
}

// Run nfa_builder with --validate-only on the given pattern file
// Returns: 0 = success or validation error (expected), 1 = crash detected
static int run_nfa_builder(const char* pattern_file) {
    pid_t pid = fork();
    if (pid < 0) {
        // Fork failed
        return 0; // Don't fail the fuzzer
    }

    if (pid == 0) {
        // Child process

        // Set resource limits before exec
        struct rlimit rl;

        // Limit memory
        rl.rlim_cur = rl.rlim_max = MAX_MEMORY;
        setrlimit(RLIMIT_AS, &rl);

        // Limit CPU time
        rl.rlim_cur = rl.rlim_max = MAX_CPU_TIME;
        setrlimit(RLIMIT_CPU, &rl);

        // Redirect stdio to /dev/null to avoid clutter
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > 2) close(devnull);
        }

        // Execute nfa_builder
        execl(NFL_BUILDER_PATH, "nfa_builder", "--validate-only", pattern_file, (char*)NULL);

        // If exec fails, exit with special code
        _exit(127);
    }

    // Parent: wait for child
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        return 0;
    }

    if (WIFSIGNALED(status)) {
        // Child crashed!
        int sig = WTERMSIG(status);
        fprintf(stderr, "\n=== CRASH DETECTED ===\n");
        fprintf(stderr, "nfa_builder crashed with signal %d (%s)\n",
                sig, strsignal(sig));
        if (WCOREDUMP(status)) {
            fprintf(stderr, "Core dump produced\n");
        }
        fprintf(stderr, "Pattern (first 200 bytes):\n");
        // We don't have the pattern here, but we'll print in parent after abort
        return 1;
    }

    // Check exit code: 0 = validation passed, 1 = validation failed (both okay)
    // Any other exit code is unexpected
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 127) {
            fprintf(stderr, "ERROR: nfa_builder exec failed\n");
        }
        // 0 and 1 are both acceptable; other codes indicate problem
        if (code > 1) {
            fprintf(stderr, "WARNING: nfa_builder exited with code %d\n", code);
        }
    }

    return 0;
}

// LLVMFuzzerTestOneInput - main fuzzing entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Limit input size
    if (size > MAX_PATTERN_SIZE) {
        size = MAX_PATTERN_SIZE;
    }

    // Ensure at least some data
    if (size == 0) {
        return 0;
    }

    // Write input to temporary file
    char* tmpfile = write_temp_file(data, size);
    if (!tmpfile) {
        return 0; // Skip this input if we can't create temp file
    }

    // Run nfa_builder on the temporary file
    int crashed = run_nfa_builder(tmpfile);

    // Clean up
    unlink(tmpfile);
    free(tmpfile);

    // If crash detected, abort to signal LibFuzzer
    if (crashed) {
        // Print the pattern for debugging
        fprintf(stderr, "Offending pattern (size %zu):\n", size);
        // Write up to 200 bytes
        size_t print_len = size < 200 ? size : 200;
        fwrite(data, 1, print_len, stderr);
        if (size > 200) fprintf(stderr, "... (truncated)");
        fprintf(stderr, "\n");
        abort();
    }

    return 0;
}
