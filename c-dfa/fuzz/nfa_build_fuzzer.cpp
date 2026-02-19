// LibFuzzer harness for NFA building (not just validation)
// Fuzzes nfa_builder's actual NFA construction by building NFA files

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

// Path to nfa_builder binary (relative to fuzzer working directory in c-dfa/fuzz/)
static const char* NFL_BUILDER_PATH = "../tools/nfa_builder";

// Maximum pattern size
static const size_t MAX_PATTERN_SIZE = 8192;

// CPU time limit (seconds) - no AS limit (was problematic)
static const rlim_t MAX_CPU_TIME = 2;

// LLVMFuzzerInitialize
extern "C" void LLVMFuzzerInitialize(void) {}

// Write data to temporary file, return filename
static char* write_temp_file(const uint8_t* data, size_t size) {
    char tmpl[] = "/tmp/nfa_build_fuzzer_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return NULL;
    write(fd, data, size);
    close(fd);
    return strdup(tmpl);
}

// Run nfa_builder to actually build NFA (not just validate)
// Returns 0 on normal exit (success or expected error), 1 on crash
static int run_nfa_builder(const char* pattern_file) {
    char output_file[] = "/tmp/nfa_build_fuzzer_out_XXXXXX.nfa";
    int outfd = mkstemp(output_file);
    if (outfd < 0) {
        // Use fallback name
        strcpy(output_file, "/tmp/nfa_build_fuzzer_out.nfa");
    } else {
        close(outfd);
        unlink(output_file); // We'll let nfa_builder create it
    }

    pid_t pid = fork();
    if (pid < 0) return 0;

    if (pid == 0) {
        // Child: set resource limits
        struct rlimit rl;
        rl.rlim_cur = rl.rlim_max = MAX_CPU_TIME;
        setrlimit(RLIMIT_CPU, &rl);

        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > 2) close(devnull);
        }

        // Build NFA (not just validate)
        execl(NFL_BUILDER_PATH, "nfa_builder", pattern_file, output_file, (char*)NULL);
        _exit(127);
    }

    int status;
    waitpid(pid, &status, 0);  // Fixed: added third argument

    // Cleanup output file
    unlink(output_file);

    if (WIFSIGNALED(status)) {
        fprintf(stderr, "\n=== CRASH DETECTED ===\n");
        fprintf(stderr, "nfa_builder (NFA build) crashed with signal %d (%s)\n",
                WTERMSIG(status), strsignal(WTERMSIG(status)));
        return 1;
    }

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 127) {
            fprintf(stderr, "ERROR: nfa_builder exec failed\n");
        }
        // Exit codes 0 (success) or 1 (validation/construction error) are OK
        if (code > 1 && code != 2 && code != 3) {
            fprintf(stderr, "WARNING: Unexpected exit code %d\n", code);
        }
    }

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > MAX_PATTERN_SIZE) size = MAX_PATTERN_SIZE;
    if (size == 0) return 0;

    char* tmpfile = write_temp_file(data, size);
    if (!tmpfile) return 0;

    int crashed = run_nfa_builder(tmpfile);
    unlink(tmpfile);
    free(tmpfile);

    if (crashed) {
        fprintf(stderr, "Offending pattern (size %zu):\n", size);
        fwrite(data, 1, size > 200 ? 200 : size, stderr);
        if (size > 200) fprintf(stderr, "...");
        fprintf(stderr, "\n");
        abort();
    }

    return 0;
}
