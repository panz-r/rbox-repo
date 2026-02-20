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
#include <limits.h>
#include <libgen.h>
#include <sys/stat.h>

// Verbosity flag (set from environment)
static int g_verbose = 0;

// Path to nfa_builder binary - will be set at runtime based on executable location
static const char* NFL_BUILDER_PATH = NULL;
static char nfa_builder_path_buf[PATH_MAX];

// Determine the absolute path to nfa_builder based on the fuzzer's location
static void init_nfa_builder_path() {
    // Get the path to the current executable
    char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (len == -1) {
        fprintf(stderr, "ERROR: Cannot read /proc/self/exe, falling back to relative path\n");
        NFL_BUILDER_PATH = "../tools/nfa_builder";
        return;
    }
    exe_path[len] = '\0';

    // Get the directory containing the executable
    char exe_dir[PATH_MAX];
    strncpy(exe_dir, exe_path, sizeof(exe_dir));
    exe_dir[sizeof(exe_dir)-1] = '\0';
    char* exe_dir_ptr = dirname(exe_dir);

    // Construct path: <exe_dir>/../tools/nfa_builder
    if (realpath(exe_dir_ptr, exe_dir) == NULL) {
        fprintf(stderr, "WARNING: realpath failed for %s: %s\n", exe_dir_ptr, strerror(errno));
        strncpy(nfa_builder_path_buf, "../tools/nfa_builder", sizeof(nfa_builder_path_buf));
    } else {
        snprintf(nfa_builder_path_buf, sizeof(nfa_builder_path_buf), "%s/../tools/nfa_builder", exe_dir);
        // Resolve to absolute path
        char resolved[PATH_MAX];
        if (realpath(nfa_builder_path_buf, resolved) == NULL) {
            fprintf(stderr, "WARNING: Cannot resolve %s: %s, using unresolved path\n",
                    nfa_builder_path_buf, strerror(errno));
        } else {
            strncpy(nfa_builder_path_buf, resolved, sizeof(nfa_builder_path_buf));
        }
    }
    NFL_BUILDER_PATH = nfa_builder_path_buf;

    // Check if the binary exists and is executable
    struct stat st;
    if (stat(NFL_BUILDER_PATH, &st) != 0) {
        fprintf(stderr, "ERROR: nfa_builder not found at %s: %s\n", NFL_BUILDER_PATH, strerror(errno));
    } else if (!S_ISREG(st.st_mode) || (st.st_mode & S_IXUSR) == 0) {
        fprintf(stderr, "ERROR: nfa_builder at %s is not a regular executable file\n", NFL_BUILDER_PATH);
    } else if (g_verbose) {
        fprintf(stderr, "DEBUG: nfa_builder path resolved to: %s\n", NFL_BUILDER_PATH);
    }
}

// Maximum pattern size
static const size_t MAX_PATTERN_SIZE = 8192;

// CPU time limit (seconds) - no AS limit (was problematic)
static const rlim_t MAX_CPU_TIME = 2;

// LLVMFuzzerInitialize
extern "C" void LLVMFuzzerInitialize(void) {
    // Check for verbosity flag via environment variable
    const char* verbose = getenv("NFA_BUILD_FUZZER_VERBOSE");
    if (verbose && (*verbose == '1' || *verbose == 'y' || *verbose == 'Y')) {
        g_verbose = 1;
    }
    init_nfa_builder_path();
}

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
    if (pid < 0) {
        perror("fork");
        return 0;
    }

    if (pid == 0) {
        if (g_verbose) {
            // Print debug info BEFORE redirecting stderr
            fprintf(stderr, "DEBUG(child): about to exec nfa_builder at: %s\n", NFL_BUILDER_PATH);
            fprintf(stderr, "DEBUG(child): pattern_file: %s, output_file: %s\n", pattern_file, output_file);
            // Check if binary exists and is executable
            struct stat st;
            if (stat(NFL_BUILDER_PATH, &st) != 0) {
                fprintf(stderr, "ERROR(child): stat failed: %s\n", strerror(errno));
            } else {
                fprintf(stderr, "DEBUG(child): nfa_builder exists, size: %ld, mode: %o\n", (long)st.st_size, st.st_mode);
            }
        }

        // Set resource limits
        struct rlimit rl;
        rl.rlim_cur = rl.rlim_max = MAX_CPU_TIME;
        if (setrlimit(RLIMIT_CPU, &rl) != 0) {
            perror("setrlimit");
            _exit(127);
        }

        // Redirect stdout/stderr to /dev/null to avoid noise
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > 2) close(devnull);
        }

        // Build NFA (not just validate)
        execl(NFL_BUILDER_PATH, "nfa_builder", pattern_file, output_file, (char*)NULL);

        // If execl returns, it's an error
        int saved_errno = errno;
        // Re-open stderr to report error (since we closed it)
        int errfd = open("/dev/stderr", O_WRONLY);
        if (errfd >= 0) {
            dprintf(errfd, "ERROR(child): execl failed: %s (errno=%d)\n", strerror(saved_errno), saved_errno);
            close(errfd);
        }
        _exit(127);
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 0;
    }

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
            fprintf(stderr, "ERROR: nfa_builder exec failed (child exit 127)\n");
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
