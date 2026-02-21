// LibFuzzer harness for c-dfa DFA evaluator
// Fuzzes dfa_evaluate() by running dfa_eval_wrapper as a subprocess

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <libgen.h>
#include <sys/stat.h>

// Verbosity flag (set from environment)
static int g_verbose = 0;

// Paths - will be resolved at runtime
static const char* DFA_FILE = NULL;
static const char* WRAPPER_PATH = NULL;
static char dfa_file_buf[PATH_MAX];
static char wrapper_path_buf[PATH_MAX];

// Maximum input size
static const size_t MAX_INPUT_SIZE = 4096;

// Determine paths based on the fuzzer's location
static void init_paths() {
    // Get the path to the current executable
    char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (len == -1) {
        fprintf(stderr, "ERROR: Cannot read /proc/self/exe, using relative paths\n");
        DFA_FILE = "../readonlybox.dfa";
        WRAPPER_PATH = "../tools/dfa_eval_wrapper";
        return;
    }
    exe_path[len] = '\0';

    // Get the directory containing the executable
    char exe_dir[PATH_MAX];
    strncpy(exe_dir, exe_path, sizeof(exe_dir));
    exe_dir[sizeof(exe_dir)-1] = '\0';
    char* exe_dir_ptr = dirname(exe_dir);

    // Construct paths
    char tmp_path[PATH_MAX];
    if (realpath(exe_dir_ptr, tmp_path) == NULL) {
        fprintf(stderr, "WARNING: realpath failed for %s: %s\n", exe_dir_ptr, strerror(errno));
        DFA_FILE = "../readonlybox.dfa";
        WRAPPER_PATH = "../tools/dfa_eval_wrapper";
        return;
    }

    snprintf(dfa_file_buf, sizeof(dfa_file_buf), "%s/../readonlybox.dfa", tmp_path);
    snprintf(wrapper_path_buf, sizeof(wrapper_path_buf), "%s/../tools/dfa_eval_wrapper", tmp_path);

    // Resolve to absolute paths
    char resolved[PATH_MAX];
    if (realpath(dfa_file_buf, resolved) != NULL) {
        strncpy(dfa_file_buf, resolved, sizeof(dfa_file_buf));
    }
    if (realpath(wrapper_path_buf, resolved) != NULL) {
        strncpy(wrapper_path_buf, resolved, sizeof(wrapper_path_buf));
    }

    DFA_FILE = dfa_file_buf;
    WRAPPER_PATH = wrapper_path_buf;

    if (g_verbose) {
        fprintf(stderr, "DEBUG: DFA file: %s\n", DFA_FILE);
        fprintf(stderr, "DEBUG: Wrapper path: %s\n", WRAPPER_PATH);
    }

    // Check if wrapper exists
    struct stat st;
    if (stat(WRAPPER_PATH, &st) != 0) {
        fprintf(stderr, "ERROR: dfa_eval_wrapper not found at %s: %s\n", WRAPPER_PATH, strerror(errno));
        fprintf(stderr, "Please build the wrapper: make -C ../tools dfa_eval_wrapper\n");
    } else if (!S_ISREG(st.st_mode) || (st.st_mode & S_IXUSR) == 0) {
        fprintf(stderr, "ERROR: dfa_eval_wrapper at %s is not executable\n", WRAPPER_PATH);
    }
}

// LLVMFuzzerInitialize
extern "C" void LLVMFuzzerInitialize(void) {
    // Check for verbosity flag via environment variable
    const char* verbose = getenv("DFA_EVAL_FUZZER_VERBOSE");
    if (verbose && (*verbose == '1' || *verbose == 'y' || *verbose == 'Y')) {
        g_verbose = 1;
    }
    init_paths();
}

// Run dfa_eval_wrapper in a subprocess
// Returns: 0 = success, 1 = crash detected, 2 = validation error
static int run_dfa_eval_wrapper(const char* input, size_t length) {
    // Create a pipe to capture output
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("pipe");
        return 0; // Skip on error
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return 0; // Skip on error
    }

    if (pid == 0) {
        // Child process
        close(pipefd[0]); // Close read end

        // Redirect stdout to pipe
        dup2(pipefd[1], STDOUT_FILENO);
        // Redirect stderr to /dev/null to avoid noise
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            if (devnull > 2) close(devnull);
        }
        close(pipefd[1]);

        // Ensure input is null-terminated for exec
        char* input_copy = (char*)malloc(length + 1);
        if (!input_copy) {
            _exit(127);
        }
        memcpy(input_copy, input, length);
        input_copy[length] = '\0';

        if (g_verbose) {
            // Can't print here since stderr is redirected
            // But we can write to the pipe
            dprintf(STDOUT_FILENO, "DEBUG: Running %s %s '%s'\n", WRAPPER_PATH, DFA_FILE, input_copy);
        }

        // Execute wrapper
        execl(WRAPPER_PATH, "dfa_eval_wrapper", DFA_FILE, input_copy, (char*)NULL);

        // If exec fails
        int saved_errno = errno;
        int errfd = open("/dev/stderr", O_WRONLY);
        if (errfd >= 0) {
            dprintf(errfd, "ERROR: execl failed: %s (errno=%d)\n", strerror(saved_errno), saved_errno);
            close(errfd);
        }
        free(input_copy);
        _exit(127);
    }

    // Parent process
    close(pipefd[1]); // Close write end

    // Read output from child
    char output_buf[512];
    ssize_t n = read(pipefd[0], output_buf, sizeof(output_buf) - 1);
    if (n > 0) {
        output_buf[n] = '\0';
        if (g_verbose) {
            fprintf(stderr, "DEBUG: Wrapper output: %s", output_buf);
        }
    }
    close(pipefd[0]);

    // Wait for child
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 0;
    }

    if (WIFSIGNALED(status)) {
        // Child crashed!
        int sig = WTERMSIG(status);
        fprintf(stderr, "\n=== CRASH DETECTED ===\n");
        fprintf(stderr, "DFA evaluator crashed with signal %d (%s)\n",
                sig, strsignal(sig));
        if (WCOREDUMP(status)) {
            fprintf(stderr, "Core dump produced\n");
        }
        return 1;
    }

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        switch (code) {
            case 0:
                // Success
                break;
            case 1:
                // Validation error - this is a bug!
                fprintf(stderr, "\n=== VALIDATION ERROR ===\n");
                fprintf(stderr, "DFA evaluator detected an internal error\n");
                return 2;
            case 2:
                // Initialization error
                fprintf(stderr, "WARNING: DFA initialization failed\n");
                break;
            case 127:
                fprintf(stderr, "ERROR: dfa_eval_wrapper exec failed\n");
                break;
            default:
                fprintf(stderr, "WARNING: Unexpected exit code %d\n", code);
                break;
        }
    }

    return 0;
}

// LLVMFuzzerTestOneInput - main fuzzing entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Limit input size
    if (size > MAX_INPUT_SIZE) {
        size = MAX_INPUT_SIZE;
    }

    if (size == 0) {
        return 0;
    }

    // Check that wrapper exists
    struct stat st;
    if (!WRAPPER_PATH || stat(WRAPPER_PATH, &st) != 0) {
        static int warned = 0;
        if (!warned) {
            fprintf(stderr, "ERROR: dfa_eval_wrapper not available, skipping inputs\n");
            warned = 1;
        }
        return 0;
    }

    // Run evaluation in subprocess via wrapper
    int result = run_dfa_eval_wrapper((const char*)data, size);

    // If crash or validation error detected, abort to signal LibFuzzer
    if (result != 0) {
        fprintf(stderr, "Offending input (size %zu):\n", size);
        fwrite(data, 1, size > 200 ? 200 : size, stderr);
        if (size > 200) fprintf(stderr, "...");
        fprintf(stderr, "\n");
        abort();
    }

    return 0;
}
