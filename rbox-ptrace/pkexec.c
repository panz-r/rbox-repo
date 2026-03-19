/*
 * pkexec.c - pkexec launching for readonlybox-ptrace
 *
 * Handles relaunching with pkexec for privilege escalation while
 * preserving the screened environment via /dev/shm temp file.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/fcntl.h>

/* Program name for error messages */
static const char *g_pkexec_progname = "readonlybox-ptrace";

/* Set program name for error messages */
void pkexec_set_progname(const char *progname) {
    if (progname) {
        g_pkexec_progname = progname;
    }
}

/* Relaunch with pkexec for privilege escalation.
 * Returns only on error (execve doesn't return on success).
 *
 * Arguments:
 *   argc, argv - original command line arguments
 *   cmd_path - the command to run
 *
 * The screened environment is written to a /dev/shm temp file
 * and its path is passed to the child via --env-file.
 */
int pkexec_launch(int argc, char *argv[], const char *cmd_path) {
    uid_t original_uid = getuid();
    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        strcpy(cwd, ".");
    }

    /* Create a temporary file in /dev/shm (tmpfs - memory-backed filesystem).
     * This keeps the environment data in kernel memory, not on disk.
     * The file has a random name and will be cleaned up on reboot. */
    char env_file_template[] = "/dev/shm/readonlybox-env-XXXXXX";
    int env_fd = mkstemp(env_file_template);
    if (env_fd < 0) {
        /* Fallback to regular tmp if /dev/shm is not available */
        char tmp_template[] = "/tmp/readonlybox-env-XXXXXX";
        env_fd = mkstemp(tmp_template);
        if (env_fd < 0) {
            perror("mkstemp");
            return 1;
        }
        strcpy(env_file_template, tmp_template);
    }

    /* Write the screened environment to the temp file */
    extern char **environ;
    FILE *env_file = fdopen(env_fd, "w");
    if (!env_file) {
        close(env_fd);
        return 1;
    }
    for (char **e = environ; *e; e++) {
        fprintf(env_file, "%s\n", *e);
    }
    fclose(env_file);  /* also closes the fd */

    /* Allocate argv: pkexec + our options + args + NULL */
    /* Estimate: 6 pkexec/our options + argc + 1 */
    char **new_argv = malloc((argc + 10) * sizeof(char *));
    if (!new_argv) {
        unlink(env_file_template);
        return 1;
    }

    /* Track allocated strings for cleanup */
#define MAX_ALLOCATED 4
    char **allocated_strings = malloc(MAX_ALLOCATED * sizeof(char *));
    if (!allocated_strings) {
        free(new_argv);
        unlink(env_file_template);
        return 1;
    }
    int allocated_count = 0;

#define ADD_ALLOCATED(str) do { \
        if ((str) && allocated_count < MAX_ALLOCATED) { \
            allocated_strings[allocated_count++] = (str); \
        } \
    } while(0)

#define FREE_ALLOCATED() do { \
        for (int _i = 0; _i < allocated_count; _i++) { \
            free(allocated_strings[_i]); \
        } \
        free(allocated_strings); \
    } while(0)

    int idx = 0;
    new_argv[idx++] = "pkexec";
    new_argv[idx++] = "--disable-internal-agent";
    new_argv[idx++] = argv[0];  /* Our program's path */
    new_argv[idx++] = "--uid";
    char uid_str[32];
    snprintf(uid_str, sizeof(uid_str), "%d", original_uid);
    new_argv[idx] = strdup(uid_str);
    if (!new_argv[idx]) { FREE_ALLOCATED(); free(new_argv); unlink(env_file_template); return 1; }
    ADD_ALLOCATED(new_argv[idx]);
    idx++;
    new_argv[idx++] = "--cwd";
    new_argv[idx] = strdup(cwd);
    if (!new_argv[idx]) { FREE_ALLOCATED(); free(new_argv); unlink(env_file_template); return 1; }
    ADD_ALLOCATED(new_argv[idx]);
    idx++;
    new_argv[idx++] = "--cmd";
    new_argv[idx] = strdup(cmd_path);
    if (!new_argv[idx]) { FREE_ALLOCATED(); free(new_argv); unlink(env_file_template); return 1; }
    ADD_ALLOCATED(new_argv[idx]);
    idx++;

    /* Pass the environment file path so the child can restore the environment */
    new_argv[idx++] = "--env-file";
    new_argv[idx] = strdup(env_file_template);
    if (!new_argv[idx]) { FREE_ALLOCATED(); free(new_argv); unlink(env_file_template); return 1; }
    ADD_ALLOCATED(new_argv[idx]);
    idx++;

    /* Hidden internal flag to indicate we've already screened the environment */
    new_argv[idx++] = "--internal-screened";

    /* Add the actual command arguments (skip argv[0] which is our program). */
    for (int i = 1; i < argc; i++) {
        new_argv[idx++] = argv[i];
    }
    new_argv[idx] = NULL;

    /* Execute pkexec. The env file is in /dev/shm (memory-backed tmpfs).
     * The child (second instance) will read and unlink the file very early
     * after pkexec completes authentication. The file exists only during
     * the brief authentication window - no watchdog needed. */
    execve("/usr/bin/pkexec", new_argv, environ);

    /* If we get here, execve failed */
    fprintf(stderr, "\n%s: Failed to execute pkexec: %s\n", g_pkexec_progname, strerror(errno));
    FREE_ALLOCATED();
    free(new_argv);
    unlink(env_file_template);
    return 1;
}
