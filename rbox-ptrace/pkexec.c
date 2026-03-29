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

#include "debug.h"

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

    int result = 1;
    char env_file_template[64] = "";
    int env_fd = -1;
    FILE *env_file = NULL;
    char **new_argv = NULL;
    char **allocated_strings = NULL;
    int allocated_count = 0;

    /* Create a temporary file in /dev/shm (tmpfs - memory-backed filesystem).
     * This keeps the environment data in kernel memory, not on disk.
     * The file has a random name and is unlinked immediately after creation
     * to prevent leaks if the process crashes. The file descriptor remains
     * open and usable until closed. */
    snprintf(env_file_template, sizeof(env_file_template), "/dev/shm/readonlybox-env-XXXXXX");
    env_fd = mkostemp(env_file_template, O_CLOEXEC);
    if (env_fd < 0) {
        /* Fallback to regular tmp if /dev/shm is not available */
        snprintf(env_file_template, sizeof(env_file_template), "/tmp/readonlybox-env-XXXXXX");
        env_fd = mkostemp(env_file_template, O_CLOEXEC);
        if (env_fd < 0) {
            LOG_ERRNO("mkostemp");
            goto cleanup;
        }
    }

    /* Unlink immediately to prevent leak if process crashes.
     * The file descriptor remains open and usable.
     * The file content persists in kernel memory until the fd is closed. */
    unlink(env_file_template);

    /* Write the screened environment to the temp file */
    extern char **environ;
    env_file = fdopen(env_fd, "w");
    if (!env_file) {
        LOG_ERRNO("fdopen");
        goto cleanup;
    }
    for (char **e = environ; *e; e++) {
        fprintf(env_file, "%s\n", *e);
    }
    /* Check for write errors before closing */
    if (fflush(env_file) != 0 || ferror(env_file)) {
        LOG_ERROR("Error writing environment to temp file");
        goto cleanup;
    }
    fclose(env_file);
    env_file = NULL;
    env_fd = -1;

    /* Allocate argv: pkexec + our options + args + NULL */
    /* pkexec args: 12 fixed (pkexec, --disable-internal-agent, argv[0], --uid, uid_str, --cwd, cwd, --cmd, cmd_path, --env-file, env_file, --internal-screened) + user args */
    new_argv = malloc((argc + 20) * sizeof(char *));
    if (!new_argv) {
        LOG_ERROR("Failed to allocate argv");
        goto cleanup;
    }

    /* Track allocated strings for cleanup */
    allocated_strings = calloc(4, sizeof(char *));
    if (!allocated_strings) {
        LOG_ERROR("Failed to allocate tracking array");
        goto cleanup;
    }

    int idx = 0;
    new_argv[idx++] = "pkexec";
    new_argv[idx++] = "--disable-internal-agent";
    new_argv[idx++] = argv[0];  /* Our program's path */
    new_argv[idx++] = "--uid";
    char uid_str[32];
    snprintf(uid_str, sizeof(uid_str), "%d", original_uid);
    new_argv[idx] = strdup(uid_str);
    if (!new_argv[idx]) {
        LOG_ERROR("Failed to allocate uid string");
        goto cleanup;
    }
    allocated_strings[allocated_count++] = new_argv[idx];
    idx++;
    new_argv[idx++] = "--cwd";
    new_argv[idx] = strdup(cwd);
    if (!new_argv[idx]) {
        LOG_ERROR("Failed to allocate cwd string");
        goto cleanup;
    }
    allocated_strings[allocated_count++] = new_argv[idx];
    idx++;
    new_argv[idx++] = "--cmd";
    new_argv[idx] = strdup(cmd_path);
    if (!new_argv[idx]) {
        LOG_ERROR("Failed to allocate cmd_path string");
        goto cleanup;
    }
    allocated_strings[allocated_count++] = new_argv[idx];
    idx++;

    /* Pass the environment file path so the child can restore the environment */
    new_argv[idx++] = "--env-file";
    new_argv[idx] = strdup(env_file_template);
    if (!new_argv[idx]) {
        LOG_ERROR("Failed to allocate env_file string");
        goto cleanup;
    }
    allocated_strings[allocated_count++] = new_argv[idx];
    idx++;

    /* Hidden internal flag to indicate we've already screened the environment */
    new_argv[idx++] = "--internal-screened";

    /* Add the actual command arguments (skip argv[0] which is our program). */
    for (int i = 1; i < argc; i++) {
        new_argv[idx++] = argv[i];
    }
    new_argv[idx] = NULL;

    /* Execute pkexec. The env file was unlinked immediately after creation,
     * so no cleanup is needed here. The file content persists in kernel memory
     * (via the open fd) until pkexec reads it and the fd is closed. */
    execve("/usr/bin/pkexec", new_argv, environ);

    /* If we get here, execve failed - but file is already unlinked */
    LOG_ERROR("Failed to execute pkexec: %s", strerror(errno));
    goto cleanup;

cleanup:
    if (env_file) {
        fclose(env_file);
    }
    if (env_fd >= 0) {
        close(env_fd);
    }
    if (env_file_template[0]) {
        unlink(env_file_template);
    }
    if (allocated_strings) {
        for (int i = 0; i < allocated_count; i++) {
            free(allocated_strings[i]);
        }
        free(allocated_strings);
    }
    free(new_argv);
    return result;
}
