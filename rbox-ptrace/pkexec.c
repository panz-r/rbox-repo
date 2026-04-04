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

static ssize_t write_full(int fd, const void *buf, size_t count) {
    const char *p = buf;
    while (count > 0) {
        ssize_t written = write(fd, p, count);
        if (written < 0) return -1;
        count -= (size_t)written;
        p += written;
    }
    return 0;
}

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

    /* Write the screened environment to the temp file.
     * The file will be unlinked by pkexec's child after reading it.
     * If execve fails, the cleanup handler will unlink it.
     * We use write_full() to handle partial writes.
     * A 128KB limit prevents abuse from huge environments. */
    #define ENV_FILE_LIMIT (128 * 1024)
    extern char **environ;
    size_t total_env_size = 0;
    for (char **e = environ; *e; e++) {
        size_t len = strlen(*e);
        if (total_env_size + len + 1 > ENV_FILE_LIMIT) {
            LOG_ERROR("Environment too large (> %d bytes), truncated", ENV_FILE_LIMIT);
            break;
        }
        total_env_size += len + 1;
        if (write_full(env_fd, *e, len) < 0 ||
            write_full(env_fd, "\n", 1) < 0) {
            LOG_ERROR("Error writing environment to temp file");
            goto cleanup;
        }
    }

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

    /* Execute pkexec. The env file will be read and unlinked by main.c
     * after pkexec passes it through. The file persists on disk (in /dev/shm)
     * until main.c unlinks it after reading. */
    execve("/usr/bin/pkexec", new_argv, environ);

    /* If we get here, execve failed - cleanup will close and unlink */
    LOG_ERROR("Failed to execute pkexec: %s", strerror(errno));
    goto cleanup;

cleanup:
    if (env_fd >= 0) {
        close(env_fd);
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
