/*
 * judge.c - Judge execution for readonlybox-ptrace
 *
 * Handles communication with readonlybox server for command decisions.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/types.h>
#include <limits.h>
#include <libgen.h>

#include "judge.h"
#include "env.h"
#include "protocol.h"
#include <rbox_protocol_defs.h>
#include <rbox_protocol.h>

/* Get path to readonlybox binary */
const char *judge_get_readonlybox_path(void) {
    static char path_buf[PATH_MAX];

    /* First, check environment variable for explicit override */
    const char *env_path = getenv("READONLYBOX_WRAP_PATH");
    if (env_path && env_path[0]) {
        if (access(env_path, X_OK) == 0) {
            return env_path;
        }
    }

    /* Try to find relative to our executable location */
    char self_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len > 0) {
        self_path[len] = '\0';
        char *dir = dirname(self_path);

        /* Try relative to executable: ../rbox-wrap/rbox-wrap */
        snprintf(path_buf, sizeof(path_buf), "%s/../rbox-wrap/rbox-wrap", dir);
        if (access(path_buf, X_OK) == 0) {
            return path_buf;
        }

        /* Try relative to executable: ../../rbox-wrap/rbox-wrap */
        snprintf(path_buf, sizeof(path_buf), "%s/../../rbox-wrap/rbox-wrap", dir);
        if (access(path_buf, X_OK) == 0) {
            return path_buf;
        }

        /* Also try readonlybox as fallback */
        snprintf(path_buf, sizeof(path_buf), "%s/../readonlybox-ptrace", dir);
        if (access(path_buf, X_OK) == 0) {
            /* This is the ptrace binary itself - check sibling directory */
            snprintf(path_buf, sizeof(path_buf), "%s/../../bin/rbox-wrap", dir);
            if (access(path_buf, X_OK) == 0) {
                return path_buf;
            }
        }
    }

    /* Try current working directory */
    if (access("./rbox-wrap/rbox-wrap", X_OK) == 0) {
        return "./rbox-wrap/rbox-wrap";
    }

    /* Try PATH */
    char *path_env = getenv("PATH");
    if (path_env) {
        char *path_copy = strdup(path_env);
        char *dir = strtok(path_copy, ":");
        while (dir) {
            snprintf(path_buf, sizeof(path_buf), "%s/rbox-wrap", dir);
            if (access(path_buf, X_OK) == 0) {
                free(path_copy);
                return path_buf;
            }
            dir = strtok(NULL, ":");
        }
        free(path_copy);
    }

    return NULL;
}

/* Run readonlybox --judge to get server decision
 * Returns: 0 = ALLOW, 9 = DENY, -1 = error
 */
int judge_run(const char *command, const char *caller_info) {
    int pipefd[2];
    pid_t pid;

    /* Dynamic buffer for server response - grows as needed */
    size_t cap = 4096;
    char *buffer = malloc(cap);
    if (!buffer) {
        return -1;
    }
    size_t bytes_read = 0;

    /* Clear any stale environment variables from previous decisions
     * This prevents stale values from being used if a later execve is
     * allowed by DFA (bypassing server call) */
    unsetenv("READONLYBOX_ENV_DECISIONS");
    unsetenv("READONLYBOX_FLAGGED_ENV_NAMES");

    /* Create pipe for reading output */
    if (pipe(pipefd) < 0) {
        free(buffer);
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        free(buffer);
        return -1;
    }

    if (pid == 0) {
        /* Child process - will exec rbox-wrap for server decision */
        /* Note: We don't call PTRACE_DETACH here - the parent will handle detaching
         * this process after fork/clone events are detected */

        /* Child: exec readonlybox --bin --judge for binary protocol */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        /* Set caller info as environment variable for the server request */
        if (caller_info) {
            setenv("READONLYBOX_CALLER", caller_info, 1);
        }

        /* Set flagged env vars so server can make decisions about them */
        /* This must be set BEFORE exec so the Go server can read it */
        /* Format: NAME1:score1,NAME2:score2,... */
        int flagged_count = env_get_flagged_count();
        if (flagged_count > 0) {
            /* 16KB buffer - enough for ~256 flagged vars with typical name lengths */
            char env_buf[16384] = {0};
            char *p = env_buf;
            size_t rem = sizeof(env_buf) - 1;
            int truncated = 0;

            for (int i = 0; i < flagged_count && rem > 1; i++) {
                const char *name = env_get_flagged_name(i);
                if (name) {
                    /* Use the actual score stored during screening */
                    double score = env_get_flagged_score(i);

                    size_t len = strlen(name);
                    /* Format: name:score (7 chars for :score + potential comma) */
                    size_t needed = len + 8;

                    if (rem >= needed) {
                        /* Format: name:score */
                        memcpy(p, name, len);
                        p += len;
                        rem -= len;

                        /* Add score */
                        int n = snprintf(p, rem, ":%.2f", score);
                        if (n > 0 && (size_t)n < rem) {
                            p += n;
                            rem -= n;
                        }

                        if (rem > 1 && i < flagged_count - 1) {
                            *p++ = ',';
                            rem--;
                        }
                    } else {
                        truncated = 1;
                    }
                }
            }

            if (env_buf[0]) {
                setenv("READONLYBOX_FLAGGED_ENVS", env_buf, 1);
            }
            if (truncated) {
                fprintf(stderr, "Warning: READONLYBOX_FLAGGED_ENVS was truncated\n");
            }
        }

        /* Find rbox-wrap binary */
        const char *readonlybox_path = judge_get_readonlybox_path();

        if (!readonlybox_path) {
            _exit(1);
        }

        /* Use binary mode for v8 protocol */
        execl(readonlybox_path, "rbox-wrap", "--bin", "--judge", command, NULL);
        /* If we get here, execl failed */
        _exit(1);
    }

    /* Parent: read binary output */
    /* Read the binary packet from the pipe while the child is running.
     * This avoids potential deadlock if the child writes more than the pipe buffer can hold. */

    /* Close parent's write end - child only needs to write */
    close(pipefd[1]);

    /* Read with dynamically growing buffer (max 64KB for protocol response) */
#define MAX_RESPONSE_SIZE 65536
    ssize_t n;
    while ((n = read(pipefd[0], buffer + bytes_read, cap - bytes_read)) > 0) {
        bytes_read += n;
        if ((size_t)bytes_read == cap) {
            if (cap >= MAX_RESPONSE_SIZE) {
                /* Response too large - reject to prevent memory exhaustion */
                kill(pid, SIGKILL);
                close(pipefd[0]);
                waitpid(pid, NULL, 0);
                free(buffer);
                return -1;
            }
            /* Grow buffer */
            size_t new_cap = cap * 2;
            if (new_cap > MAX_RESPONSE_SIZE) new_cap = MAX_RESPONSE_SIZE;
            char *new_buf = realloc(buffer, new_cap);
            if (!new_buf) {
                /* Realloc failed - kill child and cleanup */
                kill(pid, SIGKILL);
                close(pipefd[0]);
                waitpid(pid, NULL, 0);
                free(buffer);
                return -1;
            }
            buffer = new_buf;
            cap = new_cap;
        }
    }
    close(pipefd[0]);
    /* pipefd[1] already closed by parent before reading */

    /* Wait for child to finish */
    int status;
    waitpid(pid, &status, 0);

    if (bytes_read <= 0) {
        free(buffer);
        return -1;
    }

    /* Do NOT null-terminate - this is binary protocol data */

    /* Check if child exited normally or was killed by signal */
    int exit_code;
    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        exit_code = -WTERMSIG(status);  /* Treat signal as error */
    } else {
        exit_code = -1;
    }

    /* Use v8 protocol decode utilities to parse binary response */
    rbox_decoded_header_t header;
    rbox_response_details_t details;
    rbox_env_decisions_t env_decisions;
    memset(&env_decisions, 0, sizeof(env_decisions));

    /* Decode header */
    rbox_decode_header(buffer, bytes_read, &header);
    if (!header.valid) {
        /* Fall back to exit code */
        free(buffer);
        if (exit_code == 0) return 0;
        if (exit_code == 9) return 9;
        return -1;
    }

    /* Decode env decisions FIRST - apply them regardless of allow/deny decision */
    rbox_decode_env_decisions(&header, &details, buffer, bytes_read, &env_decisions);
    if (env_decisions.valid && env_decisions.env_count > 0 && env_decisions.bitmap) {
        /* Build env_decisions string with index:decision format */
        char env_decisions_buf[4096] = {0};
        char *p = env_decisions_buf;
        size_t remaining = sizeof(env_decisions_buf) - 1;

        for (int i = 0; i < env_decisions.env_count && remaining > 1; i++) {
            uint8_t bit = (env_decisions.bitmap[i / 8] >> (i % 8)) & 1;
            int n = snprintf(p, remaining, "%d:%d", i, bit);
            if (n > 0 && (size_t)n < remaining) {
                p += n;
                remaining -= n;
                if (remaining > 1 && i < env_decisions.env_count - 1) {
                    *p++ = ',';
                    remaining--;
                }
            }
        }

        if (env_decisions_buf[0]) {
            setenv("READONLYBOX_ENV_DECISIONS", env_decisions_buf, 1);
        }

        /* Also set the flagged env var names so child can filter */
        int flagged_count = env_get_flagged_count();
        if (flagged_count > 0) {
            char env_names_buf[4096] = {0};
            char *p = env_names_buf;
            size_t rem = sizeof(env_names_buf) - 1;

            for (int i = 0; i < flagged_count && i < env_decisions.env_count && rem > 1; i++) {
                const char *name = env_get_flagged_name(i);
                if (name) {
                    size_t len = strlen(name);
                    if (len < rem) {
                        memcpy(p, name, len);
                        p += len;
                        rem -= len;
                        if (rem > 1 && i < flagged_count - 1) {
                            *p++ = ',';
                            rem--;
                        }
                    }
                }
            }

            if (env_names_buf[0]) {
                setenv("READONLYBOX_FLAGGED_ENV_NAMES", env_names_buf, 1);
            }
        }

        /* Free bitmap */
        free(env_decisions.bitmap);
    }

    /* Decode response details */
    rbox_decode_response_details(&header, buffer, bytes_read, &details);
    if (details.valid) {
        /* Use decision from response packet - this is the authoritative source */
        /* Decision: RBOX_DECISION_ALLOW=2 means allow, anything else is deny */
        free(buffer);
        if (details.decision == RBOX_DECISION_ALLOW) {
            return 0;  /* Allowed */
        } else {
            return 9;  /* Denied */
        }
    }

    /* Fallback to exit code if details not valid */
    free(buffer);
    if (exit_code == 0) return 0;
    if (exit_code == 9) return 9;
    return -1;
}
