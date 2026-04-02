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
#include <sys/stat.h>
#include <signal.h>
#include <sys/types.h>
#include <limits.h>
#include <libgen.h>

#include "judge.h"
#include "env.h"
#include "validation.h"
#include "debug.h"
#include "protocol.h"
#include <rbox_protocol_defs.h>
#include <rbox_protocol.h>

static int server_socket_exists(void) {
    const char *path = validation_get_socket_path();
    struct stat st;
    return (stat(path, &st) == 0 && S_ISSOCK(st.st_mode));
}

/* Run readonlybox --judge to get server decision
 * Returns: 0 = ALLOW, 9 = DENY, -1 = error
 */
int judge_run(const char *command, const char *caller_info) {
    int retry_count = 0;
    const int MAX_RETRIES = 10;

    while (1) {
        /* Wait for socket to appear */
        while (!server_socket_exists()) {
            DEBUG_PRINT("JUDGE: waiting for server socket...\n");
            sleep(1);
        }

        /* Get wrapper binary path - resolved once at startup in validation_init */
        const char *readonlybox_path = validation_get_wrap_path();
        if (!readonlybox_path) {
            retry_count++;
            if (retry_count > MAX_RETRIES) {
                LOG_ERROR("rbox-wrap binary not found after %d retries", MAX_RETRIES);
                exit(1);
            }
            DEBUG_PRINT("JUDGE: rbox-wrap not found, retry %d/%d\n", retry_count, MAX_RETRIES);
            sleep(1);
            continue;
        }

        int pipefd[2];
        pid_t pid;

        size_t cap = 4096;
        char *buffer = malloc(cap);
        if (!buffer) return -1;
        size_t bytes_read = 0;

        unsetenv("READONLYBOX_ENV_DECISIONS");
        unsetenv("READONLYBOX_FLAGGED_ENV_NAMES");

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
            /* Child process */
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
            dup2(pipefd[1], STDERR_FILENO);
            close(pipefd[1]);

            if (caller_info) setenv("READONLYBOX_CALLER", caller_info, 1);

            int flagged_count = env_get_flagged_count();
            if (flagged_count > 0) {
                char env_buf[16384] = {0};
                char *p = env_buf;
                size_t rem = sizeof(env_buf) - 1;
                int truncated = 0;

                for (int i = 0; i < flagged_count && rem > 1; i++) {
                    const char *name = env_get_flagged_name(i);
                    if (name) {
                        double score = env_get_flagged_score(i);
                        size_t len = strlen(name);
                        size_t needed = len + 8;

                        if (rem >= needed) {
                            memcpy(p, name, len);
                            p += len;
                            rem -= len;

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

            setenv("READONLYBOX_SOCKET", validation_get_socket_path(), 1);

            execl(readonlybox_path, "rbox-wrap", "--bin", "--judge", command, NULL);
            _exit(1);
        }

        /* Parent */
        close(pipefd[1]);

#define MAX_RESPONSE_SIZE 65536
        ssize_t n;
        while ((n = read(pipefd[0], buffer + bytes_read, cap - bytes_read)) > 0) {
            bytes_read += n;
            if ((size_t)bytes_read == cap) {
                if (cap >= MAX_RESPONSE_SIZE) {
                    kill(pid, SIGKILL);
                    close(pipefd[0]);
                    waitpid(pid, NULL, 0);
                    free(buffer);
                    return -1;
                }
                size_t new_cap = cap * 2;
                if (new_cap > MAX_RESPONSE_SIZE) new_cap = MAX_RESPONSE_SIZE;
                char *new_buf = realloc(buffer, new_cap);
                if (!new_buf) {
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

        int status;
        waitpid(pid, &status, 0);

        if (bytes_read <= 0) {
            free(buffer);
            if (WIFEXITED(status)) {
                int code = WEXITSTATUS(status);
                if (code == 9) {
                    DEBUG_PRINT("JUDGE: child exited with 9 but no output - assume deny\n");
                    return 9;
                }
                /* Exit 0 with no output means rbox-wrap couldn't communicate with server
                 * and fast-path allowed - but we need server decision, so retry */
                retry_count++;
                if (retry_count > MAX_RETRIES) {
                    DEBUG_PRINT("JUDGE: rbox-wrap failed after %d retries - fail closed\n", MAX_RETRIES);
                    return 2;  /* Error: couldn't reach server, fail closed */
                }
                DEBUG_PRINT("JUDGE: child exited with code %d, retry %d/%d\n", code, retry_count, MAX_RETRIES);
                sleep(1);
                continue;
            } else {
                retry_count++;
                if (retry_count > MAX_RETRIES) {
                    DEBUG_PRINT("JUDGE: rbox-wrap terminated abnormally after %d retries - fail closed\n", MAX_RETRIES);
                    return 2;
                }
                DEBUG_PRINT("JUDGE: child terminated, retry %d/%d\n", retry_count, MAX_RETRIES);
                sleep(1);
                continue;
            }
        }

        rbox_decoded_header_t header;
        rbox_response_details_t details;
        rbox_env_decisions_t env_decisions;
        memset(&env_decisions, 0, sizeof(env_decisions));

        rbox_decode_header(buffer, bytes_read, &header);
        if (!header.valid) {
            free(buffer);
            if (WIFEXITED(status)) {
                int code = WEXITSTATUS(status);
                if (code == 9) return 9;
                /* Invalid header - retry */
                retry_count++;
                if (retry_count > MAX_RETRIES) {
                    DEBUG_PRINT("JUDGE: invalid header after %d retries - fail closed\n", MAX_RETRIES);
                    return 2;  /* Error: couldn't parse response */
                }
                DEBUG_PRINT("JUDGE: invalid header, retry %d/%d\n", retry_count, MAX_RETRIES);
                sleep(1);
                continue;
            }
            retry_count++;
            if (retry_count > MAX_RETRIES) {
                DEBUG_PRINT("JUDGE: invalid header (abnormal exit) after %d retries - fail closed\n", MAX_RETRIES);
                return 2;
            }
            DEBUG_PRINT("JUDGE: invalid header, retry %d/%d\n", retry_count, MAX_RETRIES);
            sleep(1);
            continue;
        }

        rbox_decode_env_decisions(&header, &details, buffer, bytes_read, &env_decisions);
        if (env_decisions.valid && env_decisions.env_count > 0 && env_decisions.bitmap) {
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

            free(env_decisions.bitmap);
        }

        rbox_decode_response_details(&header, buffer, bytes_read, &details);
        if (details.valid) {
            free(buffer);
            if (details.decision == RBOX_DECISION_ALLOW) return 0;
            else return 9;
        }

        free(buffer);
        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            if (code == 9) return 9;
            /* Invalid details with exit 0 - retry, don't assume allow */
            retry_count++;
            if (retry_count > MAX_RETRIES) {
                DEBUG_PRINT("JUDGE: invalid details after %d retries - fail closed\n", MAX_RETRIES);
                return 2;  /* Error: couldn't parse response */
            }
            DEBUG_PRINT("JUDGE: invalid details, retry %d/%d\n", retry_count, MAX_RETRIES);
            sleep(1);
            continue;
        }
        retry_count++;
        if (retry_count > MAX_RETRIES) {
            DEBUG_PRINT("JUDGE: invalid details (abnormal exit) after %d retries - fail closed\n", MAX_RETRIES);
            return 2;
        }
        DEBUG_PRINT("JUDGE: invalid details, retry %d/%d\n", retry_count, MAX_RETRIES);
        sleep(1);
        continue;
    }
}
