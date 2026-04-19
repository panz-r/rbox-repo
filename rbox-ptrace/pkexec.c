/*
 * pkexec.c - pkexec launching for readonlybox-ptrace
 *
 * Handles relaunching with pkexec for privilege escalation while
 * preserving the screened environment via abstract Unix socket.
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/random.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>

#include "debug.h"
#include "compat_strl.h"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

#define ENV_SEND_MAX (1024 * 1024)

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
 *   resolved_cmd - the already-resolved command path to pass via --cmd
 *
 * The screened environment is passed via an abstract Unix socket
 * to avoid any filesystem footprint.
 */
int pkexec_launch(int argc, char *argv[], const char *resolved_cmd) {
    uid_t original_uid = getuid();
    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        strcpy(cwd, ".");
    }

    int result = 1;
    int srv_fd = -1;
    pid_t helper_pid = -1;
    int ready_pipe[2] = { -1, -1 };
    char sock_name[UNIX_PATH_MAX - 1] = "";
    char **new_argv = NULL;
    char **allocated_strings = NULL;
    int allocated_count = 0;

    /* 1. Create an abstract socket with a cryptographically random name */
    unsigned int random_val;
    if (getrandom(&random_val, sizeof(random_val), 0) != sizeof(random_val)) {
        random_val = (unsigned int)getpid() ^ (unsigned int)time(NULL);
    }
    snprintf(sock_name, sizeof(sock_name), "robox-env-%d-%x", getpid(), random_val);

    /* Abstract socket name: prepend a null byte */
    char abstract_name[UNIX_PATH_MAX];
    abstract_name[0] = '\0';
    strlcpy(abstract_name + 1, sock_name, sizeof(abstract_name) - 1);
    size_t name_len = strlen(sock_name) + 1; /* including leading null */

    /* Create listening socket */
    srv_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv_fd < 0) {
        LOG_ERRNO("socket");
        goto cleanup;
    }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    memcpy(addr.sun_path, abstract_name, name_len);
    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + name_len;
    if (bind(srv_fd, (struct sockaddr*)&addr, addr_len) < 0) {
        LOG_ERRNO("bind");
        goto cleanup;
    }
    if (listen(srv_fd, 1) < 0) {
        LOG_ERRNO("listen");
        goto cleanup;
    }

    /* 2. Create pipe for coordination */
    if (pipe(ready_pipe) < 0) {
        LOG_ERRNO("pipe");
        goto cleanup;
    }

    /* 3. Fork helper process */
    helper_pid = fork();
    if (helper_pid < 0) {
        LOG_ERRNO("fork");
        goto cleanup;
    }

    if (helper_pid == 0) {
        /* === HELPER PROCESS === */
        /* Detach from parent's process group to survive pkexec */
        setsid();
        close(ready_pipe[0]);   /* we only write */
        /* Signal parent that we are ready */
        if (write(ready_pipe[1], "R", 1) != 1) {
            exit(1);
        }
        close(ready_pipe[1]);

        /* Accept one connection */
        int conn = accept(srv_fd, NULL, NULL);
        if (conn < 0) {
            exit(0);
        }

        /* Send environment, size limited to 1 MB */
        size_t total_sent = 0;
        for (char **e = environ; *e; e++) {
            size_t len = strlen(*e);
            if (total_sent + len + 2 > ENV_SEND_MAX) {
                const char *trunc_msg = "#ENV_TRUNCATED\n";
                ssize_t _w = write(conn, trunc_msg, strlen(trunc_msg));
                (void)_w;
                break;
            }
            if (write(conn, *e, len) != (ssize_t)len) {
                break;
            }
            if (write(conn, "\n", 1) != 1) {
                break;
            }
            total_sent += len + 1;
        }
        /* Write empty line to mark end */
        ssize_t _w2 = write(conn, "\n", 1);
        (void)_w2;
        close(conn);
        exit(0);
    }

    /* === PARENT (original process) === */
    close(srv_fd);
    close(ready_pipe[1]);
    ready_pipe[1] = -1;

    /* Wait for helper to signal readiness (with a small timeout) */
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(ready_pipe[0], &fds);
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    int sel = select(ready_pipe[0] + 1, &fds, NULL, NULL, &tv);
    if (sel <= 0 || !FD_ISSET(ready_pipe[0], &fds)) {
        LOG_ERROR("Helper did not start in time");
        if (helper_pid > 0) {
            kill(helper_pid, SIGTERM);
        }
        goto cleanup;
    }
    char dummy;
    ssize_t _r = read(ready_pipe[0], &dummy, 1);
    (void)_r;
    close(ready_pipe[0]);
    ready_pipe[0] = -1;

    /* 4. Prepare pkexec arguments */
    new_argv = malloc((argc + 20) * sizeof(char *));
    if (!new_argv) {
        LOG_ERROR("malloc failed");
        goto cleanup;
    }

    allocated_strings = calloc(16, sizeof(char *));
    if (!allocated_strings) {
        LOG_ERROR("calloc failed");
        goto cleanup;
    }

    int idx = 0;
    new_argv[idx++] = "pkexec";
    new_argv[idx++] = "--disable-internal-agent";
    new_argv[idx++] = argv[0];  /* our program path */
    new_argv[idx++] = "--uid";
    char uid_str[32];
    snprintf(uid_str, sizeof(uid_str), "%d", original_uid);
    new_argv[idx] = strdup(uid_str);
    if (!new_argv[idx]) goto cleanup_argv;
    allocated_strings[allocated_count++] = new_argv[idx];
    idx++;
    new_argv[idx++] = "--cwd";
    new_argv[idx] = strdup(cwd);
    if (!new_argv[idx]) goto cleanup_argv;
    allocated_strings[allocated_count++] = new_argv[idx];
    idx++;
    new_argv[idx++] = "--env-socket";
    new_argv[idx] = strdup(sock_name);
    if (!new_argv[idx]) goto cleanup_argv;
    allocated_strings[allocated_count++] = new_argv[idx];
    idx++;
    new_argv[idx++] = "--internal-screened";
    new_argv[idx++] = "--cmd";
    new_argv[idx] = strdup(resolved_cmd);
    if (!new_argv[idx]) goto cleanup_argv;
    allocated_strings[allocated_count++] = new_argv[idx];
    idx++;

    /* Add remaining original arguments */
    for (int i = 1; i < argc; i++) {
        new_argv[idx++] = argv[i];
    }
    new_argv[idx] = NULL;

    /* Execute pkexec */
    execve("/usr/bin/pkexec", new_argv, environ);
    LOG_ERROR("execve pkexec failed: %s", strerror(errno));

cleanup_argv:
    for (int i = 0; i < allocated_count; i++) {
        free(allocated_strings[i]);
    }
    free(allocated_strings);
    free(new_argv);

cleanup:
    if (srv_fd >= 0) close(srv_fd);
    if (ready_pipe[0] >= 0) close(ready_pipe[0]);
    if (ready_pipe[1] >= 0) close(ready_pipe[1]);
    if (helper_pid > 0) {
        kill(helper_pid, SIGTERM);
        waitpid(helper_pid, NULL, 0);
    }
    return result;
}
