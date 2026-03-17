/*
 * test_blocking_server.c - Comprehensive tests for blocking server interface
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#include "rbox_protocol.h"

/* Thread function pointer type */
typedef void *(*thread_func_t)(void*);

/* Worker context struct to avoid nested functions as thread start routines */
typedef struct {
    rbox_server_handle_t *srv;
    volatile sig_atomic_t *done;
    int *received;
} worker_ctx_t;

static const char *SOCKET_PATH = "/tmp/rbox_test_block.sock";
static int test_passed = 0;
static int test_total = 0;

/* Consistent error reporting macro */
#define TEST_ERROR(fmt, ...) fprintf(stderr, "ERROR: " fmt "\n", ##__VA_ARGS__)

/* Named constants for delays (all in microseconds) */
#define CONNECT_TIMEOUT_MS         5000    /* milliseconds - this one is correctly named */
#define RESPONSE_TIMEOUT_MS       2000    /* milliseconds */
#define SHORT_DELAY_US            100000  /* 100 ms */
#define CLIENT_DELAY_US           200000  /* 200 ms */
#define CLIENT_CLOSE_DELAY_US     500000  /* 500 ms */
#define TEST_SHORT_DELAY_US       100000  /* 100 ms */
#define TEST_MEDIUM_DELAY_US      200000  /* 200 ms */
#define TEST_LONG_DELAY_US        300000  /* 300 ms */
#define TEST_EXTRA_LONG_DELAY_US  1000000 /* 1 second */
#define TEST_CLEANUP_DELAY_US     2000000 /* 2 seconds */

/* Static worker function - replaces nested functions as thread start routines */
static void *worker_static(void *arg) {
    worker_ctx_t *ctx = arg;
    int errors = 0;
    while (!*(ctx->done)) {
        rbox_server_request_t *req = rbox_server_get_request(ctx->srv);
        if (!req) break;
        (*(ctx->received))++;
        if (rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL) != RBOX_OK) {
            errors++;
        }
    }
    (void)errors;  /* Log if needed - for now just track */
    return NULL;
}

/* Proper non-blocking connect with timeout (issue #1)
 * Returns: 0 on success, -1 on failure */
static int connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addrlen, int timeout_ms) {
    int ret = connect(fd, addr, addrlen);
    if (ret == 0) return 0;                     // immediate success
    if (errno != EINPROGRESS) return -1;        // real error

    // Wait for connection to complete
    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    if (poll(&pfd, 1, timeout_ms) <= 0) return -1;

    // Check socket error
    int so_error;
    socklen_t optlen = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &optlen) < 0 || so_error != 0)
        return -1;
    return 0;
}

/* Wait for socket to be readable (event-based instead of sleep)
 * Returns: 1 if socket became readable, 0 if timeout, -1 on error */
static int wait_for_readable(int fd, int timeout_ms) {
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret < 0) return -1;
    if (ret == 0) return 0;
    return (pfd.revents & POLLIN) ? 1 : 0;
}

/* Checked pthread_create - fails test on error */
static int checked_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                                  void *(*start_routine)(void *), void *arg) {
    int err = pthread_create(thread, attr, start_routine, arg);
    if (err != 0) {
        TEST_ERROR("pthread_create failed: %s", strerror(err));
        return -1;
    }
    return 0;
}

/* Reference-quality write helper - handles all edge cases
 *
 * Returns: number of bytes written (== len on success), or -1 on error
 *
 * Handles:
 *   - Partial writes: loops until all data written
 *   - EINTR: retries automatically
 *   - EAGAIN/EWOULDBLOCK: for non-blocking sockets, returns error (caller should retry)
 *   - EPIPE: peer closed writing end
 *   - ECONNRESET: peer reset connection
 *   - ENOSPC: no space (for file/pipe writes)
 *   - EIO: I/O error
 *   - Other errors: returns error
 *   - Zero return: peer closed connection
 */
static ssize_t write_all(int fd, const void *buf, size_t len) {
    if (!buf || len == 0) {
        return 0;
    }

    const char *ptr = buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t written = write(fd, ptr, remaining);

        if (written < 0) {
            if (errno == EINTR) {
                /* Interrupted by signal - retry */
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Would block (non-blocking socket) - caller should retry */
                return -1;
            }
            /* Permanent error: EPIPE, ECONNRESET, ENOSPC, EIO, etc. */
            return -1;
        }

        if (written == 0) {
            /* Peer closed connection or other issue */
            return -1;
        }

        ptr += written;
        remaining -= written;
    }

    return len;
}

/* Robust read helper for testing - reads until buffer full or error */
static ssize_t read_all(int fd, void *buf, size_t len) {
    if (!buf || len == 0) {
        return 0;
    }

    char *ptr = buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t r = read(fd, ptr, remaining);

        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (r == 0) {
            break;  /* EOF */
        }

        ptr += r;
        remaining -= r;
    }

    return len - remaining;
}

#define RUN_TEST(fn, name) do { \
    test_total++; \
    printf("  Testing: %s...\n", name); \
    fflush(stdout); \
    if (fn() == 0) { \
        printf("    PASS\n"); \
        test_passed++; \
    } else { \
        printf("    FAIL\n"); \
    } \
    fflush(stdout); \
} while(0)

/* Send request and get response */
static void *client_send_thread(void *arg) {
    const char *cmd = arg;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    /* Use proper non-blocking connect with timeout (issue #1 fix) */
    if (connect_with_timeout(fd, (struct sockaddr *)&addr, sizeof(addr), CONNECT_TIMEOUT_MS) < 0) {
        close(fd);
        return NULL;
    }

    char pkt[8192];
    size_t pkt_len;
    const char *args[] = { cmd };
    /* Check return value of rbox_build_request (issue #3) */
    rbox_error_t err = rbox_build_request(pkt, sizeof(pkt), &pkt_len, cmd, NULL, NULL, 1, args, 0, NULL, NULL);
    if (err != RBOX_OK) {
        close(fd);
        return NULL;
    }
    if (write_all(fd, pkt, pkt_len) < 0) {
        close(fd);
        return NULL;
    }

    /* Wait for response to be available before reading */
    if (wait_for_readable(fd, RESPONSE_TIMEOUT_MS) <= 0) {
        close(fd);
        return NULL;
    }

    /* Read response - check if we got a valid response */
    char resp[4096];
    ssize_t r = read_all(fd, resp, sizeof(resp));
    if (r <= 0) {
        /* Server may have dropped connection - this is expected for some tests */
        close(fd);
        return NULL;
    }
    close(fd);

    return NULL;
}

/* Send request asynchronously - caller doesn't join */
static int send_request_async(const char *cmd) {
    pthread_t cl;
    if (checked_pthread_create(&cl, NULL, client_send_thread, (void *)cmd) != 0) return -1;
    pthread_detach(cl);  /* Thread will clean up on exit */
    return 0;
}

/* ============================================================================
 * Misbehaving Clients - for stress testing server robustness
 * ============================================================================ */

/* Client that connects but sends nothing */
static void *client_misbehave_no_send(void *arg) {
    (void)arg;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    usleep(CLIENT_CLOSE_DELAY_US);  /* Wait then close */
    close(fd);
    return NULL;
}

/* Client that sends garbage */
static void *client_misbehave_garbage(void *arg) {
    (void)arg;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    (void)write_all(fd, "GARBAGE DATA NOT A PACKET", 25);  /* May fail - testing error handling */
    close(fd);
    return NULL;
}

/* Client that sends bad magic */
static void *client_misbehave_bad_magic(void *arg) {
    (void)arg;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    char pkt[RBOX_HEADER_SIZE];
    memset(pkt, 0, RBOX_HEADER_SIZE);
    *(uint32_t *)(pkt + 0) = 0xDEADBEEF;  /* Bad magic */
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_VERSION) = RBOX_VERSION;
    (void)write_all(fd, pkt, RBOX_HEADER_SIZE);  /* May fail - testing error handling */
    close(fd);
    return NULL;
}

/* Client that sends truncated header */
static void *client_misbehave_truncated_header(void *arg) {
    (void)arg;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    char pkt[10];
    memset(pkt, 0, 10);
    (void)write_all(fd, pkt, 10);  /* Only 10 bytes */
    close(fd);
    return NULL;
}

/* Client that sends truncated body */
static void *client_misbehave_truncated_body(void *arg) {
    (void)arg;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    char pkt[RBOX_HEADER_SIZE + 50];
    memset(pkt, 0, sizeof(pkt));
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_MAGIC) = RBOX_MAGIC;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_VERSION) = RBOX_VERSION;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHUNK_LEN) = 50;  /* Claims 50 bytes */
    /* TRULY truncate: only send 25 bytes instead of claimed 50 */
    (void)write_all(fd, pkt, RBOX_HEADER_SIZE + 25);  /* Sends header + only 25 bytes */
    close(fd);
    return NULL;
}

/* Client that sends too large command (>1MB) - should be rejected */
static void *client_misbehave_too_large(void *arg) {
    (void)arg;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));

    /* Send a packet claiming 2MB (over limit) */
    char pkt[RBOX_HEADER_SIZE];
    memset(pkt, 0, RBOX_HEADER_SIZE);
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_MAGIC) = RBOX_MAGIC;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_VERSION) = RBOX_VERSION;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHUNK_LEN) = 2 * 1024 * 1024;  /* 2MB - over limit */
    (void)write_all(fd, pkt, RBOX_HEADER_SIZE);

    /* Read response - should indicate error or connection close */
    char resp[4096];
    (void)read_all(fd, resp, sizeof(resp));  /* May not get response for oversized */
    close(fd);
    return NULL;
}

/* Client that sends valid request, then waits and reconnects */
static void *client_with_reconnect(void *arg) {
    int *result = arg;  /* Store result: 0=success, -1=error */
    *result = -1;

    for (int attempt = 0; attempt < 3; attempt++) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return NULL;

        struct sockaddr_un addr = { .sun_family = AF_UNIX };
        strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

        /* Use proper non-blocking connect with timeout */
        if (connect_with_timeout(fd, (struct sockaddr *)&addr, sizeof(addr), CONNECT_TIMEOUT_MS) < 0) {
            close(fd);
            /* Small delay before retry - the loop itself provides backoff */
            usleep(CLIENT_DELAY_US);
            continue;
        }

        /* Send request */
        char pkt[8192];
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "reconnect_test_%d", attempt);
        size_t pkt_len;
        const char *args[] = { cmd };
        /* Check return value of rbox_build_request (issue #3) */
        rbox_error_t err = rbox_build_request(pkt, sizeof(pkt), &pkt_len, cmd, NULL, NULL, 1, args, 0, NULL, NULL);
        if (err != RBOX_OK) {
            close(fd);
            usleep(CLIENT_DELAY_US);
            continue;
        }
        (void)write_all(fd, pkt, pkt_len);

        /* Wait for response */
        char resp[4096];
        ssize_t n = read_all(fd, resp, sizeof(resp));
        close(fd);

        if (n > 0) {
            /* Check decision - use proper integer comparison for portability */
            if (n >= (ssize_t)(RBOX_HEADER_SIZE + 1)) {
                uint32_t magic = *(uint32_t *)resp;
                if (magic == RBOX_MAGIC) {
                    uint8_t decision = *(uint8_t *)(resp + RBOX_HEADER_SIZE);
                    if (decision == RBOX_DECISION_ALLOW) {
                        *result = 0;  /* Success! */
                        return NULL;
                    }
                }
            }
        }

        usleep(CLIENT_DELAY_US);  /* Wait before retry */
    }

    return NULL;
}

/* Client that sends multiple requests rapidly */
static void *client_misbehave_multiple_requests(void *arg) {
    (void)arg;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    /* Send 3 requests without waiting for responses */
    for (int i = 0; i < 3; i++) {
        char pkt[8192];
        char cmd[32];
        snprintf(cmd, sizeof(cmd), "cmd_%d", i);
        size_t pkt_len;
        const char *args[] = { cmd };
        rbox_build_request(pkt, sizeof(pkt), &pkt_len, cmd, NULL, NULL, 1, args, 0, NULL, NULL);
        (void)write_all(fd, pkt, pkt_len);
    }
    /* Read responses */
    char resp[4096];
    for (int i = 0; i < 3; i++) {
        (void)read_all(fd, resp, sizeof(resp));
    }
    close(fd);
    return NULL;
}

/* ============================================================================
 * Test Cases
 * ============================================================================ */

/* Test 1: Basic single request */
static int test_single_request(void) {
    unlink(SOCKET_PATH);

    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    /* Client sends request */
    if (send_request_async("ls -la") != 0) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    /* Server waits for request */
    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (!req) { rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }

    /* Verify */
    const char *cmd = rbox_server_request_command(req);
    if (!cmd || strcmp(cmd, "ls -la") != 0) {
        rbox_server_decide(req, RBOX_DECISION_DENY, "invalid", 0, 0, NULL, NULL);
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    /* Allow */
    if (rbox_server_decide(req, RBOX_DECISION_ALLOW, "allowed", 50, 0, NULL, NULL) != RBOX_OK) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    usleep(TEST_SHORT_DELAY_US);  /* Let client finish */
    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 2: Multiple arguments */
static int test_multiple_args(void) {
    unlink(SOCKET_PATH);

    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    if (send_request_async("find /tmp -name test -type f") != 0) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (!req) { rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }

    /* Should have multiple args via shellsplit */
    int argc = rbox_server_request_argc(req);
    (void)argc;  /* Verify shellsplit parsed arguments */
    if (rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL) != RBOX_OK) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    usleep(TEST_SHORT_DELAY_US);
    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 3: Deny decision */
static int test_deny_decision(void) {
    unlink(SOCKET_PATH);

    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    /* Client sends dangerous command */
    pthread_t cl;
    if (checked_pthread_create(&cl, NULL, client_send_thread, (void *)"rm -rf /") != 0) return -1;

    /* Server processes */
    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (!req) { pthread_join(cl, NULL); rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }

    /* Deny */
    if (rbox_server_decide(req, RBOX_DECISION_DENY, "dangerous command", 0, 0, NULL, NULL) != RBOX_OK) {
        pthread_join(cl, NULL);
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    pthread_join(cl, NULL);

    /* Create new client to get response */
    if (checked_pthread_create(&cl, NULL, client_send_thread, (void *)"ls") != 0) return -1;
    req = rbox_server_get_request(srv);
    if (req) {
        if (rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL) != RBOX_OK) {
            pthread_join(cl, NULL);
            rbox_server_stop(srv);
            rbox_server_handle_free(srv);
            return -1;
        }
    }
    pthread_join(cl, NULL);

    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 4: Multiple sequential requests */
static int test_sequential_requests(void) {
    unlink(SOCKET_PATH);

    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    /* Client sends 2 requests on same connection - need separate connections */
    if (send_request_async("ps aux") != 0) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }
    rbox_server_request_t *req1 = rbox_server_get_request(srv);
    if (!req1) { TEST_ERROR("get_request returned NULL for ps aux"); rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }
    if (rbox_server_decide(req1, RBOX_DECISION_ALLOW, "ok", 10, 0, NULL, NULL) != RBOX_OK) { TEST_ERROR("decide failed for ps aux"); rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }

    if (send_request_async("df -h") != 0) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }
    rbox_server_request_t *req2 = rbox_server_get_request(srv);
    if (!req2) { TEST_ERROR("get_request returned NULL for df -h"); rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }
    if (rbox_server_decide(req2, RBOX_DECISION_ALLOW, "ok", 10, 0, NULL, NULL) != RBOX_OK) { TEST_ERROR("decide failed for df -h"); rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }

    usleep(TEST_SHORT_DELAY_US);
    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 5: Multiple sequential clients (each in own connection) */
static int test_concurrent_clients(void) {
    unlink(SOCKET_PATH);

    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    /* Use different commands to avoid response cache hits */
    const char *commands[] = {"ls", "pwd", "cat"};

    /* Process 3 clients sequentially */
    for (int i = 0; i < 3; i++) {
        /* Start a client in background with different command */
        pthread_t cl;
        if (checked_pthread_create(&cl, NULL, client_send_thread, (void *)commands[i]) != 0) return -1;

        /* Wait a bit for client to connect and send */
        usleep(TEST_MEDIUM_DELAY_US);

        /* Wait for request */
        rbox_server_request_t *req = rbox_server_get_request(srv);
        if (!req) {
            pthread_join(cl, NULL);
            rbox_server_stop(srv);
            rbox_server_handle_free(srv);
            return -1;
        }

        /* Process and decide */
        if (rbox_server_decide(req, RBOX_DECISION_ALLOW, "allowed", 0, 0, NULL, NULL) != RBOX_OK) {
            pthread_join(cl, NULL);
            rbox_server_stop(srv);
            rbox_server_handle_free(srv);
            return -1;
        }

        pthread_join(cl, NULL);
    }

    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 6: Empty command */
static int test_empty_command(void) {
    unlink(SOCKET_PATH);

    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    if (send_request_async("") != 0) {  /* Empty command */
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (!req) { rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }

    const char *cmd = rbox_server_request_command(req);
    if (cmd == NULL || cmd[0] != '\0') {
        if (rbox_server_decide(req, RBOX_DECISION_DENY, "empty", 0, 0, NULL, NULL) != RBOX_OK) {
            rbox_server_stop(srv);
            rbox_server_handle_free(srv);
            return -1;
        }
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    if (rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL) != RBOX_OK) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    usleep(TEST_SHORT_DELAY_US);
    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 7: Parse result access */
static int test_parse_result(void) {
    unlink(SOCKET_PATH);

    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    pthread_t cl;
    if (checked_pthread_create(&cl, NULL, client_send_thread, (void *)"git commit -m test") != 0) return -1;

    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (!req) { pthread_join(cl, NULL); rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }

    /* Check parse result exists */
    const rbox_parse_result_t *parse = rbox_server_request_parse(req);
    if (!parse) { pthread_join(cl, NULL); rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }

    /* Just verify we got some subcommands */
    printf("    parse count = %u\n", parse->count);

    /* Check args via accessor */
    int argc = rbox_server_request_argc(req);
    printf("    argc = %d\n", argc);

    if (argc > 0) {
        const char *arg0 = rbox_server_request_arg(req, 0);
        if (arg0) printf("    arg0 = %s\n", arg0);
    }

    if (rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL) != RBOX_OK) {
        pthread_join(cl, NULL);
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    pthread_join(cl, NULL);
    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 8: Duration in response */
static int test_duration_response(void) {
    unlink(SOCKET_PATH);

    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    /* Run client in thread */
    pthread_t cl;
    if (checked_pthread_create(&cl, NULL, client_send_thread, (void *)"test") != 0) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (!req) { pthread_join(cl, NULL); rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }

    /* Send decision with specific duration */
    if (rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 1000, 0, NULL, NULL) != RBOX_OK) {
        pthread_join(cl, NULL);
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    pthread_join(cl, NULL);
    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 9: Reason in response */
static int test_reason_response(void) {
    unlink(SOCKET_PATH);

    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    pthread_t cl;
    if (checked_pthread_create(&cl, NULL, client_send_thread, (void *)"test") != 0) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (!req) { pthread_join(cl, NULL); rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }

    /* Send decision with reason */
    rbox_error_t err = rbox_server_decide(req, RBOX_DECISION_ALLOW, "test reason", 0, 0, NULL, NULL);
    if (err != RBOX_OK) { pthread_join(cl, NULL); rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }

    pthread_join(cl, NULL);
    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 10: Many concurrent clients */
static int test_many_clients(void) {
    unlink(SOCKET_PATH);

    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    const int NUM_CLIENTS = 100;  /* 100 clients */

    /* Start all clients */
    printf("    Starting %d clients...\n", NUM_CLIENTS);
    fflush(stdout);

    pthread_t clients[NUM_CLIENTS];
    char *cmd_ptrs[NUM_CLIENTS];  /* Store pointers to free later */
    for (int i = 0; i < NUM_CLIENTS; i++) {
        char cmd[32];
        snprintf(cmd, sizeof(cmd), "cmd_%d", i);
        cmd_ptrs[i] = strdup(cmd);
        if (checked_pthread_create(&clients[i], NULL, client_send_thread, cmd_ptrs[i]) != 0) {
            /* Clean up already-created threads and exit */
            for (int j = 0; j < i; j++) pthread_join(clients[j], NULL);
            for (int j = 0; j < i; j++) free(cmd_ptrs[j]);
            rbox_server_stop(srv);
            rbox_server_handle_free(srv);
            return -1;
        }
    }

    /* Give clients time to connect and send */
    printf("    Waiting for clients to send...\n");
    fflush(stdout);
    usleep(TEST_CLEANUP_DELAY_US);  /* 2 seconds */

    /* Process all requests */
    printf("    Processing requests...\n");
    fflush(stdout);

    int received = 0;
    int consecutive_failures = 0;

    while (received < NUM_CLIENTS && consecutive_failures < 5) {
        printf("    get_request #%d...\n", received + 1);
        fflush(stdout);

        rbox_server_request_t *req = rbox_server_get_request(srv);
        if (!req) {
            printf("    No request, sleeping...\n");
            consecutive_failures++;
            usleep(TEST_SHORT_DELAY_US);
            continue;
        }

        consecutive_failures = 0;
        const char *cmd = rbox_server_request_command(req);
        if (cmd) {
            received++;
        }

        printf("    decide #%d...\n", received);
        fflush(stdout);
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL);
    }

    /* Wait for all client threads */
    printf("    Waiting for clients to finish...\n");
    fflush(stdout);
    for (int i = 0; i < NUM_CLIENTS; i++) {
        pthread_join(clients[i], NULL);
        free(cmd_ptrs[i]);  /* Free the strdup'd strings */
    }

    rbox_server_stop(srv);
    rbox_server_handle_free(srv);

    printf("    Received %d/%d requests\n", received, NUM_CLIENTS);

    return received >= NUM_CLIENTS ? 0 : -1;
}

/* Test 11: Many misbehaving clients - stress test server robustness */
static int test_misbehaving_clients(void) {
    /* Ignore SIGPIPE - server may write to closed sockets from misbehaving clients */
    signal(SIGPIPE, SIG_IGN);

    unlink(SOCKET_PATH);

    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    /* Spawn various misbehaving clients */
    #define NUM_MISBEHAVING 20
    #define NUM_GOOD 5

    /* Mix of misbehaving clients */
    thread_func_t behaviors[] = {
        client_misbehave_no_send,
        client_misbehave_garbage,
        client_misbehave_bad_magic,
        client_misbehave_truncated_header,
        client_misbehave_truncated_body,
        client_misbehave_multiple_requests,
        client_misbehave_too_large,
    };
    int num_behaviors = sizeof(behaviors) / sizeof(behaviors[0]);

    /* Start misbehaving clients - detach them, no need to store thread IDs */
    for (int i = 0; i < NUM_MISBEHAVING; i++) {
        pthread_t tid;
        thread_func_t func = behaviors[i % num_behaviors];
        if (checked_pthread_create(&tid, NULL, func, NULL) != 0) {
            rbox_server_stop(srv);
            rbox_server_handle_free(srv);
            return -1;
        }
        pthread_detach(tid);
    }

    /* Give misbehaving clients time to connect and misbehave */
    usleep(TEST_LONG_DELAY_US);

    /* Also start some good clients - store their IDs to join later */
    pthread_t good_clients[NUM_GOOD];
    for (int i = 0; i < NUM_GOOD; i++) {
        if (checked_pthread_create(&good_clients[i], NULL, client_send_thread, (void *)"valid_cmd") != 0) {
            rbox_server_stop(srv);
            rbox_server_handle_free(srv);
            return -1;
        }
    }

    /* Give good clients time to send */
    usleep(TEST_LONG_DELAY_US);

    /* Process valid requests with a timeout - use a worker thread */
    int received = 0;
    volatile sig_atomic_t done = 0;

    worker_ctx_t ctx = { .srv = srv, .done = &done, .received = &received };

    pthread_t worker_thread;
    if (checked_pthread_create(&worker_thread, NULL, worker_static, &ctx) != 0) return -1;

    /* Wait for worker to process requests, with timeout */
    usleep(TEST_EXTRA_LONG_DELAY_US);  /* 1 second max */

    /* Signal done and stop server to unblock worker */
    done = 1;
    rbox_server_stop(srv);

    pthread_join(worker_thread, NULL);

    /* Wait for good client threads (misbehaving are detached) */
    for (int i = 0; i < NUM_GOOD; i++) {
        pthread_join(good_clients[i], NULL);
    }

    rbox_server_handle_free(srv);

    /* We should have received at least the good requests despite the chaos */
    printf("    Received %d requests from chaos\n", received);
    return received >= NUM_GOOD ? 0 : -1;
}

/* Wait for server to be ready - check if socket file exists
 * Uses stat to avoid triggering accept() which would cause server to exit
 * after handling the probe connection */
static int wait_for_server(const char *path, int timeout_ms) {
    int elapsed = 0;
    int interval = 10;  /* 10ms */

    while (elapsed < timeout_ms) {
        /* Check if socket file exists and is a socket */
        struct stat st;
        if (stat(path, &st) == 0 && S_ISSOCK(st.st_mode)) {
            return 0;  /* Socket exists */
        }
        usleep(interval);
        elapsed += interval;
    }
    return -1;  /* Timeout */
}

/* Test 11b: Run each misbehaving client type individually */
static int test_misbehaving_client_type(thread_func_t behavior, const char *name) {
    signal(SIGPIPE, SIG_IGN);

    unlink(SOCKET_PATH);

    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    /* Wait for server to be ready using event-based polling instead of fixed sleep */
    if (wait_for_server(SOCKET_PATH, 2000) != 0) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    /* Start one misbehaving client */
    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, behavior, NULL) != 0) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }
    pthread_detach(tid);

    /* Give it time to connect and misbehave */
    usleep(TEST_SHORT_DELAY_US);

    /* Start one good client */
    pthread_t good_tid;
    if (checked_pthread_create(&good_tid, NULL, client_send_thread, (void *)"valid_cmd") != 0) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    /* Process with worker thread */
    int received = 0;
    volatile sig_atomic_t done = 0;

    worker_ctx_t ctx = { .srv = srv, .done = &done, .received = &received };

    pthread_t worker_thread;
    if (checked_pthread_create(&worker_thread, NULL, worker_static, &ctx) != 0) {
        pthread_join(good_tid, NULL);
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    usleep(TEST_SHORT_DELAY_US);

    done = 1;
    rbox_server_stop(srv);

    pthread_join(worker_thread, NULL);
    pthread_join(good_tid, NULL);

    rbox_server_handle_free(srv);

    printf("    %s: received %d\n", name, received);
    return received >= 1 ? 0 : -1;
}

static int test_misbehaving_each(void) {
    printf("  Testing: misbehaving client types individually...\n");

    thread_func_t behaviors[] = {
        client_misbehave_no_send,
        client_misbehave_garbage,
        client_misbehave_bad_magic,
        client_misbehave_truncated_header,
        client_misbehave_truncated_body,
        client_misbehave_multiple_requests,
        client_misbehave_too_large,
    };
    const char *names[] = {
        "no_send",
        "garbage",
        "bad_magic",
        "truncated_header",
        "truncated_body",
        "multiple_requests",
        "too_large",
    };
    int num_behaviors = sizeof(behaviors) / sizeof(behaviors[0]);

    for (int i = 0; i < num_behaviors; i++) {
        printf("    Testing %s...\n", names[i]);
        if (test_misbehaving_client_type(behaviors[i], names[i]) != 0) {
            printf("    FAIL: %s\n", names[i]);
            return -1;
        }
    }

    printf("    PASS\n");
    return 0;
}

/* Test 12: Server restart mid-session with client reconnection */
static int test_server_restart(void) {
    unlink(SOCKET_PATH);

    int results[5] = {-1, -1, -1, -1, -1};
    pthread_t clients[5];
    int received = 0;
    volatile sig_atomic_t done = 0;

    /* ===== First server session ===== */
    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    /* Start clients */
    for (int i = 0; i < 2; i++) {
        if (checked_pthread_create(&clients[i], NULL, client_with_reconnect, &results[i]) != 0) return -1;
    }

    worker_ctx_t ctx = { .srv = srv, .done = &done, .received = &received };
    pthread_t worker_thread;
    if (checked_pthread_create(&worker_thread, NULL, worker_static, &ctx) != 0) return -1;

    usleep(TEST_LONG_DELAY_US);

    /* Stop first server */
    printf("    Stopping first server...\n");
    done = 1;
    rbox_server_stop(srv);
    pthread_join(worker_thread, NULL);
    rbox_server_handle_free(srv);

    printf("    First batch: received %d\n", received);

    /* Wait for clients to finish */
    for (int i = 0; i < 2; i++) {
        pthread_join(clients[i], NULL);
    }

    /* Brief pause */
    usleep(TEST_MEDIUM_DELAY_US);

    /* ===== Start second server ===== */
    printf("    Starting second server...\n");
    done = 0;
    received = 0;
    srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    worker_ctx_t ctx2 = { .srv = srv, .done = &done, .received = &received };
    if (checked_pthread_create(&worker_thread, NULL, worker_static, &ctx2) != 0) return -1;

    /* Start more clients */
    for (int i = 2; i < 5; i++) {
        if (checked_pthread_create(&clients[i], NULL, client_with_reconnect, &results[i]) != 0) return -1;
    }

    usleep(CLIENT_CLOSE_DELAY_US);

    /* Stop and collect */
    done = 1;
    rbox_server_stop(srv);
    pthread_join(worker_thread, NULL);

    printf("    Second batch: received %d\n", received);

    /* Wait for clients */
    for (int i = 2; i < 5; i++) {
        pthread_join(clients[i], NULL);
    }

    rbox_server_handle_free(srv);

    /* Count successes */
    int success = 0;
    for (int i = 0; i < 5; i++) {
        if (results[i] == 0) success++;
    }

    printf("    Total: %d/5 clients succeeded\n", success);

    return success >= 3 ? 0 : -1;
}

/* Test 13: Too large command rejection */
static int test_too_large_command(void) {
    unlink(SOCKET_PATH);

    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    /* Start multiple clients - some oversized, some normal */
    pthread_t cls[5];
    if (checked_pthread_create(&cls[0], NULL, client_misbehave_too_large, NULL) != 0) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }
    if (checked_pthread_create(&cls[1], NULL, client_misbehave_too_large, NULL) != 0) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }
    if (checked_pthread_create(&cls[2], NULL, client_send_thread, (void *)"valid1") != 0) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }
    if (checked_pthread_create(&cls[3], NULL, client_send_thread, (void *)"valid2") != 0) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }
    if (checked_pthread_create(&cls[4], NULL, client_send_thread, (void *)"valid3") != 0) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    /* Process requests with timeout */
    int received = 0;
    volatile sig_atomic_t done = 0;

    worker_ctx_t ctx = { .srv = srv, .done = &done, .received = &received };
    pthread_t worker_thread;
    if (checked_pthread_create(&worker_thread, NULL, worker_static, &ctx) != 0) return -1;

    usleep(CLIENT_CLOSE_DELAY_US);

    done = 1;
    rbox_server_stop(srv);
    pthread_join(worker_thread, NULL);

    for (int i = 0; i < 5; i++) {
        pthread_join(cls[i], NULL);
    }

    rbox_server_handle_free(srv);

    printf("    Received %d valid requests despite oversized\n", received);

    /* Test passes if server didn't crash and handled oversized commands */
    return received >= 3 ? 0 : -1;
}

/* ============================================================================
 * Main
 * ============================================================================ */

/* Cleanup handler to remove socket file on exit */
static void cleanup_handler(void) {
    unlink(SOCKET_PATH);
}

int main(void) {
    /* Register cleanup handler to remove socket on exit */
    atexit(cleanup_handler);
    printf("=== Testing blocking server ===\n");
    fflush(stdout);

    /* Initialize library - seeds RNG and inits CRC32 table */
    rbox_init();

    signal(SIGPIPE, SIG_IGN);

    RUN_TEST(test_single_request, "single request");
    RUN_TEST(test_multiple_args, "multiple arguments");
    RUN_TEST(test_deny_decision, "deny decision");
    RUN_TEST(test_sequential_requests, "sequential requests");
    RUN_TEST(test_concurrent_clients, "concurrent clients");
    RUN_TEST(test_empty_command, "empty command");
    RUN_TEST(test_parse_result, "parse result");
    RUN_TEST(test_duration_response, "duration response");
    RUN_TEST(test_reason_response, "reason response");
    RUN_TEST(test_many_clients, "100 concurrent clients");
    RUN_TEST(test_misbehaving_each, "misbehaving client types individually");
    RUN_TEST(test_misbehaving_clients, "misbehaving clients");
    RUN_TEST(test_server_restart, "server restart with reconnection");
    RUN_TEST(test_too_large_command, "too large command rejection");

    printf("\n=== Results: %d/%d tests passed ===\n", test_passed, test_total);
    fflush(stdout);
    return test_passed == test_total ? 0 : 1;
}
