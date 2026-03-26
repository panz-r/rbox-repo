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

/* Request arguments for client threads */
typedef struct {
    const char *path;
    const char *cmd;
    int argc;
    const char **args;
    uint8_t expected;
    int result; /* 0 success, -1 failure */
} request_args_t;

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
    (void)errors;
    return NULL;
}

/* Proper non-blocking connect with timeout (issue #1)
 * Returns: 0 on success, -1 on failure */
static int connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addrlen, int timeout_ms) {
    int ret = connect(fd, addr, addrlen);
    if (ret == 0) return 0;
    if (errno != EINPROGRESS) return -1;

    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    if (poll(&pfd, 1, timeout_ms) <= 0) return -1;

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
    usleep(CLIENT_CLOSE_DELAY_US);
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
    (void)write(fd, "GARBAGE DATA NOT A PACKET", 25);
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
    *(uint32_t *)(pkt + 0) = 0xDEADBEEF;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_VERSION) = RBOX_VERSION;
    (void)write(fd, pkt, RBOX_HEADER_SIZE);
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
    (void)write(fd, pkt, 10);
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
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHUNK_LEN) = 50;
    (void)write(fd, pkt, RBOX_HEADER_SIZE + 25);
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

    char pkt[RBOX_HEADER_SIZE];
    memset(pkt, 0, RBOX_HEADER_SIZE);
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_MAGIC) = RBOX_MAGIC;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_VERSION) = RBOX_VERSION;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHUNK_LEN) = 2 * 1024 * 1024;
    (void)write(fd, pkt, RBOX_HEADER_SIZE);
    char resp[4096];
    (void)read(fd, resp, sizeof(resp));
    close(fd);
    return NULL;
}

/* Client that sends valid request, then waits and reconnects */
static void *client_with_reconnect(void *arg) {
    int *result = arg;
    *result = -1;

    for (int attempt = 0; attempt < 3; attempt++) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return NULL;

        struct sockaddr_un addr = { .sun_family = AF_UNIX };
        strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

        if (connect_with_timeout(fd, (struct sockaddr *)&addr, sizeof(addr), CONNECT_TIMEOUT_MS) < 0) {
            close(fd);
            usleep(CLIENT_DELAY_US);
            continue;
        }

        char pkt[8192];
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "reconnect_test_%d", attempt);
        size_t pkt_len;
        const char *args[] = { cmd };
        rbox_error_t err = rbox_build_request(pkt, sizeof(pkt), &pkt_len, cmd, NULL, NULL, 1, args, 0, NULL, NULL);
        if (err != RBOX_OK) {
            close(fd);
            usleep(CLIENT_DELAY_US);
            continue;
        }
        (void)write(fd, pkt, pkt_len);

        char resp[4096];
        ssize_t n = read(fd, resp, sizeof(resp));
        close(fd);

        if (n > 0) {
            if (n >= (ssize_t)(RBOX_HEADER_SIZE + 1)) {
                uint32_t magic = *(uint32_t *)resp;
                if (magic == RBOX_MAGIC) {
                    uint8_t decision = *(uint8_t *)(resp + RBOX_HEADER_SIZE);
                    if (decision == RBOX_DECISION_ALLOW) {
                        *result = 0;
                        return NULL;
                    }
                }
            }
        }

        usleep(CLIENT_DELAY_US);
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
    for (int i = 0; i < 3; i++) {
        char pkt[8192];
        char cmd[32];
        snprintf(cmd, sizeof(cmd), "cmd_%d", i);
        size_t pkt_len;
        const char *args[] = { cmd };
        rbox_build_request(pkt, sizeof(pkt), &pkt_len, cmd, NULL, NULL, 1, args, 0, NULL, NULL);
        (void)write(fd, pkt, pkt_len);
    }
    char resp[4096];
    for (int i = 0; i < 3; i++) {
        (void)read(fd, resp, sizeof(resp));
    }
    close(fd);
    return NULL;
}

/* ============================================================================
 * Test Cases – using high‑level client API
 * ============================================================================ */

/* Helper: send request and check decision using rbox_blocking_request */
static int do_request_decision(const char *path, const char *cmd, int argc, const char **args,
                               uint8_t expected_decision) {
    rbox_response_t resp;
    rbox_error_t err = rbox_blocking_request(path, cmd, argc, args, NULL, NULL,
                                              0, NULL, NULL, &resp, 0, 0);
    if (err != RBOX_OK) return -1;
    return (resp.decision == expected_decision) ? 0 : -1;
}

/* Thread function for client requests */
static void *request_thread(void *arg) {
    request_args_t *ra = arg;
    ra->result = do_request_decision(ra->path, ra->cmd, ra->argc, ra->args, ra->expected);
    return NULL;
}

/* Server that accepts one request and allows it */
static void *server_epoll_allow_static(void *arg) {
    const char *path = arg;
    rbox_server_handle_t *srv = rbox_server_handle_new(path);
    if (!srv) return NULL;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return NULL; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return NULL; }

    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (req) {
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL);
    }

    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return NULL;
}

/* Test 1: Basic single request */
static int test_single_request(void) {
    unlink(SOCKET_PATH);

    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_epoll_allow_static, (void *)SOCKET_PATH) != 0) {
        unlink(SOCKET_PATH);
        return -1;
    }

    /* Wait for server to be ready */
    struct stat st;
    int timeout = 2000;
    while (timeout > 0) {
        if (stat(SOCKET_PATH, &st) == 0 && S_ISSOCK(st.st_mode)) break;
        usleep(10000);
        timeout -= 10;
    }
    if (timeout <= 0) { pthread_join(tid, NULL); unlink(SOCKET_PATH); return -1; }

    const char *args[] = {"-la"};
    int ret = do_request_decision(SOCKET_PATH, "ls", 1, args, RBOX_DECISION_ALLOW);
    usleep(TEST_SHORT_DELAY_US);

    pthread_join(tid, NULL);
    unlink(SOCKET_PATH);
    return ret;
}

/* Test 2: Multiple arguments */
static int test_multiple_args(void) {
    unlink(SOCKET_PATH);

    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_epoll_allow_static, (void *)SOCKET_PATH) != 0) {
        unlink(SOCKET_PATH);
        return -1;
    }

    /* Wait for server to be ready */
    struct stat st;
    int timeout = 2000;
    while (timeout > 0) {
        if (stat(SOCKET_PATH, &st) == 0 && S_ISSOCK(st.st_mode)) break;
        usleep(10000);
        timeout -= 10;
    }
    if (timeout <= 0) { pthread_join(tid, NULL); unlink(SOCKET_PATH); return -1; }

    const char *args[] = {"/tmp", "-name", "test", "-type", "f"};
    int ret = do_request_decision(SOCKET_PATH, "find", 5, args, RBOX_DECISION_ALLOW);
    usleep(TEST_SHORT_DELAY_US);

    pthread_join(tid, NULL);
    unlink(SOCKET_PATH);
    return ret;
}

/* Server that returns DENY */
static void *server_epoll_deny_static(void *arg) {
    const char *path = arg;
    rbox_server_handle_t *srv = rbox_server_handle_new(path);
    if (!srv) return NULL;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return NULL; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return NULL; }

    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (req) {
        rbox_server_decide(req, RBOX_DECISION_DENY, "denied", 0, 0, NULL, NULL);
    }

    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return NULL;
}

/* Test 3: Deny decision */
static int test_deny_decision(void) {
    unlink(SOCKET_PATH);

    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_epoll_deny_static, (void *)SOCKET_PATH) != 0) {
        unlink(SOCKET_PATH);
        return -1;
    }

    /* Wait for server to be ready */
    struct stat st;
    int timeout = 2000;
    while (timeout > 0) {
        if (stat(SOCKET_PATH, &st) == 0 && S_ISSOCK(st.st_mode)) break;
        usleep(10000);
        timeout -= 10;
    }
    if (timeout <= 0) { pthread_join(tid, NULL); unlink(SOCKET_PATH); return -1; }

    const char *args[] = {"-la"};
    int ret = do_request_decision(SOCKET_PATH, "ls", 1, args, RBOX_DECISION_DENY);
    usleep(TEST_SHORT_DELAY_US);

    pthread_join(tid, NULL);
    unlink(SOCKET_PATH);
    return ret;
}

/* Server that accepts two sequential requests and allows them */
static void *server_epoll_allow_two_static(void *arg) {
    const char *path = arg;
    rbox_server_handle_t *srv = rbox_server_handle_new(path);
    if (!srv) return NULL;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return NULL; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return NULL; }

    for (int i = 0; i < 2; i++) {
        rbox_server_request_t *req = rbox_server_get_request(srv);
        if (req) {
            rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL);
        }
    }

    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return NULL;
}

/* Test 4: Multiple sequential requests */
static int test_sequential_requests(void) {
    unlink(SOCKET_PATH);

    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_epoll_allow_two_static, (void *)SOCKET_PATH) != 0) {
        unlink(SOCKET_PATH);
        return -1;
    }

    /* Wait for server to be ready */
    struct stat st;
    int timeout = 2000;
    while (timeout > 0) {
        if (stat(SOCKET_PATH, &st) == 0 && S_ISSOCK(st.st_mode)) break;
        usleep(10000);
        timeout -= 10;
    }
    if (timeout <= 0) { pthread_join(tid, NULL); unlink(SOCKET_PATH); return -1; }

    const char *args1[] = {"aux"};
    int ret1 = do_request_decision(SOCKET_PATH, "ps", 1, args1, RBOX_DECISION_ALLOW);
    usleep(TEST_SHORT_DELAY_US);
    const char *args2[] = {"-h"};
    int ret2 = do_request_decision(SOCKET_PATH, "df", 1, args2, RBOX_DECISION_ALLOW);
    usleep(TEST_SHORT_DELAY_US);

    pthread_join(tid, NULL);
    unlink(SOCKET_PATH);
    return (ret1 == 0 && ret2 == 0) ? 0 : -1;
}

/* Server that accepts three sequential requests and allows them */
static void *server_epoll_allow_three_static(void *arg) {
    const char *path = arg;
    rbox_server_handle_t *srv = rbox_server_handle_new(path);
    if (!srv) return NULL;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return NULL; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return NULL; }

    for (int i = 0; i < 3; i++) {
        rbox_server_request_t *req = rbox_server_get_request(srv);
        if (req) {
            rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL);
        }
    }

    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return NULL;
}

/* Test 5: Multiple sequential clients (each in own connection) */
static int test_concurrent_clients(void) {
    unlink(SOCKET_PATH);

    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_epoll_allow_three_static, (void *)SOCKET_PATH) != 0) {
        unlink(SOCKET_PATH);
        return -1;
    }

    /* Wait for server to be ready */
    struct stat st;
    int timeout = 2000;
    while (timeout > 0) {
        if (stat(SOCKET_PATH, &st) == 0 && S_ISSOCK(st.st_mode)) break;
        usleep(10000);
        timeout -= 10;
    }
    if (timeout <= 0) { pthread_join(tid, NULL); unlink(SOCKET_PATH); return -1; }

    const char *commands[][2] = {{"ls", "-la"}, {"pwd", NULL}, {"cat", "/dev/null"}};
    for (int i = 0; i < 3; i++) {
        const char *args[] = {commands[i][1]};
        int argc = (commands[i][1] != NULL) ? 1 : 0;
        if (do_request_decision(SOCKET_PATH, commands[i][0], argc, args, RBOX_DECISION_ALLOW) != 0) {
            pthread_join(tid, NULL);
            unlink(SOCKET_PATH);
            return -1;
        }
        usleep(TEST_SHORT_DELAY_US);
    }

    pthread_join(tid, NULL);
    unlink(SOCKET_PATH);
    return 0;
}

/* Test 6: Empty command */
static int test_empty_command(void) {
    unlink(SOCKET_PATH);

    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_epoll_allow_static, (void *)SOCKET_PATH) != 0) {
        unlink(SOCKET_PATH);
        return -1;
    }

    /* Wait for server to be ready */
    struct stat st;
    int timeout = 2000;
    while (timeout > 0) {
        if (stat(SOCKET_PATH, &st) == 0 && S_ISSOCK(st.st_mode)) break;
        usleep(10000);
        timeout -= 10;
    }
    if (timeout <= 0) { pthread_join(tid, NULL); unlink(SOCKET_PATH); return -1; }

    int ret = do_request_decision(SOCKET_PATH, "", 0, NULL, RBOX_DECISION_ALLOW);
    usleep(TEST_SHORT_DELAY_US);

    pthread_join(tid, NULL);
    unlink(SOCKET_PATH);
    return ret;
}

/* Test 7: Parse result access */
static int test_parse_result(void) {
    unlink(SOCKET_PATH);

    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_epoll_allow_static, (void *)SOCKET_PATH) != 0) {
        unlink(SOCKET_PATH);
        return -1;
    }

    /* Wait for server to be ready */
    struct stat st;
    int timeout = 2000;
    while (timeout > 0) {
        if (stat(SOCKET_PATH, &st) == 0 && S_ISSOCK(st.st_mode)) break;
        usleep(10000);
        timeout -= 10;
    }
    if (timeout <= 0) { pthread_join(tid, NULL); unlink(SOCKET_PATH); return -1; }

    int ret = do_request_decision(SOCKET_PATH, "git commit -m test", 3,
                                 (const char*[]){"commit", "-m", "test"}, RBOX_DECISION_ALLOW);
    usleep(TEST_SHORT_DELAY_US);

    pthread_join(tid, NULL);
    unlink(SOCKET_PATH);
    return ret;
}

/* Test 8: Duration in response */
static int test_duration_response(void) {
    unlink(SOCKET_PATH);

    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_epoll_allow_static, (void *)SOCKET_PATH) != 0) {
        unlink(SOCKET_PATH);
        return -1;
    }

    /* Wait for server to be ready */
    struct stat st;
    int timeout = 2000;
    while (timeout > 0) {
        if (stat(SOCKET_PATH, &st) == 0 && S_ISSOCK(st.st_mode)) break;
        usleep(10000);
        timeout -= 10;
    }
    if (timeout <= 0) { pthread_join(tid, NULL); unlink(SOCKET_PATH); return -1; }

    int ret = do_request_decision(SOCKET_PATH, "test", 0, NULL, RBOX_DECISION_ALLOW);
    usleep(TEST_SHORT_DELAY_US);

    pthread_join(tid, NULL);
    unlink(SOCKET_PATH);
    return ret;
}

/* Test 9: Reason in response */
static int test_reason_response(void) {
    unlink(SOCKET_PATH);

    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_epoll_allow_static, (void *)SOCKET_PATH) != 0) {
        unlink(SOCKET_PATH);
        return -1;
    }

    /* Wait for server to be ready */
    struct stat st;
    int timeout = 2000;
    while (timeout > 0) {
        if (stat(SOCKET_PATH, &st) == 0 && S_ISSOCK(st.st_mode)) break;
        usleep(10000);
        timeout -= 10;
    }
    if (timeout <= 0) { pthread_join(tid, NULL); unlink(SOCKET_PATH); return -1; }

    int ret = do_request_decision(SOCKET_PATH, "test", 0, NULL, RBOX_DECISION_ALLOW);
    usleep(TEST_SHORT_DELAY_US);

    pthread_join(tid, NULL);
    unlink(SOCKET_PATH);
    return ret;
}

/* Server that accepts multiple requests and allows them */
static void *server_epoll_allow_many_static(void *arg) {
    const char *path = arg;
    rbox_server_handle_t *srv = rbox_server_handle_new(path);
    if (!srv) return NULL;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return NULL; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return NULL; }

    const int NUM_REQUESTS = 100;
    for (int i = 0; i < NUM_REQUESTS; i++) {
        rbox_server_request_t *req = rbox_server_get_request(srv);
        if (req) {
            rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL);
        }
    }

    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return NULL;
}

/* Test 10: Many concurrent clients */
static int test_many_clients(void) {
    unlink(SOCKET_PATH);

    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_epoll_allow_many_static, (void *)SOCKET_PATH) != 0) {
        unlink(SOCKET_PATH);
        return -1;
    }

    /* Wait for server to be ready */
    struct stat st;
    int timeout = 2000;
    while (timeout > 0) {
        if (stat(SOCKET_PATH, &st) == 0 && S_ISSOCK(st.st_mode)) break;
        usleep(10000);
        timeout -= 10;
    }
    if (timeout <= 0) { pthread_join(tid, NULL); unlink(SOCKET_PATH); return -1; }

    const int NUM_CLIENTS = 100;
    pthread_t clients[NUM_CLIENTS];
    request_args_t args[NUM_CLIENTS];
    int success_count = 0;

    for (int i = 0; i < NUM_CLIENTS; i++) {
        args[i].path = SOCKET_PATH;
        args[i].cmd = "ls";
        args[i].argc = 1;
        static const char *ls_args[] = {"-la"};
        args[i].args = ls_args;
        args[i].expected = RBOX_DECISION_ALLOW;
        args[i].result = -1;
        if (checked_pthread_create(&clients[i], NULL, request_thread, &args[i]) != 0) {
            for (int j = 0; j < i; j++) {
                pthread_join(clients[j], NULL);
            }
            pthread_cancel(tid);
            pthread_join(tid, NULL);
            unlink(SOCKET_PATH);
            return -1;
        }
    }

    for (int i = 0; i < NUM_CLIENTS; i++) {
        pthread_join(clients[i], NULL);
        if (args[i].result == 0) success_count++;
    }

    pthread_join(tid, NULL);
    unlink(SOCKET_PATH);
    return (success_count == NUM_CLIENTS) ? 0 : -1;
}

/* Test 11: Many misbehaving clients - stress test server robustness */
static int test_misbehaving_clients(void) {
    signal(SIGPIPE, SIG_IGN);
    unlink(SOCKET_PATH);

    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

#define NUM_MISBEHAVING 20
#define NUM_GOOD 5

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

    for (int i = 0; i < NUM_MISBEHAVING; i++) {
        pthread_t tid;
        thread_func_t func = behaviors[i % num_behaviors];
        if (checked_pthread_create(&tid, NULL, func, NULL) != 0) {
            rbox_server_stop(srv);
            rbox_server_handle_free(srv);
            unlink(SOCKET_PATH);
            return -1;
        }
        pthread_detach(tid);
    }

    usleep(TEST_LONG_DELAY_US);

    pthread_t good_clients[NUM_GOOD];
    request_args_t good_args[NUM_GOOD];
    for (int i = 0; i < NUM_GOOD; i++) {
        good_args[i].path = SOCKET_PATH;
        good_args[i].cmd = "valid_cmd";
        good_args[i].argc = 1;
        static const char *valid_args[] = {""};
        good_args[i].args = valid_args;
        good_args[i].expected = RBOX_DECISION_ALLOW;
        good_args[i].result = -1;
        if (checked_pthread_create(&good_clients[i], NULL, request_thread, &good_args[i]) != 0) {
            rbox_server_stop(srv);
            rbox_server_handle_free(srv);
            unlink(SOCKET_PATH);
            return -1;
        }
    }

    usleep(TEST_LONG_DELAY_US);

    int received = 0;
    volatile sig_atomic_t done = 0;
    worker_ctx_t ctx = { .srv = srv, .done = &done, .received = &received };
    pthread_t worker_thread;
    if (checked_pthread_create(&worker_thread, NULL, worker_static, &ctx) != 0) return -1;

    usleep(TEST_EXTRA_LONG_DELAY_US);
    done = 1;
    rbox_server_stop(srv);

    pthread_join(worker_thread, NULL);
    for (int i = 0; i < NUM_GOOD; i++) {
        pthread_join(good_clients[i], NULL);
        if (good_args[i].result == 0) received++;
    }

    rbox_server_handle_free(srv);
    unlink(SOCKET_PATH);
    return (received >= NUM_GOOD) ? 0 : -1;
}

/* Wait for server to be ready */
static int wait_for_server(const char *path, int timeout_ms) {
    int elapsed = 0;
    int interval = 10;
    while (elapsed < timeout_ms) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISSOCK(st.st_mode)) {
            return 0;
        }
        usleep(interval * 1000);
        elapsed += interval;
    }
    return -1;
}

/* Test 11b: Run each misbehaving client type individually */
static int test_misbehaving_client_type(thread_func_t behavior, const char *name) {
    signal(SIGPIPE, SIG_IGN);
    unlink(SOCKET_PATH);

    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    if (wait_for_server(SOCKET_PATH, 2000) != 0) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, behavior, NULL) != 0) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }
    pthread_detach(tid);
    usleep(TEST_SHORT_DELAY_US);

    request_args_t good_args;
    good_args.path = SOCKET_PATH;
    good_args.cmd = "valid_cmd";
    good_args.argc = 1;
    static const char *valid_args[] = {""};
    good_args.args = valid_args;
    good_args.expected = RBOX_DECISION_ALLOW;
    good_args.result = -1;
    pthread_t good_tid;
    if (checked_pthread_create(&good_tid, NULL, request_thread, &good_args) != 0) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }

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
    unlink(SOCKET_PATH);
    printf("    %s: received %d\n", name, received);
    return (received >= 1) ? 0 : -1;
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
        "no_send", "garbage", "bad_magic", "truncated_header",
        "truncated_body", "multiple_requests", "too_large"
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

    /* First server session */
    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    for (int i = 0; i < 2; i++) {
        if (checked_pthread_create(&clients[i], NULL, client_with_reconnect, &results[i]) != 0) return -1;
    }

    worker_ctx_t ctx = { .srv = srv, .done = &done, .received = &received };
    pthread_t worker_thread;
    if (checked_pthread_create(&worker_thread, NULL, worker_static, &ctx) != 0) return -1;

    usleep(TEST_LONG_DELAY_US);
    done = 1;
    rbox_server_stop(srv);
    pthread_join(worker_thread, NULL);
    rbox_server_handle_free(srv);

    for (int i = 0; i < 2; i++) {
        pthread_join(clients[i], NULL);
    }

    usleep(TEST_MEDIUM_DELAY_US);

    /* Second server session */
    done = 0;
    received = 0;
    srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

    worker_ctx_t ctx2 = { .srv = srv, .done = &done, .received = &received };
    if (checked_pthread_create(&worker_thread, NULL, worker_static, &ctx2) != 0) return -1;

    for (int i = 2; i < 5; i++) {
        if (checked_pthread_create(&clients[i], NULL, client_with_reconnect, &results[i]) != 0) return -1;
    }

    usleep(CLIENT_CLOSE_DELAY_US);
    done = 1;
    rbox_server_stop(srv);
    pthread_join(worker_thread, NULL);

    for (int i = 2; i < 5; i++) {
        pthread_join(clients[i], NULL);
    }
    rbox_server_handle_free(srv);

    int success = 0;
    for (int i = 0; i < 5; i++) {
        if (results[i] == 0) success++;
    }
    printf("    Total: %d/5 clients succeeded\n", success);
    return (success >= 3) ? 0 : -1;
}

/* Test 13: Too large command rejection */
static int test_too_large_command(void) {
    unlink(SOCKET_PATH);

    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }

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

    request_args_t good_args[3];
    static const char *valid_args[] = {""};
    for (int i = 0; i < 3; i++) {
        good_args[i].path = SOCKET_PATH;
        good_args[i].cmd = "valid";
        good_args[i].argc = 0;
        good_args[i].args = NULL;
        good_args[i].expected = RBOX_DECISION_ALLOW;
        good_args[i].result = -1;
        if (checked_pthread_create(&cls[2 + i], NULL, request_thread, &good_args[i]) != 0) {
            rbox_server_stop(srv);
            rbox_server_handle_free(srv);
            return -1;
        }
    }

    int received = 0;
    volatile sig_atomic_t done = 0;
    worker_ctx_t ctx = { .srv = srv, .done = &done, .received = &received };
    pthread_t worker_thread;
    if (checked_pthread_create(&worker_thread, NULL, worker_static, &ctx) != 0) return -1;

    /* Wait for clients to connect and send requests (2 seconds) */
    usleep(TEST_CLEANUP_DELAY_US);

    done = 1;
    rbox_server_stop(srv);
    pthread_join(worker_thread, NULL);

    for (int i = 0; i < 5; i++) {
        pthread_join(cls[i], NULL);
    }
    for (int i = 0; i < 3; i++) {
        if (good_args[i].result == 0) received++;
    }

    rbox_server_handle_free(srv);
    unlink(SOCKET_PATH);
    printf("    Received %d valid requests despite oversized\n", received);
    return (received >= 3) ? 0 : -1;
}

/* ============================================================================
 * Main
 * ============================================================================ */

/* Cleanup handler to remove socket file on exit */
static void cleanup_handler(void) {
    unlink(SOCKET_PATH);
}

int main(void) {
    atexit(cleanup_handler);
    printf("=== Testing blocking server ===\n");
    fflush(stdout);

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
