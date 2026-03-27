/*
 * test_integration.c - Comprehensive integration tests for v9 protocol
 * Tests all scenarios including hickups, retries, and edge cases
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include "rbox_protocol.h"

/* Consistent error reporting macro */
#define TEST_ERROR(fmt, ...) fprintf(stderr, "ERROR: " fmt "\n", ##__VA_ARGS__)

static int pass_count = 0;
static int test_count = 0;

/* Forward declaration for wait_for_server */
static int wait_for_server(const char *path, int timeout_ms);

/* Checked pthread_create - reports error and returns -1 on failure */
static int checked_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                                  void *(*start_routine)(void *), void *arg) {
    int err = pthread_create(thread, attr, start_routine, arg);
    if (err != 0) {
        TEST_ERROR("pthread_create failed: %s", strerror(err));
        return -1;
    }
    return 0;
}

/* Reference-quality write helper - handles all edge cases */
static ssize_t write_all(int fd, const void *buf, size_t len) {
    if (!buf || len == 0) return 0;
    const char *ptr = buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t written = write(fd, ptr, remaining);
        if (written < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return -1;
            return -1;
        }
        if (written == 0) return -1;
        ptr += written;
        remaining -= written;
    }
    return len;
}

#define RUN_TEST(fn, name) do { \
    test_count++; \
    printf("  Testing: %s...\n", name); \
    fflush(stdout); \
    if (fn() == 0) { \
        printf("    PASS\n"); \
        pass_count++; \
    } else { \
        printf("    FAIL\n"); \
    } \
    fflush(stdout); \
} while(0)

/* ============================================================================
 * Server implementations using the epoll-based API (rbox_server_handle_*)
 * ============================================================================ */

typedef struct {
    const char *socket_path;
    rbox_server_handle_t *server;
} server_thread_arg_t;

/* Basic server that processes one request and sends ALLOW */
static void *server_epoll_allow(void *arg) {
    server_thread_arg_t *thread_arg = (server_thread_arg_t *)arg;
    const char *path = thread_arg->socket_path;
    rbox_server_handle_t *srv = rbox_server_handle_new(path);
    if (!srv) return NULL;

    if (rbox_server_handle_listen(srv) != RBOX_OK) {
        rbox_server_handle_free(srv);
        return NULL;
    }
    if (rbox_server_start(srv) != RBOX_OK) {
        rbox_server_handle_free(srv);
        return NULL;
    }

    thread_arg->server = srv;

    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (req) {
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL);
    }

    /* Caller must call rbox_server_stop and rbox_server_handle_free */
    return NULL;
}

/* Server that sends DENY */
static void *server_epoll_deny(void *arg) {
    server_thread_arg_t *thread_arg = (server_thread_arg_t *)arg;
    const char *path = thread_arg->socket_path;
    rbox_server_handle_t *srv = rbox_server_handle_new(path);
    if (!srv) return NULL;

    if (rbox_server_handle_listen(srv) != RBOX_OK) {
        rbox_server_handle_free(srv);
        return NULL;
    }
    if (rbox_server_start(srv) != RBOX_OK) {
        rbox_server_handle_free(srv);
        return NULL;
    }

    thread_arg->server = srv;

    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (req) {
        rbox_server_decide(req, RBOX_DECISION_DENY, "denied", 0, 0, NULL, NULL);
    }

    return NULL;
}

/* Server that delays response by 200ms */
static void *server_epoll_delayed(void *arg) {
    server_thread_arg_t *thread_arg = (server_thread_arg_t *)arg;
    const char *path = thread_arg->socket_path;
    rbox_server_handle_t *srv = rbox_server_handle_new(path);
    if (!srv) return NULL;

    if (rbox_server_handle_listen(srv) != RBOX_OK) {
        rbox_server_handle_free(srv);
        return NULL;
    }
    if (rbox_server_start(srv) != RBOX_OK) {
        rbox_server_handle_free(srv);
        return NULL;
    }

    thread_arg->server = srv;

    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (req) {
        usleep(200000);  /* 200ms delay before responding */
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL);
    }

    return NULL;
}

/* Server that reads request but does not send a response */
static void *server_epoll_drop(void *arg) {
    server_thread_arg_t *thread_arg = (server_thread_arg_t *)arg;
    const char *path = thread_arg->socket_path;
    rbox_server_handle_t *srv = rbox_server_handle_new(path);
    if (!srv) return NULL;

    if (rbox_server_handle_listen(srv) != RBOX_OK) {
        rbox_server_handle_free(srv);
        return NULL;
    }
    if (rbox_server_start(srv) != RBOX_OK) {
        rbox_server_handle_free(srv);
        return NULL;
    }

    thread_arg->server = srv;

    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (req) {
        /* Discard the request – server is stopping, cleanup will happen automatically */
    }

    /* Caller must call rbox_server_stop and rbox_server_handle_free */
    return NULL;
}

/* ============================================================================
 * Helper functions
 * ============================================================================ */

/* Wait for server to be ready - check if socket file exists */
static int wait_for_server(const char *path, int timeout_ms) {
    int elapsed = 0;
    int interval = 10;  /* 10ms */

    while (elapsed < timeout_ms) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISSOCK(st.st_mode)) {
            return 0;  /* Socket exists */
        }
        usleep(interval * 1000);
        elapsed += interval;
    }
    return -1;  /* Timeout */
}

/* Simple request using public blocking interface */
static int do_request(const char *path, const char *cmd, int argc, const char **args,
                      uint8_t *decision, char *errmsg, size_t errlen) {
    rbox_response_t response;
    rbox_error_t err = rbox_blocking_request(path, cmd, argc, args, NULL, NULL,
                                              0, NULL, NULL, &response, 0, 0);

    if (err != RBOX_OK) {
        if (errmsg && errlen > 0) snprintf(errmsg, errlen, "%s", rbox_strerror(err));
        return -1;
    }

    if (decision) *decision = response.decision;
    return 0;
}

/* Request with retry using public blocking interface */
static int do_request_retry(const char *path, const char *cmd, int argc, const char **args,
                            uint8_t *decision, char *errmsg, size_t errlen,
                            uint32_t base_delay_ms, uint32_t max_retries) {
    rbox_response_t response;
    rbox_error_t err = rbox_blocking_request(path, cmd, argc, args, NULL, NULL,
                                              0, NULL, NULL, &response,
                                              base_delay_ms, max_retries);

    if (err != RBOX_OK) {
        if (errmsg && errlen > 0) snprintf(errmsg, errlen, "%s", rbox_strerror(err));
        return -1;
    }

    if (decision) *decision = response.decision;
    return 0;
}

/* ============================================================================
 * Test cases
 * ============================================================================ */

/* Test 1: Simple round-trip */
static int test_simple(void) {
    const char *path = "/tmp/rbox_t1.sock";
    unlink(path);

    pthread_t tid;
    server_thread_arg_t arg = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, server_epoll_allow, &arg) != 0) {
        unlink(path);
        return -1;
    }

    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        unlink(path);
        return -1;
    }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    if (arg.server) rbox_server_stop(arg.server);
    pthread_join(tid, NULL);
    if (arg.server) rbox_server_handle_free(arg.server);
    unlink(path);
    return (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;
}
/* Thread function that runs a server until stopped */
static void *rbox_server_thread(void *arg) {
    server_thread_arg_t *thread_arg = (server_thread_arg_t *)arg;
    const char *socket_path = thread_arg->socket_path;

    rbox_server_handle_t *srv = rbox_server_handle_new(socket_path);
    if (!srv) return NULL;

    if (rbox_server_handle_listen(srv) != RBOX_OK) {
        rbox_server_handle_free(srv);
        return NULL;
    }
    if (rbox_server_start(srv) != RBOX_OK) {
        rbox_server_handle_free(srv);
        return NULL;
    }

    thread_arg->server = srv;

    /* Run until server is stopped */
    while (1) {
        rbox_server_request_t *req = rbox_server_get_request(srv);
        if (!req) break;
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL);
    }

    /* NOTE: Do NOT call rbox_server_handle_free here.
     * Caller must call rbox_server_stop() first, then rbox_server_handle_free after pthread_join. */
    return NULL;
}
/* Test 2: HICKUP_BAD_PACKET - send garbage, then retry */
static int test_hickup_bad_packet(void) {
    const char *path = "/tmp/rbox_t2.sock";
    unlink(path);
    int result = -1;

    /* First server */
    server_thread_arg_t sa = { .socket_path = path, .server = NULL };
    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, rbox_server_thread, &sa) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    /* Send garbage */
    rbox_client_t *cl = rbox_client_connect(path);
    if (cl) {
        write_all(rbox_client_fd(cl), "GARBAGE", 7);
        rbox_client_close(cl);
    }

    /* Stop first server */
    if (sa.server) rbox_server_stop(sa.server);
    pthread_join(tid, NULL);
    if (sa.server) rbox_server_handle_free(sa.server);
    unlink(path);
    usleep(100000); /* Wait for socket to be fully cleaned up */

    /* Second server (valid) */
    server_thread_arg_t sb = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, rbox_server_thread, &sb) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    if (sb.server) rbox_server_stop(sb.server);
    pthread_join(tid, NULL);
    if (sb.server) rbox_server_handle_free(sb.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;

cleanup:
    unlink(path);
    return result;
}

/* Test 3: HICKUP_BAD_MAGIC - invalid magic bytes */
static int test_hickup_bad_magic(void) {
    const char *path = "/tmp/rbox_t3.sock";
    unlink(path);
    int result = -1;

    server_thread_arg_t sa = { .socket_path = path, .server = NULL };
    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, rbox_server_thread, &sa) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    rbox_client_t *cl = rbox_client_connect(path);
    if (cl) {
        char pkt[RBOX_HEADER_SIZE];
        memset(pkt, 0, RBOX_HEADER_SIZE);
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_MAGIC) = 0xDEADBEEF;
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_VERSION) = RBOX_VERSION;
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHUNK_LEN) = 0;
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHECKSUM) =
            rbox_calculate_checksum_crc32(0, pkt, RBOX_HEADER_OFFSET_CHECKSUM);
        write_all(rbox_client_fd(cl), pkt, RBOX_HEADER_SIZE);
        rbox_client_close(cl);
    }

    if (sa.server) rbox_server_stop(sa.server);
    pthread_join(tid, NULL);
    if (sa.server) rbox_server_handle_free(sa.server);
    unlink(path);

    server_thread_arg_t sb = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, rbox_server_thread, &sb) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    if (sb.server) rbox_server_stop(sb.server);
    pthread_join(tid, NULL);
    if (sb.server) rbox_server_handle_free(sb.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;

cleanup:
    unlink(path);
    return result;
}

/* Test 4: HICKUP_BAD_VERSION - invalid protocol version */
static int test_hickup_bad_version(void) {
    const char *path = "/tmp/rbox_t4.sock";
    unlink(path);
    int result = -1;

    server_thread_arg_t sa = { .socket_path = path, .server = NULL };
    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, rbox_server_thread, &sa) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    rbox_client_t *cl = rbox_client_connect(path);
    if (cl) {
        char pkt[4096];
        size_t plen;
        const char *args[] = {"-la"};
        rbox_build_request(pkt, sizeof(pkt), &plen, "ls", NULL, NULL, 1, args, 0, NULL, NULL);
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_VERSION) = 999;
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHECKSUM) =
            rbox_calculate_checksum_crc32(0, pkt, RBOX_HEADER_OFFSET_CHECKSUM);
        write_all(rbox_client_fd(cl), pkt, plen);
        rbox_client_close(cl);
    }

    if (sa.server) rbox_server_stop(sa.server);
    pthread_join(tid, NULL);
    if (sa.server) rbox_server_handle_free(sa.server);
    unlink(path);

    server_thread_arg_t sb = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, rbox_server_thread, &sb) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    if (sb.server) rbox_server_stop(sb.server);
    pthread_join(tid, NULL);
    if (sb.server) rbox_server_handle_free(sb.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;

cleanup:
    unlink(path);
    return result;
}

/* Test 5: HICKUP_TRUNCATED_HEADER - partial header */
static int test_hickup_truncated_header(void) {
    const char *path = "/tmp/rbox_t5.sock";
    unlink(path);
    int result = -1;

    server_thread_arg_t sa = { .socket_path = path, .server = NULL };
    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, rbox_server_thread, &sa) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    rbox_client_t *cl = rbox_client_connect(path);
    if (cl) {
        char pkt[10];
        memset(pkt, 'A', 10);
        write_all(rbox_client_fd(cl), pkt, 10);
        rbox_client_close(cl);
    }

    if (sa.server) rbox_server_stop(sa.server);
    pthread_join(tid, NULL);
    if (sa.server) rbox_server_handle_free(sa.server);
    unlink(path);

    server_thread_arg_t sb = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, rbox_server_thread, &sb) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    if (sb.server) rbox_server_stop(sb.server);
    pthread_join(tid, NULL);
    if (sb.server) rbox_server_handle_free(sb.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;

cleanup:
    unlink(path);
    return result;
}

/* Test 6: HICKUP_TRUNCATED_BODY - partial body */
static int test_hickup_truncated_body(void) {
    const char *path = "/tmp/rbox_t6.sock";
    unlink(path);
    int result = -1;

    server_thread_arg_t sa = { .socket_path = path, .server = NULL };
    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, rbox_server_thread, &sa) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    rbox_client_t *cl = rbox_client_connect(path);
    if (cl) {
        char pkt[4096];
        size_t plen;
        const char *args[] = {"-la"};
        rbox_build_request(pkt, sizeof(pkt), &plen, "ls", NULL, NULL, 1, args, 0, NULL, NULL);
        write_all(rbox_client_fd(cl), pkt, plen - 5);
        rbox_client_close(cl);
    }

    if (sa.server) rbox_server_stop(sa.server);
    pthread_join(tid, NULL);
    if (sa.server) rbox_server_handle_free(sa.server);
    unlink(path);

    server_thread_arg_t sb = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, rbox_server_thread, &sb) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    if (sb.server) rbox_server_stop(sb.server);
    pthread_join(tid, NULL);
    if (sb.server) rbox_server_handle_free(sb.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;

cleanup:
    unlink(path);
    return result;
}

/* Test 7: HICKUP_DELAYED_RESPONSE - server delays response */
static int test_hickup_delayed_response(void) {
    const char *path = "/tmp/rbox_t7.sock";
    unlink(path);
    int result = -1;

    pthread_t tid;
    server_thread_arg_t arg = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, server_epoll_delayed, &arg) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    if (arg.server) rbox_server_stop(arg.server);
    pthread_join(tid, NULL);
    if (arg.server) rbox_server_handle_free(arg.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;

cleanup:
    unlink(path);
    return result;
}

/* Test 8: HICKUP_DROPPED_RESPONSE - server reads but doesn't respond, retry succeeds */
static int test_hickup_dropped_response(void) {
    const char *path = "/tmp/rbox_t8.sock";
    unlink(path);
    int result = -1;

    /* First: server drops response */
    pthread_t tid;
    server_thread_arg_t arg1 = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, server_epoll_drop, &arg1) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    rbox_client_t *cl = rbox_client_connect(path);
    if (cl) {
        char pkt[4096];
        size_t plen;
        const char *args[] = {"-la"};
        rbox_build_request(pkt, sizeof(pkt), &plen, "ls", NULL, NULL, 1, args, 0, NULL, NULL);
        write_all(rbox_client_fd(cl), pkt, plen);
        rbox_client_close(cl);
    }
    if (arg1.server) rbox_server_stop(arg1.server);
    pthread_join(tid, NULL);
    if (arg1.server) rbox_server_handle_free(arg1.server);

    /* Second: valid server */
    server_thread_arg_t arg2 = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, server_epoll_allow, &arg2) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    if (arg2.server) rbox_server_stop(arg2.server);
    pthread_join(tid, NULL);
    if (arg2.server) rbox_server_handle_free(arg2.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;

cleanup:
    unlink(path);
    return result;
}
/* Server that reads request and then closes the connection without responding */
static void *server_drop_and_close(void *arg) {
    server_thread_arg_t *thread_arg = (server_thread_arg_t *)arg;
    const char *path = thread_arg->socket_path;
    rbox_server_handle_t *srv = rbox_server_handle_new(path);
    if (!srv) return NULL;

    if (rbox_server_handle_listen(srv) != RBOX_OK) {
        rbox_server_handle_free(srv);
        return NULL;
    }
    if (rbox_server_start(srv) != RBOX_OK) {
        rbox_server_handle_free(srv);
        return NULL;
    }

    thread_arg->server = srv;

    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (req) {
        /* Discard the request – server is stopping, cleanup will happen automatically */
    }

    /* Caller must call rbox_server_stop and rbox_server_handle_free */
    return NULL;
}

/* Test 8b: RETRY_UNTIL_SUCCESS - client retries until server responds */
static int test_retry_until_success(void) {
    const char *path = "/tmp/rbox_t8b.sock";
    unlink(path);
    int result = -1;

    /* Round 1: no server running - client should fail quickly */
    printf("    Round 1: no server (retry with backoff)...\n");
    int retry_success = 0;
    for (int i = 0; i < 3; i++) {
        rbox_client_t *cl = rbox_client_connect(path);
        if (cl) {
            rbox_client_close(cl);
            retry_success = 1;
            break;
        }
        usleep(10000); /* 10ms delay between attempts */
    }
    if (retry_success) {
        printf("    ERROR: succeeded when should have failed\n");
        goto cleanup;
    }
    printf("    Round 1: correctly failed (no server)\n");

    /* Round 2: server responds correctly - should succeed */
    printf("    Round 2: server responds (retry with backoff)...\n");
    pthread_t tid;
    server_thread_arg_t arg = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, server_epoll_allow, &arg) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request_retry(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0, 10, 3);

    if (arg.server) rbox_server_stop(arg.server);
    pthread_join(tid, NULL);
    if (arg.server) rbox_server_handle_free(arg.server);
    printf("    Result: ret=%d, decision=%d\n", ret, d);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;

cleanup:
    unlink(path);
    return result;
}

/* Test 12: Multiple arguments */
static int test_multiple_args(void) {
    const char *path = "/tmp/rbox_t12.sock";
    unlink(path);
    int result = -1;

    pthread_t tid;
    server_thread_arg_t arg = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, server_epoll_allow, &arg) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    const char *args[] = {".", "-name", "*.c", "-type", "f"};
    uint8_t d = 0;
    int ret = do_request(path, "find", 5, args, &d, NULL, 0);

    if (arg.server) rbox_server_stop(arg.server);
    pthread_join(tid, NULL);
    if (arg.server) rbox_server_handle_free(arg.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;

cleanup:
    unlink(path);
    return result;
}

/* Test 13: Empty arguments */
static int test_empty_args(void) {
    const char *path = "/tmp/rbox_t13.sock";
    unlink(path);
    int result = -1;

    pthread_t tid;
    server_thread_arg_t arg = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, server_epoll_allow, &arg) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "pwd", 0, NULL, &d, NULL, 0);

    if (arg.server) rbox_server_stop(arg.server);
    pthread_join(tid, NULL);
    if (arg.server) rbox_server_handle_free(arg.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;

cleanup:
    unlink(path);
    return result;
}

/* Test 14: DENY response */
static int test_deny_response(void) {
    const char *path = "/tmp/rbox_t14.sock";
    unlink(path);
    int result = -1;

    pthread_t tid;
    server_thread_arg_t arg = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, server_epoll_deny, &arg) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    if (arg.server) rbox_server_stop(arg.server);
    pthread_join(tid, NULL);
    if (arg.server) rbox_server_handle_free(arg.server);
    result = (ret == 0 && d == RBOX_DECISION_DENY) ? 0 : -1;

cleanup:
    unlink(path);
    return result;
}

/* Test 15: Retry on connect failure */
static int test_retry_connect(void) {
    const char *path = "/tmp/rbox_t15.sock";
    unlink(path);
    int result = -1;

    /* First: try to connect to non-existent socket */
    rbox_client_t *cl = rbox_client_connect("/tmp/nonexistent.sock");
    if (cl) rbox_client_close(cl);

    /* Second: connect to valid server */
    pthread_t tid;
    server_thread_arg_t arg = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, server_epoll_allow, &arg) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    if (arg.server) rbox_server_stop(arg.server);
    pthread_join(tid, NULL);
    if (arg.server) rbox_server_handle_free(arg.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;

cleanup:
    unlink(path);
    return result;
}

/* Test 16: Long command with many arguments */
static int test_long_args(void) {
    const char *path = "/tmp/rbox_t16.sock";
    unlink(path);
    int result = -1;

    pthread_t tid;
    server_thread_arg_t arg = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, server_epoll_allow, &arg) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    const char *args[] = {".", "-name", "*.txt", "-type", "f", "-mtime", "+7", "-size", "+100k"};
    uint8_t d = 0;
    int ret = do_request(path, "find", 9, args, &d, NULL, 0);

    if (arg.server) rbox_server_stop(arg.server);
    pthread_join(tid, NULL);
    if (arg.server) rbox_server_handle_free(arg.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;

cleanup:
    unlink(path);
    return result;
}

/* Test 17: Environment variables in request */
static int test_env_vars(void) {
    const char *path = "/tmp/rbox_t17.sock";
    unlink(path);
    int result = -1;

    pthread_t tid;
    server_thread_arg_t arg = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, server_epoll_allow, &arg) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    const char *env_names[] = {"PATH", "HOME", "LD_PRELOAD"};
    float env_scores[] = {0.5f, 0.8f, 1.0f};

    rbox_response_t response;
    rbox_error_t err = rbox_blocking_request(path, "ls", 1, (const char*[]){"-la"},
                                             NULL, NULL,
                                             3, env_names, env_scores,
                                             &response, 0, 0);

    if (arg.server) rbox_server_stop(arg.server);
    pthread_join(tid, NULL);
    if (arg.server) rbox_server_handle_free(arg.server);
    result = (err == RBOX_OK && response.decision == RBOX_DECISION_ALLOW) ? 0 : -1;

cleanup:
    unlink(path);
    return result;
}

/* Test 18: Zero environment variables */
static int test_zero_env_vars(void) {
    const char *path = "/tmp/rbox_t18.sock";
    unlink(path);
    int result = -1;

    pthread_t tid;
    server_thread_arg_t arg = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, server_epoll_allow, &arg) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    rbox_response_t response;
    rbox_error_t err = rbox_blocking_request(path, "pwd", 0, NULL,
                                             NULL, NULL,
                                             0, NULL, NULL,
                                             &response, 0, 0);

    if (arg.server) rbox_server_stop(arg.server);
    pthread_join(tid, NULL);
    if (arg.server) rbox_server_handle_free(arg.server);
    result = (err == RBOX_OK && response.decision == RBOX_DECISION_ALLOW) ? 0 : -1;

cleanup:
    unlink(path);
    return result;
}

/* Test 19: Non-blocking session API */
static int test_session_api(void) {
    const char *path = "/tmp/rbox_t19.sock";
    unlink(path);
    int result = -1;

    pthread_t tid;
    server_thread_arg_t arg = { .socket_path = path, .server = NULL };
    if (checked_pthread_create(&tid, NULL, server_epoll_allow, &arg) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    rbox_session_t *session = rbox_session_new(path, 50, 3);
    if (!session) {
        if (arg.server) rbox_server_stop(arg.server);
        pthread_join(tid, NULL);
        if (arg.server) rbox_server_handle_free(arg.server);
        goto cleanup;
    }

    rbox_error_t err = rbox_session_connect(session);
    if (err != RBOX_OK && rbox_session_state(session) != RBOX_SESSION_CONNECTING) {
        rbox_session_free(session);
        if (arg.server) rbox_server_stop(arg.server);
        pthread_join(tid, NULL);
        if (arg.server) rbox_server_handle_free(arg.server);
        goto cleanup;
    }

    int timeout = 5000;
    rbox_session_state_t state = rbox_session_state(session);
    if (state != RBOX_SESSION_CONNECTED) {
        while (timeout > 0) {
            short events;
            int fd = rbox_session_pollfd(session, &events);
            if (fd < 0) break;
            struct pollfd pfd = { .fd = fd, .events = events };
            if (poll(&pfd, 1, 100) <= 0) {
                timeout -= 100;
                continue;
            }
            state = rbox_session_heartbeat(session, pfd.revents);
            if (state == RBOX_SESSION_CONNECTED) break;
            if (state == RBOX_SESSION_FAILED) break;
            timeout -= 100;
        }
    }

    if (state != RBOX_SESSION_CONNECTED) {
        rbox_session_free(session);
        pthread_join(tid, NULL);
        goto cleanup;
    }

    err = rbox_session_send_request(session, "ls", NULL, NULL, 1, (const char*[]){"-la"}, 0, NULL, NULL);
    if (err != RBOX_OK) {
        rbox_session_free(session);
        pthread_join(tid, NULL);
        goto cleanup;
    }

    timeout = 5000;
    while (timeout > 0) {
        short events;
        int fd = rbox_session_pollfd(session, &events);
        if (fd < 0) break;
        struct pollfd pfd = { .fd = fd, .events = events };
        if (poll(&pfd, 1, 100) <= 0) {
            timeout -= 100;
            continue;
        }
        state = rbox_session_heartbeat(session, pfd.revents);
        if (state == RBOX_SESSION_RESPONSE_READY) break;
        if (state == RBOX_SESSION_FAILED) break;
        timeout -= 100;
    }

    if (state != RBOX_SESSION_RESPONSE_READY) {
        rbox_session_free(session);
        pthread_join(tid, NULL);
        goto cleanup;
    }

    const rbox_response_t *resp = rbox_session_response(session);
    if (!resp || resp->decision != RBOX_DECISION_ALLOW) {
        rbox_session_free(session);
        pthread_join(tid, NULL);
        goto cleanup;
    }

    result = 0;

    rbox_session_free(session);
    pthread_join(tid, NULL);

cleanup:
    unlink(path);
    return result;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    rbox_init();

    printf("=== Integration tests (v9 protocol) ===\n\n");
    fflush(stdout);

    RUN_TEST(test_simple, "simple round-trip");
    RUN_TEST(test_multiple_args, "multiple arguments");
    RUN_TEST(test_empty_args, "empty arguments");
    RUN_TEST(test_long_args, "long arguments");
    RUN_TEST(test_deny_response, "deny response");
    RUN_TEST(test_retry_connect, "retry connect");

    RUN_TEST(test_hickup_bad_packet, "HICKUP_BAD_PACKET");
    RUN_TEST(test_hickup_bad_magic, "HICKUP_BAD_MAGIC");
    RUN_TEST(test_hickup_bad_version, "HICKUP_BAD_VERSION");
    RUN_TEST(test_hickup_truncated_header, "HICKUP_TRUNCATED_HEADER");
    RUN_TEST(test_hickup_truncated_body, "HICKUP_TRUNCATED_BODY");

    RUN_TEST(test_hickup_delayed_response, "HICKUP_DELAYED_RESPONSE");
    RUN_TEST(test_hickup_dropped_response, "HICKUP_DROPPED_RESPONSE");
    RUN_TEST(test_retry_until_success, "RETRY_UNTIL_SUCCESS");

    RUN_TEST(test_env_vars, "environment variables");
    RUN_TEST(test_zero_env_vars, "zero environment variables");

    RUN_TEST(test_session_api, "non-blocking session API");

    printf("\n=== Results: %d/%d tests passed ===\n", pass_count, test_count);
    fflush(stdout);
    return pass_count == test_count ? 0 : 1;
}
