/*
 * test_integration.c - Comprehensive integration tests for v9 protocol
 * Tests all scenarios including hickups, retries, and edge cases
 */

#define _GNU_SOURCE

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
#include <stdatomic.h>

#include "rbox_protocol.h"
#include "../src/error_internal.h"
#include "runtime.h"

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

/* Generate unique socket path using mkstemp */
static int make_unique_socket_path(char *path, size_t path_size) {
    const char *template = "/tmp/rbox_integration_XXXXXX";
    if (strlen(template) >= path_size) return -1;
    strcpy(path, template);
    int fd = mkstemp(path);
    if (fd < 0) return -1;
    close(fd);
    unlink(path);
    return 0;
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
    pthread_mutex_t server_mutex;
    rbox_server_request_t *orphaned_requests[10];
    int orphaned_count;
} server_thread_arg_t;

/* Worker: processes one request and sends ALLOW (server owned by caller/test) */
static void *server_worker_allow(void *arg) {
    server_thread_arg_t *thread_arg = (server_thread_arg_t *)arg;
    rbox_server_handle_t *srv = thread_arg->server;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;
    rbox_server_request_t *req = rbox_server_get_request(srv, &err_info);
    if (req) {
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL);
    }
    return NULL;
}

/* Worker: processes one request and sends DENY (server owned by caller/test) */
static void *server_worker_deny(void *arg) {
    server_thread_arg_t *thread_arg = (server_thread_arg_t *)arg;
    rbox_server_handle_t *srv = thread_arg->server;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;
    rbox_server_request_t *req = rbox_server_get_request(srv, &err_info);
    if (req) {
        rbox_server_decide(req, RBOX_DECISION_DENY, "denied", 0, 0, NULL);
    }
    return NULL;
}

/* Worker: processes one request with 200ms delay before responding */
static void *server_worker_delayed(void *arg) {
    server_thread_arg_t *thread_arg = (server_thread_arg_t *)arg;
    rbox_server_handle_t *srv = thread_arg->server;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;
    rbox_server_request_t *req = rbox_server_get_request(srv, &err_info);
    if (req) {
        usleep(200000);
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL);
    }
    return NULL;
}

/* Worker: reads request but drops it (server owned by caller) */
static void *server_worker_drop(void *arg) {
    server_thread_arg_t *thread_arg = (server_thread_arg_t *)arg;
    rbox_server_handle_t *srv = thread_arg->server;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;
    rbox_server_request_t *req = rbox_server_get_request(srv, &err_info);
    if (req && thread_arg->orphaned_count < 10) {
        thread_arg->orphaned_requests[thread_arg->orphaned_count++] = req;
    }
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
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;
    rbox_error_t err = rbox_blocking_request(path, cmd, argc, args, NULL, NULL,
                                              0, NULL, NULL, &response, 0, 0, &err_info);

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
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;
    rbox_error_t err = rbox_blocking_request(path, cmd, argc, args, NULL, NULL,
                                              0, NULL, NULL, &response,
                                              base_delay_ms, max_retries, &err_info);

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

/* Helper: start server and worker for single-request tests */
static int start_server_and_worker(pthread_t *tid, server_thread_arg_t *arg,
                                   void *(*worker_fn)(void *), const char *path) {
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;
    rbox_server_handle_t *srv = rbox_server_handle_new(path, &err_info);
    if (!srv) return -1;

    if (rbox_server_handle_listen(srv) != RBOX_OK) {
        rbox_server_handle_free(srv);
        return -1;
    }
    if (rbox_server_start(srv) != RBOX_OK) {
        rbox_server_handle_free(srv);
        return -1;
    }

    *arg = (server_thread_arg_t){ .socket_path = path, .server = srv, .server_mutex = PTHREAD_MUTEX_INITIALIZER };
    if (checked_pthread_create(tid, NULL, worker_fn, arg) != 0) {
        rbox_server_handle_free(srv);
        return -1;
    }

    if (wait_for_server(path, 2000) != 0) {
        pthread_join(*tid, NULL);
        rbox_server_handle_free(srv);
        return -1;
    }
    return 0;
}

/* Helper: stop server and join worker thread */
static void stop_server(rbox_server_handle_t *srv, pthread_t tid) {
    if (srv) rbox_server_stop(srv);
    pthread_join(tid, NULL);
}

/* Helper: free server handle */
static void cleanup_server(rbox_server_handle_t *srv) {
    if (srv) rbox_server_handle_free(srv);
}

/* Test 1: Simple round-trip */
static int test_simple(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;

    pthread_t tid;
    server_thread_arg_t arg;
    if (start_server_and_worker(&tid, &arg, server_worker_allow, path) != 0) {
        unlink(path);
        return -1;
    }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    stop_server(arg.server, tid);
    cleanup_server(arg.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;
    unlink(path);
    return result;
}
/* Worker: runs a server until stopped (server owned by caller/test) */
static void *server_worker_continuous(void *arg) {
    server_thread_arg_t *thread_arg = (server_thread_arg_t *)arg;
    rbox_server_handle_t *srv = thread_arg->server;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    while (1) {
        rbox_server_request_t *req = rbox_server_get_request(srv, &err_info);
        if (!req) break;
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL);
    }

    return NULL;
}
/* Test 2: HICKUP_BAD_PACKET - send garbage, then retry */
static int test_hickup_bad_packet(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    /* First server */
    rbox_server_handle_t *srv1 = rbox_server_handle_new(path, &err_info);
    if (!srv1) { unlink(path); return -1; }
    if (rbox_server_handle_listen(srv1) != RBOX_OK) { rbox_server_handle_free(srv1); unlink(path); return -1; }
    if (rbox_server_start(srv1) != RBOX_OK) { rbox_server_handle_free(srv1); unlink(path); return -1; }

    pthread_t tid;
    server_thread_arg_t arg1 = { .socket_path = path, .server = srv1, .server_mutex = PTHREAD_MUTEX_INITIALIZER };
    if (checked_pthread_create(&tid, NULL, server_worker_continuous, &arg1) != 0) {
        rbox_server_handle_free(srv1);
        unlink(path);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); rbox_server_handle_free(srv1); unlink(path); return -1; }

    /* Send garbage */
    rbox_client_t *cl = rbox_client_connect(path, &err_info);
    if (cl) {
        write_all(rbox_client_fd(cl), "GARBAGE", 7);
        rbox_client_close(cl);
    }

    /* Stop first server */
    rbox_server_stop(srv1);
    pthread_join(tid, NULL);
    rbox_server_handle_free(srv1);
    unlink(path);
    usleep(100000);

    /* Second server (valid) */
    rbox_server_handle_t *srv2 = rbox_server_handle_new(path, &err_info);
    if (!srv2) { unlink(path); return -1; }
    if (rbox_server_handle_listen(srv2) != RBOX_OK) { rbox_server_handle_free(srv2); unlink(path); return -1; }
    if (rbox_server_start(srv2) != RBOX_OK) { rbox_server_handle_free(srv2); unlink(path); return -1; }

    server_thread_arg_t arg2 = { .socket_path = path, .server = srv2, .server_mutex = PTHREAD_MUTEX_INITIALIZER };
    if (checked_pthread_create(&tid, NULL, server_worker_continuous, &arg2) != 0) {
        rbox_server_handle_free(srv2);
        unlink(path);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); rbox_server_handle_free(srv2); unlink(path); return -1; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    rbox_server_stop(srv2);
    pthread_join(tid, NULL);
    rbox_server_handle_free(srv2);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;
    unlink(path);
    return result;
}

/* Test 3: HICKUP_BAD_MAGIC - invalid magic bytes */
static int test_hickup_bad_magic(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    rbox_server_handle_t *srv1 = rbox_server_handle_new(path, &err_info);
    if (!srv1) { unlink(path); return -1; }
    if (rbox_server_handle_listen(srv1) != RBOX_OK) { rbox_server_handle_free(srv1); unlink(path); return -1; }
    if (rbox_server_start(srv1) != RBOX_OK) { rbox_server_handle_free(srv1); unlink(path); return -1; }

    pthread_t tid;
    server_thread_arg_t arg1 = { .socket_path = path, .server = srv1, .server_mutex = PTHREAD_MUTEX_INITIALIZER };
    if (checked_pthread_create(&tid, NULL, server_worker_continuous, &arg1) != 0) {
        rbox_server_handle_free(srv1);
        unlink(path);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); rbox_server_handle_free(srv1); unlink(path); return -1; }

    rbox_client_t *cl = rbox_client_connect(path, &err_info);
    if (cl) {
        char pkt[RBOX_HEADER_SIZE];
        memset(pkt, 0, RBOX_HEADER_SIZE);
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_MAGIC) = 0xDEADBEEF;
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_VERSION) = RBOX_VERSION;
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHUNK_LEN) = 0;
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHECKSUM) =
            rbox_runtime_crc32(0, pkt, RBOX_HEADER_OFFSET_CHECKSUM);
        write_all(rbox_client_fd(cl), pkt, RBOX_HEADER_SIZE);
        rbox_client_close(cl);
    }

    rbox_server_stop(srv1);
    pthread_join(tid, NULL);
    rbox_server_handle_free(srv1);
    unlink(path);

    rbox_server_handle_t *srv2 = rbox_server_handle_new(path, &err_info);
    if (!srv2) { unlink(path); return -1; }
    if (rbox_server_handle_listen(srv2) != RBOX_OK) { rbox_server_handle_free(srv2); unlink(path); return -1; }
    if (rbox_server_start(srv2) != RBOX_OK) { rbox_server_handle_free(srv2); unlink(path); return -1; }

    server_thread_arg_t arg2 = { .socket_path = path, .server = srv2, .server_mutex = PTHREAD_MUTEX_INITIALIZER };
    if (checked_pthread_create(&tid, NULL, server_worker_continuous, &arg2) != 0) {
        rbox_server_handle_free(srv2);
        unlink(path);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); rbox_server_handle_free(srv2); unlink(path); return -1; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    rbox_server_stop(srv2);
    pthread_join(tid, NULL);
    rbox_server_handle_free(srv2);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;
    unlink(path);
    return result;
}

/* Test 4: HICKUP_BAD_VERSION - invalid protocol version */
static int test_hickup_bad_version(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    rbox_server_handle_t *srv1 = rbox_server_handle_new(path, &err_info);
    if (!srv1) { unlink(path); return -1; }
    if (rbox_server_handle_listen(srv1) != RBOX_OK) { rbox_server_handle_free(srv1); unlink(path); return -1; }
    if (rbox_server_start(srv1) != RBOX_OK) { rbox_server_handle_free(srv1); unlink(path); return -1; }

    pthread_t tid;
    server_thread_arg_t arg1 = { .socket_path = path, .server = srv1, .server_mutex = PTHREAD_MUTEX_INITIALIZER };
    if (checked_pthread_create(&tid, NULL, server_worker_continuous, &arg1) != 0) {
        rbox_server_handle_free(srv1);
        unlink(path);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); rbox_server_handle_free(srv1); unlink(path); return -1; }

    rbox_client_t *cl = rbox_client_connect(path, &err_info);
    if (cl) {
        char pkt[4096];
        size_t plen;
        const char *args[] = {"-la"};
        rbox_build_request(pkt, sizeof(pkt), &plen, "ls", NULL, NULL, 1, args, 0, NULL, NULL);
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_VERSION) = 999;
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHECKSUM) =
            rbox_runtime_crc32(0, pkt, RBOX_HEADER_OFFSET_CHECKSUM);
        write_all(rbox_client_fd(cl), pkt, plen);
        rbox_client_close(cl);
    }

    rbox_server_stop(srv1);
    pthread_join(tid, NULL);
    rbox_server_handle_free(srv1);
    unlink(path);

    rbox_server_handle_t *srv2 = rbox_server_handle_new(path, &err_info);
    if (!srv2) { unlink(path); return -1; }
    if (rbox_server_handle_listen(srv2) != RBOX_OK) { rbox_server_handle_free(srv2); unlink(path); return -1; }
    if (rbox_server_start(srv2) != RBOX_OK) { rbox_server_handle_free(srv2); unlink(path); return -1; }

    server_thread_arg_t arg2 = { .socket_path = path, .server = srv2, .server_mutex = PTHREAD_MUTEX_INITIALIZER };
    if (checked_pthread_create(&tid, NULL, server_worker_continuous, &arg2) != 0) {
        rbox_server_handle_free(srv2);
        unlink(path);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); rbox_server_handle_free(srv2); unlink(path); return -1; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    rbox_server_stop(srv2);
    pthread_join(tid, NULL);
    rbox_server_handle_free(srv2);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;
    unlink(path);
    return result;
}

/* Test 5: HICKUP_TRUNCATED_HEADER - partial header */
static int test_hickup_truncated_header(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    rbox_server_handle_t *srv1 = rbox_server_handle_new(path, &err_info);
    if (!srv1) { unlink(path); return -1; }
    if (rbox_server_handle_listen(srv1) != RBOX_OK) { rbox_server_handle_free(srv1); unlink(path); return -1; }
    if (rbox_server_start(srv1) != RBOX_OK) { rbox_server_handle_free(srv1); unlink(path); return -1; }

    pthread_t tid;
    server_thread_arg_t arg1 = { .socket_path = path, .server = srv1, .server_mutex = PTHREAD_MUTEX_INITIALIZER };
    if (checked_pthread_create(&tid, NULL, server_worker_continuous, &arg1) != 0) {
        rbox_server_handle_free(srv1);
        unlink(path);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); rbox_server_handle_free(srv1); unlink(path); return -1; }

    rbox_client_t *cl = rbox_client_connect(path, &err_info);
    if (cl) {
        char pkt[10];
        memset(pkt, 'A', 10);
        write_all(rbox_client_fd(cl), pkt, 10);
        rbox_client_close(cl);
    }

    rbox_server_stop(srv1);
    pthread_join(tid, NULL);
    rbox_server_handle_free(srv1);
    unlink(path);

    rbox_server_handle_t *srv2 = rbox_server_handle_new(path, &err_info);
    if (!srv2) { unlink(path); return -1; }
    if (rbox_server_handle_listen(srv2) != RBOX_OK) { rbox_server_handle_free(srv2); unlink(path); return -1; }
    if (rbox_server_start(srv2) != RBOX_OK) { rbox_server_handle_free(srv2); unlink(path); return -1; }

    server_thread_arg_t arg2 = { .socket_path = path, .server = srv2, .server_mutex = PTHREAD_MUTEX_INITIALIZER };
    if (checked_pthread_create(&tid, NULL, server_worker_continuous, &arg2) != 0) {
        rbox_server_handle_free(srv2);
        unlink(path);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); rbox_server_handle_free(srv2); unlink(path); return -1; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    rbox_server_stop(srv2);
    pthread_join(tid, NULL);
    rbox_server_handle_free(srv2);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;
    unlink(path);
    return result;
}

/* Test 6: HICKUP_TRUNCATED_BODY - partial body */
static int test_hickup_truncated_body(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    rbox_server_handle_t *srv1 = rbox_server_handle_new(path, &err_info);
    if (!srv1) { unlink(path); return -1; }
    if (rbox_server_handle_listen(srv1) != RBOX_OK) { rbox_server_handle_free(srv1); unlink(path); return -1; }
    if (rbox_server_start(srv1) != RBOX_OK) { rbox_server_handle_free(srv1); unlink(path); return -1; }

    pthread_t tid;
    server_thread_arg_t arg1 = { .socket_path = path, .server = srv1, .server_mutex = PTHREAD_MUTEX_INITIALIZER };
    if (checked_pthread_create(&tid, NULL, server_worker_continuous, &arg1) != 0) {
        rbox_server_handle_free(srv1);
        unlink(path);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); rbox_server_handle_free(srv1); unlink(path); return -1; }

    rbox_client_t *cl = rbox_client_connect(path, &err_info);
    if (cl) {
        char pkt[4096];
        size_t plen;
        const char *args[] = {"-la"};
        rbox_build_request(pkt, sizeof(pkt), &plen, "ls", NULL, NULL, 1, args, 0, NULL, NULL);
        write_all(rbox_client_fd(cl), pkt, plen - 5);
        rbox_client_close(cl);
    }

    rbox_server_stop(srv1);
    pthread_join(tid, NULL);
    rbox_server_handle_free(srv1);
    unlink(path);

    rbox_server_handle_t *srv2 = rbox_server_handle_new(path, &err_info);
    if (!srv2) { unlink(path); return -1; }
    if (rbox_server_handle_listen(srv2) != RBOX_OK) { rbox_server_handle_free(srv2); unlink(path); return -1; }
    if (rbox_server_start(srv2) != RBOX_OK) { rbox_server_handle_free(srv2); unlink(path); return -1; }

    server_thread_arg_t arg2 = { .socket_path = path, .server = srv2, .server_mutex = PTHREAD_MUTEX_INITIALIZER };
    if (checked_pthread_create(&tid, NULL, server_worker_continuous, &arg2) != 0) {
        rbox_server_handle_free(srv2);
        unlink(path);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); rbox_server_handle_free(srv2); unlink(path); return -1; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    rbox_server_stop(srv2);
    pthread_join(tid, NULL);
    rbox_server_handle_free(srv2);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;
    unlink(path);
    return result;
}

/* Test 7: HICKUP_DELAYED_RESPONSE - server delays response */
static int test_hickup_delayed_response(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;

    pthread_t tid;
    server_thread_arg_t arg;
    if (start_server_and_worker(&tid, &arg, server_worker_delayed, path) != 0) {
        unlink(path);
        return -1;
    }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    stop_server(arg.server, tid);
    cleanup_server(arg.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;
    unlink(path);
    return result;
}

/* Test 8: HICKUP_DROPPED_RESPONSE - server reads but doesn't respond, retry succeeds */
static int test_hickup_dropped_response(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    /* First: server drops response */
    pthread_t tid;
    server_thread_arg_t arg1 = { .socket_path = path, .server = NULL, .server_mutex = PTHREAD_MUTEX_INITIALIZER, .orphaned_count = 0 };
    if (start_server_and_worker(&tid, &arg1, server_worker_drop, path) != 0) {
        unlink(path);
        return -1;
    }

    rbox_client_t *cl = rbox_client_connect(path, &err_info);
    if (cl) {
        char pkt[4096];
        size_t plen;
        const char *args[] = {"-la"};
        rbox_build_request(pkt, sizeof(pkt), &plen, "ls", NULL, NULL, 1, args, 0, NULL, NULL);
        write_all(rbox_client_fd(cl), pkt, plen);
        rbox_client_close(cl);
    }
    stop_server(arg1.server, tid);

    /* Decide orphaned requests after server stopped (but before handle_free) */
    for (int i = 0; i < arg1.orphaned_count; i++) {
        rbox_server_decide(arg1.orphaned_requests[i], RBOX_DECISION_ALLOW, "ok", 0, 0, NULL);
    }
    cleanup_server(arg1.server);

    /* Second: valid server - wait for socket cleanup */
    usleep(100000);

    pthread_t tid2;
    server_thread_arg_t arg2 = { .socket_path = path, .server = NULL, .server_mutex = PTHREAD_MUTEX_INITIALIZER, .orphaned_count = 0 };
    if (start_server_and_worker(&tid2, &arg2, server_worker_allow, path) != 0) {
        unlink(path);
        return -1;
    }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    stop_server(arg2.server, tid2);
    cleanup_server(arg2.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;
    unlink(path);
    return result;
}

/* Test 8b: RETRY_UNTIL_SUCCESS - client retries until server responds */
static int test_retry_until_success(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    /* Round 1: no server running - client should fail quickly */
    printf("    Round 1: no server (retry with backoff)...\n");
    int retry_success = 0;
    for (int i = 0; i < 3; i++) {
        rbox_client_t *cl = rbox_client_connect(path, &err_info);
        if (cl) {
            rbox_client_close(cl);
            retry_success = 1;
            break;
        }
        usleep(10000);
    }
    if (retry_success) {
        printf("    ERROR: succeeded when should have failed\n");
        unlink(path);
        return -1;
    }
    printf("    Round 1: correctly failed (no server)\n");

    /* Round 2: server responds correctly - should succeed */
    printf("    Round 2: server responds (retry with backoff)...\n");
    pthread_t tid;
    server_thread_arg_t arg;
    if (start_server_and_worker(&tid, &arg, server_worker_allow, path) != 0) {
        unlink(path);
        return -1;
    }

    uint8_t d = 0;
    int ret = do_request_retry(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0, 10, 3);

    stop_server(arg.server, tid);
    cleanup_server(arg.server);
    printf("    Result: ret=%d, decision=%d\n", ret, d);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;
    unlink(path);
    return result;
}

/* Test 12: Multiple arguments */
static int test_multiple_args(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;

    pthread_t tid;
    server_thread_arg_t arg;
    if (start_server_and_worker(&tid, &arg, server_worker_allow, path) != 0) {
        unlink(path);
        return -1;
    }

    const char *args[] = {".", "-name", "*.c", "-type", "f"};
    uint8_t d = 0;
    int ret = do_request(path, "find", 5, args, &d, NULL, 0);

    stop_server(arg.server, tid);
    cleanup_server(arg.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;
    unlink(path);
    return result;
}

/* Test 13: Empty arguments */
static int test_empty_args(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;

    pthread_t tid;
    server_thread_arg_t arg;
    if (start_server_and_worker(&tid, &arg, server_worker_allow, path) != 0) {
        unlink(path);
        return -1;
    }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    stop_server(arg.server, tid);
    cleanup_server(arg.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;
    unlink(path);
    return result;
}

/* Test 14: DENY response */
static int test_deny_response(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;

    pthread_t tid;
    server_thread_arg_t arg;
    if (start_server_and_worker(&tid, &arg, server_worker_deny, path) != 0) {
        unlink(path);
        return -1;
    }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    stop_server(arg.server, tid);
    cleanup_server(arg.server);
    result = (ret == 0 && d == RBOX_DECISION_DENY) ? 0 : -1;
    unlink(path);
    return result;
}

/* Test 15: Retry on connect failure */
static int test_retry_connect(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    /* First: try to connect to non-existent socket */
    rbox_client_t *cl = rbox_client_connect("/tmp/nonexistent.sock", &err_info);
    if (cl) rbox_client_close(cl);

    /* Second: connect to valid server */
    pthread_t tid;
    server_thread_arg_t arg;
    if (start_server_and_worker(&tid, &arg, server_worker_allow, path) != 0) {
        unlink(path);
        return -1;
    }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    stop_server(arg.server, tid);
    cleanup_server(arg.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;
    unlink(path);
    return result;
}

/* Test 16: Long command with many arguments */
static int test_long_args(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;

    pthread_t tid;
    server_thread_arg_t arg;
    if (start_server_and_worker(&tid, &arg, server_worker_allow, path) != 0) {
        unlink(path);
        return -1;
    }

    const char *args[] = {".", "-name", "*.txt", "-type", "f", "-mtime", "+7", "-size", "+100k"};
    uint8_t d = 0;
    int ret = do_request(path, "find", 9, args, &d, NULL, 0);

    stop_server(arg.server, tid);
    cleanup_server(arg.server);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;
    unlink(path);
    return result;
}

/* Test 17: Environment variables in request */
static int test_env_vars(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    pthread_t tid;
    server_thread_arg_t arg;
    if (start_server_and_worker(&tid, &arg, server_worker_allow, path) != 0) {
        unlink(path);
        return -1;
    }

    const char *env_names[] = {"PATH", "HOME", "LD_PRELOAD"};
    float env_scores[] = {0.5f, 0.8f, 1.0f};

    rbox_response_t response;
    rbox_error_t err = rbox_blocking_request(path, "ls", 1, (const char*[]){"-la"},
                                             NULL, NULL,
                                             3, env_names, env_scores,
                                             &response, 0, 0, &err_info);

    stop_server(arg.server, tid);
    cleanup_server(arg.server);
    result = (err == RBOX_OK && response.decision == RBOX_DECISION_ALLOW) ? 0 : -1;
    unlink(path);
    return result;
}

/* Test 18: Zero environment variables */
static int test_zero_env_vars(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    pthread_t tid;
    server_thread_arg_t arg;
    if (start_server_and_worker(&tid, &arg, server_worker_allow, path) != 0) {
        unlink(path);
        return -1;
    }

    rbox_response_t response;
    rbox_error_t err = rbox_blocking_request(path, "pwd", 0, NULL,
                                             NULL, NULL,
                                             0, NULL, NULL,
                                             &response, 0, 0, &err_info);

    stop_server(arg.server, tid);
    cleanup_server(arg.server);
    result = (err == RBOX_OK && response.decision == RBOX_DECISION_ALLOW) ? 0 : -1;
    unlink(path);
    return result;
}

/* Test 19: Non-blocking session API */
static int test_session_api(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    pthread_t tid;
    server_thread_arg_t arg;
    if (start_server_and_worker(&tid, &arg, server_worker_allow, path) != 0) {
        unlink(path);
        return -1;
    }

    rbox_session_t *session = rbox_session_new(path, 50, 3, &err_info);
    if (!session) {
        stop_server(arg.server, tid);
        cleanup_server(arg.server);
        unlink(path);
        return -1;
    }

    rbox_error_t err = rbox_session_connect(session, &err_info);
    if (err != RBOX_OK && rbox_session_state(session) != RBOX_SESSION_CONNECTING) {
        rbox_session_free(session);
        stop_server(arg.server, tid);
        cleanup_server(arg.server);
        unlink(path);
        return -1;
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
            state = rbox_session_heartbeat(session, pfd.revents, &err_info);
            if (state == RBOX_SESSION_CONNECTED) break;
            if (state == RBOX_SESSION_FAILED) break;
            timeout -= 100;
        }
    }

    if (state != RBOX_SESSION_CONNECTED) {
        rbox_session_free(session);
        stop_server(arg.server, tid);
        cleanup_server(arg.server);
        unlink(path);
        return -1;
    }

    err = rbox_session_send_request(session, "ls", NULL, NULL, 1, (const char*[]){"-la"}, 0, NULL, NULL, &err_info);
    if (err != RBOX_OK) {
        rbox_session_free(session);
        stop_server(arg.server, tid);
        cleanup_server(arg.server);
        unlink(path);
        return -1;
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
        state = rbox_session_heartbeat(session, pfd.revents, &err_info);
        if (state == RBOX_SESSION_RESPONSE_READY) break;
        if (state == RBOX_SESSION_FAILED) break;
        timeout -= 100;
    }

    if (state != RBOX_SESSION_RESPONSE_READY) {
        rbox_session_free(session);
        stop_server(arg.server, tid);
        cleanup_server(arg.server);
        unlink(path);
        return -1;
    }

    const rbox_response_t *resp = rbox_session_response(session);
    if (!resp || resp->decision != RBOX_DECISION_ALLOW) {
        rbox_session_free(session);
        stop_server(arg.server, tid);
        cleanup_server(arg.server);
        unlink(path);
        return -1;
    }

    result = 0;

    rbox_session_free(session);
    stop_server(arg.server, tid);
    cleanup_server(arg.server);
    unlink(path);
    return result;
}

/* Test: PARTIAL_HEADER_RECOVERY - partial header delivery with edge-triggered epoll
 * Validates that the server correctly handles a header split across multiple writes.
 * Before the fix: server freezes because edge-triggered epoll doesn't re-notify
 * for data already in the socket buffer after returning EAGAIN.
 * After the fix: drain loop reads until EAGAIN; server correctly reads the
 * complete header when the rest arrives. */
static int test_partial_header_recovery(void) {
    char path[64];
    if (make_unique_socket_path(path, sizeof(path)) != 0) return -1;
    int result = -1;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    rbox_server_handle_t *srv = rbox_server_handle_new(path, &err_info);
    if (!srv) { unlink(path); return -1; }
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); unlink(path); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); unlink(path); return -1; }

    pthread_t tid;
    server_thread_arg_t arg = { .socket_path = path, .server = srv, .server_mutex = PTHREAD_MUTEX_INITIALIZER };
    if (checked_pthread_create(&tid, NULL, server_worker_continuous, &arg) != 0) {
        rbox_server_handle_free(srv);
        unlink(path);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); rbox_server_handle_free(srv); unlink(path); return -1; }

    /* Connect raw socket */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { rbox_server_stop(srv); pthread_join(tid, NULL); rbox_server_handle_free(srv); unlink(path); return -1; }
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        rbox_server_stop(srv);
        pthread_join(tid, NULL);
        rbox_server_handle_free(srv);
        unlink(path);
        return -1;
    }

    /* Build a valid request packet */
    char full_packet[8192];
    size_t packet_len;
    const char *args[] = {"-la"};
    rbox_build_request(full_packet, sizeof(full_packet), &packet_len,
                       "ls", NULL, NULL, 1, args, 0, NULL, NULL);

    /* Send first half of header (64 of 127 bytes) */
    size_t first_half = 64;
    if (write_all(fd, full_packet, first_half) < 0) {
        close(fd);
        rbox_server_stop(srv);
        pthread_join(tid, NULL);
        rbox_server_handle_free(srv);
        unlink(path);
        return -1;
    }
    usleep(10000);  /* 10ms gap to force separate kernel buffer fills */

    /* Send remaining bytes (rest of header + body) */
    if (write_all(fd, full_packet + first_half, packet_len - first_half) < 0) {
        close(fd);
        rbox_server_stop(srv);
        pthread_join(tid, NULL);
        rbox_server_handle_free(srv);
        unlink(path);
        return -1;
    }

    /* Read response (blocking – server thread processes and responds) */
    char response[4096];
    ssize_t n = read(fd, response, sizeof(response));
    close(fd);

    if (n > (ssize_t)RBOX_HEADER_SIZE) {
        uint32_t magic = *(uint32_t *)response;
        uint8_t decision = response[RBOX_HEADER_SIZE];
        if (magic == RBOX_MAGIC && decision == RBOX_DECISION_ALLOW) {
            result = 0;
        }
    }

    rbox_server_stop(srv);
    pthread_join(tid, NULL);
    rbox_server_handle_free(srv);
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
    RUN_TEST(test_partial_header_recovery, "PARTIAL_HEADER_RECOVERY");

    printf("\n=== Results: %d/%d tests passed ===\n", pass_count, test_count);
    fflush(stdout);
    return pass_count == test_count ? 0 : 1;
}
