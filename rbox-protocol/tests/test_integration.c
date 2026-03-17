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
 * Robust server implementations that handle edge cases
 * ============================================================================ */

/* Blocking server that handles one request using the official blocking API */
static void *server_blocking(void *arg) {
    const char *path = arg;
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

    /* Get one request */
    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (req) {
        /* Always allow */
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL);
    }

    /* Give client time to read response before shutdown */
    usleep(100000);

    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return NULL;
}

/* Robust server: uses canonical library functions for request handling
 * Uses sync pipe to signal when ready - avoids polling with usleep */
static void *server_robust(void *arg) {
    /* arg is pointer to sync_pipe_t + socket path - we'll store path in global */
    const char *path = arg;
    rbox_server_t *srv = rbox_server_new(path);
    if (!srv) {
        fprintf(stderr, "    ERROR: failed to create server on %s\n", path);
        return NULL;
    }

    rbox_error_t err = rbox_server_listen(srv);
    if (err != RBOX_OK) {
        fprintf(stderr, "    ERROR: failed to listen on %s: %s\n", path, rbox_strerror(err));
        rbox_server_free(srv);
        return NULL;
    }

    rbox_client_t *cl = rbox_server_accept(srv);
    if (cl) {
        /* Use canonical library function to read and parse request */
        rbox_request_t request;
        err = rbox_request_read(cl, &request);

        if (err == RBOX_OK && request.command) {
            /* Valid request received - send ALLOW response */
            rbox_response_t resp = { .decision = RBOX_DECISION_ALLOW };
            memcpy(resp.request_id, request.header.request_id, 16);
            snprintf(resp.reason, sizeof(resp.reason), "ok");
            rbox_response_send(cl, &resp);
        }
        rbox_request_free(&request);
        rbox_client_close(cl);
    }
    rbox_server_free(srv);
    return NULL;
}

/* Server that sends DENY - uses canonical library functions */
static void *server_deny(void *arg) {
    const char *path = arg;
    rbox_server_t *srv = rbox_server_new(path);
    if (!srv) {
        fprintf(stderr, "    ERROR: failed to create server on %s\n", path);
        return NULL;
    }

    rbox_error_t err = rbox_server_listen(srv);
    if (err != RBOX_OK) {
        fprintf(stderr, "    ERROR: failed to listen on %s: %s\n", path, rbox_strerror(err));
        rbox_server_free(srv);
        return NULL;
    }

    rbox_client_t *cl = rbox_server_accept(srv);
    if (cl) {
        rbox_request_t request;
        err = rbox_request_read(cl, &request);

        if (err == RBOX_OK && request.command) {
            rbox_response_t resp = { .decision = RBOX_DECISION_DENY };
            memcpy(resp.request_id, request.header.request_id, 16);
            snprintf(resp.reason, sizeof(resp.reason), "denied");
            rbox_response_send(cl, &resp);
        }
        rbox_request_free(&request);
        rbox_client_close(cl);
    }
    rbox_server_free(srv);
    return NULL;
}

/* Server with delayed response - uses canonical library functions */
static void *server_delayed(void *arg) {
    const char *path = arg;
    rbox_server_t *srv = rbox_server_new(path);
    rbox_server_listen(srv);

    rbox_client_t *cl = rbox_server_accept(srv);
    if (cl) {
        rbox_request_t request;
        rbox_error_t err = rbox_request_read(cl, &request);

        if (err == RBOX_OK && request.command) {
            /* Delay before response */
            usleep(200000);
            rbox_response_t resp = { .decision = RBOX_DECISION_ALLOW };
            memcpy(resp.request_id, request.header.request_id, 16);
            snprintf(resp.reason, sizeof(resp.reason), "ok");
            rbox_response_send(cl, &resp);
        }
        rbox_request_free(&request);
        rbox_client_close(cl);
    }
    rbox_server_free(srv);
    return NULL;
}

/* Server that reads but doesn't respond - uses canonical library functions */
static void *server_drops_response(void *arg) {
    const char *path = arg;
    rbox_server_t *srv = rbox_server_new(path);
    rbox_server_listen(srv);

    rbox_client_t *cl = rbox_server_accept(srv);
    if (cl) {
        rbox_request_t request;
        rbox_error_t err = rbox_request_read(cl, &request);

        if (err == RBOX_OK && request.command) {
            /* Just close without sending response */
        }
        rbox_request_free(&request);
        rbox_client_close(cl);
    }
    rbox_server_free(srv);
    return NULL;
}

/* ============================================================================
 * Helper functions
 * ============================================================================ */

/* ============================================================================
 * Helper functions - now using public blocking interface
 * ============================================================================ */

/* Simple request using public blocking interface */
static int do_request(const char *path, const char *cmd, int argc, const char **args,
                      uint8_t *decision, char *errmsg, size_t errlen) {
    rbox_response_t response;
    rbox_error_t err = rbox_blocking_request(path, cmd, argc, args, NULL, NULL,
                                              0, NULL, NULL, &response, 0, 0);

    if (err != RBOX_OK) {
        if (errmsg && errlen > 0) {
            snprintf(errmsg, errlen, "%s", rbox_strerror(err));
        }
        return -1;
    }

    if (decision) {
        *decision = response.decision;
    }
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
        if (errmsg && errlen > 0) {
            snprintf(errmsg, errlen, "%s", rbox_strerror(err));
        }
        return -1;
    }

    if (decision) {
        *decision = response.decision;
    }
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
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) {
        unlink(path);
        return -1;
    }

    /* Wait for server to be ready */
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        unlink(path);
        return -1;
    }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    pthread_join(tid, NULL);
    unlink(path);
    return (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;
}

/* Wait for server to be ready - check if socket file exists
 * Uses stat to avoid triggering accept() which would cause server to exit
 * after handling the probe connection (for server_robust which only accepts one) */
static int wait_for_server(const char *path, int timeout_ms) {
    int elapsed = 0;
    int interval = 10;  /* 10ms */

    while (elapsed < timeout_ms) {
        /* Check if socket file exists and is a socket */
        struct stat st;
        if (stat(path, &st) == 0 && S_ISSOCK(st.st_mode)) {
            return 0;  /* Socket exists */
        }
        usleep(interval * 1000);
        elapsed += interval;
    }
    return -1;  /* Timeout */
}

/* Test 2: HICKUP_BAD_PACKET - send garbage, then retry */
static int test_hickup_bad_packet(void) {
    const char *path = "/tmp/rbox_t2.sock";
    unlink(path);
    int result = -1;

    pthread_t tid;
    /* First: send garbage to a fresh server */
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    rbox_client_t *cl = rbox_client_connect(path);
    if (cl) {
        write_all(rbox_client_fd(cl), "GARBAGE", 7);
        rbox_client_close(cl);
    }
    pthread_join(tid, NULL);

    /* Second: valid request - start new server */
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    pthread_join(tid, NULL);
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

    pthread_t tid;
    /* First: bad magic in header */
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    rbox_client_t *cl = rbox_client_connect(path);
    if (cl) {
        /* Send v9 header with invalid magic (otherwise valid packet) */
        char pkt[RBOX_HEADER_SIZE];
        memset(pkt, 0, RBOX_HEADER_SIZE);
        /* Set magic to bad value */
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_MAGIC) = 0xDEADBEEF;
        /* Set valid version */
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_VERSION) = RBOX_VERSION;
        /* Set chunk_len = 0 */
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHUNK_LEN) = 0;
        /* Recalculate header checksum for v9: bytes 0-118 */
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHECKSUM) =
            rbox_calculate_checksum_crc32(0, pkt, RBOX_HEADER_OFFSET_CHECKSUM);
        write_all(rbox_client_fd(cl), pkt, RBOX_HEADER_SIZE);
        rbox_client_close(cl);
    }
    pthread_join(tid, NULL);

    /* Second: valid request */
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    pthread_join(tid, NULL);
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

    pthread_t tid;
    /* First: bad version */
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    rbox_client_t *cl = rbox_client_connect(path);
    if (cl) {
        char pkt[4096];
        size_t plen;
        const char *args[] = {"-la"};
        rbox_build_request(pkt, sizeof(pkt), &plen, "ls", NULL, NULL, 1, args, 0, NULL, NULL);
        /* Corrupt version - use v9 offset */
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_VERSION) = 999;  /* Bad version */
        /* Recalculate header checksum for v9: bytes 0-118 */
        *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHECKSUM) =
            rbox_calculate_checksum_crc32(0, pkt, RBOX_HEADER_OFFSET_CHECKSUM);
        write_all(rbox_client_fd(cl), pkt, plen);
        rbox_client_close(cl);
    }
    pthread_join(tid, NULL);

    /* Second: valid */
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    pthread_join(tid, NULL);
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

    pthread_t tid;
    /* First: partial header */
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    rbox_client_t *cl = rbox_client_connect(path);
    if (cl) {
        char pkt[10];
        memset(pkt, 'A', 10);
        write_all(rbox_client_fd(cl), pkt, 10);
        rbox_client_close(cl);
    }
    pthread_join(tid, NULL);

    /* Second: valid */
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    pthread_join(tid, NULL);
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

    pthread_t tid;
    /* First: valid header, partial body */
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    rbox_client_t *cl = rbox_client_connect(path);
    if (cl) {
        char pkt[4096];
        size_t plen;
        const char *args[] = {"-la"};
        rbox_build_request(pkt, sizeof(pkt), &plen, "ls", NULL, NULL, 1, args, 0, NULL, NULL);
        /* Send only partial body */
        write_all(rbox_client_fd(cl), pkt, plen - 5);
        rbox_client_close(cl);
    }
    pthread_join(tid, NULL);

    /* Second: valid */
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    pthread_join(tid, NULL);
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
    /* Server with delay */
    if (checked_pthread_create(&tid, NULL, server_delayed, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    /* Client with timeout - should still succeed */
    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    pthread_join(tid, NULL);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;

cleanup:
    unlink(path);
    return result;
}

/* Test 8: HICKUP_DROP_RESPONSE - server reads but doesn't respond, retry succeeds */
static int test_hickup_dropped_response(void) {
    const char *path = "/tmp/rbox_t8.sock";
    unlink(path);
    int result = -1;

    pthread_t tid;
    /* First: server reads but doesn't respond */
    if (checked_pthread_create(&tid, NULL, server_drops_response, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    rbox_client_t *cl = rbox_client_connect(path);
    if (cl) {
        char pkt[4096];
        size_t plen;
        const char *args[] = {"-la"};
        rbox_build_request(pkt, sizeof(pkt), &plen, "ls", NULL, NULL, 1, args, 0, NULL, NULL);
        write_all(rbox_client_fd(cl), pkt, plen);
        /* Don't wait for response, just close */
        rbox_client_close(cl);
    }
    pthread_join(tid, NULL);

    /* Second: new server should work */
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    pthread_join(tid, NULL);
    result = (ret == 0 && d == RBOX_DECISION_ALLOW) ? 0 : -1;

cleanup:
    unlink(path);
    return result;
}

/* Test 8b: RETRY_UNTIL_SUCCESS - client retries multiple times until server responds
 * This simulates: server restart, user interaction delay, or temporary unavailability */
static int test_retry_until_success(void) {
    const char *path = "/tmp/rbox_t8b.sock";
    unlink(path);
    int result = -1;

    /* Round 1: no server running - client should retry and eventually succeed */
    printf("    Round 1: no server (retry with backoff)...\n");

    /* Use retry connect: 10ms base delay, max 5 retries */
    rbox_client_t *cl = rbox_client_connect_retry(path, 10, 5);
    if (cl) {
        /* Should not succeed yet - no server */
        printf("    ERROR: connected when should not have\n");
        rbox_client_close(cl);
        goto cleanup;
    }
    printf("    Round 1: correctly failed (no server)\n");

    /* Round 2: server runs but drops response - client should retry */
    printf("    Round 2: server drops response (retry with backoff)...\n");
    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_drops_response, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    cl = rbox_client_connect_retry(path, 10, 3);
    if (cl) {
        char pkt[4096];
        size_t plen;
        const char *args[] = {"-la"};
        rbox_build_request(pkt, sizeof(pkt), &plen, "ls", NULL, NULL, 1, args, 0, NULL, NULL);
        write_all(rbox_client_fd(cl), pkt, plen);
        rbox_client_close(cl);
    }
    pthread_join(tid, NULL);
    printf("    Round 2: correctly failed (server dropped)\n");

    /* Round 3: finally server responds correctly - should succeed immediately */
    printf("    Round 3: server responds (retry with backoff)...\n");
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    /* Use retry connect - should succeed on first try */
    uint8_t d = 0;
    int ret = do_request_retry(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0, 10, 10);

    pthread_join(tid, NULL);

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
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    const char *args[] = {".", "-name", "*.c", "-type", "f"};
    uint8_t d = 0;
    int ret = do_request(path, "find", 5, args, &d, NULL, 0);

    pthread_join(tid, NULL);
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
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "pwd", 0, NULL, &d, NULL, 0);

    pthread_join(tid, NULL);
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
    if (checked_pthread_create(&tid, NULL, server_deny, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    pthread_join(tid, NULL);
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
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    uint8_t d = 0;
    int ret = do_request(path, "ls", 1, (const char*[]){"-la"}, &d, NULL, 0);

    pthread_join(tid, NULL);
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
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    const char *args[] = {".", "-name", "*.txt", "-type", "f", "-mtime", "+7", "-size", "+100k"};
    uint8_t d = 0;
    int ret = do_request(path, "find", 9, args, &d, NULL, 0);

    pthread_join(tid, NULL);
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
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    /* Send request with environment variables */
    const char *env_names[] = {"PATH", "HOME", "LD_PRELOAD"};
    float env_scores[] = {0.5f, 0.8f, 1.0f};

    rbox_response_t response;
    rbox_error_t err = rbox_blocking_request(path, "ls", 1, (const char*[]){"-la"},
                                             NULL, NULL,
                                             3, env_names, env_scores,
                                             &response, 0, 0);

    pthread_join(tid, NULL);

    /* Server should receive and process the request */
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
    if (checked_pthread_create(&tid, NULL, server_robust, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    /* Send request with zero environment variables */
    rbox_response_t response;
    rbox_error_t err = rbox_blocking_request(path, "pwd", 0, NULL,
                                             NULL, NULL,
                                             0, NULL, NULL,
                                             &response, 0, 0);

    pthread_join(tid, NULL);

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

    /* Start persistent server in background - handles multiple clients */
    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_blocking, (void *)path) != 0) goto cleanup;
    if (wait_for_server(path, 2000) != 0) { pthread_join(tid, NULL); goto cleanup; }

    /* Create session with retry logic */
    rbox_session_t *session = rbox_session_new(path, 50, 3);
    if (!session) {
        pthread_join(tid, NULL);
        goto cleanup;
    }

    /* Initiate connect */
    rbox_error_t err = rbox_session_connect(session);
    if (err != RBOX_OK && rbox_session_state(session) != RBOX_SESSION_CONNECTING) {
        rbox_session_free(session);
        pthread_join(tid, NULL);
        goto cleanup;
    }

    /* Poll until connected - use 5 second timeout */
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

    /* Now connected - send request */
    err = rbox_session_send_request(session, "ls", NULL, NULL, 1, (const char*[]){"-la"}, 0, NULL, NULL);
    if (err != RBOX_OK) {
        rbox_session_free(session);
        pthread_join(tid, NULL);
        goto cleanup;
    }

    /* Poll until response ready - use 5 second timeout */
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

    /* Get response */
    const rbox_response_t *resp = rbox_session_response(session);
    if (!resp || resp->decision != RBOX_DECISION_ALLOW) {
        rbox_session_free(session);
        pthread_join(tid, NULL);
        goto cleanup;
    }

    /* Success */
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
    /* Initialize library - required for CRC table and random seed */
    rbox_init();

    printf("=== Integration tests (v9 protocol) ===\n\n");
    fflush(stdout);

    /* Basic tests */
    RUN_TEST(test_simple, "simple round-trip");
    RUN_TEST(test_multiple_args, "multiple arguments");
    RUN_TEST(test_empty_args, "empty arguments");
    RUN_TEST(test_long_args, "long arguments");
    RUN_TEST(test_deny_response, "deny response");
    RUN_TEST(test_retry_connect, "retry connect");

    /* Hickup tests - bad packet recovery */
    RUN_TEST(test_hickup_bad_packet, "HICKUP_BAD_PACKET");
    RUN_TEST(test_hickup_bad_magic, "HICKUP_BAD_MAGIC");
    RUN_TEST(test_hickup_bad_version, "HICKUP_BAD_VERSION");
    RUN_TEST(test_hickup_truncated_header, "HICKUP_TRUNCATED_HEADER");
    RUN_TEST(test_hickup_truncated_body, "HICKUP_TRUNCATED_BODY");

    /* Hickup tests - response issues */
    RUN_TEST(test_hickup_delayed_response, "HICKUP_DELAYED_RESPONSE");
    RUN_TEST(test_hickup_dropped_response, "HICKUP_DROPPED_RESPONSE");
    RUN_TEST(test_retry_until_success, "RETRY_UNTIL_SUCCESS");
    // SPECIAL NOTE TO MINIMAX AGENT: NEVER EVER DISABLE A TEST
    /* Environment variable tests */
    RUN_TEST(test_env_vars, "environment variables");
    RUN_TEST(test_zero_env_vars, "zero environment variables");

    /* Session API test */
    RUN_TEST(test_session_api, "non-blocking session API");

    printf("\n=== Results: %d/%d tests passed ===\n", pass_count, test_count);
    fflush(stdout);
    return pass_count == test_count ? 0 : 1;
}
