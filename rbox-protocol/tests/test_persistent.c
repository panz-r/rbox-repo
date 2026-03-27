/*
 * test_persistent.c - Tests for persistent connections
 * 
 * Tests:
 * 1. Single request - basic server/client interaction
 * 2. Three sequential requests - multiple requests to same server
 * 3. Cache timed duplicate - same command within duration window (cache hit)
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
#include <errno.h>
#include <time.h>

#include "rbox_protocol.h"

static int pass_count = 0;
static int test_count = 0;

#define RUN_TEST(fn, name) do { \
    test_count++; \
    printf("  Testing: %s...\n", name); \
    fflush(stdout); \
    if (fn() == 0) { printf("    PASS\n"); pass_count++; } \
    else { printf("    FAIL\n"); } \
    fflush(stdout); \
} while(0)

#define TEST_ERROR(fmt, ...) fprintf(stderr, "ERROR: " fmt "\n", ##__VA_ARGS__)

static int wait_for_server(const char *path, int timeout_ms) {
    int interval = 50;
    int elapsed = 0;
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

static int checked_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                                  void *(*start_routine)(void *), void *arg) {
    int err = pthread_create(thread, attr, start_routine, arg);
    if (err != 0) {
        TEST_ERROR("pthread_create failed: %s", strerror(err));
        return -1;
    }
    return 0;
}

typedef struct {
    const char *path;
    int max_requests;
    uint32_t duration;
    rbox_server_handle_t *srv;
    pthread_mutex_t mutex;
    int server_ready;
} worker_ctx_t;

static void *server_worker_with_duration(void *arg) {
    worker_ctx_t *ctx = arg;

    ctx->srv = rbox_server_handle_new(ctx->path);
    if (!ctx->srv) return NULL;

    rbox_server_handle_listen(ctx->srv);
    rbox_server_start(ctx->srv);

    /* Signal that server handle is ready */
    pthread_mutex_lock(&ctx->mutex);
    ctx->server_ready = 1;
    pthread_mutex_unlock(&ctx->mutex);

    int count = 0;
    while (count < ctx->max_requests) {
        rbox_server_request_t *req = rbox_server_get_request(ctx->srv);
        if (!req) break;  /* Server stopped, exit loop */
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", ctx->duration, 0, NULL, NULL);
        count++;
    }

    rbox_server_handle_free(ctx->srv);
    return NULL;
}

static void *server_worker_1request(void *arg) {
    const char *path = arg;
    rbox_server_handle_t *srv = rbox_server_handle_new(path);
    if (!srv) return NULL;
    rbox_server_handle_listen(srv);
    rbox_server_start(srv);

    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (req) {
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL);
    }

    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return NULL;
}

static int test_single_request(void) {
    const char *path = "/tmp/rbox_test_single.sock";
    unlink(path);

    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_worker_1request, (void *)path) != 0) return -1;
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        return -1;
    }

    rbox_response_t resp;
    rbox_error_t err = rbox_blocking_request(path, "test", 0, NULL, NULL, NULL, 0, NULL, NULL, &resp, 0, 0);
    
    pthread_join(tid, NULL);
    unlink(path);

    return (err == RBOX_OK) ? 0 : -1;
}

static int test_three_requests(void) {
    const char *path = "/tmp/rbox_test_three.sock";
    unlink(path);

    worker_ctx_t ctx = { 
        .path = path, 
        .max_requests = 3, 
        .duration = 0, 
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };
    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_worker_with_duration, &ctx) != 0) return -1;
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        return -1;
    }

    for (int i = 0; i < 3; i++) {
        rbox_response_t resp;
        rbox_error_t err = rbox_blocking_request(path, "test", 0, NULL, NULL, NULL, 0, NULL, NULL, &resp, 0, 0);
        if (err != RBOX_OK) {
            pthread_join(tid, NULL);
            return -1;
        }
    }
    
    pthread_join(tid, NULL);
    unlink(path);

    return 0;
}

/* Test cache with duration>0 for duplicate commands.
 * 
 * With duration > 0, cache matches on cmd_hash (not request_id).
 * This means the same command from any client within the duration
 * window gets a cache hit, serviced directly by main I/O loop.
 * 
 * Worker sees only the first request (cache miss). The second request
 * hits cache and is sent directly without worker involvement.
 * 
 * Main thread waits for server_ready signal before calling stop(). */
/* Test that server correctly handles decisions with duration > 0.
 * 
 * With duration > 0, the response is cached (matching on cmd_hash).
 * This test verifies the server can process such requests correctly.
 * 
 * Note: True cache hit testing (where second request hits cache without
 * worker involvement) requires either a non-blocking get_request_timed()
 * or using the session API directly. The blocking API generates unique
 * request_ids per call, so cache hits don't occur between calls. */
static int test_duration_decision(void) {
    const char *path = "/tmp/rbox_test_duration.sock";
    unlink(path);

    worker_ctx_t ctx = { 
        .path = path, 
        .max_requests = 10,  /* Expect more than we'll send - stop() will wake worker */
        .duration = 5,       /* Server caches decisions for 5 seconds */
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };
    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_worker_with_duration, &ctx) != 0) return -1;
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        return -1;
    }

    /* Wait for server handle to be stored */
    pthread_mutex_lock(&ctx.mutex);
    while (!ctx.server_ready) {
        pthread_mutex_unlock(&ctx.mutex);
        usleep(1000);
        pthread_mutex_lock(&ctx.mutex);
    }
    pthread_mutex_unlock(&ctx.mutex);

    /* Send two requests - server processes with duration=5 */
    for (int i = 0; i < 2; i++) {
        rbox_response_t resp;
        rbox_error_t err = rbox_blocking_request(path, "test", 0, NULL, NULL, NULL, 0, NULL, NULL, &resp, 0, 0);
        if (err != RBOX_OK) {
            pthread_join(tid, NULL);
            return -1;
        }
    }

    /* Small delay to ensure cache hit is processed */
    usleep(100000);

    /* Stop server - signals cond, worker wakes up from get_request() and exits */
    rbox_server_stop(ctx.srv);

    pthread_join(tid, NULL);
    unlink(path);

    return 0;
}

int main(void) {
    rbox_init();

    printf("=== Persistent connection tests ===\n\n");
    fflush(stdout);

    RUN_TEST(test_single_request, "single request");
    RUN_TEST(test_three_requests, "three sequential requests");
    RUN_TEST(test_duration_decision, "duration decision with stop");

    printf("\n=== Results: %d/%d tests passed ===\n", pass_count, test_count);
    fflush(stdout);

    unlink("/tmp/rbox_test_single.sock");
    unlink("/tmp/rbox_test_three.sock");
    unlink("/tmp/rbox_test_cache_dup.sock");

    return (pass_count == test_count) ? 0 : 1;
}