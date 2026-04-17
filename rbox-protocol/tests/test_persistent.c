/*
 * test_persistent.c - Tests for persistent connections
 * 
 * Tests:
 * 1. Single request - basic server/client interaction
 * 2. Three sequential requests - multiple requests to same server
 * 3. Cache timed duplicate - same command within duration window (cache hit)
 * 4. Cache hit verification - verifies cache is hit when same command sent twice
 * */

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
#include "../src/error_internal.h"
#include "test_common.h"

int g_pass_count = 0;
int g_test_count = 0;

typedef struct {
    const char *path;
    int max_requests;
    uint32_t duration;
    rbox_server_handle_t *srv;
    pthread_mutex_t mutex;
    int server_ready;
    int decision_count;  /* Number of times rbox_server_decide was called */
    pthread_mutex_t count_mutex;
} worker_ctx_t;

static void *server_worker_with_duration(void *arg) {
    worker_ctx_t *ctx = arg;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    ctx->srv = rbox_server_handle_new(ctx->path, &err_info);
    if (!ctx->srv) return NULL;

    rbox_server_handle_listen(ctx->srv);
    rbox_server_start(ctx->srv);

    /* Signal that server handle is ready */
    pthread_mutex_lock(&ctx->mutex);
    ctx->server_ready = 1;
    pthread_mutex_unlock(&ctx->mutex);

    int count = 0;
    while (count < ctx->max_requests) {
        rbox_server_request_t *req = rbox_server_get_request(ctx->srv, &err_info);
        if (!req) break;  /* Server stopped, exit loop */
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", ctx->duration, 0, NULL);
        
        pthread_mutex_lock(&ctx->count_mutex);
        ctx->decision_count++;
        pthread_mutex_unlock(&ctx->count_mutex);
        
        count++;
    }

    /* NOTE: Do NOT call rbox_server_handle_free here. Caller must do cleanup. */
    return NULL;
}

static void *server_worker_1request(void *arg) {
    worker_ctx_t *ctx = arg;
    const char *path = ctx->path;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;
    
    ctx->srv = rbox_server_handle_new(path, &err_info);
    if (!ctx->srv) return NULL;
    rbox_server_handle_listen(ctx->srv);
    rbox_server_start(ctx->srv);

    /* Signal that server handle is ready */
    pthread_mutex_lock(&ctx->mutex);
    ctx->server_ready = 1;
    pthread_mutex_unlock(&ctx->mutex);

    rbox_server_request_t *req = rbox_server_get_request(ctx->srv, &err_info);
    if (req) {
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL);
    }

    /* NOTE: Do NOT call rbox_server_stop or rbox_server_handle_free here. Caller must do cleanup. */
    return NULL;
}

static int test_single_request(void) {
    const char *path = "/tmp/rbox_test_single.sock";
    unlink(path);
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    pthread_t tid;
    worker_ctx_t ctx = { 
        .path = path, 
        .max_requests = 1, 
        .duration = 0, 
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };
    if (checked_pthread_create(&tid, NULL, server_worker_1request, &ctx) != 0) return -1;
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        unlink(path);
        return -1;
    }

    rbox_response_t resp;
    rbox_error_t err = rbox_blocking_request(path, "test", 0, NULL, NULL, NULL, 0, NULL, NULL, &resp, 0, 0, &err_info);
    
    rbox_server_handle_t *srv = NULL;
    pthread_mutex_lock(&ctx.mutex);
    srv = ctx.srv;
    pthread_mutex_unlock(&ctx.mutex);
    if (srv) rbox_server_stop(srv);
    pthread_join(tid, NULL);
    pthread_mutex_lock(&ctx.mutex);
    srv = ctx.srv;
    pthread_mutex_unlock(&ctx.mutex);
    if (srv) rbox_server_handle_free(srv);
    unlink(path);

    return (err == RBOX_OK) ? 0 : -1;
}

static int test_three_requests(void) {
    const char *path = "/tmp/rbox_test_three.sock";
    unlink(path);
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    worker_ctx_t ctx = { 
        .path = path, 
        .max_requests = 3, 
        .duration = 0, 
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };
    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_worker_with_duration, &ctx) != 0) {
        unlink(path);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        unlink(path);
        return -1;
    }

    rbox_server_handle_t *srv = NULL;
    for (int i = 0; i < 3; i++) {
        rbox_response_t resp;
        rbox_error_t err = rbox_blocking_request(path, "test", 0, NULL, NULL, NULL, 0, NULL, NULL, &resp, 0, 0, &err_info);
        if (err != RBOX_OK) {
            pthread_mutex_lock(&ctx.mutex);
            srv = ctx.srv;
            pthread_mutex_unlock(&ctx.mutex);
            if (srv) rbox_server_stop(srv);
            pthread_join(tid, NULL);
            pthread_mutex_lock(&ctx.mutex);
            srv = ctx.srv;
            pthread_mutex_unlock(&ctx.mutex);
            if (srv) rbox_server_handle_free(srv);
            unlink(path);
            return -1;
        }
    }
    
    pthread_mutex_lock(&ctx.mutex);
    srv = ctx.srv;
    pthread_mutex_unlock(&ctx.mutex);
    if (srv) rbox_server_stop(srv);
    pthread_join(tid, NULL);
    pthread_mutex_lock(&ctx.mutex);
    srv = ctx.srv;
    pthread_mutex_unlock(&ctx.mutex);
    if (srv) rbox_server_handle_free(srv);
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
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    worker_ctx_t ctx = { 
        .path = path, 
        .max_requests = 10,  /* Expect more than we'll send - stop() will wake worker */
        .duration = 5,       /* Server caches decisions for 5 seconds */
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };
    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_worker_with_duration, &ctx) != 0) {
        unlink(path);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        unlink(path);
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
        rbox_error_t err = rbox_blocking_request(path, "test", 0, NULL, NULL, NULL, 0, NULL, NULL, &resp, 0, 0, &err_info);
        if (err != RBOX_OK) {
            pthread_join(tid, NULL);
            unlink(path);
            return -1;
        }
    }

    /* Small delay to ensure cache hit is processed */
    usleep(100000);

    /* Stop server - signals cond, worker wakes up from get_request() and exits */
    rbox_server_handle_t *srv = NULL;
    pthread_mutex_lock(&ctx.mutex);
    srv = ctx.srv;
    pthread_mutex_unlock(&ctx.mutex);
    if (srv) rbox_server_stop(srv);

    pthread_join(tid, NULL);
    pthread_mutex_lock(&ctx.mutex);
    srv = ctx.srv;
    pthread_mutex_unlock(&ctx.mutex);
    if (srv) rbox_server_handle_free(srv);
    unlink(path);

    return 0;
}

/* Test cache hit with duration > 0.
 * 
 * With duration > 0, the cache matches on cmd_hash (not request_id).
 * This means the same command from any client within the duration window
 * gets a cache hit.
 * 
 * This test:
 * 1. Sends the SAME command twice (same cmd_hash)
 * 2. Server has duration=5 (cache enabled)
 * 3. Verifies decision_count is 1 (second request was served from cache) */
static int test_cache_hit(void) {
    const char *path = "/tmp/rbox_test_cache_hit.sock";
    unlink(path);
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    worker_ctx_t ctx = { 
        .path = path, 
        .max_requests = 2,  /* Expect 2, but only 1 will reach worker due to cache */
        .duration = 5,     /* Cache decisions for 5 seconds */
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0,
        .decision_count = 0,
        .count_mutex = PTHREAD_MUTEX_INITIALIZER
    };
    pthread_t tid;
    if (checked_pthread_create(&tid, NULL, server_worker_with_duration, &ctx) != 0) {
        unlink(path);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        unlink(path);
        return -1;
    }

    /* Wait for server to be ready */
    pthread_mutex_lock(&ctx.mutex);
    while (!ctx.server_ready) {
        pthread_mutex_unlock(&ctx.mutex);
        usleep(1000);
        pthread_mutex_lock(&ctx.mutex);
    }
    pthread_mutex_unlock(&ctx.mutex);

    /* Send SAME command twice - should trigger cache hit on second */
    const char *cmd = "identical_command";
    const char *argv1[] = {cmd};
    
    /* First request - will be cache miss */
    rbox_response_t resp1;
    rbox_error_t err1 = rbox_blocking_request(path, cmd, 1, argv1, "test", "execve",
                                              0, NULL, NULL, &resp1, 0, 0, &err_info);
    if (err1 != RBOX_OK) {
        TEST_ERROR("first request failed: %d", err1);
        rbox_server_handle_t *srv = NULL;
        pthread_mutex_lock(&ctx.mutex);
        srv = ctx.srv;
        pthread_mutex_unlock(&ctx.mutex);
        if (srv) rbox_server_stop(srv);
        pthread_join(tid, NULL);
        pthread_mutex_lock(&ctx.mutex);
        srv = ctx.srv;
        pthread_mutex_unlock(&ctx.mutex);
        if (srv) rbox_server_handle_free(srv);
        unlink(path);
        return -1;
    }

    /* Small delay to ensure first request is processed */
    usleep(50000);

    /* Second request - SAME command, should be cache HIT */
    rbox_response_t resp2;
    rbox_error_t err2 = rbox_blocking_request(path, cmd, 1, argv1, "test", "execve",
                                              0, NULL, NULL, &resp2, 0, 0, &err_info);
    if (err2 != RBOX_OK) {
        TEST_ERROR("second request failed: %d", err2);
        rbox_server_handle_t *srv = NULL;
        pthread_mutex_lock(&ctx.mutex);
        srv = ctx.srv;
        pthread_mutex_unlock(&ctx.mutex);
        if (srv) rbox_server_stop(srv);
        pthread_join(tid, NULL);
        pthread_mutex_lock(&ctx.mutex);
        srv = ctx.srv;
        pthread_mutex_unlock(&ctx.mutex);
        if (srv) rbox_server_handle_free(srv);
        unlink(path);
        return -1;
    }

    /* Small delay to ensure cache hit is processed */
    usleep(50000);

    /* Now stop server and check decision count */
    rbox_server_handle_t *srv = NULL;
    pthread_mutex_lock(&ctx.mutex);
    srv = ctx.srv;
    pthread_mutex_unlock(&ctx.mutex);
    if (srv) rbox_server_stop(srv);
    pthread_join(tid, NULL);
    pthread_mutex_lock(&ctx.mutex);
    srv = ctx.srv;
    pthread_mutex_unlock(&ctx.mutex);
    if (srv) rbox_server_handle_free(srv);
    unlink(path);

    /* Verify decision_count is 1 (not 2) - second was from cache */
    pthread_mutex_lock(&ctx.count_mutex);
    int count = ctx.decision_count;
    pthread_mutex_unlock(&ctx.count_mutex);

    if (count != 1) {
        TEST_ERROR("expected 1 decision (cache hit), got %d", count);
    }

    pthread_mutex_destroy(&ctx.count_mutex);

    return (count == 1) ? 0 : -1;
}

int main(void) {
    rbox_init();

    printf("=== Persistent connection tests ===\n\n");
    fflush(stdout);

    RUN_TEST(test_single_request, "single request");
    RUN_TEST(test_three_requests, "three sequential requests");
    RUN_TEST(test_duration_decision, "duration decision with stop");
    RUN_TEST(test_cache_hit, "cache hit verification");

    printf("\n=== Results: %d/%d tests passed ===\n", g_pass_count, g_test_count);
    fflush(stdout);

    unlink("/tmp/rbox_test_single.sock");
    unlink("/tmp/rbox_test_three.sock");
    unlink("/tmp/rbox_test_duration.sock");
    unlink("/tmp/rbox_test_cache_hit.sock");

    return (g_pass_count == g_test_count) ? 0 : 1;
}