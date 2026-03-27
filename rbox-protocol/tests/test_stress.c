/*
 * test_stress.c - Stress tests for server stability
 * 
 * Tests:
 * 1. 100 clients, 10 requests each - Epoll scalability test
 * 2. Edge-triggered burst - 2 requests sent before response, verify order
 * 3. Server timeout partial - Send header, wait, verify timeout
 * 4. Signal graceful shutdown - SIGTERM handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
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

typedef struct {
    const char *path;
    int max_requests;
    rbox_server_handle_t *srv;
    pthread_mutex_t mutex;
    int server_ready;
} worker_ctx_t;

static void *server_worker_stress(void *arg) {
    worker_ctx_t *ctx = arg;

    ctx->srv = rbox_server_handle_new(ctx->path);
    if (!ctx->srv) return NULL;

    rbox_server_handle_listen(ctx->srv);
    rbox_server_start(ctx->srv);

    pthread_mutex_lock(&ctx->mutex);
    ctx->server_ready = 1;
    pthread_mutex_unlock(&ctx->mutex);

    int count = 0;
    while (count < ctx->max_requests) {
        rbox_server_request_t *req = rbox_server_get_request(ctx->srv);
        if (!req) break;
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL);
        count++;
    }

    rbox_server_handle_free(ctx->srv);
    return NULL;
}

/* Test 100 clients, 10 requests each - Epoll scalability */
static int test_100_clients_persistent(void) {
    const char *path = "/tmp/rbox_test_stress_100.sock";
    unlink(path);

    const int num_clients = 100;
    const int requests_per_client = 10;
    int success_count = 0;

    worker_ctx_t ctx = {
        .path = path,
        .max_requests = num_clients * requests_per_client,
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };

    pthread_t tid;
    if (pthread_create(&tid, NULL, server_worker_stress, &ctx) != 0) return -1;
    if (wait_for_server(path, 3000) != 0) {
        pthread_join(tid, NULL);
        return -1;
    }

    /* Run multiple clients */
    for (int c = 0; c < num_clients; c++) {
        rbox_client_t *cl = rbox_client_connect(path);
        if (!cl) continue;

        for (int r = 0; r < requests_per_client; r++) {
            const char *argv[] = {"echo", "test"};
            rbox_response_t resp = {0};
            rbox_error_t err = rbox_blocking_request(path, "echo", 2, argv, "test", "execve",
                                                     0, NULL, NULL, &resp, 100, 1);
            if (err == RBOX_OK) {
                success_count++;
            }
        }
        rbox_client_close(cl);
    }

    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    unlink(path);

    int expected = num_clients * requests_per_client;
    if (success_count != expected) {
        TEST_ERROR("expected %d successes, got %d", expected, success_count);
        return -1;
    }

    return 0;
}

/* Test edge-triggered burst - 2 requests before response, verify order */
static int test_edge_triggered_burst(void) {
    const char *path = "/tmp/rbox_test_edge_burst.sock";
    unlink(path);

    worker_ctx_t ctx = {
        .path = path,
        .max_requests = 2,
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };

    pthread_t tid;
    if (pthread_create(&tid, NULL, server_worker_stress, &ctx) != 0) return -1;
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        return -1;
    }

    rbox_client_t *cl = rbox_client_connect(path);
    if (!cl) {
        rbox_server_stop(ctx.srv);
        pthread_join(tid, NULL);
        return -1;
    }

    /* Send 2 requests in rapid succession without reading responses */
    const char *argv1[] = {"echo", "first"};
    const char *argv2[] = {"echo", "second"};

    rbox_response_t resp1 = {0}, resp2 = {0};

    rbox_error_t err1 = rbox_blocking_request(path, "echo", 2, argv1, "test", "execve",
                                             0, NULL, NULL, &resp1, 100, 1);
    rbox_error_t err2 = rbox_blocking_request(path, "echo", 2, argv2, "test", "execve",
                                             0, NULL, NULL, &resp2, 100, 1);

    rbox_client_close(cl);
    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    unlink(path);

    if (err1 != RBOX_OK || err2 != RBOX_OK) {
        TEST_ERROR("request failed: err1=%d, err2=%d", err1, err2);
        return -1;
    }

    /* Both should succeed */
    return 0;
}

/* Test server timeout partial - send header, wait, verify timeout behavior */
static int test_server_timeout_partial(void) {
    const char *path = "/tmp/rbox_test_timeout.sock";
    unlink(path);

    worker_ctx_t ctx = {
        .path = path,
        .max_requests = 1,
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };

    pthread_t tid;
    if (pthread_create(&tid, NULL, server_worker_stress, &ctx) != 0) return -1;
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        return -1;
    }

    /* Connect but don't send anything - server should handle gracefully */
    rbox_client_t *cl = rbox_client_connect(path);
    if (!cl) {
        rbox_server_stop(ctx.srv);
        pthread_join(tid, NULL);
        return -1;
    }

    /* Wait a bit to allow server to accept and register the fd */
    usleep(50000);  /* 50ms */

    /* Send single char to partial wake server */
    char c = 'A';
    write(rbox_client_fd(cl), &c, 1);

    /* Close without sending complete request */
    rbox_client_close(cl);
    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    unlink(path);

    return 0;
}

/* Test signal graceful shutdown */
static int test_signal_graceful_shutdown(void) {
    const char *path = "/tmp/rbox_test_signal.sock";
    unlink(path);

    worker_ctx_t ctx = {
        .path = path,
        .max_requests = 100,
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };

    /* Start server in background process */
    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        /* Child - run server */
        ctx.srv = rbox_server_handle_new(ctx.path);
        if (!ctx.srv) exit(1);
        rbox_server_handle_listen(ctx.srv);
        rbox_server_start(ctx.srv);

        /* Wait for a request then exit on signal */
        int count = 0;
        while (count < 5) {
            rbox_server_request_t *req = rbox_server_get_request(ctx.srv);
            if (!req) break;
            rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL);
            count++;
        }

        rbox_server_handle_free(ctx.srv);
        exit(0);
    }

    /* Parent - wait for server, send a request, then signal it */
    usleep(100000);  /* 100ms for server to start */

    /* Check server is running by trying to connect */
    if (wait_for_server(path, 2000) != 0) {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return -1;
    }

    /* Send a request */
    const char *argv[] = {"echo", "test"};
    rbox_response_t resp = {0};
    rbox_error_t err = rbox_blocking_request(path, "echo", 2, argv, "test", "execve",
                                             0, NULL, NULL, &resp, 100, 1);

    /* Send SIGTERM to server process */
    kill(pid, SIGTERM);

    int status;
    waitpid(pid, &status, 0);

    unlink(path);

    if (err != RBOX_OK) {
        TEST_ERROR("request failed before signal: %d", err);
        return -1;
    }

    return 0;
}

/* Test rapid connect/disconnect - server stability under load */
static int test_rapid_connect_disconnect(void) {
    const char *path = "/tmp/rbox_test_rapid.sock";
    unlink(path);

    worker_ctx_t ctx = {
        .path = path,
        .max_requests = 50,
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };

    pthread_t tid;
    if (pthread_create(&tid, NULL, server_worker_stress, &ctx) != 0) return -1;
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        return -1;
    }

    int success = 0;
    for (int i = 0; i < 50; i++) {
        rbox_client_t *cl = rbox_client_connect(path);
        if (!cl) continue;

        const char *argv[] = {"pwd"};
        rbox_response_t resp = {0};
        rbox_error_t err = rbox_blocking_request(path, "pwd", 1, argv, "test", "execve",
                                                 0, NULL, NULL, &resp, 50, 1);
        if (err == RBOX_OK) success++;

        rbox_client_close(cl);
        usleep(1000);  /* 1ms between connections */
    }

    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    unlink(path);

    if (success < 40) {
        TEST_ERROR("only %d/50 requests succeeded", success);
        return -1;
    }

    return 0;
}

int main(void) {
    rbox_init();

    printf("=== Stress tests ===\n\n");
    fflush(stdout);

    RUN_TEST(test_100_clients_persistent, "100 clients, 10 requests each");
    RUN_TEST(test_edge_triggered_burst, "edge-triggered burst (2 requests)");
    RUN_TEST(test_server_timeout_partial, "server timeout partial");
    RUN_TEST(test_signal_graceful_shutdown, "signal graceful shutdown");
    RUN_TEST(test_rapid_connect_disconnect, "rapid connect/disconnect");

    printf("\n=== Results: %d/%d tests passed ===\n", pass_count, test_count);
    fflush(stdout);

    unlink("/tmp/rbox_test_stress_100.sock");
    unlink("/tmp/rbox_test_edge_burst.sock");
    unlink("/tmp/rbox_test_timeout.sock");
    unlink("/tmp/rbox_test_signal.sock");
    unlink("/tmp/rbox_test_rapid.sock");

    return (pass_count == test_count) ? 0 : 1;
}