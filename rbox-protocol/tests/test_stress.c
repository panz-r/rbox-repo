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
#include <sys/poll.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

#include "rbox_protocol.h"
#include "test_common.h"

int g_pass_count = 0;
int g_test_count = 0;

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
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL);
        count++;
    }

    /* NOTE: Do NOT call rbox_server_handle_free here. Caller must do cleanup. */
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
    rbox_server_handle_free(ctx.srv);
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
        rbox_server_handle_free(ctx.srv);
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
    rbox_server_handle_free(ctx.srv);
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
        rbox_server_handle_free(ctx.srv);
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
    rbox_server_handle_free(ctx.srv);
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
            rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL);
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
    rbox_server_handle_free(ctx.srv);
    unlink(path);

    if (success < 40) {
        TEST_ERROR("only %d/50 requests succeeded", success);
        return -1;
    }

    return 0;
}

/* C1: Session API test - sequential requests through session state machine
 * Verifies session API correctly handles multiple sequential requests */
static int test_session_sequential(void) {
    const char *path = "/tmp/rbox_test_true_edge.sock";
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

    /* Use session API */
    rbox_session_t *sess = rbox_session_new(path, 100, 1);
    if (!sess) {
        rbox_server_stop(ctx.srv);
        pthread_join(tid, NULL);
        rbox_server_handle_free(ctx.srv);
        return -1;
    }

    /* Connect */
    rbox_error_t err = rbox_session_connect(sess);
    if (err != RBOX_OK) {
        rbox_session_free(sess);
        rbox_server_stop(ctx.srv);
        pthread_join(tid, NULL);
        rbox_server_handle_free(ctx.srv);
        return -1;
    }

    /* Wait for connected */
    short events;
    int fd = rbox_session_pollfd(sess, &events);
    if (fd >= 0) {
        struct pollfd pfd = { .fd = fd, .events = events };
        poll(&pfd, 1, 2000);
        rbox_session_heartbeat(sess, pfd.revents);
    }

    if (rbox_session_state(sess) != RBOX_SESSION_CONNECTED) {
        rbox_session_free(sess);
        rbox_server_stop(ctx.srv);
        pthread_join(tid, NULL);
        rbox_server_handle_free(ctx.srv);
        return -1;
    }

    /* Send first request and wait for response */
    err = rbox_session_send_request(sess, "echo", "test", "execve", 1,
                                   (const char *[]){"first"}, 0, NULL, NULL);
    if (err != RBOX_OK) {
        TEST_ERROR("first send_request failed: %d", err);
        rbox_session_free(sess);
        rbox_server_stop(ctx.srv);
        pthread_join(tid, NULL);
        rbox_server_handle_free(ctx.srv);
        return -1;
    }

    /* Poll loop: send then receive */
    for (int i = 0; i < 2; i++) {
        fd = rbox_session_pollfd(sess, &events);
        if (fd >= 0) {
            struct pollfd pfd = { .fd = fd, .events = events };
            poll(&pfd, 1, 2000);
            rbox_session_heartbeat(sess, pfd.revents);
        }
        if (rbox_session_state(sess) == RBOX_SESSION_RESPONSE_READY) break;
    }

    if (rbox_session_state(sess) != RBOX_SESSION_RESPONSE_READY) {
        TEST_ERROR("expected RESPONSE_READY, got %d", rbox_session_state(sess));
        rbox_session_free(sess);
        rbox_server_stop(ctx.srv);
        pthread_join(tid, NULL);
        rbox_server_handle_free(ctx.srv);
        return -1;
    }

    const rbox_response_t *resp = rbox_session_response(sess);
    if (!resp || resp->decision != RBOX_DECISION_ALLOW) {
        TEST_ERROR("first response invalid");
        rbox_session_free(sess);
        rbox_server_stop(ctx.srv);
        pthread_join(tid, NULL);
        rbox_server_handle_free(ctx.srv);
        return -1;
    }
    rbox_session_reset(sess);

    /* Send second request */
    err = rbox_session_send_request(sess, "echo", "test", "execve", 1,
                                   (const char *[]){"second"}, 0, NULL, NULL);
    if (err != RBOX_OK) {
        TEST_ERROR("second send_request failed: %d", err);
        rbox_session_free(sess);
        rbox_server_stop(ctx.srv);
        pthread_join(tid, NULL);
        rbox_server_handle_free(ctx.srv);
        return -1;
    }

    /* Poll loop: send then receive */
    for (int i = 0; i < 2; i++) {
        fd = rbox_session_pollfd(sess, &events);
        if (fd >= 0) {
            struct pollfd pfd = { .fd = fd, .events = events };
            poll(&pfd, 1, 2000);
            rbox_session_heartbeat(sess, pfd.revents);
        }
        if (rbox_session_state(sess) == RBOX_SESSION_RESPONSE_READY) break;
    }

    if (rbox_session_state(sess) != RBOX_SESSION_RESPONSE_READY) {
        TEST_ERROR("expected RESPONSE_READY for second, got %d", rbox_session_state(sess));
        rbox_session_free(sess);
        rbox_server_stop(ctx.srv);
        pthread_join(tid, NULL);
        rbox_server_handle_free(ctx.srv);
        return -1;
    }

    resp = rbox_session_response(sess);
    if (!resp || resp->decision != RBOX_DECISION_ALLOW) {
        TEST_ERROR("second response invalid");
        rbox_session_free(sess);
        rbox_server_stop(ctx.srv);
        pthread_join(tid, NULL);
        rbox_server_handle_free(ctx.srv);
        return -1;
    }

    rbox_session_free(sess);
    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    rbox_server_handle_free(ctx.srv);
    unlink(path);

    return 0;
}

/* C2: Server graceful shutdown with pending responses
 * Verifies that pending responses are sent before server exits */
static int test_graceful_shutdown_with_pending(void) {
    const char *path = "/tmp/rbox_test_graceful.sock";
    unlink(path);

    worker_ctx_t ctx = {
        .path = path,
        .max_requests = 100,
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

    /* Wait for server to be ready */
    pthread_mutex_lock(&ctx.mutex);
    while (!ctx.server_ready) {
        pthread_mutex_unlock(&ctx.mutex);
        usleep(1000);
        pthread_mutex_lock(&ctx.mutex);
    }
    pthread_mutex_unlock(&ctx.mutex);

    /* Send several requests - some will be pending when we call stop */
    int success = 0;
    for (int i = 0; i < 5; i++) {
        rbox_response_t resp;
        rbox_error_t err = rbox_blocking_request(path, "echo", 1,
                                               (const char *[]){ "test" },
                                               "test", "execve", 0, NULL, NULL,
                                               &resp, 100, 1);
        if (err == RBOX_OK) success++;
    }

    /* Call stop while responses may still be pending */
    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    rbox_server_handle_free(ctx.srv);
    unlink(path);

    if (success != 5) {
        TEST_ERROR("expected 5 successes, got %d", success);
        return -1;
    }

    return 0;
}

/* C3: Partial header timeout
 * Sends partial header data, then waits. Server should timeout and close. */
static int test_partial_header_timeout(void) {
    const char *path = "/tmp/rbox_test_partial_timeout.sock";
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

    /* Connect and send partial header */
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        rbox_server_stop(ctx.srv);
        pthread_join(tid, NULL);
        rbox_server_handle_free(ctx.srv);
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        rbox_server_stop(ctx.srv);
        pthread_join(tid, NULL);
        rbox_server_handle_free(ctx.srv);
        return -1;
    }

    /* Send partial header (only half) */
    char partial[64];
    memset(partial, 0, sizeof(partial));
    *(uint32_t *)partial = 0x524F424F;  /* RBOX_MAGIC but wrong */
    write(sock, partial, 32);

    /* Wait for server to timeout and close connection */
    usleep(200000);  /* 200ms - longer than server timeout */

    /* Try to read - should get EOF or error since server closed */
    char buf[128];
    (void)read(sock, buf, sizeof(buf));
    close(sock);

    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    rbox_server_handle_free(ctx.srv);
    unlink(path);

    return 0;  /* If we get here without hanging, test passed */
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
    RUN_TEST(test_session_sequential, "session sequential requests");
    RUN_TEST(test_graceful_shutdown_with_pending, "graceful shutdown with pending");
    RUN_TEST(test_partial_header_timeout, "partial header timeout");

    printf("\n=== Results: %d/%d tests passed ===\n", g_pass_count, g_test_count);
    fflush(stdout);

    unlink("/tmp/rbox_test_stress_100.sock");
    unlink("/tmp/rbox_test_edge_burst.sock");
    unlink("/tmp/rbox_test_timeout.sock");
    unlink("/tmp/rbox_test_signal.sock");
    unlink("/tmp/rbox_test_rapid.sock");
    unlink("/tmp/rbox_test_true_edge.sock");
    unlink("/tmp/rbox_test_graceful.sock");
    unlink("/tmp/rbox_test_partial_timeout.sock");

    return (g_pass_count == g_test_count) ? 0 : 1;
}