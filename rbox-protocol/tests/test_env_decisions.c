/*
 * test_env_decisions.c - Tests for environment variable decisions
 * 
 * Tests:
 * 1. Basic env decision - server sends 3 env decisions, client verifies via bitmap
 * 2. All allow - all env decisions are ALLOW
 * 3. All deny - all env decisions are DENY
 * 4. Mixed decisions - some allow, some deny
 * 
 * Note: The current client implementation (rbox_blocking_request) does not decode
 * env decisions into rbox_response_t. These tests verify the server-side
 * rbox_server_decide accepts env decisions without error, and basic response
 * fields are correctly returned.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>

#include "rbox_protocol.h"
#include "test_common.h"

int g_pass_count = 0;
int g_test_count = 0;

typedef struct {
    const char *path;
    int env_decision_count;
    const char **env_decision_names;
    const uint8_t *env_decisions;
    rbox_server_handle_t *srv;
    pthread_mutex_t mutex;
    int server_ready;
} worker_ctx_t;

static void *server_worker_env_decisions(void *arg) {
    worker_ctx_t *ctx = arg;

    ctx->srv = rbox_server_handle_new(ctx->path);
    if (!ctx->srv) return NULL;

    rbox_server_handle_listen(ctx->srv);
    rbox_server_start(ctx->srv);

    pthread_mutex_lock(&ctx->mutex);
    ctx->server_ready = 1;
    pthread_mutex_unlock(&ctx->mutex);

    while (1) {
        rbox_server_request_t *req = rbox_server_get_request(ctx->srv);
        if (!req) break;
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0,
                          ctx->env_decision_count, ctx->env_decision_names, ctx->env_decisions);
    }

    rbox_server_handle_free(ctx->srv);
    return NULL;
}

/* Test basic env decision - server sends 3 env decisions */
static int test_basic_env_decisions(void) {
    const char *path = "/tmp/rbox_test_env_basic.sock";
    unlink(path);

    const char *env_names[] = {"PATH", "HOME", "USER"};
    uint8_t env_decisions[] = {0, 1, 0};  /* PATH=allow, HOME=deny, USER=allow */

    worker_ctx_t ctx = {
        .path = path,
        .env_decision_count = 3,
        .env_decision_names = env_names,
        .env_decisions = env_decisions,
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };

    pthread_t tid;
    if (pthread_create(&tid, NULL, server_worker_env_decisions, &ctx) != 0) return -1;
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        return -1;
    }

    const char *argv[] = {"ls", "-la"};
    rbox_response_t resp = {0};

    rbox_error_t err = rbox_blocking_request(path, "ls", 2, argv, "test", "execve",
                                             0, NULL, NULL, &resp, 100, 1);

    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    unlink(path);

    if (err != RBOX_OK) {
        TEST_ERROR("blocking_request failed: %d", err);
        return -1;
    }

    if (resp.decision != RBOX_DECISION_ALLOW) {
        TEST_ERROR("expected ALLOW decision, got %d", resp.decision);
        return -1;
    }

    /* Verify reason is "ok" */
    if (strcmp(resp.reason, "ok") != 0) {
        TEST_ERROR("expected reason 'ok', got '%s'", resp.reason);
        return -1;
    }

    /* Env decisions are sent by server but client doesn't decode them yet.
     * We verify the basic request/response works above. */
    return 0;
}

/* Test all allow - all env decisions are ALLOW */
static int test_all_allow(void) {
    const char *path = "/tmp/rbox_test_env_allow.sock";
    unlink(path);

    const char *env_names[] = {"A", "B", "C", "D"};
    uint8_t env_decisions[] = {0, 0, 0, 0};  /* all allow */

    worker_ctx_t ctx = {
        .path = path,
        .env_decision_count = 4,
        .env_decision_names = env_names,
        .env_decisions = env_decisions,
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };

    pthread_t tid;
    if (pthread_create(&tid, NULL, server_worker_env_decisions, &ctx) != 0) return -1;
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        return -1;
    }

    const char *argv[] = {"echo", "test"};
    rbox_response_t resp = {0};

    rbox_error_t err = rbox_blocking_request(path, "echo", 2, argv, "test", "execve",
                                             0, NULL, NULL, &resp, 100, 1);

    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    unlink(path);

    if (err != RBOX_OK) return -1;
    if (resp.decision != RBOX_DECISION_ALLOW) return -1;

    return 0;
}

/* Test all deny - all env decisions are DENY */
static int test_all_deny(void) {
    const char *path = "/tmp/rbox_test_env_deny.sock";
    unlink(path);

    const char *env_names[] = {"SECRET", "PASSWORD", "TOKEN"};
    uint8_t env_decisions[] = {1, 1, 1};  /* all deny */

    worker_ctx_t ctx = {
        .path = path,
        .env_decision_count = 3,
        .env_decision_names = env_names,
        .env_decisions = env_decisions,
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };

    pthread_t tid;
    if (pthread_create(&tid, NULL, server_worker_env_decisions, &ctx) != 0) return -1;
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        return -1;
    }

    const char *argv[] = {"curl", "-h"};
    rbox_response_t resp = {0};

    rbox_error_t err = rbox_blocking_request(path, "curl", 2, argv, "test", "execve",
                                             0, NULL, NULL, &resp, 100, 1);

    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    unlink(path);

    if (err != RBOX_OK) return -1;
    if (resp.decision != RBOX_DECISION_ALLOW) return -1;

    return 0;
}

/* Test mixed decisions - some allow, some deny */
static int test_mixed_decisions(void) {
    const char *path = "/tmp/rbox_test_env_mixed.sock";
    unlink(path);

    const char *env_names[] = {"SAFE_VAR", "DANGEROUS_VAR", "ANOTHER_SAFE", "SENSITIVE"};
    uint8_t env_decisions[] = {0, 1, 0, 1};  /* mixed */

    worker_ctx_t ctx = {
        .path = path,
        .env_decision_count = 4,
        .env_decision_names = env_names,
        .env_decisions = env_decisions,
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };

    pthread_t tid;
    if (pthread_create(&tid, NULL, server_worker_env_decisions, &ctx) != 0) return -1;
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        return -1;
    }

    const char *argv[] = {"env"};
    rbox_response_t resp = {0};

    rbox_error_t err = rbox_blocking_request(path, "env", 1, argv, "test", "execve",
                                             0, NULL, NULL, &resp, 100, 1);

    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    unlink(path);

    if (err != RBOX_OK) return -1;
    if (resp.decision != RBOX_DECISION_ALLOW) return -1;

    return 0;
}

/* Test zero env decisions - server sends no env decisions */
static int test_zero_env_decisions(void) {
    const char *path = "/tmp/rbox_test_env_zero.sock";
    unlink(path);

    worker_ctx_t ctx = {
        .path = path,
        .env_decision_count = 0,
        .env_decision_names = NULL,
        .env_decisions = NULL,
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };

    pthread_t tid;
    if (pthread_create(&tid, NULL, server_worker_env_decisions, &ctx) != 0) return -1;
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        return -1;
    }

    const char *argv[] = {"pwd"};
    rbox_response_t resp = {0};

    rbox_error_t err = rbox_blocking_request(path, "pwd", 1, argv, "test", "execve",
                                             0, NULL, NULL, &resp, 100, 1);

    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    unlink(path);

    if (err != RBOX_OK) return -1;
    if (resp.decision != RBOX_DECISION_ALLOW) return -1;

    return 0;
}

int main(void) {
    rbox_init();

    printf("=== Environment decision tests ===\n\n");
    fflush(stdout);

    RUN_TEST(test_basic_env_decisions, "basic env decision bitmap");
    RUN_TEST(test_all_allow, "all allow decisions");
    RUN_TEST(test_all_deny, "all deny decisions");
    RUN_TEST(test_mixed_decisions, "mixed decisions");
    RUN_TEST(test_zero_env_decisions, "zero env decisions");

    printf("\n=== Results: %d/%d tests passed ===\n", g_pass_count, g_test_count);
    fflush(stdout);

    unlink("/tmp/rbox_test_env_basic.sock");
    unlink("/tmp/rbox_test_env_allow.sock");
    unlink("/tmp/rbox_test_env_deny.sock");
    unlink("/tmp/rbox_test_env_mixed.sock");
    unlink("/tmp/rbox_test_env_zero.sock");

    return (g_pass_count == g_test_count) ? 0 : 1;
}