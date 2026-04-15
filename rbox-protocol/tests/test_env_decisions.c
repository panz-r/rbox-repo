/*
 * test_env_decisions.c - Tests for environment variable decisions
 *
 * Tests client-side decoding of env decisions from server response.
 * Server decides: deny if (index % 3) == 1, allow otherwise.
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
#include "../src/error_internal.h"
#include "test_common.h"

int g_pass_count = 0;
int g_test_count = 0;

typedef struct {
    const char *path;
    int env_decision_count;
    const uint8_t *env_decisions;
    rbox_server_handle_t *srv;
    pthread_mutex_t mutex;
    int server_ready;
} worker_ctx_t;

static void *server_worker_env_decisions(void *arg) {
    worker_ctx_t *ctx = arg;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    ctx->srv = rbox_server_handle_new(ctx->path, &err_info);
    if (!ctx->srv) return NULL;

    rbox_server_handle_listen(ctx->srv);
    rbox_server_start(ctx->srv);

    pthread_mutex_lock(&ctx->mutex);
    ctx->server_ready = 1;
    pthread_mutex_unlock(&ctx->mutex);

    while (1) {
        rbox_server_request_t *req = rbox_server_get_request(ctx->srv, &err_info);
        if (!req) break;
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0,
                          ctx->env_decision_count, ctx->env_decisions);
    }

    return NULL;
}

/* Helper: create env decision bitmap where deny if (index % 3) == 1 */
static uint8_t *make_env_decisions(int count) {
    size_t bitmap_size = (count + 7) / 8;
    uint8_t *bitmap = calloc(bitmap_size, 1);
    for (int i = 0; i < count; i++) {
        if ((i % 3 == 1)) {  /* deny every 3rd */
            bitmap[i / 8] |= (1 << (i % 8));
        }
    }
    return bitmap;
}

/* Helper: create env var names array (for client requests) */
static const char **make_env_names(int count) {
    const char **names = malloc(count * sizeof(char *));
    for (int i = 0; i < count; i++) {
        char *name = malloc(32);
        snprintf(name, 32, "VAR%d", i);
        names[i] = name;
    }
    return names;
}

/* Helper: free env names array */
static void free_env_names(const char **names, int count) {
    for (int i = 0; i < count; i++) {
        free((char *)names[i]);
    }
    free(names);
}

/* Test with 1 env var (no denials since 0%3!=1) */
static int test_env_1_var(void) {
    const char *path = "/tmp/rbox_test_env_1.sock";
    unlink(path);
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    int env_count = 1;
    const char *env_names[] = {"KEY1"};
    uint8_t *env_decisions = make_env_decisions(env_count);

    worker_ctx_t ctx = {
        .path = path,
        .env_decision_count = env_count,
        .env_decisions = env_decisions,
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };

    pthread_t tid;
    if (pthread_create(&tid, NULL, server_worker_env_decisions, &ctx) != 0) {
        free(env_decisions);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        free(env_decisions);
        return -1;
    }

    const char *argv[] = {"ls"};
    rbox_response_t resp = {0};

    rbox_error_t err = rbox_blocking_request(path, "ls", 1, argv, "test", "execve",
                                             env_count, env_names, (float[]){0.5},
                                             &resp, 100, 1, &err_info);

    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    rbox_server_handle_free(ctx.srv);
    unlink(path);

    free(env_decisions);

    if (err != RBOX_OK) {
        TEST_ERROR("blocking_request failed: %d", err);
        return -1;
    }

    if (resp.decision != RBOX_DECISION_ALLOW) {
        TEST_ERROR("expected ALLOW, got %d", resp.decision);
        rbox_response_free(&resp);
        return -1;
    }

    /* Verify env decision count */
    if (rbox_response_env_decision_count(&resp) != env_count) {
        TEST_ERROR("expected %d env decisions, got %d", env_count, rbox_response_env_decision_count(&resp));
        rbox_response_free(&resp);
        return -1;
    }

    /* Verify: index 0 should be allow (0%3!=1) */
    if (rbox_response_env_decision(&resp, 0) != 0) {
        TEST_ERROR("index 0 should be allow (0), got %d", rbox_response_env_decision(&resp, 0));
        rbox_response_free(&resp);
        return -1;
    }

    rbox_response_free(&resp);
    return 0;
}

/* Test with 3 env vars (index 1 denied) */
static int test_env_3_vars(void) {
    const char *path = "/tmp/rbox_test_env_3.sock";
    unlink(path);
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    int env_count = 3;
    const char *env_names[] = {"KEY1", "KEY2", "KEY3"};
    uint8_t *env_decisions = make_env_decisions(env_count);

    worker_ctx_t ctx = {
        .path = path,
        .env_decision_count = env_count,
        .env_decisions = env_decisions,
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };

    pthread_t tid;
    if (pthread_create(&tid, NULL, server_worker_env_decisions, &ctx) != 0) {
        free(env_decisions);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        free(env_decisions);
        return -1;
    }

    const char *argv[] = {"ls"};
    float scores[] = {0.5f, 0.6f, 0.7f};
    rbox_response_t resp = {0};

    rbox_error_t err = rbox_blocking_request(path, "ls", 1, argv, "test", "execve",
                                             env_count, env_names, scores,
                                             &resp, 100, 1, &err_info);

    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    rbox_server_handle_free(ctx.srv);
    unlink(path);

    free(env_decisions);

    if (err != RBOX_OK) {
        TEST_ERROR("blocking_request failed: %d", err);
        return -1;
    }

    if (resp.decision != RBOX_DECISION_ALLOW) {
        TEST_ERROR("expected ALLOW, got %d", resp.decision);
        rbox_response_free(&resp);
        return -1;
    }

    /* Verify env decision count */
    if (rbox_response_env_decision_count(&resp) != env_count) {
        TEST_ERROR("expected %d env decisions, got %d", env_count, rbox_response_env_decision_count(&resp));
        rbox_response_free(&resp);
        return -1;
    }

    /* Verify each decision: deny if (index % 3) == 1 */
    for (int i = 0; i < env_count; i++) {
        int expected = (i % 3 == 1) ? 1 : 0;
        if (rbox_response_env_decision(&resp, i) != expected) {
            TEST_ERROR("index %d: expected %d, got %d", i, expected, rbox_response_env_decision(&resp, i));
            rbox_response_free(&resp);
            return -1;
        }
    }

    rbox_response_free(&resp);
    return 0;
}

/* Test with 5 env vars (indices 1 and 4 denied) */
static int test_env_5_vars(void) {
    const char *path = "/tmp/rbox_test_env_5.sock";
    unlink(path);
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    int env_count = 5;
    const char *env_names[] = {"KEY1", "KEY2", "KEY3", "KEY4", "KEY5"};
    uint8_t *env_decisions = make_env_decisions(env_count);

    worker_ctx_t ctx = {
        .path = path,
        .env_decision_count = env_count,
        .env_decisions = env_decisions,
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };

    pthread_t tid;
    if (pthread_create(&tid, NULL, server_worker_env_decisions, &ctx) != 0) {
        free(env_decisions);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        free(env_decisions);
        return -1;
    }

    const char *argv[] = {"ls"};
    float scores[] = {0.5f, 0.6f, 0.7f, 0.8f, 0.9f};
    rbox_response_t resp = {0};

    rbox_error_t err = rbox_blocking_request(path, "ls", 1, argv, "test", "execve",
                                             env_count, env_names, scores,
                                             &resp, 100, 1, &err_info);

    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    rbox_server_handle_free(ctx.srv);
    unlink(path);

    free(env_decisions);

    if (err != RBOX_OK) {
        TEST_ERROR("blocking_request failed: %d", err);
        return -1;
    }

    if (resp.decision != RBOX_DECISION_ALLOW) {
        TEST_ERROR("expected ALLOW, got %d", resp.decision);
        rbox_response_free(&resp);
        return -1;
    }

    /* Verify env decision count */
    if (rbox_response_env_decision_count(&resp) != env_count) {
        TEST_ERROR("expected %d env decisions, got %d", env_count, rbox_response_env_decision_count(&resp));
        rbox_response_free(&resp);
        return -1;
    }

    /* Verify each decision */
    for (int i = 0; i < env_count; i++) {
        int expected = (i % 3 == 1) ? 1 : 0;
        if (rbox_response_env_decision(&resp, i) != expected) {
            TEST_ERROR("index %d: expected %d, got %d", i, expected, rbox_response_env_decision(&resp, i));
            rbox_response_free(&resp);
            return -1;
        }
    }

    rbox_response_free(&resp);
    return 0;
}

/* Test with 95 env vars (near max) */
static int test_env_95_vars(void) {
    const char *path = "/tmp/rbox_test_env_95.sock";
    unlink(path);
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    int env_count = 95;
    const char **env_names = make_env_names(env_count);
    uint8_t *env_decisions = make_env_decisions(env_count);

    worker_ctx_t ctx = {
        .path = path,
        .env_decision_count = env_count,
        .env_decisions = env_decisions,
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };

    pthread_t tid;
    if (pthread_create(&tid, NULL, server_worker_env_decisions, &ctx) != 0) {
        free(env_decisions);
        free_env_names(env_names, env_count);
        return -1;
    }
    if (wait_for_server(path, 2000) != 0) {
        pthread_join(tid, NULL);
        free(env_decisions);
        free_env_names(env_names, env_count);
        return -1;
    }

    /* Build scores array */
    float *scores = malloc(env_count * sizeof(float));
    for (int i = 0; i < env_count; i++) {
        scores[i] = 0.5f + (i * 0.005f);
    }

    const char *argv[] = {"ls"};
    rbox_response_t resp = {0};

    rbox_error_t err = rbox_blocking_request(path, "ls", 1, argv, "test", "execve",
                                             env_count, env_names, scores,
                                             &resp, 100, 1, &err_info);

    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    rbox_server_handle_free(ctx.srv);
    unlink(path);

    free(scores);
    free(env_decisions);
    free_env_names(env_names, env_count);

    if (err != RBOX_OK) {
        TEST_ERROR("blocking_request failed: %d", err);
        return -1;
    }

    if (resp.decision != RBOX_DECISION_ALLOW) {
        TEST_ERROR("expected ALLOW, got %d", resp.decision);
        rbox_response_free(&resp);
        return -1;
    }

    /* Verify env decision count */
    if (rbox_response_env_decision_count(&resp) != env_count) {
        TEST_ERROR("expected %d env decisions, got %d", env_count, rbox_response_env_decision_count(&resp));
        rbox_response_free(&resp);
        return -1;
    }

    /* Sample verification: check first, middle, and last indices */
    int check_indices[] = {0, 1, 2, 47, 48, 94};
    int num_checks = sizeof(check_indices) / sizeof(check_indices[0]);
    for (int c = 0; c < num_checks; c++) {
        int i = check_indices[c];
        int expected = (i % 3 == 1) ? 1 : 0;
        if (rbox_response_env_decision(&resp, i) != expected) {
            TEST_ERROR("index %d: expected %d, got %d", i, expected, rbox_response_env_decision(&resp, i));
            rbox_response_free(&resp);
            return -1;
        }
    }

    rbox_response_free(&resp);
    return 0;
}

/* Test zero env decisions */
static int test_zero_env_decisions(void) {
    const char *path = "/tmp/rbox_test_env_zero.sock";
    unlink(path);
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    worker_ctx_t ctx = {
        .path = path,
        .env_decision_count = 0,
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
                                             0, NULL, NULL,
                                             &resp, 100, 1, &err_info);

    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    rbox_server_handle_free(ctx.srv);
    unlink(path);

    if (err != RBOX_OK) return -1;
    if (resp.decision != RBOX_DECISION_ALLOW) return -1;
    if (rbox_response_env_decision_count(&resp) != 0) {
        TEST_ERROR("expected 0 env decisions, got %d", rbox_response_env_decision_count(&resp));
        rbox_response_free(&resp);
        return -1;
    }

    rbox_response_free(&resp);
    return 0;
}

int main(void) {
    rbox_init();

    printf("=== Environment decision tests ===\n\n");
    fflush(stdout);

    RUN_TEST(test_env_1_var, "1 env var");
    RUN_TEST(test_env_3_vars, "3 env vars");
    RUN_TEST(test_env_5_vars, "5 env vars");
    RUN_TEST(test_env_95_vars, "95 env vars");
    RUN_TEST(test_zero_env_decisions, "zero env decisions");

    printf("\n=== Results: %d/%d tests passed ===\n", g_pass_count, g_test_count);
    fflush(stdout);

    unlink("/tmp/rbox_test_env_1.sock");
    unlink("/tmp/rbox_test_env_3.sock");
    unlink("/tmp/rbox_test_env_5.sock");
    unlink("/tmp/rbox_test_env_95.sock");
    unlink("/tmp/rbox_test_env_zero.sock");

    return (g_pass_count == g_test_count) ? 0 : 1;
}
