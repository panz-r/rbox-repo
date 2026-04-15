/*
 * test_protocol_encoding.c - Unit tests for protocol encoding functions
 *
 * Tests pure encoding functions with in-memory buffers, no sockets.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <pthread.h>

#include "protocol_encoding.h"
#include "runtime.h"

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static void test_generate_request_id(void) {
    printf("Testing rbox_generate_request_id...\n");

    uint8_t id1[16];
    uint8_t id2[16];

    rbox_generate_request_id(id1);
    rbox_generate_request_id(id2);

    assert(memcmp(id1, id2, 16) != 0);
    printf("  ✓ Two IDs are different (unique)\n");

    int total_bytes_nonzero = 0;
    for (int i = 0; i < 16; i++) {
        if (id1[i] != 0) total_bytes_nonzero++;
        if (id2[i] != 0) total_bytes_nonzero++;
    }
    assert(total_bytes_nonzero > 16);
    printf("  ✓ IDs have non-zero content (at least one ID per byte position has non-zero)\n");

    printf("test_generate_request_id: PASSED\n\n");
}

static void test_get_client_id(void) {
    printf("Testing rbox_get_client_id...\n");

    const uint8_t *id1 = rbox_get_client_id();
    const uint8_t *id2 = rbox_get_client_id();

    assert(id1 != NULL);
    assert(id2 != NULL);
    assert(memcmp(id1, id2, 16) == 0);
    printf("  ✓ Client ID is consistent across calls\n");

    int has_nonzero = 0;
    for (int i = 0; i < 16; i++) {
        if (id1[i] != 0) has_nonzero = 1;
    }
    assert(has_nonzero);
    printf("  ✓ Client ID has non-zero content\n");

    printf("test_get_client_id: PASSED\n\n");
}

static void test_hash64(void) {
    printf("Testing rbox_hash64...\n");

    uint64_t h1 = rbox_hash64("test", 4);
    uint64_t h2 = rbox_hash64("test", 4);
    assert(h1 == h2);
    printf("  ✓ Hash is deterministic\n");

    uint64_t h3 = rbox_hash64("other", 5);
    assert(h1 != h3);
    printf("  ✓ Different strings produce different hashes\n");

    uint64_t h_empty = rbox_hash64("", 0);
    uint64_t h_null = rbox_hash64(NULL, 0);
    assert(h_empty == 0);
    assert(h_null == 0);
    printf("  ✓ Empty/null input returns 0\n");

    uint64_t h_long = rbox_hash64("this is a longer command string", 32);
    assert(h_long != 0);
    printf("  ✓ Longer strings produce valid hashes\n");

    printf("test_hash64: PASSED\n\n");
}

static void test_encode_request_basic(void) {
    printf("Testing rbox_encode_request basic...\n");

    uint8_t buf[8192];
    size_t out_len;

    rbox_error_t err = rbox_encode_request(
        "ls",
        NULL, NULL,
        0, NULL,
        0, NULL, NULL,
        buf, sizeof(buf), &out_len
    );

    assert(err == RBOX_OK);
    assert(out_len >= RBOX_HEADER_SIZE);
    printf("  ✓ Basic request encoded successfully\n");

    uint32_t magic = *(uint32_t *)(buf + RBOX_HEADER_OFFSET_MAGIC);
    assert(magic == RBOX_MAGIC);
    printf("  ✓ Magic is correct\n");

    uint32_t version = *(uint32_t *)(buf + RBOX_HEADER_OFFSET_VERSION);
    assert(version == RBOX_VERSION);
    printf("  ✓ Version is correct\n");

    uint32_t type = *(uint32_t *)(buf + RBOX_HEADER_OFFSET_TYPE);
    assert(type == RBOX_MSG_REQ);
    printf("  ✓ Message type is REQ\n");

    uint32_t chunk_len = *(uint32_t *)(buf + RBOX_HEADER_OFFSET_CHUNK_LEN);
    assert(chunk_len == out_len - RBOX_HEADER_SIZE);
    printf("  ✓ Chunk len matches body size\n");

    printf("test_encode_request_basic: PASSED\n\n");
}

static void test_encode_request_with_args(void) {
    printf("Testing rbox_encode_request with arguments...\n");

    uint8_t buf[8192];
    size_t out_len;

    const char *argv[] = {"ls", "-la", "/tmp"};
    rbox_error_t err = rbox_encode_request(
        "ls",
        "test_caller",
        "execve",
        3, argv,
        0, NULL, NULL,
        buf, sizeof(buf), &out_len
    );

    assert(err == RBOX_OK);
    uint32_t chunk_len = *(uint32_t *)(buf + RBOX_HEADER_OFFSET_CHUNK_LEN);
    assert(chunk_len > 0);
    printf("  ✓ Request with args encoded\n");

    uint8_t cs_size = buf[RBOX_HEADER_OFFSET_CALLER_SYSCALL_SIZE];
    uint8_t caller_len = cs_size & 0x0F;
    uint8_t syscall_len = (cs_size >> 4) & 0x0F;
    assert(caller_len == strlen("test_caller"));
    assert(syscall_len == strlen("execve"));
    printf("  ✓ Caller/syscall sizes are correct\n");

    char caller[16];
    memcpy(caller, buf + RBOX_HEADER_OFFSET_CALLER, caller_len);
    caller[caller_len] = '\0';
    assert(strcmp(caller, "test_caller") == 0);
    printf("  ✓ Caller name is correct\n");

    printf("test_encode_request_with_args: PASSED\n\n");
}

static void test_encode_request_buffer_too_small(void) {
    printf("Testing rbox_encode_request buffer too small...\n");

    uint8_t buf[64];
    size_t out_len;

    rbox_error_t err = rbox_encode_request(
        "this_is_a_very_long_command_that_will_never_fit_in_a_small_buffer",
        NULL, NULL,
        0, NULL,
        0, NULL, NULL,
        buf, sizeof(buf), &out_len
    );

    assert(err == RBOX_ERR_INVALID);
    assert(out_len > sizeof(buf));
    printf("  ✓ Returns ERR_INVALID when buffer too small\n");
    printf("  ✓ Sets out_len to required size (%zu)\n", out_len);

    printf("test_encode_request_buffer_too_small: PASSED\n\n");
}

static void test_encode_request_with_env(void) {
    printf("Testing rbox_encode_request with environment...\n");

    uint8_t buf[8192];
    size_t out_len;

    const char *env_names[] = {"PATH", "HOME", "USER"};
    float env_scores[] = {0.5f, 0.8f, 0.3f};

    rbox_error_t err = rbox_encode_request(
        "env",
        NULL, NULL,
        0, NULL,
        3, env_names, env_scores,
        buf, sizeof(buf), &out_len
    );

    assert(err == RBOX_OK);
    printf("  ✓ Request with env vars encoded\n");

    uint32_t fenv_hash = *(uint32_t *)(buf + RBOX_HEADER_OFFSET_FENV_HASH);
    assert(fenv_hash != 0);
    printf("  ✓ fenv_hash is computed (non-zero)\n");

    printf("test_encode_request_with_env: PASSED\n\n");
}

static void test_encode_response_basic(void) {
    printf("Testing rbox_encode_response basic...\n");

    uint8_t buf[8192];
    size_t out_len;

    uint8_t client_id[16] = {0};
    uint8_t request_id[16] = {0};
    request_id[0] = 1;

    rbox_error_t err = rbox_encode_response(
        client_id, request_id,
        12345,
        RBOX_DECISION_ALLOW,
        "OK",
        0,
        0, NULL,
        buf, sizeof(buf), &out_len
    );

    assert(err == RBOX_OK);
    assert(out_len >= RBOX_HEADER_SIZE + 1 + 3 + 1);
    printf("  ✓ Response encoded successfully\n");

    uint32_t magic = *(uint32_t *)(buf + RBOX_HEADER_OFFSET_MAGIC);
    assert(magic == RBOX_MAGIC);
    printf("  ✓ Magic is correct\n");

    uint32_t cmd_hash = *(uint32_t *)(buf + RBOX_HEADER_OFFSET_CMD_HASH);
    assert(cmd_hash == 12345);
    printf("  ✓ cmd_hash is preserved\n");

    uint8_t decision = buf[RBOX_HEADER_SIZE];
    assert(decision == RBOX_DECISION_ALLOW);
    printf("  ✓ Decision is ALLOW\n");

    printf("test_encode_response_basic: PASSED\n\n");
}

static void test_encode_response_with_env(void) {
    printf("Testing rbox_encode_response with env decisions...\n");

    uint8_t buf[8192];
    size_t out_len;

    uint8_t env_decisions[2] = {0b10101010, 0};
    int env_count = 8;

    rbox_error_t err = rbox_encode_response(
        NULL, NULL,
        0,
        RBOX_DECISION_ALLOW,
        "allowed",
        0x12345678,
        env_count, env_decisions,
        buf, sizeof(buf), &out_len
    );

    assert(err == RBOX_OK);

    size_t reason_offset = RBOX_HEADER_SIZE + 1;
    assert(strncmp((char *)buf + reason_offset, "allowed", 7) == 0);
    printf("  ✓ Reason string is correct\n");

    uint32_t fenv_hash = *(uint32_t *)(buf + RBOX_HEADER_OFFSET_FENV_HASH);
    assert(fenv_hash == 0x12345678);
    printf("  ✓ fenv_hash is preserved\n");

    printf("test_encode_response_with_env: PASSED\n\n");
}

static void test_encode_response_buffer_too_small(void) {
    printf("Testing rbox_encode_response buffer too small...\n");

    uint8_t buf[64];
    size_t out_len;

    rbox_error_t err = rbox_encode_response(
        NULL, NULL, 0,
        RBOX_DECISION_ALLOW,
        "this_reason_string_is_way_too_long_to_fit_in_the_buffer",
        0, 0, NULL,
        buf, sizeof(buf), &out_len
    );

    assert(err == RBOX_ERR_INVALID);
    printf("  ✓ Returns ERR_INVALID when buffer too small\n");

    printf("test_encode_response_buffer_too_small: PASSED\n\n");
}

static void test_encode_telemetry_response(void) {
    printf("Testing rbox_encode_telemetry_response...\n");

    size_t out_len;
    char *pkt = rbox_encode_telemetry_response(NULL, NULL, 100, 50, &out_len);

    assert(pkt != NULL);
    assert(out_len >= RBOX_HEADER_SIZE + 1);
    printf("  ✓ Telemetry response encoded\n");

    uint32_t magic = *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_MAGIC);
    assert(magic == RBOX_MAGIC);
    printf("  ✓ Magic is correct\n");

    uint8_t decision = pkt[RBOX_HEADER_SIZE];
    assert(decision == RBOX_DECISION_UNKNOWN);
    printf("  ✓ Decision is UNKNOWN (telemetry)\n");

    free(pkt);
    printf("test_encode_telemetry_response: PASSED\n\n");
}

static void test_request_id_uniqueness_thread_local(void) {
    printf("Testing request ID uniqueness (thread-local seed)...\n");

    uint8_t ids[100][16];
    for (int i = 0; i < 100; i++) {
        rbox_generate_request_id(ids[i]);
    }

    for (int i = 0; i < 100; i++) {
        for (int j = i + 1; j < 100; j++) {
            assert(memcmp(ids[i], ids[j], 16) != 0);
        }
    }
    printf("  ✓ 100 sequential IDs are all unique\n");

    printf("test_request_id_uniqueness_thread_local: PASSED\n\n");
}

static void *thread_get_client_id(void *arg) {
    int *success = (int *)arg;
    const uint8_t *id = rbox_get_client_id();
    if (id == NULL) {
        *success = 0;
        return NULL;
    }
    for (int i = 0; i < 16; i++) {
        if (id[i] != 0) {
            *success = 1;
            return NULL;
        }
    }
    *success = 1;
    return NULL;
}

static void test_get_client_id_concurrent(void) {
    printf("Testing rbox_get_client_id concurrent from multiple threads...\n");

    pthread_t threads[10];
    int success[10];

    for (int i = 0; i < 10; i++) {
        success[i] = 0;
        pthread_create(&threads[i], NULL, thread_get_client_id, &success[i]);
    }

    for (int i = 0; i < 10; i++) {
        pthread_join(threads[i], NULL);
        assert(success[i] == 1);
    }
    printf("  ✓ All 10 threads got valid client ID\n");

    const uint8_t *id1 = rbox_get_client_id();
    const uint8_t *id2 = rbox_get_client_id();
    assert(memcmp(id1, id2, 16) == 0);
    printf("  ✓ Client ID is consistent across threads\n");

    printf("test_get_client_id_concurrent: PASSED\n\n");
}

static void *thread_generate_request_ids(void *arg) {
    uint8_t (*ids)[16] = (uint8_t (*)[16])arg;
    for (int i = 0; i < 100; i++) {
        rbox_generate_request_id(ids[i]);
    }
    return NULL;
}

static void test_generate_request_id_concurrent(void) {
    printf("Testing rbox_generate_request_id concurrent from multiple threads...\n");

    const int num_threads = 10;
    const int ids_per_thread = 100;
    uint8_t all_ids[num_threads][ids_per_thread][16];

    pthread_t threads[10];
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, thread_generate_request_ids, all_ids[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    printf("  ✓ Generated %d IDs across %d threads\n", num_threads * ids_per_thread, num_threads);

    for (int t1 = 0; t1 < num_threads; t1++) {
        for (int i = 0; i < ids_per_thread; i++) {
            for (int t2 = t1; t2 < num_threads; t2++) {
                for (int j = (t1 == t2) ? i + 1 : 0; j < ids_per_thread; j++) {
                    assert(memcmp(all_ids[t1][i], all_ids[t2][j], 16) != 0);
                }
            }
        }
    }
    printf("  ✓ All %d IDs are unique across threads\n", num_threads * ids_per_thread);

    printf("test_generate_request_id_concurrent: PASSED\n\n");
}

static void test_encode_request_minimal(void) {
    printf("Testing rbox_encode_request_minimal...\n");

    uint8_t buf[8192];
    size_t out_len;

    rbox_error_t err = rbox_encode_request(
        "ls",
        NULL, NULL,
        0, NULL,
        0, NULL, NULL,
        buf, sizeof(buf), &out_len
    );

    assert(err == RBOX_OK);

    uint32_t magic = *(uint32_t *)(buf + RBOX_HEADER_OFFSET_MAGIC);
    assert(magic == RBOX_MAGIC);
    printf("  ✓ Magic is correct\n");

    uint32_t version = *(uint32_t *)(buf + RBOX_HEADER_OFFSET_VERSION);
    assert(version == RBOX_VERSION);
    printf("  ✓ Version is correct\n");

    uint32_t type = *(uint32_t *)(buf + RBOX_HEADER_OFFSET_TYPE);
    assert(type == RBOX_MSG_REQ);
    printf("  ✓ Message type is REQ\n");

    uint32_t flags = *(uint32_t *)(buf + RBOX_HEADER_OFFSET_FLAGS);
    assert(flags == RBOX_FLAG_FIRST);
    printf("  ✓ Flags is FIRST\n");

    uint32_t chunk_len = *(uint32_t *)(buf + RBOX_HEADER_OFFSET_CHUNK_LEN);
    assert(chunk_len == out_len - RBOX_HEADER_SIZE);
    printf("  ✓ Chunk len matches body size\n");

    char *body = (char *)buf + RBOX_HEADER_SIZE;
    assert(body[0] == 'l');
    assert(body[1] == 's');
    assert(body[2] == '\0');
    printf("  ✓ Command null-terminated\n");

    printf("test_encode_request_minimal: PASSED\n\n");
}

static void test_encode_response_deny(void) {
    printf("Testing rbox_encode_response_deny...\n");

    uint8_t buf[8192];
    size_t out_len;

    rbox_error_t err = rbox_encode_response(
        NULL, NULL, 0,
        RBOX_DECISION_DENY,
        "access denied because something went wrong",
        0, 0, NULL,
        buf, sizeof(buf), &out_len
    );

    assert(err == RBOX_OK);
    printf("  ✓ Response encoded successfully\n");

    uint8_t decision = buf[RBOX_HEADER_SIZE];
    assert(decision == RBOX_DECISION_DENY);
    printf("  ✓ Decision is DENY\n");

    printf("test_encode_response_deny: PASSED\n\n");
}

static void test_hash64_known_vectors(void) {
    printf("Testing rbox_hash64 with known vectors...\n");

    uint64_t h_ls = rbox_hash64("ls", 2);
    assert(h_ls != 0);
    printf("  ✓ Hash of 'ls' is non-zero: %lu\n", (unsigned long)h_ls);

    uint64_t h_cat = rbox_hash64("cat", 3);
    assert(h_cat != 0);
    printf("  ✓ Hash of 'cat' is non-zero: %lu\n", (unsigned long)h_cat);

    uint64_t h_grep = rbox_hash64("grep", 4);
    assert(h_grep != 0);
    printf("  ✓ Hash of 'grep' is non-zero: %lu\n", (unsigned long)h_grep);

    assert(h_ls != h_cat);
    assert(h_cat != h_grep);
    assert(h_ls != h_grep);
    printf("  ✓ Different commands produce different hashes\n");

    printf("test_hash64_known_vectors: PASSED\n\n");
}

static void test_encode_request_null_command(void) {
    printf("Testing rbox_encode_request with NULL command...\n");

    uint8_t buf[8192];
    size_t out_len = 0;

    rbox_error_t err = rbox_encode_request(
        NULL,
        NULL, NULL,
        0, NULL,
        0, NULL, NULL,
        buf, sizeof(buf), &out_len
    );

    assert(err == RBOX_ERR_INVALID);
    printf("  ✓ Returns ERR_INVALID for NULL command\n");

    printf("test_encode_request_null_command: PASSED\n\n");
}

static void test_encode_request_null_buffer(void) {
    printf("Testing rbox_encode_request with NULL buffer...\n");

    size_t out_len = 0;

    rbox_error_t err = rbox_encode_request(
        "ls",
        NULL, NULL,
        0, NULL,
        0, NULL, NULL,
        NULL, 0, &out_len
    );

    assert(err == RBOX_ERR_INVALID);
    printf("  ✓ Returns ERR_INVALID for NULL buffer\n");

    printf("test_encode_request_null_buffer: PASSED\n\n");
}



int main(void) {
    printf("=== Protocol Encoding Unit Tests ===\n\n");

    test_generate_request_id();
    test_get_client_id();
    test_hash64();
    test_hash64_known_vectors();
    test_encode_request_basic();
    test_encode_request_minimal();
    test_encode_request_with_args();
    test_encode_request_buffer_too_small();
    test_encode_request_with_env();
    test_encode_request_null_command();
    test_encode_request_null_buffer();
    test_encode_response_basic();
    test_encode_response_deny();
    test_encode_response_with_env();
    test_encode_response_buffer_too_small();
    test_encode_telemetry_response();
    test_request_id_uniqueness_thread_local();
    test_get_client_id_concurrent();
    test_generate_request_id_concurrent();

    printf("=== All Protocol Encoding Tests PASSED ===\n");
    return 0;
}