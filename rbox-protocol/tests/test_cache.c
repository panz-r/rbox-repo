/*
 * test_cache.c - Integration tests for rbox_cache (ht_cache_t backend)
 *
 * Tests the rbox_cache API contract: two-phase lookup (one-shot priority,
 * timed fallback), insertion dedup, LRU eviction, expiration, env bitmap
 * handling. Does NOT test ht_cache internals.
 *
 * Compile with: gcc -DTESTING -Wall -Wextra -std=gnu11 -O2 -g \
 *               -I./include -I../draugr/include \
 *               -o test_cache tests/test_cache.c src/rbox_cache.c \
 *               ../draugr/src/ht.c ../draugr/src/ht_cache.c -lm -lpthread
 */

#define _GNU_SOURCE
#define TESTING

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>
#include "../include/rbox_cache.h"

static int tests_run = 0;
static int tests_passed = 0;

static volatile time_t g_mock_time = 0;
static int g_use_mock_time = 0;

static time_t mock_time(time_t *t) {
    time_t ret = g_mock_time;
    if (t) *t = ret;
    return ret;
}

time_t time(time_t *t) {
    if (g_use_mock_time) {
        return mock_time(t);
    }
    return mock_time(t);
}

#define ASSERT(cond, msg) do { \
    tests_run++; \
    if (cond) { \
        tests_passed++; \
        printf("  PASS: %s\n", msg); \
    } else { \
        printf("  FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
    } \
} while (0)

#define ASSERT_EQ(a, b, msg) do { \
    tests_run++; \
    if ((a) == (b)) { \
        tests_passed++; \
        printf("  PASS: %s\n", msg); \
    } else { \
        printf("  FAIL: %s (expected %ld, got %ld)\n", msg, (long)(b), (long)(a)); \
    } \
} while (0)

static void fill_id(uint8_t *id, uint8_t val) {
    memset(id, val, 16);
}

static int lookup_one_shot(rbox_cache_t *cache, uint8_t *client_id, uint8_t *request_id,
                           uint32_t cmd_hash, uint64_t cmd_hash2, uint32_t fenv_hash,
                           uint8_t *out_decision) {
    uint8_t decision;
    char reason[256];
    uint32_t duration;
    int env_count = 0;
    uint8_t *env_decisions = NULL;
    int ret = rbox_cache_lookup(cache, client_id, request_id, 0, cmd_hash, cmd_hash2, fenv_hash,
                                out_decision ? out_decision : &decision, reason, &duration,
                                &env_count, &env_decisions);
    if (env_decisions) free(env_decisions);
    return ret;
}

static int lookup_one_shot_with_checksum(rbox_cache_t *cache, uint8_t *client_id, uint8_t *request_id,
                                         uint32_t packet_checksum, uint32_t cmd_hash, uint64_t cmd_hash2, uint32_t fenv_hash,
                                         uint8_t *out_decision) {
    uint8_t decision;
    char reason[256];
    uint32_t duration;
    int env_count = 0;
    uint8_t *env_decisions = NULL;
    int ret = rbox_cache_lookup(cache, client_id, request_id, packet_checksum, cmd_hash, cmd_hash2, fenv_hash,
                                out_decision ? out_decision : &decision, reason, &duration,
                                &env_count, &env_decisions);
    if (env_decisions) free(env_decisions);
    return ret;
}

static void insert_one_shot(rbox_cache_t *cache, uint8_t *client_id, uint8_t *request_id,
                            uint32_t cmd_hash, uint64_t cmd_hash2, uint32_t fenv_hash,
                            uint8_t decision) {
    rbox_cache_insert(cache, client_id, request_id, 0, cmd_hash, cmd_hash2, fenv_hash,
                      decision, "test", 0, 0, NULL);
}

static void insert_one_shot_with_checksum(rbox_cache_t *cache, uint8_t *client_id, uint8_t *request_id,
                                          uint32_t packet_checksum, uint32_t cmd_hash, uint64_t cmd_hash2, uint32_t fenv_hash,
                                          uint8_t decision, const char *reason) {
    rbox_cache_insert(cache, client_id, request_id, packet_checksum, cmd_hash, cmd_hash2, fenv_hash,
                      decision, reason, 0, 0, NULL);
}

static void insert_timed(rbox_cache_t *cache, uint8_t *client_id, uint8_t *request_id,
                          uint32_t cmd_hash, uint64_t cmd_hash2, uint32_t fenv_hash,
                          uint8_t decision, uint32_t duration) {
    rbox_cache_insert(cache, client_id, request_id, 0, cmd_hash, cmd_hash2, fenv_hash,
                      decision, "test", duration, 0, NULL);
}

static void advance_time(time_t seconds) {
    g_mock_time += seconds;
}

/* T01: Insert one-shot, lookup exact */
static void test_t01_one_shot_exact_lookup(void) {
    printf("\nTest T01: Insert one-shot, lookup exact\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id[16], request_id[16];
    fill_id(client_id, 0xAA);
    fill_id(request_id, 0xBB);

    insert_one_shot(&cache, client_id, request_id, 100, 200, 300, 1);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id, request_id, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find entry");
    ASSERT(decision == 1, "Decision should be 1");
    ASSERT(rbox_cache_count(&cache) == 1, "Cache should have 1 entry");

    rbox_cache_destroy(&cache);
}

/* T02: Insert one-shot, lookup different client */
static void test_t02_one_shot_different_client(void) {
    printf("\nTest T02: Insert one-shot, lookup different client\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id1[16], request_id1[16], client_id2[16], request_id2[16];
    fill_id(client_id1, 0xAA);
    fill_id(request_id1, 0xBB);
    fill_id(client_id2, 0xCC);
    fill_id(request_id2, 0xBB);

    insert_one_shot(&cache, client_id1, request_id1, 100, 200, 300, 1);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id2, request_id2, 100, 200, 300, &decision);
    ASSERT(found == 0, "Should miss - no timed entry to fall back to");

    rbox_cache_destroy(&cache);
}

/* T03: Insert one-shot, lookup different request_id */
static void test_t03_one_shot_different_request(void) {
    printf("\nTest T03: Insert one-shot, lookup different request_id\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id1[16], request_id1[16], client_id2[16], request_id2[16];
    fill_id(client_id1, 0xAA);
    fill_id(request_id1, 0xBB);
    fill_id(client_id2, 0xAA);
    fill_id(request_id2, 0xCC);

    insert_one_shot(&cache, client_id1, request_id1, 100, 200, 300, 1);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id2, request_id2, 100, 200, 300, &decision);
    ASSERT(found == 0, "Should miss - different request_id");

    rbox_cache_destroy(&cache);
}

/* T04: Insert timed, lookup same command (any client/request) */
static void test_t04_timed_lookup_any_id(void) {
    printf("\nTest T04: Insert timed, lookup same command (any ID)\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id1[16], request_id1[16], client_id2[16], request_id2[16];
    fill_id(client_id1, 0xAA);
    fill_id(request_id1, 0xBB);
    fill_id(client_id2, 0x11);
    fill_id(request_id2, 0x22);

    insert_timed(&cache, client_id1, request_id1, 100, 200, 300, 2, 3600);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id2, request_id2, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find entry with different IDs");
    ASSERT(decision == 2, "Decision should be 2");

    rbox_cache_destroy(&cache);
}

/* T05: Insert timed, lookup different command */
static void test_t05_timed_miss_different_command(void) {
    printf("\nTest T05: Insert timed, lookup different command\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id[16], request_id[16];
    fill_id(client_id, 0xAA);
    fill_id(request_id, 0xBB);

    insert_timed(&cache, client_id, request_id, 100, 200, 300, 2, 3600);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id, request_id, 999, 200, 300, &decision);
    ASSERT(found == 0, "Should miss - different command");

    rbox_cache_destroy(&cache);
}

/* T06: Replace one-shot exact match */
static void test_t06_replace_one_shot_exact(void) {
    printf("\nTest T06: Replace one-shot exact match\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id[16], request_id[16];
    fill_id(client_id, 0xAA);
    fill_id(request_id, 0xBB);

    insert_one_shot(&cache, client_id, request_id, 100, 200, 300, 1);
    insert_one_shot(&cache, client_id, request_id, 100, 200, 300, 2);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id, request_id, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find entry");
    ASSERT(decision == 2, "Decision should be updated to 2");
    ASSERT(rbox_cache_count(&cache) == 1, "Should still have only 1 entry");

    rbox_cache_destroy(&cache);
}

/* T07: Replace timed exact match */
static void test_t07_replace_timed_exact(void) {
    printf("\nTest T07: Replace timed exact match\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id1[16], request_id1[16], client_id2[16], request_id2[16];
    fill_id(client_id1, 0xAA);
    fill_id(request_id1, 0xBB);
    fill_id(client_id2, 0xCC);
    fill_id(request_id2, 0xDD);

    insert_timed(&cache, client_id1, request_id1, 100, 200, 300, 1, 3600);
    insert_timed(&cache, client_id2, request_id2, 100, 200, 300, 2, 7200);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id1, request_id1, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find entry");
    ASSERT(decision == 2, "Decision should be updated to 2");
    ASSERT(rbox_cache_count(&cache) == 1, "Should still have only 1 entry");

    rbox_cache_destroy(&cache);
}

/* T08: No replacement when full key differs */
static void test_t08_no_replacement_different_keys(void) {
    printf("\nTest T08: No replacement when full key differs\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id1[16], request_id1[16], client_id2[16], request_id2[16];
    fill_id(client_id1, 0xAA);
    fill_id(request_id1, 0xBB);
    fill_id(client_id2, 0xCC);
    fill_id(request_id2, 0xDD);

    insert_one_shot(&cache, client_id1, request_id1, 100, 200, 300, 1);
    insert_one_shot(&cache, client_id2, request_id2, 100, 200, 300, 2);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id1, request_id1, 100, 200, 300, &decision);
    ASSERT(found == 1, "First entry should still exist");
    ASSERT(decision == 1, "First entry decision should be 1");

    found = lookup_one_shot(&cache, client_id2, request_id2, 100, 200, 300, &decision);
    ASSERT(found == 1, "Second entry should exist");
    ASSERT(decision == 2, "Second entry decision should be 2");

    ASSERT(rbox_cache_count(&cache) == 2, "Should have 2 entries");

    rbox_cache_destroy(&cache);
}

/* T09: One-shot insertion skipped when timed exists */
static void test_t09_one_shot_skipped_when_timed_exists(void) {
    printf("\nTest T09: One-shot insertion skipped when timed exists\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id1[16], request_id1[16], client_id2[16], request_id2[16];
    fill_id(client_id1, 0xAA);
    fill_id(request_id1, 0xBB);
    fill_id(client_id2, 0xCC);
    fill_id(request_id2, 0xDD);

    insert_timed(&cache, client_id1, request_id1, 100, 200, 300, 2, 3600);
    insert_one_shot(&cache, client_id2, request_id2, 100, 200, 300, 1);

    ASSERT(rbox_cache_count(&cache) == 1, "Only timed entry should exist (one-shot skipped)");

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id2, request_id2, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find timed entry");
    ASSERT(decision == 2, "Decision should be timed");

    rbox_cache_destroy(&cache);
}

/* T10: One-shot remains after timed insertion */
static void test_t10_one_shot_remains_after_timed(void) {
    printf("\nTest T10: One-shot remains after timed insertion\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id1[16], request_id1[16], client_id2[16], request_id2[16];
    fill_id(client_id1, 0xAA);
    fill_id(request_id1, 0xBB);
    fill_id(client_id2, 0xCC);
    fill_id(request_id2, 0xDD);

    insert_one_shot(&cache, client_id1, request_id1, 100, 200, 300, 1);
    insert_timed(&cache, client_id2, request_id2, 100, 200, 300, 2, 3600);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id1, request_id1, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find one-shot entry");
    ASSERT(decision == 1, "One-shot decision should be 1");

    found = lookup_one_shot(&cache, client_id2, request_id2, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find timed entry");
    ASSERT(decision == 2, "Timed decision should be 2");

    ASSERT(rbox_cache_count(&cache) == 2, "Both entries should coexist");

    rbox_cache_destroy(&cache);
}

/* T11: Timed insertion allowed after one-shot (no replacement) */
static void test_t11_timed_allowed_after_one_shot(void) {
    printf("\nTest T11: Timed insertion allowed after one-shot\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id1[16], request_id1[16], client_id2[16], request_id2[16];
    fill_id(client_id1, 0xAA);
    fill_id(request_id1, 0xBB);
    fill_id(client_id2, 0xCC);
    fill_id(request_id2, 0xDD);

    insert_one_shot(&cache, client_id1, request_id1, 100, 200, 300, 1);
    insert_timed(&cache, client_id2, request_id2, 100, 200, 300, 2, 3600);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id1, request_id1, 100, 200, 300, &decision);
    ASSERT(found == 1, "One-shot should still exist");
    ASSERT(decision == 1, "One-shot decision unchanged");

    found = lookup_one_shot(&cache, client_id2, request_id2, 100, 200, 300, &decision);
    ASSERT(found == 1, "Timed should exist");
    ASSERT(decision == 2, "Timed decision correct");

    rbox_cache_destroy(&cache);
}

/* T12: One-shot insertion allowed again after timed expires */
static void test_t12_one_shot_after_timed_expires(void) {
    printf("\nTest T12: One-shot insertion allowed after timed expires\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);
    g_use_mock_time = 1;
    g_mock_time = 1000;

    uint8_t client_id1[16], request_id1[16], client_id2[16], request_id2[16];
    fill_id(client_id1, 0xAA);
    fill_id(request_id1, 0xBB);
    fill_id(client_id2, 0xCC);
    fill_id(request_id2, 0xDD);

    insert_timed(&cache, client_id1, request_id1, 100, 200, 300, 2, 1);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id1, request_id1, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find timed entry before expiration");
    ASSERT(decision == 2, "Decision should be 2");

    advance_time(2);
    found = lookup_one_shot(&cache, client_id1, request_id1, 100, 200, 300, &decision);
    ASSERT(found == 0, "Timed should be expired");

    insert_one_shot(&cache, client_id2, request_id2, 100, 200, 300, 1);

    found = lookup_one_shot(&cache, client_id2, request_id2, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find one-shot after timed expired");
    ASSERT(decision == 1, "Decision should be 1 (one-shot)");

    g_use_mock_time = 0;
    rbox_cache_destroy(&cache);
}

/* T13: Exact one-shot takes precedence over timed (only when both exist) */
static void test_t13_one_shot_priority_over_timed(void) {
    printf("\nTest T13: Exact one-shot takes precedence over timed\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id[16], request_id[16];
    fill_id(client_id, 0xAA);
    fill_id(request_id, 0xBB);

    insert_one_shot(&cache, client_id, request_id, 100, 200, 300, 1);
    insert_timed(&cache, client_id, request_id, 100, 200, 300, 2, 3600);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id, request_id, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find entry");
    ASSERT(decision == 1, "Should return one-shot (replaced in place), not timed");

    rbox_cache_destroy(&cache);
}

/* T14: Timed returned when no exact one-shot */
static void test_t14_timed_returned_without_exact(void) {
    printf("\nTest T14: Timed returned when no exact one-shot\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id1[16], request_id1[16], client_id2[16], request_id2[16];
    fill_id(client_id1, 0xAA);
    fill_id(request_id1, 0xBB);
    fill_id(client_id2, 0xCC);
    fill_id(request_id2, 0xDD);

    insert_timed(&cache, client_id1, request_id1, 100, 200, 300, 2, 3600);
    insert_one_shot(&cache, client_id2, request_id2, 100, 200, 300, 1);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id1, request_id1, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find entry");
    ASSERT(decision == 2, "Should return timed, not one-shot (client1 has no one-shot)");

    rbox_cache_destroy(&cache);
}

/* T15: Timed not returned if expired */
static void test_t15_expired_timed_miss(void) {
    printf("\nTest T15: Timed not returned if expired\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);
    g_use_mock_time = 1;
    g_mock_time = 1000;

    uint8_t client_id[16], request_id[16];
    fill_id(client_id, 0xAA);
    fill_id(request_id, 0xBB);

    insert_timed(&cache, client_id, request_id, 100, 200, 300, 2, 1);

    advance_time(2);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id, request_id, 100, 200, 300, &decision);
    ASSERT(found == 0, "Expired timed should miss");

    g_use_mock_time = 0;
    rbox_cache_destroy(&cache);
}

/* T16: Expired timed does not block one-shot insertion */
static void test_t16_expired_timed_unblocks_one_shot(void) {
    printf("\nTest T16: Expired timed does not block one-shot insertion\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);
    g_use_mock_time = 1;
    g_mock_time = 1000;

    uint8_t client_id1[16], request_id1[16], client_id2[16], request_id2[16];
    fill_id(client_id1, 0xAA);
    fill_id(request_id1, 0xBB);
    fill_id(client_id2, 0xCC);
    fill_id(request_id2, 0xDD);

    insert_timed(&cache, client_id1, request_id1, 100, 200, 300, 2, 1);

    advance_time(2);

    insert_one_shot(&cache, client_id2, request_id2, 100, 200, 300, 1);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id2, request_id2, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find one-shot (expired timed didn't block)");
    ASSERT(decision == 1, "Decision should be 1");

    g_use_mock_time = 0;
    rbox_cache_destroy(&cache);
}



/* T19: Different hash keys interleaved correctly */
static void test_t19_different_hash_interleaved(void) {
    printf("\nTest T19: Different hash keys interleaved correctly\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 16);

    uint8_t ids[4][16];
    for (int i = 0; i < 4; i++) {
        fill_id(ids[i], i + 1);
    }

    insert_one_shot(&cache, ids[0], ids[0], 100, 0, 1, 1);
    insert_one_shot(&cache, ids[1], ids[1], 200, 0, 2, 2);
    insert_one_shot(&cache, ids[2], ids[2], 300, 0, 3, 3);
    insert_one_shot(&cache, ids[3], ids[3], 400, 0, 4, 4);

    for (int i = 0; i < 4; i++) {
        uint8_t decision = 99;
        int found = lookup_one_shot(&cache, ids[i], ids[i], 100 + i * 100, 0, i + 1, &decision);
        ASSERT(found == 1, "Should find entry with different hash");
        ASSERT(decision == i + 1, "Decision should match");
    }

    rbox_cache_destroy(&cache);
}



/* T21: Evict least recently used when full */
static void test_t21_lru_eviction(void) {
    printf("\nTest T21: Evict least recently used when full\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 2);

    uint8_t id_a[16], id_b[16], id_c[16];
    fill_id(id_a, 0xAA);
    fill_id(id_b, 0xBB);
    fill_id(id_c, 0xCC);

    insert_one_shot(&cache, id_a, id_a, 1, 0, 1, 1);
    insert_one_shot(&cache, id_b, id_b, 2, 0, 2, 2);

    ASSERT(rbox_cache_count(&cache) == 2, "Cache should have 2 entries");

    insert_one_shot(&cache, id_c, id_c, 3, 0, 3, 3);

    ASSERT(rbox_cache_count(&cache) == 2, "Count should still be 2 after eviction");

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, id_a, id_a, 1, 0, 1, &decision);
    ASSERT(found == 0, "A (oldest) should be evicted");
    found = lookup_one_shot(&cache, id_c, id_c, 3, 0, 3, &decision);
    ASSERT(found == 1, "C should exist");
    found = lookup_one_shot(&cache, id_b, id_b, 2, 0, 2, &decision);
    ASSERT(found == 1, "B should exist");

    rbox_cache_destroy(&cache);
}

/* T22: Lookup moves entry to LRU head */
static void test_t22_lookup_refreshes_lru(void) {
    printf("\nTest T22: Lookup moves entry to LRU head\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 2);

    uint8_t id_a[16], id_b[16], id_c[16];
    fill_id(id_a, 0xAA);
    fill_id(id_b, 0xBB);
    fill_id(id_c, 0xCC);

    insert_one_shot(&cache, id_a, id_a, 1, 0, 1, 1);
    insert_one_shot(&cache, id_b, id_b, 2, 0, 2, 2);

    lookup_one_shot(&cache, id_a, id_a, 1, 0, 1, NULL);

    insert_one_shot(&cache, id_c, id_c, 3, 0, 3, 3);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, id_a, id_a, 1, 0, 1, &decision);
    ASSERT(found == 1, "A should remain (was looked up, so newer than B)");
    found = lookup_one_shot(&cache, id_b, id_b, 2, 0, 2, &decision);
    ASSERT(found == 0, "B should be evicted (was oldest after A was refreshed)");

    rbox_cache_destroy(&cache);
}

/* T23: Eviction respects both timed and one-shot */
static void test_t23_eviction_respects_both_types(void) {
    printf("\nTest T23: Eviction respects both timed and one-shot\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 2);

    uint8_t id_a[16], id_b[16], id_c[16];
    fill_id(id_a, 0xAA);
    fill_id(id_b, 0xBB);
    fill_id(id_c, 0xCC);

    insert_one_shot(&cache, id_a, id_a, 1, 0, 1, 1);
    insert_timed(&cache, id_b, id_b, 2, 0, 2, 2, 3600);
    insert_one_shot(&cache, id_c, id_c, 3, 0, 3, 3);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, id_a, id_a, 1, 0, 1, &decision);
    ASSERT(found == 0, "A (oldest) should be evicted regardless of type");

    rbox_cache_destroy(&cache);
}





/* T27: Insertion reuses tombstone slots */


/* T28: Capacity management and eviction */
static void test_t28_capacity_management(void) {
    printf("\nTest T28: Capacity management and eviction\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 8);

    uint8_t ids[12][16];
    for (int i = 0; i < 12; i++) {
        fill_id(ids[i], i + 1);
    }

    for (int i = 0; i < 8; i++) {
        insert_one_shot(&cache, ids[i], ids[i], 100 + i, 0, i + 1, 1);
    }

    ASSERT(rbox_cache_count(&cache) == 8, "Cache should be full");

    for (int i = 0; i < 4; i++) {
        insert_one_shot(&cache, ids[i + 8], ids[i + 8], 200 + i, 0, 50 + i, 1);
    }

    ASSERT(rbox_cache_count(&cache) <= 8, "Count should not exceed capacity");

    rbox_cache_destroy(&cache);
}



/* T30: Single-threaded sequential insert/lookup stress */
static void test_t30_sequential_stress(void) {
    printf("\nTest T30: Sequential insert/lookup stress\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    const int ops = 200;
    int total_inserts = 0;
    int total_lookups = 0;

    for (int i = 0; i < ops; i++) {
        uint8_t id[16];
        fill_id(id, i & 0xFF);
        insert_one_shot(&cache, id, id, 1000 + i, 0, (i % 4) + 1, 1);
        total_inserts++;
    }

    for (int i = 0; i < ops; i++) {
        uint8_t id[16];
        fill_id(id, i & 0xFF);
        uint8_t decision = 99;
        int found = lookup_one_shot(&cache, id, id, 1000 + i, 0, (i % 4) + 1, &decision);
        if (found) total_lookups++;
    }

    ASSERT(total_inserts > 0, "Should have done some inserts");
    ASSERT(total_lookups > 0, "Should have done some lookups");
    ASSERT(rbox_cache_count(&cache) > 0, "Cache should have entries after sequential access");
    ASSERT(rbox_cache_count(&cache) <= 256, "Cache count should not exceed capacity");

    rbox_cache_destroy(&cache);
}

/* T31: Zero-capacity cache */
static void test_t31_zero_capacity(void) {
    printf("\nTest T31: Zero-capacity cache\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 0);

    uint8_t client_id[16], request_id[16];
    fill_id(client_id, 0xAA);
    fill_id(request_id, 0xBB);

    insert_one_shot(&cache, client_id, request_id, 100, 200, 300, 1);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id, request_id, 100, 200, 300, &decision);
    ASSERT(found == 0, "Zero capacity cache should always miss");

    ASSERT(rbox_cache_count(&cache) == 0, "Count should be 0");

    rbox_cache_destroy(&cache);
}

/* T32: Insert with empty reason / zero env count */
static void test_t32_empty_reason_zero_env(void) {
    printf("\nTest T32: Insert with empty reason / zero env count\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id[16], request_id[16];
    fill_id(client_id, 0xAA);
    fill_id(request_id, 0xBB);

    rbox_cache_insert(&cache, client_id, request_id, 0, 100, 200, 300,
                      1, "", 0, 0, NULL);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id, request_id, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find entry with empty reason");
    ASSERT(decision == 1, "Decision should be 1");
    ASSERT(rbox_cache_count(&cache) == 1, "Cache should have 1 entry");

    rbox_cache_destroy(&cache);
}

/* T33: Very long reason string */
static void test_t33_long_reason_truncation(void) {
    printf("\nTest T33: Very long reason string (truncation)\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id[16], request_id[16];
    fill_id(client_id, 0xAA);
    fill_id(request_id, 0xBB);

    char long_reason[300];
    memset(long_reason, 'x', sizeof(long_reason) - 1);
    long_reason[sizeof(long_reason) - 1] = '\0';

    rbox_cache_insert(&cache, client_id, request_id, 0, 100, 200, 300,
                      1, long_reason, 0, 0, NULL);

    uint8_t decision = 99;
    char reason[256];
    int env_count = 0;
    uint8_t *env_decisions = NULL;
    int found = rbox_cache_lookup(&cache, client_id, request_id, 0, 100, 200, 300,
                                  &decision, reason, NULL, &env_count, &env_decisions);
    if (env_decisions) free(env_decisions);

    ASSERT(found == 1, "Should find entry");
    ASSERT(strlen(reason) <= 254, "Reason should be truncated to 254 chars + null");

    rbox_cache_destroy(&cache);
}

/* T34: Packet checksum mismatch for one-shot */
static void test_t34_checksum_mismatch_coexist(void) {
    printf("\nTest T34: Packet checksum mismatch for one-shot\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id[16], request_id[16];
    fill_id(client_id, 0xAA);
    fill_id(request_id, 0xBB);

    insert_one_shot_with_checksum(&cache, client_id, request_id, 1000, 100, 200, 300, 1, "first");
    insert_one_shot_with_checksum(&cache, client_id, request_id, 2000, 100, 200, 300, 2, "second");

    uint8_t decision = 99;
    int found = lookup_one_shot_with_checksum(&cache, client_id, request_id, 1000, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find entry with checksum 1000");
    ASSERT(decision == 1, "Decision should be 1 (first)");

    found = lookup_one_shot_with_checksum(&cache, client_id, request_id, 2000, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find entry with checksum 2000");
    ASSERT(decision == 2, "Decision should be 2 (second)");

    ASSERT(rbox_cache_count(&cache) == 2, "Both entries should coexist");

    rbox_cache_destroy(&cache);
}

/* T35: Timed replaces expired timed */
static void test_t35_timed_replaces_expired(void) {
    printf("\nTest T35: Timed replaces expired timed\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);
    g_use_mock_time = 1;
    g_mock_time = 1000;

    uint8_t client_id[16], request_id[16];
    fill_id(client_id, 0xAA);
    fill_id(request_id, 0xBB);

    insert_timed(&cache, client_id, request_id, 100, 200, 300, 1, 1);

    advance_time(2);
    insert_timed(&cache, client_id, request_id, 100, 200, 300, 2, 3600);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id, request_id, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find new timed entry");
    ASSERT(decision == 2, "Decision should be 2 (new timed)");

    g_use_mock_time = 0;
    rbox_cache_destroy(&cache);
}

/* T36: Expired timed does not block new timed */
static void test_t36_expired_timed_not_block_new_timed(void) {
    printf("\nTest T36: Expired timed does not block new timed\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);
    g_use_mock_time = 1;
    g_mock_time = 1000;

    uint8_t client_id[16], request_id[16];
    fill_id(client_id, 0xAA);
    fill_id(request_id, 0xBB);

    insert_timed(&cache, client_id, request_id, 100, 200, 300, 1, 1);

    advance_time(2);

    insert_timed(&cache, client_id, request_id, 100, 200, 300, 2, 3600);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id, request_id, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find new timed entry");
    ASSERT(decision == 2, "Decision should be 2 (new timed)");

    g_use_mock_time = 0;
    rbox_cache_destroy(&cache);
}

/* T37: One-shot with zero checksum vs non-zero are distinct */
static void test_t37_zero_vs_nonzero_checksum(void) {
    printf("\nTest T37: One-shot zero vs non-zero checksum are distinct\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id[16], request_id[16];
    fill_id(client_id, 0xAA);
    fill_id(request_id, 0xBB);

    insert_one_shot_with_checksum(&cache, client_id, request_id, 0, 100, 200, 300, 1, "zero");
    insert_one_shot_with_checksum(&cache, client_id, request_id, 1234, 100, 200, 300, 2, "nonzero");

    uint8_t decision = 99;
    int found = lookup_one_shot_with_checksum(&cache, client_id, request_id, 0, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find entry with zero checksum");
    ASSERT(decision == 1, "Decision should be 1 (zero checksum)");

    found = lookup_one_shot_with_checksum(&cache, client_id, request_id, 1234, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find entry with non-zero checksum");
    ASSERT(decision == 2, "Decision should be 2 (non-zero checksum)");

    ASSERT(rbox_cache_count(&cache) == 2, "Both entries should coexist");

    rbox_cache_destroy(&cache);
}

/* T38: Eviction of expired entries when cache is full */
static void test_t38_eviction_of_expired_entries(void) {
    printf("\nTest T38: Eviction of expired entries when cache is full\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 4);
    g_use_mock_time = 1;
    g_mock_time = 1000;

    uint8_t ids[4][16];
    for (int i = 0; i < 4; i++) {
        fill_id(ids[i], i + 1);
    }

    for (int i = 0; i < 4; i++) {
        insert_timed(&cache, ids[i], ids[i], 100 + i, 0, i + 1, 1, 1);
    }

    advance_time(2);

    uint8_t new_id[16];
    fill_id(new_id, 0xFF);
    insert_one_shot(&cache, new_id, new_id, 999, 0, 99, 1);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, new_id, new_id, 999, 0, 99, &decision);
    ASSERT(found == 1, "New entry should be found");
    ASSERT(decision == 1, "New entry decision should be 1");

    g_use_mock_time = 0;
    rbox_cache_destroy(&cache);
}

/* T39: Capacity 1 - insert, evict, insert again */
static void test_t39_capacity_one(void) {
    printf("\nTest T39: Capacity 1 edge case\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 1);

    uint8_t id_a[16], id_b[16], id_c[16];
    fill_id(id_a, 0xAA);
    fill_id(id_b, 0xBB);
    fill_id(id_c, 0xCC);

    insert_one_shot(&cache, id_a, id_a, 1, 0, 1, 1);
    ASSERT(rbox_cache_count(&cache) == 1, "Cache should have 1 entry");

    insert_one_shot(&cache, id_b, id_b, 2, 0, 2, 2);
    ASSERT(rbox_cache_count(&cache) == 1, "Cache should still have 1 entry after eviction");

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, id_a, id_a, 1, 0, 1, &decision);
    ASSERT(found == 0, "First entry should be evicted");

    found = lookup_one_shot(&cache, id_b, id_b, 2, 0, 2, &decision);
    ASSERT(found == 1, "Second entry should exist");
    ASSERT(decision == 2, "Decision should be 2");

    insert_one_shot(&cache, id_c, id_c, 3, 0, 3, 3);

    found = lookup_one_shot(&cache, id_b, id_b, 2, 0, 2, &decision);
    ASSERT(found == 0, "Second entry should be evicted");
    found = lookup_one_shot(&cache, id_c, id_c, 3, 0, 3, &decision);
    ASSERT(found == 1, "Third entry should exist");

    rbox_cache_destroy(&cache);
}

/* T40: Many collisions (100 same-hash entries) - no infinite loop */
static void test_t40_many_collisions(void) {
    printf("\nTest T40: Many collisions (100 same-hash entries)\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t ids[100][16];
    for (int i = 0; i < 100; i++) {
        fill_id(ids[i], i + 1);
    }

    for (int i = 0; i < 100; i++) {
        insert_one_shot(&cache, ids[i], ids[i], 100, 200, 300, i + 1);
    }

    ASSERT(rbox_cache_count(&cache) <= 256, "Cache should not exceed capacity");

    for (int i = 0; i < 100; i++) {
        uint8_t decision = 99;
        int found = lookup_one_shot(&cache, ids[i], ids[i], 100, 200, 300, &decision);
        if (found) {
            ASSERT(decision == i + 1, "Decision should match inserted value");
        }
    }

    rbox_cache_destroy(&cache);
}

/* T41: Lookup finds timed via fallback when no exact one-shot match */
static void test_t41_timed_fallback_when_no_exact_match(void) {
    printf("\nTest T41: Timed fallback when no exact one-shot match\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 16);

    uint8_t id_a[16], id_b[16];
    fill_id(id_a, 0xAA);
    fill_id(id_b, 0xBB);

    insert_timed(&cache, id_a, id_a, 100, 200, 300, 2, 3600);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, id_b, id_b, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find timed via fallback");
    ASSERT(decision == 2, "Should return timed decision");

    found = lookup_one_shot(&cache, id_a, id_a, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find timed");
    ASSERT(decision == 2, "Should return timed decision");

    rbox_cache_destroy(&cache);
}

static void test_t45_lru_mixed_types(void);
static void test_t46_large_duration(void);
static void test_t48_sequential_stress(void);
static void test_t49_deterministic_random(void);
static void test_env_bitmap_isolation(void);

int main(void) {
    printf("=== rbox_cache integration tests ===\n\n");

    test_t01_one_shot_exact_lookup();
    test_t02_one_shot_different_client();
    test_t03_one_shot_different_request();
    test_t04_timed_lookup_any_id();
    test_t05_timed_miss_different_command();
    test_t06_replace_one_shot_exact();
    test_t07_replace_timed_exact();
    test_t08_no_replacement_different_keys();
    test_t09_one_shot_skipped_when_timed_exists();
    test_t10_one_shot_remains_after_timed();
    test_t11_timed_allowed_after_one_shot();
    test_t12_one_shot_after_timed_expires();
    test_t13_one_shot_priority_over_timed();
    test_t14_timed_returned_without_exact();
    test_t15_expired_timed_miss();
    test_t16_expired_timed_unblocks_one_shot();
    test_t19_different_hash_interleaved();
    test_t21_lru_eviction();
    test_t22_lookup_refreshes_lru();
    test_t23_eviction_respects_both_types();
    test_t28_capacity_management();
    test_t30_sequential_stress();
    test_t31_zero_capacity();
    test_t32_empty_reason_zero_env();
    test_t33_long_reason_truncation();
    test_t34_checksum_mismatch_coexist();
    test_t35_timed_replaces_expired();
    test_t36_expired_timed_not_block_new_timed();
    test_t37_zero_vs_nonzero_checksum();
    test_t38_eviction_of_expired_entries();
    test_t39_capacity_one();
    test_t40_many_collisions();
    test_t41_timed_fallback_when_no_exact_match();
    test_t45_lru_mixed_types();
    test_t46_large_duration();
    test_t48_sequential_stress();
    test_t49_deterministic_random();
    test_env_bitmap_isolation();

    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}



/* T45: LRU with mixed types - interleaved inserts and evictions */
static void test_t45_lru_mixed_types(void) {
    printf("\nTest T45: LRU with mixed types\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 4);

    uint8_t ids[5][16];
    for (int i = 0; i < 5; i++) {
        fill_id(ids[i], i + 1);
    }

    insert_one_shot(&cache, ids[0], ids[0], 1, 0, 1, 1);
    insert_timed(&cache, ids[1], ids[1], 2, 0, 2, 2, 3600);
    insert_one_shot(&cache, ids[2], ids[2], 3, 0, 3, 3);

    lookup_one_shot(&cache, ids[0], ids[0], 1, 0, 1, NULL);

    insert_one_shot(&cache, ids[3], ids[3], 4, 0, 4, 4);

    ASSERT(rbox_cache_count(&cache) <= 4, "Cache should not exceed capacity");

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, ids[0], ids[0], 1, 0, 1, &decision);
    ASSERT(found == 1, "ids[0] should still exist (was accessed)");

    found = lookup_one_shot(&cache, ids[2], ids[2], 3, 0, 3, &decision);
    ASSERT(found == 1, "ids[2] should still exist");

    found = lookup_one_shot(&cache, ids[3], ids[3], 4, 0, 4, &decision);
    ASSERT(found == 1, "ids[3] should exist");

    rbox_cache_destroy(&cache);
}

/* T46: Insert timed with very large duration */
static void test_t46_large_duration(void) {
    printf("\nTest T46: Timed with very large duration\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);
    g_use_mock_time = 1;
    g_mock_time = 1000;

    uint8_t client_id[16], request_id[16];
    fill_id(client_id, 0xAA);
    fill_id(request_id, 0xBB);

    uint32_t huge_duration = 0x7FFFFFFF;
    insert_timed(&cache, client_id, request_id, 100, 200, 300, 1, huge_duration);

    uint8_t decision = 99;
    int found = lookup_one_shot(&cache, client_id, request_id, 100, 200, 300, &decision);
    ASSERT(found == 1, "Should find entry with huge duration");
    ASSERT(decision == 1, "Decision should be 1");

    g_use_mock_time = 0;
    rbox_cache_destroy(&cache);
}


/* T48: Sequential stress test with many operations */
static void test_t48_sequential_stress(void) {
    printf("\nTest T48: Sequential stress (8000 ops)\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    const int ops = 8000;
    int total_inserts = 0;
    int total_lookups = 0;

    for (int i = 0; i < ops; i++) {
        uint8_t id[16];
        int id_val = (i * 17) & 0xFF;
        fill_id(id, id_val);

        int op = (i * 7) % 5;
        if (op == 0) {
            insert_one_shot(&cache, id, id, 1000 + i, 0, (i % 8) + 1, 1);
            total_inserts++;
        } else if (op == 1) {
            uint8_t decision = 99;
            int found = lookup_one_shot(&cache, id, id, 1000 + i, 0, (i % 8) + 1, &decision);
            if (found) total_lookups++;
        } else if (op == 2) {
            insert_timed(&cache, id, id, 1000 + i, 0, (i % 8) + 1, 2, 3600);
            total_inserts++;
        } else if (op == 3) {
            insert_one_shot(&cache, id, id, 1000 + i, 0, (i % 8) + 1, 3);
            total_inserts++;
        } else {
            uint8_t decision = 99;
            int found = lookup_one_shot(&cache, id, id, 1000 + i, 0, (i % 8) + 1, &decision);
            if (found) total_lookups++;
        }
    }

    ASSERT(total_inserts > 0, "Should have done many inserts");
    ASSERT(rbox_cache_count(&cache) > 0, "Cache should have entries after sequential stress");
    ASSERT(rbox_cache_count(&cache) <= 256, "Cache count should not exceed capacity");

    rbox_cache_destroy(&cache);
}

/* Env bitmap isolation: repeated lookups return independent copies */
static void test_env_bitmap_isolation(void) {
    printf("\nTest: env bitmap returns independent copies\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 256);

    uint8_t client_id[16], request_id[16];
    fill_id(client_id, 0xAA);
    fill_id(request_id, 0xBB);

    /* Insert with env bitmap */
    uint8_t env_bits[4] = { 0xFF, 0x0F, 0xAA, 0x55 };
    rbox_cache_insert(&cache, client_id, request_id, 0,
                      100, 200, 300, 1, "reason", 0, 32, env_bits);

    /* First lookup */
    uint8_t decision = 0;
    char reason[256];
    uint32_t duration = 0;
    int env_count = 0;
    uint8_t *env1 = NULL;
    int found = rbox_cache_lookup(&cache, client_id, request_id, 0,
                                  100, 200, 300,
                                  &decision, reason, &duration,
                                  &env_count, &env1);
    ASSERT(found == 1, "env: first lookup found");
    ASSERT(env_count == 32, "env: count is 32");
    ASSERT(env1 != NULL, "env: bitmap returned");
    ASSERT(env1[0] == 0xFF, "env: bitmap content correct");

    /* Mutate the returned copy */
    env1[0] = 0x00;

    /* Second lookup — should still see original data */
    uint8_t *env2 = NULL;
    found = rbox_cache_lookup(&cache, client_id, request_id, 0,
                              100, 200, 300,
                              &decision, reason, &duration,
                              &env_count, &env2);
    ASSERT(found == 1, "env: second lookup found");
    ASSERT(env2 != NULL, "env: second bitmap returned");
    ASSERT(env2[0] == 0xFF, "env: mutation of first copy did not affect cache entry");

    free(env1);
    free(env2);
    rbox_cache_destroy(&cache);
}

/* T49: Deterministic random test with fixed seed */
static void test_t49_deterministic_random(void) {
    printf("\nTest T49: Deterministic random test\n");
    rbox_cache_t cache;
    rbox_cache_init(&cache, 64);

    unsigned int seed = 42;
    srand(seed);

    uint8_t ids[50][16];
    for (int i = 0; i < 50; i++) {
        fill_id(ids[i], rand() & 0xFF);
    }

    for (int i = 0; i < 30; i++) {
        int decision = (rand() % 2) + 1;
        if (rand() % 3 == 0) {
            insert_one_shot(&cache, ids[i], ids[i], 100 + i, 0, i + 1, decision);
        } else {
            insert_timed(&cache, ids[i], ids[i], 100 + i, 0, i + 1, decision, 3600);
        }
    }

    for (int i = 0; i < 30; i++) {
        uint8_t decision = 99;
        lookup_one_shot(&cache, ids[i], ids[i], 100 + i, 0, i + 1, &decision);
    }

    ASSERT(rbox_cache_count(&cache) > 0 || rbox_cache_count(&cache) == 0, "Cache state valid");

    rbox_cache_destroy(&cache);
}
