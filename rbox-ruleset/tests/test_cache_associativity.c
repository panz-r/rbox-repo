/**
 * @file test_cache_associativity.c
 * @brief Integration tests for query_cache → ht_cache_t delegation
 *
 * Tests the contract at the rule_engine ↔ ht_cache boundary:
 *   - Hit/miss statistics track correctly
 *   - Cache survives recompilation (invalidation clears, re-populates)
 *   - Subject hash discriminates entries for the same path
 *   - Eval mode coverage allows READ-warmed entries to serve COPY lookups
 *   - Global LRU evicts least-recently-used entries under pressure
 */

#include "test_framework.h"
#include "rule_engine.h"
#include "rule_engine_internal.h"
#include <string.h>

static soft_ruleset_t *make_ruleset(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();

    /* Layer 0: PRECEDENCE deny /data/... */
    soft_ruleset_add_rule_at_layer(rs, 0, "/data/...",
                   SOFT_ACCESS_DENY, SOFT_OP_READ, NULL, NULL, SOFT_RULE_RECURSIVE);
    soft_ruleset_add_rule_at_layer(rs, 0, "/public",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0);

    /* Layer 1: SPECIFICITY allow /data/project subtree */
    soft_ruleset_set_layer_type(rs, 1, LAYER_SPECIFICITY, 0);
    soft_ruleset_add_rule_at_layer(rs, 1, "/data/project/**",
                   SOFT_ACCESS_READ, SOFT_OP_READ, NULL, NULL, 0);

    /* Timed writes to /tmp */
    soft_ruleset_add_rule_at_layer(rs, 1, "/tmp/...",
                   SOFT_ACCESS_WRITE, SOFT_OP_COPY, NULL, NULL, SOFT_RULE_RECURSIVE);

    soft_ruleset_compile(rs);
    return rs;
}

/* --- Hit/miss counting --- */

static void test_cache_statistics(void)
{
    soft_ruleset_t *rs = make_ruleset();
    uint32_t g = 0;

    TEST_ASSERT(rs->stats_cache_hits == 0, "stats: initial hits 0");
    TEST_ASSERT(rs->stats_cache_misses == 0, "stats: initial misses 0");

    soft_access_ctx_t ctx = { SOFT_OP_READ, "/public", NULL, "alice" };
    soft_ruleset_check_ctx(rs, &ctx, &g, NULL);
    TEST_ASSERT(rs->stats_cache_hits == 0, "stats: first access misses");
    TEST_ASSERT(rs->stats_cache_misses == 1, "stats: 1 miss");

    soft_ruleset_check_ctx(rs, &ctx, &g, NULL);
    TEST_ASSERT(rs->stats_cache_hits == 1, "stats: second access hits");
    TEST_ASSERT(rs->stats_cache_misses == 1, "stats: still 1 miss");

    soft_access_ctx_t ctx2 = { SOFT_OP_READ, "/data/project/x.txt", NULL, "alice" };
    soft_ruleset_check_ctx(rs, &ctx2, &g, NULL);
    TEST_ASSERT(rs->stats_cache_misses == 2, "stats: different path misses");

    soft_ruleset_free(rs);
}

/* --- Invalidation clears cache on recompile --- */

static void test_invalidate_clears_cache(void)
{
    soft_ruleset_t *rs = make_ruleset();
    uint32_t g = 0;

    soft_access_ctx_t ctx = { SOFT_OP_READ, "/public", NULL, "alice" };
    soft_ruleset_check_ctx(rs, &ctx, &g, NULL);

    TEST_ASSERT(rs->stats_cache_misses == 1, "inv: first access miss");

    soft_ruleset_check_ctx(rs, &ctx, &g, NULL);
    TEST_ASSERT(rs->stats_cache_hits == 1, "inv: second access hit");

    /* Invalidate + recompile should wipe the cache */
    soft_ruleset_invalidate(rs);
    soft_ruleset_compile(rs);

    rs->stats_cache_hits = 0;
    rs->stats_cache_misses = 0;
    soft_ruleset_check_ctx(rs, &ctx, &g, NULL);
    TEST_ASSERT(rs->stats_cache_misses == 1, "inv: post-invalidate miss");
    TEST_ASSERT(rs->stats_cache_hits == 0, "inv: no hits after clear");

    soft_ruleset_free(rs);
}

/* --- Subject discrimination --- */

static void test_subject_discrimination(void)
{
    soft_ruleset_t *rs = make_ruleset();
    uint32_t g = 0;

    soft_access_ctx_t alice = { SOFT_OP_READ, "/public", NULL, "alice" };
    soft_access_ctx_t bob   = { SOFT_OP_READ, "/public", NULL, "bob" };

    soft_ruleset_check_ctx(rs, &alice, &g, NULL);
    TEST_ASSERT(rs->stats_cache_misses == 1, "subj: alice miss");

    /* Same path, different subject — should miss (different subject_hash) */
    soft_ruleset_check_ctx(rs, &bob, &g, NULL);
    TEST_ASSERT(rs->stats_cache_misses == 2, "subj: bob miss (different subject)");

    /* Alice again — should hit */
    soft_ruleset_check_ctx(rs, &alice, &g, NULL);
    TEST_ASSERT(rs->stats_cache_hits == 1, "subj: alice hit");

    soft_ruleset_free(rs);
}

/* --- Eval mode coverage: READ-warmed serves COPY --- */

static void test_eval_mode_reuse(void)
{
    soft_ruleset_t *rs = make_ruleset();
    uint32_t g = 0;

    /* Warm with READ */
    soft_access_ctx_t read_ctx = { SOFT_OP_READ, "/data/project/file.txt", NULL, "alice" };
    int r = soft_ruleset_check_ctx(rs, &read_ctx, &g, NULL);
    TEST_ASSERT(r && (g & SOFT_ACCESS_READ), "eval: READ grants READ");

    /* COPY needs READ on src, WRITE on dst. The src /data/project/file.txt
     * was cached with eval=READ. The COPY lookup for src requires
     * required_mode=READ, so (eval & READ)==READ matches → cache hit for src. */
    rs->stats_cache_hits = 0;
    rs->stats_cache_misses = 0;

    soft_access_ctx_t copy_ctx = { SOFT_OP_COPY, "/data/project/file.txt", "/tmp/out.txt", "alice" };
    r = soft_ruleset_check_ctx(rs, &copy_ctx, &g, NULL);
    /* At least the src should have been a cache hit */
    TEST_ASSERT(rs->stats_cache_hits >= 1, "eval: COPY reuses READ-cached src");

    soft_ruleset_free(rs);
}

/* --- Global LRU evicts under pressure --- */

static void test_lru_eviction_under_pressure(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    uint32_t g = 0;

    /* Fill cache: add more paths than QUERY_CACHE_SIZE */
    int total = QUERY_CACHE_SIZE + 50;
    for (int i = 0; i < total; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/lru/path%d", i);
        soft_ruleset_add_rule(rs, path, SOFT_ACCESS_READ, SOFT_OP_READ, "", "", 0);
    }
    soft_ruleset_compile(rs);

    /* Warm up first 20 paths */
    for (int i = 0; i < 20; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/lru/path%d", i);
        soft_access_ctx_t ctx = { SOFT_OP_READ, path, NULL, "user" };
        soft_ruleset_check_ctx(rs, &ctx, &g, NULL);
    }
    TEST_ASSERT(rs->stats_cache_misses == 20, "lru: 20 warmup misses");

    /* Access again — all 20 should hit */
    rs->stats_cache_hits = 0;
    rs->stats_cache_misses = 0;
    for (int i = 0; i < 20; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/lru/path%d", i);
        soft_access_ctx_t ctx = { SOFT_OP_READ, path, NULL, "user" };
        soft_ruleset_check_ctx(rs, &ctx, &g, NULL);
    }
    TEST_ASSERT(rs->stats_cache_hits == 20, "lru: 20 warmup hits");
    TEST_ASSERT(rs->stats_cache_misses == 0, "lru: 0 warmup misses");

    /* Evict everything by accessing QUERY_CACHE_SIZE+ new paths */
    for (int i = 20; i < total; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/lru/path%d", i);
        soft_access_ctx_t ctx = { SOFT_OP_READ, path, NULL, "user" };
        soft_ruleset_check_ctx(rs, &ctx, &g, NULL);
    }

    /* Original 20 should now be evicted — they'll miss */
    rs->stats_cache_hits = 0;
    rs->stats_cache_misses = 0;
    for (int i = 0; i < 20; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/lru/path%d", i);
        soft_access_ctx_t ctx = { SOFT_OP_READ, path, NULL, "user" };
        soft_ruleset_check_ctx(rs, &ctx, &g, NULL);
    }
    /* With 2048-entry cache and 50 extra paths, at least some of the
     * original 20 should have been evicted. Exact count depends on
     * which paths the LRU decided to keep. */
    TEST_ASSERT(rs->stats_cache_misses > 0,
                "lru: some original entries evicted after pressure");

    soft_ruleset_free(rs);
}

/* --- Cache works without compilation (lazy creation) --- */

static void test_lazy_cache_creation(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    uint32_t g = 0;

    soft_ruleset_add_rule(rs, "/lazy", SOFT_ACCESS_READ, SOFT_OP_READ, "", "", 0);
    /* No compile — cache is NULL, so lookups miss gracefully */

    soft_access_ctx_t ctx = { SOFT_OP_READ, "/lazy", NULL, "user" };
    int r = soft_ruleset_check_ctx(rs, &ctx, &g, NULL);
    TEST_ASSERT(r && (g & SOFT_ACCESS_READ), "lazy: evaluation works without compile");
    /* The store should have lazily created the cache */

    soft_access_ctx_t ctx2 = { SOFT_OP_READ, "/lazy", NULL, "user" };
    r = soft_ruleset_check_ctx(rs, &ctx2, &g, NULL);
    TEST_ASSERT(r && (g & SOFT_ACCESS_READ), "lazy: second access also works");

    soft_ruleset_free(rs);
}

/* Test suite registration */
void test_cache_associativity_suite(void)
{
    printf("  Running cache integration tests...\n");
    RUN_TEST(test_cache_statistics);
    RUN_TEST(test_invalidate_clears_cache);
    RUN_TEST(test_subject_discrimination);
    RUN_TEST(test_eval_mode_reuse);
    RUN_TEST(test_lru_eviction_under_pressure);
    RUN_TEST(test_lazy_cache_creation);
}

void test_cache_associativity_run(void)
{
    test_cache_associativity_suite();
}
