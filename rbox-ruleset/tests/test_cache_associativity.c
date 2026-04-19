/**
 * @file test_cache_associativity.c
 * @brief Tests for 8-way set associative cache with LRU eviction
 */

#include "test_framework.h"
#include "rule_engine.h"
#include "rule_engine_internal.h"
#include <string.h>

/* Test 8-way set associative cache behavior */
static void test_8way_associativity(void)
{
    uint32_t __g = 0;
    soft_ruleset_t *rs = soft_ruleset_new();
    
    /* Add rules that will hash to the same cache set */
    for (int i = 0; i < QUERY_CACHE_WAYS + 2; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/test/same/prefix/path%d", i);
        
        TEST_ASSERT(soft_ruleset_add_rule(rs, path, SOFT_ACCESS_READ, SOFT_OP_READ, "", "", 0) == 0,
                    "assoc: add rule for path");
    }
    
    soft_ruleset_compile(rs);
    
    /* First access - all should miss cache */
    uint64_t misses_before = rs->stats_cache_misses;
    for (int i = 0; i < QUERY_CACHE_WAYS; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/test/same/prefix/path%d", i);
        
        soft_access_ctx_t ctx = {SOFT_OP_READ, path, NULL, "test_subject"};
        int ret = soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
        TEST_ASSERT(ret, "assoc: path allowed");
    }
    uint64_t misses_after = rs->stats_cache_misses;
    TEST_ASSERT(misses_after - misses_before == QUERY_CACHE_WAYS,
                "assoc: all first accesses should miss cache");
    
    /* Reset stats and access again - all should hit cache */
    rs->stats_cache_hits = 0;
    rs->stats_cache_misses = 0;
    
    for (int i = 0; i < QUERY_CACHE_WAYS; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/test/same/prefix/path%d", i);
        
        soft_access_ctx_t ctx = {SOFT_OP_READ, path, NULL, "test_subject"};
        int ret = soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
        TEST_ASSERT(ret, "assoc: path still allowed");
    }
    
    TEST_ASSERT(rs->stats_cache_hits == QUERY_CACHE_WAYS,
                "assoc: all second accesses should hit cache");
    TEST_ASSERT(rs->stats_cache_misses == 0,
                "assoc: no misses on second access");
    
    /* Test LRU eviction */
    rs->stats_cache_hits = 0;
    rs->stats_cache_misses = 0;
    
    // Access first half to make them MRU
    for (int i = 0; i < QUERY_CACHE_WAYS/2; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/test/same/prefix/path%d", i);
        
        soft_access_ctx_t ctx = {SOFT_OP_READ, path, NULL, "test_subject"};
        int ret = soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
        TEST_ASSERT(ret, "assoc: make path MRU");
    }
    
    // Add new paths that will evict the LRU entries
    for (int i = QUERY_CACHE_WAYS; i < QUERY_CACHE_WAYS + 2; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/test/same/prefix/path%d", i);
        
        TEST_ASSERT(soft_ruleset_add_rule(rs, path, SOFT_ACCESS_READ, SOFT_OP_READ, "", "", 0) == 0,
                    "assoc: add additional rule");
        
        soft_access_ctx_t ctx = {SOFT_OP_READ, path, NULL, "test_subject"};
        int ret = soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
        TEST_ASSERT(ret, "assoc: new path allowed");
    }
    
    // The MRU paths should still be cached
    uint64_t hits = 0;
    for (int i = 0; i < QUERY_CACHE_WAYS/2; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/test/same/prefix/path%d", i);
        
        soft_access_ctx_t ctx = {SOFT_OP_READ, path, NULL, "test_subject"};
        if (soft_ruleset_check_ctx(rs, &ctx, &__g, NULL)) {
            hits++;
        }
    }
    
    TEST_ASSERT(hits > 0, "assoc: some MRU entries should still be cached after eviction");
    
    soft_ruleset_free(rs);
}

/* Test cache set distribution */
static void test_cache_set_distribution(void)
{
    uint32_t __g = 0;
    soft_ruleset_t *rs = soft_ruleset_new();
    
    /* Add many rules and check that they distribute across cache sets */
    const int NUM_RULES = 1000;
    for (int i = 0; i < NUM_RULES; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/dist/test/path/unique%d", i);
        
        TEST_ASSERT(soft_ruleset_add_rule(rs, path, SOFT_ACCESS_READ, SOFT_OP_READ, "", "", 0) == 0,
                    "dist: add rule");
    }
    
    soft_ruleset_compile(rs);
    
    /* Access all rules - should get good cache hit rate */
    // First access - all miss
    for (int i = 0; i < NUM_RULES; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/dist/test/path/unique%d", i);
        
        soft_access_ctx_t ctx = {SOFT_OP_READ, path, NULL, "test"};
        soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
    }
    
    // Second access - should get good hit rate with 8-way associativity
    rs->stats_cache_hits = 0;
    rs->stats_cache_misses = 0;
    
    for (int i = 0; i < NUM_RULES; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/dist/test/path/unique%d", i);
        
        soft_access_ctx_t ctx = {SOFT_OP_READ, path, NULL, "test"};
        soft_ruleset_check_ctx(rs, &ctx, &__g, NULL);
    }
    
    uint64_t total_hits = rs->stats_cache_hits;
    uint64_t total_misses = rs->stats_cache_misses;
    
    // With 8-way associativity, we should get excellent hit rates
    double hit_rate = (double)total_hits / ((double)total_hits + (double)total_misses);
    TEST_ASSERT(hit_rate > 0.95, "dist: should achieve >95% cache hit rate with 8-way associativity");
    
    soft_ruleset_free(rs);
}

/* Test cache statistics tracking */
static void test_cache_statistics(void)
{
    soft_ruleset_t *rs = soft_ruleset_new();
    uint32_t __g = 0;
    
    /* Add some rules */
    TEST_ASSERT(soft_ruleset_add_rule(rs, "/stats/test1", SOFT_ACCESS_READ, SOFT_OP_READ, "", "", 0) == 0,
                "stats: add rule1");
    TEST_ASSERT(soft_ruleset_add_rule(rs, "/stats/test2", SOFT_ACCESS_WRITE, SOFT_OP_WRITE, "", "", 0) == 0,
                "stats: add rule2");
    
    soft_ruleset_compile(rs);
    
    /* Verify initial stats */
    TEST_ASSERT(rs->stats_cache_hits == 0, "stats: initial hits should be 0");
    TEST_ASSERT(rs->stats_cache_misses == 0, "stats: initial misses should be 0");
    
    /* First access - should miss */
    soft_access_ctx_t ctx1 = {SOFT_OP_READ, "/stats/test1", NULL, "subject"};
    int ret1 = soft_ruleset_check_ctx(rs, &ctx1, &__g, NULL);
    TEST_ASSERT(ret1, "stats: first access allowed");
    
    TEST_ASSERT(rs->stats_cache_hits == 0, "stats: first access should miss");
    TEST_ASSERT(rs->stats_cache_misses == 1, "stats: first access should be 1 miss");
    
    /* Second access - should hit */
    int ret2 = soft_ruleset_check_ctx(rs, &ctx1, &__g, NULL);
    TEST_ASSERT(ret2, "stats: second access allowed");
    
    TEST_ASSERT(rs->stats_cache_hits == 1, "stats: second access should hit");
    TEST_ASSERT(rs->stats_cache_misses == 1, "stats: still 1 miss total");
    
    /* Different path - should miss */
    soft_access_ctx_t ctx2 = {SOFT_OP_WRITE, "/stats/test2", NULL, "subject"};
    int ret3 = soft_ruleset_check_ctx(rs, &ctx2, &__g, NULL);
    TEST_ASSERT(ret3, "stats: different path allowed");
    
    TEST_ASSERT(rs->stats_cache_hits == 1, "stats: different path should miss");
    TEST_ASSERT(rs->stats_cache_misses == 2, "stats: now 2 misses total");
    
    soft_ruleset_free(rs);
}

/* Test suite registration */
void test_cache_associativity_suite(void)
{
    printf("  Running cache associativity tests...\n");
    RUN_TEST(test_8way_associativity);
    RUN_TEST(test_cache_set_distribution);
    RUN_TEST(test_cache_statistics);
}

void test_cache_associativity_run(void)
{
    test_cache_associativity_suite();
}