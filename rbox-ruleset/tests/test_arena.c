/**
 * @file test_arena.c
 * @brief Unit tests for the arena allocator.
 */

#include "test_framework.h"
#include "arena.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/*  Basic allocation, zero alloc, strdup                               */
/* ------------------------------------------------------------------ */

static void test_arena_simple_alloc(void)
{
    arena_t a;

    /* Case 1: Basic allocations return distinct pointers */
    arena_init(&a);
    void *p1 = arena_alloc(&a, 64);
    TEST_ASSERT_NOT_NULL(p1, "basic: 64-byte alloc succeeds");
    void *p2 = arena_alloc(&a, 128);
    TEST_ASSERT_NOT_NULL(p2, "basic: 128-byte alloc succeeds");
    TEST_ASSERT(p1 != p2, "basic: two allocs return different pointers");
    arena_free(&a);

    /* Case 2: alloc(0) returns NULL */
    arena_init(&a);
    void *p3 = arena_alloc(&a, 0);
    TEST_ASSERT(p3 == NULL, "basic: alloc(0) returns NULL");
    arena_free(&a);

    /* Case 3: strdup duplicates string */
    arena_init(&a);
    const char *s = "hello, world!";
    char *d = arena_strdup(&a, s);
    TEST_ASSERT_NOT_NULL(d, "basic: strdup succeeds");
    TEST_ASSERT_STR_EQ(d, s, "basic: strdup content matches");
    arena_free(&a);
}

/* ------------------------------------------------------------------ */
/*  calloc: overflow guard + zeroed memory                            */
/* ------------------------------------------------------------------ */

static void test_arena_calloc(void)
{
    arena_t a;
    uint64_t *p;

    /* Case 1: Overflow guard — nmemb * size wraps */
    arena_init(&a);
    void *p1 = arena_calloc(&a, SIZE_MAX, 2);
    TEST_ASSERT(p1 == NULL, "calloc: overflow returns NULL");
    arena_free(&a);

    /* Case 2: Valid calloc returns zeroed memory */
    arena_init(&a);
    p = arena_calloc(&a, 10, sizeof(uint64_t));
    TEST_ASSERT_NOT_NULL(p, "calloc: succeeds");
    for (int i = 0; i < 10; i++) {
        TEST_ASSERT_EQ(p[i], 0, "calloc: zeroed memory");
    }
    arena_free(&a);
}

/* ------------------------------------------------------------------ */
/*  Alignment                                                          */
/* ------------------------------------------------------------------ */

static void test_arena_alignment(void)
{
    arena_t a;
    arena_init(&a);

    for (int i = 0; i < 100; i++) {
        void *p = arena_alloc(&a, (size_t)(i + 1));
        TEST_ASSERT_NOT_NULL(p, "align: alloc succeeds");
        TEST_ASSERT_EQ((uintptr_t)p % ARENA_ALIGN, 0,
                       "align: pointer is ARENA_ALIGN-aligned");
    }

    arena_free(&a);
}

/* ------------------------------------------------------------------ */
/*  Multi-block allocation                                             */
/* ------------------------------------------------------------------ */

static void test_arena_multi_block(void)
{
    arena_t a;
    arena_init(&a);

    /* Allocate enough to overflow a single 256 KB block */
    size_t total = 0;
    int count = 0;
    while (total < 512 * 1024) {
        void *p = arena_alloc(&a, 32 * 1024);  /* 32 KB chunks */
        if (!p) break;
        total += 32 * 1024;
        count++;
    }

    TEST_ASSERT(count >= 16, "multi-block: at least 16 allocations (512 KB)");

    /* Check that usage is approximately correct */
    size_t usage = arena_usage(&a);
    TEST_ASSERT(usage >= 512 * 1024, "multi-block: usage >= 512 KB");

    arena_free(&a);
}

/* ------------------------------------------------------------------ */
/*  Free and re-use                                                    */
/* ------------------------------------------------------------------ */

static void test_arena_free_and_reuse(void)
{
    arena_t a;
    arena_init(&a);

    arena_alloc(&a, 1024);
    size_t usage_before = arena_usage(&a);
    TEST_ASSERT(usage_before > 0, "usage > 0 before free");

    arena_free(&a);
    TEST_ASSERT_EQ(arena_usage(&a), 0, "usage == 0 after free");

    /* Re-use after free */
    void *p = arena_alloc(&a, 64);
    TEST_ASSERT_NOT_NULL(p, "alloc after free+reinit succeeds");

    arena_free(&a);
}

/* ------------------------------------------------------------------ */
/*  Runner                                                             */
/* ------------------------------------------------------------------ */

void test_arena_run(void)
{
    printf("=== Arena Allocator Tests ===\n");
    RUN_TEST(test_arena_simple_alloc);
    RUN_TEST(test_arena_calloc);
    RUN_TEST(test_arena_alignment);
    RUN_TEST(test_arena_multi_block);
    RUN_TEST(test_arena_free_and_reuse);
}
