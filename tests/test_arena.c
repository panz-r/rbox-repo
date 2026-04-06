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
/*  Basic allocation                                                  */
/* ------------------------------------------------------------------ */

static void test_arena_basic_alloc(void)
{
    arena_t a;
    arena_init(&a);

    void *p1 = arena_alloc(&a, 64);
    TEST_ASSERT_NOT_NULL(p1, "64-byte alloc succeeds");

    void *p2 = arena_alloc(&a, 128);
    TEST_ASSERT_NOT_NULL(p2, "128-byte alloc succeeds");
    TEST_ASSERT(p1 != p2, "two allocs return different pointers");

    arena_free(&a);
}

static void test_arena_alignment(void)
{
    arena_t a;
    arena_init(&a);

    /* Allocate various sizes and check alignment */
    for (int i = 0; i < 100; i++) {
        void *p = arena_alloc(&a, (size_t)(i + 1));
        TEST_ASSERT_NOT_NULL(p, "alloc succeeds");
        TEST_ASSERT_EQ((uintptr_t)p % ARENA_ALIGN, 0,
                       "pointer is ARENA_ALIGN-aligned");
    }

    arena_free(&a);
}

static void test_arena_zero_alloc(void)
{
    arena_t a;
    arena_init(&a);

    void *p = arena_alloc(&a, 0);
    TEST_ASSERT(p == NULL, "alloc(0) returns NULL");

    arena_free(&a);
}

/* ------------------------------------------------------------------ */
/*  calloc overflow guard                                             */
/* ------------------------------------------------------------------ */

static void test_arena_calloc_overflow(void)
{
    arena_t a;
    arena_init(&a);

    /* Trigger overflow: nmemb * size would wrap */
    void *p = arena_calloc(&a, SIZE_MAX, 2);
    TEST_ASSERT(p == NULL, "calloc overflow returns NULL");

    arena_free(&a);
}

static void test_arena_calloc_zeroes(void)
{
    arena_t a;
    arena_init(&a);

    uint64_t *p = arena_calloc(&a, 10, sizeof(uint64_t));
    TEST_ASSERT_NOT_NULL(p, "calloc succeeds");

    for (int i = 0; i < 10; i++) {
        TEST_ASSERT_EQ(p[i], 0, "calloc zeroed memory");
    }

    arena_free(&a);
}

/* ------------------------------------------------------------------ */
/*  strdup / memdup                                                    */
/* ------------------------------------------------------------------ */

static void test_arena_strdup(void)
{
    arena_t a;
    arena_init(&a);

    const char *s = "hello, world!";
    char *d = arena_strdup(&a, s);
    TEST_ASSERT_NOT_NULL(d, "strdup succeeds");
    TEST_ASSERT_STR_EQ(d, s, "strdup content matches");

    arena_free(&a);
}

static void test_arena_strdup_empty(void)
{
    arena_t a;
    arena_init(&a);

    char *d = arena_strdup(&a, "");
    TEST_ASSERT_NOT_NULL(d, "strdup empty string succeeds");
    TEST_ASSERT_EQ(strlen(d), 0, "strdup empty string length");

    arena_free(&a);
}

static void test_arena_memdup(void)
{
    arena_t a;
    arena_init(&a);

    uint8_t src[] = {0xDE, 0xAD, 0xBE, 0xEF};
    void *d = arena_memdup(&a, src, sizeof(src));
    TEST_ASSERT_NOT_NULL(d, "memdup succeeds");
    TEST_ASSERT(memcmp(d, src, sizeof(src)) == 0, "memdup content matches");

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
/*  arena_usage                                                        */
/* ------------------------------------------------------------------ */

static void test_arena_usage(void)
{
    arena_t a;
    arena_init(&a);

    TEST_ASSERT_EQ(arena_usage(&a), 0, "initial usage is 0");

    arena_alloc(&a, 100);
    /* After alignment: 100 rounded up to 16 = 112 */
    TEST_ASSERT(arena_usage(&a) >= 100, "usage >= allocation");

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
    RUN_TEST(test_arena_basic_alloc);
    RUN_TEST(test_arena_alignment);
    RUN_TEST(test_arena_zero_alloc);
    RUN_TEST(test_arena_calloc_overflow);
    RUN_TEST(test_arena_calloc_zeroes);
    RUN_TEST(test_arena_strdup);
    RUN_TEST(test_arena_strdup_empty);
    RUN_TEST(test_arena_memdup);
    RUN_TEST(test_arena_multi_block);
    RUN_TEST(test_arena_usage);
    RUN_TEST(test_arena_free_and_reuse);
}
