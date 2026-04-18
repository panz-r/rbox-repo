/**
 * @file benchmark.c
 * @brief Performance benchmarks for the radix tree and builder.
 */

#include "mock_fs.h"
#include "landlock_builder.h"
#include "../src/radix_tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

static double now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

#define NUM_PATHS 100000

int main(void)
{
    printf("========================================\n");
    printf("  liblandlock-builder — Benchmarks\n");
    printf("========================================\n\n");

    /* ---- Benchmark 1: Raw radix tree insertion (diverse paths) ---- */
    printf("[1] Radix tree: inserting %d diverse paths...\n", NUM_PATHS);
    double t0 = now_ms();

    radix_tree_t *tree = radix_tree_new();
    for (int i = 0; i < NUM_PATHS; i++) {
        char path[256];
        /* Create diverse paths with multiple prefixes */
        int prefix = i % 100;
        int mid = (i / 100) % 100;
        int leaf = i / 10000;
        snprintf(path, sizeof(path), "/prefix%03d/mid%02d/leaf%d", prefix, mid, leaf);
        radix_tree_allow(tree, path, 7);
    }
    double t1 = now_ms();
    printf("    Insertion time: %.2f ms (%.0f paths/sec)\n",
           t1 - t0, NUM_PATHS / ((t1 - t0) / 1000.0));

    /* Count rules */
    landlock_rule_t *rules = NULL;
    size_t count = 0;
    radix_tree_collect_rules(tree, &rules, &count);
    printf("    Rules collected: %zu\n", count);

    /* Simplify and re-count */
    radix_tree_simplify(tree);
    landlock_rule_t *rules2 = NULL;
    size_t count2 = 0;
    radix_tree_collect_rules(tree, &rules2, &count2);
    printf("    Rules after simplify: %zu\n", count2);
    printf("    Arena usage: %.1f MB\n", radix_tree_arena_usage(tree) / 1048576.0);

    for (size_t i = 0; i < count; i++) free((void *)rules[i].path);
    free(rules);
    for (size_t i = 0; i < count2; i++) free((void *)rules2[i].path);
    free(rules2);
    radix_tree_free(tree);

    /* ---- Benchmark 2: Builder with mock fs ---- */
    printf("\n[2] Builder: %d paths with mock fs...\n", NUM_PATHS / 10);
    int n = NUM_PATHS / 10;
    mock_fs_reset();

    for (int i = 0; i < n; i++) {
        char path[256];
        snprintf(path, sizeof(path), "/bench/dir%d", i);
        mock_fs_create_dir(path);
    }

    double t2 = now_ms();
    landlock_builder_t *b = landlock_builder_new();
    for (int i = 0; i < n; i++) {
        char path[256];
        snprintf(path, sizeof(path), "/bench/dir%d", i);
        landlock_builder_allow(b, path, 7);
    }
    landlock_builder_prepare(b, 2, false);
    double t3 = now_ms();

    size_t rule_count = 0;
    landlock_builder_get_rules(b, &rule_count);
    printf("    Build + prepare time: %.2f ms\n", t3 - t2);
    printf("    Final rules: %zu\n", rule_count);

    landlock_builder_free(b);

    /* ---- Benchmark 3: Simplification with deep nesting ---- */
    printf("\n[3] Simplification: deep tree (10 levels x 1000 branches)...\n");
    tree = radix_tree_new();

    double t4 = now_ms();
    for (int b_idx = 0; b_idx < 1000; b_idx++) {
        char path[256];
        snprintf(path, sizeof(path), "/root/b%d/l1/l2/l3/l4/l5/l6/l7/l8/l9",
                 b_idx);
        radix_tree_allow(tree, path, 7);
    }
    radix_tree_allow(tree, "/root", 7);
    double t5 = now_ms();
    printf("    Insertion: %.2f ms\n", t5 - t4);

    radix_tree_simplify(tree);
    double t6 = now_ms();
    printf("    Simplification: %.2f ms\n", t6 - t5);

    landlock_rule_t *srules = NULL;
    size_t scount = 0;
    radix_tree_collect_rules(tree, &srules, &scount);
    printf("    Rules after simplify: %zu (expected: 1 — /root)\n", scount);

    for (size_t i = 0; i < scount; i++) free((void *)srules[i].path);
    free(srules);
    radix_tree_free(tree);

    printf("\n========================================\n");
    printf("  Benchmarks complete\n");
    printf("========================================\n");

    return 0;
}
