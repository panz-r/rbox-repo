/**
 * @file radix_tree.h
 * @brief Internal radix tree definitions.
 */

#ifndef RADIX_TREE_H
#define RADIX_TREE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "landlock_builder.h"
#include "arena.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Inline child capacity — avoids malloc for the common case (≤8 children). */
#define RADIX_INLINE_CHILDREN 8

/** A single node in the radix tree. */
typedef struct radix_node {
    char            *seg;           /* Path segment (arena-owned, null-terminated). */
    int              seg_len;       /* Length of segment (strlen). */
    uint64_t         access_mask;   /* OR'd access rights if terminal. */
    bool             is_terminal;   /* True if an allow/deny was set here. */
    bool             is_deny;       /* True if this node is a deny rule. */
    struct radix_node *inline_children[RADIX_INLINE_CHILDREN];
    struct radix_node **children;   /* If > INLINE, points to arena-allocated array. */
    uint32_t           num_children;
    uint32_t           cap_children;  /* Capacity of `children` (0 = use inline). */
} radix_node_t;

/** The radix tree, rooted at an implicit empty-segment node. */
typedef struct radix_tree {
    radix_node_t *root;
    arena_t       arena;           /* Bump allocator for all nodes/strings. */
    size_t        num_rules;       /* Count of terminal allow nodes. */
} radix_tree_t;

/* Internal API */
radix_tree_t *radix_tree_new(void);
void          radix_tree_free(radix_tree_t *tree);
int           radix_tree_allow(radix_tree_t *tree, const char *path, uint64_t access);
int           radix_tree_deny(radix_tree_t *tree, const char *path);
int           radix_tree_is_denied(radix_tree_t *tree, const char *path);
void          radix_tree_overlap_removal(radix_tree_t *tree);
void          radix_tree_simplify(radix_tree_t *tree);
void          radix_tree_collect_rules(radix_tree_t *tree,
                                       landlock_rule_t **out_rules,
                                       size_t *out_count);
/* Query memory usage */
size_t        radix_tree_arena_usage(const radix_tree_t *tree);

#ifdef __cplusplus
}
#endif

#endif /* RADIX_TREE_H */
