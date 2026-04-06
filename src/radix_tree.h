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

/** A single node in the radix tree.
 *
 * Memory layout (40 bytes on 64-bit, vs 112 before):
 *   seg             8  pointer to arena-allocated segment string
 *   access_mask     8  OR'd access rights if terminal
 *   seg_len         4  strlen of segment
 *   num_children    2  current child count (max 65535)
 *   cap_children    2  capacity of children[] (0 = no array yet)
 *   children        8  arena-allocated child pointer array (NULL until grown)
 *   flags           2  bit 0 = is_terminal, bit 1 = is_deny
 *   --- padding ---  6  struct alignment to 8
 *
 * Children are stored sorted by segment pointer for binary search.
 * This avoids the 64-byte inline_children[] array that wasted space
 * on every node (most filesystem nodes have 1-3 children).
 */
typedef struct radix_node {
    char             *seg;          /* Arena-owned null-terminated segment */
    uint64_t         access_mask;   /* OR'd access rights if terminal */
    uint32_t         seg_len;       /* Length of segment */
    uint16_t         num_children;  /* Current child count */
    uint16_t         cap_children;  /* Capacity of children[] (0 = none) */
    struct radix_node **children;   /* Arena-allocated sorted array, or NULL */
    uint16_t         flags;         /* Bit 0 = terminal, bit 1 = deny */
} radix_node_t;

/* Flag bits */
#define RADIX_F_TERMINAL 0x01
#define RADIX_F_DENY     0x02

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
