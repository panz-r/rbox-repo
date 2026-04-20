/**
 * @file radix_tree.c
 * @brief Radix (prefix) tree for Landlock filesystem paths.
 *
 * All node and string memory is arena-allocated for performance.
 * Individual nodes are never freed — the arena is released in bulk.
 */

#define _DEFAULT_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <sys/param.h>
#include <stdbool.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include "radix_tree.h"

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

/**
 * Split an absolute path into segments (skip leading '/').
 * Returns number of segments, writes pointers into `out` (caller must
 * ensure `out` has room for at least MAX_PATH_DEPTH entries).
 * Segments are NOT null-terminated — they point into the original
 * string and length is stored in `out_lens`.
 */
static int split_path(const char *path, const char **out, int *out_lens, int max_out)
{
    int count = 0;
    const char *p = path;

    /* Skip leading slashes */
    while (*p == '/') p++;

    while (*p && count < max_out) {
        const char *start = p;
        while (*p && *p != '/') p++;
        out[count] = start;
        out_lens[count] = (int)(p - start);
        count++;
        while (*p == '/') p++;
    }
    return count;
}

/** Allocate a fresh node from the arena. */
static radix_node_t *node_new(arena_t *a, const char *seg, int seg_len)
{
    radix_node_t *n = arena_calloc(a, 1, sizeof(*n));
    if (!n) return NULL;

    /* Copy segment into arena */
    n->seg = arena_alloc(a, (size_t)seg_len + 1);
    if (!n->seg) return NULL;
    memcpy(n->seg, seg, (size_t)seg_len);
    n->seg[seg_len] = '\0';
    n->seg_len = seg_len;

    n->access_mask = 0;
    n->is_terminal = false;
    n->is_deny = false;
    n->children = NULL;      /* will point to inline_children initially */
    n->num_children = 0;
    n->cap_children = 0;     /* 0 means use inline array */

    return n;
}

/** Get the children array pointer (inline or overflow). */
static radix_node_t **children_array(radix_node_t *parent)
{
    if (parent->cap_children == 0)
        return parent->inline_children;
    return parent->children;
}

/**
 * Grow the children array.  If currently using inline, migrate to an
 * arena-allocated array.  Otherwise double the capacity.
 * Returns 0 on success, -1 on OOM.
 */
static int grow_children(arena_t *a, radix_node_t *parent)
{
    int new_cap;
    if (parent->cap_children == 0) {
        /* First time: migrate from inline to arena array of 16 slots */
        new_cap = 16;
    } else {
        new_cap = parent->cap_children * 2;
    }

    /* Use arena_calloc to zero the new entries beyond the copy range */
    radix_node_t **new_arr = arena_calloc(a, (size_t)new_cap, sizeof(radix_node_t *));
    if (!new_arr) return -1;

    /* Copy existing children */
    radix_node_t **old_arr = children_array(parent);
    memcpy(new_arr, old_arr, (size_t)parent->num_children * sizeof(radix_node_t *));

    parent->children = new_arr;
    parent->cap_children = (uint32_t)new_cap;
    return 0;
}

/** Add a child to a parent node. */
static int add_child(arena_t *a, radix_node_t *parent, radix_node_t *child)
{
    if (parent->num_children >= parent->cap_children && parent->cap_children > 0) {
        if (grow_children(a, parent) < 0) return -1;
    } else if (parent->cap_children == 0 &&
               parent->num_children >= RADIX_INLINE_CHILDREN) {
        if (grow_children(a, parent) < 0) return -1;
    }

    radix_node_t **arr = children_array(parent);
    arr[parent->num_children++] = child;
    return 0;
}

/**
 * Find a child matching the given segment (exact string match).
 * Returns index into children array, or -1.
 */
static int find_child(radix_node_t *parent, const char *seg, int seg_len)
{
    radix_node_t **arr = children_array(parent);
    for (uint32_t i = 0; i < parent->num_children; i++) {
        radix_node_t *c = arr[i];
        if (c->seg_len == seg_len &&
            memcmp(c->seg, seg, (size_t)seg_len) == 0) {
            return i;
        }
    }
    return -1;
}

/**
 * Remove child at index.  With arena allocation we CANNOT free the child
 * node or its subtree — we just compact the array.  The orphaned nodes
 * will be reclaimed when the arena is destroyed.
 */
static void remove_child_at(radix_node_t *parent, int idx)
{
    if (idx < 0 || (uint32_t)idx >= parent->num_children) return;
    /* Shift remaining children */
    radix_node_t **arr = children_array(parent);
    for (uint32_t i = (uint32_t)idx; i < parent->num_children - 1; i++) {
        arr[i] = arr[i + 1];
    }
    parent->num_children--;
}

/* ------------------------------------------------------------------ */
/*  Public tree API                                                    */
/* ------------------------------------------------------------------ */

radix_tree_t *radix_tree_new(void)
{
    radix_tree_t *tree = calloc(1, sizeof(*tree));
    if (!tree) return NULL;
    arena_init(&tree->arena);
    tree->root = node_new(&tree->arena, "", 0);
    if (!tree->root) {
        arena_free(&tree->arena);
        free(tree);
        return NULL;
    }
    tree->num_rules = 0;
    return tree;
}

void radix_tree_free(radix_tree_t *tree)
{
    if (!tree) return;
    arena_free(&tree->arena);
    free(tree);
}

int radix_tree_allow(radix_tree_t *tree, const char *path, uint64_t access)
{
    if (!tree || !path || !*path) {
        errno = EINVAL;
        return -1;
    }

    /* Make a mutable copy of the path for segmentation */
    char path_buf[PATH_MAX];
    size_t path_len = strlen(path);
    if (path_len >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(path_buf, path, path_len + 1);

    const char *segs[256];
    int seg_lens[256];
    int n_segs = split_path(path_buf, segs, seg_lens, 256);
    if (n_segs == 0) {
        /* Path is just "/" — store at root */
        bool was_terminal = tree->root->is_terminal;
        tree->root->is_terminal = true;
        tree->root->access_mask |= access;
        if (!was_terminal) tree->num_rules++;
        return 0;
    }

    radix_node_t *cur = tree->root;

    for (int i = 0; i < n_segs; i++) {
        int idx = find_child(cur, segs[i], seg_lens[i]);
        if (idx >= 0) {
            cur = children_array(cur)[idx];
        } else {
            radix_node_t *child = node_new(&tree->arena, segs[i], seg_lens[i]);
            if (!child) return -1;
            if (add_child(&tree->arena, cur, child) < 0) return -1;
            cur = child;
        }
    }

    /* Mark terminal and merge access mask */
    bool was_terminal = cur->is_terminal;
    cur->is_terminal = true;
    cur->access_mask |= access;
    cur->is_deny = false;  /* allow overrides deny flag if path reused */
    if (!was_terminal) {
        tree->num_rules++;
    }
    return 0;
}

int radix_tree_deny(radix_tree_t *tree, const char *path)
{
    if (!tree || !path || !*path) {
        errno = EINVAL;
        return -1;
    }

    char path_buf[PATH_MAX];
    size_t path_len = strlen(path);
    if (path_len >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(path_buf, path, path_len + 1);

    const char *segs[256];
    int seg_lens[256];
    int n_segs = split_path(path_buf, segs, seg_lens, 256);

    radix_node_t *cur = tree->root;

    for (int i = 0; i < n_segs; i++) {
        int idx = find_child(cur, segs[i], seg_lens[i]);
        if (idx >= 0) {
            cur = children_array(cur)[idx];
        } else {
            radix_node_t *child = node_new(&tree->arena, segs[i], seg_lens[i]);
            if (!child) return -1;
            if (add_child(&tree->arena, cur, child) < 0) return -1;
            cur = child;
        }
    }

    cur->is_deny = true;
    cur->is_terminal = true;
    cur->access_mask = 0;  /* deny has no access mask */
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Check if path is denied                                           */
/* ------------------------------------------------------------------ */

int radix_tree_is_denied(radix_tree_t *tree, const char *path)
{
    if (!tree || !tree->root || !path || !*path) return 0;

    char path_buf[PATH_MAX];
    size_t path_len = strlen(path);
    if (path_len >= PATH_MAX) return 0;
    memcpy(path_buf, path, path_len + 1);

    const char *segs[256];
    int seg_lens[256];
    int n_segs = split_path(path_buf, segs, seg_lens, 256);

    radix_node_t *cur = tree->root;
    for (int i = 0; i < n_segs; i++) {
        int idx = find_child(cur, segs[i], seg_lens[i]);
        if (idx < 0) return 0;
        cur = children_array(cur)[idx];
    }
    return cur->is_deny ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/*  Overlap removal: deny overrides allow                             */
/* ------------------------------------------------------------------ */

void radix_tree_overlap_removal(radix_tree_t *tree)
{
    if (!tree || !tree->root) return;

    /* Iterative DFS tracking deny depth */
    struct {
        radix_node_t *node;
        int deny_depth;
    } stack[4096];
    int sp = 0;

    stack[sp].node = tree->root;
    stack[sp].deny_depth = 0;
    sp++;

    while (sp > 0) {
        sp--;
        radix_node_t *cur = stack[sp].node;
        int deny_depth = stack[sp].deny_depth;

        if (cur->is_deny) deny_depth++;

        if (deny_depth > 0 && cur->is_terminal && !cur->is_deny) {
            cur->is_terminal = false;
            cur->access_mask = 0;
        }

        radix_node_t **arr = children_array(cur);
        for (int i = cur->num_children - 1; i >= 0; i--) {
            if (sp >= 4096) break;
            stack[sp].node = arr[i];
            stack[sp].deny_depth = deny_depth;
            sp++;
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Prefix simplification                                             */
/* ------------------------------------------------------------------ */

/**
 * Check if ALL terminal nodes in a subtree have access masks that are
 * subsets of `ancestor_mask`.  Returns false if any deny node is found.
 * Iterative DFS to avoid stack overflow on deep trees.
 */
static bool subtree_is_subset(const radix_node_t *root, uint64_t ancestor_mask)
{
    if (!root) return true;

    struct sis_frame {
        const radix_node_t *node;
        int child_idx;
    };
    struct sis_frame stack[4096];
    int sp = 0;

    stack[sp].node = root;
    stack[sp].child_idx = 0;
    sp++;

    while (sp > 0) {
        struct sis_frame *top = &stack[sp - 1];
        const radix_node_t *node = top->node;

        /* Deny nodes block pruning */
        if (node->is_deny) return false;

        /* If this node is terminal, check subset */
        if (node->is_terminal &&
            (node->access_mask & ~ancestor_mask) != 0) {
            return false;
        }

        /* Push children */
        if ((uint32_t)top->child_idx < node->num_children) {
            if (sp >= 4096) {
                /* Stack full — can't check deeper.  Conservative: don't prune. */
                return false;
            }
            stack[sp].node = children_array((radix_node_t *)node)[top->child_idx];
            stack[sp].child_idx = 0;
            top->child_idx++;
            sp++;
        } else {
            sp--;
        }
    }
    return true;
}

/**
 * Iterative post-order traversal: if a node's access mask is a superset
 * of ALL descendant terminal nodes' masks (and no deny exists in the
 * subtree), the children can be pruned.
 */
void radix_tree_simplify(radix_tree_t *tree)
{
    if (!tree || !tree->root) return;

    struct simplify_frame {
        radix_node_t *node;
        int child_idx;
    } stack[4096];
    int sp = 0;

    stack[sp].node = tree->root;
    stack[sp].child_idx = 0;
    sp++;

    while (sp > 0) {
        struct simplify_frame *top = &stack[sp - 1];
        radix_node_t *node = top->node;

        if ((uint32_t)top->child_idx < node->num_children) {
            if (sp >= 4096) {
                top->child_idx = node->num_children;
                continue;
            }
            stack[sp].node = children_array(node)[top->child_idx];
            stack[sp].child_idx = 0;
            top->child_idx++;
            sp++;
            continue;
        }

        /* All children processed — post-order visit */
        sp--;

        if (!node->is_terminal || node->access_mask == 0) continue;
        if (node->is_deny) continue;

        /* Check each child */
        radix_node_t **arr = children_array(node);
        for (int i = node->num_children - 1; i >= 0; i--) {
            radix_node_t *child = arr[i];

            if (child->is_deny) continue;
            if (!child->is_terminal) continue;
            if ((child->access_mask & ~node->access_mask) != 0) continue;

            /* Deep check: all terminals in child's subtree must be
             * subsets of node->access_mask */
            if (!subtree_is_subset(child, node->access_mask)) continue;

            /* Prune child and its entire subtree */
            remove_child_at(node, i);
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Rule collection                                                     */
/* ------------------------------------------------------------------ */

void radix_tree_collect_rules(radix_tree_t *tree,
                              landlock_rule_t **out_rules,
                              size_t *out_count)
{
    if (!tree || !tree->root || !out_rules || !out_count) return;

    /* Pre-allocate */
    size_t cap = tree->num_rules > 0 ? tree->num_rules : 16;
    *out_rules = calloc(cap, sizeof(landlock_rule_t));
    if (!*out_rules) {
        *out_count = 0;
        return;
    }
    *out_count = 0;

    /* DFS with path reconstruction */
    struct {
        radix_node_t *node;
        int depth;
    } stack[4096];

    /* We'll reconstruct paths by keeping a segment stack */
    const char *seg_stack[256];
    int seg_len_stack[256];

    int sp = 0;
    stack[sp].node = tree->root;
    stack[sp].depth = 0;
    sp++;

    while (sp > 0) {
        sp--;
        radix_node_t *cur = stack[sp].node;
        int depth = stack[sp].depth;

        if (cur != tree->root) {
            seg_stack[depth - 1] = cur->seg;
            seg_len_stack[depth - 1] = cur->seg_len;
        }

        if (cur->is_terminal && !cur->is_deny && cur->access_mask != 0) {
            /* Build the full path */
            char full_path[PATH_MAX];
            int pos = 0;
            for (int i = 0; i < depth; i++) {
                if (pos + 1 + seg_len_stack[i] >= PATH_MAX) break;
                full_path[pos++] = '/';
                memcpy(full_path + pos, seg_stack[i], (size_t)seg_len_stack[i]);
                pos += seg_len_stack[i];
            }
            if (pos == 0) {
                full_path[0] = '/';
                full_path[1] = '\0';
                pos = 1;
            } else {
                full_path[pos] = '\0';
            }

            /* Grow output if needed */
            if (*out_count >= cap) {
                cap *= 2;
                landlock_rule_t *tmp = realloc(*out_rules,
                                               cap * sizeof(landlock_rule_t));
                if (!tmp) break;
                *out_rules = tmp;
            }

            (*out_rules)[*out_count].path = strdup(full_path);
            (*out_rules)[*out_count].access = cur->access_mask;
            (*out_count)++;
        }

        /* Push children in reverse order so they come out forward */
        radix_node_t **arr = children_array(cur);
        for (int i = cur->num_children - 1; i >= 0; i--) {
            if (sp >= 4096) break;
            stack[sp].node = arr[i];
            stack[sp].depth = depth + 1;
            sp++;
        }
    }
}

size_t radix_tree_arena_usage(const radix_tree_t *tree)
{
    if (!tree) return 0;
    return arena_usage(&tree->arena);
}
