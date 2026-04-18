/**
 * @file radix_tree.c
 * @brief Radix (prefix) tree for Landlock filesystem paths.
 *
 * All node and string memory is arena-allocated for performance.
 * Children are stored in a sorted array for binary search.
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

/** Maximum number of path segments supported (configurable at compile time) */
#define MAX_PATH_SEGMENTS 512

#include "radix_tree.h"

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

static inline bool node_is_terminal(const radix_node_t *n) { return n->flags & RADIX_F_TERMINAL; }
static inline bool node_is_deny(const radix_node_t *n)     { return n->flags & RADIX_F_DENY; }
static inline void node_set_terminal(radix_node_t *n)      { n->flags |= RADIX_F_TERMINAL; }
static inline void node_set_deny(radix_node_t *n)          { n->flags |= RADIX_F_DENY; }

/**
 * Split an absolute path into segments (skip leading '/').
 * Returns number of segments.
 */
static int split_path(const char *path, const char **out, int *out_lens, int max_out)
{
    int count = 0;
    const char *p = path;
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
    n->seg = arena_alloc(a, (size_t)seg_len + 1);
    if (!n->seg) return NULL;
    memcpy(n->seg, seg, (size_t)seg_len);
    n->seg[seg_len] = '\0';
    n->seg_len = (uint32_t)seg_len;
    n->children = NULL;
    n->num_children = 0;
    n->cap_children = 0;
    n->flags = 0;
    return n;
}

/** Get the children array pointer (NULL if none). */
static inline radix_node_t **children_array(radix_node_t *parent)
{
    return parent->children;
}

/**
 * Binary search for a child by segment.  Children are kept sorted by
 * segment string for O(log n) lookup.
 */
static int find_child(radix_node_t *parent, const char *seg, int seg_len)
{
    if (parent->num_children == 0) return -1;
    radix_node_t **arr = parent->children;
    int lo = 0, hi = parent->num_children - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        radix_node_t *c = arr[mid];
        int cmp;
        if (c->seg_len == (uint32_t)seg_len)
            cmp = memcmp(c->seg, seg, (size_t)seg_len);
        else
            cmp = (c->seg_len < (uint32_t)seg_len) ? -1 : 1;
        if (cmp == 0) return mid;
        if (cmp < 0) lo = mid + 1;
        else hi = mid - 1;
    }
    return -1;
}

/**
 * Insert a child into the sorted children array at the correct position.
 * Returns the index where the child was inserted.
 */
static int insert_child_sorted(arena_t *a, radix_node_t *parent, radix_node_t *child)
{
    /* Grow if needed */
    if (parent->num_children >= parent->cap_children) {
        int new_cap = parent->cap_children == 0 ? 16 : parent->cap_children * 2;
        radix_node_t **new_arr = arena_calloc(a, (size_t)new_cap, sizeof(radix_node_t *));
        if (!new_arr) return -1;
        if (parent->cap_children > 0) {
            memcpy(new_arr, parent->children,
                   (size_t)parent->num_children * sizeof(radix_node_t *));
        }
        parent->children = new_arr;
        parent->cap_children = (uint16_t)new_cap;
    }

    /* Find insertion position via binary search */
    radix_node_t **arr = parent->children;
    int lo = 0, hi = parent->num_children - 1;
    int pos = parent->num_children;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        int cmp;
        if (arr[mid]->seg_len == child->seg_len)
            cmp = memcmp(arr[mid]->seg, child->seg, (size_t)child->seg_len);
        else
            cmp = (arr[mid]->seg_len < child->seg_len) ? -1 : 1;
        if (cmp < 0) lo = mid + 1;
        else { hi = mid - 1; pos = mid; }
    }

    /* Shift right to make room */
    for (int i = parent->num_children; i > pos; i--) {
        arr[i] = arr[i - 1];
    }
    arr[pos] = child;
    parent->num_children++;
    return pos;
}

/** Remove child at index by compacting the array. */
static void remove_child_at(radix_node_t *parent, int idx)
{
    if (idx < 0 || idx >= parent->num_children) return;
    radix_node_t **arr = parent->children;
    for (int i = idx; i < parent->num_children - 1; i++) {
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
    if (!tree || !path || !*path) { errno = EINVAL; return -1; }

    char path_buf[PATH_MAX];
    size_t path_len = strlen(path);
    if (path_len >= PATH_MAX) { errno = ENAMETOOLONG; return -1; }
    memcpy(path_buf, path, path_len + 1);

    const char *segs[MAX_PATH_SEGMENTS];
    int seg_lens[MAX_PATH_SEGMENTS];
    int n_segs = split_path(path_buf, segs, seg_lens, MAX_PATH_SEGMENTS);
    if (n_segs == 0) {
        bool was = node_is_terminal(tree->root);
        node_set_terminal(tree->root);
        tree->root->access_mask |= access;
        if (!was) tree->num_rules++;
        return 0;
    }

    radix_node_t *cur = tree->root;
    for (int i = 0; i < n_segs; i++) {
        int idx = find_child(cur, segs[i], seg_lens[i]);
        if (idx >= 0) {
            cur = cur->children[idx];
        } else {
            radix_node_t *child = node_new(&tree->arena, segs[i], seg_lens[i]);
            if (!child) return -1;
            if (insert_child_sorted(&tree->arena, cur, child) < 0) return -1;
            cur = child;
        }
    }

    bool was = node_is_terminal(cur);
    node_set_terminal(cur);
    cur->access_mask |= access;
    cur->flags = (uint16_t)(cur->flags & ~RADIX_F_DENY);
    if (!was) tree->num_rules++;
    return 0;
}

int radix_tree_deny(radix_tree_t *tree, const char *path)
{
    if (!tree || !path || !*path) { errno = EINVAL; return -1; }

    char path_buf[PATH_MAX];
    size_t path_len = strlen(path);
    if (path_len >= PATH_MAX) { errno = ENAMETOOLONG; return -1; }
    memcpy(path_buf, path, path_len + 1);

    const char *segs[MAX_PATH_SEGMENTS];
    int seg_lens[MAX_PATH_SEGMENTS];
    int n_segs = split_path(path_buf, segs, seg_lens, MAX_PATH_SEGMENTS);

    radix_node_t *cur = tree->root;
    for (int i = 0; i < n_segs; i++) {
        int idx = find_child(cur, segs[i], seg_lens[i]);
        if (idx >= 0) {
            cur = cur->children[idx];
        } else {
            radix_node_t *child = node_new(&tree->arena, segs[i], seg_lens[i]);
            if (!child) return -1;
            if (insert_child_sorted(&tree->arena, cur, child) < 0) return -1;
            cur = child;
        }
    }

    node_set_deny(cur);
    node_set_terminal(cur);
    cur->access_mask = 0;
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
    const char *segs[MAX_PATH_SEGMENTS];
    int seg_lens[MAX_PATH_SEGMENTS];
    int n_segs = split_path(path_buf, segs, seg_lens, MAX_PATH_SEGMENTS);
    radix_node_t *cur = tree->root;
    for (int i = 0; i < n_segs; i++) {
        int idx = find_child(cur, segs[i], seg_lens[i]);
        if (idx < 0) return 0;
        cur = cur->children[idx];
    }
    return node_is_deny(cur) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/*  Overlap removal: deny overrides allow                             */
/* ------------------------------------------------------------------ */

void radix_tree_overlap_removal(radix_tree_t *tree)
{
    if (!tree || !tree->root) return;
    struct { radix_node_t *node; int deny_depth; } stack[4096];
    int sp = 0;
    stack[sp].node = tree->root;
    stack[sp].deny_depth = 0;
    sp++;
    while (sp > 0) {
        sp--;
        radix_node_t *cur = stack[sp].node;
        int deny_depth = stack[sp].deny_depth;
        if (node_is_deny(cur)) deny_depth++;
        if (deny_depth > 0 && node_is_terminal(cur) && !node_is_deny(cur)) {
            cur->flags = (uint16_t)(cur->flags & ~RADIX_F_TERMINAL);
            cur->access_mask = 0;
        }
        for (int i = cur->num_children - 1; i >= 0; i--) {
            if (sp >= 4096) break;
            stack[sp].node = cur->children[i];
            stack[sp].deny_depth = deny_depth;
            sp++;
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Prefix simplification                                             */
/* ------------------------------------------------------------------ */

static bool subtree_is_subset(const radix_node_t *root, uint64_t ancestor_mask)
{
    if (!root) return true;
    struct sis_frame { const radix_node_t *node; int child_idx; };
    struct sis_frame stack[4096];
    int sp = 0;
    stack[sp].node = root;
    stack[sp].child_idx = 0;
    sp++;
    while (sp > 0) {
        struct sis_frame *top = &stack[sp - 1];
        const radix_node_t *node = top->node;
        if (node_is_deny(node)) return false;
        if (node_is_terminal(node) && (node->access_mask & ~ancestor_mask) != 0)
            return false;
        if (top->child_idx < node->num_children) {
            if (sp >= 4096) return false;
            stack[sp].node = node->children[top->child_idx];
            stack[sp].child_idx = 0;
            top->child_idx++;
            sp++;
        } else {
            sp--;
        }
    }
    return true;
}

void radix_tree_simplify(radix_tree_t *tree)
{
    if (!tree || !tree->root) return;
    struct simplify_frame { radix_node_t *node; int child_idx; } stack[4096];
    int sp = 0;
    size_t pruned = 0;
    stack[sp].node = tree->root;
    stack[sp].child_idx = 0;
    sp++;
    while (sp > 0) {
        struct simplify_frame *top = &stack[sp - 1];
        radix_node_t *node = top->node;
        if (top->child_idx < node->num_children) {
            if (sp >= 4096) { top->child_idx = node->num_children; continue; }
            stack[sp].node = node->children[top->child_idx];
            stack[sp].child_idx = 0;
            top->child_idx++;
            sp++;
            continue;
        }
        sp--;
        if (!node_is_terminal(node) || node->access_mask == 0) continue;
        if (node_is_deny(node)) continue;
        for (int i = node->num_children - 1; i >= 0; i--) {
            radix_node_t *child = node->children[i];
            if (node_is_deny(child)) continue;
            if (!node_is_terminal(child)) continue;
            if ((child->access_mask & ~node->access_mask) != 0) continue;
            if (!subtree_is_subset(child, node->access_mask)) continue;
            /* Count terminals before pruning */
            struct { radix_node_t *n; } cq[4096];
            int cq_sp = 0;
            cq[cq_sp].n = child;
            cq_sp++;
            while (cq_sp > 0) {
                cq_sp--;
                radix_node_t *cn = cq[cq_sp].n;
                if (node_is_terminal(cn) && !node_is_deny(cn)) pruned++;
                for (int j = 0; j < cn->num_children && cq_sp < 4096; j++) {
                    cq[cq_sp].n = cn->children[j];
                    cq_sp++;
                }
            }
            remove_child_at(node, i);
        }
    }
    if (pruned > tree->num_rules) pruned = tree->num_rules;
    tree->num_rules -= pruned;
}

/* ------------------------------------------------------------------ */
/*  Rule collection                                                     */
/* ------------------------------------------------------------------ */

void radix_tree_collect_rules(radix_tree_t *tree,
                              landlock_rule_t **out_rules,
                              size_t *out_count)
{
    if (!tree || !tree->root || !out_rules || !out_count) return;

    size_t cap = tree->num_rules > 0 ? tree->num_rules : 16;
    *out_rules = calloc(cap, sizeof(landlock_rule_t));
    if (!*out_rules) { *out_count = 0; return; }
    *out_count = 0;

    struct { radix_node_t *node; int depth; } stack[4096];
    const char *seg_stack[MAX_PATH_SEGMENTS];
    int seg_len_stack[MAX_PATH_SEGMENTS];

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
            seg_len_stack[depth - 1] = (int)cur->seg_len;
        }

        if (node_is_terminal(cur) && !node_is_deny(cur) && cur->access_mask != 0) {
            char full_path[PATH_MAX];
            int pos = 0;
            for (int i = 0; i < depth; i++) {
                if (pos + 1 + seg_len_stack[i] >= PATH_MAX) break;
                full_path[pos++] = '/';
                memcpy(full_path + pos, seg_stack[i], (size_t)seg_len_stack[i]);
                pos += seg_len_stack[i];
            }
            if (pos == 0) { full_path[0] = '/'; full_path[1] = '\0'; pos = 1; }
            else full_path[pos] = '\0';

            if (*out_count >= cap) {
                cap *= 2;
                landlock_rule_t *tmp = realloc(*out_rules, cap * sizeof(landlock_rule_t));
                if (!tmp) break;
                *out_rules = tmp;
            }
            (*out_rules)[*out_count].path = strdup(full_path);
            (*out_rules)[*out_count].access = cur->access_mask;
            (*out_count)++;
        }

        for (int i = cur->num_children - 1; i >= 0; i--) {
            if (sp >= 4096) break;
            stack[sp].node = cur->children[i];
            stack[sp].depth = depth + 1;
            sp++;
        }
    }
}

size_t radix_tree_arena_usage(const radix_tree_t *tree)
{
    return tree ? arena_usage(&tree->arena) : 0;
}
