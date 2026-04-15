/**
 * @file rule_engine_diff.c
 * @brief Ruleset diff: compare two rulesets and report changes.
 *
 * Compares rules layer by layer, detecting added, removed, modified,
 * and unchanged rules.
 */

#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "rule_engine.h"
#include "rule_engine_internal.h"

#define DIFF_INIT_CHUNK 128

/** Check if two rules are identical in all attributes. */
static bool rules_equal(const rule_t *a, const rule_t *b)
{
    return strcmp(a->pattern, b->pattern) == 0 &&
           a->mode == b->mode &&
           a->op_type == b->op_type &&
           strcmp(a->linked_path_var, b->linked_path_var) == 0 &&
           strcmp(a->subject_regex, b->subject_regex) == 0 &&
           a->flags == b->flags;
}

/** Check if two rules have the same pattern+op (for modification detection). */
static bool rules_same_pattern(const rule_t *a, const rule_t *b)
{
    return strcmp(a->pattern, b->pattern) == 0 &&
           a->op_type == b->op_type;
}

/** Ensure diff array has capacity. */
static int diff_ensure_cap(soft_ruleset_diff_t *diff)
{
    if (diff->count < diff->capacity) return 0;

    int new_cap = diff->capacity + DIFF_INIT_CHUNK;
    if (new_cap < 0) return -1;

    soft_rule_diff_t *new_arr = realloc(diff->changes,
                                        (size_t)new_cap * sizeof(soft_rule_diff_t));
    if (!new_arr) return -1;

    diff->changes = new_arr;
    diff->capacity = new_cap;
    return 0;
}

/** Add a diff entry to the report. */
static int diff_add(soft_ruleset_diff_t *diff,
                    soft_diff_type_t type,
                    int layer_a,
                    int layer_b,
                    soft_rule_info_t *info_a,
                    soft_rule_info_t *info_b)
{
    if (diff_ensure_cap(diff) < 0) return -1;

    soft_rule_diff_t *entry = &diff->changes[diff->count];
    entry->type = type;
    entry->layer_a = layer_a;
    entry->layer_b = layer_b;

    /* Store rule info by allocating a copy */
    if (info_a) {
        soft_rule_info_t *copy = malloc(sizeof(*copy));
        if (!copy) return -1;
        *copy = *info_a;
        entry->rule_a = copy;
    } else {
        entry->rule_a = NULL;
    }

    if (info_b) {
        soft_rule_info_t *copy = malloc(sizeof(*copy));
        if (!copy) {
            free((void *)entry->rule_a);
            return -1;
        }
        *copy = *info_b;
        entry->rule_b = copy;
    } else {
        entry->rule_b = NULL;
    }

    diff->count++;

    switch (type) {
    case DIFF_RULE_ADDED:     diff->added++;     break;
    case DIFF_RULE_REMOVED:   diff->removed++;   break;
    case DIFF_RULE_MODIFIED:  diff->modified++;  break;
    case DIFF_RULE_UNCHANGED: diff->unchanged++; break;
    }

    return 0;
}

int soft_ruleset_diff(const soft_ruleset_t *a,
                      const soft_ruleset_t *b,
                      soft_ruleset_diff_t *out)
{
    if (!out) { errno = EINVAL; return -1; }

    memset(out, 0, sizeof(*out));

    /* Handle NULL rulesets as empty */
    if (!a && !b) return 0;

    /* Determine max layer count */
    int max_layers = 0;
    if (a) max_layers = a->layer_count;
    if (b && b->layer_count > max_layers) max_layers = b->layer_count;
    if (max_layers == 0) return 0;

    for (int layer = 0; layer < max_layers; layer++) {
        const layer_t *lyr_a = (a && layer < a->layer_count) ? &a->layers[layer] : NULL;
        const layer_t *lyr_b = (b && layer < b->layer_count) ? &b->layers[layer] : NULL;

        int count_a = lyr_a ? lyr_a->count : 0;
        int count_b = lyr_b ? lyr_b->count : 0;

        /* If layer exists in A but not B: all rules removed */
        if (lyr_a && !lyr_b) {
            for (int i = 0; i < count_a; i++) {
                soft_rule_info_t info;
                info.pattern = lyr_a->rules[i].pattern;
                info.mode = lyr_a->rules[i].mode;
                info.op_type = lyr_a->rules[i].op_type;
                info.linked_path_var = (lyr_a->rules[i].linked_path_var[0] != '\0') ? lyr_a->rules[i].linked_path_var : NULL;
                info.subject_regex = (lyr_a->rules[i].subject_regex[0] != '\0') ? lyr_a->rules[i].subject_regex : NULL;
                info.flags = lyr_a->rules[i].flags;
                info.layer = layer;

                if (diff_add(out, DIFF_RULE_REMOVED, layer, -1, &info, NULL) < 0)
                    return -1;
            }
            continue;
        }

        /* If layer exists in B but not A: all rules added */
        if (!lyr_a && lyr_b) {
            for (int i = 0; i < count_b; i++) {
                soft_rule_info_t info;
                info.pattern = lyr_b->rules[i].pattern;
                info.mode = lyr_b->rules[i].mode;
                info.op_type = lyr_b->rules[i].op_type;
                info.linked_path_var = (lyr_b->rules[i].linked_path_var[0] != '\0') ? lyr_b->rules[i].linked_path_var : NULL;
                info.subject_regex = (lyr_b->rules[i].subject_regex[0] != '\0') ? lyr_b->rules[i].subject_regex : NULL;
                info.flags = lyr_b->rules[i].flags;
                info.layer = layer;

                if (diff_add(out, DIFF_RULE_ADDED, -1, layer, NULL, &info) < 0)
                    return -1;
            }
            continue;
        }

        /* Both layers exist: compare rules */
        /* Build a map of pattern+op indices in B for quick lookup */
        typedef struct {
            int rule_idx;      /* Index in lyr_b->rules */
            int used;          /* Whether this B rule has been matched */
        } b_map_entry_t;

        b_map_entry_t *b_map = NULL;
        int b_map_count = 0;
        if (count_b > 0) {
            b_map = calloc((size_t)count_b, sizeof(b_map_entry_t));
            if (!b_map) return -1;
            for (int i = 0; i < count_b; i++) {
                b_map[i].rule_idx = i;
                b_map[i].used = 0;
            }
            b_map_count = count_b;
        }

        /* Pass 1: Find matching rules (unchanged or modified) */
        for (int i = 0; i < count_a; i++) {
            const rule_t *ra = &lyr_a->rules[i];
            int matched_b = -1;

            for (int j = 0; j < b_map_count; j++) {
                if (b_map[j].used) continue;
                const rule_t *rb = &lyr_b->rules[b_map[j].rule_idx];
                if (rules_same_pattern(ra, rb)) {
                    matched_b = b_map[j].rule_idx;
                    b_map[j].used = 1;
                    break;
                }
            }

            if (matched_b >= 0) {
                const rule_t *rb = &lyr_b->rules[matched_b];
                soft_rule_info_t info_a, info_b;

                info_a.pattern = ra->pattern;
                info_a.mode = ra->mode;
                info_a.op_type = ra->op_type;
                info_a.linked_path_var = (ra->linked_path_var[0] != '\0') ? ra->linked_path_var : NULL;
                info_a.subject_regex = (ra->subject_regex[0] != '\0') ? ra->subject_regex : NULL;
                info_a.flags = ra->flags;
                info_a.layer = layer;

                info_b.pattern = rb->pattern;
                info_b.mode = rb->mode;
                info_b.op_type = rb->op_type;
                info_b.linked_path_var = (rb->linked_path_var[0] != '\0') ? rb->linked_path_var : NULL;
                info_b.subject_regex = (rb->subject_regex[0] != '\0') ? rb->subject_regex : NULL;
                info_b.flags = rb->flags;
                info_b.layer = layer;

                if (rules_equal(ra, rb)) {
                    if (diff_add(out, DIFF_RULE_UNCHANGED, layer, layer, &info_a, &info_b) < 0) {
                        free(b_map);
                        return -1;
                    }
                } else {
                    if (diff_add(out, DIFF_RULE_MODIFIED, layer, layer, &info_a, &info_b) < 0) {
                        free(b_map);
                        return -1;
                    }
                }
            } else {
                /* Rule in A not found in B: removed */
                soft_rule_info_t info;
                info.pattern = ra->pattern;
                info.mode = ra->mode;
                info.op_type = ra->op_type;
                info.linked_path_var = (ra->linked_path_var[0] != '\0') ? ra->linked_path_var : NULL;
                info.subject_regex = (ra->subject_regex[0] != '\0') ? ra->subject_regex : NULL;
                info.flags = ra->flags;
                info.layer = layer;

                if (diff_add(out, DIFF_RULE_REMOVED, layer, -1, &info, NULL) < 0) {
                    free(b_map);
                    return -1;
                }
            }
        }

        /* Pass 2: Remaining unused B rules are additions */
        for (int j = 0; j < b_map_count; j++) {
            if (b_map[j].used) continue;

            const rule_t *rb = &lyr_b->rules[b_map[j].rule_idx];
            soft_rule_info_t info;
            info.pattern = rb->pattern;
            info.mode = rb->mode;
            info.op_type = rb->op_type;
            info.linked_path_var = (rb->linked_path_var[0] != '\0') ? rb->linked_path_var : NULL;
            info.subject_regex = (rb->subject_regex[0] != '\0') ? rb->subject_regex : NULL;
            info.flags = rb->flags;
            info.layer = layer;

            if (diff_add(out, DIFF_RULE_ADDED, -1, layer, NULL, &info) < 0) {
                free(b_map);
                return -1;
            }
        }

        free(b_map);
    }

    return 0;
}

void soft_ruleset_diff_free(soft_ruleset_diff_t *diff)
{
    if (!diff) return;

    for (int i = 0; i < diff->count; i++) {
        free((void *)diff->changes[i].rule_a);
        free((void *)diff->changes[i].rule_b);
    }

    free(diff->changes);
    diff->changes = NULL;
    diff->count = 0;
    diff->capacity = 0;
    diff->added = 0;
    diff->removed = 0;
    diff->modified = 0;
    diff->unchanged = 0;
}
