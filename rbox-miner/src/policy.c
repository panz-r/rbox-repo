#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

/*
 * policy.c - Compact Policy Trie (CPT) with arena allocation.
 *
 * Design:
 * - Fixed-size state headers (16 bytes) in a growable array
 * - All children in a flat arena; each node owns a contiguous region
 * - Children sorted: literals first (binary search), then wildcards (type order)
 * - Wildcard bitmask per node for O(1) compatibility pre-filter
 * - String-interned token text via shared context
 * - Pattern registry: original strings stored once, referenced by ID
 */

#include "rbox_policy_learner.h"
#include "vacuum_filter.h"
#include "filter_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define CHILDREN_ARENA_INIT  4096
#define STATES_INIT          4096
#define PATTERN_REG_INIT     256
#define VERIFY_ALL_RING_CAP  64
#define MAX_CMD_TOKENS       128
#define FILTER_POS_LEVELS    4
#define FILTER_POS_CAPACITY  1024
#define MINER_LITERAL_THRESHOLD 3

/* ============================================================
 * CHILD ENTRY — 16 bytes, packed
 * ============================================================ */

typedef struct {
    const char   *text;
    uint32_t      target;
    uint8_t       type;
    uint8_t       _pad[3];
} child_entry_t;

/* ============================================================
 * POLICY STATE — 16 bytes, fixed size
 * ============================================================ */

typedef struct {
    child_entry_t *children;
    uint16_t       literal_count;
    uint16_t       wildcard_count;
    uint16_t       pattern_id;
    uint16_t       wildcard_mask;
    uint16_t       children_cap;
} policy_state_t;

/* ============================================================
 * CHILDREN — per-node dynamically allocated array
 * ============================================================ */

static child_entry_t *children_grow(child_entry_t *old, uint16_t *cap)
{
    size_t new_cap = *cap == 0 ? 4 : (size_t)*cap * 2;
    child_entry_t *new = realloc(old, new_cap * sizeof(child_entry_t));
    if (!new) return NULL;
    memset(new + *cap, 0, (new_cap - *cap) * sizeof(child_entry_t));
    *cap = (uint16_t)new_cap;
    return new;
}

/* ============================================================
 * STATES ARRAY
 * ============================================================ */

typedef struct {
    policy_state_t *states;
    size_t          count;
    size_t          capacity;
} states_array_t;

static bool states_array_init(states_array_t *a)
{
    a->capacity = STATES_INIT;
    a->states = calloc(a->capacity, sizeof(policy_state_t));
    if (!a->states) return false;
    a->count = 1;
    a->states[0].children = NULL;
    a->states[0].pattern_id = UINT16_MAX;
    return true;
}

static void states_array_free(states_array_t *a)
{
    for (size_t i = 0; i < a->count; i++) {
        free(a->states[i].children);
    }
    free(a->states);
    a->states = NULL;
}

static uint32_t states_array_alloc(states_array_t *a)
{
    if (a->count >= a->capacity) {
        size_t new_cap = a->capacity * 2;
        policy_state_t *new_states = realloc(a->states, new_cap * sizeof(policy_state_t));
        if (!new_states) return UINT32_MAX;
        a->states = new_states;
        a->capacity = new_cap;
    }
    uint32_t idx = (uint32_t)a->count;
    a->states[idx].children = NULL;
    a->states[idx].pattern_id = UINT16_MAX;
    a->states[idx].literal_count = 0;
    a->states[idx].wildcard_count = 0;
    a->states[idx].wildcard_mask = 0;
    a->count++;
    return idx;
}

/* ============================================================
 * PATTERN REGISTRY
 * ============================================================ */

typedef struct {
    const char **strings;
    size_t       count;
    size_t       capacity;
} pattern_reg_t;

static bool pattern_reg_init(pattern_reg_t *r)
{
    r->capacity = PATTERN_REG_INIT;
    r->strings = calloc(r->capacity, sizeof(const char *));
    if (!r->strings) return false;
    r->count = 0;
    return true;
}

static void pattern_reg_free(pattern_reg_t *r)
{
    free((void *)r->strings);
    r->strings = NULL;
}

static bool pattern_reg_grow(pattern_reg_t *r)
{
    size_t new_cap = r->capacity * 2;
    const char **new_strings = realloc((void *)r->strings, new_cap * sizeof(const char *));
    if (!new_strings) return false;
    r->strings = new_strings;
    r->capacity = new_cap;
    return true;
}

static uint16_t pattern_reg_add(pattern_reg_t *r, cpl_policy_ctx_t *ctx, const char *pattern)
{
    if (r->count >= r->capacity) {
        if (!pattern_reg_grow(r)) return UINT16_MAX;
    }
    const char *interned = cpl_policy_ctx_intern(ctx, pattern);
    if (!interned) return UINT16_MAX;
    uint16_t id = (uint16_t)r->count;
    r->strings[r->count++] = interned;
    return id;
}

/* ============================================================
 * POLICY STRUCTURE
 * ============================================================ */

struct cpl_policy {
    cpl_policy_ctx_t   *ctx;
    states_array_t      states;
    pattern_reg_t       patterns;
    uint64_t            epoch;
    vacuum_filter_t    *pos_filters[FILTER_POS_LEVELS];
    uint16_t            pos_wildcard_mask[FILTER_POS_LEVELS];
    uint64_t            pos_built_epoch[FILTER_POS_LEVELS];
    size_t              pattern_count;
    size_t              children_count;
    size_t              children_alloc;
};

/* ============================================================
 * COMPATIBILITY MASK
 * ============================================================ */

static const uint16_t cpl_compat_mask[CPL_TYPE_COUNT] = {
    /* LITERAL */      (1u << CPL_TYPE_ANY),
    /* HEXHASH */      (1u << CPL_TYPE_HEXHASH) | (1u << CPL_TYPE_NUMBER) | (1u << CPL_TYPE_VALUE) | (1u << CPL_TYPE_ANY),
    /* NUMBER */       (1u << CPL_TYPE_NUMBER) | (1u << CPL_TYPE_VALUE) | (1u << CPL_TYPE_ANY),
    /* IPV4 */         (1u << CPL_TYPE_IPV4) | (1u << CPL_TYPE_VALUE) | (1u << CPL_TYPE_ANY),
    /* WORD */         (1u << CPL_TYPE_WORD) | (1u << CPL_TYPE_VALUE) | (1u << CPL_TYPE_ANY),
    /* QUOTED */       (1u << CPL_TYPE_QUOTED) | (1u << CPL_TYPE_QUOTED_SPACE) | (1u << CPL_TYPE_VALUE) | (1u << CPL_TYPE_ANY),
    /* QUOTED_SPACE */ (1u << CPL_TYPE_QUOTED_SPACE) | (1u << CPL_TYPE_VALUE) | (1u << CPL_TYPE_ANY),
    /* FILENAME */     (1u << CPL_TYPE_FILENAME) | (1u << CPL_TYPE_REL_PATH) | (1u << CPL_TYPE_PATH) | (1u << CPL_TYPE_ANY),
    /* REL_PATH */     (1u << CPL_TYPE_REL_PATH) | (1u << CPL_TYPE_PATH) | (1u << CPL_TYPE_ANY),
    /* ABS_PATH */     (1u << CPL_TYPE_ABS_PATH) | (1u << CPL_TYPE_PATH) | (1u << CPL_TYPE_ANY),
    /* PATH */         (1u << CPL_TYPE_PATH) | (1u << CPL_TYPE_ANY),
    /* URL */          (1u << CPL_TYPE_URL) | (1u << CPL_TYPE_ANY),
    /* VALUE */        (1u << CPL_TYPE_VALUE) | (1u << CPL_TYPE_ANY),
    /* ANY */          (1u << CPL_TYPE_ANY),
};

static inline uint16_t compat_mask(cpl_token_type_t t)
{
    return cpl_compat_mask[t];
}

/* ============================================================
 * CHILD ACCESS
 * ============================================================ */

static inline child_entry_t *get_child(const policy_state_t *node, uint16_t idx)
{
    if (!node->children || idx >= node->literal_count + node->wildcard_count) return NULL;
    return &node->children[idx];
}

/* ============================================================
 * CHILD LOOKUP
 * ============================================================ */

static int cmp_literal_child(const void *key, const void *entry)
{
    return strcmp((const char *)key, ((const child_entry_t *)entry)->text);
}

static child_entry_t *find_literal_child(const policy_state_t *node, const char *text)
{
    uint16_t n = node->literal_count;
    if (n == 0 || !node->children) return NULL;
    return bsearch(text, node->children, n, sizeof(child_entry_t), cmp_literal_child);
}

static child_entry_t *find_wildcard_child(const policy_state_t *node, cpl_token_type_t type)
{
    if (node->wildcard_count == 0 || !node->children) return NULL;
    if (!(node->wildcard_mask & compat_mask(type))) return NULL;

    child_entry_t *base = node->children + node->literal_count;
    for (uint16_t i = 0; i < node->wildcard_count; i++) {
        if (cpl_is_compatible(type, (cpl_token_type_t)base[i].type)) return &base[i];
    }
    return NULL;
}

/* ============================================================
 * CHILD INSERTION
 * ============================================================ */

static bool insert_child(policy_state_t *node, cpl_policy_t *policy,
                         const char *text, cpl_token_type_t type, uint32_t target)
{
    bool is_literal = (type == CPL_TYPE_LITERAL);
    uint16_t total = node->literal_count + node->wildcard_count;
    uint16_t insert_pos;

    if (is_literal) {
        insert_pos = 0;
        for (uint16_t i = 0; i < node->literal_count; i++) {
            if (strcmp(text, node->children[i].text) < 0) break;
            insert_pos = i + 1;
        }
        if (insert_pos < node->literal_count &&
            node->children[insert_pos].type == CPL_TYPE_LITERAL &&
            strcmp(text, node->children[insert_pos].text) == 0) return false;
    } else {
        insert_pos = node->literal_count;
        for (uint16_t i = node->literal_count; i < total; i++) {
            if (type < node->children[i].type) break;
            insert_pos = i + 1;
        }
        if (insert_pos < total && node->children[insert_pos].type == type) return false;
    }

    const char *interned = is_literal ? cpl_policy_ctx_intern(policy->ctx, text) : NULL;
    child_entry_t new_child = { .text = interned, .target = target, .type = (uint8_t)type };

    if (total + 1 > node->children_cap) {
        size_t old_cap = node->children_cap;
        child_entry_t *grown = children_grow(node->children, &node->children_cap);
        if (!grown) return false;
        node->children = grown;
        policy->children_alloc += node->children_cap - old_cap;
    }

    memmove(node->children + insert_pos + 1,
            node->children + insert_pos,
            (total - insert_pos) * sizeof(child_entry_t));
    node->children[insert_pos] = new_child;
    policy->children_count++;

    if (is_literal) {
        node->literal_count++;
    } else {
        node->wildcard_count++;
        node->wildcard_mask |= (1u << type);
    }
    return true;
}

/* ============================================================
 * PATTERN PARSING
 * ============================================================ */

static cpl_token_t *parse_pattern(const char *pattern, size_t *out_count)
{
    size_t count = 1;
    for (const char *p = pattern; *p; p++) {
        if (*p == ' ') count++;
    }

    char *copy = strdup(pattern);
    if (!copy) return NULL;

    cpl_token_t *tokens = calloc(count, sizeof(cpl_token_t));
    if (!tokens) { free(copy); return NULL; }

    size_t ti = 0;
    char *tok = strtok(copy, " ");
    while (tok && ti < count) {
        cpl_token_type_t type = CPL_TYPE_LITERAL;
        for (int t = 1; t < CPL_TYPE_COUNT; t++) {
            if (strcmp(tok, cpl_type_symbol[t]) == 0) {
                type = (cpl_token_type_t)t;
                break;
            }
        }
        if (type == CPL_TYPE_LITERAL) {
            type = cpl_classify_token(tok);
        }
        tokens[ti].text = strdup(tok);
        tokens[ti].type = type;
        ti++;
        tok = strtok(NULL, " ");
    }
    *out_count = ti;
    free(copy);
    return tokens;
}

static void free_pattern_tokens(cpl_token_t *tokens, size_t count)
{
    if (!tokens) return;
    for (size_t i = 0; i < count; i++) free(tokens[i].text);
    free(tokens);
}

/* ============================================================
 * PER-POSITION FILTER REBUILD
 *
 * BFS-walk the trie up to depth FILTER_POS_LEVELS (4).
 * At each depth N, collect all children across all nodes at that depth:
 *   - Literals → insert into pos_filters[N]
 *   - Wildcards → OR into pos_wildcard_mask[N]
 *
 * Called lazily when pos_built_epoch[N] != policy->epoch.
 * ============================================================ */

static void policy_rebuild_filters(cpl_policy_t *policy)
{
    /* Reset or create filters, clear masks */
    for (int i = 0; i < FILTER_POS_LEVELS; i++) {
        if (policy->pos_filters[i]) {
            vacuum_filter_reset(policy->pos_filters[i]);
        } else {
            policy->pos_filters[i] = vacuum_filter_create(FILTER_POS_CAPACITY, 0, 0, 0);
        }
        policy->pos_wildcard_mask[i] = 0;
    }

    /* BFS walk: track (state_idx, depth) pairs */
    typedef struct { uint32_t idx; uint8_t depth; } bfs_q;
    bfs_q q[STATES_INIT * 2];
    size_t head = 0, tail = 0;

    q[tail].idx = 0;
    q[tail].depth = 0;
    tail++;

    while (head < tail) {
        bfs_q entry = q[head++];
        if (entry.depth >= FILTER_POS_LEVELS) continue;

        policy_state_t *node = &policy->states.states[entry.idx];
        uint16_t total = node->literal_count + node->wildcard_count;

        for (uint16_t i = 0; i < total; i++) {
            child_entry_t *c = &node->children[i];
            if (c->type == CPL_TYPE_LITERAL && !c->text) continue;

            uint8_t d = entry.depth;

            if (c->type == CPL_TYPE_LITERAL) {
                if (policy->pos_filters[d]) {
                    uint64_t h = filter_hash_fnv1a(c->text, strlen(c->text));
                    vacuum_filter_insert(policy->pos_filters[d], h);
                }
            } else {
                policy->pos_wildcard_mask[d] |= (1u << c->type);
            }

            if (tail < sizeof(q) / sizeof(q[0])) {
                q[tail].idx = c->target;
                q[tail].depth = d + 1;
                tail++;
            }
        }
    }

    for (int i = 0; i < FILTER_POS_LEVELS; i++) {
        policy->pos_built_epoch[i] = policy->epoch;
    }
}

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

cpl_policy_t *cpl_policy_new(cpl_policy_ctx_t *ctx)
{
    if (!ctx) return NULL;

    cpl_policy_t *policy = calloc(1, sizeof(cpl_policy_t));
    if (!policy) return NULL;

    if (!states_array_init(&policy->states)) { free(policy); return NULL; }
    if (!pattern_reg_init(&policy->patterns)) {
        states_array_free(&policy->states); free(policy); return NULL;
    }

    policy->ctx = ctx;
    policy->epoch = 1;
    policy->pattern_count = 0;
    policy->children_count = 0;
    policy->children_alloc = 0;
    return policy;
}

void cpl_policy_free(cpl_policy_t *policy)
{
    if (!policy) return;
    for (int i = 0; i < FILTER_POS_LEVELS; i++) {
        vacuum_filter_destroy(policy->pos_filters[i]);
    }
    pattern_reg_free(&policy->patterns);
    states_array_free(&policy->states);
    free(policy);
}

/* ============================================================
 * ADD / REMOVE
 * ============================================================ */

cpl_error_t cpl_policy_add(cpl_policy_t *policy, const char *pattern)
{
    if (!policy || !pattern || !pattern[0]) return CPL_ERR_INVALID;

    size_t token_count = 0;
    cpl_token_t *tokens = parse_pattern(pattern, &token_count);
    if (!tokens) return CPL_ERR_MEMORY;
    if (token_count == 0) { free_pattern_tokens(tokens, token_count); return CPL_ERR_INVALID; }

    uint32_t current = 0;

    for (size_t i = 0; i < token_count; i++) {
        policy_state_t *node = &policy->states.states[current];
        child_entry_t *existing = NULL;

        if (tokens[i].type == CPL_TYPE_LITERAL) {
            existing = find_literal_child(node, tokens[i].text);
        } else {
            existing = find_wildcard_child(node, tokens[i].type);
        }

        if (existing) {
            current = existing->target;
        } else {
            uint32_t new_state = states_array_alloc(&policy->states);
            if (new_state == UINT32_MAX) {
                free_pattern_tokens(tokens, token_count);
                return CPL_ERR_MEMORY;
            }
            if (!insert_child(node, policy,
                              tokens[i].text, tokens[i].type, new_state)) {
                free_pattern_tokens(tokens, token_count);
                return CPL_ERR_MEMORY;
            }
            current = new_state;
        }
    }

    policy_state_t *node = &policy->states.states[current];
    if (node->pattern_id == UINT16_MAX) {
        uint16_t pid = pattern_reg_add(&policy->patterns, policy->ctx, pattern);
        if (pid == UINT16_MAX) {
            free_pattern_tokens(tokens, token_count);
            return CPL_ERR_MEMORY;
        }
        node->pattern_id = pid;
        policy->pattern_count++;
    }

    policy->epoch++;
    free_pattern_tokens(tokens, token_count);
    return CPL_OK;
}

cpl_error_t cpl_policy_remove(cpl_policy_t *policy, const char *pattern)
{
    if (!policy || !pattern || !pattern[0]) return CPL_ERR_INVALID;

    size_t token_count = 0;
    cpl_token_t *tokens = parse_pattern(pattern, &token_count);
    if (!tokens) return CPL_ERR_MEMORY;
    if (token_count == 0) { free_pattern_tokens(tokens, token_count); return CPL_ERR_INVALID; }

    uint32_t current = 0;

    for (size_t i = 0; i < token_count; i++) {
        policy_state_t *node = &policy->states.states[current];
        child_entry_t *child = NULL;
        if (tokens[i].type == CPL_TYPE_LITERAL) {
            child = find_literal_child(node, tokens[i].text);
        } else {
            child = find_wildcard_child(node, tokens[i].type);
        }
        if (!child) {
            free_pattern_tokens(tokens, token_count);
            return CPL_OK;
        }
        current = child->target;
    }

    policy_state_t *node = &policy->states.states[current];
    if (node->pattern_id == UINT16_MAX) {
        free_pattern_tokens(tokens, token_count);
        return CPL_OK;
    }

    node->pattern_id = UINT16_MAX;
    policy->pattern_count--;

    policy->epoch++;
    free_pattern_tokens(tokens, token_count);
    return CPL_OK;
}

size_t cpl_policy_count(const cpl_policy_t *policy)
{
    if (!policy) return 0;
    return policy->pattern_count;
}

/* ============================================================
 * VERIFICATION + SUGGESTIONS (unified)
 * ============================================================ */

/* Build a pattern string from typed tokens into a fixed-size buffer. */
static bool miner_build_pattern(char *buf, size_t buf_size,
                                 const cpl_token_t *tokens, size_t count)
{
    size_t total_len = 0;
    for (size_t i = 0; i < count; i++) {
        const char *part = tokens[i].type == CPL_TYPE_LITERAL
            ? tokens[i].text
            : cpl_type_symbol[tokens[i].type];
        total_len += strlen(part) + (i > 0 ? 1 : 0);
    }
    if (total_len + 1 > buf_size) return false;

    char *p = buf;
    for (size_t i = 0; i < count; i++) {
        if (i > 0) *p++ = ' ';
        const char *part = tokens[i].type == CPL_TYPE_LITERAL
            ? tokens[i].text
            : cpl_type_symbol[tokens[i].type];
        size_t len = strlen(part);
        memcpy(p, part, len);
        p += len;
    }
    *p = '\0';
    return true;
}

/* Collect the pattern string at the deepest accepting state reachable
 * from state_idx (checks state itself, then one BFS level). */
static const char *miner_find_based_on(const cpl_policy_t *policy, uint32_t state_idx)
{
    policy_state_t *state = &policy->states.states[state_idx];
    if (state->pattern_id != UINT16_MAX && state->pattern_id < policy->patterns.count)
        return policy->patterns.strings[state->pattern_id];

    uint16_t total = state->literal_count + state->wildcard_count;
    for (uint16_t i = 0; i < total; i++) {
        child_entry_t *c = &state->children[i];
        policy_state_t *child = &policy->states.states[c->target];
        if (child->pattern_id != UINT16_MAX && child->pattern_id < policy->patterns.count)
            return policy->patterns.strings[child->pattern_id];
    }
    return NULL;
}

cpl_error_t cpl_policy_eval(const cpl_policy_t *policy,
                             const char *raw_cmd,
                             cpl_eval_result_t *result)
{
    if (!policy || !raw_cmd) return CPL_ERR_INVALID;

    if (result) {
        result->matches = false;
        result->matching_pattern = NULL;
        result->suggestion_count = 0;
    }

    cpl_token_array_t cmd;
    cmd.tokens = NULL;
    cmd.count = 0;
    cpl_error_t err = cpl_normalize_typed(raw_cmd, &cmd);
    if (err != CPL_OK) return err;

    if (cmd.count == 0 || cmd.count > MAX_CMD_TOKENS) {
        cpl_free_token_array(&cmd);
        return CPL_ERR_INVALID;
    }

    /* Per-position filter fast-path (rebuild if needed) */
    if (result) {
        size_t check_len = cmd.count < FILTER_POS_LEVELS ? cmd.count : FILTER_POS_LEVELS;
        for (size_t i = 0; i < check_len; i++) {
            if (policy->pos_built_epoch[i] != policy->epoch) {
                cpl_policy_t *mutable = (cpl_policy_t *)policy;
                policy_rebuild_filters(mutable);
                break;
            }
        }
    }

    /* Walk the trie */
    uint32_t current = 0;
    size_t match_depth = 0;
    uint32_t match_state = 0;

    for (size_t i = 0; i < cmd.count; i++) {
        cpl_token_type_t ctype = cmd.tokens[i].type;
        const char *ctext = cmd.tokens[i].text;
        policy_state_t *node = &policy->states.states[current];
        child_entry_t *found = NULL;

        if (ctype == CPL_TYPE_LITERAL)
            found = find_literal_child(node, ctext);

        if (!found) {
            uint16_t compat = compat_mask(ctype) & node->wildcard_mask;
            if (compat)
                found = find_wildcard_child(node, ctype);
        }

        if (!found) break;

        current = found->target;
        match_depth = i + 1;
        match_state = current;
    }

    policy_state_t *end_node = &policy->states.states[current];
    if (match_depth == cmd.count &&
        end_node->pattern_id != UINT16_MAX &&
        end_node->pattern_id < policy->patterns.count) {
        cpl_free_token_array(&cmd);
        if (result) {
            result->matches = true;
            result->matching_pattern = policy->patterns.strings[end_node->pattern_id];
        }
        return CPL_OK;
    }

    /* Per-position filter fast-path: reject definite no-matches */
    if (result) {
        size_t check_len = cmd.count < FILTER_POS_LEVELS ? cmd.count : FILTER_POS_LEVELS;
        for (size_t i = 0; i < check_len; i++) {
            cpl_token_type_t ctype = cmd.tokens[i].type;
            if (ctype == CPL_TYPE_LITERAL) {
                if (policy->pos_wildcard_mask[i] != 0) continue;
                if (!policy->pos_filters[i] || policy->pos_filters[i]->count == 0) continue;
                uint64_t h = filter_hash_fnv1a(cmd.tokens[i].text, strlen(cmd.tokens[i].text));
                if (!vacuum_filter_lookup(policy->pos_filters[i], h)) {
                    cpl_free_token_array(&cmd);
                    goto generate_suggestions;
                }
            } else {
                if ((policy->pos_wildcard_mask[i] & compat_mask(ctype)) == 0) {
                    if (!policy->pos_filters[i] || policy->pos_filters[i]->count == 0) {
                        cpl_free_token_array(&cmd);
                        goto generate_suggestions;
                    }
                }
            }
        }
    }

    cpl_free_token_array(&cmd);
    if (!result) return CPL_ERR_INVALID;

generate_suggestions:
    cpl_free_token_array(&cmd);
    if (!result) return CPL_ERR_INVALID;

    /* Re-normalize for suggestion generation */
    err = cpl_normalize_typed(raw_cmd, &cmd);
    if (err != CPL_OK) return err;

    double confidence = (double)match_depth / (double)cmd.count;
    const char *based_on = miner_find_based_on(policy, match_state);

    /* Suggestion A: minimal extension */
    {
        cpl_token_t *pat_tokens = malloc(cmd.count * sizeof(cpl_token_t));
        if (!pat_tokens) { cpl_free_token_array(&cmd); return CPL_ERR_MEMORY; }

        current = 0;
        for (size_t i = 0; i < match_depth; i++) {
            cpl_token_type_t ctype = cmd.tokens[i].type;
            const char *ctext = cmd.tokens[i].text;
            policy_state_t *node = &policy->states.states[current];
            child_entry_t *found = NULL;
            if (ctype == CPL_TYPE_LITERAL)
                found = find_literal_child(node, ctext);
            if (!found) {
                uint16_t compat = compat_mask(ctype) & node->wildcard_mask;
                if (compat)
                    found = find_wildcard_child(node, ctype);
            }
            if (found) {
                pat_tokens[i].text = (char *)found->text;
                pat_tokens[i].type = (cpl_token_type_t)found->type;
                current = found->target;
            } else {
                pat_tokens[i].text = (char *)cmd.tokens[i].text;
                pat_tokens[i].type = cmd.tokens[i].type;
            }
        }
        for (size_t i = match_depth; i < cmd.count; i++) {
            pat_tokens[i].text = (char *)cmd.tokens[i].text;
            pat_tokens[i].type = CPL_TYPE_LITERAL;
        }

        miner_build_pattern(result->suggestions[0].pattern,
                            sizeof(result->suggestions[0].pattern),
                            pat_tokens, cmd.count);
        result->suggestions[0].based_on = based_on;
        result->suggestions[0].confidence = confidence;
        free(pat_tokens);
    }

    /* Suggestion B: best generalization */
    size_t n_suggestions = 1;

    if (match_depth < cmd.count) {
        cpl_token_type_t div_type = cmd.tokens[match_depth].type;
        policy_state_t *div_node = &policy->states.states[match_state];

        uint16_t wm = div_node->wildcard_mask;
        if (wm != 0 && (compat_mask(div_type) & wm) != 0) {
            cpl_token_type_t best_wild = CPL_TYPE_ANY;
            uint16_t compat = compat_mask(div_type) & wm;
            while (compat) {
                int t = __builtin_ctz(compat);
                compat &= ~(1u << t);
                cpl_token_type_t wt = (cpl_token_type_t)t;
                cpl_token_type_t joined = cpl_join(wt, div_type);
                if (best_wild == CPL_TYPE_ANY || cpl_is_compatible(joined, best_wild))
                    best_wild = joined;
            }

            if (best_wild != CPL_TYPE_ANY) {
                size_t pat_len = match_depth + 1;
                cpl_token_t *pat_tokens = malloc(pat_len * sizeof(cpl_token_t));
                if (pat_tokens) {
                    current = 0;
                    for (size_t i = 0; i < match_depth; i++) {
                        cpl_token_type_t ctype = cmd.tokens[i].type;
                        const char *ctext = cmd.tokens[i].text;
                        policy_state_t *node = &policy->states.states[current];
                        child_entry_t *found = NULL;
                        if (ctype == CPL_TYPE_LITERAL)
                            found = find_literal_child(node, ctext);
                        if (!found) {
                            uint16_t compat2 = compat_mask(ctype) & node->wildcard_mask;
                            if (compat2)
                                found = find_wildcard_child(node, ctype);
                        }
                        if (found) {
                            pat_tokens[i].text = (char *)found->text;
                            pat_tokens[i].type = (cpl_token_type_t)found->type;
                            current = found->target;
                        }
                    }
                    pat_tokens[match_depth].text = (char *)cpl_type_symbol[best_wild];
                    pat_tokens[match_depth].type = best_wild;

                    miner_build_pattern(result->suggestions[1].pattern,
                                        sizeof(result->suggestions[1].pattern),
                                        pat_tokens, pat_len);
                    result->suggestions[1].based_on = based_on;
                    result->suggestions[1].confidence = confidence;
                    free(pat_tokens);
                    n_suggestions = 2;
                }
            }
        } else if (wm == 0 && div_node->literal_count >= MINER_LITERAL_THRESHOLD) {
            cpl_token_type_t joined = CPL_TYPE_LITERAL;
            uint16_t total = div_node->literal_count;
            for (uint16_t i = 0; i < total; i++) {
                child_entry_t *c = &div_node->children[i];
                if (c->type != CPL_TYPE_LITERAL) continue;
                cpl_token_type_t ct = cpl_classify_token(c->text);
                if (joined == CPL_TYPE_LITERAL) joined = ct;
                else joined = cpl_join(joined, ct);
            }
            joined = cpl_join(joined, div_type);

            if (joined != CPL_TYPE_LITERAL) {
                size_t pat_len = cmd.count;
                cpl_token_t *pat_tokens = malloc(pat_len * sizeof(cpl_token_t));
                if (pat_tokens) {
                    current = 0;
                    for (size_t i = 0; i < match_depth; i++) {
                        cpl_token_type_t ctype = cmd.tokens[i].type;
                        const char *ctext = cmd.tokens[i].text;
                        policy_state_t *node = &policy->states.states[current];
                        child_entry_t *found = NULL;
                        if (ctype == CPL_TYPE_LITERAL)
                            found = find_literal_child(node, ctext);
                        if (!found) {
                            uint16_t compat2 = compat_mask(ctype) & node->wildcard_mask;
                            if (compat2)
                                found = find_wildcard_child(node, ctype);
                        }
                        if (found) {
                            pat_tokens[i].text = (char *)found->text;
                            pat_tokens[i].type = (cpl_token_type_t)found->type;
                            current = found->target;
                        }
                    }
                    pat_tokens[match_depth].text = (char *)cpl_type_symbol[joined];
                    pat_tokens[match_depth].type = joined;
                    for (size_t i = match_depth + 1; i < cmd.count; i++) {
                        pat_tokens[i].text = (char *)cmd.tokens[i].text;
                        pat_tokens[i].type = cmd.tokens[i].type;
                    }

                    miner_build_pattern(result->suggestions[1].pattern,
                                        sizeof(result->suggestions[1].pattern),
                                        pat_tokens, pat_len);
                    result->suggestions[1].based_on = based_on;
                    result->suggestions[1].confidence = confidence;
                    free(pat_tokens);
                    n_suggestions = 2;
                }
            }
        }
    }

    if (n_suggestions < 2) {
        miner_build_pattern(result->suggestions[1].pattern,
                            sizeof(result->suggestions[1].pattern),
                            cmd.tokens, cmd.count);
        result->suggestions[1].based_on = NULL;
        result->suggestions[1].confidence = confidence;
        n_suggestions = 2;
    }

    result->suggestion_count = n_suggestions;
    cpl_free_token_array(&cmd);
    return CPL_ERR_INVALID;
}

/* ============================================================
 * VERIFY ALL
 * ============================================================ */

typedef struct {
    uint32_t state_idx;
    uint8_t  token_idx;
} bfs_entry_t;

cpl_error_t cpl_policy_verify_all(const cpl_policy_t *policy,
                                  const char *raw_cmd,
                                  const char ***matching_patterns,
                                  size_t *match_count)
{
    if (!policy || !raw_cmd || !matching_patterns || !match_count) return CPL_ERR_INVALID;
    *matching_patterns = NULL;
    *match_count = 0;

    cpl_token_array_t cmd;
    cmd.tokens = NULL;
    cmd.count = 0;
    cpl_error_t err = cpl_normalize_typed(raw_cmd, &cmd);
    if (err != CPL_OK) return err;

    if (cmd.count == 0 || cmd.count > MAX_CMD_TOKENS) {
        cpl_free_token_array(&cmd);
        return CPL_OK;
    }

    const char **matches = NULL;
    size_t match_cap = 0;
    size_t match_n = 0;

    bfs_entry_t ring[VERIFY_ALL_RING_CAP];
    size_t head = 0, tail = 0;

    ring[tail].state_idx = 0;
    ring[tail].token_idx = 0;
    tail = (tail + 1) % VERIFY_ALL_RING_CAP;

    while (head != tail) {
        bfs_entry_t entry = ring[head];
        head = (head + 1) % VERIFY_ALL_RING_CAP;

        policy_state_t *state = &policy->states.states[entry.state_idx];

        if (entry.token_idx == cmd.count) {
            if (state->pattern_id != UINT16_MAX && state->pattern_id < policy->patterns.count) {
                if (match_n >= match_cap) {
                    size_t new_cap = match_cap == 0 ? 8 : match_cap * 2;
                    const char **new_matches = realloc(matches, new_cap * sizeof(const char *));
                    if (!new_matches) {
                        free(matches);
                        cpl_free_token_array(&cmd);
                        return CPL_ERR_MEMORY;
                    }
                    matches = new_matches;
                    match_cap = new_cap;
                }
                matches[match_n++] = policy->patterns.strings[state->pattern_id];
            }
            continue;
        }

        cpl_token_type_t ctype = cmd.tokens[entry.token_idx].type;
        const char *ctext = cmd.tokens[entry.token_idx].text;

        if (ctype == CPL_TYPE_LITERAL) {
            child_entry_t *c = find_literal_child(state, ctext);
            if (c) {
                ring[tail].state_idx = c->target;
                ring[tail].token_idx = entry.token_idx + 1;
                tail = (tail + 1) % VERIFY_ALL_RING_CAP;
            }
        }

        uint16_t compat = compat_mask(ctype) & state->wildcard_mask;
        while (compat) {
            int t = __builtin_ctz(compat);
            compat &= ~(1u << t);
            child_entry_t *c = find_wildcard_child(state, (cpl_token_type_t)t);
            if (c) {
                ring[tail].state_idx = c->target;
                ring[tail].token_idx = entry.token_idx + 1;
                tail = (tail + 1) % VERIFY_ALL_RING_CAP;
            }
        }
    }

    cpl_free_token_array(&cmd);

    *matching_patterns = matches;
    *match_count = match_n;
    return CPL_OK;
}

void cpl_policy_free_matches(const char **matches, size_t count)
{
    (void)count;
    free((void *)matches);
}

/* ============================================================
 * NFA RENDERING
 * ============================================================ */

#define VSYM_BYTE_ANY 256
#define VSYM_EPS      257
#define VSYM_EOS      258
#define VSYM_SPACE    259
#define VSYM_TAB      260

typedef struct {
    FILE *fp;
    cpl_error_t error;
    uint32_t state_count;
    uint32_t pattern_id_counter;
    uint8_t  category_mask;
    bool     include_tags;
    const char *identifier;
} nfa_render_ctx_t;

static uint32_t nfa_new_state(nfa_render_ctx_t *ctx)
{
    return ctx->state_count++;
}

typedef struct {
    uint32_t count;
} nfa_count_ctx_t;

static void nfa_count_states(nfa_count_ctx_t *ctx, cpl_policy_t *policy,
                             uint32_t trie_idx, bool need_space)
{
    ctx->count++;

    policy_state_t *node = &policy->states.states[trie_idx];
    uint16_t total = node->literal_count + node->wildcard_count;

    for (uint16_t i = 0; i < total; i++) {
        child_entry_t *c = get_child(node, i);
        if (!c) continue;

        if (need_space) ctx->count++;

        if (c->type == CPL_TYPE_LITERAL) {
            ctx->count += (uint32_t)strlen(c->text);
        } else {
            ctx->count += 1;
        }

        nfa_count_states(ctx, policy, c->target, true);
    }
}

static void nfa_dfs_render(nfa_render_ctx_t *ctx, cpl_policy_t *policy,
                           uint32_t trie_idx, uint32_t nfa_state,
                           bool need_space)
{
    if (ctx->error != CPL_OK) return;

    policy_state_t *node = &policy->states.states[trie_idx];
    uint16_t total = node->literal_count + node->wildcard_count;

    if (total == 0) {
        uint16_t pid = (node->pattern_id != UINT16_MAX) ? (ctx->pattern_id_counter++) : 0;
        if (fprintf(ctx->fp, "State %u:\n", nfa_state) < 0) { ctx->error = CPL_ERR_IO; return; }
        if (fprintf(ctx->fp, "  CategoryMask: 0x%02x\n", ctx->category_mask) < 0) { ctx->error = CPL_ERR_IO; return; }
        if (fprintf(ctx->fp, "  PatternId: %u\n", pid) < 0) { ctx->error = CPL_ERR_IO; return; }
        if (fprintf(ctx->fp, "  EosTarget: yes\n") < 0) { ctx->error = CPL_ERR_IO; return; }
        if (ctx->include_tags && node->pattern_id != UINT16_MAX &&
            node->pattern_id < policy->patterns.count) {
            if (fprintf(ctx->fp, "  Tags: %s\n",
                        policy->patterns.strings[node->pattern_id]) < 0) {
                ctx->error = CPL_ERR_IO; return;
            }
        }
        if (fprintf(ctx->fp, "  Transitions: 0\n\n") < 0) { ctx->error = CPL_ERR_IO; }
        return;
    }

    int trans_count = 0;
    for (uint16_t i = 0; i < total; i++) {
        child_entry_t *c = get_child(node, i);
        if (!c) continue;
        if (c->type == CPL_TYPE_LITERAL) {
            trans_count += (int)strlen(c->text);
        } else {
            trans_count += 1;
        }
    }

    uint16_t pid = (node->pattern_id != UINT16_MAX) ? (ctx->pattern_id_counter++) : 0;

    if (fprintf(ctx->fp, "State %u:\n", nfa_state) < 0) { ctx->error = CPL_ERR_IO; return; }
    if (fprintf(ctx->fp, "  CategoryMask: 0x00\n") < 0) { ctx->error = CPL_ERR_IO; return; }
    if (fprintf(ctx->fp, "  PatternId: %u\n", pid) < 0) { ctx->error = CPL_ERR_IO; return; }
    if (fprintf(ctx->fp, "  EosTarget: no\n") < 0) { ctx->error = CPL_ERR_IO; return; }
    if (ctx->include_tags && node->pattern_id != UINT16_MAX &&
        node->pattern_id < policy->patterns.count) {
        if (fprintf(ctx->fp, "  Tags: %s\n",
                    policy->patterns.strings[node->pattern_id]) < 0) {
            ctx->error = CPL_ERR_IO; return;
        }
    }
    if (fprintf(ctx->fp, "  Transitions: %d\n", trans_count) < 0) { ctx->error = CPL_ERR_IO; return; }

    for (uint16_t i = 0; i < total; i++) {
        child_entry_t *c = get_child(node, i);
        if (!c) continue;

        if (need_space) {
            uint32_t space_state = nfa_new_state(ctx);
            if (fprintf(ctx->fp, "    Symbol %d -> %u\n", VSYM_SPACE, space_state) < 0) {
                ctx->error = CPL_ERR_IO; return;
            }
            if (c->type == CPL_TYPE_LITERAL) {
                uint32_t cur = space_state;
                for (const char *p = c->text; *p; p++) {
                    uint32_t next = nfa_new_state(ctx);
                    if (fprintf(ctx->fp, "    Symbol %d -> %u\n", (unsigned char)*p, next) < 0) {
                        ctx->error = CPL_ERR_IO; return;
                    }
                    cur = next;
                }
                nfa_dfs_render(ctx, policy, c->target, cur, true);
            } else {
                uint32_t next = nfa_new_state(ctx);
                if (fprintf(ctx->fp, "    Symbol %d -> %u\n", VSYM_BYTE_ANY, next) < 0) {
                    ctx->error = CPL_ERR_IO; return;
                }
                nfa_dfs_render(ctx, policy, c->target, next, true);
            }
        } else {
            if (c->type == CPL_TYPE_LITERAL) {
                uint32_t cur = nfa_state;
                for (const char *p = c->text; *p; p++) {
                    uint32_t next = nfa_new_state(ctx);
                    if (fprintf(ctx->fp, "    Symbol %d -> %u\n", (unsigned char)*p, next) < 0) {
                        ctx->error = CPL_ERR_IO; return;
                    }
                    cur = next;
                }
                nfa_dfs_render(ctx, policy, c->target, cur, true);
            } else {
                uint32_t next = nfa_new_state(ctx);
                if (fprintf(ctx->fp, "    Symbol %d -> %u\n", VSYM_BYTE_ANY, next) < 0) {
                    ctx->error = CPL_ERR_IO; return;
                }
                nfa_dfs_render(ctx, policy, c->target, next, true);
            }
        }
    }
}

cpl_error_t cpl_policy_render_nfa(const cpl_policy_t *policy,
                                  const char *path,
                                  const cpl_nfa_render_opts_t *opts)
{
    if (!policy || !path) return CPL_ERR_INVALID;

    FILE *fp = fopen(path, "w");
    if (!fp) return CPL_ERR_IO;

    nfa_count_ctx_t count_ctx = { .count = 0 };
    nfa_count_states(&count_ctx, (cpl_policy_t *)policy, 0, false);

    nfa_render_ctx_t ctx = {
        .fp = fp,
        .error = CPL_OK,
        .state_count = 0,
        .pattern_id_counter = opts ? opts->pattern_id_base : 1,
        .category_mask = opts ? opts->category_mask : 0x01,
        .include_tags = opts ? opts->include_tags : false,
        .identifier = opts ? opts->identifier : "rbox-miner policy",
    };

    if (fprintf(fp, "NFA_ALPHABET\n") < 0) { fclose(fp); return CPL_ERR_IO; }
    if (fprintf(fp, "Identifier: %s\n", ctx.identifier) < 0) { fclose(fp); return CPL_ERR_IO; }
    if (fprintf(fp, "AlphabetSize: 261\n") < 0) { fclose(fp); return CPL_ERR_IO; }
    if (fprintf(fp, "States: %u\n", count_ctx.count) < 0) { fclose(fp); return CPL_ERR_IO; }
    if (fprintf(fp, "Initial: 0\n\n") < 0) { fclose(fp); return CPL_ERR_IO; }

    if (fprintf(fp, "Alphabet:\n") < 0) { fclose(fp); return CPL_ERR_IO; }
    for (int i = 0; i < 256; i++) {
        if (fprintf(fp, "  Symbol %d: %d-%d\n", i, i, i) < 0) { fclose(fp); return CPL_ERR_IO; }
    }
    if (fprintf(fp, "  Symbol 256: 0-255 (special)\n") < 0) { fclose(fp); return CPL_ERR_IO; }
    if (fprintf(fp, "  Symbol 257: 1-1 (special)\n") < 0) { fclose(fp); return CPL_ERR_IO; }
    if (fprintf(fp, "  Symbol 258: 5-5 (special)\n") < 0) { fclose(fp); return CPL_ERR_IO; }
    if (fprintf(fp, "  Symbol 259: 32-32 (special)\n") < 0) { fclose(fp); return CPL_ERR_IO; }
    if (fprintf(fp, "  Symbol 260: 9-9 (special)\n\n") < 0) { fclose(fp); return CPL_ERR_IO; }

    nfa_dfs_render(&ctx, (cpl_policy_t *)policy, 0, 0, false);

    fclose(fp);
    return ctx.error;
}

/* ============================================================
 * SERIALIZATION
 * ============================================================ */

typedef struct {
    FILE *fp;
    cpl_error_t error;
} policy_save_ctx_t;

static void dfs_save(cpl_policy_t *policy, uint32_t idx, policy_save_ctx_t *ctx)
{
    if (ctx->error != CPL_OK) return;

    policy_state_t *node = &policy->states.states[idx];
    uint16_t total = node->literal_count + node->wildcard_count;

    if (node->pattern_id != UINT16_MAX && node->pattern_id < policy->patterns.count) {
        if (fprintf(ctx->fp, "%s\n", policy->patterns.strings[node->pattern_id]) < 0) {
            ctx->error = CPL_ERR_IO;
            return;
        }
    }

    for (uint16_t i = 0; i < total; i++) {
        child_entry_t *c = get_child(node, i);
        if (c) dfs_save(policy, c->target, ctx);
    }
}

cpl_error_t cpl_policy_save(const cpl_policy_t *policy, const char *path)
{
    if (!policy || !path) return CPL_ERR_INVALID;

    FILE *fp = fopen(path, "w");
    if (!fp) return CPL_ERR_IO;

    policy_save_ctx_t ctx = { .fp = fp, .error = CPL_OK };
    dfs_save((cpl_policy_t *)policy, 0, &ctx);
    fclose(fp);
    return ctx.error;
}

cpl_error_t cpl_policy_load(cpl_policy_t *policy, const char *path)
{
    if (!policy || !path) return CPL_ERR_INVALID;

    FILE *fp = fopen(path, "r");
    if (!fp) return CPL_ERR_IO;

    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0) continue;
        if (line[0] == '#') continue;

        cpl_error_t err = cpl_policy_add(policy, line);
        if (err != CPL_OK) {
            fclose(fp);
            return err;
        }
    }

    fclose(fp);
    return CPL_OK;
}

/* ============================================================
 * DIAGNOSTICS
 * ============================================================ */

size_t cpl_policy_memory_usage(const cpl_policy_t *policy)
{
    if (!policy) return 0;
    size_t states_alloc = policy->states.capacity * sizeof(policy_state_t);
    size_t patterns_alloc = policy->patterns.capacity * sizeof(const char *);
    size_t filter_bytes = 0;
    for (int i = 0; i < FILTER_POS_LEVELS; i++) {
        if (policy->pos_filters[i]) {
            filter_bytes += vacuum_filter_memory_bytes(policy->pos_filters[i]);
        }
    }
    return sizeof(cpl_policy_t) + filter_bytes + states_alloc + policy->children_alloc * sizeof(child_entry_t) + patterns_alloc;
}

size_t cpl_policy_working_set(const cpl_policy_t *policy)
{
    if (!policy) return 0;
    size_t states_used = policy->states.count * sizeof(policy_state_t);
    size_t patterns_used = policy->patterns.count * sizeof(const char *);
    size_t filter_bytes = 0;
    for (int i = 0; i < FILTER_POS_LEVELS; i++) {
        if (policy->pos_filters[i]) {
            filter_bytes += vacuum_filter_memory_bytes(policy->pos_filters[i]);
        }
    }
    return sizeof(cpl_policy_t) + filter_bytes + states_used + policy->children_count * sizeof(child_entry_t) + patterns_used;
}

size_t cpl_policy_state_count(const cpl_policy_t *policy)
{
    if (!policy) return 0;
    return policy->states.count;
}

/* ============================================================
 * POLICY EXPANSION SUGGESTIONS (Miner — Step 2 only)
 * ============================================================ */

/* Next-wider type in the lattice. */
static cpl_token_type_t next_wider_type(cpl_token_type_t t)
{
    switch (t) {
        case CPL_TYPE_HEXHASH:     return CPL_TYPE_NUMBER;
        case CPL_TYPE_NUMBER:      return CPL_TYPE_VALUE;
        case CPL_TYPE_IPV4:        return CPL_TYPE_VALUE;
        case CPL_TYPE_WORD:        return CPL_TYPE_VALUE;
        case CPL_TYPE_QUOTED:      return CPL_TYPE_QUOTED_SPACE;
        case CPL_TYPE_QUOTED_SPACE:return CPL_TYPE_VALUE;
        case CPL_TYPE_FILENAME:    return CPL_TYPE_REL_PATH;
        case CPL_TYPE_REL_PATH:    return CPL_TYPE_PATH;
        case CPL_TYPE_ABS_PATH:    return CPL_TYPE_PATH;
        case CPL_TYPE_PATH:        return CPL_TYPE_ANY;
        case CPL_TYPE_URL:         return CPL_TYPE_ANY;
        case CPL_TYPE_VALUE:       return CPL_TYPE_ANY;
        case CPL_TYPE_ANY:         return CPL_TYPE_ANY;
        default:                   return t;
    }
}

size_t cpl_policy_suggest_variants(const cpl_policy_t *policy,
                                    const cpl_token_t *tokens,
                                    size_t token_count,
                                    cpl_expand_suggestion_t out[3])
{
    if (!policy || !tokens || !out || token_count == 0) return 0;

    /* Variant 0: exact match as literal */
    {
        cpl_token_t *lit_tokens = malloc(token_count * sizeof(cpl_token_t));
        if (!lit_tokens) return 0;
        for (size_t i = 0; i < token_count; i++) {
            lit_tokens[i].text = (char *)tokens[i].text;
            lit_tokens[i].type = CPL_TYPE_LITERAL;
        }
        miner_build_pattern(out[0].pattern, sizeof(out[0].pattern),
                            lit_tokens, token_count);
        out[0].based_on = NULL;
        out[0].confidence = 1.0;
        free(lit_tokens);
    }

    /* Variants 1..N: widen one non-literal token at a time */
    size_t n_variants = 1;
    for (size_t i = 0; i < token_count && n_variants < 3; i++) {
        if (tokens[i].type == CPL_TYPE_LITERAL) continue;

        cpl_token_type_t wider = next_wider_type(tokens[i].type);
        if (wider == tokens[i].type) continue;

        cpl_token_t *pat_tokens = malloc(token_count * sizeof(cpl_token_t));
        if (!pat_tokens) continue;
        for (size_t j = 0; j < token_count; j++)
            pat_tokens[j] = tokens[j];
        pat_tokens[i].text = (char *)cpl_type_symbol[wider];
        pat_tokens[i].type = wider;

        miner_build_pattern(out[n_variants].pattern,
                            sizeof(out[n_variants].pattern),
                            pat_tokens, token_count);
        out[n_variants].based_on = NULL;
        out[n_variants].confidence = 1.0;
        free(pat_tokens);
        n_variants++;
    }

    return n_variants;
}
