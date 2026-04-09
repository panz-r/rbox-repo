/**
 * @file rule_engine.c
 * @brief ReadOnlyBox Rule Engine implementation (spec v3.0).
 *
 * Implements layered rulesets with precedence, dual-path evaluation,
 * path variables, subject constraints, and batched evaluation.
 *
 * See rule_engine_compile.c for simplification and compilation logic.
 */

#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <sys/param.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include "rule_engine.h"
#include "rule_engine_internal.h"

/* ------------------------------------------------------------------ */
/*  Path matching (shared with compile module)                         */
/* ------------------------------------------------------------------ */
/**
 * Glob-style path matching.
 *
 * Wildcards:
 *   STAR   matches any sequence of NON-slash characters (single segment)
 *   DOUBLE matches any sequence of characters INCLUDING slash (multi-segment)
 *   ... suffix matches any descendant path (recursive)
 *
 * Examples:
 *   /etc/STAR         matches /etc/passwd       but NOT /etc/cron.d/foo
 *   /etc/DOUBLE       matches /etc/cron.d/foo   and /etc/passwd
 *   /usr/DOUBLE/lib   matches /usr/lib, /usr/local/lib, /usr/x/y/lib
 *   /home/STAR/.ssh   matches /home/alice/.ssh  but NOT /home/alice/bob/.ssh
 */
bool path_matches(const char *pattern, const char *text)
{
    if (!pattern || !text) return false;

    /* Handle recursive "..." suffix */
    size_t plen = strlen(pattern);
    if (plen >= 3 && pattern[plen - 3] == '.' &&
        pattern[plen - 2] == '.' && pattern[plen - 1] == '.') {
        char base[MAX_PATTERN_LEN];
        size_t base_len = plen - 3;
        if (base_len > 0 && pattern[base_len - 1] == '/') base_len--;
        if (base_len >= MAX_PATTERN_LEN) base_len = MAX_PATTERN_LEN - 1;
        memcpy(base, pattern, base_len);
        base[base_len] = '\0';

        if (strcmp(text, base) == 0) return true;
        if (strncmp(text, base, base_len) == 0 && text[base_len] == '/') return true;
        return false;
    }

    if (strchr(pattern, '*') == NULL) {
        /* No wildcards: exact match or directory prefix */
        if (strcmp(pattern, text) == 0) return true;
        size_t plen2 = strlen(pattern);
        if (plen2 > 0 && pattern[plen2 - 1] == '/')
            return strncmp(text, pattern, plen2) == 0;
        return false;
    }

    /* Glob matching with * (single segment) and ** (multi-segment) */
    const char *p = pattern;
    const char *t = text;
    const char *star_p = NULL;  /* position of last * or ** in pattern */
    const char *match_t = NULL; /* text position right after last star */
    bool double_star = false;   /* whether star_p points to ** */

    while (*t != '\0') {
        if (*p == '*' && *(p + 1) == '*') {
            /* ** matches anything (including /) */
            double_star = true;
            star_p = p;
            match_t = t;
            p += 2;
            if (*p == '/') p++;  /* slash after double-star is optional */
            continue;
        }

        if (*p == '*') {
            /* * matches anything except / */
            double_star = false;
            star_p = p;
            match_t = t;
            p++;
            continue;
        }

        if (*p == *t) {
            p++;
            t++;
            continue;
        }

        if (star_p) {
            /* Backtrack: make the star consume one more character */
            if (double_star) {
                /* ** advances text by one (can cross /) */
                match_t++;
                t = match_t;
                p = star_p + 2;
                if (*p == '/') p++;
            } else {
                /* * advances text but cannot cross / */
                if (*match_t == '/') {
                    return false;
                }
                match_t++;
                t = match_t;
                p = star_p + 1;
            }
            continue;
        }

        /* No star to backtrack to: mismatch */
        return false;
    }

    /* Text exhausted. Consume trailing * or ** in pattern. */
    while (*p == '*') {
        if (*p == '*' && *(p + 1) == '*') p += 2;
        else p++;
    }
    if (*p == '/') p++;
    return *p == '\0';
}

/**
 * Resolve a path variable from the context.
 */
static const char *resolve_var(const char *var, const soft_access_ctx_t *ctx)
{
    if (!var || !ctx) return NULL;
    if (strcmp(var, "SRC") == 0) return ctx->src_path;
    if (strcmp(var, "DST") == 0) return ctx->dst_path;
    return NULL;
}

/**
 * Check if a pattern contains a variable placeholder.
 */
static bool pattern_has_var(const char *pattern, const char *var)
{
    char placeholder[16];
    snprintf(placeholder, sizeof(placeholder), "${%s}", var);
    return strstr(pattern, placeholder) != NULL;
}

/**
 * Replace VAR in pattern with the actual path and match.
 */

/**
 * Match a compiled rule against a path in the given context.
 * Used for dynamic rules (wildcards, recursive, templates).
 */
bool rule_matches_path(const rule_t *rule, const char *path,
                       const soft_access_ctx_t *ctx)
{
    if (!rule || !path) return false;

    bool is_template = (rule->flags & SOFT_RULE_TEMPLATE) != 0;

    if (is_template) {
        /* Resolve variable in pattern, then match against the query path */
        const char *var_name = NULL;
        if (rule->linked_path_var[0] != '\0') {
            var_name = rule->linked_path_var;
        } else if (pattern_has_var(rule->pattern, "SRC")) {
            var_name = "SRC";
        } else if (pattern_has_var(rule->pattern, "DST")) {
            var_name = "DST";
        }

        if (var_name) {
            const char *resolved = resolve_var(var_name, ctx);
            if (!resolved) return false;

            char resolved_pattern[MAX_PATTERN_LEN];
            char placeholder[16];
            snprintf(placeholder, sizeof(placeholder), "${%s}", var_name);

            const char *var_pos = strstr(rule->pattern, placeholder);
            if (!var_pos) return false;

            size_t prefix_len = (size_t)(var_pos - rule->pattern);
            size_t total_len = prefix_len + strlen(resolved) +
                               strlen(var_pos + strlen(placeholder));
            if (total_len >= MAX_PATTERN_LEN) return false;

            memcpy(resolved_pattern, rule->pattern, prefix_len);
            strcpy(resolved_pattern + prefix_len, resolved);
            strcat(resolved_pattern, var_pos + strlen(placeholder));

            return path_matches(resolved_pattern, path);
        }
    }

    return path_matches(rule->pattern, path);
}

/**
 * Check subject constraint.
 */
bool subject_matches(const rule_t *rule, const char *subject)
{
    if (rule->subject_regex[0] == '\0') return true;
    if (!subject) return false;

    size_t rlen = strlen(rule->subject_regex);
    if (rlen >= 2 && rule->subject_regex[0] == '.' &&
        rule->subject_regex[1] == '*' && rlen > 2) {
        const char *suffix = rule->subject_regex + 2;
        size_t slen = strlen(subject);
        size_t suf_len = strlen(suffix);
        if (suf_len > 0 && suffix[suf_len - 1] == '$') suf_len--;
        if (slen >= suf_len && suf_len > 0 &&
            strncmp(subject + slen - suf_len, suffix, suf_len) == 0)
            return true;
        return false;
    }

    return strcmp(rule->subject_regex, subject) == 0;
}

/* ------------------------------------------------------------------ */
/*  Layer management                                                    */
/* ------------------------------------------------------------------ */

static layer_t *ensure_layer(soft_ruleset_t *rs, int target)
{
    if (target < 0 || target >= MAX_LAYERS) return NULL;
    while (rs->layer_count <= target) {
        memset(&rs->layers[rs->layer_count], 0, sizeof(layer_t));
        rs->layer_count++;
    }
    return &rs->layers[target];
}

static int layer_add_rule(layer_t *lyr, const rule_t *r)
{
    if (!lyr) return -1;
    if (lyr->count >= lyr->capacity) {
        int new_cap = lyr->capacity + LAYER_CHUNK;
        if (new_cap < 0) return -1;
        rule_t *new_rules = realloc(lyr->rules, (size_t)new_cap * sizeof(rule_t));
        if (!new_rules) return -1;
        lyr->rules = new_rules;
        lyr->capacity = new_cap;
    }
    lyr->rules[lyr->count++] = *r;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Ruleset management                                                 */
/* ------------------------------------------------------------------ */

soft_ruleset_t *soft_ruleset_new(void)
{
    soft_ruleset_t *rs = calloc(1, sizeof(*rs));
    if (!rs) return NULL;
    rs->layer_count = 0;
    rs->is_compiled = false;
    rs->last_error[0] = '\0';
    return rs;
}

/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/*  Query result cache (LRU, round-robin eviction)                     */
/* ------------------------------------------------------------------ */

/** FNV-1a 64-bit hash of a string. */
static uint64_t fnv1a_str(const char *s)
{
    uint64_t h = 14695981039346656037ULL;
    if (s) {
        for (; *s; s++) {
            h ^= (uint8_t)*s;
            h *= 1099511628211ULL;
        }
    }
    return h;
}

/** Compute cache key for a single path. */
static uint64_t path_hash(const char *path)
{
    return fnv1a_str(path);
}

/**
 * Return the set of access modes that an evaluation with the given op
 * could have returned.  This is the `eval` mask we store in the cache.
 *
 * Unary READ only inspects READ rules, so eval = READ.
 * Binary COPY inspects COPY+READ+WRITE rules, which can grant any
 * mode, so eval = ALL.
 */
static uint32_t eval_mode_for_op(soft_binary_op_t op)
{
    switch (op) {
    case SOFT_OP_READ:       return SOFT_ACCESS_READ;
    case SOFT_OP_WRITE:      return SOFT_ACCESS_WRITE;
    case SOFT_OP_EXEC:       return SOFT_ACCESS_EXEC;
    case SOFT_OP_CHMOD_CHOWN: return SOFT_ACCESS_WRITE;
    case SOFT_OP_COPY:
    case SOFT_OP_MOVE:
    case SOFT_OP_LINK:
    case SOFT_OP_MOUNT:
    case SOFT_OP_CUSTOM:
    default:                 return SOFT_ACCESS_ALL;
    }
}

/** Look up cached result for a single path. Direct-mapped: one entry per path. */
static query_cache_entry_t *query_cache_lookup(soft_ruleset_t *rs,
                                                uint64_t phash,
                                                uint32_t subject_hash,
                                                uint32_t uid,
                                                uint32_t required_mode)
{
    uint32_t idx = (uint32_t)(phash % QUERY_CACHE_SIZE);
    query_cache_entry_t *e = &rs->query_cache[idx];
    if (e->valid && e->path_hash == phash &&
        e->subject_hash == subject_hash && e->uid == uid &&
        (e->eval & required_mode) == required_mode) {
        return e;
    }
    return NULL;
}

/** Store a result in the cache (direct-mapped: latest write wins). */
static void query_cache_store(soft_ruleset_t *rs,
                              uint64_t phash,
                              uint32_t subject_hash,
                              uint32_t uid,
                              uint32_t granted,
                              uint32_t eval,
                              int32_t deny_layer)
{
    uint32_t idx = (uint32_t)(phash % QUERY_CACHE_SIZE);
    query_cache_entry_t *e = &rs->query_cache[idx];
    e->path_hash = phash;
    e->subject_hash = subject_hash;
    e->uid = uid;
    e->granted = granted;
    e->eval = eval;
    e->deny_layer = deny_layer;
    e->valid = 1;
}

void soft_ruleset_free(soft_ruleset_t *rs)
{
    if (!rs) return;
    for (int i = 0; i < rs->layer_count; i++) {
        free(rs->layers[i].rules);
    }
    eff_free(&rs->effective);
    free(rs);
}

size_t soft_ruleset_rule_count(const soft_ruleset_t *rs)
{
    if (!rs) return 0;
    size_t total = 0;
    for (int i = 0; i < rs->layer_count; i++) {
        total += (size_t)rs->layers[i].count;
    }
    return total;
}

int soft_ruleset_layer_count(const soft_ruleset_t *rs)
{
    if (!rs) return 0;
    return rs->layer_count;
}

/* ------------------------------------------------------------------ */
/*  Rule insertion                                                     */
/* ------------------------------------------------------------------ */

int soft_ruleset_add_rule_at_layer(soft_ruleset_t *rs,
                                   int layer,
                                   const char *pattern,
                                   uint32_t mode,
                                   soft_binary_op_t op_type,
                                   const char *linked_path_var,
                                   const char *subject_regex,
                                   uint32_t min_uid,
                                   uint32_t flags)
{
    if (!rs || !pattern) { errno = EINVAL; return -1; }

    /* linked_path_var is only meaningful with template patterns */
    if (linked_path_var && linked_path_var[0] != '\0' &&
        !strstr(pattern, "${SRC}") && !strstr(pattern, "${DST}")) {
        errno = EINVAL;
        return -1;
    }

    layer_t *lyr = ensure_layer(rs, layer);
    if (!lyr) { errno = EINVAL; return -1; }

    rule_t r;
    memset(&r, 0, sizeof(r));

    size_t plen = strlen(pattern);
    if (plen >= MAX_PATTERN_LEN) { errno = ENAMETOOLONG; return -1; }
    memcpy(r.pattern, pattern, plen + 1);

    r.mode = mode;
    r.op_type = op_type;
    r.min_uid = min_uid;
    r.flags = flags;

    if (linked_path_var) {
        size_t vlen = strlen(linked_path_var);
        if (vlen >= MAX_LINKED_LEN) { errno = EINVAL; return -1; }
        memcpy(r.linked_path_var, linked_path_var, vlen + 1);
    }

    if (subject_regex) {
        size_t slen = strlen(subject_regex);
        if (slen >= sizeof(r.subject_regex)) { errno = EINVAL; return -1; }
        memcpy(r.subject_regex, subject_regex, slen + 1);
    }

    if (strstr(pattern, "${SRC}") || strstr(pattern, "${DST}")) {
        r.flags |= SOFT_RULE_TEMPLATE;
    }

    int ret = layer_add_rule(lyr, &r);
    if (ret == 0) soft_ruleset_invalidate(rs);
    return ret;
}

int soft_ruleset_add_rule(soft_ruleset_t *rs,
                          const char *pattern,
                          uint32_t mode,
                          soft_binary_op_t op_type,
                          const char *linked_path_var,
                          const char *subject_regex,
                          uint32_t min_uid,
                          uint32_t flags)
{
    return soft_ruleset_add_rule_at_layer(rs, 0, pattern, mode, op_type,
                                          linked_path_var, subject_regex,
                                          min_uid, flags);
}

/*  Layer type configuration                                           */
/* ------------------------------------------------------------------ */

int soft_ruleset_set_layer_type(soft_ruleset_t *rs,
                                int layer,
                                layer_type_t type,
                                uint32_t mask)
{
    if (!rs || layer < 0 || layer >= MAX_LAYERS) { errno = EINVAL; return -1; }
    layer_t *lyr = ensure_layer(rs, layer);
    if (!lyr) return -1;
    lyr->type = type;
    lyr->mask = mask;
    soft_ruleset_invalidate(rs);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Custom operation mode registration                                 */
/* ------------------------------------------------------------------ */

int soft_ruleset_set_custom_op_modes(soft_ruleset_t *rs,
                                     int custom_op_index,
                                     uint32_t required_src,
                                     uint32_t required_dst)
{
    if (!rs) { errno = EINVAL; return -1; }
    int idx = custom_op_index - SOFT_OP_CUSTOM;
    if (idx < 0 || idx >= MAX_CUSTOM_OPS) { errno = EINVAL; return -1; }
    rs->custom_ops[idx].src_required = required_src;
    rs->custom_ops[idx].dst_required = required_dst;
    soft_ruleset_invalidate(rs);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Expression parser                                                  */
/* ------------------------------------------------------------------ */

const char *soft_ruleset_error(const soft_ruleset_t *rs)
{
    if (!rs || rs->last_error[0] == '\0') return NULL;
    return rs->last_error;
}

static uint32_t parse_mode(const char *s)
{
    uint32_t mode = 0;
    for (; *s; s++) {
        switch (*s) {
        case 'R': case 'r': mode |= SOFT_ACCESS_READ;   break;
        case 'W': case 'w': mode |= SOFT_ACCESS_WRITE;  break;
        case 'X': case 'x': mode |= SOFT_ACCESS_EXEC;   break;
        case 'C': case 'c': mode |= SOFT_ACCESS_CREATE; break;
        case 'D': case 'd': mode = SOFT_ACCESS_DENY;    return mode;
        }
    }
    if (mode == 0) mode = SOFT_ACCESS_READ;
    return mode;
}

static soft_binary_op_t parse_op(const char *s)
{
    if (strcasecmp(s, "read") == 0 || strcasecmp(s, "r") == 0)
        return SOFT_OP_READ;
    if (strcasecmp(s, "write") == 0 || strcasecmp(s, "w") == 0)
        return SOFT_OP_WRITE;
    if (strcasecmp(s, "exec") == 0 || strcasecmp(s, "x") == 0)
        return SOFT_OP_EXEC;
    if (strcasecmp(s, "copy") == 0 || strcasecmp(s, "cp") == 0)
        return SOFT_OP_COPY;
    if (strcasecmp(s, "move") == 0 || strcasecmp(s, "mv") == 0)
        return SOFT_OP_MOVE;
    if (strcasecmp(s, "link") == 0 || strcasecmp(s, "ln") == 0)
        return SOFT_OP_LINK;
    if (strcasecmp(s, "mount") == 0) return SOFT_OP_MOUNT;
    if (strcasecmp(s, "chmod_chown") == 0) return SOFT_OP_CHMOD_CHOWN;
    return SOFT_OP_READ;
}

int soft_ruleset_add_rule_str(soft_ruleset_t *rs,
                              const char *rule_str,
                              const char *source_file)
{
    if (!rs || !rule_str) { errno = EINVAL; return -1; }
    (void)source_file;

    char buf[512];
    strncpy(buf, rule_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    int target_layer = 0;
    char *expr = buf;
    if (buf[0] == '@') {
        char *colon = strchr(buf + 1, ':');
        if (!colon) {
            snprintf(rs->last_error, sizeof(rs->last_error),
                     "Invalid @layer prefix: no colon");
            errno = EINVAL;
            return -1;
        }
        *colon = '\0';
        char *endptr;
        long val = strtol(buf + 1, &endptr, 10);
        if (*endptr != '\0' || endptr == buf + 1) {
            snprintf(rs->last_error, sizeof(rs->last_error),
                     "Invalid @layer prefix: not a number");
            errno = EINVAL;
            return -1;
        }
        if (val < 0 || val >= MAX_LAYERS) {
            snprintf(rs->last_error, sizeof(rs->last_error),
                     "Layer %ld out of range [0..%d)", val, MAX_LAYERS);
            errno = EINVAL;
            return -1;
        }
        target_layer = (int)val;
        expr = colon + 1;
    }

    char *arrow = strstr(expr, "->");
    if (!arrow) {
        snprintf(rs->last_error, sizeof(rs->last_error),
                 "Missing '-> mode' in rule");
        errno = EINVAL;
        return -1;
    }

    *arrow = '\0';
    char *mode_str = arrow + 2;
    while (*mode_str == ' ') mode_str++;

    uint32_t mode = parse_mode(mode_str);

    char *p = expr;
    char *fields[4] = { NULL, NULL, NULL, NULL };
    int field_count = 0;

    while (field_count < 4 && *p) {
        fields[field_count] = p;
        field_count++;
        char *colon = strchr(p, ':');
        if (colon) {
            *colon = '\0';
            p = colon + 1;
        } else {
            break;
        }
    }

    char *op_str = fields[0];
    char *subject = fields[1];
    char *src_pattern = fields[2];
    char *dst_pattern = fields[3];

    if (src_pattern) {
        size_t slen = strlen(src_pattern);
        while (slen > 0 && src_pattern[slen - 1] == ' ') {
            src_pattern[--slen] = '\0';
        }
    }
    if (dst_pattern) {
        size_t dlen = strlen(dst_pattern);
        while (dlen > 0 && dst_pattern[dlen - 1] == ' ') {
            dst_pattern[--dlen] = '\0';
        }
    }

    if (!op_str) {
        snprintf(rs->last_error, sizeof(rs->last_error), "Missing operation");
        errno = EINVAL;
        return -1;
    }

    soft_binary_op_t op = parse_op(op_str);

    if (src_pattern && src_pattern[0] != '\0') {
        uint32_t flags = 0;
        if (strstr(src_pattern, "...")) flags |= SOFT_RULE_RECURSIVE;
        const char *linked = NULL;
        if (strcmp(src_pattern, "${SRC}") == 0) linked = "SRC";
        else if (strcmp(src_pattern, "${DST}") == 0) linked = "DST";

        int ret = soft_ruleset_add_rule_at_layer(rs, target_layer, src_pattern,
                                                 mode, op, linked, subject, 0, flags);
        if (ret < 0) {
            snprintf(rs->last_error, sizeof(rs->last_error),
                     "Failed to add SRC rule: %s", strerror(errno));
            return -1;
        }
    }

    if (dst_pattern && dst_pattern[0] != '\0') {
        uint32_t flags = 0;
        if (strstr(dst_pattern, "...")) flags |= SOFT_RULE_RECURSIVE;
        const char *linked = NULL;
        if (strcmp(dst_pattern, "${SRC}") == 0) linked = "SRC";
        else if (strcmp(dst_pattern, "${DST}") == 0) linked = "DST";

        int ret = soft_ruleset_add_rule_at_layer(rs, target_layer, dst_pattern,
                                                 mode, op, linked, subject, 0, flags);
        if (ret < 0) {
            snprintf(rs->last_error, sizeof(rs->last_error),
                     "Failed to add DST rule: %s", strerror(errno));
            return -1;
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Evaluation                                                         */
/* ------------------------------------------------------------------ */

static uint32_t op_required_src_mode(const soft_ruleset_t *rs, soft_binary_op_t op)
{
    switch (op) {
    case SOFT_OP_READ:      return SOFT_ACCESS_READ;
    case SOFT_OP_WRITE:     return SOFT_ACCESS_WRITE;
    case SOFT_OP_EXEC:      return SOFT_ACCESS_EXEC;
    case SOFT_OP_COPY:      return SOFT_ACCESS_READ;
    case SOFT_OP_MOVE:      return SOFT_ACCESS_WRITE | SOFT_ACCESS_UNLINK;
    case SOFT_OP_LINK:      return SOFT_ACCESS_READ | SOFT_ACCESS_LINK;
    case SOFT_OP_MOUNT:     return SOFT_ACCESS_READ | SOFT_ACCESS_MOUNT_SRC;
    case SOFT_OP_CHMOD_CHOWN: return SOFT_ACCESS_WRITE;
    case SOFT_OP_CUSTOM: {
        int idx = (int)op - SOFT_OP_CUSTOM;
        if (rs && idx >= 0 && idx < MAX_CUSTOM_OPS &&
            rs->custom_ops[idx].src_required != 0) {
            return rs->custom_ops[idx].src_required;
        }
        return SOFT_ACCESS_READ;
    }
    default:                return SOFT_ACCESS_READ;
    }
}

static uint32_t op_required_dst_mode(const soft_ruleset_t *rs, soft_binary_op_t op)
{
    switch (op) {
    case SOFT_OP_COPY:      return SOFT_ACCESS_WRITE;
    case SOFT_OP_MOVE:      return SOFT_ACCESS_WRITE;
    case SOFT_OP_LINK:      return SOFT_ACCESS_WRITE;
    case SOFT_OP_MOUNT:     return SOFT_ACCESS_WRITE;
    case SOFT_OP_CHMOD_CHOWN: return SOFT_ACCESS_WRITE;
    case SOFT_OP_CUSTOM: {
        int idx = (int)op - SOFT_OP_CUSTOM;
        if (rs && idx >= 0 && idx < MAX_CUSTOM_OPS &&
            rs->custom_ops[idx].dst_required != 0) {
            return rs->custom_ops[idx].dst_required;
        }
        return SOFT_ACCESS_WRITE;
    }
    default:                return SOFT_ACCESS_WRITE;
    }
}

/**
 * Evaluate one path against all descriptive layers.
 * Used when the ruleset is NOT compiled.
 */
static uint32_t eval_all_layers(const soft_ruleset_t *rs,
                                const char *path,
                                soft_binary_op_t op,
                                const soft_access_ctx_t *ctx,
                                int *out_deny_layer,
                                const char **out_matched_pattern)
{
    if (!path) {
        if (out_deny_layer) *out_deny_layer = -1;
        if (out_matched_pattern) *out_matched_pattern = NULL;
        return 0;
    }

    /* First try the compiled effective ruleset */
    if (rs->is_compiled && (rs->effective.static_count > 0 || rs->effective.dynamic_count > 0)) {
        const char *matched = NULL;
        uint32_t granted = eval_effective_path(&rs->effective, path, op, ctx,
                                               &matched);
        if (out_matched_pattern) *out_matched_pattern = matched;
        if (granted == 0 && matched != NULL) {
            /* DENY matched in effective ruleset */
            if (out_deny_layer) *out_deny_layer = 0;
        }
        return granted;
    }

    /* Fall back to layered evaluation */

    /* Phase 1: SPECIFICITY layers — longest match wins, overrides PRECEDENCE */
        
    const char *spec_best_pattern = NULL;
    size_t spec_best_len = 0;
    uint32_t spec_best_mode = 0;
    bool spec_found = false;

    for (int i = 0; i < rs->layer_count; i++) {
        const layer_t *lyr = &rs->layers[i];
        if (lyr->count == 0 || lyr->type != LAYER_SPECIFICITY) continue;
        if (lyr->mask != 0 && !(lyr->mask & op_required_src_mode(rs, op))) continue;

        for (int j = 0; j < lyr->count; j++) {
            const rule_t *r = &lyr->rules[j];
            if (r->op_type != op && r->op_type != SOFT_OP_READ &&
                r->op_type != SOFT_OP_WRITE) continue;
            if (!subject_matches(r, ctx->subject)) continue;
            if (r->min_uid > 0 && ctx->uid < r->min_uid) continue;
            if (!rule_matches_path(r, path, ctx)) continue;

            size_t pat_len = strlen(r->pattern);
            if (!spec_found || pat_len > spec_best_len) {
                spec_best_len = pat_len;
                spec_best_pattern = r->pattern;
                spec_best_mode = r->mode;
                spec_found = true;
            }
        }
    }

    if (spec_found) {
        if (out_matched_pattern) *out_matched_pattern = spec_best_pattern;
        if (out_deny_layer) *out_deny_layer = -1; /* SPECIFICITY match, not PRECEDENCE DENY */
        return spec_best_mode & SOFT_ACCESS_DENY ? 0 : spec_best_mode;
    }

    /* Phase 2: PRECEDENCE layers — current behavior */
    uint32_t intersection = SOFT_ACCESS_ALL;
    bool any_layer_matched = false;
    const char *last_pattern = NULL;

    for (int i = 0; i < rs->layer_count; i++) {
        const layer_t *lyr = &rs->layers[i];
        if (lyr->count == 0 || lyr->type == LAYER_SPECIFICITY) continue;

        const char *layer_pattern = NULL;
        uint32_t granted = 0;
        bool has_deny = false;

        /* Pass 1: static rules */
        for (int j = 0; j < lyr->count; j++) {
            const rule_t *r = &lyr->rules[j];
            if (r->flags & SOFT_RULE_TEMPLATE) continue;
            if (r->op_type != op && r->op_type != SOFT_OP_READ &&
                r->op_type != SOFT_OP_WRITE) continue;
            if (!subject_matches(r, ctx->subject)) continue;
            if (r->min_uid > 0 && ctx->uid < r->min_uid) continue;
            if (!rule_matches_path(r, path, ctx)) continue;

            if (r->mode & SOFT_ACCESS_DENY) {
                has_deny = true;
                layer_pattern = r->pattern;
                break;
            }
            granted |= r->mode;
            layer_pattern = r->pattern;
        }

        if (!has_deny) {
            /* Pass 2: template rules */
            for (int j = 0; j < lyr->count; j++) {
                const rule_t *r = &lyr->rules[j];
                if (!(r->flags & SOFT_RULE_TEMPLATE)) continue;
                if (r->op_type != op && r->op_type != SOFT_OP_READ &&
                    r->op_type != SOFT_OP_WRITE) continue;
                if (!subject_matches(r, ctx->subject)) continue;
                if (r->min_uid > 0 && ctx->uid < r->min_uid) continue;
                if (!rule_matches_path(r, path, ctx)) continue;

                if (r->mode & SOFT_ACCESS_DENY) {
                    has_deny = true;
                    layer_pattern = r->pattern;
                    break;
                }
                granted |= r->mode;
                layer_pattern = r->pattern;
            }
        }

        if (has_deny) {
            if (out_deny_layer) *out_deny_layer = i;
            if (out_matched_pattern) *out_matched_pattern = layer_pattern;
            return 0;
        }

        if (layer_pattern != NULL) {
            intersection &= granted;
            any_layer_matched = true;
            last_pattern = layer_pattern;
        }
    }

    if (out_deny_layer) *out_deny_layer = -1;
    if (out_matched_pattern) *out_matched_pattern = last_pattern;
    if (!any_layer_matched) return 0;
    return intersection;
}

int soft_ruleset_check_ctx(const soft_ruleset_t *rs,
                           const soft_access_ctx_t *ctx,
                           soft_audit_log_t *out_log)
{
    if (!rs || !ctx) { errno = EINVAL; return -EACCES; }

    bool is_binary = (ctx->op == SOFT_OP_COPY || ctx->op == SOFT_OP_MOVE ||
                      ctx->op == SOFT_OP_LINK || ctx->op == SOFT_OP_MOUNT ||
                      ctx->op >= SOFT_OP_CUSTOM);

    uint64_t subj_hash = fnv1a_str(ctx->subject);
    uint32_t eval_mask = eval_mode_for_op(ctx->op);
    int result;

    /* Try cache lookup (skip if audit log requested) */
    if (!out_log) {
        soft_ruleset_t *mutable = (soft_ruleset_t *)rs;
        uint64_t src_hash = path_hash(ctx->src_path);
        uint32_t src_req = op_required_src_mode(rs, ctx->op);
        query_cache_entry_t *src_hit = query_cache_lookup(mutable, src_hash,
                                                           subj_hash, ctx->uid, src_req);

        if (is_binary) {
            uint64_t dst_hash = path_hash(ctx->dst_path);
            uint32_t dst_req = op_required_dst_mode(rs, ctx->op);
            query_cache_entry_t *dst_hit = query_cache_lookup(mutable, dst_hash,
                                                               subj_hash, ctx->uid, dst_req);

            if (src_hit && dst_hit) {
                /* Both subqueries cached and cover required modes */
                if (src_hit->deny_layer >= 0 || dst_hit->deny_layer >= 0)
                    return -EACCES;
                if ((src_hit->granted & src_req) != src_req ||
                    (dst_hit->granted & dst_req) != dst_req)
                    return -EACCES;
                return (int)(src_hit->granted | dst_hit->granted);
            }
        } else if (src_hit) {
            /* Unary op, fully cached */
            if (src_hit->deny_layer >= 0) return -EACCES;
            uint32_t req = op_required_src_mode(rs, ctx->op);
            if ((src_hit->granted & req) != req) return -EACCES;
            return (int)src_hit->granted;
        }
    }

    /* Evaluate */
    if (is_binary) {
        int src_deny = -1, dst_deny = -1;
        uint32_t src_granted = 0, dst_granted = 0;
        const char *src_pattern = NULL, *dst_pattern = NULL;

        src_granted = eval_all_layers(rs, ctx->src_path, ctx->op, ctx,
                                      &src_deny, &src_pattern);
        if (src_deny >= 0) {
            if (out_log) {
                out_log->result = -EACCES;
                out_log->deny_reason = "SRC denied by layer";
                out_log->deny_layer = src_deny;
                out_log->matched_rule = src_pattern;
            }
            result = -EACCES;
        } else {
            uint32_t src_req = op_required_src_mode(rs, ctx->op);
            if ((src_granted & src_req) != src_req) {
                if (out_log) {
                    out_log->result = -EACCES;
                    out_log->deny_reason = "SRC insufficient mode";
                    out_log->deny_layer = -1;
                    out_log->matched_rule = NULL;
                }
                result = -EACCES;
            } else {
                dst_granted = eval_all_layers(rs, ctx->dst_path, ctx->op, ctx,
                                              &dst_deny, &dst_pattern);
                if (dst_deny >= 0) {
                    if (out_log) {
                        out_log->result = -EACCES;
                        out_log->deny_reason = "DST denied by layer";
                        out_log->deny_layer = dst_deny;
                        out_log->matched_rule = dst_pattern;
                    }
                    result = -EACCES;
                } else {
                    uint32_t dst_req = op_required_dst_mode(rs, ctx->op);
                    if ((dst_granted & dst_req) != dst_req) {
                        if (out_log) {
                            out_log->result = -EACCES;
                            out_log->deny_reason = "DST insufficient mode";
                            out_log->deny_layer = -1;
                            out_log->matched_rule = NULL;
                        }
                        result = -EACCES;
                    } else {
                        uint32_t res = src_granted | dst_granted;
                        if (out_log) {
                            out_log->result = (int)res;
                            out_log->deny_layer = -1;
                            out_log->matched_rule = src_pattern;
                        }
                        result = (int)res;
                    }
                }
            }
        }

        /* Cache subquery results independently */
        if (!out_log) {
            soft_ruleset_t *m = (soft_ruleset_t *)rs;
            uint64_t sh = path_hash(ctx->src_path);
            query_cache_store(m, sh, subj_hash, ctx->uid,
                              src_granted, eval_mask, src_deny);
            /* Cache DST only if it was evaluated */
            if (src_deny < 0 &&
                (src_granted & op_required_src_mode(rs, ctx->op)) == op_required_src_mode(rs, ctx->op)) {
                uint64_t dh = path_hash(ctx->dst_path);
                query_cache_store(m, dh, subj_hash, ctx->uid,
                                  dst_granted, eval_mask, dst_deny);
            }
        }
    } else {
        int deny_layer = -1;
        const char *matched_pattern = NULL;

        uint32_t req = op_required_src_mode(rs, ctx->op);
        uint32_t granted = eval_all_layers(rs, ctx->src_path, ctx->op, ctx,
                                           &deny_layer, &matched_pattern);

        if (deny_layer >= 0) {
            if (out_log) {
                out_log->result = -EACCES;
                out_log->deny_reason = "Access denied by layer";
                out_log->deny_layer = deny_layer;
                out_log->matched_rule = matched_pattern;
            }
            result = -EACCES;
        } else if ((granted & req) != req) {
            if (out_log) {
                out_log->result = -EACCES;
                out_log->deny_reason = "Insufficient access mode";
                out_log->deny_layer = -1;
                out_log->matched_rule = NULL;
            }
            result = -EACCES;
        } else {
            if (out_log) {
                out_log->result = (int)granted;
                out_log->deny_layer = -1;
                out_log->matched_rule = matched_pattern;
            }
            result = (int)granted;
        }

        /* Cache unary result */
        if (!out_log) {
            soft_ruleset_t *m = (soft_ruleset_t *)rs;
            uint64_t sh = path_hash(ctx->src_path);
            query_cache_store(m, sh, subj_hash, ctx->uid,
                              granted, eval_mask, deny_layer);
        }
    }

    return result;
}

/* ------------------------------------------------------------------ */
/*  Batch evaluation with parent-directory cache                        */
/* ------------------------------------------------------------------ */

#define BATCH_CACHE_SIZE 256

typedef struct {
    char     path[PATH_MAX];
    uint32_t granted;
    int      deny_layer;
    int      valid;
} batch_cache_entry_t;

static void parent_dir(const char *path, char *out, size_t out_size)
{
    if (!path || out_size == 0) { out[0] = '\0'; return; }

    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') len--;

    const char *last_slash = NULL;
    for (size_t i = len - 1; i > 0; i--) {
        if (path[i] == '/') { last_slash = path + i; break; }
    }

    if (!last_slash || last_slash == path) {
        strncpy(out, "/", out_size - 1);
        out[out_size - 1] = '\0';
        return;
    }

    size_t parent_len = (size_t)(last_slash - path);
    if (parent_len >= out_size) parent_len = out_size - 1;
    memcpy(out, path, parent_len);
    out[parent_len] = '\0';
}

static batch_cache_entry_t *batch_cache_lookup(batch_cache_entry_t *cache,
                                               const char *path)
{
    for (int i = 0; i < BATCH_CACHE_SIZE; i++) {
        if (cache[i].valid && strcmp(cache[i].path, path) == 0)
            return &cache[i];
    }
    return NULL;
}

static void batch_cache_store(batch_cache_entry_t *cache,
                              const char *path,
                              uint32_t granted,
                              int deny_layer,
                              int *write_pos)
{
    int pos = *write_pos;
    batch_cache_entry_t *e = &cache[pos];
    strncpy(e->path, path, PATH_MAX - 1);
    e->path[PATH_MAX - 1] = '\0';
    e->granted = granted;
    e->deny_layer = deny_layer;
    e->valid = 1;
    *write_pos = (pos + 1) % BATCH_CACHE_SIZE;
}

int soft_ruleset_check_batch_ctx(const soft_ruleset_t *rs,
                                 const soft_access_ctx_t *ctxs[],
                                 int *results,
                                 int count)
{
    if (!rs || !ctxs || !results || count <= 0) { errno = EINVAL; return -1; }

    batch_cache_entry_t src_cache[BATCH_CACHE_SIZE];
    batch_cache_entry_t dst_cache[BATCH_CACHE_SIZE];
    memset(src_cache, 0, sizeof(src_cache));
    memset(dst_cache, 0, sizeof(dst_cache));
    int src_write = 0, dst_write = 0;

    for (int i = 0; i < count; i++) {
        const soft_access_ctx_t *ctx = ctxs[i];
        if (!ctx) { results[i] = -EACCES; continue; }

        bool is_binary = (ctx->op == SOFT_OP_COPY || ctx->op == SOFT_OP_MOVE ||
                          ctx->op == SOFT_OP_LINK || ctx->op == SOFT_OP_MOUNT ||
                          ctx->op >= SOFT_OP_CUSTOM);

        char src_parent[PATH_MAX], dst_parent[PATH_MAX];
        parent_dir(ctx->src_path, src_parent, sizeof(src_parent));
        if (is_binary && ctx->dst_path)
            parent_dir(ctx->dst_path, dst_parent, sizeof(dst_parent));
        else
            dst_parent[0] = '\0';

        uint32_t src_granted = 0, dst_granted = 0;
        int src_deny = -1, dst_deny = -1;

        batch_cache_entry_t *src_hit = batch_cache_lookup(src_cache, ctx->src_path);
        batch_cache_entry_t *src_par = batch_cache_lookup(src_cache, src_parent);
        if (src_hit) {
            src_granted = src_hit->granted;
            src_deny = src_hit->deny_layer;
        } else if (src_par) {
            src_granted = src_par->granted;
            src_deny = src_par->deny_layer;
        } else {
            src_granted = eval_all_layers(rs, ctx->src_path, ctx->op, ctx,
                                          &src_deny, NULL);
            batch_cache_store(src_cache, ctx->src_path, src_granted, src_deny,
                              &src_write);
            /* Don't cache root parent — it matches everything and causes false hits */
            if (strcmp(src_parent, "/") != 0)
                batch_cache_store(src_cache, src_parent, src_granted, src_deny,
                                  &src_write);
        }

        if (is_binary && ctx->dst_path) {
            batch_cache_entry_t *dst_hit = batch_cache_lookup(dst_cache, ctx->dst_path);
            batch_cache_entry_t *dst_par = batch_cache_lookup(dst_cache, dst_parent);
            if (dst_hit) {
                dst_granted = dst_hit->granted;
                dst_deny = dst_hit->deny_layer;
            } else if (dst_par) {
                dst_granted = dst_par->granted;
                dst_deny = dst_par->deny_layer;
            } else {
                dst_granted = eval_all_layers(rs, ctx->dst_path, ctx->op, ctx,
                                              &dst_deny, NULL);
                batch_cache_store(dst_cache, ctx->dst_path, dst_granted, dst_deny,
                                  &dst_write);
                /* Don't cache root parent */
                if (strcmp(dst_parent, "/") != 0)
                    batch_cache_store(dst_cache, dst_parent, dst_granted, dst_deny,
                                      &dst_write);
            }
        }

        if (is_binary) {
            if (src_deny >= 0 || dst_deny >= 0) {
                results[i] = -EACCES;
            } else {
                uint32_t src_req = op_required_src_mode(rs, ctx->op);
                uint32_t dst_req = op_required_dst_mode(rs, ctx->op);
                if ((src_granted & src_req) == src_req &&
                    (dst_granted & dst_req) == dst_req) {
                    results[i] = (int)(src_granted | dst_granted);
                } else {
                    results[i] = -EACCES;
                }
            }
        } else {
            if (src_deny >= 0) {
                results[i] = -EACCES;
            } else {
                uint32_t req = op_required_src_mode(rs, ctx->op);
                if ((src_granted & req) == req) {
                    results[i] = (int)src_granted;
                } else {
                    results[i] = -EACCES;
                }
            }
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Backward compatibility                                             */
/* ------------------------------------------------------------------ */

int soft_ruleset_check(const soft_ruleset_t *rs,
                       const char *path,
                       uint32_t mask)
{
    soft_access_ctx_t ctx = {
        .op = SOFT_OP_READ,
        .src_path = path,
        .dst_path = NULL,
        .subject = NULL,
        .uid = 0
    };
    (void)mask;
    return soft_ruleset_check_ctx(rs, &ctx, NULL);
}
