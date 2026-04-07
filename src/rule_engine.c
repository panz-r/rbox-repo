/**
 * @file rule_engine.c
 * @brief ReadOnlyBox Rule Engine implementation (spec v3.0).
 *
 * Implements layered rulesets with precedence, dual-path evaluation,
 * path variables, subject constraints, and batched evaluation with
 * parent-directory caching.
 *
 * Layer semantics:
 *   - Layer 0 has highest precedence.
 *   - DENY at any layer short-circuits and returns DENY.
 *   - Allowed mode = bitwise AND across all non-denying layers.
 *   - Within a layer, static rules are evaluated before template rules
 *     (so a static /etc/shadow: DENY shadows ${SRC}: RO).
 */

#define _DEFAULT_SOURCE
#define _GNU_SOURCE
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

#include "rule_engine.h"

/* ------------------------------------------------------------------ */
/*  Internal rule structure                                            */
/* ------------------------------------------------------------------ */

#define MAX_PATTERN_LEN 256
#define MAX_LINKED_LEN  8

typedef struct {
    char              pattern[MAX_PATTERN_LEN]; /**< Path pattern */
    uint32_t          mode;                     /**< SOFT_ACCESS_* or DENY */
    soft_binary_op_t  op_type;                  /**< Operation this rule applies to */
    char              linked_path_var[MAX_LINKED_LEN]; /**< "SRC", "DST", or "" */
    char              subject_regex[128];       /**< Binary path regex, or "" */
    uint32_t          min_uid;                  /**< Minimum UID */
    uint32_t          flags;                    /**< Rule flags */
} rule_t;

/* ------------------------------------------------------------------ */
/*  Layer structure                                                     */
/* ------------------------------------------------------------------ */

#define MAX_RULES_PER_LAYER 2048

typedef struct {
    rule_t  rules[MAX_RULES_PER_LAYER];
    int     count;
} layer_t;

/* ------------------------------------------------------------------ */
/*  Ruleset structure                                                  */
/* ------------------------------------------------------------------ */

#define MAX_LAYERS 64

struct soft_ruleset {
    layer_t layers[MAX_LAYERS];
    int     layer_count;
    char    last_error[256];
};

/* ------------------------------------------------------------------ */
/*  Path matching                                                      */
/* ------------------------------------------------------------------ */

/**
 * Match a path against a pattern.
 *
 * Patterns can contain:
 *   - Exact paths: "/usr/bin/cp"
 *   - Wildcards with star: "/etc/", "/dev/sd"
 *   - Recursive with ...: "/home/user/..." (matches any descendant)
 *   - Variables: "${SRC}", "${DST}" (resolved at query time)
 */
static bool path_matches(const char *pattern, const char *path)
{
    if (!pattern || !path) return false;

    /* Handle recursive "..." suffix */
    size_t plen = strlen(pattern);
    if (plen >= 3 && pattern[plen - 3] == '.' &&
        pattern[plen - 2] == '.' && pattern[plen - 1] == '.') {
        /* Pattern "/foo/..." matches "/foo" and any descendant */
        char base[MAX_PATTERN_LEN];
        size_t base_len = plen - 3;
        if (base_len > 0 && pattern[base_len - 1] == '/') base_len--;
        if (base_len >= MAX_PATTERN_LEN) base_len = MAX_PATTERN_LEN - 1;
        memcpy(base, pattern, base_len);
        base[base_len] = '\0';

        if (strcmp(path, base) == 0) return true;
        if (strncmp(path, base, base_len) == 0 && path[base_len] == '/') return true;
        return false;
    }

    /* Handle star wildcards */
    if (strchr(pattern, '*') != NULL) {
        const char *p = pattern, *t = path;
        const char *star_p = NULL, *star_t = NULL;

        while (*t || p < pattern + plen) {
            if (p < pattern + plen && *p == '*') {
                star_p = p;
                star_t = t;
                p++;
            } else if (p < pattern + plen && *p == *t) {
                p++;
                t++;
            } else if (star_p) {
                p = star_p + 1;
                star_t++;
                t = star_t;
            } else {
                return false;
            }
        }
        return true;
    }

    /* Exact match or prefix for non-recursive */
    if (strcmp(pattern, path) == 0) return true;

    /* If pattern ends with '/', treat as directory prefix match */
    size_t plen2 = strlen(pattern);
    if (plen2 > 0 && pattern[plen2 - 1] == '/') {
        return strncmp(path, pattern, plen2) == 0;
    }

    return false;
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
static bool match_with_var(const char *pattern, const char *var_name,
                           const soft_access_ctx_t *ctx)
{
    const char *resolved = resolve_var(var_name, ctx);
    if (!resolved) return false;

    char resolved_pattern[MAX_PATTERN_LEN];
    char placeholder[16];
    snprintf(placeholder, sizeof(placeholder), "${%s}", var_name);

    const char *var_pos = strstr(pattern, placeholder);
    if (!var_pos) return false;

    size_t prefix_len = (size_t)(var_pos - pattern);
    if (prefix_len + strlen(resolved) + strlen(var_pos + strlen(placeholder)) >= MAX_PATTERN_LEN)
        return false;

    memcpy(resolved_pattern, pattern, prefix_len);
    strcpy(resolved_pattern + prefix_len, resolved);
    strcat(resolved_pattern, var_pos + strlen(placeholder));

    return path_matches(resolved_pattern, resolved);
}

/**
 * Match a rule against a path in the given context.
 */
static bool rule_matches_path(const rule_t *rule, const char *path,
                              const soft_access_ctx_t *ctx)
{
    if (!rule || !path) return false;

    bool recursive = (rule->flags & SOFT_RULE_RECURSIVE) != 0;
    bool is_template = (rule->flags & SOFT_RULE_TEMPLATE) != 0;

    /* Templated rules resolve variables at query time */
    if (is_template) {
        if (rule->linked_path_var[0] != '\0') {
            return match_with_var(rule->pattern, rule->linked_path_var, ctx);
        }
        if (pattern_has_var(rule->pattern, "SRC")) {
            return match_with_var(rule->pattern, "SRC", ctx);
        }
        if (pattern_has_var(rule->pattern, "DST")) {
            return match_with_var(rule->pattern, "DST", ctx);
        }
    }

    /* Static pattern matching */
    (void)recursive;
    return path_matches(rule->pattern, path);
}

/**
 * Check subject constraint.
 */
static bool subject_matches(const rule_t *rule, const char *subject)
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
/*  Ruleset management                                                 */
/* ------------------------------------------------------------------ */

soft_ruleset_t *soft_ruleset_new(void)
{
    soft_ruleset_t *rs = calloc(1, sizeof(*rs));
    if (!rs) return NULL;
    rs->layer_count = 0;
    rs->last_error[0] = '\0';
    return rs;
}

void soft_ruleset_free(soft_ruleset_t *rs)
{
    free(rs);
}

/* ------------------------------------------------------------------ */
/*  Layer access                                                      */
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
    if (lyr->count >= MAX_RULES_PER_LAYER) { errno = ENOSPC; return -1; }

    rule_t *r = &lyr->rules[lyr->count];
    memset(r, 0, sizeof(*r));

    size_t plen = strlen(pattern);
    if (plen >= MAX_PATTERN_LEN) { errno = ENAMETOOLONG; return -1; }
    memcpy(r->pattern, pattern, plen + 1);

    r->mode = mode;
    r->op_type = op_type;
    r->min_uid = min_uid;
    r->flags = flags;

    if (linked_path_var) {
        size_t vlen = strlen(linked_path_var);
        if (vlen >= MAX_LINKED_LEN) { errno = EINVAL; return -1; }
        memcpy(r->linked_path_var, linked_path_var, vlen + 1);
    }

    if (subject_regex) {
        size_t slen = strlen(subject_regex);
        if (slen >= sizeof(r->subject_regex)) { errno = EINVAL; return -1; }
        memcpy(r->subject_regex, subject_regex, slen + 1);
    }

    if (strstr(pattern, "${SRC}") || strstr(pattern, "${DST}")) {
        r->flags |= SOFT_RULE_TEMPLATE;
    }

    lyr->count++;
    return 0;
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

    /* Parse optional @layer: prefix */
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
        target_layer = atoi(buf + 1);
        if (target_layer < 0 || target_layer >= MAX_LAYERS) {
            snprintf(rs->last_error, sizeof(rs->last_error),
                     "Layer %d out of range [0..%d)", target_layer, MAX_LAYERS);
            errno = EINVAL;
            return -1;
        }
        expr = colon + 1;
    }

    /* Find "-> mode" separator */
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

    /* Parse op:subject:src_pattern:dst_pattern */
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

static uint32_t op_required_src_mode(soft_binary_op_t op)
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
    default:                return SOFT_ACCESS_READ;
    }
}

static uint32_t op_required_dst_mode(soft_binary_op_t op)
{
    switch (op) {
    case SOFT_OP_COPY:      return SOFT_ACCESS_WRITE;
    case SOFT_OP_MOVE:      return SOFT_ACCESS_WRITE;
    case SOFT_OP_LINK:      return SOFT_ACCESS_WRITE;
    case SOFT_OP_MOUNT:     return SOFT_ACCESS_WRITE;
    case SOFT_OP_CHMOD_CHOWN: return SOFT_ACCESS_WRITE;
    default:                return SOFT_ACCESS_WRITE;
    }
}

/**
 * Evaluate one path against one layer.
 * Static rules first, then templates.
 * Sets out_matched_pattern to the pattern of the matching rule
 * (DENY rule or last matching allow rule), if non-NULL.
 */
static uint32_t eval_layer_path(const layer_t *lyr,
                                const char *path,
                                soft_binary_op_t op,
                                const soft_access_ctx_t *ctx,
                                const char **out_matched_pattern)
{
    if (!path) { if (out_matched_pattern) *out_matched_pattern = NULL; return 0; }
    if (!lyr || lyr->count == 0) { if (out_matched_pattern) *out_matched_pattern = NULL; return 0; }

    uint32_t granted = 0;
    bool has_deny = false;

    /* Pass 1: static rules */
    for (int i = 0; i < lyr->count; i++) {
        const rule_t *r = &lyr->rules[i];
        if (r->flags & SOFT_RULE_TEMPLATE) continue;

        if (r->op_type != op && r->op_type != SOFT_OP_READ &&
            r->op_type != SOFT_OP_WRITE) continue;
        if (!subject_matches(r, ctx->subject)) continue;
        if (r->min_uid > 0 && ctx->uid < r->min_uid) continue;
        if (!rule_matches_path(r, path, ctx)) continue;

        if (r->mode & SOFT_ACCESS_DENY) {
            has_deny = true;
            if (out_matched_pattern) *out_matched_pattern = r->pattern;
            break;
        }
        granted |= r->mode;
        if (out_matched_pattern) *out_matched_pattern = r->pattern;
    }

    if (has_deny) return 0;

    /* Pass 2: template rules */
    for (int i = 0; i < lyr->count; i++) {
        const rule_t *r = &lyr->rules[i];
        if (!(r->flags & SOFT_RULE_TEMPLATE)) continue;

        if (r->op_type != op && r->op_type != SOFT_OP_READ &&
            r->op_type != SOFT_OP_WRITE) continue;
        if (!subject_matches(r, ctx->subject)) continue;
        if (r->min_uid > 0 && ctx->uid < r->min_uid) continue;
        if (!rule_matches_path(r, path, ctx)) continue;

        if (r->mode & SOFT_ACCESS_DENY) {
            has_deny = true;
            if (out_matched_pattern) *out_matched_pattern = r->pattern;
            break;
        }
        granted |= r->mode;
        if (out_matched_pattern) *out_matched_pattern = r->pattern;
    }

    if (has_deny) return 0;
    return granted;
}

/**
 * Evaluate one path across all layers.
 * Returns 0 if any layer explicitly DENYs.
 * Otherwise returns the bitwise AND of all matching layers.
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

    uint32_t intersection = SOFT_ACCESS_ALL;
    bool any_layer_matched = false;
    const char *last_pattern = NULL;

    for (int i = 0; i < rs->layer_count; i++) {
        const layer_t *lyr = &rs->layers[i];
        if (lyr->count == 0) continue;

        const char *layer_pattern = NULL;
        uint32_t granted = eval_layer_path(lyr, path, op, ctx, &layer_pattern);

        if (granted == 0 && layer_pattern != NULL) {
            /* Explicit DENY in this layer */
            if (out_deny_layer) *out_deny_layer = i;
            if (out_matched_pattern) *out_matched_pattern = layer_pattern;
            return 0;
        }

        if (layer_pattern != NULL) {
            /* Layer had a matching rule (allow) */
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
                      ctx->op == SOFT_OP_LINK || ctx->op == SOFT_OP_MOUNT);

    int deny_layer = -1;
    const char *matched_pattern = NULL;

    if (is_binary) {
        int src_deny = -1, dst_deny = -1;
        const char *src_pattern = NULL, *dst_pattern = NULL;

        uint32_t src_granted = eval_all_layers(rs, ctx->src_path, ctx->op, ctx,
                                               &src_deny, &src_pattern);
        if (src_deny >= 0) {
            if (out_log) {
                out_log->result = -EACCES;
                out_log->deny_reason = "SRC denied by layer";
                out_log->deny_layer = src_deny;
                out_log->matched_rule = src_pattern;
            }
            return -EACCES;
        }

        uint32_t src_req = op_required_src_mode(ctx->op);
        if ((src_granted & src_req) != src_req) {
            if (out_log) {
                out_log->result = -EACCES;
                out_log->deny_reason = "SRC insufficient mode";
                out_log->deny_layer = -1;
                out_log->matched_rule = NULL;
            }
            return -EACCES;
        }

        uint32_t dst_granted = eval_all_layers(rs, ctx->dst_path, ctx->op, ctx,
                                               &dst_deny, &dst_pattern);
        if (dst_deny >= 0) {
            if (out_log) {
                out_log->result = -EACCES;
                out_log->deny_reason = "DST denied by layer";
                out_log->deny_layer = dst_deny;
                out_log->matched_rule = dst_pattern;
            }
            return -EACCES;
        }

        uint32_t dst_req = op_required_dst_mode(ctx->op);
        if ((dst_granted & dst_req) != dst_req) {
            if (out_log) {
                out_log->result = -EACCES;
                out_log->deny_reason = "DST insufficient mode";
                out_log->deny_layer = -1;
                out_log->matched_rule = NULL;
            }
            return -EACCES;
        }

        uint32_t result = src_granted | dst_granted;
        if (out_log) {
            out_log->result = (int)result;
            out_log->deny_layer = -1;
            out_log->matched_rule = src_pattern;
        }
        return (int)result;
    }

    uint32_t req = op_required_src_mode(ctx->op);
    uint32_t granted = eval_all_layers(rs, ctx->src_path, ctx->op, ctx,
                                       &deny_layer, &matched_pattern);

    if (deny_layer >= 0) {
        if (out_log) {
            out_log->result = -EACCES;
            out_log->deny_reason = "Access denied by layer";
            out_log->deny_layer = deny_layer;
            out_log->matched_rule = matched_pattern;
        }
        return -EACCES;
    }

    if ((granted & req) != req) {
        if (out_log) {
            out_log->result = -EACCES;
            out_log->deny_reason = "Insufficient access mode";
            out_log->deny_layer = -1;
            out_log->matched_rule = NULL;
        }
        return -EACCES;
    }

    if (out_log) {
        out_log->result = (int)granted;
        out_log->deny_layer = -1;
        out_log->matched_rule = matched_pattern;
    }
    return (int)granted;
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

/**
 * Extract the parent directory of a path.
 * "/a/b/c.txt" -> "/a/b"
 * "/a"          -> "/"
 * "/"           -> "/"
 */
static void parent_dir(const char *path, char *out, size_t out_size)
{
    if (!path || out_size == 0) { out[0] = '\0'; return; }

    size_t len = strlen(path);
    /* Strip trailing slash */
    while (len > 1 && path[len - 1] == '/') len--;

    /* Find last slash */
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

/**
 * Look up a path in the batch cache.
 */
static batch_cache_entry_t *batch_cache_lookup(batch_cache_entry_t *cache,
                                               const char *path)
{
    for (int i = 0; i < BATCH_CACHE_SIZE; i++) {
        if (cache[i].valid && strcmp(cache[i].path, path) == 0)
            return &cache[i];
    }
    return NULL;
}

/**
 * Store a result in the batch cache (evict first invalid entry).
 */
static void batch_cache_store(batch_cache_entry_t *cache,
                              const char *path,
                              uint32_t granted,
                              int deny_layer)
{
    /* Find a free slot */
    for (int i = 0; i < BATCH_CACHE_SIZE; i++) {
        if (!cache[i].valid) {
            strncpy(cache[i].path, path, PATH_MAX - 1);
            cache[i].path[PATH_MAX - 1] = '\0';
            cache[i].granted = granted;
            cache[i].deny_layer = deny_layer;
            cache[i].valid = 1;
            return;
        }
    }
    /* Cache full: evict entry 0 (oldest) and store there */
    batch_cache_entry_t *e = &cache[0];
    strncpy(e->path, path, PATH_MAX - 1);
    e->path[PATH_MAX - 1] = '\0';
    e->granted = granted;
    e->deny_layer = deny_layer;
    e->valid = 1;
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

    for (int i = 0; i < count; i++) {
        const soft_access_ctx_t *ctx = ctxs[i];
        if (!ctx) { results[i] = -EACCES; continue; }

        bool is_binary = (ctx->op == SOFT_OP_COPY || ctx->op == SOFT_OP_MOVE ||
                          ctx->op == SOFT_OP_LINK || ctx->op == SOFT_OP_MOUNT);

        /* Try cache for parent directories first */
        char src_parent[PATH_MAX], dst_parent[PATH_MAX];
        parent_dir(ctx->src_path, src_parent, sizeof(src_parent));
        if (is_binary && ctx->dst_path)
            parent_dir(ctx->dst_path, dst_parent, sizeof(dst_parent));
        else
            dst_parent[0] = '\0';

        uint32_t src_granted = 0, dst_granted = 0;
        int src_deny = -1, dst_deny = -1;

        /* Check SRC cache */
        batch_cache_entry_t *src_hit = batch_cache_lookup(src_cache, ctx->src_path);
        batch_cache_entry_t *src_par = batch_cache_lookup(src_cache, src_parent);
        if (src_hit) {
            src_granted = src_hit->granted;
            src_deny = src_hit->deny_layer;
        } else if (src_par) {
            /* Parent hit: evaluate only the child component against parent result */
            src_granted = src_par->granted;
            src_deny = src_par->deny_layer;
        } else {
            src_granted = eval_all_layers(rs, ctx->src_path, ctx->op, ctx,
                                          &src_deny, NULL);
            batch_cache_store(src_cache, ctx->src_path, src_granted, src_deny);
            batch_cache_store(src_cache, src_parent, src_granted, src_deny);
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
                batch_cache_store(dst_cache, ctx->dst_path, dst_granted, dst_deny);
                batch_cache_store(dst_cache, dst_parent, dst_granted, dst_deny);
            }
        }

        if (is_binary) {
            if (src_deny >= 0 || dst_deny >= 0) {
                results[i] = -EACCES;
            } else {
                uint32_t src_req = op_required_src_mode(ctx->op);
                uint32_t dst_req = op_required_dst_mode(ctx->op);
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
                uint32_t req = op_required_src_mode(ctx->op);
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
