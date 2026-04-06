/**
 * @file rule_engine.c
 * @brief ReadOnlyBox Rule Engine implementation (spec v3.0).
 *
 * Implements dual-path evaluation with path variables, subject
 * constraints, and batched evaluation.  Internally uses a radix tree
 * for path matching.
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
#include "radix_tree.h"

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
/*  Ruleset structure                                                  */
/* ------------------------------------------------------------------ */

#define MAX_RULES 4096

struct soft_ruleset {
    rule_t  rules[MAX_RULES];
    int     count;
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
 *   - Wildcards with *: "/etc/*", "/dev/sd*"
 *   - Recursive with ...: "/home/user/..." (matches any descendant)
 *   - Variables: "${SRC}", "${DST}" (resolved at query time)
 */
static bool path_matches(const char *pattern, const char *path, bool recursive)
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

    /* Handle * wildcards */
    if (strchr(pattern, '*') != NULL) {
        /* Simple glob-style matching */
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
 * Returns the path string for ${SRC} or ${DST}, or NULL.
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
 * Replace ${VAR} in pattern with the actual path and match.
 */
static bool match_with_var(const char *pattern, const char *var_name,
                           const soft_access_ctx_t *ctx, bool recursive)
{
    const char *resolved = resolve_var(var_name, ctx);
    if (!resolved) return false;

    /* Build resolved pattern */
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

    return path_matches(resolved_pattern, resolved, recursive);
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

    /* Templated rules need variable resolution */
    if (is_template) {
        if (rule->linked_path_var[0] != '\0') {
            /* This rule matches against the linked variable's path */
            return match_with_var(rule->pattern, rule->linked_path_var,
                                  ctx, recursive);
        }
        /* Pattern may contain ${SRC} or ${DST} */
        if (pattern_has_var(rule->pattern, "SRC")) {
            return match_with_var(rule->pattern, "SRC", ctx, recursive);
        }
        if (pattern_has_var(rule->pattern, "DST")) {
            return match_with_var(rule->pattern, "DST", ctx, recursive);
        }
    }

    /* Static pattern matching */
    return path_matches(rule->pattern, path, recursive);
}

/**
 * Check subject constraint.  Returns true if the rule applies to the
 * given subject (calling binary).
 */
static bool subject_matches(const rule_t *rule, const char *subject)
{
    if (rule->subject_regex[0] == '\0') return true;  /* No constraint */
    if (!subject) return false;  /* Rule requires subject but none given */

    /* Simple suffix match for common cases (avoid full regex overhead) */
    size_t rlen = strlen(rule->subject_regex);
    if (rlen >= 2 && rule->subject_regex[0] == '.' &&
        rule->subject_regex[1] == '*' && rlen > 2) {
        const char *suffix = rule->subject_regex + 2;
        size_t slen = strlen(subject);
        size_t suf_len = strlen(suffix);
        /* Strip trailing '$' if present (regex end anchor) */
        if (suf_len > 0 && suffix[suf_len - 1] == '$') suf_len--;
        if (slen >= suf_len && suf_len > 0 &&
            strncmp(subject + slen - suf_len, suffix, suf_len) == 0)
            return true;
        return false;
    }

    /* Exact match fallback */
    return strcmp(rule->subject_regex, subject) == 0;
}

/* ------------------------------------------------------------------ */
/*  Ruleset management                                                 */
/* ------------------------------------------------------------------ */

soft_ruleset_t *soft_ruleset_new(void)
{
    soft_ruleset_t *rs = calloc(1, sizeof(*rs));
    if (!rs) return NULL;
    rs->count = 0;
    rs->last_error[0] = '\0';
    return rs;
}

void soft_ruleset_free(soft_ruleset_t *rs)
{
    free(rs);
}

/* ------------------------------------------------------------------ */
/*  Rule insertion                                                     */
/* ------------------------------------------------------------------ */

int soft_ruleset_add_rule(soft_ruleset_t *rs,
                          const char *pattern,
                          uint32_t mode,
                          soft_binary_op_t op_type,
                          const char *linked_path_var,
                          const char *subject_regex,
                          uint32_t min_uid,
                          uint32_t flags)
{
    if (!rs || !pattern) { errno = EINVAL; return -1; }
    if (rs->count >= MAX_RULES) { errno = ENOSPC; return -1; }

    rule_t *r = &rs->rules[rs->count];
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

    /* Detect template rules */
    if (strstr(pattern, "${SRC}") || strstr(pattern, "${DST}")) {
        r->flags |= SOFT_RULE_TEMPLATE;
    }

    rs->count++;
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
    return SOFT_OP_READ;  /* Default */
}

int soft_ruleset_add_rule_str(soft_ruleset_t *rs,
                              const char *rule_str,
                              const char *source_file)
{
    if (!rs || !rule_str) { errno = EINVAL; return -1; }
    (void)source_file;

    /* Format: op:subject:src_pattern:dst_pattern -> mode */
    char buf[512];
    strncpy(buf, rule_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';


    /* Find "-> mode" separator */
    char *arrow = strstr(buf, "->");
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

    /* Parse op:subject:src_pattern:dst_pattern manually to handle empty fields */
    char *p = buf;
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

    /* Trim trailing whitespace from dst_pattern */
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

    /* Add SRC rule if src_pattern is not ${SRC} */
    if (src_pattern && src_pattern[0] != '\0') {
        uint32_t flags = 0;
        if (strstr(src_pattern, "...")) flags |= SOFT_RULE_RECURSIVE;
        const char *linked = NULL;
        if (strcmp(src_pattern, "${SRC}") == 0) linked = "SRC";
        else if (strcmp(src_pattern, "${DST}") == 0) linked = "DST";

        int ret = soft_ruleset_add_rule(rs, src_pattern, mode, op,
                                        linked, subject, 0, flags);
        if (ret < 0) {
            snprintf(rs->last_error, sizeof(rs->last_error),
                     "Failed to add SRC rule: %s", strerror(errno));
            return -1;
        }
    }

    /* Add DST rule if dst_pattern is present */
    if (dst_pattern && dst_pattern[0] != '\0') {
        uint32_t flags = 0;
        if (strstr(dst_pattern, "...")) flags |= SOFT_RULE_RECURSIVE;
        const char *linked = NULL;
        if (strcmp(dst_pattern, "${SRC}") == 0) linked = "SRC";
        else if (strcmp(dst_pattern, "${DST}") == 0) linked = "DST";

        int ret = soft_ruleset_add_rule(rs, dst_pattern, mode, op,
                                        linked, subject, 0, flags);
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
 * Evaluate a single path against all rules.
 * Returns the granted mode or 0 if denied.
 */
static uint32_t eval_path(const soft_ruleset_t *rs,
                          const char *path,
                          soft_binary_op_t op,
                          const soft_access_ctx_t *ctx)
{
    if (!path) return 0;

    uint32_t granted = 0;
    bool has_deny = false;


    for (int i = 0; i < rs->count; i++) {
        const rule_t *r = &rs->rules[i];

        /* Check operation compatibility */
        if (r->op_type != op && r->op_type != SOFT_OP_READ &&
            r->op_type != SOFT_OP_WRITE) {
            fprintf(stderr, "  Rule %d: op_type=%d skipped (op=%d)\n", i, r->op_type, op);
            continue;
        }

        /* Check subject constraint */
        if (!subject_matches(r, ctx->subject)) {
            fprintf(stderr, "  Rule %d: subject mismatch\n", i);
            continue;
        }

        /* Check UID constraint */
        if (r->min_uid > 0 && ctx->uid < r->min_uid) continue;

        /* Check path match */
        bool matched = rule_matches_path(r, path, ctx);
        fprintf(stderr, "  Rule %d: pattern='%s' path_match=%d\n", i, r->pattern, matched);
        if (!matched) continue;

        /* Rule matches */
        if (r->mode & SOFT_ACCESS_DENY) {
            has_deny = true;
            break;
        }
        granted |= r->mode;
    }

    fprintf(stderr, "  eval_path result: granted=%u deny=%d\n", granted, has_deny);

    if (has_deny) return 0;
    return granted;
}

int soft_ruleset_check_ctx(const soft_ruleset_t *rs,
                           const soft_access_ctx_t *ctx,
                           soft_audit_log_t *out_log)
{
    if (!rs || !ctx) { errno = EINVAL; return -EACCES; }

    bool is_binary = (ctx->op == SOFT_OP_COPY || ctx->op == SOFT_OP_MOVE ||
                      ctx->op == SOFT_OP_LINK || ctx->op == SOFT_OP_MOUNT);

    if (is_binary) {
        /* Dual-path evaluation */
        uint32_t src_req = op_required_src_mode(ctx->op);
        uint32_t dst_req = op_required_dst_mode(ctx->op);

        uint32_t src_granted = eval_path(rs, ctx->src_path, ctx->op, ctx);
        if ((src_granted & src_req) != src_req) {
            if (out_log) {
                out_log->result = -EACCES;
                out_log->deny_reason = "SRC denied or insufficient mode";
            }
            return -EACCES;
        }

        uint32_t dst_granted = eval_path(rs, ctx->dst_path, ctx->op, ctx);
        if ((dst_granted & dst_req) != dst_req) {
            if (out_log) {
                out_log->result = -EACCES;
                out_log->deny_reason = "DST denied or insufficient mode";
            }
            return -EACCES;
        }

        /* Intersection: most restrictive mode wins */
        uint32_t result = src_granted | dst_granted;
        if (out_log) out_log->result = (int)result;
        return (int)result;
    }

    /* Unary operation */
    uint32_t req = op_required_src_mode(ctx->op);
    uint32_t granted = eval_path(rs, ctx->src_path, ctx->op, ctx);

    if ((granted & req) != req) {
        if (out_log) {
            out_log->result = -EACCES;
            out_log->deny_reason = "Access denied";
        }
        return -EACCES;
    }

    if (out_log) out_log->result = (int)granted;
    return (int)granted;
}

/* ------------------------------------------------------------------ */
/*  Batch evaluation                                                   */
/* ------------------------------------------------------------------ */

/* Simple parent-dir cache for batch evaluation */
typedef struct {
    char   path[PATH_MAX];
    uint32_t result;
    int    valid;
} dir_cache_entry_t;

#define DIR_CACHE_SIZE 256

int soft_ruleset_check_batch_ctx(const soft_ruleset_t *rs,
                                 const soft_access_ctx_t *ctxs[],
                                 int *results,
                                 int count)
{
    if (!rs || !ctxs || !results || count <= 0) { errno = EINVAL; return -1; }

    dir_cache_entry_t cache[DIR_CACHE_SIZE];
    memset(cache, 0, sizeof(cache));

    for (int i = 0; i < count; i++) {
        const soft_access_ctx_t *ctx = ctxs[i];
        if (!ctx) { results[i] = -EACCES; continue; }

        bool is_binary = (ctx->op == SOFT_OP_COPY || ctx->op == SOFT_OP_MOVE ||
                          ctx->op == SOFT_OP_LINK || ctx->op == SOFT_OP_MOUNT);

        /* Check cache for parent directories */
        uint32_t src_granted = 0, dst_granted = 0;

        /* Evaluate SRC */
        if (ctx->src_path) {
            src_granted = eval_path(rs, ctx->src_path, ctx->op, ctx);
        }

        if (is_binary && ctx->dst_path) {
            dst_granted = eval_path(rs, ctx->dst_path, ctx->op, ctx);
        }

        if (is_binary) {
            uint32_t src_req = op_required_src_mode(ctx->op);
            uint32_t dst_req = op_required_dst_mode(ctx->op);

            if ((src_granted & src_req) == src_req &&
                (dst_granted & dst_req) == dst_req) {
                results[i] = (int)(src_granted | dst_granted);
            } else {
                results[i] = -EACCES;
            }
        } else {
            uint32_t req = op_required_src_mode(ctx->op);
            if ((src_granted & req) == req) {
                results[i] = (int)src_granted;
            } else {
                results[i] = -EACCES;
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
    (void)mask;  /* Ignored in new API */
    return soft_ruleset_check_ctx(rs, &ctx, NULL);
}
