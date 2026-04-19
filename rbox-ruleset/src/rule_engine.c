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
#include <ctype.h>
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

    size_t plen = strlen(pattern);
    size_t tlen = strlen(text);

    /* Fast path: recursive "..." suffix — prefix match only */
    if (plen >= 3 && pattern[plen - 3] == '.' &&
        pattern[plen - 2] == '.' && pattern[plen - 1] == '.') {
        size_t base_len = plen - 3;
        if (base_len > 0 && pattern[base_len - 1] == '/') base_len--;
        if (base_len >= MAX_PATTERN_LEN) base_len = MAX_PATTERN_LEN - 1;

        if (tlen == base_len && memcmp(text, pattern, base_len) == 0) return true;
        if (tlen > base_len && memcmp(text, pattern, base_len) == 0 &&
            text[base_len] == '/') return true;
        return false;
    }

    /* Fast path: no wildcards — exact match or directory prefix */
    if (strchr(pattern, '*') == NULL) {
        if (plen == tlen && memcmp(pattern, text, plen) == 0) return true;
        if (plen > 0 && pattern[plen - 1] == '/')
            return tlen >= plen && memcmp(text, pattern, plen) == 0;
        return false;
    }

    /* Fast path: prefix pattern ending with / ** -- simple prefix check */
    if (plen >= 3 && pattern[plen - 3] == '/' &&
        pattern[plen - 2] == '*' && pattern[plen - 1] == '*') {
        size_t prefix_len = plen - 3;
        if (tlen == prefix_len && memcmp(text, pattern, prefix_len) == 0) return true;
        if (tlen > prefix_len && memcmp(text, pattern, prefix_len) == 0 &&
            text[prefix_len] == '/') return true;
        return false;
    }

    /* Fast path: single-level wildcard ending with / * -- exact match only
     * (can't determine single-segment match without full glob, but for the
     * common case of exact segment match, check prefix first) */

    /* Full glob matching with * (single segment) and ** (multi-segment) */
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
 *
 * Supported subject pattern syntax (simplified, no regex):
 *   - Empty string or NULL: match any subject
 *   - Exact string: exact match (e.g., "/usr/bin/admin")
 *   - "*suffix": match any characters (except '/') then suffix
 *   - "**suffix": match any characters (including '/') then suffix
 *   - "$" at end anchors to end of string
 */
bool subject_matches(const rule_t *rule, const char *subject)
{
    if (rule->subject_regex[0] == '\0') return true;
    if (!subject) return false;

    const char *pat = rule->subject_regex;
    size_t plen = strlen(pat);
    size_t slen = strlen(subject);

    /* Check for "**" prefix (match any including '/') */
    if (plen >= 2 && pat[0] == '*' && pat[1] == '*') {
        const char *suffix = pat + 2;
        size_t suf_len = strlen(suffix);
        /* Strip trailing '$' if present */
        if (suf_len > 0 && suffix[suf_len - 1] == '$') suf_len--;
        if (slen >= suf_len && suf_len > 0 &&
            strncmp(subject + slen - suf_len, suffix, suf_len) == 0)
            return true;
        return false;
    }

    /* Check for "*" prefix (match any except '/') */
    if (plen >= 1 && pat[0] == '*') {
        const char *suffix = pat + 1;
        size_t suf_len = strlen(suffix);
        /* Strip trailing '$' if present */
        if (suf_len > 0 && suffix[suf_len - 1] == '$') suf_len--;
        if (slen >= suf_len && suf_len > 0 &&
            strncmp(subject + slen - suf_len, suffix, suf_len) == 0) {
            /* Verify no '/' in the prefix part */
            size_t prefix_len = slen - suf_len;
            for (size_t i = 0; i < prefix_len; i++) {
                if (subject[i] == '/') return false;
            }
            return true;
        }
        return false;
    }

    /* Strip trailing '$' for exact match */
    if (plen > 0 && pat[plen - 1] == '$') {
        plen--;
    }

    if (plen != slen) return false;
    return strncmp(pat, subject, plen) == 0;
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
    
    // Initialize cache LRU tracking
    for (uint32_t i = 0; i < QUERY_CACHE_SETS; i++) {
        for (uint8_t j = 0; j < QUERY_CACHE_WAYS; j++) {
            rs->query_cache[i].lru_order[j] = 0xFF; // Mark as invalid
        }
    }
    
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

/**
 * Update LRU order for a cache entry within a set.
 * Moves the specified way to MRU position (0).
 */
static void cache_lru_update(query_cache_set_t *set, uint8_t way)
{
    // Move the accessed way to MRU position (0)
    if (way == 0) return; // Already MRU
    
    // Shift all MRU entries down to make room
    for (uint8_t i = 0; i < way; i++) {
        if (set->lru_order[i] == way) {
            // Found it, shift it to MRU
            memmove(&set->lru_order[1], &set->lru_order[0], i);
            set->lru_order[0] = way;
            return;
        }
    }
    
    // If not found in LRU array, initialize it
    set->lru_order[0] = way;
    for (uint8_t i = 1; i < QUERY_CACHE_WAYS; i++) {
        if (set->lru_order[i] == way) {
            set->lru_order[i] = 0xFF; // Mark as invalid
        }
    }
}

/**
 * Find the LRU entry in a cache set.
 * Returns the way index of the LRU entry, or 0xFF if set is empty.
 */
static uint8_t cache_find_lru(const query_cache_set_t *set)
{
    // Find the first invalid entry (prefer reusing invalid over evicting valid)
    for (uint8_t i = 0; i < QUERY_CACHE_WAYS; i++) {
        if (!set->entries[i].valid) {
            return i;
        }
    }
    
    // Find the LRU valid entry by scanning from LRU position backwards
    // The LRU array contains valid way indices in [MRU, ..., LRU] order
    // 0xFF means empty slot, so we need to find the last valid entry
    uint8_t lru_way = 0xFF;
    for (int8_t i = QUERY_CACHE_WAYS - 1; i >= 0; i--) {
        if (set->lru_order[i] != 0xFF) {
            lru_way = set->lru_order[i];
            break;
        }
    }

    if (lru_way != 0xFF) {
        return lru_way;
    }

    // Fallback: return first entry if LRU tracking is corrupted
    return 0;
}
// Look up cached result for a single path. 8-way set associative with LRU.
static query_cache_entry_t *query_cache_lookup(soft_ruleset_t *rs,
                                                uint64_t phash,
                                                uint32_t subject_hash,
                                                uint32_t required_mode)
{
    uint32_t set_idx = (uint32_t)(phash % QUERY_CACHE_SETS);
    query_cache_set_t *set = &rs->query_cache[set_idx];
    
    // Search all ways in the set
    for (uint8_t way = 0; way < QUERY_CACHE_WAYS; way++) {
        query_cache_entry_t *e = &set->entries[way];
        if (e->valid && e->path_hash == phash &&
            e->subject_hash == subject_hash &&
            (e->eval & required_mode) == required_mode) {
            // Update LRU order
            cache_lru_update(set, way);
            return e;
        }
    }
    return NULL;
}

// Store a result in the cache (8-way set associative with LRU eviction).
static void query_cache_store(soft_ruleset_t *rs,
                              uint64_t phash,
                              uint32_t subject_hash,
                              uint32_t granted,
                              uint32_t eval,
                              int32_t deny_layer,
                              uint8_t any_matched)
{
    uint32_t set_idx = (uint32_t)(phash % QUERY_CACHE_SETS);
    query_cache_set_t *set = &rs->query_cache[set_idx];
    
    // Find an empty slot or LRU entry to evict
    uint8_t way = cache_find_lru(set);
    
    // Store the new entry
    query_cache_entry_t *e = &set->entries[way];
    e->path_hash = phash;
    e->subject_hash = subject_hash;
    e->granted = granted;
    e->eval = eval;
    e->deny_layer = deny_layer;
    e->any_matched = any_matched;
    e->valid = 1;
    
    // Update LRU order
    cache_lru_update(set, way);
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
                          uint32_t flags)
{
    return soft_ruleset_add_rule_at_layer(rs, 0, pattern, mode, op_type,
                                          linked_path_var, subject_regex,
                                          flags);
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
                                                 mode, op, linked, subject, flags);
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
                                                 mode, op, linked, subject, flags);
        if (ret < 0) {
            snprintf(rs->last_error, sizeof(rs->last_error),
                     "Failed to add DST rule: %s", strerror(errno));
            return -1;
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Compact CLI rule parser                                            */
/* ------------------------------------------------------------------ */

/**
 * Parse mode chars for compact syntax: r,w,x,D,ro (case-insensitive).
 * "ro" is treated as an alias for "r" (read-only).
 */
static uint32_t parse_compact_mode(const char *s)
{
    uint32_t mode = 0;
    for (; *s; s++) {
        char c = (char)tolower((unsigned char)*s);
        /* Handle "ro" as a unit: if we see 'r' followed by 'o', it's read-only */
        if (c == 'r') {
            mode |= SOFT_ACCESS_READ;
        } else if (c == 'w') {
            mode |= SOFT_ACCESS_WRITE;
        } else if (c == 'x') {
            mode |= SOFT_ACCESS_EXEC;
        } else if (c == 'd') {
            mode = SOFT_ACCESS_DENY;
            return mode;  /* DENY overrides everything */
        } else if (c == 'o') {
            /* 'o' alone is meaningless; only matters after 'r' (ro) */
            /* If no 'r' seen, ignore */
        }
        /* Unknown chars are silently ignored for robustness */
    }
    if (mode == 0) mode = SOFT_ACCESS_READ;  /* default: read */
    return mode;
}

int soft_ruleset_parse_compact_rules(soft_ruleset_t *rs,
                                     const char *rules_str,
                                     const char *source_name)
{
    if (!rs || !rules_str) { errno = EINVAL; return -1; }

    const char *p = rules_str;
    int rule_idx = 0;

    while (*p) {
        /* Skip leading whitespace/commas */
        while (*p == ',' || *p == ' ' || *p == '\t') p++;
        if (*p == '\0') break;

        /* Find the path:mode separator (last colon in the token) */
        const char *token_start = p;
        const char *colon = NULL;
        const char *scan = p;
        int in_brace = 0;

        while (*scan && *scan != ',') {
            if (*scan == '{') in_brace++;
            else if (*scan == '}') in_brace--;
            else if (*scan == ':' && in_brace == 0) colon = scan;
            scan++;
        }

        if (!colon) {
            /* No colon — treat entire token as path with default READ mode.
             * This allows bare paths like "/usr/bin" to default to read. */
            colon = scan;  /* mode portion is empty */
        }

        /* Extract path */
        size_t path_len = (size_t)(colon - token_start);
        if (path_len == 0) {
            snprintf(rs->last_error, sizeof(rs->last_error),
                     "%s: rule %d: empty path",
                     source_name ? source_name : "compact", rule_idx);
            errno = EINVAL;
            return -1;
        }
        char path[MAX_PATTERN_LEN];
        if (path_len >= sizeof(path)) {
            snprintf(rs->last_error, sizeof(rs->last_error),
                     "%s: rule %d: path too long",
                     source_name ? source_name : "compact", rule_idx);
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(path, token_start, path_len);
        path[path_len] = '\0';

        /* Extract mode string (may be empty if no colon was found) */
        const char *mode_start = colon + 1;
        const char *mode_end = scan;
        size_t mode_len = 0;
        if (mode_end > mode_start)
            mode_len = (size_t)(mode_end - mode_start);
        char mode_buf[16];
        if (mode_len >= sizeof(mode_buf)) {
            snprintf(rs->last_error, sizeof(rs->last_error),
                     "%s: rule %d: mode string too long",
                     source_name ? source_name : "compact", rule_idx);
            errno = EINVAL;
            return -1;
        }
        if (mode_len > 0)
            memcpy(mode_buf, mode_start, mode_len);
        mode_buf[mode_len] = '\0';

        uint32_t mode = parse_compact_mode(mode_buf);
        uint32_t flags = 0;

        /* Detect recursive wildcards */
        size_t pl = strlen(path);
        if (pl >= 3 && path[pl - 3] == '.' &&
            path[pl - 2] == '.' && path[pl - 1] == '.') {
            flags |= SOFT_RULE_RECURSIVE;
        }
        /* Path ending with /... is also recursive */
        if (pl >= 3 && path[pl - 3] == '/' &&
            path[pl - 2] == '*' && path[pl - 1] == '*') {
            flags |= SOFT_RULE_RECURSIVE;
        }

        int ret = soft_ruleset_add_rule(rs, path, mode, SOFT_OP_READ,
                                        NULL, NULL, flags);
        if (ret < 0) {
            snprintf(rs->last_error, sizeof(rs->last_error),
                     "%s: rule %d: failed to add rule for '%.100s': %.50s",
                     source_name ? source_name : "compact", rule_idx,
                     path, strerror(errno));
            return -1;
        }

        rule_idx++;
        p = scan;
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
                           uint32_t *out_granted,
                           soft_audit_log_t *out_log)
{
    if (!rs || !ctx) { if (out_granted) *out_granted = 0; return 0; }

    /* Track eval calls */
    ((soft_ruleset_t *)rs)->stats_eval_calls++;

    bool is_binary = (ctx->op == SOFT_OP_COPY || ctx->op == SOFT_OP_MOVE ||
                      ctx->op == SOFT_OP_LINK || ctx->op == SOFT_OP_MOUNT ||
                      ctx->op >= SOFT_OP_CUSTOM);

    uint64_t subj_hash = fnv1a_str(ctx->subject);
    uint32_t eval_mask = eval_mode_for_op(ctx->op);
    uint32_t granted = 0;
    int determined = 0;  /* 1 = ruleset made a decision, 0 = undetermined */

    /* Try cache lookup (skip if audit log requested) */
    if (!out_log) {
        soft_ruleset_t *mutable = (soft_ruleset_t *)rs;
        uint64_t src_hash = path_hash(ctx->src_path);
        uint32_t src_req = op_required_src_mode(rs, ctx->op);
        query_cache_entry_t *src_hit = query_cache_lookup(mutable, src_hash,
                                                           (uint32_t)subj_hash, src_req);

        if (is_binary) {
            uint64_t dst_hash = path_hash(ctx->dst_path);
            uint32_t dst_req = op_required_dst_mode(rs, ctx->op);
            query_cache_entry_t *dst_hit = query_cache_lookup(mutable, dst_hash,
                                                               (uint32_t)subj_hash, dst_req);

            if (src_hit && dst_hit) {
                /* Both subqueries cached and cover required modes */
                mutable->stats_cache_hits += 2;
                if (src_hit->deny_layer >= 0 || dst_hit->deny_layer >= 0) {
                    /* Denied by rule */
                    if (out_granted) *out_granted = 0;
                    if (out_log) {
                        out_log->result = 0;
                        out_log->deny_reason = src_hit->deny_layer >= 0 ? "SRC denied" : "DST denied";
                        out_log->deny_layer = src_hit->deny_layer >= 0 ? src_hit->deny_layer : dst_hit->deny_layer;
                        out_log->matched_rule = NULL;
                    }
                    return 1;
                }
                /* If neither sub-query matched any rule, return undetermined */
                if (!src_hit->any_matched && !dst_hit->any_matched) {
                    if (out_granted) *out_granted = 0;
                    return 0;
                }
                if ((src_hit->granted & src_req) != src_req ||
                    (dst_hit->granted & dst_req) != dst_req) {
                    if (out_granted) *out_granted = 0;
                    if (out_log) {
                        out_log->result = 0;
                        out_log->deny_reason = "Insufficient mode";
                        out_log->deny_layer = -1;
                        out_log->matched_rule = NULL;
                    }
                    return 1;
                }
                granted = src_hit->granted | dst_hit->granted;
                determined = 1;
            } else {
                if (src_hit) mutable->stats_cache_hits++;
                else mutable->stats_cache_misses++;
                if (dst_hit) mutable->stats_cache_hits++;
                else mutable->stats_cache_misses++;
            }
        } else if (src_hit) {
            /* Unary op, fully cached */
            mutable->stats_cache_hits++;
            if (!src_hit->any_matched) {
                /* No rules matched */
                if (out_granted) *out_granted = 0;
                return 0;
            }
            uint32_t req = op_required_src_mode(rs, ctx->op);
            if (src_hit->deny_layer >= 0 || (src_hit->granted & req) != req) {
                if (out_granted) *out_granted = 0;
                if (out_log) {
                    out_log->result = 0;
                    out_log->deny_reason = src_hit->deny_layer >= 0 ? "Denied by rule" : "Insufficient mode";
                    out_log->deny_layer = src_hit->deny_layer;
                    out_log->matched_rule = NULL;
                }
                return 1;
            }
            granted = src_hit->granted;
            determined = 1;
        } else {
            mutable->stats_cache_misses++;
        }
    }

    if (!determined) {
        /* Evaluate */
        if (is_binary) {
            int src_deny = -1, dst_deny = -1;
            uint32_t src_granted = 0, dst_granted = 0;
            const char *src_pattern = NULL, *dst_pattern = NULL;

            src_granted = eval_all_layers(rs, ctx->src_path, ctx->op, ctx,
                                          &src_deny, &src_pattern);
            if (src_deny >= 0) {
                granted = 0; determined = 1;
                if (out_log) {
                    out_log->result = 0;
                    out_log->deny_reason = "SRC denied by layer";
                    out_log->deny_layer = src_deny;
                    out_log->matched_rule = src_pattern;
                }
            } else {
                uint32_t src_req = op_required_src_mode(rs, ctx->op);
                if ((src_granted & src_req) != src_req) {
                    granted = 0; determined = 1;
                    if (out_log) {
                        out_log->result = 0;
                        out_log->deny_reason = "SRC insufficient mode";
                        out_log->deny_layer = -1;
                        out_log->matched_rule = NULL;
                    }
                } else {
                    dst_granted = eval_all_layers(rs, ctx->dst_path, ctx->op, ctx,
                                                  &dst_deny, &dst_pattern);
                    if (dst_deny >= 0) {
                        granted = 0; determined = 1;
                        if (out_log) {
                            out_log->result = 0;
                            out_log->deny_reason = "DST denied by layer";
                            out_log->deny_layer = dst_deny;
                            out_log->matched_rule = dst_pattern;
                        }
                    } else {
                        uint32_t dst_req = op_required_dst_mode(rs, ctx->op);
                        if ((dst_granted & dst_req) != dst_req) {
                            granted = 0; determined = 1;
                            if (out_log) {
                                out_log->result = 0;
                                out_log->deny_reason = "DST insufficient mode";
                                out_log->deny_layer = -1;
                                out_log->matched_rule = NULL;
                            }
                        } else {
                            granted = src_granted | dst_granted;
                            determined = 1;
                            if (out_log) {
                                out_log->result = (int)granted;
                                out_log->deny_layer = -1;
                                out_log->matched_rule = src_pattern;
                            }
                        }
                    }
                }
            }

            /* Cache subquery results independently */
            if (!out_log && determined) {
                soft_ruleset_t *m = (soft_ruleset_t *)rs;
                uint64_t sh = path_hash(ctx->src_path);
                query_cache_store(m, sh, (uint32_t)subj_hash,
                                  src_granted, eval_mask, src_deny,
                                  src_pattern != NULL);
                if (src_deny < 0 &&
                    (src_granted & op_required_src_mode(rs, ctx->op)) == op_required_src_mode(rs, ctx->op)) {
                    uint64_t dh = path_hash(ctx->dst_path);
                    query_cache_store(m, dh, (uint32_t)subj_hash,
                                      dst_granted, eval_mask, dst_deny,
                                      dst_pattern != NULL);
                }
            }
        } else {
            int deny_layer = -1;
            const char *matched_pattern = NULL;

            uint32_t req = op_required_src_mode(rs, ctx->op);
            uint32_t g = eval_all_layers(rs, ctx->src_path, ctx->op, ctx,
                                         &deny_layer, &matched_pattern);

            if (g == 0 && matched_pattern == NULL) {
                /* No rules matched — undetermined */
                granted = 0; determined = 0;
                if (out_log) {
                    out_log->result = 0;
                    out_log->deny_layer = -1;
                    out_log->matched_rule = NULL;
                }
            } else if (deny_layer >= 0 || (g & req) != req) {
                granted = 0; determined = 1;
                if (out_log) {
                    out_log->result = 0;
                    out_log->deny_reason = deny_layer >= 0 ? "Denied by layer" : "Insufficient mode";
                    out_log->deny_layer = deny_layer;
                    out_log->matched_rule = matched_pattern;
                }
            } else {
                granted = g; determined = 1;
                if (out_log) {
                    out_log->result = (int)granted;
                    out_log->deny_layer = -1;
                    out_log->matched_rule = matched_pattern;
                }
            }

            /* Cache unary result */
            if (!out_log && determined) {
                soft_ruleset_t *m = (soft_ruleset_t *)rs;
                uint64_t sh = path_hash(ctx->src_path);
                query_cache_store(m, sh, (uint32_t)subj_hash,
                                  granted, eval_mask, deny_layer,
                                  matched_pattern != NULL);
            }
        }
    }

    if (out_granted) *out_granted = granted;
    return determined ? 1 : 0;
}


/* ------------------------------------------------------------------ */
/*  Batch evaluation with parent-directory cache                        */
/* ------------------------------------------------------------------ */

#define BATCH_CACHE_SIZE 256
#define BATCH_CACHE_PATH_LEN 512  /* Max path length for cache entries */

typedef struct {
    char     path[BATCH_CACHE_PATH_LEN];
    uint32_t granted;
    int      deny_layer;
    uint32_t subject_hash;  /**< FNV-1a hash of subject string for cache key */
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
                                               const char *path,
                                               uint32_t subject_hash)
{
    for (int i = 0; i < BATCH_CACHE_SIZE; i++) {
        if (cache[i].valid &&
            strcmp(cache[i].path, path) == 0 &&
            cache[i].subject_hash == subject_hash)
            return &cache[i];
    }
    return NULL;
}

static void batch_cache_store(batch_cache_entry_t *cache,
                              const char *path,
                              uint32_t granted,
                              int deny_layer,
                              uint32_t subject_hash,
                              int *write_pos)
{
    int pos = *write_pos;
    batch_cache_entry_t *e = &cache[pos];
    strncpy(e->path, path, BATCH_CACHE_PATH_LEN - 1);
    e->path[BATCH_CACHE_PATH_LEN - 1] = '\0';
    e->granted = granted;
    e->deny_layer = deny_layer;
    e->subject_hash = subject_hash;
    e->valid = 1;
    *write_pos = (pos + 1) % BATCH_CACHE_SIZE;
}

int soft_ruleset_check_batch_ctx(const soft_ruleset_t *rs,
                                 const soft_access_ctx_t *ctxs[],
                                 uint32_t *out_granted,
                                 int count)
{
    if (!rs || !ctxs || !out_granted || count <= 0) { return -1; }

    /* Use stack allocation for small batches (avoids malloc overhead).
     * BATCH_CACHE_SIZE (256) * 532 bytes = ~136KB per cache, ~272KB total.
     * This fits comfortably on typical 8MB stacks. */
    batch_cache_entry_t src_cache_stack[BATCH_CACHE_SIZE];
    batch_cache_entry_t dst_cache_stack[BATCH_CACHE_SIZE];
    batch_cache_entry_t *src_cache, *dst_cache;
    int use_stack = (count <= 64);  /* Stack for small batches */

    if (use_stack) {
        src_cache = src_cache_stack;
        dst_cache = dst_cache_stack;
        memset(src_cache, 0, sizeof(src_cache_stack));
        memset(dst_cache, 0, sizeof(dst_cache_stack));
    } else {
        src_cache = calloc(BATCH_CACHE_SIZE, sizeof(batch_cache_entry_t));
        dst_cache = calloc(BATCH_CACHE_SIZE, sizeof(batch_cache_entry_t));
        if (!src_cache || !dst_cache) { free(src_cache); free(dst_cache); errno = ENOMEM; return -1; }
    }
    int src_write = 0, dst_write = 0;

    for (int i = 0; i < count; i++) {
        const soft_access_ctx_t *ctx = ctxs[i];
        if (!ctx) { out_granted[i] = 0; continue; }

        bool is_binary = (ctx->op == SOFT_OP_COPY || ctx->op == SOFT_OP_MOVE ||
                          ctx->op == SOFT_OP_LINK || ctx->op == SOFT_OP_MOUNT ||
                          ctx->op >= SOFT_OP_CUSTOM);

        /* Compute subject hash for cache keying */
        uint32_t subj_hash = 0;
        if (ctx->subject) {
            uint64_t h64 = fnv1a_str(ctx->subject);
            subj_hash = (uint32_t)(h64 ^ (h64 >> 32));
        }

        char src_parent[PATH_MAX], dst_parent[PATH_MAX];
        parent_dir(ctx->src_path, src_parent, sizeof(src_parent));
        if (is_binary && ctx->dst_path)
            parent_dir(ctx->dst_path, dst_parent, sizeof(dst_parent));
        else
            dst_parent[0] = '\0';

        uint32_t src_granted = 0, dst_granted = 0;
        int src_deny = -1, dst_deny = -1;

        batch_cache_entry_t *src_hit = batch_cache_lookup(src_cache, ctx->src_path,
                                                          subj_hash);
        batch_cache_entry_t *src_par = batch_cache_lookup(src_cache, src_parent,
                                                          subj_hash);
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
                              subj_hash, &src_write);
            /* Don't cache root parent — it matches everything and causes false hits */
            if (strcmp(src_parent, "/") != 0)
                batch_cache_store(src_cache, src_parent, src_granted, src_deny,
                                  subj_hash, &src_write);
        }

        if (is_binary && ctx->dst_path) {
            batch_cache_entry_t *dst_hit = batch_cache_lookup(dst_cache, ctx->dst_path,
                                                              subj_hash);
            batch_cache_entry_t *dst_par = batch_cache_lookup(dst_cache, dst_parent,
                                                              subj_hash);
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
                                  subj_hash, &dst_write);
                /* Don't cache root parent */
                if (strcmp(dst_parent, "/") != 0)
                    batch_cache_store(dst_cache, dst_parent, dst_granted, dst_deny,
                                      subj_hash, &dst_write);
            }
        }

        if (is_binary) {
            if (src_deny >= 0 || dst_deny >= 0) {
                out_granted[i] = 0;
            } else {
                uint32_t src_req = op_required_src_mode(rs, ctx->op);
                uint32_t dst_req = op_required_dst_mode(rs, ctx->op);
                if ((src_granted & src_req) == src_req &&
                    (dst_granted & dst_req) == dst_req) {
                    out_granted[i] = src_granted | dst_granted;
                } else {
                    out_granted[i] = 0;
                }
            }
        } else {
            if (src_deny >= 0) {
                out_granted[i] = 0;
            } else {
                uint32_t req = op_required_src_mode(rs, ctx->op);
                if ((src_granted & req) == req) {
                    out_granted[i] = src_granted;
                } else {
                    out_granted[i] = 0;
                }
            }
        }
    }

    /* Only free heap-allocated caches */
    if (!use_stack) {
        free(src_cache);
        free(dst_cache);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Rule enumeration / inspection                                      */
/* ------------------------------------------------------------------ */

int soft_ruleset_get_rule_info(const soft_ruleset_t *rs, int index,
                               soft_rule_info_t *out)
{
    if (!rs || !out || index < 0) { errno = EINVAL; return -1; }

    int remaining = index;
    for (int i = 0; i < rs->layer_count; i++) {
        const layer_t *lyr = &rs->layers[i];
        if (remaining < lyr->count) {
            const rule_t *r = &lyr->rules[remaining];
            out->pattern = r->pattern;
            out->mode = r->mode;
            out->op_type = r->op_type;
            out->linked_path_var = (r->linked_path_var[0] != '\0') ? r->linked_path_var : NULL;
            out->subject_regex = (r->subject_regex[0] != '\0') ? r->subject_regex : NULL;
            out->flags = r->flags;
            out->layer = i;
            return 0;
        }
        remaining -= lyr->count;
    }

    errno = EINVAL;
    return -1;
}

int soft_ruleset_get_layer_info(const soft_ruleset_t *rs, int layer,
                                soft_layer_info_t *out)
{
    if (!rs || !out || layer < 0 || layer >= rs->layer_count) {
        errno = EINVAL; return -1;
    }

    const layer_t *lyr = &rs->layers[layer];
    out->type = lyr->type;
    out->mask = lyr->mask;
    out->count = lyr->count;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Rule removal                                                       */
/* ------------------------------------------------------------------ */

int soft_ruleset_remove_rule(soft_ruleset_t *rs,
                             int layer,
                             const char *pattern,
                             uint32_t mode,
                             soft_binary_op_t op_type)
{
    if (!rs || !pattern || layer < 0 || layer >= rs->layer_count) {
        errno = EINVAL; return -1;
    }

    layer_t *lyr = &rs->layers[layer];
    for (int i = 0; i < lyr->count; i++) {
        rule_t *r = &lyr->rules[i];
        if (strcmp(r->pattern, pattern) == 0 &&
            r->mode == mode && r->op_type == op_type) {
            /* Remove by shifting remaining rules down */
            memmove(&lyr->rules[i], &lyr->rules[i + 1],
                    (size_t)(lyr->count - i - 1) * sizeof(rule_t));
            lyr->count--;
            soft_ruleset_invalidate(rs);
            return 0;
        }
    }

    errno = ENOENT;
    return -1;
}

int soft_ruleset_remove_rule_at_index(soft_ruleset_t *rs,
                                      int layer,
                                      int index)
{
    if (!rs || layer < 0 || layer >= rs->layer_count) {
        errno = EINVAL; return -1;
    }

    layer_t *lyr = &rs->layers[layer];
    if (index < 0 || index >= lyr->count) {
        errno = EINVAL; return -1;
    }

    memmove(&lyr->rules[index], &lyr->rules[index + 1],
            (size_t)(lyr->count - index - 1) * sizeof(rule_t));
    lyr->count--;
    soft_ruleset_invalidate(rs);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Ruleset cloning                                                    */
/* ------------------------------------------------------------------ */

soft_ruleset_t *soft_ruleset_clone(const soft_ruleset_t *rs)
{
    if (!rs) { errno = EINVAL; return NULL; }

    soft_ruleset_t *new_rs = calloc(1, sizeof(*new_rs));
    if (!new_rs) return NULL;

    new_rs->layer_count = rs->layer_count;
    new_rs->is_compiled = false;  /* Start uncompiled */
    memcpy(new_rs->last_error, rs->last_error, sizeof(new_rs->last_error));
    memcpy(new_rs->custom_ops, rs->custom_ops, sizeof(new_rs->custom_ops));

    for (int i = 0; i < rs->layer_count; i++) {
        const layer_t *src_lyr = &rs->layers[i];
        layer_t *dst_lyr = &new_rs->layers[i];

        dst_lyr->type = src_lyr->type;
        dst_lyr->mask = src_lyr->mask;
        dst_lyr->count = src_lyr->count;
        dst_lyr->capacity = src_lyr->capacity;

        if (src_lyr->count > 0 && src_lyr->rules) {
            dst_lyr->rules = malloc((size_t)src_lyr->capacity * sizeof(rule_t));
            if (!dst_lyr->rules) {
                soft_ruleset_free(new_rs);
                return NULL;
            }
            memcpy(dst_lyr->rules, src_lyr->rules,
                   (size_t)src_lyr->count * sizeof(rule_t));
        }
    }

    return new_rs;
}

/* ------------------------------------------------------------------ */
/*  Ruleset merging and insertion                                      */
/* ------------------------------------------------------------------ */

int soft_ruleset_merge(soft_ruleset_t *dest, const soft_ruleset_t *src)
{
    if (!dest || !src) { errno = EINVAL; return -1; }

    for (int i = 0; i < src->layer_count; i++) {
        const layer_t *src_lyr = &src->layers[i];
        if (src_lyr->count == 0) continue;

        layer_t *dest_lyr = ensure_layer(dest, i);
        if (!dest_lyr) return -1;

        /* Append all rules from src layer */
        for (int j = 0; j < src_lyr->count; j++) {
            if (layer_add_rule(dest_lyr, &src_lyr->rules[j]) < 0) return -1;
        }

        /* Override layer type/mask from src */
        dest_lyr->type = src_lyr->type;
        dest_lyr->mask = src_lyr->mask;
    }

    soft_ruleset_invalidate(dest);
    return 0;
}

int soft_ruleset_insert_ruleset(soft_ruleset_t *dest,
                                const soft_ruleset_t *src,
                                int depth)
{
    if (!dest || !src || depth < 0) { errno = EINVAL; return -1; }

    for (int i = 0; i < src->layer_count; i++) {
        int target_layer = i + depth;
        if (target_layer >= MAX_LAYERS) { errno = EINVAL; return -1; }

        const layer_t *src_lyr = &src->layers[i];
        if (src_lyr->count == 0) continue;

        layer_t *dest_lyr = ensure_layer(dest, target_layer);
        if (!dest_lyr) return -1;

        for (int j = 0; j < src_lyr->count; j++) {
            if (layer_add_rule(dest_lyr, &src_lyr->rules[j]) < 0) return -1;
        }

        dest_lyr->type = src_lyr->type;
        dest_lyr->mask = src_lyr->mask;
    }

    soft_ruleset_invalidate(dest);
    return 0;
}

int soft_ruleset_merge_at_layer(soft_ruleset_t *dest,
                                const soft_ruleset_t *src,
                                int target_layer)
{
    if (!dest || !src || target_layer < 0) { errno = EINVAL; return -1; }

    for (int i = 0; i < src->layer_count; i++) {
        int dest_layer = target_layer + i;
        if (dest_layer >= MAX_LAYERS) { errno = EINVAL; return -1; }

        const layer_t *src_lyr = &src->layers[i];
        if (src_lyr->count == 0) continue;

        layer_t *dest_lyr = ensure_layer(dest, dest_layer);
        if (!dest_lyr) return -1;

        for (int j = 0; j < src_lyr->count; j++) {
            if (layer_add_rule(dest_lyr, &src_lyr->rules[j]) < 0) return -1;
        }

        dest_lyr->type = src_lyr->type;
        dest_lyr->mask = src_lyr->mask;
    }

    soft_ruleset_invalidate(dest);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Meld variants (ownership transfer, no deep copy)                   */
/* ------------------------------------------------------------------ */

int soft_ruleset_meld(soft_ruleset_t *dest, soft_ruleset_t *src)
{
    if (!dest || !src) { errno = EINVAL; return -1; }

    for (int i = 0; i < src->layer_count; i++) {
        layer_t *src_lyr = &src->layers[i];
        if (src_lyr->count == 0 && src_lyr->rules == NULL) continue;

        layer_t *dest_lyr = ensure_layer(dest, i);
        if (!dest_lyr) return -1;

        /* If dest layer is empty, take ownership directly */
        if (dest_lyr->count == 0 && dest_lyr->rules == NULL) {
            dest_lyr->rules = src_lyr->rules;
            dest_lyr->count = src_lyr->count;
            dest_lyr->capacity = src_lyr->capacity;
            src_lyr->rules = NULL;
            src_lyr->count = 0;
            src_lyr->capacity = 0;
        } else {
            /* Dest has rules already — append and free src's array */
            for (int j = 0; j < src_lyr->count; j++) {
                if (layer_add_rule(dest_lyr, &src_lyr->rules[j]) < 0) {
                    free(src_lyr->rules);
                    src_lyr->rules = NULL;
                    return -1;
                }
            }
            free(src_lyr->rules);
            src_lyr->rules = NULL;
            src_lyr->count = 0;
            src_lyr->capacity = 0;
        }

        dest_lyr->type = src_lyr->type;
        dest_lyr->mask = src_lyr->mask;
    }

    src->layer_count = 0;
    soft_ruleset_invalidate(dest);
    return 0;
}

int soft_ruleset_meld_ruleset(soft_ruleset_t *dest,
                              soft_ruleset_t *src,
                              int depth)
{
    if (!dest || !src || depth < 0) { errno = EINVAL; return -1; }

    for (int i = 0; i < src->layer_count; i++) {
        int target_layer = i + depth;
        if (target_layer >= MAX_LAYERS) { errno = EINVAL; return -1; }

        layer_t *src_lyr = &src->layers[i];
        if (src_lyr->count == 0 && src_lyr->rules == NULL) continue;

        layer_t *dest_lyr = ensure_layer(dest, target_layer);
        if (!dest_lyr) return -1;

        if (dest_lyr->count == 0 && dest_lyr->rules == NULL) {
            dest_lyr->rules = src_lyr->rules;
            dest_lyr->count = src_lyr->count;
            dest_lyr->capacity = src_lyr->capacity;
            src_lyr->rules = NULL;
            src_lyr->count = 0;
            src_lyr->capacity = 0;
        } else {
            for (int j = 0; j < src_lyr->count; j++) {
                if (layer_add_rule(dest_lyr, &src_lyr->rules[j]) < 0) {
                    free(src_lyr->rules);
                    src_lyr->rules = NULL;
                    return -1;
                }
            }
            free(src_lyr->rules);
            src_lyr->rules = NULL;
            src_lyr->count = 0;
            src_lyr->capacity = 0;
        }

        dest_lyr->type = src_lyr->type;
        dest_lyr->mask = src_lyr->mask;
    }

    src->layer_count = 0;
    soft_ruleset_invalidate(dest);
    return 0;
}

int soft_ruleset_meld_at_layer(soft_ruleset_t *dest,
                               soft_ruleset_t *src,
                               int target_layer)
{
    if (!dest || !src || target_layer < 0) { errno = EINVAL; return -1; }

    for (int i = 0; i < src->layer_count; i++) {
        int dest_layer = target_layer + i;
        if (dest_layer >= MAX_LAYERS) { errno = EINVAL; return -1; }

        layer_t *src_lyr = &src->layers[i];
        if (src_lyr->count == 0 && src_lyr->rules == NULL) continue;

        layer_t *dest_lyr = ensure_layer(dest, dest_layer);
        if (!dest_lyr) return -1;

        if (dest_lyr->count == 0 && dest_lyr->rules == NULL) {
            dest_lyr->rules = src_lyr->rules;
            dest_lyr->count = src_lyr->count;
            dest_lyr->capacity = src_lyr->capacity;
            src_lyr->rules = NULL;
            src_lyr->count = 0;
            src_lyr->capacity = 0;
        } else {
            for (int j = 0; j < src_lyr->count; j++) {
                if (layer_add_rule(dest_lyr, &src_lyr->rules[j]) < 0) {
                    free(src_lyr->rules);
                    src_lyr->rules = NULL;
                    return -1;
                }
            }
            free(src_lyr->rules);
            src_lyr->rules = NULL;
            src_lyr->count = 0;
            src_lyr->capacity = 0;
        }

        dest_lyr->type = src_lyr->type;
        dest_lyr->mask = src_lyr->mask;
    }

    src->layer_count = 0;
    soft_ruleset_invalidate(dest);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Layer shifting (shared by meld and insert)                         */
/* ------------------------------------------------------------------ */

/**
 * Shift existing dest layers >= target_layer UP by src_layers positions.
 * Iterates backwards to avoid overwriting data still needed.
 * Returns new layer_count, or -1 if new_end exceeds MAX_LAYERS.
 */
static int shift_layers_up(soft_ruleset_t *dest, int src_layers, int target_layer)
{
    int dest_end = dest->layer_count;
    int new_end = (target_layer >= dest_end)
                  ? (target_layer + src_layers)
                  : (dest_end + src_layers);
    if (new_end > MAX_LAYERS) return -1;

    for (int i = dest_end - 1; i >= target_layer; i--) {
        layer_t *dst = &dest->layers[i + src_layers];
        layer_t *src_slot = &dest->layers[i];
        *dst = *src_slot;
        memset(src_slot, 0, sizeof(layer_t));
    }

    /* Zero any gap between old dest_end and target_layer */
    for (int i = dest_end; i < target_layer; i++) {
        memset(&dest->layers[i], 0, sizeof(layer_t));
    }

    return new_end;
}

/* ------------------------------------------------------------------ */
/*  Meld (ownership transfer)                                          */
/* ------------------------------------------------------------------ */

int soft_ruleset_meld_into(soft_ruleset_t *dest,
                           soft_ruleset_t *src,
                           int target_layer)
{
    if (!dest || !src || target_layer < 0) { errno = EINVAL; return -1; }
    if (src->layer_count == 0) return 0;  /* nothing to meld */

    int src_layers = src->layer_count;
    int new_end = shift_layers_up(dest, src_layers, target_layer);
    if (new_end < 0) return -1;

    /* Move src's layers into the gap — pointer ownership transfer. */
    for (int i = 0; i < src_layers; i++) {
        int dest_layer = target_layer + i;
        layer_t *dest_lyr = &dest->layers[dest_layer];
        layer_t *src_lyr  = &src->layers[i];

        *dest_lyr = *src_lyr;
        /* Zero out src so soft_ruleset_free(src) won't double-free. */
        memset(src_lyr, 0, sizeof(layer_t));
    }

    src->layer_count = 0;
    dest->layer_count = new_end;
    soft_ruleset_invalidate(dest);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Insert (clone + meld)                                              */
/* ------------------------------------------------------------------ */

int soft_ruleset_insert_at_layer(soft_ruleset_t *dest,
                                 const soft_ruleset_t *src,
                                 int target_layer)
{
    if (!dest || !src || target_layer < 0) { errno = EINVAL; return -1; }
    if (src->layer_count == 0) return 0;

    /* Clone src's layers so we own the memory, then meld the clone. */
    int src_layers = src->layer_count;

    /* Allocate a temporary ruleset to hold cloned layers. */
    layer_t *clone_layers = calloc((size_t)src_layers, sizeof(layer_t));
    if (!clone_layers) return -1;

    /* Deep-copy each src layer. */
    for (int i = 0; i < src_layers; i++) {
        const layer_t *src_lyr = &src->layers[i];
        layer_t *clone = &clone_layers[i];
        clone->type = src_lyr->type;
        clone->mask = src_lyr->mask;
        clone->count = src_lyr->count;
        clone->capacity = src_lyr->capacity;

        if (src_lyr->count > 0 && src_lyr->rules) {
            clone->rules = malloc((size_t)src_lyr->capacity * sizeof(rule_t));
            if (!clone->rules) {
                /* Rollback: free already-allocated clones. */
                for (int j = 0; j < i; j++)
                    free(clone_layers[j].rules);
                free(clone_layers);
                return -1;
            }
            memcpy(clone->rules, src_lyr->rules,
                   (size_t)src_lyr->count * sizeof(rule_t));
        }
    }

    /* Shift dest layers to make room. */
    int new_end = shift_layers_up(dest, src_layers, target_layer);
    if (new_end < 0) {
        for (int i = 0; i < src_layers; i++)
            free(clone_layers[i].rules);
        free(clone_layers);
        return -1;
    }

    /* Move cloned layers into dest. */
    for (int i = 0; i < src_layers; i++) {
        dest->layers[target_layer + i] = clone_layers[i];
        /* Don't free clone_layers[i].rules — now owned by dest. */
        clone_layers[i].rules = NULL;  /* prevent dangling free below */
    }
    free(clone_layers);

    dest->layer_count = new_end;
    soft_ruleset_invalidate(dest);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Backward compatibility                                             */
/* ------------------------------------------------------------------ */

int soft_ruleset_check(const soft_ruleset_t *rs,
                       const char *path,
                       uint32_t *out_granted)
{
    soft_access_ctx_t ctx = {
        .op = SOFT_OP_READ,
        .src_path = path,
        .dst_path = NULL,
        .subject = NULL
    };
    return soft_ruleset_check_ctx(rs, &ctx, out_granted, NULL);
}

/* ------------------------------------------------------------------ */
/*  Evaluation statistics                                               */
/* ------------------------------------------------------------------ */

void soft_ruleset_get_stats(const soft_ruleset_t *rs,
                            soft_eval_stats_t *out,
                            bool reset)
{
    if (!out) return;
    out->cache_hits = rs ? rs->stats_cache_hits : 0;
    out->cache_misses = rs ? rs->stats_cache_misses : 0;
    out->eval_calls = rs ? rs->stats_eval_calls : 0;
    if (reset && rs) {
        ((soft_ruleset_t *)rs)->stats_cache_hits = 0;
        ((soft_ruleset_t *)rs)->stats_cache_misses = 0;
        ((soft_ruleset_t *)rs)->stats_eval_calls = 0;
    }
}

/* ------------------------------------------------------------------ */
/*  Compiled footprint estimate                                       */
/* ------------------------------------------------------------------ */

int soft_ruleset_estimate_compiled(const soft_ruleset_t *rs,
                                   size_t *out_rule_bytes,
                                   size_t *out_str_bytes)
{
    if (!rs) { errno = EINVAL; return -1; }

    size_t rule_count = 0;
    size_t str_bytes = 0;

    for (int i = 0; i < rs->layer_count; i++) {
        const layer_t *lyr = &rs->layers[i];
        for (int j = 0; j < lyr->count; j++) {
            const rule_t *r = &lyr->rules[j];
            rule_count++;
            str_bytes += strlen(r->pattern) + 1;  /* +1 for null */
            if (r->subject_regex[0] != '\0')
                str_bytes += strlen(r->subject_regex) + 1;
        }
    }

    /* compiled_rule_t is ~48 bytes.  Add small overhead for arena alignment. */
    size_t rule_bytes = rule_count * (sizeof(compiled_rule_t) + 8);

    if (out_rule_bytes) *out_rule_bytes = rule_bytes;
    if (out_str_bytes) *out_str_bytes = str_bytes;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Library version and features                                       */
/* ------------------------------------------------------------------ */

#define RULE_ENGINE_VERSION "0.2.0"

const char *soft_ruleset_version(void)
{
    return RULE_ENGINE_VERSION;
}

uint32_t soft_ruleset_features(void)
{
    return SOFT_FEATURE_LANDLOCK_BRIDGE
         | SOFT_FEATURE_BINARY_SERIALIZATION
         | SOFT_FEATURE_RULE_MELD
         | SOFT_FEATURE_RULE_DIFF;
}
