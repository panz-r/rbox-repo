/**
 * @file policy_parser.c
 * @brief Text-based policy file parser and serializer for the Rule Engine.
 */

#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "policy_parser.h"
#include "rule_engine_internal.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define MAX_LINE_LEN    4096
#define MAX_MACROS      64
#define MAX_MACRO_ID    64

/* ------------------------------------------------------------------ */
/*  Parser State                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    char    id[MAX_MACRO_ID];
    char    pattern[MAX_PATTERN_LEN];
    int     valid;
} macro_entry_t;

typedef struct {
    int             current_layer;
    layer_type_t    current_type;
    uint32_t        current_mask;
    macro_entry_t   macros[MAX_MACROS];
    int             macro_count;
} parser_state_t;

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static int set_error(int *line_number, const char **error_msg,
                     int line, const char *msg)
{
    if (line_number) *line_number = line;
    if (error_msg) *error_msg = msg;
    return -1;
}

static int parse_mode_chars(const char *s, uint32_t *mode)
{
    *mode = 0;
    for (; *s; s++) {
        switch (*s) {
        case 'R': case 'r': *mode |= SOFT_ACCESS_READ;   break;
        case 'W': case 'w': *mode |= SOFT_ACCESS_WRITE;  break;
        case 'X': case 'x': *mode |= SOFT_ACCESS_EXEC;   break;
        case 'C': case 'c': *mode |= SOFT_ACCESS_CREATE; break;
        case 'U': case 'u': *mode |= SOFT_ACCESS_UNLINK; break;
        case 'L': case 'l': *mode |= SOFT_ACCESS_LINK;   break;
        case 'M': case 'm': *mode |= SOFT_ACCESS_MKDIR;  break;
        case 'D': case 'd':
            *mode = SOFT_ACCESS_DENY;
            return 0;
        default:
            return -1;
        }
    }
    return (*mode != 0) ? 0 : -1;
}

static int parse_op_type(const char *s, soft_binary_op_t *out_op)
{
    if (!s) { *out_op = SOFT_OP_READ; return 0; }
    if (strcasecmp(s, "read") == 0)       { *out_op = SOFT_OP_READ; return 0; }
    if (strcasecmp(s, "write") == 0)      { *out_op = SOFT_OP_WRITE; return 0; }
    if (strcasecmp(s, "exec") == 0)       { *out_op = SOFT_OP_EXEC; return 0; }
    if (strcasecmp(s, "copy") == 0)       { *out_op = SOFT_OP_COPY; return 0; }
    if (strcasecmp(s, "move") == 0)       { *out_op = SOFT_OP_MOVE; return 0; }
    if (strcasecmp(s, "link") == 0)       { *out_op = SOFT_OP_LINK; return 0; }
    if (strcasecmp(s, "mount") == 0)      { *out_op = SOFT_OP_MOUNT; return 0; }
    if (strcasecmp(s, "chmod") == 0)      { *out_op = SOFT_OP_CHMOD_CHOWN; return 0; }
    if (strcasecmp(s, "custom") == 0)     { *out_op = SOFT_OP_CUSTOM; return 0; }
    return -1;  /* unknown operation type */
}

static const char *op_type_to_str(soft_binary_op_t op)
{
    switch (op) {
    case SOFT_OP_READ:    return "read";
    case SOFT_OP_WRITE:   return "write";
    case SOFT_OP_EXEC:    return "exec";
    case SOFT_OP_COPY:    return "copy";
    case SOFT_OP_MOVE:    return "move";
    case SOFT_OP_LINK:    return "link";
    case SOFT_OP_MOUNT:   return "mount";
    case SOFT_OP_CHMOD_CHOWN: return "chmod";
    case SOFT_OP_CUSTOM:  return "custom";
    default:              return "read";
    }
}

static void mode_to_str(uint32_t mode, char *buf, size_t len)
{
    int n = 0;
    if (mode & SOFT_ACCESS_DENY)  { strncpy(buf, "D", len); return; }
    if (mode & SOFT_ACCESS_READ)   buf[n++] = 'R';
    if (mode & SOFT_ACCESS_WRITE)  buf[n++] = 'W';
    if (mode & SOFT_ACCESS_EXEC)   buf[n++] = 'X';
    if (mode & SOFT_ACCESS_CREATE) buf[n++] = 'C';
    if (mode & SOFT_ACCESS_UNLINK) buf[n++] = 'U';
    if (mode & SOFT_ACCESS_LINK)   buf[n++] = 'L';
    if (mode & SOFT_ACCESS_MKDIR)  buf[n++] = 'M';
    buf[n] = '\0';
}

/* ------------------------------------------------------------------ */
/*  Macro expansion                                                    */
/* ------------------------------------------------------------------ */

static void init_macros(parser_state_t *st)
{
    memset(st, 0, sizeof(*st));
    st->current_layer = 0;
    st->current_type = LAYER_PRECEDENCE;
    st->current_mask = 0;
}

static int add_macro(parser_state_t *st, const char *id, const char *pattern)
{
    if (st->macro_count >= MAX_MACROS)
        return -1;
    strncpy(st->macros[st->macro_count].id, id, MAX_MACRO_ID - 1);
    strncpy(st->macros[st->macro_count].pattern, pattern, MAX_PATTERN_LEN - 1);
    st->macros[st->macro_count].valid = 1;
    st->macro_count++;
    return 0;
}

static int find_macro(parser_state_t *st, const char *id)
{
    for (int i = 0; i < st->macro_count; i++) {
        if (st->macros[i].valid && strcmp(st->macros[i].id, id) == 0)
            return i;
    }
    return -1;
}

/** Expand all ((ID)) macros in pattern. Writes result to out. */
static int expand_macros(parser_state_t *st, const char *pattern, char *out,
                         size_t out_size, int line, const char **error_msg)
{
    char buf[MAX_PATTERN_LEN];
    strncpy(buf, pattern, MAX_PATTERN_LEN - 1);
    buf[MAX_PATTERN_LEN - 1] = '\0';

    int iterations = 0;
    while (iterations < 10) {
        char *start = strstr(buf, "((");
        if (!start) break;
        char *end = strstr(start + 2, "))");
        if (!end) {
            return set_error(NULL, error_msg, line, "Unmatched (( in macro reference");
        }
        *start = '\0';
        *end = '\0';
        char *id = start + 2;

        int idx = find_macro(st, id);
        if (idx < 0) {
            return set_error(NULL, error_msg, line, "Undefined macro");
        }

        snprintf(out, out_size, "%s%s%s", buf, st->macros[idx].pattern, end + 2);
        strncpy(buf, out, MAX_PATTERN_LEN - 1);
        iterations++;
    }

    /* Check if there are still unexpanded macro references after 10 iterations */
    if (iterations >= 10 && strstr(buf, "((") != NULL) {
        return set_error(NULL, error_msg, line, "Macro expansion depth exceeded (possible circular reference)");
    }

    strncpy(out, buf, out_size - 1);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Line parsing                                                       */
/* ------------------------------------------------------------------ */

static const char *skip_ws(const char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    return s;
}

static const char *find_token_end(const char *s)
{
    const char *p = s;
    if (*p == '"') {
        p++;
        while (*p && *p != '"') {
            if (*p == '\\' && *(p + 1)) p++;
            p++;
        }
        if (*p == '"') p++;
        return p;
    }
    while (*p && !isspace((unsigned char)*p)) p++;
    return p;
}

static const char *copy_token(const char *s, char *dst, size_t dst_size)
{
    const char *end = find_token_end(s);
    const char *p = s;
    size_t n = 0;
    int quoted = (*p == '"');
    if (quoted) p++;
    /* For quoted strings, stop before the closing quote */
    const char *limit = quoted && end > s + 1 && *(end - 1) == '"' ? end - 1 : end;
    while (p < limit) {
        if (*p == '\\' && *(p + 1)) {
            p++;
            if (n < dst_size - 1) dst[n++] = *p;
        } else {
            if (n < dst_size - 1) dst[n++] = *p;
        }
        p++;
    }
    dst[n] = '\0';
    return end;
}

static int parse_line(parser_state_t *st, soft_ruleset_t *rs,
                      const char *line, int line_num, const char **error_msg)
{
    const char *p = skip_ws(line);
    if (*p == '\0' || *p == '#') return 0;

    /* Macro definition: [ID] pattern */
    if (*p == '[') {
        char id[MAX_MACRO_ID];
        char pattern[MAX_PATTERN_LEN];
        const char *close = strchr(p, ']');
        if (!close) return set_error(NULL, error_msg, line_num, "Missing ] in macro definition");

        const char *id_start = p + 1;
        size_t id_len = (size_t)(close - id_start);
        if (id_len >= MAX_MACRO_ID) return set_error(NULL, error_msg, line_num, "Macro ID too long");
        memcpy(id, id_start, id_len);
        id[id_len] = '\0';

        /* Validate ID is not empty */
        if (id_len == 0)
            return set_error(NULL, error_msg, line_num, "Empty macro ID");

        for (size_t i = 0; i < id_len; i++) {
            char c = id[i];
            if (i == 0) {
                if (!isalpha((unsigned char)c) && c != '_')
                    return set_error(NULL, error_msg, line_num, "Invalid macro ID start char");
            } else {
                if (!isalnum((unsigned char)c) && c != '_')
                    return set_error(NULL, error_msg, line_num, "Invalid macro ID char");
            }
        }

        const char *pat_start = skip_ws(close + 1);
        if (*pat_start == '\0') return set_error(NULL, error_msg, line_num, "Empty macro pattern");
        strncpy(pattern, pat_start, MAX_PATTERN_LEN - 1);
        pattern[MAX_PATTERN_LEN - 1] = '\0';
        size_t len = strlen(pattern);
        while (len > 0 && isspace((unsigned char)pattern[len - 1])) pattern[--len] = '\0';

        return add_macro(st, id, pattern);
    }

    /* Layer declaration: @N TYPE[:MASK] */
    if (*p == '@') {
        char *endptr;
        long layer_id = strtol(p + 1, &endptr, 10);
        if (endptr == p + 1 || layer_id < 0 || layer_id >= MAX_LAYERS)
            return set_error(NULL, error_msg, line_num, "Invalid layer index");

        const char *type_start = skip_ws(endptr);
        char type_buf[32];
        /* Find end of type name (stop at ':' or whitespace) */
        const char *type_end = type_start;
        while (*type_end && *type_end != ':' && !isspace((unsigned char)*type_end)) type_end++;
        size_t type_len = (size_t)(type_end - type_start);
        if (type_len == 0 || type_len >= sizeof(type_buf))
            return set_error(NULL, error_msg, line_num, "Invalid layer type");
        memcpy(type_buf, type_start, type_len);
        type_buf[type_len] = '\0';

        if (strcasecmp(type_buf, "PRECEDENCE") == 0)
            st->current_type = LAYER_PRECEDENCE;
        else if (strcasecmp(type_buf, "SPECIFICITY") == 0)
            st->current_type = LAYER_SPECIFICITY;
        else
            return set_error(NULL, error_msg, line_num, "Unknown layer type");

        st->current_mask = 0;
        if (*type_end == ':') {
            const char *mask_start = type_end + 1;
            char mask_buf[32];
            const char *mask_end = find_token_end(mask_start);
            size_t mask_len = (size_t)(mask_end - mask_start);
            if (mask_len >= sizeof(mask_buf))
                return set_error(NULL, error_msg, line_num, "Invalid layer mask");
            memcpy(mask_buf, mask_start, mask_len);
            mask_buf[mask_len] = '\0';
            if (parse_mode_chars(mask_buf, &st->current_mask) != 0)
                return set_error(NULL, error_msg, line_num, "Invalid mode chars in layer mask");
        }

        st->current_layer = (int)layer_id;
        soft_ruleset_set_layer_type(rs, st->current_layer, st->current_type, st->current_mask);
        return 0;
    }

    /* Rule declaration: [@N] PATTERN -> MODE [OP] [subject:REGEX] [uid:NUM] [recursive] */
    int use_layer = st->current_layer;
    uint32_t use_mask = st->current_mask;

    if (*p == '@') {
        char *endptr;
        long layer_id = strtol(p + 1, &endptr, 10);
        if (endptr == p + 1 || layer_id < 0 || layer_id >= MAX_LAYERS)
            return set_error(NULL, error_msg, line_num, "Invalid layer index");
        use_layer = (int)layer_id;
        /* Use the mask of the target layer, not the current layer */
        if (use_layer < rs->layer_count && rs->layers[use_layer].type == LAYER_SPECIFICITY)
            use_mask = rs->layers[use_layer].mask;
        else
            use_mask = 0;
        p = skip_ws(endptr);
    }

    const char *arrow = strstr(p, "->");
    if (!arrow) return set_error(NULL, error_msg, line_num, "Missing '->' separator");

    char pattern_raw[MAX_PATTERN_LEN];
    size_t pat_len = (size_t)(arrow - p);
    if (pat_len >= MAX_PATTERN_LEN)
        return set_error(NULL, error_msg, line_num, "Pattern too long");
    memcpy(pattern_raw, p, pat_len);
    pattern_raw[pat_len] = '\0';
    while (pat_len > 0 && isspace((unsigned char)pattern_raw[pat_len - 1]))
        pattern_raw[--pat_len] = '\0';

    char pattern[MAX_PATTERN_LEN];
    if (expand_macros(st, pattern_raw, pattern, sizeof(pattern), line_num, error_msg) != 0)
        return -1;

    const char *after_arrow = skip_ws(arrow + 2);

    char mode_buf[32];
    const char *mode_end = find_token_end(after_arrow);
    size_t mode_len = (size_t)(mode_end - after_arrow);
    if (mode_len >= sizeof(mode_buf) || mode_len == 0)
        return set_error(NULL, error_msg, line_num, "Invalid mode");
    memcpy(mode_buf, after_arrow, mode_len);
    mode_buf[mode_len] = '\0';

    uint32_t mode;
    if (parse_mode_chars(mode_buf, &mode) != 0)
        return set_error(NULL, error_msg, line_num, "Invalid mode chars");

    /* Validate rule mode against the target layer's mask */
    if (use_mask != 0 && (mode & ~use_mask) != 0) {
        return set_error(NULL, error_msg, line_num, "Rule mode exceeds layer mask");
    }

    /* Parse optional tokens after mode */
    const char *q = mode_end;
    soft_binary_op_t op_type = SOFT_OP_READ;
    const char *subject_regex = NULL;
    uint32_t min_uid = 0;
    uint32_t flags = 0;
    char subject_buf[MAX_PATTERN_LEN];
    char uid_buf[32];

    while (*q) {
        q = skip_ws(q);
        if (*q == '\0' || *q == '#') break;

        if (*q == '/') {
            const char *op_end = find_token_end(q + 1);
            size_t op_len = (size_t)(op_end - q - 1);
            char op_buf[32];
            if (op_len >= sizeof(op_buf))
                return set_error(NULL, error_msg, line_num, "Operation type too long");
            memcpy(op_buf, q + 1, op_len);
            op_buf[op_len] = '\0';
            if (parse_op_type(op_buf, &op_type) != 0)
                return set_error(NULL, error_msg, line_num, "Unknown operation type");
            q = op_end;
        } else if (strncmp(q, "subject:", 8) == 0) {
            q = copy_token(q + 8, subject_buf, sizeof(subject_buf));
            if (*subject_buf == '\0')
                return set_error(NULL, error_msg, line_num, "Empty subject regex");
            subject_regex = subject_buf;
        } else if (strncmp(q, "uid:", 4) == 0) {
            q = copy_token(q + 4, uid_buf, sizeof(uid_buf));
            char *endptr;
            long uid_val = strtol(uid_buf, &endptr, 10);
            if (endptr == uid_buf || uid_val < 0 || uid_val > UINT32_MAX)
                return set_error(NULL, error_msg, line_num, "Invalid uid");
            min_uid = (uint32_t)uid_val;
        } else if (strncmp(q, "recursive", 9) == 0) {
            /* Ensure it's the full word (not a prefix) */
            const char *after = q + 9;
            if (*after != '\0' && *after != '#' && !isspace((unsigned char)*after))
                return set_error(NULL, error_msg, line_num, "Unknown token");
            flags |= SOFT_RULE_RECURSIVE;
            q = after;
        } else {
            return set_error(NULL, error_msg, line_num, "Unknown token");
        }
    }

    if (soft_ruleset_add_rule_at_layer(rs, use_layer, pattern, mode,
                                       op_type, NULL, subject_regex,
                                       min_uid, flags) != 0) {
        return set_error(NULL, error_msg, line_num, "Failed to add rule");
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Public API: Parsing                                                */
/* ------------------------------------------------------------------ */

int soft_ruleset_parse_text(soft_ruleset_t *rs, const char *text,
                            int *line_number, const char **error_msg)
{
    if (!rs || !text) return -1;

    parser_state_t state;
    init_macros(&state);

    char line[MAX_LINE_LEN];
    const char *p = text;
    int line_num = 0;

    while (*p) {
        line_num++;
        size_t len = 0;
        while (*p && *p != '\n' && len < MAX_LINE_LEN - 1) {
            line[len++] = *p++;
        }
        line[len] = '\0';
        if (*p == '\n') p++;

        if (parse_line(&state, rs, line, line_num, error_msg) != 0) {
            if (line_number) *line_number = line_num;
            return -1;
        }
    }

    return 0;
}

int soft_ruleset_parse_file(soft_ruleset_t *rs, const char *path,
                            int *line_number, const char **error_msg)
{
    if (!path) return -1;

    FILE *f = fopen(path, "r");
    if (!f) {
        if (error_msg) *error_msg = strerror(errno);
        return -1;
    }

    parser_state_t state;
    init_macros(&state);

    char line[MAX_LINE_LEN];
    int line_num = 0;
    int ret = 0;

    while (fgets(line, sizeof(line), f)) {
        line_num++;
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        if (parse_line(&state, rs, line, line_num, error_msg) != 0) {
            if (line_number) *line_number = line_num;
            ret = -1;
            break;
        }
    }

    fclose(f);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Public API: Serialization                                          */
/* ------------------------------------------------------------------ */

int soft_ruleset_write_text(const soft_ruleset_t *rs, char **out_text)
{
    if (!rs || !out_text) return -1;

    size_t capacity = 4096;
    size_t used = 0;
    char *buf = malloc(capacity);
    if (!buf) return -1;

    for (int i = 0; i < rs->layer_count; i++) {
        const layer_t *lyr = &rs->layers[i];
        if (lyr->count == 0) continue;

        int needs_layer_decl = 1;
        if (rs->layer_count == 1 && lyr->type == LAYER_PRECEDENCE && lyr->mask == 0)
            needs_layer_decl = 0;

        if (needs_layer_decl) {
            const char *type_str = (lyr->type == LAYER_SPECIFICITY) ? "SPECIFICITY" : "PRECEDENCE";

            while (used + 128 > capacity) {
                capacity *= 2;
                char *new_buf = realloc(buf, capacity);
                if (!new_buf) { free(buf); return -1; }
                buf = new_buf;
            }

            used += (size_t)snprintf(buf + used, capacity - used, "@%d %s", i, type_str);
            if (lyr->mask != 0) {
                char mask_str[16];
                mode_to_str(lyr->mask, mask_str, sizeof(mask_str));
                used += (size_t)snprintf(buf + used, capacity - used, ":%s", mask_str);
            }
            used += (size_t)snprintf(buf + used, capacity - used, "\n");
        }

        for (int j = 0; j < lyr->count; j++) {
            const rule_t *r = &lyr->rules[j];

            while (used + MAX_LINE_LEN > capacity) {
                capacity *= 2;
                char *new_buf = realloc(buf, capacity);
                if (!new_buf) { free(buf); return -1; }
                buf = new_buf;
            }

            int n = snprintf(buf + used, capacity - used, "%s -> ", r->pattern);
            if (n < 0 || (size_t)n >= capacity - used) { free(buf); return -1; }
            used += (size_t)n;

            char mode_str[16];
            mode_to_str(r->mode, mode_str, sizeof(mode_str));
            n = snprintf(buf + used, capacity - used, "%s", mode_str);
            if (n < 0 || (size_t)n >= capacity - used) { free(buf); return -1; }
            used += (size_t)n;

            if (r->op_type != SOFT_OP_READ) {
                n = snprintf(buf + used, capacity - used, " /%s", op_type_to_str(r->op_type));
                if (n < 0 || (size_t)n >= capacity - used) { free(buf); return -1; }
                used += (size_t)n;
            }
            if (r->subject_regex[0] != '\0') {
                /* Check if quoting is needed (contains spaces, backslashes, or #) */
                int needs_quote = 0;
                for (size_t si = 0; r->subject_regex[si]; si++) {
                    if (isspace((unsigned char)r->subject_regex[si]) ||
                        r->subject_regex[si] == '\\' ||
                        r->subject_regex[si] == '#') {
                        needs_quote = 1;
                        break;
                    }
                }
                if (needs_quote) {
                    n = snprintf(buf + used, capacity - used, " subject:\"");
                    if (n < 0 || (size_t)n >= capacity - used) { free(buf); return -1; }
                    used += (size_t)n;
                    /* Escape backslashes and quotes in the value */
                    for (size_t si = 0; r->subject_regex[si]; si++) {
                        char c = r->subject_regex[si];
                        if (c == '\\' || c == '"') {
                            if (used + 1 >= capacity) { free(buf); return -1; }
                            buf[used++] = '\\';
                        }
                        if (used + 1 >= capacity) { free(buf); return -1; }
                        buf[used++] = c;
                    }
                    if (used + 1 >= capacity) { free(buf); return -1; }
                    buf[used++] = '"';
                } else {
                    n = snprintf(buf + used, capacity - used, " subject:%s", r->subject_regex);
                    if (n < 0 || (size_t)n >= capacity - used) { free(buf); return -1; }
                    used += (size_t)n;
                }
            }
            if (r->min_uid > 0) {
                n = snprintf(buf + used, capacity - used, " uid:%u", r->min_uid);
                if (n < 0 || (size_t)n >= capacity - used) { free(buf); return -1; }
                used += (size_t)n;
            }
            if (r->flags & SOFT_RULE_RECURSIVE) {
                n = snprintf(buf + used, capacity - used, " recursive");
                if (n < 0 || (size_t)n >= capacity - used) { free(buf); return -1; }
                used += (size_t)n;
            }

            buf[used++] = '\n';
        }
    }

    if (used == 0) {
        buf = realloc(buf, 2);
        if (!buf) return -1;
        buf[0] = '\n';
        buf[1] = '\0';
        *out_text = buf;
    } else {
        buf[used] = '\0';
        *out_text = buf;
    }

    return 0;
}

int soft_ruleset_write_file(const soft_ruleset_t *rs, const char *path)
{
    if (!rs || !path) return -1;

    char *text = NULL;
    if (soft_ruleset_write_text(rs, &text) != 0) return -1;

    FILE *f = fopen(path, "w");
    if (!f) { free(text); return -1; }

    size_t len = strlen(text);
    size_t written = fwrite(text, 1, len, f);
    fclose(f);
    free(text);

    return (written > 0 || len == 0) ? 0 : -1;
}
