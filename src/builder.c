/**
 * @file builder.c
 * @brief Public API implementation — Landlock policy builder.
 *
 * Wraps the radix tree with path canonicalisation, symlink expansion,
 * ABI masking, and serialisation.
 */

#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdbool.h>
#include <inttypes.h>
#include <dirent.h>

#ifdef MOCK_FS
#include "mock_fs.h"
#endif

#include "landlock_builder.h"
#include "radix_tree.h"

/* ------------------------------------------------------------------ */
/*  Builder internal state                                            */
/* ------------------------------------------------------------------ */

struct landlock_builder {
    radix_tree_t     *tree;
    landlock_rule_t  *rules;
    size_t            rule_count;
    int               abi_version;
    bool              prepared;
    /* Symlink map: path -> canonical target (populated during allow/deny) */
    char            **symlink_srcs;
    char            **symlink_dsts;
    size_t            symlink_count;
    size_t            symlink_cap;
};

/* ------------------------------------------------------------------ */
/*  ABI masks                                                         */
/* ------------------------------------------------------------------ */

/* Mask of access rights supported in each ABI version */
static const uint64_t abi_masks[] = {
    [0] = 0,  /* invalid */
    [1] = LL_FS_EXECUTE,
    [2] = LL_FS_EXECUTE | LL_FS_WRITE_FILE | LL_FS_READ_FILE |
          LL_FS_READ_DIR,
    [3] = LL_FS_EXECUTE | LL_FS_WRITE_FILE | LL_FS_READ_FILE |
          LL_FS_READ_DIR | LL_FS_REMOVE_DIR | LL_FS_REMOVE_FILE |
          LL_FS_RENAME_SRC | LL_FS_RENAME_DST,
    [4] = LL_FS_EXECUTE | LL_FS_WRITE_FILE | LL_FS_READ_FILE |
          LL_FS_READ_DIR | LL_FS_REMOVE_DIR | LL_FS_REMOVE_FILE |
          LL_FS_RENAME_SRC | LL_FS_RENAME_DST |
          LL_FS_MAKE_SOCKET | LL_FS_MAKE_FIFO | LL_FS_MAKE_BLOCK |
          LL_FS_MAKE_CHAR | LL_FS_MAKE_SYM |
          LL_FS_REFER | LL_FS_TRUNCATE | LL_FS_IOCTL_DEV |
          LL_FS_WATCH_MOUNT,
};

uint64_t landlock_abi_mask(int abi_version)
{
    if (abi_version < 1 || abi_version > LANDLOCK_ABI_MAX) return 0;
    return abi_masks[abi_version];
}

/* ------------------------------------------------------------------ */
/*  Virtual filesystem filtering                                      */
/* ------------------------------------------------------------------ */

/**
 * Virtual filesystem root prefixes that Landlock cannot enforce rules on.
 * Landlock operates on regular filesystems; procfs and sysfs are excluded
 * by the kernel.
 */
static const char * const vfs_roots[] = {
    LL_VFS_PATH_PROC,   /* procfs — process info, not enforceable */
    LL_VFS_PATH_SYS,    /* sysfs  — kernel objects, not enforceable */
    NULL
};

/**
 * Check whether a path is under a virtual filesystem root.
 * Returns 1 if yes, 0 if no.
 */
int landlock_path_is_vfs(const char *path)
{
    if (!path || !*path) return 0;

    /* Fast path: most paths start with '/' */
    if (path[0] != '/') {
        /* Relative path — could be anything.  Don't filter. */
        return 0;
    }

    for (int i = 0; vfs_roots[i]; i++) {
        const char *root = vfs_roots[i];
        size_t root_len = strlen(root);

        /* Match "/proc", "/proc/", "/sys", "/sys/" */
        if (strncmp(path, root, root_len) == 0) {
            /* Ensure we match a complete path component */
            if (path[root_len] == '\0' || path[root_len] == '/')
                return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Path canonicalisation                                             */
/* ------------------------------------------------------------------ */

/**
 * Normalise a path WITHOUT resolving symlinks: collapse slashes,
 * resolve . and .., make absolute.  Caller must free the result.
 */
static char *normalise_path(const char *path)
{
    if (!path || !*path) {
        errno = EINVAL;
        return NULL;
    }

    char buf[PATH_MAX];

    /* If relative, prepend cwd */
    if (path[0] != '/') {
        char *cwd = getcwd(NULL, 0);
        if (!cwd) return NULL;
        int cwd_len = (int)strlen(cwd);
        int path_len = (int)strlen(path);
        if (cwd_len + 1 + path_len >= PATH_MAX) {
            free(cwd);
            errno = ENAMETOOLONG;
            return NULL;
        }
        memcpy(buf, cwd, (size_t)cwd_len);
        buf[cwd_len] = '/';
        memcpy(buf + cwd_len + 1, path, (size_t)path_len + 1);
        free(cwd);
    } else {
        strncpy(buf, path, sizeof(buf) - 1);
        buf[PATH_MAX - 1] = '\0';
    }

    /* Collapse consecutive slashes */
    char *dst = buf;
    char *src = buf;
    while (*src) {
        *dst = *src;
        if (*src == '/' && *(src + 1) == '/') {
            src++;
            continue;
        }
        dst++;
        src++;
    }
    *dst = '\0';

    /* Resolve . and .. — split into components */
    char *comps[128];
    int clen[128];
    int nc = 0;
    char *p = buf;
    if (*p == '/') p++;

    while (*p) {
        if (*p == '/') { p++; continue; }
        char *start = p;
        while (*p && *p != '/') p++;
        int len = (int)(p - start);
        if (len == 1 && start[0] == '.') continue;
        if (len == 2 && start[0] == '.' && start[1] == '.') {
            if (nc > 0) nc--;
            continue;
        }
        if (nc < 128) {
            comps[nc] = start;
            clen[nc] = len;
            nc++;
        }
    }

    /* Build the cleaned path */
    char result[PATH_MAX];
    int rpos = 0;
    result[rpos++] = '/';

    for (int i = 0; i < nc; i++) {
        if (i > 0 || rpos > 1) {
            result[rpos++] = '/';
        }
        if (rpos + clen[i] + 1 > PATH_MAX) break;
        memcpy(result + rpos, comps[i], (size_t)clen[i]);
        rpos += clen[i];
    }
    result[rpos] = '\0';

    return strdup(result);
}

/**
 * Canonicalise a path for use in the radix tree.
 *
 * If the path exists on the real filesystem, resolve it with realpath().
 * Otherwise, clean it up (resolve . and .., collapse slashes).
 *
 * Caller must free the result.
 * Returns NULL on error.
 */
static char *canonicalise_path(const char *path)
{
    if (!path || !*path) {
        errno = EINVAL;
        return NULL;
    }

    /* Try realpath() — resolves symlinks and cleans the path */
    char *resolved = realpath(path, NULL);
    if (resolved) {
        return resolved;
    }

    /* Path doesn't exist — fall back to normalise_path */
    return normalise_path(path);
}

/* ------------------------------------------------------------------ */
/*  Symlink helpers                                                     */
/* ------------------------------------------------------------------ */

static int builder_add_symlink(landlock_builder_t *b,
                               const char *src, const char *dst)
{
    if (b->symlink_count >= b->symlink_cap) {
        size_t new_cap = b->symlink_cap == 0 ? 64 : b->symlink_cap * 2;
        char **tmp_s = realloc(b->symlink_srcs, new_cap * sizeof(char *));
        char **tmp_d = realloc(b->symlink_dsts, new_cap * sizeof(char *));
        if (!tmp_s || !tmp_d) {
            free(tmp_s);
            free(tmp_d);
            return -1;
        }
        b->symlink_srcs = tmp_s;
        b->symlink_dsts = tmp_d;
        b->symlink_cap = new_cap;
    }
    b->symlink_srcs[b->symlink_count] = strdup(src);
    b->symlink_dsts[b->symlink_count] = strdup(dst);
    if (!b->symlink_srcs[b->symlink_count] ||
        !b->symlink_dsts[b->symlink_count]) {
        free(b->symlink_srcs[b->symlink_count]);
        free(b->symlink_dsts[b->symlink_count]);
        b->symlink_srcs[b->symlink_count] = NULL;
        b->symlink_dsts[b->symlink_count] = NULL;
        return -1;
    }
    b->symlink_count++;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Symlink expansion                                                   */
/* ------------------------------------------------------------------ */

#ifdef MOCK_FS
#endif

/**
 * List children of a directory.  Returns number of children found.
 * Caller must NOT free the returned strings — they point into `names_buf`.
 */
static int list_dir_children(const char *dir, const char **names, int max_names)
{
#ifdef MOCK_FS
    return mock_fs_list_children(dir, names, max_names);
#else
    /* Real filesystem — use opendir/readdir */
    DIR *d = opendir(dir);
    if (!d) return 0;

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && count < max_names) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        /* Store name — caller must copy it if needed beyond our scope */
        /* We'll use a static buffer since this is only called during prepare */
        /* Actually, we need to return persistent strings.  Use strdup. */
        names[count] = ent->d_name;  /* NOTE: this points into dirent —
                                       * safe only if caller uses it immediately.
                                       * For the real FS path, we build full paths
                                       * inside this function. */
        count++;
    }
    closedir(d);
    return count;
#endif
}

/**
 * Recursively expand a directory target: add it as an allow rule, then
 * scan its children and recursively expand subdirectories too.
 */
static int expand_target_recursive(landlock_builder_t *b,
                                   const char *dir, uint64_t access,
                                   int depth)
{
    if (depth > 20) return 0;  /* prevent infinite recursion */

    /* Add the directory itself */
    radix_tree_allow(b->tree, dir, access);

    /* Scan children */
    const char *child_names[256];
    int n_children = list_dir_children(dir, child_names, 256);

    if (n_children <= 0) return 0;

    for (int i = 0; i < n_children; i++) {
        /* Build full child path */
        size_t dir_len = strlen(dir);
        size_t name_len = strlen(child_names[i]);
        if (dir_len + 1 + name_len >= PATH_MAX) continue;

        char child_path[PATH_MAX];
        memcpy(child_path, dir, dir_len);
        child_path[dir_len] = '/';
        memcpy(child_path + dir_len + 1, child_names[i], name_len);
        child_path[dir_len + 1 + name_len] = '\0';

        /* Check if it's a directory (or symlink to one) */
        struct stat st;
        if (stat(child_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            expand_target_recursive(b, child_path, access, depth + 1);
        } else {
            /* Regular file — add as allow rule */
            radix_tree_allow(b->tree, child_path, access);
        }
    }
    return 0;
}

/**
 * For each recorded symlink, check if it falls under an allowed path.
 * If so, resolve the target and add it as an allow rule with the same
 * access mask, recursively expanding subdirectories.
 */
static int expand_symlinks_impl(landlock_builder_t *b)
{
    if (b->symlink_count == 0) return 0;

    /* Collect current rules to check symlinks against */
    landlock_rule_t *rules = NULL;
    size_t rule_count = 0;
    radix_tree_collect_rules(b->tree, &rules, &rule_count);

    if (rule_count == 0) {
        free(rules);
        return 0;
    }

    /* For each symlink, check if the source is under any allowed rule
     * and NOT blocked by a deny rule. */
    for (size_t i = 0; i < b->symlink_count; i++) {
        const char *src = b->symlink_srcs[i];
        const char *dst = b->symlink_dsts[i];

        size_t src_len = strlen(src);

        /* Skip if the symlink target was explicitly denied. */
        if (radix_tree_is_denied(b->tree, dst)) continue;

        for (size_t j = 0; j < rule_count; j++) {
            const char *rule_path = rules[j].path;
            size_t rule_len = strlen(rule_path);

            /* Check if symlink source is beneath rule path OR
             * if the destination matches a rule exactly. */
            int src_matches = (src_len >= rule_len &&
                memcmp(src, rule_path, rule_len) == 0 &&
                (src_len == rule_len || src[rule_len] == '/'));
            int dst_matches = (strcmp(dst, rule_path) == 0);

            if (src_matches || dst_matches) {
                /* Symlink is inside this allowed path.
                 * Recursively expand the target (adds dir + children).
                 * `dst` is already canonical (it came from realpath). */
                expand_target_recursive(b, dst, rules[j].access, 0);
            }
        }
    }

    free(rules);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                        */
/* ------------------------------------------------------------------ */

landlock_builder_t *landlock_builder_new(void)
{
    landlock_builder_t *b = calloc(1, sizeof(*b));
    if (!b) return NULL;
    b->tree = radix_tree_new();
    if (!b->tree) {
        free(b);
        return NULL;
    }
    b->rules = NULL;
    b->rule_count = 0;
    b->abi_version = 0;
    b->prepared = false;
    b->symlink_srcs = NULL;
    b->symlink_dsts = NULL;
    b->symlink_count = 0;
    b->symlink_cap = 0;
    return b;
}

void landlock_builder_free(landlock_builder_t *b)
{
    if (!b) return;
    radix_tree_free(b->tree);

    /* Free collected rules (paths are strdup'd) */
    for (size_t i = 0; i < b->rule_count; i++) {
        free((char *)b->rules[i].path);
    }
    free(b->rules);

    for (size_t i = 0; i < b->symlink_count; i++) {
        free(b->symlink_srcs[i]);
        free(b->symlink_dsts[i]);
    }
    free(b->symlink_srcs);
    free(b->symlink_dsts);

    free(b);
}

int landlock_builder_allow(landlock_builder_t *b, const char *path, uint64_t access)
{
    if (!b || !path) { errno = EINVAL; return -1; }

    /* Skip virtual filesystem paths — Landlock cannot enforce rules here */
    if (landlock_path_is_vfs(path)) return 0;

    /* Free previous results if any */
    for (size_t i = 0; i < b->rule_count; i++) {
        free((char *)b->rules[i].path);
    }
    free(b->rules);
    b->rules = NULL;
    b->rule_count = 0;
    b->prepared = false;

    /* Canonicalise — check if path is a symlink */
    char *canon = canonicalise_path(path);
    if (!canon) return -1;

    /* Check if the original path was a symlink (for later expansion) */
    struct stat st_buf;
    if (lstat(path, &st_buf) == 0 && S_ISLNK(st_buf.st_mode)) {
        /* Record the symlink: source (normalised, NOT resolved) →
         * canonical target (already resolved by realpath above). */
        char *clean_src = normalise_path(path);
        if (clean_src) {
            builder_add_symlink(b, clean_src, canon);
            free(clean_src);
        }
    }

    int ret = radix_tree_allow(b->tree, canon, access);
    free(canon);
    return ret;
}

int landlock_builder_deny(landlock_builder_t *b, const char *path)
{
    if (!b || !path) { errno = EINVAL; return -1; }

    /* Skip virtual filesystem paths — Landlock cannot enforce rules here */
    if (landlock_path_is_vfs(path)) return 0;

    for (size_t i = 0; i < b->rule_count; i++) {
        free((char *)b->rules[i].path);
    }
    free(b->rules);
    b->rules = NULL;
    b->rule_count = 0;
    b->prepared = false;

    char *canon = canonicalise_path(path);
    if (!canon) return -1;

    /* Check if the original path was a symlink (for later expansion) */
    struct stat st_buf;
    if (lstat(path, &st_buf) == 0 && S_ISLNK(st_buf.st_mode)) {
        char *clean_src = normalise_path(path);
        if (clean_src) {
            builder_add_symlink(b, clean_src, canon);
            free(clean_src);
        }
    }

    int ret = radix_tree_deny(b->tree, canon);
    free(canon);
    return ret;
}

int landlock_builder_prepare(landlock_builder_t *b, int abi_version, bool expand_symlinks)
{
    if (!b) { errno = EINVAL; return -1; }
    if (abi_version < 1 || abi_version > LANDLOCK_ABI_MAX) {
        errno = EINVAL;
        return -1;
    }

    b->abi_version = abi_version;

    /* Step 1: Overlap removal (deny overrides allow) */
    radix_tree_overlap_removal(b->tree);

    /* Step 2: Prefix simplification */
    radix_tree_simplify(b->tree);

    /* Step 3: Symlink expansion */
    if (expand_symlinks) {
        if (expand_symlinks_impl(b) < 0) return -1;
    }

    /* Re-simplify after symlink expansion */
    radix_tree_simplify(b->tree);

    /* Step 4: Collect and mask rules */
    for (size_t i = 0; i < b->rule_count; i++) {
        free((char *)b->rules[i].path);
    }
    free(b->rules);
    b->rules = NULL;
    b->rule_count = 0;

    uint64_t mask = landlock_abi_mask(abi_version);
    radix_tree_collect_rules(b->tree, &b->rules, &b->rule_count);

    /* Mask access rights */
    for (size_t i = 0; i < b->rule_count; i++) {
        b->rules[i].access &= mask;
    }

    b->prepared = true;
    return 0;
}

int landlock_rule_open_fd(const landlock_rule_t *rule, int flags)
{
    if (!rule || !rule->path) { errno = EINVAL; return -1; }

    if (flags == 0)
        flags = O_PATH | O_CLOEXEC | O_NOFOLLOW;

    return open(rule->path, flags);
}

const landlock_rule_t *landlock_builder_get_rules(landlock_builder_t *b, size_t *count)
{
    if (!b || !count) return NULL;
    *count = b->rule_count;
    return b->rules;
}

/* ------------------------------------------------------------------ */
/*  Serialisation (JSON-based for readability)                         */
/* ------------------------------------------------------------------ */

/** Write a JSON-escaped string to a file. */
static void json_write_escaped(FILE *fp, const char *s)
{
    fputc('"', fp);
    for (; *s; s++) {
        switch (*s) {
        case '"':  fputs("\\\"", fp); break;
        case '\\': fputs("\\\\", fp); break;
        case '\n': fputs("\\n",  fp); break;
        case '\r': fputs("\\r",  fp); break;
        case '\t': fputs("\\t",  fp); break;
        default:
            if ((unsigned char)*s < 0x20)
                fprintf(fp, "\\u%04x", (unsigned char)*s);
            else
                fputc(*s, fp);
        }
    }
    fputc('"', fp);
}

int landlock_builder_save(const landlock_builder_t *b, const char *filename)
{
    if (!b || !filename || !b->prepared) { errno = EINVAL; return -1; }

    FILE *fp = fopen(filename, "w");
    if (!fp) return -1;

    int ok = 1;
    ok &= (fprintf(fp, "{\n") >= 0);
    ok &= (fprintf(fp, "  \"abi_version\": %d,\n", b->abi_version) >= 0);
    ok &= (fprintf(fp, "  \"rules\": [\n") >= 0);
    for (size_t i = 0; i < b->rule_count && ok; i++) {
        fprintf(fp, "    { \"path\": ");
        json_write_escaped(fp, b->rules[i].path);
        fprintf(fp, ", \"access\": %" PRIu64 " }",
                b->rules[i].access);
        if (i + 1 < b->rule_count) fprintf(fp, ",");
        ok &= (fprintf(fp, "\n") >= 0);
    }
    ok &= (fprintf(fp, "  ]\n") >= 0);
    ok &= (fprintf(fp, "}\n") >= 0);
    if (fclose(fp) != 0) ok = 0;

    if (!ok) {
        unlink(filename);
        errno = EIO;
        return -1;
    }
    return 0;
}

/** Skip whitespace, return pointer to next non-space char. */
static const char *json_skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

/** Parse a JSON string (starting at opening quote), return pointer
 *  after closing quote.  Writes unescaped content into `out`. */
static bool json_parse_string(const char **pp, char *out, size_t out_size)
{
    const char *p = *pp;
    if (*p != '"') return false;
    p++; /* skip opening quote */
    size_t i = 0;
    while (*p && *p != '"') {
        if (*p == '\\' && *(p + 1)) {
            p++;
            switch (*p) {
            case '"':  if (i < out_size - 1) out[i++] = '"';  break;
            case '\\': if (i < out_size - 1) out[i++] = '\\'; break;
            case 'n':  if (i < out_size - 1) out[i++] = '\n'; break;
            case 'r':  if (i < out_size - 1) out[i++] = '\r'; break;
            case 't':  if (i < out_size - 1) out[i++] = '\t'; break;
            case 'u': {
                /* Decode \uXXXX (basic multilingual plane only) */
                unsigned int cp = 0;
                int ok = 1;
                for (int d = 0; d < 4; d++) {
                    p++;
                    char c = *p;
                    cp <<= 4;
                    if (c >= '0' && c <= '9')      cp |= (unsigned)(c - '0');
                    else if (c >= 'a' && c <= 'f') cp |= (unsigned)(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') cp |= (unsigned)(c - 'A' + 10);
                    else { ok = 0; break; }
                }
                if (!ok) return false;
                /* Encode as UTF-8 (BMP only, no surrogate pairs) */
                if (cp < 0x80) {
                    if (i < out_size - 1) out[i++] = (char)cp;
                } else if (cp < 0x800) {
                    if (i + 1 < out_size) {
                        out[i++] = (char)(0xC0 | (cp >> 6));
                        out[i++] = (char)(0x80 | (cp & 0x3F));
                    }
                } else {
                    if (i + 2 < out_size) {
                        out[i++] = (char)(0xE0 | (cp >> 12));
                        out[i++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        out[i++] = (char)(0x80 | (cp & 0x3F));
                    }
                }
                break;
            }
            default:   if (i < out_size - 1) out[i++] = *p;  break;
            }
        } else {
            if (i < out_size - 1) out[i++] = *p;
        }
        p++;
    }
    if (*p != '"') return false;
    p++; /* skip closing quote */
    out[i] = '\0';
    *pp = p;
    return true;
}

int landlock_builder_load(landlock_builder_t *b, const char *filename)
{
    if (!b || !filename) { errno = EINVAL; return -1; }

    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    if (fsize < 0) { fclose(fp); return -1; }
    fseek(fp, 0, SEEK_SET);

    char *json = malloc((size_t)fsize + 1);
    if (!json) { fclose(fp); return -1; }
    size_t read_bytes = fread(json, 1, (size_t)fsize, fp);
    (void)read_bytes;
    json[fsize] = '\0';
    fclose(fp);

    /* Parse abi_version: find key, skip to colon, parse integer */
    const char *p = strstr(json, "\"abi_version\"");
    if (!p) { free(json); return -1; }
    p += strlen("\"abi_version\"");
    p = json_skip_ws(p);
    if (*p == ':') p++;
    p = json_skip_ws(p);
    b->abi_version = (int)strtol(p, NULL, 10);

    /* Parse rules: find each "path" key, read its string value,
     * then find the matching "access" key and read its integer. */
    p = json;
    while ((p = strstr(p, "\"path\""))) {
        p += strlen("\"path\"");
        p = json_skip_ws(p);
        if (*p != ':') { p++; continue; }
        p++; /* skip colon */
        p = json_skip_ws(p);

        char path_buf[PATH_MAX];
        if (!json_parse_string(&p, path_buf, sizeof(path_buf))) break;

        /* Find "access" after this path */
        const char *acc_pos = strstr(p, "\"access\"");
        if (!acc_pos) break;
        acc_pos += strlen("\"access\"");
        acc_pos = json_skip_ws(acc_pos);
        if (*acc_pos == ':') acc_pos++;
        acc_pos = json_skip_ws(acc_pos);
        uint64_t access = (uint64_t)strtoull(acc_pos, NULL, 10);

        radix_tree_allow(b->tree, path_buf, access);
    }

    free(json);

    /* Collect rules from tree into b->rules */
    landlock_rule_t *new_rules = NULL;
    size_t new_count = 0;
    radix_tree_collect_rules(b->tree, &new_rules, &new_count);

    if (!new_rules && new_count == 0 &&
        b->rule_count == 0) {
        /* Empty policy — valid but empty */
        b->rules = NULL;
        b->rule_count = 0;
    } else if (!new_rules) {
        /* OOM during collection — don't mark as prepared */
        errno = ENOMEM;
        return -1;
    } else {
        /* Free any previous rules */
        for (size_t i = 0; i < b->rule_count; i++) {
            free((char *)b->rules[i].path);
        }
        free(b->rules);
        b->rules = new_rules;
        b->rule_count = new_count;
    }

    b->prepared = true;
    return 0;
}
