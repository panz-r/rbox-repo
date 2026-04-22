/**
 * @file mock_fs.c
 * @brief In-memory fake filesystem implementation for testing.
 */

#define _DEFAULT_SOURCE
#define MOCK_FS_INTERNAL
#include "mock_fs.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <sys/param.h>
#include <time.h>
#include <sys/types.h>
#include <dirent.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include <sys/stat.h>

/* ------------------------------------------------------------------ */
/*  Internal data structures                                           */
/* ------------------------------------------------------------------ */

#define MAX_FS_ENTRIES 4096
#define MAX_PATH_LEN   4096

typedef enum {
    FS_ENTRY_DIR,
    FS_ENTRY_FILE,
    FS_ENTRY_SYMLINK
} fs_entry_type_t;

typedef struct {
    char            path[MAX_PATH_LEN];
    fs_entry_type_t type;
    char            symlink_target[MAX_PATH_LEN];  /* Only for symlinks */
    bool            in_use;
} fs_entry_t;

static fs_entry_t fs_entries[MAX_FS_ENTRIES];
static int fs_active = 0;

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static fs_entry_t *find_entry(const char *path)
{
    for (int i = 0; i < MAX_FS_ENTRIES; i++) {
        if (fs_entries[i].in_use &&
            strcmp(fs_entries[i].path, path) == 0) {
            return &fs_entries[i];
        }
    }
    return NULL;
}

static fs_entry_t *create_entry(const char *path, fs_entry_type_t type)
{
    for (int i = 0; i < MAX_FS_ENTRIES; i++) {
        if (!fs_entries[i].in_use) {
            fs_entries[i].in_use = true;
            strncpy(fs_entries[i].path, path, MAX_PATH_LEN - 1);
            fs_entries[i].path[MAX_PATH_LEN - 1] = '\0';
            fs_entries[i].type = type;
            fs_entries[i].symlink_target[0] = '\0';
            return &fs_entries[i];
        }
    }
    return NULL; /* Full */
}

/** Clean a path (resolve . and .., collapse slashes) */
static void clean_path(const char *in, char *out, size_t out_size);

/**
 * Resolve a path in the mock filesystem, following symlinks.
 * Returns 0 on success with the resolved path in `out`.
 * Returns -1 if the path doesn't exist or too many symlinks.
 */
static int resolve_path(const char *path, char *out, int max_depth)
{
    if (max_depth <= 0) return -1;  /* Symlink loop */

    /* Normalise: remove trailing slashes (except root) */
    char norm[MAX_PATH_LEN];
    strncpy(norm, path, MAX_PATH_LEN - 1);
    norm[MAX_PATH_LEN - 1] = '\0';
    size_t nlen = strlen(norm);
    while (nlen > 1 && norm[nlen - 1] == '/') {
        norm[--nlen] = '\0';
    }

    /* Check existence */
    fs_entry_t *entry = find_entry(norm);
    if (!entry) {
        /* If it's a prefix of an existing dir, treat as dir */
        for (int i = 0; i < MAX_FS_ENTRIES; i++) {
            if (fs_entries[i].in_use) {
                size_t elen = strlen(fs_entries[i].path);
                if (memcmp(fs_entries[i].path, norm, elen) == 0 &&
                    norm[elen] == '/') {
                    /* norm is a prefix of an existing entry */
                    strncpy(out, norm, MAX_PATH_LEN - 1);
                    out[MAX_PATH_LEN - 1] = '\0';
                    return 0;
                }
            }
        }
        return -1;
    }

    if (entry->type == FS_ENTRY_SYMLINK) {
        /* Resolve the symlink target */
        const char *target = entry->symlink_target;

        if (target[0] != '/') {
            /* Relative to symlink's directory */
            char dir[MAX_PATH_LEN];
            strncpy(dir, norm, MAX_PATH_LEN - 1);
            dir[MAX_PATH_LEN - 1] = '\0';
            char *last_slash = strrchr(dir, '/');
            if (last_slash) {
                *(last_slash + 1) = '\0';
                size_t dlen = strlen(dir);
                size_t tlen = strlen(target);
                size_t cpy = tlen < (MAX_PATH_LEN - 1 - dlen) ? tlen : (MAX_PATH_LEN - 1 - dlen);
                memcpy(dir + dlen, target, cpy);
                dir[dlen + cpy] = '\0';
            } else {
                size_t tlen = strlen(target);
                size_t cpy = tlen < (MAX_PATH_LEN - 1) ? tlen : (MAX_PATH_LEN - 1);
                memcpy(dir, target, cpy);
                dir[cpy] = '\0';
            }
            /* Clean the path to resolve . and .. components */
            char cleaned[MAX_PATH_LEN];
            clean_path(dir, cleaned, sizeof(cleaned));
            return resolve_path(cleaned, out, max_depth - 1);
        } else {
            return resolve_path(target, out, max_depth - 1);
        }
    }

    /* Regular file or dir */
    strncpy(out, norm, MAX_PATH_LEN - 1);
    out[MAX_PATH_LEN - 1] = '\0';
    return 0;
}

/** Clean a path (resolve . and .., collapse slashes) */
static void clean_path(const char *in, char *out, size_t out_size)
{
    if (!in || !out || out_size == 0) return;

    /* Make absolute if not already */
    char buf[MAX_PATH_LEN];
    if (in[0] != '/') {
        /* Assume cwd is "/" for mock fs */
        buf[0] = '/';
        buf[1] = '\0';
        strncat(buf, in, MAX_PATH_LEN - 2);
    } else {
        strncpy(buf, in, MAX_PATH_LEN - 1);
        buf[MAX_PATH_LEN - 1] = '\0';
    }

    /* Collapse slashes */
    char *dst = buf;
    char *src = buf;
    while (*src) {
        *dst = *src;
        if (*src == '/' && *(src + 1) == '/') { src++; continue; }
        dst++; src++;
    }
    *dst = '\0';

    /* Split into components */
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

    /* Rebuild */
    int pos = 0;
    out[pos++] = '/';
    for (int i = 0; i < nc; i++) {
        /* Add separator if not first component */
        if (i > 0 || pos > 1) {
            out[pos++] = '/';
        }
        if (pos + clen[i] >= (int)out_size) break;
        memcpy(out + pos, comps[i], (size_t)clen[i]);
        pos += clen[i];
    }
    out[pos] = '\0';
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

int mock_fs_create_dir(const char *path)
{
    char clean[MAX_PATH_LEN];
    clean_path(path, clean, sizeof(clean));

    if (find_entry(clean)) return -1;  /* Already exists */

    /* Iteratively ensure all parent dirs exist, from root down */
    /* Collect missing parents */
    char *missing[128];
    int n_missing = 0;
    char tmp[MAX_PATH_LEN];
    strncpy(tmp, clean, MAX_PATH_LEN - 1);
    tmp[MAX_PATH_LEN - 1] = '\0';

    for (;;) {
        char *last_slash = strrchr(tmp, '/');
        if (!last_slash || last_slash == tmp) break;  /* reached root */
        *last_slash = '\0';
        if (find_entry(tmp)) break;  /* parent exists */
        if (n_missing < 128) {
            missing[n_missing] = strdup(tmp);
            n_missing++;
        }
    }

    /* Create parents from shallowest to deepest */
    for (int i = n_missing - 1; i >= 0; i--) {
        fs_entry_t *e = create_entry(missing[i], FS_ENTRY_DIR);
        free(missing[i]);
        if (!e) return -1;
    }

    fs_entry_t *e = create_entry(clean, FS_ENTRY_DIR);
    if (!e) return -1;
    return 0;
}

int mock_fs_create_file(const char *path)
{
    char clean[MAX_PATH_LEN];
    clean_path(path, clean, sizeof(clean));

    if (find_entry(clean)) return -1;
    fs_entry_t *e = create_entry(clean, FS_ENTRY_FILE);
    if (!e) return -1;
    return 0;
}

int mock_fs_create_symlink(const char *link_path, const char *target)
{
    char clean[MAX_PATH_LEN];
    clean_path(link_path, clean, sizeof(clean));

    if (find_entry(clean)) return -1;
    fs_entry_t *e = create_entry(clean, FS_ENTRY_SYMLINK);
    if (!e) return -1;
    strncpy(e->symlink_target, target, MAX_PATH_LEN - 1);
    e->symlink_target[MAX_PATH_LEN - 1] = '\0';
    return 0;
}

int mock_fs_list_children(const char *dir_path, const char **names, int max_names)
{
    char clean[MAX_PATH_LEN];
    clean_path(dir_path, clean, sizeof(clean));

    /* Normalize: remove trailing slash */
    size_t clen = strlen(clean);
    while (clen > 1 && clean[clen - 1] == '/') clean[--clen] = '\0';

    fs_entry_t *dir = find_entry(clean);
    if (!dir || dir->type != FS_ENTRY_DIR) return -1;

    int count = 0;
    size_t prefix_len = clen;
    /* Handle root specially */
    if (prefix_len == 1 && clean[0] == '/') prefix_len = 1;

    for (int i = 0; i < MAX_FS_ENTRIES && count < max_names; i++) {
        if (!fs_entries[i].in_use) continue;
        const char *ep = fs_entries[i].path;
        /* Check if this entry is a direct child of dir */
        if (clean[0] == '/' && clean[1] == '\0') {
            /* Root directory: child has exactly one '/' followed by name */
            if (ep[0] == '/' && ep[1] != '\0' && ep[1] != '/') {
                /* Check no further '/' (direct child) */
                const char *slash = strchr(ep + 1, '/');
                if (!slash) {
                    names[count++] = ep + 1;
                }
            }
        } else {
            /* Non-root: child starts with dir_path + '/' */
            size_t elen = strlen(ep);
            if (elen > prefix_len + 1 &&
                memcmp(ep, clean, prefix_len) == 0 &&
                ep[prefix_len] == '/') {
                /* Check no further '/' after the child name */
                const char *rest = ep + prefix_len + 1;
                if (!strchr(rest, '/')) {
                    names[count++] = rest;
                }
            }
        }
    }
    return count;
}

int mock_fs_exists(const char *path)
{
    char clean[MAX_PATH_LEN];
    clean_path(path, clean, sizeof(clean));
    fs_entry_t *e = find_entry(clean);
    if (!e) return 0;
    switch (e->type) {
    case FS_ENTRY_DIR:     return 1;
    case FS_ENTRY_FILE:    return 2;
    case FS_ENTRY_SYMLINK: return 3;
    }
    return 0;
}

void mock_fs_reset(void)
{
    memset(fs_entries, 0, sizeof(fs_entries));
    fs_active = 1;
}

bool mock_fs_active(void)
{
    return fs_active != 0;
}

/* ------------------------------------------------------------------ */
/*  Mock syscall replacements                                          */
/* ------------------------------------------------------------------ */

char *__wrap_realpath(const char *path, char *resolved)
{
    if (!path) { errno = EINVAL; return NULL; }

    char cleaned[MAX_PATH_LEN];
    clean_path(path, cleaned, sizeof(cleaned));

    char resolved_path[MAX_PATH_LEN];
    int rp_ret = resolve_path(cleaned, resolved_path, 40);

    if (rp_ret != 0) {
        /* Path doesn't exist — fail as real realpath would */
        errno = ENOENT;
        return NULL;
    }

    if (resolved) {
        size_t rlen = strlen(resolved_path);
        size_t cpy = rlen < (size_t)(PATH_MAX - 1) ? rlen : (size_t)(PATH_MAX - 1);
        memcpy(resolved, resolved_path, cpy);
        resolved[cpy] = '\0';
        return resolved;
    } else {
        char *r = malloc(PATH_MAX);
        if (r) {
            size_t rlen = strlen(resolved_path);
            size_t cpy = rlen < (size_t)(PATH_MAX - 1) ? rlen : (size_t)(PATH_MAX - 1);
            memcpy(r, resolved_path, cpy);
            r[cpy] = '\0';
        }
        return r;
    }
}

static int fill_stat(const char *path, struct stat *buf, int follow_symlinks)
{
    char cleaned[MAX_PATH_LEN];
    clean_path(path, cleaned, sizeof(cleaned));

    fs_entry_t *entry = find_entry(cleaned);
    if (!entry) {
        /* Try resolving through symlinks */
        char resolved[MAX_PATH_LEN];
        if (resolve_path(cleaned, resolved, 40) == 0) {
            entry = find_entry(resolved);
        }
    }
    if (!entry) {
        errno = ENOENT;
        return -1;
    }

    /* If following symlinks and this is a symlink, resolve it */
    if (follow_symlinks && entry->type == FS_ENTRY_SYMLINK) {
        char resolved[MAX_PATH_LEN];
        if (resolve_path(cleaned, resolved, 40) == 0) {
            entry = find_entry(resolved);
        }
        if (!entry) { errno = ENOENT; return -1; }
    }

    memset(buf, 0, sizeof(*buf));
    if (!follow_symlinks && entry->type == FS_ENTRY_SYMLINK) {
        buf->st_mode = S_IFLNK | 0777;
    } else if (follow_symlinks && entry->type == FS_ENTRY_SYMLINK) {
        /* Should have been resolved above — treat as target type */
        buf->st_mode = S_IFREG | 0644;
    } else if (entry->type == FS_ENTRY_DIR) {
        buf->st_mode = S_IFDIR | 0755;
    } else {
        buf->st_mode = S_IFREG | 0644;
    }
    buf->st_size = 0;
    buf->st_nlink = 1;
    buf->st_uid = 1000;
    buf->st_gid = 1000;
    time_t now = time(NULL);
    buf->st_mtime = now;
    buf->st_atime = now;
    buf->st_ctime = now;
    return 0;
}

int __wrap_stat(const char *path, struct stat *buf)
{
    return fill_stat(path, buf, 1 /* follow symlinks */);
}

int __wrap_lstat(const char *path, struct stat *buf)
{
    return fill_stat(path, buf, 0 /* don't follow symlinks */);
}

ssize_t __wrap_readlink(const char *path, char *buf, size_t bufsiz)
{
    if (!path || !buf || bufsiz == 0) { errno = EINVAL; return -1; }

    char cleaned[MAX_PATH_LEN];
    clean_path(path, cleaned, sizeof(cleaned));

    fs_entry_t *entry = find_entry(cleaned);
    if (!entry) { errno = ENOENT; return -1; }
    if (entry->type != FS_ENTRY_SYMLINK) { errno = EINVAL; return -1; }

    size_t tlen = strlen(entry->symlink_target);
    size_t copy_len = tlen < (bufsiz - 1) ? tlen : (bufsiz - 1);
    memcpy(buf, entry->symlink_target, copy_len);
    buf[copy_len] = '\0';
    return (ssize_t)copy_len;
}

/* ------------------------------------------------------------------ */
/*  Wrapped directory functions for mock filesystem                   */
/* ------------------------------------------------------------------ */

static char mock_dir_path[PATH_MAX];
static char mock_dir_entries[256][NAME_MAX];
static int mock_dir_count = 0;
static int mock_dir_index = 0;
static int mock_dir_is_open = 0;

static struct dirent mock_dirent;

static DIR *mock_dir_ptr = (DIR *)mock_dir_path;  /* Dummy non-NULL pointer */

DIR *__wrap_opendir(const char *path)
{
    char clean[MAX_PATH_LEN];
    clean_path(path, clean, sizeof(clean));

    /* Special case: root "/" always succeeds if mock fs is active */
    if (strcmp(clean, "/") == 0) {
        mock_dir_count = 0;
        mock_dir_index = 0;
        mock_dir_is_open = 1;
        strcpy(mock_dir_path, "/");
        return mock_dir_ptr;
    }

    mock_dir_count = mock_fs_list_children(clean, (const char **)mock_dir_entries, 256);
    if (mock_dir_count < 0) {
        errno = ENOENT;
        return NULL;
    }

    strncpy(mock_dir_path, clean, PATH_MAX - 1);
    mock_dir_path[PATH_MAX - 1] = '\0';
    mock_dir_index = 0;
    mock_dir_is_open = 1;

    return mock_dir_ptr;
}

struct dirent *__wrap_readdir(DIR *dir)
{
    if (!mock_dir_is_open) return readdir(dir);
    if (mock_dir_index >= mock_dir_count) return NULL;

    memset(&mock_dirent, 0, sizeof(mock_dirent));
    strncpy(mock_dirent.d_name, mock_dir_entries[mock_dir_index], NAME_MAX - 1);
    mock_dirent.d_name[NAME_MAX - 1] = '\0';
    mock_dir_index++;

    return &mock_dirent;
}

int __wrap_closedir(DIR *dir)
{
    if (!mock_dir_is_open) return closedir(dir);
    mock_dir_count = 0;
    mock_dir_index = 0;
    mock_dir_is_open = 0;
    return 0;
}
