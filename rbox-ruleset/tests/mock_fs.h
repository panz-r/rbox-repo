/**
 * @file mock_fs.h
 * @brief Mock filesystem for unit testing without real syscalls.
 *
 * When compiled with -DMOCK_FS, all realpath/stat/lstat calls made by
 * the library are redirected to this in-memory fake filesystem.
 */

#ifndef MOCK_FS_H
#define MOCK_FS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Mock filesystem API                                                */
/* ------------------------------------------------------------------ */

/** Create a directory in the mock filesystem. */
int mock_fs_create_dir(const char *path);

/** Create a regular file in the mock filesystem. */
int mock_fs_create_file(const char *path);

/** Create a symbolic link in the mock filesystem. */
int mock_fs_create_symlink(const char *link_path, const char *target);

/** Reset the mock filesystem to empty. */
void mock_fs_reset(void);

/**
 * Check if the mock filesystem is active (was initialized).
 * The library functions will use mock implementations when this is true.
 */
bool mock_fs_active(void);

/* ------------------------------------------------------------------ */
/*  Mock syscall replacements (only active when mock_fs_active())     */
/* ------------------------------------------------------------------ */

char *mock_realpath(const char *path, char *resolved);
int   mock_stat(const char *path, struct stat *buf);
int   mock_lstat(const char *path, struct stat *buf);
ssize_t mock_readlink(const char *path, char *buf, size_t bufsiz);

/**
 * List children of a directory in the mock filesystem.
 * Writes child names (relative, no leading '/') into `names`, up to `max_names`.
 * Returns number of children found, or -1 if path is not a directory.
 */
int mock_fs_list_children(const char *dir_path, const char **names, int max_names);

/** Check if a path exists in the mock filesystem and return its type. */
int mock_fs_exists(const char *path);

#ifdef __cplusplus
}
#endif

/* ------------------------------------------------------------------ */
/*  Interpose real syscalls when MOCK_FS is defined                   */
/* ------------------------------------------------------------------ */

#ifdef MOCK_FS

/* Skip macro redirections when compiling mock_fs.c itself */
#ifndef MOCK_FS_INTERNAL

/* Redirect standard library calls to mock versions.
 * We use #define tricks so the library's calls to realpath/stat/lstat
 * are transparently replaced. */

#define realpath(p, r)   mock_realpath((p), (r))
#define stat(p, b)       mock_stat((p), (b))
#define lstat(p, b)      mock_lstat((p), (b))
#define readlink(p, b, s) mock_readlink((p), (b), (s))

#endif /* MOCK_FS_INTERNAL */

#endif /* MOCK_FS */

#endif /* MOCK_FS_H */
