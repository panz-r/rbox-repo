/**
 * @file landlock_builder.h
 * @brief High-performance Landlock policy compiler library.
 *
 * Provides advanced algorithms for efficient storage, merging, symlink
 * expansion, and ABI adaptation of filesystem access policies.
 */

#ifndef LANDLOCK_BUILDER_H
#define LANDLOCK_BUILDER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <fcntl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  ABI version masks (Landlock filesystem access rights)             */
/* ------------------------------------------------------------------ */

/** Landlock ABI version 1 – supports only LANDLOCK_ACCESS_FS_EXECUTE */
#define LANDLOCK_ABI_V1  1
/** Landlock ABI version 2 – adds READ_DIR, WRITE_FILE, etc. */
#define LANDLOCK_ABI_V2  2
/** Landlock ABI version 3 – adds REMOVE_{FILE,DIR}, RENAME_{SRC,DST} */
#define LANDLOCK_ABI_V3  3
/** Landlock ABI version 4 – adds REFER, TRUNCATE, IOCTL, WATCH_MOUNT */
#define LANDLOCK_ABI_V4  4

/** Current maximum ABI version supported by this library */
#define LANDLOCK_ABI_MAX 4

/* ------------------------------------------------------------------ */
/*  Access right constants (mirrors kernel UAPI)                      */
/* ------------------------------------------------------------------ */

#define LL_FS_EXECUTE       (1ULL << 0)
#define LL_FS_WRITE_FILE    (1ULL << 1)
#define LL_FS_READ_FILE     (1ULL << 2)
#define LL_FS_READ_DIR      (1ULL << 3)
#define LL_FS_REMOVE_DIR    (1ULL << 4)
#define LL_FS_REMOVE_FILE   (1ULL << 5)
#define LL_FS_RENAME_SRC    (1ULL << 6)
#define LL_FS_RENAME_DST    (1ULL << 7)
#define LL_FS_MAKE_SOCKET   (1ULL << 8)   /* ABI v4 */
#define LL_FS_MAKE_FIFO     (1ULL << 9)   /* ABI v4 */
#define LL_FS_MAKE_BLOCK    (1ULL << 10)  /* ABI v4 */
#define LL_FS_MAKE_CHAR     (1ULL << 11)  /* ABI v4 */
#define LL_FS_MAKE_SYM      (1ULL << 12)  /* ABI v4 */
#define LL_FS_REFER         (1ULL << 13)  /* ABI v4 */
#define LL_FS_TRUNCATE      (1ULL << 14)  /* ABI v4 */
#define LL_FS_IOCTL_DEV     (1ULL << 15)  /* ABI v4 */
#define LL_FS_WATCH_MOUNT   (1ULL << 16)  /* ABI v4 */

/** Convenience: read+write+execute for files */
#define LL_FS_FILE_RWX  (LL_FS_READ_FILE | LL_FS_WRITE_FILE | LL_FS_EXECUTE)
/** Convenience: read-only for files */
#define LL_FS_FILE_READ  (LL_FS_READ_FILE)
/** Convenience: read directory */
#define LL_FS_DIR_READ   (LL_FS_READ_DIR)
/** Convenience: full access */
#define LL_FS_ALL  0xFFFFFFFFFFFFFFFFULL

/* ------------------------------------------------------------------ */
/*  Virtual filesystem prefixes (Landlock cannot enforce these)       */
/* ------------------------------------------------------------------ */

/**
 * Paths under these prefixes are silently ignored by allow()/deny()
 * because the kernel's Landlock subsystem does not enforce rules on
 * virtual filesystems (procfs, sysfs, etc.).
 */
#define LL_VFS_PATH_PROC  "/proc"
#define LL_VFS_PATH_SYS   "/sys"

/* ------------------------------------------------------------------ */
/*  Opaque builder handle                                             */
/* ------------------------------------------------------------------ */

typedef struct landlock_builder landlock_builder_t;

/* ------------------------------------------------------------------ */
/*  Output rule                                                       */
/* ------------------------------------------------------------------ */

/** A single compiled rule ready for Landlock enforcement. */
typedef struct {
    const char *path;   /**< Canonical absolute path (owned by builder). */
    uint64_t    access; /**< Access mask (already ABI-masked). */
} landlock_rule_t;

/* ------------------------------------------------------------------ */
/*  Public API                                                        */
/* ------------------------------------------------------------------ */

/**
 * Create a new Landlock policy builder.
 * @return Opaque handle, or NULL on allocation failure.
 */
landlock_builder_t *landlock_builder_new(void);

/**
 * Destroy a builder and free all associated memory.
 * @param b Builder handle (NULL is a safe no-op).
 */
void landlock_builder_free(landlock_builder_t *b);

/**
 * Add an allow rule to the policy.
 *
 * The path is canonicalised internally.  Duplicate paths are merged
 * (access masks are OR'd).
 *
 * @param b       Builder handle.
 * @param path    Absolute or relative filesystem path.
 * @param access  Bitmask of LL_FS_* access rights.
 * @return 0 on success, -1 on error (errno set).
 */
int landlock_builder_allow(landlock_builder_t *b, const char *path, uint64_t access);

/**
 * Add a deny rule to the policy.
 *
 * Deny rules override any allow rules at the same path or below after
 * `landlock_builder_prepare()` is called.
 *
 * @param b    Builder handle.
 * @param path Absolute or relative filesystem path.
 * @return 0 on success, -1 on error (errno set).
 */
int landlock_builder_deny(landlock_builder_t *b, const char *path);

/**
 * Finalise the policy: overlap removal, prefix simplification,
 * optional symlink expansion, and ABI masking.
 *
 * After this call, `landlock_builder_get_rules()` returns the
 * compiled rule set.
 *
 * @param b              Builder handle.
 * @param abi_version    Target Landlock ABI version (1..LANDLOCK_ABI_MAX).
 * @param expand_symlinks If true, expand symlinks that point inside
 *                        allowed hierarchies.
 * @return 0 on success, -1 on error (errno set).
 */
int landlock_builder_prepare(landlock_builder_t *b, int abi_version, bool expand_symlinks);

/**
 * Retrieve the compiled rules.
 *
 * The returned array is owned by the builder and remains valid until
 * the next `prepare()` call or `landlock_builder_free()`.
 *
 * @param b      Builder handle.
 * @param count  Out: number of rules.
 * @return Pointer to array of rules, or NULL if none.
 */
const landlock_rule_t *landlock_builder_get_rules(landlock_builder_t *b, size_t *count);

/**
 * Serialise the current (prepared) policy to a file.
 *
 * @param b        Builder handle (must have been prepared).
 * @param filename Output file path.
 * @return 0 on success, -1 on error (errno set).
 */
int landlock_builder_save(const landlock_builder_t *b, const char *filename);

/**
 * Load a serialised policy into a builder.
 *
 * @param b        Builder handle (freshly created).
 * @param filename Input file path.
 * @return 0 on success, -1 on error (errno set).
 */
int landlock_builder_load(landlock_builder_t *b, const char *filename);

/**
 * Open a rule's path with O_PATH and return the file descriptor.
 *
 * The caller is responsible for closing the returned fd with close(2).
 * This is the recommended way to obtain the parent_fd for constructing
 * `struct landlock_path_beneath_attr`.
 *
 * @param rule  A rule returned by landlock_builder_get_rules().
 * @param flags Additional open flags (default: O_PATH | O_CLOEXEC | O_NOFOLLOW).
 * @return File descriptor on success, -1 on error (errno set).
 */
int landlock_rule_open_fd(const landlock_rule_t *rule, int flags);

/**
 * Check whether `path` resides on a virtual filesystem that Landlock
 * cannot enforce rules on (e.g. /proc, /sys).
 *
 * Such paths are silently ignored by landlock_builder_allow() and
 * landlock_builder_deny().  Callers can use this function to detect
 * when a rule was skipped.
 *
 * @param path  Absolute or relative path to check.
 * @return 1 if path is on a virtual filesystem, 0 otherwise.
 */
int landlock_path_is_vfs(const char *path);

/**
 * Return the ABI bitmask for a given ABI version.
 *
 * @param abi_version  Landlock ABI version (1..LANDLOCK_ABI_MAX).
 * @return Bitmask of supported access rights, or 0 for invalid version.
 */
uint64_t landlock_abi_mask(int abi_version);

#ifdef __cplusplus
}
#endif

#endif /* LANDLOCK_BUILDER_H */
