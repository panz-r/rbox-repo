/**
 * @file arena.h
 * @brief Bump-pointer arena allocator for high-performance tree construction.
 *
 * Arena allocates from fixed-size blocks (256 KB).  Individual frees are
 * NOT supported — the entire arena is freed at once.  Nodes that are
 * "removed" from the tree simply become unreachable; their memory is
 * reclaimed when the arena is destroyed.
 */

#ifndef ARENA_H
#define ARENA_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ARENA_BLOCK_SIZE (256 * 1024)  /* 256 KB per block */

typedef struct arena_block {
    struct arena_block *next;
    /* Flexible array must be last — but we want a fixed-size inline buffer
     * to avoid a second allocation.  Use a large array instead. */
    char data[ARENA_BLOCK_SIZE - sizeof(struct arena_block *)];
} arena_block_t;

typedef struct {
    arena_block_t *head;   /* Current block (may be NULL). */
    size_t         offset; /* Next byte in current block. */
    size_t         total;  /* Total bytes allocated across all blocks. */
} arena_t;

/** Initialise an empty arena. */
void arena_init(arena_t *a);

/** Free all blocks in the arena. */
void arena_free(arena_t *a);

/** Allocate `size` bytes (aligned to max_align_t). Returns NULL on OOM. */
void *arena_alloc(arena_t *a, size_t size);

/** Allocate zeroed memory. */
void *arena_calloc(arena_t *a, size_t nmemb, size_t size);

/** Duplicate a string into the arena. */
char *arena_strdup(arena_t *a, const char *s);

/** Copy `n` bytes into the arena. */
void *arena_memdup(arena_t *a, const void *p, size_t n);

/** Return total bytes consumed by the arena. */
size_t arena_usage(const arena_t *a);

#ifdef __cplusplus
}
#endif

#endif /* ARENA_H */
