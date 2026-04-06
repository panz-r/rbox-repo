/**
 * @file arena.c
 * @brief Bump-pointer arena allocator implementation.
 */

#define _DEFAULT_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "arena.h"

void arena_init(arena_t *a)
{
    a->head = NULL;
    a->offset = 0;
    a->total = 0;
}

void arena_free(arena_t *a)
{
    arena_block_t *b = a->head;
    while (b) {
        arena_block_t *next = b->next;
        free(b);
        b = next;
    }
    a->head = NULL;
    a->offset = 0;
    a->total = 0;
}

/**
 * Allocate `size` bytes aligned to ARENA_ALIGN (16 bytes).
 * If the current block doesn't have room, allocate a new block.
 */
void *arena_alloc(arena_t *a, size_t size)
{
    if (size == 0) return NULL;

    const size_t align = ARENA_ALIGN;

    /* Align up, guard against overflow in the addition */
    size_t aligned;
    if (size > SIZE_MAX - (align - 1)) return NULL;  /* overflow */
    aligned = (size + align - 1) & ~(align - 1);

    /* Ensure we have a block with enough room.
     * offset + aligned cannot overflow because aligned <= SIZE_MAX/align*align
     * and both fit within a 256 KB block. */
    if (!a->head || a->offset + aligned > sizeof(a->head->data)) {
        /* Need a new block */
        arena_block_t *block = malloc(sizeof(arena_block_t));
        if (!block) return NULL;
        block->next = a->head;
        a->head = block;
        a->offset = 0;
    }

    void *ptr = (char *)(a->head->data) + a->offset;
    a->offset += aligned;
    a->total += aligned;
    return ptr;
}

void *arena_calloc(arena_t *a, size_t nmemb, size_t size)
{
    /* Overflow check: nmemb * size must not wrap */
    if (nmemb > 0 && size > SIZE_MAX / nmemb) return NULL;

    size_t total = nmemb * size;
    void *ptr = arena_alloc(a, total);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

char *arena_strdup(arena_t *a, const char *s)
{
    size_t len = strlen(s);
    char *dup = (char *)arena_alloc(a, len + 1);
    if (dup) {
        memcpy(dup, s, len);
        dup[len] = '\0';
    }
    return dup;
}

void *arena_memdup(arena_t *a, const void *p, size_t n)
{
    void *dup = arena_alloc(a, n);
    if (dup) memcpy(dup, p, n);
    return dup;
}

size_t arena_usage(const arena_t *a)
{
    return a->total;
}
