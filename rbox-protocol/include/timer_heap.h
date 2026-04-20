/*
 * timer_heap.h - Min-heap timer priority queue for rbox-protocol
 *
 * Uses a binary min-heap keyed by expiration time (absolute ms).
 * O(log n) insertion, O(log n) removal, O(1) peek at earliest.
 */

#ifndef RBOX_TIMER_HEAP_H
#define RBOX_TIMER_HEAP_H

#include <stddef.h>
#include <stdint.h>

typedef enum rbox_timeout_type {
    RBOX_TIMEOUT_IDLE,
    RBOX_TIMEOUT_HEADER,
    RBOX_TIMEOUT_BODY
} rbox_timeout_type_t;

typedef struct rbox_timer_entry {
    uint64_t expires_at;
    int fd;
    rbox_timeout_type_t type;
    size_t heap_index;
    void *data;
} rbox_timer_entry_t;

typedef struct rbox_timer_heap rbox_timer_heap_t;

rbox_timer_heap_t *rbox_timer_heap_new(void);

void rbox_timer_heap_free(rbox_timer_heap_t *heap);

int rbox_timer_add(rbox_timer_heap_t *heap, int fd, uint64_t timeout_ms, rbox_timeout_type_t type, void *data);

int rbox_timer_remove(rbox_timer_heap_t *heap, int fd);

uint64_t rbox_timer_next_expiry(rbox_timer_heap_t *heap, uint64_t now);

void rbox_timer_process_expired(rbox_timer_heap_t *heap, uint64_t now,
                                void (*cb)(int fd, rbox_timeout_type_t type));

rbox_timer_entry_t *rbox_timer_get_expired(rbox_timer_heap_t *heap);

size_t rbox_timer_count(const rbox_timer_heap_t *heap);

#endif /* RBOX_TIMER_HEAP_H */
