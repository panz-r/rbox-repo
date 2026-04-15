/*
 * timer_heap.c - Min-heap timer priority queue implementation
 *
 * Binary min-heap keyed by expiration time (absolute ms).
 * O(log n) insertion, O(log n) removal, O(1) peek at earliest.
 *
 * Thread safety: This implementation is NOT thread-safe. All access
 * should be from a single thread (e.g., the server epoll thread).
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include "timer_heap.h"

#define INITIAL_CAPACITY 16
#define MAX_FD 65536

struct rbox_timer_heap {
    rbox_timer_entry_t **entries;
    size_t capacity;
    size_t count;
    rbox_timer_entry_t **fd_to_entry;
};

static void heap_swap(rbox_timer_heap_t *heap, size_t i, size_t j) {
    rbox_timer_entry_t *tmp = heap->entries[i];
    heap->entries[i] = heap->entries[j];
    heap->entries[j] = tmp;
    heap->entries[i]->heap_index = i;
    heap->entries[j]->heap_index = j;
}

static void heap_up(rbox_timer_heap_t *heap, size_t idx) {
    while (idx > 0) {
        size_t parent = (idx - 1) / 2;
        if (heap->entries[parent]->expires_at <= heap->entries[idx]->expires_at) {
            break;
        }
        heap_swap(heap, parent, idx);
        idx = parent;
    }
}

static void heap_down(rbox_timer_heap_t *heap, size_t idx) {
    while (1) {
        size_t left = 2 * idx + 1;
        size_t right = 2 * idx + 2;
        size_t smallest = idx;

        if (left < heap->count && heap->entries[left]->expires_at < heap->entries[smallest]->expires_at) {
            smallest = left;
        }
        if (right < heap->count && heap->entries[right]->expires_at < heap->entries[smallest]->expires_at) {
            smallest = right;
        }

        if (smallest == idx) {
            break;
        }

        heap_swap(heap, idx, smallest);
        idx = smallest;
    }
}

static void heap_push(rbox_timer_heap_t *heap, rbox_timer_entry_t *entry) {
    if (heap->count >= heap->capacity) {
        size_t new_capacity = heap->capacity * 2;
        rbox_timer_entry_t **new_entries = realloc(heap->entries, new_capacity * sizeof(rbox_timer_entry_t *));
        if (!new_entries) {
            return;
        }
        heap->entries = new_entries;
        heap->capacity = new_capacity;
    }

    heap->entries[heap->count] = entry;
    entry->heap_index = heap->count;
    heap->count++;
    heap_up(heap, heap->count - 1);
}

static rbox_timer_entry_t *heap_pop_min(rbox_timer_heap_t *heap) {
    if (heap->count == 0) {
        return NULL;
    }

    rbox_timer_entry_t *min = heap->entries[0];
    heap->count--;

    if (heap->count > 0) {
        heap->entries[0] = heap->entries[heap->count];
        heap->entries[0]->heap_index = 0;
        heap_down(heap, 0);
    }

    min->heap_index = SIZE_MAX;
    return min;
}

static void heap_remove(rbox_timer_heap_t *heap, size_t idx) {
    if (idx >= heap->count) {
        return;
    }

    heap->count--;

    if (idx < heap->count) {
        heap->entries[idx] = heap->entries[heap->count];
        heap->entries[idx]->heap_index = idx;

        size_t parent = (idx - 1) / 2;
        if (idx > 0 && heap->entries[idx]->expires_at < heap->entries[parent]->expires_at) {
            heap_up(heap, idx);
        } else {
            heap_down(heap, idx);
        }
    }
}

rbox_timer_heap_t *rbox_timer_heap_new(void) {
    rbox_timer_heap_t *heap = calloc(1, sizeof(rbox_timer_heap_t));
    if (!heap) {
        return NULL;
    }

    heap->entries = calloc(INITIAL_CAPACITY, sizeof(rbox_timer_entry_t *));
    if (!heap->entries) {
        free(heap);
        return NULL;
    }

    heap->fd_to_entry = calloc(MAX_FD, sizeof(rbox_timer_entry_t *));
    if (!heap->fd_to_entry) {
        free(heap->entries);
        free(heap);
        return NULL;
    }

    heap->capacity = INITIAL_CAPACITY;
    heap->count = 0;
    return heap;
}

void rbox_timer_heap_free(rbox_timer_heap_t *heap) {
    if (!heap) {
        return;
    }

    for (size_t i = 0; i < heap->count; i++) {
        free(heap->entries[i]);
    }
    free(heap->entries);
    free(heap->fd_to_entry);
    free(heap);
}

int rbox_timer_add(rbox_timer_heap_t *heap, int fd, uint64_t timeout_ms, rbox_timeout_type_t type) {
    if (!heap || fd < 0 || fd >= MAX_FD) {
        return -1;
    }

    if (heap->fd_to_entry[fd]) {
        rbox_timer_remove(heap, fd);
    }

    rbox_timer_entry_t *entry = calloc(1, sizeof(rbox_timer_entry_t));
    if (!entry) {
        return -1;
    }

    entry->expires_at = timeout_ms;
    entry->fd = fd;
    entry->type = type;
    entry->heap_index = SIZE_MAX;

    heap_push(heap, entry);
    heap->fd_to_entry[fd] = entry;

    return 0;
}

int rbox_timer_remove(rbox_timer_heap_t *heap, int fd) {
    if (!heap || fd < 0 || fd >= MAX_FD) {
        return -1;
    }

    rbox_timer_entry_t *entry = heap->fd_to_entry[fd];
    if (!entry || entry->heap_index == SIZE_MAX) {
        return -1;
    }

    heap_remove(heap, entry->heap_index);
    heap->fd_to_entry[fd] = NULL;
    free(entry);

    return 0;
}

uint64_t rbox_timer_next_expiry(rbox_timer_heap_t *heap, uint64_t now) {
    if (!heap || heap->count == 0) {
        return UINT64_MAX;
    }

    rbox_timer_entry_t *min = heap->entries[0];
    if (min->expires_at <= now) {
        return 0;
    }

    uint64_t diff = min->expires_at - now;
    return diff;
}

void rbox_timer_process_expired(rbox_timer_heap_t *heap, uint64_t now,
                                void (*cb)(int fd, rbox_timeout_type_t type)) {
    if (!heap || !cb) {
        return;
    }

    while (heap->count > 0) {
        rbox_timer_entry_t *min = heap->entries[0];
        if (min->expires_at > now) {
            break;
        }

        int fd = min->fd;
        rbox_timeout_type_t type = min->type;

        heap_pop_min(heap);
        heap->fd_to_entry[fd] = NULL;
        free(min);

        cb(fd, type);
    }
}

rbox_timer_entry_t *rbox_timer_get_expired(rbox_timer_heap_t *heap) {
    if (!heap || heap->count == 0) {
        return NULL;
    }

    rbox_timer_entry_t *min = heap->entries[0];
    heap_pop_min(heap);
    heap->fd_to_entry[min->fd] = NULL;
    return min;
}

size_t rbox_timer_count(const rbox_timer_heap_t *heap) {
    return heap ? heap->count : 0;
}
