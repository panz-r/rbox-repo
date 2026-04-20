/*
 * test_timer_heap.c - Unit tests for the timer heap implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "../include/timer_heap.h"

static int test_timer_heap_basic(void) {
    printf("Testing timer heap basic operations...\n");

    rbox_timer_heap_t *heap = rbox_timer_heap_new();
    assert(heap != NULL);
    assert(rbox_timer_count(heap) == 0);

    uint64_t now = 1000;

    int fd1 = 5;
    assert(rbox_timer_add(heap, fd1, now + 100, RBOX_TIMEOUT_IDLE, NULL) == 0);
    assert(rbox_timer_count(heap) == 1);

    int fd2 = 10;
    assert(rbox_timer_add(heap, fd2, now + 50, RBOX_TIMEOUT_HEADER, NULL) == 0);
    assert(rbox_timer_count(heap) == 2);

    int fd3 = 15;
    assert(rbox_timer_add(heap, fd3, now + 150, RBOX_TIMEOUT_BODY, NULL) == 0);
    assert(rbox_timer_count(heap) == 3);

    uint64_t next = rbox_timer_next_expiry(heap, now);
    assert(next == 50);

    rbox_timer_entry_t *expired = rbox_timer_get_expired(heap);
    assert(expired != NULL);
    assert(expired->fd == fd2);
    assert(expired->type == RBOX_TIMEOUT_HEADER);
    assert(rbox_timer_count(heap) == 2);
    free(expired);

    next = rbox_timer_next_expiry(heap, now + 50);
    assert(next == 50);

    expired = rbox_timer_get_expired(heap);
    assert(expired != NULL);
    assert(expired->fd == fd1);
    free(expired);

    next = rbox_timer_next_expiry(heap, now + 100);
    assert(next == 50);

    expired = rbox_timer_get_expired(heap);
    assert(expired != NULL);
    assert(expired->fd == fd3);
    free(expired);

    assert(rbox_timer_count(heap) == 0);
    assert(rbox_timer_next_expiry(heap, now) == UINT64_MAX);

    rbox_timer_heap_free(heap);
    printf("  ✓ Basic operations work correctly\n");
    printf("test_timer_heap_basic: PASSED\n\n");
    return 0;
}

static int test_timer_heap_remove(void) {
    printf("Testing timer heap remove...\n");

    rbox_timer_heap_t *heap = rbox_timer_heap_new();
    uint64_t now = 1000;

    int fd1 = 5;
    int fd2 = 10;
    int fd3 = 15;

    assert(rbox_timer_add(heap, fd1, now + 100, RBOX_TIMEOUT_IDLE, NULL) == 0);
    assert(rbox_timer_add(heap, fd2, now + 50, RBOX_TIMEOUT_HEADER, NULL) == 0);
    assert(rbox_timer_add(heap, fd3, now + 150, RBOX_TIMEOUT_BODY, NULL) == 0);
    assert(rbox_timer_count(heap) == 3);

    assert(rbox_timer_remove(heap, fd2) == 0);
    assert(rbox_timer_count(heap) == 2);
    assert(rbox_timer_next_expiry(heap, now) == 100);

    rbox_timer_entry_t *expired = rbox_timer_get_expired(heap);
    assert(expired->fd == fd1);
    free(expired);

    assert(rbox_timer_remove(heap, fd1) == -1);
    assert(rbox_timer_remove(heap, 999) == -1);

    expired = rbox_timer_get_expired(heap);
    assert(expired->fd == fd3);
    free(expired);

    rbox_timer_heap_free(heap);
    printf("  ✓ Remove operations work correctly\n");
    printf("test_timer_heap_remove: PASSED\n\n");
    return 0;
}

static int test_timer_heap_replace(void) {
    printf("Testing timer heap replace (same fd)...\n");

    rbox_timer_heap_t *heap = rbox_timer_heap_new();
    uint64_t now = 1000;

    int fd = 5;
    assert(rbox_timer_add(heap, fd, now + 100, RBOX_TIMEOUT_IDLE, NULL) == 0);
    assert(rbox_timer_count(heap) == 1);

    assert(rbox_timer_add(heap, fd, now + 200, RBOX_TIMEOUT_HEADER, NULL) == 0);
    assert(rbox_timer_count(heap) == 1);

    uint64_t next = rbox_timer_next_expiry(heap, now);
    assert(next == 200);

    rbox_timer_entry_t *expired = rbox_timer_get_expired(heap);
    assert(expired->fd == fd);
    assert(expired->type == RBOX_TIMEOUT_HEADER);
    free(expired);

    assert(rbox_timer_count(heap) == 0);

    rbox_timer_heap_free(heap);
    printf("  ✓ Replace operations work correctly\n");
    printf("test_timer_heap_replace: PASSED\n\n");
    return 0;
}

static int test_timer_heap_order(void) {
    printf("Testing timer heap ordering...\n");

    rbox_timer_heap_t *heap = rbox_timer_heap_new();
    uint64_t now = 1000;

    int fds[] = {5, 10, 15, 20, 25};
    uint64_t timeouts[] = {now + 300, now + 100, now + 200, now + 50, now + 150};
    int expected_order[] = {20, 10, 25, 15, 5};

    for (int i = 0; i < 5; i++) {
        assert(rbox_timer_add(heap, fds[i], timeouts[i], RBOX_TIMEOUT_IDLE, NULL) == 0);
    }

    for (int i = 0; i < 5; i++) {
        rbox_timer_entry_t *expired = rbox_timer_get_expired(heap);
        assert(expired != NULL);
        assert(expired->fd == expected_order[i]);
        free(expired);
    }

    assert(rbox_timer_count(heap) == 0);

    rbox_timer_heap_free(heap);
    printf("  ✓ Ordering is correct (earliest expires first)\n");
    printf("test_timer_heap_order: PASSED\n\n");
    return 0;
}

static int test_timer_heap_expired_at_now(void) {
    printf("Testing timer heap with timers already expired...\n");

    rbox_timer_heap_t *heap = rbox_timer_heap_new();
    uint64_t now = 1000;

    int fd1 = 5;
    int fd2 = 10;

    assert(rbox_timer_add(heap, fd1, now - 10, RBOX_TIMEOUT_IDLE, NULL) == 0);
    assert(rbox_timer_add(heap, fd2, now + 100, RBOX_TIMEOUT_HEADER, NULL) == 0);

    assert(rbox_timer_next_expiry(heap, now) == 0);

    rbox_timer_entry_t *expired = rbox_timer_get_expired(heap);
    assert(expired != NULL);
    assert(expired->fd == fd1);
    free(expired);

    assert(rbox_timer_next_expiry(heap, now) == 100);

    expired = rbox_timer_get_expired(heap);
    assert(expired != NULL);
    assert(expired->fd == fd2);
    free(expired);

    rbox_timer_heap_free(heap);
    printf("  ✓ Expired timers handled correctly\n");
    printf("test_timer_heap_expired_at_now: PASSED\n\n");
    return 0;
}

static int test_timer_heap_many_timers(void) {
    printf("Testing timer heap with many timers...\n");

    rbox_timer_heap_t *heap = rbox_timer_heap_new();
    uint64_t now = 1000;
    int n = 1000;

    for (int i = 0; i < n; i++) {
        int fd = i + 100;
        uint64_t timeout = now + (i % 100) * 10 + 50;
        assert(rbox_timer_add(heap, fd, timeout, RBOX_TIMEOUT_IDLE, NULL) == 0);
    }
    assert(rbox_timer_count(heap) == (size_t)n);

    for (int i = 0; i < n; i++) {
        rbox_timer_entry_t *expired = rbox_timer_get_expired(heap);
        assert(expired != NULL);
        free(expired);
    }
    assert(rbox_timer_count(heap) == 0);

    rbox_timer_heap_free(heap);
    printf("  ✓ Many timers handled correctly\n");
    printf("test_timer_heap_many_timers: PASSED\n\n");
    return 0;
}

static void timer_callback(int fd, rbox_timeout_type_t type) {
    (void)fd;
    (void)type;
}

static int test_timer_heap_process_expired_callback(void) {
    printf("Testing timer heap process_expired with callback...\n");

    rbox_timer_heap_t *heap = rbox_timer_heap_new();
    uint64_t now = 1000;

    int fd1 = 5;
    int fd2 = 10;
    int fd3 = 15;

    assert(rbox_timer_add(heap, fd1, now - 10, RBOX_TIMEOUT_IDLE, NULL) == 0);
    assert(rbox_timer_add(heap, fd2, now - 5, RBOX_TIMEOUT_HEADER, NULL) == 0);
    assert(rbox_timer_add(heap, fd3, now + 100, RBOX_TIMEOUT_BODY, NULL) == 0);
    assert(rbox_timer_count(heap) == 3);

    int callback_count = 0;
    while (rbox_timer_next_expiry(heap, now) == 0) {
        rbox_timer_entry_t *timer = rbox_timer_get_expired(heap);
        if (!timer) break;
        timer_callback(timer->fd, timer->type);
        callback_count++;
        free(timer);
    }

    assert(callback_count == 2);
    assert(rbox_timer_count(heap) == 1);

    rbox_timer_heap_free(heap);
    printf("  ✓ Callback processing works correctly\n");
    printf("test_timer_heap_process_expired_callback: PASSED\n\n");
    return 0;
}

int main(void) {
    printf("=== Timer Heap Unit Tests ===\n\n");

    test_timer_heap_basic();
    test_timer_heap_remove();
    test_timer_heap_replace();
    test_timer_heap_order();
    test_timer_heap_expired_at_now();
    test_timer_heap_many_timers();
    test_timer_heap_process_expired_callback();

    printf("=== All Timer Heap Tests PASSED ===\n");
    return 0;
}
