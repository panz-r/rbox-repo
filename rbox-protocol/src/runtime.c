/*
 * runtime.c - Library runtime initialization for rbox-protocol
 *
 * Uses constructor attribute to initialize library before main()
 * Uses destructor attribute to clean up after exit()
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

#include "runtime.h"
#include "rbox_protocol_defs.h"

/* CRC32 table - used by protocol.c */
static uint32_t crc32_table[256];
static int crc32_initialized = 0;

/* Thread-local random seed */
static __thread uint32_t g_rand_seed = 0;

static int runtime_initialized = 0;

static void init_crc32_table(void) {
    if (crc32_initialized) return;
    for (int i = 0; i < 256; i++) {
        uint32_t crc = (uint32_t)i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        crc32_table[i] = crc;
    }
    crc32_initialized = 1;
}

static void runtime_init_internal(void) {
    /* Initialize CRC32 table */
    init_crc32_table();
    
    /* Seed random number generator for ID generation */
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
    
    runtime_initialized = 1;
}

static void runtime_shutdown_internal(void) {
    /* Nothing to clean up currently, but this pattern allows future cleanup */
    runtime_initialized = 0;
}

void rbox_runtime_init(void) {
    runtime_init_internal();
}

/* Backward compatibility wrapper - initialization now handled by constructor */
void rbox_init(void) {
    /* No-op: initialization is now automatic via __attribute__((constructor))
     * This function exists for backward compatibility with existing code */
}

void rbox_runtime_shutdown(void) {
    runtime_shutdown_internal();
}

uint32_t rbox_runtime_rand_seed(void) {
    if (g_rand_seed == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uintptr_t tid = (uintptr_t)pthread_self();
        g_rand_seed = (uint32_t)((uint64_t)ts.tv_sec ^ ((uint64_t)ts.tv_nsec << 32) ^ tid);
    }
    return g_rand_seed;
}

/* CRC32 checksum - composable, takes previous CRC value
 * If prev_crc is 0, starts fresh (initial CRC = 0xFFFFFFFF).
 * Otherwise continues from prev_crc (expects pre-xored value). */
uint32_t rbox_runtime_crc32(uint32_t prev_crc, const void *data, size_t len) {
    init_crc32_table();
    uint32_t crc = prev_crc == 0 ? 0xFFFFFFFF : prev_crc;
    const uint8_t *bytes = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ bytes[i]) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

/* Calculate retry delay with exponential backoff + jitter
 * base_delay_ms: base delay in ms
 * attempt: current attempt number (1-based)
 * max_delay_ms: maximum delay cap in ms (use RBOX_MAX_RETRY_DELAY_MS for standard cap)
 * seed: pointer to thread-local random seed (may be updated)
 * Returns delay in milliseconds */
uint32_t rbox_calculate_retry_delay(uint32_t base_delay_ms, uint32_t attempt, uint32_t max_delay_ms, uint32_t *seed) {
    if (base_delay_ms == 0 || attempt == 0) return 0;
    if (max_delay_ms == 0) max_delay_ms = RBOX_MAX_RETRY_DELAY_MS;

    /* Calculate max_delay with overflow check: max_delay = min(base * 64, max_delay_ms) */
    uint64_t max_delay_64;
    if (__builtin_mul_overflow(base_delay_ms, (uint32_t)64, &max_delay_64)) {
        max_delay_64 = max_delay_ms;
    } else if (max_delay_64 > max_delay_ms) {
        max_delay_64 = max_delay_ms;
    }
    uint32_t max_delay = (uint32_t)max_delay_64;

    /* Exponential backoff: exp = base * 2^(attempt-1), capped at max_delay/2 */
    uint64_t exp = base_delay_ms;
    for (uint32_t i = 1; i < attempt && exp < max_delay / 2; i++) {
        exp *= 2;
    }
    if (exp > max_delay) exp = max_delay;

    /* Jitter: 0..(base + 50ms) using pure integer arithmetic
     * Adding 50ms ensures meaningful jitter even when base is tiny */
    uint32_t jitter_range = base_delay_ms + 50;
    uint32_t jitter = rand_r(seed) % jitter_range;

    /* Delay = exp + jitter, capped at max_delay */
    uint64_t delay = exp + jitter;
    if (delay > max_delay) delay = max_delay;

    return (uint32_t)delay;
}

/* Automatic initialization before main() */
__attribute__((constructor))
static void constructor_rbox_runtime(void) {
    runtime_init_internal();
}

/* Automatic cleanup after exit() */
__attribute__((destructor))
static void destructor_rbox_runtime(void) {
    runtime_shutdown_internal();
}
