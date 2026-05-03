/*
 * rbox_cache.h - Response cache with LRU eviction via ht_cache_t
 *
 * Cache key design:
 *   - Hash computed from (cmd_hash, cmd_hash2, fenv_hash).
 *   - For one-shot entries, full equality also requires matching client_id,
 *     request_id, and packet_checksum.
 *   - For timed entries, any request with matching command fields hits the entry.
 *
 * Two-phase lookup:
 *   1. Find exact one-shot match (client_id + request_id + checksum).
 *   2. If none, fall back to first non-expired timed entry with same hash.
 *
 * Insertion policy:
 *   - One-shot (duration==0) inserted ONLY if no non-expired timed entry
 *     with the same command exists. If a timed entry exists, one-shot is skipped.
 *   - Timed entries always inserted; replaces existing timed entry if present.
 *   - Exact full-key matches trigger replacement (update decision, reason, env).
 *
 * Env bitmap is stored inline (512 bytes, supports up to 4096 env vars).
 * Lookup returns a malloc'd copy that the caller must free.
 */

#ifndef RBOX_CACHE_H
#define RBOX_CACHE_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>

typedef struct rbox_cache rbox_cache_t;

#define RBOX_RESPONSE_CACHE_SIZE 256
#define RBOX_ENV_BITMAP_SIZE 512  /* 4096 env vars / 8 bits per byte */

typedef struct {
    uint32_t cmd_hash;                 /* offset 0 — hash key field */
    uint64_t cmd_hash2;                /* offset 8 */
    uint32_t fenv_hash;                /* offset 16 */
    uint8_t  client_id[16];            /* offset 20 */
    uint8_t  request_id[16];           /* offset 36 */
    uint32_t packet_checksum;          /* offset 52 */
    uint8_t  decision;                 /* offset 56 */
    char     reason[256];              /* offset 57 */
    uint32_t duration;                 /* offset 313 */
    time_t   timestamp;                /* offset 320 */
    time_t   expires_at;               /* offset 328 */
    int      env_decision_count;       /* offset 336 */
    uint8_t  env_decisions[RBOX_ENV_BITMAP_SIZE]; /* offset 340 */
} rbox_cache_entry_t;

struct rbox_cache {
    void            *ht;
    pthread_mutex_t  mutex;
};

rbox_cache_t *rbox_cache_new(size_t capacity);
void rbox_cache_free(rbox_cache_t *cache);
void rbox_cache_init(rbox_cache_t *cache, size_t capacity);
void rbox_cache_destroy(rbox_cache_t *cache);

int rbox_cache_lookup(rbox_cache_t *cache,
                      const uint8_t *client_id,
                      const uint8_t *request_id,
                      uint32_t packet_checksum,
                      uint32_t cmd_hash, uint64_t cmd_hash2,
                      uint32_t fenv_hash,
                      uint8_t *out_decision, char *out_reason, uint32_t *out_duration,
                      int *out_env_count, uint8_t **out_env_decisions);

void rbox_cache_insert(rbox_cache_t *cache,
                       const uint8_t *client_id,
                       const uint8_t *request_id,
                       uint32_t packet_checksum,
                       uint32_t cmd_hash, uint64_t cmd_hash2,
                       uint32_t fenv_hash,
                       uint8_t decision, const char *reason, uint32_t duration,
                       int env_count, const uint8_t *env_decisions);

#ifdef TESTING
#include "draugr/ht_cache.h"

static inline size_t rbox_cache_count(rbox_cache_t *cache) {
    return ht_cache_size((ht_cache_t *)cache->ht);
}

static inline uint64_t rbox_cache_compute_hash(uint32_t cmd_hash, uint64_t cmd_hash2, uint32_t fenv_hash) {
    uint32_t h = 2166136261u;
    h = (h * 16777619) ^ cmd_hash;
    h = (h * 16777619) ^ (uint32_t)(cmd_hash2);
    h = (h * 16777619) ^ (uint32_t)(cmd_hash2 >> 32);
    h = (h * 16777619) ^ fenv_hash;
    return (uint64_t)h;
}
#endif

#endif
