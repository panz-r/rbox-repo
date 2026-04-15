/*
 * rbox_cache.h - Response cache with Robin Hood hashing
 *
 * Cache key design:
 *   - Hash key is computed from (cmd_hash, cmd_hash2, fenv_hash) only.
 *   - For one-shot entries, full equality also requires matching client_id,
 *     request_id, and packet_checksum.
 *   - For timed entries, any request with matching command fields hits the entry.
 *
 * Two-phase lookup:
 *   1. Find first slot with matching hash key.
 *   2. Scan forward while hash key matches, looking for exact one-shot match;
 *      if none found, return the first non-expired timed entry.
 *
 * Insertion policy:
 *   - One-shot (duration==0) inserted ONLY if no non-expired timed entry
 *     with the same command exists. If a timed entry exists, one-shot is skipped.
 *   - Timed entries always inserted; replaces existing timed entry if present.
 *   - Exact full-key matches trigger replacement (update decision, reason, env).
 *
 * Uses Robin Hood hashing with linear probing for balance.
 */

#ifndef RBOX_CACHE_H
#define RBOX_CACHE_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>

typedef struct rbox_cache rbox_cache_t;

#define RBOX_CACHE_STATE_EMPTY      0
#define RBOX_CACHE_STATE_OCCUPIED  1
#define RBOX_CACHE_STATE_TOMBSTONE  2

#define RBOX_RESPONSE_CACHE_SIZE 256

typedef struct rbox_cache_entry {
    uint8_t client_id[16];
    uint8_t request_id[16];
    uint32_t packet_checksum;
    uint32_t cmd_hash;
    uint64_t cmd_hash2;
    uint32_t fenv_hash;
    uint32_t key_hash;

    uint8_t decision;
    char reason[256];
    uint32_t duration;
    time_t timestamp;
    time_t expires_at;
    int env_decision_count;
    uint8_t *env_decisions;

    int probe_distance;

    struct rbox_cache_entry *lru_prev;
    struct rbox_cache_entry *lru_next;
} rbox_cache_entry_t;

struct rbox_cache {
    rbox_cache_entry_t **slots;
    uint8_t *slot_state;
    size_t capacity;
    size_t count;
    size_t tombstone_count;
    rbox_cache_entry_t *lru_head;
    rbox_cache_entry_t *lru_tail;
    pthread_mutex_t mutex;
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
typedef struct rbox_cache_internal {
    rbox_cache_entry_t **slots;
    uint8_t *slot_state;
    size_t capacity;
    size_t count;
    size_t tombstone_count;
    rbox_cache_entry_t *lru_head;
    rbox_cache_entry_t *lru_tail;
} rbox_cache_internal_t;

static inline rbox_cache_internal_t rbox_cache_get_internal(rbox_cache_t *cache) {
    rbox_cache_internal_t i = {
        .slots = cache->slots,
        .slot_state = cache->slot_state,
        .capacity = cache->capacity,
        .count = cache->count,
        .tombstone_count = cache->tombstone_count,
        .lru_head = cache->lru_head,
        .lru_tail = cache->lru_tail
    };
    return i;
}

static inline int rbox_cache_get_slot_state(rbox_cache_t *cache, size_t idx) {
    if (idx >= cache->capacity) return -1;
    return cache->slot_state[idx];
}

static inline rbox_cache_entry_t *rbox_cache_get_slot_entry(rbox_cache_t *cache, size_t idx) {
    if (idx >= cache->capacity) return NULL;
    return cache->slots[idx];
}

static inline uint32_t rbox_cache_compute_hash(uint32_t cmd_hash, uint64_t cmd_hash2, uint32_t fenv_hash) {
    uint32_t h = 2166136261u;
    h = (h * 16777619) ^ cmd_hash;
    h = (h * 16777619) ^ (uint32_t)(cmd_hash2);
    h = (h * 16777619) ^ (uint32_t)(cmd_hash2 >> 32);
    h = (h * 16777619) ^ fenv_hash;
    return h;
}
#endif

#endif
