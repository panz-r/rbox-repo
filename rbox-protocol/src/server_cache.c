/*
 * server_cache.c - Response caching for rbox-protocol server
 *
 * Layer 8: Response caching with O(1) hash table lookup and LRU eviction
 *
 * Key design:
 * - Two key types: one-shot (duration==0) and timed (duration>0)
 * - One-shot: key is (client_id, request_id, packet_checksum), probe uses full hash
 * - Timed: key is (cmd_hash, cmd_hash2, fenv_hash), probe uses command-only hash
 * - Entry's key_hash is computed appropriately based on duration
 * - Linear probing with tombstones and LRU eviction
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include "rbox_protocol.h"
#include "server_internal.h"
#include "server_cache.h"

static void cache_rebuild(rbox_server_handle_t *server);

void rbox_server_cache_init(rbox_server_handle_t *server) {
    if (!server) return;
    memset(&server->cache, 0, sizeof(server->cache));
}

void rbox_server_cache_destroy(rbox_server_handle_t *server) {
    if (!server) return;
    rbox_response_cache_t *cache = &server->cache;
    for (int i = 0; i < RBOX_RESPONSE_CACHE_SIZE; i++) {
        if (cache->slot_state[i] == RBOX_CACHE_SLOT_OCCUPIED && cache->slots[i]) {
            free(cache->slots[i]);
        }
    }
    memset(cache, 0, sizeof(*cache));
}

static void cache_lru_move_to_head(rbox_response_cache_t *cache, rbox_response_cache_entry_t *entry) {
    if (cache->lru_head == entry) return;

    if (entry->lru_prev) entry->lru_prev->lru_next = entry->lru_next;
    if (entry->lru_next) entry->lru_next->lru_prev = entry->lru_prev;
    if (cache->lru_tail == entry) cache->lru_tail = entry->lru_prev;

    entry->lru_prev = NULL;
    entry->lru_next = cache->lru_head;
    if (cache->lru_head) cache->lru_head->lru_prev = entry;
    cache->lru_head = entry;
    if (!cache->lru_tail) cache->lru_tail = entry;
}

static void cache_lru_remove(rbox_response_cache_t *cache, rbox_response_cache_entry_t *entry) {
    if (entry->lru_prev) entry->lru_prev->lru_next = entry->lru_next;
    else cache->lru_head = entry->lru_next;
    if (entry->lru_next) entry->lru_next->lru_prev = entry->lru_prev;
    if (cache->lru_tail == entry) cache->lru_tail = entry->lru_prev;
}

/* Hash for one-shot entries (duration==0) - includes all key fields */
static uint32_t compute_cache_key_hash_full(const uint8_t *client_id,
                                           const uint8_t *request_id,
                                           uint32_t packet_checksum,
                                           uint32_t cmd_hash,
                                           uint64_t cmd_hash2,
                                           uint32_t fenv_hash) {
    uint32_t h = 5381;
    for (int i = 0; i < 16; i++) {
        h = ((h << 5) + h) + client_id[i];
    }
    for (int i = 0; i < 16; i++) {
        h = ((h << 5) + h) + request_id[i];
    }
    h = ((h << 5) + h) + packet_checksum;
    h = ((h << 5) + h) + cmd_hash;
    h = ((h << 5) + h) + (uint32_t)(cmd_hash2 & 0xFFFFFFFF);
    h = ((h << 5) + h) + (uint32_t)((cmd_hash2 >> 32) & 0xFFFFFFFF);
    h = ((h << 5) + h) + fenv_hash;
    h ^= h >> 16;
    h *= 0x85EBCA6B;
    h ^= h >> 13;
    h *= 0xC2B2AE35;
    h ^= h >> 16;
    return h;
}

/* Hash for timed entries (duration>0) - command semantics only, no request identity */
static uint32_t compute_cache_key_hash_timed(uint32_t cmd_hash, uint64_t cmd_hash2, uint32_t fenv_hash) {
    uint32_t h = 5381;
    h = ((h << 5) + h) + cmd_hash;
    h = ((h << 5) + h) + (uint32_t)(cmd_hash2 & 0xFFFFFFFF);
    h = ((h << 5) + h) + (uint32_t)((cmd_hash2 >> 32) & 0xFFFFFFFF);
    h = ((h << 5) + h) + fenv_hash;
    h ^= h >> 16;
    h *= 0x85EBCA6B;
    h ^= h >> 13;
    h *= 0xC2B2AE35;
    h ^= h >> 16;
    return h;
}

static void cache_evict_lru(rbox_server_handle_t *server) {
    rbox_response_cache_t *cache = &server->cache;
    rbox_response_cache_entry_t *old = cache->lru_tail;
    if (!old) return;

    cache_lru_remove(cache, old);

    uint32_t idx = old->key_hash % RBOX_RESPONSE_CACHE_SIZE;
    while (cache->slots[idx] != old) {
        idx = (idx + 1) % RBOX_RESPONSE_CACHE_SIZE;
    }
    cache->slot_state[idx] = RBOX_CACHE_SLOT_TOMBSTONE;
    cache->tombstone_count++;
    cache->slots[idx] = NULL;
    cache->count--;

    free(old);

    if (cache->tombstone_count > RBOX_RESPONSE_CACHE_SIZE / 4) {
        cache_rebuild(server);
    }
}

static void cache_rebuild(rbox_server_handle_t *server) {
    rbox_response_cache_t *cache = &server->cache;

    rbox_response_cache_entry_t *entries[RBOX_RESPONSE_CACHE_SIZE];
    int count = 0;

    rbox_response_cache_entry_t *entry = cache->lru_head;
    while (entry) {
        entries[count++] = entry;
        entry = entry->lru_next;
    }

    for (int i = 0; i < RBOX_RESPONSE_CACHE_SIZE; i++) {
        cache->slots[i] = NULL;
        cache->slot_state[i] = RBOX_CACHE_SLOT_EMPTY;
    }

    for (int i = 0; i < count; i++) {
        entry = entries[i];
        uint32_t index = entry->key_hash % RBOX_RESPONSE_CACHE_SIZE;
        while (cache->slot_state[index] == RBOX_CACHE_SLOT_OCCUPIED) {
            index = (index + 1) % RBOX_RESPONSE_CACHE_SIZE;
        }
        cache->slots[index] = entry;
        cache->slot_state[index] = RBOX_CACHE_SLOT_OCCUPIED;
    }

    cache->tombstone_count = 0;
}

int rbox_server_cache_lookup(rbox_server_handle_t *server,
                            const uint8_t *client_id,
                            const uint8_t *request_id,
                            uint32_t packet_checksum,
                            uint32_t cmd_hash, uint64_t cmd_hash2,
                            uint32_t fenv_hash,
                            uint8_t *decision, char *reason, uint32_t *duration) {
    if (!server) return 0;
    pthread_mutex_lock(&server->cache_mutex);
    rbox_response_cache_t *cache = &server->cache;
    time_t now = time(NULL);

    uint32_t full_hash = compute_cache_key_hash_full(client_id, request_id, packet_checksum,
                                                     cmd_hash, cmd_hash2, fenv_hash);
    uint32_t timed_hash = compute_cache_key_hash_timed(cmd_hash, cmd_hash2, fenv_hash);
    uint32_t index = timed_hash % RBOX_RESPONSE_CACHE_SIZE;
    uint32_t start = index;

    do {
        if (cache->slot_state[index] == RBOX_CACHE_SLOT_EMPTY) {
            pthread_mutex_unlock(&server->cache_mutex);
            return 0;
        }
        if (cache->slot_state[index] == RBOX_CACHE_SLOT_OCCUPIED) {
            rbox_response_cache_entry_t *entry = cache->slots[index];

            if (entry->duration == 0) {
                if (entry->key_hash == full_hash &&
                    memcmp(entry->client_id, client_id, 16) == 0 &&
                    memcmp(entry->request_id, request_id, 16) == 0 &&
                    entry->packet_checksum == packet_checksum) {
                    if (decision) *decision = entry->decision;
                    if (reason) strncpy(reason, entry->reason, 255);
                    if (duration) *duration = entry->duration;
                    cache_lru_move_to_head(cache, entry);
                    pthread_mutex_unlock(&server->cache_mutex);
                    return 1;
                }
            } else {
                if (entry->expires_at > 0 && now > entry->expires_at) {
                    cache_evict_lru(server);
                    pthread_mutex_unlock(&server->cache_mutex);
                    return 0;
                }
                if (entry->key_hash == timed_hash &&
                    entry->cmd_hash == cmd_hash &&
                    entry->cmd_hash2 == cmd_hash2 &&
                    entry->fenv_hash == fenv_hash) {
                    if (decision) *decision = entry->decision;
                    if (reason) strncpy(reason, entry->reason, 255);
                    if (duration) *duration = entry->duration;
                    cache_lru_move_to_head(cache, entry);
                    pthread_mutex_unlock(&server->cache_mutex);
                    return 1;
                }
            }
        }
        index = (index + 1) % RBOX_RESPONSE_CACHE_SIZE;
    } while (index != start);

    pthread_mutex_unlock(&server->cache_mutex);
    return 0;
}

void rbox_server_cache_insert(rbox_server_handle_t *server,
                             const uint8_t *client_id,
                             const uint8_t *request_id,
                             uint32_t packet_checksum,
                             uint32_t cmd_hash, uint64_t cmd_hash2,
                             uint32_t fenv_hash,
                             uint8_t decision, const char *reason, uint32_t duration) {
    if (!server) return;
    pthread_mutex_lock(&server->cache_mutex);
    rbox_response_cache_t *cache = &server->cache;

    if (cache->count == RBOX_RESPONSE_CACHE_SIZE) {
        cache_evict_lru(server);
    }

    rbox_response_cache_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        pthread_mutex_unlock(&server->cache_mutex);
        return;
    }

    memcpy(entry->client_id, client_id, 16);
    memcpy(entry->request_id, request_id, 16);
    entry->packet_checksum = packet_checksum;
    entry->cmd_hash = cmd_hash;
    entry->cmd_hash2 = cmd_hash2;
    entry->fenv_hash = fenv_hash;
    entry->decision = decision;
    if (reason && *reason) {
        snprintf(entry->reason, sizeof(entry->reason), "%.*s", 254, reason);
    } else {
        entry->reason[0] = '\0';
    }
    entry->duration = duration;
    entry->timestamp = time(NULL);
    entry->expires_at = (duration > 0) ? entry->timestamp + duration : 0;

    if (duration > 0) {
        entry->key_hash = compute_cache_key_hash_timed(cmd_hash, cmd_hash2, fenv_hash);
    } else {
        entry->key_hash = compute_cache_key_hash_full(client_id, request_id, packet_checksum,
                                                       cmd_hash, cmd_hash2, fenv_hash);
    }

    uint32_t index = entry->key_hash % RBOX_RESPONSE_CACHE_SIZE;
    while (cache->slot_state[index] == RBOX_CACHE_SLOT_OCCUPIED) {
        index = (index + 1) % RBOX_RESPONSE_CACHE_SIZE;
    }
    cache->slots[index] = entry;
    cache->slot_state[index] = RBOX_CACHE_SLOT_OCCUPIED;
    cache->count++;

    entry->lru_prev = NULL;
    entry->lru_next = cache->lru_head;
    if (cache->lru_head) cache->lru_head->lru_prev = entry;
    cache->lru_head = entry;
    if (!cache->lru_tail) cache->lru_tail = entry;

    pthread_mutex_unlock(&server->cache_mutex);
}