/*
 * server_cache.c - Response caching for rbox-protocol server
 *
 * Layer 8: Response caching with O(1) hash table lookup and LRU eviction
 *
 * Unified hash design:
 * - All entries use the same hash function based on command fields only:
 *   (cmd_hash, cmd_hash2, fenv_hash)
 * - During lookup, we probe from the command hash index
 * - For one-shot entries (duration==0): compare full key (client_id, request_id, packet_checksum)
 * - For timed entries (duration>0): compare command fields and check expiration
 * - This ensures one-shot entries are always found, even if a timed entry with the
 *   same command hash was inserted first
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
            free(cache->slots[i]->env_decisions);
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

/* Unified hash function for all cache entries.
 * Uses only command fields (cmd_hash, cmd_hash2, fenv_hash) which are the
 * common denominator for both one-shot and timed entries. */
static uint32_t compute_cache_key_hash(uint32_t cmd_hash, uint64_t cmd_hash2, uint32_t fenv_hash) {
    uint32_t h = 5381;
    h = ((h << 5) + h) + cmd_hash;
    h = ((h << 5) + h) + (uint32_t)(cmd_hash2 & 0xFFFFFFFF);
    h = ((h << 5) + h) + (uint32_t)((cmd_hash2 >> 32) & 0xFFFFFFFF);
    h = ((h << 5) + h) + fenv_hash;
    /* final avalanche */
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

    free(old->env_decisions);
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
                            uint8_t *decision, char *reason, uint32_t *duration,
                            int *env_decision_count, uint8_t **env_decisions) {
    if (!server) return 0;
    pthread_mutex_lock(&server->cache_mutex);
    rbox_response_cache_t *cache = &server->cache;
    time_t now = time(NULL);

    uint32_t key_hash = compute_cache_key_hash(cmd_hash, cmd_hash2, fenv_hash);
    uint32_t index = key_hash % RBOX_RESPONSE_CACHE_SIZE;
    uint32_t start = index;

    do {
        if (cache->slot_state[index] == RBOX_CACHE_SLOT_EMPTY) {
            pthread_mutex_unlock(&server->cache_mutex);
            return 0;
        }
        if (cache->slot_state[index] == RBOX_CACHE_SLOT_OCCUPIED) {
            rbox_response_cache_entry_t *entry = cache->slots[index];

            if (entry->duration == 0) {
                if (entry->key_hash == key_hash &&
                    memcmp(entry->client_id, client_id, 16) == 0 &&
                    memcmp(entry->request_id, request_id, 16) == 0 &&
                    entry->packet_checksum == packet_checksum) {
                    if (decision) *decision = entry->decision;
                    if (reason) snprintf(reason, 256, "%s", entry->reason);
                    if (duration) *duration = entry->duration;
                    if (env_decision_count) *env_decision_count = entry->env_decision_count;
                    if (env_decisions && entry->env_decisions) {
                        size_t bitmap_size = (entry->env_decision_count + 7) / 8;
                        *env_decisions = malloc(bitmap_size);
                        if (*env_decisions) memcpy(*env_decisions, entry->env_decisions, bitmap_size);
                    }
                    cache_lru_move_to_head(cache, entry);
                    pthread_mutex_unlock(&server->cache_mutex);
                    return 1;
                }
            } else {
                if (entry->expires_at > 0 && now > entry->expires_at) {
                    cache_lru_remove(cache, entry);
                    cache->slot_state[index] = RBOX_CACHE_SLOT_TOMBSTONE;
                    cache->tombstone_count++;
                    free(entry->env_decisions);
                    free(entry);
                    cache->slots[index] = NULL;
                    cache->count--;
                    if (cache->tombstone_count > RBOX_RESPONSE_CACHE_SIZE / 4) {
                        cache_rebuild(server);
                    }
                    index = (index + 1) % RBOX_RESPONSE_CACHE_SIZE;
                    if (index == start) {
                        pthread_mutex_unlock(&server->cache_mutex);
                        return 0;
                    }
                    continue;
                }
                if (entry->key_hash == key_hash &&
                    entry->cmd_hash == cmd_hash &&
                    entry->cmd_hash2 == cmd_hash2 &&
                    entry->fenv_hash == fenv_hash) {
                    if (decision) *decision = entry->decision;
                    if (reason) snprintf(reason, 256, "%s", entry->reason);
                    if (duration) *duration = entry->duration;
                    if (env_decision_count) *env_decision_count = entry->env_decision_count;
                    if (env_decisions && entry->env_decisions) {
                        size_t bitmap_size = (entry->env_decision_count + 7) / 8;
                        *env_decisions = malloc(bitmap_size);
                        if (*env_decisions) memcpy(*env_decisions, entry->env_decisions, bitmap_size);
                    }
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
                             uint8_t decision, const char *reason, uint32_t duration,
                             int env_decision_count, uint8_t *env_decisions) {
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

    if (env_decision_count > 0 && env_decisions) {
        entry->env_decision_count = env_decision_count;
        size_t bitmap_size = (env_decision_count + 7) / 8;
        entry->env_decisions = malloc(bitmap_size);
        if (entry->env_decisions) {
            memcpy(entry->env_decisions, env_decisions, bitmap_size);
        } else {
            entry->env_decision_count = 0;
        }
    }

    /* Unified hash for all entries - command fields only */
    entry->key_hash = compute_cache_key_hash(cmd_hash, cmd_hash2, fenv_hash);

    uint32_t index = entry->key_hash % RBOX_RESPONSE_CACHE_SIZE;
    uint32_t start = index;
    do {
        if (cache->slot_state[index] == RBOX_CACHE_SLOT_OCCUPIED) {
            rbox_response_cache_entry_t *existing = cache->slots[index];
            if (existing->key_hash == entry->key_hash &&
                existing->cmd_hash == entry->cmd_hash &&
                existing->cmd_hash2 == entry->cmd_hash2 &&
                existing->fenv_hash == entry->fenv_hash &&
                /* Don't replace if both are one-shot but IDs differ (collision) */
                !(existing->expires_at == 0 && entry->expires_at == 0 &&
                  (memcmp(existing->client_id, entry->client_id, 16) != 0 ||
                   memcmp(existing->request_id, entry->request_id, 16) != 0 ||
                   existing->packet_checksum != entry->packet_checksum))) {
                /* Timed entry (expires_at > 0) is stronger than one-shot (expires_at == 0).
                 * A one-shot request with the same command AND identical env decisions
                 * does not replace the timed entry - the one-shot is discarded.
                 * This ensures timed entries persist for their full duration even when
                 * a client requests the same command with one-shot semantics. */
                if (existing->expires_at > 0 && entry->expires_at == 0) {
                    free(entry->env_decisions);
                    free(entry);
                    pthread_mutex_unlock(&server->cache_mutex);
                    return;
                }
                existing->decision = entry->decision;
                snprintf(existing->reason, sizeof(existing->reason), "%.*s", 254, entry->reason);
                existing->duration = entry->duration;
                existing->timestamp = entry->timestamp;
                existing->expires_at = entry->expires_at;
                existing->packet_checksum = entry->packet_checksum;
                memcpy(existing->client_id, entry->client_id, 16);
                memcpy(existing->request_id, entry->request_id, 16);
                free(existing->env_decisions);
                existing->env_decision_count = entry->env_decision_count;
                if (entry->env_decision_count > 0 && entry->env_decisions) {
                    size_t bitmap_size = (entry->env_decision_count + 7) / 8;
                    existing->env_decisions = malloc(bitmap_size);
                    if (existing->env_decisions) {
                        memcpy(existing->env_decisions, entry->env_decisions, bitmap_size);
                    } else {
                        existing->env_decision_count = 0;
                        existing->env_decisions = NULL;
                    }
                } else {
                    existing->env_decisions = NULL;
                    existing->env_decision_count = 0;
                }
                cache_lru_remove(cache, existing);
                cache_lru_move_to_head(cache, existing);
                free(entry);
                pthread_mutex_unlock(&server->cache_mutex);
                return;
            }
        } else if (cache->slot_state[index] == RBOX_CACHE_SLOT_EMPTY || 
                   cache->slot_state[index] == RBOX_CACHE_SLOT_TOMBSTONE) {
            break;
        }
        index = (index + 1) % RBOX_RESPONSE_CACHE_SIZE;
    } while (index != start);

    if (cache->count == RBOX_RESPONSE_CACHE_SIZE) {
        cache_evict_lru(server);
        index = entry->key_hash % RBOX_RESPONSE_CACHE_SIZE;
        while (cache->slot_state[index] == RBOX_CACHE_SLOT_OCCUPIED) {
            index = (index + 1) % RBOX_RESPONSE_CACHE_SIZE;
        }
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