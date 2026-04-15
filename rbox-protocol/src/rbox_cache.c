/*
 * rbox_cache.c - Response cache with Robin Hood hashing
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include "rbox_cache.h"

#define RBOX_CACHE_STATE_EMPTY     0
#define RBOX_CACHE_STATE_OCCUPIED  1
#define RBOX_CACHE_STATE_TOMBSTONE 2

static uint32_t cache_hash_key(uint32_t cmd_hash, uint64_t cmd_hash2, uint32_t fenv_hash) {
    uint32_t h = 2166136261u;
    h = (h * 16777619) ^ cmd_hash;
    h = (h * 16777619) ^ (uint32_t)(cmd_hash2);
    h = (h * 16777619) ^ (uint32_t)(cmd_hash2 >> 32);
    h = (h * 16777619) ^ fenv_hash;
    return h;
}

static int keys_equal(const rbox_cache_entry_t *e,
                      const uint8_t *client_id,
                      const uint8_t *request_id,
                      uint32_t packet_checksum,
                      uint32_t cmd_hash, uint64_t cmd_hash2,
                      uint32_t fenv_hash,
                      uint32_t new_duration) {
    if (e->cmd_hash != cmd_hash) return 0;
    if (e->cmd_hash2 != cmd_hash2) return 0;
    if (e->fenv_hash != fenv_hash) return 0;

    if (e->duration == 0 && new_duration == 0) {
        return (memcmp(e->client_id, client_id, 16) == 0 &&
                memcmp(e->request_id, request_id, 16) == 0 &&
                e->packet_checksum == packet_checksum);
    } else if (e->duration > 0 && new_duration > 0) {
        return 1;
    }
    return 0;
}

static void lru_remove(rbox_cache_t *cache, rbox_cache_entry_t *e) {
    if (e->lru_prev) e->lru_prev->lru_next = e->lru_next;
    else cache->lru_head = e->lru_next;
    if (e->lru_next) e->lru_next->lru_prev = e->lru_prev;
    else cache->lru_tail = e->lru_prev;
}

static void lru_move_to_head(rbox_cache_t *cache, rbox_cache_entry_t *e) {
    if (cache->lru_head == e) return;
    lru_remove(cache, e);
    e->lru_prev = NULL;
    e->lru_next = cache->lru_head;
    if (cache->lru_head) cache->lru_head->lru_prev = e;
    cache->lru_head = e;
    if (!cache->lru_tail) cache->lru_tail = e;
}

static void lru_add_head(rbox_cache_t *cache, rbox_cache_entry_t *e) {
    e->lru_prev = NULL;
    e->lru_next = cache->lru_head;
    if (cache->lru_head) cache->lru_head->lru_prev = e;
    cache->lru_head = e;
    if (!cache->lru_tail) cache->lru_tail = e;
}

static void cache_evict_lru(rbox_cache_t *cache);

static int robin_hood_insert(rbox_cache_t *cache, rbox_cache_entry_t *e);

static void cache_rebuild(rbox_cache_t *cache) {
    rbox_cache_entry_t *entries[256];
    int cnt = 0;
    for (rbox_cache_entry_t *e = cache->lru_head; e; e = e->lru_next) {
        entries[cnt++] = e;
    }
    memset(cache->slot_state, 0, cache->capacity);
    memset(cache->slots, 0, cache->capacity * sizeof(rbox_cache_entry_t*));
    cache->tombstone_count = 0;
    for (int i = 0; i < cnt; i++) {
        robin_hood_insert(cache, entries[i]);
    }
}

static void cache_evict_lru(rbox_cache_t *cache) {
    rbox_cache_entry_t *old = cache->lru_tail;
    if (!old) return;

    lru_remove(cache, old);

    uint32_t idx = old->key_hash % cache->capacity;
    while (cache->slots[idx] != old) {
        idx = (idx + 1) % cache->capacity;
    }
    cache->slot_state[idx] = 2;
    cache->tombstone_count++;
    cache->slots[idx] = NULL;
    cache->count--;

    free(old->env_decisions);
    free(old);

    if (cache->tombstone_count > cache->capacity / 4) {
        cache_rebuild(cache);
    }
}

static int robin_hood_insert(rbox_cache_t *cache, rbox_cache_entry_t *e) {
    uint32_t idx = e->key_hash % cache->capacity;
    int dist = 0;
    while (1) {
        if (cache->slot_state[idx] == 0 || cache->slot_state[idx] == 2) {
            cache->slots[idx] = e;
            cache->slot_state[idx] = 1;
            e->probe_distance = dist;
            return 1;
        }
        rbox_cache_entry_t *existing = cache->slots[idx];
        if (dist > existing->probe_distance) {
            cache->slots[idx] = e;
            e->probe_distance = dist;
            e = existing;
            dist = existing->probe_distance + 1;
            idx = (idx + 1) % cache->capacity;
            continue;
        }
        idx = (idx + 1) % cache->capacity;
        dist++;
    }
}

rbox_cache_t *rbox_cache_new(size_t capacity) {
    rbox_cache_t *cache = calloc(1, sizeof(*cache));
    if (!cache) return NULL;
    rbox_cache_init(cache, capacity);
    return cache;
}

void rbox_cache_free(rbox_cache_t *cache) {
    if (!cache) return;
    rbox_cache_destroy(cache);
    free(cache);
}

void rbox_cache_init(rbox_cache_t *cache, size_t capacity) {
    memset(cache, 0, sizeof(*cache));
    cache->capacity = capacity;
    cache->slots = calloc(capacity, sizeof(rbox_cache_entry_t*));
    cache->slot_state = calloc(capacity, sizeof(uint8_t));
    pthread_mutex_init(&cache->mutex, NULL);
}

void rbox_cache_destroy(rbox_cache_t *cache) {
    if (!cache) return;
    pthread_mutex_lock(&cache->mutex);
    for (size_t i = 0; i < cache->capacity; i++) {
        if (cache->slot_state[i] == 1) {
            free(cache->slots[i]->env_decisions);
            free(cache->slots[i]);
        }
    }
    free(cache->slots);
    free(cache->slot_state);
    pthread_mutex_unlock(&cache->mutex);
    pthread_mutex_destroy(&cache->mutex);
}

int rbox_cache_lookup(rbox_cache_t *cache,
                      const uint8_t *client_id,
                      const uint8_t *request_id,
                      uint32_t packet_checksum,
                      uint32_t cmd_hash, uint64_t cmd_hash2,
                      uint32_t fenv_hash,
                      uint8_t *out_decision, char *out_reason, uint32_t *out_duration,
                      int *out_env_count, uint8_t **out_env_decisions) {
    pthread_mutex_lock(&cache->mutex);

    if (cache->capacity == 0) {
        pthread_mutex_unlock(&cache->mutex);
        return 0;
    }

    uint32_t target_hash = cache_hash_key(cmd_hash, cmd_hash2, fenv_hash);
    uint32_t idx = target_hash % cache->capacity;
    uint32_t start = idx;
    time_t now = time(NULL);
    rbox_cache_entry_t *best_timed = NULL;

    do {
        if (cache->slot_state[idx] == 0) {
            pthread_mutex_unlock(&cache->mutex);
            return 0;
        }
        if (cache->slot_state[idx] == 2) {
            idx = (idx + 1) % cache->capacity;
            continue;
        }
        rbox_cache_entry_t *e = cache->slots[idx];
        if (e->key_hash == target_hash) break;
        idx = (idx + 1) % cache->capacity;
    } while (idx != start);

    if (cache->slot_state[idx] == 0) {
        pthread_mutex_unlock(&cache->mutex);
        return 0;
    }

    uint32_t scan_idx = idx;
    do {
        if (cache->slot_state[scan_idx] == 0) break;
        if (cache->slot_state[scan_idx] == 2) {
            scan_idx = (scan_idx + 1) % cache->capacity;
            continue;
        }
        rbox_cache_entry_t *e = cache->slots[scan_idx];
        if (e->key_hash != target_hash) break;

        if (e->duration == 0 &&
            keys_equal(e, client_id, request_id, packet_checksum,
                       cmd_hash, cmd_hash2, fenv_hash, 0)) {
            lru_move_to_head(cache, e);
            if (out_decision) *out_decision = e->decision;
            if (out_reason) snprintf(out_reason, 256, "%s", e->reason);
            if (out_duration) *out_duration = e->duration;
            if (out_env_count) *out_env_count = e->env_decision_count;
            if (out_env_decisions && e->env_decision_count > 0) {
                size_t bm_size = (e->env_decision_count + 7) / 8;
                *out_env_decisions = malloc(bm_size);
                if (*out_env_decisions) {
                    memcpy(*out_env_decisions, e->env_decisions, bm_size);
                } else {
                    *out_env_count = 0;
                }
            } else if (out_env_decisions) {
                *out_env_decisions = NULL;
            }
            pthread_mutex_unlock(&cache->mutex);
            return 1;
        }

        if (e->duration > 0 && (e->expires_at == 0 || now <= e->expires_at)) {
            if (!best_timed) best_timed = e;
        }
        scan_idx = (scan_idx + 1) % cache->capacity;
    } while (scan_idx != idx);

    if (best_timed) {
        lru_move_to_head(cache, best_timed);
        if (out_decision) *out_decision = best_timed->decision;
        if (out_reason) snprintf(out_reason, 256, "%s", best_timed->reason);
        if (out_duration) *out_duration = best_timed->duration;
        if (out_env_count) *out_env_count = best_timed->env_decision_count;
        if (out_env_decisions && best_timed->env_decision_count > 0) {
            size_t bm_size = (best_timed->env_decision_count + 7) / 8;
            *out_env_decisions = malloc(bm_size);
            if (*out_env_decisions) {
                memcpy(*out_env_decisions, best_timed->env_decisions, bm_size);
            } else {
                *out_env_count = 0;
            }
        } else if (out_env_decisions) {
            *out_env_decisions = NULL;
        }
        pthread_mutex_unlock(&cache->mutex);
        return 1;
    }

    pthread_mutex_unlock(&cache->mutex);
    return 0;
}

void rbox_cache_insert(rbox_cache_t *cache,
                       const uint8_t *client_id,
                       const uint8_t *request_id,
                       uint32_t packet_checksum,
                       uint32_t cmd_hash, uint64_t cmd_hash2,
                       uint32_t fenv_hash,
                       uint8_t decision, const char *reason, uint32_t duration,
                       int env_count, const uint8_t *env_decisions) {
    pthread_mutex_lock(&cache->mutex);

    if (cache->capacity == 0) {
        pthread_mutex_unlock(&cache->mutex);
        return;
    }

    uint32_t target_hash = cache_hash_key(cmd_hash, cmd_hash2, fenv_hash);
    time_t now = time(NULL);
    int is_timed = (duration > 0);

    uint32_t idx = target_hash % cache->capacity;
    uint32_t start = idx;
    rbox_cache_entry_t *existing_timed = NULL;
    rbox_cache_entry_t *exact_one_shot = NULL;

    do {
        if (cache->slot_state[idx] == 0) break;
        if (cache->slot_state[idx] == 2) {
            idx = (idx + 1) % cache->capacity;
            continue;
        }
        rbox_cache_entry_t *e = cache->slots[idx];
        if (e->key_hash != target_hash) break;

        if (e->duration > 0 && (e->expires_at == 0 || now <= e->expires_at)) {
            existing_timed = e;
        }
        if (!is_timed && e->duration == 0 &&
            keys_equal(e, client_id, request_id, packet_checksum,
                       cmd_hash, cmd_hash2, fenv_hash, 0)) {
            exact_one_shot = e;
        }
        idx = (idx + 1) % cache->capacity;
    } while (idx != start);

    if (!is_timed) {
        if (existing_timed) {
            pthread_mutex_unlock(&cache->mutex);
            return;
        }
        if (exact_one_shot) {
            free(exact_one_shot->env_decisions);
            exact_one_shot->decision = decision;
            snprintf(exact_one_shot->reason, sizeof(exact_one_shot->reason), "%.*s", 254, reason ? reason : "");
            exact_one_shot->duration = duration;
            exact_one_shot->timestamp = now;
            exact_one_shot->expires_at = 0;
            if (env_count > 0 && env_decisions) {
                size_t bm_size = (env_count + 7) / 8;
                exact_one_shot->env_decisions = malloc(bm_size);
                if (exact_one_shot->env_decisions) {
                    memcpy(exact_one_shot->env_decisions, env_decisions, bm_size);
                    exact_one_shot->env_decision_count = env_count;
                } else {
                    exact_one_shot->env_decision_count = 0;
                }
            } else {
                exact_one_shot->env_decision_count = 0;
                exact_one_shot->env_decisions = NULL;
            }
            lru_move_to_head(cache, exact_one_shot);
            pthread_mutex_unlock(&cache->mutex);
            return;
        }
    } else {
        if (existing_timed) {
            free(existing_timed->env_decisions);
            existing_timed->decision = decision;
            snprintf(existing_timed->reason, sizeof(existing_timed->reason), "%.*s", 254, reason ? reason : "");
            existing_timed->duration = duration;
            existing_timed->timestamp = now;
            existing_timed->expires_at = now + duration;
            if (env_count > 0 && env_decisions) {
                size_t bm_size = (env_count + 7) / 8;
                existing_timed->env_decisions = malloc(bm_size);
                if (existing_timed->env_decisions) {
                    memcpy(existing_timed->env_decisions, env_decisions, bm_size);
                    existing_timed->env_decision_count = env_count;
                } else {
                    existing_timed->env_decision_count = 0;
                }
            } else {
                existing_timed->env_decision_count = 0;
                existing_timed->env_decisions = NULL;
            }
            lru_move_to_head(cache, existing_timed);
            pthread_mutex_unlock(&cache->mutex);
            return;
        }
    }

    if (cache->count >= cache->capacity) {
        cache_evict_lru(cache);
    }

    rbox_cache_entry_t *e = calloc(1, sizeof(*e));
    if (!e) {
        pthread_mutex_unlock(&cache->mutex);
        return;
    }
    memcpy(e->client_id, client_id, 16);
    memcpy(e->request_id, request_id, 16);
    e->packet_checksum = packet_checksum;
    e->cmd_hash = cmd_hash;
    e->cmd_hash2 = cmd_hash2;
    e->fenv_hash = fenv_hash;
    e->key_hash = target_hash;
    e->decision = decision;
    snprintf(e->reason, sizeof(e->reason), "%.*s", 254, reason ? reason : "");
    e->duration = duration;
    e->timestamp = now;
    e->expires_at = (duration > 0) ? now + duration : 0;
    if (env_count > 0 && env_decisions) {
        size_t bm_size = (env_count + 7) / 8;
        e->env_decisions = malloc(bm_size);
        if (e->env_decisions) {
            memcpy(e->env_decisions, env_decisions, bm_size);
            e->env_decision_count = env_count;
        } else {
            e->env_decision_count = 0;
        }
    } else {
        e->env_decision_count = 0;
        e->env_decisions = NULL;
    }

    if (!robin_hood_insert(cache, e)) {
        free(e->env_decisions);
        free(e);
        pthread_mutex_unlock(&cache->mutex);
        return;
    }
    cache->count++;
    lru_add_head(cache, e);

    if (cache->tombstone_count > cache->capacity / 4) {
        cache_rebuild(cache);
    }

    pthread_mutex_unlock(&cache->mutex);
}
