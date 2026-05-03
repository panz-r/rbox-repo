/*
 * rbox_cache.c - Response cache with LRU eviction via ht_cache_t
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include "rbox_cache.h"
#include "draugr/ht_cache.h"

static uint64_t rbox_cache_hash_fn(const void *data, size_t len, void *ctx) {
    (void)len; (void)ctx;
    const rbox_cache_entry_t *e = data;
    uint32_t h = 2166136261u;
    h = (h * 16777619) ^ e->cmd_hash;
    h = (h * 16777619) ^ (uint32_t)(e->cmd_hash2);
    h = (h * 16777619) ^ (uint32_t)(e->cmd_hash2 >> 32);
    h = (h * 16777619) ^ e->fenv_hash;
    return (uint64_t)h;
}

static uint64_t compute_hash(uint32_t cmd_hash, uint64_t cmd_hash2, uint32_t fenv_hash) {
    uint32_t h = 2166136261u;
    h = (h * 16777619) ^ cmd_hash;
    h = (h * 16777619) ^ (uint32_t)(cmd_hash2);
    h = (h * 16777619) ^ (uint32_t)(cmd_hash2 >> 32);
    h = (h * 16777619) ^ fenv_hash;
    return (uint64_t)h;
}

/* eq_fn only used by ht_cache_get/ht_cache_remove — not by the two-phase
 * lookup/insert which use ht_cache_find + scan_fn. Matches on the three
 * hash fields for a simple identity check. */
static bool rbox_cache_eq_fn(const void *key, size_t key_len,
                             const void *entry, size_t entry_size, void *ctx) {
    (void)key; (void)key_len; (void)entry; (void)entry_size; (void)ctx;
    return true; /* All same-hash entries are "equal" for bare API */
}

/* Lookup scan context */
typedef struct {
    const uint8_t *client_id;
    const uint8_t *request_id;
    uint32_t packet_checksum;
    time_t now;

    rbox_cache_entry_t *exact_one_shot;
    rbox_cache_entry_t *best_timed;
} lookup_scan_t;

static bool lookup_scan_fn(void *entry, void *ctx) {
    lookup_scan_t *s = ctx;
    rbox_cache_entry_t *e = entry;

    /* Check for exact one-shot match */
    if (e->duration == 0 &&
        memcmp(e->client_id, s->client_id, 16) == 0 &&
        memcmp(e->request_id, s->request_id, 16) == 0 &&
        e->packet_checksum == s->packet_checksum) {
        s->exact_one_shot = e;
        return false; /* stop — exact match found */
    }

    /* Track best timed entry */
    if (e->duration > 0 && (e->expires_at == 0 || s->now <= e->expires_at)) {
        if (!s->best_timed) s->best_timed = e;
    }

    return true;
}

/* Insert scan context */
typedef struct {
    const uint8_t *client_id;
    const uint8_t *request_id;
    uint32_t packet_checksum;
    int is_timed;
    time_t now;

    rbox_cache_entry_t *existing_timed;
    rbox_cache_entry_t *exact_one_shot;
} insert_scan_t;

static bool insert_scan_fn(void *entry, void *ctx) {
    insert_scan_t *s = ctx;
    rbox_cache_entry_t *e = entry;

    if (e->duration > 0 && (e->expires_at == 0 || s->now <= e->expires_at)) {
        s->existing_timed = e;
    } else if (!s->is_timed && e->duration == 0 &&
               memcmp(e->client_id, s->client_id, 16) == 0 &&
               memcmp(e->request_id, s->request_id, 16) == 0 &&
               e->packet_checksum == s->packet_checksum) {
        s->exact_one_shot = e;
    }

    return true; /* scan all entries */
}

static void copy_out_result(rbox_cache_entry_t *e,
                            uint8_t *out_decision, char *out_reason,
                            uint32_t *out_duration,
                            int *out_env_count, uint8_t **out_env_decisions) {
    if (out_decision) *out_decision = e->decision;
    if (out_reason) snprintf(out_reason, 256, "%s", e->reason);
    if (out_duration) *out_duration = e->duration;
    if (out_env_count) *out_env_count = e->env_decision_count;
    if (out_env_decisions) {
        if (e->env_decision_count > 0) {
            size_t bm_size = (size_t)(e->env_decision_count + 7) / 8;
            *out_env_decisions = malloc(bm_size);
            if (*out_env_decisions) {
                memcpy(*out_env_decisions, e->env_decisions, bm_size);
            } else {
                if (out_env_count) *out_env_count = 0;
            }
        } else {
            *out_env_decisions = NULL;
        }
    }
}

static void set_env_bitmap(rbox_cache_entry_t *e, int env_count,
                           const uint8_t *env_decisions) {
    if (env_count > 0 && env_decisions) {
        size_t bm_size = (size_t)(env_count + 7) / 8;
        if (bm_size > RBOX_ENV_BITMAP_SIZE) bm_size = RBOX_ENV_BITMAP_SIZE;
        memcpy(e->env_decisions, env_decisions, bm_size);
        e->env_decision_count = env_count;
    } else {
        e->env_decision_count = 0;
        memset(e->env_decisions, 0, RBOX_ENV_BITMAP_SIZE);
    }
}

static ht_cache_t *create_ht(size_t capacity) {
    ht_cache_config_t cfg = {
        .capacity   = capacity,
        .entry_size = sizeof(rbox_cache_entry_t),
        .hash_fn    = rbox_cache_hash_fn,
        .eq_fn      = rbox_cache_eq_fn,
        .user_ctx   = NULL,
    };
    return ht_cache_create(&cfg);
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
    cache->ht = create_ht(capacity);
    pthread_mutex_init(&cache->mutex, NULL);
}

void rbox_cache_destroy(rbox_cache_t *cache) {
    if (!cache) return;
    pthread_mutex_lock(&cache->mutex);
    ht_cache_destroy((ht_cache_t *)cache->ht);
    cache->ht = NULL;
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
    if (!cache || !cache->ht) return 0;
    pthread_mutex_lock(&cache->mutex);

    uint64_t hash = compute_hash(cmd_hash, cmd_hash2, fenv_hash);
    time_t now = time(NULL);

    lookup_scan_t scan = {
        .client_id = client_id,
        .request_id = request_id,
        .packet_checksum = packet_checksum,
        .now = now,
        .exact_one_shot = NULL,
        .best_timed = NULL,
    };
    ht_cache_find((ht_cache_t *)cache->ht, hash, lookup_scan_fn, &scan);

    rbox_cache_entry_t *winner = scan.exact_one_shot ? scan.exact_one_shot : scan.best_timed;
    if (!winner) {
        pthread_mutex_unlock(&cache->mutex);
        return 0;
    }

    ht_cache_promote((ht_cache_t *)cache->ht, winner);

    copy_out_result(winner, out_decision, out_reason, out_duration,
                    out_env_count, out_env_decisions);

    pthread_mutex_unlock(&cache->mutex);
    return 1;
}

void rbox_cache_insert(rbox_cache_t *cache,
                       const uint8_t *client_id,
                       const uint8_t *request_id,
                       uint32_t packet_checksum,
                       uint32_t cmd_hash, uint64_t cmd_hash2,
                       uint32_t fenv_hash,
                       uint8_t decision, const char *reason, uint32_t duration,
                       int env_count, const uint8_t *env_decisions) {
    if (!cache || !cache->ht) return;
    pthread_mutex_lock(&cache->mutex);

    uint64_t hash = compute_hash(cmd_hash, cmd_hash2, fenv_hash);
    time_t now = time(NULL);
    int is_timed = (duration > 0);

    /* Scan for existing entries to handle dedup */
    insert_scan_t scan = {
        .client_id = client_id,
        .request_id = request_id,
        .packet_checksum = packet_checksum,
        .is_timed = is_timed,
        .now = now,
        .existing_timed = NULL,
        .exact_one_shot = NULL,
    };
    ht_cache_find((ht_cache_t *)cache->ht, hash, insert_scan_fn, &scan);

    /* One-shot: skip if timed entry exists */
    if (!is_timed) {
        if (scan.existing_timed) {
            pthread_mutex_unlock(&cache->mutex);
            return;
        }
        /* One-shot: update in-place if exact match exists */
        if (scan.exact_one_shot) {
            rbox_cache_entry_t *e = scan.exact_one_shot;
            e->decision = decision;
            snprintf(e->reason, sizeof(e->reason), "%.*s", 254, reason ? reason : "");
            e->duration = 0;
            e->timestamp = now;
            e->expires_at = 0;
            set_env_bitmap(e, env_count, env_decisions);
            ht_cache_promote((ht_cache_t *)cache->ht, e);
            pthread_mutex_unlock(&cache->mutex);
            return;
        }
    } else {
        /* Timed: update in-place if existing timed entry */
        if (scan.existing_timed) {
            rbox_cache_entry_t *e = scan.existing_timed;
            e->decision = decision;
            snprintf(e->reason, sizeof(e->reason), "%.*s", 254, reason ? reason : "");
            e->duration = duration;
            e->timestamp = now;
            e->expires_at = now + duration;
            set_env_bitmap(e, env_count, env_decisions);
            ht_cache_promote((ht_cache_t *)cache->ht, e);
            pthread_mutex_unlock(&cache->mutex);
            return;
        }
    }

    /* New entry */
    rbox_cache_entry_t e;
    memset(&e, 0, sizeof(e));
    memcpy(e.client_id, client_id, 16);
    memcpy(e.request_id, request_id, 16);
    e.packet_checksum = packet_checksum;
    e.cmd_hash = cmd_hash;
    e.cmd_hash2 = cmd_hash2;
    e.fenv_hash = fenv_hash;
    e.decision = decision;
    snprintf(e.reason, sizeof(e.reason), "%.*s", 254, reason ? reason : "");
    e.duration = duration;
    e.timestamp = now;
    e.expires_at = (duration > 0) ? now + duration : 0;
    set_env_bitmap(&e, env_count, env_decisions);

    ht_cache_put((ht_cache_t *)cache->ht, &e, sizeof(e));

    pthread_mutex_unlock(&cache->mutex);
}
