/*
 * server_cache.c - Response caching for rbox-protocol server
 *
 * Layer 8: Response caching
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include "rbox_protocol.h"
#include "server_internal.h"
#include "server_cache.h"

void rbox_server_cache_init(rbox_server_handle_t *server) {
    if (!server) return;
    memset(server->response_cache, 0, sizeof(server->response_cache));
    server->response_cache_next = 0;
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
    time_t now = time(NULL);
    for (int i = 0; i < RBOX_RESPONSE_CACHE_SIZE; i++) {
        if (!server->response_cache[i].valid) continue;
        int match = 0;
        if (server->response_cache[i].duration == 0) {
            if (memcmp(server->response_cache[i].client_id, client_id, 16) == 0 &&
                memcmp(server->response_cache[i].request_id, request_id, 16) == 0 &&
                server->response_cache[i].packet_checksum == packet_checksum) {
                match = 1;
            }
        } else {
            if (server->response_cache[i].expires_at > 0 && now > server->response_cache[i].expires_at) {
                server->response_cache[i].valid = 0;
                continue;
            }
            uint64_t fenv_hash2 = ((uint64_t)fenv_hash << 32) | (((uint64_t)fenv_hash << 16) ^ 0xDEADBEEF);
            if (server->response_cache[i].cmd_hash == cmd_hash &&
                server->response_cache[i].cmd_hash2 == cmd_hash2 &&
                server->response_cache[i].fenv_hash == fenv_hash &&
                server->response_cache[i].fenv_hash2 == fenv_hash2) {
                match = 1;
            }
        }
        if (match) {
            if (decision) *decision = server->response_cache[i].decision;
            if (reason) strncpy(reason, server->response_cache[i].reason, 255);
            if (duration) *duration = server->response_cache[i].duration;
            pthread_mutex_unlock(&server->cache_mutex);
            return 1;
        }
    }
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
    int idx = server->response_cache_next;
    server->response_cache_next = (idx + 1) % RBOX_RESPONSE_CACHE_SIZE;
    rbox_response_cache_entry_t *entry = &server->response_cache[idx];
    memcpy(entry->client_id, client_id, 16);
    memcpy(entry->request_id, request_id, 16);
    entry->packet_checksum = packet_checksum;
    entry->cmd_hash = cmd_hash;
    entry->cmd_hash2 = cmd_hash2;
    entry->fenv_hash = fenv_hash;
    entry->fenv_hash2 = ((uint64_t)fenv_hash << 32) | (((uint64_t)fenv_hash << 16) ^ 0xDEADBEEF);
    entry->decision = decision;
    if (reason && *reason) {
        snprintf(entry->reason, sizeof(entry->reason), "%.*s", 254, reason);
    } else {
        entry->reason[0] = '\0';
    }
    entry->duration = duration;
    entry->timestamp = time(NULL);
    entry->expires_at = (duration > 0) ? entry->timestamp + duration : 0;
    entry->valid = 1;
    pthread_mutex_unlock(&server->cache_mutex);
}