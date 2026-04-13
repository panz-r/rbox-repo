/*
 * server_cache.h - Response caching for rbox-protocol server
 *
 * Layer 8: Response caching
 * - Cache responses to avoid recomputation
 * - Time-based expiration
 * - Round-robin cache eviction
 */

#ifndef RBOX_SERVER_CACHE_H
#define RBOX_SERVER_CACHE_H

#include <stdint.h>

/* Forward declaration */
typedef struct rbox_server_handle rbox_server_handle_t;

/* Initialize cache */
void rbox_server_cache_init(rbox_server_handle_t *server);

/* Destroy cache - frees all entries */
void rbox_server_cache_destroy(rbox_server_handle_t *server);

/* Lookup cache entry
 * Returns: 1 if found (out params populated), 0 if not found
 * Note: env_decisions is allocated by caller, must be freed by caller if set */
int rbox_server_cache_lookup(rbox_server_handle_t *server,
                            const uint8_t *client_id,
                            const uint8_t *request_id,
                            uint32_t packet_checksum,
                            uint32_t cmd_hash, uint64_t cmd_hash2,
                            uint32_t fenv_hash,
                            uint8_t *decision, char *reason, uint32_t *duration,
                            int *env_decision_count, uint8_t **env_decisions);

/* Insert cache entry */
void rbox_server_cache_insert(rbox_server_handle_t *server,
                             const uint8_t *client_id,
                             const uint8_t *request_id,
                             uint32_t packet_checksum,
                             uint32_t cmd_hash, uint64_t cmd_hash2,
                             uint32_t fenv_hash,
                             uint8_t decision, const char *reason, uint32_t duration,
                             int env_decision_count, uint8_t *env_decisions);

#endif /* RBOX_SERVER_CACHE_H */