/*
 * server_response.h - Response dispatch for rbox-protocol server
 *
 * Layer 7: Response dispatch
 * - Build responses
 * - Queue responses for sending
 * - Send pending responses
 * - Cleanup on client disconnect
 */

#ifndef RBOX_SERVER_RESPONSE_H
#define RBOX_SERVER_RESPONSE_H

#include <stdint.h>

/* Forward declaration */
typedef struct rbox_server_request rbox_server_request_t;
typedef struct rbox_server_handle rbox_server_handle_t;

/* Build response packet
 * Returns: allocated packet (caller frees with free()), or NULL on error */
char *rbox_server_build_response(
    const uint8_t *client_id,
    const uint8_t *request_id,
    uint32_t cmd_hash,
    uint8_t decision,
    const char *reason,
    uint32_t fenv_hash,
    int env_decision_count,
    uint8_t *env_decisions,
    size_t *out_len);

#endif /* RBOX_SERVER_RESPONSE_H */