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
    uint32_t duration,
    uint32_t fenv_hash,
    int env_decision_count,
    uint8_t *env_decisions,
    size_t *out_len);

/* Add response to send queue
 * Returns: 0 on success, -1 on error */
int rbox_server_send_response(rbox_server_handle_t *server, int fd, char *data, size_t len, rbox_server_request_t *req);

/* Try to send pending data for a client fd */
void rbox_server_try_send(rbox_server_handle_t *server, int fd);

/* Cleanup pending sends for a client fd (e.g., on disconnect) */
void rbox_server_cleanup_pending(rbox_server_handle_t *server, int fd);

/* Enable EPOLLOUT for a client fd */
int rbox_server_enable_epollout(rbox_server_handle_t *server, int fd);

#endif /* RBOX_SERVER_RESPONSE_H */