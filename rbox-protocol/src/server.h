/*
 * server.h - Server thread and related structures for rbox-protocol
 *
 * This file contains the server thread implementation with non-blocking I/O
 * and proper error handling.
 */

#ifndef RBOX_SERVER_H
#define RBOX_SERVER_H

#include <stdint.h>
#include <pthread.h>
#include "server_internal.h"

/* ============================================================
 * SERVER HANDLE MANAGEMENT
 * ============================================================ */

/* Create server handle (includes socket creation, bind, and listen) */
rbox_server_handle_t *rbox_server_handle_new(const char *socket_path);

/* Free server handle */
void rbox_server_handle_free(rbox_server_handle_t *server);

/* Start background server thread */
rbox_error_t rbox_server_start(rbox_server_handle_t *server);

/* Stop server */
void rbox_server_stop(rbox_server_handle_t *server);

/* Get request from server (blocking) */
rbox_server_request_t *rbox_server_get_request(rbox_server_handle_t *server);

/* Check if server is running */
int rbox_server_is_running(rbox_server_handle_t *server);

/* Queue decision to be sent by background thread */
rbox_error_t rbox_server_decide(rbox_server_request_t *req,
    uint8_t decision, const char *reason, uint32_t duration,
    int env_decision_count, const char **env_decision_names, const uint8_t *env_decisions);

/* Set connection limits and timeouts */
void rbox_server_set_limits(rbox_server_handle_t *server, int max_clients, int idle_timeout, int request_timeout);

#endif /* RBOX_SERVER_H */
