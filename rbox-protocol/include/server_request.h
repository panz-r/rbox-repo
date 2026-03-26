/*
 * server_request.h - Request handling for rbox-protocol server
 *
 * Layer 6: Request handling
 * - Read headers from clients
 * - Read request bodies
 * - Parse request data
 * - Queue requests for processing
 */

#ifndef RBOX_SERVER_REQUEST_H
#define RBOX_SERVER_REQUEST_H

#include <stdint.h>
#include <stddef.h>

/* Forward declaration */
typedef struct rbox_server_request rbox_server_request_t;
typedef struct rbox_server_handle rbox_server_handle_t;

/* Read header from client socket
 * Returns: 0 on success, 1 if no data yet, -1 on error */
int rbox_server_read_header(int fd,
                            uint8_t *client_id,
                            uint8_t *request_id,
                            uint32_t *cmd_hash,
                            uint32_t *fenv_hash,
                            char *caller, size_t caller_len,
                            char *syscall, size_t syscall_len,
                            uint32_t *chunk_len);

/* Read request body from client socket
 * Returns: allocated buffer (caller frees), or NULL on error */
char *rbox_server_read_body(int fd, uint32_t chunk_len);

/* Create server request from parsed data
 * Returns: allocated request (caller frees via rbox_server_request_free) */
rbox_server_request_t *rbox_server_request_create(
    rbox_server_handle_t *server,
    int fd,
    const uint8_t *client_id,
    const uint8_t *request_id,
    uint32_t cmd_hash,
    uint32_t fenv_hash,
    const char *caller, size_t caller_len,
    const char *syscall, size_t syscall_len,
    const char *body_data, size_t body_len);

/* Free server request */
void rbox_server_request_free(rbox_server_request_t *req);

/* Queue request for processing
 * Returns: 0 on success, -1 on error */
int rbox_server_request_queue(rbox_server_handle_t *server, rbox_server_request_t *req);

#endif /* RBOX_SERVER_REQUEST_H */