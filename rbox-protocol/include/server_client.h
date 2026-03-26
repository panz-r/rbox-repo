/*
 * server_client.h - Client connection tracking for rbox-protocol server
 *
 * Layer 5: Client connection tracking
 * - Track active client file descriptors
 * - Add/remove client connections
 * - Close all clients on shutdown
 */

#ifndef RBOX_SERVER_CLIENT_H
#define RBOX_SERVER_CLIENT_H

#include <stdint.h>

/* Forward declaration */
typedef struct rbox_server_handle rbox_server_handle_t;

/* Add a client fd to the tracked list */
void rbox_server_client_add(rbox_server_handle_t *server, int fd);

/* Remove a client fd from the tracked list */
void rbox_server_client_remove(rbox_server_handle_t *server, int fd);

/* Close and remove all tracked client fds */
void rbox_server_client_close_all(rbox_server_handle_t *server);

/* Get count of active clients */
int rbox_server_client_count(const rbox_server_handle_t *server);

#endif /* RBOX_SERVER_CLIENT_H */