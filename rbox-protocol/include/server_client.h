/*
 * server_client.h - Client connection tracking for rbox-protocol server
 *
 * Layer 5: Client connection tracking
 * - Track active client file descriptors
 * - Add/remove client connections
 * - Close all clients on shutdown
 * - Per-client send queues with lock-free MPSC
 */

#ifndef RBOX_SERVER_CLIENT_H
#define RBOX_SERVER_CLIENT_H

#include <stdint.h>

/* Forward declaration */
typedef struct rbox_server_handle rbox_server_handle_t;
typedef struct rbox_client_fd_entry rbox_client_fd_entry_t;
typedef struct rbox_server_send_entry rbox_server_send_entry_t;

/* Add a client fd to the tracked list */
void client_fd_add(rbox_server_handle_t *server, int fd);

/* Remove a client fd from the tracked list */
void client_fd_remove(rbox_server_handle_t *server, int fd);

/* Close and remove all tracked client fds */
void client_fd_close_all(rbox_server_handle_t *server);

/* Find client fd entry by fd */
rbox_client_fd_entry_t *client_fd_find(rbox_server_handle_t *server, int fd);

/* Close a client connection and free all associated resources */
void client_connection_close(rbox_server_handle_t *server, int fd);

/* Clean up any send queue entries for a closed fd */
void cleanup_pending_sends(rbox_server_handle_t *server, int fd);

/* Lock-free send queue functions */
int send_queue_enqueue(rbox_client_fd_entry_t *client, rbox_server_send_entry_t *entry);
rbox_server_send_entry_t *send_queue_dequeue(rbox_client_fd_entry_t *client);
rbox_server_send_entry_t *send_queue_peek(rbox_client_fd_entry_t *client);

/* Get count of active clients */
int rbox_server_client_count(const rbox_server_handle_t *server);

/* Public API wrappers (for compatibility) */
void rbox_server_client_add(rbox_server_handle_t *server, int fd);
void rbox_server_client_remove(rbox_server_handle_t *server, int fd);
void rbox_server_client_close_all(rbox_server_handle_t *server);

#endif /* RBOX_SERVER_CLIENT_H */