/*
 * socket.h - Socket operations (internal)
 */

#ifndef RBOX_SOCKET_H
#define RBOX_SOCKET_H

#include <sys/types.h>

/* Get file descriptor from client */
int rbox_client_fd(const rbox_client_t *client);

/* Low-level read/write (for packet handling) */
ssize_t rbox_read(int fd, void *buf, size_t len);
ssize_t rbox_write(int fd, const void *buf, size_t len);

#endif /* RBOX_SOCKET_H */
