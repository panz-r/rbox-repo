/*
 * socket.h - Socket operations (internal)
 */

#ifndef RBOX_SOCKET_H
#define RBOX_SOCKET_H

#include <sys/types.h>

/* Server read timeout - prevents indefinite blocking from malicious clients (100 ms) */
#define RBOX_SERVER_READ_TIMEOUT 100

/* Maximum delay cap for usleep (1000 seconds) to prevent overflow */
#define RBOX_MAX_SLEEP_DELAY_MS 1000000

/* Get file descriptor from client */
int rbox_client_fd(const rbox_client_t *client);

/* Low-level read/write (for packet handling)
 * IMPORTANT: These functions BLOCK INDEFINITELY (use RBOX_DEFAULT_TIMEOUT = -1).
 * They should only be used in client-side blocking code, NOT in server/event-driven code.
 * Returns: bytes read/written on success, -1 on error (check errno)
 *   - rbox_read: returns 0 if peer closed
 *   - rbox_write: returns -1 with errno=EPIPE if peer closed
 */
ssize_t rbox_read(int fd, void *buf, size_t len);
ssize_t rbox_write(int fd, const void *buf, size_t len);

/* Non-blocking read - reads what's available, returns immediately
 * Returns: bytes read (0 if no data available), -1 on error, -2 on peer closed
 * NOTE: EINTR is treated as "would block" and returns 0 (caller polls again)
 */
ssize_t rbox_read_nonblocking(int fd, void *buf, size_t len);

/* Non-blocking write - writes what it can, returns immediately
 * Returns: bytes written (0 if no data could be written), -1 on error
 * NOTE: EINTR is treated as "would block" and returns 0 (caller polls again)
 */
ssize_t rbox_write_nonblocking(int fd, const void *buf, size_t len, size_t *io_offset);

#endif /* RBOX_SOCKET_H */
