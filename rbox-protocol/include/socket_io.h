/*
 * socket_io.h - Low-level socket I/O operations
 *
 * Thin wrappers around raw syscalls for non-blocking socket operations.
 */

#ifndef RBOX_SOCKET_IO_H
#define RBOX_SOCKET_IO_H

#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

/* ============================================================
 * NON-BLOCKING I/O PRIMITIVES
 * ============================================================ */

/* Non-blocking read - reads what it can, returns immediately
 * Returns: bytes read, 0 if peer closed, -1 on error (sets errno)
 * Does NOT block - returns immediately if no data available */
ssize_t rbox_read_nonblocking(int fd, void *buf, size_t len);

/* Non-blocking write - writes what it can, returns immediately
 * Returns: bytes written (0 if no data could be written), -1 on error
 * Use io_offset to track position across calls for partial writes */
ssize_t rbox_write_nonblocking(int fd, const void *buf, size_t len, size_t *io_offset);

/* Check if socket is ready for reading (non-blocking poll)
 * Returns: 1 if ready, 0 if not ready, -1 on error */
int rbox_pollin(int fd, int timeout_ms);

/* Check if socket is ready for writing (non-blocking poll)
 * Returns: 1 if ready, 0 if not ready, -1 on error */
int rbox_pollout(int fd, int timeout_ms);

/* ============================================================
 * BLOCKING I/O WITH TIMEOUT
 * ============================================================ */

/* Read with timeout (uses poll internally, never blocks)
 * Returns bytes read, 0 on peer close, -1 on error
 * Handles partial reads automatically */
ssize_t rbox_read(int fd, void *buf, size_t len);

/* Write with timeout (uses poll internally, never blocks)
 * Returns bytes written, -1 on error
 * Handles partial writes automatically */
ssize_t rbox_write(int fd, const void *buf, size_t len);

/* Read exactly N bytes (non-blocking, with timeout)
 * Returns bytes read (equals len on success), 0 on close, -1 on error */
ssize_t rbox_read_exact(int fd, void *buf, size_t len);

/* Write exactly N bytes (non-blocking, with timeout)
 * Returns bytes written (equals len on success), -1 on error */
ssize_t rbox_write_exact(int fd, const void *buf, size_t len);

#endif /* RBOX_SOCKET_IO_H */