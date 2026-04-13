/*
 * socket_io.c - Low-level socket I/O operations
 *
 * Thin wrappers around raw syscalls for non-blocking socket operations.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>

#include "rbox_protocol.h"
#include "socket_io.h"

/* ============================================================
 * NON-BLOCKING I/O PRIMITIVES
 * ============================================================ */

ssize_t rbox_read_nonblocking(int fd, void *buf, size_t len) {
    if (fd < 0 || !buf || len == 0) {
        errno = EINVAL;
        return -2;
    }

    /* Try to read immediately without waiting - loop on EINTR */
    ssize_t n;
    do {
        n = read(fd, buf, len);
    } while (n < 0 && errno == EINTR);
    if (n > 0) {
        return n;                     /* bytes read */
    } else if (n == 0) {
        return 0;                     /* EOF - peer closed */
    } else { /* n < 0 */
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return -1;                /* would block */
        } else {
            return -2;                /* real error */
        }
    }
}

ssize_t rbox_write_nonblocking(int fd, const void *buf, size_t len, size_t *io_offset) {
    if (fd < 0 || !buf || len == 0) {
        errno = EINVAL;
        return -1;
    }

    size_t offset = io_offset ? *io_offset : 0;
    if (offset >= len) {
        return 0;  /* Already wrote everything */
    }

    /* Loop on EINTR to handle interrupted syscalls */
    ssize_t n;
    do {
        n = write(fd, buf + offset, len - offset);
    } while (n < 0 && errno == EINTR);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;  /* Would block */
        }
        return -1;  /* Real error */
    }

    if (io_offset) {
        *io_offset += n;
    }

    return n;
}

int rbox_pollin(int fd, int timeout_ms) {
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int ret;
    do {
        ret = poll(&pfd, 1, timeout_ms);
    } while (ret < 0 && errno == EINTR);
    if (ret < 0) {
        return -1;
    }
    if (ret == 0) {
        return 0;
    }
    return (pfd.revents & (POLLIN | POLLHUP | POLLERR)) ? 1 : 0;
}

int rbox_pollout(int fd, int timeout_ms) {
    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    int ret;
    do {
        ret = poll(&pfd, 1, timeout_ms);
    } while (ret < 0 && errno == EINTR);
    if (ret < 0) {
        return -1;
    }
    if (ret == 0) {
        return 0;
    }
    return (pfd.revents & (POLLOUT | POLLHUP | POLLERR)) ? 1 : 0;
}

/* ============================================================
 * BLOCKING I/O WITH TIMEOUT
 * ============================================================ */

ssize_t rbox_read(int fd, void *buf, size_t len) {
    if (fd < 0 || !buf || len == 0) {
        errno = EINVAL;
        return -1;
    }

    size_t total_read = 0;
    while (total_read < len) {
        ssize_t n = rbox_read_nonblocking(fd, buf + total_read, len - total_read);
        if (n == -1) {
            /* Would block, wait and retry */
            if (rbox_pollin(fd, 1000) <= 0) {
                return -1;  /* Timeout or error */
            }
            continue;
        }
        if (n == -2) {
            return -1;  /* Real error */
        }
        if (n == 0) {
            return 0;  /* EOF - peer closed */
        }
        total_read += n;
    }

    return total_read;
}

ssize_t rbox_write(int fd, const void *buf, size_t len) {
    if (fd < 0 || !buf || len == 0) {
        errno = EINVAL;
        return -1;
    }

    size_t offset = 0;
    while (offset < len) {
        ssize_t n = rbox_write_nonblocking(fd, buf, len, &offset);
        if (n < 0) {
            return -1;  /* Error */
        }
        if (n == 0) {
            /* Would block, wait and retry */
            if (rbox_pollout(fd, 1000) <= 0) {
                return -1;  /* Timeout or error */
            }
            continue;
        }
    }

    return offset;
}

ssize_t rbox_read_exact(int fd, void *buf, size_t len) {
    if (fd < 0 || !buf || len == 0) {
        errno = EINVAL;
        return -1;
    }

    size_t total_read = 0;
    while (total_read < len) {
        ssize_t n = rbox_read_nonblocking(fd, buf + total_read, len - total_read);
        if (n == -1) {
            /* Would block, wait and retry */
            if (rbox_pollin(fd, 1000) <= 0) {
                return -1;  /* Timeout or error */
            }
            continue;
        }
        if (n == -2) {
            return -1;  /* Real error */
        }
        if (n == 0) {
            return 0;  /* EOF - peer closed */
        }
        total_read += n;
    }

    return total_read;
}

ssize_t rbox_write_exact(int fd, const void *buf, size_t len) {
    if (fd < 0 || !buf || len == 0) {
        errno = EINVAL;
        return -1;
    }

    size_t offset = 0;
    while (offset < len) {
        ssize_t n = rbox_write_nonblocking(fd, buf, len, &offset);
        if (n < 0) {
            return -1;  /* Error */
        }
        if (n == 0) {
            /* Would block, wait and retry */
            if (rbox_pollout(fd, 1000) <= 0) {
                return -1;  /* Timeout or error */
            }
            continue;
        }
    }

    return offset;
}
