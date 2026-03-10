/*
 * socket.c - Non-blocking socket operations for rbox-protocol
 * 
 * Uses poll() for event-driven I/O with proper state machines.
 * NEVER blocks - always returns immediately with status.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>

#include "rbox_protocol.h"
#include "socket.h"

/* Default timeout for operations (milliseconds) */
#define RBOX_DEFAULT_TIMEOUT 5000

/* Client structure */
struct rbox_client {
    int fd;
    char socket_path[256];
    int closed;           /* Peer has closed */
    int error;           /* Last error code */
};

/* Server structure */
struct rbox_server {
    int fd;
    char socket_path[256];
};

/* ============================================================
 * CLIENT FUNCTIONS
 * ============================================================ */

rbox_client_t *rbox_client_connect(const char *socket_path) {
    return rbox_client_connect_retry(socket_path, 0, 0);
}

/* Connect with retry using exponential backoff and jitter
 * 
 * Parameters:
 *   - socket_path: path to Unix domain socket
 *   - base_delay_ms: base delay in milliseconds for backoff (0 = no retry, fail immediately)
 *   - max_retries: maximum number of connection attempts (0 = unlimited)
 * 
 * Returns: connected client, or NULL on failure after all retries exhausted
 * 
 * Retry algorithm:
 *   delay = min(base_delay_ms * 2^attempt + random(0..base_delay_ms), max_delay)
 *   where max_delay = base_delay_ms * 64 (caps at 64x base)
 */
rbox_client_t *rbox_client_connect_retry(const char *socket_path, uint32_t base_delay_ms, uint32_t max_retries) {
    if (!socket_path) {
        errno = EINVAL;
        return NULL;
    }

    uint32_t attempt = 0;
    
    while (1) {
        rbox_client_t *client = calloc(1, sizeof(rbox_client_t));
        if (!client) return NULL;

        size_t len = strlen(socket_path);
        if (len >= sizeof(client->socket_path)) len = sizeof(client->socket_path) - 1;
        memcpy(client->socket_path, socket_path, len);
        client->socket_path[len] = '\0';

        /* Create socket */
        client->fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (client->fd < 0) {
            free(client);
            return NULL;
        }

        /* Set non-blocking */
        int flags = fcntl(client->fd, F_GETFL, 0);
        fcntl(client->fd, F_SETFL, flags | O_NONBLOCK);

        /* Connect (non-blocking) */
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

        int ret = connect(client->fd, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0 && errno != EINPROGRESS) {
            /* Connection failed immediately - try again with backoff */
            close(client->fd);
            free(client);
            client = NULL;
        } else if (ret < 0) {
            /* Connect in progress - wait for it */
            struct pollfd pfd = { .fd = client->fd, .events = POLLOUT };
            ret = poll(&pfd, 1, RBOX_DEFAULT_TIMEOUT);
            
            if (ret <= 0) {
                /* Timeout or error */
                close(client->fd);
                free(client);
                client = NULL;
            } else if (pfd.revents & (POLLERR | POLLHUP)) {
                /* Connection error */
                close(client->fd);
                free(client);
                client = NULL;
            } else {
                /* Check SO_ERROR to see if connect actually succeeded */
                int so_error = 0;
                socklen_t optlen = sizeof(so_error);
                getsockopt(client->fd, SOL_SOCKET, SO_ERROR, &so_error, &optlen);
                if (so_error != 0) {
                    errno = so_error;
                    close(client->fd);
                    free(client);
                    client = NULL;
                }
                /* Otherwise, connected successfully! */
            }
        }
        /* If ret == 0, connect succeeded immediately */

        /* If we have a valid connection, return it */
        if (client) {
            return client;
        }

        /* Connection failed - check if we should retry */
        if (base_delay_ms == 0) {
            /* No retry */
            return NULL;
        }
        
        if (max_retries > 0 && attempt >= max_retries) {
            /* Max retries exhausted */
            return NULL;
        }
        
        attempt++;
        
        /* Calculate delay: exponential backoff with jitter */
        /* delay = min(base * 2^attempt + random(0..base), base * 16) */
        uint32_t max_delay = base_delay_ms * 64;
        if (max_delay < base_delay_ms) max_delay = UINT32_MAX;  /* Overflow protection */
        
        uint32_t exp_delay = base_delay_ms;
        for (uint32_t i = 1; i < attempt && exp_delay < UINT32_MAX / 2; i++) {
            exp_delay *= 2;
        }
        
        /* Add jitter: random(0..base_delay_ms) */
        uint32_t jitter = (uint32_t)((double)base_delay_ms * rand() / (RAND_MAX + 1.0));
        
        uint32_t delay = exp_delay + jitter;
        if (delay > max_delay) delay = max_delay;
        
        /* Sleep for delay (convert to microseconds) */
        usleep(delay * 1000);
    }
    
    /* Never reached */
    return NULL;
}

void rbox_client_close(rbox_client_t *client) {
    if (!client) return;
    if (client->fd >= 0) {
        close(client->fd);
    }
    free(client);
}

int rbox_client_fd(const rbox_client_t *client) {
    return client ? client->fd : -1;
}

int rbox_client_is_closed(const rbox_client_t *client) {
    return client ? client->closed : 1;
}

int rbox_client_error(const rbox_client_t *client) {
    return client ? client->error : 0;
}

/* ============================================================
 * SERVER FUNCTIONS
 * ============================================================ */

rbox_server_t *rbox_server_new(const char *socket_path) {
    if (!socket_path) {
        errno = EINVAL;
        return NULL;
    }

    rbox_server_t *server = calloc(1, sizeof(rbox_server_t));
    if (!server) return NULL;

    strncpy(server->socket_path, socket_path, sizeof(server->socket_path) - 1);

    /* Create socket */
    server->fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server->fd < 0) {
        free(server);
        return NULL;
    }

    /* Note: keep listen socket blocking - we use poll in accept() to add timeout */

    /* Remove existing socket file */
    unlink(socket_path);

    /* Bind */
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (bind(server->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(server->fd);
        free(server);
        return NULL;
    }

    /* Set permissions */
    chmod(socket_path, 0666);

    return server;
}

rbox_error_t rbox_server_listen(rbox_server_t *server) {
    if (!server || server->fd < 0) {
        return RBOX_ERR_INVALID;
    }

    if (listen(server->fd, 10) < 0) {
        return RBOX_ERR_IO;
    }

    return RBOX_OK;
}

rbox_client_t *rbox_server_accept(rbox_server_t *server) {
    if (!server || server->fd < 0) {
        return NULL;
    }

    /* Wait for incoming connection (using poll with timeout) */
    struct pollfd pfd = { .fd = server->fd, .events = POLLIN };
    int ret = poll(&pfd, 1, RBOX_DEFAULT_TIMEOUT);
    
    if (ret <= 0) {
        return NULL;  /* Timeout or error */
    }
    
    if (!(pfd.revents & POLLIN)) {
        return NULL;
    }

    struct sockaddr_un addr;
    socklen_t addr_len = sizeof(addr);
    
    int client_fd = accept(server->fd, (struct sockaddr *)&addr, &addr_len);
    if (client_fd < 0) {
        return NULL;
    }

    /* Set non-blocking for accepted client socket */
    int flags = fcntl(client_fd, F_GETFL, 0);
    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

    rbox_client_t *client = calloc(1, sizeof(rbox_client_t));
    if (!client) {
        close(client_fd);
        return NULL;
    }

    client->fd = client_fd;
    size_t len = strlen(server->socket_path);
    if (len >= sizeof(client->socket_path)) len = sizeof(client->socket_path) - 1;
    memcpy(client->socket_path, server->socket_path, len);
    client->socket_path[len] = '\0';

    return client;
}

int rbox_server_fd(const rbox_server_t *server) {
    return server ? server->fd : -1;
}

void rbox_server_free(rbox_server_t *server) {
    if (!server) return;
    if (server->fd >= 0) {
        close(server->fd);
        unlink(server->socket_path);
    }
    free(server);
}

/* ============================================================
 * NON-BLOCKING READ/WRITE OPERATIONS
 * ============================================================ */

/* Read with timeout using poll
 * Returns:
 *   > 0: bytes read
 *   = 0: peer closed (client->closed = 1)
 *   < 0: error (client->error = errno)
 * 
 * NOTE: This handles partial reads automatically by polling until
 * either the requested length is read, or an error/timeout occurs.
 */
ssize_t rbox_read(int fd, void *buf, size_t len) {
    if (fd < 0 || !buf || len == 0) {
        errno = EINVAL;
        return -1;
    }

    size_t total_read = 0;
    char *ptr = (char *)buf;

    while (total_read < len) {
        /* Wait for data */
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int ret = poll(&pfd, 1, RBOX_DEFAULT_TIMEOUT);
        
        if (ret < 0) {
            if (errno == EINTR) continue;  /* Retry on interrupt */
            return -1;
        }
        if (ret == 0) {
            errno = ETIMEDOUT;
            return -1;
        }

        /* Check for errors - but allow reading if data is available */
        if (pfd.revents & (POLLERR | POLLHUP)) {
            /* If POLLIN is set, there's data to read - don't treat as error yet */
            if (!(pfd.revents & POLLIN)) {
                errno = ECONNRESET;
                return -1;
            }
        }

        /* Read */
        ssize_t n = read(fd, ptr + total_read, len - total_read);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            /* If we have data and get error, return what we have */
            if (total_read > 0) {
                break;
            }
            return -1;
        }
        if (n == 0) {
            /* Peer closed - return what we have */
            break;
        }
        
        total_read += n;
    }

    return (ssize_t)total_read;
}

/* Write with timeout using poll
 * Returns:
 *   > 0: bytes written
 *   < 0: error
 * 
 * NOTE: This handles partial writes automatically.
 */
ssize_t rbox_write(int fd, const void *buf, size_t len) {
    if (fd < 0 || !buf || len == 0) {
        errno = EINVAL;
        return -1;
    }

    size_t total_written = 0;
    const char *ptr = (const char *)buf;

    while (total_written < len) {
        /* Wait for write capability */
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        int ret = poll(&pfd, 1, RBOX_DEFAULT_TIMEOUT);
        
        if (ret < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (ret == 0) {
            errno = ETIMEDOUT;
            return -1;
        }

        /* Check for errors */
        if (pfd.revents & (POLLERR | POLLHUP)) {
            errno = ECONNRESET;
            return -1;
        }

        /* Write */
        ssize_t n = write(fd, ptr + total_written, len - total_written);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        if (n == 0) {
            errno = ECONNRESET;
            return -1;
        }
        
        total_written += n;
    }

    return (ssize_t)total_written;
}

/* Read exactly N bytes (non-blocking, with timeout)
 * Returns:
 *   > 0: bytes read (always equals len on success)
 *   = 0: peer closed
 *   < 0: error
 */
ssize_t rbox_read_exact(int fd, void *buf, size_t len) {
    if (fd < 0 || !buf || len == 0) {
        errno = EINVAL;
        return -1;
    }

    size_t total = 0;
    char *ptr = (char *)buf;

    while (total < len) {
        ssize_t n = rbox_read(fd, ptr + total, len - total);
        if (n <= 0) {
            return n;  /* Error or closed */
        }
        total += n;
    }

    return (ssize_t)total;
}

/* Write exactly N bytes (non-blocking, with timeout)
 * Returns:
 *   > 0: bytes written (always equals len on success)
 *   < 0: error
 */
ssize_t rbox_write_exact(int fd, const void *buf, size_t len) {
    if (fd < 0 || !buf || len == 0) {
        errno = EINVAL;
        return -1;
    }

    size_t total = 0;
    const char *ptr = (const char *)buf;

    while (total < len) {
        ssize_t n = rbox_write(fd, ptr + total, len - total);
        if (n < 0) {
            return n;
        }
        total += n;
    }

    return (ssize_t)total;
}

/* Check if socket is ready for reading (non-blocking poll)
 * Returns: 1 if ready, 0 if not ready, -1 on error
 */
int rbox_pollin(int fd, int timeout_ms) {
    if (fd < 0) return -1;
    
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int ret = poll(&pfd, 1, timeout_ms);
    
    if (ret < 0) return -1;
    if (ret == 0) return 0;
    
    /* Allow reading if POLLIN is set, even with POLLHUP/POLLERR */
    if (pfd.revents & POLLIN) return 1;
    if (pfd.revents & (POLLERR | POLLHUP)) return -1;
    
    return 0;
}

/* Check if socket is ready for writing (non-blocking poll)
 * Returns: 1 if ready, 0 if not ready, -1 on error
 */
int rbox_pollout(int fd, int timeout_ms) {
    if (fd < 0) return -1;
    
    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    int ret = poll(&pfd, 1, timeout_ms);
    
    if (ret < 0) return -1;
    if (ret == 0) return 0;
    
    /* Allow writing if POLLOUT is set, even with POLLHUP/POLLERR */
    if (pfd.revents & POLLOUT) return 1;
    if (pfd.revents & (POLLERR | POLLHUP)) return -1;
    
    return 0;
}
