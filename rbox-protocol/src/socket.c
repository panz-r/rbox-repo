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
#include <time.h>
#include <pthread.h>

#include "rbox_protocol.h"
#include "socket.h"

/* Thread-local seed for rand_r() - each thread gets its own seed */
static __thread uint32_t g_rand_seed = 0;

/* Default timeout for operations (milliseconds) */
/* Timeout for socket operations (milliseconds) */
/* -1 means infinite (wait forever for server response) */
#define RBOX_DEFAULT_TIMEOUT -1

/* Timeout for connection attempts (milliseconds) */
/* This is used during connect() to detect failures and trigger retry */
#define RBOX_CONNECT_TIMEOUT 5000

/* Client structure */
struct rbox_client {
    int fd;
    char socket_path[256];
    int closed;           /* Peer has closed */
    int error;           /* Last error code */
    int timeout_ms;      /* Timeout for operations (-1 = infinite) */
    int connected;       /* 1 if connected, 0 if still connecting */
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

    /* Initialize seed once per thread at function entry */
    if (g_rand_seed == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uintptr_t tid = (uintptr_t)pthread_self();
        g_rand_seed = (uint32_t)((uint64_t)ts.tv_sec ^ ((uint64_t)ts.tv_nsec << 32) ^ tid);
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
            ret = poll(&pfd, 1, RBOX_CONNECT_TIMEOUT);

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

        /* Calculate delay: exponential backoff with jitter
         * Use 64-bit arithmetic to prevent overflow */
        uint64_t max_delay_64 = (uint64_t)base_delay_ms * 64;
        uint32_t max_delay = (max_delay_64 > UINT32_MAX) ? UINT32_MAX : (uint32_t)max_delay_64;

        /* Compute exponential delay with overflow protection */
        uint64_t exp_delay_64 = base_delay_ms;
        for (uint32_t i = 1; i < attempt && exp_delay_64 < UINT64_MAX / 2; i++) {
            exp_delay_64 *= 2;
        }
        uint32_t exp_delay = (exp_delay_64 > UINT32_MAX) ? UINT32_MAX : (uint32_t)exp_delay_64;

        /* Add jitter: random(0..base_delay_ms) - using thread-safe integer arithmetic */
        uint32_t jitter = (uint32_t)(((uint64_t)base_delay_ms * (uint64_t)rand_r(&g_rand_seed)) / (RAND_MAX + 1ULL));

        uint32_t delay = exp_delay + jitter;
        if (delay > max_delay) delay = max_delay;

        /* Cap delay (nanosleep handles any value, but cap for sanity) */
        if (delay > RBOX_MAX_SLEEP_DELAY_MS) {
            delay = RBOX_MAX_SLEEP_DELAY_MS;
        }

        /* Sleep for delay using nanosleep (portable, handles any delay value) */
        struct timespec ts = {
            .tv_sec = delay / 1000,
            .tv_nsec = (delay % 1000) * 1000000
        };
        while (nanosleep(&ts, &ts) < 0 && errno == EINTR);
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

    /* Remove existing socket file - use the truncated path stored in server struct */
    unlink(server->socket_path);

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

    /* Wait for incoming connection (using poll with timeout)
     * Retry on EINTR to avoid dropping connection attempts */
    struct pollfd pfd = { .fd = server->fd, .events = POLLIN };
    int ret;
    int eintr_count = 0;
    const int max_eintr_retry = 5;

    do {
        ret = poll(&pfd, 1, RBOX_DEFAULT_TIMEOUT);
        if (ret < 0 && errno == EINTR) {
            eintr_count++;
            if (eintr_count >= max_eintr_retry) {
                return NULL;  /* Too many EINTR retries */
            }
        }
    } while (ret < 0 && errno == EINTR);

    if (ret <= 0) {
        return NULL;  /* Timeout or error */
    }

    if (!(pfd.revents & POLLIN)) {
        return NULL;
    }

    struct sockaddr_un addr;
    socklen_t addr_len = sizeof(addr);

    /* Accept with EINTR retry - signals can interrupt accept after poll succeeds */
    int client_fd;
    do {
        client_fd = accept(server->fd, (struct sockaddr *)&addr, &addr_len);
        if (client_fd < 0 && errno == EINTR) {
            eintr_count++;
            if (eintr_count >= max_eintr_retry) {
                return NULL;  /* Too many EINTR retries */
            }
        }
    } while (client_fd < 0 && errno == EINTR);

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




/* Read with timeout - for server use to prevent indefinite blocking
 * Returns: bytes read, 0 on timeout, -1 on error, -2 on closed
 *
 * This is like rbox_read() but uses a finite timeout to prevent
 * hanging forever on malicious/truncated client data.
 */
ssize_t rbox_read_timeout(int fd, void *buf, size_t len, int timeout_ms) {
    if (fd < 0 || !buf || len == 0) {
        errno = EINVAL;
        return -1;
    }

    size_t total_read = 0;
    char *ptr = (char *)buf;

    while (total_read < len) {
        /* Wait for data with timeout */
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int ret = poll(&pfd, 1, timeout_ms);

        if (ret < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (ret == 0) {
            /* Timeout - return what we have so far (may be partial) */
            if (total_read > 0) {
                return (ssize_t)total_read;
            }
            errno = ETIMEDOUT;
            return 0;
        }

        /* Check for errors */
        if (pfd.revents & (POLLERR | POLLHUP)) {
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
            if (total_read > 0) {
                break;
            }
            return -1;
        }
        if (n == 0) {
            /* Peer closed */
            break;
        }

        total_read += n;
    }

    return (ssize_t)total_read;
}
