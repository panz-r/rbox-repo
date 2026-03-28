/*
 * server.c - Server thread implementation for rbox-protocol
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/eventfd.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>

#include "rbox_protocol.h"
#include "socket.h"
#include "server.h"
#include "server_cache.h"
#include "server_response.h"

/* Debug flag – set to 1 to enable verbose tracing */
#ifndef RBOX_SERVER_DEBUG
#define RBOX_SERVER_DEBUG 0
#endif

#if RBOX_SERVER_DEBUG
#define DBG(fmt, ...) fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define DBG(fmt, ...) ((void)0)
#endif

/* ============================================================
 * FORWARD DECLARATIONS
 * ============================================================ */
static int send_queue_add(rbox_server_handle_t *server, int fd, char *data, size_t len, rbox_server_request_t *req);
static void try_send_pending(rbox_server_handle_t *server, int fd);
static void client_fd_add(rbox_server_handle_t *server, int fd);
static void client_fd_remove(rbox_server_handle_t *server, int fd);
static void client_fd_close_all(rbox_server_handle_t *server);
rbox_client_fd_entry_t *client_fd_find(rbox_server_handle_t *server, int fd);
static int epoll_del(int epoll_fd, int fd);

/* ============================================================
 * CLIENT FD TRACKING
 * ============================================================ */

static void client_fd_add(rbox_server_handle_t *server, int fd) {
    rbox_client_fd_entry_t *entry = malloc(sizeof(*entry));
    if (!entry) return;
    entry->fd = fd;
    entry->pending_request = NULL;
    entry->header_start_time = 0;
    entry->waiting_for_header = 0;
    entry->prev = NULL;
    entry->send_queue_head = NULL;
    entry->send_queue_tail = NULL;
    pthread_mutex_lock(&server->client_fd_mutex);
    entry->next = server->client_fds;
    if (server->client_fds) {
        server->client_fds->prev = entry;
    }
    server->client_fds = entry;
    server->active_client_count++;
    pthread_mutex_unlock(&server->client_fd_mutex);
}

static void client_fd_remove(rbox_server_handle_t *server, int fd) {
    pthread_mutex_lock(&server->client_fd_mutex);
    rbox_client_fd_entry_t *entry = server->client_fds;
    while (entry) {
        if (entry->fd == fd) {
            if (entry->prev) {
                entry->prev->next = entry->next;
            } else {
                server->client_fds = entry->next;
            }
            if (entry->next) {
                entry->next->prev = entry->prev;
            }
            free(entry);
            server->active_client_count--;
            break;
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&server->client_fd_mutex);
}

static void client_fd_close_all(rbox_server_handle_t *server) {
    pthread_mutex_lock(&server->client_fd_mutex);
    rbox_client_fd_entry_t *entry = server->client_fds;
    while (entry) {
        close(entry->fd);
        rbox_client_fd_entry_t *next = entry->next;
        free(entry);
        entry = next;
    }
    server->client_fds = NULL;
    server->active_client_count = 0;
    pthread_mutex_unlock(&server->client_fd_mutex);
}

/* ============================================================
 * SEND QUEUE - For non-blocking responses
 * ============================================================ */

/* Clean up any send queue entries for a closed fd - uses per-client queue */
static void cleanup_pending_sends(rbox_server_handle_t *server, int fd) {
    rbox_client_fd_entry_t *entry = client_fd_find(server, fd);
    if (!entry) return;

    pthread_mutex_lock(&server->send_mutex);
    rbox_server_send_entry_t *send_entry = entry->send_queue_head;
    while (send_entry) {
        rbox_server_send_entry_t *next = send_entry->next;
        free(send_entry->data);
        if (send_entry->request) {
            send_entry->request->fd = -1;
            server_request_free(send_entry->request);
        }
        free(send_entry);
        send_entry = next;
    }
    entry->send_queue_head = NULL;
    entry->send_queue_tail = NULL;
    pthread_mutex_unlock(&server->send_mutex);

    entry->waiting_for_header = 0;
    entry->header_start_time = 0;
}

/* Centralized function to close a client connection and free all associated resources */
static void client_connection_close(rbox_server_handle_t *server, int fd) {
    rbox_client_fd_entry_t *entry = client_fd_find(server, fd);
    if (!entry) return;

    if (entry->pending_request) {
        server_request_free(entry->pending_request);
        entry->pending_request = NULL;
    }

    cleanup_pending_sends(server, fd);

    epoll_del(server->epoll_fd, fd);
    close(fd);
    client_fd_remove(server, fd);
}

/* ============================================================
 * CLIENT FD LOOKUP - For non‑blocking body reads and timeout
 * ============================================================ */

rbox_client_fd_entry_t *client_fd_find(rbox_server_handle_t *server, int fd) {
    pthread_mutex_lock(&server->client_fd_mutex);
    rbox_client_fd_entry_t *entry = server->client_fds;
    while (entry) {
        if (entry->fd == fd) {
            pthread_mutex_unlock(&server->client_fd_mutex);
            return entry;
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&server->client_fd_mutex);
    return NULL;
}

static void pending_request_set(rbox_server_handle_t *server, int fd, rbox_server_request_t *req) {
    rbox_client_fd_entry_t *entry = client_fd_find(server, fd);
    if (entry) {
        entry->pending_request = req;
    }
}

static rbox_server_request_t *pending_request_get(rbox_server_handle_t *server, int fd) {
    rbox_client_fd_entry_t *entry = client_fd_find(server, fd);
    return entry ? entry->pending_request : NULL;
}

static void pending_request_remove(rbox_server_handle_t *server, int fd) {
    rbox_client_fd_entry_t *entry = client_fd_find(server, fd);
    if (entry) {
        entry->pending_request = NULL;
    }
}

/* Attempt to read body data for a pending request.
 * Returns:
 *   1 - body fully read
 *   0 - still pending (EAGAIN or partial read)
 *  -1 - error (EOF or other error)
 */
static int read_body_nonblocking(rbox_server_handle_t *server, int fd, rbox_server_request_t *req) {
    (void)server;
    size_t remaining = req->body_expected - req->body_received;
    if (remaining == 0) return 1;

    ssize_t n = rbox_read_nonblocking(fd, req->command_data + req->body_received, remaining);
    if (n == -2) {
        DBG("read_body_nonblocking: EOF on fd %d", fd);
        return -1;
    }
    if (n < 0) {
        DBG("read_body_nonblocking: error on fd %d: %s", fd, strerror(errno));
        return -1;
    }
    if (n == 0) {
        return 0;
    }
    req->body_received += n;
    DBG("read_body_nonblocking: read %zd bytes, total now %zu/%zu", n, req->body_received, req->body_expected);
    return (req->body_received == req->body_expected) ? 1 : 0;
}

/* Attempt to read chunked body data for a pending request.
 * Returns:
 *   1 - all chunks fully read (request complete)
 *   0 - still pending (EAGAIN or partial read)
 *  -1 - error (EOF or other error)
 */
static int read_body_chunks_nonblocking(rbox_server_handle_t *server, int fd, rbox_server_request_t *req) {
    (void)server;
    while (1) {
        if (req->reading_chunk_header) {
            char header[RBOX_HEADER_SIZE];
            ssize_t n = rbox_read_nonblocking(fd, header, RBOX_HEADER_SIZE);
            if (n == 0) return 0;
            if (n == -2) return -1;
            if (n < 0) return -1;
            if (n != RBOX_HEADER_SIZE) return -1;
            uint32_t magic = *(uint32_t *)header;
            uint32_t version = *(uint32_t *)(header + 4);
            if (magic != RBOX_MAGIC || version != RBOX_VERSION) return -1;
            uint32_t chunk_len = *(uint32_t *)(header + RBOX_HEADER_OFFSET_CHUNK_LEN);
            uint32_t flags = *(uint32_t *)(header + RBOX_HEADER_OFFSET_FLAGS);
            if (chunk_len > RBOX_CHUNK_MAX) return -1;
            req->current_chunk_len = chunk_len;
            req->current_chunk_received = 0;
            req->last_flags = flags;
            req->reading_chunk_header = 0;
            if (chunk_len == 0) {
                req->reading_chunk_header = 1;
                continue;
            }
        }
        size_t remaining = req->current_chunk_len - req->current_chunk_received;
        ssize_t n = rbox_read_nonblocking(fd, req->command_data + req->body_received, remaining);
        if (n == -2) return -1;
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        if (n == 0) return 0;
        req->current_chunk_received += n;
        req->body_received += n;
        if (req->current_chunk_received == req->current_chunk_len) {
            req->reading_chunk_header = 1;
            if (req->last_flags & RBOX_FLAG_LAST) {
                req->command_data[req->body_received] = '\0';
                return 1;
            }
            continue;
        } else {
            return 0;
        }
    }
}

/* Process a completed request: check cache, parse env vars, queue request */
static void process_completed_request(rbox_server_handle_t *server, int fd, rbox_server_request_t *req) {
    uint32_t packet_checksum = (req->command_len > 0) ? rbox_calculate_checksum_crc32(0, req->command_data, req->command_len) : 0;
    uint64_t cmd_hash2 = (req->command_len > 0) ? rbox_hash64(req->command_data, req->command_len) : 0;
    uint8_t cached_decision;
    char cached_reason[256];
    uint32_t cached_duration;
    if (rbox_server_cache_lookup(server, req->client_id, req->request_id, packet_checksum,
                                req->cmd_hash, cmd_hash2, req->fenv_hash,
                                &cached_decision, cached_reason, &cached_duration)) {
        DBG("Cache hit for request on fd %d", fd);
        size_t resp_len;
        char *resp = rbox_server_build_response(req->client_id, req->request_id, req->cmd_hash,
            cached_decision, cached_reason, cached_duration,
            req->fenv_hash, 0, NULL, &resp_len);
        if (resp) {
            send_queue_add(server, fd, resp, resp_len, NULL);
        }
        server_request_free(req);
        return;
    }

    rbox_command_parse(req->command_data, req->command_len, &req->parse);

    const char *p = req->command_data;
    const char *args_end = req->command_data;
    while (p < req->command_data + req->command_len) {
        if (*p == '\0') {
            if (p == args_end || *(p-1) == '\0') {
                args_end = p + 1;
                break;
            }
            args_end = p + 1;
        }
        p++;
    }
    p = args_end;
    size_t remaining = req->command_len - (p - req->command_data);
    while (remaining > 5) {
        size_t name_len = strlen(p);
        if (name_len == 0 || name_len > remaining - 4) break;
        req->env_var_count++;
        p += name_len + 1 + 4;
        remaining -= name_len + 1 + 4;
    }
    if (req->env_var_count > 0) {
        req->env_var_names = calloc(req->env_var_count, sizeof(char *));
        req->env_var_scores = calloc(req->env_var_count, sizeof(float));
        p = args_end;
        remaining = req->command_len - (p - req->command_data);
        int idx = 0;
        while (remaining > 5 && idx < req->env_var_count) {
            size_t name_len = strlen(p);
            req->env_var_names[idx] = strndup(p, name_len);
            memcpy(&req->env_var_scores[idx], p + name_len + 1, 4);
            const char *s = req->env_var_names[idx];
            uint32_t h = 5381;
            while (*s) h = ((h << 5) + h) + (uint32_t)(unsigned char)*s++;
            req->fenv_hash ^= h;
            p += name_len + 1 + 4;
            remaining -= name_len + 1 + 4;
            idx++;
        }
    }

    pthread_mutex_lock(&server->mutex);
    req->next = NULL;
    if (server->request_tail) {
        server->request_tail->next = req;
        server->request_tail = req;
    } else {
        server->request_queue = req;
        server->request_tail = req;
    }
    server->request_count++;
    DBG("Queued request for fd %d (count=%d), signaling", fd, server->request_count);
    pthread_cond_signal(&server->cond);
    pthread_mutex_unlock(&server->mutex);
}

/* Try to send as much data as possible from the queue for a given fd.
 * Caller must hold send_mutex when calling this. */
static void send_pending_locked(rbox_server_handle_t *server, int fd) {
    rbox_client_fd_entry_t *client_entry = client_fd_find(server, fd);
    if (!client_entry) return;

    rbox_server_send_entry_t **prev = &client_entry->send_queue_head;
    rbox_server_send_entry_t *entry = client_entry->send_queue_head;
    while (entry) {
        size_t remaining = entry->len - entry->offset;
        ssize_t w = write(entry->fd, entry->data + entry->offset, remaining);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                DBG("send_pending_locked: write would block on fd %d", entry->fd);
                break;
            }
            DBG("send_pending_locked: write failed on fd %d: %s", entry->fd, strerror(errno));
            *prev = entry->next;
            if (!entry->next) client_entry->send_queue_tail = *prev;
            if (entry->request) {
                entry->request->fd = -1;
                server_request_free(entry->request);
            }
            free(entry->data);
            free(entry);
            entry = *prev;
            continue;
        } else if (w == 0) {
            DBG("send_pending_locked: write returned 0 on fd %d", entry->fd);
            *prev = entry->next;
            if (!entry->next) client_entry->send_queue_tail = *prev;
            if (entry->request) {
                entry->request->fd = -1;
                server_request_free(entry->request);
            }
            free(entry->data);
            free(entry);
            entry = *prev;
            continue;
        } else {
            entry->offset += w;
            DBG("send_pending_locked: wrote %zd bytes on fd %d, offset now %zu/%zu", w, entry->fd, entry->offset, entry->len);
            if (entry->offset == entry->len) {
                DBG("send_pending_locked: fully sent response for fd %d", entry->fd);
                *prev = entry->next;
                if (!entry->next) client_entry->send_queue_tail = *prev;
                if (entry->request) {
                    entry->request->fd = -1;
                    server_request_free(entry->request);
                }
                free(entry->data);
                free(entry);
                entry = *prev;
            } else {
                /* Partial write, stop trying to send more on this fd (socket buffer full) */
                break;
            }
        }
    }
}

static void try_send_pending(rbox_server_handle_t *server, int fd) {
    DBG("try_send_pending: attempting to send for fd %d", fd);
    pthread_mutex_lock(&server->send_mutex);
    send_pending_locked(server, fd);
    pthread_mutex_unlock(&server->send_mutex);
}

/* Add a response to the send queue and try to send immediately. */
static int send_queue_add(rbox_server_handle_t *server, int fd, char *data, size_t len, rbox_server_request_t *req) {
    rbox_server_send_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        free(data);
        if (req) server_request_free(req);
        return -1;
    }
    entry->fd = fd;
    entry->data = data;
    entry->len = len;
    entry->request = req;
    entry->offset = 0;
    entry->next = NULL;

    rbox_client_fd_entry_t *client_entry = client_fd_find(server, fd);
    if (!client_entry) {
        free(entry);
        free(data);
        if (req) server_request_free(req);
        return -1;
    }

    pthread_mutex_lock(&server->send_mutex);
    if (client_entry->send_queue_tail) {
        client_entry->send_queue_tail->next = entry;
        client_entry->send_queue_tail = entry;
    } else {
        client_entry->send_queue_head = entry;
        client_entry->send_queue_tail = entry;
    }
    pthread_mutex_unlock(&server->send_mutex);

    DBG("send_queue_add: added response for fd %d", fd);
    try_send_pending(server, fd);
    return 0;
}

/* ============================================================
 * REQUEST HELPERS
 * ============================================================ */

void server_request_free(rbox_server_request_t *req) {
    if (!req) return;
    free(req->command_data);
    if (req->env_var_names) {
        for (int i = 0; i < req->env_var_count; i++) free(req->env_var_names[i]);
        free(req->env_var_names);
    }
    free(req->env_var_scores);
    free(req);
}

/* Read header from client (v9 protocol) – non‑blocking version */
static int server_read_header(rbox_server_handle_t *server, int fd,
                               uint8_t *client_id, uint8_t *request_id, uint32_t *cmd_hash,
                               uint32_t *fenv_hash,
                               char *caller, size_t caller_len, char *syscall, size_t syscall_len,
                               uint32_t *chunk_len, uint32_t *flags, uint64_t *total_len) {
    char header[RBOX_HEADER_SIZE];
    rbox_client_fd_entry_t *entry = client_fd_find(server, fd);
    ssize_t n = rbox_read_nonblocking(fd, header, RBOX_HEADER_SIZE);
    if (n == 0) {
        if (entry && !entry->waiting_for_header) {
            entry->waiting_for_header = 1;
            entry->header_start_time = time(NULL);
            DBG("server_read_header: started header wait for fd %d", fd);
        }
        return 1;
    } else if (n != RBOX_HEADER_SIZE) {
        if (entry) entry->waiting_for_header = 0;
        if (n == -2) DBG("server_read_header: EOF on fd %d", fd);
        else DBG("server_read_header: error on fd %d", fd);
        return -1;
    }
    if (entry) entry->waiting_for_header = 0;
    uint32_t magic = *(uint32_t *)header;
    uint32_t version = *(uint32_t *)(header + 4);
    if (magic != RBOX_MAGIC || version != RBOX_VERSION) return -1;
    if (rbox_header_validate(header, RBOX_HEADER_SIZE) != RBOX_OK) return -1;
    memcpy(client_id, header + RBOX_HEADER_OFFSET_CLIENT_ID, 16);
    memcpy(request_id, header + RBOX_HEADER_OFFSET_REQUEST_ID, 16);
    *cmd_hash = *(uint32_t *)(header + RBOX_HEADER_OFFSET_CMD_HASH);
    *fenv_hash = *(uint32_t *)(header + RBOX_HEADER_OFFSET_FENV_HASH);
    uint8_t cs_size = *(uint8_t *)(header + RBOX_HEADER_OFFSET_CALLER_SYSCALL_SIZE);
    size_t caller_size = cs_size & 0x0F;
    size_t syscall_size = (cs_size >> 4) & 0x0F;
    if (caller && caller_len > 0) {
        size_t copy_len = caller_size < caller_len ? caller_size : caller_len;
        memcpy(caller, header + RBOX_HEADER_OFFSET_CALLER, copy_len);
        caller[copy_len] = '\0';
    }
    if (syscall && syscall_len > 0) {
        size_t copy_len = syscall_size < syscall_len ? syscall_size : syscall_len;
        memcpy(syscall, header + RBOX_HEADER_OFFSET_SYSCALL, copy_len);
        syscall[copy_len] = '\0';
    }
    *chunk_len = *(uint32_t *)(header + RBOX_HEADER_OFFSET_CHUNK_LEN);
    if (*chunk_len > 1024 * 1024) return -1;
    *flags = *(uint32_t *)(header + RBOX_HEADER_OFFSET_FLAGS);
    *total_len = *(uint64_t *)(header + RBOX_HEADER_OFFSET_TOTAL_LEN);
    return 0;
}

/* Remove from epoll */
int epoll_del(int epoll_fd, int fd) {
    struct epoll_event ev = {0};
    return epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ev);
}

/* ============================================================
 * LOCK-FREE DECISION QUEUE (Michael & Scott MPSC)
 * ============================================================ */

static int decision_queue_push(rbox_server_handle_t *server, rbox_server_decision_t *dec) {
    rbox_decision_queue_t *q = &server->decision_queue;
    rbox_decision_node_t *node = malloc(sizeof(*node));
    if (!node) return RBOX_ERR_MEMORY;
    node->decision = dec;
    atomic_store_explicit(&node->next, NULL, memory_order_relaxed);

    rbox_decision_node_t *tail, *next;
    while (1) {
        tail = atomic_load_explicit(&q->tail, memory_order_acquire);
        next = atomic_load_explicit(&tail->next, memory_order_acquire);
        if (next == NULL) {
            if (atomic_compare_exchange_weak_explicit(&tail->next, &next, node,
                                                      memory_order_release, memory_order_relaxed)) {
                atomic_compare_exchange_strong_explicit(&q->tail, &tail, node,
                                                        memory_order_release, memory_order_relaxed);
                break;
            }
        } else {
            atomic_compare_exchange_weak_explicit(&q->tail, &tail, next,
                                                  memory_order_release, memory_order_relaxed);
        }
    }
    return RBOX_OK;
}

static rbox_server_decision_t *decision_queue_pop(rbox_server_handle_t *server) {
    rbox_decision_queue_t *q = &server->decision_queue;
    rbox_decision_node_t *head, *next;

    while (1) {
        head = atomic_load_explicit(&q->head, memory_order_acquire);
        next = atomic_load_explicit(&head->next, memory_order_acquire);
        if (next == NULL) {
            return NULL;
        }
        if (atomic_compare_exchange_weak_explicit(&q->head, &head, next,
                                                  memory_order_acquire, memory_order_relaxed)) {
            rbox_server_decision_t *dec = next->decision;
            next->decision = NULL;
            free(head);
            return dec;
        }
    }
}

/* ============================================================
 * SERVER THREAD
 * ============================================================ */

static void *server_thread_func(void *arg) {
    rbox_server_handle_t *server = arg;
    struct epoll_event events[64];
    int loop_count = 0;
    time_t shutdown_start = 0;

    /* Make listen socket non‑blocking */
    int flags = fcntl(server->listen_fd, F_GETFL, 0);
    fcntl(server->listen_fd, F_SETFL, flags | O_NONBLOCK);

    server->epoll_fd = epoll_create1(0);
    if (server->epoll_fd < 0) return NULL;

    struct epoll_event lev = { .events = EPOLLIN, .data.fd = server->listen_fd };
    if (epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, server->listen_fd, &lev) < 0) {
        close(server->epoll_fd);
        return NULL;
    }
    DBG("Listen fd %d added to epoll", server->listen_fd);

    if (server->wake_fd >= 0) {
        struct epoll_event wev = { .events = EPOLLIN, .data.fd = server->wake_fd };
        epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, server->wake_fd, &wev);
        DBG("Wake fd %d added to epoll", server->wake_fd);
    }

    while (1) {
        loop_count++;
        DBG("=== Top of loop (count=%d) ===", loop_count);
        DBG("server->running = %d", atomic_load(&server->running));
        DBG("server->request_count = %d", server->request_count);
        DBG("active clients = %d", server->active_client_count);

        /* Process pending decisions (lock-free pop) */
        while (1) {
            rbox_server_decision_t *dec = decision_queue_pop(server);
            if (!dec) break;
            DBG("Processing decision for fd %d", dec->request ? dec->request->fd : -1);

            if (!dec->request) {
                free(dec);
                continue;
            }

            rbox_server_request_t *req = dec->request;
            size_t resp_len;
            uint32_t cmd_hash = req->cmd_hash;
            uint64_t cmd_hash2 = (req->command_data && req->command_len > 0) ? rbox_hash64(req->command_data, req->command_len) : 0;
            uint32_t packet_checksum = (req->command_data && req->command_len > 0) ? rbox_calculate_checksum_crc32(0, req->command_data, req->command_len) : 0;
            rbox_server_cache_insert(server, req->client_id, req->request_id, packet_checksum,
                                  cmd_hash, cmd_hash2, dec->fenv_hash, dec->decision, dec->reason, dec->duration);
            char *resp = rbox_server_build_response(req->client_id, req->request_id, cmd_hash,
                dec->decision, dec->reason, dec->duration,
                dec->fenv_hash, dec->env_decision_count, (uint8_t *)dec->env_decisions, &resp_len);
            if (resp) {
                DBG("Built response of size %zu for fd %d", resp_len, req->fd);
                if (send_queue_add(server, req->fd, resp, resp_len, req) != 0) {
                    DBG("send_queue_add failed for fd %d", req->fd);
                }
            } else {
                DBG("Failed to build response for fd %d", req->fd);
            }
            if (dec->env_decision_names) {
                for (int i = 0; i < dec->env_decision_count; i++) free(dec->env_decision_names[i]);
                free(dec->env_decision_names);
            }
            free(dec->env_decisions);
            free(dec);
        }

        /* If shutdown requested, check if we can exit */
        if (!atomic_load(&server->running)) {
            int pending_sends = 0;
            pthread_mutex_lock(&server->client_fd_mutex);
            rbox_client_fd_entry_t *entry = server->client_fds;
            while (entry) {
                rbox_server_send_entry_t *se = entry->send_queue_head;
                while (se) {
                    pending_sends++;
                    se = se->next;
                }
                entry = entry->next;
            }
            pthread_mutex_unlock(&server->client_fd_mutex);
            if (pending_sends == 0 && server->active_client_count == 0) {
                DBG("No pending sends and no active clients, exiting");
                break;
            }
            if (shutdown_start == 0) shutdown_start = time(NULL);
            if (time(NULL) - shutdown_start > 2) {
                DBG("Shutdown timeout reached, exiting with %d pending sends, %d active clients",
                    pending_sends, server->active_client_count);
                break;
            }
            DBG("Shutdown in progress, %d pending sends, %d active clients",
                pending_sends, server->active_client_count);
        } else {
            shutdown_start = 0;
        }

        /* Epoll wait and event handling */
        DBG("Calling epoll_wait (timeout=100)");
        int n = epoll_wait(server->epoll_fd, events, 64, 100);
        DBG("epoll_wait returned %d events", n);
        if (n < 0) {
            if (errno == EINTR) {
                DBG("epoll_wait interrupted by EINTR");
                continue;
            }
            DBG("epoll_wait error: %s", strerror(errno));
            break;
        }

        /* Check for header read timeouts before processing events */
        time_t now = time(NULL);
        pthread_mutex_lock(&server->client_fd_mutex);
        rbox_client_fd_entry_t *tentry = server->client_fds;
        while (tentry) {
            rbox_client_fd_entry_t *next = tentry->next;
            if (tentry->waiting_for_header && tentry->header_start_time > 0) {
                if (difftime(now, tentry->header_start_time) > 5.0) {
                    int fd = tentry->fd;
                    DBG("Header read timeout on fd %d, closing", fd);
                    pthread_mutex_unlock(&server->client_fd_mutex);
                    client_connection_close(server, fd);
                    pthread_mutex_lock(&server->client_fd_mutex);
                    tentry = server->client_fds;
                    continue;
                }
            }
            tentry = next;
        }
        pthread_mutex_unlock(&server->client_fd_mutex);

        if (n > 0) {
            for (int i = 0; i < n; i++) {
                struct epoll_event *ev = &events[i];
                DBG("  Event %d: fd=%d events=0x%x", i, ev->data.fd, ev->events);

                /* Listen socket – accept new connections only if still running */
                if (ev->data.fd == server->listen_fd) {
                    if (!atomic_load(&server->running)) {
                        /* Shutdown: ignore new connections */
                        continue;
                    }
                    while (1) {
                        struct sockaddr_un addr;
                        socklen_t addrlen = sizeof(addr);
                        int cl_fd = accept(server->listen_fd, (struct sockaddr *)&addr, &addrlen);
                        if (cl_fd < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                            DBG("accept failed: %s", strerror(errno));
                            break;
                        }
                        flags = fcntl(cl_fd, F_GETFL, 0);
                        fcntl(cl_fd, F_SETFL, flags | O_NONBLOCK);
                        client_fd_add(server, cl_fd);
                        rbox_client_fd_entry_t *new_entry = server->client_fds;
                        struct epoll_event cev = { .events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET, .data.ptr = new_entry };
                        epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, cl_fd, &cev);
                        DBG("Accepted fd %d", cl_fd);
                    }
                    continue;
                }

                if (server->wake_fd >= 0 && ev->data.fd == server->wake_fd) {
                    uint64_t val;
                    ssize_t r;
                    do { r = read(server->wake_fd, &val, sizeof(val)); } while (r < 0 && (errno == EINTR || errno == EAGAIN));
                    DBG("Drained wake_fd");
                    continue;
                }

                rbox_client_fd_entry_t *entry = (rbox_client_fd_entry_t *)ev->data.ptr;
                if (!entry) continue;
                int cl_fd = entry->fd;

                int closed = 0;

                /* Handle EPOLLIN first – read data before close */
                if (ev->events & EPOLLIN) {
                    DBG("EPOLLIN for fd %d", cl_fd);

                    /* Check for pending request */
                    rbox_server_request_t *pending = pending_request_get(server, cl_fd);
                    if (pending) {
                        int result;
                        if (pending->is_chunked) {
                            result = read_body_chunks_nonblocking(server, cl_fd, pending);
                        } else {
                            result = read_body_nonblocking(server, cl_fd, pending);
                        }
                        if (result == 1) {
                            DBG("Body fully read for pending request on fd %d", cl_fd);
                            pending->reading_body = 0;
                            pending_request_remove(server, cl_fd);
                            process_completed_request(server, cl_fd, pending);
                        } else if (result == -1) {
                            DBG("Body read error for pending request on fd %d", cl_fd);
                            client_connection_close(server, cl_fd);
                            closed = 1;
                        }
                        /* else result == 0, still pending – do nothing */
                        goto next_event;
                    }

                    /* No pending request – read header */
                    uint8_t client_id[16], request_id[16];
                    uint32_t cmd_hash, fenv_hash, chunk_len, flags;
                    uint64_t total_len;
                    char caller[RBOX_MAX_CALLER_LEN + 1];
                    char syscall[RBOX_MAX_SYSCALL_LEN + 1];

                    int hdr_result = server_read_header(server, cl_fd, client_id, request_id, &cmd_hash, &fenv_hash,
                        caller, sizeof(caller), syscall, sizeof(syscall), &chunk_len, &flags, &total_len);
                    if (hdr_result == 1) {
                        DBG("No data available on fd %d, skipping", cl_fd);
                        goto next_event;
                    } else if (hdr_result == -1) {
                        DBG("Header read failed on fd %d, cleaning up", cl_fd);
                        client_connection_close(server, cl_fd);
                        closed = 1;
                        goto next_event;
                    }

                    /* Check if this is a chunked transfer */
                    int is_chunked = (flags & RBOX_FLAG_FIRST) && chunk_len < total_len;

                    if (is_chunked) {
                        rbox_server_request_t *req = calloc(1, sizeof(*req));
                        if (!req) {
                            DBG("Failed to allocate request for chunked request on fd %d", cl_fd);
                            client_connection_close(server, cl_fd);
                            closed = 1;
                            goto next_event;
                        }
                        req->fd = cl_fd;
                        memcpy(req->client_id, client_id, 16);
                        memcpy(req->request_id, request_id, 16);
                        req->cmd_hash = cmd_hash;
                        req->server = server;
                        req->fenv_hash = fenv_hash;
                        strncpy(req->caller, caller, RBOX_MAX_CALLER_LEN);
                        req->caller[RBOX_MAX_CALLER_LEN] = '\0';
                        strncpy(req->syscall, syscall, RBOX_MAX_SYSCALL_LEN);
                        req->syscall[RBOX_MAX_SYSCALL_LEN] = '\0';
                        req->command_data = malloc(total_len + 1);
                        if (!req->command_data) {
                            free(req);
                            DBG("Failed to allocate command_data for chunked request on fd %d", cl_fd);
                            client_connection_close(server, cl_fd);
                            closed = 1;
                            goto next_event;
                        }
                        req->command_len = total_len;
                        req->body_expected = total_len;
                        req->body_received = 0;
                        req->reading_body = 1;
                        req->is_chunked = 1;
                        req->reading_chunk_header = 0;
                        req->current_chunk_len = chunk_len;
                        req->current_chunk_received = 0;
                        req->last_flags = flags;

                        int result = read_body_chunks_nonblocking(server, cl_fd, req);
                        if (result == 1) {
                            req->reading_body = 0;
                            pending_request_remove(server, cl_fd);
                            process_completed_request(server, cl_fd, req);
                        } else if (result == 0) {
                            pending_request_set(server, cl_fd, req);
                            DBG("Pending chunked request for fd %d", cl_fd);
                        } else {
                            DBG("Error reading first chunk for fd %d", cl_fd);
                            server_request_free(req);
                            client_connection_close(server, cl_fd);
                            closed = 1;
                        }
                        goto next_event;
                    }

                    /* Single-chunk request – use non‑blocking */
                    rbox_server_request_t *req = calloc(1, sizeof(*req));
                    if (!req) {
                        DBG("Failed to allocate request for fd %d", cl_fd);
                        client_connection_close(server, cl_fd);
                        closed = 1;
                        goto next_event;
                    }
                    req->fd = cl_fd;
                    memcpy(req->client_id, client_id, 16);
                    memcpy(req->request_id, request_id, 16);
                    req->cmd_hash = cmd_hash;
                    req->server = server;
                    req->fenv_hash = fenv_hash;
                    strncpy(req->caller, caller, RBOX_MAX_CALLER_LEN);
                    req->caller[RBOX_MAX_CALLER_LEN] = '\0';
                    strncpy(req->syscall, syscall, RBOX_MAX_SYSCALL_LEN);
                    req->syscall[RBOX_MAX_SYSCALL_LEN] = '\0';

                    req->command_data = malloc(chunk_len + 1);
                    if (!req->command_data) {
                        free(req);
                        client_connection_close(server, cl_fd);
                        closed = 1;
                        goto next_event;
                    }
                    req->command_len = chunk_len;

                    /* Set up body reading state */
                    req->reading_body = 1;
                    req->body_expected = chunk_len;
                    req->body_received = 0;
                    req->is_chunked = 0;
                    req->reading_chunk_header = 0;
                    req->current_chunk_len = 0;
                    req->current_chunk_received = 0;

                    /* Attempt to read body non‑blocking */
                    int read_result = read_body_nonblocking(server, cl_fd, req);
                    if (read_result == 1) {
                        req->reading_body = 0;
                        process_completed_request(server, cl_fd, req);
                    } else if (read_result == 0) {
                        pending_request_set(server, cl_fd, req);
                        DBG("Pending request for fd %d (body %zu/%zu)", cl_fd, req->body_received, req->body_expected);
                    } else {
                        DBG("Error reading body for fd %d", cl_fd);
                        server_request_free(req);
                        client_connection_close(server, cl_fd);
                        closed = 1;
                    }
                    goto next_event;
                }

                    /* Handle EPOLLOUT after EPOLLIN */
                if (!closed && (ev->events & EPOLLOUT)) {
                    DBG("EPOLLOUT for fd %d", cl_fd);
                    try_send_pending(server, cl_fd);
                    /* After sending, check for EOF using MSG_PEEK */
                    char buf;
                    ssize_t r = recv(cl_fd, &buf, 1, MSG_PEEK | MSG_DONTWAIT);
                    if (r == 0) {
                        DBG("EPOLLOUT: detected EOF on fd %d, cleaning up", cl_fd);
                        client_connection_close(server, cl_fd);
                        closed = 1;
                    } else if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        DBG("EPOLLOUT: recv peek error on fd %d: %s", cl_fd, strerror(errno));
                        client_connection_close(server, cl_fd);
                        closed = 1;
                    }
                }

                /* If we get here, no EPOLLIN, so handle errors/hangup */
                if (!closed && (ev->events & (EPOLLERR | EPOLLHUP))) {
                    DBG("EPOLLHUP/ERR on fd %d, cleaning up", cl_fd);
                    client_connection_close(server, cl_fd);
                    DBG("Closed fd %d", cl_fd);
                }

                next_event: ;
            }
        }

        /* After event processing, handle decisions again (lock-free pop) */
        while (1) {
            rbox_server_decision_t *dec = decision_queue_pop(server);
            if (!dec) break;
            DBG("Processing decision for fd %d (after events)", dec->request ? dec->request->fd : -1);

            if (!dec->request) {
                free(dec);
                continue;
            }

            rbox_server_request_t *req = dec->request;
            size_t resp_len;
            uint32_t cmd_hash = req->cmd_hash;
            uint64_t cmd_hash2 = (req->command_data && req->command_len > 0) ? rbox_hash64(req->command_data, req->command_len) : 0;
            uint32_t packet_checksum = (req->command_data && req->command_len > 0) ? rbox_calculate_checksum_crc32(0, req->command_data, req->command_len) : 0;
            rbox_server_cache_insert(server, req->client_id, req->request_id, packet_checksum,
                                  cmd_hash, cmd_hash2, dec->fenv_hash, dec->decision, dec->reason, dec->duration);
            char *resp = rbox_server_build_response(req->client_id, req->request_id, cmd_hash,
                dec->decision, dec->reason, dec->duration,
                dec->fenv_hash, dec->env_decision_count, (uint8_t *)dec->env_decisions, &resp_len);
            if (resp) {
                DBG("Built response of size %zu for fd %d", resp_len, req->fd);
                if (send_queue_add(server, req->fd, resp, resp_len, req) != 0) {
                    DBG("send_queue_add failed for fd %d", req->fd);
                }
            } else {
                DBG("Failed to build response for fd %d", req->fd);
            }
            if (dec->env_decision_names) {
                for (int i = 0; i < dec->env_decision_count; i++) free(dec->env_decision_names[i]);
                free(dec->env_decision_names);
            }
            free(dec->env_decisions);
            free(dec);
        }
    }

    /* Final cleanup: close any remaining client fds (should be none) */
    client_fd_close_all(server);
    DBG("Exiting server thread (running=%d)", atomic_load(&server->running));
    close(server->epoll_fd);
    return NULL;
}

/* ============================================================
 * SERVER HANDLE MANAGEMENT
 * ============================================================ */

rbox_server_handle_t *rbox_server_handle_new(const char *socket_path) {
    if (!socket_path) return NULL;
    rbox_server_handle_t *srv = calloc(1, sizeof(*srv));
    if (!srv) return NULL;
    strncpy(srv->socket_path, socket_path, sizeof(srv->socket_path) - 1);
    srv->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv->listen_fd < 0) { free(srv); return NULL; }
    unlink(socket_path);
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    if (bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(srv->listen_fd);
        free(srv);
        return NULL;
    }
    pthread_mutex_init(&srv->mutex, NULL);
    pthread_cond_init(&srv->cond, NULL);
    pthread_mutex_init(&srv->cache_mutex, NULL);
    pthread_mutex_init(&srv->send_mutex, NULL);
    pthread_mutex_init(&srv->client_fd_mutex, NULL);
    atomic_flag_clear(&srv->stop_flag);
    srv->client_fds = NULL;
    srv->active_client_count = 0;
    rbox_server_cache_init(srv);

    rbox_decision_node_t *dummy = malloc(sizeof(*dummy));
    if (!dummy) {
        pthread_mutex_destroy(&srv->mutex);
        pthread_cond_destroy(&srv->cond);
        pthread_mutex_destroy(&srv->cache_mutex);
        pthread_mutex_destroy(&srv->send_mutex);
        pthread_mutex_destroy(&srv->client_fd_mutex);
        close(srv->listen_fd);
        free(srv);
        return NULL;
    }
    dummy->decision = NULL;
    atomic_store_explicit(&dummy->next, NULL, memory_order_relaxed);
    atomic_store_explicit(&srv->decision_queue.head, dummy, memory_order_relaxed);
    atomic_store_explicit(&srv->decision_queue.tail, dummy, memory_order_relaxed);

    srv->wake_fd = eventfd(0, EFD_NONBLOCK);
    if (srv->wake_fd < 0) srv->wake_fd = -1;
    return srv;
}

rbox_error_t rbox_server_handle_listen(rbox_server_handle_t *server) {
    if (!server) return RBOX_ERR_INVALID;
    if (listen(server->listen_fd, 10) < 0) return RBOX_ERR_IO;
    return RBOX_OK;
}

void rbox_server_handle_free(rbox_server_handle_t *server) {
    if (!server) return;

    /* Drain and free any pending requests in the queue */
    pthread_mutex_lock(&server->mutex);
    rbox_server_request_t *req = server->request_queue;
    while (req) {
        rbox_server_request_t *next = req->next;
        /* cmd_data is owned by request, free it */
        free(req->command_data);
        /* Free env var names and scores if present */
        if (req->env_var_names) {
            for (int i = 0; i < req->env_var_count; i++) free(req->env_var_names[i]);
            free(req->env_var_names);
            free(req->env_var_scores);
        }
        free(req);
        req = next;
    }
    server->request_queue = server->request_tail = NULL;
    server->request_count = 0;
    pthread_mutex_unlock(&server->mutex);

    if (server->listen_fd >= 0) {
        close(server->listen_fd);
        unlink(server->socket_path);
    }
    if (server->wake_fd >= 0) close(server->wake_fd);

    /* Free any pending requests from client list */
    pthread_mutex_lock(&server->client_fd_mutex);
    rbox_client_fd_entry_t *entry = server->client_fds;
    while (entry) {
        if (entry->pending_request) {
            server_request_free(entry->pending_request);
            entry->pending_request = NULL;
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&server->client_fd_mutex);

    /* Drain the lock-free decision queue */
    rbox_decision_node_t *node = atomic_load_explicit(&server->decision_queue.head, memory_order_acquire);
    while (node) {
        rbox_decision_node_t *next = atomic_load_explicit(&node->next, memory_order_acquire);
        if (node->decision) free(node->decision);
        free(node);
        node = next;
    }

    /* Destroy response cache */
    rbox_server_cache_destroy(server);

    pthread_mutex_destroy(&server->mutex);
    pthread_cond_destroy(&server->cond);
    pthread_mutex_destroy(&server->cache_mutex);
    pthread_mutex_destroy(&server->send_mutex);
    pthread_mutex_destroy(&server->client_fd_mutex);
    free(server);
}

rbox_error_t rbox_server_start(rbox_server_handle_t *server) {
    if (!server) return RBOX_ERR_INVALID;
    atomic_store(&server->running, 1);
    server->request_queue = server->request_tail = NULL;
    server->request_count = 0;
    if (pthread_create(&server->thread, NULL, server_thread_func, server) != 0) {
        atomic_store(&server->running, 0);
        return RBOX_ERR_IO;
    }
    return RBOX_OK;
}

rbox_server_request_t *rbox_server_get_request(rbox_server_handle_t *server) {
    if (!server) return NULL;
    pthread_mutex_lock(&server->mutex);
    while (atomic_load(&server->running) && server->request_count == 0) {
        pthread_cond_wait(&server->cond, &server->mutex);
    }
    if (!atomic_load(&server->running)) {
        pthread_mutex_unlock(&server->mutex);
        return NULL;
    }
    rbox_server_request_t *req = server->request_queue;
    server->request_queue = req->next;
    if (!server->request_queue) server->request_tail = NULL;
    req->next = NULL;
    server->request_count--;
    pthread_mutex_unlock(&server->mutex);
    return req;
}

int rbox_server_is_running(rbox_server_handle_t *server) {
    return server ? atomic_load(&server->running) : 0;
}

rbox_error_t rbox_server_decide(rbox_server_request_t *req,
    uint8_t decision, const char *reason, uint32_t duration,
    int env_decision_count, const char **env_decision_names, const uint8_t *env_decisions) {
    if (!req) return RBOX_ERR_INVALID;
    rbox_server_handle_t *server = req->server;
    if (!server) return RBOX_ERR_INVALID;

    rbox_server_decision_t *dec = calloc(1, sizeof(*dec));
    if (!dec) return RBOX_ERR_MEMORY;
    dec->request = req;
    dec->decision = decision;
    strncpy(dec->reason, reason ? reason : "", sizeof(dec->reason) - 1);
    dec->duration = duration;
    dec->ready = 1;

    if (env_decision_count > 0 && env_decision_names && env_decisions) {
        dec->env_decision_count = env_decision_count;
        dec->env_decision_names = calloc(env_decision_count, sizeof(char *));
        if (!dec->env_decision_names) { free(dec); return RBOX_ERR_MEMORY; }
        for (int i = 0; i < env_decision_count; i++) {
            if (env_decision_names[i]) dec->env_decision_names[i] = strdup(env_decision_names[i]);
        }
        size_t bitmap_size = (env_decision_count + 7) / 8;
        dec->env_decisions = malloc(bitmap_size);
        if (!dec->env_decisions) {
            for (int i = 0; i < env_decision_count; i++) free(dec->env_decision_names[i]);
            free(dec->env_decision_names);
            free(dec);
            return RBOX_ERR_MEMORY;
        }
        memcpy(dec->env_decisions, env_decisions, bitmap_size);
        dec->fenv_hash = 0;
        for (int i = 0; i < env_decision_count; i++) {
            if (env_decision_names[i]) {
                const char *s = env_decision_names[i];
                uint32_t h = 5381;
                while (*s) h = ((h << 5) + h) + (uint32_t)(unsigned char)*s++;
                dec->fenv_hash ^= h;
            }
        }
    }

    if (decision_queue_push(server, dec) != RBOX_OK) {
        if (dec->env_decision_names) {
            for (int i = 0; i < dec->env_decision_count; i++) free(dec->env_decision_names[i]);
            free(dec->env_decision_names);
        }
        free(dec->env_decisions);
        free(dec);
        return RBOX_ERR_MEMORY;
    }

    if (server->wake_fd >= 0) {
        uint64_t val = 1;
        ssize_t r;
        do { r = write(server->wake_fd, &val, sizeof(val)); } while (r < 0 && (errno == EINTR || errno == EAGAIN));
    }
    return RBOX_OK;
}

void rbox_server_stop(rbox_server_handle_t *server) {
    if (!server) return;

    /* Use atomic flag to ensure only one caller wins the shutdown */
    if (atomic_flag_test_and_set(&server->stop_flag)) {
        /* Already set - another thread already called stop */
        return;
    }

    atomic_store(&server->running, 0);
    pthread_mutex_lock(&server->mutex);
    pthread_cond_signal(&server->cond);
    pthread_mutex_unlock(&server->mutex);
    if (server->wake_fd >= 0) {
        uint64_t val = 1;
        ssize_t n = write(server->wake_fd, &val, sizeof(val));
        (void)n;
    }
    if (server->thread) {
        pthread_join(server->thread, NULL);
        server->thread = 0;
    }
}

/* ============================================================
 * SERVER REQUEST ACCESSORS
 * ============================================================ */
const char *rbox_server_request_command(const rbox_server_request_t *req) {
    return req ? req->command_data : NULL;
}

const char *rbox_server_request_arg(const rbox_server_request_t *req, int index) {
    uint32_t len;
    if (!req || index < 0 || (uint32_t)index >= req->parse.count) return NULL;
    return rbox_get_subcommand(req->command_data, &req->parse.subcommands[index], &len);
}

int rbox_server_request_argc(const rbox_server_request_t *req) {
    return req ? (int)req->parse.count : 0;
}

const rbox_parse_result_t *rbox_server_request_parse(const rbox_server_request_t *req) {
    return req ? &req->parse : NULL;
}

const char *rbox_server_request_caller(const rbox_server_request_t *req) {
    return req ? req->caller : NULL;
}

const char *rbox_server_request_syscall(const rbox_server_request_t *req) {
    return req ? req->syscall : NULL;
}

int rbox_server_request_is_stop(const rbox_server_request_t *req) {
    if (!req || !req->command_data) return 0;
    return (strcmp(req->command_data, "__RBOX_STOP__") == 0);
}

int rbox_server_request_env_var_count(const rbox_server_request_t *req) {
    return req ? req->env_var_count : 0;
}

char *rbox_server_request_env_var_name(const rbox_server_request_t *req, int index) {
    if (!req || index < 0 || index >= req->env_var_count) return NULL;
    if (!req->env_var_names || !req->env_var_names[index]) return NULL;
    return strdup(req->env_var_names[index]);
}

float rbox_server_request_env_var_score(const rbox_server_request_t *req, int index) {
    if (!req || index < 0 || index >= req->env_var_count) return 0.0f;
    if (!req->env_var_scores) return 0.0f;
    return req->env_var_scores[index];
}
