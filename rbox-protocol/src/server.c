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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/eventfd.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <stdatomic.h>

#include "rbox_protocol.h"
#include "socket.h"
#include "runtime.h"
#include "packet.h"
#include "server.h"
#include "server_cache.h"
#include "server_response.h"
#include "server_client.h"

/* Debug flag – set to 1 to enable verbose tracing */
#ifndef RBOX_SERVER_DEBUG
#define RBOX_SERVER_DEBUG 0
#endif

#if RBOX_SERVER_DEBUG
#define DBG(fmt, ...) fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define DBG(fmt, ...) ((void)0)
#endif

uint64_t get_time_ms(void);

static int send_queue_add(rbox_server_handle_t *server, int fd, char *data, size_t len, rbox_server_request_t *req);
static void try_send_pending(rbox_server_handle_t *server, int fd);

/* ============================================================
 * REQUEST POOL - Simple free list (single-threaded)
 * NOTE: This pool is used exclusively from the server thread.
 * All access is from server_thread_func - no external threads
 * access this pool, so no atomic operations or locking needed.
 * ============================================================ */

int request_pool_init(rbox_server_handle_t *server, size_t max_requests) {
    rbox_request_pool_t *pool = &server->request_pool;
    pool->free_list = NULL;
    pool->available = 0;
    pool->max_requests = max_requests;

    rbox_server_request_t *prev = NULL;
    size_t allocated = 0;
    for (size_t i = 0; i < max_requests; i++) {
        rbox_server_request_t *req = calloc(1, sizeof(*req));
        if (!req) break;
        req->next = prev;
        prev = req;
        allocated++;
    }
    pool->free_list = prev;
    pool->available = allocated;
    return (allocated > 0) ? (int)allocated : -1;
}

rbox_server_request_t *request_pool_get(rbox_server_handle_t *server) {
    rbox_request_pool_t *pool = &server->request_pool;
    rbox_server_request_t *head = pool->free_list;
    if (!head) {
        /* Pool exhausted - allocate directly */
        rbox_server_request_t *req = calloc(1, sizeof(*req));
        if (req) {
            req->server = server;
            req->using_internal_buf = 1;
            req->command_data = req->internal_buf;
        }
        return req;
    }

    pool->free_list = head->next;
    pool->available--;

    /* Reset request state */
    head->fd = 0;
    memset(head->client_id, 0, 16);
    memset(head->request_id, 0, 16);
    head->cmd_hash = 0;
    head->server = server;
    memset(head->caller, 0, sizeof(head->caller));
    memset(head->syscall, 0, sizeof(head->syscall));
    head->command_data = NULL;
    head->command_len = 0;
    memset(&head->parse, 0, sizeof(head->parse));
    head->env_var_count = 0;
    head->env_var_names = NULL;
    head->env_var_scores = NULL;
    head->fenv_hash = 0;
    head->reading_body = 0;
    head->body_expected = 0;
    head->body_received = 0;
    head->is_chunked = 0;
    head->reading_chunk_header = 0;
    head->current_chunk_len = 0;
    head->current_chunk_received = 0;
    head->last_flags = 0;
    head->using_internal_buf = 1;
    head->command_data = head->internal_buf;
    memset(head->internal_buf, 0, sizeof(head->internal_buf));
    head->next = NULL;
    return head;
}

void request_pool_put(rbox_server_handle_t *server, rbox_server_request_t *req) {
    if (!req) return;

    if (!req->using_internal_buf && req->command_data) {
        free(req->command_data);
    }
    free(req->env_var_names);
    free(req->env_var_scores);

    rbox_request_pool_t *pool = &server->request_pool;

    /* If pool is full, free the request */
    if (pool->available >= pool->max_requests) {
        free(req);
        return;
    }

    /* Reset and push to pool */
    req->using_internal_buf = 1;
    req->command_data = req->internal_buf;
    req->env_var_names = NULL;
    req->env_var_scores = NULL;
    req->env_var_count = 0;
    req->command_len = 0;
    req->next = pool->free_list;
    pool->free_list = req;
    pool->available++;
}

void request_pool_destroy(rbox_server_handle_t *server) {
    rbox_request_pool_t *pool = &server->request_pool;
    rbox_server_request_t *head = pool->free_list;
    while (head) {
        rbox_server_request_t *next = head->next;
        if (head->using_internal_buf == 0 && head->command_data) {
            free(head->command_data);
        }
        free(head->env_var_names);
        free(head->env_var_scores);
        free(head);
        head = next;
    }
    pool->free_list = NULL;
    pool->available = 0;
}

/* ============================================================
 * SEND ENTRY POOL - Simple free list (single-threaded)
 * NOTE: This pool is used exclusively from the server thread.
 * All access is from server_thread_func - no external threads
 * access this pool, so no atomic operations or locking needed.
 * ============================================================ */

int send_pool_init(rbox_server_handle_t *server, size_t max_entries) {
    rbox_send_pool_t *pool = &server->send_pool;
    pool->free_list = NULL;
    pool->available = 0;
    pool->max_entries = max_entries;

    rbox_server_send_entry_t *prev = NULL;
    size_t allocated = 0;
    for (size_t i = 0; i < max_entries; i++) {
        rbox_server_send_entry_t *entry = calloc(1, sizeof(*entry));
        if (!entry) break;
        entry->next = prev;
        prev = entry;
        allocated++;
    }
    pool->free_list = prev;
    pool->available = allocated;
    return (allocated > 0) ? (int)allocated : -1;
}

rbox_server_send_entry_t *send_pool_get(rbox_server_handle_t *server) {
    rbox_send_pool_t *pool = &server->send_pool;
    rbox_server_send_entry_t *head = pool->free_list;
    if (!head) {
        rbox_server_send_entry_t *entry = calloc(1, sizeof(*entry));
        if (entry) {
            entry->using_internal_buf = 0;
        }
        return entry;
    }

    pool->free_list = head->next;
    pool->available--;

    head->fd = 0;
    head->data = NULL;
    head->len = 0;
    head->offset = 0;
    head->request = NULL;
    head->using_internal_buf = 0;
    memset(head->internal_buf, 0, sizeof(head->internal_buf));
    head->next = NULL;
    return head;
}

void send_pool_put(rbox_server_handle_t *server, rbox_server_send_entry_t *entry) {
    if (!entry) return;

    if (entry->using_internal_buf == 0 && entry->data) {
        free(entry->data);
    }
    entry->data = NULL;
    entry->using_internal_buf = 0;

    rbox_send_pool_t *pool = &server->send_pool;

    if (pool->available >= pool->max_entries) {
        free(entry);
        return;
    }

    entry->next = pool->free_list;
    pool->free_list = entry;
    pool->available++;
}

void send_pool_destroy(rbox_server_handle_t *server) {
    rbox_send_pool_t *pool = &server->send_pool;
    rbox_server_send_entry_t *head = pool->free_list;
    while (head) {
        rbox_server_send_entry_t *next = head->next;
        if (head->using_internal_buf == 0 && head->data) {
            free(head->data);
        }
        free(head);
        head = next;
    }
    pool->free_list = NULL;
    pool->available = 0;
}

/* ============================================================
 * CLIENT FD TRACKING
 * These functions are now in server_client.c
 * ============================================================ */

/* Functions moved to server_client.c:
 * - client_fd_add
 * - client_fd_remove
 * - client_fd_close_all
 * - client_fd_find
 * - cleanup_pending_sends
 * - client_connection_close
 * - send_queue_enqueue
 * - send_queue_dequeue
 * - send_queue_peek
 */

static void pending_request_set(rbox_server_handle_t *server, int fd, rbox_server_request_t *req) {
    rbox_client_fd_entry_t *entry = client_fd_find(server, fd);
    if (entry) {
        entry->pending_request = req;
        if (req->reading_body && entry->body_start_time == 0) {
            entry->body_start_time = get_time_ms();
        }
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
        entry->body_start_time = 0;
    }
}

/* Attempt to read body data for a pending request.
 * Returns:
 *   1 - body fully read
 *   0 - still pending (EAGAIN or partial read)
 *  -1 - error (EOF or other error)
 */
static int read_body_nonblocking(rbox_server_handle_t *server, int fd, rbox_server_request_t *req) {
    if (req->body_expected == req->body_received) return 1;

    rbox_client_fd_entry_t *entry = client_fd_find(server, fd);

    while (req->body_received < req->body_expected) {
        size_t remaining = req->body_expected - req->body_received;
        ssize_t n = rbox_read_nonblocking(fd, req->command_data + req->body_received, remaining);
        if (n == 0) {
            DBG("read_body_nonblocking: EOF on fd %d", fd);
            return -1;
        }
        if (n == -1) {
            DBG("read_body_nonblocking: EAGAIN on fd %d, returning partial", fd);
            return 0;
        }
        if (n == -2) {
            DBG("read_body_nonblocking: error on fd %d: %s", fd, strerror(errno));
            return -1;
        }
        req->body_received += (size_t)n;
        if (entry) entry->last_activity = get_time_ms();
    }
    DBG("read_body_nonblocking: body complete %zu bytes", req->body_received);
    uint32_t computed_crc = rbox_runtime_crc32(0, req->command_data, req->body_received);
    if (computed_crc != req->body_checksum) {
        DBG("Single-chunk body checksum mismatch: expected %u, got %u",
            req->body_checksum, computed_crc);
        return -1;
    }
    req->command_data[req->body_received] = '\0';
    return 1;
}

/* Attempt to read chunked body data for a pending request.
 * Returns:
 *   1 - all chunks fully read (request complete)
 *   0 - still pending (EAGAIN or partial read)
 *  -1 - error (EOF or other error)
 */
static int read_body_chunks_nonblocking(rbox_server_handle_t *server, int fd, rbox_server_request_t *req) {
    while (1) {
        if (req->reading_chunk_header) {
            /* Incremental chunk header read using per-request buffer. */
            while (req->chunk_header_bytes_read < RBOX_HEADER_SIZE) {
                ssize_t n = rbox_read_nonblocking(fd,
                                req->chunk_header_buf + req->chunk_header_bytes_read,
                                RBOX_HEADER_SIZE - req->chunk_header_bytes_read);
                if (n == 0) return -1;      /* EOF */
                if (n == -1) return 0;      /* EAGAIN – partial, wait */
                if (n == -2) return -1;     /* error */
                req->chunk_header_bytes_read += (size_t)n;
                rbox_client_fd_entry_t *centry = client_fd_find(server, fd);
                if (centry) centry->last_activity = get_time_ms();
            }

            /* Full chunk header received – validate */
            char *header = req->chunk_header_buf;
            req->chunk_header_bytes_read = 0;
            uint32_t magic = *(uint32_t *)header;
            uint32_t version = *(uint32_t *)(header + 4);
            if (magic != RBOX_MAGIC || version != RBOX_VERSION) return -1;
            uint32_t stored_checksum = *(uint32_t *)(header + RBOX_HEADER_OFFSET_CHECKSUM);
            uint32_t computed_checksum = rbox_runtime_crc32(0, header, RBOX_HEADER_OFFSET_CHECKSUM);
            if (stored_checksum != computed_checksum) {
                DBG("Chunk header checksum mismatch");
                return -1;
            }
            {
                rbox_client_fd_entry_t *hentry = client_fd_find(server, fd);
                if (hentry) hentry->last_activity = get_time_ms();
            }
            uint32_t chunk_len = *(uint32_t *)(header + RBOX_HEADER_OFFSET_CHUNK_LEN);
            uint32_t flags = *(uint32_t *)(header + RBOX_HEADER_OFFSET_FLAGS);
            uint64_t chunk_offset = *(uint64_t *)(header + RBOX_HEADER_OFFSET_OFFSET);
            if (chunk_offset != req->body_received) {
                DBG("Chunk offset mismatch: expected %zu, got %lu", req->body_received, chunk_offset);
                return -1;
            }
            uint32_t body_checksum = *(uint32_t *)(header + RBOX_HEADER_OFFSET_BODY_CHECKSUM);
            uint8_t *chunk_request_id = (uint8_t *)(header + 24);
            if (memcmp(req->original_request_id, chunk_request_id, 16) != 0) {
                DBG("Chunk request_id mismatch");
                return -1;
            }
            if (chunk_len > RBOX_CHUNK_MAX) return -1;
            if (req->body_received + chunk_len > req->body_expected) return -1;
            req->current_chunk_len = chunk_len;
            req->current_chunk_received = 0;
            req->current_chunk_checksum = body_checksum;
            req->last_flags = flags;
            req->reading_chunk_header = 0;
            if (chunk_len == 0) {
                req->reading_chunk_header = 1;
                continue;
            }
        }
        size_t remaining = req->current_chunk_len - req->current_chunk_received;
        ssize_t n = rbox_read_nonblocking(fd, req->command_data + req->body_received, remaining);
        if (n == 0) return -1;
        if (n == -1) return 0;
        if (n == -2) return -1;
        req->current_chunk_received += n;
        req->body_received += n;
        rbox_client_fd_entry_t *entry = client_fd_find(server, fd);
        if (entry) entry->last_activity = get_time_ms();
        if (req->current_chunk_received == req->current_chunk_len) {
            uint32_t computed_crc = rbox_runtime_crc32(0, req->command_data + req->body_received - req->current_chunk_len, req->current_chunk_len);
            if (computed_crc != req->current_chunk_checksum) {
                DBG("Chunk body checksum mismatch: expected %u, got %u", req->current_chunk_checksum, computed_crc);
                return -1;
            }
            req->reading_chunk_header = 1;
            if (req->last_flags & RBOX_FLAG_LAST) {
                if (req->body_received != req->body_expected) {
                    DBG("Chunked body truncated: expected %zu, got %zu",
                        req->body_expected, req->body_received);
                    return -1;
                }
                req->command_data[req->body_received] = '\0';
                return 1;
            }
            continue;
        } else {
            return 0;
        }
    }
}

/* Forward declaration for request queue push */
static int request_queue_push(rbox_server_handle_t *server, rbox_server_request_t *req);

/* Process a completed request: check cache, parse env vars, queue request */
static void process_completed_request(rbox_server_handle_t *server, int fd, rbox_server_request_t *req) {
    uint32_t packet_checksum = (req->command_len > 0) ? rbox_runtime_crc32(0, req->command_data, req->command_len) : 0;
    uint64_t cmd_hash2 = (req->command_len > 0) ? rbox_hash64(req->command_data, req->command_len) : 0;
    uint8_t cached_decision;
    char cached_reason[256];
    uint32_t cached_duration;
    int cached_env_decision_count = 0;
    uint8_t *cached_env_decisions = NULL;
    if (rbox_server_cache_lookup(server, req->client_id, req->request_id, packet_checksum,
                                req->cmd_hash, cmd_hash2, req->fenv_hash,
                                &cached_decision, cached_reason, &cached_duration,
                                &cached_env_decision_count, &cached_env_decisions)) {
        DBG("Cache hit for request on fd %d", fd);
        size_t resp_len;
        char *resp = rbox_server_build_response(req->client_id, req->request_id, req->cmd_hash,
            cached_decision, cached_reason,
            req->fenv_hash, cached_env_decision_count, cached_env_decisions, &resp_len);
        free(cached_env_decisions);
        if (resp) {
            send_queue_add(server, fd, resp, resp_len, NULL);
        }
        server_request_free(req);
        return;
    }

    /* First, find args_end to know where argv ends (before env vars) */
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
    size_t args_len = args_end - req->command_data;

    if (rbox_command_parse(req->command_data, args_len, &req->parse) != RBOX_OK) {
        DBG("Failed to parse command from fd %d", fd);
        size_t resp_len;
        char *resp = rbox_server_build_response(req->client_id, req->request_id, req->cmd_hash,
            RBOX_DECISION_DENY, "parse error",
            req->fenv_hash, 0, NULL, &resp_len);
        if (resp) {
            send_queue_add(server, fd, resp, resp_len, NULL);
        }
        server_request_free(req);
        return;
    }

    p = args_end;
    size_t remaining = req->command_len - (p - req->command_data);
    while (remaining > 5) {
        if (p >= req->command_data + req->command_len) break;
        size_t name_len = strnlen(p, remaining);
        if (name_len == 0 || name_len + 5 > remaining) break;
        req->env_var_count++;
        p += name_len + 1 + 4;
        remaining -= name_len + 1 + 4;
    }
    if (req->env_var_count > 0) {
        req->env_var_names = calloc(req->env_var_count, sizeof(const char *));
        req->env_var_scores = calloc(req->env_var_count, sizeof(float));
        if (!req->env_var_names || !req->env_var_scores) {
            free(req->env_var_names);
            free(req->env_var_scores);
            req->env_var_names = NULL;
            req->env_var_scores = NULL;
            req->env_var_count = 0;
            size_t resp_len;
            char *resp = rbox_server_build_response(req->client_id, req->request_id, req->cmd_hash,
                RBOX_DECISION_DENY, "memory allocation failed",
                req->fenv_hash, 0, NULL, &resp_len);
            if (resp) {
                send_queue_add(server, fd, resp, resp_len, NULL);
            }
            server_request_free(req);
            return;
        }
        p = args_end;
        remaining = req->command_len - (p - req->command_data);
        int idx = 0;
        while (remaining > 5 && idx < req->env_var_count) {
            size_t name_len = strnlen(p, remaining);
            req->env_var_names[idx] = p;  /* pointer into command_data, no copy */
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

    if (request_queue_push(server, req) != 0) {
        DBG("Request queue full, closing connection for fd %d", fd);
        server_request_free(req);
        client_connection_close(server, fd);
        return;
    }
    if (server->request_wake_fd >= 0) {
        uint64_t val = 1;
        ssize_t w = write(server->request_wake_fd, &val, sizeof(val));
        if (w < 0) {
            DBG("eventfd_write failed: %s", strerror(errno));
        }
    }
}

/* Try to send as much data as possible from the queue for a given fd.
 * Uses peek-first approach to avoid losing entries on EAGAIN.
 * Entry is only dequeued after write completes or on permanent failure. */
static void send_pending_locked(rbox_server_handle_t *server, int fd) {
    rbox_client_fd_entry_t *client_entry = client_fd_find(server, fd);
    if (!client_entry) return;

    while (1) {
        rbox_server_send_entry_t *entry = send_queue_peek(client_entry);
        if (!entry) break;

        size_t remaining = entry->len - entry->offset;
        ssize_t w = write(entry->fd, entry->data + entry->offset, remaining);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                DBG("send_pending_locked: write would block on fd %d", entry->fd);
                return;
            }
            if (errno == EINTR) {
                DBG("send_pending_locked: write interrupted, retrying");
                continue;
            }
            DBG("send_pending_locked: write failed on fd %d: %s", entry->fd, strerror(errno));
            send_queue_dequeue(client_entry);
            if (entry->request) {
                entry->request->fd = -1;
                server_request_free(entry->request);
            }
            entry->request = NULL;
            send_pool_put(server, entry);
            continue;
        } else if (w == 0) {
            DBG("send_pending_locked: write returned 0 on fd %d", entry->fd);
            send_queue_dequeue(client_entry);
            if (entry->request) {
                entry->request->fd = -1;
                server_request_free(entry->request);
            }
            entry->request = NULL;
            send_pool_put(server, entry);
            continue;
        } else {
            entry->offset += w;
            client_entry->last_activity = get_time_ms();
            DBG("send_pending_locked: wrote %zd bytes on fd %d, offset now %zu/%zu", w, entry->fd, entry->offset, entry->len);
            if (entry->offset == entry->len) {
                DBG("send_pending_locked: fully sent response for fd %d", entry->fd);
                uint8_t sent_decision = (uint8_t)entry->data[RBOX_HEADER_SIZE];
                if (sent_decision == RBOX_DECISION_ALLOW) {
                    atomic_fetch_add(&server->telemetry_allow_sent, 1);
                } else if (sent_decision == RBOX_DECISION_DENY) {
                    atomic_fetch_add(&server->telemetry_deny_sent, 1);
                }
                send_queue_dequeue(client_entry);
                if (entry->request) {
                    entry->request->fd = -1;
                    server_request_free(entry->request);
                }
                entry->request = NULL;
                send_pool_put(server, entry);
            } else {
                DBG("send_pending_locked: partial write, waiting for EPOLLOUT");
                return;
            }
        }
    }
}

static void try_send_pending(rbox_server_handle_t *server, int fd) {
    (void)server;
    DBG("try_send_pending: attempting to send for fd %d", fd);
    send_pending_locked(server, fd);
}

/* Add a response to the send queue and try to send immediately. */
static int send_queue_add(rbox_server_handle_t *server, int fd, char *data, size_t len, rbox_server_request_t *req) {
    rbox_server_send_entry_t *entry = send_pool_get(server);
    if (!entry) {
        free(data);
        if (req) server_request_free(req);
        return -1;
    }
    entry->fd = fd;
    entry->request = req;
    entry->offset = 0;
    entry->len = len;

    if (len <= sizeof(entry->internal_buf)) {
        memcpy(entry->internal_buf, data, len);
        entry->data = entry->internal_buf;
        entry->using_internal_buf = 1;
        free(data);
    } else {
        entry->data = data;
        entry->using_internal_buf = 0;
    }

    rbox_client_fd_entry_t *client_entry = client_fd_find(server, fd);
    if (!client_entry) {
        entry->request = NULL;
        send_pool_put(server, entry);
        if (req) server_request_free(req);
        return -1;
    }

    if (send_queue_enqueue(client_entry, entry) != 0) {
        entry->request = NULL;
        send_pool_put(server, entry);
        if (req) server_request_free(req);
        return -1;
    }

    DBG("send_queue_add: added response for fd %d", fd);
    try_send_pending(server, fd);
    return 0;
}

/* ============================================================
 * REQUEST HELPERS
 * ============================================================ */

void rbox_server_request_free(rbox_server_request_t *req) {
    server_request_free(req);
}

void server_request_free(rbox_server_request_t *req) {
    if (!req) return;
    if (req->command_data && !req->using_internal_buf) {
        free(req->command_data);
        req->command_data = NULL;
    }
    if (req->env_var_names) {
        free(req->env_var_names);
        req->env_var_names = NULL;
    }
    if (req->env_var_scores) {
        free(req->env_var_scores);
        req->env_var_scores = NULL;
    }
    request_pool_put(req->server, req);
}

/* Read header from client (v9 protocol) – non‑blocking version
 * Uses per-client header buffer to handle partial header reads */
static int server_read_header(rbox_server_handle_t *server, int fd,
                               uint8_t *client_id, uint8_t *request_id, uint32_t *cmd_hash,
                               uint32_t *fenv_hash,
                               char *caller, size_t caller_len, char *syscall, size_t syscall_len,
                               uint32_t *chunk_len, uint32_t *flags, uint64_t *total_len,
                               uint32_t *msg_type) {
    rbox_client_fd_entry_t *entry = client_fd_find(server, fd);
    if (!entry) return -1;
    char *header = entry->header_buf;
    size_t *bytes_read = &entry->header_bytes_read;

    while (*bytes_read < RBOX_HEADER_SIZE) {
        ssize_t n = rbox_read_nonblocking(fd, header + *bytes_read,
                                          RBOX_HEADER_SIZE - *bytes_read);
        if (n == 0) {
            DBG("server_read_header: EOF on fd %d", fd);
            entry->waiting_for_header = 0;
            return -1;
        }
        if (n == -1) {
            if (!entry->waiting_for_header) {
                entry->waiting_for_header = 1;
                entry->header_start_time = get_time_ms();
                DBG("server_read_header: started header wait for fd %d", fd);
                return 1;
            }
            return 1;
        }
        if (n == -2) {
            DBG("server_read_header: error on fd %d: %s", fd, strerror(errno));
            entry->waiting_for_header = 0;
            return -1;
        }

        *bytes_read += (size_t)n;
        entry->last_activity = get_time_ms();
    }

    entry->waiting_for_header = 0;
    entry->header_bytes_read = 0;

    uint32_t magic = *(uint32_t *)header;
    uint32_t version = *(uint32_t *)(header + 4);
    if (magic != RBOX_MAGIC || version != RBOX_VERSION) return -1;
    if (rbox_header_validate(header, RBOX_HEADER_SIZE) != RBOX_OK) return -1;
    entry->last_activity = get_time_ms();
    *msg_type = *(uint32_t *)(header + RBOX_HEADER_OFFSET_TYPE);
    memcpy(client_id, header + RBOX_HEADER_OFFSET_CLIENT_ID, 16);
    memcpy(request_id, header + RBOX_HEADER_OFFSET_REQUEST_ID, 16);
    *cmd_hash = *(uint32_t *)(header + RBOX_HEADER_OFFSET_CMD_HASH);
    *fenv_hash = *(uint32_t *)(header + RBOX_HEADER_OFFSET_FENV_HASH);
    uint8_t cs_size = *(uint8_t *)(header + RBOX_HEADER_OFFSET_CALLER_SYSCALL_SIZE);
    size_t caller_size = cs_size & 0x0F;
    if (caller_size > 15) caller_size = 15;
    size_t syscall_size = (cs_size >> 4) & 0x0F;
    if (syscall_size > 15) syscall_size = 15;
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
    if (*chunk_len > RBOX_CHUNK_MAX) return -1;
    *flags = *(uint32_t *)(header + RBOX_HEADER_OFFSET_FLAGS);
    *total_len = *(uint64_t *)(header + RBOX_HEADER_OFFSET_TOTAL_LEN);
    if (*chunk_len > *total_len) return -1;
    return 0;
}

int epoll_del(int epoll_fd, int fd) {
    if (epoll_fd < 0) return 0;
    struct epoll_event ev = {0};
    return epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ev);
}

/* ============================================================
 * LOCK-FREE DECISION QUEUE (Michael & Scott MPSC)
 * ============================================================ */

static int decision_queue_push(rbox_server_handle_t *server, rbox_server_decision_t *dec) {
    /* Reject new decisions if server is stopping to prevent memory leaks */
    if (!atomic_load(&server->running)) {
        return RBOX_ERR_INVALID;
    }
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
 * LOCK-FREE REQUEST QUEUE (Michael & Scott MPSC)
 * ============================================================ */

/* Lock-free enqueue for request queue */
static int request_queue_push(rbox_server_handle_t *server, rbox_server_request_t *req) {
    size_t depth = atomic_load_explicit(&server->request_queue_depth, memory_order_relaxed);
    if (depth >= RBOX_MAX_REQUEST_QUEUE_DEPTH) {
        return -1;
    }
    rbox_request_queue_t *q = &server->request_queue;
    rbox_request_node_t *node = malloc(sizeof(*node));
    if (!node) return -1;
    node->request = req;
    atomic_store_explicit(&node->next, NULL, memory_order_relaxed);

    rbox_request_node_t *tail, *next;
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
    atomic_store_explicit(&server->request_queue_depth, depth + 1, memory_order_relaxed);
    return 0;
}

/* Lock-free dequeue for request queue - consumer side only */
static rbox_server_request_t *request_queue_pop(rbox_server_handle_t *server) {
    rbox_request_queue_t *q = &server->request_queue;
    rbox_request_node_t *head, *next;

    while (1) {
        head = atomic_load_explicit(&q->head, memory_order_acquire);
        next = atomic_load_explicit(&head->next, memory_order_acquire);
        if (next == NULL) {
            return NULL;
        }
        if (atomic_compare_exchange_weak_explicit(&q->head, &head, next,
                                                  memory_order_acquire, memory_order_relaxed)) {
            rbox_server_request_t *req = next->request;
            next->request = NULL;
            atomic_fetch_sub_explicit(&server->request_queue_depth, 1, memory_order_relaxed);
            free(head);
            return req;
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
    uint64_t shutdown_start = 0;

    /* Make listen socket non‑blocking.
     * We do this here (after listen() is called) rather than in rbox_server_handle_new()
     * because we need to be able to propagate failures. If we set O_NONBLOCK during
     * handle creation, we couldn't easily return an error to the caller if fcntl failed.
     * By deferring to the server thread startup, we can return NULL from this function
     * if fcntl fails, cleanly shutting down the server. The listen socket is only used
     * for accept() in this thread, so setting O_NONBLOCK before entering the main loop
     * is the correct point for this operation. */
    int flags = fcntl(server->listen_fd, F_GETFL, 0);
    if (flags < 0) {
        return NULL;
    }
    if (fcntl(server->listen_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return NULL;
    }

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
            uint32_t packet_checksum = (req->command_data && req->command_len > 0) ? rbox_runtime_crc32(0, req->command_data, req->command_len) : 0;
            rbox_server_cache_insert(server, req->client_id, req->request_id, packet_checksum,
                                  cmd_hash, cmd_hash2, dec->fenv_hash, dec->decision, dec->reason, dec->duration,
                                  dec->env_decision_count, dec->env_decisions);
            char *resp = rbox_server_build_response(req->client_id, req->request_id, cmd_hash,
                dec->decision, dec->reason,
                dec->fenv_hash, dec->env_decision_count, (uint8_t *)dec->env_decisions, &resp_len);
            if (resp) {
                DBG("Built response of size %zu for fd %d", resp_len, req->fd);
                if (send_queue_add(server, req->fd, resp, resp_len, req) != 0) {
                    DBG("send_queue_add failed for fd %d", req->fd);
                    req = NULL;
                }
            } else {
                DBG("Failed to build response for fd %d", req->fd);
                server_request_free(req);
            }
            free(dec->env_decisions);
            free(dec);
        }

        /* If shutdown requested, check if we can exit */
        if (!atomic_load(&server->running)) {
            if (server->active_client_count == 0) {
                DBG("No active clients, exiting");
                break;
            }
            if (shutdown_start == 0) shutdown_start = get_time_ms();
            uint64_t shutdown_elapsed = get_time_ms() - shutdown_start;
            if (shutdown_elapsed > 2000) {
                DBG("Shutdown timeout reached, exiting with %d active clients",
                    server->active_client_count);
                break;
            }
            DBG("Shutdown in progress, %d active clients",
                server->active_client_count);
        } else {
            shutdown_start = 0;
        }

        /* Epoll wait and event handling */
        int n = epoll_wait(server->epoll_fd, events, 64, 100);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        /* Process events first */
        if (n > 0) {
            for (int i = 0; i < n; i++) {
                struct epoll_event *ev = &events[i];

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
                        if (server->max_clients > 0 && server->active_client_count >= server->max_clients) {
                            DBG("max clients (%d) reached, refusing connection on fd %d", server->max_clients, cl_fd);
                            close(cl_fd);
                            break;
                        }
                        flags = fcntl(cl_fd, F_GETFL, 0);
                        if (flags < 0) {
                            close(cl_fd);
                            break;
                        }
                        if (fcntl(cl_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
                            close(cl_fd);
                            break;
                        }
                        if (client_fd_add(server, cl_fd) != 0) {
                            close(cl_fd);
                            break;
                        }
                        rbox_client_fd_entry_t *new_entry = server->client_fds;
                        struct epoll_event cev = { .events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET, .data.ptr = new_entry };
                        epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, cl_fd, &cev);
                    }
                    continue;
                }

                if (server->wake_fd >= 0 && ev->data.fd == server->wake_fd) {
                    uint64_t val;
                    ssize_t r;
                    do { r = read(server->wake_fd, &val, sizeof(val)); } while (r < 0 && (errno == EINTR || errno == EAGAIN));
                    continue;
                }

                rbox_client_fd_entry_t *entry = (rbox_client_fd_entry_t *)ev->data.ptr;
                if (!entry) {
                    continue;
                }
                int cl_fd = entry->fd;

                int closed = 0;

                /* Handle EPOLLIN first – read data before close */
                if (ev->events & EPOLLIN) {
                    /* Drain loop: with EPOLLET we must read until EAGAIN to
                     * avoid losing events.  After each complete request we
                     * loop back to check for pipelined data in the same
                     * socket buffer. */
                    int keep_reading = 1;
                    while (keep_reading && !closed) {
                        /* Check for pending request (body read in progress) */
                        rbox_server_request_t *pending = pending_request_get(server, cl_fd);
                        if (pending) {
                            int result;
                            if (pending->is_chunked) {
                                result = read_body_chunks_nonblocking(server, cl_fd, pending);
                            } else {
                                result = read_body_nonblocking(server, cl_fd, pending);
                            }
                            if (result == 1) {
                                pending->reading_body = 0;
                                pending_request_remove(server, cl_fd);
                                process_completed_request(server, cl_fd, pending);
                                keep_reading = 1;
                                continue;
                            } else if (result == -1) {
                                client_connection_close(server, cl_fd);
                                closed = 1;
                                keep_reading = 0;
                            } else {
                                /* EAGAIN – stop reading */
                                keep_reading = 0;
                            }
                            continue;
                        }

                        /* No pending request – read header */
                        uint8_t client_id[16], request_id[16];
                        uint32_t cmd_hash, fenv_hash, chunk_len, flags, msg_type;
                        uint64_t total_len;
                        char caller[RBOX_MAX_CALLER_LEN + 1];
                        char syscall[RBOX_MAX_SYSCALL_LEN + 1];

                        int hdr_result = server_read_header(server, cl_fd, client_id, request_id, &cmd_hash, &fenv_hash,
                            caller, sizeof(caller), syscall, sizeof(syscall), &chunk_len, &flags, &total_len, &msg_type);
                        if (hdr_result == 1) {
                            /* Partial header – stop reading for now */
                            keep_reading = 0;
                            continue;
                        } else if (hdr_result == -1) {
                            client_connection_close(server, cl_fd);
                            closed = 1;
                            keep_reading = 0;
                            continue;
                        }

                        /* Handle telemetry request */
                        if (msg_type == RBOX_MSG_TELEMETRY) {
                            size_t resp_len;
                            char *resp = rbox_server_build_telemetry_response(
                                client_id, request_id,
                                atomic_load(&server->telemetry_allow_sent),
                                atomic_load(&server->telemetry_deny_sent),
                                &resp_len);
                            if (resp) {
                                send_queue_add(server, cl_fd, resp, resp_len, NULL);
                            }
                            keep_reading = 1;
                            continue;
                        }

                        /* Handle abort request */
                        if (msg_type == RBOX_MSG_ABORT) {
                            client_connection_close(server, cl_fd);
                            closed = 1;
                            keep_reading = 0;
                            continue;
                        }

                        /* Handle log message */
                        if (msg_type == RBOX_MSG_LOG) {
                            keep_reading = 1;
                            continue;
                        }

                        /* Handle chunk (intermediate) - should come after FIRST */
                        if (msg_type == RBOX_MSG_CHUNK) {
                            client_connection_close(server, cl_fd);
                            closed = 1;
                            keep_reading = 0;
                            continue;
                        }

                        /* Handle complete */
                        if (msg_type == RBOX_MSG_COMPLETE) {
                            client_connection_close(server, cl_fd);
                            closed = 1;
                            keep_reading = 0;
                            continue;
                        }

                        /* Check if this is a chunked transfer */
                        int is_chunked = (flags & RBOX_FLAG_FIRST) && chunk_len < total_len;

                        if (is_chunked) {
                            rbox_server_request_t *req = request_pool_get(server);
                            if (!req) {
                                client_connection_close(server, cl_fd);
                                closed = 1;
                                keep_reading = 0;
                                continue;
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
                            if ((size_t)total_len > RBOX_MAX_TOTAL_SIZE) {
                                request_pool_put(server, req);
                                client_connection_close(server, cl_fd);
                                closed = 1;
                                keep_reading = 0;
                                continue;
                            }
                            req->command_data = malloc(total_len + 1);
                            req->using_internal_buf = 0;
                            if (!req->command_data) {
                                request_pool_put(server, req);
                                client_connection_close(server, cl_fd);
                                closed = 1;
                                keep_reading = 0;
                                continue;
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
                                keep_reading = 1;
                            } else if (result == 0) {
                                pending_request_set(server, cl_fd, req);
                                keep_reading = 0;
                            } else {
                                server_request_free(req);
                                client_connection_close(server, cl_fd);
                                closed = 1;
                                keep_reading = 0;
                            }
                            continue;
                        }

                        /* Single-chunk request – use non-blocking */
                        rbox_server_request_t *req = request_pool_get(server);
                        if (!req) {
                            client_connection_close(server, cl_fd);
                            closed = 1;
                            keep_reading = 0;
                            continue;
                        }
                        req->fd = cl_fd;
                        memcpy(req->client_id, client_id, 16);
                        memcpy(req->request_id, request_id, 16);
                        memcpy(req->original_request_id, request_id, 16);
                        req->cmd_hash = cmd_hash;
                        req->server = server;
                        req->fenv_hash = fenv_hash;
                        strncpy(req->caller, caller, RBOX_MAX_CALLER_LEN);
                        req->caller[RBOX_MAX_CALLER_LEN] = '\0';
                        strncpy(req->syscall, syscall, RBOX_MAX_SYSCALL_LEN);
                        req->syscall[RBOX_MAX_SYSCALL_LEN] = '\0';

                        if (chunk_len + 1 <= sizeof(req->internal_buf)) {
                            req->command_data = req->internal_buf;
                            req->using_internal_buf = 1;
                        } else {
                            req->command_data = malloc(chunk_len + 1);
                            req->using_internal_buf = 0;
                        }
                        if (!req->command_data) {
                            request_pool_put(server, req);
                            client_connection_close(server, cl_fd);
                            closed = 1;
                            keep_reading = 0;
                            continue;
                        }
                        req->command_len = chunk_len;

                        /* Set up body reading state */
                        req->reading_body = 1;
                        req->body_expected = chunk_len;
                        req->body_received = 0;
                        req->body_checksum = *(uint32_t *)(entry->header_buf + RBOX_HEADER_OFFSET_BODY_CHECKSUM);
                        req->is_chunked = 0;
                        req->reading_chunk_header = 0;
                        req->current_chunk_len = 0;
                        req->current_chunk_received = 0;

                        /* Attempt to read body non-blocking */
                        int result = read_body_nonblocking(server, cl_fd, req);
                        if (result == 1) {
                            req->reading_body = 0;
                            pending_request_remove(server, cl_fd);
                            process_completed_request(server, cl_fd, req);
                            keep_reading = 1;
                        } else if (result == 0) {
                            pending_request_set(server, cl_fd, req);
                            keep_reading = 0;
                        } else {
                            server_request_free(req);
                            client_connection_close(server, cl_fd);
                            closed = 1;
                            keep_reading = 0;
                        }
                    } /* end while (keep_reading) */
                }

                /* Handle EPOLLRDHUP - remote closed connection (check early to avoid wasted work) */
                if (!closed && (ev->events & EPOLLRDHUP)) {
                    DBG("EPOLLRDHUP on fd %d, closing", cl_fd);
                    client_connection_close(server, cl_fd);
                    closed = 1;
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
                if (!closed && (ev->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) {
                    DBG("EPOLLHUP/RDHUP/ERR on fd %d, cleaning up", cl_fd);
                    client_connection_close(server, cl_fd);
                    DBG("Closed fd %d", cl_fd);
                }

                next_event: ;
            }
        }

        /* Check for timeouts AFTER processing events to avoid use-after-free
         * (events array may contain fds that were closed in a previous iteration) */
        uint64_t now = get_time_ms();
        pthread_mutex_lock(&server->client_fd_mutex);
        rbox_client_fd_entry_t *tentry = server->client_fds;
        while (tentry) {
            rbox_client_fd_entry_t *next = tentry->next;
            int should_close = 0;
            int close_reason = 0;

            if (server->request_timeout > 0) {
                if (tentry->waiting_for_header && tentry->header_start_time > 0) {
                    uint64_t elapsed = now - tentry->header_start_time;
                    if (elapsed > (uint64_t)server->request_timeout * 1000) {
                        should_close = 1;
                        close_reason = 1;
                    }
                } else if (tentry->pending_request && tentry->pending_request->reading_body) {
                    uint64_t elapsed = now - tentry->body_start_time;
                    if (elapsed > (uint64_t)server->request_timeout * 1000) {
                        should_close = 1;
                        close_reason = 2;
                    }
                }
            }

            if (!should_close && server->client_idle_timeout > 0 && !tentry->pending_request) {
                uint64_t idle = now - tentry->last_activity;
                if (idle > (uint64_t)server->client_idle_timeout * 1000) {
                    should_close = 1;
                    close_reason = 3;
                }
            }

            if (should_close) {
                int fd = tentry->fd;
                (void)close_reason;  /* unused when DBG is disabled */
                DBG("Timeout check: fd %d reason %d, closing", fd, close_reason);
                pthread_mutex_unlock(&server->client_fd_mutex);
                client_connection_close(server, fd);
                pthread_mutex_lock(&server->client_fd_mutex);
                tentry = server->client_fds;
                continue;
            }
            tentry = next;
        }
        pthread_mutex_unlock(&server->client_fd_mutex);
    }

    /* Final cleanup: close any remaining client fds (should be none) */
    client_fd_close_all(server);
    DBG("Exiting server thread (running=%d)", atomic_load(&server->running));
    close(server->epoll_fd);
    server->epoll_fd = -1;
    return NULL;
}

/* ============================================================
 * SERVER HANDLE MANAGEMENT
 * ============================================================ */

rbox_server_handle_t *rbox_server_handle_new(const char *socket_path) {
    if (!socket_path) return NULL;
    rbox_server_handle_t *srv = calloc(1, sizeof(*srv));
    if (!srv) return NULL;
    srv->epoll_fd = -1;
    strncpy(srv->socket_path, socket_path, sizeof(srv->socket_path) - 1);
    srv->listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (srv->listen_fd < 0) { free(srv); return NULL; }
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    if (bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno == EADDRINUSE) {
            unlink(socket_path);
            if (bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                close(srv->listen_fd);
                free(srv);
                return NULL;
            }
        } else {
            close(srv->listen_fd);
            free(srv);
            return NULL;
        }
    }
    if (chmod(socket_path, 0666) < 0) {
        close(srv->listen_fd);
        unlink(socket_path);
        free(srv);
        return NULL;
    }
    if (pthread_mutex_init(&srv->cache_mutex, NULL) != 0) {
        free(srv);
        return NULL;
    }
    if (pthread_mutex_init(&srv->client_fd_mutex, NULL) != 0) {
        pthread_mutex_destroy(&srv->cache_mutex);
        free(srv);
        return NULL;
    }
    atomic_flag_clear(&srv->stop_flag);
    srv->client_fds = NULL;
    srv->active_client_count = 0;
    rbox_server_cache_init(srv);
    if (request_pool_init(srv, RBOX_REQUEST_POOL_SIZE) < 0) {
        /* Pool init completely failed - continue with malloc fallback */
    }
    if (send_pool_init(srv, RBOX_SEND_POOL_SIZE) < 0) {
        /* Pool init completely failed - continue with malloc fallback */
    }

    /* Initialize lock-free request queue with dummy node */
    rbox_request_node_t *req_dummy = malloc(sizeof(*req_dummy));
    if (!req_dummy) {
        request_pool_destroy(srv);
        send_pool_destroy(srv);
        pthread_mutex_destroy(&srv->cache_mutex);
        pthread_mutex_destroy(&srv->client_fd_mutex);
        close(srv->listen_fd);
        free(srv);
        return NULL;
    }
    req_dummy->request = NULL;
    atomic_store_explicit(&req_dummy->next, NULL, memory_order_relaxed);
    atomic_store_explicit(&srv->request_queue.head, req_dummy, memory_order_relaxed);
    atomic_store_explicit(&srv->request_queue.tail, req_dummy, memory_order_relaxed);
    srv->request_wake_fd = eventfd(0, EFD_NONBLOCK);
    if (srv->request_wake_fd < 0) {
        request_pool_destroy(srv);
        send_pool_destroy(srv);
        pthread_mutex_destroy(&srv->cache_mutex);
        pthread_mutex_destroy(&srv->client_fd_mutex);
        close(srv->listen_fd);
        free(srv);
        return NULL;
    }

    rbox_decision_node_t *dummy = malloc(sizeof(*dummy));
    if (!dummy) {
        close(srv->request_wake_fd);
        request_pool_destroy(srv);
        send_pool_destroy(srv);
        pthread_mutex_destroy(&srv->cache_mutex);
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
    if (srv->wake_fd < 0) {
        close(srv->request_wake_fd);
        request_pool_destroy(srv);
        send_pool_destroy(srv);
        pthread_mutex_destroy(&srv->cache_mutex);
        pthread_mutex_destroy(&srv->client_fd_mutex);
        close(srv->listen_fd);
        free(srv);
        return NULL;
    }

    atomic_init(&srv->telemetry_allow_queued, 0);
    atomic_init(&srv->telemetry_deny_queued, 0);
    atomic_init(&srv->telemetry_allow_sent, 0);
    atomic_init(&srv->telemetry_deny_sent, 0);

    return srv;
}

rbox_error_t rbox_server_handle_listen(rbox_server_handle_t *server) {
    if (!server) return RBOX_ERR_INVALID;
    if (listen(server->listen_fd, SOMAXCONN) < 0) return RBOX_ERR_IO;
    return RBOX_OK;
}

void rbox_server_handle_free(rbox_server_handle_t *server) {
    if (!server) return;

    if (atomic_load(&server->running)) {
        rbox_server_stop(server);
    }

    /* Drain and free any pending requests in the lock-free queue */
    rbox_request_node_t *req_node = atomic_load_explicit(&server->request_queue.head, memory_order_acquire);
    while (req_node) {
        rbox_request_node_t *next = atomic_load_explicit(&req_node->next, memory_order_acquire);
        if (req_node->request) server_request_free(req_node->request);
        free(req_node);
        req_node = next;
    }

    if (server->listen_fd >= 0) {
        close(server->listen_fd);
        unlink(server->socket_path);
    }
    if (server->wake_fd >= 0) close(server->wake_fd);
    if (server->request_wake_fd >= 0) close(server->request_wake_fd);

    /* Close all client connections and drain send queues - must be called
     * after server thread has exited to avoid races with epoll operations */
    client_fd_close_all(server);

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
        if (node->decision) {
            free(node->decision->env_decisions);
            free(node->decision);
        }
        free(node);
        node = next;
    }

    /* Destroy request pool */
    request_pool_destroy(server);

    /* Destroy send pool */
    send_pool_destroy(server);

    /* Destroy response cache */
    rbox_server_cache_destroy(server);

    pthread_mutex_destroy(&server->cache_mutex);
    pthread_mutex_destroy(&server->client_fd_mutex);
    free(server);
}

void rbox_server_set_limits(rbox_server_handle_t *server, int max_clients, int idle_timeout, int request_timeout) {
    if (!server) return;
    server->max_clients = max_clients;
    server->client_idle_timeout = idle_timeout;
    server->request_timeout = request_timeout;
}

rbox_error_t rbox_server_start(rbox_server_handle_t *server) {
    if (!server) return RBOX_ERR_INVALID;
    atomic_store(&server->running, 1);
    if (pthread_create(&server->thread, NULL, server_thread_func, server) != 0) {
        atomic_store(&server->running, 0);
        return RBOX_ERR_IO;
    }
    return RBOX_OK;
}

rbox_server_request_t *rbox_server_get_request(rbox_server_handle_t *server) {
    if (!server) return NULL;
    while (atomic_load(&server->running)) {
        rbox_server_request_t *req = request_queue_pop(server);
        if (req) return req;

        /* Wait for wakeup */
        struct pollfd pfd = { .fd = server->request_wake_fd, .events = POLLIN };
        if (poll(&pfd, 1, -1) < 0) {
            if (errno == EINTR) continue;
            return NULL;
        }
        /* Drain the eventfd */
        uint64_t val;
        ssize_t r = read(server->request_wake_fd, &val, sizeof(val));
        (void)r;
    }
    /* Server stopped - drain queue one more time */
    return request_queue_pop(server);
}

int rbox_server_is_running(rbox_server_handle_t *server) {
    return server ? atomic_load(&server->running) : 0;
}

rbox_error_t rbox_server_decide(rbox_server_request_t *req,
    uint8_t decision, const char *reason, uint32_t duration,
    int env_decision_count, const uint8_t *env_decisions) {
    if (!req) return RBOX_ERR_INVALID;
    rbox_server_handle_t *server = req->server;
    if (!server) return RBOX_ERR_INVALID;

    rbox_server_decision_t *dec = calloc(1, sizeof(*dec));
    if (!dec) return RBOX_ERR_MEMORY;
    dec->request = req;
    dec->decision = decision;
    dec->fenv_hash = req->fenv_hash;
    strncpy(dec->reason, reason ? reason : "", sizeof(dec->reason) - 1);
    dec->duration = duration;

    if (decision == RBOX_DECISION_ALLOW) {
        atomic_fetch_add(&server->telemetry_allow_queued, 1);
    } else if (decision == RBOX_DECISION_DENY) {
        atomic_fetch_add(&server->telemetry_deny_queued, 1);
    }

    if (env_decision_count > 0 && env_decisions) {
        dec->env_decision_count = env_decision_count;
        size_t bitmap_size = (env_decision_count + 7) / 8;
        dec->env_decisions = malloc(bitmap_size);
        if (!dec->env_decisions) {
            free(dec);
            return RBOX_ERR_MEMORY;
        }
        memcpy(dec->env_decisions, env_decisions, bitmap_size);
        dec->fenv_hash = 0;
    }

    if (decision_queue_push(server, dec) != RBOX_OK) {
        free(dec->env_decisions);
        server_request_free(dec->request);
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
    if (server->request_wake_fd >= 0) {
        uint64_t val = 1;
        ssize_t n = write(server->request_wake_fd, &val, sizeof(val));
        if (n < 0) {
            DBG("eventfd_write failed: %s", strerror(errno));
        }
    }
    if (server->wake_fd >= 0) {
        uint64_t val = 1;
        ssize_t n = write(server->wake_fd, &val, sizeof(val));
        if (n < 0) {
            DBG("eventfd_write failed: %s", strerror(errno));
        }
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
    const char *stop_cmd = "__RBOX_STOP__";
    size_t stop_len = 14;
    if (req->command_len < stop_len) return 0;
    return (memcmp(req->command_data, stop_cmd, stop_len) == 0);
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
