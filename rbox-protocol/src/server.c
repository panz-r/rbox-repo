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
static void server_request_free(rbox_server_request_t *req);
static void try_send_pending(rbox_server_handle_t *server, int fd);
static void client_fd_add(rbox_server_handle_t *server, int fd);
static void client_fd_remove(rbox_server_handle_t *server, int fd);
static void client_fd_close_all(rbox_server_handle_t *server);

/* ============================================================
 * CLIENT FD TRACKING
 * ============================================================ */

static void client_fd_add(rbox_server_handle_t *server, int fd) {
    rbox_client_fd_entry_t *entry = malloc(sizeof(*entry));
    if (!entry) return;
    entry->fd = fd;
    pthread_mutex_lock(&server->client_fd_mutex);
    entry->next = server->client_fds;
    server->client_fds = entry;
    server->active_client_count++;
    pthread_mutex_unlock(&server->client_fd_mutex);
}

static void client_fd_remove(rbox_server_handle_t *server, int fd) {
    pthread_mutex_lock(&server->client_fd_mutex);
    rbox_client_fd_entry_t **prev = &server->client_fds;
    rbox_client_fd_entry_t *entry = server->client_fds;
    while (entry) {
        if (entry->fd == fd) {
            *prev = entry->next;
            free(entry);
            server->active_client_count--;
            break;
        }
        prev = &entry->next;
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

/* Clean up any send queue entries for a closed fd */
static void cleanup_pending_sends(rbox_server_handle_t *server, int fd) {
    pthread_mutex_lock(&server->send_mutex);
    rbox_server_send_entry_t **prev = &server->send_queue;
    rbox_server_send_entry_t *entry = server->send_queue;
    while (entry) {
        if (entry->fd == fd) {
            *prev = entry->next;
            if (!entry->next) server->send_tail = *prev;
            server->send_count--;
            free(entry->data);
            if (entry->request) {
                entry->request->fd = -1;
                server_request_free(entry->request);
            }
            free(entry);
            entry = *prev;
        } else {
            prev = &entry->next;
            entry = entry->next;
        }
    }
    pthread_mutex_unlock(&server->send_mutex);
}

/* Try to send as much data as possible from the queue for a given fd.
 * Caller must hold send_mutex when calling this. */
static void send_pending_locked(rbox_server_handle_t *server, int fd) {
    rbox_server_send_entry_t **prev = &server->send_queue;
    rbox_server_send_entry_t *entry = server->send_queue;
    while (entry) {
        if (entry->fd == fd) {
            size_t remaining = entry->len - entry->offset;
            ssize_t w = write(entry->fd, entry->data + entry->offset, remaining);
            if (w < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    DBG("send_pending_locked: write would block on fd %d", entry->fd);
                    break;
                }
                DBG("send_pending_locked: write failed on fd %d: %s", entry->fd, strerror(errno));
                *prev = entry->next;
                if (!entry->next) server->send_tail = *prev;
                server->send_count--;
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
                if (!entry->next) server->send_tail = *prev;
                server->send_count--;
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
                    if (!entry->next) server->send_tail = *prev;
                    server->send_count--;
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
        } else {
            prev = &entry->next;
            entry = entry->next;
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

    pthread_mutex_lock(&server->send_mutex);
    entry->next = NULL;
    if (server->send_tail) {
        server->send_tail->next = entry;
        server->send_tail = entry;
    } else {
        server->send_queue = entry;
        server->send_tail = entry;
    }
    server->send_count++;
    pthread_mutex_unlock(&server->send_mutex);

    DBG("send_queue_add: added response for fd %d", fd);
    try_send_pending(server, fd);
    return 0;
}

/* ============================================================
 * REQUEST HELPERS
 * ============================================================ */

static void server_request_free(rbox_server_request_t *req) {
    if (!req) return;
    if (req->fd >= 0) {
        client_fd_remove(req->server, req->fd);
        close(req->fd);
    }
    free(req->command_data);
    if (req->env_var_names) {
        for (int i = 0; i < req->env_var_count; i++) free(req->env_var_names[i]);
        free(req->env_var_names);
    }
    free(req->env_var_scores);
    free(req);
}

/* Read header from client (v9 protocol) – non‑blocking version */
static int server_read_header(int fd, uint8_t *client_id, uint8_t *request_id, uint32_t *cmd_hash,
                               uint32_t *fenv_hash,
                               char *caller, size_t caller_len, char *syscall, size_t syscall_len,
                               uint32_t *chunk_len, uint32_t *flags, uint64_t *total_len) {
    char header[RBOX_HEADER_SIZE];
    ssize_t n = rbox_read_nonblocking(fd, header, RBOX_HEADER_SIZE);
    if (n == 0) {
        /* No data available yet – don't close the connection */
        DBG("server_read_header: no data available on fd %d", fd);
        return 1; /* Indicate no data available */
    } else if (n != RBOX_HEADER_SIZE) {
        /* Error or EOF – close the connection */
        if (n == -2) DBG("server_read_header: EOF on fd %d", fd);
        else DBG("server_read_header: error on fd %d", fd);
        return -1;
    }
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

/* Read request body – loops until all data is received */
static char *read_body(int fd, uint32_t chunk_len) {
    if (chunk_len == 0) {
        char *empty = malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }
    char *data = malloc(chunk_len + 1);
    if (!data) return NULL;

    size_t total_read = 0;
    while (total_read < chunk_len) {
        ssize_t n = rbox_read(fd, data + total_read, chunk_len - total_read);
        if (n <= 0) {
            free(data);
            return NULL;
        }
        total_read += n;
    }
    data[chunk_len] = '\0';
    return data;
}

/* Read and accumulate chunks until RBOX_FLAG_LAST is received
 * Returns malloc'd buffer with all chunks concatenated, or NULL on error
 * Sets out_total_len to total bytes accumulated */
static char *read_body_chunks(int fd, uint32_t first_chunk_len, uint64_t total_len,
                               uint32_t first_flags, size_t *out_total_len,
                               const uint8_t *client_id, const uint8_t *request_id) {
    if (out_total_len) *out_total_len = 0;
    
    /* Allocate buffer for total_len if known, otherwise use dynamic growth */
    size_t buf_capacity = (total_len > 0 && total_len <= 1024 * 1024) ? total_len : first_chunk_len;
    if (buf_capacity == 0) buf_capacity = 4096;
    /* +1 for null terminator */
    char *buffer = malloc(buf_capacity + 1);
    if (!buffer) return NULL;
    
    size_t buf_len = 0;
    uint32_t flags = first_flags;
    
    /* Read first chunk */
    if (first_chunk_len > 0) {
        char *chunk = read_body(fd, first_chunk_len);
        if (!chunk) {
            free(buffer);
            return NULL;
        }
        if (buf_len + first_chunk_len > buf_capacity) {
            buf_capacity = buf_len + first_chunk_len;
            char *new_buf = realloc(buffer, buf_capacity + 1);
            if (!new_buf) {
                free(chunk);
                free(buffer);
                return NULL;
            }
            buffer = new_buf;
        }
        memcpy(buffer + buf_len, chunk, first_chunk_len);
        buf_len += first_chunk_len;
        free(chunk);
    }
    
    /* If FIRST and LAST are both set, this was a single-chunk transfer */
    if ((flags & (RBOX_FLAG_FIRST | RBOX_FLAG_LAST)) == (RBOX_FLAG_FIRST | RBOX_FLAG_LAST)) {
        if (out_total_len) *out_total_len = buf_len;
        return buffer;
    }
    
    /* Continue reading chunks until RBOX_FLAG_LAST is set */
    while (!(flags & RBOX_FLAG_LAST)) {
        char header[RBOX_HEADER_SIZE];
        ssize_t n = rbox_read_nonblocking(fd, header, RBOX_HEADER_SIZE);
        if (n == 0) {
            /* No data yet - wait a bit and retry */
            usleep(1000);
            continue;
        } else if (n < 0) {
            /* Error or no data (EAGAIN) - wait and retry */
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;
            }
            free(buffer);
            return NULL;
        } else if (n != RBOX_HEADER_SIZE) {
            free(buffer);
            return NULL;
        }
        
        uint32_t magic = *(uint32_t *)header;
        uint32_t version = *(uint32_t *)(header + 4);
        if (magic != RBOX_MAGIC || version != RBOX_VERSION) {
            free(buffer);
            return NULL;
        }
        
        flags = *(uint32_t *)(header + RBOX_HEADER_OFFSET_FLAGS);
        uint32_t chunk_len = *(uint32_t *)(header + RBOX_HEADER_OFFSET_CHUNK_LEN);
        
        if (chunk_len > 1024 * 1024) {
            free(buffer);
            return NULL;
        }
        
        /* Read chunk data */
        if (chunk_len > 0) {
            char *chunk = read_body(fd, chunk_len);
            if (!chunk) {
                free(buffer);
                return NULL;
            }
            
            if (buf_len + chunk_len > buf_capacity) {
                buf_capacity = buf_len + chunk_len;
                char *new_buf = realloc(buffer, buf_capacity + 1);
                if (!new_buf) {
                    free(chunk);
                    free(buffer);
                    return NULL;
                }
                buffer = new_buf;
            }
            memcpy(buffer + buf_len, chunk, chunk_len);
            buf_len += chunk_len;
            free(chunk);
        }
    }
    
    if (out_total_len) *out_total_len = buf_len;
    /* Null-terminate the buffer for safe string parsing */
    buffer[buf_len] = '\0';
    return buffer;
}

/* Remove from epoll */
static int epoll_del(int epoll_fd, int fd) {
    struct epoll_event ev = {0};
    return epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ev);
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

        /* Process pending decisions */
        pthread_mutex_lock(&server->decision_mutex);
        DBG("decision_mutex locked, decision_queue=%p", (void*)server->decision_queue);
        while (server->decision_queue && server->decision_queue->ready) {
            rbox_server_decision_t *dec = server->decision_queue;
            server->decision_queue = (void*)dec->next;
            if (!server->decision_queue) server->decision_tail = NULL;
            server->decision_count--;
            pthread_mutex_unlock(&server->decision_mutex);
            DBG("Processing decision for fd %d", dec->request ? dec->request->fd : -1);

            if (!dec || !dec->request) {
                free(dec);
                pthread_mutex_lock(&server->decision_mutex);
                continue;
            }

            rbox_server_request_t *req = dec->request;
            if (req) {
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
                        resp = NULL;
                        req = NULL;
                    }
                } else {
                    DBG("Failed to build response for fd %d", req->fd);
                }
                if (dec->env_decision_names) {
                    for (int i = 0; i < dec->env_decision_count; i++) free(dec->env_decision_names[i]);
                    free(dec->env_decision_names);
                }
                free(dec->env_decisions);
            }
            free(dec);
            pthread_mutex_lock(&server->decision_mutex);
        }
        pthread_mutex_unlock(&server->decision_mutex);
        DBG("decision_mutex unlocked");

        /* If shutdown requested, check if we can exit */
        if (!atomic_load(&server->running)) {
            int pending_sends = 0;
            pthread_mutex_lock(&server->send_mutex);
            pending_sends = server->send_count;
            pthread_mutex_unlock(&server->send_mutex);
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
                         struct epoll_event cev = { .events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET, .data.fd = cl_fd };
                        epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, cl_fd, &cev);
                        client_fd_add(server, cl_fd);
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

                int cl_fd = ev->data.fd;
                if (cl_fd < 0) continue;

                int closed = 0;

                /* Handle EPOLLIN first – read data before close */
                if (ev->events & EPOLLIN) {
                    uint8_t client_id[16], request_id[16];
                    uint32_t cmd_hash, fenv_hash, chunk_len, flags;
                    uint64_t total_len;
                    char caller[RBOX_MAX_CALLER_LEN + 1];
                    char syscall[RBOX_MAX_SYSCALL_LEN + 1];

                    int hdr_result = server_read_header(cl_fd, client_id, request_id, &cmd_hash, &fenv_hash,
                        caller, sizeof(caller), syscall, sizeof(syscall), &chunk_len, &flags, &total_len);
                    if (hdr_result == 1) {
                        /* No data available yet – skip further processing for this event */
                        DBG("No data available on fd %d, skipping", cl_fd);
                        goto next_event;
                    } else if (hdr_result == 0) {
                        /* Read body - either single chunk or accumulated chunks */
                        size_t cmd_len;
                        char *cmd_data;
                        if ((flags & RBOX_FLAG_FIRST) && chunk_len < total_len) {
                            /* This is a multi-chunk transfer - read all chunks
                             * FIRST is set and chunk_len < total_len means more chunks coming */
                            cmd_data = read_body_chunks(cl_fd, chunk_len, total_len, flags, &cmd_len, client_id, request_id);
                        } else {
                            /* Single chunk transfer */
                            cmd_data = read_body(cl_fd, chunk_len);
                            cmd_len = chunk_len;
                        }
                        if (cmd_data) {
                            /* Check response cache before creating request */
                            uint32_t packet_checksum = (cmd_len > 0) ? rbox_calculate_checksum_crc32(0, cmd_data, cmd_len) : 0;
                            uint64_t cmd_hash2 = (cmd_len > 0) ? rbox_hash64(cmd_data, cmd_len) : 0;
                            uint8_t cached_decision;
                            char cached_reason[256];
                            uint32_t cached_duration;
                            if (rbox_server_cache_lookup(server, client_id, request_id, packet_checksum,
                                                        cmd_hash, cmd_hash2, fenv_hash,
                                                        &cached_decision, cached_reason, &cached_duration)) {
                                /* Cache hit - send cached response */
                                DBG("Cache hit for request, sending cached response");
                                size_t resp_len;
                                char *resp = rbox_server_build_response(client_id, request_id, cmd_hash,
                                    cached_decision, cached_reason, cached_duration,
                                    fenv_hash, 0, NULL, &resp_len);
                                if (resp) {
                                    send_queue_add(server, cl_fd, resp, resp_len, NULL);
                                }
                                free(cmd_data);
                                goto next_event;
                            }
                            /* Cache miss - proceed with normal request handling */
                            rbox_server_request_t *req = calloc(1, sizeof(*req));
                            if (req) {
                                req->fd = cl_fd;
                                memcpy(req->client_id, client_id, 16);
                                memcpy(req->request_id, request_id, 16);
                                req->cmd_hash = cmd_hash;
                                req->server = server;
                                req->command_data = cmd_data;
                                req->command_len = cmd_len;
                                strncpy(req->caller, caller, RBOX_MAX_CALLER_LEN);
                                req->caller[RBOX_MAX_CALLER_LEN] = '\0';
                                strncpy(req->syscall, syscall, RBOX_MAX_SYSCALL_LEN);
                                req->syscall[RBOX_MAX_SYSCALL_LEN] = '\0';
                                rbox_command_parse(cmd_data, cmd_len, &req->parse);

                                /* Parse env vars (simplified) */
                                const char *p = cmd_data;
                                const char *args_end = cmd_data;
                                while (p < cmd_data + cmd_len) {
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
                                size_t remaining = cmd_len - (p - cmd_data);
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
                                    if (p >= cmd_data + cmd_len) {
                                        remaining = 0;
                                    } else {
                                        remaining = cmd_data + cmd_len - p;
                                    }
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
                                DBG("Queued request for fd %d (count=%d), signaling", cl_fd, server->request_count);
                                pthread_cond_signal(&server->cond);
                                pthread_mutex_unlock(&server->mutex);
                                /* We read a request and queued it, skip further handling for this event */
                                goto next_event;
                            }
                            free(cmd_data);
                        }
                    } else {
                        DBG("Header read failed on fd %d, cleaning up", cl_fd);
                    }

                    /* Read failed – clean up and close */
                    cleanup_pending_sends(server, cl_fd);
                    client_fd_remove(server, cl_fd);
                    epoll_del(server->epoll_fd, cl_fd);
                    close(cl_fd);
                    DBG("Closed fd %d", cl_fd);
                    closed = 1;
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
                        cleanup_pending_sends(server, cl_fd);
                        client_fd_remove(server, cl_fd);
                        epoll_del(server->epoll_fd, cl_fd);
                        close(cl_fd);
                        closed = 1;
                    } else if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        DBG("EPOLLOUT: recv peek error on fd %d: %s", cl_fd, strerror(errno));
                        cleanup_pending_sends(server, cl_fd);
                        client_fd_remove(server, cl_fd);
                        epoll_del(server->epoll_fd, cl_fd);
                        close(cl_fd);
                        closed = 1;
                    }
                }

                /* If we get here, no EPOLLIN, so handle errors/hangup */
                if (!closed && (ev->events & (EPOLLERR | EPOLLHUP))) {
                    DBG("EPOLLHUP/ERR on fd %d, cleaning up", cl_fd);
                    cleanup_pending_sends(server, cl_fd);
                    client_fd_remove(server, cl_fd);
                    epoll_del(server->epoll_fd, cl_fd);
                    close(cl_fd);
                    DBG("Closed fd %d", cl_fd);
                }

                next_event: ;
            }
        }

        /* After event processing, handle decisions again (in case they were added) */
        pthread_mutex_lock(&server->decision_mutex);
        while (server->decision_queue && server->decision_queue->ready) {
            rbox_server_decision_t *dec = server->decision_queue;
            server->decision_queue = (void*)dec->next;
            if (!server->decision_queue) server->decision_tail = NULL;
            server->decision_count--;
            pthread_mutex_unlock(&server->decision_mutex);
            DBG("Processing decision for fd %d (after events)", dec->request ? dec->request->fd : -1);

            if (!dec || !dec->request) {
                free(dec);
                pthread_mutex_lock(&server->decision_mutex);
                continue;
            }

            rbox_server_request_t *req = dec->request;
            if (req) {
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
                        resp = NULL;
                        req = NULL;
                    }
                } else {
                    DBG("Failed to build response for fd %d", req->fd);
                }
                if (dec->env_decision_names) {
                    for (int i = 0; i < dec->env_decision_count; i++) free(dec->env_decision_names[i]);
                    free(dec->env_decision_names);
                }
                free(dec->env_decisions);
            }
            free(dec);
            pthread_mutex_lock(&server->decision_mutex);
        }
        pthread_mutex_unlock(&server->decision_mutex);
        DBG("decision_mutex unlocked (after events)");
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
    pthread_mutex_init(&srv->decision_mutex, NULL);
    pthread_cond_init(&srv->decision_cond, NULL);
    pthread_mutex_init(&srv->cache_mutex, NULL);
    pthread_mutex_init(&srv->send_mutex, NULL);
    pthread_mutex_init(&srv->client_fd_mutex, NULL);
    atomic_flag_clear(&srv->stop_flag);
    srv->client_fds = NULL;
    srv->active_client_count = 0;
    srv->send_queue = srv->send_tail = NULL;
    srv->send_count = 0;
    rbox_server_cache_init(srv);
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
    pthread_mutex_destroy(&server->mutex);
    pthread_cond_destroy(&server->cond);
    pthread_mutex_destroy(&server->decision_mutex);
    pthread_cond_destroy(&server->decision_cond);
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

    pthread_mutex_lock(&server->decision_mutex);
    if (server->decision_tail) server->decision_tail->next = (void*)dec;
    else server->decision_queue = dec;
    server->decision_tail = dec;
    server->decision_count++;
    pthread_cond_signal(&server->decision_cond);
    pthread_mutex_unlock(&server->decision_mutex);

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
