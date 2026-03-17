/*
 * server.c - Server thread implementation for rbox-protocol
 *
 * Note: Uses standard malloc/free. For high-performance scenarios,
 * a lock-free pool allocator can be added later.
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

#include "rbox_protocol.h"
#include "socket.h"
#include "server.h"

/* Debug flag - set to 1 to enable request_id tracing */
#ifndef RBOX_SERVER_DEBUG
#define RBOX_SERVER_DEBUG 1
#endif

/* Debug helper to print request_id */
static void debug_print_request_id(const char *msg, const uint8_t *request_id) {
    if (RBOX_SERVER_DEBUG) {
        fprintf(stderr, "[DEBUG] %s: %02x%02x%02x%02x-%02x%02x%02x%02x-%02x%02x%02x%02x-%02x%02x%02x%02x\n",
                msg,
                request_id[0], request_id[1], request_id[2], request_id[3],
                request_id[4], request_id[5], request_id[6], request_id[7],
                request_id[8], request_id[9], request_id[10], request_id[11],
                request_id[12], request_id[13], request_id[14], request_id[15]);
    }
}

/* ============================================================
 * FORWARD DECLARATIONS
 * ============================================================ */

/* Encode response body (decision, reason, fenv decisions) to buffer
 * Returns: number of bytes written, or 0 on error */
static size_t rbox_encode_response_body(uint8_t decision, const char *reason,
                            uint32_t fenv_hash, int env_decision_count,
                            uint8_t *env_decisions, char *body_buf, size_t body_buf_size) {
    size_t reason_len = reason ? strlen(reason) : 0;
    if (reason_len > RBOX_RESPONSE_MAX_REASON) reason_len = RBOX_RESPONSE_MAX_REASON;

    size_t bitmap_size = 0;
    if (env_decision_count > 0 && env_decisions) bitmap_size = (env_decision_count + 7) / 8;

    size_t body_len = 1 + reason_len + 1 + 4 + 2 + bitmap_size;
    if (body_len > body_buf_size) return 0;

    size_t pos = 0;
    body_buf[pos++] = decision;
    if (reason_len > 0) {
        memcpy(body_buf + pos, reason, reason_len);
        pos += reason_len;
    }
    body_buf[pos++] = '\0';
    *(uint32_t *)(body_buf + pos) = fenv_hash;
    pos += 4;
    *(uint16_t *)(body_buf + pos) = (uint16_t)env_decision_count;
    pos += 2;
    if (bitmap_size > 0 && env_decisions) {
        memcpy(body_buf + pos, env_decisions, bitmap_size);
        pos += bitmap_size;
    }
    return pos;
}

/* Build response packet - encodes header and body with checksums
 * This is the SINGLE function for building response packets */
char *rbox_build_response_internal(uint8_t *client_id, uint8_t *request_id, uint32_t cmd_hash,
                           uint8_t decision, const char *reason, uint32_t duration,
                           uint32_t fenv_hash, int env_decision_count, uint8_t *env_decisions,
                           size_t *out_len) {
    /* Duration is used by caller for caching, not encoded in response */
    (void)duration;

    /* Encode body first */
    size_t body_buf_size = 1 + RBOX_RESPONSE_MAX_REASON + 1 + 4 + 2 + 256;
    char *body_buf = alloca(body_buf_size);
    size_t body_len = rbox_encode_response_body(decision, reason, fenv_hash, env_decision_count, env_decisions, body_buf, body_buf_size);
    if (body_len == 0) return NULL;

    size_t total_len = RBOX_HEADER_SIZE + body_len;
    char *pkt = malloc(total_len);
    if (!pkt) return NULL;
    memset(pkt, 0, total_len);

    /* Header */
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_MAGIC) = RBOX_MAGIC;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_VERSION) = RBOX_VERSION;
    if (client_id) {
        memcpy(pkt + RBOX_HEADER_OFFSET_CLIENT_ID, client_id, 16);
    }
    if (request_id) {
        memcpy(pkt + RBOX_HEADER_OFFSET_REQUEST_ID, request_id, 16);
    }
    memset(pkt + RBOX_HEADER_OFFSET_SERVER_ID, 'S', 16);
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_TYPE) = 0;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_FLAGS) = 0;
    *(uint64_t *)(pkt + RBOX_HEADER_OFFSET_OFFSET) = 0;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHUNK_LEN) = body_len;
    *(uint64_t *)(pkt + RBOX_HEADER_OFFSET_TOTAL_LEN) = body_len;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CMD_HASH) = cmd_hash;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_FENV_HASH) = fenv_hash;

    /* Copy body */
    memcpy(pkt + RBOX_HEADER_SIZE, body_buf, body_len);

    /* Header checksum (bytes 0-118, excluding checksum at 119) */
    uint32_t checksum = rbox_calculate_checksum_crc32(0, pkt, RBOX_HEADER_OFFSET_CHECKSUM);
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHECKSUM) = checksum;

    /* Body checksum (bytes 127 onwards) */
    uint32_t body_checksum = rbox_calculate_checksum_crc32(0, pkt + RBOX_HEADER_SIZE, body_len);
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_BODY_CHECKSUM) = body_checksum;

    *out_len = total_len;
    return pkt;
}

static void send_queue_add(rbox_server_handle_t *server, int fd, char *data, size_t len, rbox_server_request_t *req);
static int response_cache_lookup(rbox_server_handle_t *server,
                                 const uint8_t *client_id,
                                 const uint8_t *request_id,
                                 uint32_t packet_checksum,
                                 uint32_t cmd_hash, uint64_t cmd_hash2,
                                 uint32_t fenv_hash,
                                 uint8_t *decision, char *reason, uint32_t *duration);
static void response_cache_insert(rbox_server_handle_t *server,
                                  const uint8_t *client_id,
                                  const uint8_t *request_id,
                                  uint32_t packet_checksum,
                                  uint32_t cmd_hash, uint64_t cmd_hash2,
                                  uint32_t fenv_hash,
                                  uint8_t decision, const char *reason, uint32_t duration);
static void server_request_free(rbox_server_request_t *req);

/* ============================================================
 * SEND QUEUE - For non-blocking responses
 * ============================================================ */

/* Queue a response for sending via epoll (non-blocking) */
static void send_queue_add(rbox_server_handle_t *server, int fd, char *data, size_t len, rbox_server_request_t *req) {
    rbox_server_send_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        free(data);
        return;
    }
    entry->fd = fd;
    entry->data = data;
    entry->len = len;
    entry->request = req;  /* Store request pointer for later cleanup */

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

    /* Add socket to epoll for EPOLLOUT - response will be sent when ready */
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLOUT;  /* Keep EPOLLIN for new requests, add EPOLLOUT for response */
    ev.data.fd = fd;

    /* Try MOD first (fd already in epoll from accept), if fails try ADD */
    int mod_result = epoll_ctl(server->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
    if (mod_result < 0) {
        int add_result = epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
        fprintf(stderr, "[DEBUG] send_queue_add: MOD failed (%s), ADD result=%d, fd=%d\n",
                strerror(errno), add_result, fd);
    } else {
        fprintf(stderr, "[DEBUG] send_queue_add: MOD succeeded, fd=%d\n", fd);
    }
}

/* ============================================================
 * RESPONSE CACHE
 * ============================================================ */

/* Response cache lookup - returns 1 if found, fills in decision/reason/duration */
/*
 * Matching criteria:
 * - Once (duration=0): ClientID + RequestID + packet_checksum (always return cached)
 * - Duration > 0: cmd_hash + cmd_hash2 + fenv_hash + fenv_hash2 (with expiration check)
 */
static int response_cache_lookup(rbox_server_handle_t *server,
                                 const uint8_t *client_id,
                                 const uint8_t *request_id,
                                 uint32_t packet_checksum,
                                 uint32_t cmd_hash, uint64_t cmd_hash2,
                                 uint32_t fenv_hash,
                                 uint8_t *decision, char *reason, uint32_t *duration) {
    pthread_mutex_lock(&server->cache_mutex);
    time_t now = time(NULL);
    for (int i = 0; i < RBOX_RESPONSE_CACHE_SIZE; i++) {
        /* Only match valid entries */
        if (!server->response_cache[i].valid) continue;

        /* Check for match */
        int match = 0;

        /* For once decisions (duration=0): match client_id + request_id + packet_checksum */
        if (server->response_cache[i].duration == 0) {
            if (memcmp(server->response_cache[i].client_id, client_id, 16) == 0 &&
                memcmp(server->response_cache[i].request_id, request_id, 16) == 0 &&
                server->response_cache[i].packet_checksum == packet_checksum) {
                match = 1;
            }
        } else {
            /* For duration decisions: check expiration first */
            if (server->response_cache[i].expires_at > 0 &&
                now > server->response_cache[i].expires_at) {
                /* Entry expired - mark invalid and skip */
                server->response_cache[i].valid = 0;
                continue;
            }

            /* Compute fenv_hash2 for matching */
            uint64_t fenv_hash2 = ((uint64_t)fenv_hash << 32) | (((uint64_t)fenv_hash << 16) ^ 0xDEADBEEF);

            /* Match by cmd_hash + cmd_hash2 + fenv_hash + fenv_hash2 */
            if (server->response_cache[i].cmd_hash == cmd_hash &&
                server->response_cache[i].cmd_hash2 == cmd_hash2 &&
                server->response_cache[i].fenv_hash == fenv_hash &&
                server->response_cache[i].fenv_hash2 == fenv_hash2) {
                match = 1;
            }
        }

        if (match) {
            /* Copy response data before releasing lock */
            *decision = server->response_cache[i].decision;
            strncpy(reason, server->response_cache[i].reason, 255);
            *duration = server->response_cache[i].duration;
            pthread_mutex_unlock(&server->cache_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&server->cache_mutex);
    return 0;
}

/* Response cache insert - stores response for future duplicate requests */
/* Stores client_id, request_id, packet_checksum, cmd_hash, cmd_hash2, fenv_hash, fenv_hash2 */
static void response_cache_insert(rbox_server_handle_t *server,
                                  const uint8_t *client_id,
                                  const uint8_t *request_id,
                                  uint32_t packet_checksum,
                                  uint32_t cmd_hash, uint64_t cmd_hash2,
                                  uint32_t fenv_hash,
                                  uint8_t decision, const char *reason, uint32_t duration) {
    pthread_mutex_lock(&server->cache_mutex);
    int idx = server->response_cache_next;
    server->response_cache_next = (idx + 1) % RBOX_RESPONSE_CACHE_SIZE;

    rbox_response_cache_entry_t *entry = &server->response_cache[idx];
    memcpy(entry->client_id, client_id, 16);
    memcpy(entry->request_id, request_id, 16);
    entry->packet_checksum = packet_checksum;
    entry->cmd_hash = cmd_hash;
    entry->cmd_hash2 = cmd_hash2;
    entry->fenv_hash = fenv_hash;
    /* Compute fenv_hash2 from fenv_hash (simple 64-bit extension) */
    entry->fenv_hash2 = ((uint64_t)fenv_hash << 32) | (((uint64_t)fenv_hash << 16) ^ 0xDEADBEEF);
    entry->decision = decision;
    /* Reason max is 255 bytes, ensure null termination */
    if (reason && *reason) {
        snprintf(entry->reason, sizeof(entry->reason), "%.*s", 254, reason);
    } else {
        entry->reason[0] = '\0';
    }
    entry->duration = duration;
    entry->timestamp = time(NULL);

    /* Calculate expiration time if duration > 0 */
    if (duration > 0) {
        entry->expires_at = entry->timestamp + duration;
    } else {
        entry->expires_at = 0;  /* Never expires */
    }

    entry->valid = 1;
    pthread_mutex_unlock(&server->cache_mutex);
}

/* ============================================================
 * REQUEST HELPERS
 * ============================================================ */

/* Free server request */
static void server_request_free(rbox_server_request_t *req) {
    if (!req) return;
    if (req->fd >= 0) {
        close(req->fd);
    }
    free(req->command_data);

    /* Free env vars */
    if (req->env_var_names) {
        for (int i = 0; i < req->env_var_count; i++) {
            free(req->env_var_names[i]);
        }
        free(req->env_var_names);
    }
    free(req->env_var_scores);

    free(req);
}

/* Read header from client (v9 protocol) */
static int server_read_header(int fd, uint8_t *client_id, uint8_t *request_id, uint32_t *cmd_hash,
                               uint32_t *fenv_hash,
                               char *caller, size_t caller_len, char *syscall, size_t syscall_len,
                               uint32_t *chunk_len) {
    char header[RBOX_HEADER_SIZE];
    /* Use timeout to prevent indefinite blocking (DoS vulnerability) */
    ssize_t n = rbox_read_timeout(fd, header, RBOX_HEADER_SIZE, RBOX_SERVER_READ_TIMEOUT);
    if (n != RBOX_HEADER_SIZE) {
        if (n == 0 && errno == ETIMEDOUT) {
            fprintf(stderr, "ERROR: server_read_header timeout on fd %d\n", fd);
        }
        return -1;
    }

    /* Validate magic and version */
    uint32_t magic = *(uint32_t *)header;
    uint32_t version = *(uint32_t *)(header + 4);
    if (magic != RBOX_MAGIC || version != RBOX_VERSION) {
        return -1;
    }

    /* Validate header checksum */
    if (rbox_header_validate(header, RBOX_HEADER_SIZE) != RBOX_OK) {
        return -1;
    }

    /* Get client_id and request_id */
    memcpy(client_id, header + RBOX_HEADER_OFFSET_CLIENT_ID, 16);
    memcpy(request_id, header + RBOX_HEADER_OFFSET_REQUEST_ID, 16);
    debug_print_request_id("server_read_header: request_id from packet", request_id);

    /* Get cmd_hash */
    *cmd_hash = *(uint32_t *)(header + RBOX_HEADER_OFFSET_CMD_HASH);

    /* Get fenv_hash (v9) */
    *fenv_hash = *(uint32_t *)(header + RBOX_HEADER_OFFSET_FENV_HASH);

    /* Get caller and syscall from header */
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

    /* Get chunk_len */
    *chunk_len = *(uint32_t *)(header + RBOX_HEADER_OFFSET_CHUNK_LEN);
    if (*chunk_len > 1024 * 1024) { /* 1MB max */
        return -1;
    }

    return 0;
}

/* Read request body with timeout to prevent indefinite blocking */
static char *read_body(int fd, uint32_t chunk_len) {
    if (chunk_len == 0) {
        char *empty = malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }

    char *data = malloc(chunk_len + 1);
    if (!data) return NULL;

    /* Use timeout to prevent indefinite blocking (DoS vulnerability) */
    ssize_t n = rbox_read_timeout(fd, data, chunk_len, RBOX_SERVER_READ_TIMEOUT);
    if (n != (ssize_t)chunk_len) {
        if (n == 0 && errno == ETIMEDOUT) {
            fprintf(stderr, "ERROR: read_body timeout on fd %d\n", fd);
        }
        free(data);
        return NULL;
    }

    data[chunk_len] = '\0';
    return data;
}

/* ============================================================
 * SERVER THREAD
 * ============================================================ */

/* Remove from epoll */
static int epoll_del(int epoll_fd, int fd) {
    struct epoll_event ev = {0};
    return epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ev);
}

/* Background server thread */
static void *server_thread_func(void *arg) {
    rbox_server_handle_t *server = arg;
    struct epoll_event events[64];

    /* Create epoll instance */
    server->epoll_fd = epoll_create1(0);
    if (server->epoll_fd < 0) {
        return NULL;
    }

    /* Add listen socket to epoll - use fd as key */
    struct epoll_event lev = {
        .events = EPOLLIN,
        .data.fd = server->listen_fd
    };
    if (epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, server->listen_fd, &lev) < 0) {
        close(server->epoll_fd);
        return NULL;
    }

    /* Add wake eventfd to epoll */
    if (server->wake_fd >= 0) {
        struct epoll_event wev = {
            .events = EPOLLIN,
            .data.fd = server->wake_fd
        };
        epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, server->wake_fd, &wev);
    }

    while (server->running) {
        /* First, check for pending decisions */
        pthread_mutex_lock(&server->decision_mutex);
        while (server->decision_queue && server->decision_queue->ready) {
            rbox_server_decision_t *dec = server->decision_queue;
            server->decision_queue = (void*)dec->next;
            if (!server->decision_queue) {
                server->decision_tail = NULL;
            }
            server->decision_count--;
            pthread_mutex_unlock(&server->decision_mutex);

            /* CRITICAL: Check dec is valid before using */
            if (!dec || !dec->request) {
                fprintf(stderr, "ERROR: dec=%p req=%p\n", (void*)dec, (void*)(dec ? dec->request : NULL));
                continue;
            }

            /* Actually send the decision (now on epoll thread) */
            rbox_server_request_t *req = dec->request;

            /* Continue processing... */

            if (req) {
                size_t resp_len;
                uint32_t cmd_hash = req->cmd_hash;

                /* Compute 64-bit hash of command for time-limited decisions */
                uint64_t cmd_hash2 = 0;
                if (req->command_data && req->command_len > 0) {
                    cmd_hash2 = rbox_hash64(req->command_data, req->command_len);
                }

                /* Compute packet checksum from request body for once decisions */
                uint32_t packet_checksum = 0;
                if (req->command_data && req->command_len > 0) {
                    packet_checksum = rbox_calculate_checksum_crc32(0, req->command_data, req->command_len);
                }

                /* First, store response in cache for duplicate requests */
                response_cache_insert(server, req->client_id, req->request_id, packet_checksum,
                                      cmd_hash, cmd_hash2,
                                      dec->fenv_hash, dec->decision, dec->reason, dec->duration);

                /* Build response and queue for non-blocking send via epoll */
                debug_print_request_id("Decision queue: building response with request_id", req->request_id);
                char *resp = rbox_build_response_internal(req->client_id, req->request_id, cmd_hash,
                    dec->decision, dec->reason, dec->duration,
                    dec->fenv_hash, dec->env_decision_count, (uint8_t *)dec->env_decisions, &resp_len);

                if (resp) {
                    /* Queue for send via central epoll loop - NOT a blocking write */
                    send_queue_add(server, req->fd, resp, resp_len, req);
                    /* Don't close fd or free req yet - epoll will handle send then cleanup */
                }
                /* Request will be freed after send completes (in EPOLLOUT handler) */

                /* Free env decisions */
                if (dec->env_decision_names) {
                    for (int i = 0; i < dec->env_decision_count; i++) {
                        free(dec->env_decision_names[i]);
                    }
                    free(dec->env_decision_names);
                }
                free(dec->env_decisions);
            }
            free(dec);
            pthread_mutex_lock(&server->decision_mutex);
        }
        pthread_mutex_unlock(&server->decision_mutex);

        /* Process epoll events */
        int n = epoll_wait(server->epoll_fd, events, 64, 100); /* 100ms timeout */
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (n == 0) {
            /* Timeout - just continue */
            continue;
        }


        for (int i = 0; i < n; i++) {
            struct epoll_event *ev = &events[i];

            /* Listen socket - accept new connection */
            if (ev->data.fd == server->listen_fd) {
                struct sockaddr_un addr;
                socklen_t addrlen = sizeof(addr);
                int cl_fd = accept(server->listen_fd, (struct sockaddr *)&addr, &addrlen);
                if (cl_fd >= 0) {
                    /* Add to epoll for reading - use fd as key */
                    struct epoll_event cev = {
                        .events = EPOLLIN,
                        .data.fd = cl_fd
                    };
                    epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, cl_fd, &cev);
                }
                continue;
            }

            /* Check for wake event */
            if (server->wake_fd >= 0 && ev->data.fd == server->wake_fd) {
                /* Drain the eventfd */
                uint64_t val;
                ssize_t r;
                do {
                    r = read(server->wake_fd, &val, sizeof(val));
                } while (r < 0 && (errno == EINTR || errno == EAGAIN));
                continue;
            }

            /* Client socket event */
            int cl_fd = ev->data.fd;

            if (cl_fd < 0) {
                continue;
            }

            if (ev->events & (EPOLLERR | EPOLLHUP)) {
                /* Error or hangup - close */
                epoll_del(server->epoll_fd, cl_fd);
                close(cl_fd);
                continue;
            }

            /* Handle EPOLLOUT - try to send pending response */
            if (ev->events & EPOLLOUT) {
                /* Look for pending response in send queue for this fd */
                pthread_mutex_lock(&server->send_mutex);
                rbox_server_send_entry_t **prev = &server->send_queue;
                rbox_server_send_entry_t *entry = server->send_queue;
                while (entry) {
                    if (entry->fd == cl_fd) {
                        /* Found pending response for this fd */
                        *prev = entry->next;
                        if (!entry->next) {
                            server->send_tail = *prev;
                        }
                        server->send_count--;
                        pthread_mutex_unlock(&server->send_mutex);

                        /* Send response (non-blocking, socket ready for write) */
                        ssize_t n = write(entry->fd, entry->data, entry->len);
                        if (n < 0) {
                            /* Write failed - log error and cleanup */
                            fprintf(stderr, "ERROR: write failed on fd %d: %s\n", entry->fd, strerror(errno));
                        } else if ((size_t)n < entry->len) {
                            /* Partial write - could implement retry but for now just log */
                            fprintf(stderr, "ERROR: partial write on fd %d: %zu of %zu bytes\n",
                                    entry->fd, (size_t)n, entry->len);
                        } else {
                            fprintf(stderr, "[DEBUG] EPOLLOUT: successfully wrote %zd bytes to fd %d\n", n, entry->fd);
                            /* Print the request_id in the response for debugging */
                            if (entry->request) {
                                fprintf(stderr, "[DEBUG] EPOLLOUT: response request_id: %02x%02x%02x%02x-%02x%02x%02x%02x-%02x%02x%02x%02x-%02x%02x%02x%02x\n",
                                        entry->request->request_id[0], entry->request->request_id[1],
                                        entry->request->request_id[2], entry->request->request_id[3],
                                        entry->request->request_id[4], entry->request->request_id[5],
                                        entry->request->request_id[6], entry->request->request_id[7],
                                        entry->request->request_id[8], entry->request->request_id[9],
                                        entry->request->request_id[10], entry->request->request_id[11],
                                        entry->request->request_id[12], entry->request->request_id[13],
                                        entry->request->request_id[14], entry->request->request_id[15]);
                            }
                        }

                        /* Free associated request (but don't close fd - send queue handles it) */
                        if (entry->request) {
                            entry->request->fd = -1;  /* Prevent double-close in server_request_free */
                            server_request_free(entry->request);
                        }

                        /* Instead of closing the fd, update epoll to receive next request */
                        if (entry->fd >= 0) {
                            struct epoll_event rev;
                            memset(&rev, 0, sizeof(rev));
                            rev.events = EPOLLIN;  /* Ready for next request */
                            rev.data.fd = entry->fd;
                            if (epoll_ctl(server->epoll_fd, EPOLL_CTL_MOD, entry->fd, &rev) < 0) {
                                fprintf(stderr, "[DEBUG] EPOLLOUT: failed to MOD fd %d: %s\n",
                                        entry->fd, strerror(errno));
                                close(entry->fd);
                            } else {
                                fprintf(stderr, "[DEBUG] EPOLLOUT: MOD fd %d to EPOLLIN for next request\n", entry->fd);
                            }
                        }
                        free(entry->data);
                        free(entry);
                        break;
                    }
                    prev = &entry->next;
                    entry = entry->next;
                }
                if (!entry) {
                    pthread_mutex_unlock(&server->send_mutex);
                }
                /* If no pending response, just continue */
            }

            if (ev->events & EPOLLIN) {
                fprintf(stderr, "[DEBUG] EPOLLIN: fd=%d, processing request\n", cl_fd);

                /* Try to read request */
                uint8_t client_id[16], request_id[16];
                uint32_t cmd_hash, fenv_hash, chunk_len;
                char caller[RBOX_MAX_CALLER_LEN + 1];
                char syscall[RBOX_MAX_SYSCALL_LEN + 1];

                int hdr_result = server_read_header(cl_fd, client_id, request_id, &cmd_hash, &fenv_hash,
                    caller, sizeof(caller), syscall, sizeof(syscall), &chunk_len);
                fprintf(stderr, "[DEBUG] EPOLLIN: hdr_result=%d for fd=%d\n", hdr_result, cl_fd);

                if (hdr_result == 0) {

                    /* Read the body first so we can compute cmd_hash2 for cache lookup */
                    char *cmd_data = read_body(cl_fd, chunk_len);

                    /* Compute 64-bit hash for time-limited decision matching */
                    uint64_t cmd_hash2 = 0;
                    if (cmd_data && chunk_len > 0) {
                        cmd_hash2 = rbox_hash64(cmd_data, chunk_len);
                    }

                    // Check response cache for duplicate request (now includes cmd_hash2 and fenv_hash)
                    uint8_t cached_decision;
                    char cached_reason[256];
                    uint32_t cached_duration;
                    /* Compute packet checksum from request body for cache lookup */
                    uint32_t packet_checksum = 0;
                    if (cmd_data && chunk_len > 0) {
                        packet_checksum = rbox_calculate_checksum_crc32(0, cmd_data, chunk_len);
                    }

                    /* Check response cache - for once: client_id+request_id+packet_checksum */
                    /* for duration: cmd_hash+cmd_hash2+fenv_hash+fenv_hash2 */
                    if (response_cache_lookup(server, client_id, request_id, packet_checksum, cmd_hash, cmd_hash2, fenv_hash, &cached_decision, cached_reason, &cached_duration)) {
                        /* Send cached response via send queue for non-blocking send */
                        size_t resp_len;
                        /* Note: Cached responses don't include env decisions  */
                        char *resp = rbox_build_response_internal(client_id, request_id, cmd_hash, cached_decision, cached_reason, cached_duration, 0, 0, NULL, &resp_len);
                        if (resp) {
                            /* Queue for send via central epoll loop - NOT a blocking write */
                            send_queue_add(server, cl_fd, resp, resp_len, NULL);
                            /* Don't close fd yet - epoll will handle send then close */
                        }
                        free(cmd_data);
                        /* Request handled via send queue - continue to next event */
                        continue;
                    }

                    if (cmd_data) {

                        /* Create request handle */
                        rbox_server_request_t *req = calloc(1, sizeof(*req));
                        if (req) {
                            req->fd = cl_fd;
                            memcpy(req->client_id, client_id, 16);
                            memcpy(req->request_id, request_id, 16);
                            debug_print_request_id("EPOLLIN: stored request_id in req", req->request_id);
                            req->cmd_hash = cmd_hash;
                            req->server = server;
                            req->command_data = cmd_data;
                            req->command_len = chunk_len;

                            /* Store caller and syscall  */
                            strncpy(req->caller, caller, RBOX_MAX_CALLER_LEN);
                            req->caller[RBOX_MAX_CALLER_LEN] = '\0';
                            strncpy(req->syscall, syscall, RBOX_MAX_SYSCALL_LEN);
                            req->syscall[RBOX_MAX_SYSCALL_LEN] = '\0';

                            /* Parse command */
                            rbox_command_parse(cmd_data, chunk_len, &req->parse);

                            /* Parse env vars from body (after command/args) */
                            /* Format: command\0args...\0env_name\0score(4 bytes)... */
                            /* Find end of args by scanning for double-null */
                            const char *p = cmd_data;
                            const char *args_end = cmd_data;
                            while (p < cmd_data + chunk_len) {
                                if (*p == '\0') {
                                    if (p == args_end || *(p-1) == '\0') {
                                        /* Double null - args end */
                                        args_end = p + 1;
                                        break;
                                    }
                                    args_end = p + 1;
                                }
                                p++;
                            }

                            /* Now parse env vars from args_end */
                            p = args_end;
                            size_t remaining = chunk_len - (p - cmd_data);

                            while (remaining > 5) {
                                size_t name_len = strlen(p);
                                if (name_len == 0 || name_len > remaining - 4) break;

                                req->env_var_count++;
                                p += name_len + 1;  /* skip name + null */
                                p += 4;  /* skip score */
                                remaining -= name_len + 1 + 4;
                            }

                            /* Allocate arrays and parse */
                            if (req->env_var_count > 0) {
                                req->env_var_names = calloc(req->env_var_count, sizeof(char *));
                                req->env_var_scores = calloc(req->env_var_count, sizeof(float));

                                p = args_end;
                                remaining = chunk_len - (p - cmd_data);
                                int idx = 0;

                                while (remaining > 5 && idx < req->env_var_count) {
                                    size_t name_len = strlen(p);
                                    if (name_len == 0 || name_len > remaining - 4) break;

                                    req->env_var_names[idx] = strndup(p, name_len);
                                    memcpy(&req->env_var_scores[idx], p + name_len + 1, 4);

                                    /* Compute fenv_hash */
                                    const char *s = req->env_var_names[idx];
                                    uint32_t h = 5381;
                                    while (*s) {
                                        h = ((h << 5) + h) + (uint32_t)(unsigned char)*s++;
                                    }
                                    req->fenv_hash ^= h;

                                    p += name_len + 1 + 4;
                                    remaining -= name_len + 1 + 4;
                                    idx++;
                                }
                            }

                            /* Add to queue and signal */
                            pthread_mutex_lock(&server->mutex);
                            req->next = NULL;
                            fprintf(stderr, "[DEBUG] enqueue: before - count=%d, queue=%p, tail=%p, new_req=%p\n",
                                    server->request_count, (void*)server->request_queue,
                                    (void*)server->request_tail, (void*)req);
                            if (server->request_tail) {
                                server->request_tail->next = req;
                                server->request_tail = req;
                            } else {
                                server->request_queue = req;
                                server->request_tail = req;
                            }
                            server->request_count++;
                            fprintf(stderr, "[DEBUG] enqueue: after - count=%d, queue=%p, tail=%p\n",
                                    server->request_count, (void*)server->request_queue, (void*)server->request_tail);
                            pthread_cond_signal(&server->cond);
                            pthread_mutex_unlock(&server->mutex);

                            /* Remove from epoll - caller now owns fd */
                            epoll_del(server->epoll_fd, cl_fd);

                            /* Continue to next event */
                            continue;
                        }
                        free(cmd_data);
                    }
                }

                /* Read failed - close connection */
                epoll_del(server->epoll_fd, cl_fd);
                close(cl_fd);
            }
        }
    }

    /* Cleanup */
    close(server->epoll_fd);

    return NULL;
}

/* ============================================================
 * SERVER HANDLE MANAGEMENT
 * ============================================================ */

/* Create blocking server handle */
rbox_server_handle_t *rbox_server_handle_new(const char *socket_path) {
    if (!socket_path) return NULL;

    rbox_server_handle_t *srv = calloc(1, sizeof(*srv));
    if (!srv) return NULL;

    strncpy(srv->socket_path, socket_path, sizeof(srv->socket_path) - 1);

    /* Create Unix domain socket */
    srv->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv->listen_fd < 0) {
        free(srv);
        return NULL;
    }

    /* Remove old socket file */
    unlink(socket_path);

    /* Bind */
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    if (bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(srv->listen_fd);
        free(srv);
        return NULL;
    }

    /* Initialize mutex/cond */
    pthread_mutex_init(&srv->mutex, NULL);
    pthread_cond_init(&srv->cond, NULL);
    pthread_mutex_init(&srv->decision_mutex, NULL);
    pthread_cond_init(&srv->decision_cond, NULL);
    pthread_mutex_init(&srv->cache_mutex, NULL);
    pthread_mutex_init(&srv->send_mutex, NULL);

    /* Initialize send queue */
    srv->send_queue = NULL;
    srv->send_tail = NULL;
    srv->send_count = 0;

    /* Initialize response cache - set all to invalid */
    for (int i = 0; i < RBOX_RESPONSE_CACHE_SIZE; i++) {
        srv->response_cache[i].valid = 0;
    }
    srv->response_cache_next = 0;

    /* Create eventfd for waking epoll thread */
    srv->wake_fd = eventfd(0, EFD_NONBLOCK);
    if (srv->wake_fd < 0) {
        srv->wake_fd = -1;
    }

    return srv;
}

/* Start listening */
rbox_error_t rbox_server_handle_listen(rbox_server_handle_t *server) {
    if (!server) return RBOX_ERR_INVALID;

    if (listen(server->listen_fd, 10) < 0) {
        return RBOX_ERR_IO;
    }

    return RBOX_OK;
}

/* Free blocking server */
void rbox_server_handle_free(rbox_server_handle_t *server) {
    if (!server) return;

    if (server->listen_fd >= 0) {
        close(server->listen_fd);
        unlink(server->socket_path);
    }

    /* Close wake_fd */
    if (server->wake_fd >= 0) {
        close(server->wake_fd);
    }

    pthread_mutex_destroy(&server->mutex);
    pthread_cond_destroy(&server->cond);
    pthread_mutex_destroy(&server->decision_mutex);
    pthread_cond_destroy(&server->decision_cond);
    pthread_mutex_destroy(&server->cache_mutex);
    pthread_mutex_destroy(&server->send_mutex);

    free(server);
}

/* Start background thread */
rbox_error_t rbox_server_start(rbox_server_handle_t *server) {
    if (!server) return RBOX_ERR_INVALID;

    server->running = 1;
    server->request_queue = NULL;
    server->request_tail = NULL;
    server->request_count = 0;

    if (pthread_create(&server->thread, NULL, server_thread_func, server) != 0) {
        server->running = 0;
        return RBOX_ERR_IO;
    }

    return RBOX_OK;
}

/* Block until request is ready */
rbox_server_request_t *rbox_server_get_request(rbox_server_handle_t *server) {
    if (!server) return NULL;

    pthread_mutex_lock(&server->mutex);

    while (server->running && server->request_count == 0) {
        pthread_cond_wait(&server->cond, &server->mutex);
    }

    if (!server->running) {
        pthread_mutex_unlock(&server->mutex);
        return NULL;
    }

    /* Pop request from queue */
    rbox_server_request_t *req = server->request_queue;
    fprintf(stderr, "[DEBUG] get_request: before pop - count=%d, queue=%p, req=%p, req->next=%p\n",
            server->request_count, (void*)server->request_queue, (void*)req, (void*)(req ? req->next : NULL));
    server->request_queue = req->next;
    if (server->request_queue == NULL) {
        server->request_tail = NULL;
    }
    req->next = NULL;
    server->request_count--;
    fprintf(stderr, "[DEBUG] get_request: after pop - count=%d, queue=%p, returned req=%p\n",
            server->request_count, (void*)server->request_queue, (void*)req);

    pthread_mutex_unlock(&server->mutex);

    return req;
}

/* Check if server is running */
int rbox_server_is_running(rbox_server_handle_t *server) {
    if (!server) return 0;
    return server->running;
}

/* Queue decision to be sent by background thread (thread-safe) */
rbox_error_t rbox_server_decide(rbox_server_request_t *req,
    uint8_t decision, const char *reason, uint32_t duration,
    int env_decision_count, const char **env_decision_names, const uint8_t *env_decisions) {
    if (!req) return RBOX_ERR_INVALID;

    /* Get server handle from request */
    rbox_server_handle_t *server = req->server;
    if (!server) return RBOX_ERR_INVALID;

    /* Allocate decision struct */
    rbox_server_decision_t *dec = calloc(1, sizeof(*dec));
    if (!dec) return RBOX_ERR_MEMORY;

    dec->request = req;
    dec->decision = decision;
    strncpy(dec->reason, reason ? reason : "", sizeof(dec->reason) - 1);
    dec->duration = duration;
    dec->ready = 1;

    /* Copy env decisions */
    if (env_decision_count > 0 && env_decision_names && env_decisions) {
        dec->env_decision_count = env_decision_count;

        /* Copy names */
        dec->env_decision_names = calloc(env_decision_count, sizeof(char *));
        if (!dec->env_decision_names) {
            /* Allocation failed - free dec and return error */
            free(dec);
            return RBOX_ERR_MEMORY;
        }
        for (int i = 0; i < env_decision_count; i++) {
            if (env_decision_names[i]) {
                dec->env_decision_names[i] = strdup(env_decision_names[i]);
            }
        }

        /* Copy bitmap */
        size_t bitmap_size = (env_decision_count + 7) / 8;
        dec->env_decisions = malloc(bitmap_size);
        if (!dec->env_decisions) {
            /* Allocation failed - free names and dec */
            for (int i = 0; i < env_decision_count; i++) {
                free(dec->env_decision_names[i]);
            }
            free(dec->env_decision_names);
            free(dec);
            return RBOX_ERR_MEMORY;
        }
        memcpy(dec->env_decisions, env_decisions, bitmap_size);

        /* Compute fenv_hash from env var names */
        dec->fenv_hash = 0;
        for (int i = 0; i < env_decision_count; i++) {
            if (env_decision_names[i]) {
                const char *s = env_decision_names[i];
                uint32_t h = 5381;
                while (*s) {
                    h = ((h << 5) + h) + (uint32_t)(unsigned char)*s++;
                }
                dec->fenv_hash ^= h;
            }
        }
    }

    /* Queue decision (thread-safe) */
    pthread_mutex_lock(&server->decision_mutex);
    if (server->decision_tail) {
        server->decision_tail->next = (void*)dec;
    } else {
        server->decision_queue = dec;
    }
    server->decision_tail = dec;
    server->decision_count++;
    pthread_cond_signal(&server->decision_cond);
    pthread_mutex_unlock(&server->decision_mutex);

    /* Wake up epoll thread via eventfd */
    if (server->wake_fd >= 0) {
        uint64_t val = 1;
        ssize_t r;
        do {
            r = write(server->wake_fd, &val, sizeof(val));
        } while (r < 0 && (errno == EINTR || errno == EAGAIN));
    }

    return RBOX_OK;
}

/* Signal shutdown */
void rbox_server_stop(rbox_server_handle_t *server) {
    if (!server) return;

    server->running = 0;

    /* Wake up any waiting thread */
    pthread_mutex_lock(&server->mutex);
    pthread_cond_signal(&server->cond);
    pthread_mutex_unlock(&server->mutex);

    /* Wait for thread to exit */
    if (server->thread) {
        pthread_join(server->thread, NULL);
    }
}

/* ============================================================
 * SERVER REQUEST ACCESSORS
 * ============================================================ */

/* Get command from request */
const char *rbox_server_request_command(const rbox_server_request_t *req) {
    if (!req) return NULL;
    return req->command_data;
}

/* Get argument by index */
const char *rbox_server_request_arg(const rbox_server_request_t *req, int index) {
    uint32_t len;
    if (!req || index < 0 || (uint32_t)index >= req->parse.count) {
        return NULL;
    }
    return rbox_get_subcommand(req->command_data, &req->parse.subcommands[index], &len);
}

/* Get argument count */
int rbox_server_request_argc(const rbox_server_request_t *req) {
    if (!req) return 0;
    return (int)req->parse.count;
}

/* Get parse result */
const rbox_parse_result_t *rbox_server_request_parse(const rbox_server_request_t *req) {
    if (!req) return NULL;
    return &req->parse;
}

/* Get caller from request (null-terminated) */
const char *rbox_server_request_caller(const rbox_server_request_t *req) {
    if (!req) return NULL;
    return req->caller;
}

/* Get syscall from request (null-terminated) */
const char *rbox_server_request_syscall(const rbox_server_request_t *req) {
    if (!req) return NULL;
    return req->syscall;
}

/* Check if request is a stop request */
int rbox_server_request_is_stop(const rbox_server_request_t *req) {
    if (!req || !req->command_data) return 0;
    return (strcmp(req->command_data, "__RBOX_STOP__") == 0);
}

/* Get env var count */
int rbox_server_request_env_var_count(const rbox_server_request_t *req) {
    if (!req) return 0;
    return req->env_var_count;
}

/* Get env var name */
char *rbox_server_request_env_var_name(const rbox_server_request_t *req, int index) {
    if (!req || index < 0 || index >= req->env_var_count) return NULL;
    if (!req->env_var_names || !req->env_var_names[index]) return NULL;
    return strdup(req->env_var_names[index]);
}

/* Get env var score */
float rbox_server_request_env_var_score(const rbox_server_request_t *req, int index) {
    if (!req || index < 0 || index >= req->env_var_count) return 0.0f;
    if (!req->env_var_scores) return 0.0f;
    return req->env_var_scores[index];
}
