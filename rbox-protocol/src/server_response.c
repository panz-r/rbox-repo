/*
 * server_response.c - Response dispatch for rbox-protocol server
 *
 * Layer 7: Response dispatch
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include "rbox_protocol.h"
#include "protocol.h"
#include "server_internal.h"
#include "server_request.h"
#include "server_response.h"

char *rbox_server_build_response(
    const uint8_t *client_id,
    const uint8_t *request_id,
    uint32_t cmd_hash,
    uint8_t decision,
    const char *reason,
    uint32_t duration,
    uint32_t fenv_hash,
    int env_decision_count,
    uint8_t *env_decisions,
    size_t *out_len) {
    (void)duration;

    if (!out_len) return NULL;

    size_t reason_len = reason ? strlen(reason) : 0;
    if (reason_len > RBOX_RESPONSE_MAX_REASON) reason_len = RBOX_RESPONSE_MAX_REASON;
    size_t bitmap_size = (env_decision_count > 0 && env_decisions) ? (env_decision_count + 7) / 8 : 0;
    size_t body_len = 1 + reason_len + 1 + 4 + 2 + bitmap_size;

    size_t total_len = RBOX_HEADER_SIZE + body_len;
    char *pkt = malloc(total_len);
    if (!pkt) return NULL;
    memset(pkt, 0, total_len);

    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_MAGIC) = RBOX_MAGIC;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_VERSION) = RBOX_VERSION;
    if (client_id) memcpy(pkt + RBOX_HEADER_OFFSET_CLIENT_ID, client_id, 16);
    if (request_id) memcpy(pkt + RBOX_HEADER_OFFSET_REQUEST_ID, request_id, 16);
    memset(pkt + RBOX_HEADER_OFFSET_SERVER_ID, 'S', 16);
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_TYPE) = 0;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_FLAGS) = 0;
    *(uint64_t *)(pkt + RBOX_HEADER_OFFSET_OFFSET) = 0;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHUNK_LEN) = body_len;
    *(uint64_t *)(pkt + RBOX_HEADER_OFFSET_TOTAL_LEN) = body_len;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CMD_HASH) = cmd_hash;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_FENV_HASH) = fenv_hash;

    char *body = pkt + RBOX_HEADER_SIZE;
    size_t pos = 0;
    body[pos++] = decision;
    if (reason_len > 0) {
        memcpy(body + pos, reason, reason_len);
        pos += reason_len;
    }
    body[pos++] = '\0';
    *(uint32_t *)(body + pos) = fenv_hash;
    pos += 4;
    *(uint16_t *)(body + pos) = (uint16_t)env_decision_count;
    pos += 2;
    if (bitmap_size > 0 && env_decisions) {
        memcpy(body + pos, env_decisions, bitmap_size);
        pos += bitmap_size;
    }

    uint32_t checksum = rbox_protocol_checksum_crc32(0, pkt, RBOX_HEADER_OFFSET_CHECKSUM);
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHECKSUM) = checksum;
    uint32_t body_checksum = rbox_protocol_checksum_crc32(0, body, body_len);
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_BODY_CHECKSUM) = body_checksum;

    *out_len = total_len;
    return pkt;
}

int rbox_server_enable_epollout(rbox_server_handle_t *server, int fd) {
    if (!server || fd < 0) return -1;
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
    ev.data.fd = fd;
    if (epoll_ctl(server->epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1) {
        return -1;
    }
    return 0;
}

static void send_pending_locked(rbox_server_handle_t *server, int fd) {
    rbox_client_fd_entry_t *client = client_fd_find(server, fd);
    if (!client) return;

    rbox_server_send_entry_t **prev = &client->send_queue_head;
    rbox_server_send_entry_t *entry = client->send_queue_head;
    while (entry) {
        size_t remaining = entry->len - entry->offset;
        ssize_t w = write(entry->fd, entry->data + entry->offset, remaining);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            *prev = entry->next;
            if (!entry->next) client->send_queue_tail = *prev;
            if (entry->request) {
                entry->request->fd = -1;
                rbox_server_request_free(entry->request);
            }
            free(entry->data);
            free(entry);
            entry = *prev;
            continue;
        } else if (w == 0) {
            *prev = entry->next;
            if (!entry->next) client->send_queue_tail = *prev;
            if (entry->request) {
                entry->request->fd = -1;
                rbox_server_request_free(entry->request);
            }
            free(entry->data);
            free(entry);
            entry = *prev;
            continue;
        } else {
            entry->offset += w;
            if (entry->offset == entry->len) {
                *prev = entry->next;
                if (!entry->next) client->send_queue_tail = *prev;
                if (entry->request) {
                    entry->request->fd = -1;
                    rbox_server_request_free(entry->request);
                }
                free(entry->data);
                free(entry);
                entry = *prev;
            } else {
                break;
            }
        }
    }
}

void rbox_server_try_send(rbox_server_handle_t *server, int fd) {
    if (!server || fd < 0) return;
    pthread_mutex_lock(&server->send_mutex);
    send_pending_locked(server, fd);
    pthread_mutex_unlock(&server->send_mutex);
}

void rbox_server_cleanup_pending(rbox_server_handle_t *server, int fd) {
    if (!server || fd < 0) return;
    pthread_mutex_lock(&server->send_mutex);

    rbox_client_fd_entry_t *client = client_fd_find(server, fd);
    if (!client) {
        pthread_mutex_unlock(&server->send_mutex);
        return;
    }

    rbox_server_send_entry_t **prev = &client->send_queue_head;
    rbox_server_send_entry_t *entry = client->send_queue_head;
    while (entry) {
        *prev = entry->next;
        if (!entry->next) client->send_queue_tail = *prev;
        if (entry->request) {
            entry->request->fd = -1;
            rbox_server_request_free(entry->request);
        }
        free(entry->data);
        free(entry);
        entry = *prev;
    }
    pthread_mutex_unlock(&server->send_mutex);
}

int rbox_server_send_response(rbox_server_handle_t *server, int fd, char *data, size_t len, rbox_server_request_t *req) {
    if (!server || fd < 0 || !data) return -1;

    rbox_server_send_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        free(data);
        if (req) rbox_server_request_free(req);
        return -1;
    }
    entry->fd = fd;
    entry->data = data;
    entry->len = len;
    entry->request = req;
    entry->offset = 0;

    pthread_mutex_lock(&server->send_mutex);

    rbox_client_fd_entry_t *client = client_fd_find(server, fd);
    if (!client) {
        pthread_mutex_unlock(&server->send_mutex);
        free(entry->data);
        free(entry);
        if (req) rbox_server_request_free(req);
        return -1;
    }

    entry->next = NULL;
    if (client->send_queue_tail) {
        client->send_queue_tail->next = entry;
        client->send_queue_tail = entry;
    } else {
        client->send_queue_head = entry;
        client->send_queue_tail = entry;
    }
    pthread_mutex_unlock(&server->send_mutex);

    rbox_server_try_send(server, fd);
    return 0;
}