/*
 * server_request.c - Request handling for rbox-protocol server
 *
 * Layer 6: Request handling
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include "rbox_protocol.h"
#include "server_internal.h"
#include "socket_io.h"
#include "server_client.h"
#include "server_request.h"

int rbox_server_read_header(int fd,
                           uint8_t *client_id,
                           uint8_t *request_id,
                           uint32_t *cmd_hash,
                           uint32_t *fenv_hash,
                           char *caller, size_t caller_len,
                           char *syscall, size_t syscall_len,
                           uint32_t *chunk_len) {
    char header[RBOX_HEADER_SIZE];
    ssize_t n = rbox_read_nonblocking(fd, header, RBOX_HEADER_SIZE);
    if (n == 0) {
        return 1;
    } else if (n != RBOX_HEADER_SIZE) {
        return -1;
    }
    uint32_t magic = *(uint32_t *)header;
    uint32_t version = *(uint32_t *)(header + 4);
    if (magic != RBOX_MAGIC || version != RBOX_VERSION) return -1;
    if (rbox_header_validate(header, RBOX_HEADER_SIZE) != RBOX_OK) return -1;
    if (client_id) memcpy(client_id, header + RBOX_HEADER_OFFSET_CLIENT_ID, 16);
    if (request_id) memcpy(request_id, header + RBOX_HEADER_OFFSET_REQUEST_ID, 16);
    if (cmd_hash) *cmd_hash = *(uint32_t *)(header + RBOX_HEADER_OFFSET_CMD_HASH);
    if (fenv_hash) *fenv_hash = *(uint32_t *)(header + RBOX_HEADER_OFFSET_FENV_HASH);
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
    if (chunk_len) *chunk_len = *(uint32_t *)(header + RBOX_HEADER_OFFSET_CHUNK_LEN);
    if (chunk_len && *chunk_len > 1024 * 1024) return -1;
    return 0;
}

char *rbox_server_read_body(int fd, uint32_t chunk_len) {
    if (chunk_len == 0) {
        char *empty = malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }
    char *data = malloc(chunk_len + 1);
    if (!data) return NULL;
    ssize_t n = rbox_read_nonblocking(fd, data, chunk_len);
    if (n != (ssize_t)chunk_len) {
        free(data);
        return NULL;
    }
    data[chunk_len] = '\0';
    return data;
}

rbox_server_request_t *rbox_server_request_create(
    rbox_server_handle_t *server,
    int fd,
    const uint8_t *client_id,
    const uint8_t *request_id,
    uint32_t cmd_hash,
    uint32_t fenv_hash,
    const char *caller, size_t caller_len,
    const char *syscall, size_t syscall_len,
    const char *body_data, size_t body_len) {

    rbox_server_request_t *req = calloc(1, sizeof(*req));
    if (!req) return NULL;

    req->fd = fd;
    if (client_id) memcpy(req->client_id, client_id, 16);
    if (request_id) memcpy(req->request_id, request_id, 16);
    req->cmd_hash = cmd_hash;
    req->fenv_hash = fenv_hash;
    req->server = server;

    if (caller && caller_len > 0) {
        size_t copy_len = caller_len < sizeof(req->caller) - 1 ? caller_len : sizeof(req->caller) - 1;
        memcpy(req->caller, caller, copy_len);
        req->caller[copy_len] = '\0';
    }

    if (syscall && syscall_len > 0) {
        size_t copy_len = syscall_len < sizeof(req->syscall) - 1 ? syscall_len : sizeof(req->syscall) - 1;
        memcpy(req->syscall, syscall, copy_len);
        req->syscall[copy_len] = '\0';
    }

    if (body_data && body_len > 0) {
        req->command_data = malloc(body_len + 1);
        if (!req->command_data) {
            free(req);
            return NULL;
        }
        memcpy(req->command_data, body_data, body_len);
        req->command_data[body_len] = '\0';
        req->command_len = body_len;
        rbox_command_parse(req->command_data, body_len, &req->parse);

        const char *p = body_data;
        const char *args_end = body_data;
        while (p < body_data + body_len) {
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
        size_t remaining = body_len - (p - body_data);
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
            remaining = body_len - (p - body_data);
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
    }

    return req;
}

void rbox_server_request_free(rbox_server_request_t *req) {
    if (!req) return;
    if (req->fd >= 0) {
        rbox_server_client_remove(req->server, req->fd);
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

int rbox_server_request_queue(rbox_server_handle_t *server, rbox_server_request_t *req) {
    if (!server || !req) return -1;
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
    pthread_cond_signal(&server->cond);
    pthread_mutex_unlock(&server->mutex);
    return 0;
}