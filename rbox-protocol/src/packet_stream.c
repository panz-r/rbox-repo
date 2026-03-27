/*
 * packet_stream.c - Chunked transfer streaming for rbox-protocol
 *
 * Layer 4: Chunked transfer - client and server stream management
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/poll.h>

#include "rbox_protocol.h"
#include "socket.h"
#include "socket_io.h"
#include "protocol.h"

/* Stream state for client sending chunks */
struct rbox_stream {
    uint8_t  client_id[16];
    uint8_t  request_id[16];
    uint64_t offset;
    uint64_t total_len;
    int      is_server;
    char    *buffer;
    size_t   buf_capacity;
    size_t   buf_len;
};

rbox_stream_t *rbox_stream_new(const uint8_t *client_id, const uint8_t *request_id) {
    rbox_stream_t *stream = calloc(1, sizeof(rbox_stream_t));
    if (!stream) return NULL;

    if (client_id) memcpy(stream->client_id, client_id, 16);
    if (request_id) memcpy(stream->request_id, request_id, 16);

    stream->offset = 0;
    stream->total_len = 0;
    stream->is_server = 0;

    return stream;
}

rbox_stream_t *rbox_server_stream_new(const uint8_t *client_id, const uint8_t *request_id,
                                       uint64_t total_len) {
    rbox_stream_t *stream = calloc(1, sizeof(rbox_stream_t));
    if (!stream) return NULL;

    if (client_id) memcpy(stream->client_id, client_id, 16);
    if (request_id) memcpy(stream->request_id, request_id, 16);

    stream->offset = 0;
    stream->total_len = total_len;
    stream->is_server = 1;

    if (total_len > 0 && total_len <= RBOX_MAX_TOTAL_SIZE) {
        stream->buffer = malloc(total_len);
        if (!stream->buffer) {
            free(stream);
            return NULL;
        }
        stream->buf_capacity = total_len;
    }

    return stream;
}

void rbox_stream_free(rbox_stream_t *stream) {
    if (!stream) return;
    free(stream->buffer);
    free(stream);
}

uint64_t rbox_stream_offset(const rbox_stream_t *stream) {
    return stream ? stream->offset : 0;
}

rbox_error_t rbox_stream_send_chunk(rbox_client_t *client, rbox_stream_t *stream,
                                     const void *data, size_t len,
                                     uint32_t flags, uint64_t total_len) {
    if (!client || !stream || !data || len == 0) {
        return RBOX_ERR_INVALID;
    }

    char buffer[RBOX_HEADER_SIZE + RBOX_CHUNK_MAX];
    memset(buffer, 0, sizeof(buffer));
    size_t pos = 0;

    uint32_t magic = RBOX_MAGIC;
    memcpy(buffer + pos, &magic, 4);
    pos += 4;

    uint32_t version = RBOX_VERSION;
    memcpy(buffer + pos, &version, 4);
    pos += 4;

    memcpy(buffer + pos, stream->client_id, 16);
    pos += 16;

    memcpy(buffer + pos, stream->request_id, 16);
    pos += 16;

    memset(buffer + pos, 'S', 16);
    pos += 16;

    uint32_t type = (flags & RBOX_FLAG_FIRST) ? RBOX_MSG_REQ : RBOX_MSG_CHUNK;
    memcpy(buffer + pos, &type, 4);
    pos += 4;

    memcpy(buffer + pos, &flags, 4);
    pos += 4;

    memcpy(buffer + pos, &stream->offset, 8);
    pos += 8;

    memcpy(buffer + pos, &len, 4);
    pos += 4;

    memcpy(buffer + pos, &total_len, 8);
    pos += 8;

    uint32_t checksum = rbox_protocol_checksum_crc32(0, buffer, RBOX_HEADER_OFFSET_CHECKSUM);
    memcpy(buffer + RBOX_HEADER_OFFSET_CHECKSUM, &checksum, 4);
    pos += 4;

    memcpy(buffer + RBOX_HEADER_SIZE, data, len);

    ssize_t sent = rbox_write(rbox_client_fd(client), buffer, RBOX_HEADER_SIZE + len);
    if (sent != (ssize_t)(RBOX_HEADER_SIZE + len)) {
        return RBOX_ERR_IO;
    }

    if (flags & RBOX_FLAG_FIRST) {
        stream->total_len = total_len;
        stream->offset = 0;
    }

    return RBOX_OK;
}

rbox_error_t rbox_stream_read_ack(rbox_client_t *client, rbox_stream_t *stream) {
    if (!client || !stream) {
        return RBOX_ERR_INVALID;
    }

    struct pollfd pfd = {
        .fd = rbox_client_fd(client),
        .events = POLLIN,
        .revents = 0
    };

    int poll_ret = poll(&pfd, 1, 5000);
    if (poll_ret <= 0 || !(pfd.revents & POLLIN)) {
        return RBOX_ERR_IO;
    }

    char ack_buf[RBOX_ACK_SIZE + 256];
    ssize_t n = rbox_read(rbox_client_fd(client), ack_buf, sizeof(ack_buf));
    if (n < (ssize_t)RBOX_ACK_SIZE) {
        return RBOX_ERR_TRUNCATED;
    }

    uint32_t magic = *(uint32_t *)ack_buf;
    if (magic != RBOX_MAGIC) {
        return RBOX_ERR_MAGIC;
    }

    uint64_t offset = *(uint64_t *)(ack_buf + RBOX_ACK_OFFSET_OFFSET);
    int32_t status = *(int32_t *)(ack_buf + RBOX_ACK_OFFSET_STATUS);

    stream->offset = offset;

    if (status == RBOX_ACK_ERROR) {
        return RBOX_ERR_INVALID;
    }

    return RBOX_OK;
}

rbox_error_t rbox_server_stream_recv(rbox_client_t *client, rbox_stream_t *stream,
                                      void *buffer, size_t buf_size,
                                      size_t *out_chunk_len) {
    if (!client || !stream || !buffer || !out_chunk_len) {
        return RBOX_ERR_INVALID;
    }

    struct pollfd pfd = {
        .fd = rbox_client_fd(client),
        .events = POLLIN,
        .revents = 0
    };

    int poll_ret = poll(&pfd, 1, 5000);
    if (poll_ret <= 0 || !(pfd.revents & POLLIN)) {
        return RBOX_ERR_IO;
    }

    rbox_header_t header_buf;
    ssize_t n = rbox_read(rbox_client_fd(client), &header_buf, sizeof(header_buf));
    if (n != sizeof(header_buf)) {
        return RBOX_ERR_TRUNCATED;
    }

    if (header_buf.magic != RBOX_MAGIC) {
        return RBOX_ERR_MAGIC;
    }
    if (header_buf.version != RBOX_VERSION) {
        return RBOX_ERR_VERSION;
    }

    if (header_buf.offset != stream->offset) {
        return RBOX_ERR_INVALID;
    }

    size_t chunk_len = header_buf.chunk_len;
    if (chunk_len > buf_size || chunk_len > RBOX_CHUNK_MAX) {
        return RBOX_ERR_INVALID;
    }

    n = rbox_read(rbox_client_fd(client), buffer, chunk_len);
    if (n != (ssize_t)chunk_len) {
        return RBOX_ERR_TRUNCATED;
    }

    if (stream->buffer && stream->buf_len + chunk_len <= stream->buf_capacity) {
        memcpy(stream->buffer + stream->buf_len, buffer, chunk_len);
        stream->buf_len += chunk_len;
    }

    stream->offset += chunk_len;
    *out_chunk_len = chunk_len;

    return RBOX_OK;
}

rbox_error_t rbox_server_stream_ack(rbox_client_t *client, rbox_stream_t *stream,
                                     int32_t status, const char *reason) {
    if (!client || !stream) {
        return RBOX_ERR_INVALID;
    }

    char ack[RBOX_ACK_SIZE + 256];
    size_t pos = 0;

    uint32_t magic = RBOX_MAGIC;
    memcpy(ack + pos, &magic, 4);
    pos += 4;

    memset(ack + pos, 'S', 16);
    pos += 16;

    memcpy(ack + pos, stream->client_id, 16);
    pos += 16;

    memcpy(ack + pos, stream->request_id, 16);
    pos += 16;

    memcpy(ack + pos, &stream->offset, 8);
    pos += 8;

    memcpy(ack + pos, &status, 4);
    pos += 4;

    uint32_t reason_len = reason ? strlen(reason) : 0;
    memcpy(ack + pos, &reason_len, 4);
    pos += 4;

    if (reason && reason_len > 0) {
        memcpy(ack + pos, reason, reason_len + 1);
        pos += reason_len + 1;
    }

    ssize_t sent = rbox_write(rbox_client_fd(client), ack, pos);
    if (sent != (ssize_t)pos) {
        return RBOX_ERR_IO;
    }

    return RBOX_OK;
}

rbox_error_t rbox_server_stream_complete(rbox_stream_t *stream,
                                         rbox_request_t *out_request) {
    if (!stream || !out_request) {
        return RBOX_ERR_INVALID;
    }

    out_request->data = stream->buffer;
    out_request->data_len = stream->buf_len;
    out_request->header.chunk_len = stream->buf_len;
    out_request->header.total_len = stream->total_len;

    stream->buffer = NULL;
    stream->buf_len = 0;

    if (out_request->data_len > 0) {
        out_request->command = out_request->data;

        out_request->argv = calloc(32, sizeof(char *));
        if (out_request->argv) {
            char *p = out_request->data;
            int argc = 0;

            while (*p && p < out_request->data + out_request->data_len) p++;
            if (*p) p++;

            while (p < out_request->data + out_request->data_len && *p && argc < 31) {
                out_request->argv[argc++] = p;
                while (*p && p < out_request->data + out_request->data_len) p++;
                if (*p) p++;
            }
            out_request->argv_len = argc;
        }
    }

    return RBOX_OK;
}
