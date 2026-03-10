/*
 * packet.c - Packet parsing and building for rbox-protocol
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

#include "rbox_protocol.h"
#include "socket.h"

/* ============================================================
 * CHECKSUM
 * ============================================================ */

/* CRC32 lookup table */
static uint32_t crc32_table[256];

static void init_crc32_table(void) {
    for (int i = 0; i < 256; i++) {
        uint32_t crc = (uint32_t)i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        crc32_table[i] = crc;
    }
}

/* Call once at program start to initialize CRC32 table */
void rbox_init(void) {
    init_crc32_table();
}

/* CRC32 checksum - used for packet validation
 * IMPORTANT: The checksum bytes (offset 68-71) must be zeroed 
 * before calculating, so they don't affect the checksum itself. */
uint32_t rbox_calculate_checksum(const void *data, size_t len) {
    /* Always initialize table - may be called from different translation units */
    init_crc32_table();
    
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ bytes[i]) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

/* ============================================================
 * HEADER VALIDATION
 * ============================================================ */

rbox_error_t rbox_header_validate(const rbox_header_t *header) {
    if (!header) return RBOX_ERR_INVALID;

    /* Check magic */
    if (header->magic != RBOX_MAGIC) {
        return RBOX_ERR_MAGIC;
    }

    /* Check version */
    if (header->version != RBOX_VERSION) {
        return RBOX_ERR_VERSION;
    }

    /* Verify checksum - make a copy to not modify original
     * IMPORTANT: Calculate over bytes 0-83 only (exclude checksum field at offset 84)
     * For v5 protocol: header is 88 bytes, checksum at offset 84 */
    rbox_header_t temp;
    memcpy(&temp, header, sizeof(temp));
    temp.checksum = 0;
    uint32_t calc_checksum = rbox_calculate_checksum(&temp, 84);
    
    /* Debug: print what's being compared */
    /* printf("DEBUG: stored=0x%08x calc=0x%08x\n", header->checksum, calc_checksum); */
    
    if (header->checksum != calc_checksum) {
        return RBOX_ERR_CHECKSUM;
    }

    return RBOX_OK;
}

/* ============================================================
 * ERROR HANDLING
 * ============================================================ */

const char *rbox_strerror(rbox_error_t err) {
    switch (err) {
        case RBOX_OK:           return "Success";
        case RBOX_ERR_INVALID:   return "Invalid parameter";
        case RBOX_ERR_MAGIC:     return "Invalid magic number";
        case RBOX_ERR_VERSION:  return "Unsupported protocol version";
        case RBOX_ERR_CHECKSUM:  return "Checksum mismatch";
        case RBOX_ERR_TRUNCATED: return "Truncated data";
        case RBOX_ERR_IO:       return "I/O error";
        case RBOX_ERR_MEMORY:   return "Memory allocation failed";
        default:                return "Unknown error";
    }
}

/* ============================================================
 * REQUEST READING
 * ============================================================ */

static rbox_error_t read_header(rbox_client_t *client, rbox_header_t *header) {
    ssize_t n = rbox_read(rbox_client_fd(client), header, RBOX_HEADER_SIZE);
    if (n < 0) {
        return RBOX_ERR_IO;
    }
    if (n != RBOX_HEADER_SIZE) {
        return RBOX_ERR_TRUNCATED;
    }

    /* Validate header - checks magic, version, and checksum */
    rbox_error_t err = rbox_header_validate(header);
    if (err != RBOX_OK) {
        return err;
    }

    return RBOX_OK;
}

static rbox_error_t read_request_data(rbox_client_t *client, 
                                     const rbox_header_t *header,
                                     rbox_request_t *request) {
    /* For single-chunk requests, use chunk_len to determine size
     * For chunked requests, this will be called per-chunk by the stream functions
     */
    size_t buf_size = header->chunk_len;
    if (buf_size < 256) buf_size = 256;
    if (buf_size > RBOX_CHUNK_MAX) buf_size = RBOX_CHUNK_MAX;

    request->data = malloc(buf_size);
    if (!request->data) {
        return RBOX_ERR_MEMORY;
    }

    /* Read data */
    ssize_t n = rbox_read(rbox_client_fd(client), request->data, buf_size);
    if (n <= 0) {
        free(request->data);
        return RBOX_ERR_IO;
    }

    request->data_len = n;

    /* Parse the data - assume simple format: command\0args\0... */
    /* For now, just set command and a simple argv with one entry */
    request->command = request->data;
    
    request->argv = calloc(2, sizeof(char *));
    if (request->argv) {
        request->argv[0] = request->data;
        request->argv_len = 1;
    }
    
    request->envp = NULL;
    request->envp_len = 0;

    return RBOX_OK;
}

rbox_error_t rbox_request_read(rbox_client_t *client, rbox_request_t *request) {
    if (!client || !request) {
        return RBOX_ERR_INVALID;
    }

    memset(request, 0, sizeof(*request));

    /* Read header */
    rbox_error_t err = read_header(client, &request->header);
    if (err != RBOX_OK) {
        return err;
    }

    /* Read data */
    err = read_request_data(client, &request->header, request);
    if (err != RBOX_OK) {
        rbox_request_free(request);
    }

    return err;
}

void rbox_request_free(rbox_request_t *request) {
    if (!request) return;
    free(request->data);
    free(request->argv);
    free(request->envp);
    memset(request, 0, sizeof(*request));
}

/* ============================================================
 * REQUEST GETTERS
 * ============================================================ */

const char *rbox_request_get_command(const rbox_request_t *req) {
    return req ? req->command : NULL;
}

const char *rbox_request_get_arg(const rbox_request_t *req, int index) {
    if (!req || index < 0 || index >= req->argv_len) {
        return NULL;
    }
    return req->argv[index];
}

/* ============================================================
 * RESPONSE SENDING
 * ============================================================ */

rbox_error_t rbox_response_send(rbox_client_t *client, const rbox_response_t *response) {
    if (!client || !response) {
        return RBOX_ERR_INVALID;
    }

    /* Build binary response packet matching protocol */
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));  /* Zero the buffer */
    size_t pos = 0;
    
    /* Magic (4 bytes) */
    uint32_t magic = RBOX_MAGIC;
    memcpy(buffer + pos, &magic, 4);
    pos += 4;
    
    /* Server ID (16 bytes) - use default */
    memset(buffer + pos, 'S', 16);
    pos += 16;
    
    /* Request ID (4 bytes) */
    uint32_t req_id = 1;
    memcpy(buffer + pos, &req_id, 4);
    pos += 4;
    
    /* Decision (1 byte) */
    buffer[pos] = response->decision;
    pos += 1;
    
    /* Reason length (4 bytes) */
    uint32_t reason_len = strlen(response->reason);
    memcpy(buffer + pos, &reason_len, 4);
    pos += 4;
    
    /* Reason (null-terminated) */
    memcpy(buffer + pos, response->reason, reason_len + 1);
    pos += reason_len + 1;

    /* Send response using rbox_write (handles all I/O correctly) */
    /* Note: rbox_write returns -1 on error or if peer closed, but that's OK - 
     * the client may have already closed */
    ssize_t n = rbox_write(rbox_client_fd(client), buffer, pos);
    if (n < 0) {
        /* Peer closed or error - this is acceptable */
        return RBOX_OK;
    }

    return RBOX_OK;
}

/* ============================================================
 * CHUNKED TRANSFER - STREAM MANAGEMENT
 * ============================================================ */

/* Stream state for client sending chunks */
struct rbox_stream {
    uint8_t  client_id[16];
    uint8_t  request_id[16];
    uint64_t offset;         /* Bytes sent/acknowledged */
    uint64_t total_len;      /* Total size of all chunks */
    int      is_server;       /* 1 if server-side stream */
    char    *buffer;         /* Server-side accumulation buffer */
    size_t   buf_capacity;
    size_t   buf_len;
};

/* Create a new stream for chunked sending (client side) */
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

/* Create stream state for incoming chunks (server side) */
rbox_stream_t *rbox_server_stream_new(const uint8_t *client_id, const uint8_t *request_id,
                                       uint64_t total_len) {
    rbox_stream_t *stream = calloc(1, sizeof(rbox_stream_t));
    if (!stream) return NULL;
    
    if (client_id) memcpy(stream->client_id, client_id, 16);
    if (request_id) memcpy(stream->request_id, request_id, 16);
    
    stream->offset = 0;
    stream->total_len = total_len;
    stream->is_server = 1;
    
    /* Allocate buffer for accumulating chunks */
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

/* Free stream */
void rbox_stream_free(rbox_stream_t *stream) {
    if (!stream) return;
    free(stream->buffer);
    free(stream);
}

/* Get current stream offset */
uint64_t rbox_stream_offset(const rbox_stream_t *stream) {
    return stream ? stream->offset : 0;
}

/* Send chunk to server */
rbox_error_t rbox_stream_send_chunk(rbox_client_t *client, rbox_stream_t *stream,
                                    const void *data, size_t len,
                                    uint32_t flags, uint64_t total_len) {
    if (!client || !stream || !data || len == 0) {
        return RBOX_ERR_INVALID;
    }
    
    /* Build chunk packet */
    char buffer[RBOX_HEADER_SIZE + RBOX_CHUNK_MAX];
    size_t pos = 0;
    
    /* Magic */
    uint32_t magic = RBOX_MAGIC;
    memcpy(buffer + pos, &magic, 4);
    pos += 4;
    
    /* Version */
    uint32_t version = RBOX_VERSION;
    memcpy(buffer + pos, &version, 4);
    pos += 4;
    
    /* Client ID */
    memcpy(buffer + pos, stream->client_id, 16);
    pos += 16;
    
    /* Request ID */
    memcpy(buffer + pos, stream->request_id, 16);
    pos += 16;
    
    /* Server ID (placeholder) */
    memset(buffer + pos, 'S', 16);
    pos += 16;
    
    /* Type */
    uint32_t type = (flags & RBOX_FLAG_FIRST) ? RBOX_MSG_REQ : RBOX_MSG_CHUNK;
    memcpy(buffer + pos, &type, 4);
    pos += 4;
    
    /* Flags */
    memcpy(buffer + pos, &flags, 4);
    pos += 4;
    
    /* Offset */
    memcpy(buffer + pos, &stream->offset, 8);
    pos += 8;
    
    /* Chunk length */
    memcpy(buffer + pos, &len, 4);
    pos += 4;
    
    /* Total length */
    memcpy(buffer + pos, &total_len, 8);
    pos += 8;
    
    /* Checksum (over header + data) */
    uint32_t checksum = 0;
    memcpy(buffer + pos, &checksum, 4);  /* Zero for calculation */
    memcpy(buffer + RBOX_HEADER_OFFSET_CHECKSUM, &checksum, 4);
    checksum = rbox_calculate_checksum(buffer, RBOX_HEADER_SIZE + len);
    memcpy(buffer + pos, &checksum, 4);
    pos += 4;
    
    /* Data */
    memcpy(buffer + RBOX_HEADER_SIZE, data, len);
    
    /* Send */
    ssize_t sent = rbox_write(rbox_client_fd(client), buffer, RBOX_HEADER_SIZE + len);
    if (sent != (ssize_t)(RBOX_HEADER_SIZE + len)) {
        return RBOX_ERR_IO;
    }
    
    /* Update offset if FIRST chunk (starting) */
    if (flags & RBOX_FLAG_FIRST) {
        stream->total_len = total_len;
        stream->offset = 0;
    }
    
    return RBOX_OK;
}

/* Read ACK from server */
rbox_error_t rbox_stream_read_ack(rbox_client_t *client, rbox_stream_t *stream) {
    if (!client || !stream) {
        return RBOX_ERR_INVALID;
    }
    
    /* Wait for ACK using poll */
    struct pollfd pfd = {
        .fd = rbox_client_fd(client),
        .events = POLLIN,
        .revents = 0
    };
    
    int poll_ret = poll(&pfd, 1, 5000);
    if (poll_ret <= 0 || !(pfd.revents & POLLIN)) {
        return RBOX_ERR_IO;
    }
    
    /* Read ACK */
    char ack_buf[RBOX_ACK_SIZE + 256];
    ssize_t n = rbox_read(rbox_client_fd(client), ack_buf, sizeof(ack_buf));
    if (n < (ssize_t)RBOX_ACK_SIZE) {
        return RBOX_ERR_TRUNCATED;
    }
    
    /* Validate magic */
    uint32_t magic = *(uint32_t *)ack_buf;
    if (magic != RBOX_MAGIC) {
        return RBOX_ERR_MAGIC;
    }
    
    /* Get offset and status */
    uint64_t offset = *(uint64_t *)(ack_buf + RBOX_ACK_OFFSET_OFFSET);
    int32_t status = *(int32_t *)(ack_buf + RBOX_ACK_OFFSET_STATUS);
    
    /* Update stream offset */
    stream->offset = offset;
    
    if (status == RBOX_ACK_ERROR) {
        return RBOX_ERR_INVALID;
    }
    
    return RBOX_OK;
}

/* Server: Receive a chunk */
rbox_error_t rbox_server_stream_recv(rbox_client_t *client, rbox_stream_t *stream,
                                     void *buffer, size_t buf_size,
                                     size_t *out_chunk_len) {
    if (!client || !stream || !buffer || !out_chunk_len) {
        return RBOX_ERR_INVALID;
    }
    
    /* Wait for data using poll */
    struct pollfd pfd = {
        .fd = rbox_client_fd(client),
        .events = POLLIN,
        .revents = 0
    };
    
    int poll_ret = poll(&pfd, 1, 5000);
    if (poll_ret <= 0 || !(pfd.revents & POLLIN)) {
        return RBOX_ERR_IO;
    }
    
    /* Read header first */
    char header[RBOX_HEADER_SIZE];
    ssize_t n = rbox_read(rbox_client_fd(client), header, RBOX_HEADER_SIZE);
    if (n != RBOX_HEADER_SIZE) {
        return RBOX_ERR_TRUNCATED;
    }
    
    /* Validate header */
    rbox_header_t *hdr = (rbox_header_t *)header;
    if (hdr->magic != RBOX_MAGIC) {
        return RBOX_ERR_MAGIC;
    }
    if (hdr->version != RBOX_VERSION) {
        return RBOX_ERR_VERSION;
    }
    
    /* Validate offset matches expected */
    if (hdr->offset != stream->offset) {
        /* Client trying to resume from wrong offset */
        return RBOX_ERR_INVALID;
    }
    
    /* Read chunk data */
    size_t chunk_len = hdr->chunk_len;
    if (chunk_len > buf_size || chunk_len > RBOX_CHUNK_MAX) {
        return RBOX_ERR_INVALID;
    }
    
    n = rbox_read(rbox_client_fd(client), buffer, chunk_len);
    if (n != (ssize_t)chunk_len) {
        return RBOX_ERR_TRUNCATED;
    }
    
    /* Store in buffer if server stream */
    if (stream->buffer && stream->buf_len + chunk_len <= stream->buf_capacity) {
        memcpy(stream->buffer + stream->buf_len, buffer, chunk_len);
        stream->buf_len += chunk_len;
    }
    
    stream->offset += chunk_len;
    *out_chunk_len = chunk_len;
    
    return RBOX_OK;
}

/* Server: Send ACK to client */
rbox_error_t rbox_server_stream_ack(rbox_client_t *client, rbox_stream_t *stream,
                                    int32_t status, const char *reason) {
    if (!client || !stream) {
        return RBOX_ERR_INVALID;
    }
    
    char ack[RBOX_ACK_SIZE + 256];
    size_t pos = 0;
    
    /* Magic */
    uint32_t magic = RBOX_MAGIC;
    memcpy(ack + pos, &magic, 4);
    pos += 4;
    
    /* Server ID */
    memset(ack + pos, 'S', 16);
    pos += 16;
    
    /* Client ID */
    memcpy(ack + pos, stream->client_id, 16);
    pos += 16;
    
    /* Request ID */
    memcpy(ack + pos, stream->request_id, 16);
    pos += 16;
    
    /* Offset received */
    memcpy(ack + pos, &stream->offset, 8);
    pos += 8;
    
    /* Status */
    memcpy(ack + pos, &status, 4);
    pos += 4;
    
    /* Reason */
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

/* Server: Complete stream and get final request data */
rbox_error_t rbox_server_stream_complete(rbox_stream_t *stream,
                                         rbox_request_t *out_request) {
    if (!stream || !out_request) {
        return RBOX_ERR_INVALID;
    }
    
    /* Copy accumulated data to request */
    out_request->data = stream->buffer;
    out_request->data_len = stream->buf_len;
    out_request->header.chunk_len = stream->buf_len;
    out_request->header.total_len = stream->total_len;
    
    /* Take ownership of buffer (don't free on stream free) */
    stream->buffer = NULL;
    stream->buf_len = 0;
    
    /* Parse command from data */
    if (out_request->data_len > 0) {
        out_request->command = out_request->data;
        
        /* Allocate argv */
        out_request->argv = calloc(32, sizeof(char *));
        if (out_request->argv) {
            /* Simple parsing: first string is command, rest are args */
            char *p = out_request->data;
            int argc = 0;
            
            /* Skip command */
            while (*p && p < out_request->data + out_request->data_len) p++;
            if (*p) p++;
            
            /* Parse args */
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

/* ============================================================
 * PACKET BUILDING & PARSING
 * ============================================================ */

/* Build request packet (v5 protocol) */
rbox_error_t rbox_build_request(char *packet, size_t *out_len,
                               const char *command, int argc, const char **argv) {
    if (!packet || !command || !out_len) {
        return RBOX_ERR_INVALID;
    }
    
    memset(packet, 0, 4096);
    
    /* Header fields */
    uint32_t magic = RBOX_MAGIC;
    uint32_t version = RBOX_VERSION;
    uint32_t type = RBOX_MSG_REQ;
    uint32_t flags = RBOX_FLAG_FIRST;
    uint64_t offset = 0;
    uint32_t chunk_len = 0;
    uint64_t total_len = 0;
    
    memcpy(packet + 0, &magic, 4);
    memcpy(packet + 4, &version, 4);
    memset(packet + 8, 0, 16);  /* client_id */
    memset(packet + 24, 0, 16); /* request_id */
    memcpy(packet + 56, &type, 4);
    memcpy(packet + 60, &flags, 4);
    memcpy(packet + 64, &offset, 8);
    memcpy(packet + 72, &chunk_len, 4);
    memcpy(packet + 76, &total_len, 8);
    
    /* Body: command + args */
    size_t pos = 88;
    
    memcpy(packet + pos, command, strlen(command) + 1);
    pos += strlen(command) + 1;
    
    for (int i = 0; i < argc; i++) {
        if (!argv[i]) break;
        memcpy(packet + pos, argv[i], strlen(argv[i]) + 1);
        pos += strlen(argv[i]) + 1;
    }
    
    /* Update chunk_len and total_len */
    chunk_len = pos - 88;
    total_len = chunk_len;
    memcpy(packet + 72, &chunk_len, 4);
    memcpy(packet + 76, &total_len, 8);
    
    /* Calculate checksum */
    uint32_t checksum = rbox_calculate_checksum(packet, 84);
    memcpy(packet + 84, &checksum, 4);
    
    *out_len = pos;
    return RBOX_OK;
}

/* Parse response packet */
int rbox_parse_response(const char *packet, size_t len, uint8_t *out_decision) {
    if (!packet || len < 29 || !out_decision) {
        return -1;
    }
    
    /* Check magic */
    uint32_t magic = *(uint32_t *)packet;
    if (magic != RBOX_MAGIC) {
        return -1;
    }
    
    /* Get decision */
    *out_decision = packet[24];
    return 0;
}
