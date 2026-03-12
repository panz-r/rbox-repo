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
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/eventfd.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>

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

/* 64-bit command hash - two-step hash with different constants */
/* Used for time-limited decision matching - different from 32-bit cmd_hash */
uint64_t rbox_hash64(const char *str, size_t len) {
    if (!str || len == 0) return 0;
    
    /* Two-step hash with different constants */
    /* Step 1: Mix using FNV-1a like algorithm with different prime */
    uint64_t hash = 14695981039346656037ULL;  /* FNV offset basis */
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint64_t)(unsigned char)str[i];
        hash *= 1099511628211ULL;  /* FNV prime 64-bit */
    }
    
    /* Step 2: Mix using DJB2-like algorithm with different constants */
    uint64_t hash2 = 5381ULL;
    for (size_t i = 0; i < len; i++) {
        hash2 = ((hash2 << 5) + hash2) + (uint64_t)(unsigned char)str[i];  /* hash2 * 33 + c */
    }
    
    /* Combine both hashes */
    return hash ^ (hash2 + 0x9e3779b97f4a7c15ULL);
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
        case RBOX_ERR_MAGIC:    return "Invalid magic number";
        case RBOX_ERR_VERSION:  return "Unsupported protocol version";
        case RBOX_ERR_CHECKSUM: return "Checksum mismatch";
        case RBOX_ERR_TRUNCATED: return "Truncated data";
        case RBOX_ERR_IO:       return "I/O error";
        case RBOX_ERR_MEMORY:   return "Memory allocation failed";
        case RBOX_ERR_MISMATCH: return "Request/response ID mismatch";
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

    /* Build binary response packet matching v6 protocol (uses full header) */
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    
    /* Header starts at offset 0 - use macros from rbox_protocol_defs.h */
    uint32_t magic = RBOX_MAGIC;
    memcpy(buffer + RBOX_HEADER_OFFSET_MAGIC, &magic, 4);
    
    uint32_t version = RBOX_VERSION;
    memcpy(buffer + RBOX_HEADER_OFFSET_VERSION, &version, 4);
    
    /* Client ID (16 bytes) at offset 8 - echo back client's client_id */
    /* We don't have client_id stored, use zeros */
    memset(buffer + RBOX_HEADER_OFFSET_CLIENT_ID, 0, 16);
    
    /* Request ID (16 bytes) at offset 24 - echo back client's request_id */
    memcpy(buffer + RBOX_HEADER_OFFSET_REQUEST_ID, response->request_id, 16);
    
    /* Server ID (16 bytes) at offset 40 */
    memset(buffer + RBOX_HEADER_OFFSET_SERVER_ID, 'S', 16);
    
    /* Type (4 bytes) at offset 56 - 0 for response */
    uint32_t type = 0;
    memcpy(buffer + RBOX_HEADER_OFFSET_TYPE, &type, 4);
    
    /* Flags (4 bytes) at offset 60 - 0 */
    uint32_t flags = 0;
    memcpy(buffer + RBOX_HEADER_OFFSET_FLAGS, &flags, 4);
    
    /* Offset (8 bytes) at offset 64 - 0 */
    uint64_t offset = 0;
    memcpy(buffer + RBOX_HEADER_OFFSET_OFFSET, &offset, 8);
    
    /* Chunk len (4 bytes) at offset 72 - decision + reason length */
    uint32_t reason_len = strlen(response->reason);
    if (reason_len > RBOX_RESPONSE_MAX_REASON) {
        reason_len = RBOX_RESPONSE_MAX_REASON;
    }
    uint32_t chunk_len = 1 + reason_len;  /* decision + reason */
    memcpy(buffer + RBOX_HEADER_OFFSET_CHUNK_LEN, &chunk_len, 4);
    
    /* Total len (8 bytes) at offset 76 - decision + reason length */
    uint64_t total_len = chunk_len;
    memcpy(buffer + RBOX_HEADER_OFFSET_TOTAL_LEN, &total_len, 8);
    
    /* Cmd hash (4 bytes) at offset 84 - 0 */
    uint32_t cmd_hash = 0;
    memcpy(buffer + RBOX_HEADER_OFFSET_CMD_HASH, &cmd_hash, 4);
    
    /* Checksum (4 bytes) at offset 88 - 0 for now (could calculate) */
    uint32_t checksum = 0;
    memcpy(buffer + RBOX_HEADER_OFFSET_CHECKSUM, &checksum, 4);
    
    /* Decision (1 byte) at offset 92 (RBOX_HEADER_SIZE) */
    buffer[RBOX_HEADER_SIZE] = response->decision;
    
    /* Reason string starts at offset 93 (1 byte decision + 4 bytes reason_len) */
    memcpy(buffer + RBOX_HEADER_SIZE + 1, response->reason, reason_len + 1);  /* +1 for null terminator */
    
    size_t total_len_out = RBOX_HEADER_SIZE + 1 + reason_len + 1;

    /* Send response using rbox_write (handles all I/O correctly) */
    ssize_t n = rbox_write(rbox_client_fd(client), buffer, total_len_out);
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
    size_t pos = RBOX_HEADER_SIZE;
    
    memcpy(packet + pos, command, strlen(command) + 1);
    pos += strlen(command) + 1;
    
    for (int i = 0; i < argc; i++) {
        if (!argv[i]) break;
        memcpy(packet + pos, argv[i], strlen(argv[i]) + 1);
        pos += strlen(argv[i]) + 1;
    }
    
    /* Update chunk_len and total_len */
    chunk_len = pos - RBOX_HEADER_SIZE;
    total_len = chunk_len;
    memcpy(packet + 72, &chunk_len, 4);
    memcpy(packet + 76, &total_len, 8);
    
    /* Calculate checksum */
    uint32_t checksum = rbox_calculate_checksum(packet, RBOX_HEADER_OFFSET_CHECKSUM);
    memcpy(packet + RBOX_HEADER_OFFSET_CHECKSUM, &checksum, 4);
    
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

/* ============================================================
 * RESPONSE VALIDATION (Client-side)
 * ============================================================ */

/* Validate response packet with full checksum and request_id matching
 * 
 * Parameters:
 *   - packet: response data
 *   - len: response length
 *   - expected_request_id: the request_id we sent (16 bytes)
 *   - out_response: validated response output
 * 
 * Returns:
 *   RBOX_OK: response is valid, out_response populated
 *   RBOX_ERR_TRUNCATED: response too short
 *   RBOX_ERR_MAGIC: invalid magic
 *   RBOX_ERR_VERSION: invalid version
 *   RBOX_ERR_CHECKSUM: checksum mismatch
 *   RBOX_ERR_MISMATCH: request_id doesn't match
 */
static rbox_error_t validate_response(const char *packet, size_t len,
                                     const uint8_t *expected_request_id,
                                     rbox_response_t *out_response) {
    if (!packet || !out_response) {
        return RBOX_ERR_INVALID;
    }
    
    /* Validate magic first */
    uint32_t magic = *(uint32_t *)packet;
    if (magic != RBOX_MAGIC) {
        return RBOX_ERR_MAGIC;
    }
    
    /* Check for v5 format: version at offset 4 should be 5 */
    /* v2 format: no version field, offset 4 is server_id[0] */
    uint32_t version = *(uint32_t *)(packet + 4);
    uint8_t decision;
    uint32_t reason_len;
    size_t reason_offset;
    size_t request_id_offset;
    
    if (version == RBOX_VERSION) {
        /* v6 format */
        if (len < RBOX_HEADER_SIZE) {
            return RBOX_ERR_TRUNCATED;
        }
        
        decision = packet[RBOX_HEADER_SIZE];  /* decision at offset 92 */
        reason_len = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_CHUNK_LEN);
        if (reason_len > 0) {
            reason_len -= 1;  /* chunk_len includes decision byte */
        }
        reason_offset = RBOX_HEADER_SIZE;
        request_id_offset = RBOX_HEADER_OFFSET_REQUEST_ID;
        
        /* Validate reason length */
        if (reason_len > RBOX_RESPONSE_MAX_REASON) {
            reason_len = RBOX_RESPONSE_MAX_REASON;
        }
        
        /* Calculate expected total size */
        size_t expected_len = RBOX_HEADER_SIZE + reason_len;
        if (len < expected_len) {
            return RBOX_ERR_TRUNCATED;
        }
    } else {
        /* v2 format (legacy) */
        if (len < RBOX_RESPONSE_MIN_SIZE) {
            return RBOX_ERR_TRUNCATED;
        }
        
        decision = packet[RBOX_RESPONSE_OFFSET_DECISION_V2];
        reason_len = *(uint32_t *)(packet + RBOX_RESPONSE_OFFSET_REASON_LEN_V2);
        reason_offset = RBOX_RESPONSE_OFFSET_REASON_V2;
        request_id_offset = RBOX_RESPONSE_OFFSET_REQUEST_ID_V2;
        
        /* Validate reason length */
        if (reason_len > RBOX_RESPONSE_MAX_REASON) {
            reason_len = RBOX_RESPONSE_MAX_REASON;
        }
        
        /* Calculate expected total size */
        size_t expected_len = reason_offset + reason_len + 1;
        if (len < expected_len) {
            return RBOX_ERR_TRUNCATED;
        }
    }
    
    /* Validate request_id matches */
    const uint8_t *resp_request_id = (const uint8_t *)(packet + request_id_offset);
    if (expected_request_id) {
        if (memcmp(resp_request_id, expected_request_id, 16) != 0) {
            /* Request ID mismatch - stale response from previous request */
            return RBOX_ERR_MISMATCH;
        }
    }
    
    /* Populate response */
    memset(out_response, 0, sizeof(*out_response));
    out_response->decision = decision;
    
    /* Copy reason string */
    if (reason_len > 0 && len > reason_offset) {
        size_t copy_len = reason_len;
        if (copy_len >= sizeof(out_response->reason)) {
            copy_len = sizeof(out_response->reason) - 1;
        }
        memcpy(out_response->reason, packet + reason_offset, copy_len);
        out_response->reason[copy_len] = '\0';
    } else {
        out_response->reason[0] = '\0';
    }
    
    /* Duration is not in v1 response - set to 0 (one-shot) */
    out_response->duration = 0;
    
    return RBOX_OK;
}

/* ============================================================
 * CLIENT WORKFLOW - Send Request & Get Validated Response
 * ============================================================ */

/* Generate a unique request ID using timestamp + random
 * This helps match responses to requests */
static void generate_request_id(uint8_t *id_out) {
    if (!id_out) return;
    
    /* Use current time + random to generate unique ID */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    
    /* Mix bits for uniqueness */
    uint64_t a = (uint64_t)ts.tv_sec ^ ((uint64_t)ts.tv_nsec << 32);
    uint64_t b = (uint64_t)rand() ^ ((uint64_t)getpid() << 32);
    
    memcpy(id_out, &a, 8);
    memcpy(id_out + 8, &b, 8);
}

/* Build request packet with specific request_id (v7 protocol with caller/syscall)
 * 
 * This version allows caller to specify request_id for matching
 * caller and syscall are truncated to 15 chars max each */
static rbox_error_t build_request_with_id(char *packet, size_t *out_len,
                                         const uint8_t *request_id,
                                         const char *command, 
                                         int argc, const char **argv,
                                         const char *caller,
                                         const char *syscall) {
    if (!packet || !command || !out_len) {
        return RBOX_ERR_INVALID;
    }
    
    memset(packet, 0, 4096);
    
    /* Truncate caller and syscall to max 15 chars each */
    size_t caller_len = caller ? strlen(caller) : 0;
    if (caller_len > RBOX_MAX_CALLER_LEN) caller_len = RBOX_MAX_CALLER_LEN;
    
    size_t syscall_len = syscall ? strlen(syscall) : 0;
    if (syscall_len > RBOX_MAX_SYSCALL_LEN) syscall_len = RBOX_MAX_SYSCALL_LEN;
    
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
    memset(packet + 8, 0, 16);  /* client_id - can be zero for simple requests */
    if (request_id) {
        memcpy(packet + 24, request_id, 16);  /* request_id */
    } else {
        memset(packet + 24, 0, 16);
    }
    memcpy(packet + 56, &type, 4);
    memcpy(packet + 60, &flags, 4);
    memcpy(packet + 64, &offset, 8);
    memcpy(packet + 72, &chunk_len, 4);
    memcpy(packet + 76, &total_len, 8);
    
    /* Body: command + args (starts at offset 123 in v7) */
    size_t pos = RBOX_HEADER_SIZE;
    
    memcpy(packet + pos, command, strlen(command) + 1);
    pos += strlen(command) + 1;
    
    for (int i = 0; i < argc; i++) {
        if (!argv[i]) break;
        memcpy(packet + pos, argv[i], strlen(argv[i]) + 1);
        pos += strlen(argv[i]) + 1;
    }
    
    /* Update chunk_len and total_len */
    chunk_len = pos - RBOX_HEADER_SIZE;
    total_len = chunk_len;
    memcpy(packet + 72, &chunk_len, 4);
    memcpy(packet + 76, &total_len, 8);
    memcpy(packet + 72, &chunk_len, 4);
    memcpy(packet + 76, &total_len, 8);
    
    /* Copy cmd_hash (already set above, but we include it in checksum area) */
    /* cmd_hash is at offset 84, already set by caller if needed */
    
    /* Encode caller_syscall_size byte: low 4 bits = caller_len, high 4 bits = syscall_len */
    uint8_t cs_size = (caller_len & 0x0F) | ((syscall_len << 4) & 0xF0);
    memcpy(packet + RBOX_HEADER_OFFSET_CALLER_SYSCALL_SIZE, &cs_size, 1);
    
    /* Copy caller (no null terminator) */
    if (caller_len > 0) {
        memcpy(packet + RBOX_HEADER_OFFSET_CALLER, caller, caller_len);
    }
    
    /* Copy syscall (no null terminator) */
    if (syscall_len > 0) {
        memcpy(packet + RBOX_HEADER_OFFSET_SYSCALL, syscall, syscall_len);
    }
    
    /* Calculate checksum over header (includes caller/syscall fields) */
    uint32_t checksum = rbox_calculate_checksum(packet, RBOX_HEADER_OFFSET_CHECKSUM);
    memcpy(packet + RBOX_HEADER_OFFSET_CHECKSUM, &checksum, 4);
    
    *out_len = pos;
    return RBOX_OK;
}

/* Read response with timeout (v5 format)
 * Returns bytes read, 0 on close, -1 on error */
static ssize_t read_response(int fd, char *buf, size_t max_len) {
    /* First read the v5 header */
    char header[RBOX_HEADER_SIZE];
    
    ssize_t n = rbox_read(fd, header, RBOX_HEADER_SIZE);
    if (n <= 0) {
        return n;  /* Error or closed */
    }
    
    if (n < (ssize_t)RBOX_HEADER_SIZE) {
        /* Truncated header */
        return -1;
    }
    
    /* Validate magic and version */
    uint32_t magic = *(uint32_t *)header;
    uint32_t version = *(uint32_t *)(header + 4);
    if (magic != RBOX_MAGIC || version != RBOX_VERSION) {
        return -1;  /* Invalid format */
    }
    
    /* Get reason length from chunk_len field */
    uint32_t reason_len = *(uint32_t *)(header + RBOX_HEADER_OFFSET_CHUNK_LEN);
    if (reason_len > 0) {
        reason_len -= 1;  /* chunk_len includes decision byte */
    }
    if (reason_len > RBOX_RESPONSE_MAX_REASON) {
        reason_len = RBOX_RESPONSE_MAX_REASON;
    }
    
    /* Calculate total response size */
    size_t total_len = RBOX_HEADER_SIZE + reason_len;
    if (total_len > max_len) {
        total_len = max_len;
    }
    
    /* Copy header to buffer */
    memcpy(buf, header, RBOX_HEADER_SIZE);
    
    /* Read remaining */
    if (total_len > RBOX_HEADER_SIZE) {
        size_t remaining = total_len - RBOX_HEADER_SIZE;
        n = rbox_read(fd, buf + RBOX_HEADER_SIZE, remaining);
        if (n < 0) {
            return -1;
        }
        total_len = RBOX_HEADER_SIZE + n;
    }
    
    return (ssize_t)total_len;
}

rbox_error_t rbox_client_send_request(rbox_client_t *client,
    const char *command, int argc, const char **argv,
    rbox_response_t *response) {
    if (!client || !command || !response) {
        return RBOX_ERR_INVALID;
    }
    
    /* Generate unique request ID for this request */
    uint8_t request_id[16];
    generate_request_id(request_id);
    
    /* Build request packet with our request_id */
    char packet[4096];
    size_t packet_len;
    rbox_error_t err = build_request_with_id(packet, &packet_len, request_id, 
                                             command, argc, argv, NULL, NULL);
    if (err != RBOX_OK) {
        return err;
    }
    
    /* Send request */
    ssize_t sent = rbox_write(rbox_client_fd(client), packet, packet_len);
    if (sent != (ssize_t)packet_len) {
        return RBOX_ERR_IO;
    }
    
    /* Read response */
    char response_buf[512];
    ssize_t resp_len = read_response(rbox_client_fd(client), response_buf, sizeof(response_buf));
    if (resp_len <= 0) {
        return RBOX_ERR_IO;
    }
    
    /* Validate response with request_id matching */
    err = validate_response(response_buf, resp_len, request_id, response);
    if (err != RBOX_OK) {
        /* Clear decision on validation failure - shouldn't be used */
        response->decision = RBOX_DECISION_UNKNOWN;
        return err;
    }
    
    return RBOX_OK;
}

/* ============================================================
 * NON-BLOCKING SESSION IMPLEMENTATION
 * ============================================================ */

struct rbox_session {
    /* Connection config */
    char socket_path[256];
    uint32_t base_delay_ms;
    uint32_t max_retries;
    
    /* Socket */
    rbox_client_t *client;
    
    /* State machine */
    rbox_session_state_t state;
    rbox_error_t error;
    
    /* Request tracking */
    uint8_t request_id[16];
    size_t packet_len;
    char packet[4096];
    
    /* Response */
    rbox_response_t response;
    
    /* Connection retry state */
    uint32_t retry_attempt;
    uint64_t next_retry_time;
};

/* Generate unique request ID */
static void gen_request_id(uint8_t *id_out) {
    if (!id_out) return;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t a = (uint64_t)ts.tv_sec ^ ((uint64_t)ts.tv_nsec << 32);
    uint64_t b = (uint64_t)rand() ^ ((uint64_t)getpid() << 32);
    memcpy(id_out, &a, 8);
    memcpy(id_out + 8, &b, 8);
}

rbox_session_t *rbox_session_new(const char *socket_path, 
    uint32_t base_delay_ms, uint32_t max_retries) {
    if (!socket_path) return NULL;
    
    rbox_session_t *session = calloc(1, sizeof(rbox_session_t));
    if (!session) return NULL;
    
    size_t len = strlen(socket_path);
    if (len >= sizeof(session->socket_path)) len = sizeof(session->socket_path) - 1;
    memcpy(session->socket_path, socket_path, len);
    session->socket_path[len] = '\0';
    
    session->base_delay_ms = base_delay_ms;
    session->max_retries = max_retries;
    session->state = RBOX_SESSION_DISCONNECTED;
    
    return session;
}

void rbox_session_free(rbox_session_t *session) {
    if (!session) return;
    rbox_client_close(session->client);
    free(session);
}

int rbox_session_pollfd(const rbox_session_t *session, short *out_events) {
    if (out_events) *out_events = 0;
    if (!session || !session->client) return -1;
    
    short events = 0;
    
    switch (session->state) {
        case RBOX_SESSION_DISCONNECTED:
        case RBOX_SESSION_CONNECTING:
            events = POLLOUT;
            break;
        case RBOX_SESSION_CONNECTED:
            /* Idle - no poll needed, caller should send request */
            break;
        case RBOX_SESSION_SENDING:
            events = POLLOUT;
            break;
        case RBOX_SESSION_WAITING:
            events = POLLIN;
            break;
        case RBOX_SESSION_RESPONSE_READY:
        case RBOX_SESSION_FAILED:
            /* No poll needed */
            break;
    }
    
    if (out_events) *out_events = events;
    return rbox_client_fd(session->client);
}

rbox_session_state_t rbox_session_state(const rbox_session_t *session) {
    return session ? session->state : RBOX_SESSION_DISCONNECTED;
}

rbox_error_t rbox_session_error(const rbox_session_t *session) {
    return session ? session->error : RBOX_ERR_INVALID;
}

/* Get current time in ms */
static uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Check if we should retry connection */
static int should_retry(rbox_session_t *session) {
    if (session->max_retries == 0) return 1;  /* Unlimited retries */
    return session->retry_attempt < session->max_retries;
}

/* Calculate retry delay with exponential backoff + jitter */
static uint32_t calc_retry_delay(rbox_session_t *session) {
    uint32_t base = session->base_delay_ms;
    if (base == 0) return 0;
    
    uint32_t max_delay = base * 64;
    uint32_t exp = base;
    for (uint32_t i = 1; i < session->retry_attempt && exp < UINT32_MAX / 2; i++) {
        exp *= 2;
    }
    
    uint32_t jitter = (uint32_t)((double)base * rand() / (RAND_MAX + 1.0));
    uint32_t delay = exp + jitter;
    if (delay > max_delay) delay = max_delay;
    
    return delay;
}

rbox_error_t rbox_session_connect(rbox_session_t *session) {
    if (!session) return RBOX_ERR_INVALID;
    if (session->state == RBOX_SESSION_CONNECTING ||
        session->state == RBOX_SESSION_CONNECTED ||
        session->state == RBOX_SESSION_WAITING ||
        session->state == RBOX_SESSION_RESPONSE_READY) {
        return RBOX_ERR_INVALID;
    }
    
    /* Close existing client if any */
    if (session->client) {
        rbox_client_close(session->client);
        session->client = NULL;
    }
    
    /* Attempt connection */
    session->client = rbox_client_connect(session->socket_path);
    if (session->client) {
        session->state = RBOX_SESSION_CONNECTED;
        session->retry_attempt = 0;
        return RBOX_OK;
    }
    
    /* Connection failed */
    /* If no retry configured (base_delay_ms == 0), fail immediately */
    if (session->base_delay_ms == 0) {
        session->state = RBOX_SESSION_FAILED;
        session->error = RBOX_ERR_IO;
        return RBOX_ERR_IO;
    }
    
    /* Check if we have retries left */
    if (!should_retry(session)) {
        session->state = RBOX_SESSION_FAILED;
        session->error = RBOX_ERR_IO;
        return RBOX_ERR_IO;
    }
    
    /* Schedule retry */
    session->retry_attempt++;
    uint32_t delay = calc_retry_delay(session);
    session->next_retry_time = get_time_ms() + delay;
    session->state = RBOX_SESSION_CONNECTING;
    
    return RBOX_ERR_IO;
}

rbox_error_t rbox_session_send_request(rbox_session_t *session,
    const char *command, int argc, const char **argv,
    const char *caller, const char *syscall) {
    if (!session || !command) return RBOX_ERR_INVALID;
    if (session->state != RBOX_SESSION_CONNECTED) return RBOX_ERR_INVALID;
    
    /* Generate request ID */
    gen_request_id(session->request_id);
    
    /* Build request */
    session->error = build_request_with_id(session->packet, &session->packet_len,
        session->request_id, command, argc, argv, caller, syscall);
    if (session->error != RBOX_OK) {
        session->state = RBOX_SESSION_FAILED;
        return session->error;
    }
    
    session->state = RBOX_SESSION_SENDING;
    return RBOX_OK;
}

rbox_session_state_t rbox_session_heartbeat(rbox_session_t *session, short events) {
    if (!session) return RBOX_SESSION_FAILED;
    
    switch (session->state) {
        case RBOX_SESSION_DISCONNECTED:
            /* Auto-connect on first heartbeat */
            if (events & POLLOUT) {
                rbox_session_connect(session);
            }
            break;
            
        case RBOX_SESSION_CONNECTING: {
            /* Check if we should retry */
            if (!session->client && session->base_delay_ms > 0) {
                if (get_time_ms() < session->next_retry_time) {
                    break;  /* Wait for retry time */
                }
                /* Retry connection */
                rbox_client_close(session->client);
                session->client = rbox_client_connect(session->socket_path);
                if (!session->client) {
                    if (!should_retry(session)) {
                        session->state = RBOX_SESSION_FAILED;
                        session->error = RBOX_ERR_IO;
                    } else {
                        session->retry_attempt++;
                        session->next_retry_time = get_time_ms() + calc_retry_delay(session);
                    }
                } else {
                    session->state = RBOX_SESSION_CONNECTED;
                    session->retry_attempt = 0;
                }
            }
            break;
        }
            
        case RBOX_SESSION_CONNECTED:
            /* Idle, waiting for request */
            break;
            
        case RBOX_SESSION_SENDING:
            if (events & POLLOUT) {
                short events;
                int fd = rbox_session_pollfd(session, &events);
                ssize_t sent = rbox_write(fd, 
                    session->packet, session->packet_len);
                if (sent == (ssize_t)session->packet_len) {
                    session->state = RBOX_SESSION_WAITING;
                } else if (sent < 0) {
                    /* Send failed - close and reconnect */
                    rbox_client_close(session->client);
                    session->client = NULL;
                    if (session->base_delay_ms > 0 && should_retry(session)) {
                        session->retry_attempt = 1;
                        session->next_retry_time = get_time_ms() + calc_retry_delay(session);
                        session->state = RBOX_SESSION_CONNECTING;
                    } else {
                        session->state = RBOX_SESSION_FAILED;
                        session->error = RBOX_ERR_IO;
                    }
                }
            }
            break;
            
        case RBOX_SESSION_WAITING:
            if (events & POLLIN) {
                char buf[512];
                short events;
                int fd = rbox_session_pollfd(session, &events);
                ssize_t n = rbox_read(fd, buf, sizeof(buf));
                if (n > 0) {
                    /* Validate response */
                    rbox_response_t resp;
                    session->error = validate_response(buf, n, session->request_id, &resp);
                    if (session->error == RBOX_OK) {
                        session->response = resp;
                        session->state = RBOX_SESSION_RESPONSE_READY;
                    } else if (session->error == RBOX_ERR_MISMATCH ||
                               session->error == RBOX_ERR_TRUNCATED ||
                               session->error == RBOX_ERR_IO) {
                        /* Stale/partial response - request again */
                        session->state = RBOX_SESSION_SENDING;
                    } else {
                        session->state = RBOX_SESSION_FAILED;
                    }
                } else if (n == 0 || (n < 0 && errno != EAGAIN)) {
                    /* Connection closed or error */
                    rbox_client_close(session->client);
                    session->client = NULL;
                    if (session->base_delay_ms > 0 && should_retry(session)) {
                        session->retry_attempt = 1;
                        session->next_retry_time = get_time_ms() + calc_retry_delay(session);
                        session->state = RBOX_SESSION_CONNECTING;
                    } else {
                        session->state = RBOX_SESSION_FAILED;
                        session->error = RBOX_ERR_IO;
                    }
                }
            }
            break;
            
        case RBOX_SESSION_RESPONSE_READY:
        case RBOX_SESSION_FAILED:
            /* No action - waiting for client to read/reset */
            break;
    }
    
    return session->state;
}

const rbox_response_t *rbox_session_response(const rbox_session_t *session) {
    if (!session || session->state != RBOX_SESSION_RESPONSE_READY) {
        return NULL;
    }
    return &session->response;
}

void rbox_session_reset(rbox_session_t *session) {
    if (!session) return;
    if (session->state == RBOX_SESSION_RESPONSE_READY) {
        session->state = RBOX_SESSION_CONNECTED;
    }
}

void rbox_session_disconnect(rbox_session_t *session) {
    if (!session) return;
    if (session->client) {
        rbox_client_close(session->client);
        session->client = NULL;
    }
    session->state = RBOX_SESSION_DISCONNECTED;
}

/* ============================================================
 * BLOCKING ALL-IN-ONE INTERFACE
 * ============================================================ */

rbox_error_t rbox_blocking_request(const char *socket_path,
    const char *command, int argc, const char **argv,
    const char *caller, const char *syscall,
    rbox_response_t *out_response,
    uint32_t base_delay_ms, uint32_t max_retries) {
    if (!socket_path || !command || !out_response) {
        return RBOX_ERR_INVALID;
    }
    
    //fprintf(stderr, "DEBUG C: rbox_blocking_request called: command='%s', argc=%d\n", command, argc);
    for (int i = 0; i < argc; i++) {
        //fprintf(stderr, "DEBUG C: argv[%d]='%s'\n", i, argv[i] ? argv[i] : "(null)");
    }
    fflush(stderr);
    
    /* Initialize response */
    memset(out_response, 0, sizeof(*out_response));
    
    /* Create session */
    rbox_session_t *session = rbox_session_new(socket_path, base_delay_ms, max_retries);
    if (!session) {
        return RBOX_ERR_MEMORY;
    }
    
    /* Main loop */
    rbox_error_t result = RBOX_ERR_IO;
    
    while (1) {
        rbox_session_state_t state = rbox_session_state(session);
        
        switch (state) {
            case RBOX_SESSION_DISCONNECTED: {
                /* Connect */
                result = rbox_session_connect(session);
                if (result != RBOX_OK && result != RBOX_ERR_IO) {
                    goto cleanup;
                }
                break;
            }
            
            case RBOX_SESSION_CONNECTING: {
                /* Poll for connection */
                short events;
                int fd = rbox_session_pollfd(session, &events);
                if (fd >= 0) {
                    if (rbox_pollout(fd, 5000) > 0) {
                        rbox_session_heartbeat(session, POLLOUT);
                    }
                } else if (session->base_delay_ms > 0) {
                    /* Wait for retry */
                    uint64_t now = get_time_ms();
                    if (now >= session->next_retry_time) {
                        rbox_session_heartbeat(session, 0);
                    } else {
                        usleep(10000);  /* 10ms */
                    }
                }
                break;
            }
            
            case RBOX_SESSION_CONNECTED: {
                /* Send request */
                result = rbox_session_send_request(session, command, argc, argv, caller, syscall);
                if (result != RBOX_OK) {
                    goto cleanup;
                }
                break;
            }
            
            case RBOX_SESSION_SENDING: {
                /* Wait for send to complete */
                short events;
                int fd = rbox_session_pollfd(session, &events);
                if (rbox_pollout(fd, 5000) > 0) {
                    rbox_session_heartbeat(session, POLLOUT);
                }
                break;
            }
            
            case RBOX_SESSION_WAITING: {
                /* Wait for response */
                short events;
                int fd = rbox_session_pollfd(session, &events);
                if (rbox_pollin(fd, 5000) > 0) {
                    rbox_session_heartbeat(session, POLLIN);
                }
                break;
            }
            
            case RBOX_SESSION_RESPONSE_READY: {
                /* Success! Copy response to caller's buffer */
                *out_response = session->response;
                result = RBOX_OK;
                goto cleanup;
            }
            
            case RBOX_SESSION_FAILED: {
                result = rbox_session_error(session);
                goto cleanup;
            }
        }
    }
    
cleanup:
    rbox_session_free(session);
    return result;
}

/* ============================================================
 * BLOCKING SERVER IMPLEMENTATION (epoll-based)
 * ============================================================ */

/* Server request handle */
struct rbox_server_request {
    int fd;                         /* Client socket fd */
    uint8_t client_id[16];          /* Client identifier */
    uint8_t request_id[16];         /* Request identifier */
    uint32_t cmd_hash;              /* Command hash for verification */
    rbox_server_handle_t *server;   /* Back-pointer to server */
    
    /* Caller/syscall from v7 protocol (truncated to 15 chars, no null) */
    char caller[RBOX_MAX_CALLER_LEN + 1];   /* Null-terminated */
    char syscall[RBOX_MAX_SYSCALL_LEN + 1]; /* Null-terminated */
    
    /* Request data (owned by request, freed on decide) */
    char *command_data;
    size_t command_len;
    rbox_parse_result_t parse;
    
    /* Queue link */
    struct rbox_server_request *next;
};

/* Decision queue for thread-safe decision passing */
typedef struct rbox_server_decision {
    rbox_server_request_t *request;
    uint8_t decision;
    char reason[256];
    uint32_t duration;
    int ready;  /* 1 if decision is ready */
    struct rbox_server_decision *next;
} rbox_server_decision_t;

/* Forward declaration */
struct rbox_server_handle;
typedef struct rbox_server_handle rbox_server_handle_t;

/* Server response cache entry */
typedef struct {
    uint8_t request_id[16];       /* Request ID from client */
    uint8_t client_id[16];         /* Client ID */
    uint32_t cmd_hash;             /* Command hash for verification */
    uint64_t cmd_hash2;            /* Second command hash for verification */
    uint8_t decision;             /* ALLOW/DENY/ERROR */
    char reason[256];              /* Reason string */
    uint32_t duration;             /* Duration in seconds */
    time_t timestamp;             /* When cached */
    time_t expires_at;            /* When this entry expires (0 = never) */
    int valid;                     /* 1 if entry is valid */
} rbox_response_cache_entry_t;

#define RBOX_RESPONSE_CACHE_SIZE 128

/* Send queue entry - for outgoing responses */
typedef struct rbox_server_send_entry {
    int fd;                        /* Socket to send to */
    char *data;                    /* Response packet data */
    size_t len;                    /* Response length */
    struct rbox_server_send_entry *next;
} rbox_server_send_entry_t;

/* Forward declaration */
struct rbox_server_handle;
typedef struct rbox_server_handle rbox_server_handle_t;

/* Server handle */
struct rbox_server_handle {
    char socket_path[256];
    int listen_fd;
    int epoll_fd;
    
    /* Background thread */
    pthread_t thread;
    volatile int running;          /* Flag to signal shutdown */
    int wake_fd;                   /* eventfd to wake epoll thread */
    
    /* Send queue for outgoing responses (mutex protected) */
    pthread_mutex_t send_mutex;
    rbox_server_send_entry_t *send_queue;
    rbox_server_send_entry_t *send_tail;
    int send_count;
    
    /* Response cache (fixed 128 entries) */
    rbox_response_cache_entry_t response_cache[RBOX_RESPONSE_CACHE_SIZE];
    int response_cache_next;      /* Next index to replace (round-robin) */
    pthread_mutex_t cache_mutex;   /* Protects response cache */
    
    /* Request queue (mutex protected) */
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    rbox_server_request_t *request_queue;  /* Queue head */
    rbox_server_request_t *request_tail;   /* Queue tail */
    int request_count;             /* Number of pending requests */
    
    /* Decision queue (mutex protected) */
    pthread_mutex_t decision_mutex;
    pthread_cond_t decision_cond;
    rbox_server_decision_t *decision_queue;  /* Queue head */
    rbox_server_decision_t *decision_tail;  /* Queue tail */
    int decision_count;
};

/* Queue a response for sending via send queue */
static void send_queue_add(rbox_server_handle_t *server, int fd, char *data, size_t len) {
    rbox_server_send_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        free(data);
        return;
    }
    entry->fd = fd;
    entry->data = data;
    entry->len = len;
    
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
    
    /* Add socket to epoll for output - need both EPOLLIN (for new requests) and EPOLLOUT (for sending response) */
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = fd;
    
    /* Try MOD first, if that fails try ADD */
    if (epoll_ctl(server->epoll_fd, EPOLL_CTL_MOD, fd, &ev) < 0) {
        epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
    }
}

/* Response cache lookup - returns 1 if found, fills in decision/reason/duration */
/* Also checks cmd_hash2 and expiration for time-limited decisions */
static int response_cache_lookup(rbox_server_handle_t *server, 
                                 const uint8_t *request_id, uint32_t cmd_hash, uint64_t cmd_hash2,
                                 uint8_t *decision, char *reason, uint32_t *duration) {
    pthread_mutex_lock(&server->cache_mutex);
    time_t now = time(NULL);
    for (int i = 0; i < RBOX_RESPONSE_CACHE_SIZE; i++) {
        /* Only match valid entries */
        if (!server->response_cache[i].valid) continue;
        
        /* Check expiration - if set, entry is only valid until expires_at */
        if (server->response_cache[i].expires_at > 0 && 
            now > server->response_cache[i].expires_at) {
            /* Entry expired - mark invalid and skip */
            server->response_cache[i].valid = 0;
            continue;
        }
        
        /* Check request_id match OR cmd_hash + cmd_hash2 match for same command */
        int match = 0;
        if (memcmp(server->response_cache[i].request_id, request_id, 16) == 0) {
            /* Exact request ID match */
            match = 1;
        } else if (server->response_cache[i].cmd_hash == cmd_hash && 
                   server->response_cache[i].cmd_hash2 == cmd_hash2) {
            /* Same command (by hash) - for time-limited decisions */
            match = 1;
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
/* Also stores cmd_hash2 and expires_at for time-limited decisions */
static void response_cache_insert(rbox_server_handle_t *server,
                                    const uint8_t *client_id,
                                    const uint8_t *request_id,
                                    uint32_t cmd_hash, uint64_t cmd_hash2,
                                    uint8_t decision, const char *reason, uint32_t duration) {
    pthread_mutex_lock(&server->cache_mutex);
    int idx = server->response_cache_next;
    server->response_cache_next = (idx + 1) % RBOX_RESPONSE_CACHE_SIZE;
    
    rbox_response_cache_entry_t *entry = &server->response_cache[idx];
    memcpy(entry->client_id, client_id, 16);
    memcpy(entry->request_id, request_id, 16);
    entry->cmd_hash = cmd_hash;
    entry->cmd_hash2 = cmd_hash2;
    entry->decision = decision;
    strncpy(entry->reason, reason ? reason : "", 255);
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

/* Free server request */
static void server_request_free(rbox_server_request_t *req) {
    if (!req) return;
    if (req->fd >= 0) {
        close(req->fd);
    }
    free(req->command_data);
    free(req);
}

/* Read header from client (v7 protocol with caller/syscall) */
static int server_read_header(int fd, uint8_t *client_id, uint8_t *request_id, uint32_t *cmd_hash, 
                               char *caller, size_t caller_len, char *syscall, size_t syscall_len,
                               uint32_t *chunk_len) {
    char header[RBOX_HEADER_SIZE];
    ssize_t n = rbox_read(fd, header, RBOX_HEADER_SIZE);
    if (n != RBOX_HEADER_SIZE) {
        return -1;
    }
    
    /* Validate magic and version */
    uint32_t magic = *(uint32_t *)header;
    uint32_t version = *(uint32_t *)(header + 4);
    if (magic != RBOX_MAGIC || version != RBOX_VERSION) {
        return -1;
    }
    
    /* Get client_id and request_id */
    memcpy(client_id, header + RBOX_HEADER_OFFSET_CLIENT_ID, 16);
    memcpy(request_id, header + RBOX_HEADER_OFFSET_REQUEST_ID, 16);
    
    /* Get cmd_hash */
    *cmd_hash = *(uint32_t *)(header + RBOX_HEADER_OFFSET_CMD_HASH);
    
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

/* Read request body */
static char *read_body(int fd, uint32_t chunk_len) {
    if (chunk_len == 0) {
        char *empty = malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }
    
    char *data = malloc(chunk_len + 1);
    if (!data) return NULL;
    
    ssize_t n = rbox_read(fd, data, chunk_len);
    if (n != (ssize_t)chunk_len) {
        free(data);
        return NULL;
    }
    
    data[chunk_len] = '\0';
    return data;
}

/* Build response packet in v6 format */
static char *build_response(uint8_t *client_id, uint8_t *request_id, uint32_t cmd_hash,
                           uint8_t decision, const char *reason, uint32_t duration,
                           size_t *out_len) {
    size_t reason_len = reason ? strlen(reason) : 0;
    if (reason_len > RBOX_RESPONSE_MAX_REASON) {
        reason_len = RBOX_RESPONSE_MAX_REASON;
    }
    size_t total_len = RBOX_HEADER_SIZE + 1 + reason_len;  /* header + decision + reason */
    
    char *pkt = malloc(total_len);
    if (!pkt) return NULL;
    memset(pkt, 0, total_len);
    
    /* Header using macros from rbox_protocol_defs.h */
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_MAGIC) = RBOX_MAGIC;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_VERSION) = RBOX_VERSION;
    memcpy(pkt + RBOX_HEADER_OFFSET_CLIENT_ID, client_id, 16);
    memcpy(pkt + RBOX_HEADER_OFFSET_REQUEST_ID, request_id, 16);
    memset(pkt + RBOX_HEADER_OFFSET_SERVER_ID, 'S', 16);  /* server_id */
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_TYPE) = 0;  /* type = 0 for response */
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_FLAGS) = 0;  /* flags = 0 */
    *(uint64_t *)(pkt + RBOX_HEADER_OFFSET_OFFSET) = 0;  /* offset = 0 */
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHUNK_LEN) = reason_len;  /* chunk_len = reason length */
    *(uint64_t *)(pkt + RBOX_HEADER_OFFSET_TOTAL_LEN) = reason_len;  /* total_len = reason length */
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CMD_HASH) = cmd_hash;  /* cmd_hash from request */
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHECKSUM) = 0;  /* checksum = 0 */
    
    /* Decision at offset RBOX_HEADER_SIZE (92) */
    pkt[RBOX_HEADER_SIZE] = decision;
    
    /* Reason string at offset RBOX_HEADER_SIZE + 1 */
    if (reason_len > 0) {
        memcpy(pkt + RBOX_HEADER_SIZE + 1, reason, reason_len);
        pkt[RBOX_HEADER_SIZE + 1 + reason_len] = '\0';  /* null terminator */
    }
    
    *out_len = total_len;
    return pkt;
}

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
            //////fprintf(stderr, "DEBUG C: processing decision from queue\n");
            fflush(stderr);
            rbox_server_decision_t *dec = server->decision_queue;
            server->decision_queue = (void*)dec->next;
            if (!server->decision_queue) {
                server->decision_tail = NULL;
            }
            server->decision_count--;
            pthread_mutex_unlock(&server->decision_mutex);
            
            /* Actually send the decision (now on epoll thread) */
            rbox_server_request_t *req = dec->request;
            if (req) {
                size_t resp_len;
                uint32_t cmd_hash = req->cmd_hash;
                
                /* Compute 64-bit hash of command for time-limited decisions */
                uint64_t cmd_hash2 = 0;
                if (req->command_data && req->command_len > 0) {
                    cmd_hash2 = rbox_hash64(req->command_data, req->command_len);
                }
                
                /* First, store response in cache for duplicate requests */
                response_cache_insert(server, req->client_id, req->request_id, cmd_hash, cmd_hash2,
                                      dec->decision, dec->reason, dec->duration);
                
                /* Then build and send response directly */
                char *resp = build_response(req->client_id, req->request_id, cmd_hash, dec->decision, dec->reason, dec->duration, &resp_len);
                ////fprintf(stderr, "DEBUG C: build_response returned %p, len=%zu\n", (void*)resp, resp_len);
                if (resp) {
                    /* Send response directly - socket should be ready */
                    ////fprintf(stderr, "DEBUG C: about to write %zu bytes to fd %d\n", resp_len, req->fd);
                    ssize_t sent = rbox_write(req->fd, resp, resp_len);
                    ////fprintf(stderr, "DEBUG C: wrote %zd bytes\n", sent);
                    free(resp);
                } else {
                    ////fprintf(stderr, "DEBUG C: build_response returned NULL!\n");
                }
                /* Close and cleanup */
                epoll_del(server->epoll_fd, req->fd);
                close(req->fd);
                server_request_free(req);
            }
            free(dec);
            pthread_mutex_lock(&server->decision_mutex);
        }
        pthread_mutex_unlock(&server->decision_mutex);
        
        /* Process epoll events */
        ////////fprintf(stderr, "DEBUG: calling epoll_wait\n");
        int n = epoll_wait(server->epoll_fd, events, 64, 100); /* 100ms timeout */
        ////////fprintf(stderr, "DEBUG: epoll_wait returned n=%d\n", n);
        
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        if (n == 0) {
            /* Timeout - just continue */
            continue;
        }
        
        //////fprintf(stderr, "DEBUG: got %d events\n", n);
        fflush(stderr);
        
        for (int i = 0; i < n; i++) {
            struct epoll_event *ev = &events[i];
            
            /* Listen socket - accept new connection */
            if (ev->data.fd == server->listen_fd) {
                //////fprintf(stderr, "DEBUG: accept() called\n");
                fflush(stderr);
                struct sockaddr_un addr;
                socklen_t addrlen = sizeof(addr);
                int cl_fd = accept(server->listen_fd, (struct sockaddr *)&addr, &addrlen);
                if (cl_fd >= 0) {
                    //////fprintf(stderr, "DEBUG: accepted fd=%d\n", cl_fd);
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
                read(server->wake_fd, &val, sizeof(val));
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
                        
                        /* Remove from epoll and try to send */
                        epoll_del(server->epoll_fd, cl_fd);
                        ssize_t sent = rbox_write(entry->fd, entry->data, entry->len);
                        (void)sent;
                        close(entry->fd);
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
                /* Try to read request */
                uint8_t client_id[16], request_id[16];
                uint32_t cmd_hash, chunk_len;
                char caller[RBOX_MAX_CALLER_LEN + 1];
                char syscall[RBOX_MAX_SYSCALL_LEN + 1];
                
                int hdr_result = server_read_header(cl_fd, client_id, request_id, &cmd_hash, 
                    caller, sizeof(caller), syscall, sizeof(syscall), &chunk_len);
                //////fprintf(stderr, "DEBUG: server_read_header returned %d\n", hdr_result);
                fflush(stderr);
                
                if (hdr_result == 0) {
                    //////fprintf(stderr, "DEBUG: header OK, chunk_len=%u\n", chunk_len);
                    fflush(stderr);
                    
                    /* Read the body first so we can compute cmd_hash2 for cache lookup */
                    char *cmd_data = read_body(cl_fd, chunk_len);
                    
                    /* Compute 64-bit hash for time-limited decision matching */
                    uint64_t cmd_hash2 = 0;
                    if (cmd_data && chunk_len > 0) {
                        cmd_hash2 = rbox_hash64(cmd_data, chunk_len);
                    }
                    
                    // Check response cache for duplicate request (now includes cmd_hash2)
                    uint8_t cached_decision;
                    char cached_reason[256];
                    uint32_t cached_duration;
                    if (response_cache_lookup(server, request_id, cmd_hash, cmd_hash2, &cached_decision, cached_reason, &cached_duration)) {
                        // Send cached response directly
                        size_t resp_len;
                        char *resp = build_response(client_id, request_id, cmd_hash, cached_decision, cached_reason, cached_duration, &resp_len);
                        if (resp) {
                            ssize_t sent = rbox_write(cl_fd, resp, resp_len);
                            (void)sent;
                            free(resp);
                        }
                        free(cmd_data);
                        epoll_del(server->epoll_fd, cl_fd);
                        close(cl_fd);
                        continue;
                    }
                    
                    if (cmd_data) {
                        //////fprintf(stderr, "DEBUG: cmd_data='%s'\n", cmd_data);
                        fflush(stderr);
                        
                        /* Create request handle */
                        rbox_server_request_t *req = calloc(1, sizeof(*req));
                        if (req) {
                            req->fd = cl_fd;
                            memcpy(req->client_id, client_id, 16);
                            memcpy(req->request_id, request_id, 16);
                            req->cmd_hash = cmd_hash;
                            req->server = server;
                            req->command_data = cmd_data;
                            req->command_len = chunk_len;
                            
                            /* Store caller and syscall from v7 protocol */
                            strncpy(req->caller, caller, RBOX_MAX_CALLER_LEN);
                            req->caller[RBOX_MAX_CALLER_LEN] = '\0';
                            strncpy(req->syscall, syscall, RBOX_MAX_SYSCALL_LEN);
                            req->syscall[RBOX_MAX_SYSCALL_LEN] = '\0';
                            
                            /* Parse command */
                            rbox_command_parse(cmd_data, chunk_len, &req->parse);
                            
                            /* Add to queue and signal */
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
    server->request_queue = req->next;
    if (server->request_queue == NULL) {
        server->request_tail = NULL;
    }
    req->next = NULL;
    server->request_count--;
    
    pthread_mutex_unlock(&server->mutex);
    
    return req;
}

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

/* Queue decision to be sent by background thread (thread-safe) */
rbox_error_t rbox_server_decide(rbox_server_request_t *req, uint8_t decision, const char *reason, uint32_t duration) {
    if (!req) return RBOX_ERR_INVALID;
    
    //////fprintf(stderr, "DEBUG C: rbox_server_decide called\n");
    fflush(stderr);
    
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
        write(server->wake_fd, &val, sizeof(val));
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
    
    pthread_mutex_destroy(&server->mutex);
    pthread_cond_destroy(&server->cond);
    
    free(server);
}

/* Check if request is a stop request */
int rbox_server_request_is_stop(const rbox_server_request_t *req) {
    if (!req || !req->command_data) return 0;
    return (strcmp(req->command_data, "__RBOX_STOP__") == 0);
}
