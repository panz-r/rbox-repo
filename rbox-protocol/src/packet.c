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

/* Thread-local seed for rand_r() - initialized on first use per thread */
static __thread uint32_t g_rand_seed = 0;

/* Initialize the thread-local seed if not yet initialized */
static void ensure_rand_seed_init(void) {
    if (g_rand_seed == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uintptr_t tid = (uintptr_t)pthread_self();
        g_rand_seed = (uint32_t)((uint64_t)ts.tv_sec ^ ((uint64_t)ts.tv_nsec << 32) ^ tid);
    }
}

/* Forward declarations for layered encoding functions */
static int rbox_decode_request_body(const char *body_buf, size_t body_len,
                            rbox_request_t *request);

static int rbox_decode_request_body(const char *body_buf, size_t body_len,
                            rbox_request_t *request) {
    if (!body_buf || !request) return -1;
    if (body_len == 0) return -1;

    memset(request, 0, sizeof(*request));
    request->data = malloc(body_len + 1);  /* +1 for null terminator */
    if (!request->data) return -1;

    memcpy(request->data, body_buf, body_len);
    request->data[body_len] = '\0';  /* Null terminate */
    request->data_len = body_len;

    /* Parse: command\0caller\0syscall\0argv...\0 */
    char *p = request->data;
    size_t remaining = body_len;

    /* command - must have at least 1 byte + null terminator */
    if (remaining < 2) goto parse_error;
    request->command = p;
    size_t token_len = strlen(p);
    if (token_len + 1 > remaining) goto parse_error;
    p += token_len + 1;
    remaining -= token_len + 1;

    /* caller (skip) - must have at least 1 byte + null terminator */
    if (remaining < 1) goto parse_error;
    if (p[0] != '\0') {
        token_len = strlen(p);
        if (token_len + 1 > remaining) goto parse_error;
        p += token_len + 1;
        remaining -= token_len + 1;
    } else {
        p++;
        remaining--;
    }

    /* syscall (skip) - must have at least 1 byte + null terminator */
    if (remaining < 1) goto parse_error;
    if (p[0] != '\0') {
        token_len = strlen(p);
        if (token_len + 1 > remaining) goto parse_error;
        p += token_len + 1;
        remaining -= token_len + 1;
    } else {
        p++;
        remaining--;
    }

    /* Count and parse argv */
    char *argv_start = p;
    int argc = 0;
    while (remaining > 0 && p[0] != '\0') {
        token_len = strlen(p);
        if (token_len + 1 > remaining) goto parse_error;
        p += token_len + 1;
        remaining -= token_len + 1;
        argc++;
    }

    /* Skip final \0 - need at least 1 byte */
    if (remaining < 1) goto parse_error;
    p++;  /* Skip final \0 */
    remaining--;

    /* Allocate argv array */
    request->argv = calloc(argc + 1, sizeof(char *));
    if (!request->argv) {
        rbox_request_free(request);
        return -1;
    }

    /* Fill argv pointers */
    p = argv_start;
    for (int i = 0; i < argc; i++) {
        request->argv[i] = p;
        p += strlen(p) + 1;
    }
    request->argv_len = argc;
    request->argv[argc] = NULL;

    return 0;

parse_error:
    /* Clean up on parse error */
    if (request->data) free(request->data);
    if (request->argv) free(request->argv);
    memset(request, 0, sizeof(*request));
    return -1;
}

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

/* Call once at program start to initialize CRC32 table and random seed */
void rbox_init(void) {
    init_crc32_table();
    /* Initialize random seed for request/client ID generation */
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
}

/* Forward declarations for ID generation functions */
static void generate_request_id(uint8_t *id_out);
static void generate_client_id(uint8_t *id_out);
static void init_client_id_once(void);

/* Static client_id - generated once per process */
static uint8_t g_client_id[16] = {0};
static pthread_once_t g_client_id_once = PTHREAD_ONCE_INIT;

/* CRC32 checksum - composable, takes previous CRC value
 * If prev_crc is 0, starts fresh (initial CRC = 0xFFFFFFFF).
 * Otherwise continues from prev_crc (expects pre-xored value). */
uint32_t rbox_calculate_checksum_crc32(uint32_t prev_crc, const void *data, size_t len) {
    /* Always initialize table */
    init_crc32_table();

    /* Start from initial CRC or continue from given value (already xored) */
    uint32_t crc = prev_crc == 0 ? 0xFFFFFFFF : prev_crc;
    const uint8_t *bytes = (const uint8_t *)data;
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

/* Validate header from binary packet - uses explicit byte offsets, NOT struct
 * This ensures we validate the actual binary format, not struct layout */
rbox_error_t rbox_header_validate(const char *packet, size_t len) {
    if (!packet || len < RBOX_HEADER_SIZE) return RBOX_ERR_INVALID;

    /* Check magic at offset 0 */
    uint32_t magic = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_MAGIC);
    if (magic != RBOX_MAGIC) {
        return RBOX_ERR_MAGIC;
    }

    /* Check version at offset 4 */
    uint32_t version = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_VERSION);
    if (version != RBOX_VERSION) {
        return RBOX_ERR_VERSION;
    }

    /* Verify checksum at offset 119 - compute CRC over bytes 0-118 only */
    uint32_t stored_checksum = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_CHECKSUM);
    uint32_t calc_checksum = rbox_calculate_checksum_crc32(0, packet, RBOX_HEADER_OFFSET_CHECKSUM);

    if (stored_checksum != calc_checksum) {
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

/* Read header from client - validates binary packet format */
static rbox_error_t read_header(rbox_client_t *client, rbox_header_t *header) {
    char packet[RBOX_HEADER_SIZE];
    ssize_t n = rbox_read(rbox_client_fd(client), packet, RBOX_HEADER_SIZE);
    if (n < 0) {
        return RBOX_ERR_IO;
    }
    if (n != RBOX_HEADER_SIZE) {
        return RBOX_ERR_TRUNCATED;
    }

    /* Validate header - checks magic, version, and checksum using binary format */
    rbox_error_t err = rbox_header_validate(packet, RBOX_HEADER_SIZE);
    if (err != RBOX_OK) {
        return err;
    }

    /* Copy to struct for caller convenience */
    memcpy(header, packet, RBOX_HEADER_SIZE);

    return RBOX_OK;
}

static rbox_error_t read_request_data(rbox_client_t *client,
                                     const rbox_header_t *header,
                                     rbox_request_t *request) {
    /* For single-chunk requests, use chunk_len to determine size
     * For chunked requests, this will be called per-chunk by the stream functions
     */
    size_t buf_size = header->chunk_len;
    if (buf_size == 0) {
        return RBOX_ERR_IO;  /* No body to read */
    }
    if (buf_size > RBOX_CHUNK_MAX) buf_size = RBOX_CHUNK_MAX;

    char *body_buf = malloc(buf_size);
    if (!body_buf) {
        return RBOX_ERR_MEMORY;
    }

    /* Read exactly chunk_len bytes */
    ssize_t n = rbox_read(rbox_client_fd(client), body_buf, buf_size);
    if (n <= 0) {
        free(body_buf);
        return RBOX_ERR_IO;
    }

    /* Decode body to request structure */
    if (rbox_decode_request_body(body_buf, n, request) != 0) {
        free(body_buf);
        return RBOX_ERR_IO;
    }

    free(body_buf);
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
    memset(buffer, 0, sizeof(buffer));
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

    /* Checksum (over header + data, excluding checksum field at offset 123) */
    uint32_t checksum = rbox_calculate_checksum_crc32(0, buffer, RBOX_HEADER_OFFSET_CHECKSUM);
    checksum = rbox_calculate_checksum_crc32(checksum, buffer + RBOX_HEADER_OFFSET_CHECKSUM + 4,
                                              RBOX_HEADER_SIZE + len - (RBOX_HEADER_OFFSET_CHECKSUM + 4));
    memcpy(buffer + RBOX_HEADER_OFFSET_CHECKSUM, &checksum, 4);
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
    rbox_header_t header_buf;
    ssize_t n = rbox_read(rbox_client_fd(client), &header_buf, sizeof(header_buf));
    if (n != sizeof(header_buf)) {
        return RBOX_ERR_TRUNCATED;
    }

    /* Validate header */
    if (header_buf.magic != RBOX_MAGIC) {
        return RBOX_ERR_MAGIC;
    }
    if (header_buf.version != RBOX_VERSION) {
        return RBOX_ERR_VERSION;
    }

    /* Validate offset matches expected */
    if (header_buf.offset != stream->offset) {
        /* Client trying to resume from wrong offset */
        return RBOX_ERR_INVALID;
    }

    /* Read chunk data */
    size_t chunk_len = header_buf.chunk_len;
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

/* Build request packet - uses layered encoding
 * Format: command\0caller\0syscall\0argv[0]\0argv[1]\0...\0
 *
 * Parameters:
 *   - packet: output buffer
 *   - capacity: size of output buffer (must be >= RBOX_HEADER_SIZE + min_body_size)
 *   - out_len: actual packet length written
 *   - command: the command to execute
 *   - caller: optional caller identifier (e.g., "judge", "run")
 *   - syscall: optional syscall being queried (e.g., "execve")
 *   - argc: number of arguments
 *   - argv: argument array */
rbox_error_t rbox_build_request(char *packet, size_t capacity, size_t *out_len,
                               const char *command, const char *caller, const char *syscall,
                               int argc, const char **argv,
                               int env_var_count, const char **env_var_names, const float *env_var_scores) {
    if (!packet || !command || !out_len) {
        return RBOX_ERR_INVALID;
    }

    /* Estimate required capacity: header + command + caller + syscall + argv + env vars.
       Each env var: name + null + 4 bytes score. */
    size_t needed = RBOX_HEADER_SIZE + strlen(command) + 1;
    if (caller) needed += strlen(caller) + 1;
    else needed += 1;  /* empty caller */
    if (syscall) needed += strlen(syscall) + 1;
    else needed += 1;  /* empty syscall */
    for (int i = 0; i < argc; i++) {
        if (argv[i]) needed += strlen(argv[i]) + 1;
    }
    needed += 1; /* final null after argv */
    for (int i = 0; i < env_var_count; i++) {
        if (env_var_names[i]) {
            needed += strlen(env_var_names[i]) + 1 + 4;
        }
    }
    if (capacity < needed) {
        return RBOX_ERR_INVALID;
    }

    memset(packet, 0, capacity);

    /* Encode body: command\0caller\0syscall\0argv[0]\0...\0\0 env_name\0score... */
    size_t pos = RBOX_HEADER_SIZE;
    char *body = packet + RBOX_HEADER_SIZE;

    /* command */
    size_t cmd_len = strlen(command);
    memcpy(body + pos - RBOX_HEADER_SIZE, command, cmd_len + 1);
    pos += cmd_len + 1;

    /* caller */
    if (caller && caller[0]) {
        size_t caller_len = strlen(caller);
        memcpy(body + pos - RBOX_HEADER_SIZE, caller, caller_len + 1);
        pos += caller_len + 1;
    } else {
        body[pos - RBOX_HEADER_SIZE] = '\0';
        pos += 1;
    }

    /* syscall */
    if (syscall && syscall[0]) {
        size_t syscall_len = strlen(syscall);
        memcpy(body + pos - RBOX_HEADER_SIZE, syscall, syscall_len + 1);
        pos += syscall_len + 1;
    } else {
        body[pos - RBOX_HEADER_SIZE] = '\0';
        pos += 1;
    }

    /* argv */
    for (int i = 0; i < argc; i++) {
        if (!argv[i]) break;
        size_t arg_len = strlen(argv[i]);
        memcpy(body + pos - RBOX_HEADER_SIZE, argv[i], arg_len + 1);
        pos += arg_len + 1;
    }
    /* End of argv marker (extra null) */
    body[pos - RBOX_HEADER_SIZE] = '\0';
    pos += 1;

    /* Environment variables */
    uint32_t fenv_hash = 0;
    for (int i = 0; i < env_var_count; i++) {
        if (!env_var_names[i]) continue;
        size_t name_len = strlen(env_var_names[i]);
        memcpy(body + pos - RBOX_HEADER_SIZE, env_var_names[i], name_len + 1);
        pos += name_len + 1;
        float score = env_var_scores[i];
        memcpy(body + pos - RBOX_HEADER_SIZE, &score, 4);
        pos += 4;

        /* Update fenv_hash (simple djb2) */
        const char *s = env_var_names[i];
        uint32_t h = 5381;
        while (*s) {
            h = ((h << 5) + h) + (uint32_t)(unsigned char)*s++;
        }
        fenv_hash ^= h;
    }

    size_t body_len = pos - RBOX_HEADER_SIZE;

    /* Fill header */
    uint32_t magic = RBOX_MAGIC;
    uint32_t version = RBOX_VERSION;
    uint32_t type = RBOX_MSG_REQ;
    uint32_t flags = RBOX_FLAG_FIRST;
    uint64_t offset = 0;
    uint32_t chunk_len = body_len;
    uint64_t total_len = body_len;

    memcpy(packet + 0, &magic, 4);
    memcpy(packet + 4, &version, 4);
    generate_client_id((uint8_t *)(packet + 8));
    generate_request_id((uint8_t *)(packet + 24));
    memcpy(packet + 56, &type, 4);
    memcpy(packet + 60, &flags, 4);
    memcpy(packet + 64, &offset, 8);
    memcpy(packet + 72, &chunk_len, 4);
    memcpy(packet + 76, &total_len, 8);
    /* Set cmd_hash (optional, can be 0) */
    *(uint32_t *)(packet + RBOX_HEADER_OFFSET_CMD_HASH) = 0;
    /* Set fenv_hash */
    *(uint32_t *)(packet + RBOX_HEADER_OFFSET_FENV_HASH) = fenv_hash;

    /* Set caller and syscall sizes in header (same as before) */
    size_t caller_len = caller ? strlen(caller) : 0;
    size_t syscall_len = syscall ? strlen(syscall) : 0;
    if (caller_len > 15) caller_len = 15;
    if (syscall_len > 15) syscall_len = 15;
    uint8_t cs_size = ((syscall_len << 4) & 0xF0) | (caller_len & 0x0F);
    memcpy(packet + RBOX_HEADER_OFFSET_CALLER_SYSCALL_SIZE, &cs_size, 1);
    if (caller && caller_len > 0) {
        memcpy(packet + RBOX_HEADER_OFFSET_CALLER, caller, caller_len);
    }
    if (syscall && syscall_len > 0) {
        memcpy(packet + RBOX_HEADER_OFFSET_SYSCALL, syscall, syscall_len);
    }

    /* Calculate header checksum (bytes 0–118) */
    uint32_t checksum = rbox_calculate_checksum_crc32(0, packet, RBOX_HEADER_OFFSET_CHECKSUM);
    memcpy(packet + RBOX_HEADER_OFFSET_CHECKSUM, &checksum, 4);

    /* Calculate body checksum (bytes from RBOX_HEADER_SIZE onward) */
    uint32_t body_checksum = rbox_calculate_checksum_crc32(0, packet + RBOX_HEADER_SIZE, body_len);
    memcpy(packet + RBOX_HEADER_OFFSET_BODY_CHECKSUM, &body_checksum, 4);

    *out_len = RBOX_HEADER_SIZE + body_len;
    return RBOX_OK;
}

/* Parse response packet - v9 format: header (127 bytes) + body with decision at RBOX_HEADER_SIZE */
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
        /* v9 format */
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
 * LAYERED DECODE UTILITIES (v9)
 * ============================================================ */

/* Compute checksum for header verification */
/* Note: Currently unused - kept for potential future use */
static __attribute__((unused)) uint32_t compute_header_checksum(const char *packet, size_t len) {
    if (!packet || len < RBOX_HEADER_SIZE) return 0;
    uint32_t sum = 0;
    for (size_t i = 0; i < RBOX_HEADER_OFFSET_CHECKSUM; i++) {
        sum ^= (uint32_t)(unsigned char)packet[i];
    }
    for (size_t i = RBOX_HEADER_OFFSET_CHECKSUM + 4; i < RBOX_HEADER_SIZE && i < len; i++) {
        sum ^= (uint32_t)(unsigned char)packet[i];
    }
    return sum;
}

/* Decode header from packet - verifies magic, version, checksum
 * Returns: header struct with valid=1 if successful */
//export rbox_decode_header
void rbox_decode_header(const char *packet, size_t len, rbox_decoded_header_t *header) {
    if (!packet || !header) return;
    memset(header, 0, sizeof(*header));
    if (len < RBOX_HEADER_SIZE) return;

    header->magic = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_MAGIC);
    if (header->magic != RBOX_MAGIC) return;
    header->version = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_VERSION);
    if (header->version != RBOX_VERSION) return;

    memcpy(header->client_id, packet + RBOX_HEADER_OFFSET_CLIENT_ID, 16);
    memcpy(header->request_id, packet + RBOX_HEADER_OFFSET_REQUEST_ID, 16);
    memcpy(header->server_id, packet + RBOX_HEADER_OFFSET_SERVER_ID, 16);
    header->cmd_type = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_TYPE);
    header->flags = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_FLAGS);
    header->offset = *(uint64_t *)(packet + RBOX_HEADER_OFFSET_OFFSET);
    header->chunk_len = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_CHUNK_LEN);
    header->total_len = *(uint64_t *)(packet + RBOX_HEADER_OFFSET_TOTAL_LEN);
    header->cmd_hash = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_CMD_HASH);
    header->fenv_hash = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_FENV_HASH);
    header->checksum = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_CHECKSUM);

    /* Verify header checksum: compute CRC over header bytes 0-118 (excluding checksum at 119) */
    uint32_t hdr_crc = rbox_calculate_checksum_crc32(0, packet, RBOX_HEADER_OFFSET_CHECKSUM);
    if (header->checksum != hdr_crc) {
        memset(header, 0, sizeof(*header));
        return;
    }
    header->valid = 1;
}

/* Decode response details from packet */
//export rbox_decode_response_details
void rbox_decode_response_details(const rbox_decoded_header_t *header, const char *packet, size_t len, rbox_response_details_t *details) {
    if (!header || !packet || !details) return;
    memset(details, 0, sizeof(*details));
    if (!header->valid || len <= RBOX_HEADER_SIZE) return;

    details->decision = (uint8_t)packet[RBOX_HEADER_SIZE];
    size_t reason_offset = RBOX_HEADER_SIZE + 1;
    details->reason_len = 0;
    while (reason_offset < len && details->reason_len < 255) {
        if (packet[reason_offset] == '\0') break;
        details->reason[details->reason_len++] = packet[reason_offset++];
    }
    details->reason[details->reason_len] = '\0';
    details->valid = 1;
}

/* Decode env decisions from packet */
//export rbox_decode_env_decisions
void rbox_decode_env_decisions(const rbox_decoded_header_t *header, const rbox_response_details_t *details, const char *packet, size_t len, rbox_env_decisions_t *env_decisions) {
    if (!header || !details || !packet || !env_decisions) return;
    memset(env_decisions, 0, sizeof(*env_decisions));
    if (!header->valid || !details->valid) return;

    size_t reason_offset = RBOX_HEADER_SIZE + 1 + details->reason_len + 1;
    if (len < reason_offset + 6) return;

    env_decisions->fenv_hash = *(uint32_t *)(packet + reason_offset);
    size_t env_offset = reason_offset + 4;
    env_decisions->env_count = *(uint16_t *)(packet + env_offset);
    env_offset += 2;

    if (env_decisions->env_count == 0 || env_decisions->env_count > 256) {
        env_decisions->valid = 1;
        return;
    }

    size_t bitmap_size = (env_decisions->env_count + 7) / 8;
    if (len < env_offset + bitmap_size) {
        env_decisions->env_count = 0;
        return;
    }

    env_decisions->bitmap = malloc(bitmap_size);
    if (!env_decisions->bitmap) {
        env_decisions->env_count = 0;
        return;
    }
    memcpy(env_decisions->bitmap, packet + env_offset, bitmap_size);
    env_decisions->valid = 1;
}

/* Free env decisions */
//export rbox_free_env_decisions
void rbox_free_env_decisions(rbox_env_decisions_t *env_decisions) {
    if (!env_decisions) return;
    free(env_decisions->bitmap);
    env_decisions->bitmap = NULL;
    env_decisions->env_count = 0;
    env_decisions->valid = 0;
}

/* ============================================================
 * CLIENT WORKFLOW - Send Request & Get Validated Response
 * ============================================================ */

/* Generate a unique request ID using timestamp + random
 * This helps match responses to requests */
static void generate_request_id(uint8_t *id_out) {
    if (!id_out) return;

    ensure_rand_seed_init();

    /* Use current time + random to generate unique ID */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    /* Mix bits for uniqueness */
    uint64_t a = (uint64_t)ts.tv_sec ^ ((uint64_t)ts.tv_nsec << 32);
    uint64_t b = (uint64_t)rand_r(&g_rand_seed) ^ ((uint64_t)getpid() << 32);

    memcpy(id_out, &a, 8);
    memcpy(id_out + 8, &b, 8);
}

/* Generate client ID using pid + ppid + random
 * Client ID should be consistent for a process across requests (generated once) */
static void init_client_id_once(void) {
    ensure_rand_seed_init();

    pid_t pid = getpid();
    pid_t ppid = getppid();

    /* First 8 bytes: pid + ppid */
    uint64_t id_part1 = ((uint64_t)(uint32_t)pid << 32) | (uint32_t)ppid;

    /* Last 8 bytes: random + timestamp */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t random_part = ((uint64_t)rand_r(&g_rand_seed) << 32) ^ (uint64_t)ts.tv_nsec;

    memcpy(g_client_id, &id_part1, 8);
    memcpy(g_client_id + 8, &random_part, 8);
}

static void generate_client_id(uint8_t *id_out) {
    if (!id_out) return;

    /* Generate client_id once per process using pthread_once */
    pthread_once(&g_client_id_once, init_client_id_once);

    /* Copy the persistent client_id to output */
    memcpy(id_out, g_client_id, 16);
}

/* Read response - uses proper rbox-protocol interface functions
 * Returns bytes read, 0 on close, -1 on error */
static ssize_t read_response(int fd, char *buf, size_t max_len) {
    /* First read the header */
    char header[RBOX_HEADER_SIZE];

    ssize_t n = rbox_read(fd, header, RBOX_HEADER_SIZE);
    if (n <= 0) {
        return n;  /* Error or closed */
    }

    if (n < (ssize_t)RBOX_HEADER_SIZE) {
        /* Truncated header */
        return -1;
    }

    /* Validate header using proper interface */
    rbox_error_t hdr_err = rbox_header_validate(header, RBOX_HEADER_SIZE);
    if (hdr_err != RBOX_OK) {
        return -1;  /* Invalid header */
    }

    /* Decode header to get body length */
    rbox_decoded_header_t decoded;
    rbox_decode_header(header, RBOX_HEADER_SIZE, &decoded);
    if (!decoded.valid) {
        return -1;
    }

    /* Get body length from chunk_len field */
    uint32_t body_len = decoded.chunk_len;
    if (body_len > RBOX_CHUNK_MAX) {
        body_len = RBOX_CHUNK_MAX;
    }

    /* Calculate total response size */
    size_t total_len = RBOX_HEADER_SIZE + body_len;
    if (total_len > max_len) {
        total_len = max_len;
    }

    /* Copy header to buffer */
    memcpy(buf, header, RBOX_HEADER_SIZE);

    /* Read remaining body */
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
    const char *command, const char *caller, const char *syscall, int argc, const char **argv,
    int env_var_count, const char **env_var_names, const float *env_var_scores,
    rbox_response_t *response) {
    if (!client || !command || !response) {
        return RBOX_ERR_INVALID;
    }

    /* Build request packet using canonical layered function */
    char packet[4096];
    size_t packet_len;
    rbox_error_t err = rbox_build_request(packet, sizeof(packet), &packet_len, command, caller, syscall, argc, argv, env_var_count, env_var_names, env_var_scores);
    if (err != RBOX_OK) {
        return err;
    }

    /* Extract the actual request ID from the packet (the one that will be sent) */
    uint8_t request_id[16];
    memcpy(request_id, packet + RBOX_HEADER_OFFSET_REQUEST_ID, 16);

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

    /* Validate response with the extracted request_id */
    err = validate_response(response_buf, resp_len, request_id, response);
    if (err != RBOX_OK) {
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

    /* Send state (non-blocking) */
    char   *send_buf;         /* Dynamically allocated request packet */
    size_t  send_len;         /* Total length to send */
    size_t  send_offset;      /* Number of bytes already sent */

    /* Receive state (non-blocking) */
    char   *recv_buf;         /* Buffer for accumulating response data */
    size_t  recv_capacity;    /* Current capacity of recv_buf */
    size_t  recv_len;         /* Number of bytes received so far */

    /* Response - raw data (for --bin mode) */
    char *response_data;
    size_t response_len;

    /* Response - parsed (for normal mode) */
    rbox_response_t response;

    /* Connection retry state */
    uint32_t retry_attempt;
    uint64_t next_retry_time;
};

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

    /* No initial packet buffer - we'll allocate send_buf on demand */
    return session;
}

void rbox_session_free(rbox_session_t *session) {
    if (!session) return;
    rbox_client_close(session->client);
    free(session->send_buf);
    free(session->recv_buf);
    free(session->response_data);
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

    ensure_rand_seed_init();

    uint32_t max_delay = base * 64;
    uint32_t exp = base;
    for (uint32_t i = 1; i < session->retry_attempt && exp < UINT32_MAX / 2; i++) {
        exp *= 2;
    }

    uint32_t jitter = (uint32_t)((double)base * rand_r(&g_rand_seed) / (RAND_MAX + 1.0));
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
    const char *command, const char *caller, const char *syscall,
    int argc, const char **argv,
    int env_var_count, const char **env_var_names, const float *env_var_scores) {
    if (!session || !command) return RBOX_ERR_INVALID;
    if (session->state != RBOX_SESSION_CONNECTED) return RBOX_ERR_INVALID;

    /* Build request into a temporary buffer */
    char tmp[8192];
    size_t tmp_len;
    rbox_error_t err = rbox_build_request(tmp, sizeof(tmp), &tmp_len,
        command, caller, syscall, argc, argv,
        env_var_count, env_var_names, env_var_scores);  /* let build_request generate the request_id */
    if (err != RBOX_OK) {
        session->state = RBOX_SESSION_FAILED;
        session->error = err;
        return err;
    }

    /* Extract the generated request_id from the packet */
    memcpy(session->request_id, tmp + RBOX_HEADER_OFFSET_REQUEST_ID, 16);

    /* Allocate send buffer and copy the packet */
    session->send_buf = malloc(tmp_len);
    if (!session->send_buf) {
        session->state = RBOX_SESSION_FAILED;
        session->error = RBOX_ERR_MEMORY;
        return RBOX_ERR_MEMORY;
    }
    memcpy(session->send_buf, tmp, tmp_len);
    session->send_len = tmp_len;
    session->send_offset = 0;

    session->state = RBOX_SESSION_SENDING;
    return RBOX_OK;
}

/* Send raw packet data (pre-built) */
rbox_error_t rbox_session_send_raw(rbox_session_t *session, const char *data, size_t len) {
    if (!session || !data || len == 0) return RBOX_ERR_INVALID;
    if (session->state != RBOX_SESSION_CONNECTED) return RBOX_ERR_INVALID;

    /* Allocate send buffer and copy data */
    free(session->send_buf);  /* free any previous buffer */
    session->send_buf = malloc(len);
    if (!session->send_buf) {
        session->state = RBOX_SESSION_FAILED;
        return RBOX_ERR_MEMORY;
    }
    memcpy(session->send_buf, data, len);
    session->send_len = len;
    session->send_offset = 0;

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

            case RBOX_SESSION_CONNECTING:
                /* If socket is writable, check connection status */
                if (events & POLLOUT) {
                    int fd = rbox_client_fd(session->client);
                    int so_error;
                    socklen_t optlen = sizeof(so_error);
                    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &optlen) == 0 && so_error == 0) {
                        session->state = RBOX_SESSION_CONNECTED;
                        session->retry_attempt = 0;
                    } else {
                        /* Connection failed */
                        rbox_client_close(session->client);
                        session->client = NULL;
                        if (session->base_delay_ms > 0 && should_retry(session)) {
                            session->retry_attempt++;
                            session->next_retry_time = get_time_ms() + calc_retry_delay(session);
                            /* remain in CONNECTING */
                        } else {
                            session->state = RBOX_SESSION_FAILED;
                            session->error = RBOX_ERR_IO;
                        }
                    }
                    break;
                }

                /* Handle retry timeouts (existing code) */
                if (!session->client && session->base_delay_ms > 0) {
                    if (get_time_ms() < session->next_retry_time) {
                        break;
                    }
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

        case RBOX_SESSION_CONNECTED:
            /* Idle, waiting for request */
            break;

        case RBOX_SESSION_SENDING:
            if (events & POLLOUT) {
                int fd = rbox_client_fd(session->client);
                ssize_t n = rbox_write_nonblocking(fd,
                    session->send_buf, session->send_len, &session->send_offset);
                if (n < 0) {
                    /* Write error - close and reconnect if retry allowed */
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
                    break;
                }
                if (session->send_offset == session->send_len) {
                    /* All data sent – free buffer and move to WAITING */
                    free(session->send_buf);
                    session->send_buf = NULL;
                    session->state = RBOX_SESSION_WAITING;
                }
                /* else still sending, wait for next POLLOUT */
            }
            break;

        case RBOX_SESSION_WAITING:
            if (events & POLLIN) {
                int fd = rbox_client_fd(session->client);

                /* Allocate receive buffer if not yet done */
                if (!session->recv_buf) {
                    session->recv_capacity = 4096;
                    session->recv_buf = malloc(session->recv_capacity);
                    if (!session->recv_buf) {
                        session->state = RBOX_SESSION_FAILED;
                        session->error = RBOX_ERR_MEMORY;
                        break;
                    }
                    session->recv_len = 0;
                }

                /* Read as much as possible without blocking */
                size_t space = session->recv_capacity - session->recv_len;
                ssize_t n = rbox_read_nonblocking(fd,
                             session->recv_buf + session->recv_len, space);
                if (n == -2) {  /* peer closed */
                    /* If we already have enough data to form a complete response,
                       we can still validate it. Otherwise, fail. */
                    if (session->recv_len < RBOX_HEADER_SIZE) {
                        session->state = RBOX_SESSION_FAILED;
                        session->error = RBOX_ERR_IO;
                        break;
                    }
                    /* We'll attempt validation below using the data we have. */
                } else if (n < 0) {
                    session->state = RBOX_SESSION_FAILED;
                    session->error = RBOX_ERR_IO;
                    break;
                } else if (n == 0) {
                    /* No data yet – wait for next POLLIN */
                    break;
                } else {
                    session->recv_len += n;
                }

                /* Check if we have a complete header */
                if (session->recv_len >= RBOX_HEADER_SIZE) {
                    rbox_decoded_header_t hdr;
                    rbox_decode_header(session->recv_buf, session->recv_len, &hdr);
                    if (!hdr.valid) {
                        session->state = RBOX_SESSION_FAILED;
                        session->error = RBOX_ERR_INVALID;
                        break;
                    }
                    size_t total_needed = RBOX_HEADER_SIZE + hdr.chunk_len;
                    if (session->recv_len >= total_needed) {
                        /* Full response received – validate */
                        rbox_response_t resp;
                        rbox_error_t err = validate_response(session->recv_buf,
                                            session->recv_len, session->request_id, &resp);
                        if (err == RBOX_OK) {
                            session->response = resp;
                            /* Transfer raw buffer to response_data */
                            session->response_data = session->recv_buf;
                            session->response_len = session->recv_len;
                            session->recv_buf = NULL;
                            session->recv_len = 0;
                            session->recv_capacity = 0;
                            session->state = RBOX_SESSION_RESPONSE_READY;
                        } else if (err == RBOX_ERR_MISMATCH ||
                                   err == RBOX_ERR_IO) {
                            /* Stale response – try again? For now, fail. */
                            session->state = RBOX_SESSION_FAILED;
                            session->error = err;
                        } else {
                            session->state = RBOX_SESSION_FAILED;
                            session->error = err;
                        }
                        break;
                    }
                    /* else still need more data – continue waiting */
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
        /* Free response data and receive buffer (if any) */
        free(session->response_data);
        session->response_data = NULL;
        session->response_len = 0;
        free(session->recv_buf);
        session->recv_buf = NULL;
        session->recv_len = 0;
        session->recv_capacity = 0;
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

/* Blocking request - calls raw and decodes the response */
rbox_error_t rbox_blocking_request(const char *socket_path,
    const char *command, int argc, const char **argv,
    const char *caller, const char *syscall,
    int env_var_count, const char **env_var_names, const float *env_var_scores,
    rbox_response_t *out_response,
    uint32_t base_delay_ms, uint32_t max_retries) {
    if (!socket_path || !command || !out_response) {
        return RBOX_ERR_INVALID;
    }

    /* Initialize response */
    memset(out_response, 0, sizeof(*out_response));

    /* Call raw version and decode result */
    char *packet = NULL;
    size_t packet_len = 0;

    rbox_error_t err = rbox_blocking_request_raw(socket_path, command, argc, argv,
        caller, syscall,
        env_var_count, env_var_names, env_var_scores,
        &packet, &packet_len, base_delay_ms, max_retries);

    if (err != RBOX_OK || !packet || packet_len == 0) {
        return err ? err : RBOX_ERR_IO;
    }

    /* Decode the response */
    rbox_decoded_header_t header;
    rbox_decode_header(packet, packet_len, &header);
    if (!header.valid) {
        free(packet);
        return RBOX_ERR_IO;
    }

    rbox_response_details_t details;
    rbox_decode_response_details(&header, packet, packet_len, &details);
    if (!details.valid) {
        free(packet);
        return RBOX_ERR_IO;
    }

    /* Copy to output response */
    out_response->decision = details.decision;
    strncpy(out_response->reason, details.reason, sizeof(out_response->reason) - 2);
    out_response->reason[sizeof(out_response->reason) - 1] = '\0';
    out_response->duration = 0;
    memcpy(out_response->request_id, header.request_id, 16);

    free(packet);
    return RBOX_OK;
}

/* Extended version that returns raw response packet (for --bin mode)
 * Has proper retry logic like rbox_blocking_request */
rbox_error_t rbox_blocking_request_raw(const char *socket_path,
    const char *command, int argc, const char **argv,
    const char *caller, const char *syscall,
    int env_var_count, const char **env_var_names, const float *env_var_scores,
    char **out_packet, size_t *out_packet_len,
    uint32_t base_delay_ms, uint32_t max_retries) {

    if (!socket_path || !command || !out_packet || !out_packet_len) {
        return RBOX_ERR_INVALID;
    }

    *out_packet = NULL;
    *out_packet_len = 0;

    /* Compute fenv_hash from flagged env vars */
    uint32_t fenv_hash = 0;
    if (env_var_count > 0 && env_var_names) {
        for (int i = 0; i < env_var_count; i++) {
            if (env_var_names[i]) {
                const char *s = env_var_names[i];
                uint32_t h = 5381;
                while (*s) {
                    h = ((h << 5) + h) + (uint32_t)(unsigned char)*s++;
                }
                fenv_hash ^= h;
            }
        }
    }

    /* Main retry loop - keep trying until success or max retries reached */
    while (1) {
        /* Build request packet */
        char *packet = malloc(8192);
        if (!packet) {
            return RBOX_ERR_MEMORY;
        }
        size_t packet_len = 0;

        rbox_error_t err = rbox_build_request(packet, 8192, &packet_len,
            command, caller, syscall, argc, argv,
            env_var_count, env_var_names, env_var_scores);
        if (err != RBOX_OK || packet_len == 0) {
            free(packet);
            return err ? err : RBOX_ERR_MEMORY;
        }

        /* Extract the request ID from the packet */
        uint8_t request_id[16];
        memcpy(request_id, packet + RBOX_HEADER_OFFSET_REQUEST_ID, 16);

        /* Create session */
        rbox_session_t *session = rbox_session_new(socket_path, base_delay_ms, max_retries);
        if (!session) {
            free(packet);
            return RBOX_ERR_MEMORY;
        }

        /* Set the session's request ID for later validation */
        memcpy(session->request_id, request_id, 16);

        /* Session loop */
        while (1) {
            rbox_session_state_t state = rbox_session_state(session);

            switch (state) {
                case RBOX_SESSION_DISCONNECTED: {
                    err = rbox_session_connect(session);
                    if (err != RBOX_OK && err != RBOX_ERR_IO) {
                        free(packet);
                        rbox_session_free(session);
                        return err;
                    }
                    break;
                }

                case RBOX_SESSION_CONNECTING: {
                    short events;
                    int fd = rbox_session_pollfd(session, &events);
                    if (fd >= 0 && rbox_pollout(fd, 5000) > 0) {
                        rbox_session_heartbeat(session, POLLOUT);
                    } else if (session->base_delay_ms > 0) {
                        uint64_t now = get_time_ms();
                        if (now >= session->next_retry_time) {
                            rbox_session_heartbeat(session, 0);
                        } else {
                            usleep(10000);
                        }
                    }
                    break;
                }

                case RBOX_SESSION_CONNECTED: {
                    err = rbox_session_send_raw(session, packet, packet_len);
                    if (err != RBOX_OK) {
                        break;
                    }
                    break;
                }

                case RBOX_SESSION_SENDING: {
                    short events;
                    int fd = rbox_session_pollfd(session, &events);
                    if (fd >= 0 && rbox_pollout(fd, 5000) > 0) {
                        rbox_session_heartbeat(session, POLLOUT);
                    }
                    break;
                }

                case RBOX_SESSION_WAITING:
                case RBOX_SESSION_RESPONSE_READY: {
                    /* Wait for response */
                    short events;
                    int fd = rbox_session_pollfd(session, &events);
                    if (fd >= 0) {
                        uint32_t revents = 0;
                        if (events & POLLIN) revents |= POLLIN;
                        if (events & POLLOUT) revents |= POLLOUT;
                        rbox_session_heartbeat(session, revents);
                    } else {
                        usleep(10000);
                    }
                    break;
                }

                case RBOX_SESSION_FAILED: {
                    /* Retry if allowed */
                    rbox_session_free(session);
                    free(packet);
                    goto retry;
                }
            }

            if (rbox_session_state(session) == RBOX_SESSION_RESPONSE_READY) {
                /* Success! */
                *out_packet = (char *)session->response_data;
                *out_packet_len = session->response_len;
                session->response_data = NULL;
                session->response_len = 0;
                rbox_session_free(session);
                free(packet);
                return RBOX_OK;
            }
        }

retry:
        /* Will loop back and retry if we haven't exceeded max_retries */
        /* The session state machine handles retry logic internally */
    }
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

    /* Caller/syscall  (truncated to 15 chars, no null) */
    char caller[RBOX_MAX_CALLER_LEN + 1];   /* Null-terminated */
    char syscall[RBOX_MAX_SYSCALL_LEN + 1]; /* Null-terminated */

    /* Request data (owned by request, freed on decide) */
    char *command_data;
    size_t command_len;
    rbox_parse_result_t parse;

    /* Flagged env vars  */
    int env_var_count;
    char **env_var_names;
    float *env_var_scores;
    uint32_t fenv_hash;

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

    /* Env decisions (v9) */
    uint32_t fenv_hash;
    int env_decision_count;
    char **env_decision_names;
    uint8_t *env_decisions;  /* bitmap: bit i = decision for env var i */

    struct rbox_server_decision *next;
} rbox_server_decision_t;

/* Forward declaration */
struct rbox_server_handle;
typedef struct rbox_server_handle rbox_server_handle_t;

/* Server response cache entry */
typedef struct {
    uint8_t request_id[16];       /* Request ID from client */
    uint8_t client_id[16];         /* Client ID */
    uint32_t packet_checksum;      /* Full packet checksum for once decisions */
    uint32_t cmd_hash;             /* Command hash for verification */
    uint64_t cmd_hash2;            /* Second command hash for verification */
    uint32_t fenv_hash;            /* Hash of flagged env var names */
    uint64_t fenv_hash2;           /* Second hash of flagged env vars */
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
    rbox_server_request_t *request;  /* Associated request to free after send */
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

/* rbox_response_send - uses rbox_build_response */
rbox_error_t rbox_response_send(rbox_client_t *client, const rbox_response_t *response) {
    if (!client || !response) return RBOX_ERR_INVALID;

    size_t pkt_len;
    char *pkt = rbox_build_response_internal(NULL, (uint8_t *)response->request_id, 0, response->decision,
                                   response->reason, response->duration, 0, 0, NULL, &pkt_len);
    if (!pkt) return RBOX_ERR_MEMORY;

    ssize_t n = rbox_write(rbox_client_fd(client), pkt, pkt_len);
    free(pkt);
    if (n < 0) return RBOX_ERR_IO;  /* ← FIX: return error on write failure */
    return RBOX_OK;
}

/* Public rbox_build_response - builds a response packet (for DFA fast-path)
 * This is the canonical function for building response packets */
rbox_error_t rbox_build_response(
    uint8_t decision, const char *reason, uint32_t duration,
    uint32_t fenv_hash, int env_decision_count, uint8_t *env_decisions,
    char **out_packet, size_t *out_len) {

    if (!out_packet || !out_len) return RBOX_ERR_INVALID;

    uint8_t client_id[16] = {0};
    uint8_t request_id[16] = {0};

    char *pkt = rbox_build_response_internal(client_id, request_id, 0, decision, reason, duration,
                                     fenv_hash, env_decision_count, env_decisions, out_len);
    if (!pkt) return RBOX_ERR_MEMORY;

    *out_packet = pkt;
    return RBOX_OK;
}


/* ============================================================
 * RESPONSE ENV DECISION FUNCTIONS
 * ============================================================ */

int rbox_response_env_decision_count(const rbox_response_t *resp) {
    if (!resp) return 0;
    return resp->env_decision_count;
}

char *rbox_response_env_decision_name(const rbox_response_t *resp, int index) {
    if (!resp || index < 0 || index >= resp->env_decision_count) return NULL;
    if (!resp->env_decision_names || !resp->env_decision_names[index]) return NULL;
    return strdup(resp->env_decision_names[index]);
}

int rbox_response_env_decision(const rbox_response_t *resp, int index) {
    if (!resp || index < 0 || index >= resp->env_decision_count) return -1;
    if (!resp->env_decisions) return -1;
    return resp->env_decisions[index];
}
