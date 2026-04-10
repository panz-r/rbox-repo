/*
 * rbox_protocol_defs.h - ReadOnlyBox Protocol Definitions
 * 
 * Single source of truth for protocol structure.
 * Shared by both client and server implementations.
 */

#ifndef RBOX_PROTOCOL_DEFS_H
#define RBOX_PROTOCOL_DEFS_H

#include <stdint.h>
#include <stddef.h>

/* ============================================================
 * MAGIC & VERSION
 * ============================================================ */

#define RBOX_MAGIC       0x524F424F  /* "ROBO" */
#define RBOX_VERSION     9  /* Protocol version with separate header/body checksums */

/* ============================================================
 * MESSAGE TYPES
 * ============================================================ */

#define RBOX_MSG_LOG     0   /* Log message from client */
#define RBOX_MSG_REQ     1   /* Command request from client (or first chunk) */
#define RBOX_MSG_CHUNK   2   /* Subsequent chunk */
#define RBOX_MSG_COMPLETE 3  /* All chunks received */
#define RBOX_MSG_ABORT   4   /* Client aborted */

/* ============================================================
 * CALLER/SYSCALL LIMITS (max 15 chars each, stored in 4 bits)
 * ============================================================ */

#define RBOX_MAX_CALLER_LEN  15
#define RBOX_MAX_SYSCALL_LEN 15

/* ============================================================
 * CHUNK FLAGS
 * ============================================================ */

#define RBOX_FLAG_FIRST      0x01  /* First chunk of stream */
#define RBOX_FLAG_LAST       0x02  /* Last chunk of stream */
#define RBOX_FLAG_CONTINUE  0x04  /* Continuation chunk */

/* ============================================================
 * CHUNK LIMITS
 * ============================================================ */

#define RBOX_CHUNK_SIZE      32768  /* 32KB default chunk size */
#define RBOX_CHUNK_MAX       65536  /* 64KB max chunk size */
#define RBOX_STREAM_TIMEOUT  30     /* Stream timeout in seconds */
#define RBOX_MAX_TOTAL_SIZE  (1024 * 1024)  /* 1MB max total */

/* ============================================================
 * ACK STATUS CODES
 * ============================================================ */

#define RBOX_ACK_OK       0   /* Chunk received OK */
#define RBOX_ACK_ERROR   -1  /* Error receiving chunk */
#define RBOX_ACK_COMPLETE 1  /* All chunks received */

/* ============================================================
 * DECISION CODES
 * ============================================================ */

#define RBOX_DECISION_UNKNOWN  0
#define RBOX_DECISION_ALLOW    2
#define RBOX_DECISION_DENY     3
#define RBOX_DECISION_ERROR    4

/* ============================================================
 * SOCKET PATH
 * ============================================================ */

#define RBOX_DEFAULT_SOCKET  "/run/readonlybox/readonlybox.sock"

/* ============================================================
 * RETRY DELAY LIMITS
 * ============================================================ */

#define RBOX_MAX_RETRY_DELAY_MS 900000  /* 15 minutes in milliseconds */

/* ============================================================
 * HEADER STRUCTURE (127 bytes total)
 * All fields are little-endian
 * ============================================================ */

/*
 * Header layout with byte offsets:
 * 
 * Offset  Size  Field
 * ------  ----  -----
 *   0      4    magic
 *   4      4    version
 *   8     16    client_id (session identifier for resume)
 *  24     16    request_id (stream identifier for resume)
 *  40     16    server_id
 *  56      4    type (message type)
 *  60      4    flags (FIRST/LAST/CONTINUE)
 *  64      8    offset (byte offset in total stream)
 *  72      4    chunk_len (length of this chunk's data)
 *  76      8    total_len (total expected length of all chunks)
 *  84      4    cmd_hash (hash of command for verification)
 *  88      4    fenv_hash (hash of flagged env vars)
 *  92      1    caller_syscall_size
 *  93     15    caller name
 * 108     15    syscall name
 * 119      4    header_checksum (CRC32 of header bytes 0-118)
 * 123      4    body_checksum (CRC32 of body)
 * 127           (end of header)
 */

#define RBOX_HEADER_OFFSET_MAGIC           0
#define RBOX_HEADER_OFFSET_VERSION        4
#define RBOX_HEADER_OFFSET_CLIENT_ID      8
#define RBOX_HEADER_OFFSET_REQUEST_ID    24
#define RBOX_HEADER_OFFSET_SERVER_ID    40
#define RBOX_HEADER_OFFSET_TYPE         56
#define RBOX_HEADER_OFFSET_FLAGS         60
#define RBOX_HEADER_OFFSET_OFFSET        64
#define RBOX_HEADER_OFFSET_CHUNK_LEN     72
#define RBOX_HEADER_OFFSET_TOTAL_LEN     76
#define RBOX_HEADER_OFFSET_CMD_HASH      84
#define RBOX_HEADER_OFFSET_FENV_HASH     88
#define RBOX_HEADER_OFFSET_CALLER_SYSCALL_SIZE 92
#define RBOX_HEADER_OFFSET_CALLER        93
#define RBOX_HEADER_OFFSET_SYSCALL      108
#define RBOX_HEADER_OFFSET_CHECKSUM    119
#define RBOX_HEADER_OFFSET_BODY_CHECKSUM 123
#define RBOX_HEADER_SIZE                127

/* Backward compatibility aliases (v4 protocol used these fields) */
#define RBOX_HEADER_OFFSET_ARGC       RBOX_HEADER_OFFSET_FLAGS  /* Reuse flags offset for argc */
#define RBOX_HEADER_OFFSET_ENVC       RBOX_HEADER_OFFSET_OFFSET /* Reuse offset for envc */

/* ============================================================
 * ACK RESPONSE STRUCTURE
 * ============================================================ */

/*
 * ACK layout:
 * 
 * Offset  Size  Field
 * ------  ----  -----
 *   0      4    magic
 *   4     16    server_id
 *  20     16    client_id
 *  36     16    request_id
 *  52      8    offset (bytes received so far)
 *  60      4    status (ACK_OK, ACK_ERROR, ACK_COMPLETE)
 *  64      4    reason_len
 *  68      n    reason (null-terminated)
 */

#define RBOX_ACK_OFFSET_MAGIC       0
#define RBOX_ACK_OFFSET_SERVER_ID   4
#define RBOX_ACK_OFFSET_CLIENT_ID   20
#define RBOX_ACK_OFFSET_REQUEST_ID  36
#define RBOX_ACK_OFFSET_OFFSET      52
#define RBOX_ACK_OFFSET_STATUS      60
#define RBOX_ACK_OFFSET_REASON_LEN 64
#define RBOX_ACK_OFFSET_REASON     68

#define RBOX_ACK_SIZE               68

/* Legacy response (for compatibility) */
#define RBOX_RESPONSE_OFFSET_MAGIC       0
#define RBOX_RESPONSE_OFFSET_SERVER_ID    4
#define RBOX_RESPONSE_OFFSET_REQUEST_ID  20
#define RBOX_RESPONSE_OFFSET_DECISION    24
#define RBOX_RESPONSE_OFFSET_REASON_LEN 25
#define RBOX_RESPONSE_OFFSET_REASON      29

/* Response packet (sent by server)
 * 
 * Offset  Size  Field
 * ------  ----  -----
 *   0      4    magic
 *   4     16    server_id
 *  20     16    request_id (MUST match client's request_id)
 *  36      1    decision (ALLOW/DENY/ERROR)
 *  37      4    reason_len
 *  41     n    reason (null-terminated string)
 *  --     --
 *  41+          (minimum size)
 */

#define RBOX_RESPONSE_OFFSET_MAGIC_V2    0
#define RBOX_RESPONSE_OFFSET_SERVER_ID_V2 4
#define RBOX_RESPONSE_OFFSET_REQUEST_ID_V2 20
#define RBOX_RESPONSE_OFFSET_DECISION_V2 36
#define RBOX_RESPONSE_OFFSET_REASON_LEN_V2 37
#define RBOX_RESPONSE_OFFSET_REASON_V2    41

#define RBOX_RESPONSE_MIN_SIZE          41
#define RBOX_RESPONSE_MAX_REASON         256

#define RBOX_RESPONSE_HEADER_SIZE        29

/* ============================================================
 * STRUCTURES (for convenience)
 * ============================================================ */

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t version;
    uint8_t  client_id[16];
    uint8_t  request_id[16];
    uint8_t  server_id[16];
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint32_t chunk_len;
    uint64_t total_len;
    uint32_t cmd_hash;
    uint32_t fenv_hash;                    /* Hash of flagged env vars */
    uint8_t  caller_syscall_size;          /* bits 0-3: caller_len, bits 4-7: syscall_len */
    uint8_t  caller[15];                   /* caller name, truncated to 15 chars */
    uint8_t  syscall[15];                  /* syscall name, truncated to 15 chars */
    uint32_t checksum;                     /* Header checksum */
    uint32_t body_checksum;                /* Body checksum */
} rbox_header_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t  server_id[16];
    uint8_t  client_id[16];
    uint8_t  request_id[16];
    uint64_t offset;
    int32_t  status;
    uint32_t reason_len;
} rbox_ack_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t  server_id[16];
    uint32_t request_id;
    uint8_t  decision;
    uint32_t reason_len;
} rbox_response_header_t;

#endif /* RBOX_PROTOCOL_DEFS_H */
