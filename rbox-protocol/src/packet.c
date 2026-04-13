/*
 * packet.c - Packet parsing and building for rbox-protocol
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
#include "protocol.h"
#include "runtime.h"
#include "session_internal.h"
#include "server_response.h"

/* Debug flag – set to 1 to enable client tracing */
#ifndef RBOX_CLIENT_DEBUG
#define RBOX_CLIENT_DEBUG 0
#endif

#if RBOX_CLIENT_DEBUG
#define CDBG(fmt, ...) fprintf(stderr, "[CLIENT] " fmt "\n", ##__VA_ARGS__)
#else
#define CDBG(fmt, ...) ((void)0)
#endif

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

/* ============================================================
 * CHECKSUM
 * ============================================================ */

/* Forward declarations for ID generation functions */
static void generate_request_id(uint8_t *id_out);
static void generate_client_id(uint8_t *id_out);
static void init_client_id_once(void);

/* Static client_id - generated once per process */
static uint8_t g_client_id[16] = {0};
static pthread_once_t g_client_id_once = PTHREAD_ONCE_INIT;

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
    if (!packet || len < RBOX_HEADER_SIZE) return RBOX_ERR_TRUNCATED;

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
    uint32_t calc_checksum = rbox_runtime_crc32(0, packet, RBOX_HEADER_OFFSET_CHECKSUM);

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

/* ============================================================
 * RESPONSE SENDING
 * ============================================================ */

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
       Each env var: name + null + 4 bytes score. Use checked arithmetic to prevent overflow. */
    size_t needed = RBOX_HEADER_SIZE;
    size_t addend = strlen(command) + 1;
    if (__builtin_add_overflow(needed, addend, &needed)) return RBOX_ERR_INVALID;
    if (caller) {
        addend = strlen(caller) + 1;
        if (__builtin_add_overflow(needed, addend, &needed)) return RBOX_ERR_INVALID;
    } else {
        if (__builtin_add_overflow(needed, 1, &needed)) return RBOX_ERR_INVALID;
    }
    if (syscall) {
        addend = strlen(syscall) + 1;
        if (__builtin_add_overflow(needed, addend, &needed)) return RBOX_ERR_INVALID;
    } else {
        if (__builtin_add_overflow(needed, 1, &needed)) return RBOX_ERR_INVALID;
    }
    for (int i = 0; i < argc; i++) {
        if (argv[i]) {
            addend = strlen(argv[i]) + 1;
            if (__builtin_add_overflow(needed, addend, &needed)) return RBOX_ERR_INVALID;
        }
    }
    if (__builtin_add_overflow(needed, 1, &needed)) return RBOX_ERR_INVALID;
    for (int i = 0; i < env_var_count; i++) {
        if (env_var_names[i]) {
            addend = strlen(env_var_names[i]) + 1 + 4;
            if (__builtin_add_overflow(needed, addend, &needed)) return RBOX_ERR_INVALID;
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
    uint32_t checksum = rbox_runtime_crc32(0, packet, RBOX_HEADER_OFFSET_CHECKSUM);
    memcpy(packet + RBOX_HEADER_OFFSET_CHECKSUM, &checksum, 4);

    /* Calculate body checksum (bytes from RBOX_HEADER_SIZE onward) */
    uint32_t body_checksum = rbox_runtime_crc32(0, packet + RBOX_HEADER_SIZE, body_len);
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
rbox_error_t validate_response(const char *packet, size_t len,
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

        uint32_t chunk_len = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_CHUNK_LEN);
        if (len < RBOX_HEADER_SIZE + chunk_len) {
            return RBOX_ERR_TRUNCATED;
        }

        decision = packet[RBOX_HEADER_SIZE];  /* decision at offset 92 */
        reason_offset = RBOX_HEADER_SIZE + 1;  /* reason starts after decision byte */
        /* Parse reason string to find actual length (null-terminated) */
        reason_len = 0;
        size_t scan_offset = RBOX_HEADER_SIZE + 1;
        while (scan_offset < len && reason_len < RBOX_RESPONSE_MAX_REASON) {
            if (packet[scan_offset] == '\0') break;
            reason_len++;
            scan_offset++;
        }
        request_id_offset = RBOX_HEADER_OFFSET_REQUEST_ID;

        /* Calculate expected total size */
        size_t expected_len = RBOX_HEADER_SIZE + 1 + reason_len + 1;  /* decision + reason + null */
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

    /* Validate body checksum if body exists */
    if (len > RBOX_HEADER_SIZE) {
        uint32_t stored_body_checksum = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_BODY_CHECKSUM);
        uint32_t computed_body_checksum = rbox_runtime_crc32(0, packet + RBOX_HEADER_SIZE, len - RBOX_HEADER_SIZE);
        if (stored_body_checksum != computed_body_checksum) {
            return RBOX_ERR_CHECKSUM;
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

    /* Decode env decisions from response body (after reason)
     * Body format: decision(1) + reason(reason_len) + \0 + fenv_hash(4) + env_count(2) + bitmap
     * In v9, decision is at RBOX_HEADER_SIZE, so env_count is at RBOX_HEADER_SIZE + 1 + reason_len + 1 + 4 = RBOX_HEADER_SIZE + reason_len + 6 */
    if (version == RBOX_VERSION) {
        size_t env_offset = RBOX_HEADER_SIZE + 1 + reason_len + 1 + 4;
        if (len >= env_offset + 2) {
            uint16_t resp_env_count = *(uint16_t *)(packet + env_offset);
            if (resp_env_count > 0 && resp_env_count <= 256) {
                size_t bitmap_size = (resp_env_count + 7) / 8;
                if (len >= env_offset + 2 + bitmap_size) {
                    out_response->env_decision_count = resp_env_count;
                    out_response->env_decisions = malloc(bitmap_size);
                    if (out_response->env_decisions) {
                        memcpy(out_response->env_decisions, packet + env_offset + 2, bitmap_size);
                    }
                }
            }
        }
    }
    /* v2 format does not include env decisions */

    return RBOX_OK;
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
    uint32_t hdr_crc = rbox_runtime_crc32(0, packet, RBOX_HEADER_OFFSET_CHECKSUM);
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

    /* Calculate total response size and validate against buffer capacity */
    size_t expected_len = RBOX_HEADER_SIZE + body_len;
    if (expected_len > max_len) {
        return -1;
    }

    /* Copy header to buffer */
    memcpy(buf, header, RBOX_HEADER_SIZE);

    /* Read remaining body */
    if (expected_len > RBOX_HEADER_SIZE) {
        size_t remaining = expected_len - RBOX_HEADER_SIZE;
        n = rbox_read(fd, buf + RBOX_HEADER_SIZE, remaining);
        if (n < 0) {
            return -1;
        }
        if ((size_t)n < remaining) {
            return -1;
        }
    }

    return (ssize_t)expected_len;
}

rbox_error_t rbox_client_send_request(rbox_client_t *client,
    const char *command, const char *caller, const char *syscall, int argc, const char **argv,
    int env_var_count, const char **env_var_names, const float *env_var_scores,
    rbox_response_t *response) {
    if (!client || !command || !response) {
        return RBOX_ERR_INVALID;
    }

    /* Build request packet using canonical layered function.
     * Use 64KB stack buffer first; fall back to heap if request is larger. */
    char stack_buf[65536];
    char *packet = stack_buf;
    size_t packet_len;
    rbox_error_t err = rbox_build_request(packet, sizeof(stack_buf), &packet_len, command, caller, syscall, argc, argv, env_var_count, env_var_names, env_var_scores);
    if (err != RBOX_OK) {
        /* If buffer was too small, allocate dynamically and retry.
         * rbox_build_request returns RBOX_ERR_INVALID when capacity is insufficient.
         * We need to allocate based on the estimated size - the function populates
         * out_len with the actual size needed even on failure. */
        if (err == RBOX_ERR_INVALID && packet_len > sizeof(stack_buf)) {
            packet = malloc(packet_len);
            if (!packet) return RBOX_ERR_MEMORY;
            err = rbox_build_request(packet, packet_len, &packet_len, command, caller, syscall, argc, argv, env_var_count, env_var_names, env_var_scores);
            if (err != RBOX_OK) {
                free(packet);
                return err;
            }
        } else {
            return err;
        }
    }

    /* Extract the actual request ID from the packet (the one that will be sent) */
    uint8_t request_id[16];
    memcpy(request_id, packet + RBOX_HEADER_OFFSET_REQUEST_ID, 16);

    /* Send request */
    ssize_t sent = rbox_write(rbox_client_fd(client), packet, packet_len);
    if (sent != (ssize_t)packet_len) {
        if (packet != stack_buf) free(packet);
        return RBOX_ERR_IO;
    }

    /* Read response - use 64KB stack buffer with malloc fallback */
    char resp_buf[65536];
    char *response_buf = resp_buf;
    size_t resp_capacity = sizeof(resp_buf);
    char *dyn_buf = NULL;

    ssize_t resp_len = read_response(rbox_client_fd(client), response_buf, resp_capacity);
    if (resp_len <= 0) {
        if (dyn_buf) free(dyn_buf);
        if (packet != stack_buf) free(packet);
        return RBOX_ERR_IO;
    }

    /* If response was truncated at buffer size, realloc and read remainder */
    if (resp_len == (ssize_t)resp_capacity && response_buf == resp_buf) {
        dyn_buf = malloc(resp_capacity * 2);
        if (dyn_buf) {
            memcpy(dyn_buf, resp_buf, resp_len);
            response_buf = dyn_buf;
            resp_capacity *= 2;
            ssize_t more_len = read_response(rbox_client_fd(client), 
                                              response_buf + resp_len, 
                                              resp_capacity - resp_len);
            if (more_len > 0) resp_len += more_len;
        }
    }

    /* Validate response with the extracted request_id */
    err = validate_response(response_buf, resp_len, request_id, response);
    if (err != RBOX_OK) {
        response->decision = RBOX_DECISION_UNKNOWN;
    }

    if (dyn_buf) free(dyn_buf);
    if (packet != stack_buf) free(packet);
    return err;
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

    memset(out_response, 0, sizeof(*out_response));

    char *packet = NULL;
    size_t packet_len = 0;

    rbox_error_t err = rbox_blocking_request_raw(socket_path, command, argc, argv,
        caller, syscall,
        env_var_count, env_var_names, env_var_scores,
        &packet, &packet_len, base_delay_ms, max_retries);

    if (err != RBOX_OK || !packet || packet_len == 0) {
        return err ? err : RBOX_ERR_IO;
    }

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

    out_response->decision = details.decision;
    strncpy(out_response->reason, details.reason, sizeof(out_response->reason) - 2);
    out_response->reason[sizeof(out_response->reason) - 1] = '\0';
    out_response->duration = 0;
    memcpy(out_response->request_id, header.request_id, 16);

    /* Decode env decisions if present */
    rbox_env_decisions_t env_decisions;
    memset(&env_decisions, 0, sizeof(env_decisions));
    rbox_decode_env_decisions(&header, &details, packet, packet_len, &env_decisions);
    if (env_decisions.valid && env_decisions.env_count > 0 && env_decisions.bitmap) {
        out_response->env_decision_count = env_decisions.env_count;
        out_response->env_decisions = env_decisions.bitmap;  /* takes ownership */
    }

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

    uint32_t attempt = 0;

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

        uint8_t request_id[16];
        memcpy(request_id, packet + RBOX_HEADER_OFFSET_REQUEST_ID, 16);

        rbox_session_t *session = rbox_session_new(socket_path, base_delay_ms, max_retries);
        if (!session) {
            free(packet);
            return RBOX_ERR_MEMORY;
        }

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
                    if (fd >= 0) {
                        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
                        int ret = poll(&pfd, 1, 10);
                        if (ret > 0) {
                            rbox_session_heartbeat(session, POLLOUT);
                        } else if (ret == 0) {
                            rbox_session_heartbeat(session, 0);
                        } else if (ret < 0 && errno != EINTR) {
                            rbox_session_heartbeat(session, POLLERR);
                        }
                    } else {
                        /* No client fd (retry wait period) – drive the
                         * time-based retry logic by calling heartbeat
                         * with no events, then sleep briefly to avoid
                         * busy-looping. */
                        rbox_session_heartbeat(session, 0);
                        usleep(10000);
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
                    short events;
                    int fd = rbox_session_pollfd(session, &events);
                    if (fd >= 0) {
                        struct pollfd pfd = { .fd = fd, .events = events };
                        int ret = poll(&pfd, 1, 100);
                        if (ret > 0) {
                            rbox_session_heartbeat(session, pfd.revents);
                        } else if (ret == 0) {
                            rbox_session_heartbeat(session, 0);
                        } else if (ret < 0 && errno != EINTR) {
                            rbox_session_heartbeat(session, POLLERR);
                        }
                    } else {
                        usleep(10000);
                    }
                    break;
                }

                case RBOX_SESSION_FAILED: {
                    /* Session failed – break out to retry outer loop */
                    goto session_failed;
                }
            }

            if (rbox_session_state(session) == RBOX_SESSION_RESPONSE_READY) {
                *out_packet = (char *)session->response_data;
                *out_packet_len = session->response_len;
                session->response_data = NULL;
                session->response_len = 0;
                rbox_session_free(session);
                free(packet);
                return RBOX_OK;
            }
        }

session_failed:
        rbox_session_free(session);
        free(packet);
        attempt++;
        if (max_retries > 0 && attempt >= max_retries) {
            break;
        }
        if (base_delay_ms > 0) {
            usleep(base_delay_ms * 1000 * attempt);
        }
    }

    return RBOX_ERR_IO;
}


/* rbox_response_send - uses rbox_build_response */
rbox_error_t rbox_response_send(rbox_client_t *client, const rbox_response_t *response) {
    if (!client || !response) return RBOX_ERR_INVALID;

    size_t pkt_len;
    char *pkt = rbox_server_build_response(NULL, (uint8_t *)response->request_id, 0, response->decision,
                                   response->reason, 0, 0, NULL, &pkt_len);
    if (!pkt) return RBOX_ERR_MEMORY;

    ssize_t n = rbox_write(rbox_client_fd(client), pkt, pkt_len);
    free(pkt);
    if (n < 0) return RBOX_ERR_IO;
    return RBOX_OK;
}

/* Public rbox_build_response - builds a response packet (for DFA fast-path)
 * This is the canonical function for building response packets */
rbox_error_t rbox_build_response(
    uint8_t decision, const char *reason,
    uint32_t fenv_hash, int env_decision_count, uint8_t *env_decisions,
    char **out_packet, size_t *out_len) {

    if (!out_packet || !out_len) return RBOX_ERR_INVALID;

    uint8_t client_id[16] = {0};
    uint8_t request_id[16] = {0};

    char *pkt = rbox_server_build_response(client_id, request_id, 0, decision, reason,
                                     fenv_hash, env_decision_count, env_decisions, out_len);
    if (!pkt) return RBOX_ERR_MEMORY;

    *out_packet = pkt;
    return RBOX_OK;
}

char *rbox_build_response_internal(uint8_t *client_id, uint8_t *request_id, uint32_t cmd_hash,
                           uint8_t decision, const char *reason,
                           uint32_t fenv_hash, int env_decision_count, uint8_t *env_decisions,
                           size_t *out_len) {
    return rbox_server_build_response(client_id, request_id, cmd_hash, decision, reason,
                                     fenv_hash, env_decision_count, env_decisions, out_len);
}


/* ============================================================
 * RESPONSE ENV DECISION FUNCTIONS
 * ============================================================ */

int rbox_response_env_decision_count(const rbox_response_t *resp) {
    if (!resp) return 0;
    return resp->env_decision_count;
}

int rbox_response_env_decision(const rbox_response_t *resp, int index) {
    if (!resp || index < 0 || index >= resp->env_decision_count) return -1;
    if (!resp->env_decisions) return -1;
    return (resp->env_decisions[index / 8] >> (index % 8)) & 1;
}

//export rbox_response_free
void rbox_response_free(rbox_response_t *resp) {
    if (!resp) return;
    free(resp->env_decisions);
    resp->env_decisions = NULL;
    resp->env_decision_count = 0;
}

/* Telemetry stats query - connects to server and requests stats */
rbox_error_t rbox_telemetry_get_stats(
    const char *socket_path,
    uint32_t *out_allow,
    uint32_t *out_deny) {

    if (!socket_path || !out_allow || !out_deny) {
        return RBOX_ERR_INVALID;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return RBOX_ERR_IO;

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return RBOX_ERR_IO;
    }

    uint8_t header[RBOX_HEADER_SIZE] = {0};
    *(uint32_t *)(header + 0) = RBOX_MAGIC;
    *(uint32_t *)(header + 4) = RBOX_VERSION;
    *(uint32_t *)(header + 56) = RBOX_MSG_TELEMETRY;

    uint32_t checksum = rbox_runtime_crc32(0, header, RBOX_HEADER_OFFSET_CHECKSUM);
    *(uint32_t *)(header + RBOX_HEADER_OFFSET_CHECKSUM) = checksum;
    *(uint32_t *)(header + RBOX_HEADER_OFFSET_BODY_CHECKSUM) = 0;

    if (write(fd, header, RBOX_HEADER_SIZE) != RBOX_HEADER_SIZE) {
        close(fd);
        return RBOX_ERR_IO;
    }

    uint8_t resp_header[RBOX_HEADER_SIZE];
    ssize_t n = rbox_read(fd, resp_header, RBOX_HEADER_SIZE);
    if (n != RBOX_HEADER_SIZE) {
        close(fd);
        return RBOX_ERR_IO;
    }

    uint32_t resp_magic = *(uint32_t *)resp_header;
    if (resp_magic != RBOX_MAGIC) {
        close(fd);
        return RBOX_ERR_IO;
    }

    rbox_error_t hdr_err = rbox_header_validate((char *)resp_header, RBOX_HEADER_SIZE);
    if (hdr_err != RBOX_OK) {
        close(fd);
        return RBOX_ERR_IO;
    }

    uint32_t resp_chunk_len = *(uint32_t *)(resp_header + RBOX_HEADER_OFFSET_CHUNK_LEN);
    if (resp_chunk_len > 4096) {
        close(fd);
        return RBOX_ERR_IO;
    }

    size_t total_resp_len = RBOX_HEADER_SIZE + resp_chunk_len;
    char *resp_body = malloc(total_resp_len);
    if (!resp_body) {
        close(fd);
        return RBOX_ERR_MEMORY;
    }
    memcpy(resp_body, resp_header, RBOX_HEADER_SIZE);

    size_t remaining = resp_chunk_len;
    size_t pos = RBOX_HEADER_SIZE;
    while (remaining > 0) {
        n = rbox_read(fd, resp_body + pos, remaining);
        if (n <= 0) {
            free(resp_body);
            close(fd);
            return RBOX_ERR_IO;
        }
        pos += n;
        remaining -= n;
    }

    uint32_t stored_checksum = *(uint32_t *)(resp_body + RBOX_HEADER_OFFSET_BODY_CHECKSUM);
    uint32_t computed_checksum = rbox_runtime_crc32(0, resp_body + RBOX_HEADER_SIZE, resp_chunk_len);
    if (stored_checksum != computed_checksum) {
        free(resp_body);
        close(fd);
        return RBOX_ERR_IO;
    }

    uint32_t reason_len = resp_chunk_len - 1;
    if (reason_len > 1024) reason_len = 1024;

    char reason[1025];
    size_t copy_len = reason_len < sizeof(reason) - 1 ? reason_len : sizeof(reason) - 1;
    memcpy(reason, resp_body + RBOX_HEADER_SIZE + 1, copy_len);
    reason[copy_len] = '\0';

    free(resp_body);
    close(fd);

    uint32_t allow = 0, deny = 0;
    sscanf(reason, "ALLOW:%u DENY:%u", &allow, &deny);

    *out_allow = allow;
    *out_deny = deny;

    return RBOX_OK;
}