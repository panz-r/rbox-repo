/*
 * protocol_encoding.h - Pure protocol encoding functions
 *
 * No dependencies on sockets, threads, or session state.
 * All functions operate on caller-provided memory buffers.
 *
 * This module provides two layers:
 * 1. High-level encoding functions (rbox_encode_request, rbox_encode_response)
 * 2. Low-level writer helpers for endian-safe, position-based serialization
 *
 * The writer helpers (rbox_writer_t) provide a self-documenting way to build
 * packets. They assume the caller has already ensured sufficient buffer capacity.
 * No runtime bounds checking is performed.
 */

#ifndef RBOX_PROTOCOL_ENCODING_H
#define RBOX_PROTOCOL_ENCODING_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>  /* for htole32, htole64 */

#include "rbox_protocol_defs.h"
#include "rbox_protocol.h"  /* for rbox_error_t */

/* ============================================================
 * WRITER HELPERS
 * Lightweight, non-allocating views for building packets.
 * Caller must ensure buffer stays alive and capacity is sufficient.
 * Not thread-safe - use stack-local instances only.
 * ============================================================ */

typedef struct {
    uint8_t *buf;   /* Start of buffer (writable) */
    size_t cap;     /* Total capacity */
    size_t pos;     /* Current write position */
} rbox_writer_t;

/* Initialize a writer on a buffer */
static inline void rbox_writer_init(rbox_writer_t *w, uint8_t *buf, size_t cap) {
    w->buf = buf;
    w->cap = cap;
    w->pos = 0;
}

/* Skip ahead without writing (for reserved fields) */
static inline void rbox_writer_skip(rbox_writer_t *w, size_t n) {
    w->pos += n;
}

/* Skip to an absolute position in the buffer */
static inline void rbox_writer_skip_to(rbox_writer_t *w, size_t offset) {
    w->pos = offset;
}

/* Write a byte (no endianness conversion needed) */
static inline void rbox_write_u8(rbox_writer_t *w, uint8_t val) {
    w->buf[w->pos] = val;
    w->pos += 1;
}

/* Write a 16-bit integer in little-endian byte order */
static inline void rbox_write_u16(rbox_writer_t *w, uint16_t val) {
    uint16_t le = htole16(val);
    memcpy(w->buf + w->pos, &le, 2);
    w->pos += 2;
}

/* Write a 32-bit integer in little-endian byte order */
static inline void rbox_write_u32(rbox_writer_t *w, uint32_t val) {
    uint32_t le = htole32(val);
    memcpy(w->buf + w->pos, &le, 4);
    w->pos += 4;
}

/* Write a 64-bit integer in little-endian byte order */
static inline void rbox_write_u64(rbox_writer_t *w, uint64_t val) {
    uint64_t le = htole64(val);
    memcpy(w->buf + w->pos, &le, 8);
    w->pos += 8;
}

/* Write raw bytes (no conversion) */
static inline void rbox_write_bytes(rbox_writer_t *w, const void *data, size_t len) {
    memcpy(w->buf + w->pos, data, len);
    w->pos += len;
}

/* Current position (useful for computing lengths) */
static inline size_t rbox_writer_pos(const rbox_writer_t *w) {
    return w->pos;
}

/* Generate a unique request ID (fills 16 bytes).
 * Thread-safe using thread-local seed. */
void rbox_generate_request_id(uint8_t id_out[16]);

/* Return the persistent client ID (16 bytes).
 * Generated once per process, thread-safe via pthread_once.
 * Returns pointer to internal static storage - do not free. */
const uint8_t *rbox_get_client_id(void);

/* 64-bit hash for command strings (used in cache).
 * Deterministic, two-step hash combining FNV-1a and DJB2. */
uint64_t rbox_hash64(const char *str, size_t len);

/* Build a request packet into a caller-provided buffer.
 * Format: header (RBOX_HEADER_SIZE bytes) + body
 *
 * Returns RBOX_OK and sets *out_len on success.
 * If buffer too small, returns RBOX_ERR_INVALID and sets *out_len to required size.
 *
 * Parameters:
 *   - command: the command to execute (required)
 *   - caller: optional caller identifier (e.g., "judge", "run")
 *   - syscall: optional syscall being queried (e.g., "execve")
 *   - argc: number of arguments
 *   - argv: argument array
 *   - env_var_count: number of environment variables
 *   - env_var_names: array of env var names
 *   - env_var_scores: array of env var scores (may be NULL)
 *   - out_buf: output buffer (must be at least RBOX_HEADER_SIZE)
 *   - buf_capacity: size of output buffer
 *   - out_len: (out) actual packet length written
 */
rbox_error_t rbox_encode_request(
    const char *command,
    const char *caller,
    const char *syscall,
    int argc,
    const char **argv,
    int env_var_count,
    const char **env_var_names,
    const float *env_var_scores,
    uint8_t *out_buf,
    size_t buf_capacity,
    size_t *out_len
);

/* Build a response packet into a caller-provided buffer.
 * Uses the provided client_id and request_id (can be NULL to use zeros).
 *
 * Returns RBOX_OK and sets *out_len on success.
 * If buffer too small, returns RBOX_ERR_INVALID and sets *out_len to required size.
 *
 * Parameters:
 *   - client_id: 16 bytes, may be NULL
 *   - request_id: 16 bytes, may be NULL
 *   - cmd_hash: command hash for the request
 *   - decision: RBOX_DECISION_ALLOW or RBOX_DECISION_DENY
 *   - reason: null-terminated reason string (may be NULL)
 *   - fenv_hash: environment hash
 *   - env_decision_count: number of env decisions
 *   - env_decisions: bitmap of env decisions (may be NULL)
 *   - out_buf: output buffer (must be at least RBOX_HEADER_SIZE)
 *   - buf_capacity: size of output buffer
 *   - out_len: (out) actual packet length written
 */
rbox_error_t rbox_encode_response(
    const uint8_t *client_id,
    const uint8_t *request_id,
    uint32_t cmd_hash,
    uint8_t decision,
    const char *reason,
    uint32_t fenv_hash,
    int env_decision_count,
    const uint8_t *env_decisions,
    uint8_t *out_buf,
    size_t buf_capacity,
    size_t *out_len
);

/* Build a telemetry response packet.
 * Contains allow/deny counts in the reason field.
 *
 * Returns allocated packet (caller must free with free()).
 * Sets *out_len to packet length.
 */
char *rbox_encode_telemetry_response(
    const uint8_t *client_id,
    const uint8_t *request_id,
    uint32_t allow_count,
    uint32_t deny_count,
    size_t *out_len
);

#endif /* RBOX_PROTOCOL_ENCODING_H */
