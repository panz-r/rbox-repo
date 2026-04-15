/*
 * protocol_decoding.h - Pure protocol decoding functions
 *
 * No dependencies on sockets, threads, or session state.
 * All functions operate on read-only memory buffers.
 *
 * This module provides two layers:
 * 1. High-level decoding functions (rbox_decode_response_raw, etc.)
 * 2. Low-level reader helpers for endian-safe, position-based deserialization
 *
 * The reader helpers (rbox_reader_t) provide a self-documenting way to parse
 * packets. They assume the caller has already validated sufficient input length.
 * No runtime bounds checking is performed.
 */

#ifndef RBOX_PROTOCOL_DECODING_H
#define RBOX_PROTOCOL_DECODING_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>  /* for le32toh, le64toh */

#include "rbox_protocol.h"

/* ============================================================
 * READER HELPERS
 * Lightweight, non-allocating views for parsing packets.
 * Caller must ensure buffer stays alive and length is sufficient.
 * Not thread-safe - use stack-local instances only.
 * ============================================================ */

typedef struct {
    const uint8_t *buf;  /* Start of buffer (read-only) */
    size_t len;          /* Total valid length */
    size_t pos;          /* Current read position */
} rbox_reader_t;

/* Initialize a reader on a buffer */
static inline void rbox_reader_init(rbox_reader_t *r, const uint8_t *buf, size_t len) {
    r->buf = buf;
    r->len = len;
    r->pos = 0;
}

/* Skip ahead without reading (for padding/reserved fields) */
static inline void rbox_reader_skip(rbox_reader_t *r, size_t n) {
    r->pos += n;
}

/* Skip to an absolute position in the buffer */
static inline void rbox_reader_skip_to(rbox_reader_t *r, size_t offset) {
    r->pos = offset;
}

/* Read a byte (no endianness conversion needed) */
static inline uint8_t rbox_read_u8(rbox_reader_t *r) {
    uint8_t val = r->buf[r->pos];
    r->pos += 1;
    return val;
}

/* Read a 16-bit integer in little-endian byte order */
static inline uint16_t rbox_read_u16(rbox_reader_t *r) {
    uint16_t val;
    memcpy(&val, r->buf + r->pos, 2);
    r->pos += 2;
    return le16toh(val);
}

/* Read a 32-bit integer in little-endian byte order */
static inline uint32_t rbox_read_u32(rbox_reader_t *r) {
    uint32_t val;
    memcpy(&val, r->buf + r->pos, 4);
    r->pos += 4;
    return le32toh(val);
}

/* Read a 64-bit integer in little-endian byte order */
static inline uint64_t rbox_read_u64(rbox_reader_t *r) {
    uint64_t val;
    memcpy(&val, r->buf + r->pos, 8);
    r->pos += 8;
    return le64toh(val);
}

/* Read raw bytes into output buffer (no conversion) */
static inline void rbox_read_bytes(rbox_reader_t *r, void *out, size_t len) {
    memcpy(out, r->buf + r->pos, len);
    r->pos += len;
}

/* Current position */
static inline size_t rbox_reader_pos(const rbox_reader_t *r) {
    return r->pos;
}

/* Remaining bytes */
static inline size_t rbox_reader_remaining(const rbox_reader_t *r) {
    return r->len > r->pos ? r->len - r->pos : 0;
}

/* Validate header magic, version, and checksum.
 * Returns RBOX_OK if valid, error code otherwise.
 * Does not allocate memory. */
rbox_error_t rbox_validate_header(const uint8_t *packet, size_t len);

/* Internal header decoding - uint8_t version.
 * Sets header->valid = 1 if checksum valid.
 * Does not allocate memory - uses out parameter. */
void rbox_decode_header_raw(const uint8_t *packet, size_t len, rbox_decoded_header_t *out);

/* Internal response details decoding - uint8_t version.
 * Returns RBOX_OK and populates out_details (no allocation). */
rbox_error_t rbox_decode_response_details_raw(
    const uint8_t *packet,
    size_t len,
    rbox_decoded_header_t *header,
    rbox_response_details_t *out_details
);

/* Internal env decisions decoding - uint8_t version.
 * Allocates *out_bitmap; caller must free with free(). */
rbox_error_t rbox_decode_env_decisions_raw(
    const uint8_t *packet,
    size_t len,
    rbox_decoded_header_t *header,
    rbox_response_details_t *details,
    rbox_env_decisions_t *out_env_decisions
);

/* Full response validation and decoding.
 * Validates magic, version, header checksum, body checksum, and request ID match.
 * Populates out_response (including env_decisions allocation).
 * Returns RBOX_OK on success. */
rbox_error_t rbox_decode_response_raw(
    const uint8_t *packet,
    size_t len,
    const uint8_t expected_request_id[16],
    rbox_response_t *out_response
);

#endif /* RBOX_PROTOCOL_DECODING_H */
