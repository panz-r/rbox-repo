/*
 * protocol.h - Protocol encoding and decoding for rbox-protocol
 *
 * Layer 2: Protocol encoding/decoding
 * - Header validation
 * - Checksum calculation
 * - ID generation
 */

#ifndef RBOX_PROTOCOL_LAYER_H
#define RBOX_PROTOCOL_LAYER_H

#include <stdint.h>
#include <stddef.h>

/* ============================================================
 * CHECKSUM
 * ============================================================ */

/* Initialize CRC32 table (called automatically) */
void rbox_protocol_init_crc32(void);

/* Calculate CRC32 checksum - composable, prev_crc=0 for fresh start */
uint32_t rbox_protocol_checksum_crc32(uint32_t prev_crc, const void *data, size_t len);

/* 64-bit command hash - two-step hash for time-limited decisions */
uint64_t rbox_protocol_hash64(const char *str, size_t len);

/* Server-side 64-bit hash - FNV-1a + DJB2 mix
 * Used for command hash verification (different from rbox_protocol_hash64) */
uint64_t rbox_server_hash64(const char *str, size_t len);

/* ============================================================
 * ID GENERATION
 * ============================================================ */

/* Generate a unique request ID */
void rbox_protocol_generate_request_id(uint8_t *id_out);

/* Generate a unique client ID */
void rbox_protocol_generate_client_id(uint8_t *id_out);

/* ============================================================
 * HEADER VALIDATION
 * ============================================================ */

/* Validate packet header
 * Returns: RBOX_OK if valid, error code otherwise */
int rbox_protocol_validate_header(const char *packet, size_t len);

/* ============================================================
 * LIBRARY INITIALIZATION
 * ============================================================ */

/* Initialize protocol layer (call once at startup) */
void rbox_protocol_init(void);

#endif /* RBOX_PROTOCOL_LAYER_H */