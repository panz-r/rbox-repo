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

/* Two-step 64-bit hash for time-limited decisions */
uint64_t rbox_protocol_hash64(const char *str, size_t len);

/* FNV-1a + DJB2 mix for server-side command hash verification */
uint64_t rbox_server_hash64(const char *str, size_t len);

/* ============================================================
 * ID GENERATION
 * ============================================================ */

/* Generate a unique request ID */
void rbox_protocol_generate_request_id(uint8_t *id_out);

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