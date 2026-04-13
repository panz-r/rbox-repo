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

/* ============================================================
 * ID GENERATION
 * ============================================================ */

/* Generate a unique request ID */
void rbox_protocol_generate_request_id(uint8_t *id_out);

/* ============================================================
 * LIBRARY INITIALIZATION
 * ============================================================ */

/* Initialize protocol layer (call once at startup) */
void rbox_protocol_init(void);

#endif /* RBOX_PROTOCOL_LAYER_H */