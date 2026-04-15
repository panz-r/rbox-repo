/*
 * protocol_decoding.h - Pure protocol decoding functions
 *
 * No dependencies on sockets, threads, or session state.
 * All functions operate on read-only memory buffers.
 */

#ifndef RBOX_PROTOCOL_DECODING_H
#define RBOX_PROTOCOL_DECODING_H

#include <stdint.h>
#include <stddef.h>
#include "rbox_protocol.h"

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
