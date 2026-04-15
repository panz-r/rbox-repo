/*
 * protocol_decoding.c - Pure protocol decoding functions
 *
 * No dependencies on sockets, threads, or session state.
 */

#include <stdlib.h>
#include <string.h>

#include "protocol_decoding.h"
#include "runtime.h"

/* ============================================================
 * HEADER VALIDATION
 * ============================================================ */

rbox_error_t rbox_validate_header(const uint8_t *packet, size_t len) {
    if (!packet || len < RBOX_HEADER_SIZE) return RBOX_ERR_TRUNCATED;

    /* Use reader helpers for endian-safe parsing */
    rbox_reader_t r;
    rbox_reader_init(&r, packet, RBOX_HEADER_SIZE);

    uint32_t magic = rbox_read_u32(&r);
    if (magic != RBOX_MAGIC) {
        return RBOX_ERR_MAGIC;
    }

    uint32_t version = rbox_read_u32(&r);
    if (version != RBOX_VERSION) {
        return RBOX_ERR_VERSION;
    }

    rbox_reader_skip_to(&r, RBOX_HEADER_OFFSET_CHUNK_LEN);

    uint32_t chunk_len = rbox_read_u32(&r);
    if (chunk_len > RBOX_CHUNK_MAX) {
        return RBOX_ERR_INVALID;
    }

    rbox_reader_skip_to(&r, RBOX_HEADER_OFFSET_CHECKSUM);

    uint32_t stored_checksum = rbox_read_u32(&r);
    uint32_t calc_checksum = rbox_runtime_crc32(0, packet, RBOX_HEADER_OFFSET_CHECKSUM);

    if (stored_checksum != calc_checksum) {
        return RBOX_ERR_CHECKSUM;
    }

    return RBOX_OK;
}

/* ============================================================
 * HEADER DECODING
 * ============================================================ */

void rbox_decode_header_raw(const uint8_t *packet, size_t len, rbox_decoded_header_t *header) {
    if (!packet || !header) return;
    memset(header, 0, sizeof(*header));
    if (len < RBOX_HEADER_SIZE) return;

    /* Use reader helpers for endian-safe, position-based parsing */
    rbox_reader_t r;
    rbox_reader_init(&r, packet, RBOX_HEADER_SIZE);

    header->magic = rbox_read_u32(&r);
    if (header->magic != RBOX_MAGIC) return;
    header->version = rbox_read_u32(&r);
    if (header->version != RBOX_VERSION) return;

    rbox_read_bytes(&r, header->client_id, 16);
    rbox_read_bytes(&r, header->request_id, 16);
    rbox_read_bytes(&r, header->server_id, 16);
    header->cmd_type = rbox_read_u32(&r);
    header->flags = rbox_read_u32(&r);
    header->offset = rbox_read_u64(&r);
    header->chunk_len = rbox_read_u32(&r);
    header->total_len = rbox_read_u64(&r);
    header->cmd_hash = rbox_read_u32(&r);
    header->fenv_hash = rbox_read_u32(&r);

    rbox_reader_skip_to(&r, RBOX_HEADER_OFFSET_CHECKSUM);

    header->checksum = rbox_read_u32(&r);

    /* Verify header checksum */
    uint32_t hdr_crc = rbox_runtime_crc32(0, packet, RBOX_HEADER_OFFSET_CHECKSUM);
    if (header->checksum != hdr_crc) {
        memset(header, 0, sizeof(*header));
        return;
    }
    header->valid = 1;
}

/* ============================================================
 * RESPONSE DETAILS DECODING
 * ============================================================ */

rbox_error_t rbox_decode_response_details_raw(
    const uint8_t *packet,
    size_t len,
    rbox_decoded_header_t *header,
    rbox_response_details_t *out_details) {

    if (!header || !packet || !out_details) return RBOX_ERR_INVALID;
    memset(out_details, 0, sizeof(*out_details));
    if (!header->valid || len <= RBOX_HEADER_SIZE) return RBOX_ERR_INVALID;

    out_details->decision = packet[RBOX_HEADER_SIZE];
    size_t reason_offset = RBOX_HEADER_SIZE + 1;
    out_details->reason_len = 0;
    while (reason_offset < len && out_details->reason_len < 255) {
        if (packet[reason_offset] == '\0') break;
        out_details->reason[out_details->reason_len++] = packet[reason_offset++];
    }
    out_details->reason[out_details->reason_len] = '\0';
    out_details->valid = 1;
    return RBOX_OK;
}

/* ============================================================
 * ENV DECISIONS DECODING
 * ============================================================ */

rbox_error_t rbox_decode_env_decisions_raw(
    const uint8_t *packet,
    size_t len,
    rbox_decoded_header_t *header,
    rbox_response_details_t *details,
    rbox_env_decisions_t *out_env_decisions) {

    if (!header || !details || !packet || !out_env_decisions) return RBOX_ERR_INVALID;
    memset(out_env_decisions, 0, sizeof(*out_env_decisions));
    if (!header->valid || !details->valid) return RBOX_ERR_INVALID;

    size_t reason_offset = RBOX_HEADER_SIZE + 1 + details->reason_len + 1;
    if (len < reason_offset + 6) return RBOX_ERR_INVALID;

    out_env_decisions->fenv_hash = *(uint32_t *)(packet + reason_offset);
    size_t env_offset = reason_offset + 4;
    out_env_decisions->env_count = *(uint16_t *)(packet + env_offset);
    env_offset += 2;

    if (out_env_decisions->env_count == 0 || out_env_decisions->env_count > 256) {
        out_env_decisions->valid = 1;
        return RBOX_OK;
    }

    size_t bitmap_size = (out_env_decisions->env_count + 7) / 8;
    if (len < env_offset + bitmap_size) {
        out_env_decisions->env_count = 0;
        return RBOX_ERR_INVALID;
    }

    out_env_decisions->bitmap = malloc(bitmap_size);
    if (!out_env_decisions->bitmap) {
        out_env_decisions->env_count = 0;
        return RBOX_ERR_MEMORY;
    }
    memcpy(out_env_decisions->bitmap, packet + env_offset, bitmap_size);
    out_env_decisions->valid = 1;
    return RBOX_OK;
}

/* ============================================================
 * FULL RESPONSE DECODING
 * ============================================================ */

rbox_error_t rbox_decode_response_raw(
    const uint8_t *packet,
    size_t len,
    const uint8_t expected_request_id[16],
    rbox_response_t *out_response) {

    if (!packet || !out_response) return RBOX_ERR_INVALID;

    /* Validate magic */
    uint32_t magic = *(uint32_t *)packet;
    if (magic != RBOX_MAGIC) {
        return RBOX_ERR_MAGIC;
    }

    /* Check version */
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
        if (chunk_len > RBOX_CHUNK_MAX) {
            return RBOX_ERR_INVALID;
        }
        if (len < RBOX_HEADER_SIZE + chunk_len) {
            return RBOX_ERR_TRUNCATED;
        }

        /* Validate header checksum */
        uint32_t stored_hdr_checksum = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_CHECKSUM);
        uint32_t computed_hdr_checksum = rbox_runtime_crc32(0, packet, RBOX_HEADER_OFFSET_CHECKSUM);
        if (stored_hdr_checksum != computed_hdr_checksum) {
            return RBOX_ERR_CHECKSUM;
        }

        decision = packet[RBOX_HEADER_SIZE];
        reason_offset = RBOX_HEADER_SIZE + 1;
        reason_len = 0;
        size_t scan_offset = RBOX_HEADER_SIZE + 1;
        size_t scan_bound = RBOX_HEADER_SIZE + chunk_len;
        while (scan_offset < scan_bound && reason_len < RBOX_RESPONSE_MAX_REASON) {
            if (packet[scan_offset] == '\0') break;
            reason_len++;
            scan_offset++;
        }
        request_id_offset = RBOX_HEADER_OFFSET_REQUEST_ID;

        size_t expected_len = RBOX_HEADER_SIZE + 1 + reason_len + 1;
        if (len < expected_len) {
            return RBOX_ERR_TRUNCATED;
        }
    } else {
        /* Legacy v2 format */
        if (len < RBOX_RESPONSE_MIN_SIZE) {
            return RBOX_ERR_TRUNCATED;
        }

        decision = packet[RBOX_RESPONSE_OFFSET_DECISION_V2];
        reason_len = *(uint32_t *)(packet + RBOX_RESPONSE_OFFSET_REASON_LEN_V2);
        reason_offset = RBOX_RESPONSE_OFFSET_REASON_V2;
        request_id_offset = RBOX_RESPONSE_OFFSET_REQUEST_ID_V2;

        if (reason_len > RBOX_RESPONSE_MAX_REASON) {
            reason_len = RBOX_RESPONSE_MAX_REASON;
        }

        size_t expected_len = reason_offset + reason_len + 1;
        if (len < expected_len) {
            return RBOX_ERR_TRUNCATED;
        }
    }

    /* Validate request_id */
    const uint8_t *resp_request_id = packet + request_id_offset;
    if (expected_request_id) {
        if (memcmp(resp_request_id, expected_request_id, 16) != 0) {
            return RBOX_ERR_MISMATCH;
        }
    }

    /* Validate body checksum */
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

    out_response->duration = 0;

    /* Decode env decisions for v9 */
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
                    } else {
                        out_response->env_decision_count = 0;
                    }
                }
            }
        }
    }

    return RBOX_OK;
}
