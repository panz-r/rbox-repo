/*
 * protocol.c - Protocol encoding and decoding for rbox-protocol
 *
 * Layer 2: Protocol encoding/decoding
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <pthread.h>

#include "rbox_protocol.h"
#include "protocol.h"
#include "runtime.h"

/* Thread-local seed for request ID generation - initialized on first use */
static __thread uint32_t g_request_id_seed = 0;

/* Generate request ID using persistent thread-local seed */
void rbox_protocol_generate_request_id(uint8_t *id_out) {
    if (!id_out) return;
    if (g_request_id_seed == 0) {
        g_request_id_seed = rbox_runtime_rand_seed();
    }
    for (int i = 0; i < 16; i += 4) {
        uint32_t r = rand_r(&g_request_id_seed);
        id_out[i] = (r >> 24) & 0xFF;
        id_out[i + 1] = (r >> 16) & 0xFF;
        id_out[i + 2] = (r >> 8) & 0xFF;
        id_out[i + 3] = r & 0xFF;
    }
}

/* ============================================================
 * HEADER VALIDATION
 * ============================================================ */

int rbox_protocol_validate_header(const char *packet, size_t len) {
    if (!packet || len < RBOX_HEADER_SIZE) return RBOX_ERR_TRUNCATED;

    uint32_t magic = *(uint32_t *)packet;
    uint32_t version = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_VERSION);
    if (magic != RBOX_MAGIC) return RBOX_ERR_MAGIC;
    if (version != RBOX_VERSION) return RBOX_ERR_VERSION;

    uint32_t stored_checksum = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_CHECKSUM);
    uint32_t computed_checksum = rbox_runtime_crc32(0, packet, RBOX_HEADER_OFFSET_CHECKSUM);
    if (stored_checksum != computed_checksum) return RBOX_ERR_CHECKSUM;

    return RBOX_OK;
}

/* ============================================================
 * PACKET DECODING
 * ============================================================ */

int rbox_protocol_decode_header(const char *packet, size_t len,
                                uint32_t *magic, uint32_t *version,
                                uint8_t *client_id, uint8_t *request_id,
                                uint32_t *cmd_hash, uint32_t *fenv_hash,
                                uint32_t *chunk_len) {
    if (!packet || len < RBOX_HEADER_SIZE) return RBOX_ERR_TRUNCATED;

    if (magic) *magic = *(uint32_t *)packet;
    if (version) *version = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_VERSION);
    if (client_id) memcpy(client_id, packet + RBOX_HEADER_OFFSET_CLIENT_ID, 16);
    if (request_id) memcpy(request_id, packet + RBOX_HEADER_OFFSET_REQUEST_ID, 16);
    if (cmd_hash) *cmd_hash = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_CMD_HASH);
    if (fenv_hash) *fenv_hash = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_FENV_HASH);
    if (chunk_len) *chunk_len = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_CHUNK_LEN);

    return RBOX_OK;
}

/* ============================================================
 * LIBRARY INITIALIZATION
 * ============================================================ */

void rbox_protocol_init(void) {
    /* Initialization is now handled automatically by runtime constructor */
}
