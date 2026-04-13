/*
 * server_response.c - Response dispatch for rbox-protocol server
 *
 * Layer 7: Response dispatch
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include "rbox_protocol.h"
#include "protocol.h"
#include "runtime.h"
#include "server_internal.h"
#include "server_response.h"

char *rbox_server_build_response(
    const uint8_t *client_id,
    const uint8_t *request_id,
    uint32_t cmd_hash,
    uint8_t decision,
    const char *reason,
    uint32_t fenv_hash,
    int env_decision_count,
    uint8_t *env_decisions,
    size_t *out_len) {

    if (!out_len) return NULL;

    if (env_decision_count > 4096) return NULL;

    size_t reason_len = reason ? strlen(reason) : 0;
    if (reason_len > RBOX_RESPONSE_MAX_REASON) reason_len = RBOX_RESPONSE_MAX_REASON;
    size_t bitmap_size = (env_decision_count > 0 && env_decisions) ? (env_decision_count + 7) / 8 : 0;
    size_t body_len = 1 + reason_len + 1 + 4 + 2 + bitmap_size;

    size_t total_len = RBOX_HEADER_SIZE + body_len;
    char *pkt = malloc(total_len);
    if (!pkt) return NULL;
    memset(pkt, 0, total_len);

    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_MAGIC) = RBOX_MAGIC;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_VERSION) = RBOX_VERSION;
    if (client_id) memcpy(pkt + RBOX_HEADER_OFFSET_CLIENT_ID, client_id, 16);
    if (request_id) memcpy(pkt + RBOX_HEADER_OFFSET_REQUEST_ID, request_id, 16);
    memset(pkt + RBOX_HEADER_OFFSET_SERVER_ID, 'S', 16);
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_TYPE) = 0;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_FLAGS) = 0;
    *(uint64_t *)(pkt + RBOX_HEADER_OFFSET_OFFSET) = 0;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHUNK_LEN) = body_len;
    *(uint64_t *)(pkt + RBOX_HEADER_OFFSET_TOTAL_LEN) = body_len;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CMD_HASH) = cmd_hash;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_FENV_HASH) = fenv_hash;

    char *body = pkt + RBOX_HEADER_SIZE;
    size_t pos = 0;
    body[pos++] = decision;
    if (reason_len > 0) {
        memcpy(body + pos, reason, reason_len);
        pos += reason_len;
    }
    body[pos++] = '\0';
    *(uint32_t *)(body + pos) = fenv_hash;
    pos += 4;
    *(uint16_t *)(body + pos) = (uint16_t)env_decision_count;
    pos += 2;
    if (bitmap_size > 0 && env_decisions) {
        memcpy(body + pos, env_decisions, bitmap_size);
        pos += bitmap_size;
    }

    uint32_t checksum = rbox_runtime_crc32(0, pkt, RBOX_HEADER_OFFSET_CHECKSUM);
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHECKSUM) = checksum;
    uint32_t body_checksum = rbox_runtime_crc32(0, body, body_len);
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_BODY_CHECKSUM) = body_checksum;

    *out_len = total_len;
    return pkt;
}

char *rbox_server_build_telemetry_response(
    const uint8_t *client_id,
    const uint8_t *request_id,
    uint32_t allow_count,
    uint32_t deny_count,
    size_t *out_len) {

    if (!out_len) return NULL;

    char reason[64];
    int snprinted = snprintf(reason, sizeof(reason), "ALLOW:%u DENY:%u\n", allow_count, deny_count);
    size_t reason_len = (snprinted < 0) ? 0 : (size_t)snprinted;
    if (reason_len >= sizeof(reason)) {
        reason_len = sizeof(reason) - 1;
    }
    reason[reason_len] = '\0';

    size_t body_len = 1 + reason_len + 1;

    size_t total_len = RBOX_HEADER_SIZE + body_len;
    char *pkt = malloc(total_len);
    if (!pkt) return NULL;
    memset(pkt, 0, total_len);

    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_MAGIC) = RBOX_MAGIC;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_VERSION) = RBOX_VERSION;
    if (client_id) memcpy(pkt + RBOX_HEADER_OFFSET_CLIENT_ID, client_id, 16);
    if (request_id) memcpy(pkt + RBOX_HEADER_OFFSET_REQUEST_ID, request_id, 16);
    memset(pkt + RBOX_HEADER_OFFSET_SERVER_ID, 'S', 16);
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_TYPE) = 0;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_FLAGS) = 0;
    *(uint64_t *)(pkt + RBOX_HEADER_OFFSET_OFFSET) = 0;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHUNK_LEN) = body_len;
    *(uint64_t *)(pkt + RBOX_HEADER_OFFSET_TOTAL_LEN) = body_len;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CMD_HASH) = 0;
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_FENV_HASH) = 0;

    char *body = pkt + RBOX_HEADER_SIZE;
    size_t pos = 0;
    body[pos++] = RBOX_DECISION_UNKNOWN;
    memcpy(body + pos, reason, reason_len);
    pos += reason_len;
    body[pos++] = '\0';

    uint32_t checksum = rbox_runtime_crc32(0, pkt, RBOX_HEADER_OFFSET_CHECKSUM);
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_CHECKSUM) = checksum;
    uint32_t body_checksum = rbox_runtime_crc32(0, body, body_len);
    *(uint32_t *)(pkt + RBOX_HEADER_OFFSET_BODY_CHECKSUM) = body_checksum;

    *out_len = total_len;
    return pkt;
}