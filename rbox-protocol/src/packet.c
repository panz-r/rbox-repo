/*
 * packet.c - Packet parsing and building for rbox-protocol
 *
 * NOTE: Pure protocol encoding/decoding has moved to:
 *   - protocol_encoding.c (request/response building, ID generation, hashing)
 *   - protocol_decoding.c (header validation, response parsing)
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
#include "protocol_encoding.h"
#include "protocol_decoding.h"
#include "error_internal.h"
#include "error_messages.h"
#include "rbox_log.h"

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

    /* Verify chunk_len is within bounds */
    uint32_t chunk_len = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_CHUNK_LEN);
    if (chunk_len > RBOX_CHUNK_MAX) {
        return RBOX_ERR_INVALID;
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

char *rbox_strerror_r(rbox_error_t err, int sys_errno, const char *message, char *buf, size_t buf_len) {
    if (!buf || buf_len == 0) return buf;

    const char *err_str = rbox_strerror(err);
    if (message && message[0] != '\0') {
        snprintf(buf, buf_len, "%s: %s", err_str, message);
    } else if (sys_errno != 0) {
        snprintf(buf, buf_len, "%s: %s", err_str, strerror(sys_errno));
    } else {
        snprintf(buf, buf_len, "%s", err_str);
    }

    return buf;
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

    return rbox_encode_request(command, caller, syscall, argc, argv,
                               env_var_count, env_var_names, env_var_scores,
                               (uint8_t *)packet, capacity, out_len);
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
    rbox_response_t *response, rbox_error_info_t *err_info) {
    if (!client || !command || !response) {
        rbox_error_set(err_info, RBOX_ERR_INVALID, 0, RBOX_MSG_INVALID_PARAM);
        return RBOX_ERR_INVALID;
    }

    /* Build request packet using canonical layered function.
     * Use 64KB stack buffer first; fall back to heap if request is larger. */
    char stack_buf[65536];
    char *packet = stack_buf;
    size_t packet_len = 0;
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
    err = rbox_decode_response_raw((const uint8_t *)response_buf, resp_len, request_id, response);
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
    uint32_t base_delay_ms, uint32_t max_retries,
    rbox_error_info_t *err_info) {
    if (!socket_path || !command || !out_response) {
        rbox_error_set(err_info, RBOX_ERR_INVALID, 0, RBOX_MSG_INVALID_PARAM);
        return RBOX_ERR_INVALID;
    }

    memset(out_response, 0, sizeof(*out_response));

    char *packet = NULL;
    size_t packet_len = 0;

    rbox_error_t err = rbox_blocking_request_raw(socket_path, command, argc, argv,
        caller, syscall,
        env_var_count, env_var_names, env_var_scores,
        &packet, &packet_len, base_delay_ms, max_retries, 0, NULL);

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
 * Has proper retry logic like rbox_blocking_request
 * timeout_ms: 0 means no timeout (wait forever), otherwise max wait in milliseconds
 */
rbox_error_t rbox_blocking_request_raw(const char *socket_path,
    const char *command, int argc, const char **argv,
    const char *caller, const char *syscall,
    int env_var_count, const char **env_var_names, const float *env_var_scores,
    char **out_packet, size_t *out_packet_len,
    uint32_t base_delay_ms, uint32_t max_retries, uint32_t timeout_ms,
    rbox_error_info_t *err_info) {

    rbox_error_t err = RBOX_OK;
    char *packet = NULL;
    rbox_session_t *session = NULL;

    if (!socket_path || !command || !out_packet || !out_packet_len) {
        rbox_error_set(err_info, RBOX_ERR_INVALID, 0, RBOX_MSG_INVALID_PARAM);
        return RBOX_ERR_INVALID;
    }

    *out_packet = NULL;
    *out_packet_len = 0;

    uint32_t attempt = 0;
    uint64_t start_time = (timeout_ms > 0) ? get_time_ms() : 0;
    uint64_t deadline = (timeout_ms > 0) ? start_time + timeout_ms : 0;

    while (1) {
        err = RBOX_OK;

        packet = malloc(8192);
        if (!packet) {
            err = RBOX_ERR_MEMORY;
            goto cleanup;
        }
        size_t packet_len = 0;

        err = rbox_build_request(packet, 8192, &packet_len,
            command, caller, syscall, argc, argv,
            env_var_count, env_var_names, env_var_scores);
        if (err != RBOX_OK || packet_len == 0) {
            err = err ? err : RBOX_ERR_MEMORY;
            goto cleanup;
        }

        uint8_t request_id[16];
        memcpy(request_id, packet + RBOX_HEADER_OFFSET_REQUEST_ID, 16);

        session = rbox_session_new(socket_path, base_delay_ms, max_retries, NULL);
        if (!session) {
            err = RBOX_ERR_MEMORY;
            goto cleanup;
        }

        memcpy(session->request_id, request_id, 16);

        while (1) {
            rbox_session_state_t state = rbox_session_state(session);

            switch (state) {
                case RBOX_SESSION_DISCONNECTED: {
                    err = rbox_session_connect(session, NULL);
                    if (err != RBOX_OK && err != RBOX_ERR_IO) {
                        goto cleanup;
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
                            rbox_session_heartbeat(session, POLLOUT, NULL);
                        } else if (ret == 0) {
                            rbox_session_heartbeat(session, 0, NULL);
                        } else if (ret < 0 && errno != EINTR) {
                            rbox_session_heartbeat(session, POLLERR, NULL);
                        }
                    } else {
                        rbox_session_heartbeat(session, 0, NULL);
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
                        rbox_session_heartbeat(session, POLLOUT, NULL);
                    }
                    break;
                }

                case RBOX_SESSION_WAITING:
                case RBOX_SESSION_RESPONSE_READY: {
                    if (timeout_ms > 0 && get_time_ms() > deadline) {
                        err = RBOX_ERR_IO;
                        goto cleanup;
                    }
                    short events;
                    int fd = rbox_session_pollfd(session, &events);
                    if (fd >= 0) {
                        struct pollfd pfd = { .fd = fd, .events = events };
                        int ret = poll(&pfd, 1, 100);
                        if (ret > 0) {
                            rbox_session_heartbeat(session, pfd.revents, NULL);
                        } else if (ret == 0) {
                            rbox_session_heartbeat(session, 0, NULL);
                        } else if (ret < 0 && errno != EINTR) {
                            rbox_session_heartbeat(session, POLLERR, NULL);
                        }
                    } else {
                        usleep(10000);
                    }
                    break;
                }

                case RBOX_SESSION_FAILED: {
                    err = RBOX_ERR_IO;
                    goto cleanup;
                }
            }

            if (rbox_session_state(session) == RBOX_SESSION_RESPONSE_READY) {
                *out_packet = (char *)session->response_data;
                *out_packet_len = session->response_len;
                session->response_data = NULL;
                session->response_len = 0;
                rbox_session_free(session);
                session = NULL;
                RBOX_FREE(packet);
                return RBOX_OK;
            }
        }

cleanup:
        rbox_session_free(session);
        session = NULL;
        RBOX_FREE(packet);
        packet = NULL;

        if (err != RBOX_ERR_IO || (max_retries > 0 && attempt >= max_retries)) {
            break;
        }
        attempt++;
        if (base_delay_ms > 0) {
            usleep(base_delay_ms * 1000 * attempt);
        }
    }

    return err ? err : RBOX_ERR_IO;
}


/* rbox_response_send - uses rbox_encode_response */
rbox_error_t rbox_response_send(rbox_client_t *client, const rbox_response_t *response, rbox_error_info_t *err_info) {
    if (!client || !response) {
        rbox_error_set(err_info, RBOX_ERR_INVALID, 0, RBOX_MSG_INVALID_PARAM);
        return RBOX_ERR_INVALID;
    }

    uint8_t resp_buf[1024];
    size_t pkt_len;
    rbox_error_t err = rbox_encode_response(NULL, response->request_id, 0, response->decision,
                                   response->reason, 0, 0, NULL,
                                   resp_buf, sizeof(resp_buf), &pkt_len, NULL);
    if (err != RBOX_OK) {
        rbox_error_set(err_info, err, 0, RBOX_MSG_MEMORY);
        return RBOX_ERR_MEMORY;
    }

    ssize_t n = rbox_write(rbox_client_fd(client), (char *)resp_buf, pkt_len);
    if (n < 0) {
        rbox_error_set(err_info, RBOX_ERR_IO, errno, RBOX_MSG_WRITE_FAILED);
        return RBOX_ERR_IO;
    }
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

    uint8_t *pkt = malloc(1024);
    if (!pkt) return RBOX_ERR_MEMORY;

    rbox_error_t err = rbox_encode_response(client_id, request_id, 0, decision, reason,
                                     fenv_hash, env_decision_count, env_decisions,
                                     pkt, 1024, out_len, NULL);
    if (err != RBOX_OK) {

        free(pkt);
        return err;
    }

    *out_packet = (char *)pkt;
    return RBOX_OK;
}

char *rbox_build_response_internal(uint8_t *client_id, uint8_t *request_id, uint32_t cmd_hash,
                           uint8_t decision, const char *reason,
                           uint32_t fenv_hash, int env_decision_count, uint8_t *env_decisions,
                           size_t *out_len) {
    uint8_t *pkt = malloc(1024);
    if (!pkt) return NULL;

    rbox_error_t err = rbox_encode_response(client_id, request_id, cmd_hash, decision, reason,
                                     fenv_hash, env_decision_count, env_decisions,
                                     pkt, 1024, out_len, NULL);
    if (err != RBOX_OK) {
        free(pkt);
        return NULL;
    }
    *out_len = 1024;
    return (char *)pkt;
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
    uint32_t *out_deny,
    rbox_error_info_t *err_info) {

    if (!socket_path || !out_allow || !out_deny) {
        rbox_error_set(err_info, RBOX_ERR_INVALID, 0, RBOX_MSG_INVALID_PARAM);
        return RBOX_ERR_INVALID;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        rbox_error_set(err_info, RBOX_ERR_IO, errno, RBOX_MSG_CONN_FAILED);
        return RBOX_ERR_IO;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        rbox_error_set(err_info, RBOX_ERR_IO, errno, RBOX_MSG_CONN_REFUSED);
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

    if (rbox_write_exact(fd, header, RBOX_HEADER_SIZE) != (ssize_t)RBOX_HEADER_SIZE) {
        rbox_error_set(err_info, RBOX_ERR_IO, errno, RBOX_MSG_WRITE_FAILED);
        close(fd);
        return RBOX_ERR_IO;
    }

    uint8_t resp_header[RBOX_HEADER_SIZE];
    ssize_t n = rbox_read(fd, resp_header, RBOX_HEADER_SIZE);
    if (n != RBOX_HEADER_SIZE) {
        rbox_error_set(err_info, RBOX_ERR_IO, errno, RBOX_MSG_READ_FAILED);
        close(fd);
        return RBOX_ERR_IO;
    }

    uint32_t resp_magic = *(uint32_t *)resp_header;
    if (resp_magic != RBOX_MAGIC) {
        rbox_error_set(err_info, RBOX_ERR_MAGIC, 0, RBOX_MSG_MAGIC_INVALID);
        close(fd);
        return RBOX_ERR_IO;
    }

    rbox_error_t hdr_err = rbox_header_validate((char *)resp_header, RBOX_HEADER_SIZE);
    if (hdr_err != RBOX_OK) {
        rbox_error_set(err_info, hdr_err, 0, RBOX_MSG_HEADER_INVALID);
        close(fd);
        return RBOX_ERR_IO;
    }

    uint32_t resp_chunk_len = *(uint32_t *)(resp_header + RBOX_HEADER_OFFSET_CHUNK_LEN);
    if (resp_chunk_len > 4096) {
        rbox_error_set(err_info, RBOX_ERR_TRUNCATED, 0, RBOX_MSG_TRUNCATED);
        close(fd);
        return RBOX_ERR_IO;
    }

    size_t total_resp_len = RBOX_HEADER_SIZE + resp_chunk_len;
    char *resp_body = malloc(total_resp_len);
    if (!resp_body) {
        rbox_error_set(err_info, RBOX_ERR_MEMORY, 0, RBOX_MSG_MEMORY);
        close(fd);
        return RBOX_ERR_MEMORY;
    }
    memcpy(resp_body, resp_header, RBOX_HEADER_SIZE);

    size_t remaining = resp_chunk_len;
    size_t pos = RBOX_HEADER_SIZE;
    while (remaining > 0) {
        n = rbox_read(fd, resp_body + pos, remaining);
        if (n <= 0) {
            rbox_error_set(err_info, RBOX_ERR_IO, errno, RBOX_MSG_READ_FAILED);
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