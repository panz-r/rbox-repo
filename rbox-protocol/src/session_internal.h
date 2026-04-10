/*
 * session_internal.h - Internal session structure definition
 *
 * This header contains the rbox_session struct definition that is shared
 * between packet.c (session implementation) and session.c
 *
 * NOTE: rbox_session_state_t is already defined in rbox_protocol.h
 */

#ifndef RBOX_SESSION_INTERNAL_H
#define RBOX_SESSION_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include <rbox_protocol.h>
#include "socket.h"

/* Get current time in ms (defined in session.c) */
uint64_t get_time_ms(void);

/* Send raw data on session (defined in session.c) */
rbox_error_t rbox_session_send_raw(rbox_session_t *session, const char *data, size_t len);

/* Validate response (defined in packet.c) */
rbox_error_t validate_response(const char *packet, size_t len,
                               const uint8_t *expected_request_id,
                               rbox_response_t *out_response);

/*
 * Session structure - shared between packet.c and session.c
 */
struct rbox_session {
    /* Connection config */
    char socket_path[256];
    uint32_t base_delay_ms;
    uint32_t max_retries;

    /* Socket */
    rbox_client_t *client;

    /* State machine */
    rbox_session_state_t state;
    rbox_error_t error;

    /* Request tracking */
    uint8_t request_id[16];

    /* Send state (non-blocking) */
    char   *send_buf;
    size_t  send_len;
    size_t  send_offset;

    /* Receive state (non-blocking) */
    char   *recv_buf;
    size_t  recv_capacity;
    size_t  recv_len;

    /* Response - raw data (for --bin mode) */
    char *response_data;
    size_t response_len;

    /* Response - parsed (for normal mode) */
    rbox_response_t response;

    /* Connection retry state */
    uint32_t retry_attempt;
    uint32_t retry_seed;  /* Persistent seed for retry delay jitter */
    uint64_t next_retry_time;
};

#endif /* RBOX_SESSION_INTERNAL_H */