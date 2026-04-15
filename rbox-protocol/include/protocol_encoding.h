/*
 * protocol_encoding.h - Pure protocol encoding functions
 *
 * No dependencies on sockets, threads, or session state.
 * All functions operate on caller-provided memory buffers.
 */

#ifndef RBOX_PROTOCOL_ENCODING_H
#define RBOX_PROTOCOL_ENCODING_H

#include <stdint.h>
#include <stddef.h>
#include "rbox_protocol_defs.h"
#include "rbox_protocol.h"  /* for rbox_error_t */

/* Generate a unique request ID (fills 16 bytes).
 * Thread-safe using thread-local seed. */
void rbox_generate_request_id(uint8_t id_out[16]);

/* Return the persistent client ID (16 bytes).
 * Generated once per process, thread-safe via pthread_once.
 * Returns pointer to internal static storage - do not free. */
const uint8_t *rbox_get_client_id(void);

/* 64-bit hash for command strings (used in cache).
 * Deterministic, two-step hash combining FNV-1a and DJB2. */
uint64_t rbox_hash64(const char *str, size_t len);

/* Build a request packet into a caller-provided buffer.
 * Format: header (RBOX_HEADER_SIZE bytes) + body
 *
 * Returns RBOX_OK and sets *out_len on success.
 * If buffer too small, returns RBOX_ERR_INVALID and sets *out_len to required size.
 *
 * Parameters:
 *   - command: the command to execute (required)
 *   - caller: optional caller identifier (e.g., "judge", "run")
 *   - syscall: optional syscall being queried (e.g., "execve")
 *   - argc: number of arguments
 *   - argv: argument array
 *   - env_var_count: number of environment variables
 *   - env_var_names: array of env var names
 *   - env_var_scores: array of env var scores (may be NULL)
 *   - out_buf: output buffer (must be at least RBOX_HEADER_SIZE)
 *   - buf_capacity: size of output buffer
 *   - out_len: (out) actual packet length written
 */
rbox_error_t rbox_encode_request(
    const char *command,
    const char *caller,
    const char *syscall,
    int argc,
    const char **argv,
    int env_var_count,
    const char **env_var_names,
    const float *env_var_scores,
    uint8_t *out_buf,
    size_t buf_capacity,
    size_t *out_len
);

/* Build a response packet into a caller-provided buffer.
 * Uses the provided client_id and request_id (can be NULL to use zeros).
 *
 * Returns RBOX_OK and sets *out_len on success.
 * If buffer too small, returns RBOX_ERR_INVALID and sets *out_len to required size.
 *
 * Parameters:
 *   - client_id: 16 bytes, may be NULL
 *   - request_id: 16 bytes, may be NULL
 *   - cmd_hash: command hash for the request
 *   - decision: RBOX_DECISION_ALLOW or RBOX_DECISION_DENY
 *   - reason: null-terminated reason string (may be NULL)
 *   - fenv_hash: environment hash
 *   - env_decision_count: number of env decisions
 *   - env_decisions: bitmap of env decisions (may be NULL)
 *   - out_buf: output buffer (must be at least RBOX_HEADER_SIZE)
 *   - buf_capacity: size of output buffer
 *   - out_len: (out) actual packet length written
 */
rbox_error_t rbox_encode_response(
    const uint8_t *client_id,
    const uint8_t *request_id,
    uint32_t cmd_hash,
    uint8_t decision,
    const char *reason,
    uint32_t fenv_hash,
    int env_decision_count,
    const uint8_t *env_decisions,
    uint8_t *out_buf,
    size_t buf_capacity,
    size_t *out_len
);

/* Build a telemetry response packet.
 * Contains allow/deny counts in the reason field.
 *
 * Returns allocated packet (caller must free with free()).
 * Sets *out_len to packet length.
 */
char *rbox_encode_telemetry_response(
    const uint8_t *client_id,
    const uint8_t *request_id,
    uint32_t allow_count,
    uint32_t deny_count,
    size_t *out_len
);

#endif /* RBOX_PROTOCOL_ENCODING_H */
