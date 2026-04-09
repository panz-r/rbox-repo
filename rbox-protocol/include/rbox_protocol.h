/*
 * rbox-protocol.h - ReadOnlyBox Protocol Library
 *
 * Unified client-server communication for ReadOnlyBox.
 * Handles socket I/O, packet parsing, and shellsplit integration.
 */

#ifndef RBOX_PROTOCOL_H
#define RBOX_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

/* Include protocol definitions (offsets, constants, structures) */
#include "rbox_protocol_defs.h"

/* Forward declare shell tokenizer */
#include <shell_tokenizer.h>

/* ============================================================
 * ERROR CODES
 * ============================================================ */

typedef enum {
    RBOX_OK = 0,
    RBOX_ERR_INVALID     = -1,  /* Invalid packet format */
    RBOX_ERR_MAGIC      = -2,  /* Wrong magic number */
    RBOX_ERR_VERSION   = -3,  /* Unsupported version */
    RBOX_ERR_CHECKSUM   = -4,  /* Checksum mismatch */
    RBOX_ERR_TRUNCATED = -5,  /* Truncated data */
    RBOX_ERR_IO        = -6,  /* Socket I/O error */
    RBOX_ERR_MEMORY    = -7,  /* Memory allocation failed */
    RBOX_ERR_MISMATCH  = -8,  /* Request/response ID mismatch (stale response) */
} rbox_error_t;

/* ============================================================
 * REQUEST/RESPONSE STRUCTURES
 * ============================================================ */

/* Forward declarations for types defined later */
struct rbox_parse_result;
typedef struct rbox_parse_result rbox_parse_result_t;

/* Decoded response details */
typedef struct rbox_response_details {
    uint8_t decision;
    char reason[256];
    uint32_t reason_len;
    int valid;  /* 1 if details are valid */
} rbox_response_details_t;

/* Decoded env decisions from response */
typedef struct rbox_env_decisions {
    uint32_t fenv_hash;
    uint16_t env_count;
    uint8_t *bitmap;  /* Caller must free */
    int valid;  /* 1 if env decisions are valid */
} rbox_env_decisions_t;

/* Decoded header with validation status (not packed, for decoded values) */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint8_t client_id[16];
    uint8_t request_id[16];
    uint8_t server_id[16];
    uint32_t cmd_type;  /* Renamed from type to avoid Go keyword conflict */
    uint32_t flags;
    uint64_t offset;
    uint32_t chunk_len;
    uint64_t total_len;
    uint32_t cmd_hash;
    uint32_t fenv_hash;
    uint32_t checksum;        /* Header checksum */
    uint32_t body_checksum;   /* Body checksum */
    int valid;  /* 1 if header is valid (checksum passed) */
} rbox_decoded_header_t;

/* Response structure */
typedef struct {
    uint8_t decision;       /* ALLOW/DENY/ERROR */
    char     reason[256];   /* Reason string */
    uint32_t duration;       /* Duration in seconds (0 = once) */
    uint8_t request_id[16]; /* Server should echo back client's request_id */

    /* Env decisions from server */
    int env_decision_count;
    char **env_decision_names;   /* Array of env var names */
    uint8_t *env_decisions;     /* Array of decisions: 0=allow, 1=deny */
} rbox_response_t;

/* Get env decision count from response */
//export rbox_response_env_decision_count
int rbox_response_env_decision_count(const rbox_response_t *resp);

/* Get env decision at index (0=allow, 1=deny) */
//export rbox_response_env_decision
int rbox_response_env_decision(const rbox_response_t *resp, int index);

/* Free all fields in response */
//export rbox_response_free
void rbox_response_free(rbox_response_t *resp);

/* ============================================================
 * LAYERED DECODE UTILITIES
 * ============================================================ */

/* Decode header from packet - verifies magic, version, checksum
 * Returns: header struct with valid=1 if successful, valid=0 if failed
 * Caller provides allocated rbox_decoded_header_t* */
//export rbox_decode_header
void rbox_decode_header(const char *packet, size_t len, rbox_decoded_header_t *header);

/* Decode response details from packet using header
 * Returns: details struct with valid=1 if successful, valid=0 if failed
 * Caller provides allocated rbox_response_details_t* */
//export rbox_decode_response_details
void rbox_decode_response_details(const rbox_decoded_header_t *header, const char *packet, size_t len, rbox_response_details_t *details);

/* Decode env decisions from packet using header and details
 * Returns: env_decisions struct with valid=1 if successful, valid=0 if failed
 * Caller provides allocated rbox_env_decisions_t*, bitmap is allocated and must be freed by caller
 * If no env decisions in packet, bitmap will be NULL and count will be 0 */
//export rbox_decode_env_decisions
void rbox_decode_env_decisions(const rbox_decoded_header_t *header, const rbox_response_details_t *details, const char *packet, size_t len, rbox_env_decisions_t *env_decisions);

/* Free env decisions resources */
//export rbox_free_env_decisions
void rbox_free_env_decisions(rbox_env_decisions_t *env_decisions);

/* ============================================================
 * CLIENT HANDLE
 * ============================================================ */

typedef struct rbox_client rbox_client_t;

/* Create client socket and connect to server */
rbox_client_t *rbox_client_connect(const char *socket_path);

/* Connect with retry (exponential backoff + jitter)
 * base_delay_ms: base delay in ms (0 = no retry)
 * max_retries: max attempts (0 = unlimited) */
rbox_client_t *rbox_client_connect_retry(const char *socket_path, uint32_t base_delay_ms, uint32_t max_retries);

/* Close client connection */
void rbox_client_close(rbox_client_t *client);

/* Get file descriptor (for direct I/O) */
int rbox_client_fd(const rbox_client_t *client);

/* Check if peer has closed connection */
int rbox_client_is_closed(const rbox_client_t *client);

/* Get last error code */
int rbox_client_error(const rbox_client_t *client);

/* Send request and receive validated response
 *
 * This is the main client workflow function. It:
 * 1. Generates a unique request_id
 * 2. Builds and sends the request packet
 * 3. Reads and validates the response:
 *    - Validates magic, version, checksum
 *    - Matches request_id to detect stale responses
 * 4. Returns validated decision in response
 *
 * If validation fails, returns error so caller can retry.
 *
 * Parameters:
 *   - client: connected client handle
 *   - command: command to execute
 *   - argc: number of arguments
 *   - argv: argument array
 *   - response: output response (only valid if return is RBOX_OK)
 *
 * Returns:
 *   RBOX_OK: response is valid, decision in response->decision
 *   RBOX_ERR_INVALID: invalid parameters
 *   RBOX_ERR_IO: socket I/O error (may retry)
 *   RBOX_ERR_TRUNCATED: truncated response (may retry)
 *   RBOX_ERR_MAGIC: invalid magic in response (don't retry)
 *   RBOX_ERR_VERSION: invalid version in response (don't retry)
 *   RBOX_ERR_CHECKSUM: checksum mismatch (may retry - corrupted)
 *   RBOX_ERR_MISMATCH: request_id mismatch (may retry - stale response)
 */
rbox_error_t rbox_client_send_request(rbox_client_t *client,
    const char *command, const char *caller, const char *syscall, int argc, const char **argv,
    int env_var_count, const char **env_var_names, const float *env_var_scores,
    rbox_response_t *response);

/* ============================================================
 * SERVER HANDLE
 * ============================================================ */

typedef struct rbox_server rbox_server_t;

/* Create server socket */
rbox_server_t *rbox_server_new(const char *socket_path);

/* Start listening */
rbox_error_t rbox_server_listen(rbox_server_t *server);

/* Get server listen file descriptor */
int rbox_server_fd(const rbox_server_t *server);

/* Accept incoming connection (for non-blocking use) */
rbox_client_t *rbox_server_accept(rbox_server_t *server);

/* Free server */
void rbox_server_free(rbox_server_t *server);

/* ============================================================
 * BLOCKING SERVER INTERFACE (Thread with epoll internally)
 * ============================================================ */

/*
 * Blocking server - uses epoll internally to handle many connections
 * Ideal for Go cgo integration
 *
 * Usage:
 *   1. rbox_server_new() - create server
 *   2. rbox_server_listen() - start listening
 *   3. rbox_server_start() - spawn background thread with epoll
 *   4. rbox_server_get_request() - block until request ready (returns handle)
 *   5. Process request using rbox_server_request_* functions
 *   6. rbox_server_decide() - send response
 *   7. Repeat from step 4
 *   8. rbox_server_stop() - signal shutdown
 *   9. rbox_server_free() - cleanup
 */

/* Opaque server handle for blocking server */
typedef struct rbox_server_handle rbox_server_handle_t;

/* Opaque request handle - returned when request is ready */
typedef struct rbox_server_request rbox_server_request_t;

/* Create blocking server socket */
//export rbox_server_handle_new
rbox_server_handle_t *rbox_server_handle_new(const char *socket_path);

/* Start listening */
//export rbox_server_handle_listen
rbox_error_t rbox_server_handle_listen(rbox_server_handle_t *server);

/* Free blocking server */
//export rbox_server_handle_free
void rbox_server_handle_free(rbox_server_handle_t *server);

/* Start background thread with epoll
 * After calling, background thread accepts connections
 * Returns immediately (non-blocking)
 */
//export rbox_server_start
rbox_error_t rbox_server_start(rbox_server_handle_t *server);

/*
 * Block until a request is ready
 *
 * Returns request handle when request is fully read and parsed.
 * Zero-copy access to request data and shell parse result.
 *
 * Call rbox_server_decide() to send response.
 * Then call rbox_server_get_request() again for next request.
 *
 * Returns: request handle, or NULL on error / shutdown
 */
//export rbox_server_get_request
rbox_server_request_t *rbox_server_get_request(rbox_server_handle_t *server);

/* Check if server is still running
 * Returns: 1 if running, 0 if stopped
 */
int rbox_server_is_running(rbox_server_handle_t *server);

/* Get command from request (zero-copy) */
//export rbox_server_request_command
const char *rbox_server_request_command(const rbox_server_request_t *req);

/* Get argument by index */
//export rbox_server_request_arg
const char *rbox_server_request_arg(const rbox_server_request_t *req, int index);

/* Get argument count */
//export rbox_server_request_argc
int rbox_server_request_argc(const rbox_server_request_t *req);

/* Check if this is a stop request (server is shutting down) */
//export rbox_server_request_is_stop
int rbox_server_request_is_stop(const rbox_server_request_t *req);

/* Get shell parse result from request */
//export rbox_server_request_parse
const rbox_parse_result_t *rbox_server_request_parse(const rbox_server_request_t *req);

/* Get caller from request (null-terminated) */
//export rbox_server_request_caller
const char *rbox_server_request_caller(const rbox_server_request_t *req);

/* Get syscall from request (null-terminated) */
//export rbox_server_request_syscall
const char *rbox_server_request_syscall(const rbox_server_request_t *req);

/* Get flagged env var count from request */
//export rbox_server_request_env_var_count
int rbox_server_request_env_var_count(const rbox_server_request_t *req);

/* Get flagged env var name at index (caller frees) */
//export rbox_server_request_env_var_name
char *rbox_server_request_env_var_name(const rbox_server_request_t *req, int index);

/* Get flagged env var score at index */
//export rbox_server_request_env_var_score
float rbox_server_request_env_var_score(const rbox_server_request_t *req, int index);

/* Free a server request without sending a response
 * This closes the client socket and frees all request resources.
 * Use this if you want to discard the request without responding. */
void rbox_server_request_free(rbox_server_request_t *req);

/*
 * Send decision to client and free request buffers
 *
 * Must be called after get_request() to send the decision back
 * and release the request buffers
 *
 * Extended version with env decisions (v9)
 */
//export rbox_server_decide
rbox_error_t rbox_server_decide(rbox_server_request_t *req,
    uint8_t decision, const char *reason, uint32_t duration,
    int env_decision_count, const char **env_decision_names, const uint8_t *env_decisions);

/*
 * Signal shutdown and wait for background thread to exit
 * After calling stop, get_request() will return NULL
 *
 * Note: Caller should have no active requests when calling stop
 */
//export rbox_server_stop
void rbox_server_stop(rbox_server_handle_t *server);

/* Free server - must be called after stop() */
void rbox_server_free(rbox_server_t *server);


/* ============================================================
 * RESPONSE SENDING
 * ============================================================ */

/* Send response to client */
rbox_error_t rbox_response_send(rbox_client_t *client, const rbox_response_t *response);

/* ============================================================
 * UTILITY FUNCTIONS
 * ============================================================ */

/* Get error string */
//export rbox_strerror
const char *rbox_strerror(rbox_error_t err);

/* Validate packet header */
rbox_error_t rbox_header_validate(const char *packet, size_t len);

/* Calculate CRC32 checksum - composable, prev_crc=0 for fresh start */
uint32_t rbox_calculate_checksum_crc32(uint32_t prev_crc, const void *data, size_t len);

/* 64-bit command hash - two-step hash for time-limited decisions */
uint64_t rbox_hash64(const char *str, size_t len);

/* Initialize library (call once at startup) */
void rbox_init(void);

/* ============================================================
 * BLOCKING CLIENT INTERFACE (All-in-One)
 * ============================================================ */

/* Send request with full retry loop - blocks until valid response
 *
 * This is the simple blocking interface that:
 * - Connects to server (with retry/backoff)
 * - Sends request
 * - Reads response
 * - Validates response (magic, version, request_id match)
 * - Retries on transient errors
 * - Returns only when valid decision received
 *
 * Parameters:
 *   - socket_path: path to server socket
 *   - command: command to execute
 *   - argc: argument count
 *   - argv: argument array
 *   - out_response: caller's pre-allocated response buffer
 *                    On RBOX_OK, contains validated decision and reason
 *   - base_delay_ms: base delay for retry backoff (0 = no retry)
 *   - max_retries: max connection attempts (0 = unlimited)
 *
 * Returns:
 *   RBOX_OK: valid decision in out_response->decision
 *   RBOX_ERR_*: error (out_response not valid)
 */

/* Blocking request - supports flagged env vars for decisions */
rbox_error_t rbox_blocking_request(const char *socket_path,
    const char *command, int argc, const char **argv,
    const char *caller, const char *syscall,
    int env_var_count, const char **env_var_names, const float *env_var_scores,
    rbox_response_t *out_response,
    uint32_t base_delay_ms, uint32_t max_retries);

/* Extended version that returns raw response packet (for --bin mode)
 * Caller must free the returned packet with free()
 * Returns packet starting from magic (includes full header)
 */
//export rbox_blocking_request_raw
rbox_error_t rbox_blocking_request_raw(const char *socket_path,
    const char *command, int argc, const char **argv,
    const char *caller, const char *syscall,
    int env_var_count, const char **env_var_names, const float *env_var_scores,
    char **out_packet, size_t *out_packet_len,
    uint32_t base_delay_ms, uint32_t max_retries);

/* ============================================================
 * RESPONSE PACKET BUILDING (For DFA fast-path and testing)
 * ============================================================ */

/* Build a response packet (allocates memory)
 * Returns: packet in *out_packet, length in *out_len
 * Caller must free the packet with free() */
//export rbox_build_response
rbox_error_t rbox_build_response(
    uint8_t decision, const char *reason, uint32_t duration,
    uint32_t fenv_hash, int env_decision_count, uint8_t *env_decisions,
    char **out_packet, size_t *out_len);

/* Internal: Build response packet (used by server) */
char *rbox_build_response_internal(uint8_t *client_id, uint8_t *request_id, uint32_t cmd_hash,
                           uint8_t decision, const char *reason, uint32_t duration,
                           uint32_t fenv_hash, int env_decision_count, uint8_t *env_decisions,
                           size_t *out_len);

/* ============================================================
 * NON-BLOCKING SESSION INTERFACE (For clients with own poll loop)
 * ============================================================ */

/* Session state machine */
typedef enum {
    RBOX_SESSION_DISCONNECTED = 0,  /* Not connected */
    RBOX_SESSION_CONNECTING,         /* Attempting to connect */
    RBOX_SESSION_CONNECTED,         /* Connected, idle */
    RBOX_SESSION_SENDING,           /* Sending request */
    RBOX_SESSION_WAITING,           /* Waiting for response */
    RBOX_SESSION_RESPONSE_READY,     /* Response ready to read */
    RBOX_SESSION_FAILED,            /* Error occurred */
} rbox_session_state_t;

/* Session object - client manages */
typedef struct rbox_session rbox_session_t;

/* Create new session
 * Parameters:
 *   - socket_path: path to server socket
 *   - base_delay_ms: base delay for connection retry (0 = fail immediately)
 *   - max_retries: max connection attempts (0 = unlimited)
 *
 * Returns: session object or NULL on error */
rbox_session_t *rbox_session_new(const char *socket_path,
    uint32_t base_delay_ms, uint32_t max_retries);

/* Free session
 *
 * IMPORTANT: Read the response BEFORE freeing - see rbox_session_response().
 * This function disconnects automatically and frees all resources.
 * After calling, the session pointer is invalid. */
void rbox_session_free(rbox_session_t *session);

/* Get file descriptor for poll() and required events
 *
 * Parameters:
 *   - session: the session
 *   - out_events: pointer to store required poll events (can be NULL)
 *
 * Returns: fd to poll on, or -1 if not connected/idle
 *
 * The client should poll on the returned fd with the events:
 *   - POLLOUT: when connecting or sending
 *   - POLLIN: when waiting for response
 *
 * Example usage:
 *   short events;
 *   int fd = rbox_session_pollfd(session, &events);
 *   if (fd >= 0) {
 *       struct pollfd pfd = { .fd = fd, .events = events };
 *       poll(&pfd, 1, timeout);
 *       rbox_session_heartbeat(session, pfd.revents);
 *   }
 */
int rbox_session_pollfd(const rbox_session_t *session, short *out_events);

/* Get current session state */
rbox_session_state_t rbox_session_state(const rbox_session_t *session);

/* Get last error code (valid when state is FAILED) */
rbox_error_t rbox_session_error(const rbox_session_t *session);

/* Start a new request
 *
 * Call this when session is in CONNECTED state to initiate a request.
 * After calling, poll for POLLOUT, then call rbox_session_heartbeat().
 *
 * Returns:
 *   RBOX_OK: request sent, state -> WAITING
 *   RBOX_ERR_INVALID: wrong state or null params
 *   RBOX_ERR_IO: send failed (state -> FAILED)
 *
 * caller and syscall: optional caller identification (truncated to 15 chars each) */
rbox_error_t rbox_session_send_request(rbox_session_t *session,
    const char *command, const char *caller, const char *syscall,
    int argc, const char **argv,
    int env_var_count, const char **env_var_names, const float *env_var_scores);

/* Session heartbeat - call when fd is ready
 *
 * Call this when poll() indicates the fd is ready:
 * - POLLOUT: socket ready for writing (connect or send)
 * - POLLIN: data available to read
 *
 * This function advances the state machine and returns the new state.
 *
 * Returns: current state after processing */
rbox_session_state_t rbox_session_heartbeat(rbox_session_t *session, short events);

/* Get response (valid when state is RESPONSE_READY)
 *
 * The response is validated (magic, version, request_id match).
 *
 * IMPORTANT: Call this BEFORE disconnecting or freeing the session.
 * The response is only accessible while in RESPONSE_READY state.
 * After calling this, you must call rbox_session_reset() to start a new request,
 * or call rbox_session_free() to clean up.
 *
 * Returns: pointer to response, or NULL if not in RESPONSE_READY state
 *
 * NOTE: The returned pointer points to memory owned by the session object.
 * Do not free this pointer - it will be freed when rbox_session_free() is called. */
const rbox_response_t *rbox_session_response(const rbox_session_t *session);

/* Reset session to connected state for next request
 *
 * Call this after reading the response to start a new request.
 * This must be called before sending another request.
 *
 * State transitions: RESPONSE_READY -> CONNECTED */
void rbox_session_reset(rbox_session_t *session);

/* Force disconnect
 *
 * Closes connection and resets to DISCONNECTED state.
 * Note: Response must be read BEFORE calling this - see rbox_session_response().
 *
 * After disconnecting, you can call rbox_session_connect() to reconnect,
 * or call rbox_session_free() to clean up. */
void rbox_session_disconnect(rbox_session_t *session);

/* Attempt to connect (for non-blocking start)
 *
 * Call this to initiate connection. Then poll for POLLOUT
 * and call heartbeat().
 *
 * Returns:
 *   RBOX_OK: connection in progress, state -> CONNECTING
 *   RBOX_ERR_IO: failed to start connect */
rbox_error_t rbox_session_connect(rbox_session_t *session);

/* Build request packet (v9 protocol)
 * Parameters:
 *   - packet: output buffer
 *   - capacity: size of output buffer
 *   - out_len: actual packet length written
 * Returns packet length in *out_len
 * Data format: header + command\0caller\0syscall\0argv[0]\0argv[1]\0...\0 */
rbox_error_t rbox_build_request(char *packet, size_t capacity, size_t *out_len,
                               const char *command, const char *caller, const char *syscall,
                               int argc, const char **argv,
                               int env_var_count, const char **env_var_names, const float *env_var_scores);

/* ============================================================
 * NON-BLOCKING SOCKET I/O
 * ============================================================ */

/* Read with timeout (uses poll internally, never blocks)
 * Returns bytes read, 0 on peer close, -1 on error
 * Handles partial reads automatically */
ssize_t rbox_read(int fd, void *buf, size_t len);

/* Write with timeout (uses poll internally, never blocks)
 * Returns bytes written, -1 on error
 * Handles partial writes automatically */
ssize_t rbox_write(int fd, const void *buf, size_t len);

/* Read exactly N bytes (non-blocking, with timeout)
 * Returns bytes read (equals len on success), 0 on close, -1 on error */
ssize_t rbox_read_exact(int fd, void *buf, size_t len);

/* Write exactly N bytes (non-blocking, with timeout)
 * Returns bytes written (equals len on success), -1 on error */
ssize_t rbox_write_exact(int fd, const void *buf, size_t len);

/* Non-blocking write - writes what it can, returns immediately
 * Returns: bytes written (0 if no data could be written), -1 on error
 * Use io_offset to track position across calls for partial writes */
ssize_t rbox_write_nonblocking(int fd, const void *buf, size_t len, size_t *io_offset);

/* Check if socket is ready for reading (non-blocking poll)
 * Returns: 1 if ready, 0 if not ready, -1 on error */
int rbox_pollin(int fd, int timeout_ms);

/* Check if socket is ready for writing (non-blocking poll)
 * Returns: 1 if ready, 0 if not ready, -1 on error */
int rbox_pollout(int fd, int timeout_ms);

/* ============================================================
 * SHELL PARSING (Zero-Copy via shellsplit)
 * ============================================================ */

/* Max subcommands we support */
#define RBOX_MAX_SUBCOMMANDS SHELL_MAX_SUBCOMMANDS

/* Subcommand (references original buffer) */
typedef struct {
    uint32_t start;      /* Offset into command string */
    uint32_t len;        /* Length */
    uint16_t type;       /* shell_cmd_type_t */
    uint16_t features;   /* shell_cmd_features_t */
} rbox_subcommand_t;

/* Parse result */
typedef struct rbox_parse_result {
    rbox_subcommand_t subcommands[RBOX_MAX_SUBCOMMANDS];
    uint32_t count;           /* Number of subcommands */
    uint32_t has_variables;   /* Contains variables like $VAR */
    uint32_t truncated;        /* Hit limits, may have more */
    size_t cmd_len;          /* Original command length (for bounds checking) */
} rbox_parse_result_t;

/* Parse command into subcommands (zero-copy) */
rbox_error_t rbox_command_parse(const char *command, size_t cmd_len,
                                rbox_parse_result_t *result);

/* Get subcommand pointer (not null-terminated) */
const char *rbox_get_subcommand(const char *command,
                                const rbox_subcommand_t *sub,
                                uint32_t *out_len);

/* Get subcommand as null-terminated string (caller must free) */
char *rbox_dup_subcommand(const char *command, const rbox_subcommand_t *sub);

/* Get command name from parse result */
const char *rbox_get_command_name(const char *command,
                                   const rbox_parse_result_t *parse);

#endif /* RBOX_PROTOCOL_H */
