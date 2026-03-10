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
} rbox_error_t;

/* ============================================================
 * REQUEST/RESPONSE STRUCTURES
 * ============================================================ */

/* Request structure - owns its data */
typedef struct {
    rbox_header_t    header;
    char            *data;       /* Raw data (args + env, null-separated) */
    size_t           data_len;  /* Length of data */
    
    /* Parsed fields (point into data) */
    char            *command;    /* Command name */
    char          **argv;       /* Arguments (array of pointers into data) */
    int              argv_len;  /* Number of arguments */
    char          **envp;       /* Environment (array of pointers into data) */
    int              envp_len;  /* Number of env vars */
} rbox_request_t;

/* Response structure */
typedef struct {
    uint8_t decision;   /* ALLOW/DENY/ERROR */
    char     reason[256];  /* Reason string */
    uint32_t duration;    /* Duration in seconds (0 = once) */
} rbox_response_t;

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

/* ============================================================
 * SERVER HANDLE  
 * ============================================================ */

typedef struct rbox_server rbox_server_t;

/* Create server socket */
rbox_server_t *rbox_server_new(const char *socket_path);

/* Start listening */
rbox_error_t rbox_server_listen(rbox_server_t *server);

/* Accept incoming connection */
rbox_client_t *rbox_server_accept(rbox_server_t *server);

/* Get server listen file descriptor */
int rbox_server_fd(const rbox_server_t *server);

/* Free server */
void rbox_server_free(rbox_server_t *server);

/* ============================================================
 * REQUEST PARSING
 * ============================================================ */

/* Read request from client (blocks) */
rbox_error_t rbox_request_read(rbox_client_t *client, rbox_request_t *request);

/* Free request data */
void rbox_request_free(rbox_request_t *request);

/* Get command from request (zero-copy) */
const char *rbox_request_get_command(const rbox_request_t *req);

/* Get argument by index */
const char *rbox_request_get_arg(const rbox_request_t *req, int index);

/* ============================================================
 * RESPONSE SENDING
 * ============================================================ */

/* Send response to client */
rbox_error_t rbox_response_send(rbox_client_t *client, const rbox_response_t *response);

/* ============================================================
 * CHUNKED TRANSFER (Large Packet Support)
 * ============================================================ */

/* Stream state for chunked transfers */
typedef struct rbox_stream rbox_stream_t;

/* Create a new stream for chunked sending */
rbox_stream_t *rbox_stream_new(const uint8_t *client_id, const uint8_t *request_id);

/* Free stream */
void rbox_stream_free(rbox_stream_t *stream);

/* Send chunk to server 
 * Returns offset where chunk was placed in buffer
 */
rbox_error_t rbox_stream_send_chunk(rbox_client_t *client, rbox_stream_t *stream,
                                    const void *data, size_t len,
                                    uint32_t flags, uint64_t total_len);

/* Read ACK from server
 * Updates stream->offset on success
 */
rbox_error_t rbox_stream_read_ack(rbox_client_t *client, rbox_stream_t *stream);

/* Get current stream offset */
uint64_t rbox_stream_offset(const rbox_stream_t *stream);

/* Server: Create stream state for incoming chunks */
rbox_stream_t *rbox_server_stream_new(const uint8_t *client_id, const uint8_t *request_id,
                                       uint64_t total_len);

/* Server: Receive a chunk
 * Returns chunk data and validates offset
 */
rbox_error_t rbox_server_stream_recv(rbox_client_t *client, rbox_stream_t *stream,
                                     void *buffer, size_t buf_size,
                                     size_t *out_chunk_len);

/* Server: Send ACK to client */
rbox_error_t rbox_server_stream_ack(rbox_client_t *client, rbox_stream_t *stream,
                                    int32_t status, const char *reason);

/* Server: Complete stream and get final request data */
rbox_error_t rbox_server_stream_complete(rbox_stream_t *stream,
                                         rbox_request_t *out_request);

/* ============================================================
 * UTILITY FUNCTIONS
 * ============================================================ */

/* Get error string */
const char *rbox_strerror(rbox_error_t err);

/* Validate packet header */
rbox_error_t rbox_header_validate(const rbox_header_t *header);

/* Calculate header checksum */
uint32_t rbox_calculate_checksum(const void *data, size_t len);

/* Initialize library (call once at startup) */
void rbox_init(void);

/* Build request packet (v5 protocol)
 * Returns packet length in *out_len
 * Data format: header + command\0 + args...\0 */
rbox_error_t rbox_build_request(char *packet, size_t *out_len,
                               const char *command, int argc, const char **argv);

/* Parse response packet
 * Returns decision in *out_decision
 * Returns 0 on success */
int rbox_parse_response(const char *packet, size_t len, uint8_t *out_decision);

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
typedef struct {
    rbox_subcommand_t subcommands[RBOX_MAX_SUBCOMMANDS];
    uint32_t count;           /* Number of subcommands */
    uint32_t has_variables;   /* Contains variables like $VAR */
    uint32_t truncated;        /* Hit limits, may have more */
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
