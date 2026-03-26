/*
 * session.h - Client session state machine for rbox-protocol
 *
 * Layer 3: Client session state machine
 * - Non-blocking client interface for poll()/epoll()-based applications
 */

#ifndef RBOX_SESSION_H
#define RBOX_SESSION_H

#include <stdint.h>
#include <sys/types.h>
#include <rbox_protocol.h>

/* Session object - client manages */
typedef struct rbox_session rbox_session_t;

/* Create new session
 * Parameters:
 *   - socket_path: path to server socket
 *   - base_delay_ms: base delay for connection retry (0 = fail immediately)
 *   - max_retries: max connection attempts (0 = unlimited)
 * Returns: session object or NULL on error */
rbox_session_t *rbox_session_new(const char *socket_path,
    uint32_t base_delay_ms, uint32_t max_retries);

/* Free session
 * IMPORTANT: Read the response BEFORE freeing - see rbox_session_response().
 * This function disconnects automatically and frees all resources. */
void rbox_session_free(rbox_session_t *session);

/* Get file descriptor for poll() and required events
 * Returns: fd to poll on, or -1 if not connected/idle
 * Output events: POLLOUT when connecting or sending, POLLIN when waiting */
int rbox_session_pollfd(const rbox_session_t *session, short *out_events);

/* Get current session state */
rbox_session_state_t rbox_session_state(const rbox_session_t *session);

/* Get last error code (valid when state is FAILED) */
rbox_error_t rbox_session_error(const rbox_session_t *session);

/* Start a new request
 * Call when session is in CONNECTED state to initiate a request.
 * After calling, poll for POLLOUT, then call rbox_session_heartbeat().
 * Returns: RBOX_OK, RBOX_ERR_INVALID, or RBOX_ERR_IO */
rbox_error_t rbox_session_send_request(rbox_session_t *session,
    const char *command, const char *caller, const char *syscall,
    int argc, const char **argv,
    int env_var_count, const char **env_var_names, const float *env_var_scores);

/* Session heartbeat - call when fd is ready
 * Call this when poll() indicates the fd is ready.
 * Returns: current state after processing */
rbox_session_state_t rbox_session_heartbeat(rbox_session_t *session, short events);

/* Get response (valid when state is RESPONSE_READY)
 * IMPORTANT: Call this BEFORE disconnecting or freeing the session.
 * The response is only accessible while in RESPONSE_READY state. */
const rbox_response_t *rbox_session_response(const rbox_session_t *session);

/* Reset session to connected state for next request
 * State transitions: RESPONSE_READY -> CONNECTED */
void rbox_session_reset(rbox_session_t *session);

/* Force disconnect
 * Closes connection and resets to DISCONNECTED state.
 * Note: Response must be read BEFORE calling this. */
void rbox_session_disconnect(rbox_session_t *session);

/* Attempt to connect (for non-blocking start)
 * Call this to initiate connection. Then poll for POLLOUT
 * and call heartbeat().
 * Returns: RBOX_OK or RBOX_ERR_IO */
rbox_error_t rbox_session_connect(rbox_session_t *session);

#endif /* RBOX_SESSION_H */