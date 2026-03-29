/*
 * readonlybox-client protocol definitions
 *
 * Protocol for communication between LD_PRELOAD client and server.
 * Uses request/response IDs for multiplexing over a single socket.
 */

#ifndef READONLYBOX_PROTOCOL_H
#define READONLYBOX_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

/* Protocol magic bytes - "ROBO" = ReadOnlyBox */
#define ROBO_MAGIC      0x524F424F
#define ROBO_VERSION    1

/* Protocol constants */
#define ROBO_MAX_CMD    256
#define ROBO_MAX_ARGS   64
#define ROBO_MAX_ENV    256
#define ROBO_MAX_PATH   1024

/* Decision codes */
#define ROBO_DECISION_UNKNOWN  0
#define ROBO_DECISION_LOG      1
#define ROBO_DECISION_ALLOW    2
#define ROBO_DECISION_DENY     3
#define ROBO_DECISION_ERROR    4

/* Request/response packet structures */
typedef struct {
    uint32_t magic;      /* ROBO_MAGIC */
    uint32_t id;         /* Request ID */
    uint32_t argc;       /* Argument count */
    uint32_t envc;       /* Environment count */
    /* Followed by: cmd\0, arg0\0, arg1\0, ..., env0\0, env1\0, ... */
} __attribute__((packed)) robo_request_header_t;

typedef struct {
    uint32_t magic;      /* ROBO_MAGIC */
    uint32_t id;         /* Request ID (matches request) */
    uint8_t  decision;   /* ROBO_DECISION_* */
    uint8_t  reserved[3]; /* Padding */
    uint32_t reason_len; /* Length of reason string (0 if none) */
    /* Followed by: reason\0 (if reason_len > 0) */
} __attribute__((packed)) robo_response_header_t;

/* Connection state */
typedef enum {
    ROBO_STATE_DISCONNECTED = 0,
    ROBO_STATE_CONNECTING,
    ROBO_STATE_CONNECTED,
    ROBO_STATE_ERROR
} robo_state_t;

/* Configuration for the client */
typedef struct {
    char socket_path[ROBO_MAX_PATH];
    uint32_t reconnect_delay_ms;
    uint32_t max_reconnect_attempts;
    uint8_t debug_enabled;
} robo_config_t;

/* Request in the pending queue */
typedef struct robo_request {
    uint32_t id;
    char cmd[ROBO_MAX_CMD];
    char **argv;
    int argc;
    char **envp;
    int envc;
    uint8_t decision;
    char reason[256];
    int complete;
    void *user_data;
    struct robo_request *next;
} robo_request_t;

/* Response handler callback */
typedef void (*robo_response_cb_t)(uint32_t id, uint8_t decision, const char *reason, void *user_data);

/* Initialize the client library */
int robo_client_init(const char *socket_path);

/* Shutdown the client library */
void robo_client_shutdown(void);

/* Check if connected to server */
int robo_client_connected(void);

/* Send a request and wait for response (blocking) */
int robo_client_send_request(
    const char *cmd,
    char *const argv[],
    char *const envp[],
    uint8_t *out_decision,
    char *out_reason,
    size_t reason_size,
    int timeout_ms
);

/* Non-blocking request with callback */
int robo_client_send_request_async(
    const char *cmd,
    char *const argv[],
    char *const envp[],
    robo_response_cb_t callback,
    void *user_data
);

/* Process pending responses (call from main thread) */
int robo_client_poll(void);

/* Get last error message */
const char *robo_client_last_error(void);

/* Set configuration */
void robo_client_set_config(const robo_config_t *config);

/* Get current configuration */
void robo_client_get_config(robo_config_t *config);

#endif /* READONLYBOX_PROTOCOL_H */
