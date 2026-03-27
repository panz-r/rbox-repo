/*
 * server_internal.h - Internal server structures for rbox-protocol
 *
 * This file contains the server handle and request structures that are
 * defined in packet.c but needed by server.c
 */

#ifndef RBOX_SERVER_INTERNAL_H
#define RBOX_SERVER_INTERNAL_H

#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>

/* Response cache entry type - must be defined before use */
#define RBOX_RESPONSE_CACHE_SIZE 128

/* Server response cache entry */
typedef struct {
    uint8_t request_id[16];       /* Request ID from client */
    uint8_t client_id[16];         /* Client ID */
    uint32_t packet_checksum;      /* Full packet checksum for once decisions */
    uint32_t cmd_hash;             /* Command hash for verification */
    uint64_t cmd_hash2;            /* Second command hash for verification */
    uint32_t fenv_hash;            /* Hash of flagged env var names */
    uint64_t fenv_hash2;           /* Second hash of flagged env vars */
    uint8_t decision;             /* ALLOW/DENY/ERROR */
    char reason[256];              /* Reason string */
    uint32_t duration;             /* Duration in seconds */
    time_t timestamp;             /* When cached */
    time_t expires_at;            /* When this entry expires (0 = never) */
    int valid;                     /* 1 if entry is valid */
} rbox_response_cache_entry_t;

/* Decision queue for thread-safe decision passing */
typedef struct rbox_server_decision {
    rbox_server_request_t *request;
    uint8_t decision;
    char reason[256];
    uint32_t duration;
    int ready;  /* 1 if decision is ready */

    /* Env decisions (v9) */
    uint32_t fenv_hash;
    int env_decision_count;
    char **env_decision_names;
    uint8_t *env_decisions;  /* bitmap: bit i = decision for env var i */

    struct rbox_server_decision *next;
} rbox_server_decision_t;

/* Send queue entry - for outgoing responses */
typedef struct rbox_server_send_entry {
    int fd;                        /* Socket to send to */
    char *data;                    /* Response packet data */
    size_t len;                    /* Response length */
    size_t offset;
    struct rbox_server_send_entry *next;
    rbox_server_request_t *request;  /* Associated request to free after send */
} rbox_server_send_entry_t;

/* Forward declaration */
typedef struct rbox_server_handle rbox_server_handle_t;

/* Server request handle */
struct rbox_server_request {
    int fd;                         /* Client socket fd */
    uint8_t client_id[16];          /* Client identifier */
    uint8_t request_id[16];         /* Request identifier */
    uint32_t cmd_hash;              /* Command hash for verification */
    rbox_server_handle_t *server;   /* Back-pointer to server */

    /* Caller/syscall  (truncated to 15 chars, no null) */
    char caller[RBOX_MAX_CALLER_LEN + 1];   /* Null-terminated */
    char syscall[RBOX_MAX_SYSCALL_LEN + 1]; /* Null-terminated */

    /* Request data (owned by request, freed on decide) */
    char *command_data;
    size_t command_len;
    rbox_parse_result_t parse;

    /* Flagged env vars */
    int env_var_count;
    char **env_var_names;
    float *env_var_scores;
    uint32_t fenv_hash;

    /* Body reading state for non-blocking reads */
    int reading_body;               /* 1 if waiting for body data */
    size_t body_expected;          /* Total body bytes expected */
    size_t body_received;           /* Bytes received so far */

    /* Chunked transfer state */
    int is_chunked;                 /* 1 if this is a chunked transfer */
    int reading_chunk_header;       /* 1 if expecting a chunk header (for chunked) */
    uint32_t current_chunk_len;     /* Size of the current chunk being read */
    uint32_t current_chunk_received;/* Bytes of current chunk already read */
    uint32_t last_flags;            /* Flags from most recent chunk header (RBOX_FLAG_LAST) */

    /* Queue link */
    struct rbox_server_request *next;
};

typedef struct rbox_server_request rbox_server_request_t;

/* Client fd list entry */
typedef struct rbox_client_fd_entry {
    int fd;
    rbox_server_request_t *pending_request;  /* Non-null if body is being read */
    time_t header_start_time;                /* When we started waiting for header */
    int waiting_for_header;                 /* 1 if we are in header read timeout state */
    struct rbox_client_fd_entry *next;
} rbox_client_fd_entry_t;

/* Server handle */
struct rbox_server_handle {
    char socket_path[256];
    int listen_fd;
    int epoll_fd;

    /* Background thread */
    pthread_t thread;
    atomic_int running;            /* Atomic flag to signal shutdown */
    atomic_flag stop_flag;         /* Atomic flag - only one stop() wins */
    int wake_fd;                   /* eventfd to wake epoll thread */

    /* Send queue for outgoing responses (mutex protected) */
    pthread_mutex_t send_mutex;
    rbox_server_send_entry_t *send_queue;  /* Queue head */
    rbox_server_send_entry_t *send_tail;   /* Queue tail */
    int send_count;

    /* Response cache (fixed 128 entries) */
    rbox_response_cache_entry_t response_cache[RBOX_RESPONSE_CACHE_SIZE];
    int response_cache_next;       /* Next index to replace (round-robin) */
    pthread_mutex_t cache_mutex;   /* Protects response cache */

    /* Request queue (mutex protected) */
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    rbox_server_request_t *request_queue;  /* Queue head */
    rbox_server_request_t *request_tail;   /* Queue tail */
    int request_count;

    /* Decision queue (mutex protected) */
    pthread_mutex_t decision_mutex;
    pthread_cond_t decision_cond;
    rbox_server_decision_t *decision_queue;  /* Queue head */
    rbox_server_decision_t *decision_tail;   /* Queue tail */
    int decision_count;

    pthread_mutex_t client_fd_mutex;
    rbox_client_fd_entry_t *client_fds;
    int active_client_count; /* Number of active clients */
};

#endif /* RBOX_SERVER_INTERNAL_H */
