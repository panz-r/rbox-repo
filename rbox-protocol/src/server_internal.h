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
#include "rbox_protocol_defs.h"
#include "protocol.h"
#include "rbox_protocol.h"

/* Forward declaration */
typedef struct rbox_server_request rbox_server_request_t;
typedef struct rbox_server_handle rbox_server_handle_t;

/* Response cache configuration */
#define RBOX_RESPONSE_CACHE_SIZE 256
#define RBOX_CACHE_SLOT_EMPTY 0
#define RBOX_CACHE_SLOT_OCCUPIED 1
#define RBOX_CACHE_SLOT_TOMBSTONE 2

/* Server response cache entry - used in open-addressing hash table with LRU */
typedef struct rbox_response_cache_entry {
    /* key fields */
    uint8_t client_id[16];
    uint8_t request_id[16];
    uint32_t packet_checksum;
    uint32_t cmd_hash;
    uint64_t cmd_hash2;
    uint32_t fenv_hash;
    uint32_t key_hash;            /* precomputed hash for quick mismatch detection */

    /* value fields */
    uint8_t decision;
    char reason[256];
    uint32_t duration;
    time_t timestamp;
    time_t expires_at;

    /* Env decisions (v9) */
    int env_decision_count;
    uint8_t *env_decisions;       /* bitmap: bit i = decision for env var i */

    /* LRU list pointers */
    struct rbox_response_cache_entry *lru_prev;
    struct rbox_response_cache_entry *lru_next;
} rbox_response_cache_entry_t;

/* Hash table cache structure with LRU eviction */
typedef struct {
    rbox_response_cache_entry_t *slots[RBOX_RESPONSE_CACHE_SIZE];
    uint8_t slot_state[RBOX_RESPONSE_CACHE_SIZE];
    int tombstone_count;
    rbox_response_cache_entry_t *lru_head;
    rbox_response_cache_entry_t *lru_tail;
    int count;
} rbox_response_cache_t;

/* Decision queue for thread-safe decision passing */
typedef struct rbox_server_decision {
    rbox_server_request_t *request;
    uint8_t decision;
    char reason[256];
    uint32_t duration;

    /* Env decisions (v9) */
    uint32_t fenv_hash;
    int env_decision_count;
    uint8_t *env_decisions;  /* bitmap: bit i = decision for env var i */

    struct rbox_server_decision *next;
} rbox_server_decision_t;

/* Lock-free MPSC queue node (Michael & Scott algorithm) */
typedef struct rbox_decision_node {
    rbox_server_decision_t *decision;
    _Atomic(struct rbox_decision_node *) next;
} rbox_decision_node_t;

/* Lock-free MPSC queue structure */
typedef struct {
    _Atomic(rbox_decision_node_t *) head;
    _Atomic(rbox_decision_node_t *) tail;
} rbox_decision_queue_t;

/* Lock-free MPSC request queue node (Michael & Scott algorithm) */
typedef struct rbox_request_node {
    rbox_server_request_t *request;
    _Atomic(struct rbox_request_node *) next;
} rbox_request_node_t;

/* Lock-free MPSC request queue structure */
typedef struct {
    _Atomic(rbox_request_node_t *) head;
    _Atomic(rbox_request_node_t *) tail;
} rbox_request_queue_t;

/* Send queue entry - for outgoing responses */
typedef struct rbox_server_send_entry {
    int fd;                        /* Socket to send to */
    char *data;                    /* Response packet data (points to internal_buf or malloc'd) */
    size_t len;                    /* Response length */
    size_t offset;
    rbox_server_request_t *request;  /* Associated request to free after send */
    char internal_buf[512];        /* Inline buffer for small responses */
    int using_internal_buf;        /* 1 if data points to internal_buf */
    uint8_t decision;              /* Decision type for telemetry tracking */
    struct rbox_server_send_entry *next; /* Free list link */
} rbox_server_send_entry_t;

/* Lock-free MPSC send queue node (Michael & Scott algorithm) */
typedef struct rbox_send_node {
    rbox_server_send_entry_t *entry;
    _Atomic(struct rbox_send_node *) next;
} rbox_send_node_t;

/* Lock-free MPSC send queue structure */
typedef struct {
    _Atomic(rbox_send_node_t *) head;
    _Atomic(rbox_send_node_t *) tail;
} rbox_send_queue_t;

/* Forward declaration */
typedef struct rbox_server_handle rbox_server_handle_t;

/*
 * Zero-Copy Request Body Design:
 * --------------------------------
 * The server reads request bodies directly into the final `command_data` buffer
 * without any intermediate copies:
 *
 * - For single-chunk requests: command_data is allocated with exact size needed
 *   (malloc(chunk_len + 1)), and data is read directly into it via rbox_read_nonblocking().
 *
 * - For chunked requests: command_data is allocated upfront with total_len + 1 bytes
 *   (validated against RBOX_MAX_TOTAL_SIZE), and each chunk is read directly into
 *   the appropriate offset within command_data.
 *
 * The buffer is freed only when the request is processed (via server_request_free()).
 * No temporary buffers or intermediate copies are used in the production code path.
 */

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

    /* Flagged env vars - pointers into command_data, no copies */
    int env_var_count;
    const char **env_var_names;
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
    uint32_t current_chunk_checksum;/* Expected body_checksum for current chunk */
    uint32_t last_flags;            /* Flags from most recent chunk header (RBOX_FLAG_LAST) */

    /* Internal buffer for small requests (reduces allocation overhead) */
    char internal_buf[4096];
    int using_internal_buf;         /* 1 if command_data points to internal_buf */

    /* Queue link / free list link */
    struct rbox_server_request *next;
};

typedef struct rbox_server_request rbox_server_request_t;

/* Client fd list entry */
typedef struct rbox_client_fd_entry {
    int fd;
    rbox_server_request_t *pending_request;  /* Non-null if body is being read */
    time_t header_start_time;                /* When we started waiting for header */
    time_t body_start_time;                 /* When we started reading body */
    int waiting_for_header;                 /* 1 if we are in header read timeout state */
    time_t last_activity;                   /* Last read/write activity time */
    char header_buf[RBOX_HEADER_SIZE];      /* Partial header buffer for incremental reads */
    size_t header_bytes_read;              /* Bytes of header currently in buffer */
    struct rbox_client_fd_entry *prev;       /* Previous entry in doubly-linked list */
    struct rbox_client_fd_entry *next;       /* Next entry in doubly-linked list */
    rbox_send_queue_t send_queue;           /* Lock-free MPSC send queue */
} rbox_client_fd_entry_t;

/* Request pool - simple free list (NOT thread-safe)
 * NOTE: This pool is used exclusively from the server thread.
 * All access is from server_thread_func - no external threads
 * access this pool, so no atomic operations or locking needed. */
#define RBOX_REQUEST_POOL_SIZE 10
typedef struct rbox_request_pool {
    rbox_server_request_t *free_list;
    size_t available;
    size_t max_requests;
} rbox_request_pool_t;

/* Request pool functions */
int request_pool_init(rbox_server_handle_t *server, size_t max_requests);
rbox_server_request_t *request_pool_get(rbox_server_handle_t *server);
void request_pool_put(rbox_server_handle_t *server, rbox_server_request_t *req);
void request_pool_destroy(rbox_server_handle_t *server);

/* Send entry pool - simple free list (NOT thread-safe)
 * NOTE: This pool is used exclusively from the server thread.
 * All access is from server_thread_func - no external threads
 * access this pool, so no atomic operations or locking needed. */
#define RBOX_SEND_POOL_SIZE 10
typedef struct rbox_send_pool {
    rbox_server_send_entry_t *free_list;
    size_t available;
    size_t max_entries;
} rbox_send_pool_t;

/* Send pool functions */
int send_pool_init(rbox_server_handle_t *server, size_t max_entries);
rbox_server_send_entry_t *send_pool_get(rbox_server_handle_t *server);
void send_pool_put(rbox_server_handle_t *server, rbox_server_send_entry_t *entry);
void send_pool_destroy(rbox_server_handle_t *server);

/* Lock-free send queue functions */
int send_queue_enqueue(rbox_client_fd_entry_t *client, rbox_server_send_entry_t *entry);
rbox_server_send_entry_t *send_queue_dequeue(rbox_client_fd_entry_t *client);

/* Epoll helper (used by server_client.c) */
int epoll_del(int epoll_fd, int fd);

/* Free server request - returns to pool if from pool, otherwise frees */
void server_request_free(rbox_server_request_t *req);

/* Find client fd entry by fd (used by server_response.c) */
rbox_client_fd_entry_t *client_fd_find(rbox_server_handle_t *server, int fd);

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

    /* Response cache (hash table with LRU) */
    rbox_response_cache_t cache;
    pthread_mutex_t cache_mutex;   /* Protects response cache */

    /* Request queue - lock-free MPSC (Michael & Scott) */
    rbox_request_queue_t request_queue;
    int request_wake_fd;          /* eventfd to wake consumers */

    /* Decision queue - lock-free MPSC (Michael & Scott) */
    rbox_decision_queue_t decision_queue;

    /* Request pool - lock-free free list for reduced allocation overhead */
    rbox_request_pool_t request_pool;

    /* Send entry pool - lock-free free list for reduced allocation overhead */
    rbox_send_pool_t send_pool;

    pthread_mutex_t client_fd_mutex;
    rbox_client_fd_entry_t *client_fds;
    int active_client_count; /* Number of active clients */

    /* Telemetry counters */
    atomic_uint telemetry_allow_queued;
    atomic_uint telemetry_deny_queued;
    atomic_uint telemetry_allow_sent;
    atomic_uint telemetry_deny_sent;

    /* Connection limits and timeouts */
    int max_clients;               /* 0 = unlimited */
    int client_idle_timeout;       /* seconds, 0 = disabled */
    int request_timeout;           /* seconds, 0 = disabled */
};

#endif /* RBOX_SERVER_INTERNAL_H */
