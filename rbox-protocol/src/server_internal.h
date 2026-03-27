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
    uint64_t fenv_hash2;
    uint32_t key_hash;            /* precomputed for quick lookup */

    /* value fields */
    uint8_t decision;
    char reason[256];
    uint32_t duration;
    time_t timestamp;
    time_t expires_at;

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
    struct rbox_client_fd_entry *prev;       /* Previous entry in doubly-linked list */
    struct rbox_client_fd_entry *next;       /* Next entry in doubly-linked list */
    rbox_server_send_entry_t *send_queue_head; /* Per-client send queue head */
    rbox_server_send_entry_t *send_queue_tail; /* Per-client send queue tail */
} rbox_client_fd_entry_t;

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

    /* Send queue mutex (for thread-safe access to per-client queues) */
    pthread_mutex_t send_mutex;

    /* Response cache (hash table with LRU) */
    rbox_response_cache_t cache;
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
