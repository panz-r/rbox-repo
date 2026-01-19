/*
 * libreadonlybox_client.so - LD_PRELOAD client for command interception
 *
 * Simple synchronous design:
 * - Each execve interception sends request to server, waits for response
 * - Single persistent connection reused for all requests
 * - Automatic reconnection on socket death
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/select.h>

#include "dfa.h"

/* Protocol constants */
#define ROBO_MAGIC      0x524F424F
#define ROBO_VERSION    3  /* Protocol version */
#define ROBO_CLIENT_VERSION "1.0.0"

/* Message types - distinguished by ID field */
#define ROBO_MSG_LOG    0  /* Log message from client */
#define ROBO_MSG_REQ    1  /* Command request from client */

/* Decision codes (from server response) */
#define ROBO_DECISION_UNKNOWN  0
#define ROBO_DECISION_ALLOW    2
#define ROBO_DECISION_DENY     3
#define ROBO_DECISION_ERROR    4

/* Configuration */
static char g_socket_path[1024] = "/tmp/readonlybox.sock";
static int g_socket_fd = -1;
static pthread_mutex_t g_socket_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct timeval g_recv_timeout = {30, 0}; /* 30 second timeout for recv */
static struct timeval g_conn_timeout = {5, 0}; /* 5 second timeout for connect */
static FILE *g_logfile = NULL;
static int g_verbose_logging = 1; /* Verbose logging enabled by default */

/* UUIDs for request matching across reconnects */
static unsigned char g_client_uuid[16];
static unsigned char g_request_uuid[16];

/* Time-limited decision cache using CLOCK_BOOTTIME */
#define MAX_DECISION_CACHE_SIZE 128

static struct {
    char cmd[256];           /* Command string (e.g., "vim.tiny --version") */
    uint8_t decision;        /* ROBO_DECISION_ALLOW or ROBO_DECISION_DENY */
    int64_t expires_ns;      /* Expiry time in nanoseconds (CLOCK_BOOTTIME) */
} g_decision_cache[MAX_DECISION_CACHE_SIZE];
static int g_decision_cache_count = 0;
static pthread_mutex_t g_decision_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Get current time in nanoseconds using CLOCK_BOOTTIME (includes suspend time) */
static int64_t get_boottime_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_BOOTTIME, &ts) == 0) {
        return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
    }
    /* Fallback to CLOCK_MONOTONIC if BOOTTIME not available */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
    }
    /* Last resort fallback */
    return (int64_t)time(NULL) * 1000000000LL;
}

/* Convert duration string to nanoseconds */
static int64_t parse_duration_ns(const char *str) {
    if (!str || !str[0]) return 0;
    
    char *end;
    long val = strtol(str, &end, 10);
    if (val <= 0 || end == str) return 0;
    
    int64_t seconds = 0;
    if (strcmp(end, "h") == 0) {
        seconds = val * 3600;
    } else if (strcmp(end, "m") == 0) {
        seconds = val * 60;
    } else if (strcmp(end, "s") == 0) {
        seconds = val;
    }
    return seconds * 1000000000LL;
}

/* Generate UUID */
static void generate_uuid(unsigned char uuid[16]) {
    /* Use timestamp and random data */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t timestamp = (uint64_t)ts.tv_sec * 1000000ULL + (ts.tv_nsec / 1000);
    
    /* Mix timestamp into first 8 bytes */
    for (int i = 0; i < 8; i++) {
        uuid[i] = (timestamp >> (i * 8)) & 0xFF;
    }
    /* Fill rest with random data */
    for (int i = 8; i < 16; i++) {
        uuid[i] = rand() % 256;
    }
}

/* Increment request UUID for each request */
static void next_request_uuid(unsigned char uuid[16]) {
    /* Add 1 to the UUID as a 128-bit integer */
    int carry = 1;
    for (int i = 0; i < 16 && carry; i++) {
        int val = uuid[i] + carry;
        uuid[i] = val & 0xFF;
        carry = (val > 0xFF) ? 1 : 0;
    }
}

/* Forward declaration for logging */
static void log_msg(const char *format, ...);

/* Socket keepalive - prevent premature connection close */
static time_t g_last_activity = 0;
static pthread_mutex_t g_activity_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_keepalive_thread;
static int g_keepalive_running = 0;
static time_t g_keepalive_timeout = 30; /* Close socket after 30 seconds of inactivity */

/* Keepalive thread - closes socket after timeout */
static void *keepalive_thread(void *arg) {
    while (g_keepalive_running) {
        sleep(5);  /* Check every 5 seconds */
        
        pthread_mutex_lock(&g_activity_mutex);
        time_t now = time(NULL);
        time_t idle_time = now - g_last_activity;
        
        if (idle_time > g_keepalive_timeout && g_socket_fd >= 0) {
            pthread_mutex_lock(&g_socket_mutex);
            if (g_socket_fd >= 0) {
                close(g_socket_fd);
                g_socket_fd = -1;
            }
            pthread_mutex_unlock(&g_socket_mutex);
        }
        pthread_mutex_unlock(&g_activity_mutex);
    }
    
    return NULL;
}

/* Update last activity timestamp */
static void update_activity(void) {
    pthread_mutex_lock(&g_activity_mutex);
    g_last_activity = time(NULL);
    pthread_mutex_unlock(&g_activity_mutex);
}

/* Initialize verbose logging */
static void init_logging(void) {
    g_logfile = fopen("/tmp/client_verbose.log", "a");
}

/* Check time-limited decision cache for command (uses CLOCK_BOOTTIME) */
static int check_decision_cache(const char *cmd, uint8_t *out_decision, char *out_reason, size_t reason_size) {
    pthread_mutex_lock(&g_decision_cache_mutex);
    
    int64_t now_ns = get_boottime_ns();
    int cleaned = 0;
    
    /* Opportunistically clean expired entries from the end */
    while (g_decision_cache_count > 0 && 
           now_ns >= g_decision_cache[g_decision_cache_count - 1].expires_ns) {
        g_decision_cache_count--;
    }
    
    /* Search cache for matching command */
    for (int i = 0; i < g_decision_cache_count; i++) {
        /* Check if expired using CLOCK_BOOTTIME */
        if (now_ns >= g_decision_cache[i].expires_ns) {
            /* Remove expired entry and shift remaining */
            if (i < g_decision_cache_count - 1) {
                memmove(&g_decision_cache[i], &g_decision_cache[i+1],
                        sizeof(g_decision_cache[0]) * (g_decision_cache_count - i - 1));
            }
            g_decision_cache_count--;
            i--;
            continue;
        }
        
        /* String comparison for command matching */
        if (strcmp(g_decision_cache[i].cmd, cmd) == 0) {
            *out_decision = g_decision_cache[i].decision;
            
            /* Build reason string with remaining time */
            int64_t remaining_ns = g_decision_cache[i].expires_ns - now_ns;
            int remaining_sec = (int)(remaining_ns / 1000000000LL);
            
            if (remaining_sec >= 3600) {
                snprintf(out_reason, reason_size, "cached: %d min remaining", remaining_sec / 60);
            } else if (remaining_sec >= 60) {
                snprintf(out_reason, reason_size, "cached: %d min remaining", remaining_sec / 60);
            } else {
                snprintf(out_reason, reason_size, "cached: %d sec remaining", remaining_sec);
            }
            
            pthread_mutex_unlock(&g_decision_cache_mutex);
            return 1;  /* Cache hit */
        }
    }
    
    pthread_mutex_unlock(&g_decision_cache_mutex);
    return 0;  /* Cache miss */
}

/* Add decision to time-limited cache (uses CLOCK_BOOTTIME) */
static void add_decision_cache(const char *cmd, uint8_t decision, int64_t duration_ns) {
    pthread_mutex_lock(&g_decision_cache_mutex);
    
    int64_t now_ns = get_boottime_ns();
    int64_t expires_ns = now_ns + duration_ns;
    
    /* Check if already exists and update */
    for (int i = 0; i < g_decision_cache_count; i++) {
        if (strcmp(g_decision_cache[i].cmd, cmd) == 0) {
            g_decision_cache[i].decision = decision;
            g_decision_cache[i].expires_ns = expires_ns;
            pthread_mutex_unlock(&g_decision_cache_mutex);
            return;
        }
    }
    
    /* Add new entry */
    if (g_decision_cache_count < MAX_DECISION_CACHE_SIZE) {
        strncpy(g_decision_cache[g_decision_cache_count].cmd, cmd, 
                sizeof(g_decision_cache[g_decision_cache_count].cmd) - 1);
        g_decision_cache[g_decision_cache_count].cmd[
            sizeof(g_decision_cache[g_decision_cache_count].cmd) - 1] = '\0';
        g_decision_cache[g_decision_cache_count].decision = decision;
        g_decision_cache[g_decision_cache_count].expires_ns = expires_ns;
        g_decision_cache_count++;
    }
    
    pthread_mutex_unlock(&g_decision_cache_mutex);
}

/* Parse decision and optional duration from reason string */
/* Format: "ALLOW", "ALLOW:4h", "ALLOW:1h", "ALLOW:15m", "DENY", "DENY:4h", etc. */
static int parse_decision_reason(const char *reason, uint8_t *decision, int64_t *duration_ns) {
    *duration_ns = 0;
    
    if (strncmp(reason, "ALLOW", 5) == 0) {
        *decision = ROBO_DECISION_ALLOW;
        if (reason[5] == ':') {
            *duration_ns = parse_duration_ns(reason + 6);
        }
        return 1;
    } else if (strncmp(reason, "DENY", 4) == 0) {
        *decision = ROBO_DECISION_DENY;
        if (reason[4] == ':') {
            *duration_ns = parse_duration_ns(reason + 5);
        }
        return 1;
    }
    return 0;
}

static void log_msg(const char *format, ...) {
    if (g_logfile == NULL) return;
    va_list args;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    fprintf(g_logfile, "[%02d:%02d:%02d] ", tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
    va_start(args, format);
    vfprintf(g_logfile, format, args);
    va_end(args);
    fprintf(g_logfile, "\n");
    fflush(g_logfile);
}

/* Async send queue for logs */
#define MAX_QUEUE_SIZE 64
#define MAX_MESSAGE_SIZE 4096

static struct {
    char messages[MAX_QUEUE_SIZE][MAX_MESSAGE_SIZE];
    int count;
    int head;
    int tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;      /* For signaling new messages */
    pthread_cond_t space_cond; /* For signaling queue space available */
    int shutdown;
    pthread_t thread;
} g_send_queue;

/* Forward declarations */
static void *sender_thread(void *arg);
static void queue_message(const char *msg);
static void shutdown_sender(void);
static void lazy_init(void);  /* Lazy initialization for threads/logging */
static int connect_to_server(void);
static void disconnect_from_server(void);
static int send_request(const char *cmd, char *const argv[], char *const envp[],
                        uint8_t *out_decision, char *out_reason, size_t reason_size);
static const char *get_basename(const char *cmd);
static int should_fast_allow(const char *cmd);
static void send_log(const char *format, ...);
static int set_socket_timeout(int fd, struct timeval *tv);
static int check_and_execute(const char *syscall_name, const char *path, char *const argv[], char *const envp[]);

/* Send a single message (must hold g_socket_mutex) */
static int send_message_locked(const char *msg, size_t len) {
    if (g_socket_fd < 0) {
        return -1;
    }
    ssize_t sent = send(g_socket_fd, msg, len, 0);
    return (sent == (ssize_t)len) ? 0 : -1;
}

/* Background sender thread */
static void *sender_thread(void *arg) {
    while (!g_send_queue.shutdown) {
        char *msg = NULL;
        size_t len = 0;

        /* Wait for message */
        pthread_mutex_lock(&g_send_queue.mutex);
        while (g_send_queue.count == 0 && !g_send_queue.shutdown) {
            pthread_cond_wait(&g_send_queue.cond, &g_send_queue.mutex);
        }

        if (g_send_queue.count > 0) {
            /* Get message */
            msg = g_send_queue.messages[g_send_queue.head];
            len = strlen(msg) + 1;
            g_send_queue.head = (g_send_queue.head + 1) % MAX_QUEUE_SIZE;
            g_send_queue.count--;
            /* Signal that space is available */
            pthread_cond_signal(&g_send_queue.space_cond);
        }
        pthread_mutex_unlock(&g_send_queue.mutex);

        /* Send message */
        if (msg) {
            pthread_mutex_lock(&g_socket_mutex);
            send_message_locked(msg, len);
            pthread_mutex_unlock(&g_socket_mutex);
        }
    }
    return NULL;
}

/* Queue a message for async sending - blocks if queue is full */
static void queue_message(const char *msg) {
    lazy_init();  /* Ensure threads are started */
    
    pthread_mutex_lock(&g_send_queue.mutex);
    
    /* Wait for space in the queue */
    while (g_send_queue.count >= MAX_QUEUE_SIZE && !g_send_queue.shutdown) {
        pthread_cond_wait(&g_send_queue.space_cond, &g_send_queue.mutex);
    }
    
    if (!g_send_queue.shutdown) {
        strncpy(g_send_queue.messages[g_send_queue.tail], msg, MAX_MESSAGE_SIZE - 1);
        g_send_queue.messages[g_send_queue.tail][MAX_MESSAGE_SIZE - 1] = '\0';
        g_send_queue.tail = (g_send_queue.tail + 1) % MAX_QUEUE_SIZE;
        g_send_queue.count++;
        pthread_cond_signal(&g_send_queue.cond);
    }
    
    pthread_mutex_unlock(&g_send_queue.mutex);
}

/* Shutdown the sender thread */
static void shutdown_sender(void) {
    /* Stop keepalive thread first */
    g_keepalive_running = 0;
    pthread_join(g_keepalive_thread, NULL);
    log_msg("shutdown_sender: keepalive thread stopped");
    
    /* Stop sender thread */
    pthread_mutex_lock(&g_send_queue.mutex);
    g_send_queue.shutdown = 1;
    /* Wake up all waiters */
    pthread_cond_broadcast(&g_send_queue.cond);
    pthread_cond_broadcast(&g_send_queue.space_cond);
    pthread_mutex_unlock(&g_send_queue.mutex);
    
    /* Wait for sender thread to exit */
    pthread_join(g_send_queue.thread, NULL);
}

/* Initialize on load - MINIMAL initialization to avoid deadlocks */
__attribute__((constructor))
static void init_client(void) {
    const char *env_path = getenv("READONLYBOX_SOCKET");
    if (env_path && env_path[0]) {
        strncpy(g_socket_path, env_path, sizeof(g_socket_path) - 1);
    }

    /* Generate client UUID for request matching */
    generate_uuid(g_client_uuid);
    generate_uuid(g_request_uuid);  /* Initial request UUID */
    
    /* DON'T initialize send queue here - defer to lazy_init() */
    /* DON'T open log file here - defer to lazy_init() */
    /* DON'T start threads here - defer to lazy_init() */
    /* DON'T register atexit here - it's unreliable in shared libraries */
}

/* Lazy initialization - called on first use */
static void lazy_init(void) {
    static int initialized = 0;
    static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    if (initialized) return;
    
    pthread_mutex_lock(&init_mutex);
    if (!initialized) {
        /* Initialize send queue (just memset, no I/O or threads in constructor) */
        memset(&g_send_queue, 0, sizeof(g_send_queue));
        pthread_mutex_init(&g_send_queue.mutex, NULL);
        pthread_cond_init(&g_send_queue.cond, NULL);
        pthread_cond_init(&g_send_queue.space_cond, NULL);
        
        /* Initialize log file */
        g_logfile = fopen("/tmp/client_verbose.log", "a");
        
        /* Start sender thread */
        pthread_create(&g_send_queue.thread, NULL, sender_thread, NULL);
        
        /* Start keepalive thread */
        g_keepalive_running = 1;
        g_last_activity = time(NULL);
        pthread_create(&g_keepalive_thread, NULL, keepalive_thread, NULL);
        
        initialized = 1;
    }
    pthread_mutex_unlock(&init_mutex);
}

/* Exponential backoff state */
static struct {
    useconds_t delay_us;  /* Current delay in microseconds */
    int retries;          /* Number of retries at current delay */
} g_backoff_state = {
    .delay_us = 50000,   /* Start at 50ms */
    .retries = 0,
};

/* Backoff constants */
#define BACKOFF_INITIAL_US 50000      /* 50ms */
#define BACKOFF_MAX_US     120000000  /* 120s */
#define BACKOFF_JITTER     0.3        /* 30% jitter */
#define BACKOFF_SUSTAINED_US 300000000 /* 5 minutes */

/* Reset backoff to initial value */
static void reset_backoff(void) {
    g_backoff_state.delay_us = BACKOFF_INITIAL_US;
    g_backoff_state.retries = 0;
}

/* Calculate next backoff delay with jitter */
static void advance_backoff(void) {
    /* Add jitter: +/- 30% */
    double jitter = ((double)rand() / RAND_MAX - 0.5) * 2 * BACKOFF_JITTER;
    double delay = (double)g_backoff_state.delay_us * (1.0 + jitter);

    if (delay < BACKOFF_INITIAL_US * (1 - BACKOFF_JITTER)) {
        delay = BACKOFF_INITIAL_US * (1 - BACKOFF_JITTER);
    }

    /* Double the delay (exponential backoff) */
    g_backoff_state.delay_us = (useconds_t)(delay * 2);

    /* Cap at max */
    if (g_backoff_state.delay_us > BACKOFF_MAX_US) {
        g_backoff_state.delay_us = BACKOFF_MAX_US;
    }

    g_backoff_state.retries++;
}

/* Get current backoff delay in microseconds */
static useconds_t get_backoff_delay(void) {
    if (g_backoff_state.delay_us >= BACKOFF_MAX_US) {
        return BACKOFF_SUSTAINED_US;  /* After max, use sustained delay */
    }
    return g_backoff_state.delay_us;
}

/* Seed random for jitter */
__attribute__((constructor))
static void init_random(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    srand((unsigned int)(ts.tv_sec ^ ts.tv_nsec));
}

/* Forward declarations */
static int connect_to_server(void);
static void disconnect_from_server(void);
static int send_request(const char *cmd, char *const argv[], char *const envp[],
                        uint8_t *out_decision, char *out_reason, size_t reason_size);
static const char *get_basename(const char *cmd);
static int should_fast_allow(const char *cmd);
static void send_log(const char *format, ...);
static int set_socket_timeout(int fd, struct timeval *tv);
static int check_and_execute(const char *syscall_name, const char *path, char *const argv[], char *const envp[]);

/* Connect to server with retry */
static int connect_to_server(void) {
    pthread_mutex_lock(&g_socket_mutex);

    if (g_socket_fd >= 0) {
        pthread_mutex_unlock(&g_socket_mutex);
        return 0;
    }

    g_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_socket_fd < 0) {
        pthread_mutex_unlock(&g_socket_mutex);
        return -1;
    }

    /* Set connect timeout */
    setsockopt(g_socket_fd, SOL_SOCKET, SO_SNDTIMEO, &g_conn_timeout, sizeof(g_conn_timeout));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_socket_path, sizeof(addr.sun_path) - 1);

    if (connect(g_socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(g_socket_fd);
        g_socket_fd = -1;
        pthread_mutex_unlock(&g_socket_mutex);
        return -1;
    }

    pthread_mutex_unlock(&g_socket_mutex);
    update_activity();
    return 0;
}

/* Disconnect from server */
static void disconnect_from_server(void) {
    pthread_mutex_lock(&g_socket_mutex);
    if (g_socket_fd >= 0) {
        close(g_socket_fd);
        g_socket_fd = -1;
    }
    pthread_mutex_unlock(&g_socket_mutex);
}

/* Set socket receive timeout */
static int set_socket_timeout(int fd, struct timeval *tv) {
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, tv, sizeof(*tv)) < 0) {
        return -1;
    }
    return 0;
}

/* Send request and get response */
static int send_request(const char *cmd, char *const argv[], char *const envp[],
                        uint8_t *out_decision, char *out_reason, size_t reason_size) {
    int argc = 0, envc = 0;
    if (argv) { while (argv[argc]) argc++; }
    if (envp) { while (envp[envc]) envc++; }

    /* Build packet */
    char packet[8192];
    size_t pos = 0;

    /* Magic and header - Protocol v3 with UUIDs */
    uint32_t magic = ROBO_MAGIC;
    uint32_t id = ROBO_MSG_REQ;  /* 1 = REQUEST */
    uint32_t version = ROBO_VERSION;

    memcpy(packet + pos, &magic, 4);
    pos += 4;
    memcpy(packet + pos, &version, 4);
    pos += 4;
    memcpy(packet + pos, g_client_uuid, 16);  /* Client UUID */
    pos += 16;
    memcpy(packet + pos, g_request_uuid, 16);  /* Request UUID */
    pos += 16;
    memset(packet + pos, 0, 16);  /* Server UUID (filled by server) */
    pos += 16;
    memcpy(packet + pos, &id, 4);
    pos += 4;
    memcpy(packet + pos, &argc, 4);
    pos += 4;
    memcpy(packet + pos, &envc, 4);
    pos += 4;

    /* Command */
    strcpy(packet + pos, cmd);
    pos += strlen(cmd) + 1;

    /* Arguments */
    for (int i = 0; i < argc && pos < sizeof(packet) - 256; i++) {
        size_t len = strlen(argv[i]) + 1;
        if (pos + len < sizeof(packet)) {
            memcpy(packet + pos, argv[i], len);
            pos += len;
        }
    }
    packet[pos++] = '\0';

    /* Environment */
    for (int i = 0; i < envc && pos < sizeof(packet) - 256; i++) {
        size_t len = strlen(envp[i]) + 1;
        if (pos + len < sizeof(packet)) {
            memcpy(packet + pos, envp[i], len);
            pos += len;
        }
    }
    packet[pos++] = '\0';

    /* Send */
    pthread_mutex_lock(&g_socket_mutex);
    if (g_socket_fd < 0) {
        pthread_mutex_unlock(&g_socket_mutex);
        return -1;
    }

    /* Set receive timeout */
    set_socket_timeout(g_socket_fd, &g_recv_timeout);

    ssize_t sent = send(g_socket_fd, packet, pos, 0);
    if (sent != (ssize_t)pos) {
        disconnect_from_server();
        pthread_mutex_unlock(&g_socket_mutex);
        return -1;
    }

    /* Receive response header - handle partial reads and timeouts */
    uint32_t resp_magic = 0, resp_id = 0, reason_len = 0;
    uint8_t decision = 0;
    unsigned char resp_server_uuid[16];  /* Server UUID from response */
    char *recv_ptr;
    size_t recv_remaining;

    /* Read magic (4 bytes) - may need to retry on timeout */
    recv_ptr = (char *)&resp_magic;
    recv_remaining = 4;
    int timeout_count = 0;
    while (recv_remaining > 0) {
        ssize_t n = recv(g_socket_fd, recv_ptr, recv_remaining, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                timeout_count++;
                if (timeout_count > 30) {
                    disconnect_from_server();
                    pthread_mutex_unlock(&g_socket_mutex);
                    return -1;
                }
                continue;
            }
            disconnect_from_server();
            pthread_mutex_unlock(&g_socket_mutex);
            return -1;
        }
        if (n == 0) {
            disconnect_from_server();
            pthread_mutex_unlock(&g_socket_mutex);
            return -1;
        }
        recv_ptr += n;
        recv_remaining -= n;
    }

    /* Read ID (4 bytes) */
    recv_ptr = (char *)&resp_id;
    recv_remaining = 4;
    while (recv_remaining > 0) {
        ssize_t n = recv(g_socket_fd, recv_ptr, recv_remaining, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                disconnect_from_server();
                pthread_mutex_unlock(&g_socket_mutex);
                return -1;
            }
            disconnect_from_server();
            pthread_mutex_unlock(&g_socket_mutex);
            return -1;
        }
        if (n == 0) {
            disconnect_from_server();
            pthread_mutex_unlock(&g_socket_mutex);
            return -1;
        }
        recv_ptr += n;
        recv_remaining -= n;
    }

    /* Read ServerID (16 bytes) - for cache validation */
    recv_ptr = (char *)resp_server_uuid;
    recv_remaining = 16;
    while (recv_remaining > 0) {
        ssize_t n = recv(g_socket_fd, recv_ptr, recv_remaining, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                disconnect_from_server();
                pthread_mutex_unlock(&g_socket_mutex);
                return -1;
            }
            disconnect_from_server();
            pthread_mutex_unlock(&g_socket_mutex);
            return -1;
        }
        if (n == 0) {
            disconnect_from_server();
            pthread_mutex_unlock(&g_socket_mutex);
            return -1;
        }
        recv_ptr += n;
        recv_remaining -= n;
    }

    /* Read decision (1 byte) - may need to retry on timeout */
    timeout_count = 0;
    ssize_t n;
    while (1) {
        n = recv(g_socket_fd, &decision, 1, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                timeout_count++;
                if (timeout_count > 30) {
                    disconnect_from_server();
                    pthread_mutex_unlock(&g_socket_mutex);
                    return -1;
                }
                continue;
            }
            disconnect_from_server();
            pthread_mutex_unlock(&g_socket_mutex);
            return -1;
        }
        if (n == 0) {
            disconnect_from_server();
            pthread_mutex_unlock(&g_socket_mutex);
            return -1;
        }
        break;  /* Got the decision byte */
    }

    /* Read reason_len (4 bytes) - may need to retry on timeout */
    recv_ptr = (char *)&reason_len;
    recv_remaining = 4;
    timeout_count = 0;
    while (recv_remaining > 0) {
        n = recv(g_socket_fd, recv_ptr, recv_remaining, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                timeout_count++;
                if (timeout_count > 30) {
                    disconnect_from_server();
                    pthread_mutex_unlock(&g_socket_mutex);
                    return -1;
                }
                continue;
            }
            disconnect_from_server();
            pthread_mutex_unlock(&g_socket_mutex);
            return -1;
        }
        if (n == 0) {
            disconnect_from_server();
            pthread_mutex_unlock(&g_socket_mutex);
            return -1;
        }
        recv_ptr += n;
        recv_remaining -= n;
    }

    /* Read reason - may need to retry on timeout */
    if (reason_len > 0 && reason_len < reason_size) {
        recv_ptr = out_reason;
        recv_remaining = reason_len;
        timeout_count = 0;
        while (recv_remaining > 0) {
            n = recv(g_socket_fd, recv_ptr, recv_remaining, 0);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    log_msg("send_request: timeout waiting for reason, retrying...");
                    timeout_count++;
                    if (timeout_count > 30) {
                        disconnect_from_server();
                        pthread_mutex_unlock(&g_socket_mutex);
                        return -1;
                    }
                    continue;
                }
                disconnect_from_server();
                pthread_mutex_unlock(&g_socket_mutex);
                return -1;
            }
            if (n == 0) {
                disconnect_from_server();
                pthread_mutex_unlock(&g_socket_mutex);
                return -1;
            }
            recv_ptr += n;
            recv_remaining -= n;
        }
    }

    pthread_mutex_unlock(&g_socket_mutex);

    /* Check for time-limited decision and cache it */
    uint8_t timed_decision;
    int64_t duration_ns;
    if (parse_decision_reason(out_reason, &timed_decision, &duration_ns) && duration_ns > 0) {
        /* Build command string for caching */
        char cmd_str[512] = "";
        strncat(cmd_str, cmd, sizeof(cmd_str) - strlen(cmd_str) - 1);
        for (int i = 0; i < argc && strlen(cmd_str) < sizeof(cmd_str) - 50; i++) {
            strncat(cmd_str, " ", sizeof(cmd_str) - strlen(cmd_str) - 1);
            strncat(cmd_str, argv[i], sizeof(cmd_str) - strlen(cmd_str) - 1);
        }
        add_decision_cache(cmd_str, timed_decision, duration_ns);
    }

    /* Increment request UUID for next request */
    next_request_uuid(g_request_uuid);

    *out_decision = decision;
    return 0;
}

/* Send log message to server - fire and forget via async queue */
static void send_log(const char *format, ...) {
    char log_msg[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(log_msg, sizeof(log_msg), format, args);
    va_end(args);

    /* Build packet */
    char packet[8192];
    size_t pos = 0;

    /* Magic and header - Protocol v3 with UUIDs */
    uint32_t magic = ROBO_MAGIC;
    uint32_t id = ROBO_MSG_LOG;  /* 0 = LOG */
    uint32_t version = ROBO_VERSION;
    uint32_t argc = 0;
    uint32_t envc = 1;  /* We'll put the log message as a fake env var */

    memcpy(packet + pos, &magic, 4);
    pos += 4;
    memcpy(packet + pos, &version, 4);
    pos += 4;
    memcpy(packet + pos, g_client_uuid, 16);  /* Client UUID */
    pos += 16;
    memcpy(packet + pos, g_request_uuid, 16);  /* Request UUID */
    pos += 16;
    memset(packet + pos, 0, 16);  /* Server UUID (not needed for logs) */
    pos += 16;
    memcpy(packet + pos, &id, 4);
    pos += 4;
    memcpy(packet + pos, &argc, 4);
    pos += 4;
    memcpy(packet + pos, &envc, 4);
    pos += 4;

    /* Command (ignored for LOG messages, but must be present) */
    const char *cmd = "LOG";
    strcpy(packet + pos, cmd);
    pos += strlen(cmd) + 1;

    /* Arguments (empty) */
    packet[pos++] = '\0';

    /* Environment - contains log message */
    strcpy(packet + pos, log_msg);
    pos += strlen(log_msg) + 1;

    /* Queue for async sending */
    queue_message(packet);
}

/* Get basename of path */
static const char *get_basename(const char *path) {
    if (!path) return NULL;
    const char *last_slash = strrchr(path, '/');
    return last_slash ? last_slash + 1 : path;
}

/* Fast path check - allow using DFA */
static int should_fast_allow(const char *cmd) {
    return dfa_should_allow(cmd);
}

/* Check if path is readonlybox itself */
static int is_readonlybox_path(const char *path) {
    if (!path) return 0;
    if (strstr(path, "readonlybox") != NULL) return 1;
    if (strstr(path, "/readonlybox") != NULL) return 1;
    return 0;
}

/* Check for write operations in arguments */
static int has_write_operation(char *const argv[]) {
    for (int i = 0; argv && argv[i]; i++) {
        if (strcmp(argv[i], ">") == 0 || strcmp(argv[i], ">>") == 0 ||
            strcmp(argv[i], "2>") == 0 || strcmp(argv[i], "&>") == 0 ||
            strcmp(argv[i], "1>") == 0 || strcmp(argv[i], "2>>") == 0) {
            return 1;
        }
    }
    return 0;
}

/* Request decision from server - returns 0 on allow, -1 on deny, 1 on error (retry) */
static int request_decision(const char *syscall_name, const char *cmd, char *const argv[], char *const envp[],
                           char *out_reason, size_t reason_size) {
    uint8_t decision;
    char reason[256];

    reset_backoff();

    for (;;) {
        /* Ensure connected */
        if (connect_to_server() < 0) {
            send_log("[readonlybox-client] Server unavailable, retrying in %lu ms...", get_backoff_delay() / 1000);
            usleep(get_backoff_delay());
            advance_backoff();
            continue;
        }

        /* Send request with syscall name prefixed */
        char prefixed_cmd[512];
        snprintf(prefixed_cmd, sizeof(prefixed_cmd), "%s:%s", syscall_name, cmd);
        if (send_request(prefixed_cmd, argv, envp, &decision, reason, sizeof(reason)) < 0) {
            send_log("[readonlybox-client] Connection lost, retrying in %lu ms...", get_backoff_delay() / 1000);
            disconnect_from_server();
            usleep(get_backoff_delay());
            advance_backoff();
            continue;
        }

        /* Got a decision */
        break;
    }

    if (decision == ROBO_DECISION_DENY) {
        strncpy(out_reason, reason, reason_size - 1);
        out_reason[reason_size - 1] = '\0';
        return -1;
    }

    /* ALLOW */
    strncpy(out_reason, reason, reason_size - 1);
    out_reason[reason_size - 1] = '\0';
    return 0;
}

/* Common execution check - returns 0 to proceed, -1 to block */
static int check_and_execute(const char *syscall_name, const char *path, char *const argv[], char *const envp[]) {
    const char *cmd = get_basename(path);

    if (!cmd) {
        return 0;
    }

    /* Skip if already going through readonlybox */
    if (is_readonlybox_path(path)) {
        return 0;
    }

    /* Fast allow - only for known safe commands, always check unknown syscalls */
    if (should_fast_allow(cmd)) {
        return 0;
    }

    /* Build command string for time-limited cache lookup */
    char cmd_str[512] = "";
    strncat(cmd_str, cmd, sizeof(cmd_str) - 1);
    for (int i = 0; argv && argv[i] && strlen(cmd_str) < sizeof(cmd_str) - 50; i++) {
        strncat(cmd_str, " ", sizeof(cmd_str) - strlen(cmd_str) - 1);
        strncat(cmd_str, argv[i], sizeof(cmd_str) - strlen(cmd_str) - 1);
    }

    /* Check time-limited decision cache first */
    uint8_t cached_decision;
    char cached_reason[256];
    if (check_decision_cache(cmd_str, &cached_decision, cached_reason, sizeof(cached_reason))) {
        if (cached_decision == ROBO_DECISION_DENY) {
            errno = EACCES;
            return -1;
        }
        return 0;
    }

    /* Check for write operations */
    int is_write = has_write_operation(argv);

    /* Get decision from server - always check for posix_spawn and write ops */
    char reason[256];
    int result = request_decision(syscall_name, cmd, argv, envp, reason, sizeof(reason));

    if (result < 0) {
        /* Denied */
        send_log("[readonlybox-client] DENY (%s): %s - %s", syscall_name, cmd, reason);
        errno = EACCES;
        return -1;
    }

    /* Allowed - log if it was a write operation or posix_spawn */
    if (is_write || strcmp(syscall_name, "posix_spawn") == 0) {
        send_log("[readonlybox-client] ALLOW (%s): %s - %s", syscall_name, cmd, reason);
    }

    return 0;
}

/* execve interception */
int execve(const char *path, char *const argv[], char *const envp[]) {
    static int (*real_execve)(const char *, char *const[], char *const[]) = NULL;

    if (real_execve == NULL) {
        real_execve = dlsym(RTLD_NEXT, "execve");
    }

    int check = check_and_execute("execve", path, argv, envp);
    if (check < 0) {
        /* Denied - print error and exit to prevent shell retry loops */
        const char *cmd = get_basename(path);
        if (cmd) {
            fprintf(stderr, "%s: Permission denied\n", cmd);
        }
        /* Use _exit to avoid flushing buffers and prevent any retry */
        _exit(1);
        return -1;  /* Never reached */
    }

    return real_execve(path, argv, envp);
}

/* execveat interception */
int execveat(int dirfd, const char *pathname, char *const argv[],
             char *const envp[], int flags) {
    static int (*real_execveat)(int, const char *, char *const[], char *const[], int) = NULL;

    if (real_execveat == NULL) {
        real_execveat = dlsym(RTLD_NEXT, "execveat");
    }

    /* Get full path for checking */
    char fullpath[4096];
    if (pathname && pathname[0] != '/') {
        /* Relative path - would need /proc/self/fd, skip check */
        return real_execveat(dirfd, pathname, argv, envp, flags);
    }
    snprintf(fullpath, sizeof(fullpath), "%s", pathname);

    int check = check_and_execute("execveat", fullpath, argv, envp);
    if (check < 0) {
        return -1;
    }

    return real_execveat(dirfd, pathname, argv, envp, flags);
}

/* Helper to extract path from posix_spawn attributes */
static const char *get_path_from_file_actions(const char *file_actions) {
    /* This is tricky - posix_spawn uses file_actions struct internally
     * The simplest approach: if we can't easily check, let it through
     * but log that posix_spawn was used */
    return NULL;
}

/* posix_spawn interception - basic version */
int posix_spawn(pid_t *pid, const char *path,
                const void *file_actions, const void *attrp,
                char *const argv[], char *const envp[]) {
    static int (*real_posix_spawn)(pid_t *, const char *, const void *, const void *,
                                   char *const[], char *const[]) = NULL;

    if (real_posix_spawn == NULL) {
        real_posix_spawn = dlsym(RTLD_NEXT, "posix_spawn");
    }

    int check = check_and_execute("posix_spawn", path, argv, envp);
    if (check < 0) {
        return EPERM;
    }

    return real_posix_spawn(pid, path, file_actions, attrp, argv, envp);
}

/* posix_spawnp interception - searches PATH */
int posix_spawnp(pid_t *pid, const char *file,
                 const void *file_actions, const void *attrp,
                 char *const argv[], char *const envp[]) {
    static int (*real_posix_spawnp)(pid_t *, const char *, const void *, const void *,
                                    char *const[], char *const[]) = NULL;

    if (real_posix_spawnp == NULL) {
        real_posix_spawnp = dlsym(RTLD_NEXT, "posix_spawnp");
    }

    /* For spawnp, we need to resolve the path first - this is complex
     * For now, we'll skip the check and let it through */
    return real_posix_spawnp(pid, file, file_actions, attrp, argv, envp);
}
