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
#include <stdatomic.h>
#include <stdarg.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/select.h>

#include "dfa.h"
#include <shell_tokenizer.h>

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

/* Detected parent application name (set once at library load) */
static char g_parent_app_name[256] = {0};
static char g_cwd[512] = {0};

/* Initialization states for atomic state machine */
#define STATE_NOT_STARTED   0
#define STATE_IN_PROGRESS   1
#define STATE_COMPLETED     2

static atomic_int g_init_state = 0;

/* Forward declaration */
static void detect_parent_app_once(void);

/* Extract basename from path */
static const char *extract_basename(const char *path) {
    if (!path) return "unknown";
    const char *base = strrchr(path, '/');
    if (base && base[1]) {
        return base + 1;
    }
    return path;
}

/* Check if string looks like a version number (X.Y.Z format) */
static int is_version_number(const char *str) {
    if (!str || strlen(str) < 3) return 0;
    /* Check for X.Y.Z or X.Y.Z.Z format */
    int dots = 0;
    for (int i = 0; str[i]; i++) {
        if (str[i] == '.') {
            dots++;
        } else if (str[i] < '0' || str[i] > '9') {
            return 0;
        }
    }
    return dots >= 2; /* At least X.Y */
}

/* Try to resolve a version number to an app name */
static void resolve_app_name(char *buf, size_t buf_size, const char *exe_path) {
    const char *basename = extract_basename(exe_path);
    
    /* If not a version number, just use the basename */
    if (!is_version_number(basename)) {
        snprintf(buf, buf_size, "%s", basename);
        return;
    }
    
    /* Check if this version matches known apps by checking path pattern */
    /* Format: /home/panz/.local/share/claude/versions/X.Y.Z */
    if (strstr(exe_path, "/claude/versions/") != NULL) {
        snprintf(buf, buf_size, "claude");
        return;
    } else if (strstr(exe_path, "/cursor/versions/") != NULL) {
        snprintf(buf, buf_size, "cursor");
        return;
    } else if (strstr(exe_path, "/code/versions/") != NULL) {
        snprintf(buf, buf_size, "code");
        return;
    }
    
    /* Fallback to basename */
    snprintf(buf, buf_size, "%s", basename);
}

/* Thread-safe parent app detection using C11 atomics */
static void detect_parent_app_once(void) {
    /* Check if already completed (relaxed read - no synchronization needed yet) */
    int state = atomic_load_explicit(&g_init_state, memory_order_relaxed);
    
    if (state == STATE_COMPLETED) {
        return; /* Already done, nothing to do */
    }
    
    /* Not completed - try to claim initialization work using fetch-or */
    int old_val = atomic_fetch_or_explicit(&g_init_state, STATE_IN_PROGRESS, memory_order_acq_rel);
    
    if (old_val == STATE_NOT_STARTED) {
        /* We won the race - we are responsible for initialization */
        
        /* First, try /proc/self/exe to get the actual running binary */
        char exe_buf[256] = {0};
        ssize_t exe_len = readlink("/proc/self/exe", exe_buf, sizeof(exe_buf) - 1);
        if (exe_len > 0) {
            exe_buf[exe_len] = '\0';
            /* Try to resolve version numbers to app names via symlinks */
            resolve_app_name(g_parent_app_name, sizeof(g_parent_app_name), exe_buf);
            /* If resolution didn't find a name, use basename */
            if (!g_parent_app_name[0]) {
                const char *exe_name = extract_basename(exe_buf);
                if (exe_name && strlen(exe_name) > 3 && 
                    strncmp(exe_name, "ld-", 3) != 0 &&
                    strncmp(exe_name, "libc", 4) != 0 &&
                    strcmp(exe_name, "[heap]") != 0 &&
                    strcmp(exe_name, "[stack]") != 0) {
                    snprintf(g_parent_app_name, sizeof(g_parent_app_name), "%s", exe_name);
                }
            }
        }
        
        /* Also capture current working directory */
        if (getcwd(g_cwd, sizeof(g_cwd)) == NULL) {
            g_cwd[0] = '\0';
        }
        
        /* Mark initialization as complete with release ordering */
        /* This ensures all our writes are visible to other threads */
        atomic_store_explicit(&g_init_state, STATE_COMPLETED, memory_order_release);
    } else {
        /* Someone else is already doing initialization (or completed) */
        /* Spin-wait until they finish with acquire ordering */
        while (atomic_load_explicit(&g_init_state, memory_order_acquire) != STATE_COMPLETED) {
            /* Spin - could add small sleep/yield here if needed */
        }
    }
}

/* Get cached parent app name (thread-safe, always fast after first call) */
static const char *get_parent_app_name(void) {
    /* Ensure initialization happened (spins if another thread is initializing) */
    while (atomic_load_explicit(&g_init_state, memory_order_acquire) != STATE_COMPLETED) {
        detect_parent_app_once();
    }
    return g_parent_app_name[0] ? g_parent_app_name : "unknown";
}

/* Get cached CWD (thread-safe, always fast after first call) */
static const char *get_cwd(void) {
    /* Ensure initialization happened */
    while (atomic_load_explicit(&g_init_state, memory_order_acquire) != STATE_COMPLETED) {
        detect_parent_app_once();
    }
    return g_cwd[0] ? g_cwd : "";
}

__attribute__((constructor))
static void init_readonlybox_client(void) {
    /* Detect and store parent app name at load time */
    detect_parent_app_once();
}


/* UUIDs for request matching across reconnects */
static unsigned char g_client_uuid[16];
static unsigned char g_request_uuid[16];

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

    /* Get cached Cwd to include in packet */
    const char *cwd = get_cwd();

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
    /* Include Cwd as extra env var if available */
    int envcWithCwd = envc + (cwd && cwd[0] ? 1 : 0);
    memcpy(packet + pos, &envcWithCwd, 4);
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

    /* Environment */
    for (int i = 0; i < envc && pos < sizeof(packet) - 256; i++) {
        size_t len = strlen(envp[i]) + 1;
        if (pos + len < sizeof(packet)) {
            memcpy(packet + pos, envp[i], len);
            pos += len;
        }
    }
    /* Add READONLYBOX_CWD if we have it */
    if (cwd && cwd[0] && pos < sizeof(packet) - 256) {
        char cwdEnv[1024];
        snprintf(cwdEnv, sizeof(cwdEnv), "READONLYBOX_CWD=%s", cwd);
        size_t len = strlen(cwdEnv) + 1;
        if (pos + len < sizeof(packet)) {
            memcpy(packet + pos, cwdEnv, len);
            pos += len;
        }
    }
    /* No extra null - server reads exactly envc env vars */

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
        /* Time-limited decision - could be cached server-side */
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

/* Modify command string to include parent app name if it's a known app */
static void augment_command_with_app(char *cmd_str, size_t max_len, const char *parent_app) {
    if (!cmd_str || !parent_app || !parent_app[0]) {
        return;
    }
    
    /* Known apps that use claude-style syntax */
    if (strcmp(parent_app, "claude") == 0 || 
        strcmp(parent_app, "cursor") == 0 ||
        strcmp(parent_app, "code") == 0 ||
        strstr(parent_app, "claude") != NULL) {
        /* Prepend app name to command for server-side detection */
        char augmented[512];
        snprintf(augmented, sizeof(augmented), "[app:%s] %s", parent_app, cmd_str);
        strncpy(cmd_str, augmented, max_len - 1);
        cmd_str[max_len - 1] = '\0';
    }
}

/* Wrapper around c-dfa shell tokenizer - extracts individual commands */
static int extract_commands_from_shell(const char* cmd, char commands[][256], int max_commands) {
    shell_command_t* shell_cmds = NULL;
    size_t cmd_count = 0;

    if (!shell_tokenize_commands(cmd, &shell_cmds, &cmd_count)) {
        return 0;
    }

    int result = 0;
    for (size_t i = 0; i < cmd_count && result < max_commands; i++) {
        shell_command_t* sc = &shell_cmds[i];
        /* Extract command by concatenating tokens up to first pipe/semicolon */
        char buf[256] = "";
        size_t buf_len = 0;

        for (size_t j = 0; j < sc->token_count && buf_len < sizeof(buf) - 1; j++) {
            shell_token_t* tok = &sc->tokens[j];
            /* Skip operator tokens */
            if (tok->type == TOKEN_PIPE || tok->type == TOKEN_SEMICOLON ||
                tok->type == TOKEN_AND || tok->type == TOKEN_OR ||
                tok->type == TOKEN_REDIRECT_IN || tok->type == TOKEN_REDIRECT_OUT ||
                tok->type == TOKEN_REDIRECT_APPEND) {
                break;
            }
            /* Add space between arguments */
            if (buf_len > 0 && buf_len < sizeof(buf) - 1) {
                buf[buf_len++] = ' ';
            }
            /* Copy token */
            size_t tok_len = tok->length;
            if (buf_len + tok_len >= sizeof(buf)) {
                tok_len = sizeof(buf) - buf_len - 1;
            }
            memcpy(buf + buf_len, tok->start, tok_len);
            buf_len += tok_len;
        }

        if (buf_len > 0) {
            strncpy(commands[result], buf, 255);
            commands[result][255] = '\0';
            result++;
        }
    }

    shell_free_commands(shell_cmds, cmd_count);
    return result;
}

/* Fast path check - handles shell constructs (pipes, semicolons, etc.) */
static int should_fast_allow(const char *cmd) {
    /* First check the whole command as-is */
    if (dfa_should_allow(cmd)) {
        return 1;
    }

    /* Check if this is a simple command (no shell operators) */
    int has_operator = 0;
    const char* p = cmd;
    int in_quote = 0;
    while (*p) {
        if (*p == '"' || *p == '\'') {
            in_quote = !in_quote;
        } else if (!in_quote && (*p == '|' || *p == ';' ||
                   (*p == '&' && p[1] == '&') ||
                   (*p == '|' && p[1] == '|'))) {
            has_operator = 1;
            break;
        }
        p++;
    }

    /* If no shell operators and dfa_should_allow failed, deny */
    if (!has_operator) {
        return 0;
    }

    /* Tokenize and check each command separately */
    char commands[8][256];
    int cmd_count = extract_commands_from_shell(cmd, commands, 8);

    /* All commands must be allowed */
    for (int i = 0; i < cmd_count; i++) {
        if (!dfa_should_allow(commands[i])) {
            return 0;
        }
    }

    return 1;
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

/* Forward declaration for redirect function */
static int redirect_through_readonlybox(const char *path, char *const argv[], char *const envp[]);

/* Common execution check - returns 0 to proceed, -1 to block */
static int check_and_execute(const char *syscall_name, const char *path, char *const argv[], char *const envp[]) {
    const char *base_cmd = extract_basename(path);

    if (!base_cmd) {
        return 0;
    }

    /* Build full command string from base command and arguments */
    char cmd_str[512] = "";
    if (argv && argv[0]) {
        strncat(cmd_str, argv[0], sizeof(cmd_str) - 1);
        for (int i = 1; argv && argv[i] && strlen(cmd_str) < sizeof(cmd_str) - 50; i++) {
            strncat(cmd_str, " ", sizeof(cmd_str) - strlen(cmd_str) - 1);
            strncat(cmd_str, argv[i], sizeof(cmd_str) - strlen(cmd_str) - 1);
        }
    }

    /* Fast allow - only for known safe commands via DFA (check BEFORE augmentation) */
    if (should_fast_allow(cmd_str)) {
        return 0;
    }

    /* Augment command with parent app name for server-side parsing */
    const char *parent_app = get_parent_app_name();
    augment_command_with_app(cmd_str, sizeof(cmd_str), parent_app);

    /* DFA didn't match - redirect through readonlybox --run for validation */
    return redirect_through_readonlybox(path, argv, envp);
}

/* Shared function to redirect through readonlybox --run */
static int redirect_through_readonlybox(const char *path, char *const argv[], char *const envp[]) {
    static int (*real_execve)(const char *, char *const[], char *const[]) = NULL;

    if (real_execve == NULL) {
        real_execve = dlsym(RTLD_NEXT, "execve");
    }

    char readonlybox_path[1024];
    snprintf(readonlybox_path, sizeof(readonlybox_path), "%s/readonlybox", "/home/panz/osrc/lms-test/readonlybox/bin");

    /* Get parent app name and syscall info to pass to readonlybox */
    const char *parent_app = get_parent_app_name();
    const char *cwd = get_cwd();
    
    /* Build args: readonlybox --caller <appname:syscall> --cwd <path> --run <original-path> <original-args...> */
    /* Format: [caller:appname:syscall] */
    char caller_info[320];
    if (parent_app && parent_app[0]) {
        snprintf(caller_info, sizeof(caller_info), "%s:execve", parent_app);
    } else {
        snprintf(caller_info, sizeof(caller_info), "unknown:execve");
    }
    
    char *new_argv[130]; /* Extra slots for --caller, --cwd, --run */
    int idx = 0;
    new_argv[idx++] = "readonlybox";
    new_argv[idx++] = "--caller";
    new_argv[idx++] = caller_info;
    new_argv[idx++] = "--cwd";
    new_argv[idx++] = (char*)cwd;
    new_argv[idx++] = "--run";
    new_argv[idx++] = (char*)path;

    /* Copy original args (skip argv[0] since path is already the command) */
    int i;
    for (i = 1; argv && argv[i] && idx < 127; i++) {
        new_argv[idx++] = argv[i];
    }
    new_argv[idx++] = NULL;

    /* If envp is NULL, use current environment from environ global */
    char **exec_env_to_free = NULL;
    char **exec_env = (char **)envp;
    
    if (envp == NULL) {
        /* Count environment variables */
        int envc = 0;
        for (char **e = environ; *e; e++) envc++;
        
        /* Allocate new environment array (+2 for CWD env and NULL) */
        exec_env_to_free = malloc((envc + 2) * sizeof(char*));
        for (int j = 0; j < envc; j++) {
            exec_env_to_free[j] = environ[j];
        }
        /* Add READONLYBOX_CWD - must be allocated since we're freeing later */
        char *cwd_env_alloc = malloc(1024);
        snprintf(cwd_env_alloc, 1024, "READONLYBOX_CWD=%s", cwd);
        exec_env_to_free[envc] = cwd_env_alloc;
        exec_env_to_free[envc + 1] = NULL;
        exec_env = exec_env_to_free;
    } else {
        /* Count envp variables */
        int envc = 0;
        for (char *const *e = envp; *e; e++) envc++;
        
        /* Allocate new environment array (+2 for CWD env and NULL) */
        exec_env_to_free = malloc((envc + 2) * sizeof(char*));
        int cwd_env_idx = -1;
        for (int j = 0; j < envc; j++) {
            exec_env_to_free[j] = envp[j];
            /* Check if READONLYBOX_CWD already exists and replace it */
            if (strncmp(envp[j], "READONLYBOX_CWD=", 16) == 0) {
                cwd_env_idx = j;
                /* Allocate new string since we're freeing envp */
                char *cwd_env_alloc = malloc(1024);
                snprintf(cwd_env_alloc, 1024, "READONLYBOX_CWD=%s", cwd);
                exec_env_to_free[j] = cwd_env_alloc;
            }
        }
        /* If not found, add it at the end */
        if (cwd_env_idx < 0) {
            char *cwd_env_alloc = malloc(1024);
            snprintf(cwd_env_alloc, 1024, "READONLYBOX_CWD=%s", cwd);
            exec_env_to_free[envc] = cwd_env_alloc;
            exec_env_to_free[envc + 1] = NULL;
        } else {
            exec_env_to_free[envc + 1] = NULL;
        }
        exec_env = exec_env_to_free;
    }

    int result = real_execve(readonlybox_path, new_argv, exec_env);

    /* If we allocated new_env, free it */
    if (exec_env_to_free != NULL) {
        free(exec_env_to_free);
    }

    return result;
}

/* execve interception - uses DFA for fast-path allowed commands */
int execve(const char *path, char *const argv[], char *const envp[]) {
    static int (*real_execve)(const char *, char *const[], char *const[]) = NULL;

    if (real_execve == NULL) {
        real_execve = dlsym(RTLD_NEXT, "execve");
    }

    /* Check and execute - returns 0 to proceed, -1 to block */
    if (check_and_execute("execve", path, argv, envp) < 0) {
        /* Blocked - print error and return error code */
        fprintf(stderr, "readonlybox: Permission denied, possibly unsafe command.\n");
        errno = EACCES;
        return -1;
    }

    return real_execve(path, argv, envp);
}

/* Also intercept execvpe - used by bash and other shells */
int execvpe(const char *file, char *const argv[], char *const envp[]) {
    static int (*real_execvpe)(const char *, char *const[], char *const[]) = NULL;

    if (real_execvpe == NULL) {
        real_execvpe = dlsym(RTLD_NEXT, "execvpe");
    }

    /* Check and execute - returns 0 to proceed, -1 to block */
    if (check_and_execute("execvpe", file, argv, envp) < 0) {
        fprintf(stderr, "readonlybox: Permission denied, possibly unsafe command.\n");
        errno = EACCES;
        return -1;
    }

    return real_execvpe(file, argv, envp);
}

/* execveat interception - uses DFA for fast-path allowed commands */
int execveat(int dirfd, const char *pathname, char *const argv[],
             char *const envp[], int flags) {
    static int (*real_execveat)(int, const char *, char *const[], char *const[], int) = NULL;

    if (real_execveat == NULL) {
        real_execveat = dlsym(RTLD_NEXT, "execveat");
    }

    /* Resolve full path from dirfd + pathname */
    char fullpath[4096];
    if (pathname && pathname[0] == '/') {
        snprintf(fullpath, sizeof(fullpath), "%s", pathname);
    } else if (dirfd >= 0) {
        /* Read symlink from /proc/self/fd */
        char fdpath[64];
        snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", dirfd);
        ssize_t len = readlink(fdpath, fullpath, sizeof(fullpath) - 1);
        if (len > 0) {
            fullpath[len] = '\0';
            if (pathname && pathname[0]) {
                size_t prefix_len = strlen(fullpath);
                snprintf(fullpath + prefix_len, sizeof(fullpath) - prefix_len, "/%s", pathname);
            }
        } else {
            snprintf(fullpath, sizeof(fullpath), "%s", pathname ? pathname : "");
        }
    } else {
        snprintf(fullpath, sizeof(fullpath), "%s", pathname ? pathname : "");
    }

    /* Check using DFA fast path and server fallback */
    if (check_and_execute("execveat", fullpath, argv, envp) == 0) {
        return real_execveat(dirfd, pathname, argv, envp, flags);
    }

    /* Blocked by check_and_execute */
    fprintf(stderr, "readonlybox: Permission denied\n");
    errno = EACCES;
    return -1;
}

/* posix_spawn interception - uses DFA for fast-path allowed commands */
int posix_spawn(pid_t *pid, const char *path,
                const void *file_actions, const void *attrp,
                char *const argv[], char *const envp[]) {
    static int (*real_posix_spawn)(pid_t *, const char *, const void *, const void *,
                                   char *const[], char *const[]) = NULL;

    if (real_posix_spawn == NULL) {
        real_posix_spawn = dlsym(RTLD_NEXT, "posix_spawn");
    }

    /* Check using DFA fast path and server fallback */
    if (check_and_execute("posix_spawn", path, argv, envp) == 0) {
        return real_posix_spawn(pid, path, file_actions, attrp, argv, envp);
    }

    /* Blocked by check_and_execute - just return error, don't print */
    errno = EACCES;
    return EACCES;
}

/* posix_spawnp interception - uses DFA for fast-path allowed commands */
int posix_spawnp(pid_t *pid, const char *file,
                 const void *file_actions, const void *attrp,
                 char *const argv[], char *const envp[]) {
    static int (*real_posix_spawnp)(pid_t *, const char *, const void *, const void *,
                                    char *const[], char *const[]) = NULL;

    if (real_posix_spawnp == NULL) {
        real_posix_spawnp = dlsym(RTLD_NEXT, "posix_spawnp");
    }

    /* For posix_spawnp, we need to resolve the path first */
    const char *resolved_path = file;

    /* If file doesn't contain a path separator, search PATH */
    if (file && strchr(file, '/') == NULL) {
        const char *path_env = NULL;
        for (char *const *env = envp; *env; env++) {
            if (strncmp(*env, "PATH=", 5) == 0) {
                path_env = *env + 5;
                break;
            }
        }

        if (path_env) {
            char path_buf[4096];
            const char *path_copy = path_env;
            const char *colon;

            while ((colon = strchr(path_copy, ':')) != NULL) {
                size_t dir_len = colon - path_copy;
                if (dir_len > 0 && dir_len < sizeof(path_buf) - strlen(file) - 2) {
                    memcpy(path_buf, path_copy, dir_len);
                    path_buf[dir_len] = '/';
                    strcpy(path_buf + dir_len + 1, file);
                    if (access(path_buf, X_OK) == 0) {
                        resolved_path = path_buf;
                        break;
                    }
                }
                path_copy = colon + 1;
            }

            /* Check the last directory in PATH */
            if (!resolved_path || resolved_path == file) {
                size_t last_len = strlen(path_copy);
                if (last_len > 0 && last_len < sizeof(path_buf) - strlen(file) - 2) {
                    strcpy(path_buf, path_copy);
                    path_buf[last_len] = '/';
                    strcpy(path_buf + last_len + 1, file);
                    if (access(path_buf, X_OK) == 0) {
                        resolved_path = path_buf;
                    }
                }
            }
        }
    }

    /* Check using DFA fast path and server fallback with resolved path */
    if (check_and_execute("posix_spawnp", resolved_path, argv, envp) == 0) {
        return real_posix_spawnp(pid, resolved_path, file_actions, attrp, argv, envp);
    }

    /* Blocked by check_and_execute - just return error, don't print */
    errno = EACCES;
    return EACCES;
}
