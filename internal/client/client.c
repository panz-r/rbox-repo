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

/* Protocol constants */
#define ROBO_MAGIC      0x524F424F
#define ROBO_VERSION    1

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

/* Fast path command lists */
static const char *fast_allowed[] = {
    "ls", "cat", "head", "tail", "wc", "uniq", "sort", "grep", "echo",
    "date", "pwd", "hostname", "uname", "whoami", "id", "who", "last",
    "printenv", "sleep", "expr", "timeout", "true", "false", "null",
    "basename", "dirname", "readlink", "uptime", "which", "test", "[",
    "stat", "file", "find", "xargs", "tr", "cut", "join", "paste",
    "comm", "diff", "nl", "od", "base64", "strings",
    NULL
};

/* Forward declarations */
static int connect_to_server(void);
static void disconnect_from_server(void);
static int send_request(const char *cmd, char *const argv[], char *const envp[],
                        uint8_t *out_decision, char *out_reason, size_t reason_size);
static const char *get_basename(const char *cmd);
static int should_fast_allow(const char *cmd);
static void send_log(const char *format, ...);

/* Initialize on load */
__attribute__((constructor))
static void init_client(void) {
    const char *env_path = getenv("READONLYBOX_SOCKET");
    if (env_path && env_path[0]) {
        strncpy(g_socket_path, env_path, sizeof(g_socket_path) - 1);
    }
    send_log("[readonlybox-client] Initialized, socket=%s", g_socket_path);
}

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

/* Send request and get response */
static int send_request(const char *cmd, char *const argv[], char *const envp[],
                       uint8_t *out_decision, char *out_reason, size_t reason_size) {
    /* Build packet */
    char packet[8192];
    size_t pos = 0;
    
    /* Magic and header */
    uint32_t magic = ROBO_MAGIC;
    uint32_t id = ROBO_MSG_REQ;  /* 1 = REQUEST */
    
    /* Count args and env */
    int argc = 0, envc = 0;
    if (argv) { while (argv[argc]) argc++; }
    if (envp) { while (envp[envc]) envc++; }
    
    memcpy(packet + pos, &magic, 4);
    pos += 4;
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
    
    ssize_t sent = send(g_socket_fd, packet, pos, 0);
    if (sent != (ssize_t)pos) {
        disconnect_from_server();
        pthread_mutex_unlock(&g_socket_mutex);
        return -1;
    }
    
    /* Receive response header */
    uint32_t resp_magic, resp_id, reason_len;
    uint8_t decision;
    
    ssize_t n = recv(g_socket_fd, &resp_magic, 4, MSG_WAITALL);
    if (n != 4) {
        disconnect_from_server();
        pthread_mutex_unlock(&g_socket_mutex);
        return -1;
    }
    
    n = recv(g_socket_fd, &resp_id, 4, MSG_WAITALL);
    if (n != 4) {
        disconnect_from_server();
        pthread_mutex_unlock(&g_socket_mutex);
        return -1;
    }
    
    n = recv(g_socket_fd, &decision, 1, MSG_WAITALL);
    if (n != 1) {
        disconnect_from_server();
        pthread_mutex_unlock(&g_socket_mutex);
        return -1;
    }
    
    n = recv(g_socket_fd, &reason_len, 4, MSG_WAITALL);
    if (n != 4) {
        disconnect_from_server();
        pthread_mutex_unlock(&g_socket_mutex);
        return -1;
    }
    
    /* Read reason */
    if (reason_len > 0 && reason_len < reason_size) {
        n = recv(g_socket_fd, out_reason, reason_len, MSG_WAITALL);
        if (n != (ssize_t)reason_len) {
            disconnect_from_server();
            pthread_mutex_unlock(&g_socket_mutex);
            return -1;
        }
        out_reason[reason_len - 1] = '\0';
    } else {
        out_reason[0] = '\0';
    }
    
    pthread_mutex_unlock(&g_socket_mutex);
    
    *out_decision = decision;
    return 0;
}

/* Send log message to server */
static void send_log(const char *format, ...) {
    char log_msg[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(log_msg, sizeof(log_msg), format, args);
    va_end(args);

    /* Build packet */
    char packet[8192];
    size_t pos = 0;

    /* Magic and header - ID=0 means LOG message */
    uint32_t magic = ROBO_MAGIC;
    uint32_t id = ROBO_MSG_LOG;  /* 0 = LOG */
    uint32_t argc = 0;
    uint32_t envc = 1;  /* We'll put the log message as a fake env var */

    memcpy(packet + pos, &magic, 4);
    pos += 4;
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

    /* Send */
    pthread_mutex_lock(&g_socket_mutex);
    if (g_socket_fd < 0) {
        pthread_mutex_unlock(&g_socket_mutex);
        return;
    }

    send(g_socket_fd, packet, pos, 0);
    
    /* Read response */
    uint32_t resp_magic, resp_id;
    uint8_t decision;
    uint32_t reason_len;
    
    recv(g_socket_fd, &resp_magic, 4, MSG_WAITALL);
    recv(g_socket_fd, &resp_id, 4, MSG_WAITALL);
    recv(g_socket_fd, &decision, 1, MSG_WAITALL);
    recv(g_socket_fd, &reason_len, 4, MSG_WAITALL);
    
    pthread_mutex_unlock(&g_socket_mutex);
}

/* Get basename of path */
static const char *get_basename(const char *path) {
    if (!path) return NULL;
    const char *last_slash = strrchr(path, '/');
    return last_slash ? last_slash + 1 : path;
}

/* Fast path check - allow */
static int should_fast_allow(const char *cmd) {
    if (!cmd) return 0;
    for (int i = 0; fast_allowed[i] != NULL; i++) {
        if (strcmp(cmd, fast_allowed[i]) == 0) return 1;
    }
    return 0;
}

/* execve interception */
int execve(const char *path, char *const argv[], char *const envp[]) {
    static int (*real_execve)(const char *, char *const[], char *const[]) = NULL;
    
    if (real_execve == NULL) {
        real_execve = dlsym(RTLD_NEXT, "execve");
    }
    
    const char *cmd = get_basename(path);
    
    if (!cmd) {
        return real_execve(path, argv, envp);
    }
    
    /* Skip if already going through readonlybox */
    if (strstr(path, "readonlybox") != NULL) {
        return real_execve(path, argv, envp);
    }
    
    /* Fast allow */
    if (should_fast_allow(cmd)) {
        return real_execve(path, argv, envp);
    }
    
    /* Check for write operations in arguments */
    for (int i = 0; argv && argv[i]; i++) {
        if (strcmp(argv[i], ">") == 0 || strcmp(argv[i], ">>") == 0 ||
            strcmp(argv[i], "2>") == 0 || strcmp(argv[i], "&>") == 0) {
            /* Write operation - ask server */
            uint8_t decision;
            char reason[256];
            
            if (connect_to_server() < 0) {
                /* Server unavailable, allow by default */
                send_log("[readonlybox-client] Server unavailable, allowing write");
                return real_execve(path, argv, envp);
            }
            
            if (send_request(cmd, argv, envp, &decision, reason, sizeof(reason)) < 0) {
                /* Request failed, allow by default */
                send_log("[readonlybox-client] Request failed, allowing");
                return real_execve(path, argv, envp);
            }
            
            if (decision == ROBO_DECISION_DENY) {
                send_log("[readonlybox-client] DENY: %s - %s", cmd, reason);
                errno = EACCES;
                return -1;
            }
            
            /* Allowed */
            return real_execve(path, argv, envp);
        }
    }
    
    /* Read-only operation - check server for policy */
    uint8_t decision;
    char reason[256];
    
    if (connect_to_server() < 0) {
        /* Server unavailable, allow by default */
        send_log("[readonlybox-client] Server unavailable, allowing");
        return real_execve(path, argv, envp);
    }
    
    if (send_request(cmd, argv, envp, &decision, reason, sizeof(reason)) < 0) {
        /* Request failed, allow by default */
        send_log("[readonlybox-client] Request failed, allowing");
        return real_execve(path, argv, envp);
    }
    
    if (decision == ROBO_DECISION_DENY) {
        send_log("[readonlybox-client] DENY: %s - %s", cmd, reason);
        errno = EACCES;
        return -1;
    }
    
    /* Allowed */
    return real_execve(path, argv, envp);
}

/* execveat interception */
int execveat(int dirfd, const char *pathname, char *const argv[],
             char *const envp[], int flags) {
    static int (*real_execveat)(int, const char *, char *const[], char *const[], int) = NULL;
    
    if (real_execveat == NULL) {
        real_execveat = dlsym(RTLD_NEXT, "execveat");
    }
    
    const char *cmd = get_basename(pathname);
    
    if (should_fast_allow(cmd)) {
        return real_execveat(dirfd, pathname, argv, envp, flags);
    }
    
    return real_execveat(dirfd, pathname, argv, envp, flags);
}
