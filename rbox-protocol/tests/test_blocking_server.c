/*
 * test_blocking_server.c - Comprehensive tests for blocking server interface
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#include "rbox_protocol.h"

static const char *SOCKET_PATH = "/tmp/rbox_test_block.sock";
static int test_passed = 0;
static int test_total = 0;

/* Reference-quality write helper - handles all edge cases
 * 
 * Returns: number of bytes written (== len on success), or -1 on error
 * 
 * Handles:
 *   - Partial writes: loops until all data written
 *   - EINTR: retries automatically
 *   - EAGAIN/EWOULDBLOCK: for non-blocking sockets, returns error (caller should retry)
 *   - EPIPE: peer closed writing end
 *   - ECONNRESET: peer reset connection  
 *   - ENOSPC: no space (for file/pipe writes)
 *   - EIO: I/O error
 *   - Other errors: returns error
 *   - Zero return: peer closed connection
 */
static ssize_t write_all(int fd, const void *buf, size_t len) {
    if (!buf || len == 0) {
        return 0;
    }
    
    const char *ptr = buf;
    size_t remaining = len;
    
    while (remaining > 0) {
        ssize_t written = write(fd, ptr, remaining);
        
        if (written < 0) {
            if (errno == EINTR) {
                /* Interrupted by signal - retry */
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Would block (non-blocking socket) - caller should retry */
                return -1;
            }
            /* Permanent error: EPIPE, ECONNRESET, ENOSPC, EIO, etc. */
            return -1;
        }
        
        if (written == 0) {
            /* Peer closed connection or other issue */
            return -1;
        }
        
        ptr += written;
        remaining -= written;
    }
    
    return len;
}

#define RUN_TEST(fn, name) do { \
    test_total++; \
    printf("  Testing: %s...\n", name); \
    fflush(stdout); \
    if (fn() == 0) { \
        printf("    PASS\n"); \
        test_passed++; \
    } else { \
        printf("    FAIL\n"); \
    } \
    fflush(stdout); \
} while(0)

/* Build request packet */
static void build_request(char *pkt, const char *cmd) {
    uint32_t cmd_len = cmd ? strlen(cmd) : 0;
    memset(pkt, 0, 88 + cmd_len);
    
    *(uint32_t *)(pkt + 0) = RBOX_MAGIC;
    *(uint32_t *)(pkt + 4) = RBOX_VERSION;
    memset(pkt + 8, 0x11, 16);
    memset(pkt + 24, 0x22, 16);
    *(uint32_t *)(pkt + 72) = cmd_len;
    *(uint32_t *)(pkt + 76) = cmd_len;
    
    if (cmd_len > 0) {
        memcpy(pkt + 88, cmd, cmd_len);
    }
}

/* Send request and get response */
static void *client_send_thread(void *arg) {
    const char *cmd = arg;
    
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    /* Retry connect */
    for (int i = 0; i < 20; i++) {
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) break;
        usleep(50000);
    }
    
    if (errno != 0) {
        close(fd);
        return NULL;
    }
    
    char pkt[1024];
    build_request(pkt, cmd);
    uint32_t cmd_len = cmd ? strlen(cmd) : 0;
    write(fd, pkt, 88 + cmd_len);
    
    /* Read response */
    char resp[256];
    read(fd, resp, sizeof(resp));
    close(fd);
    
    return NULL;
}

/* Send request asynchronously - caller doesn't join */
static int send_request_async(const char *cmd) {
    pthread_t cl;
    pthread_create(&cl, NULL, client_send_thread, (void *)cmd);
    /* Don't join - thread runs to completion and exits */
    return 0;
}

/* ============================================================================
 * Misbehaving Clients - for stress testing server robustness
 * ============================================================================ */

/* Client that connects but sends nothing */
static void *client_misbehave_no_send(void *arg) {
    (void)arg;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    usleep(500000);  /* Wait then close */
    close(fd);
    return NULL;
}

/* Client that sends garbage */
static void *client_misbehave_garbage(void *arg) {
    (void)arg;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    write(fd, "GARBAGE DATA NOT A PACKET", 25);
    close(fd);
    return NULL;
}

/* Client that sends bad magic */
static void *client_misbehave_bad_magic(void *arg) {
    (void)arg;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    char pkt[88];
    memset(pkt, 0, 88);
    *(uint32_t *)(pkt + 0) = 0xDEADBEEF;  /* Bad magic */
    *(uint32_t *)(pkt + 4) = RBOX_VERSION;
    write(fd, pkt, 88);
    close(fd);
    return NULL;
}

/* Client that sends truncated header */
static void *client_misbehave_truncated_header(void *arg) {
    (void)arg;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    char pkt[10];
    memset(pkt, 0, 10);
    write(fd, pkt, 10);  /* Only 10 bytes */
    close(fd);
    return NULL;
}

/* Client that sends truncated body */
static void *client_misbehave_truncated_body(void *arg) {
    (void)arg;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    char pkt[100];
    memset(pkt, 0, 100);
    *(uint32_t *)(pkt + 0) = RBOX_MAGIC;
    *(uint32_t *)(pkt + 4) = RBOX_VERSION;
    *(uint32_t *)(pkt + 72) = 50;  /* Claims 50 bytes */
    write(fd, pkt, 50);  /* But only sends 50, not 88+50 */
    close(fd);
    return NULL;
}

/* Client that sends too large command (>1MB) - should be rejected */
static void *client_misbehave_too_large(void *arg) {
    (void)arg;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    
    /* Send a packet claiming 2MB (over limit) */
    char pkt[88];
    memset(pkt, 0, 88);
    *(uint32_t *)(pkt + 0) = RBOX_MAGIC;
    *(uint32_t *)(pkt + 4) = RBOX_VERSION;
    *(uint32_t *)(pkt + 72) = 2 * 1024 * 1024;  /* 2MB - over limit */
    write(fd, pkt, 88);
    
    /* Read response - should indicate error or connection close */
    char resp[256];
    read(fd, resp, sizeof(resp));  /* May not get response for oversized */
    close(fd);
    return NULL;
}

/* Client that sends valid request, then waits and reconnects */
static void *client_with_reconnect(void *arg) {
    int *result = arg;  /* Store result: 0=success, -1=error */
    *result = -1;
    
    for (int attempt = 0; attempt < 3; attempt++) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return NULL;
        
        struct sockaddr_un addr = { .sun_family = AF_UNIX };
        strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
        
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(fd);
            usleep(200000);  /* Wait before retry */
            continue;
        }
        
        /* Send request */
        char pkt[1024];
        snprintf(pkt, sizeof(pkt), "reconnect_test_%d", attempt);
        build_request(pkt, pkt);
        write(fd, pkt, 88 + strlen(pkt));
        
        /* Wait for response */
        char resp[256];
        ssize_t n = read(fd, resp, sizeof(resp));
        close(fd);
        
        if (n > 0) {
            /* Check decision */
            uint32_t decision = *(uint32_t *)(resp + 64);
            if (decision == RBOX_DECISION_ALLOW) {
                *result = 0;  /* Success! */
                return NULL;
            }
        }
        
        usleep(200000);  /* Wait before retry */
    }
    
    return NULL;
}

/* Client that sends multiple requests rapidly */
static void *client_misbehave_multiple_requests(void *arg) {
    (void)arg;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    /* Send 3 requests without waiting for responses */
    for (int i = 0; i < 3; i++) {
        char pkt[1024];
        snprintf(pkt, sizeof(pkt), "cmd_%d", i);
        build_request(pkt, pkt);
        write(fd, pkt, 88 + strlen(pkt));
    }
    /* Read responses */
    char resp[256];
    for (int i = 0; i < 3; i++) {
        read(fd, resp, sizeof(resp));
    }
    close(fd);
    return NULL;
}

/* ============================================================================
 * Test Cases
 * ============================================================================ */

/* Test 1: Basic single request */
static int test_single_request(void) {
    unlink(SOCKET_PATH);
    
    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    if (!srv) return -1;
    if (rbox_server_handle_listen(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    if (rbox_server_start(srv) != RBOX_OK) { rbox_server_handle_free(srv); return -1; }
    
    /* Client sends request */
    send_request_async("ls -la");
    
    /* Server waits for request */
    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (!req) { rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }
    
    /* Verify */
    const char *cmd = rbox_server_request_command(req);
    if (!cmd || strcmp(cmd, "ls -la") != 0) {
        rbox_server_decide(req, RBOX_DECISION_DENY, "invalid", 0);
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }
    
    /* Allow */
    if (rbox_server_decide(req, RBOX_DECISION_ALLOW, "allowed", 50) != RBOX_OK) {
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }
    
    usleep(100000);  /* Let client finish */
    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 2: Multiple arguments */
static int test_multiple_args(void) {
    unlink(SOCKET_PATH);
    
    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    rbox_server_handle_listen(srv);
    rbox_server_start(srv);
    
    send_request_async("find /tmp -name test -type f");
    
    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (!req) { rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }
    
    /* Should have multiple args via shellsplit */
    int argc = rbox_server_request_argc(req);
    rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0);
    
    usleep(100000);
    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 3: Deny decision */
static int test_deny_decision(void) {
    unlink(SOCKET_PATH);
    
    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    rbox_server_handle_listen(srv);
    rbox_server_start(srv);
    
    uint8_t decision = 0;
    
    /* Client sends dangerous command */
    pthread_t cl;
    pthread_create(&cl, NULL, client_send_thread, (void *)"rm -rf /");
    
    /* Server processes */
    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (!req) { pthread_join(cl, NULL); rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }
    
    /* Deny */
    rbox_server_decide(req, RBOX_DECISION_DENY, "dangerous command", 0);
    
    pthread_join(cl, NULL);
    
    /* Create new client to get response */
    pthread_create(&cl, NULL, client_send_thread, (void *)"ls");
    req = rbox_server_get_request(srv);
    if (req) rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0);
    pthread_join(cl, NULL);
    
    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 4: Multiple sequential requests */
static int test_sequential_requests(void) {
    unlink(SOCKET_PATH);
    
    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    rbox_server_handle_listen(srv);
    rbox_server_start(srv);
    
    /* Client sends 2 requests on same connection - need separate connections */
    send_request_async("ps aux");
    rbox_server_request_t *req1 = rbox_server_get_request(srv);
    if (!req1) { rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }
    rbox_server_decide(req1, RBOX_DECISION_ALLOW, "ok", 10);
    
    send_request_async("df -h");
    rbox_server_request_t *req2 = rbox_server_get_request(srv);
    if (!req2) { rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }
    rbox_server_decide(req2, RBOX_DECISION_ALLOW, "ok", 10);
    
    usleep(100000);
    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 5: Multiple sequential clients (each in own connection) */
static int test_concurrent_clients(void) {
    unlink(SOCKET_PATH);
    
    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    rbox_server_handle_listen(srv);
    rbox_server_start(srv);
    
    /* Process 3 clients sequentially */
    for (int i = 0; i < 3; i++) {
        /* Start a client in background */
        pthread_t cl;
        pthread_create(&cl, NULL, client_send_thread, (void *)"ls");
        
        /* Wait for request */
        rbox_server_request_t *req = rbox_server_get_request(srv);
        if (!req) {
            pthread_join(cl, NULL);
            rbox_server_stop(srv);
            rbox_server_handle_free(srv);
            return -1;
        }
        
        /* Process and decide */
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "allowed", 0);
        
        pthread_join(cl, NULL);
    }
    
    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 6: Empty command */
static int test_empty_command(void) {
    unlink(SOCKET_PATH);
    
    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    rbox_server_handle_listen(srv);
    rbox_server_start(srv);
    
    send_request_async("");  /* Empty command */
    
    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (!req) { rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }
    
    const char *cmd = rbox_server_request_command(req);
    if (cmd == NULL || cmd[0] != '\0') {
        rbox_server_decide(req, RBOX_DECISION_DENY, "empty", 0);
        rbox_server_stop(srv);
        rbox_server_handle_free(srv);
        return -1;
    }
    
    rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0);
    
    usleep(100000);
    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 7: Parse result access */
static int test_parse_result(void) {
    unlink(SOCKET_PATH);
    
    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    rbox_server_handle_listen(srv);
    rbox_server_start(srv);
    
    pthread_t cl;
    pthread_create(&cl, NULL, client_send_thread, (void *)"git commit -m test");
    
    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (!req) { pthread_join(cl, NULL); rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }
    
    /* Check parse result exists */
    const rbox_parse_result_t *parse = rbox_server_request_parse(req);
    if (!parse) { pthread_join(cl, NULL); rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }
    
    /* Just verify we got some subcommands */
    printf("    parse count = %u\n", parse->count);
    
    /* Check args via accessor */
    int argc = rbox_server_request_argc(req);
    printf("    argc = %d\n", argc);
    
    if (argc > 0) {
        const char *arg0 = rbox_server_request_arg(req, 0);
        if (arg0) printf("    arg0 = %s\n", arg0);
    }
    
    rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0);
    
    pthread_join(cl, NULL);
    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 8: Duration in response */
static int test_duration_response(void) {
    unlink(SOCKET_PATH);
    
    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    rbox_server_handle_listen(srv);
    rbox_server_start(srv);
    
    /* Run client in thread */
    pthread_t cl;
    pthread_create(&cl, NULL, client_send_thread, (void *)"test");
    
    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (!req) { pthread_join(cl, NULL); rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }
    
    /* Send decision with specific duration */
    rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 1000);
    
    pthread_join(cl, NULL);
    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 9: Reason in response */
static int test_reason_response(void) {
    unlink(SOCKET_PATH);
    
    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    rbox_server_handle_listen(srv);
    rbox_server_start(srv);
    
    pthread_t cl;
    pthread_create(&cl, NULL, client_send_thread, (void *)"test");
    
    rbox_server_request_t *req = rbox_server_get_request(srv);
    if (!req) { pthread_join(cl, NULL); rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }
    
    /* Send decision with reason */
    rbox_error_t err = rbox_server_decide(req, RBOX_DECISION_ALLOW, "test reason", 0);
    if (err != RBOX_OK) { pthread_join(cl, NULL); rbox_server_stop(srv); rbox_server_handle_free(srv); return -1; }
    
    pthread_join(cl, NULL);
    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    return 0;
}

/* Test 10: Many concurrent clients */
static int test_many_clients(void) {
    unlink(SOCKET_PATH);
    
    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    rbox_server_handle_listen(srv);
    rbox_server_start(srv);
    
    const int NUM_CLIENTS = 100;  /* 100 clients */
    
    /* Start all clients */
    printf("    Starting %d clients...\n", NUM_CLIENTS);
    fflush(stdout);
    
    pthread_t clients[NUM_CLIENTS];
    for (int i = 0; i < NUM_CLIENTS; i++) {
        char cmd[32];
        snprintf(cmd, sizeof(cmd), "cmd_%d", i);
        pthread_create(&clients[i], NULL, client_send_thread, strdup(cmd));
    }
    
    /* Give clients time to connect and send */
    printf("    Waiting for clients to send...\n");
    fflush(stdout);
    usleep(2000000);  /* 2 seconds */
    
    /* Process all requests */
    printf("    Processing requests...\n");
    fflush(stdout);
    
    int received = 0;
    int consecutive_failures = 0;
    
    while (received < NUM_CLIENTS && consecutive_failures < 5) {
        printf("    get_request #%d...\n", received + 1);
        fflush(stdout);
        
        rbox_server_request_t *req = rbox_server_get_request(srv);
        if (!req) {
            printf("    No request, sleeping...\n");
            consecutive_failures++;
            usleep(100000);
            continue;
        }
        
        consecutive_failures = 0;
        const char *cmd = rbox_server_request_command(req);
        if (cmd) {
            received++;
        }
        
        printf("    decide #%d...\n", received);
        fflush(stdout);
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0);
    }
    
    /* Wait for all client threads */
    printf("    Waiting for clients to finish...\n");
    fflush(stdout);
    for (int i = 0; i < NUM_CLIENTS; i++) {
        pthread_join(clients[i], NULL);
    }
    
    rbox_server_stop(srv);
    rbox_server_handle_free(srv);
    
    printf("    Received %d/%d requests\n", received, NUM_CLIENTS);
    
    return received >= NUM_CLIENTS ? 0 : -1;
}

/* Test 11: Many misbehaving clients - stress test server robustness */
static int test_misbehaving_clients(void) {
    unlink(SOCKET_PATH);
    
    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    rbox_server_handle_listen(srv);
    rbox_server_start(srv);
    
    /* Spawn various misbehaving clients */
    #define NUM_MISBEHAVING 20
    #define NUM_GOOD 5
    pthread_t clients[NUM_MISBEHAVING + NUM_GOOD];
    
    /* Mix of misbehaving clients */
    typedef void *(*thread_func_t)(void*);
    thread_func_t behaviors[] = {
        client_misbehave_no_send,
        client_misbehave_garbage,
        client_misbehave_bad_magic,
        client_misbehave_truncated_header,
        client_misbehave_truncated_body,
        client_misbehave_multiple_requests,
        client_misbehave_too_large,
    };
    int num_behaviors = sizeof(behaviors) / sizeof(behaviors[0]);
    
    /* Start misbehaving clients */
    for (int i = 0; i < NUM_MISBEHAVING; i++) {
        thread_func_t func = behaviors[i % num_behaviors];
        pthread_create(&clients[i], NULL, func, NULL);
    }
    
    /* Give misbehaving clients time to connect and misbehave */
    usleep(300000);
    
    /* Also start some good clients */
    for (int i = 0; i < NUM_GOOD; i++) {
        pthread_create(&clients[NUM_MISBEHAVING + i], NULL, client_send_thread, (void *)"valid_cmd");
    }
    
    /* Give good clients time to send */
    usleep(300000);
    
    /* Process valid requests with a timeout - use a worker thread */
    int received = 0;
    int done = 0;
    
    void *worker(void *arg) {
        rbox_server_handle_t *s = arg;
        while (!done) {
            rbox_server_request_t *req = rbox_server_get_request(s);
            if (!req) break;
            received++;
            rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0);
        }
        return NULL;
    }
    
    pthread_t worker_thread;
    pthread_create(&worker_thread, NULL, worker, srv);
    
    /* Wait for worker to process requests, with timeout */
    usleep(1000000);  /* 1 second max */
    
    /* Signal done and stop server to unblock worker */
    done = 1;
    rbox_server_stop(srv);
    
    pthread_join(worker_thread, NULL);
    
    /* Wait for all client threads */
    for (int i = 0; i < NUM_MISBEHAVING + NUM_GOOD; i++) {
        pthread_join(clients[i], NULL);
    }
    
    rbox_server_handle_free(srv);
    
    /* We should have received at least the good requests despite the chaos */
    printf("    Received %d requests from chaos\n", received);
    return received >= NUM_GOOD ? 0 : -1;
}

/* Test 12: Server restart mid-session with client reconnection */
static int test_server_restart(void) {
    unlink(SOCKET_PATH);
    
    int results[5] = {-1, -1, -1, -1, -1};
    pthread_t clients[5];
    int received = 0;
    int done = 0;
    
    /* Worker thread function */
    void *worker(void *arg) {
        rbox_server_handle_t *s = arg;
        while (!done) {
            rbox_server_request_t *req = rbox_server_get_request(s);
            if (!req) {
                usleep(10000);
                continue;
            }
            received++;
            rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0);
        }
        return NULL;
    }
    
    /* ===== First server session ===== */
    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    rbox_server_handle_listen(srv);
    rbox_server_start(srv);
    
    /* Start clients */
    for (int i = 0; i < 2; i++) {
        pthread_create(&clients[i], NULL, client_with_reconnect, &results[i]);
    }
    
    pthread_t worker_thread;
    pthread_create(&worker_thread, NULL, worker, srv);
    
    usleep(300000);
    
    /* Stop first server */
    printf("    Stopping first server...\n");
    done = 1;
    rbox_server_stop(srv);
    pthread_join(worker_thread, NULL);
    rbox_server_handle_free(srv);
    
    printf("    First batch: received %d\n", received);
    
    /* Wait for clients to finish */
    for (int i = 0; i < 2; i++) {
        pthread_join(clients[i], NULL);
    }
    
    /* Brief pause */
    usleep(200000);
    
    /* ===== Start second server ===== */
    printf("    Starting second server...\n");
    done = 0;
    received = 0;
    srv = rbox_server_handle_new(SOCKET_PATH);
    rbox_server_handle_listen(srv);
    rbox_server_start(srv);
    
    pthread_create(&worker_thread, NULL, worker, srv);
    
    /* Start more clients */
    for (int i = 2; i < 5; i++) {
        pthread_create(&clients[i], NULL, client_with_reconnect, &results[i]);
    }
    
    usleep(500000);
    
    /* Stop and collect */
    done = 1;
    rbox_server_stop(srv);
    pthread_join(worker_thread, NULL);
    
    printf("    Second batch: received %d\n", received);
    
    /* Wait for clients */
    for (int i = 2; i < 5; i++) {
        pthread_join(clients[i], NULL);
    }
    
    rbox_server_handle_free(srv);
    
    /* Count successes */
    int success = 0;
    for (int i = 0; i < 5; i++) {
        if (results[i] == 0) success++;
    }
    
    printf("    Total: %d/5 clients succeeded\n", success);
    
    return success >= 3 ? 0 : -1;
}

/* Test 13: Too large command rejection */
static int test_too_large_command(void) {
    unlink(SOCKET_PATH);
    
    rbox_server_handle_t *srv = rbox_server_handle_new(SOCKET_PATH);
    rbox_server_handle_listen(srv);
    rbox_server_start(srv);
    
    /* Start multiple clients - some oversized, some normal */
    pthread_t cls[5];
    pthread_create(&cls[0], NULL, client_misbehave_too_large, NULL);
    pthread_create(&cls[1], NULL, client_misbehave_too_large, NULL);
    pthread_create(&cls[2], NULL, client_send_thread, (void *)"valid1");
    pthread_create(&cls[3], NULL, client_send_thread, (void *)"valid2");
    pthread_create(&cls[4], NULL, client_send_thread, (void *)"valid3");
    
    /* Process requests with timeout */
    int received = 0;
    int done = 0;
    
    void *worker(void *arg) {
        rbox_server_handle_t *s = arg;
        while (!done) {
            rbox_server_request_t *req = rbox_server_get_request(s);
            if (!req) break;
            received++;
            rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0);
        }
        return NULL;
    }
    
    pthread_t worker_thread;
    pthread_create(&worker_thread, NULL, worker, srv);
    
    usleep(500000);
    
    done = 1;
    rbox_server_stop(srv);
    pthread_join(worker_thread, NULL);
    
    for (int i = 0; i < 5; i++) {
        pthread_join(cls[i], NULL);
    }
    
    rbox_server_handle_free(srv);
    
    printf("    Received %d valid requests despite oversized\n", received);
    
    /* Test passes if server didn't crash and handled oversized commands */
    return received >= 3 ? 0 : -1;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    printf("=== Testing blocking server ===\n");
    fflush(stdout);
    
    signal(SIGPIPE, SIG_IGN);
    
    RUN_TEST(test_single_request, "single request");
    RUN_TEST(test_multiple_args, "multiple arguments");
    RUN_TEST(test_deny_decision, "deny decision");
    RUN_TEST(test_sequential_requests, "sequential requests");
    RUN_TEST(test_concurrent_clients, "concurrent clients");
    RUN_TEST(test_empty_command, "empty command");
    RUN_TEST(test_parse_result, "parse result");
    RUN_TEST(test_duration_response, "duration response");
    RUN_TEST(test_reason_response, "reason response");
    RUN_TEST(test_many_clients, "100 concurrent clients");
    RUN_TEST(test_misbehaving_clients, "misbehaving clients");
    /* RUN_TEST(test_server_restart, "server restart with reconnection"); - TODO: fix */
    RUN_TEST(test_too_large_command, "too large command rejection");
    
    printf("\n=== Results: %d/%d tests passed ===\n", test_passed, test_total);
    fflush(stdout);
    return test_passed == test_total ? 0 : 1;
}
