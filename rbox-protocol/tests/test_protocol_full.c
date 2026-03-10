/*
 * test_protocol_full.c - Comprehensive protocol tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <signal.h>

#include "rbox_protocol.h"

/* Include internal headers */
#include "../src/socket.h"

/* Also include protocol definitions for the offsets in tests */
#include "rbox_protocol_defs.h"

/* Forward declare stream for internal access in tests */

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static int test_count = 0;
static int pass_count = 0;

/* Ignore SIGPIPE to prevent crashes on broken connections */
__attribute__((constructor))
static void ignore_sigpipe(void) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

#define TEST(name) \
    do { \
        printf("  Testing: %s...\n", name); \
        test_count++; \
    } while(0)

#define ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            printf("    FAIL: %s\n", msg); \
            return -1; \
        } \
    } while(0)

#define PASS() \
    do { \
        printf("    PASS\n"); \
        pass_count++; \
        return 0; \
    } while(0)

/* ============================================================
 * HEADER TESTS
 * ============================================================ */

static int test_header_valid(void) {
    TEST("valid header");
    
    rbox_header_t header = {0};
    header.magic = RBOX_MAGIC;
    header.version = RBOX_VERSION;
    header.type = RBOX_MSG_REQ;
    header.flags = RBOX_FLAG_FIRST;
    header.chunk_len = 100;
    header.total_len = 100;
    
    /* Calculate checksum over first 84 bytes (v5 protocol) */
    header.checksum = rbox_calculate_checksum(&header, 84);
    
    ASSERT(rbox_header_validate(&header) == RBOX_OK, "valid header should pass");
    PASS();
}

static int test_header_magic(void) {
    TEST("invalid magic");
    
    rbox_header_t header = {0};
    header.magic = 0xDEADBEEF;
    header.version = RBOX_VERSION;
    header.checksum = rbox_calculate_checksum(&header, RBOX_HEADER_SIZE);
    
    ASSERT(rbox_header_validate(&header) == RBOX_ERR_MAGIC, "invalid magic should fail");
    PASS();
}

static int test_header_version(void) {
    TEST("invalid version");
    
    rbox_header_t header = {0};
    header.magic = RBOX_MAGIC;
    header.version = 999;
    header.checksum = rbox_calculate_checksum(&header, 68);  /* 68 bytes, not 72 */
    
    ASSERT(rbox_header_validate(&header) == RBOX_ERR_VERSION, "invalid version should fail");
    PASS();
}

static int test_header_checksum(void) {
    TEST("checksum validation");
    
    /* Test 1: Valid CRC32 checksum should pass */
    rbox_header_t header = {0};
    header.magic = RBOX_MAGIC;
    header.version = RBOX_VERSION;
    header.flags = RBOX_FLAG_FIRST;
    header.chunk_len = 100;
    header.total_len = 100;
    header.checksum = rbox_calculate_checksum(&header, 84);  /* 84 bytes for v5 */
    
    ASSERT(rbox_header_validate(&header) == RBOX_OK, "valid CRC32 checksum should pass");
    
    /* Test 2: Wrong checksum should fail */
    rbox_header_t header2 = {0};
    header2.magic = RBOX_MAGIC;
    header2.version = RBOX_VERSION;
    header2.checksum = 0x12345678;
    
    ASSERT(rbox_header_validate(&header2) == RBOX_ERR_CHECKSUM, "wrong checksum should fail");
    
    PASS();
}

/* ============================================================
 * ERROR STRING TESTS
 * ============================================================ */

static int test_strerror(void) {
    TEST("error strings");
    
    ASSERT(strcmp(rbox_strerror(RBOX_OK), "Success") == 0, "RBOX_OK");
    ASSERT(strcmp(rbox_strerror(RBOX_ERR_INVALID), "Invalid parameter") == 0, "INVALID");
    ASSERT(strcmp(rbox_strerror(RBOX_ERR_MAGIC), "Invalid magic number") == 0, "MAGIC");
    ASSERT(strcmp(rbox_strerror(RBOX_ERR_VERSION), "Unsupported protocol version") == 0, "VERSION");
    ASSERT(strcmp(rbox_strerror(RBOX_ERR_CHECKSUM), "Checksum mismatch") == 0, "CHECKSUM");
    ASSERT(strcmp(rbox_strerror(RBOX_ERR_TRUNCATED), "Truncated data") == 0, "TRUNCATED");
    ASSERT(strcmp(rbox_strerror(RBOX_ERR_IO), "I/O error") == 0, "IO");
    ASSERT(strcmp(rbox_strerror(RBOX_ERR_MEMORY), "Memory allocation failed") == 0, "MEMORY");
    
    PASS();
}

/* ============================================================
 * SOCKET TESTS
 * ============================================================ */

static int test_socket_create(void) {
    TEST("server socket create/bind");
    
    const char *test_sock = "/tmp/rbox_test.sock";
    unlink(test_sock);
    
    rbox_server_t *server = rbox_server_new(test_sock);
    ASSERT(server != NULL, "server should be created");
    
    rbox_error_t err = rbox_server_listen(server);
    ASSERT(err == RBOX_OK, "server should listen");
    
    rbox_server_free(server);
    
    /* File should be cleaned up */
    struct stat st;
    ASSERT(stat(test_sock, &st) < 0, "socket file should be removed");
    
    PASS();
}

static int test_socket_connect(void) {
    TEST("client connect");
    
    const char *test_sock = "/tmp/rbox_test_connect.sock";
    unlink(test_sock);
    
    /* Create server */
    rbox_server_t *server = rbox_server_new(test_sock);
    ASSERT(server != NULL, "server created");
    
    rbox_server_listen(server);
    
    /* Connect client */
    rbox_client_t *client = rbox_client_connect(test_sock);
    ASSERT(client != NULL, "client should connect");
    
    rbox_client_close(client);
    rbox_server_free(server);
    
    PASS();
}

static int test_accept_loop(void) {
    TEST("accept and communication");
    
    const char *test_sock = "/tmp/rbox_test_accept.sock";
    unlink(test_sock);
    
    /* Create server */
    rbox_server_t *server = rbox_server_new(test_sock);
    rbox_server_listen(server);
    
    /* Client connect */
    rbox_client_t *client = rbox_client_connect(test_sock);
    ASSERT(client != NULL, "client connected");
    
    /* Server accept */
    rbox_client_t *server_client = rbox_server_accept(server);
    ASSERT(server_client != NULL, "server accepted");
    
    rbox_client_close(client);
    rbox_client_close(server_client);
    rbox_server_free(server);
    
    PASS();
}

/* ============================================================
 * PACKET BUILDING TESTS
 * ============================================================ */

static int test_build_request(void) {
    TEST("build request packet");
    
    /* Build a request manually and verify structure matches header */
    char packet[4096];
    size_t pos = 0;
    
    /* Header (88 bytes) */
    uint32_t magic = RBOX_MAGIC;
    uint32_t version = RBOX_VERSION;
    uint32_t msg_type = RBOX_MSG_REQ;
    uint32_t flags = RBOX_FLAG_FIRST;
    uint64_t offset = 0;
    uint32_t chunk_len = 100;
    uint64_t total_len = 100;
    
    memcpy(packet + pos, &magic, 4); pos += 4;
    memcpy(packet + pos, &version, 4); pos += 4;
    memset(packet + pos, 'A', 16); pos += 16; /* ClientID */
    memset(packet + pos, 'R', 16); pos += 16; /* RequestID */
    memset(packet + pos, 0, 16); pos += 16;  /* ServerID */
    memcpy(packet + pos, &msg_type, 4); pos += 4;
    memcpy(packet + pos, &flags, 4); pos += 4;
    memcpy(packet + pos, &offset, 8); pos += 8;
    memcpy(packet + pos, &chunk_len, 4); pos += 4;
    memcpy(packet + pos, &total_len, 8); pos += 8;
    
    /* Checksum */
    uint32_t checksum = rbox_calculate_checksum(packet, 68);
    memcpy(packet + pos, &checksum, 4); pos += 4;
    
    /* Body */
    const char *cmd = "ls";
    memcpy(packet + pos, cmd, strlen(cmd) + 1); pos += strlen(cmd) + 1;
    
    const char *arg1 = "-la";
    memcpy(packet + pos, arg1, strlen(arg1) + 1); pos += strlen(arg1) + 1;
    
    const char *arg2 = "/tmp";
    memcpy(packet + pos, arg2, strlen(arg2) + 1); pos += strlen(arg2) + 1;
    
    const char *env1 = "HOME=/root";
    memcpy(packet + pos, env1, strlen(env1) + 1); pos += strlen(env1) + 1;
    
    /* Verify header is 88 bytes */
    ASSERT(pos >= 88, "header should be 88 bytes");
    
    /* Verify header parsing */
    rbox_header_t *hdr = (rbox_header_t *)packet;
    ASSERT(hdr->magic == RBOX_MAGIC, "parsed magic");
    ASSERT(hdr->version == RBOX_VERSION, "parsed version");
    ASSERT(hdr->type == RBOX_MSG_REQ, "parsed type");
    ASSERT(hdr->flags == RBOX_FLAG_FIRST, "parsed flags");
    ASSERT(hdr->chunk_len == 100, "parsed chunk_len");
    
    PASS();
}

static int test_build_response(void) {
    TEST("build response packet");
    
    char packet[1024];
    size_t pos = 0;
    
    /* Response header */
    uint32_t magic = RBOX_MAGIC;
    uint8_t server_id[16] = {0};
    uint32_t id = 1; /* Request ID */
    uint8_t decision = RBOX_DECISION_ALLOW;
    const char *reason = "read-only command";
    uint32_t reason_len = strlen(reason) + 1;
    
    memcpy(packet + pos, &magic, 4); pos += 4;
    memcpy(packet + pos, server_id, 16); pos += 16;
    memcpy(packet + pos, &id, 4); pos += 4;
    memcpy(packet + pos, &decision, 1); pos += 1;
    memcpy(packet + pos, &reason_len, 4); pos += 4;
    memcpy(packet + pos, reason, reason_len); pos += reason_len;
    
    /* Verify */
    ASSERT(pos == 4 + 16 + 4 + 1 + 4 + reason_len, "response size");
    
    /* Parse back */
    ASSERT(memcmp(packet, &magic, 4) == 0, "response magic");
    ASSERT(packet[24] == decision, "response decision");
    
    PASS();
}

/* ============================================================
 * SHELLSPLIT PARSING TESTS
 * ============================================================ */

static int test_shellsplit_simple(void) {
    TEST("shellsplit simple command");
    
    const char *cmd = "ls -la /tmp";
    rbox_parse_result_t result = {0};
    
    rbox_error_t err = rbox_command_parse(cmd, strlen(cmd), &result);
    ASSERT(err == RBOX_OK, "parse should succeed");
    ASSERT(result.count >= 1, "should have at least 1 subcommand");
    
    /* First subcommand should be "ls" */
    uint32_t len = 0;
    const char *sub = rbox_get_subcommand(cmd, &result.subcommands[0], &len);
    ASSERT(len > 0, "subcommand should have length");
    ASSERT(strncmp(sub, "ls", 2) == 0, "first subcommand should be ls");
    
    PASS();
}

static int test_shellsplit_pipeline(void) {
    TEST("shellsplit pipeline");
    
    const char *cmd = "ps aux | grep nginx | head -5";
    rbox_parse_result_t result = {0};
    
    rbox_error_t err = rbox_command_parse(cmd, strlen(cmd), &result);
    ASSERT(err == RBOX_OK, "parse should succeed");
    ASSERT(result.count == 3, "should have 3 subcommands");
    
    /* Verify each subcommand */
    uint32_t len0, len1, len2;
    const char *sub0 = rbox_get_subcommand(cmd, &result.subcommands[0], &len0);
    const char *sub1 = rbox_get_subcommand(cmd, &result.subcommands[1], &len1);
    const char *sub2 = rbox_get_subcommand(cmd, &result.subcommands[2], &len2);
    
    ASSERT(strncmp(sub0, "ps aux", 6) == 0, "first subcommand");
    ASSERT(strncmp(sub1, "grep nginx", 10) == 0, "second subcommand");
    ASSERT(strncmp(sub2, "head -5", 7) == 0, "third subcommand");
    
    PASS();
}

static int test_shellsplit_redirect(void) {
    TEST("shellsplit redirect");
    
    const char *cmd = "cat file.txt > output.txt";
    rbox_parse_result_t result = {0};
    
    rbox_error_t err = rbox_command_parse(cmd, strlen(cmd), &result);
    ASSERT(err == RBOX_OK, "parse should succeed");
    
    /* First subcommand should be "cat file.txt" */
    uint32_t len = 0;
    const char *sub = rbox_get_subcommand(cmd, &result.subcommands[0], &len);
    
    printf("    subcommand: %.*s\n", len, sub);
    
    PASS();
}

static int test_shellsplit_dup(void) {
    TEST("shellsplit dup subcommand");
    
    const char *cmd = "ls -la";
    rbox_parse_result_t result = {0};
    
    rbox_command_parse(cmd, strlen(cmd), &result);
    
    char *dup = rbox_dup_subcommand(cmd, &result.subcommands[0]);
    ASSERT(dup != NULL, "dup should succeed");
    ASSERT(strcmp(dup, "ls -la") == 0, "dup should match");
    
    free(dup);
    PASS();
}

/* ============================================================
 * CLIENT-SERVER INTEGRATION TESTS
 * ============================================================ */

/* ============================================================
 * INTEGRATION TESTS - Both sides use the library
 * Each test uses a dedicated temporary socket
 * ============================================================ */

/* Simulated server that reads request and sends configurable response */
static void *server_for_test1(void *arg);
static void *server_for_test2(void *arg);
static void *server_for_test3(void *arg);
static void *server_for_test4(void *arg);

/* ============================================================
 * COMPREHENSIVE INTEGRATION TEST FRAMEWORK
 * ============================================================ */

/* Hickup types for client */
typedef enum {
    HICKUP_NONE = 0,
    HICKUP_SOCKET_RETRY,       /* Connection fails first time */
    HICKUP_REQUEST_RESEND,    /* Request needs to be resent */
    HICKUP_DELAYED_RESPONSE,   /* Response is delayed */
    HICKUP_INVALID_MAGIC,     /* Send invalid magic number */
    HICKUP_INVALID_VERSION,   /* Send invalid protocol version */
    HICKUP_TRUNCATED_HEADER,  /* Send only partial header */
    HICKUP_MULTI_ARG,         /* Command with multiple arguments */
    HICKUP_WITH_ENV,          /* Command with environment variables */
    /* Chunked transfer hickups */
    HICKUP_CHUNK_DROP_MIDDLE, /* Drop a chunk mid-transfer */
    HICKUP_CHUNK_DROP_LAST,   /* Drop last chunk */
    HICKUP_CHUNK_RESUME,      /* Resume after partial send */
} hickup_type_t;

/* Server decision */
typedef enum {
    SERVER_ALLOW = 0,
    SERVER_DENY,
} server_decision_t;

/* Server config for test */
typedef struct {
    const char *socket_path;
    server_decision_t decision;
    hickup_type_t hickup;
    _Atomic int *ready_flag;
    _Atomic int *request_count;
    _Atomic int server_closed_flag;
} test_server_config_t;

/* Client result */
typedef struct {
    uint8_t decision;      /* ALLOW or DENY */
    char reason[256];
    int success;           /* 1 if successful */
    int attempts;         /* Number of connection attempts */
} client_result_t;

/* Build a test request packet - v5 protocol */
static void build_request_packet(char *packet, size_t *out_len, 
                                const char *cmd, int argc, const char **args) {
    memset(packet, 0, 4096);
    
    /* Header - v5 protocol */
    uint32_t magic = RBOX_MAGIC;
    uint32_t version = RBOX_VERSION;
    uint32_t msg_type = RBOX_MSG_REQ;
    uint32_t flags = RBOX_FLAG_FIRST;
    uint64_t offset = 0;
    uint32_t chunk_len = 0;
    uint64_t total_len = 0;
    
    memcpy(packet + RBOX_HEADER_OFFSET_MAGIC, &magic, 4);
    memcpy(packet + RBOX_HEADER_OFFSET_VERSION, &version, 4);
    memset(packet + RBOX_HEADER_OFFSET_CLIENT_ID, 'C', 16);
    memset(packet + RBOX_HEADER_OFFSET_REQUEST_ID, 'R', 16);
    memcpy(packet + RBOX_HEADER_OFFSET_TYPE, &msg_type, 4);
    memcpy(packet + RBOX_HEADER_OFFSET_FLAGS, &flags, 4);
    memcpy(packet + RBOX_HEADER_OFFSET_OFFSET, &offset, 8);
    memcpy(packet + RBOX_HEADER_OFFSET_CHUNK_LEN, &chunk_len, 4);
    memcpy(packet + RBOX_HEADER_OFFSET_TOTAL_LEN, &total_len, 8);
    
    /* Body: command + args */
    size_t pos = RBOX_HEADER_SIZE;
    
    memcpy(packet + pos, cmd, strlen(cmd) + 1);
    pos += strlen(cmd) + 1;
    
    for (int i = 0; i < argc; i++) {
        memcpy(packet + pos, args[i], strlen(args[i]) + 1);
        pos += strlen(args[i]) + 1;
    }
    
    /* Calculate chunk_len (body size) */
    chunk_len = pos - RBOX_HEADER_SIZE;
    total_len = chunk_len;
    memcpy(packet + RBOX_HEADER_OFFSET_CHUNK_LEN, &chunk_len, 4);
    memcpy(packet + RBOX_HEADER_OFFSET_TOTAL_LEN, &total_len, 8);
    
    /* Calculate checksum over bytes 0-83 */
    uint32_t checksum = rbox_calculate_checksum(packet, 84);
    memcpy(packet + RBOX_HEADER_OFFSET_CHECKSUM, &checksum, 4);
    
    *out_len = pos;
}

/* Parse response packet */
static int parse_response(const char *resp, size_t len, client_result_t *result) {
    if (len < RBOX_RESPONSE_HEADER_SIZE) {
        return -1;
    }
    
    /* Check magic */
    uint32_t magic = *(uint32_t *)resp;
    if (magic != RBOX_MAGIC) {
        return -1;
    }
    
    /* Get decision */
    result->decision = resp[RBOX_RESPONSE_OFFSET_DECISION];
    fprintf(stderr, "    DEBUG: full response: ");
    for (size_t i = 0; i < len && i < 40; i++) {
        fprintf(stderr, "%02x ", (unsigned char)resp[i]);
    }
    fprintf(stderr, "\n    DEBUG: response[24]=%d (0x%02x) magic=0x%08x\n", 
            result->decision, resp[24], *(uint32_t *)resp);
    
    /* Get reason length */
    uint32_t reason_len = *(uint32_t *)(resp + RBOX_RESPONSE_OFFSET_REASON_LEN);
    
    /* Get reason */
    if (reason_len > 0 && reason_len < sizeof(result->reason)) {
        memcpy(result->reason, resp + RBOX_RESPONSE_OFFSET_REASON, reason_len);
        result->reason[reason_len] = '\0';
    } else {
        result->reason[0] = '\0';
    }
    
    return 0;
}

/* Send request with retry logic - simulates client behavior */
static int send_request_with_retry(const char *socket_path, 
                                   const char *cmd, int argc, const char **args,
                                   hickup_type_t hickup,
                                   client_result_t *result) {
    result->success = 0;
    result->attempts = 0;
    
    /* Retry loop - up to 3 attempts */
    for (int attempt = 0; attempt < 3; attempt++) {
        result->attempts++;
        
        /* Simulate hickup: socket retry - fail first connection attempt */
        if (hickup == HICKUP_SOCKET_RETRY && attempt == 0) {
            /* Try to connect to non-existent socket first */
            rbox_client_t *bad_client = rbox_client_connect("/tmp/nonexistent.sock");
            if (bad_client) {
                rbox_client_close(bad_client);
            }
            /* Wait for server to be ready using poll on our real socket path */
            struct pollfd pfd = {
                .fd = socket(AF_UNIX, SOCK_STREAM, 0),
                .events = POLLOUT,
                .revents = 0
            };
            if (pfd.fd >= 0) {
                close(pfd.fd);
            }
            continue;
        }
        
        /* Connect */
        rbox_client_t *client = rbox_client_connect(socket_path);
        if (!client) {
            continue;
        }
        
        /* Build request */
        char packet[4096];
        size_t packet_len;
        build_request_packet(packet, &packet_len, cmd, argc, args);
        
        /* Simulate hickup: request resend - send invalid checksum on first attempt */
        if (hickup == HICKUP_REQUEST_RESEND && attempt == 0) {
            /* Build packet with wrong checksum */
            char bad_packet[4096];
            size_t bad_len;
            build_request_packet(bad_packet, &bad_len, cmd, argc, args);
            /* Corrupt the checksum */
            *(uint32_t *)(bad_packet + 68) ^= 0xFFFFFFFF;
            write(rbox_client_fd(client), bad_packet, bad_len);
            rbox_client_close(client);
            continue;
        }
        
        /* Poll for write readiness before sending */
        struct pollfd pfd = {
            .fd = rbox_client_fd(client),
            .events = POLLOUT,
            .revents = 0
        };
        
        int poll_ret = poll(&pfd, 1, 5000);
        if (poll_ret <= 0 || !(pfd.revents & POLLOUT)) {
            rbox_client_close(client);
            continue;
        }
        
        /* Send request */
        ssize_t sent = write(rbox_client_fd(client), packet, packet_len);
        if (sent != (ssize_t)packet_len) {
            rbox_client_close(client);
            continue;
        }
        
        /* Simulate hickup: delayed response - close and reconnect */
        if (hickup == HICKUP_DELAYED_RESPONSE && attempt == 0) {
            rbox_client_close(client);
            /* Wait a bit then retry */
            struct timespec ts = {0, 200000000};  /* 200ms */
            nanosleep(&ts, NULL);
            continue;
        }
        
        /* Simulate hickup: invalid magic - send garbage */
        if (hickup == HICKUP_INVALID_MAGIC && attempt == 0) {
            char bad_packet[72];
            memset(bad_packet, 0xFF, 72);  /* Invalid magic */
            write(rbox_client_fd(client), bad_packet, 72);
            rbox_client_close(client);
            continue;
        }
        
        /* Simulate hickup: invalid version */
        if (hickup == HICKUP_INVALID_VERSION && attempt == 0) {
            char bad_packet[4096];
            size_t bad_len;
            build_request_packet(bad_packet, &bad_len, cmd, argc, args);
            /* Set invalid version */
            *(uint32_t *)(bad_packet + 4) = 999;
            /* Recalculate checksum */
            *(uint32_t *)(bad_packet + 68) = 0;
            *(uint32_t *)(bad_packet + 68) = rbox_calculate_checksum(bad_packet, 68);
            write(rbox_client_fd(client), bad_packet, bad_len);
            rbox_client_close(client);
            continue;
        }
        
        /* Simulate hickup: truncated header */
        if (hickup == HICKUP_TRUNCATED_HEADER && attempt == 0) {
            char partial[10];
            memset(partial, 'A', 10);
            write(rbox_client_fd(client), partial, 10);
            rbox_client_close(client);
            continue;
        }
        
        /* Poll for read readiness (response) */
        pfd.events = POLLIN;
        pfd.revents = 0;
        poll_ret = poll(&pfd, 1, 5000);
        
        if (poll_ret <= 0 || !(pfd.revents & POLLIN)) {
            rbox_client_close(client);
            continue;
        }
        
        /* Read response */
        char resp[1024];
        ssize_t n = read(rbox_client_fd(client), resp, sizeof(resp));
        
        if (n > 0) {
            /* Success! Parse response */
            if (parse_response(resp, n, result) == 0) {
                result->success = 1;
                rbox_client_close(client);
                return 0;  /* Success */
            }
        }
        
        /* Failed */
        rbox_client_close(client);
    }
    
    return -1;  /* All retries failed */
}

/* Send large request using chunked transfer */
static int send_chunked_request(const char *socket_path,
                                const char *cmd, int argc, const char **args,
                                hickup_type_t hickup,
                                client_result_t *result) {
    result->success = 0;
    result->attempts = 0;
    
    /* Build the full request data */
    char full_data[1024 * 1024];  /* 1MB max */
    size_t pos = 0;
    
    /* Command */
    size_t cmd_len = strlen(cmd);
    memcpy(full_data + pos, cmd, cmd_len + 1);
    pos += cmd_len + 1;
    
    /* Arguments */
    for (int i = 0; i < argc; i++) {
        size_t arg_len = strlen(args[i]);
        if (pos + arg_len + 1 >= sizeof(full_data)) break;
        memcpy(full_data + pos, args[i], arg_len + 1);
        pos += arg_len + 1;
    }
    
    size_t total_len = pos;
    
    /* Generate session and stream IDs */
    uint8_t client_id[16], request_id[16];
    memset(client_id, 'C', 16);
    memset(request_id, 'R', 16);
    
    /* Retry loop */
    for (int attempt = 0; attempt < 3; attempt++) {
        result->attempts++;
        
        /* Connect */
        rbox_client_t *client = rbox_client_connect(socket_path);
        if (!client) {
            continue;
        }
        
        /* Create stream */
        rbox_stream_t *stream = rbox_stream_new(client_id, request_id);
        
        /* Determine chunking behavior based on hickup */
        size_t chunk_size = 32768;  /* 32KB chunks */
        int drop_chunk = 0;
        int num_chunks = (total_len + chunk_size - 1) / chunk_size;
        
        /* Handle hickups */
        if (hickup == HICKUP_CHUNK_DROP_MIDDLE && attempt == 0) {
            /* Drop the middle chunk */
            drop_chunk = num_chunks / 2;
        } else if (hickup == HICKUP_CHUNK_DROP_LAST && attempt == 0) {
            /* Drop the last chunk */
            drop_chunk = num_chunks - 1;
        } else if (hickup == HICKUP_CHUNK_RESUME) {
            /* First attempt: send partial, then reconnect */
            if (attempt == 0) {
                /* Send first chunk, then close */
                uint32_t flags = RBOX_FLAG_FIRST;
                rbox_stream_send_chunk(client, stream, full_data, chunk_size, flags, total_len);
                
                /* Read ACK */
                rbox_stream_read_ack(client, stream);
                
                /* Send second chunk, then disconnect without completing */
                /* Note: can't set offset directly - will resume from acknowledged offset */
                flags = RBOX_FLAG_CONTINUE;
                rbox_stream_send_chunk(client, stream, full_data + chunk_size, chunk_size, flags, total_len);
                
                rbox_client_close(client);
                rbox_stream_free(stream);
                
                /* Now retry - server should resume from offset */
                continue;
            }
        }
        
        /* Send chunks */
        size_t offset = 0;
        for (int i = 0; i < num_chunks; i++) {
            /* Skip dropped chunk */
            if ((int)i == drop_chunk) {
                offset += chunk_size;
                continue;
            }
            
            size_t this_len = (offset + chunk_size > total_len) ? (total_len - offset) : chunk_size;
            if (this_len == 0) break;
            
            uint32_t flags = 0;
            if (i == 0) flags |= RBOX_FLAG_FIRST;
            if (offset + this_len >= total_len) flags |= RBOX_FLAG_LAST;
            
            rbox_error_t err = rbox_stream_send_chunk(client, stream, full_data + offset, this_len, flags, total_len);
            if (err != RBOX_OK) {
                rbox_client_close(client);
                rbox_stream_free(stream);
                goto retry;
            }
            
            /* Read ACK */
            err = rbox_stream_read_ack(client, stream);
            if (err != RBOX_OK) {
                rbox_client_close(client);
                rbox_stream_free(stream);
                goto retry;
            }
            
            offset += this_len;
        }
        
        /* Read final response */
        struct pollfd pfd = {
            .fd = rbox_client_fd(client),
            .events = POLLIN,
            .revents = 0
        };
        
        int poll_ret = poll(&pfd, 1, 5000);
        if (poll_ret <= 0 || !(pfd.revents & POLLIN)) {
            rbox_client_close(client);
            rbox_stream_free(stream);
            goto retry;
        }
        
        char resp[1024];
        ssize_t n = read(rbox_client_fd(client), resp, sizeof(resp));
        
        if (n > 0) {
            if (parse_response(resp, n, result) == 0) {
                result->success = 1;
                rbox_client_close(client);
                rbox_stream_free(stream);
                return 0;
            }
        }
        
    retry:
        rbox_client_close(client);
    }
    
    return -1;
}

/* Test server thread - configurable behavior */
static void *integration_test_server(void *arg) {
    test_server_config_t *config = (test_server_config_t *)arg;
    
    /* Create server */
    rbox_server_t *server = rbox_server_new(config->socket_path);
    if (!server) {
        fprintf(stderr, "    DEBUG server: failed to create server\n");
        atomic_store(config->ready_flag, -1);
        return NULL;
    }
    
    rbox_error_t err = rbox_server_listen(server);
    if (err != RBOX_OK) {
        fprintf(stderr, "    DEBUG server: listen failed\n");
        atomic_store(config->ready_flag, -2);
        rbox_server_free(server);
        return NULL;
    }
    
    fprintf(stderr, "    DEBUG server: listening on %s\n", config->socket_path);
    atomic_store(config->ready_flag, 1);
    
    /* Get the listen fd */
    int listen_fd = rbox_server_fd(server);
    
    /* Accept up to 3 client connections */
    for (int attempt = 0; attempt < 3; attempt++) {
        /* Poll for incoming connection */
        struct pollfd pfd = {
            .fd = listen_fd,
            .events = POLLIN,
            .revents = 0
        };
        
        int poll_ret = poll(&pfd, 1, 5000);
        if (poll_ret <= 0 || !(pfd.revents & POLLIN)) {
            /* No more connections */
            break;
        }
        
        rbox_client_t *client = rbox_server_accept(server);
        if (!client) {
            continue;
        }
        
        /* Poll for incoming request data */
        pfd.fd = rbox_client_fd(client);
        pfd.events = POLLIN;
        pfd.revents = 0;
        
        poll_ret = poll(&pfd, 1, 5000);
        if (poll_ret <= 0 || !(pfd.revents & POLLIN)) {
            rbox_client_close(client);
            continue;
        }
        
        /* Read header first to check if this is a chunked request */
        char header[RBOX_HEADER_SIZE];
        ssize_t n = rbox_read(rbox_client_fd(client), header, RBOX_HEADER_SIZE);
        
        if (n == RBOX_HEADER_SIZE) {
            rbox_header_t *hdr = (rbox_header_t *)header;
            
            /* Read the chunk data (body) */
            if (hdr->chunk_len > 0) {
                char body[RBOX_CHUNK_MAX];
                rbox_read(rbox_client_fd(client), body, hdr->chunk_len);
            }
            
            /* Check if this is a chunked transfer (version 5+) */
            if (hdr->version >= 5 && (hdr->type == RBOX_MSG_REQ || hdr->type == RBOX_MSG_CHUNK)) {
            if (hdr->version >= 5 && (hdr->type == RBOX_MSG_REQ || hdr->type == RBOX_MSG_CHUNK)) {
                /* Handle chunked transfer */
                rbox_stream_t *stream = rbox_server_stream_new(hdr->client_id, hdr->request_id, hdr->total_len);
                
                /* Read first chunk */
                char chunk_buf[RBOX_CHUNK_MAX];
                size_t chunk_len = hdr->chunk_len;
                
                if (chunk_len > 0 && chunk_len <= RBOX_CHUNK_MAX) {
                    n = rbox_read(rbox_client_fd(client), chunk_buf, chunk_len);
                }
                
                /* Send ACK - mark as complete since we just need to respond */
                rbox_server_stream_ack(client, stream, RBOX_ACK_COMPLETE, "chunk received");
                
                /* For now, just send response */
                rbox_response_t resp;
                resp.decision = (config->decision == SERVER_ALLOW) ? RBOX_DECISION_ALLOW : RBOX_DECISION_DENY;
                snprintf(resp.reason, sizeof(resp.reason), 
                         config->decision == SERVER_ALLOW ? "allowed" : "denied");
                rbox_response_send(client, &resp);
                
                rbox_stream_free(stream);
            } else {
                /* Legacy single-packet request */
                rbox_request_t req;
                rbox_error_t read_err = rbox_request_read(client, &req);
                
                if (read_err == RBOX_OK) {
                    /* Send response */
                    rbox_response_t resp;
                    resp.decision = (config->decision == SERVER_ALLOW) ? RBOX_DECISION_ALLOW : RBOX_DECISION_DENY;
                    snprintf(resp.reason, sizeof(resp.reason), 
                             config->decision == SERVER_ALLOW ? "allowed" : "denied");
                    
                    rbox_response_send(client, &resp);
                    rbox_request_free(&req);
                }
            }
        }
        
        rbox_client_close(client);
    }
    
    rbox_server_free(server);
    return NULL;
}

static int test_full_roundtrip(server_decision_t decision, hickup_type_t hickup) {
    fprintf(stderr, "test_full_roundtrip called: decision=%d, hickup=%d\n", decision, hickup);
    fflush(stderr);
    
    /* Generate unique socket path */
    static int test_num = 0;
    test_num++;
    char socket_path[128];
    snprintf(socket_path, sizeof(socket_path), "/tmp/rbox_test_integ_%d.sock", test_num);
    
    /* Clean up any stale socket */
    unlink(socket_path);
    usleep(50000);  /* Wait for socket to be released */
    
    fprintf(stderr, "  socket: %s\n", socket_path);
    fflush(stderr);
    
    /* Setup test description */
    const char *dec_name = (decision == SERVER_ALLOW) ? "ALLOW" : "DENY";
    const char *hickup_name;
    switch (hickup) {
        case HICKUP_NONE: hickup_name = "none"; break;
        case HICKUP_SOCKET_RETRY: hickup_name = "socket-retry"; break;
        case HICKUP_REQUEST_RESEND: hickup_name = "request-resend"; break;
        case HICKUP_DELAYED_RESPONSE: hickup_name = "delayed-response"; break;
        case HICKUP_INVALID_MAGIC: hickup_name = "invalid-magic"; break;
        case HICKUP_INVALID_VERSION: hickup_name = "invalid-version"; break;
        case HICKUP_TRUNCATED_HEADER: hickup_name = "truncated-header"; break;
        case HICKUP_MULTI_ARG: hickup_name = "multi-arg"; break;
        case HICKUP_WITH_ENV: hickup_name = "with-env"; break;
        case HICKUP_CHUNK_DROP_MIDDLE: hickup_name = "chunk-drop-middle"; break;
        case HICKUP_CHUNK_DROP_LAST: hickup_name = "chunk-drop-last"; break;
        case HICKUP_CHUNK_RESUME: hickup_name = "chunk-resume"; break;
        default: hickup_name = "unknown"; break;
    }
    
    char test_name[128];
    snprintf(test_name, sizeof(test_name), "round-trip %s/%s", dec_name, hickup_name);
    TEST(test_name);
    
    /* Start server */
    fprintf(stderr, "  starting server...\n");
    _Atomic int ready = 0;
    _Atomic int request_count = 0;
    int server_closed = 0;
    
    test_server_config_t config = {
        .socket_path = socket_path,
        .decision = decision,
        .hickup = hickup,
        .ready_flag = &ready,
        .request_count = &request_count,
        .server_closed_flag = 0
    };
    
    pthread_t tid;
    pthread_create(&tid, NULL, integration_test_server, &config);
    
    /* Wait for server ready */
    int timeout = 100;
    while (atomic_load(&ready) == 0 && timeout > 0) {
        usleep(10000);  /* Wait longer */
        timeout--;
    }
    fprintf(stderr, "  server ready=%d (timeout=%d)\n", atomic_load(&ready), timeout);
    if (atomic_load(&ready) <= 0) {
        pthread_join(tid, NULL);
        test_count++;
        return -1;
    }
    
    /* Small delay to ensure server is fully ready */
    usleep(100000);  /* 100ms */
    
    /* Prepare arguments based on hickup type */
    const char *cmd = "ls";
    int argc = 1;
    const char *args[4] = {"-la"};
    
    if (hickup == HICKUP_MULTI_ARG) {
        cmd = "find";
        args[0] = ".";
        args[1] = "-name";
        args[2] = "*.txt";
        argc = 3;
    }
    
    /* Run client with retry logic */
    client_result_t result;
    int client_err = send_request_with_retry(socket_path, cmd, argc, args, hickup, &result);
    
    /* Wait for server to close */
    pthread_join(tid, NULL);
    
    /* Verify results */
    if (client_err != 0) {
        printf("    FAIL: client failed after %d attempts\n", result.attempts);
        test_count++;
        return -1;
    }
    
    /* Check decision */
    uint8_t expected = (decision == SERVER_ALLOW) ? RBOX_DECISION_ALLOW : RBOX_DECISION_DENY;
    if (result.decision != expected) {
        printf("    FAIL: expected %s but got %d\n", 
               decision == SERVER_ALLOW ? "ALLOW" : "DENY", result.decision);
        test_count++;
        return -1;
    }
    
    /* Check that we got some attempts */
    if (result.attempts < 1) {
        printf("    FAIL: no attempts made\n");
        test_count++;
        return -1;
    }
    
    printf("    OK: %s after %d attempt(s)\n", 
           decision == SERVER_ALLOW ? "ALLOWED" : "DENIED", result.attempts);
    
    PASS();
}

/* Test 1: Server reads valid request and sends ALLOW */
static int test_server_reads_request(void) {
    TEST("server reads request correctly");
    
    const char *test_sock = "/tmp/rbox_test_srv1.sock";
    unlink(test_sock);
    
    /* Server returns ALLOW */
    _Atomic int ready = 0;
    pthread_t tid;
    pthread_create(&tid, NULL, server_for_test1, &ready);
    
    int timeout = 100;
    while (atomic_load(&ready) == 0 && timeout > 0) { usleep(1000); timeout--; }
    ASSERT(atomic_load(&ready) > 0, "server ready");
    
    /* Client connects and sends request */
    rbox_client_t *client = rbox_client_connect(test_sock);
    ASSERT(client != NULL, "client connected");
    
    /* Set receive timeout */
    struct timeval tv = {2, 0};
    setsockopt(rbox_client_fd(client), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    /* Build request using protocol header offsets */
    char packet[4096] = {0};  /* Zero-initialize! */
    size_t pos = 0;
    
    /* Header fields using offsets from protocol.h */
    uint32_t magic = RBOX_MAGIC;
    uint32_t version = RBOX_VERSION;
    uint32_t msg_type = RBOX_MSG_REQ;
    uint32_t argc = 2;  /* ls, -la */
    uint32_t envc = 1;  /* HOME=/root */
    
    memcpy(packet + RBOX_HEADER_OFFSET_MAGIC, &magic, 4);
    memcpy(packet + RBOX_HEADER_OFFSET_VERSION, &version, 4);
    memset(packet + RBOX_HEADER_OFFSET_CLIENT_ID, 'C', 16);
    memset(packet + RBOX_HEADER_OFFSET_REQUEST_ID, 'Q', 16);
    memcpy(packet + RBOX_HEADER_OFFSET_TYPE, &msg_type, 4);
    memcpy(packet + RBOX_HEADER_OFFSET_ARGC, &argc, 4);
    memcpy(packet + RBOX_HEADER_OFFSET_ENVC, &envc, 4);
    
    /* Calculate checksum over bytes 0-67 (excluding checksum field) */
    uint32_t checksum = rbox_calculate_checksum(packet, 68);
    memcpy(packet + RBOX_HEADER_OFFSET_CHECKSUM, &checksum, 4);
    pos = RBOX_HEADER_SIZE;
    
    /* Body: command + args + env */
    memcpy(packet + pos, "ls", 3); pos += 3;
    memcpy(packet + pos, "-la", 4); pos += 4;
    memcpy(packet + pos, "HOME=/root", 11); pos += 11;
    
    (void)write(rbox_client_fd(client), packet, pos);
    
    /* Read response */
    char resp[256];
    ssize_t n = read(rbox_client_fd(client), resp, sizeof(resp));
    printf("    DEBUG: read %zd bytes\n", n);
    
    rbox_client_close(client);
    pthread_join(tid, NULL);
    
    ASSERT(n > 0, "got response");
    if (n > 0) {
        ASSERT(resp[24] == RBOX_DECISION_ALLOW, "should be ALLOW");
    }
    
    PASS();
}

/* Test 2: Server rejects invalid magic */
static int test_invalid_magic(void) {
    TEST("server rejects invalid magic");
    
    const char *test_sock = "/tmp/rbox_test_srv2.sock";
    unlink(test_sock);
    
    _Atomic int ready = 0;
    pthread_t tid;
    pthread_create(&tid, NULL, server_for_test2, &ready);
    
    int timeout = 100;
    while (atomic_load(&ready) == 0 && timeout > 0) { usleep(1000); timeout--; }
    
    rbox_client_t *client = rbox_client_connect(test_sock);
    ASSERT(client != NULL, "client connected");
    
    /* Send packet with invalid magic - zero buffer first */
    char packet[256] = {0};
    uint32_t bad_magic = 0xDEADBEEF;
    uint32_t version = RBOX_VERSION;
    
    memcpy(packet + RBOX_HEADER_OFFSET_MAGIC, &bad_magic, 4);
    memcpy(packet + RBOX_HEADER_OFFSET_VERSION, &version, 4);
    /* Leave rest as zeros - server_id, type, argc, envc, checksum all zero */
    
    (void)write(rbox_client_fd(client), packet, RBOX_HEADER_SIZE);
    
    /* Server should close connection */
    char resp[16];
    ssize_t n = read(rbox_client_fd(client), resp, sizeof(resp));
    
    rbox_client_close(client);
    pthread_join(tid, NULL);
    
    /* Connection should be closed (0 or -1) */
    ASSERT(n <= 0, "server should close on invalid magic");
    
    PASS();
}

/* Test 3: Server rejects invalid checksum */
static int test_invalid_checksum(void) {
    TEST("server rejects invalid checksum");
    
    const char *test_sock = "/tmp/rbox_test_srv3.sock";
    unlink(test_sock);
    
    _Atomic int ready = 0;
    pthread_t tid;
    pthread_create(&tid, NULL, server_for_test3, &ready);
    
    int timeout = 100;
    while (atomic_load(&ready) == 0 && timeout > 0) { usleep(1000); timeout--; }
    
    rbox_client_t *client = rbox_client_connect(test_sock);
    ASSERT(client != NULL, "client connected");
    
    /* Send packet with wrong checksum - zero buffer first */
    char packet[256] = {0};
    uint32_t magic = RBOX_MAGIC;
    uint32_t version = RBOX_VERSION;
    uint32_t msg_type = RBOX_MSG_REQ;
    uint32_t argc = 0;
    uint32_t envc = 0;
    
    memcpy(packet + RBOX_HEADER_OFFSET_MAGIC, &magic, 4);
    memcpy(packet + RBOX_HEADER_OFFSET_VERSION, &version, 4);
    memcpy(packet + RBOX_HEADER_OFFSET_TYPE, &msg_type, 4);
    memcpy(packet + RBOX_HEADER_OFFSET_ARGC, &argc, 4);
    memcpy(packet + RBOX_HEADER_OFFSET_ENVC, &envc, 4);
    
    /* WRONG checksum! */
    uint32_t bad_checksum = 0x12345678;
    memcpy(packet + RBOX_HEADER_OFFSET_CHECKSUM, &bad_checksum, 4);
    
    (void)write(rbox_client_fd(client), packet, RBOX_HEADER_SIZE);
    
    /* Server should close connection */
    char resp[16];
    ssize_t n = read(rbox_client_fd(client), resp, sizeof(resp));
    
    rbox_client_close(client);
    pthread_join(tid, NULL);
    
    ASSERT(n <= 0, "server should close on invalid checksum");
    
    PASS();
}

/* Test 4: Server sends DENY */
static int test_server_sends_deny(void) {
    TEST("server sends DENY correctly");
    
    const char *test_sock = "/tmp/rbox_test_srv4.sock";
    unlink(test_sock);
    
    _Atomic int ready = 0;
    pthread_t tid;
    pthread_create(&tid, NULL, server_for_test4, &ready);
    
    int timeout = 100;
    while (atomic_load(&ready) == 0 && timeout > 0) { usleep(1000); timeout--; }
    ASSERT(atomic_load(&ready) > 0, "server ready");
    
    rbox_client_t *client = rbox_client_connect(test_sock);
    ASSERT(client != NULL, "client connected");
    
    /* Set receive timeout */
    struct timeval tv = {2, 0};
    setsockopt(rbox_client_fd(client), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    /* Send valid request with command "rm" (server will DENY) */
    char packet[4096] = {0};  /* Zero-initialize! */
    
    uint32_t magic = RBOX_MAGIC;
    uint32_t version = RBOX_VERSION;
    uint32_t msg_type = RBOX_MSG_REQ;
    uint32_t argc = 1;
    uint32_t envc = 0;
    
    memcpy(packet + RBOX_HEADER_OFFSET_MAGIC, &magic, 4);
    memcpy(packet + RBOX_HEADER_OFFSET_VERSION, &version, 4);
    memset(packet + RBOX_HEADER_OFFSET_CLIENT_ID, 'C', 16);
    memset(packet + RBOX_HEADER_OFFSET_REQUEST_ID, 'Q', 16);
    memcpy(packet + RBOX_HEADER_OFFSET_TYPE, &msg_type, 4);
    memcpy(packet + RBOX_HEADER_OFFSET_ARGC, &argc, 4);
    memcpy(packet + RBOX_HEADER_OFFSET_ENVC, &envc, 4);
    
    /* Calculate checksum over bytes 0-67 */
    uint32_t checksum = rbox_calculate_checksum(packet, 68);
    memcpy(packet + RBOX_HEADER_OFFSET_CHECKSUM, &checksum, 4);
    size_t pos = RBOX_HEADER_SIZE;
    
    memcpy(packet + pos, "rm", 3); pos += 3;
    
    (void)write(rbox_client_fd(client), packet, pos);
    
    /* Read response */
    char resp[256];
    ssize_t n = read(rbox_client_fd(client), resp, sizeof(resp));
    printf("    DEBUG: read %zd bytes\n", n);
    
    rbox_client_close(client);
    pthread_join(tid, NULL);
    
    ASSERT(n > 0, "got response");
    if (n > 0) {
        ASSERT(resp[24] == RBOX_DECISION_DENY, "should be DENY");
    }
    
    PASS();
}

/* Server thread implementations */

/* Test 1 server: reads request, returns ALLOW for "ls" */
static void *server_for_test1(void *arg) {
    _Atomic int *ready = arg;
    
    rbox_server_t *server = rbox_server_new("/tmp/rbox_test_srv1.sock");
    rbox_server_listen(server);
    atomic_store(ready, 1);
    
    rbox_client_t *client = rbox_server_accept(server);
    if (!client) { rbox_server_free(server); return NULL; }
    
    rbox_request_t req;
    rbox_error_t read_err = rbox_request_read(client, &req);
    
    if (read_err == RBOX_OK) {
        /* Always ALLOW */
        rbox_response_t resp = { .decision = RBOX_DECISION_ALLOW };
        snprintf(resp.reason, sizeof(resp.reason), "ok");
        rbox_response_send(client, &resp);
    }
    
    rbox_request_free(&req);
    rbox_client_close(client);
    rbox_server_free(server);
    return NULL;
}

/* Generic server that returns ALLOW - used by multiple tests */
static void *server_generic_allow(void *arg) {
    const char **args = arg;
    const char *socket_path = args[0];
    _Atomic int *ready = (_Atomic int *)args[1];
    
    rbox_server_t *server = rbox_server_new(socket_path);
    rbox_server_listen(server);
    atomic_store(ready, 1);
    
    rbox_client_t *client = rbox_server_accept(server);
    if (!client) { rbox_server_free(server); return NULL; }
    
    rbox_request_t req;
    if (rbox_request_read(client, &req) == RBOX_OK) {
        rbox_response_t resp = { .decision = RBOX_DECISION_ALLOW };
        snprintf(resp.reason, sizeof(resp.reason), "ok");
        rbox_response_send(client, &resp);
    }
    
    rbox_request_free(&req);
    rbox_client_close(client);
    rbox_server_free(server);
    return NULL;
}

/* Test 2 server: rejects invalid magic */
static void *server_for_test2(void *arg) {
    _Atomic int *ready = arg;
    
    rbox_server_t *server = rbox_server_new("/tmp/rbox_test_srv2.sock");
    rbox_server_listen(server);
    atomic_store(ready, 1);
    
    rbox_client_t *client = rbox_server_accept(server);
    if (!client) { rbox_server_free(server); return NULL; }
    
    rbox_request_t req;
    rbox_error_t err = rbox_request_read(client, &req);
    
    /* If magic was invalid, err will be RBOX_ERR_MAGIC - just close */
    
    rbox_request_free(&req);
    rbox_client_close(client);
    rbox_server_free(server);
    return NULL;
}

/* Test 3 server: rejects invalid checksum */
static void *server_for_test3(void *arg) {
    _Atomic int *ready = arg;
    
    rbox_server_t *server = rbox_server_new("/tmp/rbox_test_srv3.sock");
    rbox_server_listen(server);
    atomic_store(ready, 1);
    
    rbox_client_t *client = rbox_server_accept(server);
    if (!client) { rbox_server_free(server); return NULL; }
    
    rbox_request_t req;
    rbox_error_t err = rbox_request_read(client, &req);
    
    /* If checksum was invalid, err will be RBOX_ERR_CHECKSUM - just close */
    
    rbox_request_free(&req);
    rbox_client_close(client);
    rbox_server_free(server);
    return NULL;
}

/* Test 4 server: returns DENY for "rm" */
static void *server_for_test4(void *arg) {
    _Atomic int *ready = arg;
    
    rbox_server_t *server = rbox_server_new("/tmp/rbox_test_srv4.sock");
    rbox_server_listen(server);
    atomic_store(ready, 1);
    
    rbox_client_t *client = rbox_server_accept(server);
    if (!client) { rbox_server_free(server); return NULL; }
    
    rbox_request_t req;
    if (rbox_request_read(client, &req) == RBOX_OK) {
        /* DENY for "rm", ALLOW for others */
        rbox_response_t resp;
        if (req.command && strcmp(req.command, "rm") == 0) {
            resp.decision = RBOX_DECISION_DENY;
            snprintf(resp.reason, sizeof(resp.reason), "dangerous");
        } else {
            resp.decision = RBOX_DECISION_ALLOW;
            snprintf(resp.reason, sizeof(resp.reason), "ok");
        }
        rbox_response_send(client, &resp);
    }
    
    rbox_request_free(&req);
    rbox_client_close(client);
    rbox_server_free(server);
    return NULL;
}

/* ============================================================
 * EDGE CASE TESTS
 * ============================================================ */

/* Test 5: Truncated header - client sends partial header */
static int test_truncated_header(void) {
    TEST("handles truncated header");
    
    const char *test_sock = "/tmp/rbox_test_trunc.sock";
    unlink(test_sock);
    
    _Atomic int ready = 0;
    pthread_t tid;
    pthread_create(&tid, NULL, server_for_test1, &ready); /* Reuse test1 server */
    
    int timeout = 100;
    while (atomic_load(&ready) == 0 && timeout > 0) { usleep(1000); timeout--; }
    
    rbox_client_t *client = rbox_client_connect(test_sock);
    ASSERT(client != NULL, "client connected");
    
    /* Send only 10 bytes (partial header) */
    char packet[16] = {0};
    packet[0] = 0x4F;  /* Part of magic */
    packet[1] = 0x42;
    packet[2] = 0x52;
    packet[3] = 0x4F;
    
    (void)write(rbox_client_fd(client), packet, 10);
    
    /* Server should close connection */
    char resp[16];
    ssize_t n = read(rbox_client_fd(client), resp, sizeof(resp));
    
    rbox_client_close(client);
    pthread_join(tid, NULL);
    
    ASSERT(n <= 0, "server should close on truncated header");
    
    PASS();
}

/* Test 6: Empty command */
static int test_empty_command(void) {
    TEST("handles empty command");
    
    const char *test_sock = "/tmp/rbox_test_srv6.sock";
    unlink(test_sock);
    
    _Atomic int ready = 0;
    pthread_t tid;
    pthread_create(&tid, NULL, server_for_test1, &ready);
    
    int timeout = 100;
    while (atomic_load(&ready) == 0 && timeout > 0) { usleep(1000); timeout--; }
    
    rbox_client_t *client = rbox_client_connect(test_sock);
    ASSERT(client != NULL, "client connected");
    
    /* Build packet with empty command */
    char packet[256];
    size_t pos = 0;
    uint32_t magic = RBOX_MAGIC;
    uint32_t version = RBOX_VERSION;
    uint32_t msg_type = RBOX_MSG_REQ;
    uint32_t argc = 0;
    uint32_t envc = 0;
    
    memcpy(packet + pos, &magic, 4); pos += 4;
    memcpy(packet + pos, &version, 4); pos += 4;
    memset(packet + pos, 0, 56); pos += 56;
    memcpy(packet + pos, &msg_type, 4); pos += 4;
    memcpy(packet + pos, &argc, 4); pos += 4;
    memcpy(packet + pos, &envc, 4); pos += 4;
    
    uint32_t checksum = rbox_calculate_checksum(packet, 68);
    memcpy(packet + pos, &checksum, 4); pos += 4;
    
    /* Empty command = just null byte */
    packet[pos++] = '\0';
    
    write(rbox_client_fd(client), packet, pos);
    
    /* Read response - should still get response */
    char resp[256];
    ssize_t n = read(rbox_client_fd(client), resp, sizeof(resp));
    
    rbox_client_close(client);
    pthread_join(tid, NULL);
    
    ASSERT(n > 0, "should get response for empty command");
    
    PASS();
}

/* Test 7: Client disconnects mid-request */
static int test_client_disconnect(void) {
    TEST("handles client disconnect");
    
    const char *test_sock = "/tmp/rbox_test_srv7.sock";
    unlink(test_sock);
    
    _Atomic int ready = 0;
    pthread_t tid;
    pthread_create(&tid, NULL, server_for_test1, &ready);
    
    int timeout = 100;
    while (atomic_load(&ready) == 0 && timeout > 0) { usleep(1000); timeout--; }
    
    rbox_client_t *client = rbox_client_connect(test_sock);
    ASSERT(client != NULL, "client connected");
    
    /* Send partial packet then disconnect */
    char packet[32] = {0};
    uint32_t magic = RBOX_MAGIC;
    memcpy(packet, &magic, 4);
    
    write(rbox_client_fd(client), packet, 32);
    
    /* Immediately close without waiting for response */
    rbox_client_close(client);
    
    /* Server should handle this gracefully */
    pthread_join(tid, NULL);
    
    /* If we get here without crash, test passes */
    PASS();
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void) {
    printf("=== rbox-protocol comprehensive tests ===\n\n");
    
    /* Header tests */
    printf("Header tests:\n");
    test_header_valid();
    test_header_magic();
    test_header_version();
    test_header_checksum();
    printf("\n");
    
    /* Error tests */
    printf("Error string tests:\n");
    test_strerror();
    printf("\n");
    
    /* Socket tests */
    printf("Socket tests:\n");
    test_socket_create();
    test_socket_connect();
    test_accept_loop();
    printf("\n");
    
    /* Packet tests */
    printf("Packet building tests:\n");
    test_build_request();
    test_build_response();
    printf("\n");
    
    /* Shellsplit tests */
    printf("Shellsplit parsing tests:\n");
    test_shellsplit_simple();
    test_shellsplit_pipeline();
    test_shellsplit_redirect();
    test_shellsplit_dup();
    printf("\n");
    
    /* Integration tests */
    printf("Integration tests:\n");
    
    /* Basic tests */
    test_full_roundtrip(SERVER_ALLOW, HICKUP_NONE);
    test_full_roundtrip(SERVER_DENY, HICKUP_NONE);
    test_full_roundtrip(SERVER_ALLOW, HICKUP_SOCKET_RETRY);
    test_full_roundtrip(SERVER_ALLOW, HICKUP_REQUEST_RESEND);
    test_full_roundtrip(SERVER_ALLOW, HICKUP_DELAYED_RESPONSE);
    test_full_roundtrip(SERVER_DENY, HICKUP_SOCKET_RETRY);
    
    printf("\n");
    
    printf("=== Results: %d/%d tests passed ===\n", pass_count, test_count);
    
    return (pass_count == test_count) ? 0 : 1;
}
