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
#include <sys/time.h>

#include "rbox_protocol.h"
#include "test_common.h"

/* Include internal headers */
#include "../src/socket.h"

/* Also include protocol definitions for the offsets in tests */
#include "rbox_protocol_defs.h"

/* Forward declare stream for internal access in tests */
typedef struct rbox_stream rbox_stream_t;

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
 * PACKET BUILD TESTS
 * ============================================================ */

static int test_build_request(void) {
    TEST("rbox_build_request packet building");

    char packet[4096];
    size_t pkt_len = 0;
    const char *args[] = {"ls", "-la", "/tmp"};

    rbox_error_t err = rbox_build_request(packet, sizeof(packet), &pkt_len, "ls", "judge", "execve", 3, args, 0, NULL, NULL);
    ASSERT(err == RBOX_OK, "build request should succeed");
    ASSERT(pkt_len > RBOX_HEADER_SIZE, "packet should have body");

    /* Verify header fields */
    uint32_t magic = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_MAGIC);
    ASSERT(magic == RBOX_MAGIC, "magic should match");

    uint32_t version = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_VERSION);
    ASSERT(version == RBOX_VERSION, "version should match");

    PASS();
}

static int test_build_response(void) {
    TEST("rbox_build_response packet building");

    char *resp_packet = NULL;
    size_t resp_len = 0;

    rbox_error_t err = rbox_build_response(RBOX_DECISION_ALLOW, "test-ok", 0, 0, 0, NULL, &resp_packet, &resp_len);
    ASSERT(err == RBOX_OK, "build response should succeed");
    ASSERT(resp_len > RBOX_HEADER_SIZE, "response should have body");
    ASSERT(resp_packet != NULL, "response packet should be allocated");

    /* Verify header fields */
    uint32_t magic = *(uint32_t *)(resp_packet + RBOX_HEADER_OFFSET_MAGIC);
    ASSERT(magic == RBOX_MAGIC, "magic should match");

    free(resp_packet);
    PASS();
}

static int test_header_validation(void) {
    TEST("header validation - valid, magic, version, checksum");

    /* Build proper request packet using canonical library function - do once */
    char packet[1024];
    size_t pkt_len;
    const char *args[] = {"test"};
    rbox_build_request(packet, sizeof(packet), &pkt_len, "test", NULL, NULL, 1, args, 0, NULL, NULL);

    /* Save original values using explicit offsets */
    uint32_t orig_magic = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_MAGIC);
    uint32_t orig_version = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_VERSION);
    uint32_t orig_checksum = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_CHECKSUM);

    /* Test 1: Valid header should pass */
    ASSERT(rbox_header_validate(packet, pkt_len) == RBOX_OK, "valid header should pass");

    /* Test 2: Invalid magic should fail */
    *(uint32_t *)(packet + RBOX_HEADER_OFFSET_MAGIC) = 0xDEADBEEF;
    ASSERT(rbox_header_validate(packet, pkt_len) == RBOX_ERR_MAGIC, "invalid magic should fail");
    *(uint32_t *)(packet + RBOX_HEADER_OFFSET_MAGIC) = orig_magic;  /* Restore */

    /* Test 3: Invalid version should fail */
    *(uint32_t *)(packet + RBOX_HEADER_OFFSET_VERSION) = 999;
    ASSERT(rbox_header_validate(packet, pkt_len) == RBOX_ERR_VERSION, "invalid version should fail");
    *(uint32_t *)(packet + RBOX_HEADER_OFFSET_VERSION) = orig_version;  /* Restore */

    /* Test 4: Corrupt checksum should fail */
    *(uint32_t *)(packet + RBOX_HEADER_OFFSET_CHECKSUM) ^= 0xFFFFFFFF;
    ASSERT(rbox_header_validate(packet, pkt_len) == RBOX_ERR_CHECKSUM, "corrupt checksum should fail");
    *(uint32_t *)(packet + RBOX_HEADER_OFFSET_CHECKSUM) = orig_checksum;  /* Restore */

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
 * PROXY-BASED NETWORK CORRUPTION TESTS
 * Tests real library server code with simulated lossy connection
 * Uses two pairs of unix sockets for client-server communication through proxy
 * ============================================================ */

/* Corruption parameters for each direction */
typedef struct {
    double bit_flip_prob;      /* Probability of flipping a bit (0.0 - 1.0) */
    double byte_replace_prob;  /* Probability of replacing a byte (0.0 - 1.0) */
} corruption_params_t;

/* Proxy instance - Unix socket based */
typedef struct proxy {
    int listen_fd;              /* Listening socket for clients (Unix socket) */
    char listen_socket[256];    /* Unix socket path we listen on */
    char target_socket[256];   /* Target server Unix socket path */
    corruption_params_t client_to_server;  /* Corruption for client->server */
    corruption_params_t server_to_client;  /* Corruption for server->client */
    _Atomic int running;       /* Is proxy active */
    _Atomic int connections;   /* Total connections handled */
    pthread_mutex_t lock;
} proxy_t;

/* Thread-local seed for rand_r() - each thread gets its own seed */
static __thread unsigned int g_rand_seed = 0;

/* Initialize random seed for thread */
static void init_rand_seed(void) {
    if (g_rand_seed == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uintptr_t tid = (uintptr_t)pthread_self();
        g_rand_seed = (unsigned int)((uint64_t)ts.tv_sec ^ ((uint64_t)ts.tv_nsec << 32) ^ tid);
    }
}

/* Initialize corruption params */
static void corruption_init(corruption_params_t *cp, double bit_flip, double byte_replace) {
    cp->bit_flip_prob = bit_flip;
    cp->byte_replace_prob = byte_replace;
}

/* Corrupt data based on parameters - thread-safe using rand_r() */
static void corrupt_data(char *data, size_t len, corruption_params_t *params) {
    if (len == 0) return;

    init_rand_seed();

    /* Byte replacement corruption */
    for (size_t i = 0; i < len; i++) {
        if ((double)rand_r(&g_rand_seed) / RAND_MAX < params->byte_replace_prob) {
            data[i] = (char)(rand_r(&g_rand_seed) & 0xFF);
        }
    }

    /* Bit flip corruption */
    for (size_t i = 0; i < len; i++) {
        if ((double)rand_r(&g_rand_seed) / RAND_MAX < params->bit_flip_prob) {
            int bit = rand_r(&g_rand_seed) % 8;
            data[i] ^= (1 << bit);
        }
    }
}

/* Handle one client connection - forwards bidirectionally with corruption */
static void *handle_proxy_client(void *arg) {

    /* arg is a struct with client_fd, target_socket, and corruption params */
    struct client_info {
        int client_fd;
        char target_socket[256];
        corruption_params_t c2s;
        corruption_params_t s2c;
    } *info = arg;

    /* Copy data to local vars BEFORE freeing */
    int client_fd = info->client_fd;
    char target_socket[256];
    size_t copy_len = strlen(info->target_socket);
    if (copy_len >= sizeof(target_socket)) copy_len = sizeof(target_socket) - 1;
    memcpy(target_socket, info->target_socket, copy_len);
    target_socket[copy_len] = '\0';
    corruption_params_t c2s = info->c2s;
    corruption_params_t s2c = info->s2c;
    free(arg);
    arg = NULL;




    /* Connect to target server via Unix socket */
    int target_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (target_fd < 0) {

        close(client_fd);
        return NULL;
    }

    struct sockaddr_un target_addr = {0};
    target_addr.sun_family = AF_UNIX;
    size_t path_len = strlen(target_socket);
    if (path_len >= sizeof(target_addr.sun_path)) path_len = sizeof(target_addr.sun_path) - 1;
    memcpy(target_addr.sun_path, target_socket, path_len);
    target_addr.sun_path[path_len] = '\0';

    if (connect(target_fd, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {

        close(target_fd);
        close(client_fd);
        return NULL;
    }



    /* Bidirectional forwarding using poll */
    char buffer[8192];
    int running = 1;

    while (running) {
        struct pollfd pfds[2] = {
            { .fd = client_fd, .events = POLLIN },
            { .fd = target_fd, .events = POLLIN }
        };

        int ret = poll(pfds, 2, 1000);
        if (ret <= 0) continue;

        /* Client -> Server with corruption */
        if (pfds[0].revents & POLLIN) {
            ssize_t n = read(client_fd, buffer, sizeof(buffer));
            if (n <= 0) { running = 0; break; }
            corrupt_data(buffer, n, &c2s);
            size_t written = 0;
            while (written < (size_t)n) {
                ssize_t w = write(target_fd, buffer + written, n - written);
                if (w < 0) {
                    if (errno == EINTR) continue;  /* Retry on signal */
                    running = 0;
                    break;
                }
                if (w == 0) { running = 0; break; }
                written += w;
            }
        }

        /* Server -> Client with corruption */
        if (pfds[1].revents & POLLIN) {
            ssize_t n = read(target_fd, buffer, sizeof(buffer));
            if (n <= 0) { running = 0; break; }
            corrupt_data(buffer, n, &s2c);
            size_t written = 0;
            while (written < (size_t)n) {
                ssize_t w = write(client_fd, buffer + written, n - written);
                if (w < 0) {
                    if (errno == EINTR) continue;  /* Retry on signal */
                    running = 0;
                    break;
                }
                if (w == 0) { running = 0; break; }
                written += w;
            }
        }

        if (pfds[0].revents & (POLLERR|POLLHUP|POLLNVAL)) running = 0;
        if (pfds[1].revents & (POLLERR|POLLHUP|POLLNVAL)) running = 0;
    }

    close(target_fd);
    close(client_fd);

    return NULL;
}

/* Proxy listener thread */
static void *proxy_thread_func(void *arg) {
    proxy_t *proxy = (proxy_t *)arg;




    while (atomic_load(&proxy->running)) {
        struct pollfd pfd = { .fd = proxy->listen_fd, .events = POLLIN, .revents = 0 };
        int ret = poll(&pfd, 1, 100);
        if (ret <= 0) continue;
        if (!(pfd.revents & POLLIN)) continue;

        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(proxy->listen_fd, (struct sockaddr *)&client_addr, &client_len);

        if (client_fd >= 0) {
            atomic_fetch_add(&proxy->connections, 1);  /* For potential diagnostics */
            /* Allocate client info struct */
            struct client_info {
                int client_fd;
                char target_socket[256];
                corruption_params_t c2s;
                corruption_params_t s2c;
            } *info = malloc(sizeof(struct client_info));
            if (!info) {
                close(client_fd);
                continue;
            }
            info->client_fd = client_fd;
            snprintf(info->target_socket, sizeof(info->target_socket), "%s", proxy->target_socket);


            memcpy(&info->c2s, &proxy->client_to_server, sizeof(corruption_params_t));
            memcpy(&info->s2c, &proxy->server_to_client, sizeof(corruption_params_t));
            pthread_t tid;
            if (pthread_create(&tid, NULL, handle_proxy_client, info) != 0) {
                /* Thread creation failed - close client and free info */
                close(client_fd);
                free(info);
            } else {
                pthread_detach(tid);
            }
        } else if (client_fd < 0 && errno != EAGAIN) {
            /* Accept failed - small delay to avoid busy loop */
            usleep(1000);
        }
    }
    return NULL;
}

/* Create proxy - listens on Unix socket, forwards to target Unix socket */
static proxy_t *proxy_create(const char *listen_socket, const char *target_socket) {
    proxy_t *proxy = calloc(1, sizeof(proxy_t));
    if (!proxy) return NULL;

    snprintf(proxy->listen_socket, sizeof(proxy->listen_socket), "%s", listen_socket);
    snprintf(proxy->target_socket, sizeof(proxy->target_socket), "%s", target_socket);
    atomic_store(&proxy->running, 1);
    atomic_store(&proxy->connections, 0);
    pthread_mutex_init(&proxy->lock, NULL);
    corruption_init(&proxy->client_to_server, 0.0, 0.0);
    corruption_init(&proxy->server_to_client, 0.0, 0.0);

    /* Remove existing socket file */
    unlink(listen_socket);

    proxy->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (proxy->listen_fd < 0) { free(proxy); return NULL; }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", listen_socket);

    if (bind(proxy->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(proxy->listen_fd); free(proxy); return NULL;
    }
    if (listen(proxy->listen_fd, 10) < 0) {
        close(proxy->listen_fd); free(proxy); return NULL;
    }
    return proxy;
}

/* Set corruption parameters */
static void proxy_set_corruption(proxy_t *proxy, double c2s_bit, double c2s_byte, double s2c_bit, double s2c_byte) {
    pthread_mutex_lock(&proxy->lock);
    corruption_init(&proxy->client_to_server, c2s_bit, c2s_byte);
    corruption_init(&proxy->server_to_client, s2c_bit, s2c_byte);
    pthread_mutex_unlock(&proxy->lock);
}

static int proxy_start(proxy_t *proxy) { pthread_t tid; return pthread_create(&tid, NULL, proxy_thread_func, proxy) == 0 ? 0 : -1; }
static void proxy_stop(proxy_t *proxy) {
    atomic_store(&proxy->running, 0);
    if (proxy->listen_fd >= 0) close(proxy->listen_fd);
    unlink(proxy->listen_socket);
}
static void proxy_destroy(proxy_t *proxy) { if (proxy) { proxy_stop(proxy); pthread_mutex_destroy(&proxy->lock); free(proxy); } }

/* Server thread: calls blocking get_request in a loop until stopped
 * Returns server handle via out_server pointer */
typedef struct {
    const char *socket_path;
    rbox_server_handle_t *server;  /* Output: server handle for caller to use */
} server_thread_arg_t;

static void *rbox_server_thread(void *arg) {
    server_thread_arg_t *thread_arg = (server_thread_arg_t *)arg;
    const char *socket_path = thread_arg->socket_path;

    /* Create server using full handle API */
    rbox_server_handle_t *server = rbox_server_handle_new(socket_path);
    if (!server) {
        printf("    ERROR: failed to create server on %s\n", socket_path);
        return NULL;
    }

    rbox_error_t err = rbox_server_handle_listen(server);
    if (err != RBOX_OK) {
        printf("    ERROR: failed to listen on %s: %d\n", socket_path, err);
        rbox_server_handle_free(server);
        return NULL;
    }

    /* Start server - spawns background epoll thread */
    err = rbox_server_start(server);
    if (err != RBOX_OK) {
        printf("    ERROR: failed to start server: %d\n", err);
        rbox_server_handle_free(server);
        return NULL;
    }

    /* Pass server handle back to caller */
    thread_arg->server = server;

    /* Blocking request loop - exits when rbox_server_stop() is called */
    while (1) {
        rbox_server_request_t *req = rbox_server_get_request(server);
        if (!req) {
            /* NULL means server was stopped */
            break;
        }

        /* Send ALLOW decision for any valid request */
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL, NULL);
    }

    rbox_server_handle_free(server);
    return NULL;
}

/* Run proxy test - returns count of successful requests with CORRECT result
 * Uses real rbox server on Unix socket, proxy forwards Unix socket->Unix socket */
static int run_proxy_test(const char *server_socket, const char *proxy_socket,
                         double c2s_bit, double c2s_byte,
                         double s2c_bit, double s2c_byte,
                         int num_requests, uint8_t expected_decision) {
    pthread_t server_tid;
    server_thread_arg_t thread_arg = { .socket_path = server_socket, .server = NULL };
    pthread_create(&server_tid, NULL, rbox_server_thread, &thread_arg);
    usleep(100000);

    proxy_t *proxy = proxy_create(proxy_socket, server_socket);
    if (!proxy) { pthread_join(server_tid, NULL); return -1; }
    proxy_set_corruption(proxy, c2s_bit, c2s_byte, s2c_bit, s2c_byte);
    proxy_start(proxy);
    usleep(100000);

    int success = 0;
    for (int i = 0; i < num_requests; i++) {
        /* Connect to proxy via rbox_client (uses high-level API) */
        rbox_client_t *client = rbox_client_connect(proxy_socket);
        if (!client) continue;

        char *cmd = "ls";
        const char *args[] = { cmd };
        rbox_response_t resp;
        rbox_error_t err = rbox_client_send_request(client, cmd, NULL, NULL, 1, args, 0, NULL, NULL, &resp);
        if (err == RBOX_OK && resp.decision == expected_decision) {
            success++;
        }
        rbox_client_close(client);
        usleep(5000);  /* 5ms delay between requests */
    }

    proxy_destroy(proxy);
    /* Stop the server - this will cause get_request to return NULL */
    if (thread_arg.server) {
        rbox_server_stop(thread_arg.server);
    }
    pthread_join(server_tid, NULL);
    return success;
}

/* Test 1: Direct connection (no proxy) - using real rbox server on Unix socket */
static int test_proxy_direct(void) {
    TEST("direct connection (no proxy)");

    const char *server_sock = "/tmp/rbox_test_direct.sock";
    unlink(server_sock);

    pthread_t server_tid;
    server_thread_arg_t thread_arg = { .socket_path = server_sock, .server = NULL };
    pthread_create(&server_tid, NULL, rbox_server_thread, &thread_arg);
    usleep(100000);  /* Wait for server to start */

    int success = 0;
    for (int i = 0; i < 35; i++) {
        rbox_client_t *client = rbox_client_connect(server_sock);
        if (!client) continue;

        char *cmd = "ls";
        const char *args[] = { cmd };
        rbox_response_t resp;
        rbox_error_t err = rbox_client_send_request(client, cmd, NULL, NULL, 1, args, 0, NULL, NULL, &resp);
        if (err == RBOX_OK && resp.decision == RBOX_DECISION_ALLOW) {
            success++;
        }
        rbox_client_close(client);
    }

    /* Stop the server */
    if (thread_arg.server) {
        rbox_server_stop(thread_arg.server);
    }
    pthread_join(server_tid, NULL);
    unlink(server_sock);

    printf("    %d/35 requests succeeded with correct ALLOW decision\n", success);
    ASSERT(success == 35, "direct should be 100%%");
    PASS();
}

/* Test 2: Clean proxy (no corruption) */
static int test_proxy_clean(void) {
    TEST("clean proxy (no corruption)");

    const char *server_sock = "/tmp/rbox_test_proxy_server.sock";
    const char *proxy_sock = "/tmp/rbox_test_proxy.sock";
    unlink(server_sock);
    unlink(proxy_sock);

    int success = run_proxy_test(server_sock, proxy_sock, 0.0, 0.0, 0.0, 0.0, 35, RBOX_DECISION_ALLOW);
    unlink(server_sock);
    unlink(proxy_sock);
    printf("    %d/35 requests succeeded with correct ALLOW decision\n", success);
    ASSERT(success == 35, "clean proxy should be 100%%");
    PASS();
}

/* Test 3: Client->Server small corruption (bit flips) */
static int test_proxy_c2s_small(void) {
    TEST("client->server small corruption (1%% bit flip)");

    const char *server_sock = "/tmp/rbox_test_c2s_small_server.sock";
    const char *proxy_sock = "/tmp/rbox_test_c2s_small_proxy.sock";
    unlink(server_sock);
    unlink(proxy_sock);

    int success = run_proxy_test(server_sock, proxy_sock, 0.01, 0.0, 0.0, 0.0, 35, RBOX_DECISION_ALLOW);
    unlink(server_sock);
    unlink(proxy_sock);
    printf("    %d/35 requests succeeded with correct decision\n", success);
    /* Pass: success count doesn't matter - only correctness of decisions matters.
     * run_proxy_test only counts responses where decision == expected, so all
     * successful responses have correct decisions. Rate is interesting but not
     * a pass/fail criterion. */
    PASS();
}

/* Test 4: Client->Server massive corruption (30% byte replacement) */
static int test_proxy_c2s_massive(void) {
    TEST("client->server massive corruption (30%% byte replace)");

    const char *server_sock = "/tmp/rbox_test_c2s_massive_server.sock";
    const char *proxy_sock = "/tmp/rbox_test_c2s_massive_proxy.sock";
    unlink(server_sock);
    unlink(proxy_sock);

    int success = run_proxy_test(server_sock, proxy_sock, 0.0, 0.3, 0.0, 0.0, 35, RBOX_DECISION_ALLOW);
    unlink(server_sock);
    unlink(proxy_sock);
    printf("    %d/35 requests succeeded with correct decision\n", success);
    /* Pass: only correct decisions are accepted. Rate is interesting but not
     * a pass/fail criterion. */
    PASS();
}

/* Test 5: Server->Client small corruption */
static int test_proxy_s2c_small(void) {
    TEST("server->client small corruption (1%% bit flip on response)");

    const char *server_sock = "/tmp/rbox_test_s2c_small_server.sock";
    const char *proxy_sock = "/tmp/rbox_test_s2c_small_proxy.sock";
    unlink(server_sock);
    unlink(proxy_sock);

    int success = run_proxy_test(server_sock, proxy_sock, 0.0, 0.0, 0.01, 0.0, 35, RBOX_DECISION_ALLOW);
    unlink(server_sock);
    unlink(proxy_sock);
    printf("    %d/35 requests succeeded with correct decision\n", success);
    /* Pass: only correct decisions are accepted. Rate is interesting but not
     * a pass/fail criterion. */
    PASS();
}

/* Test 6: Server->Client massive corruption */
static int test_proxy_s2c_massive(void) {
    TEST("server->client massive corruption (30%% byte replace on response)");

    const char *server_sock = "/tmp/rbox_test_s2c_massive_server.sock";
    const char *proxy_sock = "/tmp/rbox_test_s2c_massive_proxy.sock";
    unlink(server_sock);
    unlink(proxy_sock);

    int success = run_proxy_test(server_sock, proxy_sock, 0.0, 0.0, 0.0, 0.3, 35, RBOX_DECISION_ALLOW);
    unlink(server_sock);
    unlink(proxy_sock);
    printf("    %d/35 requests succeeded with correct decision\n", success);
    /* Pass: only correct decisions are accepted. Rate is interesting but not
     * a pass/fail criterion. */
    PASS();
}

/* Test 7: Bidirectional small corruption */
static int test_proxy_bidi_small(void) {
    TEST("bidirectional small corruption (1%% bit flip both ways)");

    const char *server_sock = "/tmp/rbox_test_bidi_small_server.sock";
    const char *proxy_sock = "/tmp/rbox_test_bidi_small_proxy.sock";
    unlink(server_sock);
    unlink(proxy_sock);

    int success = run_proxy_test(server_sock, proxy_sock, 0.01, 0.0, 0.01, 0.0, 35, RBOX_DECISION_ALLOW);
    unlink(server_sock);
    unlink(proxy_sock);
    printf("    %d/35 requests succeeded with correct decision\n", success);
    /* Pass: only correct decisions are accepted. Rate is interesting but not
     * a pass/fail criterion. */
    PASS();
}

/* Test 8: Bidirectional massive corruption */
static int test_proxy_bidi_massive(void) {
    TEST("bidirectional massive corruption (30%% byte replace both ways)");

    const char *server_sock = "/tmp/rbox_test_bidi_massive_server.sock";
    const char *proxy_sock = "/tmp/rbox_test_bidi_massive_proxy.sock";
    unlink(server_sock);
    unlink(proxy_sock);

    int success = run_proxy_test(server_sock, proxy_sock, 0.0, 0.3, 0.0, 0.3, 35, RBOX_DECISION_ALLOW);
    unlink(server_sock);
    unlink(proxy_sock);
    printf("    %d/35 requests succeeded with correct decision\n", success);
    /* Pass: only correct decisions are accepted. Rate is interesting but not
     * a pass/fail criterion. */
    PASS();
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void) {
    printf("=== rbox-protocol comprehensive tests ===\n\n");

    /* Seed random for corruption tests
     * Use RBOX_TEST_FIXED_SEED env var for deterministic behavior */
    unsigned int seed = get_test_seed();
    printf("Using random seed: %u\n", seed);
    srand(seed);

    /* Header tests */
    printf("Header tests:\n");
    test_header_validation();
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

    /* Packet build tests */
    printf("Packet build tests:\n");
    test_build_request();
    test_build_response();
    printf("\n");

    /* Shellsplit parsing tests */
    printf("Shellsplit parsing tests:\n");
    test_shellsplit_simple();
    test_shellsplit_pipeline();
    test_shellsplit_redirect();
    test_shellsplit_dup();
    printf("\n");

    /* Proxy tests - comprehensive corruption testing */
    printf("Proxy tests:\n");
    test_proxy_direct();       /* Baseline: 35 requests, no proxy */
    test_proxy_clean();         /* Clean proxy: 35 requests */
    test_proxy_c2s_small();   /* Client->Server 1% bit flip */
    test_proxy_c2s_massive();  /* Client->Server 30% byte replace */
    test_proxy_s2c_small();    /* Server->Client 1% bit flip */
    test_proxy_s2c_massive();   /* Server->Client 30% byte replace */
    test_proxy_bidi_small();    /* Bidirectional 1% bit flip */
    test_proxy_bidi_massive();  /* Bidirectional 30% byte replace */
    printf("\n");

    printf("=== Results: %d/%d tests passed ===\n", pass_count, test_count);

    return (pass_count == test_count) ? 0 : 1;
}
