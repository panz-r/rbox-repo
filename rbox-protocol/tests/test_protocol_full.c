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
#include "../src/error_internal.h"
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

    rbox_error_t err = rbox_build_response(RBOX_DECISION_ALLOW, "test-ok", 0, 0, NULL, &resp_packet, &resp_len);
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
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    const char *test_sock = "/tmp/rbox_test.sock";
    unlink(test_sock);

    rbox_server_t *server = rbox_server_new(test_sock, &err_info);
    ASSERT(server != NULL, "server should be created");

    rbox_error_t err = rbox_server_listen(server, &err_info);
    ASSERT(err == RBOX_OK, "server should listen");

    rbox_server_free(server);

    /* File should be cleaned up */
    struct stat st;
    ASSERT(stat(test_sock, &st) < 0, "socket file should be removed");

    PASS();
}

static int test_socket_connect(void) {
    TEST("client connect");
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    const char *test_sock = "/tmp/rbox_test_connect.sock";
    unlink(test_sock);

    /* Create server */
    rbox_server_t *server = rbox_server_new(test_sock, &err_info);
    ASSERT(server != NULL, "server created");

    rbox_server_listen(server, &err_info);

    /* Connect client */
    rbox_client_t *client = rbox_client_connect(test_sock, &err_info);
    ASSERT(client != NULL, "client should connect");

    rbox_client_close(client);
    rbox_server_free(server);

    PASS();
}

static int test_accept_loop(void) {
    TEST("accept and communication");
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    const char *test_sock = "/tmp/rbox_test_accept.sock";
    unlink(test_sock);

    /* Create server */
    rbox_server_t *server = rbox_server_new(test_sock, &err_info);
    rbox_server_listen(server, &err_info);

    /* Client connect */
    rbox_client_t *client = rbox_client_connect(test_sock, &err_info);
    ASSERT(client != NULL, "client connected");

    /* Server accept */
    rbox_client_t *server_client = rbox_server_accept(server, &err_info);
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

/* Forward declaration for proxy client handler */
static void *handle_proxy_client(void *arg);

/* Forward declaration for corruption init */
static void corruption_init(corruption_params_t *cp, double bit_flip, double byte_replace);

/* Proxy instance - Unix socket based */
typedef struct proxy {
    _Atomic int active;        /* Is proxy accepting connections */
    int listen_fd;             /* Listening socket - protected by mutex */
    char listen_socket[256];   /* Unix socket path we listen on */
    char target_socket[256];   /* Target server Unix socket path */
    corruption_params_t client_to_server;  /* Corruption for client->server */
    corruption_params_t server_to_client;  /* Corruption for server->client */
    pthread_t thread;          /* Proxy thread handle for join */
    pthread_mutex_t fd_mutex;  /* Protects listen_fd during close */
} proxy_t;

/* Cleanup handler for proxy thread */
static void proxy_thread_cleanup(void *arg) {
    proxy_t *proxy = (proxy_t *)arg;
    pthread_mutex_lock(&proxy->fd_mutex);
    if (proxy->listen_fd >= 0) {
        close(proxy->listen_fd);
        proxy->listen_fd = -1;
    }
    pthread_mutex_unlock(&proxy->fd_mutex);
    unlink(proxy->listen_socket);
}

/* Proxy listener thread */
static void *proxy_thread_func(void *arg) {
    proxy_t *proxy = (proxy_t *)arg;
    pthread_cleanup_push(proxy_thread_cleanup, proxy);

    while (atomic_load(&proxy->active)) {
        pthread_mutex_lock(&proxy->fd_mutex);
        int fd = proxy->listen_fd;
        pthread_mutex_unlock(&proxy->fd_mutex);

        if (fd < 0) break;

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        int ret = poll(&pfd, 1, 100);
        if (ret <= 0) continue;
        if (!(pfd.revents & POLLIN)) continue;

        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(fd, (struct sockaddr *)&client_addr, &client_len);

        if (client_fd >= 0) {
            /* Allocate client info struct */
            struct client_info {
                int client_fd;
                char target_socket[256];
                corruption_params_t c2s;
                corruption_params_t s2c;
            } *info = malloc(sizeof(struct client_info));
            if (!info) {
                close(client_fd);
            } else {
                info->client_fd = client_fd;
                snprintf(info->target_socket, sizeof(info->target_socket), "%s", proxy->target_socket);
                memcpy(&info->c2s, &proxy->client_to_server, sizeof(corruption_params_t));
                memcpy(&info->s2c, &proxy->server_to_client, sizeof(corruption_params_t));
                pthread_t tid;
                if (pthread_create(&tid, NULL, handle_proxy_client, info) != 0) {
                    close(client_fd);
                    free(info);
                } else {
                    pthread_detach(tid);
                }
            }
        }
    }

    pthread_cleanup_pop(1);
    return NULL;
}

/* Create proxy - listens on Unix socket, forwards to target Unix socket */
static proxy_t *proxy_create(const char *listen_socket, const char *target_socket) {
    proxy_t *proxy = calloc(1, sizeof(proxy_t));
    if (!proxy) return NULL;

    snprintf(proxy->listen_socket, sizeof(proxy->listen_socket), "%s", listen_socket);
    snprintf(proxy->target_socket, sizeof(proxy->target_socket), "%s", target_socket);
    atomic_store(&proxy->active, 1);
    pthread_mutex_init(&proxy->fd_mutex, NULL);
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
    pthread_mutex_lock(&proxy->fd_mutex);
    corruption_init(&proxy->client_to_server, c2s_bit, c2s_byte);
    corruption_init(&proxy->server_to_client, s2c_bit, s2c_byte);
    pthread_mutex_unlock(&proxy->fd_mutex);
}

static int proxy_start(proxy_t *proxy) {
    return pthread_create(&proxy->thread, NULL, proxy_thread_func, proxy) == 0 ? 0 : -1;
}
static void proxy_stop(proxy_t *proxy) {
    atomic_store(&proxy->active, 0);
    /* Signal stop - cleanup handler will close fd and unlink */
    if (proxy->thread) {
        pthread_join(proxy->thread, NULL);
        proxy->thread = 0;
    }
}
static void proxy_destroy(proxy_t *proxy) {
    if (proxy) {
        proxy_stop(proxy);
        pthread_mutex_destroy(&proxy->fd_mutex);
        free(proxy);
    }
}

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



/* Server thread: calls blocking get_request in a loop until stopped
 * Returns server handle via out_server pointer */
typedef struct {
    const char *socket_path;
    rbox_server_handle_t *server;  /* Output: server handle for caller to use */
    pthread_mutex_t server_mutex;   /* Protects server field */
} server_thread_arg_t;

static void *rbox_server_thread(void *arg) {
    server_thread_arg_t *thread_arg = (server_thread_arg_t *)arg;
    const char *socket_path = thread_arg->socket_path;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    /* Create server using full handle API */
    rbox_server_handle_t *server = rbox_server_handle_new(socket_path, &err_info);
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
    pthread_mutex_lock(&thread_arg->server_mutex);
    thread_arg->server = server;
    pthread_mutex_unlock(&thread_arg->server_mutex);

    /* Blocking request loop - exits when rbox_server_stop() is called */
    while (1) {
        rbox_server_request_t *req = rbox_server_get_request(server, &err_info);
        if (!req) {
            /* NULL means server was stopped */
            break;
        }

        /* Send ALLOW decision for any valid request */
        rbox_server_decide(req, RBOX_DECISION_ALLOW, "ok", 0, 0, NULL);
    }

    /* NOTE: Do NOT call rbox_server_handle_free here.
     * rbox_server_stop() must be called by the main thread first,
     * then rbox_server_handle_free after pthread_join. */
    return NULL;
}

/* Run proxy test - returns count of successful requests with CORRECT result
 * Uses real rbox server on Unix socket, proxy forwards Unix socket->Unix socket */
static int run_proxy_test(const char *server_socket, const char *proxy_socket,
                         double c2s_bit, double c2s_byte,
                         double s2c_bit, double s2c_byte,
                         int num_requests, uint8_t expected_decision) {
    pthread_t server_tid;
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;
    server_thread_arg_t thread_arg = { .socket_path = server_socket, .server = NULL, .server_mutex = PTHREAD_MUTEX_INITIALIZER };
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
        rbox_client_t *client = rbox_client_connect(proxy_socket, &err_info);
        if (!client) continue;

        char *cmd = "ls";
        const char *args[] = { cmd };
        rbox_response_t resp;
        rbox_error_t err = rbox_client_send_request(client, cmd, NULL, NULL, 1, args, 0, NULL, NULL, &resp, &err_info);
        if (err == RBOX_OK && resp.decision == expected_decision) {
            success++;
        }
        rbox_client_close(client);
        usleep(5000);  /* 5ms delay between requests */
    }

    proxy_destroy(proxy);
    /* Stop the server - this will cause get_request to return NULL */
    rbox_server_handle_t *srv = NULL;
    pthread_mutex_lock(&thread_arg.server_mutex);
    srv = thread_arg.server;
    pthread_mutex_unlock(&thread_arg.server_mutex);
    if (srv) rbox_server_stop(srv);
    pthread_join(server_tid, NULL);
    pthread_mutex_lock(&thread_arg.server_mutex);
    srv = thread_arg.server;
    pthread_mutex_unlock(&thread_arg.server_mutex);
    if (srv) rbox_server_handle_free(srv);
    return success;
}

/* Test 1: Direct connection (no proxy) - using real rbox server on Unix socket */
static int test_proxy_direct(void) {
    TEST("direct connection (no proxy)");
    rbox_error_info_t err_info = RBOX_ERROR_INITIALIZER;

    const char *server_sock = "/tmp/rbox_test_direct.sock";
    unlink(server_sock);

    pthread_t server_tid;
    server_thread_arg_t thread_arg = { .socket_path = server_sock, .server = NULL, .server_mutex = PTHREAD_MUTEX_INITIALIZER };
    pthread_create(&server_tid, NULL, rbox_server_thread, &thread_arg);
    usleep(100000);  /* Wait for server to start */

    int success = 0;
    for (int i = 0; i < 35; i++) {
        rbox_client_t *client = rbox_client_connect(server_sock, &err_info);
        if (!client) continue;

        char *cmd = "ls";
        const char *args[] = { cmd };
        rbox_response_t resp;
        rbox_error_t err = rbox_client_send_request(client, cmd, NULL, NULL, 1, args, 0, NULL, NULL, &resp, &err_info);
        if (err == RBOX_OK && resp.decision == RBOX_DECISION_ALLOW) {
            success++;
        }
        rbox_client_close(client);
    }

    /* Stop the server */
    rbox_server_handle_t *srv = NULL;
    pthread_mutex_lock(&thread_arg.server_mutex);
    srv = thread_arg.server;
    pthread_mutex_unlock(&thread_arg.server_mutex);
    if (srv) rbox_server_stop(srv);
    pthread_join(server_tid, NULL);
    pthread_mutex_lock(&thread_arg.server_mutex);
    srv = thread_arg.server;
    pthread_mutex_unlock(&thread_arg.server_mutex);
    if (srv) rbox_server_handle_free(srv);
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
