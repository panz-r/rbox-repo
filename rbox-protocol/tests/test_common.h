/*
 * test_common.h - Shared test utilities for rbox-protocol tests
 * 
 * Provides common helpers to reduce duplication across test files.
 */

#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

/* Global test state */
extern int g_pass_count;
extern int g_test_count;

/* Run a test function and track results */
#define RUN_TEST(fn, name) do { \
    g_test_count++; \
    printf("  Testing: %s...\n", name); \
    fflush(stdout); \
    if (fn() == 0) { printf("    PASS\n"); g_pass_count++; } \
    else { printf("    FAIL\n"); } \
    fflush(stdout); \
} while(0)

/* Print error message */
#define TEST_ERROR(fmt, ...) fprintf(stderr, "ERROR: " fmt "\n", ##__VA_ARGS__)

/* Wait for server socket to be ready */
static inline int wait_for_server(const char *path, int timeout_ms) {
    int interval = 50;
    int elapsed = 0;
    while (elapsed < timeout_ms) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISSOCK(st.st_mode)) {
            return 0;
        }
        usleep(interval * 1000);
        elapsed += interval;
    }
    return -1;
}

/* Create thread with error checking */
static inline int checked_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                                        void *(*start_routine)(void *), void *arg) {
    int err = pthread_create(thread, attr, start_routine, arg);
    if (err != 0) {
        TEST_ERROR("pthread_create failed: %s", strerror(err));
        return -1;
    }
    return 0;
}

/* Generate unique socket path for test isolation */
static inline int make_unique_socket_path(char *buf, size_t bufsize, const char *test_name) {
    snprintf(buf, bufsize, "/tmp/rbox_test_%s_%d.sock", test_name, (int)getpid());
    return 0;
}

/* Get test seed for deterministic random testing
 * Returns fixed seed if RBOX_TEST_FIXED_SEED env var is set, else returns time-based */
static inline unsigned int get_test_seed(void) {
    const char *env_seed = getenv("RBOX_TEST_FIXED_SEED");
    if (env_seed) {
        return (unsigned int)atoi(env_seed);
    }
    return (unsigned int)time(NULL);
}

/* Cleanup socket file if it exists */
static inline void cleanup_socket(const char *path) {
    if (path) unlink(path);
}

/* Cleanup multiple sockets */
static inline void cleanup_sockets(const char *paths[], int count) {
    for (int i = 0; i < count; i++) {
        if (paths[i]) unlink(paths[i]);
    }
}

#endif /* TEST_COMMON_H */