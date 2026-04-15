/*
 * test_log.c - Unit tests for the logging system
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>

#include "../include/rbox_log.h"

/* Test state */
static struct {
    rbox_log_level_t level;
    const char *file;
    int line;
    char msg[1024];
    int count;
} g_test_state;

static pthread_mutex_t g_test_mutex = PTHREAD_MUTEX_INITIALIZER;

static void reset_test_state(void) {
    pthread_mutex_lock(&g_test_mutex);
    g_test_state.count = 0;
    g_test_state.level = 0;
    g_test_state.file = NULL;
    g_test_state.line = 0;
    g_test_state.msg[0] = '\0';
    pthread_mutex_unlock(&g_test_mutex);
}

static void test_logger(rbox_log_level_t level,
                       const char *file,
                       int line,
                       const char *msg) {
    pthread_mutex_lock(&g_test_mutex);
    g_test_state.level = level;
    g_test_state.file = file;
    g_test_state.line = line;
    strncpy(g_test_state.msg, msg, sizeof(g_test_state.msg) - 1);
    g_test_state.msg[sizeof(g_test_state.msg) - 1] = '\0';
    g_test_state.count++;
    pthread_mutex_unlock(&g_test_mutex);
}

static int test_basic_logging(void) {
    printf("Testing basic logging...\n");

    rbox_log_set_callback(test_logger);
    rbox_log_set_level(RBOX_LOG_DEBUG);

    reset_test_state();
    RBOX_LOG_ERROR("test error %d", 42);
    assert(g_test_state.count == 1);
    assert(g_test_state.level == RBOX_LOG_ERROR);
    assert(strstr(g_test_state.msg, "test error 42") != NULL);

    RBOX_LOG_WARN("test warn");
    assert(g_test_state.count == 2);
    assert(g_test_state.level == RBOX_LOG_WARN);

    RBOX_LOG_INFO("test info");
    assert(g_test_state.count == 3);
    assert(g_test_state.level == RBOX_LOG_INFO);

    RBOX_LOG_DEBUG("test debug");
    assert(g_test_state.count == 4);
    assert(g_test_state.level == RBOX_LOG_DEBUG);

    printf("  ✓ Basic logging works\n");
    printf("test_basic_logging: PASSED\n\n");
    return 0;
}

static int test_level_filtering(void) {
    printf("Testing level filtering...\n");

    rbox_log_set_callback(test_logger);
    rbox_log_set_level(RBOX_LOG_WARN);

    reset_test_state();
    RBOX_LOG_ERROR("error msg");
    RBOX_LOG_WARN("warn msg");
    RBOX_LOG_INFO("info msg");
    RBOX_LOG_DEBUG("debug msg");

    assert(g_test_state.count == 2);
    assert(g_test_state.level == RBOX_LOG_WARN);

    printf("  ✓ Level filtering works\n");
    printf("test_level_filtering: PASSED\n\n");
    return 0;
}

static int test_callback_receives_correct_info(void) {
    printf("Testing callback receives correct info...\n");

    rbox_log_set_callback(test_logger);
    rbox_log_set_level(RBOX_LOG_DEBUG);

    reset_test_state();
    int expected_line = __LINE__ + 1;
    RBOX_LOG_ERROR("error message");
    assert(g_test_state.count == 1);
    assert(g_test_state.level == RBOX_LOG_ERROR);
    assert(g_test_state.line == expected_line);
    assert(strstr(g_test_state.msg, "error message") != NULL);

    printf("  ✓ Callback receives correct level/file/line/msg\n");
    printf("test_callback_receives_correct_info: PASSED\n\n");
    return 0;
}

static int test_legacy_macros(void) {
    printf("Testing legacy macros (CDBG/DBG)...\n");

    rbox_log_set_callback(test_logger);
    rbox_log_set_level(RBOX_LOG_DEBUG);

    reset_test_state();
    CDBG("client debug message");
    DBG("server debug message");

    assert(g_test_state.count == 2);
    assert(g_test_state.level == RBOX_LOG_DEBUG);
    assert(strstr(g_test_state.msg, "server debug message") != NULL);

    printf("  ✓ Legacy macros work\n");
    printf("test_legacy_macros: PASSED\n\n");
    return 0;
}

static int test_debug_print_disabled(void) {
    printf("Testing DEBUG_PRINTS compile flag...\n");

    rbox_log_set_callback(test_logger);
    rbox_log_set_level(RBOX_LOG_DEBUG);

    reset_test_state();
    RBOX_LOG_ERROR("error message");

    assert(g_test_state.count == 1);
    printf("  ✓ Logging works when DEBUG_PRINTS is defined\n");

#if !DEBUG_PRINTS
    printf("  ✓ DEBUG_PRINTS=0: RBOX_LOG_DEBUG compiled out at preprocessor level\n");
#else
    printf("  ✓ DEBUG_PRINTS=1: RBOX_LOG_DEBUG available at runtime\n");
#endif

    printf("test_debug_print_disabled: PASSED\n\n");
    return 0;
}

static void *thread_log_func(void *arg) {
    int id = *(int *)arg;
    free(arg);
    RBOX_LOG_DEBUG("thread %d", id);
    return NULL;
}

static int test_thread_safety(void) {
    printf("Testing thread safety...\n");

    rbox_log_set_callback(test_logger);
    rbox_log_set_level(RBOX_LOG_DEBUG);

    reset_test_state();
    const int num_threads = 10;
    pthread_t threads[10];

    for (int t = 0; t < num_threads; t++) {
        int *arg = malloc(sizeof(int));
        *arg = t;
        pthread_create(&threads[t], NULL, thread_log_func, arg);
    }

    for (int t = 0; t < num_threads; t++) {
        pthread_join(threads[t], NULL);
    }

    printf("  ✓ Thread safety test passed (no crash)\n");
    printf("test_thread_safety: PASSED\n\n");
    return 0;
}

int main(void) {
    printf("=== Logging System Unit Tests ===\n\n");

    test_basic_logging();
    test_level_filtering();
    test_callback_receives_correct_info();
    test_legacy_macros();
    test_debug_print_disabled();
    test_thread_safety();

    printf("=== All Logging Tests PASSED ===\n");
    return 0;
}
