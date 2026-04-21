/*
 * test_soft_policy.c - Unit tests for soft filesystem policy evaluation
 *
 * These tests verify the pure policy evaluation subsystem in isolation.
 * The soft_policy module receives paths and evaluates them against rules,
 * but does not handle syscall interception or path extraction.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>

#include "../soft_policy.h"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static int test_##name(void)

#define RUN_TEST(name) do { \
    printf("  Running %s... ", #name); \
    fflush(stdout); \
    tests_run++; \
    if (test_##name() == 0) { \
        printf("PASSED\n"); \
        tests_passed++; \
    } else { \
        printf("FAILED\n"); \
        tests_failed++; \
    } \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        return 1; \
    } \
} while(0)

#define ASSERT_EQ(a, b) ASSERT(((a) == (b)))
#define ASSERT_NE(a, b) ASSERT(((a) != (b)))
#define ASSERT_NULL(p) ASSERT(((p) == NULL))
#define ASSERT_NOT_NULL(p) ASSERT(((p) != NULL))
#define ASSERT_STR_EQ(a, b) ASSERT((strcmp((a), (b)) == 0))

/* ==================== soft_policy_init tests ==================== */

TEST(init_basic) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    ASSERT_EQ(soft_policy_get_count(&policy), 0);
    ASSERT_EQ(soft_policy_get_default_mode(&policy), SOFT_MODE_DENY);
    soft_policy_free(&policy);
    return 0;
}

TEST(init_null_policy) {
    soft_policy_init(NULL);
    return 0;
}

/* ==================== soft_policy_add_rule tests ==================== */

TEST(add_single_rule) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    int result = soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_DENY);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(soft_policy_get_count(&policy), 1);
    soft_policy_rule_t rule;
    ASSERT_EQ(soft_policy_get_rule(&policy, 0, &rule), 0);
    ASSERT_STR_EQ(rule.path, "/tmp");
    ASSERT_EQ(rule.mode, SOFT_MODE_DENY);

    soft_policy_free(&policy);
    return 0;
}

TEST(add_multiple_rules) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    ASSERT_EQ(soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_DENY), 0);
    ASSERT_EQ(soft_policy_add_rule(&policy, "/var", SOFT_MODE_RO), 0);
    ASSERT_EQ(soft_policy_add_rule(&policy, "/home", SOFT_MODE_DENY), 0);

    ASSERT_EQ(soft_policy_get_count(&policy), 3);
    soft_policy_rule_t rule;
    ASSERT_EQ(soft_policy_get_rule(&policy, 0, &rule), 0);
    ASSERT_STR_EQ(rule.path, "/tmp");
    ASSERT_EQ(soft_policy_get_rule(&policy, 1, &rule), 0);
    ASSERT_STR_EQ(rule.path, "/var");
    ASSERT_EQ(soft_policy_get_rule(&policy, 2, &rule), 0);
    ASSERT_STR_EQ(rule.path, "/home");

    soft_policy_free(&policy);
    return 0;
}

TEST(add_null_policy) {
    int result = soft_policy_add_rule(NULL, "/tmp", SOFT_MODE_DENY);
    ASSERT_EQ(result, -1);
    return 0;
}

TEST(add_null_path) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    int result = soft_policy_add_rule(&policy, NULL, SOFT_MODE_DENY);
    ASSERT_EQ(result, -1);

    soft_policy_free(&policy);
    return 0;
}

TEST(add_empty_path) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    int result = soft_policy_add_rule(&policy, "", SOFT_MODE_DENY);
    ASSERT_EQ(result, -1);

    soft_policy_free(&policy);
    return 0;
}

TEST(add_relative_path) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    int result = soft_policy_add_rule(&policy, "tmp", SOFT_MODE_DENY);
    ASSERT_EQ(result, -1);

    result = soft_policy_add_rule(&policy, "etc/passwd", SOFT_MODE_DENY);
    ASSERT_EQ(result, -1);

    soft_policy_free(&policy);
    return 0;
}

/* ==================== soft_policy_check tests ==================== */

TEST(check_empty_policy) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    soft_path_mode_t inputs[] = {{"/tmp", SOFT_ACCESS_READ}};
    int results[1];
    soft_policy_check(&policy, inputs, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_exact_match_allow) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_RO);

    soft_path_mode_t inputs[] = {{"/tmp", SOFT_ACCESS_READ}};
    int results[1];
    soft_policy_check(&policy, inputs, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_exact_match_deny) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_DENY);

    soft_path_mode_t inputs[] = {{"/tmp", SOFT_ACCESS_READ}};
    int results[1];
    soft_policy_check(&policy, inputs, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_prefix_match) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_DENY);

    soft_path_mode_t inputs1[] = {{"/tmp", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs2[] = {{"/tmp/subdir", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs3[] = {{"/tmp/subdir/file.txt", SOFT_ACCESS_READ}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs3, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_longest_prefix_match) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_DENY);
    soft_policy_add_rule(&policy, "/tmp/safe", SOFT_MODE_RO);

    soft_path_mode_t inputs1[] = {{"/tmp", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs2[] = {{"/tmp/other", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs3[] = {{"/tmp/safe", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs4[] = {{"/tmp/safe/subdir", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs5[] = {{"/tmp/unsafe", SOFT_ACCESS_READ}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs3, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs4, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs5, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_no_match) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_set_default(&policy, SOFT_MODE_RO);
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_DENY);

    soft_path_mode_t inputs1[] = {{"/var", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs2[] = {{"/home/user", SOFT_ACCESS_READ}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_trailing_slash_match) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_set_default(&policy, SOFT_MODE_RO);
    soft_policy_add_rule(&policy, "/tmp/", SOFT_MODE_DENY);

    soft_path_mode_t inputs1[] = {{"/tmp", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs2[] = {{"/tmp/subdir", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs3[] = {{"/tmpx", SOFT_ACCESS_READ}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs3, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_partial_component_not_matched) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_set_default(&policy, SOFT_MODE_RO);

    soft_policy_add_rule(&policy, "/home/user", SOFT_MODE_DENY);

    soft_path_mode_t inputs1[] = {{"/home/user", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs2[] = {{"/home/user1", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs3[] = {{"/home/user/", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs4[] = {{"/home/user1/file", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs5[] = {{"/home/user/file", SOFT_ACCESS_READ}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs3, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs4, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs5, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_null_policy) {
    soft_path_mode_t inputs[] = {{"/tmp", SOFT_ACCESS_READ}};
    int results[1];
    int r = soft_policy_check(NULL, inputs, results, 1);
    ASSERT_EQ(r, -1);
    return 0;
}

TEST(check_null_path) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_DENY);

    soft_path_mode_t inputs[] = {{NULL, SOFT_ACCESS_READ}};
    int results[1];
    soft_policy_check(&policy, inputs, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_root_match) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_add_rule(&policy, "/", SOFT_MODE_DENY);

    soft_path_mode_t inputs1[] = {{"/", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs2[] = {{"/tmp", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs3[] = {{"/var/log", SOFT_ACCESS_READ}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs3, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_complex_prefixes) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    soft_policy_add_rule(&policy, "/home/user/docs", SOFT_MODE_RO);
    soft_policy_add_rule(&policy, "/home/user", SOFT_MODE_DENY);
    soft_policy_add_rule(&policy, "/home", SOFT_MODE_RO);

    soft_path_mode_t inputs1[] = {{"/home", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs2[] = {{"/home/user", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs3[] = {{"/home/user/file.txt", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs4[] = {{"/home/user/docs", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs5[] = {{"/home/user/docs/subdir", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs6[] = {{"/home/other", SOFT_ACCESS_READ}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs3, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs4, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs5, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs6, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_free(&policy);
    return 0;
}

/* ==================== Access mode tests ==================== */

TEST(check_rw_allows_read) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_RW);

    soft_path_mode_t inputs[] = {{"/tmp", SOFT_ACCESS_READ}};
    int results[1];
    soft_policy_check(&policy, inputs, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_rw_allows_write) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_RW);

    soft_path_mode_t inputs[] = {{"/tmp", SOFT_ACCESS_WRITE}};
    int results[1];
    soft_policy_check(&policy, inputs, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_rw_denies_exec) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_RW);

    soft_path_mode_t inputs[] = {{"/tmp", SOFT_ACCESS_EXEC}};
    int results[1];
    soft_policy_check(&policy, inputs, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_rx_allows_read) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_RX);

    soft_path_mode_t inputs[] = {{"/tmp", SOFT_ACCESS_READ}};
    int results[1];
    soft_policy_check(&policy, inputs, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_rx_allows_exec) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_RX);

    soft_path_mode_t inputs[] = {{"/tmp", SOFT_ACCESS_EXEC}};
    int results[1];
    soft_policy_check(&policy, inputs, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_rx_denies_write) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_RX);

    soft_path_mode_t inputs[] = {{"/tmp", SOFT_ACCESS_WRITE}};
    int results[1];
    soft_policy_check(&policy, inputs, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_mkdir_access) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_RW);

    soft_path_mode_t inputs[] = {{"/tmp", SOFT_ACCESS_MKDIR}};
    int results[1];
    soft_policy_check(&policy, inputs, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_multiple_access) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_RW);

    soft_path_mode_t inputs[] = {{"/tmp", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE}};
    int results[1];
    soft_policy_check(&policy, inputs, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_multiple_access_partial) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_RO);

    soft_path_mode_t inputs[] = {{"/tmp", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE}};
    int results[1];
    soft_policy_check(&policy, inputs, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

/* ==================== soft_policy_set_default tests ==================== */

TEST(set_default_deny) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    ASSERT_EQ(soft_policy_get_default_mode(&policy), SOFT_MODE_DENY);
    soft_policy_set_default(&policy, SOFT_MODE_DENY);
    ASSERT_EQ(soft_policy_get_default_mode(&policy), SOFT_MODE_DENY);

    soft_path_mode_t inputs[] = {{"/any/path", SOFT_ACCESS_READ}};
    int results[1];
    soft_policy_check(&policy, inputs, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(set_default_allow) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    soft_policy_set_default(&policy, SOFT_MODE_DENY);
    ASSERT_EQ(soft_policy_get_default_mode(&policy), SOFT_MODE_DENY);
    soft_policy_set_default(&policy, SOFT_MODE_RO);
    ASSERT_EQ(soft_policy_get_default_mode(&policy), SOFT_MODE_RO);

    soft_policy_free(&policy);
    return 0;
}

TEST(set_default_null_policy) {
    soft_policy_set_default(NULL, SOFT_MODE_DENY);
    return 0;
}

/* ==================== soft_policy_is_active tests ==================== */

TEST(is_active_empty) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    ASSERT(!soft_policy_is_active(&policy));

    soft_policy_free(&policy);
    return 0;
}

TEST(is_active_with_rules) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    ASSERT(!soft_policy_is_active(&policy));
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_DENY);
    ASSERT(soft_policy_is_active(&policy));

    soft_policy_free(&policy);
    return 0;
}

TEST(is_active_null) {
    ASSERT(!soft_policy_is_active(NULL));
    return 0;
}

/* ==================== soft_policy_free tests ==================== */

TEST(free_basic) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_DENY);
    soft_policy_add_rule(&policy, "/var", SOFT_MODE_RO);

    soft_policy_free(&policy);
    ASSERT_EQ(soft_policy_get_count(&policy), 0);
    return 0;
}

TEST(free_empty) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    soft_policy_free(&policy);
    ASSERT_EQ(soft_policy_get_count(&policy), 0);
    return 0;
}

TEST(free_null) {
    soft_policy_free(NULL);
    return 0;
}

TEST(clear_basic) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_DENY);
    soft_policy_add_rule(&policy, "/var", SOFT_MODE_RO);

    soft_policy_clear(&policy);
    ASSERT_EQ(soft_policy_get_count(&policy), 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(clear_then_reload) {
    unsetenv("READONLYBOX_SOFT_ALLOW");
    unsetenv("READONLYBOX_SOFT_DENY");

    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_add_rule(&policy, "/old", SOFT_MODE_DENY);

    setenv("READONLYBOX_SOFT_ALLOW", "/new:rw", 1);
    soft_policy_clear(&policy);
    int result = soft_policy_load_from_env(&policy);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(soft_policy_get_count(&policy), 1);

    soft_policy_rule_t rule;
    int found_new = 0;
    for (size_t i = 0; i < soft_policy_get_count(&policy); i++) {
        if (soft_policy_get_rule(&policy, i, &rule) == 0 && strcmp(rule.path, "/new") == 0) {
            found_new = 1;
            break;
        }
    }
    ASSERT(found_new);

    int found_old = 0;
    for (size_t i = 0; i < soft_policy_get_count(&policy); i++) {
        if (soft_policy_get_rule(&policy, i, &rule) == 0 && strcmp(rule.path, "/old") == 0) {
            found_old = 1;
            break;
        }
    }
    ASSERT(!found_old);

    soft_policy_free(&policy);
    unsetenv("READONLYBOX_SOFT_ALLOW");
    return 0;
}

/* ==================== soft_policy_load_from_env tests ==================== */

TEST(load_from_env_null_policy) {
    unsetenv("READONLYBOX_SOFT_ALLOW");
    unsetenv("READONLYBOX_SOFT_DENY");
    int result = soft_policy_load_from_env(NULL);
    ASSERT_EQ(result, -1);
    return 0;
}

TEST(load_from_env_no_env) {
    unsetenv("READONLYBOX_SOFT_ALLOW");
    unsetenv("READONLYBOX_SOFT_DENY");

    soft_policy_t policy;
    soft_policy_init(&policy);
    int result = soft_policy_load_from_env(&policy);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(soft_policy_get_count(&policy), 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(load_from_env_allow) {
    setenv("READONLYBOX_SOFT_ALLOW", "/tmp,/var", 1);
    unsetenv("READONLYBOX_SOFT_DENY");

    soft_policy_t policy;
    soft_policy_init(&policy);
    int result = soft_policy_load_from_env(&policy);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(soft_policy_get_count(&policy), 2);
    soft_policy_rule_t rule;
    ASSERT_EQ(soft_policy_get_rule(&policy, 0, &rule), 0);
    ASSERT_STR_EQ(rule.path, "/tmp");
    ASSERT_EQ(rule.mode, SOFT_MODE_RO);
    ASSERT_EQ(soft_policy_get_rule(&policy, 1, &rule), 0);
    ASSERT_STR_EQ(rule.path, "/var");
    ASSERT_EQ(rule.mode, SOFT_MODE_RO);

    unsetenv("READONLYBOX_SOFT_ALLOW");
    soft_policy_free(&policy);
    return 0;
}

TEST(load_from_env_deny) {
    unsetenv("READONLYBOX_SOFT_ALLOW");
    setenv("READONLYBOX_SOFT_DENY", "/home,/root", 1);

    soft_policy_t policy;
    soft_policy_init(&policy);
    int result = soft_policy_load_from_env(&policy);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(soft_policy_get_count(&policy), 2);
    soft_policy_rule_t rule;
    ASSERT_EQ(soft_policy_get_rule(&policy, 0, &rule), 0);
    ASSERT_STR_EQ(rule.path, "/home");
    ASSERT_EQ(rule.mode, SOFT_MODE_DENY);
    ASSERT_EQ(soft_policy_get_rule(&policy, 1, &rule), 0);
    ASSERT_STR_EQ(rule.path, "/root");
    ASSERT_EQ(rule.mode, SOFT_MODE_DENY);

    unsetenv("READONLYBOX_SOFT_DENY");
    soft_policy_free(&policy);
    return 0;
}

TEST(load_from_env_both) {
    setenv("READONLYBOX_SOFT_ALLOW", "/tmp", 1);
    setenv("READONLYBOX_SOFT_DENY", "/home", 1);

    soft_policy_t policy;
    soft_policy_init(&policy);
    int result = soft_policy_load_from_env(&policy);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(soft_policy_get_count(&policy), 2);

    unsetenv("READONLYBOX_SOFT_ALLOW");
    unsetenv("READONLYBOX_SOFT_DENY");
    soft_policy_free(&policy);
    return 0;
}

TEST(load_from_env_with_spaces) {
    setenv("READONLYBOX_SOFT_ALLOW", "  /tmp  ,  /var  ", 1);
    unsetenv("READONLYBOX_SOFT_DENY");

    soft_policy_t policy;
    soft_policy_init(&policy);
    int result = soft_policy_load_from_env(&policy);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(soft_policy_get_count(&policy), 2);
    soft_policy_rule_t rule;
    ASSERT_EQ(soft_policy_get_rule(&policy, 0, &rule), 0);
    ASSERT_STR_EQ(rule.path, "/tmp");
    ASSERT_EQ(soft_policy_get_rule(&policy, 1, &rule), 0);
    ASSERT_STR_EQ(rule.path, "/var");

    unsetenv("READONLYBOX_SOFT_ALLOW");
    soft_policy_free(&policy);
    return 0;
}

TEST(load_from_env_with_mode) {
    setenv("READONLYBOX_SOFT_ALLOW", "/tmp:rw,/var:rx", 1);
    unsetenv("READONLYBOX_SOFT_DENY");

    soft_policy_t policy;
    soft_policy_init(&policy);
    int result = soft_policy_load_from_env(&policy);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(soft_policy_get_count(&policy), 2);
    soft_policy_rule_t rule;
    ASSERT_EQ(soft_policy_get_rule(&policy, 0, &rule), 0);
    ASSERT_STR_EQ(rule.path, "/tmp");
    ASSERT_EQ(rule.mode, SOFT_MODE_RW);
    ASSERT_EQ(soft_policy_get_rule(&policy, 1, &rule), 0);
    ASSERT_STR_EQ(rule.path, "/var");
    ASSERT_EQ(rule.mode, SOFT_MODE_RX);

    unsetenv("READONLYBOX_SOFT_ALLOW");
    soft_policy_free(&policy);
    return 0;
}

TEST(load_from_env_mixed_deny_allow) {
    setenv("READONLYBOX_SOFT_ALLOW", "/tmp", 1);
    setenv("READONLYBOX_SOFT_DENY", "/home", 1);

    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_load_from_env(&policy);

    soft_path_mode_t inputs1[] = {{"/tmp", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs2[] = {{"/home", SOFT_ACCESS_READ}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 0);

    unsetenv("READONLYBOX_SOFT_ALLOW");
    unsetenv("READONLYBOX_SOFT_DENY");
    soft_policy_free(&policy);
    return 0;
}

/* ==================== Complex rule interaction tests ==================== */

TEST(check_allow_deny_allow_chain) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    soft_policy_add_rule(&policy, "/tmp/a", SOFT_MODE_RO);
    soft_policy_add_rule(&policy, "/tmp/a/b", SOFT_MODE_DENY);
    soft_policy_add_rule(&policy, "/tmp/a/b/c", SOFT_MODE_RO);

    soft_path_mode_t inputs1[] = {{"/tmp/a", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs2[] = {{"/tmp/a/b", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs3[] = {{"/tmp/a/b/c", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs4[] = {{"/tmp/a/x", SOFT_ACCESS_READ}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs3, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs4, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_deny_allow_allow_chain) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    soft_policy_add_rule(&policy, "/tmp/a", SOFT_MODE_DENY);
    soft_policy_add_rule(&policy, "/tmp/a/b", SOFT_MODE_RO);
    soft_policy_add_rule(&policy, "/tmp/a/b/c", SOFT_MODE_RO);

    soft_path_mode_t inputs1[] = {{"/tmp/a", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs2[] = {{"/tmp/a/b", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs3[] = {{"/tmp/a/b/c", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs4[] = {{"/tmp/a/x", SOFT_ACCESS_READ}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs3, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs4, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_overlapping_siblings) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    soft_policy_add_rule(&policy, "/tmp/allowed", SOFT_MODE_RO);
    soft_policy_add_rule(&policy, "/tmp/denied", SOFT_MODE_DENY);

    soft_path_mode_t inputs1[] = {{"/tmp/allowed", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs2[] = {{"/tmp/allowed/subdir", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs3[] = {{"/tmp/denied", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs4[] = {{"/tmp/denied/subdir", SOFT_ACCESS_READ}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs3, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs4, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_parent_deny_child_allow_rw) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_set_default(&policy, SOFT_MODE_RO);

    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_DENY);
    soft_policy_add_rule(&policy, "/tmp/public", SOFT_MODE_RW);

    soft_path_mode_t inputs1[] = {{"/tmp", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs2[] = {{"/tmp", SOFT_ACCESS_WRITE}};
    soft_path_mode_t inputs3[] = {{"/tmp/public", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs4[] = {{"/tmp/public", SOFT_ACCESS_WRITE}};
    soft_path_mode_t inputs5[] = {{"/tmp/public/subdir", SOFT_ACCESS_WRITE}};
    soft_path_mode_t inputs6[] = {{"/other", SOFT_ACCESS_READ}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs3, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs4, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs5, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs6, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_three_level_override) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    soft_policy_add_rule(&policy, "/data", SOFT_MODE_RO);
    soft_policy_add_rule(&policy, "/data/cache", SOFT_MODE_RW);
    soft_policy_add_rule(&policy, "/data/cache/temp", SOFT_MODE_DENY);

    soft_path_mode_t inputs1[] = {{"/data", SOFT_ACCESS_WRITE}};
    soft_path_mode_t inputs2[] = {{"/data/file.txt", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs3[] = {{"/data/cache", SOFT_ACCESS_WRITE}};
    soft_path_mode_t inputs4[] = {{"/data/cache/file.txt", SOFT_ACCESS_WRITE}};
    soft_path_mode_t inputs5[] = {{"/data/cache/temp", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs6[] = {{"/data/cache/temp", SOFT_ACCESS_WRITE}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs3, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs4, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs5, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs6, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_unrelated_paths_not_affected) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_set_default(&policy, SOFT_MODE_RO);

    soft_policy_add_rule(&policy, "/tmp/secret", SOFT_MODE_DENY);
    soft_policy_add_rule(&policy, "/var/public", SOFT_MODE_RO);

    soft_path_mode_t inputs1[] = {{"/tmp/secret", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs2[] = {{"/var/public", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs3[] = {{"/home/user", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs4[] = {{"/etc/config", SOFT_ACCESS_READ}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs3, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs4, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_same_path_different_modes) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_RO);
    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_RW);

    soft_path_mode_t inputs1[] = {{"/tmp", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs2[] = {{"/tmp", SOFT_ACCESS_WRITE}};
    soft_path_mode_t inputs3[] = {{"/tmp", SOFT_ACCESS_EXEC}};
    soft_path_mode_t inputs4[] = {{"/tmp", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs3, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs4, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_multiple_access_with_mode) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_RW);

    soft_path_mode_t inputs1[] = {{"/tmp", SOFT_ACCESS_READ | SOFT_ACCESS_WRITE}};
    soft_path_mode_t inputs2[] = {{"/tmp", SOFT_ACCESS_READ | SOFT_ACCESS_EXEC}};
    soft_path_mode_t inputs3[] = {{"/tmp", SOFT_ACCESS_READ | SOFT_ACCESS_MKDIR}};
    soft_path_mode_t inputs4[] = {{"/tmp", SOFT_ACCESS_WRITE}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs3, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs4, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_default_mode_with_rules) {
    soft_policy_t policy;
    soft_policy_init(&policy);
    soft_policy_set_default(&policy, SOFT_MODE_DENY);

    soft_policy_add_rule(&policy, "/tmp", SOFT_MODE_RO);

    soft_path_mode_t inputs1[] = {{"/tmp", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs2[] = {{"/tmp", SOFT_ACCESS_WRITE}};
    soft_path_mode_t inputs3[] = {{"/var", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs4[] = {{"/var", SOFT_ACCESS_WRITE}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs3, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs4, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

TEST(check_very_deep_nesting) {
    soft_policy_t policy;
    soft_policy_init(&policy);

    soft_policy_add_rule(&policy, "/a", SOFT_MODE_DENY);
    soft_policy_add_rule(&policy, "/a/b", SOFT_MODE_RO);
    soft_policy_add_rule(&policy, "/a/b/c", SOFT_MODE_DENY);
    soft_policy_add_rule(&policy, "/a/b/c/d", SOFT_MODE_RO);
    soft_policy_add_rule(&policy, "/a/b/c/d/e", SOFT_MODE_DENY);

    soft_path_mode_t inputs1[] = {{"/a", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs2[] = {{"/a/b", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs3[] = {{"/a/b/c", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs4[] = {{"/a/b/c/d", SOFT_ACCESS_READ}};
    soft_path_mode_t inputs5[] = {{"/a/b/c/d/e", SOFT_ACCESS_READ}};
    int results[1];

    soft_policy_check(&policy, inputs1, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs2, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs3, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_check(&policy, inputs4, results, 1);
    ASSERT_EQ(results[0], 1);

    soft_policy_check(&policy, inputs5, results, 1);
    ASSERT_EQ(results[0], 0);

    soft_policy_free(&policy);
    return 0;
}

/* Helper: check that a path matches the expected allowed access bits */
static int check_path_access(soft_policy_t *policy, const char *path, uint32_t access_mask, int expected_allowed) {
    soft_path_mode_t input = {path, access_mask};
    int result;
    int ret = soft_policy_check(policy, &input, &result, 1);
    if (ret != 0) return 0;
    return (result == expected_allowed);
}

/* ==================== Run all tests ==================== */

void run_soft_policy_tests(void) {
    printf("\n=== Soft Policy Tests ===\n");

    RUN_TEST(init_basic);
    RUN_TEST(init_null_policy);

    RUN_TEST(add_single_rule);
    RUN_TEST(add_multiple_rules);
    RUN_TEST(add_null_policy);
    RUN_TEST(add_null_path);
    RUN_TEST(add_empty_path);
    RUN_TEST(add_relative_path);

    RUN_TEST(check_empty_policy);
    RUN_TEST(check_exact_match_allow);
    RUN_TEST(check_exact_match_deny);
    RUN_TEST(check_prefix_match);
    RUN_TEST(check_longest_prefix_match);
    RUN_TEST(check_no_match);
    RUN_TEST(check_trailing_slash_match);
    RUN_TEST(check_partial_component_not_matched);
    RUN_TEST(check_null_policy);
    RUN_TEST(check_null_path);
    RUN_TEST(check_root_match);
    RUN_TEST(check_complex_prefixes);

    RUN_TEST(check_rw_allows_read);
    RUN_TEST(check_rw_allows_write);
    RUN_TEST(check_rw_denies_exec);
    RUN_TEST(check_rx_allows_read);
    RUN_TEST(check_rx_allows_exec);
    RUN_TEST(check_rx_denies_write);
    RUN_TEST(check_mkdir_access);
    RUN_TEST(check_multiple_access);
    RUN_TEST(check_multiple_access_partial);

    RUN_TEST(set_default_deny);
    RUN_TEST(set_default_allow);
    RUN_TEST(set_default_null_policy);

    RUN_TEST(is_active_empty);
    RUN_TEST(is_active_with_rules);
    RUN_TEST(is_active_null);

    RUN_TEST(free_basic);
    RUN_TEST(free_empty);
    RUN_TEST(free_null);
    RUN_TEST(clear_basic);
    RUN_TEST(clear_then_reload);

    RUN_TEST(load_from_env_null_policy);
    RUN_TEST(load_from_env_no_env);
    RUN_TEST(load_from_env_allow);
    RUN_TEST(load_from_env_deny);
    RUN_TEST(load_from_env_both);
    RUN_TEST(load_from_env_with_spaces);
    RUN_TEST(load_from_env_with_mode);
    RUN_TEST(load_from_env_mixed_deny_allow);

    RUN_TEST(check_allow_deny_allow_chain);
    RUN_TEST(check_deny_allow_allow_chain);
    RUN_TEST(check_overlapping_siblings);
    RUN_TEST(check_parent_deny_child_allow_rw);
    RUN_TEST(check_three_level_override);
    RUN_TEST(check_unrelated_paths_not_affected);
    RUN_TEST(check_same_path_different_modes);
    RUN_TEST(check_multiple_access_with_mode);
    RUN_TEST(check_default_mode_with_rules);
    RUN_TEST(check_very_deep_nesting);
}

void get_soft_policy_test_stats(int *run, int *passed, int *failed) {
    *run = tests_run;
    *passed = tests_passed;
    *failed = tests_failed;
}

void reset_soft_policy_test_stats(void) {
    tests_run = 0;
    tests_passed = 0;
    tests_failed = 0;
}
