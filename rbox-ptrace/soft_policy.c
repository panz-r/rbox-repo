/*
 * soft_policy.c - Soft filesystem access policy implementation
 *
 * Provides a list-based matcher for soft filesystem access control.
 * Rules are loaded from environment variables or added programmatically.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include "soft_policy.h"
#include "debug.h"

bool g_soft_debug = false;

static soft_policy_t g_soft_policy = {
    .rules = NULL,
    .count = 0,
    .capacity = 0,
    .default_mode = SOFT_MODE_DENY
};

struct builtin_rule_def {
    const char *path;
    soft_mode_t mode;
};

static const struct builtin_rule_def BUILTIN_ALLOW_RULES[] = {
    { "/",                 SOFT_MODE_RO },
    { "/usr",              SOFT_MODE_RX },
    { "/lib",              SOFT_MODE_RX },
    { "/lib64",            SOFT_MODE_RX },
    { "/usr/lib",          SOFT_MODE_RX },
    { "/usr/local/lib",    SOFT_MODE_RX },
    { "/etc",              SOFT_MODE_RO },
    { "/proc",             SOFT_MODE_RO },
    { "/sys",              SOFT_MODE_RO },
    { "/dev",              SOFT_MODE_RO },
    { "/dev/null",         SOFT_MODE_RW },
    { "/dev/shm",         SOFT_MODE_RW },
    { "/tmp",              SOFT_MODE_RW },
    { "/var/tmp",          SOFT_MODE_RW },
    { "/var",              SOFT_MODE_RO },
    { "/run",              SOFT_MODE_RO },
};

#define NUM_BUILTIN_ALLOW_RULES (sizeof(BUILTIN_ALLOW_RULES) / sizeof(BUILTIN_ALLOW_RULES[0]))

static const struct builtin_rule_def BUILTIN_DENY_RULES[] = {
    { "/home",             SOFT_MODE_DENY },
    { "/root",             SOFT_MODE_DENY },
    { "/var/log",          SOFT_MODE_DENY },
    { "/var/spool",        SOFT_MODE_DENY },
    { "/etc/shadow",       SOFT_MODE_DENY },
    { "/etc/gshadow",      SOFT_MODE_DENY },
    { "/etc/securetty",    SOFT_MODE_DENY },
    { "/etc/sudoers",      SOFT_MODE_DENY },
    { "/etc/ssh/ssh_host_rsa_key",   SOFT_MODE_DENY },
    { "/etc/ssh/ssh_host_ecdsa_key", SOFT_MODE_DENY },
    { "/etc/ssh/ssh_host_ed25519_key", SOFT_MODE_DENY },
    { "/run/user",         SOFT_MODE_DENY },
};

#define NUM_BUILTIN_DENY_RULES (sizeof(BUILTIN_DENY_RULES) / sizeof(BUILTIN_DENY_RULES[0]))

uint32_t soft_mode_to_access_mask(soft_mode_t mode) {
    switch (mode) {
        case SOFT_MODE_DENY:
            return 0;
        case SOFT_MODE_RO:
            return SOFT_ACCESS_READ;
        case SOFT_MODE_RX:
            return SOFT_ACCESS_READ | SOFT_ACCESS_EXEC;
        case SOFT_MODE_RW:
            return SOFT_ACCESS_READ | SOFT_ACCESS_WRITE |
                   SOFT_ACCESS_MKDIR | SOFT_ACCESS_RMDIR |
                   SOFT_ACCESS_UNLINK | SOFT_ACCESS_RENAME |
                   SOFT_ACCESS_CHMOD | SOFT_ACCESS_CHOWN |
                   SOFT_ACCESS_TRUNCATE;
        case SOFT_MODE_RWX:
            return SOFT_ACCESS_READ | SOFT_ACCESS_WRITE | SOFT_ACCESS_EXEC |
                   SOFT_ACCESS_MKDIR | SOFT_ACCESS_RMDIR |
                   SOFT_ACCESS_UNLINK | SOFT_ACCESS_RENAME |
                   SOFT_ACCESS_CHMOD | SOFT_ACCESS_CHOWN |
                   SOFT_ACCESS_TRUNCATE | SOFT_ACCESS_SYMLINK | SOFT_ACCESS_LINK;
        default:
            return 0;
    }
}

soft_mode_t soft_parse_mode(const char *mode_str) {
    if (!mode_str) return SOFT_MODE_RO;

    if (strcmp(mode_str, "deny") == 0) return SOFT_MODE_DENY;
    if (strcmp(mode_str, "ro") == 0) return SOFT_MODE_RO;
    if (strcmp(mode_str, "rx") == 0) return SOFT_MODE_RX;
    if (strcmp(mode_str, "rw") == 0) return SOFT_MODE_RW;
    if (strcmp(mode_str, "rwx") == 0) return SOFT_MODE_RWX;

    return SOFT_MODE_RO;
}

void soft_policy_init(soft_policy_t *policy) {
    if (!policy) return;
    policy->rules = NULL;
    policy->count = 0;
    policy->capacity = 0;
    policy->default_mode = SOFT_MODE_DENY;
}

static void soft_policy_add_current_user_rules(soft_policy_t *policy) {
    if (!policy) return;

    const char *orig_uid_env = getenv("READONLYBOX_ORIGINAL_UID");
    uid_t uid;
    if (orig_uid_env) {
        uid = (uid_t)atoi(orig_uid_env);
    } else {
        uid = getuid();
    }

    if (uid == 0) return;

    const char *user = getenv("USER");
    if (!user) {
        struct passwd *pw = getpwuid(uid);
        user = pw ? pw->pw_name : NULL;
    }
    if (!user) return;

    char path[PATH_MAX];

    snprintf(path, sizeof(path), "/home/%s", user);
    soft_policy_add_rule(policy, path, SOFT_MODE_RWX);

    snprintf(path, sizeof(path), "/run/user/%d", uid);
    soft_policy_add_rule(policy, path, SOFT_MODE_RW);

    snprintf(path, sizeof(path), "/var/spool/mail/%s", user);
    soft_policy_add_rule(policy, path, SOFT_MODE_RW);

    snprintf(path, sizeof(path), "/var/spool/cron/crontabs/%s", user);
    soft_policy_add_rule(policy, path, SOFT_MODE_RW);

    snprintf(path, sizeof(path), "/var/lib/AccountsService/users/%s", user);
    soft_policy_add_rule(policy, path, SOFT_MODE_RO);
}

void soft_policy_load_builtin(soft_policy_t *policy) {
    if (!policy) return;

    for (size_t i = 0; i < NUM_BUILTIN_ALLOW_RULES; i++) {
        soft_policy_add_rule(policy, BUILTIN_ALLOW_RULES[i].path, BUILTIN_ALLOW_RULES[i].mode);
    }

    for (size_t i = 0; i < NUM_BUILTIN_DENY_RULES; i++) {
        soft_policy_add_rule(policy, BUILTIN_DENY_RULES[i].path, BUILTIN_DENY_RULES[i].mode);
    }

    soft_policy_add_current_user_rules(policy);
}

static int soft_policy_grow(soft_policy_t *policy) {
    if (!policy) return -1;
    if (policy->count < policy->capacity) return 0;
    if (policy->capacity >= MAX_SOFT_RULES) return -1;

    int new_capacity = policy->capacity == 0 ? 8 : policy->capacity * 2;
    if (new_capacity > MAX_SOFT_RULES) {
        new_capacity = MAX_SOFT_RULES;
    }

    soft_rule_t *new_rules = realloc(policy->rules, new_capacity * sizeof(soft_rule_t));
    if (!new_rules) {
        LOG_ERROR("Failed to allocate soft policy rules");
        return -1;
    }

    policy->rules = new_rules;
    policy->capacity = new_capacity;
    return 0;
}

int soft_policy_add_rule(soft_policy_t *policy, const char *path, soft_mode_t mode) {
    if (!policy || !path || path[0] == '\0') return -1;
    if (strlen(path) > PATH_MAX) {
        LOG_ERROR("Path too long (>%d bytes)", PATH_MAX);
        return -1;
    }
    if (path[0] != '/') {
        LOG_ERROR("Soft policy path '%s' is not absolute; ignoring", path);
        return -1;
    }

    char *path_copy = strdup(path);
    if (!path_copy) {
        LOG_ERROR("Failed to allocate path string");
        return -1;
    }

    if (soft_policy_grow(policy) != 0) {
        free(path_copy);
        return -1;
    }
    if (policy->count >= MAX_SOFT_RULES) {
        LOG_ERROR("Maximum soft policy rules (%d) exceeded", MAX_SOFT_RULES);
        free(path_copy);
        return -1;
    }

    size_t len = strlen(path_copy);
    while (len > 1 && path_copy[len - 1] == '/') {
        path_copy[--len] = '\0';
    }

    policy->rules[policy->count].path = path_copy;
    policy->rules[policy->count].mode = mode;
    policy->count++;

    DEBUG_PRINT("SOFT_POLICY: Added rule mode=%d '%s'\n", mode, path_copy);

    return 0;
}

int soft_policy_prepend_rule(soft_policy_t *policy, const char *path, soft_mode_t mode) {
    if (!policy || !path || path[0] == '\0') return -1;
    if (strlen(path) > PATH_MAX) {
        LOG_ERROR("Path too long (>%d bytes)", PATH_MAX);
        return -1;
    }
    if (path[0] != '/') {
        LOG_ERROR("Soft policy path '%s' is not absolute; ignoring", path);
        return -1;
    }

    char *path_copy = strdup(path);
    if (!path_copy) {
        LOG_ERROR("Failed to allocate path string");
        return -1;
    }

    if (soft_policy_grow(policy) != 0) {
        free(path_copy);
        return -1;
    }
    if (policy->count >= MAX_SOFT_RULES) {
        LOG_ERROR("Maximum soft policy rules (%d) exceeded", MAX_SOFT_RULES);
        free(path_copy);
        return -1;
    }

    size_t len = strlen(path_copy);
    while (len > 1 && path_copy[len - 1] == '/') {
        path_copy[--len] = '\0';
    }

    memmove(&policy->rules[1], &policy->rules[0], policy->count * sizeof(soft_rule_t));
    policy->rules[0].path = path_copy;
    policy->rules[0].mode = mode;
    policy->count++;

    DEBUG_PRINT("SOFT_POLICY: Prepended rule mode=%d '%s'\n", mode, path_copy);

    return 0;
}

void soft_policy_free(soft_policy_t *policy) {
    if (!policy) return;
    if (policy == &g_soft_policy) return;

    for (int i = 0; i < policy->count; i++) {
        free(policy->rules[i].path);
    }
    free(policy->rules);
    policy->rules = NULL;
    policy->count = 0;
    policy->capacity = 0;
}

void soft_policy_clear(soft_policy_t *policy) {
    if (!policy) return;
    if (policy == &g_soft_policy) return;
    for (int i = 0; i < policy->count; i++) {
        free(policy->rules[i].path);
    }
    free(policy->rules);
    policy->rules = NULL;
    policy->count = 0;
    policy->capacity = 0;
}

static int path_matches(const char *rule_path, const char *target_path) {
    if (!rule_path || !target_path) return 0;

    size_t rule_len = strlen(rule_path);
    size_t target_len = strlen(target_path);

    if (rule_len > target_len) return 0;

    if (rule_len == 1 && rule_path[0] == '/') {
        return 1;
    }

    if (strncmp(rule_path, target_path, rule_len) != 0) return 0;

    if (rule_len == target_len) return 1;

    if (target_path[rule_len] == '/') return 1;

    if (target_path[rule_len] == '\0') return 1;

    return 0;
}

int soft_policy_check(const soft_policy_t *policy, const soft_path_mode_t *inputs, int *results, int count) {
    if (!policy || !inputs || !results) return -1;
    if (count > MAX_SOFT_RULES) return -1;

    for (int i = 0; i < count; i++) {
        const char *path = inputs[i].path;
        uint32_t access_mask = inputs[i].access_mask;

        if (!path) {
            results[i] = 0;
            continue;
        }

        ssize_t best_match_len = -1;
        uint32_t allowed_access = soft_mode_to_access_mask(policy->default_mode);

        for (int j = 0; j < policy->count; j++) {
            if (path_matches(policy->rules[j].path, path)) {
                size_t match_len = strlen(policy->rules[j].path);
                if ((ssize_t)match_len >= best_match_len) {
                    best_match_len = (ssize_t)match_len;
                    allowed_access = soft_mode_to_access_mask(policy->rules[j].mode);
                }
            }
        }

        if (allowed_access == 0) {
            results[i] = 0;
        } else {
            results[i] = (allowed_access & access_mask) == access_mask ? 1 : 0;
        }

        DEBUG_PRINT("SOFT_POLICY: path='%s' access=0x%x allowed=0x%x -> %s\n",
                    path, access_mask, allowed_access, results[i] ? "ALLOWED" : "DENIED");
    }

    return 0;
}

void soft_policy_set_default(soft_policy_t *policy, soft_mode_t mode) {
    if (policy) {
        policy->default_mode = mode;
    }
}

bool soft_policy_is_active(const soft_policy_t *policy) {
    return policy && policy->count > 0;
}

int soft_policy_load_from_env(soft_policy_t *policy) {
    if (!policy) return -1;

    if (policy == &g_soft_policy) {
        for (int i = 0; i < policy->count; i++) {
            free(policy->rules[i].path);
        }
        free(policy->rules);
        policy->rules = NULL;
        policy->count = 0;
        policy->capacity = 0;
    } else {
        soft_policy_clear(policy);
    }

    const char *allow_env = getenv("READONLYBOX_SOFT_ALLOW");
    const char *deny_env = getenv("READONLYBOX_SOFT_DENY");

    if ((!allow_env || !*allow_env) && (!deny_env || !*deny_env)) {
        DEBUG_PRINT("SOFT_POLICY: No soft policy rules in environment\n");
        return 0;
    }

    char *env_copy = NULL;
    int result = 0;

    if (allow_env && *allow_env) {
        env_copy = strdup(allow_env);
        if (!env_copy) {
            result = -1;
            goto cleanup;
        }

        char *saveptr = NULL;
        char *token = strtok_r(env_copy, ",", &saveptr);
        while (token) {
            while (*token == ' ' || *token == '\t') token++;

            size_t len = strlen(token);
            while (len > 0 && (token[len - 1] == ' ' || token[len - 1] == '\t')) {
                len--;
                token[len] = '\0';
            }

            if (len > 0) {
                soft_mode_t mode = SOFT_MODE_RO;

                char *colon = strchr(token, ':');
                if (colon) {
                    *colon = '\0';
                    const char *mode_str = colon + 1;
                    mode = soft_parse_mode(mode_str);
                }

                if (soft_policy_add_rule(policy, token, mode) != 0) {
                    result = -1;
                    goto cleanup;
                }
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
        free(env_copy);
        env_copy = NULL;
    }

    if (deny_env && *deny_env) {
        env_copy = strdup(deny_env);
        if (!env_copy) {
            result = -1;
            goto cleanup;
        }

        char *saveptr = NULL;
        char *token = strtok_r(env_copy, ",", &saveptr);
        while (token) {
            while (*token == ' ' || *token == '\t') token++;

            size_t len = strlen(token);
            while (len > 0 && (token[len - 1] == ' ' || token[len - 1] == '\t')) {
                len--;
                token[len] = '\0';
            }

            if (len > 0) {
                if (soft_policy_add_rule(policy, token, SOFT_MODE_DENY) != 0) {
                    result = -1;
                    goto cleanup;
                }
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
        free(env_copy);
        env_copy = NULL;
    }

cleanup:
    if (result != 0) {
        soft_policy_clear(policy);
    }
    return result;
}

static int soft_policy_count_env_entries(const char *env_value) {
    if (!env_value || !*env_value) return 0;

    int count = 0;
    char *copy = strdup(env_value);
    if (!copy) return -1;

    char *saveptr = NULL;
    char *token = strtok_r(copy, ",", &saveptr);
    while (token) {
        while (*token == ' ' || *token == '\t') token++;

        size_t len = strlen(token);
        while (len > 0 && (token[len - 1] == ' ' || token[len - 1] == '\t')) {
            len--;
            token[len] = '\0';
        }

        if (len > 0) {
            count++;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    free(copy);
    return count;
}

static int soft_policy_validate_path(const char *path) {
    if (!path || path[0] == '\0') return -1;
    if (path[0] != '/') return -1;
    return 0;
}

int soft_policy_validate_from_env(void) {
    const char *allow_env = getenv("READONLYBOX_SOFT_ALLOW");
    const char *deny_env = getenv("READONLYBOX_SOFT_DENY");

    if ((!allow_env || !*allow_env) && (!deny_env || !*deny_env)) {
        return 0;
    }

    int allow_count = 0;
    int deny_count = 0;

    if (allow_env && *allow_env) {
        allow_count = soft_policy_count_env_entries(allow_env);
        if (allow_count < 0) return -1;

        char *env_copy = strdup(allow_env);
        if (!env_copy) return -1;

        char *saveptr = NULL;
        char *token = strtok_r(env_copy, ",", &saveptr);
        while (token) {
            while (*token == ' ' || *token == '\t') token++;

            size_t len = strlen(token);
            while (len > 0 && (token[len - 1] == ' ' || token[len - 1] == '\t')) {
                len--;
                token[len] = '\0';
            }

            if (len > 0) {
                char *colon = strchr(token, ':');
                if (colon) {
                    *colon = '\0';
                }
                if (soft_policy_validate_path(token) != 0) {
                    LOG_ERROR("Invalid soft policy path: '%s'", token);
                    free(env_copy);
                    return -1;
                }
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
        free(env_copy);
    }

    if (deny_env && *deny_env) {
        deny_count = soft_policy_count_env_entries(deny_env);
        if (deny_count < 0) return -1;

        char *env_copy = strdup(deny_env);
        if (!env_copy) return -1;

        char *saveptr = NULL;
        char *token = strtok_r(env_copy, ",", &saveptr);
        while (token) {
            while (*token == ' ' || *token == '\t') token++;

            size_t len = strlen(token);
            while (len > 0 && (token[len - 1] == ' ' || token[len - 1] == '\t')) {
                len--;
                token[len] = '\0';
            }

            if (len > 0) {
                if (soft_policy_validate_path(token) != 0) {
                    LOG_ERROR("Invalid soft policy path: '%s'", token);
                    free(env_copy);
                    return -1;
                }
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
        free(env_copy);
    }

    if (allow_count + deny_count > MAX_SOFT_RULES) {
        LOG_ERROR("Too many soft policy rules (%d + %d > %d)", allow_count, deny_count, MAX_SOFT_RULES);
        return -1;
    }

    return 0;
}

soft_policy_t *soft_policy_get_global(void) {
    return &g_soft_policy;
}
