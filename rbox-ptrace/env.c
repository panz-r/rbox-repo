/*
 * env.c - Environment screening for readonlybox-ptrace
 *
 * Screens environment variables for secrets before passing to commands.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include "env.h"
#include "env_screener.h"

/* Structure to hold flagged environment variable with its score */
typedef struct {
    char *name;
    double score;
} FlaggedEnv;

/* Global storage for flagged env vars with scores (used by run_judge) */
static FlaggedEnv g_flagged_envs[256];
static int g_flagged_env_count = 0;

/* Get flagged env count for external use */
int env_get_flagged_count(void) {
    return g_flagged_env_count;
}

/* Get flagged env name by index */
const char *env_get_flagged_name(int idx) {
    if (idx >= 0 && idx < g_flagged_env_count && idx < 256) {
        return g_flagged_envs[idx].name;
    }
    return NULL;
}

/* Get flagged env score by index */
double env_get_flagged_score(int idx) {
    if (idx >= 0 && idx < g_flagged_env_count && idx < 256) {
        return g_flagged_envs[idx].score;
    }
    return 0.0;
}

/* Clear all flagged envs */
void env_clear_flagged(void) {
    for (int i = 0; i < g_flagged_env_count && i < 256; i++) {
        if (g_flagged_envs[i].name) {
            free(g_flagged_envs[i].name);
            g_flagged_envs[i].name = NULL;
        }
    }
    g_flagged_env_count = 0;
}

/* Helper to extract name from environ entry */
static void extract_env_name(const char *entry, char *name, size_t name_size) {
    const char *eq = strchr(entry, '=');
    if (eq) {
        size_t len = eq - entry;
        if (len >= name_size) len = name_size - 1;
        strncpy(name, entry, len);
        name[len] = '\0';
    } else {
        name[0] = '\0';
    }
}

/* Helper to extract value from environ entry */
static const char *extract_env_value(const char *entry) {
    const char *eq = strchr(entry, '=');
    return eq ? eq + 1 : "";
}

/* Screen environment using shellsplit module - ptrace client handles prompting */
void env_screen(void) {
    /* Check if stdin is a terminal - if not, auto-block high-confidence vars */
    int is_terminal = isatty(STDIN_FILENO);

    /* Dynamically grow indices buffer until we have enough space */
    int indices_capacity = 32;
    int *indices = malloc(indices_capacity * sizeof(int));
    if (!indices) {
        return;  /* Memory allocation failed - skip screening */
    }
    int flagged_count = 0;

    env_screener_status_t status;
    while ((status = env_screener_scan(
            indices,
            indices_capacity,
            &flagged_count,
            0.7,   /* posterior_threshold - 0.7 for high confidence */
            12     /* min_length */
            )) == ENV_SCREENER_BUFFER_TOO_SMALL) {
        /* Buffer too small - grow it */
        int *larger = realloc(indices, flagged_count * sizeof(int));
        if (!larger) {
            free(indices);
            return;  /* Memory allocation failed */
        }
        indices = larger;
        indices_capacity = flagged_count;
    }

    if (status != ENV_SCREENER_OK || flagged_count == 0) {
        free(indices);
        return;
    }

    /* Reset the flagged env names list - we'll add only allowed vars */
    for (int i = 0; i < g_flagged_env_count; i++) {
        if (g_flagged_envs[i].name) {
            free(g_flagged_envs[i].name);
            g_flagged_envs[i].name = NULL;
        }
    }
    g_flagged_env_count = 0;

    /* Prompt user for each flagged variable and only add allowed ones */
    for (int i = 0; i < flagged_count; i++) {
        extern char **environ;
        if (indices[i] < 0) continue;
        char *entry = environ[indices[i]];
        if (!entry) continue;

        char name[256];
        const char *value = extract_env_value(entry);
        extract_env_name(entry, name, sizeof(name));

        double score = env_screener_combined_score_name(name, value);

        /* Check if we have room for more flagged envs */
        if (g_flagged_env_count >= 256) {
            /* No more room - unset to block this var */
            unsetenv(name);
            fprintf(stderr, "   → Auto-blocked (capacity): %s\n", name);
            continue;
        }

        if (!is_terminal) {
            /* Non-interactive mode: auto-block high-confidence, allow others */
            if (score > 0.8) {
                fprintf(stderr, "   → Auto-blocked (non-interactive): %s\n", name);
            } else {
                /* Allow low-confidence vars by adding to list */
                char *dup = strdup(name);
                if (!dup) {
                    fprintf(stderr, "   → Auto-blocked (memory allocation failed): %s\n", name);
                    continue;
                }
                g_flagged_envs[g_flagged_env_count].name = dup;
                g_flagged_envs[g_flagged_env_count].score = score;
                g_flagged_env_count++;
            }
            continue;
        }

        /* Interactive mode - prompt user */
        if (score > 0.8) {
            fprintf(stderr, "\n⚠️  High-confidence secret detected:\n");
            fprintf(stderr, "   %s=*** (score: %.2f)\n", name, score);
        } else {
            fprintf(stderr, "\n⚠️  Potential secret detected:\n");
            fprintf(stderr, "   %s=*** (score: %.2f)\n", name, score);
        }

        fprintf(stderr, "   Pass this variable to the command? [y/N]: ");

        /* Read full line to avoid stdin residue issues */
        char *line = NULL;
        size_t line_cap = 0;
        ssize_t line_len = getline(&line, &line_cap, stdin);
        if (line_len > 0 && (line[0] == 'y' || line[0] == 'Y')) {
            /* User allowed this variable */
            char *dup = strdup(name);
            if (!dup) {
                fprintf(stderr, "   → Blocked (memory allocation failed): %s\n", name);
                unsetenv(name);
            } else {
                g_flagged_envs[g_flagged_env_count].name = dup;
                g_flagged_envs[g_flagged_env_count].score = score;
                g_flagged_env_count++;
            }
        } else {
            /* User blocked this variable or invalid input */
            unsetenv(name);
            fprintf(stderr, "   → Blocked: %s\n", name);
        }
        free(line);
    }

    free(indices);
    fprintf(stderr, "\n✓ Environment screened\n");
}
