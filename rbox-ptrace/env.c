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
#define MAX_FLAGGED_ENVS 1024
static FlaggedEnv g_flagged_envs[MAX_FLAGGED_ENVS];
static int g_flagged_env_count = 0;

/* Get flagged env count for external use */
int env_get_flagged_count(void) {
    return g_flagged_env_count;
}

/* Get flagged env name by index */
const char *env_get_flagged_name(int idx) {
    if (idx >= 0 && idx < g_flagged_env_count && idx < MAX_FLAGGED_ENVS) {
        return g_flagged_envs[idx].name;
    }
    return NULL;
}

/* Get flagged env score by index */
double env_get_flagged_score(int idx) {
    if (idx >= 0 && idx < g_flagged_env_count && idx < MAX_FLAGGED_ENVS) {
        return g_flagged_envs[idx].score;
    }
    return 0.0;
}

/* Clear all flagged envs */
void env_clear_flagged(void) {
    for (int i = 0; i < g_flagged_env_count && i < MAX_FLAGGED_ENVS; i++) {
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
        snprintf(name, name_size, "%.*s", (int)len, entry);
    } else {
        name[0] = '\0';
    }
}

/* Helper to extract value from environ entry */
static const char *extract_env_value(const char *entry) {
    const char *eq = strchr(entry, '=');
    return eq ? eq + 1 : "";
}

/* Helper to add a variable to the unset list with dynamic growth.
 * Returns 0 on success, -1 on allocation failure. */
static int add_to_unset(char ***unset_vars, int *unset_count, int *unset_capacity, const char *name) {
    if (*unset_count >= *unset_capacity) {
        int new_capacity = *unset_capacity ? *unset_capacity * 2 : 16;
        char **new_unset = realloc(*unset_vars, new_capacity * sizeof(char *));
        if (!new_unset) {
            return -1;
        }
        *unset_capacity = new_capacity;
        *unset_vars = new_unset;
    }

    (*unset_vars)[*unset_count] = strdup(name);
    if (!(*unset_vars)[*unset_count]) {
        return -1;
    }
    (*unset_count)++;
    return 0;
}

/* Free the unset list */
static void free_unset_list(char **unset_vars, int unset_count) {
    for (int i = 0; i < unset_count; i++) {
        free(unset_vars[i]);
    }
    free(unset_vars);
}

/* Screen environment using shellsplit module - ptrace client handles prompting.
 * Returns 0 on success, -1 on error (memory allocation failure). */
int env_screen(void) {
    /* Check if stdin is a terminal - if not, auto-block high-confidence vars */
    int is_terminal = isatty(STDIN_FILENO);

    /* Dynamically grow indices buffer until we have enough space */
    int indices_capacity = 32;
    int *indices = malloc(indices_capacity * sizeof(int));
    if (!indices) {
        return -1;
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
            return -1;
        }
        indices = larger;
        indices_capacity = flagged_count;
    }

    if (status != ENV_SCREENER_OK || flagged_count == 0) {
        free(indices);
        return 0;
    }

    /* Reset the flagged env names list - we'll add only allowed vars */
    for (int i = 0; i < g_flagged_env_count; i++) {
        if (g_flagged_envs[i].name) {
            free(g_flagged_envs[i].name);
            g_flagged_envs[i].name = NULL;
        }
    }
    g_flagged_env_count = 0;

    /* Collect variables to unset AFTER processing (to avoid environ reallocation issues) */
    char **unset_vars = NULL;
    int unset_capacity = 0;
    int unset_count = 0;

    /* Prompt user for each flagged variable and only add allowed ones */
    int capacity_hit = 0;
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
        if (g_flagged_env_count >= MAX_FLAGGED_ENVS) {
            /* No more room - mark for unsetting and stop processing */
            capacity_hit = 1;
            break;
        }

        if (!is_terminal) {
            /* Non-interactive mode: auto-block high-confidence, allow others */
            if (score > 0.8) {
                if (add_to_unset(&unset_vars, &unset_count, &unset_capacity, name) < 0) {
                    free_unset_list(unset_vars, unset_count);
                    free(indices);
                    return -1;
                }
                fprintf(stderr, "   → Auto-blocked (non-interactive): %s\n", name);
            } else {
                /* Allow low-confidence vars by adding to list */
                char *dup = strdup(name);
                if (!dup) {
                    if (add_to_unset(&unset_vars, &unset_count, &unset_capacity, name) < 0) {
                        free_unset_list(unset_vars, unset_count);
                        free(indices);
                        return -1;
                    }
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
                if (add_to_unset(&unset_vars, &unset_count, &unset_capacity, name) < 0) {
                    free(line);
                    free_unset_list(unset_vars, unset_count);
                    free(indices);
                    return -1;
                }
                fprintf(stderr, "   → Blocked (memory allocation failed): %s\n", name);
            } else {
                g_flagged_envs[g_flagged_env_count].name = dup;
                g_flagged_envs[g_flagged_env_count].score = score;
                g_flagged_env_count++;
            }
        } else {
            /* User blocked this variable or invalid input */
            if (add_to_unset(&unset_vars, &unset_count, &unset_capacity, name) < 0) {
                free(line);
                free_unset_list(unset_vars, unset_count);
                free(indices);
                return -1;
            }
            fprintf(stderr, "   → Blocked: %s\n", name);
        }
        free(line);
    }

    /* If capacity was reached, mark all remaining flagged vars for unsetting */
    if (capacity_hit && flagged_count > MAX_FLAGGED_ENVS) {
        int remaining = flagged_count - MAX_FLAGGED_ENVS;
        fprintf(stderr, "   → Auto-blocked %d more env vars (capacity %d reached)\n",
                remaining, MAX_FLAGGED_ENVS);
        for (int i = MAX_FLAGGED_ENVS; i < flagged_count; i++) {
            if (indices[i] < 0) continue;
            extern char **environ;
            char *entry = environ[indices[i]];
            if (!entry) continue;
            char name[256];
            extract_env_name(entry, name, sizeof(name));
            if (add_to_unset(&unset_vars, &unset_count, &unset_capacity, name) < 0) {
                free_unset_list(unset_vars, unset_count);
                free(indices);
                return -1;
            }
        }
    }

    /* Now unset all blocked variables (after processing to avoid environ reallocation) */
    for (int i = 0; i < unset_count; i++) {
        if (unset_vars[i]) {
            unsetenv(unset_vars[i]);
            free(unset_vars[i]);
        }
    }
    free(unset_vars);

    free(indices);
    fprintf(stderr, "\n✓ Environment screened\n");
    return 0;
}
