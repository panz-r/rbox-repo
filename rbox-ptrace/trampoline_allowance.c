#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include "trampoline_allowance.h"
#include "shell_tokenizer.h"
#include "debug.h"

/*
 * Trampoline Allowance Implementation
 *
 * This module implements a hierarchical command allowance system where:
 * - GRANT parses commands recursively, extracting chains and subcommands
 * - Each allowance entry has a constraint (.after) specifying required predecessor
 * - CONSUME validates both argv match AND constraint satisfaction
 *
 * Vector layout: entries are stored in order of discovery
 * - When a chain is found, it is stored first, then we recurse on continuation
 * - Subcommands discovered via shell_parse_fast are stored after chain
 * - The .after field links subcommands to their containing chain
 */

typedef bool (*ContinuationExtractFunc)(char * restrict cmd);

static bool extract_timeout(char *cmd) {
    if (!cmd || *cmd == '\0') return false;
    while (*cmd == ' ' || *cmd == '\t') cmd++;
    if (*cmd == '-') {
        while (*cmd && !isspace((unsigned char)*cmd)) cmd++;
        while (*cmd && isspace((unsigned char)*cmd)) cmd++;
    }
    if (*cmd == '\0') return false;
    if (!isdigit((unsigned char)*cmd)) return false;
    char *after_digits = cmd;
    while (*after_digits && isdigit((unsigned char)*after_digits)) after_digits++;
    while (*after_digits && isspace((unsigned char)*after_digits)) after_digits++;
    if (*after_digits == '\0') return false;
    memmove(cmd, after_digits, strlen(after_digits) + 1);
    return true;
}

static bool extract_sh_c(char *cmd) {
    if (!cmd || *cmd == '\0') return false;
    while (*cmd == ' ' || *cmd == '\t') cmd++;
    if (*cmd == '\0') return false;
    char quote = *cmd;
    if (quote != '\'' && quote != '"') return false;
    char *p = cmd + 1;
    while (*p != quote && *p != '\0') p++;
    if (*p != quote) return false;
    size_t content_len = p - cmd - 1;
    memmove(cmd, cmd + 1, content_len);
    cmd[content_len] = '\0';
    return true;
}

static bool extract_nice(char *cmd) {
    if (!cmd || *cmd == '\0') return false;
    while (*cmd == ' ' || *cmd == '\t') cmd++;
    if (*cmd == '\0') return false;

    char *cmd_start = cmd;

    if (*cmd == '-') {
        while (*cmd == '-') {
            char *opt_start = cmd;
            while (*cmd && !isspace((unsigned char)*cmd) && *cmd != '=') cmd++;
            if (*cmd == '=') {
                cmd++;
                while (*cmd && !isspace((unsigned char)*cmd)) cmd++;
                while (*cmd && isspace((unsigned char)*cmd)) cmd++;
                continue;
            }
            if (opt_start[1] == 'i' || (opt_start[1] == '-' && cmd - opt_start == 2)) {
                while (*cmd && isspace((unsigned char)*cmd)) cmd++;
                continue;
            }
            if (cmd - opt_start == 2 && (opt_start[1] == 'n' || opt_start[1] == 'p')) {
                while (*cmd && isspace((unsigned char)*cmd)) cmd++;
                while (*cmd && isdigit((unsigned char)*cmd)) cmd++;
                while (*cmd && isspace((unsigned char)*cmd)) cmd++;
                continue;
            }
            return false;
        }
    }

    if (*cmd == '\0') return false;

    if (*cmd == '\'' || *cmd == '"') {
        char quote = *cmd++;
        char *start = cmd;
        char *p = cmd;
        while (*p && *p != quote) p++;
        if (*p != quote) return false;
        size_t len = p - start;
        memmove(cmd_start, start, len);
        cmd_start[len] = '\0';
        return true;
    }

    if (cmd != cmd_start) {
        char *p = cmd;
        char *dst = cmd_start;
        while (*p) *dst++ = *p++;
        *dst = '\0';
    }
    return true;
}

static const struct {
    const char *name;
    ContinuationExtractFunc extract;
} CHAIN_SPECS[] = {
    {"sh -c",    extract_sh_c},
    {"timeout",  extract_timeout},
    {"nice",     extract_nice},
    {NULL, NULL}
};

/*
 * Get command continuation after splitting a chain.
 * Returns pointer to continuation in dst, or NULL if no chain found.
 * The returned pointer is within dst buffer.
 */
const char *get_command_continuation(const char *full_cmd,
                                                  char *dst, size_t dst_size) {
    errno = 0;
    if (!full_cmd || !dst || dst_size < 2) {
        errno = EINVAL;
        return NULL;
    }
    size_t len = strlen(full_cmd);
    if (len + 1 > dst_size) {
        errno = ERANGE;
        return NULL;
    }
    memcpy(dst, full_cmd, len + 1);
    for (int i = 0; CHAIN_SPECS[i].name; i++) {
        const char *wname = CHAIN_SPECS[i].name;
        size_t wlen = strlen(wname);
        if (strncmp(dst, wname, wlen) != 0) continue;
        char *after = dst + wlen;
        if (*after != ' ' && *after != '\t' && *after != '\0') continue;
        while (*after == ' ' || *after == '\t') after++;
        if (CHAIN_SPECS[i].extract(after)) return after;
    }
    return NULL;
}

/*
 * Quote-aware argv vs string comparison.
 * Returns 1 if full match, 0 if no match.
 */
static int argv_matches_string(const char *const argv[], const char *str) {
    if (!argv || !argv[0] || !str) return 0;

    int argi = 0;
    const char *p = str;

    while (*p) {
        if (*p == ' ' || *p == '\t') {
            p++;
            continue;
        }

        if (*p == '\'' || *p == '"') {
            char quote = *p++;
            const char *start = p;
            while (*p && *p != quote) p++;
            if (*p == quote) p++;

            if (argi >= 0 && argv[argi]) {
                if (strncmp(start, argv[argi], p - start - 1) != 0 || argv[argi][p - start - 1] != '\0') {
                    return 0;
                }
                argi++;
            } else {
                return 0;
            }
            continue;
        }

        if (isspace((unsigned char)*p)) {
            if (argi == 0) return 0;
            argi++;
            p++;
            continue;
        }

        int si = 0;
        while (p[si] && p[si] != ' ' && p[si] != '\t' && p[si] != '\'' && p[si] != '"') {
            if (p[si] == '\\' && p[si+1]) {
                si += 2;
                continue;
            }
            si++;
        }

        if (argi >= 0 && argv[argi]) {
            if (strncmp(p, argv[argi], si) != 0 || argv[argi][si] != '\0') {
                return 0;
            }
            argi++;
        } else {
            return 0;
        }

        p += si;
    }

    if (argv[argi] && argv[argi+1]) return 0;

    return 1;
}

/* ----------------------------------------------------------------------
 * Public API
 */

void allowset_init(AllowSet *a) {
    if (!a) return;
    memset(a, 0, sizeof(*a));
    a->vecv = calloc(7, sizeof(struct Allowance));
    a->vecc = 0;
    a->veca = 7;
}

void allowset_deinit(AllowSet *a) {
    if (!a) return;
    for (int i = 0; i < a->vecc; i++) {
        free(a->vecv[i].command);
        a->vecv[i].command = NULL;
        a->vecv[i].after = -1;
    }
    free(a->vecv);
    a->vecv = NULL;
    a->vecc = 0;
}

/* Strip outer quotes from a string if present */
static void strip_outer_quotes(char *str) {
    size_t len = strlen(str);
    if (len >= 2 && ((str[0] == '"' && str[len-1] == '"') ||
                    (str[0] == '\'' && str[len-1] == '\''))) {
        memmove(str, str + 1, len - 2);
        str[len - 2] = '\0';
    }
}

/* Check if command contains quote characters */
static int cmd_has_quotes(const char *cmd) {
    if (!cmd) return 0;
    while (*cmd) {
        if (*cmd == '\'' || *cmd == '"') return 1;
        cmd++;
    }
    return 0;
}

/*
 * Recursively parse command, building allowance vector.
 * The after_index specifies which entry must be consumed before
 * entries discovered here can be consumed. -1 means no constraint.
 * Uses a->veca for capacity tracking (starts at 0, grows to 7, then doubles).
 * Returns 0 on success, negative on error.
 */
static int grant_parse_recursive(AllowSet *a, const char *cmd, int after_index, bool is_first_call) {
    if (!a || !cmd || !*cmd) return 0;

    if (a->vecc >= ALLOWSET_MAX_ENTRIES) {
        return ALLOWSET_ERR_TOOLARGE;
    }

    if (a->vecc >= a->veca) {
        if (a->veca == 0) {
            a->veca = 7;
        } else {
            int new_cap = a->veca * 2;
            if (new_cap > ALLOWSET_MAX_ENTRIES) {
                return ALLOWSET_ERR_TOOLARGE;
            }
            a->veca = new_cap;
        }

        struct Allowance *new_vecv = realloc(a->vecv, a->veca * sizeof(struct Allowance));
        if (!new_vecv) {
            return ALLOWSET_ERR_NOMEM;
        }
        a->vecv = new_vecv;
    }

    char buf[4096];
    const char *continuation = get_command_continuation(cmd, buf, sizeof(buf));

    if (continuation && *continuation) {
        char cont_buf[4096];
        const char *subContinuation = get_command_continuation(continuation, cont_buf, sizeof(cont_buf));
        if (subContinuation && *subContinuation) {
            int current_index = a->vecc;
            size_t cont_len = strlen(continuation);
            a->vecv[current_index].command = malloc(cont_len + 1);
            if (!a->vecv[current_index].command) {
                return ALLOWSET_ERR_NOMEM;
            }
            strlcpy(a->vecv[current_index].command, continuation, cont_len + 1);
            a->vecv[current_index].after = after_index;
            a->vecc++;
            int ret = grant_parse_recursive(a, continuation, current_index, false);
            if (ret < 0) return ret;
        } else {
            int ret = grant_parse_recursive(a, continuation, after_index, false);
            if (ret < 0) return ret;
        }
    } else if (!is_first_call) {
        int sub_after = after_index;
        shell_parse_result_t result;
        shell_error_t err = shell_parse_fast(cmd, strlen(cmd), &SHELL_LIMITS_DEFAULT, &result);
        if ((err == SHELL_OK || err == SHELL_ETRUNC) && result.count > 0) {
            for (int i = 0; i < (int)result.count && a->vecc < a->veca; i++) {
                uint32_t len;
                const char *sub = shell_get_subcommand(cmd, &result.cmds[i], &len);
                if (sub && len > 0) {
                    char *copy = strndup(sub, len);
                    if (copy) {
                        strip_outer_quotes(copy);
                        if (result.count == 1 && strcmp(copy, cmd) == 0 && cmd_has_quotes(cmd)) {
                            free(copy);
                            continue;
                        }
                        if (a->vecc >= a->veca) {
                            if (a->veca == 0) {
                                a->veca = 7;
                            } else {
                                int new_cap = a->veca * 2;
                                if (new_cap > ALLOWSET_MAX_ENTRIES) {
                                    free(copy);
                                    return ALLOWSET_ERR_TOOLARGE;
                                }
                                a->veca = new_cap;
                            }

                            struct Allowance *new_vecv = realloc(a->vecv, a->veca * sizeof(struct Allowance));
                            if (!new_vecv) {
                                free(copy);
                                return ALLOWSET_ERR_NOMEM;
                            }
                            a->vecv = new_vecv;
                        }
                        a->vecv[a->vecc].command = copy;
                        a->vecv[a->vecc].after = sub_after;
                        a->vecc++;
                    }
                }
            }
        }
    } else {
        shell_parse_result_t result;
        shell_error_t err = shell_parse_fast(cmd, strlen(cmd), &SHELL_LIMITS_DEFAULT, &result);
        if ((err == SHELL_OK || err == SHELL_ETRUNC) && result.count > 0) {
            for (int i = 0; i < (int)result.count && a->vecc < a->veca; i++) {
                uint32_t len;
                const char *sub = shell_get_subcommand(cmd, &result.cmds[i], &len);
                if (sub && len > 0) {
                    char *copy = strndup(sub, len);
                    if (copy) {
                        strip_outer_quotes(copy);
                        if (result.count == 1 && strcmp(copy, cmd) == 0 && cmd_has_quotes(cmd)) {
                            free(copy);
                            continue;
                        }
                        if (a->vecc >= a->veca) {
                            if (a->veca == 0) {
                                a->veca = 7;
                            } else {
                                int new_cap = a->veca * 2;
                                if (new_cap > ALLOWSET_MAX_ENTRIES) {
                                    free(copy);
                                    return ALLOWSET_ERR_TOOLARGE;
                                }
                                a->veca = new_cap;
                            }

                            struct Allowance *new_vecv = realloc(a->vecv, a->veca * sizeof(struct Allowance));
                            if (!new_vecv) {
                                free(copy);
                                return ALLOWSET_ERR_NOMEM;
                            }
                            a->vecv = new_vecv;
                        }
                        a->vecv[a->vecc].command = copy;
                        a->vecv[a->vecc].after = after_index;
                        a->vecc++;
                    }
                }
            }
        }
    }
    return 0;
}

int allowset_grant(AllowSet *a, const char *full_command) {
    if (!a || !full_command || !*full_command) return -1;

    int ret = grant_parse_recursive(a, full_command, -1, true);

    if (ret < 0) {
        allowset_deinit(a);
        allowset_init(a);
        return ret;
    }

    clock_gettime(CLOCK_MONOTONIC, &a->expiration);

    return 0;
}

/*
 * Consume an allowance entry matching argv.
 * Returns 1 if match found and constraint satisfied, 0 otherwise.
 *
 * Constraint semantics: if entry.after != -1, the entry at that index
 * must already be consumed (command set to NULL) before this entry
 * can be consumed.
 */
int allowset_consume_argv(AllowSet *a, const char *const argv[]) {
    if (!a || !argv || !argv[0]) return 0;

    for (int i = 0; i < a->vecc; i++) {
        if (!a->vecv[i].command) continue;  /* already consumed */

        if (!argv_matches_string(argv, a->vecv[i].command)) continue;

        /* Check constraint: if after != -1, predecessor must be consumed */
        if (a->vecv[i].after != -1) {
            int pred = a->vecv[i].after;
            /* Safety check - vecv is valid if non-NULL, after values are initialized */
            if (pred < 0 || pred >= a->vecc || a->vecv[pred].command != NULL) {
                /* Constraint violated - predecessor not consumed yet */
                return 0;
            }
        }

        /* Match found and constraint satisfied */
        free(a->vecv[i].command);
        a->vecv[i].command = NULL;
        return 1;
    }
    return 0;
}

int allowset_expire(AllowSet *a, const struct timespec *now) {
    if (!a || !now) return 0;

    double age = now->tv_sec - a->expiration.tv_sec;
    if (age > ALLOWANCE_TIMEOUT_SECONDS) {
        allowset_deinit(a);
        allowset_init(a);
        return 1;
    }
    return 0;
}
