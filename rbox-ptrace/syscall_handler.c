/*
 * syscall_handler.c - Execve syscall interception and handling
 */

#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <libgen.h>
#include <limits.h>

#include "syscall_handler.h"
#include "memory.h"
#include "validation.h"
#include "protocol.h"
#include "debug.h"
#include "judge.h"
#include "soft_policy.h"
#include <shell_tokenizer.h>

/* Forward declarations */
static int filter_env_decisions(ProcessState *state, pid_t pid, USER_REGS *regs);

/*
 * Wrapper specification with remainder extraction.
 * Each wrapper has a name and a function that extracts the remainder
 * (the command that will be executed after the wrapper).
 * Extractors receive a modifiable string and may modify it in place.
 */
typedef char* (*WrapperExtractFunc)(char *cmd);

/* Strip surrounding quotes from a string (modifies in place).
 * Handles both single quotes ('...') and double quotes ("...").
 * Returns pointer to the unquoted content (inside the original string).
 * If no surrounding quotes, returns original pointer. */
static char* strip_quotes(char *str) {
    if (!str) return NULL;
    char *end = str + strlen(str) - 1;
    if ((str[0] == '\'' && end[0] == '\'') ||
        (str[0] == '"' && end[0] == '"')) {
        /* Strip surrounding quotes by shifting content left */
        /* Move content bytes (end - str bytes from str+1) */
        memmove(str, str + 1, end - str);
        /* Null terminate after the last content character */
        str[end - str] = '\0';
    }
    return str;
}

/* Skip n tokens (words) and return pointer past them, or NULL if not enough tokens */
static char* skip_tokens(char *s, int n) {
    while (n > 0 && *s) {
        /* Skip current token (any non-whitespace) */
        while (*s && !isspace((unsigned char)*s)) s++;
        if (*s == '\0') return NULL;  /* reached end before n tokens */
        /* Skip whitespace to next token */
        while (*s && isspace((unsigned char)*s)) s++;
        n--;
    }
    return s;  /* points to start of next token or end */
}

/* Generic extractor: skip n tokens and return the rest */
static char* extract_skip_n(char *cmd, int tokens_to_skip) {
    char *p = skip_tokens(cmd, tokens_to_skip);
    if (!p || *p == '\0') return NULL;
    return p;
}

/* Extract remainder for "timeout": skip one token (the duration) and return the rest.
 * After wrapper name is stripped, cmd is "1 ls", so we skip 1 token to get "ls". */
static char* extract_timeout(char *cmd) {
    return extract_skip_n(cmd, 1);  /* skip duration, return remainder */
}

/* Extract remainder for "sh -c": return everything after "sh -c ", with quotes stripped.
 * For sh -c, the rest of the string IS the command to execute.
 * Note: after wrapper name matching, there may be leading whitespace before the argument. */
static char* extract_sh_c(char *cmd) {
    if (!cmd || *cmd == '\0') return NULL;
    while (*cmd == ' ' || *cmd == '\t') cmd++;
    return strip_quotes(cmd);
}

/* Extract remainder for wrappers that pass entire remainder through (nice, strace, env, etc.)
 * These wrappers parse their own arguments and pass the rest to the child. */
static char* extract_rest(char *cmd) {
    return cmd;  /* pass through unchanged */
}

/* Wrapper specifications - ordered by specificity (longer names first) */
static const struct {
    const char *name;
    WrapperExtractFunc extract;
} WRAPPER_SPECS[] = {
    /* "sh -c" must come before "sh" to match correctly */
    {"sh -c",    extract_sh_c},
    /* timeout takes one argument (duration) */
    {"timeout",  extract_timeout},
    /* These pass the entire remainder through to the child */
    {"nice",     extract_rest},     /* nice [-n level] <cmd> → child gets entire remainder */
    {"strace",   extract_rest},     /* strace <options> <cmd> → child gets entire remainder */
    {"env",      extract_rest},      /* env [VAR=value...] <cmd> → child gets entire remainder */
    {"time",     extract_rest},     /* time <cmd> → child gets entire remainder */
    {"xargs",    extract_rest},     /* xargs <cmd> → child gets entire remainder */
    {"setarch",  extract_rest},     /* setarch <arch> <cmd> → child gets entire remainder */
    {"chroot",   extract_rest},     /* chroot <dir> <cmd> → child gets entire remainder */
    {"envoy",    extract_rest},      /* envoy <cmd> → child gets entire remainder */
    {NULL, NULL}
};

/* Returns the number of characters consumed by the outermost wrapper
 * (including the wrapper name, its arguments, and any following whitespace),
 * or 0 if the string does not start with a known wrapper.
 * This operates entirely within the provided buffer - callers must ensure
 * the buffer is large enough. */
static size_t wrapper_prefix_len(char *cmd) {
    if (!cmd) return 0;

    for (int i = 0; WRAPPER_SPECS[i].name; i++) {
        const char *wrapper_name = WRAPPER_SPECS[i].name;
        size_t name_len = strlen(wrapper_name);
        if (strncmp(cmd, wrapper_name, name_len) != 0) continue;

        char *after_name = cmd + name_len;
        if (*after_name != ' ' && *after_name != '\t' && *after_name != '\0')
            continue;
        while (*after_name == ' ' || *after_name == '\t') after_name++;

        char *remainder = WRAPPER_SPECS[i].extract(after_name);
        if (remainder) {
            /* remainder points into cmd (the extractor works on the same buffer) */
            return (size_t)(remainder - cmd);
        }
    }
    return 0;
}

/* Helper to expire old allowance sets and clear empty ones from a given set */
static void expire_allowance_set(AllowanceSet *set) {
    if (!set || set->subcommand_count == 0) return;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    double age_seconds = (now.tv_sec - set->timestamp.tv_sec) +
                        (now.tv_nsec - set->timestamp.tv_nsec) / 1e9;
    if (age_seconds > ALLOWANCE_TIMEOUT_SECONDS) {
        DEBUG_PRINT("ALLOWANCE: expired allowance set for pid\n");
        for (int j = 0; j < set->subcommand_count; j++) {
            free(set->subcommands[j]);
            set->subcommands[j] = NULL;
        }
        set->subcommand_count = 0;
        memset(set->used_mask, 0, sizeof(set->used_mask));
    }
}

/* Check if all subcommands in a set have been used (via used_mask) */
static int is_set_fully_used(AllowanceSet *set) {
    if (set->subcommand_count == 0) return 0;
    for (int i = 0; i < set->subcommand_count; i++) {
        int word_idx = i / 32;
        int bit_idx = i % 32;
        if (!(set->used_mask[word_idx] & (1 << bit_idx))) {
            return 0;
        }
    }
    return 1;
}

/* Check if a process has a valid allowance for a specific subcommand.
 * Iterates through all allowance sets (inline + spillover). */
static int consume_allowance(ProcessState *state, const char *subcommand) {
    if (!state) return 0;

    /* Check inline sets */
    for (int i = 0; i < INLINE_ALLOWANCE_SETS; i++) {
        AllowanceSet *set = &state->allowances.inline_sets[i];

        /* Skip empty sets */
        if (set->subcommand_count == 0) continue;

        /* Check timeout and expire if needed */
        expire_allowance_set(set);
        if (set->subcommand_count == 0) continue;

        /* Look for matching subcommand */
        for (int j = 0; j < set->subcommand_count; j++) {
            int word_idx = j / 32;
            int bit_idx = j % 32;

            /* Already used? */
            if (set->used_mask[word_idx] & (1 << bit_idx)) {
                continue;
            }

            /* Full string match */
            if (set->subcommands[j] &&
                strcmp(set->subcommands[j], subcommand) == 0) {

                /* Mark as used */
                set->used_mask[word_idx] |= (1 << bit_idx);

                if (is_set_fully_used(set)) {
                    set->subcommand_count = 0;
                }

                DEBUG_PRINT("ALLOWANCE: using allowance set %d, subcommand '%s'\n",
                           i, subcommand);
                return 1;
            }
        }
    }

    /* Check spillover sets */
    AllowanceSpillover *node = state->allowances.spillover;
    while (node) {
        for (int i = 0; i < SPILLOVER_ALLOWANCE_SETS; i++) {
            AllowanceSet *set = &node->sets[i];

            if (set->subcommand_count == 0) continue;

            expire_allowance_set(set);
            if (set->subcommand_count == 0) continue;

            for (int j = 0; j < set->subcommand_count; j++) {
                int word_idx = j / 32;
                int bit_idx = j % 32;

                if (set->used_mask[word_idx] & (1 << bit_idx)) {
                    continue;
                }

                if (set->subcommands[j] &&
                    strcmp(set->subcommands[j], subcommand) == 0) {

                    set->used_mask[word_idx] |= (1 << bit_idx);

                    if (is_set_fully_used(set)) {
                        set->subcommand_count = 0;
                    }

                    DEBUG_PRINT("ALLOWANCE: using spillover set %d, subcommand '%s'\n",
                               i, subcommand);
                    return 1;
                }
            }
        }
        node = node->next;
    }

    return 0;
}

/* Strip outermost wrapper from command, storing result in dst.
 * Returns pointer to result in dst on success, NULL on failure.
 * If dst is too small (command + null > dst_size), returns NULL with errno=ERANGE.
 * Caller may pass a 4KB buffer initially, and retry with a larger buffer
 * (e.g., malloc(strlen(full_command) + 1)) if ERANGE is returned.
 *
 * The extractor function handles wrapper-specific argument parsing:
 * - "timeout 1 ls" → returns "ls" (skips wrapper + duration)
 * - "sh -c 'echo hi'" → returns "echo hi" (with quotes stripped)
 * - "nice -n 5 ls" → returns "ls" (skips wrapper + level)
 */
static const char *strip_outermost_wrapper_prefix(const char *full_command,
                                                    char *dst, size_t dst_size) {
    errno = 0;
    if (!full_command || !dst || dst_size < 2) {
        errno = EINVAL;
        return NULL;
    }

    size_t cmd_len = strlen(full_command);
    if (cmd_len + 1 > dst_size) {
        errno = ERANGE;
        return NULL;
    }

    /* Copy input to destination where extractors can modify in place */
    memmove(dst, full_command, cmd_len + 1);

    /* Try each known wrapper */
    for (int i = 0; WRAPPER_SPECS[i].name; i++) {
        const char *wrapper_name = WRAPPER_SPECS[i].name;
        size_t name_len = strlen(wrapper_name);

        /* Check if command starts with this wrapper name */
        if (strncmp(dst, wrapper_name, name_len) != 0) {
            continue;
        }

        /* Ensure there's whitespace or end-of-string after the wrapper name */
        char *after_name = dst + name_len;
        if (*after_name != ' ' && *after_name != '\t' && *after_name != '\0') {
            continue;  /* e.g., "timeout1" doesn't match "timeout" */
        }

        /* Skip whitespace to get to what comes after the wrapper */
        while (*after_name == ' ' || *after_name == '\t') after_name++;

        /* Call the extractor to get the remainder after wrapper-specific args */
        char *remainder = WRAPPER_SPECS[i].extract(after_name);
        if (remainder) {
            DEBUG_PRINT("WRAPPER: matched '%s', remainder '%s'\n", wrapper_name, remainder);
            return remainder;
        }
    }

    return NULL;
}

/* Check and consume a wrapper chain for a process.
 * Returns 1 if the execve should be allowed.
 *
 * Grammar: wrappee = wrapper wrappee | wrappee (base)
 * Example: timeout timeout ls
 *   → wrapper=timeout, wrappee="timeout ls"
 *   → wrapper=timeout, wrappee="ls"
 *   → wrappee="ls" (base case)
 *
 * Logic:
 * - If first word of execve IS a wrapper: advance offset past it, transfer remaining to child
 * - If first word of execve is NOT a wrapper (base wrappee): consume chain (allow)
 * - If execve matches remaining suffix AND first word is NOT a wrapper: consume
 *
 * When a wrapper prefix is detected (case 1), the remaining suffix is copied to the
 * child's wrapper_chain so nested wrappers like "npx tsx script.ts" can continue
 * propagating through multiple exec levels.
 */
static int consume_wrapper_chain(ProcessState *parent_state, ProcessState *child_state, const char *subcommand) {
    if (!parent_state) return 0;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    /* No wrapper chain if wrapper_command is NULL */
    if (!parent_state->wrapper_chain.wrapper_command) {
        return 0;
    }

    /* Check timeout - discard chains older than 10 minutes */
    double age_seconds = (now.tv_sec - parent_state->wrapper_chain.timestamp.tv_sec) +
                        (now.tv_nsec - parent_state->wrapper_chain.timestamp.tv_nsec) / 1e9;
    if (age_seconds > ALLOWANCE_TIMEOUT_SECONDS) {
        DEBUG_PRINT("WRAPPER_CHAIN: expired for pid %d\n", parent_state->pid);
        free(parent_state->wrapper_chain.wrapper_command);
        parent_state->wrapper_chain.wrapper_command = NULL;
        return 0;
    }

    const char *remaining_suffix = parent_state->wrapper_chain.wrapper_command;
    size_t suffix_len = strlen(remaining_suffix);
    size_t subcommand_len = strlen(subcommand);

    /* Create a copy of the original suffix for length calculation (local_suffix).
     * wrapper_prefix_len must be called on the original since it returns a byte
     * offset into the string. */
    char *local_suffix = malloc(suffix_len + 1);
    if (!local_suffix) return 0;
    memcpy(local_suffix, remaining_suffix, suffix_len + 1);

    /* Create a separate buffer for comparison (normalized), with quotes stripped
     * for sh -c so we can match against child's argv (which has no quotes). */
    char *normalized = malloc(suffix_len + 1);
    if (!normalized) {
        free(local_suffix);
        return 0;
    }
    memcpy(normalized, local_suffix, suffix_len + 1);

    /* For sh -c: strip quotes from the argument after -c in the normalized buffer only */
    if (strncmp(normalized, "sh -c", 5) == 0) {
        char *ptr = strstr(normalized, "-c");
        if (ptr) {
            ptr += 2;
            while (*ptr == ' ' || *ptr == '\t') ptr++;
            strip_quotes(ptr);
        }
    }

    /* Compare normalized suffix with child command */
    DEBUG_PRINT("WRAPPER_CHAIN: comparing normalized='%s' vs subcommand='%s'\n", normalized, subcommand);
    if (strcmp(normalized, subcommand) != 0) {
        DEBUG_PRINT("WRAPPER_CHAIN: no match, trying next ancestor\n");
        free(local_suffix);
        free(normalized);
        return 0;   /* No match */
    }
    DEBUG_PRINT("WRAPPER_CHAIN: match found!\n");

    /* Match found. Use the original local_suffix (not normalized) for offset calculation */
    DEBUG_PRINT("WRAPPER_CHAIN: child '%s' matches parent's suffix '%s'\n",
                subcommand, remaining_suffix);

    size_t consumed = wrapper_prefix_len(local_suffix);
    int result = 0;

    if (consumed > 0) {
        /* Compute canonical remainder by stripping the wrapper from the child's command.
         * Use dynamically allocated buffer sized for the actual subcommand length. */
        char *child_remainder = malloc(subcommand_len + 1);
        if (!child_remainder) {
            free(local_suffix);
            free(normalized);
            return 0;
        }
        memcpy(child_remainder, subcommand, subcommand_len + 1);

        const char *canonical = strip_outermost_wrapper_prefix(child_remainder, child_remainder, subcommand_len + 1);
        if (canonical && *canonical) {
            /* Update parent's chain to the canonical remainder (no quotes) */
            free(parent_state->wrapper_chain.wrapper_command);
            parent_state->wrapper_chain.wrapper_command = strdup(canonical);
            clock_gettime(CLOCK_MONOTONIC, &parent_state->wrapper_chain.timestamp);
            DEBUG_PRINT("WRAPPER_CHAIN: parent chain updated to '%s'\n", canonical);

            /* Set child's chain to the same canonical remainder */
            free(child_state->wrapper_chain.wrapper_command);
            child_state->wrapper_chain.wrapper_command = strdup(canonical);
            if (child_state->wrapper_chain.wrapper_command) {
                clock_gettime(CLOCK_MONOTONIC, &child_state->wrapper_chain.timestamp);
                DEBUG_PRINT("WRAPPER_CHAIN: transferred chain '%s' to child pid %d\n",
                            canonical, child_state->pid);
            }
        } else {
            /* No further wrapper: clear both chains */
            free(parent_state->wrapper_chain.wrapper_command);
            parent_state->wrapper_chain.wrapper_command = NULL;
            free(child_state->wrapper_chain.wrapper_command);
            child_state->wrapper_chain.wrapper_command = NULL;
        }
        free(child_remainder);
        /* Mark command as validated to prevent repeated execve detections */
        free(child_state->last_validated_cmd);
        child_state->last_validated_cmd = strdup(subcommand);
        result = 1;
    } else {
        /* Base wrappee: child has no wrapper. Consume entire parent chain and clear child's chain. */
        free(parent_state->wrapper_chain.wrapper_command);
        parent_state->wrapper_chain.wrapper_command = NULL;
        free(child_state->wrapper_chain.wrapper_command);
        child_state->wrapper_chain.wrapper_command = NULL;
        /* Mark command as validated to prevent repeated execve detections */
        free(child_state->last_validated_cmd);
        child_state->last_validated_cmd = strdup(subcommand);
        DEBUG_PRINT("WRAPPER_CHAIN: base wrappee matched, chain consumed\n");
        result = 1;
    }

    free(local_suffix);
    free(normalized);
    return result;
}




/* Grant allowances to a process based on the full command.
 * Finds an empty slot (or allocates spillover) to preserve existing allowances. */
static void grant_allowance(ProcessState *state, const char *full_command) {
    if (!state) return;

    shell_parse_result_t result;
    shell_error_t err;

    /* Try to parse with fast tokenizer */
    err = shell_parse_fast(full_command, strlen(full_command),
                          &SHELL_LIMITS_DEFAULT, &result);

    if (err != SHELL_OK && err != SHELL_ETRUNC) {
        /* Parse failed - no allowances */
        DEBUG_PRINT("ALLOWANCE: shell_parse_fast failed for '%s', no allowances\n", full_command);
        return;
    }

    DEBUG_PRINT("ALLOWANCE: parsed '%s' into %d subcommands\n", full_command, result.count);

    /* If full command begins with a known wrapper, setup a chain allowance for the wrapped. */
    if (result.count <= 1) {
        char suffix_buf[4096];
        char *large_buf = NULL;
        const char *suffix = strip_outermost_wrapper_prefix(full_command, suffix_buf, sizeof(suffix_buf));

        if (!suffix && errno == ERANGE) {
            /* Buffer too small - allocate based on actual command length */
            size_t cmd_len = strlen(full_command);
            large_buf = malloc(cmd_len + 1);
            if (large_buf) {
                suffix = strip_outermost_wrapper_prefix(full_command, large_buf, cmd_len + 1);
            }
        }

        if (!suffix) {
            DEBUG_PRINT("ALLOWANCE: single subcommand (full command), no allowances to store\n");
            free(large_buf);
            return;
        }

        /* Store the suffix as a wrapper-chain allowance (do NOT strip quotes).
         * Quotes carry information about command structure and must be preserved. */
        free(state->wrapper_chain.wrapper_command);
        state->wrapper_chain.wrapper_command = strdup(suffix);
        free(large_buf);
        if (!state->wrapper_chain.wrapper_command) {
            DEBUG_PRINT("WRAPPER_CHAIN: failed to allocate memory for '%s'\n", suffix);
            return;
        }
        clock_gettime(CLOCK_MONOTONIC, &state->wrapper_chain.timestamp);
        DEBUG_PRINT("WRAPPER_CHAIN: stored '%s' for pid %d\n", suffix, state->pid);

        /* Parse the suffix for subcommands and grant allowances for them.
         * This handles sh -c 'cmd1; cmd2' and nested wrappers like timeout sh -c '...'.
         * We parse the original suffix (with quotes preserved) and directly store allowances
         * without recursing into grant_allowance (which would store wrapper_chain at each level). */
        DEBUG_PRINT("GRANT_ALLOWANCE: parsing suffix='%s' (len=%zu)\n", suffix, strlen(suffix));
        shell_parse_result_t inner_result;
        shell_error_t parse_err = shell_parse_fast(suffix, strlen(suffix), &SHELL_LIMITS_DEFAULT, &inner_result);
        if (parse_err == SHELL_OK) {
            DEBUG_PRINT("GRANT_ALLOWANCE: parsed %u subcommands from '%s'\n", inner_result.count, suffix);
            /* Find an empty slot for the allowances */
            AllowanceSet *slot = NULL;
            for (int i = 0; i < INLINE_ALLOWANCE_SETS; i++) {
                expire_allowance_set(&state->allowances.inline_sets[i]);
                if (state->allowances.inline_sets[i].subcommand_count == 0) {
                    slot = &state->allowances.inline_sets[i];
                    break;
                }
            }
            if (!slot) {
                AllowanceSpillover **node_ptr = &state->allowances.spillover;
                while (*node_ptr) {
                    for (int i = 0; i < SPILLOVER_ALLOWANCE_SETS; i++) {
                        expire_allowance_set(&(*node_ptr)->sets[i]);
                        if ((*node_ptr)->sets[i].subcommand_count == 0) {
                            slot = &(*node_ptr)->sets[i];
                            break;
                        }
                    }
                    if (slot) break;
                    node_ptr = &(*node_ptr)->next;
                }
                if (!slot) {
                    /* Count existing spillover nodes */
                    int node_count = 0;
                    AllowanceSpillover *count_node = state->allowances.spillover;
                    while (count_node) {
                        node_count++;
                        count_node = count_node->next;
                    }
                    if (node_count < MAX_SPILLOVER_NODES) {
                        *node_ptr = calloc(1, sizeof(AllowanceSpillover));
                        if (*node_ptr) {
                            slot = &(*node_ptr)->sets[0];
                        }
                    }
                }
            }
            if (slot) {
                clock_gettime(CLOCK_MONOTONIC, &slot->timestamp);
                slot->subcommand_count = 0;
                memset(slot->used_mask, 0, sizeof(slot->used_mask));
                DEBUG_PRINT("GRANT_ALLOWANCE: storing subcommands in slot, count=%u\n", inner_result.count);
                for (uint32_t i = 0; i < inner_result.count && i < SHELL_MAX_SUBCOMMANDS; i++) {
                    uint32_t subcmd_len;
                    const char *subcmd_ptr = shell_get_subcommand(suffix, &inner_result.cmds[i], &subcmd_len);
                    if (subcmd_len > 0) {
                        /* Create a modifiable copy of the subcommand */
                        char *subcmd_copy = strndup(subcmd_ptr, subcmd_len);
                        if (!subcmd_copy) continue;
                        
                        /* Strip wrapper prefix to get inner command.
                         * For example: "sh -c noop" -> "noop"
                         * This ensures children exec'ing "noop" find the allowance. */
                        char inner_buf[4096];
                        const char *inner = strip_outermost_wrapper_prefix(subcmd_copy, inner_buf, sizeof(inner_buf));
                        
                        if (inner) {
                            /* Successfully stripped wrapper, use the inner command */
                            slot->subcommands[slot->subcommand_count] = strdup(inner);
                            DEBUG_PRINT("GRANT_ALLOWANCE: stored subcommand[%d]='%s' (stripped from '%.*s')\n", 
                                       slot->subcommand_count, inner, subcmd_len, subcmd_ptr);
                        } else {
                            /* No wrapper, store original subcommand (strip quotes for proper matching) */
                            strip_quotes(subcmd_copy);
                            slot->subcommands[slot->subcommand_count] = strdup(subcmd_copy);
                            DEBUG_PRINT("GRANT_ALLOWANCE: stored subcommand[%d]='%s'\n", 
                                       slot->subcommand_count, subcmd_copy);
                            free(subcmd_copy);
                            subcmd_copy = NULL; /* ownership transferred */
                        }
                        free(subcmd_copy);
                        if (slot->subcommands[slot->subcommand_count]) {
                            slot->subcommand_count++;
                        }
                    }
                }
                DEBUG_PRINT("GRANT_ALLOWANCE: final slot subcommand_count=%d\n", slot->subcommand_count);
            } else {
                DEBUG_PRINT("GRANT_ALLOWANCE: no slot found to store subcommands!\n");
            }
        } else {
            DEBUG_PRINT("GRANT_ALLOWANCE: shell_parse_fast failed for '%s', err=%d\n", suffix, parse_err);
        }
        return;
    }

    /* Multiple subcommands - find an empty slot for the new allowance.
     * We don't clear existing allowances - children may still be using them. */
    AllowanceSet *slot = NULL;

    /* First try inline sets - find one with subcommand_count == 0 (empty) */
    for (int i = 0; i < INLINE_ALLOWANCE_SETS; i++) {
        expire_allowance_set(&state->allowances.inline_sets[i]);
        if (state->allowances.inline_sets[i].subcommand_count == 0) {
            slot = &state->allowances.inline_sets[i];
            DEBUG_PRINT("ALLOWANCE: using inline slot %d for pid %d\n", i, state->pid);
            break;
        }
    }

    /* If no inline slot available, check/allocate spillover */
    if (!slot) {
        AllowanceSpillover **node_ptr = &state->allowances.spillover;
        while (*node_ptr) {
            /* First expire old sets in this node */
            for (int i = 0; i < SPILLOVER_ALLOWANCE_SETS; i++) {
                expire_allowance_set(&(*node_ptr)->sets[i]);
                if ((*node_ptr)->sets[i].subcommand_count == 0) {
                    slot = &(*node_ptr)->sets[i];
                    DEBUG_PRINT("ALLOWANCE: using existing spillover slot %d for pid %d\n", i, state->pid);
                    break;
                }
            }
            if (slot) break;
            node_ptr = &(*node_ptr)->next;
        }

        /* If still no slot, allocate new spillover node (with limit check) */
        if (!slot) {
            /* Count existing spillover nodes */
            int node_count = 0;
            AllowanceSpillover *count_node = state->allowances.spillover;
            while (count_node) {
                node_count++;
                count_node = count_node->next;
            }

            if (node_count >= MAX_SPILLOVER_NODES) {
                DEBUG_PRINT("ALLOWANCE: max spillover nodes (%d) reached for pid %d, skipping\n",
                           MAX_SPILLOVER_NODES, state->pid);
                return;
            }

            *node_ptr = calloc(1, sizeof(AllowanceSpillover));
            if (*node_ptr) {
                slot = &(*node_ptr)->sets[0];
                DEBUG_PRINT("ALLOWANCE: allocated new spillover node %d, using slot 0 for pid %d\n",
                           node_count + 1, state->pid);
            } else {
                DEBUG_PRINT("ALLOWANCE: failed to allocate spillover node\n");
                return;
            }
        }
    }

    /* Populate the slot */
    clock_gettime(CLOCK_MONOTONIC, &slot->timestamp);
    slot->subcommand_count = 0;
    memset(slot->used_mask, 0, sizeof(slot->used_mask));

    for (uint32_t i = 0; i < result.count && i < SHELL_MAX_SUBCOMMANDS; i++) {
        uint32_t subcmd_len;
        const char *subcmd_ptr = shell_get_subcommand(full_command, &result.cmds[i], &subcmd_len);

        if (subcmd_len > 0) {
            slot->subcommands[slot->subcommand_count] = strndup(subcmd_ptr, subcmd_len);
            if (!slot->subcommands[slot->subcommand_count]) {
                DEBUG_PRINT("ALLOWANCE: failed to allocate memory for subcommand %d\n", i);
                /* Free already-allocated subcommands */
                for (int j = 0; j < slot->subcommand_count; j++) {
                    free(slot->subcommands[j]);
                }
                slot->subcommand_count = 0;
                return;
            }
            slot->subcommand_count++;
            DEBUG_PRINT("ALLOWANCE: granted subcommand '%.*s' to pid %d\n",
                       subcmd_len, subcmd_ptr, state->pid);
        }
    }
}

/* Process state table (simple hash map).
 *
 * IMPORTANT: This is for CONCURRENT processes, not total spawns over time.
 * When a process exits, its entry is removed and can be reused.
 * The limit (4096) is the maximum number of processes that can be
 * traced simultaneously. For long-running shells that spawn many
 * commands over time, this is sufficient because each command process
 * exits and frees its table entry.
 *
 * The table is dynamically resizing - it starts with INITIAL_CAPACITY
 * and grows when the load factor exceeds 0.75, to handle arbitrary
 * numbers of concurrent processes without hitting a fixed limit.
 */
#define INITIAL_PROCESS_TABLE_CAPACITY 64
#define PROCESS_TABLE_LOAD_FACTOR_THRESHOLD 0.75
#define TOMBSTONE_THRESHOLD 0.5

#define TOMBSTONE ((ProcessState *)-1)

typedef struct {
    ProcessState **entries;
    size_t capacity;
    size_t count;
    size_t tombstone_count;
} ProcessTable;

static ProcessTable g_process_table = {NULL, 0, 0, 0};
static pid_t g_main_process_pid = 0;

/* Get hash index for pid */
static size_t pid_hash(pid_t pid, size_t capacity) {
    return ((size_t)pid * 2654435761U) % capacity;  /* Knuth's multiplicative hash */
}

/* Resize the process table - only rehashes live entries, skips tombstones */
static int resize_process_table(size_t new_capacity) {
    ProcessState **new_entries = calloc(new_capacity, sizeof(ProcessState *));
    if (!new_entries) {
        return -1;
    }

    /* Rehash existing live entries only (skip tombstones) */
    for (size_t i = 0; i < g_process_table.capacity; i++) {
        if (g_process_table.entries[i] && g_process_table.entries[i] != TOMBSTONE) {
            ProcessState *p = g_process_table.entries[i];
            size_t idx = pid_hash(p->pid, new_capacity);

            /* Linear probe for empty slot - keep probing until we find one */
            size_t probe = idx;
            bool placed = false;
            for (size_t j = 0; j < new_capacity; j++) {
                if (!new_entries[probe]) {
                    new_entries[probe] = p;
                    placed = true;
                    break;
                }
                probe = (probe + 1) % new_capacity;
            }
            /* With proper load factor management, we should ALWAYS find a slot.
             * If we don't, it's a critical error - entries would be lost. */
            if (!placed) {
                LOG_ERROR("CRITICAL: hash table resize failed to place entry - table corrupted");
                free(new_entries);
                return -1;
            }
        }
    }

    free(g_process_table.entries);
    g_process_table.entries = new_entries;
    g_process_table.capacity = new_capacity;
    g_process_table.tombstone_count = 0;

    return 0;
}

/* Free all resources in a process state (allowances, wrapper chain, execve data) */
static void free_process_state(ProcessState *p) {
    if (!p) return;

    /* Free inline allowance sets */
    for (int j = 0; j < INLINE_ALLOWANCE_SETS; j++) {
        for (int k = 0; k < p->allowances.inline_sets[j].subcommand_count; k++) {
            free(p->allowances.inline_sets[j].subcommands[k]);
        }
    }

    /* Free spillover linked list */
    AllowanceSpillover *node = p->allowances.spillover;
    while (node) {
        for (int j = 0; j < SPILLOVER_ALLOWANCE_SETS; j++) {
            for (int k = 0; k < node->sets[j].subcommand_count; k++) {
                free(node->sets[j].subcommands[k]);
            }
        }
        AllowanceSpillover *next = node->next;
        free(node);
        node = next;
    }

    /* Free wrapper chain */
    free(p->wrapper_chain.wrapper_command);

    /* Free execve data */
    free(p->execve_pathname);
    memory_free_string_array(p->execve_argv);
    memory_free_string_array(p->execve_envp);
    memory_free_ulong_array(p->execve_envp_addrs);
    free(p->last_validated_cmd);
}

/* Set the main process PID */
void syscall_set_main_process(pid_t pid) {
    g_main_process_pid = pid;
}

/* Initialize syscall handler */
int syscall_handler_init(void) {
    g_process_table.entries = calloc(INITIAL_PROCESS_TABLE_CAPACITY, sizeof(ProcessState *));
    if (!g_process_table.entries) {
        return -1;
    }
    g_process_table.capacity = INITIAL_PROCESS_TABLE_CAPACITY;
    g_process_table.count = 0;
    g_process_table.tombstone_count = 0;
    g_main_process_pid = 0;
    return 0;
}

/* Cleanup syscall handler */
void syscall_handler_cleanup(void) {
    if (g_process_table.entries) {
        for (size_t i = 0; i < g_process_table.capacity; i++) {
            ProcessState *entry = g_process_table.entries[i];
            if (entry && entry != TOMBSTONE) {
                free_process_state(entry);
                free(entry);
            }
        }
        free(g_process_table.entries);
        g_process_table.entries = NULL;
        g_process_table.capacity = 0;
        g_process_table.count = 0;
        g_process_table.tombstone_count = 0;
    }
}

/* Get process state (create if needed) */
ProcessState *syscall_get_process_state(pid_t pid) {
    if (!g_process_table.entries) {
        return NULL;
    }

    /* Check if tombstone cleanup needed */
    if (g_process_table.capacity > INITIAL_PROCESS_TABLE_CAPACITY &&
        (double)g_process_table.tombstone_count / g_process_table.capacity > TOMBSTONE_THRESHOLD) {
        if (resize_process_table(g_process_table.capacity) != 0) {
            return NULL;
        }
    }

    /* Check if resize needed */
    if (g_process_table.count > 0 &&
        (double)g_process_table.count / g_process_table.capacity > PROCESS_TABLE_LOAD_FACTOR_THRESHOLD) {
        size_t new_capacity = g_process_table.capacity * 2;
        if (resize_process_table(new_capacity) != 0) {
            return NULL;
        }
    }

    size_t idx = pid_hash(pid, g_process_table.capacity);
    size_t first_tombstone = SIZE_MAX;

    /* Search for existing entry */
    for (size_t i = 0; i < g_process_table.capacity; i++) {
        size_t probe = (idx + i) % g_process_table.capacity;
        ProcessState *entry = g_process_table.entries[probe];

        if (entry == TOMBSTONE) {
            if (first_tombstone == SIZE_MAX) {
                first_tombstone = probe;
            }
            continue;
        }
        if (!entry) {
            /* Found empty slot - use first tombstone if found, otherwise this slot */
            size_t insert_at = (first_tombstone != SIZE_MAX) ? first_tombstone : probe;

            /* Create new entry at insert_at */
            g_process_table.entries[insert_at] = calloc(1, sizeof(ProcessState));
            if (g_process_table.entries[insert_at]) {
                g_process_table.entries[insert_at]->pid = pid;
                g_process_table.count++;
                if (first_tombstone != SIZE_MAX) {
                    g_process_table.tombstone_count--;
                }
            }
            return g_process_table.entries[insert_at];
        }
        if (entry->pid == pid) {
            return entry;
        }
    }

    /* No NULL slot found - reuse first tombstone if available */
    if (first_tombstone != SIZE_MAX) {
        g_process_table.entries[first_tombstone] = calloc(1, sizeof(ProcessState));
        if (g_process_table.entries[first_tombstone]) {
            g_process_table.entries[first_tombstone]->pid = pid;
            g_process_table.count++;
            g_process_table.tombstone_count--;
        }
        return g_process_table.entries[first_tombstone];
    }

    return NULL;  /* Should not reach here with dynamic resizing */
}

/* Find process state without creating - returns NULL if not found */
ProcessState *syscall_find_process_state(pid_t pid) {
    if (!g_process_table.entries) {
        return NULL;
    }

    size_t idx = pid_hash(pid, g_process_table.capacity);

    /* Search for existing entry */
    for (size_t i = 0; i < g_process_table.capacity; i++) {
        size_t probe = (idx + i) % g_process_table.capacity;
        ProcessState *entry = g_process_table.entries[probe];
        if (entry == TOMBSTONE) {
            continue;
        }
        if (!entry) {
            return NULL;
        }
        if (entry->pid == pid) {
            return entry;
        }
    }

    return NULL;  /* Not found */
}

/* Remove process state */
void syscall_remove_process_state(pid_t pid) {
    if (!g_process_table.entries) {
        return;
    }

    size_t idx = pid_hash(pid, g_process_table.capacity);

    for (size_t i = 0; i < g_process_table.capacity; i++) {
        size_t probe = (idx + i) % g_process_table.capacity;
        ProcessState *entry = g_process_table.entries[probe];
        if (entry == TOMBSTONE) {
            continue;
        }
        if (!entry) {
            return;
        }
        if (entry->pid == pid) {
            free_process_state(entry);
            free(entry);
            g_process_table.entries[probe] = TOMBSTONE;
            g_process_table.count--;
            g_process_table.tombstone_count++;
            return;
        }
    }
}

/* Check if syscall is execve or execveat */
int syscall_is_execve(USER_REGS *regs) {
    long sysnum = REG_SYSCALL(regs);
    return (sysnum == SYSCALL_EXECVE || sysnum == SYSCALL_EXECVEAT);
}

/* Check if syscall is fork/clone/vfork */
int syscall_is_fork(USER_REGS *regs) {
    long sysnum = REG_SYSCALL(regs);
    return (sysnum == SYSCALL_CLONE ||
            sysnum == SYSCALL_FORK ||
            sysnum == SYSCALL_VFORK);
}

/* Check if syscall is a filesystem syscall subject to soft policy */
static int syscall_is_filesystem(USER_REGS *regs) {
    long sysnum = REG_SYSCALL(regs);
    switch (sysnum) {
        case SYSCALL_OPEN:
        case SYSCALL_OPENAT:
        case SYSCALL_CREAT:
        case SYSCALL_MKDIR:
        case SYSCALL_MKDIRAT:
        case SYSCALL_RMDIR:
        case SYSCALL_UNLINK:
        case SYSCALL_UNLINKAT:
        case SYSCALL_RENAME:
        case SYSCALL_RENAMEAT:
        case SYSCALL_SYMLINK:
        case SYSCALL_SYMLINKAT:
        case SYSCALL_LINK:
        case SYSCALL_LINKAT:
        case SYSCALL_CHMOD:
        case SYSCALL_CHOWN:
        case SYSCALL_TRUNCATE:
        case SYSCALL_FTRUNCATE:
        case SYSCALL_UTIME:
        case SYSCALL_STAT:
        case SYSCALL_LSTAT:
        case SYSCALL_NEWFSTATAT:
        case SYSCALL_FSTAT:
        case SYSCALL_ACCESS:
        case SYSCALL_FACCESSAT:
        case SYSCALL_FACCESSAT2:
            return 1;
        default:
            return 0;
    }
}

/*
 * Resolve a path for a *_at syscall or any syscall with a relative path.
 *
 * For absolute paths, this returns a realpath-resolved canonical path.
 * For relative paths:
 *   - If dirfd == AT_FDCWD, resolves against the child process's cwd.
 *   - Otherwise, resolves against the directory referred to by dirfd.
 *
 * If the path does not exist (e.g., for file creation), this function
 * resolves the parent directory and appends the basename. This allows
 * policy checking on creation operations.
 *
 * chdir() handling: We read /proc/pid/cwd fresh on every call, so chdir()
 * is handled automatically without needing to intercept that syscall.
 *
 * TOCTOU note: There is an inherent race between reading /proc/PID/cwd or
 * /proc/PID/fd/N and the actual syscall execution. A process could change
 * its cwd or close/reopen a directory fd between our readlink() and the
 * kernel's actual path resolution. This is a fundamental limitation of
 * ptrace-based interception and cannot be fixed without kernel support.
 * The policy is best-effort, not a hard security boundary.
 *
 * Returns NULL on error (path cannot be resolved).
 */
static void strip_trailing_slashes(char *p) {
    size_t len = strlen(p);
    while (len > 1 && p[len-1] == '/') p[--len] = '\0';
}

static void get_parent_path(const char *path, char *parent, size_t parent_size) {
    const char *last_slash = strrchr(path, '/');
    if (last_slash && last_slash != path) {
        size_t parent_len = last_slash - path;
        if (parent_len >= parent_size) parent_len = parent_size - 1;
        memcpy(parent, path, parent_len);
        parent[parent_len] = '\0';
    } else if (last_slash == path) {
        strcpy(parent, "/");
    } else {
        strcpy(parent, ".");
    }
}

static char *resolve_path_at(pid_t pid, int dirfd, const char *path, char *buf, size_t buf_size, int *file_exists) {
    char dir_buf[PATH_MAX];
    char *result;
    int exists = -1;

    if (!path || !buf || buf_size < PATH_MAX) return NULL;
    if (file_exists) *file_exists = -1;

    if (path[0] == '/') {
        result = realpath(path, buf);
        if (result) {
            exists = 1;
        } else if (errno == ENOENT) {
            exists = 0;
            strlcpy(buf, path, buf_size);
            strip_trailing_slashes(buf);
            if (buf[0] == '\0') {
                strcpy(buf, "/");
            }
        } else {
            return NULL;
        }
        if (file_exists) *file_exists = exists;
        return exists >= 0 ? buf : NULL;
    }

    if (dirfd == AT_FDCWD) {
        snprintf(dir_buf, sizeof(dir_buf), "/proc/%d/cwd", pid);
    } else {
        snprintf(dir_buf, sizeof(dir_buf), "/proc/%d/fd/%d", pid, dirfd);
    }

    char link_buf[PATH_MAX];
    ssize_t len = readlink(dir_buf, link_buf, sizeof(link_buf)-1);
    if (len <= 0) {
        DEBUG_PRINT("HANDLER: failed to read link %s: %s\n", dir_buf, strerror(errno));
        return NULL;
    }
    link_buf[len] = '\0';

    size_t link_len = strlen(link_buf);
    size_t path_len = strlen(path);
    if (link_len + 1 + path_len >= buf_size) {
        DEBUG_PRINT("HANDLER: path too long: %s/%s\n", link_buf, path);
        return NULL;
    }

    int written = snprintf(buf, buf_size, "%s/%s", link_buf, path);
    if (written < 0 || (size_t)written >= buf_size) {
        DEBUG_PRINT("HANDLER: snprintf failed or truncated: %s/%s\n", link_buf, path);
        return NULL;
    }

    char tmp_buf[PATH_MAX];
    result = realpath(buf, tmp_buf);
    if (result) {
        exists = 1;
        size_t copy_len = strlen(tmp_buf);
        if (copy_len >= buf_size) copy_len = buf_size - 1;
        memcpy(buf, tmp_buf, copy_len);
        buf[copy_len] = '\0';
    } else if (errno == ENOENT) {
        exists = 0;
        strip_trailing_slashes(buf);
    } else {
        return NULL;
    }
    if (file_exists) *file_exists = exists;
    return buf;
}

/* Check if a string needs quoting for shell safety */
static int needs_shell_quoting(const char *str) {
    if (!str || !*str) return 0;
    for (const char *p = str; *p; p++) {
        char c = *p;
        if (c == ' ' || c == '\t' || c == '\n' || c == ';' || 
            c == '\'' || c == '"' || c == '$' || c == '`' ||
            c == '\\' || c == '(' || c == ')' || c == '[' || 
            c == ']' || c == '{' || c == '}' || c == '<' ||
            c == '>' || c == '&' || c == '|' || c == '*' ||
            c == '?' || c == '!' || c == '#' || c == '~') {
            return 1;
        }
    }
    return 0;
}

/* Build command string from argv - dynamic allocation.
 * Properly quotes arguments that contain shell special characters. */
#define MAX_COMMAND_STRING_LEN 65536  /* 64KB sanity limit */

static char *build_command_string_alloc(char *const argv[]) {
    if (!argv || !argv[0]) return NULL;

    /* First pass: calculate total length needed, accounting for quoting */
    size_t total_len = 0;
    for (int i = 0; argv[i]; i++) {
        size_t len = strlen(argv[i]);
        if (needs_shell_quoting(argv[i])) {
            /* Count single quotes to see if we can use single quoting */
            int has_single_quote = 0;
            for (size_t j = 0; j < len; j++) {
                if (argv[i][j] == '\'') {
                    has_single_quote = 1;
                    break;
                }
            }
            if (has_single_quote) {
                /* Use double quotes - need to escape $, `, \, and " */
                total_len += 2;  /* opening and closing " */
                for (size_t j = 0; j < len; j++) {
                    char c = argv[i][j];
                    if (c == '$' || c == '`' || c == '\\' || c == '"') {
                        total_len += 2;  /* backslash escape */
                    }
                    total_len++;
                }
            } else {
                /* Use single quotes: 'arg' -> no special char escaping needed */
                total_len += 2;  /* opening and closing ' */
                total_len += len;
            }
        } else {
            total_len += len;
        }
        total_len += 1;  /* space separator */
        /* Check for integer overflow */
        if (total_len > MAX_COMMAND_STRING_LEN) {
            DEBUG_PRINT("HANDLER: command string too large or overflow\n");
            return NULL;
        }
    }

    if (total_len == 0) return NULL;

    /* Allocate buffer */
    char *buf = malloc(total_len + 1);
    if (!buf) return NULL;

    /* Second pass: build the string with proper quoting */
    char *p = buf;
    for (int i = 0; argv[i]; i++) {
        if (i > 0) {
            *p++ = ' ';
        }
        size_t len = strlen(argv[i]);
        if (needs_shell_quoting(argv[i])) {
            /* Count single quotes */
            int has_single_quote = 0;
            for (size_t j = 0; j < len; j++) {
                if (argv[i][j] == '\'') {
                    has_single_quote = 1;
                    break;
                }
            }
            if (has_single_quote) {
                /* Use double quotes with escaping */
                *p++ = '"';
                for (size_t j = 0; j < len; j++) {
                    char c = argv[i][j];
                    if (c == '$' || c == '`' || c == '\\' || c == '"') {
                        *p++ = '\\';
                    }
                    *p++ = c;
                }
                *p++ = '"';
            } else {
                /* Use single quotes */
                *p++ = '\'';
                memcpy(p, argv[i], len);
                p += len;
                *p++ = '\'';
            }
        } else {
            memcpy(p, argv[i], len);
            p += len;
        }
    }
    *p = '\0';

    return buf;
}

/* Get basename from path */
static const char *get_basename(const char *path) {
    if (!path) return "unknown";
    const char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

/* Block a filesystem syscall by returning an error and skipping the syscall instruction.
 * Returns 1 if blocked, -1 on error. */
static int block_syscall(pid_t pid, USER_REGS *regs) {
#ifdef __x86_64__
    regs->rax = -EACCES;
    regs->rip += 2;
#elif defined(__i386__)
    regs->eax = -EACCES;
    regs->eip += 2;
#elif defined(__aarch64__)
    regs->regs[0] = -EACCES;
    regs->pc += 4;
#elif defined(__riscv)
    regs->regs[0] = -EACCES;
    regs->epc += 4;
#else
    return -1;
#endif

    if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1) {
        perror("ptrace(SETREGS) for block_syscall");
        kill(pid, SIGKILL);
        return -1;
    }

    DEBUG_PRINT("HANDLER: blocked filesystem syscall\n");
    return 1;
}

/* Block execve by replacing it with a shell command that prints permission denied */
static int block_execve(pid_t pid, USER_REGS *regs) {
    MemoryContext mem_ctx;

    /* Initialize memory context */
    if (memory_init(&mem_ctx, pid, REG_SP(regs)) < 0) {
        LOG_ERROR("Failed to init memory context for block");
        return -1;
    }

    /* Try multiple shell paths - some minimal systems may not have /bin/sh */
    const char *shell_paths[] = { "/bin/sh", "/bin/bash", "/bin/dash", NULL };
    const char *sh_path = NULL;
    for (int i = 0; shell_paths[i]; i++) {
        if (access(shell_paths[i], X_OK) == 0) {
            sh_path = shell_paths[i];
            break;
        }
    }
    if (!sh_path) {
        DEBUG_PRINT("HANDLER: no shell found for block_execve, using kill\n");
        return -1;
    }

    const char *dash_c = "-c";
    const char *message_cmd = "echo 'Permission denied, this command was not executed and had no effects on the system.' >&2; exit 1";

    /* Write strings to process memory */
    unsigned long sh_addr = memory_write_string(&mem_ctx, sh_path);
    unsigned long dash_c_addr = memory_write_string(&mem_ctx, dash_c);
    unsigned long cmd_addr = memory_write_string(&mem_ctx, message_cmd);

    if (!sh_addr || !dash_c_addr || !cmd_addr) {
        LOG_ERROR("Failed to write shell command strings");
        return -1;
    }

    /* Create argv = {"/bin/sh", "-c", "echo ...", NULL} */
    unsigned long argv_ptrs[4];
    argv_ptrs[0] = sh_addr;
    argv_ptrs[1] = dash_c_addr;
    argv_ptrs[2] = cmd_addr;
    argv_ptrs[3] = 0;

    unsigned long new_argv = memory_write_pointer_array(&mem_ctx, argv_ptrs, 3);
    if (!new_argv) {
        LOG_ERROR("Failed to write argv for shell");
        return -1;
    }

    /* Update registers to exec /bin/sh
     * Note: execveat has different argument order:
     *   execve(path, argv, envp) -> rdi, rsi, rdx
     *   execveat(dirfd, path, argv, envp, flags) -> rdi, rsi, rdx, r10
     */
    if (REG_SYSCALL(regs) == SYSCALL_EXECVEAT) {
        /* For execveat: set dirfd = AT_FDCWD */
        REG_ARG1(regs) = -100;  /* AT_FDCWD */
        REG_ARG2(regs) = sh_addr;
        REG_ARG3(regs) = new_argv;
        REG_ARG4(regs) = 0;  /* envp = NULL */
    } else {
        /* For execve: standard arguments */
        REG_ARG1(regs) = sh_addr;
        REG_ARG2(regs) = new_argv;
        REG_ARG3(regs) = 0;  /* envp = NULL */
    }

    /* Apply changes */
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1) {
        perror("ptrace(SETREGS)");
        return -1;
    }

    return 0;
}

/* Handle syscall entry (before execution) */
int syscall_handle_entry(pid_t pid, USER_REGS *regs, ProcessState *state) {
    if (!state) {
        DEBUG_PRINT("HANDLER: No state for pid=%d\n", pid);
        return 0;
    }

    /* Skip detached processes */
    if (state->detached) {
        return 0;
    }

    /* Clear stale environment decisions before any DFA or filtering checks.
     * These variables may be set from a previous command and should not affect
     * subsequent commands (especially DFA-fast-path commands that don't query the server). */
    unsetenv("READONLYBOX_ENV_DECISIONS");
    unsetenv("READONLYBOX_FLAGGED_ENV_NAMES");

    /* Only check execve syscalls */
    if (syscall_is_execve(regs)) {
        DEBUG_PRINT("HANDLER: pid=%d execve detected, initial=%d, detached=%d\n",
                    pid, state->initial_execve, state->detached);

        /* New execve that needs validation - reset validated flag */
        state->validated = 0;
        state->in_execve = 1;

        /* Read execve/execveat arguments */
        /* Note: execveat has different argument order than execve:
         *   execve(pathname, argv, envp)
         *   execveat(dirfd, pathname, argv, envp, flags)
         */
        unsigned long pathname_addr;
        unsigned long argv_addr;
        unsigned long envp_addr;
        int dirfd = AT_FDCWD;

        if (REG_SYSCALL(regs) == SYSCALL_EXECVEAT) {
            /* execveat: dirfd is in arg1, pathname in arg2 */
            dirfd = (int)REG_ARG1(regs);
            pathname_addr = REG_ARG2(regs);
            argv_addr = REG_ARG3(regs);
            envp_addr = REG_ARG4(regs);
        } else {
            /* execve: all arguments in standard positions */
            pathname_addr = REG_ARG1(regs);
            argv_addr = REG_ARG2(regs);
            envp_addr = REG_ARG3(regs);
        }

        /* Save original arguments */
        free(state->execve_pathname);
        memory_free_string_array(state->execve_argv);
        memory_free_string_array(state->execve_envp);
        memory_free_ulong_array(state->execve_envp_addrs);

        state->execve_pathname = memory_read_string(pid, pathname_addr);

        /* Handle empty pathname with AT_EMPTY_PATH semantics:
         * If pathname is empty, resolve from dirfd using /proc/<pid>/fd/<dirfd>.
         * This handles execveat(dirfd, "", argv, envp, AT_EMPTY_PATH) correctly. */
        if (state->execve_pathname && state->execve_pathname[0] == '\0' && dirfd != AT_FDCWD) {
            char fd_path[64];
            char resolved[PATH_MAX];
            snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", pid, dirfd);
            ssize_t len = readlink(fd_path, resolved, sizeof(resolved) - 1);
            if (len > 0) {
                resolved[len] = '\0';
                free(state->execve_pathname);
                state->execve_pathname = strdup(resolved);
            }
        }

        state->execve_argv = memory_read_string_array(pid, argv_addr);
        /* Also capture the addresses of environment variables in child memory */
        state->execve_envp = memory_read_string_array_with_addrs(pid, envp_addr, &state->execve_envp_addrs);

        if (!state->execve_pathname || !state->execve_argv) {
            /* Block the command by replacing it with a permission denied message */
            if (block_execve(pid, regs) < 0) {
                /* If we can't block it, kill the process */
                kill(pid, SIGKILL);
            }
            return 0;
        }

        /* Build command string for validation - use dynamic allocation to avoid truncation */
        char *command = build_command_string_alloc(state->execve_argv);
        DEBUG_PRINT("HANDLER: pid=%d built command string: '%s'\n", pid, command);
        if (!command) {
            /* Allocation failed - block the command to be safe */
            DEBUG_PRINT("HANDLER: pid=%d failed to build command string, blocking\n", pid);
            if (block_execve(pid, regs) < 0) {
                kill(pid, SIGKILL);
            }
            return 0;
        }

        /* Check if this is the main process's initial execve - allow without validation */
        if (!state->initial_execve && pid == g_main_process_pid) {
            /* This is the main process's first execve, allow without validation */
            DEBUG_PRINT("HANDLER: Allowing main process %d initial execve without validation\n", pid);
            state->initial_execve = 1;
            free(command);
            /* Don't detach - continue tracing this process for future execves */
            return 0;
        }

        /* Mark that we've seen an execve for this process */
        if (!state->initial_execve) {
            state->initial_execve = 1;
        }

        /* Get parent PID to check for allowances */
        char proc_status[64];
        snprintf(proc_status, sizeof(proc_status), "/proc/%d/status", pid);
        FILE *status_file = fopen(proc_status, "r");
        pid_t parent_pid = 0;
        if (status_file) {
            char line[256];
            while (fgets(line, sizeof(line), status_file)) {
                if (strncmp(line, "PPid:", 5) == 0) {
                    sscanf(line + 5, "%d", &parent_pid);
                    break;
                }
            }
            fclose(status_file);
        } else {
            /* /proc may not be mounted (e.g., containers with limited procfs).
             * In this case, we skip the allowance check - commands will be
             * validated normally via DFA/server. This is a safe degradation. */
            DEBUG_PRINT("HANDLER: pid=%d could not open %s, skipping allowance check\n",
                       pid, proc_status);
        }

        /* Walk up the process tree to find an ancestor with allowances.
         * A child consumes allowances from its parent (not inherited, directly accessed).
         * Stop when we reach the ptrace process itself (g_main_process_pid).
         * 
         * IMPORTANT: For execve-based wrappers like sh -c, the process making the execve
         * is the SAME process that runs the wrapper command. So we must check the CURRENT
         * process's state (not just ancestors) for allowances stored from a previous execve.
         */
        DEBUG_PRINT("HANDLER: pid=%d walking tree from parent=%d looking for '%s'\n", pid, parent_pid, command);
        
        /* First check the CURRENT process's own state (for execve-based wrappers).
         * After execve, the process continues running but with a new program.
         * Allowances from the PREVIOUS execve are still in this process's state. */
        DEBUG_PRINT("HANDLER: pid=%d checking own state for wrapper-chain\n", pid);
        if (consume_wrapper_chain(state, state, command)) {
            DEBUG_PRINT("HANDLER: pid=%d has wrapper-chain from self for '%s', allowing\n",
                       pid, command);
            state->validated = 1;
            free(command);
            return 0;
        }
        DEBUG_PRINT("HANDLER: pid=%d checking allowances in self for '%s'\n", pid, command);
        if (consume_allowance(state, command)) {
            DEBUG_PRINT("HANDLER: pid=%d has allowance from self for '%s', allowing\n",
                       pid, command);
            state->validated = 1;
            free(command);
            return 0;
        }
        
        /* Then walk up to ancestors */
        pid_t ancestor_pid = parent_pid;
        while (ancestor_pid > 0 && ancestor_pid != g_main_process_pid) {
            ProcessState *ancestor_state = syscall_find_process_state(ancestor_pid);
            DEBUG_PRINT("HANDLER: pid=%d checking ancestor_pid=%d state=%s\n", pid, ancestor_pid, ancestor_state ? "found" : "NULL");
            if (ancestor_state) {
                /* First check wrapper chain - if first word is a wrapper, advance offset.
                 * If first word is NOT a wrapper, consume the wrapper chain.
                 * Then check subcommand allowances. */
                if (consume_wrapper_chain(ancestor_state, state, command)) {
                    DEBUG_PRINT("HANDLER: pid=%d has wrapper-chain from ancestor %d for '%s', allowing\n",
                               pid, ancestor_pid, command);
                    state->validated = 1;
                    free(command);
                    return 0;
                }
                /* Check subcommand allowances */
                DEBUG_PRINT("HANDLER: pid=%d checking allowances in ancestor %d for '%s'\n", pid, ancestor_pid, command);
                if (consume_allowance(ancestor_state, command)) {
                    DEBUG_PRINT("HANDLER: pid=%d has allowance from ancestor %d for '%s', allowing\n",
                               pid, ancestor_pid, command);
                    state->validated = 1;
                    free(command);
                    return 0;
                }
            }

            /* Get parent's parent to continue walking up the tree */
            char ancestor_status_path[64];
            snprintf(ancestor_status_path, sizeof(ancestor_status_path), "/proc/%d/status", ancestor_pid);
            FILE *ancestor_status = fopen(ancestor_status_path, "r");
            pid_t next_ancestor = 0;
            if (ancestor_status) {
                char line[256];
                while (fgets(line, sizeof(line), ancestor_status)) {
                    if (strncmp(line, "PPid:", 5) == 0) {
                        sscanf(line + 5, "%d", &next_ancestor);
                        break;
                    }
                }
                fclose(ancestor_status);
            }
            if (next_ancestor == 0 || next_ancestor == ancestor_pid) {
                /* Can't go further up the tree */
                break;
            }
            ancestor_pid = next_ancestor;
        }

        /* Check if this is the same command we just validated for this process.
         * This prevents duplicate requests when a process retries exec while we're waiting.
         * Must come after wrapper chain to allow chain propagation first. */
        if (state->last_validated_cmd && strcmp(state->last_validated_cmd, command) == 0) {
            DEBUG_PRINT("HANDLER: pid=%d command '%s' already validated, allowing\n", pid, command);
            free(command);
            state->validated = 1;
            return 0;
        }

        /* For subsequent execves (commands run by bash), validate with server */
        /* Check DFA fast-path */
        int dfa_result = validation_check_dfa(command);

        /* Debug: print DFA result for every command */
        DEBUG_PRINT("DFA: command='%s' result=%s\n", command,
                dfa_result == VALIDATION_ALLOW ? "ALLOW" :
                (dfa_result == VALIDATION_DENY ? "DENY" : "ASK"));

        if (dfa_result == VALIDATION_ALLOW) {
            /* Fast allow - mark as validated but continue tracing for future execves */
            DEBUG_PRINT("DFA: Fast-allowing command '%s', continuing to trace\n", command);
            state->validated = 1;

            /* Filter environment variables even for DFA-allowed commands */
            if (filter_env_decisions(state, pid, regs) < 0) {
                /* Filter failed - log but continue (not critical for DFA-allowed) */
                DEBUG_PRINT("HANDLER: pid=%d env filter failed for '%s', continuing anyway\n", pid, command);
            }

            /* Clear environment decision variables to prevent leakage to subsequent commands */
            unsetenv("READONLYBOX_ENV_DECISIONS");
            unsetenv("READONLYBOX_FLAGGED_ENV_NAMES");

            /* Continue tracing - don't detach */
            free(command);
            return 0;
        }

        /* DFA didn't allow - need to ask server for decision */
        DEBUG_PRINT("HANDLER: pid=%d DFA result=%d, asking server for decision on '%s'\n",
                    pid, dfa_result, command);

        /* Build caller info for the request */
        char caller_info[256 + 8] = {0};  /* basename + ":execve" - safe */
        char exe_link[64];
        snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
        char exe_path[PATH_MAX];
        ssize_t exe_len = readlink(exe_link, exe_path, sizeof(exe_path) - 1);
        if (exe_len > 0) {
            exe_path[exe_len] = '\0';
            const char *base = get_basename(exe_path);
            /* Safely copy basename, truncating if needed but preserving null terminator */
            size_t base_len = strlen(base);
            if (base_len > 255) base_len = 255;
            memcpy(caller_info, base, base_len);
            memcpy(caller_info + base_len, ":execve", 8);
        } else {
            strcpy(caller_info, "unknown:execve");
        }

        /* Ask server for decision via readonlybox --judge
         * judge_run now waits indefinitely for server availability */
        int decision = judge_run(command, caller_info);

        DEBUG_PRINT("JUDGE: pid=%d command='%s' decision=%d\n", pid, command, decision);

        if (decision != 0) {
            /* Server denied (exit 9) or timeout after retries - block the command */
            DEBUG_PRINT("HANDLER: pid=%d server denied command '%s', blocking\n", pid, command);
            if (block_execve(pid, regs) < 0) {
                kill(pid, SIGKILL);
            }
            free(command);
            return 0;
        }

        /* Server allowed - let the execve proceed */
        DEBUG_PRINT("HANDLER: pid=%d server allowed command '%s', continuing to trace\n", pid, command);
        state->validated = 1;

        /* Grant allowances to this process for subcommands of the allowed command.
         * Child processes will be able to exec subcommands without new server requests. */
        grant_allowance(state, command);

        /* Track this validated command to prevent duplicates on retry */
        free(state->last_validated_cmd);
        state->last_validated_cmd = strdup(command);

        /* Filter environment variables based on server decisions and apply to child */
        if (filter_env_decisions(state, pid, regs) < 0) {
            /* Filter failed - block the command to be safe */
            DEBUG_PRINT("HANDLER: pid=%d env filter failed for '%s', blocking\n", pid, command);
            if (block_execve(pid, regs) < 0) {
                kill(pid, SIGKILL);
            }
            /* Clear environment decision variables before returning */
            unsetenv("READONLYBOX_ENV_DECISIONS");
            unsetenv("READONLYBOX_FLAGGED_ENV_NAMES");
            free(command);
            return 0;
        }

        free(command);
        return 0;
    }

    /* Check for filesystem syscalls (soft policy) */
    if (syscall_is_filesystem(regs)) {
        soft_policy_t *policy = soft_policy_get_global();
        if (soft_policy_is_active(policy)) {
            soft_path_mode_t inputs[16];
            int results[16];
            int count = 0;
            long sysnum = REG_SYSCALL(regs);
            uint32_t access_mask = 0;
            char *path1 = NULL;
            char *path2 = NULL;
            char path_buf1[PATH_MAX];
            char path_buf2[PATH_MAX];
            int dirfd1 = AT_FDCWD;
            int dirfd2 = AT_FDCWD;
            int ret = 0;
            int is_creat = 0;
            int modifies_dir_entry = 0;

            switch (sysnum) {
                case SYSCALL_OPEN: {
                    access_mask = SOFT_ACCESS_READ | SOFT_ACCESS_WRITE;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    if (path1) {
                        int flags = (int)REG_ARG2(regs);
                        if ((flags & O_ACCMODE) == O_RDONLY) {
                            access_mask = SOFT_ACCESS_READ;
                        } else if ((flags & O_ACCMODE) == O_WRONLY) {
                            access_mask = SOFT_ACCESS_WRITE;
                        } else if ((flags & O_ACCMODE) == O_RDWR) {
                            access_mask = SOFT_ACCESS_READ | SOFT_ACCESS_WRITE;
                        }
                        if (flags & O_TRUNC) {
                            access_mask |= SOFT_ACCESS_TRUNCATE;
                        }
                        if (flags & O_CREAT) {
                            access_mask |= SOFT_ACCESS_WRITE;
                            is_creat = 1;
                        }
                    }
                    dirfd1 = AT_FDCWD;
                    break;
                }
                case SYSCALL_OPENAT: {
                    access_mask = SOFT_ACCESS_READ | SOFT_ACCESS_WRITE;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    if (path1) {
                        int flags = (int)REG_ARG3(regs);
                        if ((flags & O_ACCMODE) == O_RDONLY) {
                            access_mask = SOFT_ACCESS_READ;
                        } else if ((flags & O_ACCMODE) == O_WRONLY) {
                            access_mask = SOFT_ACCESS_WRITE;
                        } else if ((flags & O_ACCMODE) == O_RDWR) {
                            access_mask = SOFT_ACCESS_READ | SOFT_ACCESS_WRITE;
                        }
                        if (flags & O_TRUNC) {
                            access_mask |= SOFT_ACCESS_TRUNCATE;
                        }
                        if (flags & O_CREAT) {
                            access_mask |= SOFT_ACCESS_WRITE;
                            is_creat = 1;
                        }
                    }
                    break;
                }
                case SYSCALL_CREAT:
                    access_mask = SOFT_ACCESS_WRITE | SOFT_ACCESS_TRUNCATE;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    is_creat = 1;
                    break;
                case SYSCALL_MKDIR:
                    access_mask = SOFT_ACCESS_MKDIR;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_MKDIRAT:
                    access_mask = SOFT_ACCESS_MKDIR;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    break;
                case SYSCALL_RMDIR:
                    access_mask = SOFT_ACCESS_RMDIR;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_UNLINK:
                    access_mask = SOFT_ACCESS_UNLINK;
                    modifies_dir_entry = 1;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_UNLINKAT:
                    access_mask = SOFT_ACCESS_UNLINK;
                    modifies_dir_entry = 1;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    break;
                case SYSCALL_RENAME:
                    access_mask = SOFT_ACCESS_RENAME;
                    modifies_dir_entry = 1;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    path2 = memory_read_string(pid, REG_ARG2(regs));
                    dirfd1 = AT_FDCWD;
                    dirfd2 = AT_FDCWD;
                    break;
                case SYSCALL_RENAMEAT:
                    access_mask = SOFT_ACCESS_RENAME;
                    modifies_dir_entry = 1;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    dirfd2 = (int)REG_ARG3(regs);
                    path2 = memory_read_string(pid, REG_ARG4(regs));
                    break;
                case SYSCALL_SYMLINK:
                    access_mask = SOFT_ACCESS_SYMLINK;
                    modifies_dir_entry = 1;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    path2 = memory_read_string(pid, REG_ARG2(regs));
                    dirfd1 = AT_FDCWD;
                    dirfd2 = AT_FDCWD;
                    break;
                case SYSCALL_SYMLINKAT:
                    access_mask = SOFT_ACCESS_SYMLINK;
                    modifies_dir_entry = 1;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    dirfd2 = AT_FDCWD;
                    path2 = memory_read_string(pid, REG_ARG3(regs));
                    break;
                case SYSCALL_LINK:
                    access_mask = SOFT_ACCESS_LINK;
                    modifies_dir_entry = 1;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    path2 = memory_read_string(pid, REG_ARG2(regs));
                    dirfd1 = AT_FDCWD;
                    dirfd2 = AT_FDCWD;
                    break;
                case SYSCALL_LINKAT:
                    access_mask = SOFT_ACCESS_LINK;
                    modifies_dir_entry = 1;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    dirfd2 = (int)REG_ARG3(regs);
                    path2 = memory_read_string(pid, REG_ARG4(regs));
                    break;
                case SYSCALL_CHMOD:
                    access_mask = SOFT_ACCESS_CHMOD;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_CHOWN:
                    access_mask = SOFT_ACCESS_CHOWN;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_TRUNCATE:
                    access_mask = SOFT_ACCESS_WRITE | SOFT_ACCESS_TRUNCATE;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_FTRUNCATE:
                    /* ftruncate operates on a file descriptor, not a path.
                     * We cannot apply soft policy without tracking open file descriptors.
                     * The file descriptor was already checked at open() time. */
                    DEBUG_PRINT("HANDLER: pid=%d ftruncate (fd-based), allowing\n", pid);
                    return 0;
                case SYSCALL_UTIME:
                    access_mask = SOFT_ACCESS_WRITE;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_STAT:
                    access_mask = SOFT_ACCESS_READ;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_LSTAT:
                    access_mask = SOFT_ACCESS_READ;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_NEWFSTATAT:
                    access_mask = SOFT_ACCESS_READ;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    break;
                case SYSCALL_FSTAT:
                    /* fstat operates on a file descriptor, not a path.
                     * We cannot apply soft policy without tracking open file descriptors.
                     * The file descriptor was already checked at open() time. */
                    DEBUG_PRINT("HANDLER: pid=%d fstat (fd-based), allowing\n", pid);
                    return 0;
                case SYSCALL_ACCESS:
                    access_mask = SOFT_ACCESS_READ;
                    path1 = memory_read_string(pid, REG_ARG1(regs));
                    dirfd1 = AT_FDCWD;
                    break;
                case SYSCALL_FACCESSAT:
                    access_mask = SOFT_ACCESS_READ;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    break;
                case SYSCALL_FACCESSAT2:
                    access_mask = SOFT_ACCESS_READ;
                    dirfd1 = (int)REG_ARG1(regs);
                    path1 = memory_read_string(pid, REG_ARG2(regs));
                    break;
                default:
                    DEBUG_PRINT("HANDLER: pid=%d unknown filesystem syscall %ld\n", pid, sysnum);
                    return 0;
            }

            if (path1) {
                int file_exists = -1;
                char *resolved = resolve_path_at(pid, dirfd1, path1, path_buf1, sizeof(path_buf1), &file_exists);
                if (!resolved) {
                    DEBUG_PRINT("HANDLER: pid=%d path resolution failed for '%s', allowing kernel to handle\n", pid, path1);
                    free(path1);
                    path1 = NULL;
                } else if (is_creat && !file_exists) {
                    char parent_buf[PATH_MAX];
                    get_parent_path(path_buf1, parent_buf, sizeof(parent_buf));
                    char *parent_resolved = resolve_path_at(pid, dirfd1, parent_buf, parent_buf, sizeof(parent_buf), &file_exists);
                    (void)file_exists;
                    DEBUG_PRINT("HANDLER: pid=%d O_CREAT on non-existent '%s', checking parent '%s'\n", pid, path1, parent_buf);
                    free(path1);
                    path1 = NULL;
                    if (parent_resolved) {
                        inputs[count].path = strdup(parent_buf);
                        inputs[count].access_mask = SOFT_ACCESS_WRITE;
                        count++;
                    }
                } else {
                    /* For dir entry modifications (rename/symlink/link/unlink), check parent with WRITE.
                     * For symlink/link, also check target with READ if it exists. */
                    if (modifies_dir_entry) {
                        char parent_buf[PATH_MAX];
                        get_parent_path(path_buf1, parent_buf, sizeof(parent_buf));
                        inputs[count].path = strdup(parent_buf);
                        inputs[count].access_mask = SOFT_ACCESS_WRITE;
                        count++;
                        /* For symlink/link: check target (path1) with READ if it exists */
                        if ((sysnum == SYSCALL_SYMLINK || sysnum == SYSCALL_SYMLINKAT ||
                             sysnum == SYSCALL_LINK || sysnum == SYSCALL_LINKAT) && file_exists) {
                            inputs[count].path = strdup(path_buf1);
                            inputs[count].access_mask = SOFT_ACCESS_READ;
                            count++;
                        }
                    }
                    free(path1);
                    path1 = NULL;
                    inputs[count].path = strdup(path_buf1);
                    inputs[count].access_mask = access_mask;
                    count++;
                }
            }

            if (path2) {
                int file_exists = -1;
                char *resolved = resolve_path_at(pid, dirfd2, path2, path_buf2, sizeof(path_buf2), &file_exists);
                if (!resolved) {
                    DEBUG_PRINT("HANDLER: pid=%d path resolution failed for '%s', allowing kernel to handle\n", pid, path2);
                    free(path2);
                    path2 = NULL;
                } else if (is_creat && !file_exists) {
                    char parent_buf[PATH_MAX];
                    get_parent_path(path_buf2, parent_buf, sizeof(parent_buf));
                    char *parent_resolved = resolve_path_at(pid, dirfd2, parent_buf, parent_buf, sizeof(parent_buf), &file_exists);
                    (void)file_exists;
                    DEBUG_PRINT("HANDLER: pid=%d O_CREAT on non-existent '%s', checking parent '%s'\n", pid, path2, parent_buf);
                    free(path2);
                    path2 = NULL;
                    if (parent_resolved) {
                        inputs[count].path = strdup(parent_buf);
                        inputs[count].access_mask = SOFT_ACCESS_WRITE;
                        count++;
                    }
                } else {
                    /* For dir entry modifications, check parent with WRITE */
                    if (modifies_dir_entry) {
                        char parent_buf[PATH_MAX];
                        get_parent_path(path_buf2, parent_buf, sizeof(parent_buf));
                        inputs[count].path = strdup(parent_buf);
                        inputs[count].access_mask = SOFT_ACCESS_WRITE;
                        count++;
                    }
                    free(path2);
                    path2 = NULL;
                    inputs[count].path = strdup(path_buf2);
                    inputs[count].access_mask = access_mask;
                    count++;
                }
            }

            if (count > 0) {
                DEBUG_PRINT("HANDLER: pid=%d filesystem syscall %ld, checking %d paths\n",
                           pid, sysnum, count);
                int check_result = soft_policy_check(policy, inputs, results, count);
                if (check_result != 0) {
                    DEBUG_PRINT("HANDLER: soft_policy_check failed (error), blocking syscall\n");
                    if (block_syscall(pid, regs) < 0) {
                        kill(pid, SIGKILL);
                    }
                    ret = -1;
                    goto cleanup;
                } else {
                    for (int i = 0; i < count; i++) {
                        if (g_soft_debug) {
                            fprintf(stderr, "SOFT: syscall=%ld path=%s access=0x%x -> %s\n",
                                    sysnum, inputs[i].path, inputs[i].access_mask,
                                    results[i] ? "ALLOW" : "DENY");
                        }
                        if (!results[i]) {
                            DEBUG_PRINT("HANDLER: pid=%d SOFT POLICY DENY path '%s'\n", pid, inputs[i].path);
                            int block_result = block_syscall(pid, regs);
                            if (block_result < 0) {
                                DEBUG_PRINT("HANDLER: failed to block syscall, killing child\n");
                                kill(pid, SIGKILL);
                                ret = -1;
                                goto cleanup;
                            }
                            ret = block_result;
                            goto cleanup;
                        }
                    }
                }
            }

cleanup:
            free(path1);
            free(path2);
            return ret;
        }
    }

    return 0;
}

/* Filter environment variables based on server decisions
 * Reads READONLYBOX_ENV_DECISIONS and removes denied vars from state->execve_envp
 * Also writes the filtered envp to the child's memory and updates the register
 * Returns: 0 on success, -1 on error (parse error or allocation failure) */
static int filter_env_decisions(ProcessState *state, pid_t pid, USER_REGS *regs) {
    if (!state || !state->execve_envp || !state->execve_envp_addrs) return 0;

    const char *env_decisions_str = getenv("READONLYBOX_ENV_DECISIONS");
    if (!env_decisions_str || strlen(env_decisions_str) == 0) return 0;

    DEBUG_PRINT("FILTER: parsing env decisions: '%s'\n", env_decisions_str);

    /* Parse decisions: format is "index:decision,index:decision,..."
     * where decision is 0=allow, 1=deny
     * Uses strict parsing - abort on any malformed input */
    int decisions[256] = {0};  /* index -> decision */
    int max_index = -1;
    int parse_error = 0;

    const char *p = env_decisions_str;
    while (*p) {
        /* Parse index - must be non-negative integer */
        char *end;
        long idx = strtol(p, &end, 10);
        if (end == p || idx < 0 || idx >= 256) { parse_error = 1; break; }
        if (*end != ':') { parse_error = 1; break; }
        p = end + 1;

        /* Parse decision - must be 0 or 1 */
        int decision = *p - '0';
        if (decision != 0 && decision != 1) { parse_error = 1; break; }
        p++;

        /* Must be either comma (more entries) or null (end) */
        if (*p == ',') {
            p++;
        } else if (*p == '\0') {
            /* Valid end of string */
            decisions[(int)idx] = decision;
            if ((int)idx > max_index) max_index = (int)idx;
            break;
        } else {
            parse_error = 1; break;
        }

        decisions[(int)idx] = decision;
        if ((int)idx > max_index) max_index = (int)idx;
    }

    /* Abort on parse error - reject potentially malicious/malformed input */
    if (parse_error) {
        DEBUG_PRINT("FILTER: env decision parse error, rejecting\n");
        return -1;
    }

    if (max_index < 0) return 0;

    /* Get flagged env var names from environment */
    const char *env_names_str = getenv("READONLYBOX_FLAGGED_ENV_NAMES");
    char *flagged_names[256] = {0};
    int flagged_count = 0;

    if (!env_names_str || strlen(env_names_str) == 0) {
        DEBUG_PRINT("FILTER: no flagged env var names available\n");
        return 0;
    }

    /* Parse names from environment */
    char buf[4096];
    strlcpy(buf, env_names_str, sizeof(buf));

    char *saveptr;
    char *token = strtok_r(buf, ",", &saveptr);
    while (token && flagged_count < 256) {
        flagged_names[flagged_count++] = token;
        token = strtok_r(NULL, ",", &saveptr);
    }

    /* Filter envp - remove denied vars */
    /* Build new filtered envp */
    int env_count = 0;
    while (state->execve_envp[env_count]) env_count++;

    /* Allocate new envp */
    char **new_envp = calloc(env_count + 1, sizeof(char *));
    if (!new_envp) {
        DEBUG_PRINT("FILTER: failed to allocate new_envp\n");
        return -1;
    }
    unsigned long *new_env_addrs = calloc(env_count + 1, sizeof(unsigned long));
    if (!new_env_addrs) {
        free(new_envp);
        DEBUG_PRINT("FILTER: failed to allocate new_env_addrs\n");
        return -1;
    }

    /* Track which entries are being removed (for cleanup on success) */
    int *removed_indices = calloc(env_count, sizeof(int));
    if (!removed_indices) {
        free(new_envp);
        free(new_env_addrs);
        DEBUG_PRINT("FILTER: failed to allocate removed_indices\n");
        return -1;
    }
    int removed_count = 0;

    int new_idx = 0;
    for (int i = 0; i < env_count && state->execve_envp[i]; i++) {
        /* Get env var name */
        char *eq = strchr(state->execve_envp[i], '=');
        size_t name_len = eq ? (size_t)(eq - state->execve_envp[i]) : strlen(state->execve_envp[i]);

        /* Check if this var is in flagged list and denied */
        int denied = 0;
        for (int j = 0; j < flagged_count && j <= max_index; j++) {
            if (decisions[j] == 1 && flagged_names[j]) {
                if (strncmp(state->execve_envp[i], flagged_names[j], name_len) == 0 &&
                    (flagged_names[j][name_len] == '\0' || flagged_names[j][name_len] == '=')) {
                    /* This env var is denied */
                    DEBUG_PRINT("FILTER: removing denied env var '%s'\n", state->execve_envp[i]);
                    denied = 1;
                    break;
                }
            }
        }

        if (!denied) {
            new_envp[new_idx] = state->execve_envp[i];
            new_env_addrs[new_idx] = state->execve_envp_addrs[i];
            new_idx++;
        } else {
            removed_indices[removed_count++] = i;
        }
    }
    new_envp[new_idx] = NULL;
    new_env_addrs[new_idx] = 0;

    /* Keep pointers to old state for cleanup on failure */
    char **old_envp = state->execve_envp;
    unsigned long *old_env_addrs = state->execve_envp_addrs;

    /* Write the new envp array to the child's memory and update the register */
    MemoryContext mem_ctx;
    if (memory_init(&mem_ctx, pid, REG_SP(regs)) < 0) {
        DEBUG_PRINT("FILTER: failed to init memory context\n");
        free(new_envp);
        free(new_env_addrs);
        free(removed_indices);
        return -1;
    }

    /* Count how many env vars we're keeping */
    int keep_count = 0;
    while (new_envp[keep_count]) keep_count++;

    if (keep_count == 0) {
        /* No environment variables - set envp to NULL */
        unsigned long new_envp_addr = 0;

        /* Update register */
        if (REG_SYSCALL(regs) == SYSCALL_EXECVEAT) {
            REG_ARG4(regs) = new_envp_addr;
        } else {
            REG_ARG3(regs) = new_envp_addr;
        }

        if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1) {
            DEBUG_PRINT("FILTER: failed to set regs: %s\n", strerror(errno));
            free(new_envp);
            free(new_env_addrs);
            free(removed_indices);
            kill(pid, SIGKILL);
            return -1;
        }

        /* Success - now update state and free removed entries */
        for (int i = 0; i < removed_count; i++) {
            free(old_envp[removed_indices[i]]);
        }
        free(old_envp);
        free(old_env_addrs);
        free(removed_indices);
        state->execve_envp = new_envp;
        state->execve_envp_addrs = new_env_addrs;

        DEBUG_PRINT("FILTER: env vars filtered, 0 remaining (empty envp)\n");
        return 0;
    }

    /* Allocate space in child for the new envp pointer array */
    unsigned long new_envp_addr = memory_alloc(&mem_ctx, (keep_count + 1) * sizeof(unsigned long));
    if (!new_envp_addr) {
        DEBUG_PRINT("FILTER: failed to allocate memory for envp\n");
        free(new_envp);
        free(new_env_addrs);
        free(removed_indices);
        return -1;
    }

    /* Write each pointer to the child's memory.
     * We use the original addresses of each string in the child memory. */
    for (int i = 0; i < keep_count; i++) {
        if (memory_write_pointer_at(&mem_ctx, new_envp_addr + i * sizeof(unsigned long),
                                     new_env_addrs[i]) < 0) {
            DEBUG_PRINT("FILTER: failed to write envp pointer %d\n", i);
            free(new_envp);
            free(new_env_addrs);
            free(removed_indices);
            return -1;
        }
    }

    /* Write NULL terminator */
    if (memory_write_pointer_at(&mem_ctx, new_envp_addr + keep_count * sizeof(unsigned long), 0) < 0) {
        DEBUG_PRINT("FILTER: failed to write envp NULL terminator\n");
        free(new_envp);
        free(new_env_addrs);
        free(removed_indices);
        return -1;
    }

    /* Update register to point to new envp array */
    if (REG_SYSCALL(regs) == SYSCALL_EXECVEAT) {
        REG_ARG4(regs) = new_envp_addr;
    } else {
        REG_ARG3(regs) = new_envp_addr;
    }

    /* Apply changes to the child */
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1) {
        DEBUG_PRINT("FILTER: failed to set regs: %s\n", strerror(errno));
        free(new_envp);
        free(new_env_addrs);
        free(removed_indices);
        kill(pid, SIGKILL);
        return -1;
    }

    /* Success - now update state and free removed entries */
    for (int i = 0; i < removed_count; i++) {
        free(old_envp[removed_indices[i]]);
    }
    free(old_envp);
    free(old_env_addrs);
    free(removed_indices);
    state->execve_envp = new_envp;
    state->execve_envp_addrs = new_env_addrs;

    DEBUG_PRINT("FILTER: env vars filtered, %d remaining, envp updated at 0x%lx\n", keep_count, new_envp_addr);
    return 0;
}

/* Handle syscall exit (after execution) */
int syscall_handle_exit(pid_t pid, USER_REGS *regs, ProcessState *state) {
    (void)pid;  /* Currently unused but may be needed for future logging */

    if (!state) return 0;

    if (state->in_execve && syscall_is_execve(regs)) {
        state->in_execve = 0;

        /* Check if execve failed */
        long retval = REG_ARG1(regs);  /* Return value is in RAX */
        if (retval < 0) {
            /* execve failed - clean up saved state */
            free(state->execve_pathname);
            state->execve_pathname = NULL;
            memory_free_string_array(state->execve_argv);
            state->execve_argv = NULL;
            memory_free_string_array(state->execve_envp);
            state->execve_envp = NULL;
        }

        /* Note: We now detach in syscall_handle_entry when post_redirect_exec is first set,
         * so this block is no longer needed. The state is also cleaned up there.
         * Keeping this only for cleanup of saved state on execve failure.
         */
    }

    return 0;
}
