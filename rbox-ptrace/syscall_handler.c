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
        memmove(str, str + 1, end - str);
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
 * For sh -c, the rest of the string IS the command to execute. */
static char* extract_sh_c(char *cmd) {
    if (!cmd || *cmd == '\0') return NULL;
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
        parent_state->wrapper_chain.wrapper_offset = 0;
        return 0;
    }

    const char *remaining_suffix = parent_state->wrapper_chain.wrapper_command + parent_state->wrapper_chain.wrapper_offset;

    /* Create a copy of the original suffix for length calculation (local_suffix).
     * wrapper_prefix_len must be called on the original since it returns a byte
     * offset into the string. */
    char local_suffix[4096];
    size_t copy_len = strlen(remaining_suffix);
    if (copy_len >= sizeof(local_suffix)) copy_len = sizeof(local_suffix) - 1;
    memcpy(local_suffix, remaining_suffix, copy_len);
    local_suffix[copy_len] = '\0';

    /* Create a separate buffer for comparison (normalized), with quotes stripped
     * for sh -c so we can match against child's argv (which has no quotes). */
    char normalized[4096];
    strncpy(normalized, local_suffix, sizeof(normalized) - 1);
    normalized[sizeof(normalized) - 1] = '\0';

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
    if (strcmp(normalized, subcommand) != 0) {
        return 0;   /* No match */
    }

    /* Match found. Use the original local_suffix (not normalized) for offset calculation */
    DEBUG_PRINT("WRAPPER_CHAIN: child '%s' matches parent's suffix '%s'\n",
                subcommand, remaining_suffix);

    size_t consumed = wrapper_prefix_len(local_suffix);
    if (consumed > 0) {
        /* Compute canonical remainder by stripping the wrapper from the child's command */
        char child_remainder[4096];
        strncpy(child_remainder, subcommand, sizeof(child_remainder)-1);
        child_remainder[sizeof(child_remainder)-1] = '\0';
        const char *canonical = strip_outermost_wrapper_prefix(child_remainder, child_remainder, sizeof(child_remainder));
        if (canonical && *canonical) {
            /* Update parent's chain to the canonical remainder (no quotes) */
            free(parent_state->wrapper_chain.wrapper_command);
            parent_state->wrapper_chain.wrapper_command = strdup(canonical);
            parent_state->wrapper_chain.wrapper_offset = 0;
            clock_gettime(CLOCK_MONOTONIC, &parent_state->wrapper_chain.timestamp);
            DEBUG_PRINT("WRAPPER_CHAIN: parent chain updated to '%s'\n", canonical);

            /* Set child's chain to the same canonical remainder */
            free(child_state->wrapper_chain.wrapper_command);
            child_state->wrapper_chain.wrapper_command = strdup(canonical);
            if (child_state->wrapper_chain.wrapper_command) {
                child_state->wrapper_chain.wrapper_offset = 0;
                clock_gettime(CLOCK_MONOTONIC, &child_state->wrapper_chain.timestamp);
                DEBUG_PRINT("WRAPPER_CHAIN: transferred chain '%s' to child pid %d\n",
                            canonical, child_state->pid);
            }
        } else {
            /* No further wrapper: clear both chains */
            free(parent_state->wrapper_chain.wrapper_command);
            parent_state->wrapper_chain.wrapper_command = NULL;
            parent_state->wrapper_chain.wrapper_offset = 0;
            free(child_state->wrapper_chain.wrapper_command);
            child_state->wrapper_chain.wrapper_command = NULL;
            child_state->wrapper_chain.wrapper_offset = 0;
        }
        /* Mark command as validated to prevent repeated execve detections */
        free(child_state->last_validated_cmd);
        child_state->last_validated_cmd = strdup(subcommand);
        return 1;
    } else {
        /* Base wrappee: child has no wrapper. Consume entire parent chain and clear child's chain. */
        free(parent_state->wrapper_chain.wrapper_command);
        parent_state->wrapper_chain.wrapper_command = NULL;
        parent_state->wrapper_chain.wrapper_offset = 0;
        free(child_state->wrapper_chain.wrapper_command);
        child_state->wrapper_chain.wrapper_command = NULL;
        child_state->wrapper_chain.wrapper_offset = 0;
        /* Mark command as validated to prevent repeated execve detections */
        free(child_state->last_validated_cmd);
        child_state->last_validated_cmd = strdup(subcommand);
        DEBUG_PRINT("WRAPPER_CHAIN: base wrappee matched, chain consumed\n");
        return 1;
    }
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

        /* Store the suffix as a wrapper-chain allowance */
        /* Clear any existing wrapper chain */
        free(state->wrapper_chain.wrapper_command);
        state->wrapper_chain.wrapper_command = strdup(suffix);
        free(large_buf);
        if (!state->wrapper_chain.wrapper_command) {
            DEBUG_PRINT("WRAPPER_CHAIN: failed to allocate memory for '%s'\n", suffix);
            return;
        }
        state->wrapper_chain.wrapper_offset = 0;
        clock_gettime(CLOCK_MONOTONIC, &state->wrapper_chain.timestamp);
        DEBUG_PRINT("WRAPPER_CHAIN: stored '%s' for pid %d\n", suffix, state->pid);
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

/* Build command string from argv - dynamic allocation */
#define MAX_COMMAND_STRING_LEN 65536  /* 64KB sanity limit */

static char *build_command_string_alloc(char *const argv[]) {
    if (!argv || !argv[0]) return NULL;

    /* First pass: calculate total length needed */
    size_t total_len = 0;
    for (int i = 0; argv[i]; i++) {
        size_t len = strlen(argv[i]) + 1;  /* +1 for space separator */
        /* Check for integer overflow */
        if (total_len + len < total_len || total_len + len > MAX_COMMAND_STRING_LEN) {
            DEBUG_PRINT("HANDLER: command string too large or overflow\n");
            return NULL;
        }
        total_len += len;
    }

    if (total_len == 0) return NULL;

    /* Allocate buffer (add 1 for null terminator) */
    char *buf = malloc(total_len + 1);
    if (!buf) return NULL;

    /* Second pass: build the string */
    char *p = buf;
    for (int i = 0; argv[i]; i++) {
        if (i > 0) {
            *p++ = ' ';
        }
        size_t len = strlen(argv[i]);
        memcpy(p, argv[i], len);
        p += len;
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

/* Block execve by replacing it with a shell command that prints permission denied */
static int block_execve(pid_t pid, USER_REGS *regs) {
    MemoryContext mem_ctx;

    /* Initialize memory context */
    if (memory_init(&mem_ctx, pid, REG_SP(regs)) < 0) {
        LOG_ERROR("Failed to init memory context for block");
        return -1;
    }

    /* Use /bin/sh to print the permission denied message */
    const char *sh_path = "/bin/sh";
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

        if (REG_SYSCALL(regs) == SYSCALL_EXECVEAT) {
            /* execveat: dirfd is in arg1, pathname in arg2 */
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

        /* Check if parent has an allowance for this subcommand */
        if (parent_pid > 0) {
            /* Look up parent's process state */
            ProcessState *parent_state = syscall_find_process_state(parent_pid);
            if (parent_state) {
                /* First check wrapper chain - if first word is a wrapper, advance offset.
                 * If first word is NOT a wrapper, consume the wrapper chain.
                 * Then check subcommand allowances. */
                if (consume_wrapper_chain(parent_state, state, command)) {
                    DEBUG_PRINT("HANDLER: pid=%d has wrapper-chain from parent %d for '%s', allowing\n",
                               pid, parent_pid, command);
                    state->validated = 1;
                    return 0;
                }
                /* Check subcommand allowances */
                if (consume_allowance(parent_state, command)) {
                    DEBUG_PRINT("HANDLER: pid=%d has allowance from parent %d for '%s', allowing\n",
                               pid, parent_pid, command);
                    state->validated = 1;
                    return 0;
                }
            }
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

        /* Clear environment decision variables to prevent leakage to subsequent commands */
        unsetenv("READONLYBOX_ENV_DECISIONS");
        unsetenv("READONLYBOX_FLAGGED_ENV_NAMES");

        free(command);
        return 0;
    }

    return 0;
}

/* Filter environment variables based on server decisions
 * Reads READONLYBOX_ENV_DECISIONS and removes denied vars from state->execve_envp
 * Also writes the filtered envp to the child's memory and updates the register */
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
    strncpy(buf, env_names_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

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

        if (denied) {
            /* Free the string for denied env vars to prevent memory leak */
            free(state->execve_envp[i]);
            state->execve_envp[i] = NULL;
        } else {
            new_envp[new_idx] = state->execve_envp[i];
            new_env_addrs[new_idx] = state->execve_envp_addrs[i];
            new_idx++;
        }
    }
    new_envp[new_idx] = NULL;
    new_env_addrs[new_idx] = 0;

    /* Replace envp */
    free(state->execve_envp);
    state->execve_envp = new_envp;
    free(state->execve_envp_addrs);
    state->execve_envp_addrs = new_env_addrs;

    /* Write the new envp array to the child's memory and update the register */
    MemoryContext mem_ctx;
    if (memory_init(&mem_ctx, pid, REG_SP(regs)) < 0) {
        DEBUG_PRINT("FILTER: failed to init memory context\n");
        return -1;
    }

    /* Count how many env vars we're keeping */
    int keep_count = 0;
    while (state->execve_envp[keep_count]) keep_count++;

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
            return -1;
        }

        DEBUG_PRINT("FILTER: env vars filtered, 0 remaining (empty envp)\n");
        return 0;
    }

    /* Allocate space in child for the new envp pointer array */
    unsigned long new_envp_addr = memory_alloc(&mem_ctx, (keep_count + 1) * sizeof(unsigned long));
    if (!new_envp_addr) {
        DEBUG_PRINT("FILTER: failed to allocate memory for envp\n");
        return -1;
    }

    /* Write each pointer to the child's memory.
     * We use the original addresses of each string in the child memory. */
    for (int i = 0; i < keep_count; i++) {
        if (memory_write_pointer_at(&mem_ctx, new_envp_addr + i * sizeof(unsigned long),
                                     state->execve_envp_addrs[i]) < 0) {
            DEBUG_PRINT("FILTER: failed to write envp pointer %d\n", i);
            return -1;
        }
    }

    /* Write NULL terminator */
    if (memory_write_pointer_at(&mem_ctx, new_envp_addr + keep_count * sizeof(unsigned long), 0) < 0) {
        DEBUG_PRINT("FILTER: failed to write envp NULL terminator\n");
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
        return -1;
    }

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
