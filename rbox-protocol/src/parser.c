/*
 * parser.c - Shell command parsing using shellsplit
 *
 * Provides zero-copy command parsing for rbox-protocol.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "rbox_protocol.h"
#include "shell_tokenizer.h"

/*
 * Parse command using shellsplit (zero-copy)
 *
 * The request structure will hold pointers into the original data buffer.
 * This avoids any string copies.
 */
rbox_error_t rbox_command_parse(const char *command, size_t cmd_len,
                                rbox_parse_result_t *result) {
    if (!command || !result) {
        return RBOX_ERR_INVALID;
    }

    /* Validate input - cmd_len must be reasonable */
    if (cmd_len == 0 || cmd_len > (size_t)(1024 * 1024)) {  /* 1MB max */
        return RBOX_ERR_INVALID;
    }

    shell_parse_result_t parse_result;
    shell_error_t err = shell_parse_fast(command, cmd_len, NULL, &parse_result);

    if (err == SHELL_EINPUT) {
        return RBOX_ERR_INVALID;
    }

    if (err == SHELL_EPARSE) {
        return RBOX_ERR_INVALID;
    }

    /* Determine how many subcommands we can copy */
    uint32_t copy_count = parse_result.count;
    int truncated_by_limit = 0;

    if (copy_count > RBOX_MAX_SUBCOMMANDS) {
        copy_count = RBOX_MAX_SUBCOMMANDS;
        truncated_by_limit = 1;
    }

    /* Validate bounds of subcommands we're going to copy */
    for (uint32_t i = 0; i < copy_count; i++) {
        uint32_t start = parse_result.cmds[i].start;
        uint32_t len = parse_result.cmds[i].len;

        /* Check for integer overflow and bounds */
        if (start >= cmd_len) {
            return RBOX_ERR_INVALID;  /* Start beyond buffer */
        }
        if (len > cmd_len) {
            return RBOX_ERR_INVALID;  /* Length exceeds buffer */
        }
        if (start + len > cmd_len) {
            return RBOX_ERR_INVALID;  /* Extends beyond buffer */
        }
    }

    /* Determine has_variables by checking SHELL_FEAT_VARS in subcommands */
    result->has_variables = 0;
    for (uint32_t i = 0; i < copy_count; i++) {
        if (parse_result.cmds[i].features & SHELL_FEAT_VARS) {
            result->has_variables = 1;
            break;
        }
    }

    /* Convert shellsplit result to our format - cap count to what we copied */
    result->count = copy_count;
    result->truncated = ((parse_result.status & SHELL_STATUS_TRUNCATED) != 0) || truncated_by_limit;

    for (uint32_t i = 0; i < copy_count; i++) {
        result->subcommands[i].start = parse_result.cmds[i].start;
        result->subcommands[i].len = parse_result.cmds[i].len;
        result->subcommands[i].type = parse_result.cmds[i].type;
        result->subcommands[i].features = parse_result.cmds[i].features;
    }

    return RBOX_OK;
}

/* Get subcommand as pointer into original buffer */
const char *rbox_get_subcommand(const char *command,
                                const rbox_subcommand_t *sub,
                                uint32_t *out_len) {
    if (!command || !sub) {
        return NULL;
    }

    /* Robust check: validate bounds even in release builds */
    if (sub->len > 16384) {
        return NULL;  /* Max reasonable subcommand length exceeded */
    }
    if (sub->start + sub->len < sub->start) {
        return NULL;  /* Overflow check */
    }

    *out_len = sub->len;
    return command + sub->start;
}

/* Get subcommand as null-terminated string (caller must free) */
char *rbox_dup_subcommand(const char *command, const rbox_subcommand_t *sub) {
    if (!command || !sub || sub->len == 0) {
        return NULL;
    }

    /* Robust check: validate bounds even in release builds */
    if (sub->len > 16384) {
        return NULL;  /* Max reasonable subcommand length exceeded */
    }
    if (sub->start + sub->len < sub->start) {
        return NULL;  /* Overflow check */
    }

    char *result = malloc(sub->len + 1);
    if (!result) {
        return NULL;
    }

    memcpy(result, command + sub->start, sub->len);
    result[sub->len] = '\0';

    return result;
}

/* Get command name (first subcommand) */
const char *rbox_get_command_name(const char *command,
                                   const rbox_parse_result_t *parse) {
    if (!command || !parse || parse->count == 0) {
        return NULL;
    }

    /* First subcommand is the command name */
    const rbox_subcommand_t *sub = &parse->subcommands[0];

    /* Return pointer to start - caller handles truncation if needed */
    return command + sub->start;
}
