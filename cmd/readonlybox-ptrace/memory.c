/*
 * memory.c - Process memory operations for ptrace client
 */

#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "memory.h"

/* Initialize memory context for a traced process */
int memory_init(MemoryContext *ctx, pid_t pid, unsigned long stack_pointer) {
    if (!ctx) return -1;

    ctx->pid = pid;
    ctx->stack_base = stack_pointer;
    /* Use stack area with margin for our data */
    ctx->free_addr = stack_pointer - 8192;

    return 0;
}

/* Read a string from traced process memory */
char *memory_read_string(pid_t pid, unsigned long addr) {
    if (addr == 0) return NULL;

    char *buffer = malloc(4096);
    if (!buffer) return NULL;

    unsigned long word;
    int offset = 0;

    while (offset < 4095) {
        errno = 0;
        word = ptrace(PTRACE_PEEKDATA, pid, addr + offset, NULL);
        if (errno != 0) {
            free(buffer);
            return NULL;
        }

        /* Copy bytes from the word */
        for (size_t i = 0; i < sizeof(long); i++) {
            char c = (word >> (i * 8)) & 0xFF;
            buffer[offset + i] = c;
            if (c == '\0') {
                return buffer;
            }
        }
        offset += sizeof(long);
    }

    buffer[4095] = '\0';
    return buffer;
}

/* Read a null-terminated array of strings from traced process memory */
char **memory_read_string_array(pid_t pid, unsigned long addr) {
    if (addr == 0) return NULL;

    char **array = malloc(256 * sizeof(char *));
    if (!array) return NULL;

    unsigned long ptr;
    int i = 0;

    while (i < 255) {
        errno = 0;
        ptr = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(long), NULL);
        if (errno != 0 || ptr == 0) break;

        array[i] = memory_read_string(pid, ptr);
        if (!array[i]) break;

        i++;
    }

    array[i] = NULL;
    return array;
}

/* Write a string to traced process memory */
unsigned long memory_write_string(MemoryContext *ctx, const char *str) {
    if (!ctx || !str) return 0;

    int len = strlen(str) + 1;
    int words = (len + sizeof(long) - 1) / sizeof(long);

    for (int i = 0; i < words; i++) {
        long word = 0;
        int bytes_to_copy = (len - i * sizeof(long)) > sizeof(long) ?
                            sizeof(long) : (len - i * sizeof(long));
        memcpy(&word, str + i * sizeof(long), bytes_to_copy);

        if (ptrace(PTRACE_POKEDATA, ctx->pid, ctx->free_addr + i * sizeof(long), word) == -1) {
            return 0;
        }
    }

    unsigned long result = ctx->free_addr;
    ctx->free_addr += words * sizeof(long);
    return result;
}

/* Write an array of pointers to traced process memory */
unsigned long memory_write_pointer_array(MemoryContext *ctx, unsigned long *pointers, int count) {
    if (!ctx || !pointers || count < 0) return 0;

    unsigned long base = ctx->free_addr;

    for (int i = 0; i < count; i++) {
        if (ptrace(PTRACE_POKEDATA, ctx->pid, base + i * sizeof(long), pointers[i]) == -1) {
            return 0;
        }
    }

    /* Add NULL terminator */
    if (ptrace(PTRACE_POKEDATA, ctx->pid, base + count * sizeof(long), 0) == -1) {
        return 0;
    }

    ctx->free_addr += (count + 1) * sizeof(long);
    return base;
}

/* Free memory allocated by read operations */
void memory_free_string(char *str) {
    free(str);
}

void memory_free_string_array(char **array) {
    if (!array) return;

    for (int i = 0; array[i] != NULL; i++) {
        free(array[i]);
    }
    free(array);
}
