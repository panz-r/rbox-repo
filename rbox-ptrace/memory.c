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
#include <limits.h>

#include "memory.h"
#include "debug.h"

/*
 * Memory string read limit.
 * PATH_MAX is the maximum length of a full pathname on Linux (typically 4096).
 * We use this as the limit to prevent truncation of path arguments.
 */
#define MEMORY_STRING_MAX PATH_MAX

/* Initialize memory context for a traced process */
int memory_init(MemoryContext *ctx, pid_t pid, unsigned long stack_pointer) {
    if (!ctx) return -1;

    ctx->pid = pid;
    ctx->stack_base = stack_pointer;
    /* Use stack area with margin for our data */
    ctx->free_addr = stack_pointer - 8192;

    return 0;
}

/* Read a string from traced process memory.
 * Returns a newly allocated string that must be freed by the caller.
 * Strings longer than MEMORY_STRING_MAX - 1 are truncated.
 */
char *memory_read_string(pid_t pid, unsigned long addr) {
    if (addr == 0) return NULL;

    char *buffer = malloc(MEMORY_STRING_MAX);
    if (!buffer) return NULL;

    unsigned long word;
    int offset = 0;

    while (offset < MEMORY_STRING_MAX - 1) {
        errno = 0;
        word = ptrace(PTRACE_PEEKDATA, pid, addr + offset, NULL);
        if (errno != 0) {
            DEBUG_PRINT("memory_read_string: ptrace PEEKDATA failed at addr=0x%lx: %s\n",
                        addr + offset, strerror(errno));
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

    buffer[MEMORY_STRING_MAX - 1] = '\0';
    return buffer;
}

/* Read a null-terminated array of strings from traced process memory */
char **memory_read_string_array(pid_t pid, unsigned long addr) {
    unsigned long *addrs;
    char **result = memory_read_string_array_with_addrs(pid, addr, &addrs);
    free(addrs);
    return result;
}

/* Read a null-terminated array of strings and also store addresses */
char **memory_read_string_array_with_addrs(pid_t pid, unsigned long addr, unsigned long **out_addrs) {
    if (addr == 0) {
        if (out_addrs) *out_addrs = NULL;
        return NULL;
    }

    /* Limit to 1024 env vars to prevent excessive memory allocation
     * This is well beyond typical needs (usually < 50) and exceeds the
     * server protocol limit of 256, so no legitimate use case should be affected. */
#define MAX_ENV_ARRAY_SIZE 1024
    char **array = malloc(MAX_ENV_ARRAY_SIZE * sizeof(char *));
    unsigned long *addrs = malloc(MAX_ENV_ARRAY_SIZE * sizeof(unsigned long));
    if (!array || !addrs) {
        free(array);
        free(addrs);
        return NULL;
    }

    unsigned long ptr;
    int i = 0;

    while (i < MAX_ENV_ARRAY_SIZE - 1) {
        errno = 0;
        ptr = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(long), NULL);
        if (errno != 0 || ptr == 0) break;

        addrs[i] = ptr;
        array[i] = memory_read_string(pid, ptr);
        if (!array[i]) break;

        i++;
    }

    array[i] = NULL;
    addrs[i] = 0;

    if (out_addrs) {
        *out_addrs = addrs;
    } else {
        free(addrs);
    }

    return array;
}

/* Allocate space in traced process memory */
unsigned long memory_alloc(MemoryContext *ctx, size_t size) {
    if (!ctx) return 0;
    
    /* Align to 8 bytes */
    size_t aligned_size = (size + 7) & ~7;
    if (aligned_size < 8) aligned_size = 8;
    
    unsigned long addr = ctx->free_addr;
    ctx->free_addr += aligned_size;
    
    return addr;
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

        unsigned long addr = ctx->free_addr + i * sizeof(long);
        errno = 0;
        if (ptrace(PTRACE_POKEDATA, ctx->pid, addr, word) == -1) {
            DEBUG_PRINT("memory_write_string: ptrace POKEDATA failed at addr=0x%lx: %s\n",
                        addr, strerror(errno));
            return 0;
        }
    }

    unsigned long result = ctx->free_addr;
    ctx->free_addr += words * sizeof(long);
    return result;
}

/* Write a pointer to traced process memory at a specific address */
int memory_write_pointer_at(MemoryContext *ctx, unsigned long addr, unsigned long value) {
    if (!ctx || addr == 0) return -1;
    
    errno = 0;
    if (ptrace(PTRACE_POKEDATA, ctx->pid, addr, value) == -1) {
        DEBUG_PRINT("memory_write_pointer_at: ptrace POKEDATA failed at addr=0x%lx: %s\n",
                    addr, strerror(errno));
        return -1;
    }
    return 0;
}

/* Write an array of pointers to traced process memory */
unsigned long memory_write_pointer_array(MemoryContext *ctx, unsigned long *pointers, int count) {
    if (!ctx || !pointers || count < 0) return 0;

    unsigned long base = ctx->free_addr;

    for (int i = 0; i < count; i++) {
        unsigned long addr = base + i * sizeof(long);
        errno = 0;
        if (ptrace(PTRACE_POKEDATA, ctx->pid, addr, pointers[i]) == -1) {
            DEBUG_PRINT("memory_write_pointer_array: ptrace POKEDATA failed at addr=0x%lx: %s\n",
                        addr, strerror(errno));
            return 0;
        }
    }

    /* Add NULL terminator */
    unsigned long null_addr = base + count * sizeof(long);
    errno = 0;
    if (ptrace(PTRACE_POKEDATA, ctx->pid, null_addr, 0) == -1) {
        DEBUG_PRINT("memory_write_pointer_array: ptrace POKEDATA NULL terminator failed at addr=0x%lx: %s\n",
                    null_addr, strerror(errno));
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

/* Free addresses array */
void memory_free_ulong_array(unsigned long *array) {
    free(array);
}
