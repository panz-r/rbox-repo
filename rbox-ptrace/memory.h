/*
 * memory.h - Process memory operations for ptrace client
 *
 * IMPLEMENTATION LIMITS:
 * - Maximum string length: PATH_MAX (typically 4096 on Linux)
 * - Maximum env array size: 1024 entries (prevents truncation while bounding allocation)
 * - Stack assumption: memory_init() reserves STACK_RESERVE bytes below the stack pointer.
 *   This assumes the stack has sufficient grow-down space. On Linux, stacks are
 *   typically 8MB and grow down from high addresses, so 8KB is safe.
 *
 * These limits are architectural constraints that prevent unbounded memory
 * allocation when dealing with untrusted process memory.
 */

#ifndef READONLYBOX_PTRACE_MEMORY_H
#define READONLYBOX_PTRACE_MEMORY_H

#include <sys/types.h>
#include <stdint.h>

/* Memory context for writing to traced process */
typedef struct {
    pid_t pid;
    unsigned long free_addr;
    unsigned long stack_base;
} MemoryContext;

/* Initialize memory context for a traced process */
int memory_init(MemoryContext *ctx, pid_t pid, unsigned long stack_pointer);

/* Read a string from traced process memory */
char *memory_read_string(pid_t pid, unsigned long addr);

/* Read a null-terminated array of strings from traced process memory */
char **memory_read_string_array(pid_t pid, unsigned long addr);

/* Read a null-terminated array of strings and also store addresses */
char **memory_read_string_array_with_addrs(pid_t pid, unsigned long addr, unsigned long **out_addrs);

/* Write a string to traced process memory */
unsigned long memory_write_string(MemoryContext *ctx, const char *str);

/* Allocate space in traced process memory */
unsigned long memory_alloc(MemoryContext *ctx, size_t size);

/* Write an array of pointers to traced process memory */
unsigned long memory_write_pointer_array(MemoryContext *ctx, unsigned long *pointers, int count);

/* Write a pointer to traced process memory at a specific address */
int memory_write_pointer_at(MemoryContext *ctx, unsigned long addr, unsigned long value);

/* Free memory allocated by read operations */
void memory_free_string(char *str);
void memory_free_string_array(char **array);

/* Free addresses array */
void memory_free_ulong_array(unsigned long *array);

#endif /* READONLYBOX_PTRACE_MEMORY_H */
