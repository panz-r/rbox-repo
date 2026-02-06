/*
 * memory.h - Process memory operations for ptrace client
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

/* Write a string to traced process memory */
unsigned long memory_write_string(MemoryContext *ctx, const char *str);

/* Write an array of pointers to traced process memory */
unsigned long memory_write_pointer_array(MemoryContext *ctx, unsigned long *pointers, int count);

/* Free memory allocated by read operations */
void memory_free_string(char *str);
void memory_free_string_array(char **array);

#endif /* READONLYBOX_PTRACE_MEMORY_H */
