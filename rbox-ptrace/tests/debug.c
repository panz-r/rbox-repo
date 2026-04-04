/*
 * debug.c - Debug utilities stub for tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

FILE *g_debug_file = NULL;
int g_verbose_level = 0;

void debug_init(void) {
    if (g_debug_file) return;
    /* Stub implementation - debug output goes to /dev/null during tests */
    int fd = open("/dev/null", O_WRONLY);
    if (fd >= 0) {
        g_debug_file = fdopen(fd, "w");
    }
}
