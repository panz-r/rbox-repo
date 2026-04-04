/*
 * progname.c - Program name handling
 * Provides g_progname which is set from argv[0] in main()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *g_progname = "readonlybox-ptrace";

void progname_set(const char *name) {
    if (name && name[0]) {
        const char *basename = strrchr(name, '/');
        g_progname = basename ? basename + 1 : name;
    }
}
