/**
 * golden_utils.c - Shared golden file utilities for tests
 */

#include "golden_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char* golden_get_dir(const char* subdir) {
    static char path[512];
    
    // Try relative path from build directory first
    snprintf(path, sizeof(path), "../golden/%s", subdir);
    if (access(path, F_OK) == 0) {
        return path;
    }
    
    // Fall back to path from c-dfa/ (CTest working dir)
    snprintf(path, sizeof(path), "golden/%s", subdir);
    return path;
}

char* golden_load(const char* dir, const char* filename) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, filename);
    
    FILE* f = fopen(path, "r");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    
    size_t n = fread(buf, 1, (size_t)sz, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}
