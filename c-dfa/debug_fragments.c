#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

// Simplified fragment storage for debugging
#define MAX_FRAGMENTS 100
#define MAX_FRAGMENT_NAME 64
#define MAX_FRAGMENT_VALUE 512

typedef struct {
    char name[MAX_FRAGMENT_NAME];
    char value[MAX_FRAGMENT_VALUE];
} fragment_t;

static fragment_t fragments[MAX_FRAGMENTS];
static int fragment_count = 0;

static const char* find_fragment(const char* name) {
    for (int i = 0; i < fragment_count; i++) {
        if (strcmp(fragments[i].name, name) == 0) {
            return fragments[i].value;
        }
    }
    return NULL;
}

int main() {
    // Parse patterns_safe_commands.txt for fragments
    FILE* f = fopen("patterns_safe_commands.txt", "r");
    if (!f) {
        fprintf(stderr, "Cannot open patterns file\n");
        return 1;
    }
    
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') continue;
        
        // Check for fragment definition
        if (strncmp(line, "[fragment:", 10) == 0) {
            const char* name_start = line + 10;
            const char* name_end = strchr(name_start, ']');
            if (name_end && fragment_count < MAX_FRAGMENTS) {
                size_t name_len = name_end - name_start;
                if (name_len < MAX_FRAGMENT_NAME) {
                    strncpy(fragments[fragment_count].name, name_start, name_len);
                    fragments[fragment_count].name[name_len] = '\0';
                    
                    const char* value_start = name_end + 1;
                    while (*value_start == ' ' || *value_start == '\t') value_start++;
                    strncpy(fragments[fragment_count].value, value_start, MAX_FRAGMENT_VALUE - 1);
                    fragments[fragment_count].value[MAX_FRAGMENT_VALUE - 1] = '\0';
                    
                    // Remove trailing newline
                    size_t vlen = strlen(fragments[fragment_count].value);
                    if (vlen > 0 && fragments[fragment_count].value[vlen-1] == '\n') {
                        fragments[fragment_count].value[vlen-1] = '\0';
                    }
                    
                    if (strstr(fragments[fragment_count].name, "SAFE::FILENAME")) {
                        printf("Found fragment: [%s] = [%s]\n", 
                               fragments[fragment_count].name, 
                               fragments[fragment_count].value);
                    }
                    fragment_count++;
                }
            }
        }
    }
    fclose(f);
    
    // Look up SAFE::FILENAME
    const char* value = find_fragment("SAFE::FILENAME");
    if (value) {
        printf("\nSAFE::FILENAME expands to: '%s'\n", value);
        
        // Parse the character class manually
        printf("\nCharacter class parsing:\n");
        const char* p = value;
        if (*p == '[') {
            p++;
            printf("  Starts with '[' - character class detected\n");
            
            while (*p && *p != ']') {
                printf("  Char '%c' (%d)\n", *p, (int)(unsigned char)*p);
                p++;
            }
        }
    } else {
        printf("SAFE::FILENAME not found!\n");
    }
    
    return 0;
}
