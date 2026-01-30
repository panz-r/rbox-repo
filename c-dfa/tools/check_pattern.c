#include <stdio.h>
#include <string.h>

// Simple pattern parser to see how commands.txt is being interpreted

int main() {
    FILE* f = fopen("commands.txt", "r");
    if (!f) return 1;
    
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == 0) continue;
        
        // Check for cat capture pattern
        if (strstr(line, "cat") && strstr(line, "FILENAME")) {
            printf("Pattern line: '%s'\n", line);
            
            // Parse the pattern part (after the category)
            char* pattern = strstr(line, "] ");
            if (pattern) {
                pattern += 2; // Skip "] "
                printf("  Pattern: '%s'\n", pattern);
                
                // Show each character
                printf("  Chars: ");
                for (int i = 0; pattern[i]; i++) {
                    printf("%d ", (int)(unsigned char)pattern[i]);
                }
                printf("\n");
            }
        }
    }
    
    fclose(f);
    return 0;
}
