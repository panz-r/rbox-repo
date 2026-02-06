#include <stdio.h>
#include <stdint.h>
#include "include/dfa_types.h"

int main() {
    printf("Structure Size Analysis:\n");
    printf("  sizeof(dfa_t): %zu\n", sizeof(dfa_t));
    printf("  sizeof(dfa_state_t): %zu\n", sizeof(dfa_state_t));
    printf("  sizeof(dfa_transition_t): %zu\n", sizeof(dfa_transition_t));
    
    // Manually calculate dfa_t size
    printf("\nManual dfa_t calculation:\n");
    printf("  magic: 4 bytes (offset 0)\n");
    printf("  version: 2 bytes (offset 4)\n");
    printf("  state_count: 2 bytes (offset 6)\n");
    printf("  initial_state: 4 bytes (offset 8)\n");
    printf("  accepting_mask: 4 bytes (offset 12)\n");
    printf("  flags: 2 bytes (offset 16)\n");
    printf("  identifier_length: 1 byte (offset 18)\n");
    printf("  identifier[0]: 1 byte (offset 19)\n");
    
    // Check alignment
    printf("\nAlignment analysis:\n");
    printf("  After identifier_length (offset 18), next is uint32_t at offset 19\n");
    printf("  This requires 4-byte alignment, so offset 19 needs padding\n");
    printf("  Likely sizeof(dfa_t) = 20, 24, or 28 depending on packing\n");
    
    // With identifier
    printf("\nWith 6-byte identifier:\n");
    printf("  Total header = 19 + 6 = 25 bytes\n");
    printf("  State array starts at offset 25\n");
    
    // If using sizeof(dfa_t) = 20
    printf("\nIf code uses sizeof(dfa_t) = 20:\n");
    printf("  States would be written at offset 20 (WRONG!)\n");
    printf("  Bytes 20-24 would be identifier bytes, not state data\n");
    printf("  This would corrupt the file!\n");
    
    return 0;
}
