#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../include/dfa_types.h"

void dump_hex(const char* data, size_t offset, size_t len) {
    printf("  Offset %zu: ", offset);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02X ", (unsigned char)data[offset + i]);
    }
    printf("\n");
}

void dump_state(const char* base, size_t offset) {
    const dfa_state_t* state = (const dfa_state_t*)(base + offset);
    printf("  State at offset %zu:\n", offset);
    printf("    transitions_offset = %u (0x%X)\n", state->transitions_offset, state->transitions_offset);
    printf("    transition_count = %u\n", state->transition_count);
    printf("    flags = 0x%04X\n", state->flags);
    printf("    accepting_pattern_id = %u\n", state->accepting_pattern_id);
    printf("    eos_target = %u\n", state->eos_target);
    printf("    eos_marker_offset = %u\n", state->eos_marker_offset);
    
    uint8_t category = (state->flags >> 8) & 0xFF;
    printf("    Category mask = 0x%02X\n", category);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <dfa_file>\n", argv[0]);
        return 1;
    }
    
    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s\n", argv[1]);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* data = malloc(size);
    if (fread(data, 1, size, f) != size) {
        fprintf(stderr, "Failed to read file\n");
        fclose(f);
        free(data);
        return 1;
    }
    fclose(f);
    
    const dfa_t* dfa = (const dfa_t*)data;
    
    printf("=== DFA FILE ANALYSIS ===\n");
    printf("File size: %zu bytes\n", size);
    printf("Magic: 0x%08X (expected 0x%08X)\n", dfa->magic, DFA_MAGIC);
    printf("Version: %u\n", dfa->version);
    printf("State count: %u\n", dfa->state_count);
    printf("Initial state offset: %u\n", dfa->initial_state);
    printf("Accepting mask: 0x%08X\n", dfa->accepting_mask);
    printf("Identifier length: %u\n", dfa->identifier_length);
    printf("Metadata offset: %u\n", dfa->metadata_offset);
    
    if (dfa->identifier_length > 0 && dfa->identifier_length < 256) {
        printf("Identifier: ");
        for (uint8_t i = 0; i < dfa->identifier_length; i++) {
            printf("%c", dfa->identifier[i]);
        }
        printf("\n");
    }
    
    printf("\n=== STRUCT SIZES ===\n");
    printf("sizeof(dfa_t) = %zu\n", sizeof(dfa_t));
    printf("sizeof(dfa_state_t) = %zu\n", sizeof(dfa_state_t));
    printf("sizeof(dfa_rule_t) = %zu\n", sizeof(dfa_rule_t));
    
    printf("\n=== STATE OFFSETS ===\n");
    size_t state_size = sizeof(dfa_state_t);
    size_t rule_size = sizeof(dfa_rule_t);
    printf("Each state: %zu bytes\n", state_size);
    printf("Each rule: %zu bytes\n", rule_size);
    printf("Initial state offset (header + id): %zu + %u = %u\n", 
           sizeof(dfa_t), dfa->identifier_length, dfa->initial_state);
    
    printf("\n=== DUMPING STATES ===\n");
    for (uint16_t i = 0; i < dfa->state_count && i < 20; i++) {
        size_t offset = dfa->initial_state + i * state_size;
        printf("\nState %u:\n", i);
        dump_state(data, offset);
        
        if (((const dfa_state_t*)(data + offset))->transition_count > 0) {
            size_t rule_offset = ((const dfa_state_t*)(data + offset))->transitions_offset;
            printf("  Rules at offset %zu:\n", rule_offset);
            const dfa_rule_t* rule = (const dfa_rule_t*)(data + rule_offset);
            for (uint16_t r = 0; r < ((const dfa_state_t*)(data + offset))->transition_count && r < 5; r++) {
                printf("    Rule %u: type=%u, data1=0x%02X, data2=0x%02X, target=%u, marker=%u\n",
                       r, rule[r].type, rule[r].data1, rule[r].data2, rule[r].target, rule[r].marker_offset);
            }
        }
    }
    
    printf("\n=== RAW HEADER DUMP ===\n");
    dump_hex(data, 0, 32);
    
    printf("\n=== EXPECTED VS ACTUAL STATE 0 ===\n");
    size_t expected_state_0 = dfa->initial_state;
    printf("Expected state 0 offset: %zu\n", expected_state_0);
    dump_hex(data, expected_state_0, 32);
    
    free(data);
    return 0;
}
