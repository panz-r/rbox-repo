#!/bin/bash
# Generate seed corpus for dfa_eval_fuzzer
# Format: [dfa_size:4][dfa_data][num_strings:2][string_len:2][string]...

set -e

DFA_FILE="../readonlybox.dfa"
OUTPUT_DIR="corpus/seed/dfa_binary"

mkdir -p "$OUTPUT_DIR"

# Test strings to include
STRINGS=(
    "git status"
    "ls -la"
    "cat file.txt"
    "ps aux"
    "df -h"
    "du -sh *"
    "find . -name '*.c'"
    "grep pattern file"
    "echo hello"
    "pwd"
)

# Generate a single corpus file with all strings
generate_file() {
    local output="$1"
    local dfa_size=$(stat -c%s "$DFA_FILE")
    
    # Write DFA size (little-endian 4 bytes)
    printf "\\x$(printf '%02x' $((dfa_size & 0xFF)))"
    printf "\\x$(printf '%02x' $(((dfa_size >> 8) & 0xFF)))"
    printf "\\x$(printf '%02x' $(((dfa_size >> 16) & 0xFF)))"
    printf "\\x$(printf '%02x' $(((dfa_size >> 24) & 0xFF)))"
    
    # Write DFA data
    cat "$DFA_FILE"
    
    # Write number of strings (little-endian 2 bytes)
    local num_strings=${#STRINGS[@]}
    printf "\\x$(printf '%02x' $((num_strings & 0xFF)))"
    printf "\\x$(printf '%02x' $(((num_strings >> 8) & 0xFF)))"
    
    # Write each string
    for str in "${STRINGS[@]}"; do
        local len=${#str}
        # String length (little-endian 2 bytes)
        printf "\\x$(printf '%02x' $((len & 0xFF)))"
        printf "\\x$(printf '%02x' $(((len >> 8) & 0xFF)))"
        # String data
        printf "%s" "$str"
    done
} > "$OUTPUT_DIR/seed_001.bin"

echo "Generated seed corpus in $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"
