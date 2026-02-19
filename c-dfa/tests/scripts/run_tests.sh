#!/bin/bash
TESTS=(
    "cp src dst"
    "mv file1 file2"
    "echo hello world"
    "touch file"
    "ls -la /tmp"
    "cat test.txt"
    "head -n 20"
    "head -n 5"
    "mkdir testdir"
    "ls -a path"
)

for input in "${TESTS[@]}"; do
    echo ""
    echo "=== Input: '$input' ==="
    ./test_capture_edge capture_edge.dfa "$input" 2>&1 | grep -A 10 "Result:"
done
