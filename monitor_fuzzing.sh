#!/bin/bash
echo "=== Monitoring pattern parser fuzzing ==="
echo "Time: $(date)"
echo ""

echo "Fuzzer processes:"
ps aux | grep pattern_parse_fuzzer | grep -v grep | wc -l

echo ""
echo "Crashes found:"
find c-dfa/fuzz/crashes -type f 2>/dev/null | wc -l

echo ""
echo "Interesting corpus growth:"
find c-dfa/fuzz/corpus/interesting -type f 2>/dev/null | wc -l

echo ""
echo "Latest fuzzer log tail (fuzz-3.log):"
tail -20 c-dfa/fuzz/fuzz-3.log 2>/dev/null || echo "No log yet"

echo ""
echo "=== Press Ctrl+C to stop monitoring ==="
