#!/bin/bash
# Run rbox-protocol fuzzer with timeout and memory monitoring
# Uses ulimit instead of cgroups (for environments without cgroup access)

set -e

FUZZER="${FUZZER:-./protocol_fuzzer}"
CORPUS="${CORPUS:-corpus/seed}"
MAX_TIME="${MAX_TIME:-1800}"  # 30 minutes default

# Memory limit via ulimit (2GB virtual, 1GB resident)
ulimit -v 2097152  # 2GB virtual
ulimit -m 1048576  # 1GB resident

echo "Starting fuzzer for ${MAX_TIME} seconds..."
echo "Memory limits: virtual=2GB, resident=1GB"

timeout --signal=TERM "$MAX_TIME" "$FUZZER" "$CORPUS" -merge=corpus/interesting -artifact_prefix=crashes/ -max_len=4096 -jobs=4 -workers=4

echo ""
echo "Fuzzing complete!"
echo ""
echo "Corpus in corpus/interesting/"
ls -la corpus/interesting/ 2>/dev/null || echo "(none)"
echo ""
echo "Crashes in crashes/"
ls -la crashes/ 2>/dev/null || echo "(none)"
