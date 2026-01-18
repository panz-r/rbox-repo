#!/bin/bash
# Quick test script for readonlybox server and client
# Tests blocking behavior - client waits for server decision

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Cleanup
pkill -9 readonlybox-server 2>/dev/null || true
rm -f /tmp/readonlybox.sock

# Use debug-tui mode for testing (simulates TUI decisions after 30s timeout)
echo "=== Starting readonlybox-server in debug-tui mode ==="
"$ROOT_DIR/readonlybox-server" --debug-tui -vv &
SERVER_PID=$!
sleep 1

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
}
trap cleanup EXIT

echo ""
echo "=== Test 1: Blocked command (rm - immediate denial) ==="
time LD_PRELOAD="$ROOT_DIR/internal/client/libreadonlybox_client.so" sh -c 'rm /tmp/testfile' 2>&1 || true

echo ""
echo "=== Test 2: Unknown command (python3 - waits 30s for debug auto-allow) ==="
time LD_PRELOAD="$ROOT_DIR/internal/client/libreadonlybox_client.so" sh -c 'python3 --version'

echo ""
echo "=== Test 3: Fast allow command (ls - immediate) ==="
time LD_PRELOAD="$ROOT_DIR/internal/client/libreadonlybox_client.so" ls /tmp | head -1

echo ""
echo "=== All tests completed ==="
