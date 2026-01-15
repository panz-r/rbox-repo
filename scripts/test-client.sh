#!/bin/bash
# Quick test script for readonlybox server and client

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Cleanup
pkill -9 readonlybox-server 2>/dev/null || true
rm -f /tmp/readonlybox.sock

echo "=== Starting readonlybox-server in very verbose mode ==="
"$ROOT_DIR/readonlybox-server" -vv &
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
echo "=== Test 1: Blocked command (rm) ==="
LD_PRELOAD="$ROOT_DIR/internal/client/libreadonlybox_client.so" sh -c 'rm /tmp/testfile' 2>&1 || true

echo ""
echo "=== Test 2: Allowed command (ls) ==="
LD_PRELOAD="$ROOT_DIR/internal/client/libreadonlybox_client.so" ls /tmp | head -3

echo ""
echo "=== Test 3: Another allowed command (cat) ==="
LD_PRELOAD="$ROOT_DIR/internal/client/libreadonlybox_client.so" cat /etc/hostname

echo ""
echo "=== All tests completed ==="
