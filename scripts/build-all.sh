#!/bin/bash
# Build all readonlybox components

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "Building readonlybox-server..."
cd cmd/readonlybox-server
go build -o ../../readonlybox-server .

echo "Building libreadonlybox_client.so..."
cd ../../internal/client
gcc -shared -fPIC -O2 -o libreadonlybox_client.so client.c -pthread

echo ""
echo "Build complete!"
echo ""
echo "Binaries:"
echo "  - ./readonlybox-server"
echo "  - ./internal/client/libreadonlybox_client.so"
echo ""
echo "Usage:"
echo "  # Start server in very verbose mode"
echo "  ./readonlybox-server -vv"
echo ""
echo "  # Test with client"
echo "  LD_PRELOAD=./internal/client/libreadonlybox_client.so sh -c 'rm /tmp/testfile'"
