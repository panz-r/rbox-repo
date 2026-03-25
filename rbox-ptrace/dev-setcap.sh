#!/bin/bash
# Development script: Set capabilities on local readonlybox-ptrace binary
# This is for DEVELOPMENT/TESTING only - not for installation
# Usage: ./dev-setcap.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$SCRIPT_DIR/readonlybox-ptrace"

if [ ! -f "$BINARY" ]; then
    echo "Error: readonlybox-ptrace binary not found. Run 'make' first."
    exit 1
fi

echo "Setting capabilities on $BINARY..."
sudo setcap cap_sys_ptrace,cap_sys_admin+eip "$BINARY"
echo "Done. You can now run ./readonlybox-ptrace without sudo."
