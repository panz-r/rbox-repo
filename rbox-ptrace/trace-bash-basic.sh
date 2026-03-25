#!/bin/bash
# Run bash under readonlybox-ptrace with basic security restrictions:
# - Network access blocked
# - Memory limited to 1GB
# - Landlock restricts filesystem access
#
# Usage: ./trace-bash-basic.sh [bash args...]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PTRACE="$SCRIPT_DIR/readonlybox-ptrace"

if [ ! -x "$PTRACE" ]; then
    echo "Error: readonlybox-ptrace not built. Run 'make' first."
    exit 1
fi

exec "$PTRACE" \
    --no-network \
    --memory-limit 1G \
    --landlock-paths /w:rwx,/usr/bin:rx,/lib64:rx,/usr/lib:rx,/etc:ro,/tmp:rw,/proc:ro,/dev/null:rw \
    -- \
    bash "$@"
