#!/bin/bash
# Launch rbox-protocol fuzzer with timeout and memory monitoring
# Uses ulimit for memory limits (fallback for environments without cgroups)
#
# Usage:
#   ./run_fuzzing.sh [--fuzzer <path>] [--corpus <path>] [--max-time <seconds>] [--dry-run]
#   ./run_fuzzing.sh --help
#
# Arguments:
#   --fuzzer      Path to fuzzer binary (default: ./protocol_fuzzer)
#   --corpus      Seed corpus directory (default: ./corpus/seed)
#   --max-time    Fuzzing runtime in seconds (default: 1800)
#   --dry-run     Show what would be run without executing
#
# Output:
#   Corpus updates in ./corpus/interesting/
#   Crashes in ./crashes/

set -euo pipefail

# --- Defaults ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FUZZER="$SCRIPT_DIR/protocol_fuzzer"
CORPUS="$SCRIPT_DIR/corpus/seed"
MAX_TIME=1800  # 30 minutes default
DRY_RUN=false

# --- Parse Arguments ---
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --help)
            echo "Usage: ./run_fuzzing.sh [--fuzzer <path>] [--corpus <path>] [--max-time <seconds>] [--dry-run]"
            echo ""
            echo "Arguments:"
            echo "  --fuzzer      Path to fuzzer binary (default: ./protocol_fuzzer)"
            echo "  --corpus      Seed corpus directory (default: ./corpus/seed)"
            echo "  --max-time    Fuzzing runtime in seconds (default: 1800)"
            echo "  --dry-run     Show what would be run without executing"
            echo ""
            echo "Example:"
            echo "  ./run_fuzzing.sh --max-time 3600 --dry-run"
            exit 0
            ;;
        --fuzzer) FUZZER="$2"; shift ;;
        --corpus) CORPUS="$2"; shift ;;
        --max-time) MAX_TIME="$2"; shift ;;
        --dry-run) DRY_RUN=true ;;
        *)
            echo "ERROR: Unknown argument $1"
            echo "Use --help for usage instructions."
            exit 1
            ;;
    esac
    shift
done

# --- Dry Run ---
if [ "$DRY_RUN" == "true" ]; then
    echo "DRY RUN: Would run fuzzer with:"
    echo "  Fuzzer: $FUZZER"
    echo "  Corpus: $CORPUS"
    echo "  Max Time: $MAX_TIME seconds"
    echo "  Args: -merge=$SCRIPT_DIR/corpus/interesting -artifact_prefix=$SCRIPT_DIR/crashes/ -max_len=4096 -jobs=4 -workers=4"
    exit 0
fi

# --- Validate fuzzer binary ---
if [ ! -x "$FUZZER" ]; then
    echo "ERROR: Fuzzer $FUZZER is not executable or does not exist."
    echo "Building protocol_fuzzer..."
    make
    if [ ! -x "$FUZZER" ]; then
        echo "ERROR: Failed to build fuzzer."
        exit 1
    fi
fi

# --- Validate corpus directory ---
if [ ! -d "$CORPUS" ]; then
    echo "ERROR: Corpus directory $CORPUS does not exist."
    exit 1
fi

# --- Set memory limits via ulimit (2GB virtual, 1GB resident) ---
if ! ulimit -v 2097152; then  # 2GB virtual
    echo "ERROR: Failed to set virtual memory limit."
    exit 1
fi
if ! ulimit -m 1048576; then  # 1GB resident
    echo "ERROR: Failed to set resident memory limit."
    exit 1
fi

# --- Cleanup handler ---
FUZZER_PID=""
WATCHDOG_PID=""
cleanup() {
    echo "Cleaning up..."
    if [ -n "$FUZZER_PID" ]; then
        pkill -P "$FUZZER_PID" 2>/dev/null || true
        wait "$FUZZER_PID" 2>/dev/null || true
    fi
    if [ -n "$WATCHDOG_PID" ]; then
        kill "$WATCHDOG_PID" 2>/dev/null || true
    fi
    echo "Cleanup complete."
}
trap cleanup EXIT SIGINT SIGTERM

# --- Start fuzzer and watchdog ---
echo "Starting fuzzer for ${MAX_TIME} seconds..."
echo "Memory limits: virtual=2GB, resident=1GB"

# Launch fuzzer in background
"$FUZZER" "$CORPUS" -merge="$SCRIPT_DIR/corpus/interesting" \
  -artifact_prefix="$SCRIPT_DIR/crashes/" \
  -max_len=4096 -jobs=4 -workers=4 >fuzz.log 2>&1 &
FUZZER_PID=$!

# Launch memory watchdog (target the fuzzer PID)
WATCHDOG_TARGET_PID=$FUZZER_PID "$SCRIPT_DIR/memory_watchdog.sh" &
WATCHDOG_PID=$!

# Wait for fuzzer to complete OR timeout
# Start a background timer that will kill the fuzzer if timeout is reached
(
    sleep "$MAX_TIME"
    echo "Timeout reached, sending TERM to fuzzer..."
    kill -TERM "$FUZZER_PID" 2>/dev/null || true
) &
TIMER_PID=$!

# Wait for fuzzer to finish (either naturally or from timeout)
wait "$FUZZER_PID" 2>/dev/null
FUZZER_EXIT=$?

# Kill timer if still running
kill "$TIMER_PID" 2>/dev/null || true
wait "$TIMER_PID" 2>/dev/null || true

if [ $FUZZER_EXIT -eq 128 ] || [ $FUZZER_EXIT -eq 143 ] || [ $FUZZER_EXIT -eq 137 ]; then
    # Signal exit (143 = 128 + 15 SIGTERM, 137 = 128 + 9 SIGKILL)
    echo "Fuzzer timed out after ${MAX_TIME} seconds."
else
    echo "Fuzzer completed normally."
fi

# Cleanup is handled automatically by the trap
