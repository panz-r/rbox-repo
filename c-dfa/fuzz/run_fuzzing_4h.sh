#!/bin/bash
# Run fuzzing session for 4 hours with full protection
# Usage: ./run_fuzzing_4h.sh [dfa|pattern|nfa-build]

set -e

FUZZER_TYPE="${1:-dfa}"
DURATION=14400  # 4 hours in seconds
MEMORY_LIMIT="${FUZZ_MEMORY_LIMIT:-8G}"

# Create log directory
LOG_DIR="logs/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

echo "========================================"
echo "ReadOnlyBox Fuzzing Session"
echo "========================================"
echo "Fuzzer: $FUZZER_TYPE"
echo "Duration: 4 hours"
echo "Memory limit: $MEMORY_LIMIT"
echo "Log directory: $LOG_DIR"
echo "========================================"

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "========================================"
    echo "Fuzzing session ending"
    echo "========================================"
    # Kill watchdog if running
    if [ -n "$WATCHDOG_PID" ]; then
        kill "$WATCHDOG_PID" 2>/dev/null || true
        wait "$WATCHDOG_PID" 2>/dev/null || true
    fi
    # Show summary
    if [ -f "$LOG_DIR/crashes.log" ]; then
        echo "Crashes found: $(wc -l < "$LOG_DIR/crashes.log")"
    fi
}
trap cleanup EXIT INT TERM

# Build command based on fuzzer type
case "$FUZZER_TYPE" in
    dfa)
        FUZZER_BIN="./dfa_eval_fuzzer"
        CORPUS="corpus/seed/dfa_eval"
        INTERESTING="corpus/interesting/dfa_eval"
        ARTIFACT_PREFIX="crashes/dfa_eval_"
        MAX_LEN=4096
        JOBS=4
        ;;
    pattern)
        FUZZER_BIN="./pattern_parse_fuzzer"
        CORPUS="corpus/seed/pattern_parser"
        INTERESTING="corpus/interesting/pattern_parser"
        ARTIFACT_PREFIX="crashes/pattern_parse_"
        MAX_LEN=8192
        JOBS=4
        ;;
    nfa-build)
        FUZZER_BIN="./nfa_build_fuzzer"
        CORPUS="corpus/seed/pattern_parser"
        INTERESTING="corpus/interesting/nfa_build"
        ARTIFACT_PREFIX="crashes/nfa_build_"
        MAX_LEN=32768
        JOBS=2
        ;;
    *)
        echo "Unknown fuzzer type: $FUZZER_TYPE"
        echo "Valid types: dfa, pattern, nfa-build"
        exit 1
        ;;
esac

# Check if fuzzer exists
if [ ! -f "$FUZZER_BIN" ]; then
    echo "Fuzzer not found: $FUZZER_BIN"
    echo "Building..."
    make all
fi

# Build fuzzer command
FUZZER_ARGS=(
    "$CORPUS"
    "-merge=$INTERESTING"
    "-artifact_prefix=$ARTIFACT_PREFIX"
    "-max_len=$MAX_LEN"
    "-max_total_time=$DURATION"
    "-jobs=$JOBS"
    "-workers=$JOBS"
    "-print_final_stats=1"
    "-rss_limit_mb=4096"
    "-ignore_crashes=1"
)

# Add dictionary for dfa fuzzer
if [ "$FUZZER_TYPE" = "dfa" ] && [ -f "cmd_dict.txt" ]; then
    FUZZER_ARGS+=("-dict=cmd_dict.txt")
fi

echo ""
echo "Starting fuzzer: $FUZZER_BIN ${FUZZER_ARGS[*]}"
echo ""

# Start the fuzzer in cgroup
./run_in_cgroup.sh "$FUZZER_BIN" "${FUZZER_ARGS[@]}" 2>&1 | tee "$LOG_DIR/fuzzer.log" &
FUZZER_PID=$!

# Start memory watchdog
WATCHDOG_TARGET_PID=$FUZZER_PID ./memory_watchdog.sh 2>&1 | tee "$LOG_DIR/watchdog.log" &
WATCHDOG_PID=$!

echo "Fuzzer PID: $FUZZER_PID"
echo "Watchdog PID: $WATCHDOG_PID"
echo ""
echo "To monitor progress: tail -f $LOG_DIR/fuzzer.log"
echo "To stop gracefully: kill -TERM $FUZZER_PID"
echo ""

# Wait for fuzzer to complete
wait "$FUZZER_PID"
FUZZER_EXIT=$?

echo ""
echo "Fuzzer exited with code: $FUZZER_EXIT"

# Show final stats
if [ -f "$LOG_DIR/fuzzer.log" ]; then
    echo ""
    echo "Final statistics:"
    grep -E "(Done|runs|cov|corp|units|slowest|max|rss)" "$LOG_DIR/fuzzer.log" | tail -20 || true
fi

exit $FUZZER_EXIT
