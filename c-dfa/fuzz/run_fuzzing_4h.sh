#!/bin/bash
# Run fuzzing session with round-robin worker model
# Each worker cycles through all fuzzers, running 144 cases per slot
# Usage: ./run_fuzzing_4h.sh [workers] [total_duration]
# Default: 2 workers, 4 hours total

set -e

WORKERS="${1:-2}"
TOTAL_DURATION="${2:-14400}"
RUNS_PER_SLOT=144

FUZZERS=(dfa pattern nfa-build pipeline loader)

declare -A FUZZER_BIN
declare -A CORPUS
declare -A INTERESTING
declare -A ARTIFACT_PREFIX
declare -A MAX_LEN
declare -A USE_DICT

FUZZER_BIN[dfa]="./dfa_eval_fuzzer"
CORPUS[dfa]="corpus/seed/dfa_binary"
INTERESTING[dfa]="corpus/interesting/dfa_binary"
ARTIFACT_PREFIX[dfa]="crashes/dfa_eval_"
MAX_LEN[dfa]=131072
USE_DICT[dfa]="yes"

FUZZER_BIN[pattern]="./pattern_parse_fuzzer"
CORPUS[pattern]="corpus/seed/pattern_parser"
INTERESTING[pattern]="corpus/interesting/pattern_parser"
ARTIFACT_PREFIX[pattern]="crashes/pattern_parse_"
MAX_LEN[pattern]=8192
USE_DICT[pattern]="no"

FUZZER_BIN[nfa-build]="./nfa_build_fuzzer"
CORPUS[nfa-build]="corpus/seed/pattern_parser"
INTERESTING[nfa-build]="corpus/interesting/nfa_build"
ARTIFACT_PREFIX[nfa-build]="crashes/nfa_build_"
MAX_LEN[nfa-build]=32768
USE_DICT[nfa-build]="no"

FUZZER_BIN[pipeline]="./pipeline_fuzzer"
CORPUS[pipeline]="corpus/seed/pattern_parser"
INTERESTING[pipeline]="corpus/interesting/pipeline"
ARTIFACT_PREFIX[pipeline]="crashes/pipeline_"
MAX_LEN[pipeline]=4096
USE_DICT[pipeline]="no"

FUZZER_BIN[loader]="./dfa_loader_fuzzer"
CORPUS[loader]="corpus/seed/dfa_binary"
INTERESTING[loader]="corpus/interesting/loader"
ARTIFACT_PREFIX[loader]="crashes/loader_"
MAX_LEN[loader]=65536
USE_DICT[loader]="no"

LOG_DIR="logs/worker_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

echo "========================================"
echo "Round-Robin Fuzzing Session"
echo "========================================"
echo "Workers: $WORKERS"
echo "Duration: $TOTAL_DURATION seconds"
echo "Runs per slot: $RUNS_PER_SLOT"
echo "Fuzzers: ${FUZZERS[*]}"
echo "========================================"

cleanup() {
    echo "Cleaning up..."
    pkill -f "dfa_eval_fuzzer" 2>/dev/null || true
    pkill -f "pattern_parse_fuzzer" 2>/dev/null || true
    pkill -f "nfa_build_fuzzer" 2>/dev/null || true
    pkill -f "pipeline_fuzzer" 2>/dev/null || true
    pkill -f "dfa_loader_fuzzer" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for fuzzer in "${FUZZERS[@]}"; do
    if [ ! -f "${FUZZER_BIN[$fuzzer]}" ]; then
        echo "Building fuzzers..."
        make all
        break
    fi
done

START_TIME=$(date +%s)
WORKER_PIDS=()

for w in $(seq 0 $((WORKERS - 1))); do
    (
        fuzzer_idx=0
        slot=0
        
        while true; do
            elapsed=$(($(date +%s) - $START_TIME))
            if [ $elapsed -ge $TOTAL_DURATION ]; then
                break
            fi
            
            fuzzer="${FUZZERS[$fuzzer_idx]}"
            slot=$((slot + 1))
            round=$((slot / ${#FUZZERS[@]}))
            
            log_file="$LOG_DIR/worker_${w}_s${slot}_${fuzzer}.log"
            mkdir -p "${INTERESTING[$fuzzer]}"
            
            FUZZER_ARGS=(
                "${CORPUS[$fuzzer]}"
                "-merge=${INTERESTING[$fuzzer]}"
                "-artifact_prefix=${ARTIFACT_PREFIX[$fuzzer]}"
                "-max_len=${MAX_LEN[$fuzzer]}"
                "-runs=$RUNS_PER_SLOT"
                "-jobs=1"
                "-workers=1"
                "-print_final_stats=1"
                "-rss_limit_mb=4096"
                "-ignore_crashes=1"
            )
            
            if [ "${USE_DICT[$fuzzer]}" = "yes" ] && [ -f "cmd_dict.txt" ]; then
                FUZZER_ARGS+=("-dict=cmd_dict.txt")
            fi
            
            ./run_in_cgroup.sh "${FUZZER_BIN[$fuzzer]}" "${FUZZER_ARGS[@]}" > "$log_file" 2>&1 || true
            
            fuzzer_idx=$(( (fuzzer_idx + 1) % ${#FUZZERS[@]} ))
            if [ $((slot % ${#FUZZERS[@]})) -eq 0 ]; then
                echo "w${w} round $round done" >> "$LOG_DIR/worker_${w}_summary.log"
            fi
        done
    ) &
    WORKER_PIDS+=($!)
done

for pid in "${WORKER_PIDS[@]}"; do
    wait $pid || true
done

echo ""
echo "========================================"
echo "COMPLETED"
echo "========================================"
echo "Logs: $LOG_DIR/"

echo ""
echo "Rounds completed per worker:"
for w in $(seq 0 $((WORKERS - 1))); do
    if [ -f "$LOG_DIR/worker_${w}_summary.log" ]; then
        count=$(wc -l < "$LOG_DIR/worker_${w}_summary.log")
        echo "  Worker $w: $count rounds"
    fi
done

echo ""
echo "Crash summary:"
for fuzzer in "${FUZZERS[@]}"; do
    count=$(find crashes/ -name "${ARTIFACT_PREFIX[$fuzzer]}*" -type f 2>/dev/null | wc -l)
    echo "  $fuzzer: $count crashes"
done
