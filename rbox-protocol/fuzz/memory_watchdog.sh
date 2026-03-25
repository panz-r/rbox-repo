#!/bin/bash
# Memory watchdog for rbox-protocol fuzzer
# Proactively kills fuzzer if memory usage exceeds threshold.
#
# Usage:
#   WATCHDOG_TARGET_PID=<pid> ./memory_watchdog.sh
#
# Environment:
#   WATCHDOG_TARGET_PID (required): PID to monitor
#   WATCHDOG_INTERVAL (default: 1): Check interval in seconds
#   WATCHDOG_THRESHOLD (default: 95): Memory % threshold
#   WATCHDOG_TIMEOUT (default: 86400): Max runtime in seconds (24h)
#   WATCHDOG_DRY_RUN (default: false): If true, log actions without killing
#
# Exit Codes:
#   0  - Target process exited normally
#   1  - Memory threshold exceeded (process killed)
#   2  - Invalid usage or missing WATCHDOG_TARGET_PID

set -euo pipefail

# --- Environment Variables ---
WATCHDOG_INTERVAL="${WATCHDOG_INTERVAL:-1}"
MEMORY_THRESHOLD="${WATCHDOG_THRESHOLD:-95}"
TARGET_PID="${WATCHDOG_TARGET_PID:-}"
WATCHDOG_TIMEOUT="${WATCHDOG_TIMEOUT:-86400}"
WATCHDOG_DRY_RUN="${WATCHDOG_DRY_RUN:-false}"

# --- Usage ---
if [ -z "$TARGET_PID" ]; then
    echo "Usage: WATCHDOG_TARGET_PID=<pid> $0"
    echo ""
    echo "Environment:"
    echo "  WATCHDOG_TARGET_PID (required): PID to monitor"
    echo "  WATCHDOG_INTERVAL (default: 1): Check interval in seconds"
    echo "  WATCHDOG_THRESHOLD (default: 95): Memory % threshold"
    echo "  WATCHDOG_TIMEOUT (default: 86400): Max runtime in seconds (24h)"
    echo "  WATCHDOG_DRY_RUN (default: false): If true, log actions without killing"
    echo ""
    echo "Exit Codes:"
    echo "  0  - Target process exited normally"
    echo "  1  - Memory threshold exceeded (process killed)"
    echo "  2  - Invalid usage or missing WATCHDOG_TARGET_PID"
    exit 2
fi

# Validate target PID
if ! kill -0 "$TARGET_PID" 2>/dev/null; then
    echo "ERROR: PID $TARGET_PID is not running or invalid."
    exit 2
fi

trap 'echo "Watchdog: received signal. Killing target process..."; \
      if [ "$WATCHDOG_DRY_RUN" != "true" ]; then \
          kill -9 "$TARGET_PID" 2>/dev/null || true; \
          pkill -9 -P "$TARGET_PID" 2>/dev/null || true; \
      fi; \
      exit 1' SIGINT SIGTERM

get_cgroup_memory_usage() {
    local pid=$1
    local cgroup_path current max mem_current mem_max rss kb_total

    cgroup_path=$(cat /proc/$pid/cgroup 2>/dev/null | grep '^0::' | cut -d: -f3)
    if [ -n "$cgroup_path" ]; then
        mem_current="/sys/fs/cgroup$cgroup_path/memory.current"
        mem_max="/sys/fs/cgroup$cgroup_path/memory.max"
        if [ -f "$mem_current" ] && [ -f "$mem_max" ]; then
            current=$(cat "$mem_current" 2>/dev/null || echo 0)
            max=$(cat "$mem_max" 2>/dev/null || echo 0)
            if [ "$max" != "0" ] && [ "$max" != "max" ]; then
                echo "$((current * 100 / max))"
                return
            fi
        fi
    fi

    # Fallback: check process RSS
    rss=$(cat /proc/$pid/status 2>/dev/null | grep VmRSS | awk '{print $2}')
    kb_total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    if [ -n "$rss" ] && [ -n "$kb_total" ] && [ "$kb_total" != "0" ]; then
        echo "$((rss * 100 / kb_total))"
    else
        echo "0"
    fi
}

get_all_children() {
    local parent=$1
    local children
    children=$(pgrep -P "$parent" 2>/dev/null) || return
    echo "$parent $children"
    for child in $children; do
        get_all_children "$child"
    done
}

echo "Memory watchdog started for PID $TARGET_PID (threshold: ${MEMORY_THRESHOLD}%, interval: ${WATCHDOG_INTERVAL}s)"

end_time=$(( $(date +%s) + WATCHDOG_TIMEOUT ))
while kill -0 "$TARGET_PID" 2>/dev/null && [ $(date +%s) -lt $end_time ]; do
    sleep "$WATCHDOG_INTERVAL" || {
        echo "ERROR: sleep interrupted. Exiting."
        exit 1
    }

    # Check all child processes
    for pid in $(get_all_children "$TARGET_PID"); do
        mem_pct=$(get_cgroup_memory_usage "$pid")
        if [ "$mem_pct" -ge "$MEMORY_THRESHOLD" ]; then
            echo "WARNING: PID $pid at ${mem_pct}% memory - killing process tree"
            if [ "$WATCHDOG_DRY_RUN" != "true" ]; then
                kill -9 "$TARGET_PID" 2>/dev/null || true
                pkill -9 -P "$TARGET_PID" 2>/dev/null || true
            fi
            exit 1
        fi
    done
done

echo "Watchdog: target process exited"
exit 0
