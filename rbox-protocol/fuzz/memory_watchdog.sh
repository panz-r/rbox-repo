#!/bin/bash
# Memory watchdog for rbox-protocol fuzzer
# Proactively kills fuzzer if memory usage exceeds threshold

INTERVAL="${WATCHDOG_INTERVAL:-1}"
MEMORY_THRESHOLD="${WATCHDOG_THRESHOLD:-95}"
TARGET_PID="${WATCHDOG_TARGET_PID:-}"

if [ -z "$TARGET_PID" ]; then
    echo "Usage: WATCHDOG_TARGET_PID=<pid> $0"
    echo ""
    echo "Environment:"
    echo "  WATCHDOG_TARGET_PID - PID to monitor"
    echo "  WATCHDOG_INTERVAL   - Check interval in seconds (default: 1)"
    echo "  WATCHDOG_THRESHOLD  - Memory % threshold (default: 95)"
    exit 1
fi

get_cgroup_memory_usage() {
    local pid=$1
    local cgroup_path

    cgroup_path=$(cat /proc/$pid/cgroup 2>/dev/null | grep '^0::' | cut -d: -f3)
    if [ -n "$cgroup_path" ]; then
        local mem_current="/sys/fs/cgroup$cgroup_path/memory.current"
        local mem_max="/sys/fs/cgroup$cgroup_path/memory.max"
        if [ -f "$mem_current" ] && [ -f "$mem_max" ]; then
            local current max
            current=$(cat "$mem_current" 2>/dev/null || echo 0)
            max=$(cat "$mem_max" 2>/dev/null || echo 0)
            if [ "$max" != "0" ] && [ "$max" != "max" ]; then
                echo "$((current * 100 / max))"
                return
            fi
        fi
    fi

    # Fallback: check process RSS
    local rss kb_total
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
    children=$(pgrep -P "$parent" 2>/dev/null || true)
    echo "$parent $children"
    for child in $children; do
        get_all_children "$child"
    done
}

echo "Memory watchdog started for PID $TARGET_PID (threshold: ${MEMORY_THRESHOLD}%)"

while kill -0 "$TARGET_PID" 2>/dev/null; do
    sleep "$INTERVAL"
    
    # Check all child processes
    for pid in $(get_all_children "$TARGET_PID"); do
        mem_pct=$(get_cgroup_memory_usage "$pid")
        if [ "$mem_pct" -ge "$MEMORY_THRESHOLD" ]; then
            echo "WARNING: PID $pid at ${mem_pct}% memory - killing process tree"
            kill -9 "$TARGET_PID" 2>/dev/null || true
            pkill -9 -P "$TARGET_PID" 2>/dev/null || true
            exit 1
        fi
    done
done

echo "Watchdog: target process exited"
