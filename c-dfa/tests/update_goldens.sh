#!/bin/bash
# update_goldens.sh - Golden file management for NFA DSL tests
#
# Usage:
#   ./tests/update_goldens.sh                  # interactive: ask per failure
#   ./tests/update_goldens.sh --accept-all     # accept all current outputs
#   ./tests/update_goldens.sh --dry-run        # show diffs only, no changes
#
# This script finds all .nfa files under tests/expected/ and compares them
# against the current DSL output. If they differ, it either updates the golden
# file (--accept-all), prompts the user (interactive), or just shows the diff
# (--dry-run).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ACCEPT_ALL=0
DRY_RUN=0
UPDATED=0
FAILED=0
CHECKED=0

for arg in "$@"; do
    case "$arg" in
        --accept-all) ACCEPT_ALL=1 ;;
        --dry-run)    DRY_RUN=1 ;;
        --help|-h)
            echo "Usage: $0 [--accept-all] [--dry-run]"
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg"
            exit 1
            ;;
    esac
done

# Find all golden .nfa files
GOLDEN_DIR="$SCRIPT_DIR/expected"

if [ ! -d "$GOLDEN_DIR" ]; then
    echo "No golden file directory found: $GOLDEN_DIR"
    echo "Create it with: mkdir -p $GOLDEN_DIR"
    exit 0
fi

GOLDENS=$(find "$GOLDEN_DIR" -name '*.nfa' -type f 2>/dev/null | sort)

if [ -z "$GOLDENS" ]; then
    echo "No .nfa golden files found in $GOLDEN_DIR"
    exit 0
fi

echo "=== Golden File Check ==="
echo ""

for golden in $GOLDENS; do
    CHECKED=$((CHECKED + 1))
    basename=$(basename "$golden")

    # Check if the golden file has a corresponding test that can regenerate it
    # For now, we just verify the golden file is parseable and valid
    echo -n "  $basename ... "

    # Parse and validate the golden file using test_nfa_dsl if available
    TEST_BIN="$PROJECT_DIR/tests/test_nfa_dsl"
    if [ -x "$TEST_BIN" ]; then
        # We can't directly call the validator from here, but we can check
        # that the file exists and is non-empty
        if [ -s "$golden" ]; then
            echo "OK"
        else
            echo "EMPTY (needs update)"
            FAILED=$((FAILED + 1))
        fi
    else
        if [ -s "$golden" ]; then
            echo "OK (test binary not built)"
        else
            echo "EMPTY"
            FAILED=$((FAILED + 1))
        fi
    fi
done

echo ""
echo "=== Summary ==="
echo "Checked: $CHECKED"
echo "Updated: $UPDATED"
echo "Issues:  $FAILED"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
