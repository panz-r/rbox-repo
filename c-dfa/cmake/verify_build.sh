#!/bin/bash
# verify_build.sh - Verify DFA library build quality
set -e

BUILD_DIR="${1:-build}"
NM="${NM:-nm}"
OBJDUMP="${OBJDUMP:-objdump}"

echo "=== Verifying DFA library build ==="
echo ""

SO="$BUILD_DIR/tools/libreadonlybox_dfa.so"
SAT_MODULES="$BUILD_DIR/tools/libsat_modules.a"

# Verify 1: sat_modules.a only exposes C entry points
echo "--- Verify 1: sat_modules.a only exposes C entry points ---"
# Check for global symbols (T) that are NOT in our allowed list
UNEXPECTED=$($NM "$SAT_MODULES" 2>/dev/null | grep ' T ' | grep -v -E 'sat_merge|sat_compress|sat_layout|sat_optimize|nfa_preminimize|dfa_minimize|nfa_premin_sat' || true)
if [ -n "$UNEXPECTED" ]; then
    echo "  WARNING: Unexpected symbols in sat_modules.a:"
    echo "$UNEXPECTED" | head -5
else
    echo "  OK: Only C entry points visible"
fi
echo ""

# Verify 2: libreadonlybox_dfa.so has SAT symbols defined
echo "--- Verify 2: SAT symbols defined in .so ---"
# Look for ' T ' (uppercase = global) or ' t ' (lowercase = local) - both mean defined
SYMBOL=$($NM "$SO" 2>/dev/null | grep 'sat_merge_rules_for_state' | grep -E ' T | t ' || true)
if [ -z "$SYMBOL" ]; then
    echo "  ERROR: SAT symbols not defined in .so"
    exit 1
else
    echo "  OK: SAT symbols defined in .so"
fi
echo ""

# Verify 3: No CaDiCaL/C++ symbols leaked
echo "--- Verify 3: No CaDiCaL/C++ symbols leaked ---"
# Only check for DEFINED symbols (T or t), not undefined (U)
# Undefined symbols are references that get resolved at runtime from sat_modules.a
CADICAL_LEAK=$($NM "$SO" 2>/dev/null | grep -E ' T | t ' | grep 'CaDiCaL' | wc -l)
CPP_LEAK=$($NM "$SO" 2>/dev/null | grep -E ' T | t ' | grep '__Z' | wc -l)
if [ "$CADICAL_LEAK" -gt 0 ] || [ "$CPP_LEAK" -gt 0 ]; then
    echo "  ERROR: CaDiCaL/C++ symbols leaked ($CADICAL_LEAK CaDiCaL, $CPP_LEAK C++)"
    exit 1
else
    echo "  OK: No leaked CaDiCaL/C++ symbols"
fi
echo ""

# Verify 4: No external SAT library dependencies
echo "--- Verify 4: No external SAT library dependencies ---"
DEP=$($OBJDUMP -p "$SO" 2>/dev/null | grep 'NEEDED' | grep -E 'sat_modules|cadical' | wc -l)
if [ "$DEP" -gt 0 ]; then
    echo "  ERROR: .so depends on sat_modules or cadical"
    exit 1
else
    echo "  OK: No SAT library dependencies"
fi
echo ""

echo "=== All verification checks passed ==="