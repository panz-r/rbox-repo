#!/bin/bash
# ============================================================================
# Test Pattern Builder and Runner
# ============================================================================
# This script builds DFAs for each test pattern file and runs tests

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PATTERNS_DIR="$SCRIPT_DIR/test_patterns"
BUILD_DIR="$SCRIPT_DIR/build/test_patterns"
NFA_BUILDER="$SCRIPT_DIR/tools/nfa_builder"
NFA2DFA="$SCRIPT_DIR/tools/nfa2dfa_advanced"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "================================================"
echo "Test Pattern Builder and Runner"
echo "================================================"
echo ""

# Create build directory
mkdir -p "$BUILD_DIR"

# Find all pattern files
pattern_files=$(find "$PATTERNS_DIR" -name "*.txt" -type f | sort)

total_patterns=0
total_tests=0
total_passed=0

for pattern_file in $pattern_files; do
    pattern_name=$(basename "$pattern_file" .txt)
    echo "================================================"
    echo "Testing: $pattern_name"
    echo "================================================"
    
    # Build NFA
    nfa_file="$BUILD_DIR/${pattern_name}.nfa"
    dfa_file="$BUILD_DIR/${pattern_name}.dfa"
    
    echo "Building NFA from $pattern_file..."
    if ! "$NFA_BUILDER" "$pattern_file" "$nfa_file" 2>/dev/null; then
        echo -e "${RED}ERROR: Failed to build NFA for $pattern_name${NC}"
        continue
    fi
    
    echo "Converting NFA to DFA..."
    if ! "$NFA2DFA" "$nfa_file" "$dfa_file" 2>/dev/null; then
        echo -e "${RED}ERROR: Failed to convert NFA to DFA for $pattern_name${NC}"
        continue
    fi
    
    echo -e "${GREEN}DFA built successfully: $dfa_file${NC}"
    echo ""
    
    total_patterns=$((total_patterns + 1))
done

echo ""
echo "================================================"
echo "Summary"
echo "================================================"
echo "Built $total_patterns pattern files"
echo ""
echo "DFA files are in: $BUILD_DIR"
echo ""
for dfa_file in "$BUILD_DIR"/*.dfa; do
    if [ -f "$dfa_file" ]; then
        echo "  - $(basename "$dfa_file")"
    fi
done

echo ""
echo "================================================"
echo "Test pattern files created successfully!"
echo "================================================"
