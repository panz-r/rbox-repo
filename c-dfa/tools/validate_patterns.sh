#!/bin/bash
# ============================================================================
# Pattern Validation Script for ReadOnlyBox
# ============================================================================
#
# Usage: ./validate_patterns.sh [pattern_file]
#
# This script validates patterns in a ReadOnlyBox pattern file.
# It checks for:
#   - Syntax errors in pattern lines
#   - Missing fragment definitions
#   - Unused fragment definitions
#   - Malformed category specifications
#   - Common mistakes and anti-patterns
#
# ============================================================================

PATTERN_FILE="${1:-../patterns_safe_commands.txt}"
VERBOSE=0
ERRORS=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }  # WARNINGS don't count as errors
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ERRORS=$((ERRORS+1)); }

# Check if pattern file exists
if [ ! -f "$PATTERN_FILE" ]; then
    echo "Error: Pattern file not found: $PATTERN_FILE"
    exit 1
fi

echo "================================================="
echo "ReadOnlyBox Pattern Validator"
echo "================================================="
echo "Validating: $PATTERN_FILE"
echo ""

# Extract fragments
declare -A FRAGMENTS
FRAGMENT_ORDER=()

while IFS= read -r line; do
    # Check for fragment definition
    if [[ "$line" =~ ^\[fragment:([^]]+)\]\ +(.+)$ ]]; then
        frag_name="${BASH_REMATCH[1]}"
        frag_value="${BASH_REMATCH[2]}"
        FRAGMENTS["$frag_name"]="$frag_value"
        FRAGMENT_ORDER+=("$frag_name")
    fi
done < "$PATTERN_FILE"

log_info "Found ${#FRAGMENTS[@]} fragment definitions"
for frag in "${FRAGMENT_ORDER[@]}"; do
    log_info "  Fragment: $frag -> ${FRAGMENTS[$frag]}"
done

# Track used fragments
declare -A USED_FRAGMENTS

# Extract and validate patterns
echo ""
echo "Validating pattern lines..."
LINE_NUM=0

while IFS= read -r line || [ -n "$line" ]; do
    LINE_NUM=$((LINE_NUM + 1))

    # Skip empty lines and comments
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

    # Extract category and pattern
    if [[ "$line" =~ ^\[([^]]+)\]\ *(.+)$ ]]; then
        category="${BASH_REMATCH[1]}"

        # Skip fragment definitions (they start with [fragment:)
        if [[ "$category" == "fragment:"* ]]; then
            continue
        fi
        pattern="${BASH_REMATCH[2]}"

        # Validate category format (at least one component)
        IFS=':' read -ra CAT_PARTS <<< "$category"
        if [ ${#CAT_PARTS[@]} -lt 1 ] || [ -z "${CAT_PARTS[0]}" ]; then
            log_fail "Line $LINE_NUM: Invalid category format: [$category]"
            continue
        fi

        # Check for valid category names
        VALID_CATEGORIES=("safe" "caution" "modifying" "dangerous" "network" "admin" "build" "container")
        CATEGORY_FOUND=0
        for cat in "${VALID_CATEGORIES[@]}"; do
            if [[ "${CAT_PARTS[0]}" == "$cat" ]]; then
                CATEGORY_FOUND=1
                break
            fi
        done
        if [ $CATEGORY_FOUND -eq 0 ]; then
            log_warn "Line $LINE_NUM: Unknown category: ${CAT_PARTS[0]}"
        fi

        # Check for fragment references
        FRAG_FOUND=1
        FRAGMENTS_TO_CHECK=0
        while [[ "$pattern" =~ \(\(([a-zA-Z0-9_:]+)\)\) ]]; do
            FRAGMENTS_TO_CHECK=$((FRAGMENTS_TO_CHECK + 1))
            frag_ref="${BASH_REMATCH[1]}"
            USED_FRAGMENTS["$frag_ref"]=1

            # Check if fragment exists
            if [ -z "${FRAGMENTS[$frag_ref]+exists}" ]; then
                log_fail "Line $LINE_NUM: Fragment '$frag_ref' not defined"
                FRAG_FOUND=0
            fi
            # Remove found fragment from pattern to continue searching
            pattern="${pattern/${BASH_REMATCH[0]}/X}"
        done

        # Only log PASS if there were fragments to check AND all were found
        if [ $FRAGMENTS_TO_CHECK -eq 0 ]; then
            log_pass "[$category] $pattern"
        elif [ $FRAG_FOUND -eq 1 ]; then
            log_pass "[$category] $pattern"
        fi

        # Check for common issues
        # Issue: + quantifier on character class without fragment
        if [[ "$pattern" =~ \[.*\]\+ ]]; then
            log_warn "Line $LINE_NUM: + quantifier on character class (use fragments for best results)"
        fi

        # Issue: Multiple consecutive wildcards
        if [[ "$pattern" =~ \*[[:space:]]+\* ]]; then
            log_warn "Line $LINE_NUM: Multiple consecutive wildcards"
        fi
    else
        # Line doesn't match expected format
        if [[ ! "$line" =~ ^[[:space:]]*$ ]]; then
            log_warn "Line $LINE_NUM: Malformed line (expected [category] pattern format)"
        fi
    fi
done < "$PATTERN_FILE"

# Check for unused fragments
echo ""
log_info "Checking for unused fragments..."
WARNINGS=0
for frag in "${FRAGMENT_ORDER[@]}"; do
    if [ -z "${USED_FRAGMENTS[$frag]+exists}" ]; then
        log_warn "Fragment '$frag' is defined but never used"
        WARNINGS=$((WARNINGS + 1))
    fi
done

# Summary
echo ""
echo "================================================="
echo "VALIDATION SUMMARY"
echo "================================================="
echo "Pattern file: $PATTERN_FILE"
echo "Fragments defined: ${#FRAGMENTS[@]}"
echo "Fragments used: ${#USED_FRAGMENTS[@]}"
echo "Fragments unused: $WARNINGS"

if [ $ERRORS -gt 0 ]; then
    echo -e "${RED}Errors: $ERRORS${NC}"
    exit 1
else
    if [ $WARNINGS -gt 0 ]; then
        echo -e "${YELLOW}Warnings: $WARNINGS (pattern is valid but could be improved)${NC}"
    fi
    echo -e "${GREEN}All checks passed!${NC}"
    exit 0
fi

