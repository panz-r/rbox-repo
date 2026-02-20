#!/bin/bash
# Generate pattern files with 10+ lines by concatenating existing patterns

OUT_DIR="corpus/seed_multiline/pattern_parser"
mkdir -p "$OUT_DIR"

# Get all individual pattern files
PATTERN_FILES=(../patterns_*.txt)
echo "Using ${#PATTERN_FILES[@]} pattern files as source"

# For each number of lines (10, 20, 30, 50, 100)
for LINES in 10 20 30 50 100; do
    echo "Generating ${LINES}-line pattern files..."
    
    # Create 5 different random combinations for each line count
    for ITER in 1 2 3 4 5; do
        OUTFILE="${OUT_DIR}/multi_${LINES}_lines_${ITER}.txt"
        
        # Randomly select pattern lines from all sources
        > "$OUTFILE"  # empty file
        
        # Use all patterns, but shuffle and take first $LINES
        # We'll just cat a bunch of pattern files and take first $LINES non-empty lines
        for pf in "${PATTERN_FILES[@]}"; do
            if [ -f "$pf" ]; then
                grep -E '^\s*\[.*\]\s+.+' "$pf" | \
                    sed -E 's/^\s*\[[^]]+\]\s+//; s/->.*$//' >> "$OUTFILE"
            fi
        done
        
        # Take first N lines
        head -n "$LINES" "$OUTFILE" > "$OUTFILE.tmp" && mv "$OUTFILE.tmp" "$OUTFILE"
        
        # Verify we got enough lines
        COUNT=$(wc -l < "$OUTFILE")
        if [ "$COUNT" -lt "$LINES" ]; then
            echo "WARNING: $OUTFILE only has $COUNT lines (wanted $LINES)"
        fi
    done
done

echo "Generated multi-line corpus in $OUT_DIR"
ls -lht "$OUT_DIR" | wc -l
