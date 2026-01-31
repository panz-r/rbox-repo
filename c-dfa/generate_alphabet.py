#!/usr/bin/env python3
"""Generate pattern-aware alphabet with per-character symbols for specific digits."""

import sys
import re


def load_base_alphabet(base_file):
    """Load base alphabet and return entries list."""
    entries = []
    with open(base_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                symbol_id = int(parts[0])
                start = int(parts[1])
                end = int(parts[2])
                desc = " ".join(parts[3:]).replace("#", "").strip()
                entries.append((symbol_id, start, end, desc))
    return entries


def find_specific_digits(patterns_file):
    """Find digits that appear literally in patterns (not in ranges)."""
    specific_digits = set()

    with open(patterns_file, "r") as f:
        content = f.read()

    # Look for literal digits outside of character classes
    for line in content.split("\n"):
        if "#" in line:
            line = line[: line.index("#")]
        line = line.strip()

        # Skip empty lines and fragment definitions only
        if not line:
            continue
        if line.startswith("[fragment:"):
            continue

        # Get pattern part after category spec
        if "]" in line:
            pattern = line.split("]", 1)[1].strip()
        else:
            pattern = line

        if not pattern:
            continue

        # Remove character classes [0-9], fragments ((...)), operators
        temp = re.sub(r"\[[^\]]+\]", "", pattern)
        temp = re.sub(r"\(\([^)]+\)\)", "", temp)
        temp = re.sub(r"<[^>]+>", "", temp)
        temp = re.sub(r"[\\+?*()|]", "", temp)

        # Find literal digits
        for char in temp:
            if char.isdigit():
                specific_digits.add(char)

    return specific_digits


def generate_alphabet(patterns_file, output_file, base_alphabet_file):
    """Generate alphabet with per-character symbols for specific digits."""

    # Load base alphabet
    base_entries = load_base_alphabet(base_alphabet_file)

    # Find specific digits needed
    specific_digits = find_specific_digits(patterns_file)
    print(f"Specific digits found: {sorted(specific_digits)}")

    # Start with base entries, but remove the 0-9 range entry if we have specific digits
    new_entries = []
    max_symbol = 0

    for entry in base_entries:
        symbol_id, start, end, desc = entry
        # Skip the 0-9 range entry if we have specific digits
        if start == 48 and end == 57 and desc == "0-9" and specific_digits:
            print(f"Replacing 0-9 range with per-character digits")
            continue
        new_entries.append(entry)
        max_symbol = max(max_symbol, symbol_id)

    # Add per-character symbols for specific digits
    next_symbol = max_symbol + 1
    for d in sorted(specific_digits):
        code = ord(d)
        new_entries.append((next_symbol, code, code, d))
        next_symbol += 1

    # Add 0-9 range for remaining digits if there are any
    remaining = set("0123456789") - specific_digits
    if remaining:
        codes = sorted([ord(d) for d in remaining])
        new_entries.append(
            (next_symbol, codes[0], codes[-1], f"{chr(codes[0])}-{chr(codes[-1])}")
        )
        next_symbol += 1

    # Sort by symbol ID
    new_entries.sort(key=lambda x: x[0])

    # Write output
    with open(output_file, "w") as f:
        f.write("# Pattern-Aware Alphabet Map\n")
        f.write(f"# Based on: {base_alphabet_file}\n")
        f.write(f"# Specific digits: {sorted(specific_digits)}\n\n")

        for symbol_id, start, end, desc in new_entries:
            f.write(f"{symbol_id} {start} {end}       # {desc}\n")

    return len(new_entries)


def main():
    if len(sys.argv) < 3:
        print(
            "Usage: python3 generate_alphabet.py <patterns_file> <output_map_file> [base_alphabet]"
        )
        sys.exit(1)

    patterns_file = sys.argv[1]
    output_file = sys.argv[2]
    base_alphabet = sys.argv[3] if len(sys.argv) > 3 else "alphabet_per_char.map"

    print(f"Analyzing patterns: {patterns_file}")
    num = generate_alphabet(patterns_file, output_file, base_alphabet)
    print(f"Generated {num} symbols in {output_file}")


if __name__ == "__main__":
    main()
