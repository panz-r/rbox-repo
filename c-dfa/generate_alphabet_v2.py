#!/usr/bin/env python3
"""Generate pattern-aware alphabet by extending base alphabet."""

import sys
import re

def load_fragments(patterns_file):
    """Load fragment definitions from patterns file."""
    fragments = {}
    
    with open(patterns_file, 'r') as f:
        content = f.read()
    
    # Find fragment definitions
    for match in re.finditer(r'\[fragment:([^\]]+)\]\s*([^
]+)', content):
        name = match.group(1)
        value = match.group(2).strip()
        fragments[name] = value
    
    return fragments

def expand_fragment(fragment_name, fragments, depth=0):
    """Expand a fragment reference to get all its characters."""
    if depth > 10:  # Prevent infinite recursion
        return set()
    
    if fragment_name not in fragments:
        return set()
    
    value = fragments[fragment_name]
    chars = set()
    
    # Parse fragment content (alternation with |)
    for part in value.split('|'):
        part = part.strip()
        if len(part) == 1:
            chars.add(part)
        elif len(part) == 3 and part[1] == '-':
            # Range like a-z
            for c in range(ord(part[0]), ord(part[2]) + 1):
                chars.add(chr(c))
    
    return chars

def analyze_patterns(patterns_file):
    """Find all characters used in patterns, including fragments."""
    individual_chars = set()
    fragments = load_fragments(patterns_file)
    
    with open(patterns_file, 'r') as f:
        content = f.read()
    
    # Process each line
    for line in content.split('\n'):
        if '#' in line:
            line = line[:line.index('#')]
        line = line.strip()
        if not line or line.startswith('['):
            continue
            
        # Get pattern part
        if ']' in line:
            pattern = line.split(']', 1)[1].strip()
        else:
            pattern = line
            
        if not pattern:
            continue
        
        # Find fragment references like ((git::DIGIT))+
        for match in re.finditer(r'\(\(([^)]+)\)\)', pattern):
            fragment_name = match.group(1)
            fragment_chars = expand_fragment(fragment_name, fragments)
            individual_chars.update(fragment_chars)
        
        # Remove fragment refs, capture tags, character classes, operators
        temp = re.sub(r'\(\([^)]+\)\)', '', pattern)
        temp = re.sub(r'<[^>]+>', '', temp)
        temp = re.sub(r'\[[^\]]+\]', '', temp)
        temp = re.sub(r'[\\+?*()|]', '', temp)
        
        for char in temp:
            if 32 <= ord(char) <= 126:
                individual_chars.add(char)
    
    return individual_chars

def load_base_alphabet(base_file):
    """Load base alphabet entries."""
    entries = []
    
    try:
        with open(base_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    symbol_id = int(parts[0])
                    start_code = int(parts[1])
                    end_code = int(parts[2])
                    desc = ' '.join(parts[3:]).replace('#', '').strip()
                    entries.append((symbol_id, start_code, end_code, desc))
    except Exception as e:
        print(f"Warning: Could not load base alphabet: {e}")
    
    return entries

def generate_alphabet(patterns_file, output_file, base_alphabet_file):
    """Generate alphabet by extending base with pattern-specific chars."""
    
    # Load base alphabet
    base_entries = load_base_alphabet(base_alphabet_file)
    
    # Find chars needed by patterns
    needed_chars = analyze_patterns(patterns_file)
    
    # Start with all base entries
    final_entries = list(base_entries)
    used_symbols = {e[0] for e in base_entries}
    base_chars = {chr(e[1]) for e in base_entries if e[1] == e[2] and e[1] >= 32}
    
    # Add any new chars not in base
    next_symbol = max(used_symbols) + 1 if used_symbols else 4
    
    for char in sorted(needed_chars):
        if char not in base_chars:
            # Add new entry for this char
            code = ord(char)
            final_entries.append((next_symbol, code, code, char))
            used_symbols.add(next_symbol)
            next_symbol += 1
    
    # Sort by symbol ID
    final_entries.sort(key=lambda x: x[0])
    
    # Write output
    with open(output_file, 'w') as f:
        f.write("# Pattern-Aware Alphabet Map\n")
        f.write(f"# Based on: {base_alphabet_file}\n")
        f.write(f"# Extended for: {patterns_file}\n\n")
        
        for symbol_id, start, end, desc in final_entries:
            f.write(f"{symbol_id} {start} {end}       # {desc}\n")
    
    return len(final_entries)

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 generate_alphabet.py <patterns_file> <output_map_file> [base_alphabet]")
        sys.exit(1)
    
    patterns_file = sys.argv[1]
    output_file = sys.argv[2]
    base_alphabet = sys.argv[3] if len(sys.argv) > 3 else "alphabet_per_char.map"
    
    print(f"Analyzing patterns from: {patterns_file}")
    needed = analyze_patterns(patterns_file)
    print(f"Characters needed: {sorted(needed)}")
    
    print(f"\nGenerating alphabet: {output_file}")
    print(f"Base alphabet: {base_alphabet}")
    num = generate_alphabet(patterns_file, output_file, base_alphabet)
    
    print(f"Generated {num} symbols")

if __name__ == "__main__":
    main()
