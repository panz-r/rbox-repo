#!/usr/bin/env python3
"""
Generate seed corpus for dfa_eval_fuzzer.
Format: [dfa_size:4 LE][dfa_data][num_strings:2 LE][string_len:2 LE][string bytes]...
"""

import struct
import os
import sys
from pathlib import Path


def write_le16(val):
    return struct.pack("<H", val & 0xFFFF)


def write_le32(val):
    return struct.pack("<I", val & 0xFFFFFFFF)


def create_corpus_entry(dfa_path, output_path, test_strings):
    """Create a fuzzer corpus entry from a DFA file."""
    with open(dfa_path, "rb") as f:
        dfa_data = f.read()

    dfa_size = len(dfa_data)

    with open(output_path, "wb") as f:
        # Write DFA size (4 bytes LE)
        f.write(write_le32(dfa_size))
        # Write DFA data
        f.write(dfa_data)
        # Write number of strings (2 bytes LE)
        f.write(write_le16(len(test_strings)))
        # Write each string
        for s in test_strings:
            s_bytes = s.encode("utf-8")
            f.write(write_le16(len(s_bytes)))  # string length
            f.write(s_bytes)


def main():
    script_dir = Path(__file__).parent
    output_dir = script_dir / "corpus" / "seed" / "dfa_binary"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Find all DFA files from tests
    cdfa_dir = script_dir.parent
    dfa_files = []

    # Priority DFA files (larger, more complete)
    priority_dfa = [
        cdfa_dir / "readonlybox.dfa",
        cdfa_dir / "readonlybox_new.dfa",
        cdfa_dir / "test_group.dfa",
    ]

    for dfa_path in priority_dfa:
        if dfa_path.exists():
            dfa_files.append((dfa_path, 100))

    # Build test DFA files
    build_test_dir = cdfa_dir / "build_test"
    if build_test_dir.exists():
        for dfa_path in build_test_dir.glob("*.dfa"):
            dfa_files.append((dfa_path, 50))

    # Test output DFA files
    output_test_dir = cdfa_dir / "output"
    if output_test_dir.exists():
        for dfa_path in output_test_dir.glob("*.dfa"):
            dfa_files.append((dfa_path, 30))

    if not dfa_files:
        print("No DFA files found!")
        sys.exit(1)

    # Sort by priority (higher first)
    dfa_files.sort(key=lambda x: -x[1])

    # Test strings to pair with DFA files
    test_strings = [
        ["git status", "ls -la", "cat file.txt"],
        ["ps aux", "df -h", "du -sh *"],
        ["find . -name '*.c'", "grep pattern file"],
        ["echo hello", "pwd", "whoami", "date"],
        ["uname -a", "id", "ls", "git log"],
        ["cat /etc/passwd", "ps aux | grep root"],
        ["df -h", "mount", "free -m"],
        ["pwd", "cd /tmp", "ls"],
        ["echo test", "printf hello"],
        ["whoami", "id -u", "groups"],
    ]

    count = 0
    for i, (dfa_path, priority) in enumerate(dfa_files):
        strings_idx = i % len(test_strings)
        output_path = output_dir / f"seed_{count:03d}.bin"

        try:
            create_corpus_entry(
                str(dfa_path), str(output_path), test_strings[strings_idx]
            )
            count += 1
            print(
                f"  Created: {output_path.name} ({dfa_path.name}, priority={priority})"
            )
        except Exception as e:
            print(f"  Error with {dfa_path.name}: {e}")

        if count >= 50:
            break

    print(f"\nCreated {count} corpus files in {output_dir}")
    print(f"Total files: {len(list(output_dir.glob('*.bin')))}")


if __name__ == "__main__":
    main()
