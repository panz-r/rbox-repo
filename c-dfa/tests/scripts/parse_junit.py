#!/usr/bin/env python3
"""Parse JUnit XML from ctest and print test summary."""

import sys
import re
import xml.etree.ElementTree as ET

SUMMARY_PATTERN = re.compile(
    r"SUMMARY:\s*(\d+)/(\d+)\s+passed(?:\s*\((\d+)/(\d+)\s+groups\))?(?:\s*,\s*(\d+)\s+failed)?"
)


def parse_summary(text):
    """Parse SUMMARY: X/Y passed (Z/W groups) lines."""
    match = SUMMARY_PATTERN.search(text)
    if not match:
        return None
    passed = int(match.group(1))
    total = int(match.group(2))
    groups_run = int(match.group(3)) if match.group(3) else 0
    groups_total = int(match.group(4)) if match.group(4) else 0
    return (passed, total, groups_run, groups_total)


def main():
    if len(sys.argv) < 2:
        print("Usage: parse_junit.py <junit-xml-file>")
        sys.exit(1)

    xml_file = sys.argv[1]

    try:
        tree = ET.parse(xml_file)
    except ET.ParseError as e:
        print(f"Failed to parse XML: {e}", file=sys.stderr)
        sys.exit(1)

    root = tree.getroot()

    total_passed = 0
    total_tests = 0
    total_groups_run = 0
    total_groups_total = 0

    for testcase in root.findall(".//testcase"):
        system_out = testcase.find("system-out")
        if system_out is not None and system_out.text:
            result = parse_summary(system_out.text)
            if result:
                p, t, gr, gt = result
                total_passed += p
                total_tests += t
                total_groups_run += gr
                total_groups_total += gt

    # If no SUMMARY found, use JUnit-level counts
    if total_tests == 0:
        total_tests = int(root.get("tests", 0))
        failures = int(root.get("failures", 0))
        errors = int(root.get("errors", 0))
        total_passed = total_tests - failures - errors
        total_groups_total = len(root.findall(".//testcase"))
        total_groups_run = total_groups_total - failures - errors

    if total_tests > 0:
        print(f"Tests: {total_passed}/{total_tests} passed", file=sys.stderr)
        print(
            f"Groups: {total_groups_run}/{total_groups_total} groups", file=sys.stderr
        )
        print(
            f"\nTEST SUMMARY: {total_passed}/{total_tests} tests, {total_groups_run}/{total_groups_total} groups"
        )

    sys.exit(0)


if __name__ == "__main__":
    main()
