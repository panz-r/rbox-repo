#!/usr/bin/env python3
"""CTest-based test runner for c-dfa test suite.

Uses ctest as the test orchestrator for proper:
- Output isolation (each test runs independently)
- Parallel execution (ctest --parallel)
- XML output for CI integration
- Aggregated summary from all test sets

Usage: python3 run_test_suite.py [options]

Options:
  --xml          Generate JUnit XML output
  --parallel N   Run N tests in parallel (default: auto-detect CPU count)
  --verbose      Show verbose test output
  --help         Show this help message

Examples:
  python3 run_test_suite.py                  # Run all tests in parallel
  python3 run_test_suite.py --parallel 4      # Run with 4 parallel jobs
  python3 run_test_suite.py --xml             # Generate XML output for CI
  cd build && ctest --parallel 8             # Direct ctest usage
"""

import subprocess
import sys
import os
import re
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Tuple, Optional


SUMMARY_PATTERN = re.compile(
    r"SUMMARY:\s*(\d+)/(\d+)\s+passed(?:\s*\((\d+)/(\d+)\s+groups\))?(?:,\s*(\d+)\s+failed)?"
)


def parse_summary_from_output(output: str) -> Optional[Tuple[int, int, int, int, int]]:
    """Parse SUMMARY line from dfa_test output.

    Returns: (passed, total, groups_run, groups_total, groups_failed) or None
    """
    match = SUMMARY_PATTERN.search(output)
    if not match:
        return None
    passed = int(match.group(1))
    total = int(match.group(2))
    groups_run = int(match.group(3)) if match.group(3) else 0
    groups_total = int(match.group(4)) if match.group(4) else 0
    groups_failed = int(match.group(5)) if match.group(5) else 0
    return (passed, total, groups_run, groups_total, groups_failed)


def parse_junit_xml(xml_path: str) -> Tuple[int, int, int, int, int, int]:
    """Parse JUnit XML and extract summary information from test outputs.

    Returns: (total_passed, total_tests, total_groups_run, total_groups_total,
              failed_test_sets, failed_groups)
    """
    if not os.path.exists(xml_path):
        return (0, 0, 0, 0, 0, 0)

    tree = ET.parse(xml_path)
    root = tree.getroot()

    total_passed = 0
    total_tests = 0
    total_groups_run = 0
    total_groups_total = 0
    failed_test_sets = 0
    failed_groups = 0

    for testcase in root.iter("testcase"):
        name = testcase.get("name", "unknown")
        failure = testcase.find("failure")
        error = testcase.find("error")

        if failure is not None or error is not None:
            failed_test_sets += 1
            failed_groups += 1
            continue

        system_out = testcase.find("system-out")
        if system_out is not None and system_out.text:
            summary = parse_summary_from_output(system_out.text)
            if summary:
                p, t, gr, gt, gf = summary
                total_passed += p
                total_tests += t
                total_groups_run += gr
                total_groups_total += gt
                failed_groups += gf

    return (
        total_passed,
        total_tests,
        total_groups_run,
        total_groups_total,
        failed_test_sets,
        failed_groups,
    )


def run_ctest(
    build_dir: str, parallel: int = 0, verbose: bool = False, xml: bool = False
) -> int:
    """Run ctest in parallel mode.

    Returns exit code (0 = all passed).
    """
    cmd = ["ctest", "--parallel"]
    if parallel:
        cmd.append(str(parallel))
    else:
        cmd.append(str(os.cpu_count() or 4))

    if verbose:
        cmd.append("-V")
    else:
        cmd.append("--output-on-failure")

    if xml:
        junit_path = os.path.join(build_dir, "test_results.xml")
        if os.path.exists(junit_path):
            os.remove(junit_path)
        cmd.extend(["--output-junit", junit_path])
        cmd.extend(["--test-output-size-passed", "0"])
        cmd.extend(["--test-output-size-failed", "0"])

    result = subprocess.run(cmd, cwd=build_dir)
    return result.returncode


def main():
    parser = argparse.ArgumentParser(
        description="CTest-based test runner for c-dfa",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--xml", action="store_true", help="Generate JUnit XML output")
    parser.add_argument(
        "--parallel",
        type=int,
        default=None,
        help="Number of parallel jobs (default: auto-detect CPU count)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show verbose test output"
    )
    parser.add_argument(
        "--build-dir",
        default=None,
        help="Build directory (default: <script_dir>/../build)",
    )

    args = parser.parse_args()

    if args.build_dir:
        build_dir = args.build_dir
    else:
        script_dir = Path(__file__).resolve().parent
        build_dir = str(script_dir.parent / "build")

    project_dir = str(Path(build_dir).parent)

    print("=" * 80)
    print("C-DFA TEST SUITE (using ctest)")
    print("=" * 80)
    print()
    print(f"Project directory: {project_dir}")
    print(f"Build directory: {build_dir}")
    print(f"Parallel jobs: {args.parallel or os.cpu_count() or 4}")
    print(f"XML output: {'enabled' if args.xml else 'disabled'}")
    print()

    # Build first to ensure tests are up to date
    print("Building tests...")
    build_result = subprocess.run(
        ["cmake", "--build", ".", "--target", "tests"],
        cwd=build_dir,
        capture_output=True,
        text=True,
    )
    if build_result.returncode != 0:
        print("Build failed:")
        print(build_result.stderr)
        return 1
    print("Build complete.")
    print()

    # Run ctest
    print("Running tests in parallel...")
    print()

    exit_code = run_ctest(
        build_dir=build_dir, parallel=args.parallel, verbose=args.verbose, xml=True
    )

    # Parse results from JUnit XML and print summary
    junit_path = os.path.join(build_dir, "test_results.xml")
    if os.path.exists(junit_path):
        (
            total_passed,
            total_tests,
            total_groups_run,
            total_groups_total,
            failed_test_sets,
            failed_groups,
        ) = parse_junit_xml(junit_path)

        print()
        print("=" * 80)
        print("TEST SUMMARY")
        print("=" * 80)
        print(f"Tests:      {total_passed}/{total_tests} passed")
        print(f"Groups:     {total_groups_run}/{total_groups_total} groups")
        if failed_groups > 0 or failed_test_sets > 0:
            print(
                f"Failures:   {failed_groups} test groups failed ({failed_test_sets} test sets)"
            )
        else:
            print("Failures:   none")
        print("=" * 80)

        if args.xml:
            print()
            print(f"XML report: {junit_path}")
    else:
        print("Warning: JUnit XML not found at", junit_path)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
