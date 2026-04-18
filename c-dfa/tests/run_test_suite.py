#!/usr/bin/env python3
"""CTest-based test runner for c-dfa test suite.

Uses ctest as the test orchestrator for proper:
- Output isolation (each test runs independently)
- Parallel execution (ctest --parallel)
- XML output for CI integration

Usage: python3 run_test_suite.py [options]

Options:
  --xml          Generate JUnit XML output (ctest -T Test)
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
from pathlib import Path


def run_ctest(
    build_dir: str, parallel: int = 0, verbose: bool = False, xml: bool = False
) -> int:
    """Run ctest in parallel mode.

    Returns exit code (0 = all passed).
    """
    # Build command
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
        cmd.extend(["-T", "Test"])

    # Run ctest
    result = subprocess.run(cmd, cwd=build_dir)
    return result.returncode


def main():
    parser = argparse.ArgumentParser(
        description="CTest-based test runner for c-dfa",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--xml", action="store_true", help="Generate JUnit XML output (ctest -T Test)"
    )
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

    # Detect directories
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

    return run_ctest(
        build_dir=build_dir, parallel=args.parallel, verbose=args.verbose, xml=args.xml
    )


if __name__ == "__main__":
    sys.exit(main())
