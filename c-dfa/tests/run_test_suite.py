#!/usr/bin/env python3
"""Aggregated test runner for c-dfa test suite.

Runs all test suites in parallel and produces:
1. Per-suite timing table (name, time, result)
2. Per-suite failure details (only if suite fails)
3. Aggregated summary line at end

Usage: python3 run_test_suite.py [working_dir]
"""

import subprocess
import sys
import time
import re
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, List, Tuple


@dataclass
class SuiteResult:
    name: str
    passed: int = 0
    total: int = 0
    groups_run: int = 0
    groups_total: int = 0
    failed_groups: int = 0
    elapsed: float = 0.0
    success: bool = False
    output: str = ""


def parse_summary(output: str) -> Tuple[int, int, int, int, int]:
    """Parse SUMMARY or Tests line from output.

    Handles formats:
    - "SUMMARY: 468/468 passed (44/44 groups)"
    - "SUMMARY: 20/20 passed"
    - "Tests: 5/6 passed"
    - "SUMMARY: 30/30 passed"

    Returns (passed, total, groups_run, groups_total, failed_groups)
    """
    passed = total = groups_run = groups_total = failed_groups = 0

    m = re.search(r"SUMMARY:\s*(\d+)/(\d+)\s*passed", output)
    if m:
        passed = int(m.group(1))
        total = int(m.group(2))

    m = re.search(r"Tests:\s*(\d+)/(\d+)\s*passed", output)
    if m:
        passed = int(m.group(1))
        total = int(m.group(2))

    m = re.search(r"\((\d+)/(\d+)\s*groups?\)", output)
    if m:
        groups_run = int(m.group(1))
        groups_total = int(m.group(2))

    m = re.search(r"(\d+)\s*failed", output)
    if m:
        failed_groups = int(m.group(1))

    return passed, total, groups_run, groups_total, failed_groups


def run_suite(
    name: str, cmd: List[str], cwd: str, env: Optional[dict] = None
) -> SuiteResult:
    """Run a single test suite and return results."""
    start = time.time()
    try:
        # Merge environment variables
        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        result = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=600, env=run_env
        )
        elapsed = time.time() - start
        output = result.stdout + result.stderr
        passed, total, groups_run, groups_total, failed_groups = parse_summary(output)
        success = result.returncode == 0 and passed == total and failed_groups == 0
        return SuiteResult(
            name=name,
            passed=passed,
            total=total,
            groups_run=groups_run,
            groups_total=groups_total,
            failed_groups=failed_groups,
            elapsed=elapsed,
            success=success,
            output=output,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        return SuiteResult(name=name, elapsed=elapsed, success=False, output="TIMEOUT")
    except Exception as e:
        elapsed = time.time() - start
        return SuiteResult(name=name, elapsed=elapsed, success=False, output=str(e))


def print_table(results: List[SuiteResult]):
    """Print per-suite timing table."""
    print()
    print("Test Suites")
    print("-" * 80)
    print(f"{'Suite':<50} {'Time':>8} {'Tests':>14} {'Result':>8}")
    print("-" * 80)

    for r in results:
        if r.groups_total > 0:
            test_str = f"{r.passed}/{r.total} ({r.groups_run}/{r.groups_total} grps)"
        else:
            test_str = f"{r.passed}/{r.total}"

        result_str = "PASS" if r.success else "FAIL"
        time_str = f"{r.elapsed:>7.2f}s"

        print(f"{r.name:<50} {time_str} {test_str:>14} {result_str:>8}")

    print("-" * 80)


def print_failures(results: List[SuiteResult]):
    """Print detailed failure info for failed suites."""
    failed = [r for r in results if not r.success]
    if not failed:
        return

    print()
    print("Failed Suites")
    print("=" * 80)

    for r in failed:
        print(f"\n{r.name}")
        print("-" * 40)
        lines = r.output.split("\n")
        summary_lines = [
            l
            for l in lines
            if "SUMMARY" in l
            or "Tests:" in l
            or "FAIL" in l
            or "failed" in l
            or "[FAIL]" in l
        ]
        if summary_lines:
            for line in summary_lines[-15:]:
                print(f"  {line}")
        else:
            print("  (no summary found)")
        print()


def run_parallel(
    suites: List[Tuple[str, List[str], Optional[dict]]], cwd: str, max_workers: int
) -> List[SuiteResult]:
    """Run suites in parallel, returning results in completion order."""
    results: List[Optional[SuiteResult]] = [None] * len(suites)
    completed_count = 0

    def worker(
        idx: int, name: str, cmd: List[str], env: Optional[dict]
    ) -> Tuple[int, SuiteResult]:
        return idx, run_suite(name, cmd, cwd, env)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(worker, i, name, cmd, env): i
            for i, (name, cmd, env) in enumerate(suites)
        }

        for future in as_completed(futures):
            idx, result = future.result()
            results[idx] = result
            completed_count += 1
            # Progress is printed by main thread only
            print(
                f"  [{completed_count}/{len(suites)}] {result.name} - {'PASS' if result.success else 'FAIL'} ({result.elapsed:.2f}s)",
                flush=True,
            )

    # All results are populated since futures complete before returning
    return results  # type: ignore[return-value]


def main():
    cwd = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )

    print("=" * 80)
    print("C-DFA FULL TEST SUITE")
    print("=" * 80)

    # Build directory for tests
    build_dir = os.path.join(cwd, "build")
    build_env = {"BUILD_DIR": build_dir}

    suites = [
        (
            "MOORE ALGORITHM (Test-Set A) with SAT compression",
            [
                "./build/tests/dfa_test",
                "--minimize-moore",
                "--compress-sat",
                "--test-set",
                "A",
            ],
            None,
        ),
        (
            "HOPCROFT ALGORITHM (Test-Set B) with SAT compression",
            [
                "./build/tests/dfa_test",
                "--minimize-hopcroft",
                "--compress-sat",
                "--test-set",
                "B",
            ],
            None,
        ),
        (
            "STRESS TESTS (Test-Set C) with SAT compression",
            [
                "./build/tests/dfa_test",
                "--minimize-moore",
                "--compress-sat",
                "--test-set",
                "C",
            ],
            None,
        ),
        (
            "MINIMIZATION INTEGRITY TEST",
            ["./build/tests/test_minimize_integrity"],
            None,
        ),
        ("LIBRARY API TESTS", ["./build/tests/test_library_api"], None),
        ("EVAL-ONLY LIBRARY TESTS", ["./build/tests/test_eval_only"], None),
        ("DFA2C_ARRAY TOOL TESTS", ["bash", "./tests/test_dfa2c_array.sh"], build_env),
        (
            "BINARY FORMAT EDGE CASE TESTS",
            ["bash", "./tests/test_binary_format.sh"],
            build_env,
        ),
        ("CAPTURE SYSTEM TESTS", ["bash", "./tests/test_captures.sh"], build_env),
        ("PATTERN REGRESSION TESTS", ["./build/tests/regression_test"], None),
    ]

    print()
    print("Running suites in parallel...")
    print()

    max_workers = min(len(suites), 8)
    results = run_parallel(suites, cwd, max_workers)

    total_passed = sum(r.passed for r in results)
    total_total = sum(r.total for r in results)
    groups_run = sum(r.groups_run for r in results)
    groups_total = sum(r.groups_total for r in results)

    print_table(results)
    print_failures(results)

    print()
    print("=" * 80)
    if groups_total > 0:
        print(
            f"AGGREGATE SUMMARY: {total_passed}/{total_total} tests ({groups_run}/{groups_total} groups)"
        )
    else:
        print(f"AGGREGATE SUMMARY: {total_passed}/{total_total} tests")
    print("=" * 80)

    all_passed = all(r.success for r in results)
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
