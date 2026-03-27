#!/usr/bin/env python3
"""Week 4: Automated release quality gate checker.

Runs all automated gates from docs/release-quality-gate.md and reports pass/fail.
Manual checks are listed as reminders but not executed.

Usage:
    python scripts/release_gate.py
"""

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS: list[tuple[str, bool, str]] = []


def run_gate(name: str, cmd: list[str], cwd: Path = PROJECT_ROOT) -> bool:
    print(f"  Running: {name}...", end=" ", flush=True)
    try:
        result = subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0:
            print("PASS")
            RESULTS.append((name, True, ""))
            return True
        else:
            detail = (result.stderr or result.stdout or "").strip().split("\n")[-1][:120]
            print(f"FAIL ({detail})")
            RESULTS.append((name, False, detail))
            return False
    except subprocess.TimeoutExpired:
        print("FAIL (timeout)")
        RESULTS.append((name, False, "Command timed out after 300s"))
        return False
    except FileNotFoundError as exc:
        print(f"FAIL ({exc})")
        RESULTS.append((name, False, str(exc)))
        return False


def check_file_exists(name: str, path: Path) -> bool:
    exists = path.exists()
    status = "PASS" if exists else "FAIL"
    print(f"  Checking: {name}... {status}")
    RESULTS.append((name, exists, "" if exists else f"File not found: {path}"))
    return exists


def main():
    print("=" * 60)
    print("RELEASE QUALITY GATE CHECK")
    print("=" * 60)

    # ── Automated Gates ──
    print("\n[1/4] Automated Gates\n")
    run_gate("Compile check (make lint)", ["make", "lint"])
    run_gate("Unit + smoke tests (make test-ci)", ["make", "test-ci"])
    run_gate("Benchmark pipeline (make benchmark)", ["make", "benchmark"])
    run_gate("Memory smoke test", ["pytest", "-q", "tests/unit/test_memory.py"])

    # Check frontend tests only if apps/web exists
    web_dir = PROJECT_ROOT / "apps" / "web"
    if web_dir.exists():
        run_gate("Frontend tests", ["npm", "run", "test", "--", "--passWithNoTests"], cwd=web_dir)
    else:
        print("  Skipping: Frontend tests (apps/web not found)")

    # ── Quality Documents ──
    print("\n[2/4] Required Documents\n")
    check_file_exists("docs/contracts.md", PROJECT_ROOT / "docs" / "contracts.md")
    check_file_exists("docs/pr-checklist.md", PROJECT_ROOT / "docs" / "pr-checklist.md")
    check_file_exists("docs/test-tracker.md", PROJECT_ROOT / "docs" / "test-tracker.md")
    check_file_exists("docs/release-quality-gate.md", PROJECT_ROOT / "docs" / "release-quality-gate.md")

    # ── Benchmark Artifacts ──
    print("\n[3/4] Benchmark Artifacts\n")
    check_file_exists(
        "Benchmark latest.json",
        PROJECT_ROOT / "data" / "benchmarks" / "results" / "latest.json",
    )

    # ── Summary ──
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    failed = sum(1 for _, ok, _ in RESULTS if not ok)

    print(f"\n{'=' * 60}")
    print(f"RESULTS: {passed} passed, {failed} failed")
    print(f"{'=' * 60}")

    if failed:
        print("\nFailed gates:")
        for name, ok, detail in RESULTS:
            if not ok:
                print(f"  FAIL: {name} — {detail}")

    # ── Manual Reminders ──
    print("\n[4/4] Manual Checks (not automated — complete before release)")
    print("  [ ] Integration tests pass locally (Person 2)")
    print("  [ ] Real-LLM benchmark G1 with f1 >= 0.5 (Person 1)")
    print("  [ ] Real-LLM benchmark G2 with f1 >= 0.5 (Person 1)")
    print("  [ ] Prompt injection → needs_human verified (Person 1)")
    print("  [ ] Sandbox simulate+analyze for sqli/xss/bruteforce (Person 5)")
    print("  [ ] Frontend renders API response with trace (Person 1)")
    print("\nSignoff required from: Person 1 + Person 2 + one of Person 3/4/5")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
