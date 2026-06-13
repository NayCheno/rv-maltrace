from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


QUICK_COMMANDS = [
    ["tools/check_genesys2_reproducibility_manifest.py", "--root", "{root}"],
    ["tools/check_genesys2_artifact_package.py", "--root", "{root}"],
    ["tools/check_ccfa_case_study_manifest.py", "--root", "{root}"],
    ["tools/check_ccfa_current_quality.py", "--root", "{root}"],
    ["tools/run_check_suite.py", "--suite", "genesys2-current"],
]

FULL_EXTRA_COMMANDS = [
    ["tools/run_check_suite.py", "--suite", "genesys2-artifacts"],
    ["tools/run_check_suite.py", "--suite", "genesys2-self-test"],
    ["tools/run_check_suite.py", "--suite", "ccfa-gate-self-test"],
]


def expand(command: list[str], root: Path) -> list[str]:
    return [sys.executable, *[str(root) if token == "{root}" else token for token in command]]


def display(command: list[str], root: Path) -> str:
    return "uv run python " + " ".join(str(root) if token == "{root}" else token for token in command)


def commands(full: bool) -> list[list[str]]:
    return [*QUICK_COMMANDS, *(FULL_EXTRA_COMMANDS if full else [])]


def run_commands(root: Path, full: bool, dry_run: bool) -> int:
    failed: list[str] = []
    selected = commands(full)
    for index, command in enumerate(selected, start=1):
        print(f"[RUN {index}/{len(selected)}] {display(command, root)}", flush=True)
        if dry_run:
            continue
        result = subprocess.run(expand(command, root), cwd=root)
        if result.returncode != 0:
            failed.append(" ".join(command))
            print(f"[FAIL] reproduction command exited {result.returncode}", file=sys.stderr, flush=True)
        else:
            print("[PASS] reproduction command", flush=True)
    if failed:
        print("[FAIL] Genesys2/CVA6 current reproduction failed", file=sys.stderr)
        for command in failed:
            print(f"- {command}", file=sys.stderr)
        return 1
    print("[PASS] Genesys2/CVA6 current reproduction command set")
    return 0


def self_test() -> int:
    quick = "\n".join(display(command, Path(".")) for command in commands(full=False))
    full = "\n".join(display(command, Path(".")) for command in commands(full=True))
    required = [
        "tools/check_genesys2_reproducibility_manifest.py --root .",
        "tools/check_genesys2_artifact_package.py --root .",
        "tools/check_ccfa_case_study_manifest.py --root .",
        "tools/check_ccfa_current_quality.py --root .",
        "tools/run_check_suite.py --suite genesys2-current",
        "tools/run_check_suite.py --suite genesys2-artifacts",
        "tools/run_check_suite.py --suite genesys2-self-test",
        "tools/run_check_suite.py --suite ccfa-gate-self-test",
    ]
    missing = [item for item in required if item not in full]
    if missing:
        print("[FAIL] reproduction self-test missing commands", file=sys.stderr)
        for item in missing:
            print(f"- {item}", file=sys.stderr)
        return 1
    if "genesys2-artifacts" in quick:
        print("[FAIL] quick reproduction should avoid artifact inventory", file=sys.stderr)
        return 1
    print("[PASS] Genesys2/CVA6 reproduction script self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reproduce the current controlled Genesys2/CVA6 evidence gates from a fresh clone.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--quick", action="store_true", help="Run the fast current evidence reproduction set.")
    parser.add_argument("--full", action="store_true", help="Run quick checks plus artifact inventory and self-tests.")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing them.")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    full = bool(args.full)
    if args.quick and args.full:
        print("[FAIL] choose only one of --quick or --full", file=sys.stderr)
        return 2
    return run_commands(root, full=full, dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
