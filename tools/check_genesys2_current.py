from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple


class CheckSpec(NamedTuple):
    label: str
    script: Path


DEFAULT_CHECKS = (
    CheckSpec("Genesys2/CVA6 board baseline evidence", Path("tools/check_board_baseline.py")),
    CheckSpec("Genesys2/CVA6 minimal trace policy", Path("tools/check_board_trace_minimal.py")),
    CheckSpec("Genesys2/CVA6 board trace validation program plan", Path("tools/check_board_trace_programs.py")),
    CheckSpec("Genesys2/CVA6 safe surrogate evidence boundary", Path("tools/check_genesys2_safe_surrogate.py")),
)


def command_for(root: Path, spec: CheckSpec) -> list[str]:
    return [sys.executable, str(root / spec.script), "--root", str(root)]


def display_command(root: Path, spec: CheckSpec) -> str:
    return f"uv run python {spec.script.as_posix()} --root {root}"


def selected_checks(skip_safe_surrogate: bool) -> tuple[CheckSpec, ...]:
    if not skip_safe_surrogate:
        return DEFAULT_CHECKS
    return tuple(spec for spec in DEFAULT_CHECKS if spec.script.name != "check_genesys2_safe_surrogate.py")


def self_test() -> int:
    scripts = {spec.script.as_posix() for spec in DEFAULT_CHECKS}
    required = {
        "tools/check_board_baseline.py",
        "tools/check_board_trace_minimal.py",
        "tools/check_board_trace_programs.py",
        "tools/check_genesys2_safe_surrogate.py",
    }
    missing = sorted(required - scripts)
    if missing:
        print(f"[FAIL] missing required Genesys2 checks: {', '.join(missing)}", file=sys.stderr)
        return 1
    legacy = [spec.script.as_posix() for spec in DEFAULT_CHECKS if "35t" in spec.script.as_posix().lower()]
    if legacy:
        print(f"[FAIL] current gate must not include legacy 35T checks: {', '.join(legacy)}", file=sys.stderr)
        return 1
    skipped = selected_checks(skip_safe_surrogate=True)
    if any(spec.script.name == "check_genesys2_safe_surrogate.py" for spec in skipped):
        print("[FAIL] --skip-safe-surrogate did not remove the safe surrogate gate", file=sys.stderr)
        return 1
    if len(skipped) != len(DEFAULT_CHECKS) - 1:
        print("[FAIL] --skip-safe-surrogate changed the wrong number of checks", file=sys.stderr)
        return 1
    print("[PASS] Genesys2/CVA6 current gate self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the current Digilent Genesys2 + CVA6 repository gates. "
            "This intentionally excludes legacy 35T checks."
        )
    )
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root. Defaults to current directory.")
    parser.add_argument("--list", action="store_true", help="List the commands without running them.")
    parser.add_argument("--self-test", action="store_true", help="Check the gate composition without running evidence gates.")
    parser.add_argument(
        "--skip-safe-surrogate",
        action="store_true",
        help="Run only the board/baseline gates, omitting the safe surrogate evidence boundary gate.",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    root = args.root.resolve()
    checks = selected_checks(args.skip_safe_surrogate)
    if args.list:
        for spec in checks:
            print(f"{spec.label}: {display_command(root, spec)}")
        return 0

    failed: list[str] = []
    for index, spec in enumerate(checks, start=1):
        script = root / spec.script
        if not script.is_file():
            print(f"[FAIL] {spec.label}: missing {spec.script.as_posix()}", file=sys.stderr)
            failed.append(spec.label)
            continue
        print(f"[RUN {index}/{len(checks)}] {spec.label}", flush=True)
        result = subprocess.run(command_for(root, spec), cwd=root)
        if result.returncode != 0:
            print(f"[FAIL] {spec.label}: exit {result.returncode}", file=sys.stderr)
            failed.append(spec.label)
        else:
            print(f"[PASS] {spec.label}")

    if failed:
        print("[FAIL] Genesys2/CVA6 current gate failed: " + ", ".join(failed), file=sys.stderr)
        return 1
    print("[PASS] Genesys2/CVA6 current gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
