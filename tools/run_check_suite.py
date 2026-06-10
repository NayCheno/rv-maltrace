from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


DEFAULT_MANIFEST = Path("tools/check_suites.json")
REQUIRED_GENESYS2_CURRENT_SCRIPTS = {
    "tools/check_board_baseline.py",
    "tools/check_board_trace_minimal.py",
    "tools/check_board_trace_programs.py",
    "tools/check_board_trace_evidence.py",
    "tools/check_board_local_code_analysis.py",
    "tools/check_genesys2_safe_surrogate.py",
    "tools/check_genesys2_safe_surrogate_coverage.py",
}


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def load_manifest(root: Path, manifest_path: Path) -> dict[str, Any]:
    path = resolve(root, manifest_path)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def suites_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    suites = manifest.get("suites")
    if not isinstance(suites, list):
        raise ValueError("manifest.suites must be a list")
    result: dict[str, dict[str, Any]] = {}
    for suite in suites:
        if not isinstance(suite, dict):
            raise ValueError("suite entries must be objects")
        suite_id = suite.get("id")
        if not isinstance(suite_id, str) or not suite_id:
            raise ValueError("suite.id must be a nonempty string")
        if suite_id in result:
            raise ValueError(f"duplicate suite id: {suite_id}")
        result[suite_id] = suite
    return result


def command_tokens(check: dict[str, Any]) -> list[str]:
    command = check.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command):
        raise ValueError(f"{check.get('id', '<unknown>')}: command must be a nonempty string list")
    return command


def expand_command(command: list[str], root: Path) -> list[str]:
    replacements = {
        "{python}": sys.executable,
        "{root}": str(root),
    }
    return [replacements.get(token, token) for token in command]


def display_command(command: list[str], root: Path) -> str:
    expanded = expand_command(command, root)
    if command[0] == "{python}" and len(command) >= 2:
        rest = [token if token != "{root}" else str(root) for token in command[1:]]
        return "uv run python " + " ".join(rest)
    return " ".join(expanded)


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes, remainder = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m {remainder:.1f}s"
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)}h {int(minutes)}m {remainder:.0f}s"


def runtime_note(item: dict[str, Any]) -> str:
    parts: list[str] = []
    if item.get("long"):
        parts.append("long")
    expected_seconds = item.get("expected_seconds")
    expected_minutes = item.get("expected_minutes")
    if isinstance(expected_seconds, (int, float)):
        parts.append(f"expected ~{format_duration(float(expected_seconds))}")
    elif isinstance(expected_minutes, (int, float)):
        parts.append(f"expected ~{format_duration(float(expected_minutes) * 60)}")
    return ", ".join(parts)


def iter_checks(suite: dict[str, Any]) -> list[dict[str, Any]]:
    checks = suite.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ValueError(f"{suite.get('id', '<unknown>')}: checks must be a nonempty list")
    for check in checks:
        if not isinstance(check, dict):
            raise ValueError(f"{suite.get('id', '<unknown>')}: check entries must be objects")
    return checks


def list_suites(manifest: dict[str, Any]) -> None:
    for suite in suites_by_id(manifest).values():
        legacy = " legacy" if suite.get("legacy") else ""
        current = " current" if suite.get("current") else ""
        long = " long" if suite.get("long") else ""
        tier = suite.get("tier", "uncategorized")
        note = runtime_note(suite)
        suffix = f" ({note})" if note else ""
        print(f"{suite['id']}: {suite.get('title', '')} [{tier}{current}{legacy}{long}]{suffix}")


def list_checks(suite: dict[str, Any], root: Path) -> None:
    for check in iter_checks(suite):
        command = command_tokens(check)
        print(f"{check.get('id')}: {check.get('label', '')}")
        note = runtime_note(check)
        if note:
            print(f"  runtime: {note}")
        print(f"  {display_command(command, root)}")


def run_suite(suite: dict[str, Any], root: Path, dry_run: bool) -> int:
    checks = iter_checks(suite)
    failed: list[str] = []
    total_started = time.perf_counter()
    for index, check in enumerate(checks, start=1):
        check_id = str(check.get("id", f"check-{index}"))
        label = str(check.get("label", check_id))
        command = command_tokens(check)
        print(f"[RUN {index}/{len(checks)}] {check_id}: {label}", flush=True)
        note = runtime_note(check)
        if note:
            print(f"  runtime: {note}", flush=True)
        print(f"  {display_command(command, root)}", flush=True)
        if dry_run:
            continue
        started = time.perf_counter()
        result = subprocess.run(expand_command(command, root), cwd=root)
        elapsed = time.perf_counter() - started
        if result.returncode != 0:
            print(f"[FAIL] {check_id}: exit {result.returncode} after {format_duration(elapsed)}", file=sys.stderr)
            failed.append(check_id)
        else:
            print(f"[PASS] {check_id} ({format_duration(elapsed)})")
    if failed:
        elapsed = time.perf_counter() - total_started
        print(f"[FAIL] suite {suite['id']} failed after {format_duration(elapsed)}: {', '.join(failed)}", file=sys.stderr)
        return 1
    elapsed = time.perf_counter() - total_started
    print(
        f"[PASS] suite {suite['id']} ({format_duration(elapsed)})"
        if not dry_run
        else f"[PASS] suite {suite['id']} dry-run"
    )
    return 0


def python_script_from(command: list[str]) -> str | None:
    if len(command) >= 2 and command[0] == "{python}" and command[1].endswith(".py"):
        return command[1]
    return None


def validate_manifest(root: Path, manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema") != "rvmt.check_suites.v1":
        errors.append("manifest.schema must be rvmt.check_suites.v1")
    try:
        suites = suites_by_id(manifest)
    except ValueError as exc:
        return [str(exc)]
    if "genesys2-current" not in suites:
        errors.append("missing genesys2-current suite")
    if "repo-hygiene" not in suites:
        errors.append("missing repo-hygiene suite")

    for suite_id, suite in suites.items():
        if suite.get("long") and suite_id == "genesys2-current":
            errors.append("genesys2-current must remain a fast non-long suite")
        seen_checks: set[str] = set()
        try:
            checks = iter_checks(suite)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        for check in checks:
            check_id = check.get("id")
            if not isinstance(check_id, str) or not check_id:
                errors.append(f"{suite_id}: check.id must be a nonempty string")
                continue
            if check_id in seen_checks:
                errors.append(f"{suite_id}: duplicate check id {check_id}")
            seen_checks.add(check_id)
            try:
                command = command_tokens(check)
            except ValueError as exc:
                errors.append(str(exc))
                continue
            script = python_script_from(command)
            if script and not resolve(root, Path(script)).is_file():
                errors.append(f"{suite_id}.{check_id}: missing script {script}")
            if suite.get("current") and not suite.get("legacy"):
                text = json.dumps({"suite": suite_id, "check": check}, sort_keys=True).lower()
                if "35t" in text:
                    errors.append(f"{suite_id}.{check_id}: current suites must not include 35T checks")

    current = suites.get("genesys2-current")
    if current:
        scripts = {
            script
            for check in iter_checks(current)
            for script in [python_script_from(command_tokens(check))]
            if script
        }
        if scripts != REQUIRED_GENESYS2_CURRENT_SCRIPTS:
            errors.append(
                "genesys2-current scripts mismatch: expected "
                + ", ".join(sorted(REQUIRED_GENESYS2_CURRENT_SCRIPTS))
            )
    return errors


def self_test(root: Path, manifest_path: Path) -> int:
    try:
        manifest = load_manifest(root, manifest_path)
    except Exception as exc:
        print(f"[FAIL] check suite manifest self-test: {exc}", file=sys.stderr)
        return 1
    errors = validate_manifest(root, manifest)
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] check suite manifest self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run organized rv-maltrace check suites.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root. Defaults to current directory.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--suite", help="Suite id to run or list.")
    parser.add_argument("--list-suites", action="store_true", help="List available suites.")
    parser.add_argument("--list-checks", action="store_true", help="List checks in --suite without running them.")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without running them.")
    parser.add_argument("--include-legacy", action="store_true", help="Allow running suites marked as legacy.")
    parser.add_argument("--include-long", action="store_true", help="Allow running suites marked as long.")
    parser.add_argument("--self-test", action="store_true", help="Validate the suite manifest.")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    if args.self_test:
        return self_test(root, args.manifest)

    try:
        manifest = load_manifest(root, args.manifest)
        suites = suites_by_id(manifest)
    except Exception as exc:
        print(f"run_check_suite: error: {exc}", file=sys.stderr)
        return 2

    if args.list_suites:
        list_suites(manifest)
        return 0

    if not args.suite:
        print("run_check_suite: error: --suite is required unless --list-suites or --self-test is used", file=sys.stderr)
        return 2
    suite = suites.get(args.suite)
    if suite is None:
        print(f"run_check_suite: error: unknown suite {args.suite!r}", file=sys.stderr)
        return 2
    if suite.get("legacy") and not args.include_legacy:
        print(f"run_check_suite: error: suite {args.suite!r} is legacy; pass --include-legacy to run it", file=sys.stderr)
        return 2
    if suite.get("long") and not args.include_long and not args.dry_run:
        print(f"run_check_suite: error: suite {args.suite!r} is long; pass --include-long to run it", file=sys.stderr)
        return 2
    if args.list_checks:
        list_checks(suite, root)
        return 0
    return run_suite(suite, root, args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
