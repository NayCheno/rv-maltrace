from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/counter_access_matrix_summary.json")
SUMMARY_SCHEMA = "rvmt.genesys2.counter_access_matrix.v1"
COUNTER_ACCESS_RE = re.compile(
    r"RVMT_COUNTER_ACCESS name=(?P<name>\S+) status=(?P<status>\S+)"
    r"(?: first=(?P<first>\d+) second=(?P<second>\d+) immediate_delta=(?P<immediate_delta>\d+))?"
)
COUNTER_DELTA_RE = re.compile(
    r"RVMT_COUNTER_DELTA rep=(?P<rep>\d+) name=(?P<name>\S+) "
    r"loop_delta=(?P<loop_delta>\d+) syscall_delta=(?P<syscall_delta>\d+) "
    r"total_delta=(?P<total_delta>\d+) pid=(?P<pid>-?\d+) sink=(?P<sink>\d+)"
)
CLOCK_ACCESS_RE = re.compile(
    r"RVMT_CLOCK_ACCESS name=(?P<name>\S+) status=(?P<status>\S+)"
    r"(?: res_ns=(?P<res_ns>-?\d+) immediate_delta_ns=(?P<immediate_delta_ns>-?\d+))?"
    r"(?: op=(?P<op>\S+) errno=(?P<errno>-?\d+) reason=(?P<reason>.*))?"
)
CLOCK_DELTA_RE = re.compile(
    r"RVMT_CLOCK_DELTA rep=(?P<rep>\d+) name=(?P<name>\S+) "
    r"loop_delta_ns=(?P<loop_delta_ns>-?\d+) syscall_delta_ns=(?P<syscall_delta_ns>-?\d+) "
    r"total_delta_ns=(?P<total_delta_ns>-?\d+) pid=(?P<pid>-?\d+) sink=(?P<sink>\d+)"
)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rel_or_abs(root: Path, value: str) -> Path:
    candidate = Path(value)
    return candidate if candidate.is_absolute() else root / candidate


def repo_rel(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def artifact_row(root: Path, path: Path) -> dict[str, Any]:
    return {
        "path": repo_rel(root, path),
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def parse_matrix_log(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    counter_access: dict[str, dict[str, Any]] = {}
    counter_rows: list[dict[str, Any]] = []
    clock_access: dict[str, dict[str, Any]] = {}
    clock_rows: list[dict[str, Any]] = []
    for match in COUNTER_ACCESS_RE.finditer(text):
        row: dict[str, Any] = {"name": match.group("name"), "status": match.group("status")}
        for key in ("first", "second", "immediate_delta"):
            value = match.group(key)
            if value is not None:
                row[key] = int(value, 10)
        counter_access[row["name"]] = row
    for match in COUNTER_DELTA_RE.finditer(text):
        row = {"name": match.group("name")}
        for key in ("rep", "loop_delta", "syscall_delta", "total_delta", "pid", "sink"):
            row[key] = int(match.group(key), 10)
        counter_rows.append(row)
    for match in CLOCK_ACCESS_RE.finditer(text):
        row = {"name": match.group("name"), "status": match.group("status")}
        for key in ("res_ns", "immediate_delta_ns", "errno"):
            value = match.group(key)
            if value is not None:
                row[key] = int(value, 10)
        for key in ("op", "reason"):
            value = match.group(key)
            if value is not None:
                row[key] = value.strip()
        clock_access[row["name"]] = row
    for match in CLOCK_DELTA_RE.finditer(text):
        row = {"name": match.group("name")}
        for key in ("rep", "loop_delta_ns", "syscall_delta_ns", "total_delta_ns", "pid", "sink"):
            row[key] = int(match.group(key), 10)
        clock_rows.append(row)
    return {
        "counter_access": counter_access,
        "counter_rows": counter_rows,
        "clock_access": clock_access,
        "clock_rows": clock_rows,
    }


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def check_artifact(errors: list[str], root: Path, summary: dict[str, Any], name: str) -> Path | None:
    artifacts = summary.get("artifacts") if isinstance(summary.get("artifacts"), dict) else {}
    row = artifacts.get(name) if isinstance(artifacts.get(name), dict) else {}
    value = row.get("path")
    if not value:
        errors.append(f"artifact missing: {name}")
        return None
    path = rel_or_abs(root, str(value))
    if not path.is_file():
        errors.append(f"artifact file missing: {name}: {value}")
        return None
    require(errors, row.get("sha256") == sha256_file(path), f"artifact sha256 mismatch: {name}")
    return path


def counter_available(data: dict[str, Any], name: str) -> bool:
    access = data.get("counter_access") if isinstance(data.get("counter_access"), dict) else {}
    row = access.get(name) if isinstance(access.get(name), dict) else {}
    return row.get("status") == "AVAILABLE"


def clock_available(data: dict[str, Any], name: str) -> bool:
    access = data.get("clock_access") if isinstance(data.get("clock_access"), dict) else {}
    row = access.get(name) if isinstance(access.get(name), dict) else {}
    return row.get("status") == "AVAILABLE"


def check_summary(root: Path, path: Path, *, require_pass: bool) -> list[str]:
    errors: list[str] = []
    data = load_json(path)
    require(errors, data.get("schema") == SUMMARY_SCHEMA, f"schema must be {SUMMARY_SCHEMA}")
    status = str(data.get("status") or "")
    if require_pass:
        require(errors, status == "PASS", f"status must be PASS under --require-pass, got {status}")
    else:
        require(errors, status == "PASS" or status.startswith("BLOCKED_"), f"status must be PASS or truthful BLOCKED status, got {status}")
    for name in ("source", "binary", "build_manifest", "run_log"):
        check_artifact(errors, root, data, name)
    run_log = check_artifact(errors, root, data, "run_log")
    if run_log is not None:
        parsed = parse_matrix_log(run_log)
        require(errors, parsed.get("counter_access") == data.get("counter_access"), "counter_access must match run_log parse")
        require(errors, parsed.get("counter_rows") == data.get("counter_rows"), "counter_rows must match run_log parse")
        require(errors, parsed.get("clock_access") == data.get("clock_access"), "clock_access must match run_log parse")
        require(errors, parsed.get("clock_rows") == data.get("clock_rows"), "clock_rows must match run_log parse")
    boundary = data.get("claim_boundary") if isinstance(data.get("claim_boundary"), dict) else {}
    if status == "PASS":
        require(errors, counter_available(data, "cycle"), "PASS requires user rdcycle to be available")
        require(errors, boundary.get("board_cycle_counter_claimed") is True, "PASS must claim board cycle counter availability")
    else:
        require(errors, boundary.get("board_cycle_counter_claimed") is False, "BLOCKED summary must not claim board cycle counter")
        require(errors, bool(data.get("blocked_reason")), "BLOCKED summary must include blocked_reason")
    require(errors, boundary.get("cycle_level_overhead_claimed") is False, "matrix probe must not claim cycle-level overhead")
    require(errors, boundary.get("production_runtime_slowdown_claimed") is False, "matrix probe must not claim production slowdown")
    require(errors, boundary.get("board_rdtime_source_observed") is counter_available(data, "time"), "rdtime observation boundary mismatch")
    require(
        errors,
        boundary.get("board_clock_gettime_source_observed")
        is (clock_available(data, "clock_monotonic") or clock_available(data, "clock_monotonic_raw")),
        "clock_gettime observation boundary mismatch",
    )
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-counter-access-matrix-") as tmp:
        root = Path(tmp)
        source = root / "board/trace_validation/programs/counter_access_matrix.c"
        binary = root / "build/board/genesys2_counter_access_matrix/counter_access_matrix.riscv64"
        build_manifest = root / "build/board/genesys2_counter_access_matrix/build_manifest.json"
        run_log = root / "results/board/genesys2_trace_validation/counter_matrix/uart.log"
        for path, text in (
            (source, "int main(void) { return 0; }\n"),
            (binary, "ELF fixture\n"),
            (build_manifest, '{"status":"PASS"}\n'),
            (
                run_log,
                "RVMT_COUNTER_MATRIX_BEGIN reps=2 iters=100\n"
                "RVMT_COUNTER_ACCESS name=cycle status=ILLEGAL_INSTRUCTION\n"
                "RVMT_COUNTER_ACCESS name=time status=AVAILABLE first=10 second=12 immediate_delta=2\n"
                "RVMT_COUNTER_DELTA rep=1 name=time loop_delta=100 syscall_delta=10 total_delta=110 pid=1 sink=7\n"
                "RVMT_COUNTER_DELTA rep=2 name=time loop_delta=101 syscall_delta=11 total_delta=112 pid=1 sink=8\n"
                "RVMT_COUNTER_ACCESS name=instret status=ILLEGAL_INSTRUCTION\n"
                "RVMT_CLOCK_ACCESS name=clock_monotonic status=AVAILABLE res_ns=1 immediate_delta_ns=30\n"
                "RVMT_CLOCK_DELTA rep=1 name=clock_monotonic loop_delta_ns=1000 syscall_delta_ns=300 total_delta_ns=1300 pid=1 sink=7\n"
                "RVMT_COUNTER_MATRIX_DONE reps=2 iters=100\n",
            ),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
        parsed = parse_matrix_log(run_log)
        summary = root / DEFAULT_SUMMARY
        write_json(
            summary,
            {
                "schema": SUMMARY_SCHEMA,
                "status": "BLOCKED_BOARD_CYCLE_COUNTER_UNAVAILABLE_NONCYCLE_TIME_AVAILABLE",
                "blocked_reason": "user rdcycle is unavailable; rdtime and/or clock_gettime remain available as non-cycle time sources",
                **parsed,
                "artifacts": {
                    "source": artifact_row(root, source),
                    "binary": artifact_row(root, binary),
                    "build_manifest": artifact_row(root, build_manifest),
                    "run_log": artifact_row(root, run_log),
                },
                "claim_boundary": {
                    "board_cycle_counter_claimed": False,
                    "board_rdtime_source_observed": True,
                    "board_clock_gettime_source_observed": True,
                    "cycle_level_overhead_claimed": False,
                    "production_runtime_slowdown_claimed": False,
                },
            },
        )
        errors = check_summary(root, summary, require_pass=False)
        if errors:
            print("[FAIL] counter-access matrix checker self-test", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
            return 1
        require_errors = check_summary(root, summary, require_pass=True)
        if not require_errors:
            print("[FAIL] counter-access matrix --require-pass accepted blocked fixture", file=sys.stderr)
            return 1
    print("[PASS] counter-access matrix checker self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check a Genesys2/CVA6 board counter-access matrix summary.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--require-pass", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = args.summary if args.summary.is_absolute() else root / args.summary
    if not summary.is_file():
        if args.require_pass:
            print(f"[FAIL] counter-access matrix summary missing: {summary}", file=sys.stderr)
            return 1
        print(f"[BLOCKED_HOST_GENESYS2_REQUIRED] counter-access matrix summary missing: {summary}")
        return 0
    errors = check_summary(root, summary, require_pass=args.require_pass)
    if errors:
        print("[FAIL] counter-access matrix summary is not acceptable", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    data = load_json(summary)
    print(f"[PASS] counter-access matrix summary accepted: {summary} status={data.get('status')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
