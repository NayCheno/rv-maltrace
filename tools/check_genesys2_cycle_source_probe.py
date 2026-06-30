from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from genesys2_experiment_common import artifact_row, check_artifact, load_json, require, write_json


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/cycle_source_probe_summary.json")
SUMMARY_SCHEMA = "rvmt.genesys2.cycle_source_probe.v1"
ROW_RE = re.compile(
    r"RVMT_CYCLE_SOURCE rep=(?P<rep>\d+) "
    r"source=(?P<source>\S+) "
    r"loop_delta=(?P<loop_delta>0x[0-9a-fA-F]+|\d+) "
    r"syscall_delta=(?P<syscall_delta>0x[0-9a-fA-F]+|\d+) "
    r"total_delta=(?P<total_delta>0x[0-9a-fA-F]+|\d+) "
    r"pid=(?P<pid>-?0x[0-9a-fA-F]+|-?\d+) "
    r"sink=(?P<sink>0x[0-9a-fA-F]+|\d+)"
)
UNAVAILABLE_RE = re.compile(r"RVMT_CYCLE_SOURCE_UNAVAILABLE source=(?P<source>\S+) reason=(?P<reason>\S+) code=(?P<code>-?\d+)")


def parse_probe_log(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    text = path.read_text(encoding="utf-8", errors="replace")
    unavailable = None
    unavailable_match = UNAVAILABLE_RE.search(text)
    if unavailable_match:
        unavailable = {
            "source": unavailable_match.group("source"),
            "reason": unavailable_match.group("reason"),
            "code": int(unavailable_match.group("code"), 10),
        }
    rows: list[dict[str, Any]] = []
    for match in ROW_RE.finditer(text):
        row: dict[str, Any] = {}
        for key, value in match.groupdict().items():
            row[key] = value if key == "source" else int(value, 0)
        rows.append(row)
    return rows, unavailable


def check_summary(root: Path, path: Path, *, require_pass: bool) -> list[str]:
    errors: list[str] = []
    data = load_json(path)
    require(errors, data.get("schema") == SUMMARY_SCHEMA, f"schema must be {SUMMARY_SCHEMA}")
    require(errors, data.get("cycle_source") == "kernel_perf_hw_cycles", "cycle_source must be kernel_perf_hw_cycles")
    status = str(data.get("status") or "")
    if require_pass:
        require(errors, status == "PASS", f"status must be PASS under --require-pass, got {status}")
    else:
        require(errors, status == "PASS" or status.startswith("BLOCKED_"), f"status must be PASS or truthful BLOCKED status, got {status}")
    for name in ("source", "binary", "build_manifest", "run_log"):
        check_artifact(errors, root, data, name)
    if status == "PASS":
        run_log = check_artifact(errors, root, data, "run_log")
        if run_log is not None:
            parsed_rows, unavailable = parse_probe_log(run_log)
            require(errors, unavailable is None, f"cycle source reported unavailable: {unavailable}")
            require(errors, len(parsed_rows) >= int(data.get("minimum_repetitions") or 0), "cycle-source row count below minimum")
            require(errors, parsed_rows == data.get("rows"), "summary rows must match run_log parse")
        rows = data.get("rows") if isinstance(data.get("rows"), list) else []
        require(errors, bool(rows), "PASS summary must include rows")
        for row in rows:
            if not isinstance(row, dict):
                errors.append("cycle-source row must be an object")
                continue
            require(errors, row.get("source") == "perf_hw_cycles", "row source must be perf_hw_cycles")
            require(errors, int(row.get("loop_delta") or 0) > 0, "loop_delta must be positive")
            require(errors, int(row.get("syscall_delta") or 0) > 0, "syscall_delta must be positive")
            require(errors, int(row.get("total_delta") or 0) > 0, "total_delta must be positive")
        boundary = data.get("claim_boundary") if isinstance(data.get("claim_boundary"), dict) else {}
        require(errors, boundary.get("board_kernel_perf_cycle_source_claimed") is True, "PASS must claim board kernel perf cycle source")
        require(errors, boundary.get("board_rdcycle_smoke_claimed") is False, "perf-source PASS must not claim board rdcycle smoke")
        require(errors, boundary.get("cycle_level_overhead_claimed") is False, "source probe must not claim cycle-level overhead")
        require(errors, boundary.get("production_runtime_slowdown_claimed") is False, "source probe must not claim production slowdown")
    else:
        boundary = data.get("claim_boundary") if isinstance(data.get("claim_boundary"), dict) else {}
        require(errors, boundary.get("board_kernel_perf_cycle_source_claimed") is False, "BLOCKED summary must not claim board perf cycle source")
        require(errors, boundary.get("cycle_level_overhead_claimed") is False, "BLOCKED summary must not claim cycle-level overhead")
        require(errors, bool(data.get("blocked_reason")), "BLOCKED summary must include blocked_reason")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-cycle-source-probe-") as tmp:
        root = Path(tmp)
        source = root / "board/trace_validation/programs/cycle_source_probe.c"
        binary = root / "build/board/genesys2_cycle_source_probe/cycle_source_probe.riscv64"
        build_manifest = root / "build/board/genesys2_cycle_source_probe/build_manifest.json"
        run_log = root / "results/board/genesys2_trace_validation/cycle_source/uart.log"
        for path, text in (
            (source, "int main(void) { return 0; }\n"),
            (binary, "ELF fixture\n"),
            (build_manifest, '{"status":"PASS"}\n'),
            (
                run_log,
                "RVMT_CYCLE_SOURCE_BEGIN source=perf_hw_cycles reps=2 iters=100\n"
                "RVMT_CYCLE_SOURCE_AVAILABLE source=perf_hw_cycles value=10\n"
                "RVMT_CYCLE_SOURCE rep=1 source=perf_hw_cycles loop_delta=100 syscall_delta=20 total_delta=120 pid=1 sink=7\n"
                "RVMT_CYCLE_SOURCE rep=2 source=perf_hw_cycles loop_delta=101 syscall_delta=21 total_delta=122 pid=1 sink=8\n"
                "RVMT_CYCLE_SOURCE_DONE source=perf_hw_cycles reps=2\n",
            ),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
        rows, unavailable = parse_probe_log(run_log)
        assert unavailable is None
        summary = root / DEFAULT_SUMMARY
        write_json(
            summary,
            {
                "schema": SUMMARY_SCHEMA,
                "status": "PASS",
                "cycle_source": "kernel_perf_hw_cycles",
                "minimum_repetitions": 2,
                "rows": rows,
                "artifacts": {
                    "source": artifact_row(root, source),
                    "binary": artifact_row(root, binary),
                    "build_manifest": artifact_row(root, build_manifest),
                    "run_log": artifact_row(root, run_log),
                },
                "claim_boundary": {
                    "board_kernel_perf_cycle_source_claimed": True,
                    "board_rdcycle_smoke_claimed": False,
                    "cycle_level_overhead_claimed": False,
                    "production_runtime_slowdown_claimed": False,
                },
            },
        )
        errors = check_summary(root, summary, require_pass=True)
        if errors:
            print("[FAIL] cycle-source probe checker self-test", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
            return 1
    print("[PASS] cycle-source probe checker self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check a Genesys2/CVA6 board kernel-perf cycle-source probe summary.")
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
            print(f"[FAIL] cycle-source probe summary missing: {summary}", file=sys.stderr)
            return 1
        print(f"[BLOCKED_HOST_GENESYS2_REQUIRED] cycle-source probe summary missing: {summary}")
        return 0
    errors = check_summary(root, summary, require_pass=args.require_pass)
    if errors:
        print("[FAIL] cycle-source probe summary is not acceptable", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    data = load_json(summary)
    print(f"[PASS] cycle-source probe summary accepted: {summary} status={data.get('status')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
