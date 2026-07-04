from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import load_json, repo_path, require, write_json
from run_genesys2_hardware_trace_cycle_window import SCHEMA


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/hardware_trace_cycle_window_summary.json")


def num(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def check_file_row(errors: list[str], root: Path, row: Any, label: str) -> None:
    if not isinstance(row, dict):
        errors.append(f"{label}: file row must be an object")
        return
    path = row.get("path")
    require(errors, bool(path), f"{label}: path missing")
    if path:
        actual = repo_path(root, str(path))
        require(errors, actual.is_file(), f"{label}: file missing: {path}")
        if actual.is_file():
            require(errors, num(row.get("size_bytes")) == actual.stat().st_size, f"{label}: size_bytes mismatch")
    digest = str(row.get("sha256") or "")
    require(errors, len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest), f"{label}: sha256 invalid")


def validate_summary(root: Path, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == SCHEMA, f"schema must be {SCHEMA}")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("cycle_source") == "rv_maltrace_fpga_trace_cycle_field", "cycle_source mismatch")
    boundary = data.get("claim_boundary") if isinstance(data.get("claim_boundary"), dict) else {}
    require(errors, boundary.get("hardware_trace_cycle_window_claimed") is True, "hardware trace cycle claim must be true")
    require(errors, boundary.get("linux_perf_cycle_source_claimed") is False, "must not claim Linux perf cycle source")
    require(errors, boundary.get("user_rdcycle_source_claimed") is False, "must not claim user rdcycle source")
    require(errors, boundary.get("trace_off_slowdown_claimed") is False, "must not claim trace-off slowdown")
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "not linux perf" in non_claims or "not linux perf_event_open" in non_claims, "non_claims must exclude Linux perf")
    require(errors, "does not by itself claim trace-off slowdown" in non_claims, "non_claims must exclude trace-off slowdown")
    policy = data.get("acceptance_policy") if isinstance(data.get("acceptance_policy"), dict) else {}
    required_policy = " ".join(str(item).lower() for item in as_list(policy.get("required")))
    auxiliary_policy = " ".join(str(item).lower() for item in as_list(policy.get("auxiliary")))
    require(errors, "bram" in required_policy and "marker" in required_policy, "acceptance policy must require BRAM marker evidence")
    require(errors, "uart" in auxiliary_policy and "not required" in auxiliary_policy, "acceptance policy must make UART rc auxiliary")

    repetitions = [row for row in as_list(data.get("repetitions")) if isinstance(row, dict)]
    accepted = [row for row in repetitions if row.get("accepted") is True]
    require(errors, len(accepted) >= int(num(data.get("minimum_repetitions"), 1)), "accepted repetitions below minimum")
    stats = data.get("marker_cycle_delta_stats") if isinstance(data.get("marker_cycle_delta_stats"), dict) else {}
    require(errors, num(stats.get("count")) == len(accepted), "marker delta stats count mismatch")
    require(errors, num(stats.get("median")) > 0, "marker cycle delta median must be positive")

    if data.get("bitstream") is not None:
        check_file_row(errors, root, data.get("bitstream"), "bitstream")
    if data.get("ltx") is not None:
        check_file_row(errors, root, data.get("ltx"), "ltx")

    for index, rep in enumerate(accepted, start=1):
        label = f"rep[{index}] {rep.get('sample_id')}/{rep.get('repetition')}"
        require(errors, num(rep.get("begin_marker_count")) == 1, f"{label}: begin marker must be unique")
        require(errors, num(rep.get("end_marker_count")) == 1, f"{label}: end marker must be unique")
        require(errors, num(rep.get("marker_cycle_delta")) > 0, f"{label}: marker cycle delta must be positive")
        require(errors, rep.get("marker_cycle_wrapped") in {False, True}, f"{label}: marker_cycle_wrapped must be boolean")
        require(errors, as_list(rep.get("sequence_gaps")) == [], f"{label}: sequence_gaps must be empty")
        require(errors, rep.get("bram_marker_window_complete") is True, f"{label}: BRAM marker window must be complete")
        basis = as_list(rep.get("acceptance_basis"))
        require(errors, "bram_marker_window_complete" in basis, f"{label}: acceptance basis must include BRAM marker window")
        require(errors, rep.get("uart_rc_required_for_acceptance") is False, f"{label}: UART rc must be auxiliary")
        if rep.get("uart_rc") is not None and rep.get("sample_id") != "illegal_instruction":
            require(errors, num(rep.get("uart_rc")) == 0, f"{label}: observed UART rc must be zero")
        bram = rep.get("bram_ring") if isinstance(rep.get("bram_ring"), dict) else {}
        require(errors, num(bram.get("event_count")) > 0, f"{label}: event_count must be positive")
        require(errors, num(bram.get("captured_count")) == num(bram.get("event_count")), f"{label}: captured_count must equal event_count")
        require(errors, num(bram.get("dropped_count")) == 0, f"{label}: dropped_count must be zero")
        require(errors, num(bram.get("wrap_count")) == 0, f"{label}: wrap_count must be zero")
        require(errors, bram.get("full") is False, f"{label}: BRAM must not be full")
        artifacts = rep.get("artifacts") if isinstance(rep.get("artifacts"), dict) else {}
        for key in ("bram_summary", "bram_records", "capture_csv", "capture_log", "capture_err_log", "uart_log"):
            check_file_row(errors, root, artifacts.get(key), f"{label}: artifact {key}")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        rep_dir = root / "run/hello_write/rep_01"
        rep_dir.mkdir(parents=True)
        for name in ("bram_summary.json", "bram_records.jsonl", "capture.csv", "capture.log", "capture.err.log", "uart.log"):
            (rep_dir / name).write_text("fixture\n", encoding="utf-8")
        row = {
            "sample_id": "hello_write",
            "repetition": "rep_01",
            "accepted": True,
            "acceptance_basis": ["bram_marker_window_complete", "uart_rc_not_observed_auxiliary"],
            "bram_marker_window_complete": True,
            "uart_rc_observed": False,
            "uart_rc_required_for_acceptance": False,
            "begin_marker_count": 1,
            "end_marker_count": 1,
            "marker_cycle_delta": 42,
            "marker_cycle_wrapped": False,
            "sequence_gaps": [],
            "uart_rc": None,
            "bram_ring": {"event_count": 2, "captured_count": 2, "dropped_count": 0, "wrap_count": 0, "full": False},
            "artifacts": {
                key: {
                    "path": f"run/hello_write/rep_01/{name}",
                    "sha256": "0" * 64,
                    "size_bytes": (rep_dir / name).stat().st_size,
                }
                for key, name in {
                    "bram_summary": "bram_summary.json",
                    "bram_records": "bram_records.jsonl",
                    "capture_csv": "capture.csv",
                    "capture_log": "capture.log",
                    "capture_err_log": "capture.err.log",
                    "uart_log": "uart.log",
                }.items()
            },
        }
        summary = {
            "schema": SCHEMA,
            "status": "PASS",
            "cycle_source": "rv_maltrace_fpga_trace_cycle_field",
            "minimum_repetitions": 1,
            "acceptance_policy": {
                "required": ["BRAM marker window evidence"],
                "auxiliary": ["UART return code is not required for acceptance"],
            },
            "marker_cycle_delta_stats": {"count": 1, "median": 42},
            "repetitions": [row],
            "claim_boundary": {
                "hardware_trace_cycle_window_claimed": True,
                "linux_perf_cycle_source_claimed": False,
                "user_rdcycle_source_claimed": False,
                "trace_off_slowdown_claimed": False,
            },
            "non_claims": [
                "The cycle source is not Linux perf_event_open.",
                "This summary measures marker-window cycle duration and does not by itself claim trace-off slowdown.",
            ],
        }
        write_json(root / "summary.json", summary)
        errors = validate_summary(root, load_json(root / "summary.json"))
    if errors:
        print("[FAIL] hardware trace cycle-window checker self-test:", "; ".join(errors), file=sys.stderr)
        return 1
    print("[PASS] hardware trace cycle-window checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Genesys2/CVA6 hardware trace cycle-window evidence.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = repo_path(root, args.summary)
    data = load_json(summary)
    errors = validate_summary(root, data)
    if errors:
        print(f"[FAIL] hardware trace cycle-window summary rejected: {summary}", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"[PASS] hardware trace cycle-window summary accepted: {summary} status={data.get('status')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
