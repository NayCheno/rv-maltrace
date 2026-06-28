from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

import official_image_evidence_common as common


SCHEMA = "rvmt.genesys2.official_image_repeatability_drop_wrap.v1"
DEFAULT_OUT = common.CURRENT_ROOT / "official_image_repeatability_summary.json"
DEFAULT_P0 = common.CURRENT_ROOT / "p0_bram_trace_summary.json"
DEFAULT_WORKLOADS = common.CURRENT_ROOT / "official_image_workload_summary.json"
DEFAULT_DROP = common.CURRENT_ROOT / "drop_accounting_summary.json"


def sample_rows_from_p0(p0: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for sample in p0.get("samples", []):
        if not isinstance(sample, dict):
            continue
        stats = sample.get("attempt_statistics") if isinstance(sample.get("attempt_statistics"), dict) else {}
        rows.append(
            {
                "source": "p0_bram_trace_summary",
                "sample_id": sample.get("sample_id"),
                "pass_repetitions": int(sample.get("pass_repetition_count") or stats.get("pass_repetition_count") or 0),
                "attempt_count": int(sample.get("attempt_count") or stats.get("repetition_count") or 0),
                "max_wrap_count": int(stats.get("max_wrap_count") or sample.get("bram_ring", {}).get("wrap_count") or 0),
                "max_unaccounted_drop": int(stats.get("max_unaccounted_drop") or 0),
                "status": "PASS" if int(sample.get("pass_repetition_count") or stats.get("pass_repetition_count") or 0) >= 10 else "FAIL",
            }
        )
    return rows


def sample_rows_from_workloads(workloads: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for sample in workloads.get("samples", []):
        if not isinstance(sample, dict):
            continue
        max_wrap = 0
        max_drop = 0
        for rep in sample.get("repetitions", []):
            if isinstance(rep, dict):
                ring = rep.get("bram_ring") if isinstance(rep.get("bram_ring"), dict) else {}
                max_wrap = max(max_wrap, int(ring.get("wrap_count") or 0))
                max_drop = max(max_drop, int(ring.get("dropped_count") or 0))
        rows.append(
            {
                "source": "official_image_workload_summary",
                "sample_id": sample.get("sample_id"),
                "pass_repetitions": int(sample.get("pass_repetitions") or 0),
                "blocked_repetitions": int(sample.get("blocked_repetitions") or 0),
                "attempt_count": int(sample.get("attempt_count") or 0),
                "max_wrap_count": max_wrap,
                "max_drop_count": max_drop,
                "status": sample.get("status"),
            }
        )
    return rows


def package_summary(p0_path: Path, workloads_path: Path, drop_path: Path, out: Path) -> dict[str, Any]:
    p0 = common.load_json(p0_path)
    workloads = common.load_json(workloads_path)
    drop = common.load_json(drop_path)
    p0_rows = sample_rows_from_p0(p0)
    workload_rows = sample_rows_from_workloads(workloads)
    p0_all_repeatable = all(row["status"] == "PASS" and row["pass_repetitions"] >= 10 for row in p0_rows)
    official_pass_rows = [row for row in workload_rows if row.get("status") == "PASS"]
    official_blocked_rows = [row for row in workload_rows if str(row.get("status") or "").startswith("BLOCKED_")]
    if p0_all_repeatable and not official_blocked_rows and len(official_pass_rows) >= 7:
        status = "PASS"
        blocked_reason = None
    elif official_blocked_rows:
        status = "BLOCKED_OFFICIAL_WORKLOAD_REPEATABILITY_LIMITED_BY_BRAM_RING_DEPTH"
        blocked_reason = "official-image BusyBox workload repeatability cannot be promoted while required core samples overflow the current BRAM ring"
    else:
        status = "BLOCKED_OFFICIAL_WORKLOAD_REPEATABILITY_INCOMPLETE"
        blocked_reason = "official-image workload repeatability has insufficient accepted repetitions"
    summary = {
        "schema": SCHEMA,
        "status": status,
        "scope": "board repeatability, failed-run retention, drop/wrap accounting for official-image plan",
        "p0_repeatability": {
            "status": "PASS" if p0_all_repeatable else "FAIL",
            "sample_count": len(p0_rows),
            "samples": p0_rows,
            "summary": common.file_row(p0_path),
        },
        "official_image_workload_repeatability": {
            "status": workloads.get("status"),
            "pass_sample_count": len(official_pass_rows),
            "blocked_sample_count": len(official_blocked_rows),
            "samples": workload_rows,
            "summary": common.file_row(workloads_path),
        },
        "drop_accounting": {
            "summary": common.file_row(drop_path),
            "p0_bram_run_root": drop.get("p0_bram_run_root"),
            "safe_surrogate_bram_run_root": drop.get("safe_surrogate_bram_run_root"),
        },
        "blocked_reason": blocked_reason,
        "claim_boundary": {
            "official_image_repeatability_claimed": status == "PASS",
            "p0_repeatability_claimed": p0_all_repeatable,
            "failed_attempts_retained": int(p0.get("failed_attempt_count") or 0) > 0 or any(row.get("blocked_repetitions", 0) for row in workload_rows),
            "bram_ring_overflow_not_promoted": status.startswith("BLOCKED_"),
            "cycle_level_overhead_claimed": False,
            "real_malware_validation_claimed": False,
        },
        "non_claims": [
            "The P0 strict-SRET cohort is repeatable, but official-image BusyBox workload repeatability remains blocked when BRAM wrap/drop occurs.",
            "Drop/wrap accounting is not converted into cycle-level overhead or production slowdown claims.",
        ],
    }
    common.write_json(out, summary)
    return summary


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-repeatability-") as tmp:
        root = Path(tmp)
        p0 = root / "p0.json"
        workloads = root / "workloads.json"
        drop = root / "drop.json"
        common.write_json(p0, {"samples": [{"sample_id": "hello", "pass_repetition_count": 10, "attempt_count": 10, "attempt_statistics": {"max_wrap_count": 0, "max_unaccounted_drop": 0}}], "failed_attempt_count": 1})
        common.write_json(workloads, {"status": "BLOCKED_OFFICIAL_WORKLOAD_CORE_RING_DEPTH_INSUFFICIENT", "samples": [{"sample_id": "native_ls_proc", "status": "BLOCKED_BRAM_RING_DEPTH_INSUFFICIENT", "pass_repetitions": 0, "blocked_repetitions": 1, "attempt_count": 1}]})
        common.write_json(drop, {"p0_bram_run_root": "raw/p0"})
        summary = package_summary(p0, workloads, drop, root / "summary.json")
    if summary.get("status") != "BLOCKED_OFFICIAL_WORKLOAD_REPEATABILITY_LIMITED_BY_BRAM_RING_DEPTH":
        print("[FAIL] repeatability fixture should block on official workload BRAM depth", file=sys.stderr)
        return 1
    print("[PASS] official-image repeatability packager self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Package board repeatability/drop-wrap evidence for the official-image plan.")
    parser.add_argument("--p0-summary", type=Path, default=DEFAULT_P0)
    parser.add_argument("--workload-summary", type=Path, default=DEFAULT_WORKLOADS)
    parser.add_argument("--drop-summary", type=Path, default=DEFAULT_DROP)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    summary = package_summary(args.p0_summary, args.workload_summary, args.drop_summary, args.out)
    print(f"[{summary['status']}] wrote {args.out}")
    return 0 if summary["status"] == "PASS" or str(summary["status"]).startswith("BLOCKED_") else 1


if __name__ == "__main__":
    raise SystemExit(main())
