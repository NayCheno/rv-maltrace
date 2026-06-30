from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    write_json,
)


SAMPLES = {
    "hello_write": {
        "begin_marker": 0xB0000A01,
        "end_marker": 0xE0000A01,
        "required_events": {"MARKER", "SYSCALL_ENTRY", "SYSCALL_RET"},
    },
    "illegal_instruction": {
        "begin_marker": 0xB0000A04,
        "end_marker": 0xE0000A04,
        "required_events": {"MARKER", "SYSCALL_ENTRY", "SYSCALL_RET", "TRAP"},
    },
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    return rows


def marker_values(records: list[dict[str, Any]]) -> set[int]:
    values: set[int] = set()
    for record in records:
        if record.get("evt") != "MARKER":
            continue
        values.add(int(str(record.get("packed_primary", "0")), 16) & 0xFFFFFFFF)
    return values


def event_set(records: list[dict[str, Any]]) -> set[str]:
    return {str(record.get("evt")) for record in records}


def recall_for_sample(sample_id: str, records: list[dict[str, Any]]) -> tuple[float, list[str]]:
    spec = SAMPLES[sample_id]
    expected_items = set(spec["required_events"]) | {"begin_marker", "end_marker"}
    present: set[str] = set()
    events = event_set(records)
    for evt in spec["required_events"]:
        if evt in events:
            present.add(evt)
    markers = marker_values(records)
    if spec["begin_marker"] in markers:
        present.add("begin_marker")
    if spec["end_marker"] in markers:
        present.add("end_marker")
    missing = sorted(expected_items - present)
    return len(present) / len(expected_items), missing


def rep_sort_key(path: Path) -> tuple[int, str]:
    digits = "".join(ch for ch in path.parent.name if ch.isdigit())
    return (int(digits) if digits else 0, path.parent.name)


def find_rep_summaries(run_root: Path, sample_id: str) -> list[Path]:
    sample_dirs = [path for path in run_root.iterdir() if path.is_dir() and sample_id in path.name]
    paths: list[Path] = []
    for sample_dir in sample_dirs:
        paths.extend(sample_dir.glob("rep_*/bram_summary.json"))
        paths.extend(sample_dir.glob("rep_*/bram_ring_summary.json"))
    return sorted(paths, key=rep_sort_key)


def package_run(run_root: Path, *, bitstream: str | None, bitstream_sha256: str | None, ltx: str | None, ltx_sha256: str | None) -> dict[str, Any]:
    samples: list[dict[str, Any]] = []
    overall_pass = True
    for sample_id in SAMPLES:
        reps: list[dict[str, Any]] = []
        for index, summary_path in enumerate(find_rep_summaries(run_root, sample_id), start=1):
            summary = load_json(summary_path)
            records_path = summary_path.parent / "bram_records.jsonl"
            if not records_path.is_file():
                records_path = summary_path.parent / "bram_ring_records.jsonl"
            records = load_jsonl(records_path) if records_path.is_file() else []
            recall, missing = recall_for_sample(sample_id, records)
            bram = summary.get("bram_ring", {}) if isinstance(summary.get("bram_ring"), dict) else {}
            parse_success = summary.get("status") == "PASS" and not missing and recall >= 1.0
            unaccounted_drop = 0 if int(bram.get("dropped_count", 0) or 0) == 0 else int(bram.get("dropped_count", 0) or 0)
            reps.append(
                {
                    "rep": index,
                    "trace_sink_mode": "bram_ring",
                    "parse_success": parse_success,
                    "expected_event_recall": recall,
                    "missing_expected_items": missing,
                    "unaccounted_drop": unaccounted_drop,
                    "csv": summary.get("csv"),
                    "records": records_path.as_posix() if records_path.is_file() else None,
                    "bram_ring": {
                        "sequence_number": bram.get("sequence_number", 0),
                        "event_count": bram.get("event_count", 0),
                        "captured_count": bram.get("captured_count", 0),
                        "dropped_count": bram.get("dropped_count", 0),
                        "wrap_count": bram.get("wrap_count", 0),
                        "start_timestamp": bram.get("start_timestamp", 0),
                        "end_timestamp": bram.get("end_timestamp", 0),
                    },
                }
            )
            overall_pass = overall_pass and parse_success and unaccounted_drop == 0
        overall_pass = overall_pass and len(reps) >= 10
        samples.append({"sample_id": sample_id, "repetitions": reps})
    return {
        "schema": "rvmt.genesys2.bram_trace_sink.v1",
        "status": "PASS" if overall_pass else "FAIL",
        "trace_sink_modes": ["ila_debug", "bram_ring"],
        "run_root": run_root.as_posix(),
        "board": "Digilent Genesys2",
        "cpu": "CVA6 rv64gc sv39",
        "bitstream": bitstream,
        "bitstream_sha256": bitstream_sha256,
        "ltx": ltx,
        "ltx_sha256": ltx_sha256,
        "samples": samples,
    }


def run_self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for sample_id, spec in SAMPLES.items():
            for rep in range(1, 11):
                rep_dir = root / f"01_{sample_id}" / f"rep_{rep:02d}"
                rep_dir.mkdir(parents=True)
                records = [
                    {"evt": "MARKER", "packed_primary": f"0x{spec['begin_marker']:08x}"},
                    {"evt": "SYSCALL_ENTRY", "packed_primary": "0x00000040"},
                    {"evt": "SYSCALL_RET", "packed_primary": "0x00000040"},
                    {"evt": "TRAP", "packed_primary": "0x00000002"},
                    {"evt": "MARKER", "packed_primary": f"0x{spec['end_marker']:08x}"},
                ]
                (rep_dir / "bram_records.jsonl").write_text(
                    "".join(json.dumps(row) + "\n" for row in records),
                    encoding="utf-8",
                    newline="\n",
                )
                write_json(
                    rep_dir / "bram_summary.json",
                    {
                        "schema": "rvmt.genesys2.bram_ring_dump.v1",
                        "status": "PASS",
                        "csv": (rep_dir / "capture.csv").as_posix(),
                        "bram_ring": {
                            "sequence_number": 4,
                            "event_count": 5,
                            "captured_count": 5,
                            "dropped_count": 0,
                            "wrap_count": 0,
                            "start_timestamp": 1,
                            "end_timestamp": 5,
                        },
                    },
                )
        summary = package_run(root, bitstream="a.bit", bitstream_sha256="0" * 64, ltx="a.ltx", ltx_sha256="1" * 64)
    if summary.get("status") != "PASS":
        print("[FAIL] expected fixture package to pass", file=sys.stderr)
        return 1
    if any(len(sample.get("repetitions", [])) != 10 for sample in summary.get("samples", [])):
        print("[FAIL] fixture repetitions missing", file=sys.stderr)
        return 1
    print("[PASS] Genesys2 BRAM trace sink packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package Genesys2 BRAM ring dump repetitions into the Phase C trace sink summary.")
    parser.add_argument("--run-root", type=Path, help="Run root containing sample/rep BRAM summaries.")
    parser.add_argument("--out", type=Path, help="Output trace_sink_summary.json path.")
    parser.add_argument("--bitstream")
    parser.add_argument("--bitstream-sha256")
    parser.add_argument("--ltx")
    parser.add_argument("--ltx-sha256")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()
    if not args.run_root or not args.out:
        parser.error("--run-root and --out are required unless --self-test is used")
    try:
        summary = package_run(
            args.run_root,
            bitstream=args.bitstream,
            bitstream_sha256=args.bitstream_sha256,
            ltx=args.ltx,
            ltx_sha256=args.ltx_sha256,
        )
        write_json(args.out, summary)
    except Exception as exc:
        print(f"package_genesys2_bram_trace_sink_summary: error: {exc}", file=sys.stderr)
        return 2
    print(f"[PASS] wrote BRAM trace sink summary to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
