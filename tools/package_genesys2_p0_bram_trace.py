from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any


SAMPLES = {
    "hello_write": {
        "dirname": "01_hello_write",
        "begin_marker": 0xB0000A01,
        "end_marker": 0xE0000A01,
    },
    "file_open_read_write": {
        "dirname": "02_file_open_read_write",
        "begin_marker": 0xB0000A02,
        "end_marker": 0xE0000A02,
    },
    "fork_exec": {
        "dirname": "03_fork_exec",
        "begin_marker": 0xB0000A03,
        "end_marker": 0xE0000A03,
    },
    "illegal_instruction": {
        "dirname": "04_illegal_instruction",
        "begin_marker": 0xB0000A04,
        "end_marker": 0xE0000A04,
    },
}

DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260612-p0-bram-repetitions")
DEFAULT_BUILD_ROOT = Path("build/board/genesys2_cva6_p0_marker")
DEFAULT_OUT = Path("results/evaluation/genesys2-cva6/current/p0_bram_trace_summary.json")
DEFAULT_BITSTREAM = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.bit")
DEFAULT_LTX = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx")
EXIT_SYSCALL_NR = 93


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            rows.append(value)
    return rows


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def sha256_file(path: Path | None) -> str | None:
    if path is None or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
        except ValueError:
            return None
    return None


def marker_positions(records: list[dict[str, Any]], begin_marker: int, end_marker: int) -> dict[str, Any]:
    markers: list[dict[str, Any]] = []
    for record in records:
        if record.get("evt") != "MARKER":
            continue
        primary = parse_int(record.get("packed_primary"))
        if primary is None:
            continue
        markers.append(
            {
                "primary": f"0x{primary:08x}",
                "sequence_number": record.get("sequence_number"),
                "cycle": record.get("cycle"),
                "pc": record.get("pc"),
            }
        )
    begin = [row for row in markers if row.get("primary") == f"0x{begin_marker:08x}"]
    end = [row for row in markers if row.get("primary") == f"0x{end_marker:08x}"]
    post_end_tail = 0
    if end:
        end_sequence = int(end[-1].get("sequence_number") or 0)
        post_end_tail = sum(1 for row in records if int(row.get("sequence_number") or 0) > end_sequence)
    return {
        "begin_marker": f"0x{begin_marker:08x}",
        "end_marker": f"0x{end_marker:08x}",
        "markers_seen": markers,
        "begin_count": len(begin),
        "end_count": len(end),
        "begin_sequence": begin[0].get("sequence_number") if begin else None,
        "end_sequence": end[-1].get("sequence_number") if end else None,
        "post_end_tail_event_count": post_end_tail,
    }


def sequence_gaps(records: list[dict[str, Any]]) -> list[dict[str, int]]:
    sequences = [int(row.get("sequence_number")) for row in records if row.get("sequence_number") is not None]
    gaps: list[dict[str, int]] = []
    for left, right in zip(sequences, sequences[1:]):
        if right != left + 1:
            gaps.append({"after": left, "before": right})
    return gaps


def expected_syscall_entries(manifest: dict[str, Any]) -> int:
    sequence = manifest.get("syscall_sequence")
    if not isinstance(sequence, list):
        return 0
    return sum(1 for item in sequence if str(item) != "rvmt_marker")


def expected_pairable_entries(manifest: dict[str, Any]) -> int:
    sequence = manifest.get("syscall_sequence")
    if not isinstance(sequence, list):
        return 0
    return sum(1 for item in sequence if str(item) not in {"rvmt_marker", "exit"})


def strict_syscall_pairs(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    returns: dict[int, tuple[int, dict[str, Any]]] = {}
    for index, row in enumerate(records):
        if row.get("evt") != "SYSCALL_RET":
            continue
        syscall_id = parse_int(row.get("packed_primary") or row.get("syscall_id"))
        if syscall_id is not None:
            returns[syscall_id] = (index, row)
    pairs: list[dict[str, Any]] = []
    for index, row in enumerate(records):
        if row.get("evt") != "SYSCALL_ENTRY":
            continue
        syscall_id = parse_int(row.get("packed_aux") or row.get("syscall_id"))
        number = parse_int(row.get("packed_primary") or row.get("a7"))
        if syscall_id is None or syscall_id == 0 or number == EXIT_SYSCALL_NR:
            continue
        if syscall_id not in returns:
            continue
        ret_index, ret = returns[syscall_id]
        pairs.append(
            {
                "entry_sequence": row.get("sequence_number"),
                "return_sequence": ret.get("sequence_number"),
                "entry_index": index,
                "return_index": ret_index,
                "syscall_id": f"0x{syscall_id:08x}",
                "number": number,
            }
        )
    return pairs


def rep_sort_key(path: Path) -> tuple[int, str]:
    suffix = path.name.removeprefix("rep_")
    try:
        return (int(suffix), path.name)
    except ValueError:
        return (10**9, path.name)


def find_rep_dirs(run_root: Path, sample_id: str) -> list[Path]:
    sample_root = run_root / sample_id
    if not sample_root.is_dir():
        return []
    return sorted(
        [path for path in sample_root.glob("rep_*") if (path / "bram_summary.json").is_file()],
        key=rep_sort_key,
    )


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * quantile))
    return ordered[index]


def numeric_stats(values: list[int | float]) -> dict[str, Any]:
    numeric = [float(value) for value in values]
    if not numeric:
        return {"min": 0, "median": 0, "p95": 0, "max": 0, "variance": 0}
    return {
        "min": min(numeric),
        "median": statistics.median(numeric),
        "p95": percentile(numeric, 0.95),
        "max": max(numeric),
        "variance": statistics.pvariance(numeric) if len(numeric) > 1 else 0.0,
    }


def package_repetition(run_root: Path, build_root: Path, sample_id: str, rep_dir: Path) -> dict[str, Any]:
    spec = SAMPLES[sample_id]
    summary_path = rep_dir / "bram_summary.json"
    records_path = rep_dir / "bram_records.jsonl"
    manifest_path = build_root / sample_id / "build_manifest.json"
    binary_path = build_root / sample_id / f"{sample_id}.riscv64"
    summary = load_json(summary_path)
    records = load_jsonl(records_path)
    manifest = load_json(manifest_path)
    bram = summary.get("bram_ring", {}) if isinstance(summary.get("bram_ring"), dict) else {}
    event_counts = summary.get("event_counts", {}) if isinstance(summary.get("event_counts"), dict) else {}
    expected_entries = expected_syscall_entries(manifest)
    observed_entries = int(event_counts.get("SYSCALL_ENTRY", 0) or 0)
    expected_pairs = expected_pairable_entries(manifest)
    pairs = strict_syscall_pairs(records)
    marker_window = marker_positions(records, int(spec["begin_marker"]), int(spec["end_marker"]))
    gaps = sequence_gaps(records)
    parse_success = (
        summary.get("status") == "PASS"
        and bool(records)
        and int(bram.get("dropped_count", 0) or 0) == 0
        and int(bram.get("wrap_count", 0) or 0) == 0
        and not gaps
        and marker_window.get("begin_count") == 1
        and marker_window.get("end_count") == 1
        and marker_window.get("begin_sequence") == 0
        and observed_entries >= expected_entries
        and len(pairs) >= expected_pairs
    )
    return {
        "sample_id": sample_id,
        "repetition": rep_dir.name,
        "sample_class": "p0_safe_synthetic",
        "trace_sink_mode": "bram_ring",
        "continuity_scope": "begin-marker-cleared BRAM ring through capture readout",
        "parse_success": parse_success,
        "expected_syscall_entries": expected_entries,
        "observed_syscall_entries": observed_entries,
        "expected_pairable_syscall_entries": expected_pairs,
        "strict_pairable_syscall_entries": len(pairs),
        "strict_syscall_id_pairs": pairs,
        "sequence_gaps": gaps,
        "unaccounted_drop": int(bram.get("dropped_count", 0) or 0) + len(gaps),
        "event_counts": event_counts,
        "marker_window": marker_window,
        "bram_ring": {
            "event_count": bram.get("event_count", 0),
            "captured_count": bram.get("captured_count", 0),
            "dropped_count": bram.get("dropped_count", 0),
            "wrap_count": bram.get("wrap_count", 0),
            "full": bram.get("full", False),
            "start_timestamp": bram.get("start_timestamp", 0),
            "end_timestamp": bram.get("end_timestamp", 0),
            "sequence_first": summary.get("sequence_first"),
            "sequence_last": summary.get("sequence_last"),
        },
        "artifacts": {
            "bram_summary": summary_path.as_posix(),
            "bram_records": records_path.as_posix(),
            "csv": summary.get("csv"),
            "uart_log": (rep_dir / "uart.log").as_posix(),
            "capture_log": (rep_dir / "capture.log").as_posix(),
            "capture_err_log": (rep_dir / "capture.err.log").as_posix(),
            "build_manifest": manifest_path.as_posix(),
            "binary": binary_path.as_posix(),
            "binary_sha256": sha256_file(binary_path),
        },
    }


def sample_statistics(repetitions: list[dict[str, Any]]) -> dict[str, Any]:
    window_cycles: list[int] = []
    for rep in repetitions:
        bram = rep.get("bram_ring", {}) if isinstance(rep.get("bram_ring"), dict) else {}
        window_cycles.append(int(bram.get("end_timestamp", 0) or 0) - int(bram.get("start_timestamp", 0) or 0))
    return {
        "repetition_count": len(repetitions),
        "pass_repetition_count": sum(1 for rep in repetitions if rep.get("parse_success") is True),
        "event_count": numeric_stats(
            [int((rep.get("bram_ring", {}) if isinstance(rep.get("bram_ring"), dict) else {}).get("event_count", 0) or 0) for rep in repetitions]
        ),
        "marker_window_cycles": numeric_stats(window_cycles),
        "max_unaccounted_drop": max([int(rep.get("unaccounted_drop", 0) or 0) for rep in repetitions], default=0),
        "max_wrap_count": max(
            [int((rep.get("bram_ring", {}) if isinstance(rep.get("bram_ring"), dict) else {}).get("wrap_count", 0) or 0) for rep in repetitions],
            default=0,
        ),
        "min_pairable_syscall_entries": min([int(rep.get("strict_pairable_syscall_entries", 0) or 0) for rep in repetitions], default=0),
    }


def package_sample(run_root: Path, build_root: Path, sample_id: str, *, minimum_repetitions: int) -> dict[str, Any]:
    attempts = [package_repetition(run_root, build_root, sample_id, rep_dir) for rep_dir in find_rep_dirs(run_root, sample_id)]
    if not attempts:
        raise FileNotFoundError(f"{run_root / sample_id}: no rep_*/bram_summary.json files found")
    repetitions = [rep for rep in attempts if rep.get("parse_success") is True]
    failed_attempts = [rep for rep in attempts if rep.get("parse_success") is not True]
    stats = sample_statistics(repetitions)
    attempt_stats = sample_statistics(attempts)
    representative = repetitions[0] if repetitions else attempts[0]
    parse_success = (
        len(repetitions) >= minimum_repetitions
        and stats["pass_repetition_count"] == len(repetitions)
        and stats["max_unaccounted_drop"] == 0
        and stats["max_wrap_count"] == 0
    )
    return {
        **representative,
        "sample_id": sample_id,
        "attempt_count": len(attempts),
        "failed_attempt_count": len(failed_attempts),
        "repetition_count": len(repetitions),
        "pass_repetition_count": len(repetitions),
        "minimum_repetitions": minimum_repetitions,
        "parse_success": parse_success,
        "repetitions": repetitions,
        "failed_attempts": failed_attempts,
        "statistics": stats,
        "attempt_statistics": attempt_stats,
    }


def package_run(
    run_root: Path,
    build_root: Path,
    *,
    bitstream: Path | None,
    ltx: Path | None,
    minimum_repetitions: int,
) -> dict[str, Any]:
    samples = [package_sample(run_root, build_root, sample_id, minimum_repetitions=minimum_repetitions) for sample_id in SAMPLES]
    overall_pass = all(sample.get("parse_success") is True and sample.get("unaccounted_drop") == 0 for sample in samples)
    rep_counts = [int(sample.get("repetition_count", 0) or 0) for sample in samples]
    attempt_counts = [int(sample.get("attempt_count", sample.get("repetition_count", 0)) or 0) for sample in samples]
    failed_attempt_count = sum(int(sample.get("failed_attempt_count", 0) or 0) for sample in samples)
    return {
        "schema": "rvmt.genesys2.p0_bram_trace.v1",
        "status": "PASS" if overall_pass else "FAIL",
        "evidence_scope": "p0_safe_synthetic_marker_windows",
        "continuity_scope": "begin-marker-cleared BRAM ring through capture readout",
        "trace_sink_mode": "bram_ring",
        "board": "Digilent Genesys2",
        "cpu": "CVA6 rv64gc sv39",
        "run_root": run_root.as_posix(),
        "build_root": build_root.as_posix(),
        "bitstream": bitstream.as_posix() if bitstream else None,
        "bitstream_sha256": sha256_file(bitstream),
        "ltx": ltx.as_posix() if ltx else None,
        "ltx_sha256": sha256_file(ltx),
        "sample_count": len(samples),
        "expected_samples": list(SAMPLES),
        "minimum_repetitions_per_sample": minimum_repetitions,
        "repetitions_per_sample": dict(zip(SAMPLES, rep_counts)),
        "attempts_per_sample": dict(zip(SAMPLES, attempt_counts)),
        "total_repetitions": sum(rep_counts),
        "total_attempts": sum(attempt_counts),
        "failed_attempt_count": failed_attempt_count,
        "statistical_robustness": {
            "claimed": min(rep_counts, default=0) >= 10,
            "minimum_observed_repetitions": min(rep_counts, default=0),
            "sample_repetition_goal": minimum_repetitions,
            "total_repetitions": sum(rep_counts),
            "all_repetitions_parse_success": all(sample.get("pass_repetition_count") == sample.get("repetition_count") for sample in samples),
            "max_unaccounted_drop": max([sample.get("statistics", {}).get("max_unaccounted_drop", 0) for sample in samples], default=0),
            "max_wrap_count": max([sample.get("statistics", {}).get("max_wrap_count", 0) for sample in samples], default=0),
        },
        "allowed_claims": [
            "P0 safe synthetic Genesys2/CVA6 accepted BRAM marker-window repetitions have the recorded repetition count, clear begin/end markers, strict syscall-id entry/return pairing for pairable syscalls, sequence continuity, wrap=0, and unaccounted DROP=0.",
        ],
        "non_claims": [
            "These are repository-authored safe synthetic P0 workloads, not real malware payloads.",
            "Failed attempts, if any, are retained separately and are not counted as accepted PASS repetitions.",
            "This BRAM repetition summary does not claim full hardware pointer-string reconstruction.",
            "This evidence is marker-window BRAM evidence and is not a production streaming/DMA throughput claim.",
        ],
        "samples": samples,
    }


def run_self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        run_root = root / "run"
        build_root = root / "build"
        for sample_id, spec in SAMPLES.items():
            for rep in range(1, 11):
                rep_dir = run_root / sample_id / f"rep_{rep:02d}"
                rep_dir.mkdir(parents=True)
                records = [
                    {"evt": "MARKER", "packed_primary": f"0x{int(spec['begin_marker']):08x}", "sequence_number": 0, "cycle": 1},
                    {"evt": "SYSCALL_ENTRY", "packed_primary": "0x00000040", "packed_aux": "0x00000001", "sequence_number": 1, "cycle": 2},
                    {"evt": "SYSCALL_RET", "packed_primary": "0x00000001", "sequence_number": 2, "cycle": 3},
                    {"evt": "MARKER", "packed_primary": f"0x{int(spec['end_marker']):08x}", "sequence_number": 3, "cycle": 4},
                    {"evt": "SYSCALL_ENTRY", "packed_primary": "0x0000005d", "packed_aux": "0x00000002", "sequence_number": 4, "cycle": 5},
                ]
                (rep_dir / "bram_records.jsonl").write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
                write_json(
                    rep_dir / "bram_summary.json",
                    {
                        "schema": "rvmt.genesys2.bram_ring_dump.v1",
                        "status": "PASS",
                        "csv": (rep_dir / "capture.csv").as_posix(),
                        "sequence_first": 0,
                        "sequence_last": 4,
                        "event_counts": {"MARKER": 2, "SYSCALL_ENTRY": 2, "SYSCALL_RET": 1},
                        "bram_ring": {
                            "event_count": 5,
                            "captured_count": 5,
                            "dropped_count": 0,
                            "wrap_count": 0,
                            "full": False,
                            "start_timestamp": 1,
                            "end_timestamp": 5,
                        },
                    },
                )
                for name in ("uart.log", "capture.log", "capture.err.log", "capture.csv"):
                    (rep_dir / name).write_text("fixture\n", encoding="utf-8")
            manifest_dir = build_root / sample_id
            manifest_dir.mkdir(parents=True)
            write_json(manifest_dir / "build_manifest.json", {"sample_id": sample_id, "syscall_sequence": ["rvmt_marker", "write", "rvmt_marker", "exit"]})
            (manifest_dir / f"{sample_id}.riscv64").write_bytes(b"\x7fELFfixture")
        summary = package_run(run_root, build_root, bitstream=None, ltx=None, minimum_repetitions=10)
    if summary.get("status") != "PASS" or summary.get("total_repetitions") != 40:
        print("[FAIL] P0 BRAM packager fixture did not pass", file=sys.stderr)
        return 1
    print("[PASS] Genesys2 P0 BRAM trace packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package Genesys2 P0 BRAM marker-window repetition evidence.")
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--build-root", type=Path, default=DEFAULT_BUILD_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--bitstream", type=Path, default=DEFAULT_BITSTREAM)
    parser.add_argument("--ltx", type=Path, default=DEFAULT_LTX)
    parser.add_argument("--minimum-repetitions", type=int, default=10)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    try:
        summary = package_run(
            args.run_root,
            args.build_root,
            bitstream=args.bitstream,
            ltx=args.ltx,
            minimum_repetitions=args.minimum_repetitions,
        )
        write_json(args.out, summary)
    except Exception as exc:
        print(f"package_genesys2_p0_bram_trace: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] wrote P0 BRAM trace summary to {args.out}")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
