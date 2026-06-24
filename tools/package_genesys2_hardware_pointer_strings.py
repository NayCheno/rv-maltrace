from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from check_genesys2_external_closure_intake import (
    DEFAULT_EXTERNAL_ROOT,
    EXPECTED_EXTERNAL_SUMMARIES,
    validate_external_summary,
)
from external_closure_artifacts import (
    ROOT,
    evidence_rows,
    external_record_root,
    load_json,
    load_jsonl,
    repo_path,
    repo_relative,
    sha256_file,
    write_json_artifact,
    write_summary,
    write_text_artifact,
)


RECORD_ID = "full_hardware_pointer_strings"
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260613-v3-full-pointer-strings")
DEFAULT_OUT = EXPECTED_EXTERNAL_SUMMARIES[RECORD_ID]["path"]
REQUIRED_SAMPLES = ("file_scan", "batch_open_read_write", "process_chain")
REQUIRED_SYSCALLS = ("openat", "write", "execve")
SYSCALL_NAMES = {56: "openat", 64: "write", 221: "execve"}
REQUIRED_REPS_PER_SAMPLE = 10


def parse_int(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip().replace("_", "")
    if not text:
        return 0
    return int(text, 16 if text.lower().startswith("0x") else 10)


def is_true(value: Any) -> bool:
    return value is True or value == 1 or str(value).strip().lower() in {"1", "true", "yes"}


def redacted_preview(byte_map: dict[int, int]) -> str:
    if not byte_map:
        return ""
    max_offset = min(max(byte_map), 31)
    chars = []
    for offset in range(max_offset + 1):
        value = byte_map.get(offset)
        if value is None:
            chars.append("?")
        elif 32 <= value < 127:
            chars.append(chr(value))
        else:
            chars.append(".")
    return "".join(chars)


def analyze_records(sample_id: str, repetition: str, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    syscall_by_id: dict[int, str] = {}
    groups: dict[tuple[int, int], dict[str, Any]] = {}
    for row in sorted(records, key=lambda item: parse_int(item.get("sequence_number"))):
        evt = str(row.get("evt") or "")
        if evt == "SYSCALL_ENTRY":
            syscall_nr = parse_int(row.get("packed_primary"))
            syscall_id = parse_int(row.get("packed_aux"))
            syscall_name = SYSCALL_NAMES.get(syscall_nr)
            if syscall_name:
                syscall_by_id[syscall_id] = syscall_name
        elif evt == "ARG_MEM":
            syscall_id = parse_int(row.get("syscall_id") or row.get("syscall_id_full"))
            syscall_name = syscall_by_id.get(syscall_id)
            if syscall_name not in REQUIRED_SYSCALLS:
                continue
            arg_index = parse_int(row.get("arg_index") if row.get("arg_index") is not None else row.get("arg_index_full"))
            key = (syscall_id, arg_index)
            mem_base = parse_int(row.get("mem_base") or row.get("mem_base_full"))
            mem_addr = parse_int(row.get("mem_addr") or row.get("mem_addr_full"))
            mem_data = parse_int(row.get("mem_data") or row.get("mem_data_full"))
            mem_size = parse_int(row.get("snapshot_bytes") or row.get("mem_size") or row.get("mem_size_full"))
            payload_width = parse_int(row.get("payload_width"))
            source = str(row.get("snapshot_source") or "")
            group = groups.setdefault(
                key,
                {
                    "id": f"{sample_id}:{repetition}:syscall_{syscall_id:x}:arg{arg_index}",
                    "sample_id": sample_id,
                    "repetition": repetition,
                    "syscall_id": syscall_id,
                    "syscall_name": syscall_name,
                    "arg_index": arg_index,
                    "mem_base": mem_base,
                    "_bytes": {},
                    "_sources": set(),
                    "_payload_widths": [],
                    "mem_last_observed": False,
                    "companion_derived_strings_as_hardware": False,
                    "kernel_fragment_count": 0,
                },
            )
            group["_sources"].add(source)
            group["_payload_widths"].append(payload_width)
            if mem_base >= (1 << 63):
                group["kernel_fragment_count"] += 1
            if is_true(row.get("mem_last") if row.get("mem_last") is not None else row.get("mem_last_full")):
                group["mem_last_observed"] = True
            offset = mem_addr - mem_base
            if mem_base and offset >= 0 and mem_size > 0:
                for index in range(min(mem_size, 8)):
                    group["_bytes"][offset + index] = (mem_data >> (8 * index)) & 0xFF
    result: list[dict[str, Any]] = []
    for group in groups.values():
        byte_map = group.pop("_bytes")
        sources = sorted(group.pop("_sources"))
        payload_widths = group.pop("_payload_widths")
        max_offset = max(byte_map) if byte_map else -1
        contiguous = bool(byte_map) and min(byte_map) == 0 and all(offset in byte_map for offset in range(max_offset + 1))
        v3_hardware = bool(payload_widths) and min(payload_widths) >= 716 and sources == ["hardware_bram_ring_v3"]
        group.update(
            {
                "full_string_claimed": contiguous and group["mem_last_observed"] and v3_hardware and group["kernel_fragment_count"] == 0,
                "contiguous_from_offset_zero": contiguous,
                "hardware_bram_v3_source": v3_hardware,
                "snapshot_sources": sources,
                "min_payload_width": min(payload_widths) if payload_widths else 0,
                "reconstructed_byte_count": len(byte_map),
                "redacted_ascii_preview": redacted_preview(byte_map),
            }
        )
        result.append(group)
    return result


def accepted_repetition(summary: dict[str, Any]) -> bool:
    ring = summary.get("bram_ring") if isinstance(summary.get("bram_ring"), dict) else {}
    return (
        summary.get("status") == "PASS"
        and parse_int(summary.get("payload_width")) >= 716
        and parse_int(ring.get("dropped_count", summary.get("dropped_count"))) == 0
        and parse_int(ring.get("wrap_count", summary.get("wrap_count"))) == 0
    )


def collect_pointer_evidence(root: Path, run_root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    sample_rows: list[dict[str, Any]] = []
    pointer_groups: list[dict[str, Any]] = []
    failed_attempts: list[str] = []
    for sample_id in REQUIRED_SAMPLES:
        sample_dir = run_root / sample_id
        accepted = 0
        sample_group_count = 0
        for records_path in sorted(sample_dir.glob("rep_*/bram_records.jsonl")):
            rep_dir = records_path.parent
            summary_path = rep_dir / "bram_summary.json"
            repetition = rep_dir.name
            if not summary_path.is_file():
                failed_attempts.append(f"{sample_id}/{repetition}: missing bram_summary.json")
                continue
            try:
                summary = load_json(summary_path)
                records = load_jsonl(records_path)
            except Exception as exc:
                failed_attempts.append(f"{sample_id}/{repetition}: unreadable capture: {exc}")
                continue
            if not accepted_repetition(summary):
                failed_attempts.append(
                    f"{sample_id}/{repetition}: not accepted status={summary.get('status')} payload_width={summary.get('payload_width')}"
                )
                continue
            groups = analyze_records(sample_id, repetition, records)
            accepted += 1
            sample_group_count += len(groups)
            pointer_groups.extend(groups)
        sample_rows.append(
            {
                "id": sample_id,
                "sample_dir": repo_relative(root, sample_dir),
                "accepted_repetitions": accepted,
                "required_repetitions": REQUIRED_REPS_PER_SAMPLE,
                "pointer_group_count": sample_group_count,
            }
        )
        if accepted < REQUIRED_REPS_PER_SAMPLE:
            failed_attempts.append(f"{sample_id}: accepted repetitions {accepted} < {REQUIRED_REPS_PER_SAMPLE}")
    return sample_rows, pointer_groups, failed_attempts


def source_manifest(root: Path) -> dict[str, Any]:
    files = [
        Path("rtl/trace/trace_pkg.sv"),
        Path("rtl/trace/arg_mem_tap.sv"),
        Path("rtl/trace/trace_bram_ring.sv"),
        Path("rtl/cva6/corev_apu/fpga/src/ariane_xilinx.sv"),
        Path("tools/decode_genesys2_bram_ring_dump.py"),
    ]
    rows = []
    for path in files:
        full = repo_path(root, path)
        rows.append({"path": path.as_posix(), "sha256": sha256_file(full) if full.is_file() else None, "exists": full.is_file()})
    return {"payload_version": "v3", "probe2_width_bits": 716, "v3_mem_base_full_bits": "332..395", "sources": rows}


def package_summary(root: Path, run_root_arg: Path, resource_timing_report: Path | None = None) -> dict[str, Any]:
    run_root = repo_path(root, run_root_arg)
    run_root_for_command = repo_relative(root, run_root)
    record_root = external_record_root(root, RECORD_ID)
    sample_rows, pointer_groups, failures = collect_pointer_evidence(root, run_root)
    resource_source = repo_path(root, resource_timing_report) if resource_timing_report else None
    if resource_source is None or not resource_source.is_file():
        failures.append("resource_timing_report: missing production bitstream resource/timing report")
    resource_for_command = repo_relative(root, resource_source) if resource_source is not None else "<missing-resource-timing-report>"

    coverage: dict[str, dict[str, Any]] = {}
    for syscall_name in REQUIRED_SYSCALLS:
        rows = [row for row in pointer_groups if row.get("syscall_name") == syscall_name and row.get("full_string_claimed") is True]
        coverage[syscall_name] = {
            "full_string_group_count": len(rows),
            "gap_free": bool(rows) and all(row.get("contiguous_from_offset_zero") is True for row in rows),
            "mem_last_observed": bool(rows) and all(row.get("mem_last_observed") is True for row in rows),
            "companion_derived_strings_as_hardware": False,
        }

    full_groups = [row for row in pointer_groups if row.get("full_string_claimed") is True]
    pass_conditions = [
        all(row["accepted_repetitions"] >= REQUIRED_REPS_PER_SAMPLE for row in sample_rows),
        all(coverage[name]["full_string_group_count"] > 0 for name in REQUIRED_SYSCALLS),
        all(row.get("hardware_bram_v3_source") is True for row in full_groups),
        all(row.get("mem_last_observed") is True for row in full_groups),
        all(row.get("contiguous_from_offset_zero") is True for row in full_groups),
        not failures,
    ]
    status = "PASS" if all(pass_conditions) else "FAIL"

    artifacts: dict[str, Path] = {
        "rtl_design_manifest": write_json_artifact(root, RECORD_ID, "rtl_design_manifest", source_manifest(root)),
        "pointer_capture_manifest": write_json_artifact(
            root,
            RECORD_ID,
            "pointer_capture_manifest",
            {
                "run_root": repo_relative(root, run_root),
                "required_samples": list(REQUIRED_SAMPLES),
                "required_reps_per_sample": REQUIRED_REPS_PER_SAMPLE,
                "samples": sample_rows,
                "failed_attempts": failures,
            },
        ),
        "pointer_group_reconstruction": write_json_artifact(root, RECORD_ID, "pointer_group_reconstruction", pointer_groups),
        "mem_last_or_terminator_report": write_json_artifact(
            root,
            RECORD_ID,
            "mem_last_or_terminator_report",
            {
                "full_group_count": len(full_groups),
                "all_full_groups_have_mem_last": bool(full_groups) and all(row.get("mem_last_observed") is True for row in full_groups),
                "groups_missing_mem_last": [row["id"] for row in pointer_groups if row.get("mem_last_observed") is not True],
            },
        ),
        "redaction_policy": write_text_artifact(
            root,
            RECORD_ID,
            "redaction_policy",
            "Summaries expose byte counts and short redacted ASCII previews only; raw board trace records remain in the run root and are not companion-derived.",
        ),
        "kernel_space_filter_report": write_json_artifact(
            root,
            RECORD_ID,
            "kernel_space_filter_report",
            {
                "kernel_fragment_count": sum(int(row.get("kernel_fragment_count") or 0) for row in pointer_groups),
                "policy": "Pointer reconstruction accepts only non-kernel user addresses with mem_base_full and nonnegative offsets.",
            },
        ),
        "companion_substitution_audit": write_json_artifact(
            root,
            RECORD_ID,
            "companion_substitution_audit",
            {
                "companion_derived_strings_as_hardware": 0,
                "accepted_sources": sorted({source for row in pointer_groups for source in row.get("snapshot_sources", [])}),
                "required_source": "hardware_bram_ring_v3",
            },
        ),
    }
    if resource_source and resource_source.is_file():
        artifacts["resource_timing_report"] = write_text_artifact(
            root,
            RECORD_ID,
            "resource_timing_report",
            resource_source.read_text(encoding="utf-8", errors="replace"),
        )
    else:
        artifacts["resource_timing_report"] = write_text_artifact(
            root,
            RECORD_ID,
            "resource_timing_report",
            "MISSING: production bitstream resource/timing report was not provided to the packager.",
        )

    summary = {
        "schema": "rvmt.genesys2.hardware_pointer_strings.v1",
        "status": status,
        "evidence_artifacts": evidence_rows(root, artifacts),
        "claim_boundary": {
            "real_malware_validation_claimed": False,
            "hardware_full_pointer_strings_claimed": status == "PASS",
            "companion_strings_substituted_as_hardware": False,
            "kernel_or_full_memory_dump_claimed": False,
        },
        "aggregate": {
            "full_string_claimed": status == "PASS",
            "contiguous_from_offset_zero": bool(full_groups) and all(row.get("contiguous_from_offset_zero") is True for row in full_groups),
            "mem_last_observed": bool(full_groups) and all(row.get("mem_last_observed") is True for row in full_groups),
            "companion_derived_strings_as_hardware": 0,
            "kernel_fragment_count": sum(int(row.get("kernel_fragment_count") or 0) for row in pointer_groups),
            "full_memory_dump_count": 0,
        },
        "full_string_group_count": len(full_groups),
        "redaction_policy": "artifact-backed redacted pointer reconstruction; no companion or kernel/full-memory strings are counted as hardware evidence",
        "failed_attempts": failures,
        "pointer_groups": full_groups,
        "syscall_coverage": coverage,
        "record_root": repo_relative(root, record_root),
        "validation_commands": [
            " ".join(
                [
                    "uv run python tools/package_genesys2_hardware_pointer_strings.py",
                    f"--run-root {run_root_for_command}",
                    f"--resource-timing-report {resource_for_command}",
                ]
            ),
            "uv run python tools/check_genesys2_hardware_pointer_strings.py --root .",
            "uv run python tools/package_genesys2_external_closure_intake.py",
            "uv run python tools/check_genesys2_external_closure_intake.py --root .",
        ],
    }
    return summary


def write_fixture_run(root: Path, run_root: Path) -> Path:
    for sample_id in REQUIRED_SAMPLES:
        for rep_index in range(1, REQUIRED_REPS_PER_SAMPLE + 1):
            rep_dir = run_root / sample_id / f"rep_{rep_index:02d}"
            rep_dir.mkdir(parents=True, exist_ok=True)
            rows: list[dict[str, Any]] = []
            sequence = 0
            for syscall_nr, syscall_name, syscall_id, payload in (
                (56, "openat", rep_index * 100 + 1, b"/tmp/a\0"),
                (64, "write", rep_index * 100 + 2, b"hello\0"),
                (221, "execve", rep_index * 100 + 3, b"/bin/sh\0"),
            ):
                base = 0x100000 + syscall_id * 0x100
                data = int.from_bytes(payload.ljust(8, b"\0")[:8], "little")
                rows.append({"evt": "SYSCALL_ENTRY", "sequence_number": sequence, "packed_primary": f"0x{syscall_nr:08x}", "packed_aux": f"0x{syscall_id:08x}"})
                sequence += 1
                rows.append(
                    {
                        "evt": "ARG_MEM",
                        "sequence_number": sequence,
                        "payload_width": 716,
                        "snapshot_source": "hardware_bram_ring_v3",
                        "syscall_id": f"0x{syscall_id:016x}",
                        "arg_index": 0,
                        "mem_base": f"0x{base:016x}",
                        "mem_addr": f"0x{base:016x}",
                        "mem_data": f"0x{data:016x}",
                        "snapshot_bytes": len(payload),
                        "mem_last": True,
                        "syscall_name_fixture": syscall_name,
                    }
                )
                sequence += 1
            (rep_dir / "bram_records.jsonl").write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            (rep_dir / "bram_summary.json").write_text(
                json.dumps(
                    {
                        "schema": "rvmt.genesys2.bram_ring_dump.v1",
                        "status": "PASS",
                        "sample_id": sample_id,
                        "payload_width": 716,
                        "bram_ring": {"dropped_count": 0, "wrap_count": 0},
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
    report = run_root / "timing_resource_report.txt"
    report.write_text("fixture timing/resource report: timing_passed=true resource_delta_recorded=true\n", encoding="utf-8")
    return report


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        run_root = root / "run"
        report = write_fixture_run(root, run_root)
        summary = package_summary(root, run_root, report)
        errors = validate_external_summary(RECORD_ID, summary, root)
        if errors:
            print("[FAIL] hardware pointer string PASS fixture rejected", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        bad_summary = package_summary(root, run_root, None)
        if not validate_external_summary(RECORD_ID, bad_summary, root):
            print("[FAIL] missing resource/timing report fixture accepted", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 hardware pointer strings packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package v3 Genesys2 hardware full pointer-string evidence for external closure intake.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--resource-timing-report", type=Path)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = package_summary(root, args.run_root, args.resource_timing_report)
    out = write_summary(root, args.out, summary)
    errors = validate_external_summary(RECORD_ID, summary, root)
    status = "PASS" if not errors else "FAIL"
    print(f"[{status}] wrote hardware pointer string summary to {out}")
    for error in errors:
        print(f"- {error}")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
