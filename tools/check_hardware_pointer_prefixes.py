from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_list,
    load_json,
    repo_path,
    require,
    write_json,
)


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/hardware_pointer_prefix_summary.json")
REQUIRED_SYSCALLS = {"openat", "write", "execve"}


def num(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default


def check_group(errors: list[str], sample_id: str, rep: str, index: int, group: dict[str, Any]) -> None:
    label = f"{sample_id}/{rep}/group_{index:02d}"
    require(errors, group.get("hardware_source") is True, f"{label}: hardware_source must be true")
    require(errors, group.get("full_string_claimed") is False, f"{label}: full_string_claimed must be false")
    require(errors, str(group.get("syscall_name") or "") in REQUIRED_SYSCALLS, f"{label}: syscall_name must be one of required syscalls")
    require(errors, num(group.get("record_count")) > 0, f"{label}: record_count must be positive")
    require(errors, num(group.get("captured_byte_count")) > 0, f"{label}: captured_byte_count must be positive")
    require(errors, num(group.get("fragment_count")) > 0, f"{label}: fragment_count must be positive")
    require(errors, num(group.get("contiguous_prefix_bytes")) > 0, f"{label}: contiguous_prefix_bytes must be positive")
    require(
        errors,
        str(group.get("confidence") or "") in {"bounded_hardware_prefix", "hardware_fragments_with_gaps"},
        f"{label}: confidence invalid",
    )
    if num(group.get("gap_count")) > 0:
        require(errors, group.get("confidence") == "hardware_fragments_with_gaps", f"{label}: gapped groups must not claim bounded_hardware_prefix")
        require(errors, as_list(group.get("gaps")), f"{label}: gap details required")
    fragments = as_list(group.get("fragments"))
    require(errors, len(fragments) == int(num(group.get("fragment_count"))), f"{label}: fragment_count mismatch")
    for fragment_index, fragment in enumerate(fragments, start=1):
        if not isinstance(fragment, dict):
            errors.append(f"{label}/fragment_{fragment_index:02d}: fragment must be object")
            continue
        require(errors, fragment.get("kernel_address") is False, f"{label}/fragment_{fragment_index:02d}: kernel address capture is forbidden")
        require(errors, str(fragment.get("snapshot_source") or "").startswith("hardware_"), f"{label}/fragment_{fragment_index:02d}: hardware snapshot source required")
        require(errors, num(fragment.get("byte_count")) > 0, f"{label}/fragment_{fragment_index:02d}: byte_count must be positive")
        require(errors, bool(fragment.get("bytes_hex")), f"{label}/fragment_{fragment_index:02d}: bytes_hex required")


def check_summary(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == "rvmt.hardware_pointer_prefixes.v1", "schema must be rvmt.hardware_pointer_prefixes.v1")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("trace_sink_mode") == "bram_ring", "trace_sink_mode must be bram_ring")
    require(errors, data.get("hardware_pointer_bytes_observed") is True, "hardware pointer bytes must be observed")
    require(errors, data.get("hardware_pointer_prefixes_claimed") is True, "bounded hardware prefix claim must be true")
    require(errors, data.get("hardware_pointer_strings_claimed") is False, "hardware pointer strings claim must be false")
    require(errors, data.get("full_string_claimed") is False, "full string claim must be false")
    require(errors, data.get("companion_derived_strings_as_hardware") is False, "companion strings must not be reported as hardware")
    require(errors, num(data.get("total_repetitions")) >= 30, "expected at least 30 pointer snapshot repetitions")
    require(errors, num(data.get("pointer_group_count")) > 0, "pointer_group_count must be positive")
    require(errors, num(data.get("captured_byte_count")) > 0, "captured_byte_count must be positive")
    require(errors, num(data.get("kernel_fragment_count")) == 0, "kernel_fragment_count must be zero")
    syscalls = {str(item) for item in as_list(data.get("syscall_names"))}
    require(errors, REQUIRED_SYSCALLS <= syscalls, "required syscall coverage missing")
    coverage = data.get("required_syscall_coverage") if isinstance(data.get("required_syscall_coverage"), dict) else {}
    for syscall in REQUIRED_SYSCALLS:
        require(errors, coverage.get(syscall) is True, f"required syscall coverage false: {syscall}")
    run_root = data.get("run_root")
    require(errors, bool(run_root), "run_root required")
    if run_root:
        require(errors, repo_path(root, run_root).is_dir(), f"run_root missing: {run_root}")
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "does not preserve full pointer strings" in non_claims, "non_claims must reject full pointer strings")
    require(errors, "not reported as hardware-derived pointer strings" in non_claims, "non_claims must reject companion string promotion")
    samples = as_list(data.get("samples"))
    require(errors, len(samples) >= 3, "expected at least three pointer snapshot samples")
    observed_reps = 0
    observed_groups = 0
    observed_contiguous_write = False
    for sample in samples:
        if not isinstance(sample, dict):
            errors.append("sample rows must be objects")
            continue
        sample_id = str(sample.get("sample_id") or "")
        require(errors, bool(sample_id), "sample_id required")
        require(errors, num(sample.get("repetition_count")) >= 10, f"{sample_id}: expected at least 10 repetitions")
        require(errors, num(sample.get("pointer_group_count")) > 0, f"{sample_id}: pointer_group_count must be positive")
        require(errors, num(sample.get("captured_byte_count")) > 0, f"{sample_id}: captured_byte_count must be positive")
        require(errors, num(sample.get("kernel_fragment_count")) == 0, f"{sample_id}: kernel_fragment_count must be zero")
        reps = as_list(sample.get("repetitions"))
        observed_reps += len(reps)
        for rep_row in reps:
            if not isinstance(rep_row, dict):
                errors.append(f"{sample_id}: repetition row must be object")
                continue
            rep = str(rep_row.get("repetition") or "")
            require(errors, bool(rep), f"{sample_id}: repetition label required")
            require(errors, repo_path(root, rep_row.get("trace")).is_file(), f"{sample_id}/{rep}: trace file missing")
            require(errors, num(rep_row.get("pointer_group_count")) > 0, f"{sample_id}/{rep}: pointer_group_count must be positive")
            require(errors, num(rep_row.get("kernel_fragment_count")) == 0, f"{sample_id}/{rep}: kernel_fragment_count must be zero")
            groups = as_list(rep_row.get("groups"))
            observed_groups += len(groups)
            for index, group in enumerate(groups, start=1):
                if not isinstance(group, dict):
                    errors.append(f"{sample_id}/{rep}/group_{index:02d}: group must be object")
                    continue
                check_group(errors, sample_id, rep, index, group)
                if group.get("syscall_name") == "write" and group.get("confidence") == "bounded_hardware_prefix":
                    observed_contiguous_write = True
    require(errors, observed_reps == int(num(data.get("total_repetitions"))), "total_repetitions mismatch")
    require(errors, observed_groups == int(num(data.get("pointer_group_count"))), "pointer_group_count mismatch")
    require(errors, observed_contiguous_write, "expected at least one contiguous hardware write prefix")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        trace = root / "run" / "file_scan" / "rep_01" / "bram_records.jsonl"
        trace.parent.mkdir(parents=True, exist_ok=True)
        trace.write_text("{}\n", encoding="utf-8", newline="\n")
        groups = [
            {
                "syscall_name": "write",
                "record_count": 3,
                "captured_byte_count": 3,
                "fragment_count": 3,
                "contiguous_prefix_bytes": 3,
                "contiguous_prefix_ascii": "abc",
                "gap_count": 0,
                "gaps": [],
                "hardware_source": True,
                "full_string_claimed": False,
                "confidence": "bounded_hardware_prefix",
                "fragments": [
                    {"snapshot_source": "hardware_bram_ring_compact", "kernel_address": False, "byte_count": 1, "bytes_hex": "61"},
                    {"snapshot_source": "hardware_bram_ring_compact", "kernel_address": False, "byte_count": 1, "bytes_hex": "62"},
                    {"snapshot_source": "hardware_bram_ring_compact", "kernel_address": False, "byte_count": 1, "bytes_hex": "63"},
                ],
            }
        ]
        samples = []
        for sample_id, syscall in [("file_scan", "openat"), ("batch_open_read_write", "write"), ("process_chain", "execve")]:
            sample_groups = [dict(groups[0], syscall_name=syscall)]
            reps = []
            for rep in range(1, 11):
                reps.append(
                    {
                        "sample_id": sample_id,
                        "repetition": f"rep_{rep:02d}",
                        "trace": trace.relative_to(root).as_posix(),
                        "pointer_group_count": 1,
                        "captured_byte_count": 3,
                        "kernel_fragment_count": 0,
                        "groups": sample_groups,
                    }
                )
            samples.append(
                {
                    "sample_id": sample_id,
                    "repetition_count": 10,
                    "pointer_group_count": 10,
                    "captured_byte_count": 30,
                    "kernel_fragment_count": 0,
                    "repetitions": reps,
                }
            )
        summary = {
            "schema": "rvmt.hardware_pointer_prefixes.v1",
            "status": "PASS",
            "run_root": "run",
            "trace_sink_mode": "bram_ring",
            "hardware_pointer_bytes_observed": True,
            "hardware_pointer_prefixes_claimed": True,
            "hardware_pointer_strings_claimed": False,
            "full_string_claimed": False,
            "companion_derived_strings_as_hardware": False,
            "total_repetitions": 30,
            "pointer_group_count": 30,
            "captured_byte_count": 90,
            "kernel_fragment_count": 0,
            "syscall_names": sorted(REQUIRED_SYSCALLS),
            "required_syscall_coverage": {name: True for name in REQUIRED_SYSCALLS},
            "non_claims": [
                "The current compact BRAM record format does not preserve full pointer strings.",
                "Trusted companion strings remain semantic sidecar evidence and are not reported as hardware-derived pointer strings.",
            ],
            "samples": samples,
        }
        write_json(root / "summary.json", summary)
        errors = check_summary(load_json(root / "summary.json"), root)
        if errors:
            print("[FAIL] hardware pointer prefix good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        summary["hardware_pointer_strings_claimed"] = True
        write_json(root / "bad.json", summary)
        errors = check_summary(load_json(root / "bad.json"), root)
        if not errors:
            print("[FAIL] hardware pointer prefix bad fixture passed", file=sys.stderr)
            return 1
    print("[PASS] hardware pointer prefix checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check hardware ARG_MEM byte-fragment/prefix evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] missing hardware pointer prefix summary: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root)
    except Exception as exc:
        print(f"[FAIL] hardware pointer prefix checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] hardware pointer prefix evidence is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] hardware pointer prefix evidence accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
