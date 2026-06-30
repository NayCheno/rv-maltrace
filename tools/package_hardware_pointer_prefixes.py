from __future__ import annotations

import argparse
import json
import string
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_jsonl,
    repo_rel_from,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260612-pointer-snapshot-bram")
DEFAULT_OUT = Path("results/evaluation/genesys2-cva6/current/hardware_pointer_prefix_summary.json")
USER_POINTER_MAX = 0x0000_4000_0000_0000
TARGET_SYSCALLS = {
    56: "openat",
    64: "write",
    221: "execve",
}


repo_rel = repo_rel_from(ROOT)


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


def event_name(row: dict[str, Any]) -> str:
    return str(row.get("evt") or "").upper()


def is_arg_mem(row: dict[str, Any]) -> bool:
    return event_name(row) in {"ARG_MEM", "EVT_ARG_MEM", "POINTER_SNAPSHOT"} or parse_int(row.get("evt_code")) == 10


def is_user_pointer(addr: int | None) -> bool:
    return addr is not None and 0 <= addr < USER_POINTER_MAX


def little_endian_bytes(value: int, width: int) -> bytes:
    return bytes((value >> (8 * index)) & 0xFF for index in range(max(width, 0)))


def byte_display(raw: bytes) -> str:
    printable = set(string.printable.encode("ascii")) - {0x0B, 0x0C}
    return "".join(chr(byte) if byte in printable and byte != 0 else "." for byte in raw)


def escape_ascii(raw: bytes) -> str:
    return raw.decode("ascii", errors="backslashreplace").replace("\x00", "\\0")


def rep_sort_key(path: Path) -> tuple[int, str]:
    name = path.parent.name if path.name == "bram_records.jsonl" else path.name
    try:
        return (int(name.split("_", 1)[1]), name)
    except (IndexError, ValueError):
        return (10**9, name)


def bram_record_paths(run_root: Path) -> list[Path]:
    return sorted((path for path in run_root.glob("*/rep_*/bram_records.jsonl") if path.is_file()), key=rep_sort_key)


def infer_record_width(rows: list[dict[str, Any]], index: int) -> int:
    current = rows[index]
    declared = parse_int(current.get("snapshot_bytes")) or 4
    addr = parse_int(current.get("mem_addr"))
    if addr is None:
        return min(declared, 4)
    next_addr = None
    previous_addr = None
    for row in rows[index + 1 :]:
        candidate = parse_int(row.get("mem_addr"))
        if candidate is not None and candidate > addr:
            next_addr = candidate
            break
    for row in reversed(rows[:index]):
        candidate = parse_int(row.get("mem_addr"))
        if candidate is not None and candidate < addr:
            previous_addr = candidate
            break
    if next_addr is not None:
        delta = next_addr - addr
        if delta == 1:
            return 1
        if 1 < delta < declared:
            return delta
        return min(declared, 4)
    if previous_addr is not None and addr - previous_addr == 1:
        return 1
    return min(declared, 4)


def fragment_from_event(row: dict[str, Any], width: int) -> dict[str, Any] | None:
    addr = parse_int(row.get("mem_addr"))
    data = parse_int(row.get("mem_data") or row.get("packed_aux"))
    if addr is None or data is None:
        return None
    raw = little_endian_bytes(data, width)
    return {
        "sequence_number": parse_int(row.get("sequence_number")),
        "cycle": parse_int(row.get("cycle")),
        "pc": row.get("pc"),
        "mem_addr": f"0x{addr:016x}",
        "byte_count": width,
        "bytes_hex": raw.hex(),
        "ascii_preview": byte_display(raw),
        "snapshot_source": row.get("snapshot_source") or "hardware_bram_ring_compact",
        "compact_width_inferred": width,
        "kernel_address": not is_user_pointer(addr),
    }


def contiguous_prefix(fragments: list[dict[str, Any]]) -> tuple[bytes, bool, list[dict[str, Any]]]:
    prefix = bytearray()
    gaps: list[dict[str, Any]] = []
    expected_next: int | None = None
    for fragment in sorted(fragments, key=lambda item: (parse_int(item.get("mem_addr")) or 0, int(item.get("sequence_number") or 0))):
        addr = parse_int(fragment.get("mem_addr"))
        raw = bytes.fromhex(str(fragment.get("bytes_hex") or ""))
        if addr is None:
            continue
        if expected_next is None:
            prefix.extend(raw)
            expected_next = addr + len(raw)
            continue
        if addr == expected_next:
            prefix.extend(raw)
            expected_next = addr + len(raw)
            continue
        if addr > expected_next:
            gaps.append(
                {
                    "after_addr": f"0x{expected_next:016x}",
                    "next_addr": f"0x{addr:016x}",
                    "missing_bytes": addr - expected_next,
                }
            )
        break
    return bytes(prefix), not gaps, gaps


def build_pointer_groups(trace_path: Path) -> list[dict[str, Any]]:
    records = load_jsonl(trace_path)
    groups: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    current_arg_rows: list[dict[str, Any]] = []

    def finish() -> None:
        nonlocal current, current_arg_rows
        if current is None:
            current_arg_rows = []
            return
        fragments: list[dict[str, Any]] = []
        sorted_arg_rows = sorted(current_arg_rows, key=lambda item: (parse_int(item.get("mem_addr")) or 0, int(item.get("sequence_number") or 0)))
        for index, row in enumerate(sorted_arg_rows):
            width = infer_record_width(sorted_arg_rows, index)
            fragment = fragment_from_event(row, width)
            if fragment is not None:
                fragments.append(fragment)
        if fragments:
            prefix, contiguous, gaps = contiguous_prefix(fragments)
            nul_index = prefix.find(b"\x00")
            visible = prefix if nul_index < 0 else prefix[:nul_index]
            current.update(
                {
                    "record_count": len(fragments),
                    "captured_byte_count": sum(int(fragment.get("byte_count") or 0) for fragment in fragments),
                    "fragment_count": len(fragments),
                    "fragments": fragments,
                    "contiguous_prefix_bytes": len(prefix),
                    "contiguous_prefix_ascii": escape_ascii(visible),
                    "contiguous_prefix_hex": prefix.hex(),
                    "contiguous_from_first_fragment": contiguous,
                    "gap_count": len(gaps),
                    "gaps": gaps,
                    "nul_seen_in_contiguous_prefix": nul_index >= 0,
                    "hardware_source": True,
                    "full_string_claimed": False,
                    "confidence": "bounded_hardware_prefix" if contiguous and len(prefix) > 0 else "hardware_fragments_with_gaps",
                }
            )
            groups.append(current)
        current = None
        current_arg_rows = []

    for row in records:
        evt = event_name(row)
        if evt == "SYSCALL_ENTRY":
            finish()
            syscall_nr = parse_int(row.get("packed_primary") or row.get("syscall_nr") or row.get("a7"))
            syscall_id = parse_int(row.get("packed_aux") or row.get("syscall_id"))
            if syscall_nr in TARGET_SYSCALLS:
                current = {
                    "syscall_name": TARGET_SYSCALLS[syscall_nr],
                    "syscall_nr": syscall_nr,
                    "syscall_id": f"0x{syscall_id:08x}" if syscall_id is not None else None,
                    "entry_sequence": parse_int(row.get("sequence_number")),
                    "entry_pc": row.get("pc"),
                }
            else:
                current = None
        elif is_arg_mem(row):
            if current is not None:
                current_arg_rows.append(row)
        elif evt == "SYSCALL_RET":
            ret_syscall_id = parse_int(row.get("packed_primary") or row.get("syscall_id"))
            if current is not None:
                current["return_sequence"] = parse_int(row.get("sequence_number"))
                current["return_value"] = row.get("packed_aux")
                if current.get("syscall_id") and ret_syscall_id is not None:
                    current["return_syscall_id"] = f"0x{ret_syscall_id:08x}"
            finish()
    finish()
    return groups


def summarize_repetition(path: Path, run_root: Path) -> dict[str, Any]:
    sample_id = path.parents[1].name
    rep = path.parent.name
    groups = build_pointer_groups(path)
    syscall_names = sorted({str(group.get("syscall_name")) for group in groups if group.get("syscall_name")})
    kernel_fragment_count = sum(
        1
        for group in groups
        for fragment in group.get("fragments", [])
        if isinstance(fragment, dict) and fragment.get("kernel_address") is True
    )
    return {
        "sample_id": sample_id,
        "repetition": rep,
        "trace": repo_rel(path),
        "pointer_group_count": len(groups),
        "captured_byte_count": sum(int(group.get("captured_byte_count") or 0) for group in groups),
        "syscall_names": syscall_names,
        "kernel_fragment_count": kernel_fragment_count,
        "groups": groups,
    }


def package_summary(run_root: Path) -> dict[str, Any]:
    paths = bram_record_paths(run_root)
    repetitions = [summarize_repetition(path, run_root) for path in paths]
    sample_map: dict[str, list[dict[str, Any]]] = {}
    for row in repetitions:
        sample_map.setdefault(str(row["sample_id"]), []).append(row)
    samples: list[dict[str, Any]] = []
    for sample_id in sorted(sample_map):
        reps = sorted(sample_map[sample_id], key=lambda item: rep_sort_key(Path(str(item["repetition"]))))
        samples.append(
            {
                "sample_id": sample_id,
                "repetition_count": len(reps),
                "pointer_group_count": sum(int(rep.get("pointer_group_count") or 0) for rep in reps),
                "captured_byte_count": sum(int(rep.get("captured_byte_count") or 0) for rep in reps),
                "syscall_names": sorted({name for rep in reps for name in rep.get("syscall_names", [])}),
                "kernel_fragment_count": sum(int(rep.get("kernel_fragment_count") or 0) for rep in reps),
                "repetitions": reps,
            }
        )
    total_groups = sum(int(rep.get("pointer_group_count") or 0) for rep in repetitions)
    total_bytes = sum(int(rep.get("captured_byte_count") or 0) for rep in repetitions)
    syscalls = sorted({name for rep in repetitions for name in rep.get("syscall_names", [])})
    kernel_fragments = sum(int(rep.get("kernel_fragment_count") or 0) for rep in repetitions)
    status = "PASS" if paths and total_groups > 0 and total_bytes > 0 and kernel_fragments == 0 else "FAIL"
    return {
        "schema": "rvmt.hardware_pointer_prefixes.v1",
        "status": status,
        "board": "Digilent Genesys2",
        "cpu": "CVA6 rv64gc sv39",
        "run_root": repo_rel(run_root),
        "trace_sink_mode": "bram_ring",
        "source_record_format": "compact_arg_mem_32bit_addr_data_prefix",
        "hardware_pointer_bytes_observed": total_bytes > 0,
        "hardware_pointer_prefixes_claimed": True,
        "hardware_pointer_strings_claimed": False,
        "full_string_claimed": False,
        "companion_derived_strings_as_hardware": False,
        "total_repetitions": len(repetitions),
        "sample_count": len(samples),
        "pointer_group_count": total_groups,
        "captured_byte_count": total_bytes,
        "syscall_names": syscalls,
        "required_syscall_coverage": {name: name in syscalls for name in sorted(set(TARGET_SYSCALLS.values()))},
        "kernel_fragment_count": kernel_fragments,
        "allowed_claims": [
            "Current Genesys2/CVA6 BRAM compact ARG_MEM records expose bounded hardware byte fragments and contiguous prefixes for selected user-pointer syscall arguments.",
        ],
        "non_claims": [
            "The current compact BRAM record format does not preserve full pointer strings.",
            "Gapped fragments are not joined into complete strings.",
            "Trusted companion strings remain semantic sidecar evidence and are not reported as hardware-derived pointer strings.",
            "The emitted byte previews are bounded safe-synthetic evidence and are not a raw-payload release policy for untrusted or real-malware inputs.",
            "This artifact does not validate real malware payloads.",
        ],
        "samples": samples,
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        trace = root / "run" / "batch_open_read_write" / "rep_01" / "bram_records.jsonl"
        trace.parent.mkdir(parents=True, exist_ok=True)
        rows = [
            {"evt": "SYSCALL_ENTRY", "packed_primary": "0x00000040", "packed_aux": "0x00000001", "sequence_number": 1, "pc": "0x100"},
            {"evt": "ARG_MEM", "mem_addr": "0x0000000000010000", "mem_data": "0x0000000000000072", "snapshot_bytes": 4, "snapshot_source": "hardware_bram_ring_compact", "sequence_number": 2},
            {"evt": "ARG_MEM", "mem_addr": "0x0000000000010001", "mem_data": "0x0000000000000076", "snapshot_bytes": 4, "snapshot_source": "hardware_bram_ring_compact", "sequence_number": 3},
            {"evt": "ARG_MEM", "mem_addr": "0x0000000000010002", "mem_data": "0x000000000000006d", "snapshot_bytes": 4, "snapshot_source": "hardware_bram_ring_compact", "sequence_number": 4},
            {"evt": "SYSCALL_RET", "packed_primary": "0x00000001", "packed_aux": "0x00000003", "sequence_number": 5},
        ]
        trace.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8", newline="\n")
        summary = package_summary(root / "run")
    if summary.get("status") != "PASS":
        print("[FAIL] expected good fixture to pass", file=sys.stderr)
        return 1
    group = summary["samples"][0]["repetitions"][0]["groups"][0]
    if group.get("contiguous_prefix_ascii") != "rvm" or group.get("full_string_claimed") is not False:
        print("[FAIL] fixture prefix reconstruction mismatch", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        summary = package_summary(Path(tmp) / "missing")
    if summary.get("status") == "PASS":
        print("[FAIL] expected missing fixture to fail", file=sys.stderr)
        return 1
    print("[PASS] hardware pointer prefix packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package hardware ARG_MEM byte-fragment/prefix evidence.")
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    try:
        summary = package_summary(args.run_root)
        write_json(args.out, summary)
    except Exception as exc:
        print(f"package_hardware_pointer_prefixes: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] wrote hardware pointer prefix summary to {args.out}")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
