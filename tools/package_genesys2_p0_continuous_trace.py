from __future__ import annotations

import argparse
import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

from join_trace_code_map import annotate_events
from recover_behavior import write_outputs as write_behavior_outputs


ROOT = Path(__file__).resolve().parents[1]
BITSTREAM = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.bit")
LTX = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx")
P0_BUILD_ROOT = Path("build/board/genesys2_cva6_p0_marker")

P0_SAMPLES = [
    ("01_hello_write", "hello_write", 0xA01, [64], []),
    ("02_file_open_read_write", "file_open_read_write", 0xA02, [56, 64, 57, 56, 63, 64, 57], []),
    ("03_fork_exec", "fork_exec", 0xA03, [220, 260, 221], []),
    ("04_illegal_instruction", "illegal_instruction", 0xA04, [134, 64], [2]),
]


def repo_rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


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


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8", newline="\n")


def parse_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 16) if text.startswith("0x") else int(text, 10)
        except ValueError:
            return None
    return None


def sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def marker_indexes(events: list[dict[str, Any]], payload: int) -> tuple[int | None, int | None]:
    begin_value = 0xB0000000 | payload
    end_value = 0xE0000000 | payload
    begin = [index for index, event in enumerate(events) if event.get("evt") == "MARKER" and parse_int(event.get("value")) == begin_value]
    end = [index for index, event in enumerate(events) if event.get("evt") == "MARKER" and parse_int(event.get("value")) == end_value]
    return (begin[0] if len(begin) == 1 else None, end[0] if len(end) == 1 else None)


def raw_strict_pairs(scoped_events: list[dict[str, Any]], base_index: int) -> list[dict[str, Any]]:
    returns_by_id: dict[int, tuple[int, dict[str, Any]]] = {}
    for offset, event in enumerate(scoped_events):
        if event.get("evt") != "SYSCALL_RET":
            continue
        syscall_id = parse_int(event.get("syscall_id"))
        if syscall_id is not None:
            returns_by_id[syscall_id] = (base_index + offset, event)
    pairs: list[dict[str, Any]] = []
    for offset, event in enumerate(scoped_events):
        if event.get("evt") != "SYSCALL_ENTRY":
            continue
        syscall_id = parse_int(event.get("syscall_id"))
        if syscall_id is None or syscall_id == 0 or syscall_id not in returns_by_id:
            continue
        ret_index, ret = returns_by_id[syscall_id]
        pairs.append(
            {
                "entry_index": base_index + offset,
                "return_index": ret_index,
                "syscall_id": f"0x{syscall_id:016x}",
                "number": parse_int(event.get("a7")),
                "entry_cycle": event.get("cycle"),
                "return_cycle": ret.get("cycle"),
                "return_pc": ret.get("pc"),
            }
        )
    return pairs


def target_semantic_syscalls(semantic: dict[str, Any], begin: int, end: int) -> list[dict[str, Any]]:
    syscalls = semantic.get("syscall_sequence", [])
    if not isinstance(syscalls, list):
        return []
    result = []
    for syscall in syscalls:
        if not isinstance(syscall, dict):
            continue
        index = syscall.get("index")
        if not isinstance(index, int) or not (begin < index < end):
            continue
        if syscall.get("pc_owner") == "target_sample" and syscall.get("process_owner") == "target_child":
            result.append(syscall)
    return result


def package_sample(run_root: Path, dirname: str, sample_id: str, payload: int, required_syscalls: list[int], required_traps: list[int]) -> dict[str, Any]:
    sample_root = run_root / dirname
    sample_root.mkdir(parents=True, exist_ok=True)
    trace_path = sample_root / "trace.jsonl"
    runtime_path = sample_root / "runtime_process_map.json"
    if not trace_path.is_file():
        raise FileNotFoundError(trace_path)
    if not runtime_path.is_file():
        raise FileNotFoundError(runtime_path)

    code_dir = sample_root / "trace_code_map"
    code_dir.mkdir(parents=True, exist_ok=True)
    source_code_map = ROOT / P0_BUILD_ROOT / sample_id / "code_map" / "code_map.json"
    if not source_code_map.is_file():
        raise FileNotFoundError(source_code_map)
    code_map_path = code_dir / "code_map.json"
    shutil.copy2(source_code_map, code_map_path)

    events = load_jsonl(trace_path)
    runtime_map = load_json(runtime_path)
    code_map = load_json(code_map_path)
    annotated, attribution = annotate_events(events, code_map, runtime_map)
    write_jsonl(code_dir / "source_attribution.jsonl", annotated)
    write_json(code_dir / "source_attribution_summary.json", attribution)

    write_behavior_outputs(trace_path, sample_root, code_map_path, runtime_path)
    semantic = load_json(sample_root / "semantic_events.json")
    graph = load_json(sample_root / "behavior_graph.json")

    begin, end = marker_indexes(events, payload)
    if begin is None or end is None:
        scoped: list[dict[str, Any]] = []
    else:
        scoped = events[begin : end + 1]
    strict_pairs = raw_strict_pairs(scoped, begin or 0)
    strict_counts = Counter(pair["number"] for pair in strict_pairs)
    required_counts = Counter(required_syscalls)
    strict_pairing = all(strict_counts[number] >= count for number, count in required_counts.items())

    target_syscalls = target_semantic_syscalls(semantic, begin or -1, end or -1)
    observed_target = Counter(int(row.get("number")) for row in target_syscalls if isinstance(row.get("number"), int))
    trap_causes = {parse_int(event.get("cause")) for event in scoped if event.get("evt") == "TRAP"}
    drop_events = [event for event in events if event.get("evt") == "DROP"]
    drop_total = sum(parse_int(event.get("value")) or 0 for event in drop_events)
    bit_path = ROOT / BITSTREAM
    ltx_path = ROOT / LTX
    bit = {
        "path": repo_rel(bit_path),
        "sha256": sha256_file(bit_path),
        "ltx": repo_rel(ltx_path),
        "ltx_sha256": sha256_file(ltx_path),
        "ila_payload_format": "packed_136bit_entry_syscall_id_aux_ret_syscall_id_primary",
    }
    marker_scope = {
        "status": "PASS" if begin is not None and end is not None and begin < end else "FAIL",
        "same_window": begin is not None and end is not None and begin < end,
        "begin_index": begin,
        "end_index": end,
        "payload": f"0x{payload:08x}",
        "begin_value": f"0x{0xB0000000 | payload:08x}",
        "end_value": f"0x{0xE0000000 | payload:08x}",
    }
    summary = {
        "schema": "rvmt.genesys2.p0.trace_summary.v1",
        "sample_id": sample_id,
        "sample_class": "p0_safe_synthetic",
        "safe_surrogate_only": True,
        "evidence_root": repo_rel(sample_root),
        "run_root": repo_rel(run_root),
        "board": "Digilent Genesys2",
        "cpu": "CVA6 rv64gc sv39",
        "os": "Buildroot Linux 6.19.6 riscv64",
        "bitstream": bit,
        "trace": repo_rel(trace_path),
        "trace_events": len(events),
        "event_counts": dict(sorted(Counter(str(event.get("evt")) for event in events).items())),
        "marker_scope": marker_scope,
        "drop_accounting": {
            "status": "PASS" if drop_total == 0 and not drop_events else "FAIL",
            "drop_event_count": len(drop_events),
            "unaccounted_drop": drop_total,
        },
        "runtime_process_map": repo_rel(runtime_path),
        "runtime_process_map_status": runtime_map.get("status"),
        "runtime_process_attribution_proven": attribution.get("runtime_process_attribution_proven") is True,
        "runtime_process": {
            "pid": runtime_map.get("pid"),
            "tgid": runtime_map.get("tgid"),
            "comm": runtime_map.get("comm"),
            "cmdline": runtime_map.get("cmdline"),
            "exe": runtime_map.get("exe"),
            "map_count": len(runtime_map.get("maps") or []),
            "target_exit_from_map_run": runtime_map.get("target_exit"),
        },
        "code_attribution": {
            "status": "PASS" if attribution.get("runtime_process_attribution_proven") else "FAIL",
            "code_map": repo_rel(code_map_path),
            "summary": repo_rel(code_dir / "source_attribution_summary.json"),
            "target_attributed_events": attribution.get("target_attributed_events", 0),
            "process_attributed_code_site_events": attribution.get("process_attributed_code_site_events", 0),
            "function_level_available": attribution.get("source_attribution", {}).get("function_level_available"),
            "source_line_available": attribution.get("source_attribution", {}).get("source_line_available"),
        },
        "syscall_pairing": {
            "status": "PASS" if strict_pairing else "FAIL",
            "strict_entry_return_syscall_id_pairing": strict_pairing,
            "strict_syscall_id_pairs": strict_pairs,
            "same_window_ordered_entry_return_pairing": bool(strict_pairs),
        },
        "target_behavior": {
            "status": "PASS"
            if all(observed_target[number] >= count for number, count in required_counts.items())
            and all(cause in trap_causes for cause in required_traps)
            else "FAIL",
            "required_syscalls": required_syscalls,
            "observed_target_syscalls": sorted(observed_target),
            "missing_required_syscalls": [
                number for number, count in sorted(required_counts.items()) if observed_target[number] < count
            ],
            "required_trap_causes": required_traps,
            "observed_trap_causes": sorted(cause for cause in trap_causes if cause is not None),
            "missing_required_trap_causes": [cause for cause in required_traps if cause not in trap_causes],
            "paired_target_syscalls": sum(1 for row in target_syscalls if str(row.get("confidence", "")).startswith("paired_")),
        },
        "artifacts": {
            "ila_csv": repo_rel(next(sample_root.glob("*.csv"))),
            "capture_log": repo_rel(next(sample_root.glob("*_capture.log"))),
            "capture_err_log": repo_rel(next(sample_root.glob("*_capture.err.log"))),
            "uart_log": repo_rel(sample_root / "uart_run.log"),
            "semantic_events": repo_rel(sample_root / "semantic_events.json"),
            "behavior_graph": repo_rel(sample_root / "behavior_graph.json"),
            "recovery_report": repo_rel(sample_root / "recovery_report.md"),
        },
    }
    write_json(sample_root / "trace_summary.json", summary)

    pass_conditions = {
        "same_window_marker_trace": marker_scope["status"] == "PASS",
        "strict_syscall_id_entry_return_pairing": strict_pairing,
        "runtime_process_attribution_proven": summary["runtime_process_attribution_proven"],
        "code_attribution_to_target_elf": attribution.get("target_attributed_events", 0) > 0,
        "drop_accounting_zero": summary["drop_accounting"]["status"] == "PASS",
        "required_behavior_present": summary["target_behavior"]["status"] == "PASS",
        "board_cpu_bitstream_metadata_present": bool(bit["path"] and bit["sha256"] and bit["ltx_sha256"]),
    }
    integrated = {
        "schema": "rvmt.genesys2.p0.integrated_validation.v1",
        "sample_id": sample_id,
        "status": "PASS" if all(pass_conditions.values()) else "FAIL",
        "pass_conditions": pass_conditions,
        "non_claims": [
            "Not real malware validation.",
            "Not malware detection quality evidence.",
            "Not production trace sink evidence.",
        ],
        "evidence": {
            "trace_summary": repo_rel(sample_root / "trace_summary.json"),
            "runtime_process_map": repo_rel(runtime_path),
            "source_attribution_summary": repo_rel(code_dir / "source_attribution_summary.json"),
            "semantic_events": repo_rel(sample_root / "semantic_events.json"),
            "behavior_graph": repo_rel(sample_root / "behavior_graph.json"),
        },
    }
    write_json(sample_root / "integrated_validation.json", integrated)
    return {
        "sample_id": sample_id,
        "status": integrated["status"],
        "evidence_root": repo_rel(sample_root),
        "pass_conditions": pass_conditions,
        "blocking_failures": [key for key, value in pass_conditions.items() if not value],
    }


def package_run(run_root: Path) -> dict[str, Any]:
    samples = [package_sample(run_root, *row) for row in P0_SAMPLES]
    bit_path = ROOT / BITSTREAM
    ltx_path = ROOT / LTX
    summary = {
        "schema": "rvmt.genesys2.p0.run_summary.v1",
        "status": "PASS" if all(row["status"] == "PASS" for row in samples) else "FAIL",
        "run_root": repo_rel(run_root),
        "board": "Digilent Genesys2",
        "cpu": "CVA6 rv64gc sv39",
        "bitstream": {
            "path": repo_rel(bit_path),
            "sha256": sha256_file(bit_path),
            "ltx": repo_rel(ltx_path),
            "ltx_sha256": sha256_file(ltx_path),
        },
        "allowed_claims": [
            "P0 safe synthetic marker-scoped same-window Genesys2/CVA6 board trace evidence with strict raw syscall_id entry/return pairing."
        ],
        "non_claims": [
            "Not real malware validation.",
            "Not detection quality evidence.",
            "Not production trace sink evidence.",
        ],
        "samples": samples,
    }
    write_json(run_root / "run_summary.json", summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package Genesys2/CVA6 P0 continuous trace evidence.")
    parser.add_argument("--run-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        run_root = args.run_root if args.run_root.is_absolute() else ROOT / args.run_root
        summary = package_run(run_root)
    except Exception as exc:
        print(f"package_genesys2_p0_continuous_trace: error: {exc}", file=__import__("sys").stderr)
        return 2
    print(f"[{summary['status']}] packaged Genesys2 P0 continuous trace evidence: {repo_rel(run_root)}")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
