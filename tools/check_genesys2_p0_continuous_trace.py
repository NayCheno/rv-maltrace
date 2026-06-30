from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    load_jsonl,
    require,
)

from genesys2_latest import DEFAULT_LATEST_MANIFEST, active_run_root


P0_SAMPLES = [
    ("01_hello_write", "hello_write", 0xA01, [64], []),
    ("02_file_open_read_write", "file_open_read_write", 0xA02, [56, 64, 57, 56, 63, 64, 57], []),
    ("03_fork_exec", "fork_exec", 0xA03, [220, 260, 221], []),
    ("04_illegal_instruction", "illegal_instruction", 0xA04, [134, 64], [2]),
]


REQUIRED_FILES = [
    "trace.jsonl",
    "trace_summary.json",
    "uart_run.log",
    "runtime_process_map.json",
    "trace_code_map/code_map.json",
    "trace_code_map/source_attribution_summary.json",
    "semantic_events.json",
    "behavior_graph.json",
    "recovery_report.md",
    "integrated_validation.json",
]


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
        ret_index, _ = returns_by_id[syscall_id]
        pairs.append(
            {
                "entry_index": base_index + offset,
                "return_index": ret_index,
                "syscall_id": syscall_id,
                "number": parse_int(event.get("a7")),
            }
        )
    return pairs


def target_semantic_syscalls(semantic: dict[str, Any], begin: int, end: int) -> list[dict[str, Any]]:
    syscalls = semantic.get("syscall_sequence", [])
    if not isinstance(syscalls, list):
        return []
    result: list[dict[str, Any]] = []
    for syscall in syscalls:
        if not isinstance(syscall, dict):
            continue
        index = syscall.get("index")
        if not isinstance(index, int) or not (begin < index < end):
            continue
        if syscall.get("pc_owner") == "target_sample" and syscall.get("process_owner") == "target_child":
            result.append(syscall)
    return result


def check_sample(run_root: Path, dirname: str, sample_id: str, payload: int, required_syscalls: list[int], required_traps: list[int]) -> list[str]:
    errors: list[str] = []
    sample_root = run_root / dirname
    require(errors, sample_root.is_dir(), f"{sample_id}: evidence root missing: {sample_root}")
    if errors:
        return errors

    for relative in REQUIRED_FILES:
        require(errors, (sample_root / relative).is_file(), f"{sample_id}: required artifact missing: {relative}")
    capture_logs = list(sample_root.glob("*_capture.log"))
    capture_err_logs = list(sample_root.glob("*_capture.err.log"))
    csv_files = list(sample_root.glob("*.csv"))
    require(errors, bool(capture_logs), f"{sample_id}: Vivado/JTAG/ILA capture log missing")
    require(errors, bool(capture_err_logs), f"{sample_id}: Vivado/JTAG/ILA capture stderr log missing")
    require(errors, bool(csv_files), f"{sample_id}: ILA CSV capture missing")
    if errors:
        return errors

    trace = load_jsonl(sample_root / "trace.jsonl")
    summary = load_json(sample_root / "trace_summary.json")
    integrated = load_json(sample_root / "integrated_validation.json")
    runtime_map = load_json(sample_root / "runtime_process_map.json")
    attribution = load_json(sample_root / "trace_code_map/source_attribution_summary.json")
    semantic = load_json(sample_root / "semantic_events.json")
    graph = load_json(sample_root / "behavior_graph.json")

    begin, end = marker_indexes(trace, payload)
    require(errors, begin is not None and end is not None and begin < end, f"{sample_id}: marker begin/end not present in one ordered trace window")
    if begin is None or end is None:
        return errors
    scoped = trace[begin : end + 1]

    drop_events = [event for event in trace if event.get("evt") == "DROP"]
    drop_total = sum(parse_int(event.get("value")) or 0 for event in drop_events)
    require(errors, drop_total == 0 and not drop_events, f"{sample_id}: unaccounted drop is nonzero or DROP events are present")

    target_syscalls = target_semantic_syscalls(semantic, begin, end)
    observed = Counter(int(syscall.get("number")) for syscall in target_syscalls if isinstance(syscall.get("number"), int))
    required = Counter(required_syscalls)
    for number, count in required.items():
        require(errors, observed[number] >= count, f"{sample_id}: missing target syscall {number}; need {count}, observed {observed[number]}")
    paired_target = [syscall for syscall in target_syscalls if str(syscall.get("confidence", "")).startswith("paired_")]
    require(errors, len(paired_target) >= len(required_syscalls), f"{sample_id}: target syscall entry/return semantic pairing incomplete")

    trap_causes = {parse_int(event.get("cause")) for event in scoped if event.get("evt") == "TRAP"}
    for cause in required_traps:
        require(errors, cause in trap_causes, f"{sample_id}: missing required trap cause {cause}")

    strict_pairs = raw_strict_pairs(scoped, begin)
    strict_numbers = Counter(pair.get("number") for pair in strict_pairs)
    for number, count in required.items():
        require(
            errors,
            strict_numbers[number] >= count,
            f"{sample_id}: raw SYSCALL_ENTRY/SYSCALL_RET cannot be paired by matching syscall_id for syscall {number}; "
            f"need {count}, observed {strict_numbers[number]}",
        )

    require(errors, runtime_map.get("status") == "PASS", f"{sample_id}: runtime_process_map status is not PASS")
    require(errors, runtime_map.get("pid") is not None and runtime_map.get("tgid") is not None, f"{sample_id}: PID/TGID missing")
    require(errors, bool(runtime_map.get("comm")) and bool(runtime_map.get("cmdline")) and bool(runtime_map.get("exe")), f"{sample_id}: comm/cmdline/exe missing")
    require(errors, isinstance(runtime_map.get("maps"), list) and bool(runtime_map.get("maps")), f"{sample_id}: /proc/$pid/maps missing")

    require(errors, attribution.get("runtime_process_attribution_proven") is True, f"{sample_id}: runtime_process_attribution_proven is not true")
    require(errors, int(attribution.get("target_attributed_events", 0)) > 0, f"{sample_id}: no events attributed to target ELF")
    require(errors, attribution.get("source_attribution", {}).get("function_level_available") is True, f"{sample_id}: function-level attribution missing")

    marker_scope = summary.get("marker_scope", {}) if isinstance(summary.get("marker_scope"), dict) else {}
    require(errors, marker_scope.get("same_window") is True and marker_scope.get("status") == "PASS", f"{sample_id}: trace_summary marker scope not PASS")
    require(errors, summary.get("runtime_process_attribution_proven") is True, f"{sample_id}: trace_summary runtime attribution not proven")
    require(errors, summary.get("drop_accounting", {}).get("unaccounted_drop") == 0, f"{sample_id}: trace_summary drop accounting not zero")
    require(errors, "Genesys2" in str(summary.get("board")), f"{sample_id}: board metadata missing Genesys2")
    require(errors, "CVA6" in str(summary.get("cpu")), f"{sample_id}: CPU metadata missing CVA6")
    bitstream = summary.get("bitstream", {}) if isinstance(summary.get("bitstream"), dict) else {}
    require(errors, bool(bitstream.get("path")) and bool(bitstream.get("sha256")) and bool(bitstream.get("ltx_sha256")), f"{sample_id}: bitstream metadata incomplete")

    pass_conditions = integrated.get("pass_conditions", {}) if isinstance(integrated.get("pass_conditions"), dict) else {}
    require(errors, pass_conditions.get("strict_syscall_id_entry_return_pairing") is True, f"{sample_id}: integrated validation strict syscall-id pairing is not true")
    non_claims = " ".join(str(item).lower() for item in integrated.get("non_claims", []))
    detection_non_claim = "not detection quality" in non_claims or "not malware detection quality" in non_claims
    require(errors, "not real malware" in non_claims and detection_non_claim, f"{sample_id}: non-claims missing")
    require(errors, graph.get("schema") == "rvmt.behavior.graph.v1", f"{sample_id}: behavior graph schema mismatch")
    return errors


def check_run(run_root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, run_root.is_dir(), f"run root missing: {run_root}")
    require(errors, (run_root / "run_summary.json").is_file(), "run_summary.json missing")
    if errors:
        return errors
    for sample in P0_SAMPLES:
        errors.extend(check_sample(run_root, *sample))
    return errors


def write_fixture(root: Path, strict_pairing: bool) -> None:
    run_root = root / "run"
    for dirname, sample_id, payload, required_syscalls, required_traps in P0_SAMPLES:
        sample_root = run_root / dirname
        (sample_root / "trace_code_map").mkdir(parents=True)
        begin = f"0x{0xB0000000 | payload:016x}"
        end = f"0x{0xE0000000 | payload:016x}"
        trace = [{"evt": "MARKER", "value": begin, "pc": "0x00010100"}]
        semantic_syscalls = []
        next_pc = 0x00010104
        for seq, number in enumerate(required_syscalls, start=1):
            entry_id = f"0x{seq:016x}" if strict_pairing else "0x0000000000000000"
            trace.append({"evt": "SYSCALL_ENTRY", "syscall_id": entry_id, "a7": f"0x{number:016x}", "pc": f"0x{next_pc:08x}"})
            semantic_syscalls.append(
                {
                    "index": len(trace) - 1,
                    "number": number,
                    "confidence": "paired_target_ecall_return",
                    "pc_owner": "target_sample",
                    "process_owner": "target_child",
                }
            )
            next_pc += 4
            trace.append({"evt": "SYSCALL_RET", "syscall_id": f"0x{seq:016x}", "pc": "0x803d3226"})
            next_pc += 4
        if required_traps:
            trace.append({"evt": "TRAP", "cause": f"0x{required_traps[0]:016x}", "pc": "0x00010108"})
        trace.append({"evt": "MARKER", "value": end, "pc": "0x0001010c"})
        (sample_root / "trace.jsonl").write_text("".join(json.dumps(row) + "\n" for row in trace), encoding="utf-8")
        for name in ("uart_run.log", "x_capture.log", "x_capture.err.log", "x.csv", "recovery_report.md"):
            (sample_root / name).write_text("fixture\n", encoding="utf-8")
        runtime = {
            "status": "PASS",
            "pid": 11,
            "tgid": 11,
            "comm": sample_id[:15],
            "cmdline": f"/tmp/rvmt_p0/{sample_id}",
            "exe": f"/tmp/rvmt_p0/{sample_id}",
            "maps": [{"start": "0x0000000000010000", "end": "0x0000000000012000", "path": f"/tmp/rvmt_p0/{sample_id}"}],
        }
        (sample_root / "runtime_process_map.json").write_text(json.dumps(runtime), encoding="utf-8")
        (sample_root / "trace_code_map/code_map.json").write_text(json.dumps({"sample_id": sample_id}), encoding="utf-8")
        attribution = {
            "runtime_process_attribution_proven": True,
            "target_attributed_events": 1,
            "source_attribution": {"function_level_available": True},
        }
        (sample_root / "trace_code_map/source_attribution_summary.json").write_text(json.dumps(attribution), encoding="utf-8")
        semantic = {"syscall_sequence": semantic_syscalls}
        (sample_root / "semantic_events.json").write_text(json.dumps(semantic), encoding="utf-8")
        (sample_root / "behavior_graph.json").write_text(json.dumps({"schema": "rvmt.behavior.graph.v1"}), encoding="utf-8")
        summary = {
            "marker_scope": {"same_window": True, "status": "PASS"},
            "runtime_process_attribution_proven": True,
            "drop_accounting": {"unaccounted_drop": 0},
            "board": "Digilent Genesys2",
            "cpu": "CVA6 rv64gc sv39",
            "bitstream": {"path": "x.bit", "sha256": "a", "ltx_sha256": "b"},
        }
        (sample_root / "trace_summary.json").write_text(json.dumps(summary), encoding="utf-8")
        integrated = {
            "pass_conditions": {"strict_syscall_id_entry_return_pairing": strict_pairing},
            "non_claims": ["Not real malware validation.", "Not detection quality evidence."],
        }
        (sample_root / "integrated_validation.json").write_text(json.dumps(integrated), encoding="utf-8")
    (run_root / "run_summary.json").write_text(json.dumps({"status": "fixture"}), encoding="utf-8")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root, strict_pairing=True)
        errors = check_run(root / "run")
        if errors:
            print("[FAIL] self-test strict fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root, strict_pairing=False)
        errors = check_run(root / "run")
        if not any("matching syscall_id" in error or "strict syscall-id" in error for error in errors):
            print("[FAIL] self-test packed fixture did not fail strict syscall-id pairing", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 P0 continuous trace checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Genesys2/CVA6 P0 marker-scoped continuous trace evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--latest-manifest", type=Path, default=DEFAULT_LATEST_MANIFEST)
    parser.add_argument("--run-root", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    if args.run_root is None:
        try:
            run_root = active_run_root(root, "p0_continuous_trace", args.latest_manifest)
        except Exception as exc:
            print(f"[FAIL] latest manifest could not resolve p0_continuous_trace: {exc}", file=sys.stderr)
            return 2
    else:
        run_root = args.run_root if args.run_root.is_absolute() else root / args.run_root
    try:
        errors = check_run(run_root)
    except Exception as exc:
        print(f"[FAIL] checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] Genesys2 P0 continuous trace evidence is not yet acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] Genesys2 P0 continuous trace evidence accepted: {run_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
