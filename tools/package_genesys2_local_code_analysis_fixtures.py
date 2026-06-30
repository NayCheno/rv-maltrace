from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    write_json,
)

from analyze_single_riscv_binary_trace import (
    apply_runtime_load_base,
    enrich_function_annotations,
    summary_from_analysis,
)
from join_trace_code_map import annotate_events


DEFAULT_OUT = Path("results/evaluation/genesys2-cva6/current/local_code_analysis_fixture_summary.json")
SCHEMA = "rvmt.genesys2.local_code_analysis_fixtures.v1"
PASS_STATUS = "PASS_LOCAL_CODE_ANALYSIS_FIXTURES"


def hx(value: int) -> str:
    return f"0x{value:016x}"


def base_dyn_code_map() -> dict[str, Any]:
    return {
        "schema": "rvmt.code_map.v1",
        "sample_id": "fixture_pie_exact_elf",
        "binary_role": "single_riscv_binary",
        "elf": "fixtures/pie_exact_board.elf",
        "sha256": "11" * 32,
        "elf_type": "DYN",
        "load_base_assumption": "pie_vaddr_zero_requires_runtime_load_base",
        "elf_header": {"class": "ELF64", "type": "DYN", "machine": 243, "entry": "0x0000000000000100"},
        "load_ranges": [{"start": "0x0000000000000000", "end": "0x0000000000001000", "segment": "text", "perms": "R-X"}],
        "sections": [{"name": ".text", "start": "0x0000000000000000", "end": "0x0000000000001000"}],
        "symbols": [
            {"name": "_start", "start": "0x0000000000000100", "end": "0x0000000000000110"},
            {"name": "main", "start": "0x0000000000000120", "end": "0x0000000000000180"},
        ],
        "function_ranges": [
            {"function": "_start", "start": "0x0000000000000100", "end": "0x0000000000000110", "confidence": "symbol_table"},
            {"function": "main", "start": "0x0000000000000120", "end": "0x0000000000000180", "confidence": "symbol_table"},
        ],
        "syscall_sites": [{"pc": "0x0000000000000128", "symbol": "main", "asm": "ecall"}],
        "trap_sites": [{"pc": "0x0000000000000140", "symbol": "main", "kind": "illegal_instruction"}],
        "source_locations": [{"pc": "0x0000000000000128", "function": "main", "file": "fixture_pie.c", "line": 17}],
        "source_attribution": {
            "function_level": "available",
            "source_line_level": "available",
            "function_count": 2,
            "source_location_count": 1,
        },
    }


def runtime_process_map(load_base: int, library_base: int) -> dict[str, Any]:
    return {
        "schema": "rvmt.runtime_process_map.v1",
        "status": "PASS",
        "sample_id": "fixture_pie_exact_elf",
        "rep": 0,
        "owners": {
            "target_child": {
                "role": "target_child",
                "pid": 4100,
                "tgid": 4100,
                "comm": "fixture_pie",
                "exe": "/tmp/rvmt_p0/fixture_pie",
                "maps": [
                    {"start": hx(load_base), "end": hx(load_base + 0x1000), "perms": "r-xp", "path": "/tmp/rvmt_p0/fixture_pie"},
                    {
                        "start": hx(library_base),
                        "end": hx(library_base + 0x2000),
                        "perms": "r-xp",
                        "path": "/lib/ld-linux-riscv64-lp64d.so.1",
                    },
                ],
            },
            "runner_parent": {
                "role": "runner_parent",
                "pid": 4099,
                "tgid": 4099,
                "comm": "rvmt_exp_runner",
                "exe": "/usr/bin/rvmt_exp_runner",
                "maps": [{"start": "0x0000000000010000", "end": "0x0000000000014000", "perms": "r-xp", "path": "/usr/bin/rvmt_exp_runner"}],
            },
            "kernel": {
                "role": "kernel",
                "pid": 0,
                "tgid": 0,
                "comm": "kernel",
                "exe": "",
                "maps": [{"start": "0xffffffff80000000", "end": "0xffffffffffffffff", "perms": "r-xp", "path": "linux_kernel"}],
            },
        },
        "provenance": {
            "source": "fixture_runtime_map",
            "board_native": False,
            "oracle": False,
        },
    }


def pie_events(load_base: int, library_base: int) -> list[dict[str, Any]]:
    return [
        {"evt": "MARKER", "value": "0xb0000001", "cycle": 1, "pc": hx(load_base + 0x100), "sequence_number": 0},
        {
            "evt": "SYSCALL_ENTRY",
            "cycle": 2,
            "pc": hx(load_base + 0x128),
            "instr": "0x00000073",
            "priv": "U",
            "syscall_id": "0x1",
            "sequence_number": 1,
        },
        {"evt": "RETIRE", "cycle": 3, "pc": hx(library_base + 0x40), "instr": "0x00000013", "priv": "U", "sequence_number": 2},
        {"evt": "TRAP", "cycle": 4, "pc": hx(load_base + 0x140), "instr": "0xffffffff", "cause": "0x2", "tval": "0xffffffff", "priv": "U", "sequence_number": 3},
        {"evt": "MARKER", "value": "0xe0000001", "cycle": 5, "pc": hx(load_base + 0x144), "sequence_number": 4},
    ]


def stripped_code_map(load_base: int) -> dict[str, Any]:
    return {
        "schema": "rvmt.code_map.v1",
        "sample_id": "fixture_stripped",
        "binary_role": "single_riscv_binary",
        "elf": "fixtures/stripped_board.elf",
        "sha256": "22" * 32,
        "elf_type": "EXEC",
        "load_base_assumption": "fixed_vaddr_exec",
        "elf_header": {"class": "ELF64", "type": "EXEC", "machine": 243, "entry": hx(load_base)},
        "load_ranges": [{"start": hx(load_base), "end": hx(load_base + 0x1000), "segment": "text", "perms": "R-X"}],
        "sections": [{"name": ".text", "start": hx(load_base), "end": hx(load_base + 0x1000)}],
        "symbols": [],
        "function_ranges": [],
        "syscall_sites": [{"pc": hx(load_base + 0x20), "symbol": None, "asm": "ecall"}],
        "trap_sites": [],
        "source_locations": [],
        "source_attribution": {
            "function_level": "unavailable",
            "source_line_level": "unavailable",
            "function_count": 0,
            "source_location_count": 0,
        },
    }


def analyze_fixture(
    *,
    trace_name: str,
    elf_name: str,
    code_map: dict[str, Any],
    events: list[dict[str, Any]],
    load_base: int | None,
    runtime_map: dict[str, Any] | None,
    exact_elf_sha256: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    shifted = apply_runtime_load_base(code_map, load_base)
    annotated, join_summary = annotate_events(events, shifted, runtime_map)
    annotated = enrich_function_annotations(annotated, shifted)
    summary = summary_from_analysis(
        trace=Path(trace_name),
        elf=Path(elf_name),
        code_map=shifted,
        annotated=annotated,
        join_summary=join_summary,
        load_base=load_base,
        runtime_process_map=Path("fixtures/runtime_process_map.json") if runtime_map is not None else None,
        exact_elf_sha256=exact_elf_sha256,
    )
    return annotated, summary


def package_summary() -> dict[str, Any]:
    pie_base = 0x0000005555554000
    lib_base = 0x0000007fff000000
    pie_map = base_dyn_code_map()
    runtime_map = runtime_process_map(pie_base, lib_base)
    pie_annotated, pie_summary = analyze_fixture(
        trace_name="fixtures/pie_exact_trace.jsonl",
        elf_name="fixtures/pie_exact_board.elf",
        code_map=pie_map,
        events=pie_events(pie_base, lib_base),
        load_base=pie_base,
        runtime_map=runtime_map,
        exact_elf_sha256="11" * 32,
    )
    lib_rows = [
        row
        for row in pie_annotated
        if isinstance(row.get("runtime_map_match"), dict)
        and str(row["runtime_map_match"].get("path", "")).startswith("/lib/")
    ]

    stripped_base = 0x0000000000010000
    stripped_events = [
        {"evt": "MARKER", "value": "0xb0000002", "cycle": 1, "pc": hx(stripped_base), "sequence_number": 0},
        {"evt": "SYSCALL_ENTRY", "cycle": 2, "pc": hx(stripped_base + 0x20), "instr": "0x00000073", "priv": "U", "syscall_id": "0x2", "sequence_number": 1},
        {"evt": "MARKER", "value": "0xe0000002", "cycle": 3, "pc": hx(stripped_base + 0x24), "sequence_number": 2},
    ]
    stripped_annotated, stripped_summary = analyze_fixture(
        trace_name="fixtures/stripped_trace.jsonl",
        elf_name="fixtures/stripped_board.elf",
        code_map=stripped_code_map(stripped_base),
        events=stripped_events,
        load_base=None,
        runtime_map=None,
        exact_elf_sha256="22" * 32,
    )

    fork_exec_fixture = {
        "parent_pid": 4099,
        "child_pid": 4100,
        "exec_path": "/tmp/rvmt_p0/fixture_pie",
        "runtime_process_map_status": runtime_map["status"],
        "child_process_target_attribution_proven": pie_summary.get("marker_scope", {}).get("status") == "PASS"
        and any(row.get("process_owner") == "target_child" for row in pie_annotated),
        "exec_path_source": "runtime-map",
        "oracle_used_for_ground_truth_only": True,
    }

    rows = {
        "pie_exact_elf_runtime_map": {
            "status": "PASS",
            "elf_type": pie_summary["elf_type"],
            "exact_elf_sha256_match": pie_summary["exact_elf_sha256_match"],
            "runtime_load_base": pie_summary["runtime_load_base"],
            "runtime_process_map_applied": pie_summary["runtime_process_map_applied"],
            "target_pc_events": pie_summary["target_pc_events"],
            "function_events": pie_summary["function_events"],
            "source_line_events": pie_summary["source_line_events"],
            "runtime_process_attribution_proven": any(
                row.get("attribution_confidence") == "marker_scoped_runtime_map_code_site" for row in pie_annotated
            ),
        },
        "dynamic_library_separation": {
            "status": "PASS",
            "dynamic_library_event_count": len(lib_rows),
            "dynamic_library_events_not_misattributed_to_target_elf": all(row.get("pc_owner") != "target_sample" for row in lib_rows),
            "dynamic_library_process_owner": sorted({str(row.get("process_owner")) for row in lib_rows}),
        },
        "fork_exec_runtime_map": fork_exec_fixture,
        "stripped_elf_degrade": {
            "status": "PASS",
            "stripped_elf": stripped_summary["stripped_elf"],
            "target_pc_events": stripped_summary["target_pc_events"],
            "function_events": stripped_summary["function_events"],
            "source_line_events": stripped_summary["source_line_events"],
            "degrades_to_section_or_offset_only": stripped_summary["claim_boundary"][
                "stripped_elf_degrades_to_section_or_offset_only"
            ],
            "annotated_target_rows": [
                {
                    "pc": row.get("pc"),
                    "pc_owner": row.get("pc_owner"),
                    "section": row.get("section"),
                    "analysis_function": row.get("analysis_function"),
                }
                for row in stripped_annotated
                if row.get("pc_owner") == "target_sample"
            ],
        },
    }
    status = PASS_STATUS
    if not rows["pie_exact_elf_runtime_map"]["exact_elf_sha256_match"]:
        status = "FAIL"
    if not rows["dynamic_library_separation"]["dynamic_library_events_not_misattributed_to_target_elf"]:
        status = "FAIL"
    if not rows["fork_exec_runtime_map"]["child_process_target_attribution_proven"]:
        status = "FAIL"
    if not rows["stripped_elf_degrade"]["degrades_to_section_or_offset_only"]:
        status = "FAIL"

    return {
        "schema": SCHEMA,
        "status": status,
        "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
        "fixture_scope": "local code-attribution semantics; no new board/Vivado execution",
        "fixtures": rows,
        "sidecar_policy": {
            "sidecar_is_not_board_native_dwarf": True,
            "board_native_dwarf_claimed": False,
            "source_line_sidecar_claim": "offline exact-ELF/code-map fixture only",
            "board_native_dwarf_requires": [
                "exact board ELF SHA256 match",
                "DWARF/debug_line retained in the same ELF executed on the board",
                "runtime process map or equivalent fork/exec provenance for ownership",
            ],
        },
        "provenance_policy": {
            "exact_elf": "required for board-native code attribution claims",
            "pie_aslr_load_bias": "required for ET_DYN/PIE runtime PCs",
            "dynamic_libraries": "separated by runtime maps and never attributed to the target ELF static range",
            "fork_exec": "requires runtime map/process ownership evidence",
            "stripped_elf": "section/load-range attribution only; no source-line claim",
            "oracle": "strace/QEMU may label expected behavior only, not hardware code recovery",
        },
        "claim_boundary": {
            "local_fixture_only": True,
            "new_genesys2_board_run_performed": False,
            "board_native_dwarf_claimed": False,
            "sidecar_is_board_native_dwarf": False,
            "real_malware_validation_claimed": False,
        },
        "validation_commands": [
            "uv run python tools/package_genesys2_local_code_analysis_fixtures.py --root .",
            "uv run python tools/check_genesys2_local_code_analysis_fixtures.py --root .",
            "uv run python tools/analyze_single_riscv_binary_trace.py --self-test",
        ],
    }


def self_test() -> int:
    summary = package_summary()
    if summary.get("status") != PASS_STATUS:
        print("[FAIL] local code-analysis fixture summary did not pass")
        return 1
    fixtures = summary.get("fixtures", {})
    if not fixtures.get("dynamic_library_separation", {}).get("dynamic_library_events_not_misattributed_to_target_elf"):
        print("[FAIL] dynamic-library separation fixture failed")
        return 1
    if not summary.get("sidecar_policy", {}).get("sidecar_is_not_board_native_dwarf"):
        print("[FAIL] sidecar policy fixture failed")
        return 1
    with tempfile.TemporaryDirectory(prefix="rvmt-local-code-analysis-fixtures-") as tmp:
        out = Path(tmp) / "summary.json"
        write_json(out, summary)
        loaded = json.loads(out.read_text(encoding="utf-8"))
        if loaded.get("schema") != SCHEMA:
            print("[FAIL] local code-analysis fixture JSON roundtrip failed")
            return 1
    print("[PASS] Genesys2 local code-analysis fixture packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package local code-analysis fixture evidence for Genesys2/CVA6.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    out = args.out if args.out.is_absolute() else root / args.out
    summary = package_summary()
    write_json(out, summary)
    print(f"[{summary['status']}] wrote local code-analysis fixture summary to {out}")
    return 0 if summary["status"] == PASS_STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
