from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_dict,
    as_list,
    load_json,
    repo_path,
    require,
    write_json,
)


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/source_line_toolchain_probe.json")
REQUIRED_BOARD_IDS = {
    "phase4_uart_pass",
    "phase4_onboard_uart_pass",
    "p0_marker_hello_write",
    "safe_surrogate_file_scan",
}


def require_file(errors: list[str], root: Path, value: Any, context: str) -> None:
    if not value:
        errors.append(f"{context}: path missing")
        return
    if not repo_path(root, value).is_file():
        errors.append(f"{context}: file missing: {value}")


def check_summary(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == "rvmt.genesys2.source_line_toolchain_probe.v1", "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")

    toolchain = as_dict(data.get("toolchain"))
    require(errors, toolchain.get("docker_service") == "linux-behavior", "toolchain docker service mismatch")
    require(errors, "riscv64-linux-gnu-gcc" in str(toolchain.get("compiler") or ""), "compiler version missing")
    require(errors, "qemu-riscv64" in str(toolchain.get("qemu") or ""), "qemu version missing")
    require(errors, "strace" in str(toolchain.get("strace") or "").lower(), "strace version missing")
    require(errors, "addr2line" in str(toolchain.get("addr2line") or "").lower(), "addr2line version missing")
    require(errors, "readelf" in str(toolchain.get("readelf") or "").lower(), "readelf version missing")

    probe = as_dict(data.get("probe"))
    require_file(errors, root, probe.get("source_path"), "probe.source_path")
    require_file(errors, root, probe.get("elf_path"), "probe.elf_path")
    require_file(errors, root, probe.get("code_map_path"), "probe.code_map_path")
    require_file(errors, root, probe.get("readelf_sections"), "probe.readelf_sections")
    require(errors, probe.get("debug_sections_present") is True, "probe debug sections must be present")
    debug_sections = {str(item) for item in as_list(probe.get("debug_section_names"))}
    require(errors, ".debug_line" in debug_sections, "probe must include .debug_line")
    require(errors, ".debug_info" in debug_sections, "probe must include .debug_info")
    require(errors, probe.get("addr2line_source_line_available") is True, "addr2line source-line mapping must be available")
    require(errors, int(probe.get("source_location_count") or 0) > 0, "source_location_count must be positive")
    locations = as_list(probe.get("source_locations"))
    require(errors, bool(locations), "source_locations must be present")
    require(
        errors,
        any(str(row.get("file") or "").replace("\\", "/").endswith("source_line_probe.c") and int(row.get("line") or 0) > 0 for row in locations if isinstance(row, dict)),
        "source_locations must include source_line_probe.c with a positive line",
    )

    board_rows = {str(row.get("id")): row for row in as_list(data.get("current_board_elfs")) if isinstance(row, dict) and row.get("id")}
    missing = sorted(REQUIRED_BOARD_IDS - set(board_rows))
    require(errors, not missing, f"missing board ELF rows: {', '.join(missing)}")
    for board_id, row in board_rows.items():
        require(errors, row.get("exists") is True, f"{board_id}: board ELF must exist")
        require_file(errors, root, row.get("path"), f"{board_id}.path")
        require_file(errors, root, row.get("readelf_sections"), f"{board_id}.readelf_sections")
        require(errors, row.get("debug_sections_present") is False, f"{board_id}: current board ELF must not be reported as DWARF-enabled")
        require(errors, not as_list(row.get("debug_section_names")), f"{board_id}: debug section list must be empty")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("toolchain_source_line_probe_passed") is True, "toolchain probe pass flag missing")
    require(errors, boundary.get("debug_counterpart_source_line_available") is True, "debug counterpart source-line flag missing")
    require(errors, boundary.get("current_board_elf_dwarf_available") is False, "current board ELF DWARF must not be claimed")
    require(errors, boundary.get("current_board_trace_source_line_available") is False, "current board trace source-line must not be claimed")
    require(errors, boundary.get("board_rerun_required_for_board_native_source_lines") is True, "board rerun boundary missing")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")

    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "not current board-trace dwarf attribution" in non_claims, "non_claims must reject current board-trace DWARF attribution")
    require(errors, "remain function-level" in non_claims, "non_claims must preserve function-level current board boundary")
    require(errors, "does not add real-malware validation" in non_claims, "non_claims must reject real-malware validation")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / "results/evaluation/genesys2-cva6/current"
        build = root / "build/source_line_toolchain_probe"
        build.mkdir(parents=True)
        for name in ("source_line_probe.c", "source_line_probe.riscv64", "source_line_probe.code_map.json", "probe.readelf_sections.txt"):
            (build / name).write_text("fixture\n", encoding="utf-8")
        board_rows: list[dict[str, Any]] = []
        for board_id in REQUIRED_BOARD_IDS:
            board = root / "board" / f"{board_id}.elf"
            board.parent.mkdir(parents=True, exist_ok=True)
            board.write_text("elf\n", encoding="utf-8")
            sections = build / f"board_{board_id}.readelf_sections.txt"
            sections.write_text("[ 1] .text PROGBITS\n", encoding="utf-8")
            board_rows.append(
                {
                    "id": board_id,
                    "path": board.relative_to(root).as_posix(),
                    "exists": True,
                    "readelf_sections": sections.relative_to(root).as_posix(),
                    "debug_sections_present": False,
                    "debug_section_names": [],
                }
            )
        summary = {
            "schema": "rvmt.genesys2.source_line_toolchain_probe.v1",
            "status": "PASS",
            "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
            "toolchain": {
                "docker_service": "linux-behavior",
                "compiler": "riscv64-linux-gnu-gcc fixture",
                "qemu": "qemu-riscv64 fixture",
                "strace": "strace fixture",
                "addr2line": "GNU addr2line fixture",
                "readelf": "GNU readelf fixture",
            },
            "probe": {
                "source_path": "build/source_line_toolchain_probe/source_line_probe.c",
                "elf_path": "build/source_line_toolchain_probe/source_line_probe.riscv64",
                "code_map_path": "build/source_line_toolchain_probe/source_line_probe.code_map.json",
                "readelf_sections": "build/source_line_toolchain_probe/probe.readelf_sections.txt",
                "debug_sections_present": True,
                "debug_section_names": [".debug_info", ".debug_line"],
                "addr2line_source_line_available": True,
                "source_location_count": 1,
                "source_locations": [{"file": "build/source_line_toolchain_probe/source_line_probe.c", "line": 10}],
            },
            "current_board_elfs": board_rows,
            "claim_boundary": {
                "toolchain_source_line_probe_passed": True,
                "debug_counterpart_source_line_available": True,
                "current_board_elf_dwarf_available": False,
                "current_board_trace_source_line_available": False,
                "board_rerun_required_for_board_native_source_lines": True,
                "real_malware_validation_claimed": False,
            },
            "non_claims": [
                "This proves the RISC-V Linux debug/no-PIE source-line toolchain path, not current board-trace DWARF attribution.",
                "Current generated board ELFs remain function-level for board trace attribution.",
                "This probe does not add real-malware validation.",
            ],
        }
        write_json(current / "source_line_toolchain_probe.json", summary)
        errors = check_summary(load_json(current / "source_line_toolchain_probe.json"), root)
        if errors:
            print("[FAIL] source-line toolchain probe good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        summary["claim_boundary"]["current_board_trace_source_line_available"] = True
        write_json(current / "bad.json", summary)
        errors = check_summary(load_json(current / "bad.json"), root)
        if not errors:
            print("[FAIL] source-line toolchain probe bad fixture passed", file=sys.stderr)
            return 1
    print("[PASS] source-line toolchain probe checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the Genesys2/CVA6 source-line toolchain probe.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] missing source-line toolchain probe: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root)
    except Exception as exc:
        print(f"[FAIL] source-line toolchain probe checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] source-line toolchain probe is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] source-line toolchain probe accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
