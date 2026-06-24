from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from package_genesys2_local_code_analysis_fixtures import DEFAULT_OUT, PASS_STATUS, SCHEMA, package_summary, write_json


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def check_summary(data: dict[str, Any], *, compare_generated: bool = True) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == SCHEMA, f"schema must be {SCHEMA}")
    require(errors, data.get("status") == PASS_STATUS, f"status must be {PASS_STATUS}")
    require(
        errors,
        data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current",
        "canonical evaluation root mismatch",
    )
    fixtures = as_dict(data.get("fixtures"))
    pie = as_dict(fixtures.get("pie_exact_elf_runtime_map"))
    require(errors, pie.get("status") == "PASS", "PIE exact-ELF fixture must pass")
    require(errors, pie.get("elf_type") == "DYN", "PIE fixture must use DYN/PIE ELF type")
    require(errors, pie.get("exact_elf_sha256_match") is True, "exact ELF SHA256 must match")
    require(errors, isinstance(pie.get("runtime_load_base"), str) and pie.get("runtime_load_base", "").startswith("0x"), "runtime load base missing")
    require(errors, pie.get("runtime_process_map_applied") is True, "runtime process map must be applied")
    require(errors, int(pie.get("target_pc_events") or 0) > 0, "PIE fixture must have target PC events")
    require(errors, int(pie.get("function_events") or 0) > 0, "PIE fixture must have function attribution")
    require(errors, int(pie.get("source_line_events") or 0) > 0, "PIE fixture must have source-line attribution")
    require(errors, pie.get("runtime_process_attribution_proven") is True, "PIE fixture must prove runtime process attribution")

    dylib = as_dict(fixtures.get("dynamic_library_separation"))
    require(errors, dylib.get("status") == "PASS", "dynamic-library fixture must pass")
    require(errors, int(dylib.get("dynamic_library_event_count") or 0) > 0, "dynamic-library fixture must include library events")
    require(
        errors,
        dylib.get("dynamic_library_events_not_misattributed_to_target_elf") is True,
        "dynamic-library events must not be attributed to the target ELF static range",
    )
    require(errors, "target_child" in {str(item) for item in as_list(dylib.get("dynamic_library_process_owner"))}, "dynamic-library runtime owner must remain process-scoped")

    fork_exec = as_dict(fixtures.get("fork_exec_runtime_map"))
    require(errors, fork_exec.get("child_process_target_attribution_proven") is True, "fork/exec child attribution must be proven")
    require(errors, isinstance(fork_exec.get("child_pid"), int) and fork_exec.get("child_pid") != fork_exec.get("parent_pid"), "fork/exec fixture must separate parent and child PIDs")
    require(errors, str(fork_exec.get("exec_path") or "").startswith("/tmp/rvmt_p0/"), "fork/exec exec path mismatch")
    require(errors, fork_exec.get("exec_path_source") == "runtime-map", "fork/exec path source must be runtime-map")
    require(errors, fork_exec.get("oracle_used_for_ground_truth_only") is True, "fork/exec oracle boundary missing")

    stripped = as_dict(fixtures.get("stripped_elf_degrade"))
    require(errors, stripped.get("status") == "PASS", "stripped fixture must pass")
    require(errors, stripped.get("stripped_elf") is True, "stripped fixture must be marked stripped")
    require(errors, int(stripped.get("target_pc_events") or 0) > 0, "stripped fixture must still match load ranges")
    require(errors, int(stripped.get("function_events") if stripped.get("function_events") is not None else -1) == 0, "stripped fixture must not claim function attribution")
    require(errors, int(stripped.get("source_line_events") if stripped.get("source_line_events") is not None else -1) == 0, "stripped fixture must not claim source-line attribution")
    require(errors, stripped.get("degrades_to_section_or_offset_only") is True, "stripped fixture must degrade to section/offset only")
    for index, row in enumerate(as_list(stripped.get("annotated_target_rows"))):
        item = as_dict(row)
        require(errors, item.get("pc_owner") == "target_sample", f"stripped row {index} must remain load-range target_sample")
        require(errors, item.get("section") == ".text", f"stripped row {index} must retain section attribution")
        require(errors, item.get("analysis_function") is None, f"stripped row {index} must not invent function attribution")

    sidecar = as_dict(data.get("sidecar_policy"))
    require(errors, sidecar.get("sidecar_is_not_board_native_dwarf") is True, "sidecar must not be board-native DWARF")
    require(errors, sidecar.get("board_native_dwarf_claimed") is False, "must not claim board-native DWARF")
    require(errors, "offline" in str(sidecar.get("source_line_sidecar_claim") or ""), "sidecar claim must be offline-scoped")
    requires = " ".join(str(item).lower() for item in as_list(sidecar.get("board_native_dwarf_requires")))
    require(errors, "exact board elf sha256" in requires, "board-native DWARF requirements must include exact board ELF hash")
    require(errors, "dwarf" in requires and "runtime process map" in requires, "board-native DWARF requirements incomplete")

    provenance = as_dict(data.get("provenance_policy"))
    for key in ("exact_elf", "pie_aslr_load_bias", "dynamic_libraries", "fork_exec", "stripped_elf", "oracle"):
        require(errors, isinstance(provenance.get(key), str) and bool(provenance.get(key)), f"provenance policy missing {key}")
    require(errors, "not hardware code recovery" in str(provenance.get("oracle")), "oracle policy must reject hardware recovery substitution")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("local_fixture_only") is True, "local fixture boundary missing")
    require(errors, boundary.get("new_genesys2_board_run_performed") is False, "must not claim a new board run")
    require(errors, boundary.get("board_native_dwarf_claimed") is False, "must not claim board-native DWARF")
    require(errors, boundary.get("sidecar_is_board_native_dwarf") is False, "must not label sidecar as board-native DWARF")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "must not claim real malware validation")

    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "package_genesys2_local_code_analysis_fixtures.py --root ." in commands, "validation commands missing packager")
    require(errors, "check_genesys2_local_code_analysis_fixtures.py --root ." in commands, "validation commands missing checker")
    require(errors, "analyze_single_riscv_binary_trace.py --self-test" in commands, "validation commands missing analyzer self-test")

    if compare_generated:
        generated = package_summary()
        require(errors, data == generated, "summary does not match regenerated local fixture package")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-local-code-analysis-check-") as tmp:
        path = Path(tmp) / "summary.json"
        summary = package_summary()
        write_json(path, summary)
        errors = check_summary(load_json(path))
        if errors:
            print("[FAIL] local code-analysis checker rejected good fixture", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        bad = package_summary()
        bad["sidecar_policy"]["board_native_dwarf_claimed"] = True
        errors = check_summary(bad, compare_generated=False)
        if not any("board-native DWARF" in error for error in errors):
            print("[FAIL] local code-analysis checker missed sidecar overclaim", file=sys.stderr)
            return 1
        bad = package_summary()
        bad["fixtures"]["dynamic_library_separation"]["dynamic_library_events_not_misattributed_to_target_elf"] = False
        errors = check_summary(bad, compare_generated=False)
        if not any("dynamic-library" in error for error in errors):
            print("[FAIL] local code-analysis checker missed dynamic-library misattribution", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 local code-analysis fixture checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check local code-analysis fixture evidence for Genesys2/CVA6.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = args.summary if args.summary.is_absolute() else root / args.summary
    if not summary.is_file():
        print(f"[FAIL] missing local code-analysis fixture summary: {summary}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(summary))
    except Exception as exc:
        print(f"[FAIL] local code-analysis fixture checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] local code-analysis fixture summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] local code-analysis fixture summary accepted: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
