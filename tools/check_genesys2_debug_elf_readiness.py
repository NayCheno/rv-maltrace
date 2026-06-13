from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from ccfa_gate_common import ALL_CCFA_SAMPLES, P0_SAMPLES, SAFE_SURROGATE_SAMPLES
import package_genesys2_debug_elf_readiness as packager


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/debug_elf_readiness_summary.json")
EXPECTED_SCHEMA = "rvmt.genesys2.debug_elf_readiness.v1"


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def repo_path(root: Path, value: Any) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else root / path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def require_file_hash(errors: list[str], root: Path, path_value: Any, expected_sha: Any, context: str) -> Path | None:
    if not path_value:
        errors.append(f"{context}: path missing")
        return None
    path = repo_path(root, path_value)
    if not path.is_file():
        errors.append(f"{context}: file missing: {path_value}")
        return None
    actual = sha256_file(path)
    require(errors, expected_sha == actual, f"{context}: sha256 mismatch")
    return path


def expected_source_map() -> dict[str, Path]:
    return {
        **{sample_id: packager.P0_SOURCE_PATHS[sample_id] for sample_id in P0_SAMPLES},
        **{sample_id: packager.SAFE_SOURCE_PATHS[sample_id] for sample_id in SAFE_SURROGATE_SAMPLES},
    }


def source_location_matches(location: dict[str, Any], source: Path) -> bool:
    file_value = str(location.get("file") or "").replace("\\", "/")
    return file_value.endswith(source.as_posix()) and int(location.get("line") or 0) > 0


def check_sample(errors: list[str], root: Path, row: dict[str, Any], expected_source: Path) -> None:
    sample_id = str(row.get("id") or "")
    require(errors, row.get("status") == "PASS", f"{sample_id}: status must be PASS")
    expected_class = "p0_safe_synthetic" if sample_id in P0_SAMPLES else "malware_like_synthetic_syscall_only"
    require(errors, row.get("sample_class") == expected_class, f"{sample_id}: sample_class mismatch")
    require(errors, row.get("real_malware") is False, f"{sample_id}: real_malware must be false")
    require(errors, row.get("board_capture_required") is True, f"{sample_id}: board capture requirement missing")
    require(errors, row.get("accepted_as_board_evidence") is False, f"{sample_id}: must not be accepted as board evidence")
    require(errors, row.get("source_path") == expected_source.as_posix(), f"{sample_id}: source path mismatch")

    source_path = require_file_hash(errors, root, row.get("source_path"), row.get("source_sha256"), f"{sample_id}.source")
    elf_path = require_file_hash(errors, root, row.get("debug_elf_path"), row.get("debug_elf_sha256"), f"{sample_id}.debug_elf")
    readelf_path = require_file_hash(errors, root, row.get("readelf_sections_path"), row.get("readelf_sections_sha256"), f"{sample_id}.readelf_sections")
    nm_path = require_file_hash(errors, root, row.get("nm_path"), row.get("nm_sha256"), f"{sample_id}.nm")
    code_map_path = require_file_hash(errors, root, row.get("code_map_path"), row.get("code_map_sha256"), f"{sample_id}.code_map")
    del source_path, nm_path

    debug_sections = {str(item) for item in as_list(row.get("debug_section_names"))}
    require(errors, row.get("debug_sections_present") is True, f"{sample_id}: debug_sections_present must be true")
    require(errors, ".debug_line" in debug_sections, f"{sample_id}: .debug_line missing")
    require(errors, ".debug_info" in debug_sections, f"{sample_id}: .debug_info missing")
    if readelf_path is not None:
        text_sections = set(packager.read_debug_sections(readelf_path))
        require(errors, debug_sections == text_sections, f"{sample_id}: debug section list must match readelf transcript")

    require(errors, row.get("source_line_available") is True, f"{sample_id}: source line availability missing")
    require(errors, int(row.get("source_location_count") or 0) > 0, f"{sample_id}: source_location_count must be positive")
    require(errors, int(row.get("sample_source_location_count") or 0) > 0, f"{sample_id}: sample source location count must be positive")
    require(errors, str(row.get("runtime_path") or "") == f"/tmp/rvmt_debug/{sample_id}", f"{sample_id}: runtime path mismatch")

    if code_map_path is not None:
        code_map = load_json(code_map_path)
        require(errors, code_map.get("schema") == "rvmt.code_map.v1", f"{sample_id}: code map schema mismatch")
        require(errors, code_map.get("sample_id") == sample_id, f"{sample_id}: code map sample_id mismatch")
        require(errors, str(code_map.get("source") or "") == expected_source.as_posix(), f"{sample_id}: code map source mismatch")
        source_attr = as_dict(code_map.get("source_attribution"))
        require(errors, source_attr.get("source_line_level") == "available", f"{sample_id}: code map source-line level must be available")
        require(errors, int(source_attr.get("source_location_count") or 0) > 0, f"{sample_id}: code map source locations must be positive")
        locations = [loc for loc in as_list(code_map.get("source_locations")) if isinstance(loc, dict)]
        require(errors, any(source_location_matches(loc, expected_source) for loc in locations), f"{sample_id}: code map must include sample source file:line")
        if elf_path is not None:
            require(errors, code_map.get("sha256") == sha256_file(elf_path), f"{sample_id}: code map ELF sha256 mismatch")


def check_summary(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == EXPECTED_SCHEMA, "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    require(
        errors,
        data.get("evidence_scope") == "debug_no_pie_elf_and_code_map_readiness_for_future_board_source_line_rerun",
        "evidence_scope mismatch",
    )
    require(errors, data.get("sample_count") == len(ALL_CCFA_SAMPLES), "sample_count mismatch")
    require(errors, data.get("p0_sample_count") == len(P0_SAMPLES), "p0 sample count mismatch")
    require(errors, data.get("safe_surrogate_sample_count") == len(SAFE_SURROGATE_SAMPLES), "safe sample count mismatch")

    toolchain = as_dict(data.get("toolchain"))
    require(errors, toolchain.get("docker_service") == "linux-behavior", "toolchain docker service mismatch")
    require(errors, "riscv64-linux-gnu-gcc" in str(toolchain.get("compiler") or ""), "compiler version missing")
    require(errors, "addr2line" in str(toolchain.get("addr2line") or "").lower(), "addr2line version missing")
    require(errors, "readelf" in str(toolchain.get("readelf") or "").lower(), "readelf version missing")

    rows = {str(row.get("id")): row for row in as_list(data.get("samples")) if isinstance(row, dict) and row.get("id")}
    require(errors, list(rows) == ALL_CCFA_SAMPLES, "sample rows must match the CCFA sample order exactly")
    sources = expected_source_map()
    for sample_id in ALL_CCFA_SAMPLES:
        row = rows.get(sample_id)
        if row is None:
            continue
        check_sample(errors, root, row, sources[sample_id])

    contribution = as_dict(data.get("future_external_artifact_contribution"))
    require(errors, contribution.get("debug_elf_manifest") == "prepared", "debug ELF manifest contribution missing")
    require(errors, contribution.get("readelf_debug_line_transcript") == "prepared", "readelf transcript contribution missing")
    require(errors, contribution.get("board_capture_manifest") == "not_prepared_external_board_rerun_required", "board capture must remain external")
    require(errors, contribution.get("captured_elf_sha256_exact_match") == "not_claimed_until_board_rerun", "captured ELF exact match must not be claimed")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("debug_no_pie_elf_readiness_claimed") is True, "debug readiness claim flag missing")
    require(errors, boundary.get("board_native_source_line_attribution_claimed") is False, "board-native source-line attribution must not be claimed")
    require(errors, boundary.get("captured_elf_sha256_exact_match") is False, "captured ELF exact match must not be claimed")
    require(errors, boundary.get("current_board_trace_source_line_available") is False, "current board trace source lines must not be claimed")
    require(errors, boundary.get("board_rerun_required_for_board_native_source_lines") is True, "board rerun requirement missing")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")

    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "not board-native source-line attribution" in non_claims, "board-native non-claim missing")
    require(errors, "not claimed to match current captured board elf hashes" in non_claims, "captured ELF hash non-claim missing")
    require(errors, "does not add real-malware validation" in non_claims, "real-malware non-claim missing")
    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "tools/package_genesys2_debug_elf_readiness.py" in commands, "packager validation command missing")
    require(errors, "tools/check_genesys2_debug_elf_readiness.py --root ." in commands, "checker validation command missing")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / "results/evaluation/genesys2-cva6/current"
        current.mkdir(parents=True, exist_ok=True)
        build_root = Path("build/debug_elf_readiness_fixture")
        packager.write_fixture_outputs(root, build_root)
        summary = packager.package_summary(root, current, build_root, None)
        errors = check_summary(summary, root)
        if errors:
            print("[FAIL] debug ELF readiness good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        summary["claim_boundary"]["board_native_source_line_attribution_claimed"] = True
        errors = check_summary(summary, root)
        if not any("board-native source-line attribution" in error for error in errors):
            print("[FAIL] debug ELF readiness overclaim fixture passed", file=sys.stderr)
            return 1
        summary = packager.package_summary(root, current, build_root, None)
        summary["samples"][0]["debug_elf_sha256"] = "0" * 64
        errors = check_summary(summary, root)
        if not any("sha256 mismatch" in error for error in errors):
            print("[FAIL] debug ELF readiness sha mismatch fixture passed", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 debug ELF readiness checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check debug/no-PIE ELF readiness for future Genesys2/CVA6 board source-line rerun.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] missing debug ELF readiness summary: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root)
    except Exception as exc:
        print(f"[FAIL] debug ELF readiness checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] debug ELF readiness summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] debug ELF readiness summary accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
