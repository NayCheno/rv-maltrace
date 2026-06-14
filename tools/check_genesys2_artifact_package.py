from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/artifact_package_manifest.json")
REQUIRED_INCLUDED_PATHS = {
    "README.md",
    "pyproject.toml",
    "uv.lock",
    "tools/check_suites.json",
    "tools/run_check_suite.py",
    "tools/reproduce_genesys2_current.py",
    "tools/view_trace_terminal.py",
    "tools/analyze_single_riscv_binary_trace.py",
    "src/rv_maltrace/cli.py",
    "tools/check_baseline_pass_criteria.py",
    "tools/check_board_trace_programs.py",
    "tools/check_board_trace_evidence.py",
    "tools/gen_rv_trace_fuzz.py",
    "tools/check_fuzz_trace.py",
    "tools/check_fuzz_trace_plan.py",
    "tools/check_risk_log_current.py",
    "tools/check_evaluation_plan.py",
    "tools/package_genesys2_review_closure_audit.py",
    "tools/check_genesys2_review_closure_audit.py",
    "tools/package_genesys2_artifact_package.py",
    "tools/check_genesys2_artifact_package.py",
    "tools/package_genesys2_reproducibility_manifest.py",
    "tools/check_genesys2_reproducibility_manifest.py",
    "tools/package_genesys2_statistical_robustness.py",
    "tools/check_genesys2_statistical_robustness.py",
    "tools/package_genesys2_streaming_dma_target.py",
    "tools/check_genesys2_streaming_dma_target.py",
    "tools/package_genesys2_streaming_dma_readiness.py",
    "tools/check_genesys2_streaming_dma_readiness.py",
    "tools/package_genesys2_pointer_string_readiness.py",
    "tools/check_genesys2_pointer_string_readiness.py",
    "tools/package_genesys2_debug_elf_readiness.py",
    "tools/check_genesys2_debug_elf_readiness.py",
    "tools/package_genesys2_board_benign_readiness.py",
    "tools/check_genesys2_board_benign_readiness.py",
    "tools/package_ccfa_case_study_manifest.py",
    "tools/check_ccfa_case_study_manifest.py",
    "tools/package_genesys2_external_closure_readiness.py",
    "tools/check_genesys2_external_closure_readiness.py",
    "tools/package_genesys2_external_closure_intake.py",
    "tools/check_genesys2_external_closure_intake.py",
    "tools/package_genesys2_external_closure_plan.py",
    "tools/check_genesys2_external_closure_plan.py",
    "tools/package_genesys2_external_closure_preflight.py",
    "tools/check_genesys2_external_closure_preflight.py",
    "tools/package_genesys2_external_operator_packet.py",
    "tools/check_genesys2_external_operator_packet.py",
    "tools/prepare_genesys2_external_summary.py",
    "tools/check_ccfa_current_quality.py",
    "tools/check_genesys2_bitstream_artifacts.py",
    "docs/03-platform-architecture/genesys2/baseline_pass_criteria.md",
    "docs/03-platform-architecture/genesys2/board_bringup.md",
    "docs/03-platform-architecture/genesys2/board_trace_validation.md",
    "board/trace_validation/manifest.json",
    "board/trace_validation/expected/hello_write.expected.json",
    "board/trace_validation/expected/file_open_read_write.expected.json",
    "board/trace_validation/expected/fork_exec.expected.json",
    "board/trace_validation/expected/illegal_instruction.expected.json",
    "board/trace_validation/programs/hello_write.c",
    "board/trace_validation/programs/file_open_read_write.c",
    "board/trace_validation/programs/fork_exec.c",
    "board/trace_validation/programs/illegal_instruction.c",
    "docs/06-validation-gates/fuzz_trace_validation.md",
    "sim/golden/fuzz_invariants.json",
    "sim/golden/fuzz_trace_smoke.trace.jsonl",
    "sim/golden/fuzz_cf.trace.jsonl",
    "sim/golden/fuzz_trap.trace.jsonl",
    "sim/golden/fuzz_syscall.trace.jsonl",
    "sim/golden/fuzz_context.trace.jsonl",
    "sim/golden/fuzz_overflow.trace.jsonl",
    "docs/10-process/risk_log.md",
    "docs/10-process/check_suites.md",
    "docs/07-evaluation-evidence/evaluation_plan.md",
    "results/evaluation/genesys2-cva6/current/reproducibility_manifest.json",
    "results/evaluation/genesys2-cva6/current/streaming_dma_target_summary.json",
    "results/evaluation/genesys2-cva6/current/streaming_dma_readiness_summary.json",
    "results/evaluation/genesys2-cva6/current/pointer_string_readiness_summary.json",
    "results/evaluation/genesys2-cva6/current/debug_elf_readiness_summary.json",
    "results/evaluation/genesys2-cva6/current/board_benign_readiness_summary.json",
    "results/evaluation/genesys2-cva6/current/external_closure_templates/board_native_source_lines_summary.template.json",
    "results/evaluation/genesys2-cva6/current/external_closure_templates/hardware_pointer_strings_summary.template.json",
    "results/evaluation/genesys2-cva6/current/external_closure_templates/streaming_dma_throughput_summary.template.json",
    "results/evaluation/genesys2-cva6/current/external_closure_templates/board_benign_control_summary.template.json",
    "results/evaluation/genesys2-cva6/current/external_operator_packet.json",
    "docs/07-evaluation-evidence/reports/ccfa_external_operator_packet.md",
    "docs/07-evaluation-evidence/reports/ccfa_readiness_matrix.md",
    "docs/07-evaluation-evidence/reports/ccfa_next_closure_plan.md",
}
REQUIRED_RAW_ROOT_IDS = {
    "p0_bram_repetitions",
    "safe_surrogate_bram_repetitions",
    "pointer_snapshot_bram",
    "p0_continuous_trace",
    "safe_surrogate_runtime_map",
}


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


def git_publishable(root: Path, path_value: str) -> bool | None:
    if not (root / ".git").exists():
        return None
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", path_value],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if tracked.returncode == 0:
        return True
    ignored = subprocess.run(
        ["git", "check-ignore", "-q", "--", path_value],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if ignored.returncode == 0:
        return False
    if ignored.returncode == 1:
        return True
    return None


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def row_map(rows: list[Any], key: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get(key), str) and row.get(key):
            result[str(row[key])] = row
    return result


def check_summary(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == "rvmt.genesys2.artifact_package.v1", "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("package_kind") == "lightweight-current-evidence-manifest", "package_kind mismatch")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    generated_from = data.get("generated_from")
    require(errors, generated_from == "results/evaluation/genesys2-cva6/current/reproducibility_manifest.json", "generated_from must be current reproducibility manifest")
    if generated_from:
        repro = repo_path(root, generated_from)
        require(errors, repro.is_file(), f"generated_from missing: {generated_from}")
        if repro.is_file():
            try:
                repro_data = load_json(repro)
            except Exception as exc:
                errors.append(f"generated_from invalid JSON: {exc}")
            else:
                require(errors, repro_data.get("schema") == "rvmt.genesys2.reproducibility_manifest.v1", "generated_from schema mismatch")
                require(errors, repro_data.get("status") == "PASS", "generated_from status must be PASS")

    fresh = as_dict(data.get("fresh_clone_reproduction"))
    require(errors, fresh.get("script") == "tools/reproduce_genesys2_current.py", "fresh clone script mismatch")
    require(errors, fresh.get("requires_board_or_vivado") is False, "fresh clone checks must not require board/Vivado")
    require(errors, fresh.get("requires_network") is False, "fresh clone checks must not require network")
    quick = str(fresh.get("quick_command") or "")
    local = str(fresh.get("local_command") or "")
    full = str(fresh.get("full_command") or "")
    dry = str(fresh.get("dry_run_command") or "")
    rvmt_quick = str(fresh.get("rvmt_quick_command") or "")
    rvmt_local = str(fresh.get("rvmt_local_command") or "")
    rvmt_full = str(fresh.get("rvmt_full_command") or "")
    require(errors, "tools/reproduce_genesys2_current.py --quick" in quick, "quick reproduction command missing")
    require(errors, "tools/reproduce_genesys2_current.py --local" in local, "local reproduction command missing")
    require(errors, "tools/reproduce_genesys2_current.py --full" in full, "full reproduction command missing")
    require(errors, "tools/reproduce_genesys2_current.py --full --dry-run" in dry, "dry-run reproduction command missing")
    require(errors, "rvmt repro:quick" in rvmt_quick, "rvmt quick reproduction command missing")
    require(errors, "rvmt repro:local" in rvmt_local, "rvmt local reproduction command missing")
    require(errors, "rvmt repro:full" in rvmt_full, "rvmt full reproduction command missing")

    included = row_map(as_list(data.get("included_files")), "path")
    missing_paths = sorted(REQUIRED_INCLUDED_PATHS - set(included))
    require(errors, not missing_paths, f"missing included files: {', '.join(missing_paths)}")
    for path_value, row in included.items():
        path = repo_path(root, path_value)
        require(errors, row.get("exists") is True, f"{path_value}: included file must exist")
        require(errors, path.is_file(), f"{path_value}: file missing")
        if path.is_file():
            require(errors, row.get("sha256") == sha256_file(path), f"{path_value}: sha256 mismatch")
            require(errors, int(row.get("size_bytes") or 0) == path.stat().st_size, f"{path_value}: size mismatch")
        publishable = git_publishable(root, path_value)
        if publishable is not None:
            require(errors, publishable is True, f"{path_value}: included file is ignored by git and would be omitted from the package")
            if "git_publishable" in row:
                require(errors, row.get("git_publishable") is True, f"{path_value}: git_publishable metadata must be true")

    raw_rows = row_map(as_list(data.get("referenced_raw_artifact_roots")), "id")
    missing_raw = sorted(REQUIRED_RAW_ROOT_IDS - set(raw_rows))
    require(errors, not missing_raw, f"missing raw roots: {', '.join(missing_raw)}")
    for root_id, row in raw_rows.items():
        require(errors, row.get("exists") is True, f"{root_id}: raw root must exist")
        path_value = row.get("path")
        require(errors, bool(path_value), f"{root_id}: raw root path missing")
        if path_value:
            require(errors, repo_path(root, path_value).is_dir(), f"{root_id}: raw root directory missing: {path_value}")
        counts = as_dict(row.get("file_counts"))
        require(errors, bool(counts) and any(int(value or 0) > 0 for value in counts.values()), f"{root_id}: raw root file_counts must be positive")
        policy = str(row.get("release_policy") or "").lower()
        require(errors, "not copied" in policy and "lightweight" in policy, f"{root_id}: raw root release policy must avoid copying")

    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "tools/package_genesys2_artifact_package.py" in commands, "validation command must include packager")
    require(errors, "tools/check_genesys2_artifact_package.py --root ." in commands, "validation command must include checker")
    require(errors, "tools/reproduce_genesys2_current.py --quick" in commands, "validation command must include quick reproduction")
    require(errors, "tools/reproduce_genesys2_current.py --local" in commands, "validation command must include local reproduction")
    require(errors, "rvmt repro:local" in commands, "validation command must include simplified rvmt reproduction")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("fresh_clone_reproduction_script_available") is True, "fresh clone boundary missing")
    require(errors, boundary.get("lightweight_manifest_package") is True, "lightweight boundary missing")
    require(errors, boundary.get("raw_board_artifacts_copied") is False, "raw board artifacts must not be copied")
    require(errors, boundary.get("requires_board_rerun_for_reproduction_checks") is False, "fresh clone checks must not require board rerun")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")
    require(errors, boundary.get("production_streaming_dma_throughput_claimed") is False, "streaming/DMA throughput must not be claimed")
    require(errors, boundary.get("board_native_source_line_attribution_claimed") is False, "board-native source-line attribution must not be claimed")
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "does not copy large raw board artifacts" in non_claims, "non_claims must reject raw-copy package")
    require(errors, "do not perform a new board run" in non_claims, "non_claims must reject board rerun")
    require(errors, "does not add real-malware validation" in non_claims, "non_claims must reject real malware validation")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for path_value in REQUIRED_INCLUDED_PATHS:
            path = root / path_value
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"schema": "rvmt.genesys2.reproducibility_manifest.v1", "status": "PASS"} if path.name == "reproducibility_manifest.json" else "fixture\n"
            if isinstance(payload, dict):
                write_json(path, payload)
            else:
                path.write_text(payload, encoding="utf-8")
        raw = root / "raw"
        raw.mkdir()
        (raw / "artifact.log").write_text("fixture\n", encoding="utf-8")
        included = []
        for path_value in REQUIRED_INCLUDED_PATHS:
            path = root / path_value
            included.append({"path": path_value, "exists": True, "sha256": sha256_file(path), "size_bytes": path.stat().st_size})
        summary = {
            "schema": "rvmt.genesys2.artifact_package.v1",
            "status": "PASS",
            "package_kind": "lightweight-current-evidence-manifest",
            "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
            "generated_from": "results/evaluation/genesys2-cva6/current/reproducibility_manifest.json",
            "fresh_clone_reproduction": {
                "script": "tools/reproduce_genesys2_current.py",
                "quick_command": "uv run python tools/reproduce_genesys2_current.py --quick",
                "local_command": "uv run python tools/reproduce_genesys2_current.py --local",
                "full_command": "uv run python tools/reproduce_genesys2_current.py --full",
                "dry_run_command": "uv run python tools/reproduce_genesys2_current.py --full --dry-run",
                "rvmt_quick_command": "uv run rvmt repro:quick",
                "rvmt_local_command": "uv run rvmt repro:local",
                "rvmt_full_command": "uv run rvmt repro:full",
                "requires_board_or_vivado": False,
                "requires_network": False,
            },
            "included_files": included,
            "referenced_raw_artifact_roots": [
                {"id": root_id, "path": "raw", "exists": True, "file_counts": {"logs": 1}, "release_policy": "referenced-by-manifest; raw board artifacts are not copied into this lightweight package"}
                for root_id in REQUIRED_RAW_ROOT_IDS
            ],
            "validation_commands": [
                "uv run python tools/package_genesys2_artifact_package.py",
                "uv run python tools/check_genesys2_artifact_package.py --root .",
                "uv run python tools/reproduce_genesys2_current.py --quick",
                "uv run python tools/reproduce_genesys2_current.py --local",
                "uv run rvmt repro:local --dry-run",
            ],
            "claim_boundary": {
                "fresh_clone_reproduction_script_available": True,
                "lightweight_manifest_package": True,
                "raw_board_artifacts_copied": False,
                "requires_board_rerun_for_reproduction_checks": False,
                "real_malware_validation_claimed": False,
                "production_streaming_dma_throughput_claimed": False,
                "board_native_source_line_attribution_claimed": False,
            },
            "non_claims": [
                "This is a lightweight manifest package; it does not copy large raw board artifacts.",
                "Fresh-clone reproduction commands do not perform a new board run.",
                "The package does not add real-malware validation.",
            ],
        }
        errors = check_summary(summary, root)
        if errors:
            print("[FAIL] artifact package good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        summary["claim_boundary"]["raw_board_artifacts_copied"] = True
        errors = check_summary(summary, root)
        if not errors:
            print("[FAIL] artifact package bad fixture passed", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 artifact package checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the current Genesys2/CVA6 lightweight artifact package manifest.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] missing artifact package manifest: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root)
    except Exception as exc:
        print(f"[FAIL] artifact package checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] artifact package manifest is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] artifact package manifest accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
