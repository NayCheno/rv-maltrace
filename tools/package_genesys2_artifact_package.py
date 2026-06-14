from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_REPRO_MANIFEST = DEFAULT_CURRENT_ROOT / "reproducibility_manifest.json"
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "artifact_package_manifest.json"

CORE_FILES = [
    "README.md",
    "pyproject.toml",
    "uv.lock",
    "tools/check_suites.json",
    "tools/run_check_suite.py",
    "tools/reproduce_genesys2_current.py",
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
]


def repo_rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


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


def unique_paths(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        result.append(path)
    return result


def file_row(path_value: str, role: str) -> dict[str, Any]:
    path = ROOT / path_value
    return {
        "path": path_value,
        "role": role,
        "exists": path.is_file(),
        "sha256": sha256_file(path) if path.is_file() else None,
        "size_bytes": path.stat().st_size if path.is_file() else None,
        "git_publishable": git_publishable(ROOT, path_value),
    }


def rows_from_repro(repro: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in repro.get("summary_artifacts", []):
        if isinstance(row, dict) and isinstance(row.get("path"), str):
            rows.append(file_row(row["path"], "summary_artifact"))
    for row in repro.get("report_rows", []):
        if isinstance(row, dict) and isinstance(row.get("report"), str):
            rows.append(file_row(row["report"], "paper_facing_report"))
    return rows


def package_manifest(current_root: Path, repro_path: Path) -> dict[str, Any]:
    repro = load_json(ROOT / repro_path)
    included_paths = unique_paths(
        [
            *CORE_FILES,
            repo_rel(ROOT / repro_path),
            *[
                str(row.get("path"))
                for row in repro.get("summary_artifacts", [])
                if isinstance(row, dict) and isinstance(row.get("path"), str)
            ],
            *[
                str(row.get("report"))
                for row in repro.get("report_rows", [])
                if isinstance(row, dict) and isinstance(row.get("report"), str)
            ],
        ]
    )
    included = [file_row(path, "core_reproduction_file") for path in CORE_FILES]
    included.extend(row for row in rows_from_repro(repro) if row["path"] not in CORE_FILES)
    existing_paths = {row["path"] for row in included}
    for path in included_paths:
        if path not in existing_paths:
            included.append(file_row(path, "referenced_file"))
    raw_roots: list[dict[str, Any]] = []
    for row in repro.get("raw_artifact_roots", []):
        if not isinstance(row, dict):
            continue
        raw_roots.append(
            {
                "id": row.get("id"),
                "path": row.get("path"),
                "exists": row.get("exists"),
                "file_counts": row.get("file_counts"),
                "release_policy": "referenced-by-manifest; raw board artifacts are not copied into this lightweight package",
            }
        )
    status = "PASS"
    if repro.get("status") != "PASS":
        status = "FAIL"
    if any(row.get("exists") is not True for row in included):
        status = "FAIL"
    if not raw_roots or any(row.get("exists") is not True for row in raw_roots):
        status = "FAIL"
    return {
        "schema": "rvmt.genesys2.artifact_package.v1",
        "status": status,
        "package_kind": "lightweight-current-evidence-manifest",
        "canonical_evaluation_root": repo_rel(ROOT / current_root),
        "generated_from": repo_rel(ROOT / repro_path),
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
        "referenced_raw_artifact_roots": raw_roots,
        "validation_commands": [
            "uv run python tools/package_genesys2_artifact_package.py",
            "uv run python tools/check_genesys2_artifact_package.py --root .",
            "uv run python tools/reproduce_genesys2_current.py --quick",
            "uv run python tools/reproduce_genesys2_current.py --local",
            "uv run python tools/reproduce_genesys2_current.py --full --dry-run",
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
            "This is a lightweight manifest package for the controlled Genesys2/CVA6 evidence chain; it does not copy large raw board artifacts.",
            "Fresh-clone reproduction commands re-run repository checkers over checked-in manifests and referenced artifact paths; they do not perform a new board run.",
            "The package does not add real-malware validation, full hardware pointer strings, board-native DWARF source-line attribution, or production streaming/DMA throughput evidence.",
        ],
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        current.mkdir(parents=True, exist_ok=True)
        for path in CORE_FILES:
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("fixture\n", encoding="utf-8")
        report = root / "docs/07-evaluation-evidence/reports/ccfa_readiness_matrix.md"
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text("fixture\n", encoding="utf-8")
        summary = current / "summary.json"
        write_json(summary, {"schema": "fixture", "status": "PASS"})
        raw = root / "raw"
        raw.mkdir()
        repro = {
            "schema": "rvmt.genesys2.reproducibility_manifest.v1",
            "status": "PASS",
            "summary_artifacts": [{"id": "summary", "path": summary.relative_to(root).as_posix()}],
            "report_rows": [{"id": "report", "report": report.relative_to(root).as_posix()}],
            "raw_artifact_roots": [{"id": "raw", "path": "raw", "exists": True, "file_counts": {"logs": 1}}],
        }
        write_json(current / "reproducibility_manifest.json", repro)
        old_root = globals()["ROOT"]
        try:
            globals()["ROOT"] = root
            manifest = package_manifest(DEFAULT_CURRENT_ROOT, DEFAULT_REPRO_MANIFEST)
        finally:
            globals()["ROOT"] = old_root
    if manifest.get("status") != "PASS":
        print("[FAIL] expected artifact package fixture to pass", file=sys.stderr)
        return 1
    if manifest.get("claim_boundary", {}).get("raw_board_artifacts_copied") is not False:
        print("[FAIL] artifact package must not copy raw board artifacts", file=sys.stderr)
        return 1
    print("[PASS] Genesys2 artifact package packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package the current Genesys2/CVA6 lightweight artifact manifest.")
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--reproducibility-manifest", type=Path, default=DEFAULT_REPRO_MANIFEST)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        manifest = package_manifest(args.current_root, args.reproducibility_manifest)
        write_json(args.out, manifest)
    except Exception as exc:
        print(f"package_genesys2_artifact_package: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{manifest['status']}] wrote Genesys2 artifact package manifest to {args.out}")
    return 0 if manifest["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
