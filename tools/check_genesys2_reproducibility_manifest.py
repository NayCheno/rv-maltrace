from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/reproducibility_manifest.json")
REQUIRED_SUMMARY_IDS = {
    "latest_manifest",
    "trace_sink",
    "safe_surrogate_bram_trace",
    "p0_bram_trace",
    "drop_accounting",
    "statistical_robustness",
    "streaming_dma_target",
    "streaming_dma_readiness",
    "pointer_snapshot_guardrails",
    "hardware_pointer_prefixes",
    "pointer_string_readiness",
    "benign_control",
    "board_benign_readiness",
    "production_runtime_benchmark",
    "semantic_reconstruction",
    "fd_path_graph",
    "source_line_attribution",
    "source_line_sidecar",
    "source_line_toolchain_probe",
    "debug_elf_readiness",
    "external_closure_readiness",
    "external_closure_intake",
    "external_closure_plan",
    "external_closure_preflight",
    "external_operator_packet",
    "external_template_board_native_source_lines",
    "external_template_hardware_pointer_strings",
    "external_template_streaming_dma_throughput",
    "external_template_board_benign_control",
    "process_elf_ownership",
    "dynamic_mapping_attribution",
    "ccfa_evaluation_matrix",
    "baseline_alignment",
    "behavior_audit_metrics",
    "case_study_manifest",
    "review_closure_audit",
    "real_malware_containment",
}
TEMPLATE_SUMMARY_IDS = {
    "external_template_board_native_source_lines",
    "external_template_hardware_pointer_strings",
    "external_template_streaming_dma_throughput",
    "external_template_board_benign_control",
}
REQUIRED_RAW_ROOT_IDS = {
    "p0_bram_repetitions",
    "safe_surrogate_bram_repetitions",
    "pointer_snapshot_bram",
    "p0_continuous_trace",
    "safe_surrogate_runtime_map",
    "production_runtime_benchmark",
}
REQUIRED_VALIDATION_COMMANDS = {
    "genesys2-current": "validation commands must include genesys2-current",
    "genesys2-artifacts": "validation commands must include genesys2-artifacts",
    "genesys2-self-test": "validation commands must include genesys2-self-test",
    "ccfa-gate-self-test": "validation commands must include ccfa-gate-self-test",
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


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def row_map(rows: list[Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("id"), str) and row.get("id")
    }


def check_summary(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == "rvmt.genesys2.reproducibility_manifest.v1", "schema must be rvmt.genesys2.reproducibility_manifest.v1")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical_evaluation_root mismatch")
    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("controlled_safe_surrogate_evidence") is True, "controlled safe/surrogate boundary missing")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")
    require(errors, boundary.get("hardware_full_pointer_strings_claimed") is False, "full hardware pointer strings must not be claimed")
    require(errors, boundary.get("production_streaming_dma_throughput_claimed") is False, "production streaming/DMA throughput must not be claimed")
    require(errors, boundary.get("board_native_source_line_attribution_claimed") is False, "board-native DWARF source-line attribution must not be claimed")
    require(errors, boundary.get("debug_toolchain_source_line_probe_available") is True, "debug toolchain source-line probe must be available")
    require(errors, boundary.get("debug_no_pie_elf_readiness_available") is True, "debug/no-PIE ELF readiness must be available")
    require(errors, boundary.get("board_benign_readiness_available") is True, "board benign readiness must be available")
    require(errors, boundary.get("streaming_dma_readiness_available") is True, "streaming/DMA readiness must be available")
    require(errors, boundary.get("pointer_string_readiness_available") is True, "pointer string readiness must be available")
    require(errors, boundary.get("dated_roots_are_provenance_only") is True, "dated roots must be provenance only")

    summaries = row_map(as_list(data.get("summary_artifacts")))
    missing_summary_ids = sorted(REQUIRED_SUMMARY_IDS - set(summaries))
    require(errors, not missing_summary_ids, f"missing summary artifact ids: {', '.join(missing_summary_ids)}")
    for artifact_id, row in summaries.items():
        path_value = row.get("path")
        require(errors, bool(path_value), f"{artifact_id}: path required")
        if not path_value:
            continue
        path = repo_path(root, path_value)
        require(errors, path.is_file(), f"{artifact_id}: artifact missing: {path_value}")
        if path.is_file():
            require(errors, row.get("sha256") == sha256_file(path), f"{artifact_id}: sha256 mismatch")
            try:
                artifact = load_json(path)
            except Exception as exc:
                errors.append(f"{artifact_id}: JSON load failed: {exc}")
                continue
            require(errors, row.get("schema") == artifact.get("schema"), f"{artifact_id}: schema mismatch")
            if artifact_id in TEMPLATE_SUMMARY_IDS:
                require(errors, row.get("status") == "TEMPLATE_NOT_EVIDENCE" and artifact.get("status") == "TEMPLATE_NOT_EVIDENCE", f"{artifact_id}: status must be TEMPLATE_NOT_EVIDENCE")
            elif artifact_id != "source_line_sidecar":
                require(errors, row.get("status") == "PASS" and artifact.get("status") == "PASS", f"{artifact_id}: status must be PASS")
        require(errors, "uv run python" in str(row.get("checker_command") or ""), f"{artifact_id}: checker_command required")

    raw_roots = row_map(as_list(data.get("raw_artifact_roots")))
    missing_raw_ids = sorted(REQUIRED_RAW_ROOT_IDS - set(raw_roots))
    require(errors, not missing_raw_ids, f"missing raw artifact root ids: {', '.join(missing_raw_ids)}")
    for root_id, row in raw_roots.items():
        path_value = row.get("path")
        require(errors, row.get("exists") is True, f"{root_id}: root must exist")
        require(errors, bool(path_value), f"{root_id}: path required")
        if path_value:
            require(errors, repo_path(root, path_value).is_dir(), f"{root_id}: directory missing: {path_value}")
        counts = as_dict(row.get("file_counts"))
        require(errors, bool(counts), f"{root_id}: file_counts required")
        require(errors, any(int(value or 0) > 0 for value in counts.values()), f"{root_id}: file_counts must include positive evidence")

    report_rows = as_list(data.get("report_rows"))
    require(errors, len(report_rows) >= 3, "report row coverage is too small")
    for row in report_rows:
        if not isinstance(row, dict):
            errors.append("report rows must be objects")
            continue
        report = row.get("report")
        require(errors, bool(report), "report row path required")
        if report:
            require(errors, repo_path(root, report).is_file(), f"report file missing: {report}")
        for summary_id in as_list(row.get("source_summary_ids")):
            require(errors, str(summary_id) in summaries, f"{row.get('id')}: unknown source_summary_id {summary_id}")
        for raw_id in as_list(row.get("raw_root_ids")):
            require(errors, str(raw_id) in raw_roots, f"{row.get('id')}: unknown raw_root_id {raw_id}")
        require(errors, bool(as_list(row.get("checker_commands"))), f"{row.get('id')}: checker commands required")
    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    for suite_id, message in REQUIRED_VALIDATION_COMMANDS.items():
        require(errors, suite_id in commands, message)
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "does not add real-malware validation" in non_claims, "non_claims must reject real-malware validation")
    require(errors, "does not make current board traces dwarf source-line attributed" in non_claims, "non_claims must preserve board source-line boundary")
    require(errors, "preflight proves only local scripts" in non_claims, "non_claims must preserve external preflight boundary")
    require(errors, "external operator packet is an execution handoff" in non_claims, "non_claims must preserve external operator packet boundary")
    require(errors, "templates are template_not_evidence scaffolding" in non_claims, "non_claims must preserve external template boundary")
    require(errors, "does not make randomized workload or real-malware generalization claims" in non_claims, "non_claims must preserve statistical robustness boundary")
    require(errors, "does not complete production streaming/dma throughput evidence" in non_claims, "non_claims must preserve streaming/DMA target boundary")
    require(errors, "streaming/dma readiness summary" in non_claims, "non_claims must preserve streaming/DMA readiness boundary")
    require(errors, "pointer string readiness summary" in non_claims, "non_claims must preserve pointer string readiness boundary")
    require(errors, "does not complete board benign false-positive evidence" in non_claims, "non_claims must preserve board benign boundary")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / "results/evaluation/genesys2-cva6/current"
        current.mkdir(parents=True, exist_ok=True)
        report = root / "docs/07-evaluation-evidence/reports/ccfa_readiness_matrix.md"
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text("# fixture\n", encoding="utf-8")
        summary_rows = []
        for artifact_id in REQUIRED_SUMMARY_IDS:
            path = current / f"{artifact_id}.json"
            status = "TEMPLATE_NOT_EVIDENCE" if artifact_id in TEMPLATE_SUMMARY_IDS else "PASS"
            write_json(path, {"schema": f"rvmt.fixture.{artifact_id}.v1", "status": status})
            summary_rows.append(
                {
                    "id": artifact_id,
                    "path": path.relative_to(root).as_posix(),
                    "sha256": sha256_file(path),
                    "schema": f"rvmt.fixture.{artifact_id}.v1",
                    "status": status,
                    "checker_command": "uv run python tools/check_fixture.py --root .",
                }
            )
        raw = root / "raw"
        raw.mkdir()
        (raw / "artifact.log").write_text("fixture\n", encoding="utf-8")
        manifest = {
            "schema": "rvmt.genesys2.reproducibility_manifest.v1",
            "status": "PASS",
            "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
            "claim_boundary": {
                "controlled_safe_surrogate_evidence": True,
                "real_malware_validation_claimed": False,
                "hardware_full_pointer_strings_claimed": False,
                "production_streaming_dma_throughput_claimed": False,
                "board_native_source_line_attribution_claimed": False,
                "debug_toolchain_source_line_probe_available": True,
                "debug_no_pie_elf_readiness_available": True,
                "board_benign_readiness_available": True,
                "streaming_dma_readiness_available": True,
                "pointer_string_readiness_available": True,
                "dated_roots_are_provenance_only": True,
            },
            "summary_artifacts": summary_rows,
            "raw_artifact_roots": [
                {"id": raw_id, "path": "raw", "exists": True, "file_counts": {"logs": 1}}
                for raw_id in REQUIRED_RAW_ROOT_IDS
            ],
            "report_rows": [
                {
                    "id": "readiness_claim_gates",
                    "report": report.relative_to(root).as_posix(),
                    "source_summary_ids": sorted(REQUIRED_SUMMARY_IDS),
                    "raw_root_ids": sorted(REQUIRED_RAW_ROOT_IDS),
                    "checker_commands": ["uv run python tools/run_check_suite.py --suite genesys2-current"],
                },
                {
                    "id": "next_closure_completed_items",
                    "report": report.relative_to(root).as_posix(),
                    "source_summary_ids": ["latest_manifest"],
                    "raw_root_ids": ["p0_bram_repetitions"],
                    "checker_commands": ["uv run python tools/check_ccfa_current_quality.py --root ."],
                },
                {
                    "id": "p0_evidence_chain",
                    "report": report.relative_to(root).as_posix(),
                    "source_summary_ids": ["p0_bram_trace"],
                    "raw_root_ids": ["p0_continuous_trace"],
                    "checker_commands": ["uv run python tools/check_genesys2_p0_bram_trace.py --root ."],
                },
            ],
            "validation_commands": [
                "uv run python tools/run_check_suite.py --suite genesys2-current",
                "uv run python tools/run_check_suite.py --suite genesys2-artifacts",
                "uv run python tools/run_check_suite.py --suite genesys2-self-test",
                "uv run python tools/run_check_suite.py --suite ccfa-gate-self-test",
            ],
            "non_claims": [
                "This manifest ties evidence together but does not add real-malware validation.",
                "The source-line toolchain probe does not make current board traces DWARF source-line attributed.",
                "The debug ELF readiness summary prepares rerun candidates but does not make current board traces DWARF source-line attributed.",
                "The external closure preflight proves only local scripts and does not replace external execution.",
                "The external operator packet is an execution handoff and does not replace external board, RTL, host transport, or reviewer execution.",
                "The external summary templates are TEMPLATE_NOT_EVIDENCE scaffolding and must not be treated as accepted external summaries.",
                "The statistical robustness summary audits controlled repetitions but does not make randomized workload or real-malware generalization claims.",
                "The streaming/DMA target summary is local only and does not complete production streaming/DMA throughput evidence.",
                "The streaming/DMA readiness summary is local only and does not complete production streaming/DMA throughput evidence.",
                "The pointer string readiness summary is local only and does not complete full hardware pointer-string evidence.",
                "The board benign readiness summary is local only and does not complete board benign false-positive evidence.",
            ],
        }
        errors = check_summary(manifest, root)
        if errors:
            print("[FAIL] reproducibility manifest good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        manifest["claim_boundary"]["real_malware_validation_claimed"] = True
        errors = check_summary(manifest, root)
        if not errors:
            print("[FAIL] reproducibility manifest bad fixture passed", file=sys.stderr)
            return 1
        manifest["claim_boundary"]["real_malware_validation_claimed"] = False
        manifest["validation_commands"] = [
            "uv run python tools/run_check_suite.py --suite genesys2-current",
            "uv run python tools/run_check_suite.py --suite genesys2-self-test",
            "uv run python tools/run_check_suite.py --suite ccfa-gate-self-test",
        ]
        errors = check_summary(manifest, root)
        if not any("genesys2-artifacts" in error for error in errors):
            print("[FAIL] reproducibility manifest missed absent artifact suite", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 reproducibility manifest checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check current Genesys2/CVA6 reproducibility manifest.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] missing reproducibility manifest: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root)
    except Exception as exc:
        print(f"[FAIL] reproducibility manifest checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] reproducibility manifest is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] reproducibility manifest accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
