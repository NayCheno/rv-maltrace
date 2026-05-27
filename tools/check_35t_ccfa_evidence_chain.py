from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PRIMARY_RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
SURROGATE_RUN_ID = "35t-surrogate-darthra-p0a-r512-abba-r5-20260524"
MIRAI_RUN_ID = "35t-mirai-reference-nonnetwork-p0a-r512-abba-r5-v3-20260524"
DEFAULT_RESULTS_BASE = Path("results/experiments/35t")
DEFAULT_EVIDENCE_BASE = Path("docs/results/evidence")
DEFAULT_EVIDENCE_ROOT = DEFAULT_EVIDENCE_BASE / "35t-ccfa-strong-evidence-chain-20260524"
LINEAGE_EVIDENCE_ROOT = DEFAULT_EVIDENCE_BASE / "35t-real-malware-derived-lineage-20260524"
BASELINE_EVIDENCE_ROOT = DEFAULT_EVIDENCE_BASE / "35t-real-malware-derived-baseline-comparison-20260524"
BOOT_EVIDENCE_ROOT = DEFAULT_EVIDENCE_BASE / "35t-surrogate-boot-provenance-20260524"
CLAIM_TABLE_EVIDENCE_ROOT = DEFAULT_EVIDENCE_BASE / "35t-paper-claim-evidence-table-20260524"
REAL_MALWARE_MANIFEST = Path("experiments/linux_behavior/real_malware/manifest.json")
REAL_MALWARE_RESULTS_ROOT = Path("results/experiments/real_malware/manual")
SCHEMA = "rvmt.35t.ccfa_style_evidence_chain.v1"
PASS_STATUS = "CCFA_STYLE_STRONG_EVIDENCE_CHAIN_PASS_WITH_BOUNDED_LIMITATIONS"
FAIL_STATUS = "FAIL"
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted malware-behavior evidence chain prototype"
EXPECTED_SURROGATE_SAMPLES = (
    "darthra_elf_header_probe",
    "darthra_rootkit_device_probe",
    "darthra_virus_fixture_walk_sim",
)
EXPECTED_MIRAI_SAMPLES = (
    "mirai_proc_scan_sim",
    "mirai_watchdog_probe_sim",
    "mirai_encoded_table_sim",
)
EXCLUDED_NETWORK_SAMPLES = ("loopback_network_client", "mirai_c2_loopback_probe")
SNAPSHOT_FILES = (
    "README.md",
    "artifact_hash_manifest.json",
    "ccfa_evidence_chain.json",
    "ccfa_evidence_chain.md",
    "claim_boundary.json",
    "claim_boundary.md",
    "reproduction_commands.md",
    "reviewer_checklist.md",
)
NON_CLAIMS = [
    "CCF-A-style evidence discipline is not a CCF-A acceptance guarantee",
    "external-quarantine payload execution remains a separate gated boundary",
    "DarthRa-derived samples are safety-controlled malware behavior cases",
    "Mirai-reference samples are non-network malware behavior cases",
    "no CVA6 board claim",
    "no mature detector or classifier-accuracy claim",
    "no complete semantic reconstruction claim under p0a arg-mem-disabled tracing",
]
TOOLING_PROVENANCE_PATHS = (
    Path("tools/check_35t_ccfa_evidence_chain.py"),
    Path("tools/check_real_malware_surrogate_gate.py"),
    Path("tools/check_35t_extension_gate.py"),
    Path("tools/check_real_malware_validation_gate.py"),
    Path("tools/check_35t_real_malware_derived_lineage.py"),
    Path("tools/check_35t_behavior_baseline_comparison.py"),
    Path("tools/check_35t_surrogate_boot_provenance.py"),
    Path("tools/check_35t_claim_evidence_table.py"),
    Path("tools/check_35t_artifact_package_readiness.py"),
    Path("tools/check_35t_evidence_consistency.py"),
    Path("tools/experiment_35t.py"),
    Path("tools/audit_behavior.py"),
    Path("src/rv_maltrace/explain.py"),
    Path("experiments/linux_behavior/behavior_audit_rules.json"),
    Path("experiments/linux_behavior/malware_like/extension_plan.json"),
    Path("experiments/linux_behavior/malware_like/manifest.json"),
    Path("experiments/linux_behavior/real_malware/manifest.json"),
    Path("experiments/linux_behavior/real_malware/reference_sources/mirai_botnet_behavior_reference.json"),
    Path("experiments/linux_behavior/real_malware_surrogate/manifest.json"),
    Path("experiments/linux_behavior/real_malware_surrogate/behavior_lineage_matrix.json"),
    Path("experiments/linux_behavior/malware_like/extension_programs/mirai_proc_scan_sim.c"),
    Path("experiments/linux_behavior/malware_like/extension_programs/mirai_watchdog_probe_sim.c"),
    Path("experiments/linux_behavior/malware_like/extension_programs/mirai_encoded_table_sim.c"),
    Path("experiments/linux_behavior/real_malware_surrogate/programs/darthra_elf_header_probe.c"),
    Path("experiments/linux_behavior/real_malware_surrogate/programs/darthra_rootkit_device_probe.c"),
    Path("experiments/linux_behavior/real_malware_surrogate/programs/darthra_virus_fixture_walk_sim.c"),
    Path("docs/linux/linux_real_malware_surrogate_validation.md"),
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def repo_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def read_json(path: Path, failures: list[str], repo_root: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        failures.append(f"missing {label}: {rel(path, repo_root)}")
        return {}
    try:
        return load_json(path)
    except Exception as exc:
        failures.append(f"invalid {label}: {rel(path, repo_root)}: {exc}")
        return {}


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def nonempty_file(path: Path) -> bool:
    return path.is_file() and path.stat().st_size > 0


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_record(path: Path, repo_root: Path) -> dict[str, Any]:
    return {
        "path": rel(path, repo_root),
        "bytes": path.stat().st_size,
        "sha256": file_digest(path),
    }


def class_digest(files: list[Path], repo_root: Path) -> str | None:
    if not files:
        return None
    digest = hashlib.sha256()
    for path in sorted(files, key=lambda item: rel(item, repo_root)):
        digest.update(rel(path, repo_root).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(path.stat().st_size).encode("ascii"))
        digest.update(b"\0")
        digest.update(file_digest(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def collect_files(root: Path, patterns: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()
    for pattern in patterns:
        for path in root.glob(pattern):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            files.append(path)
    return sorted(files, key=lambda item: item.as_posix())


def manifest_rows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    rows = manifest.get("committed_artifacts", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def manifest_hash_errors(repo_root: Path, rows: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for row in rows:
        artifact = str(row.get("artifact") or "")
        committed_path = row.get("committed_path")
        if not artifact:
            errors.append("manifest row missing artifact name")
            continue
        if artifact in seen:
            errors.append(f"duplicate manifest artifact: {artifact}")
        seen.add(artifact)
        if not isinstance(committed_path, str) or not committed_path:
            errors.append(f"{artifact}: missing committed_path")
            continue
        path = repo_path(repo_root, Path(committed_path))
        if not path.is_file():
            errors.append(f"{artifact}: committed_path does not exist: {rel(path, repo_root)}")
            continue
        if row.get("bytes") != path.stat().st_size:
            errors.append(f"{artifact}: byte count mismatch")
        if row.get("sha256") != file_digest(path):
            errors.append(f"{artifact}: sha256 mismatch")
    return errors


def check_evidence_snapshot(repo_root: Path, evidence_root: Path, *, label: str) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    manifest = read_json(evidence_root / "evidence_manifest.json", failures, repo_root, f"{label} evidence manifest")
    rows = manifest_rows(manifest)
    hash_errors = manifest_hash_errors(repo_root, rows) if manifest else []
    failures.extend(f"{label}:manifest:{item}" for item in hash_errors)
    return {
        "label": label,
        "path": rel(evidence_root, repo_root),
        "present": evidence_root.is_dir(),
        "schema": manifest.get("schema"),
        "status": manifest.get("status"),
        "claim_level": manifest.get("claim_level"),
        "artifact_count": len(rows),
        "hash_errors": hash_errors,
    }, failures


def check_run_config(
    repo_root: Path,
    results_root: Path,
    *,
    label: str,
    expected_samples: tuple[str, ...],
    expected_kind: str,
) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    path = results_root / "run_config.json"
    data = read_json(path, failures, repo_root, f"{label} run_config")
    checks: dict[str, bool] = {}
    if data:
        samples = [str(item) for item in data.get("samples", [])] if isinstance(data.get("samples"), list) else []
        trace_controls = data.get("trace_controls", {}) if isinstance(data.get("trace_controls"), dict) else {}
        checks = {
            "run_id_matches": data.get("run_id") == results_root.name,
            "reps_at_least_5": int(data.get("reps") or 0) >= 5,
            "runtime_order_abba": data.get("runtime_order") == "abba",
            "network_disabled": data.get("network") == "disabled",
            "real_malware_forbidden": data.get("real_malware") == "forbidden",
            "syscall_side_channel_disabled": data.get("syscall_side_channel") is False,
            "trace_profile_p0a": data.get("trace_profile") == "p0a_syscall_drop",
            "trace_records_at_least_512": int(data.get("trace_records") or 0) >= 512,
            "arg_mem_disabled": trace_controls.get("enable_arg_mem") is False,
            "expected_samples_exact": set(samples) == set(expected_samples),
        }
        if expected_kind == "surrogate":
            checks.update(
                {
                    "include_surrogate_samples": data.get("include_surrogate_samples") is True,
                    "include_extension_samples_false": data.get("include_extension_samples") is False,
                }
            )
        elif expected_kind == "mirai":
            checks.update(
                {
                    "include_extension_samples": data.get("include_extension_samples") is True,
                    "include_surrogate_samples_false": data.get("include_surrogate_samples") is False,
                    "trace_profile_policy_35t_small_capacity": data.get("trace_profile_policy") == "35t_small_capacity",
                }
            )
    failures.extend(f"{label}:run_config:{key}" for key, ok in checks.items() if not ok)
    return {
        "label": label,
        "path": rel(path, repo_root),
        "present": path.is_file(),
        "checks": checks,
        "config": data,
    }, failures


def check_gate_report(
    repo_root: Path,
    evidence_root: Path,
    *,
    label: str,
    gate_file: str,
    expected_samples: tuple[str, ...],
    expected_status: str,
) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    path = evidence_root / gate_file
    gate = read_json(path, failures, repo_root, f"{label} gate")
    checks: dict[str, bool] = {}
    sample_reports: list[dict[str, Any]] = []
    if gate:
        rows = [row for row in gate.get("samples", []) if isinstance(row, dict)] if isinstance(gate.get("samples"), list) else []
        by_sample = {str(row.get("sample_id")): row for row in rows if row.get("sample_id")}
        checks = {
            "status_expected": gate.get("status") == expected_status,
            "expected_samples_present": set(expected_samples) <= set(by_sample),
        }
        if gate_file == "extension_gate_check.json":
            excluded = [str(item) for item in gate.get("excluded_samples", [])] if isinstance(gate.get("excluded_samples"), list) else []
            checks["network_optional_samples_excluded"] = set(EXCLUDED_NETWORK_SAMPLES) <= set(excluded)
        for sample_id in expected_samples:
            row = by_sample.get(sample_id, {})
            row_checks = row.get("checks", {}) if isinstance(row.get("checks"), dict) else {}
            sample_status = row.get("sample_status", {}) if isinstance(row.get("sample_status"), dict) else {}
            strong_checks = {
                "status_pass": row.get("status") == "PASS",
                "gate_status_pass": row.get("gate_status") == "PASS",
                "sample_status_pass": sample_status.get("status") == "PASS",
                "trace_on_5_of_5": int(sample_status.get("trace_on_pass") or 0) >= 5,
                "trace_artifacts_5_of_5": int(row.get("trace_artifact_count") or 0) >= 5,
                "semantic_artifacts_5_of_5": int(row.get("semantic_artifact_count") or 0) >= 5,
                "behavior_audit_artifacts_5_of_5": int(row.get("behavior_audit_artifact_count") or 0) >= 5,
                "unknown_corrupt_zero": int(row.get("unknown_event_count") or 0) == 0
                and int(row.get("corrupt_record_count") or 0) == 0,
                "drop_rate_median_le_5pct": float(row.get("drop_rate_median") or 0.0) <= 0.05,
                "strong_expected_behavior_matched": row_checks.get("strong_expected_behavior_matched") is True,
                "runtime_process_attribution_pass": row_checks.get("runtime_process_attribution_pass") is True,
                "marker_scope_pass": row_checks.get("marker_scope_pass") is True,
                "no_trace_cap_hit": row_checks.get("no_trace_cap_hit") is True,
            }
            if not row:
                strong_checks = {key: False for key in strong_checks}
            sample_reports.append(
                {
                    "sample_id": sample_id,
                    "status": "PASS" if all(strong_checks.values()) else "FAIL",
                    "checks": strong_checks,
                    "matched_expected": row.get("matched_expected", []),
                    "expected_evidence_source": row.get("expected_evidence_source"),
                    "drop_rate_median": row.get("drop_rate_median"),
                    "unknown_event_count": row.get("unknown_event_count"),
                    "corrupt_record_count": row.get("corrupt_record_count"),
                }
            )
            failures.extend(
                f"{label}:sample:{sample_id}:{check}" for check, ok in strong_checks.items() if not ok
            )
    failures.extend(f"{label}:gate:{key}" for key, ok in checks.items() if not ok)
    return {
        "label": label,
        "path": rel(path, repo_root),
        "present": path.is_file(),
        "status": gate.get("status"),
        "checks": checks,
        "samples": sample_reports,
    }, failures


def check_metrics(repo_root: Path, results_root: Path, *, label: str) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    path = results_root / "aggregate" / "metrics.json"
    metrics = read_json(path, failures, repo_root, f"{label} metrics")
    checks: dict[str, bool] = {}
    if metrics:
        confusion = metrics.get("confusion", {}) if isinstance(metrics.get("confusion"), dict) else {}
        rule_confusion = metrics.get("rule_confusion", {}) if isinstance(metrics.get("rule_confusion"), dict) else {}
        checks = {
            "confusion_fp_zero": int(confusion.get("fp") or 0) == 0,
            "confusion_fn_zero": int(confusion.get("fn") or 0) == 0,
            "rule_confusion_fp_zero": int(rule_confusion.get("fp") or 0) == 0,
            "rule_confusion_fn_zero": int(rule_confusion.get("fn") or 0) == 0,
            "sample_rows_present": bool(metrics.get("samples")),
        }
    failures.extend(f"{label}:metrics:{key}" for key, ok in checks.items() if not ok)
    return {
        "label": label,
        "path": rel(path, repo_root),
        "present": path.is_file(),
        "checks": checks,
        "confusion": metrics.get("confusion", {}),
        "rule_confusion": metrics.get("rule_confusion", {}),
    }, failures


def artifact_classes_for_run(sample_count: int) -> tuple[dict[str, Any], ...]:
    rep_count = sample_count * 5
    build_hash_count = sample_count * 3
    return (
        {
            "artifact_id": "run_metadata",
            "description": "run config and run manifests",
            "min_count": 2,
            "patterns": ("run_config.json", "run_behavior_manifest.json", "run_malware_manifest.json"),
        },
        {
            "artifact_id": "raw_uart",
            "description": "board-level and per-repetition raw UART captures",
            "min_count": 1,
            "patterns": ("board/raw_uart.log", "samples/**/board/trace-on/rep_*/trace_raw_uart.log"),
        },
        {
            "artifact_id": "decoded_trace",
            "description": "decoded hardware trace JSONL",
            "min_count": rep_count,
            "patterns": ("samples/**/board/trace-on/rep_*/trace.jsonl",),
        },
        {
            "artifact_id": "runtime_process_map",
            "description": "runtime process attribution maps",
            "min_count": rep_count,
            "patterns": ("samples/**/board/trace-on/rep_*/runtime_process_map.json",),
        },
        {
            "artifact_id": "trace_code_map",
            "description": "trace-to-code map summaries and joins",
            "min_count": rep_count,
            "patterns": (
                "samples/**/board/trace-on/rep_*/trace_code_map/trace_code_map_summary.json",
                "samples/**/board/trace-on/rep_*/trace_code_map/trace.code_map.jsonl",
            ),
        },
        {
            "artifact_id": "semantic_events",
            "description": "semantic event recovery outputs",
            "min_count": rep_count,
            "patterns": ("samples/**/board/trace-on/rep_*/behavior_recovery/semantic_events.json",),
        },
        {
            "artifact_id": "behavior_audit",
            "description": "per-repetition behavior audit evidence",
            "min_count": rep_count,
            "patterns": ("samples/**/board/trace-on/rep_*/behavior_audit/behavior_audit.json",),
        },
        {
            "artifact_id": "alignment",
            "description": "trace-to-groundtruth alignment evidence",
            "min_count": rep_count,
            "patterns": ("samples/**/board/trace-on/rep_*/alignment/alignment.json",),
        },
        {
            "artifact_id": "build_provenance",
            "description": "source, host ELF, RISC-V ELF hashes and compiler records",
            "min_count": build_hash_count,
            "patterns": ("samples/**/build/*.sha256", "samples/**/build/compiler.txt"),
        },
        {
            "artifact_id": "aggregate_reports",
            "description": "aggregate metrics and reports",
            "min_count": 3,
            "patterns": ("aggregate/*",),
        },
    )


def build_run_hash_inventory(
    repo_root: Path,
    results_root: Path,
    *,
    label: str,
    sample_count: int,
) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    class_rows: list[dict[str, Any]] = []
    file_rows: list[dict[str, Any]] = []
    for spec in artifact_classes_for_run(sample_count):
        files = collect_files(results_root, tuple(spec["patterns"]))
        records = [file_record(path, repo_root) for path in files]
        file_rows.extend({"artifact_id": spec["artifact_id"], **record} for record in records)
        row = {
            "artifact_id": spec["artifact_id"],
            "description": spec["description"],
            "count": len(files),
            "min_count": spec["min_count"],
            "total_bytes": sum(path.stat().st_size for path in files),
            "class_digest": class_digest(files, repo_root),
            "representative_files": records[:5],
            "status": "PASS" if len(files) >= int(spec["min_count"]) else "FAIL",
        }
        if row["status"] != "PASS":
            failures.append(f"{label}:artifact_class:{spec['artifact_id']}:count_{len(files)}_lt_{spec['min_count']}")
        class_rows.append(row)
    return {
        "label": label,
        "run_id": results_root.name,
        "results_root": rel(results_root, repo_root),
        "classes": class_rows,
        "files": sorted(file_rows, key=lambda item: (str(item["artifact_id"]), str(item["path"]))),
    }, failures


def check_raw_sanitization(repo_root: Path, evidence_root: Path, *, label: str) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    path = evidence_root / "raw_artifact_sanitization.json"
    report = read_json(path, failures, repo_root, f"{label} raw artifact sanitization")
    files = [row for row in report.get("files", []) if isinstance(row, dict)] if isinstance(report.get("files"), list) else []
    hash_errors: list[str] = []
    for row in files:
        file_path = row.get("path")
        if not isinstance(file_path, str) or not file_path:
            hash_errors.append("row_missing_path")
            continue
        resolved = repo_path(repo_root, Path(file_path))
        if not resolved.is_file():
            hash_errors.append(f"missing:{file_path}")
            continue
        if row.get("bytes") != resolved.stat().st_size:
            hash_errors.append(f"bytes:{file_path}")
        if row.get("sha256") != file_digest(resolved):
            hash_errors.append(f"sha256:{file_path}")
    failures.extend(f"{label}:raw_sanitization:{item}" for item in hash_errors)
    return {
        "label": label,
        "path": rel(path, repo_root),
        "present": path.is_file(),
        "schema": report.get("schema"),
        "status": report.get("status"),
        "file_count": len(files),
        "hash_errors": hash_errors,
    }, failures


def check_board_boot(repo_root: Path, run_id: str) -> dict[str, Any]:
    path = repo_root / "results" / "board" / "artix7_35t_litex" / run_id / "06_linux_boot" / "uart_linux_boot.log"
    markers = {
        "serialboot_upload_summary": False,
        "jumped_to_kernel": False,
        "linux_version": False,
        "rvmt_linux_user_pass": False,
    }
    if path.is_file():
        text = path.read_text(encoding="utf-8", errors="replace")
        markers = {
            "serialboot_upload_summary": "serialboot upload summary" in text,
            "jumped_to_kernel": "jumped to" in text,
            "linux_version": "Linux version" in text,
            "rvmt_linux_user_pass": "RVMT_LINUX_USER_PASS" in text,
        }
    return {
        "run_id": run_id,
        "path": rel(path, repo_root),
        "present": path.is_file(),
        "checks": markers,
        "status": "PASS" if path.is_file() and all(markers.values()) else "MISSING_OR_INCOMPLETE",
        "hash": file_record(path, repo_root) if path.is_file() else None,
    }


def build_tooling_provenance(repo_root: Path) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    files: list[Path] = []
    missing: list[str] = []
    for rel_path in TOOLING_PROVENANCE_PATHS:
        path = repo_root / rel_path
        if not path.is_file():
            missing.append(rel_path.as_posix())
            continue
        files.append(path)
    failures.extend(f"tooling_provenance:missing:{path}" for path in missing)
    return {
        "schema": "rvmt.35t.ccfa_style_tooling_provenance.v1",
        "status": "PASS" if not missing else "FAIL",
        "class_digest": class_digest(files, repo_root),
        "files": [file_record(path, repo_root) for path in files],
        "missing": missing,
    }, failures


def check_claim_boundary(repo_root: Path, mirai_gate: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    manifest = read_json(repo_root / REAL_MALWARE_MANIFEST, failures, repo_root, "real-malware manifest")
    payload_dirs = (
        Path("experiments/linux_behavior/real_malware/samples"),
        Path("experiments/linux_behavior/real_malware/payloads"),
        Path("experiments/linux_behavior/real_malware/binaries"),
    )
    payload_findings: list[str] = []
    for directory in payload_dirs:
        root = repo_root / directory
        if not root.exists():
            continue
        payload_findings.extend(rel(path, repo_root) for path in root.rglob("*") if path.is_file())
    checks = {
        "manifest_schema": manifest.get("schema") == "rvmt.real_malware.validation_manifest.v1",
        "sample_class_real_malware": manifest.get("sample_class") == "real_malware",
        "default_disabled": manifest.get("default_enabled") is False,
        "external_quarantine_hash_only": manifest.get("payload_policy") == "external_quarantine_hash_only",
        "repository_payloads_disallowed": manifest.get("repository_payloads_allowed") is False,
        "no_repository_payload_files": not payload_findings,
        "manual_real_malware_results_absent": not (repo_root / REAL_MALWARE_RESULTS_ROOT).exists(),
    }
    excluded = mirai_gate.get("checks", {}).get("network_optional_samples_excluded") is True
    checks["mirai_network_optional_samples_excluded"] = excluded
    failures.extend(f"claim_boundary:{key}" for key, ok in checks.items() if not ok)
    return {
        "schema": "rvmt.35t.ccfa_style_claim_boundary.v1",
        "status": "PASS" if not failures else "FAIL",
        "external_payload_gate_status": "REAL_MALWARE_VALIDATION_BLOCKED_NO_RUN_ARTIFACTS",
        "true_real_malware_gate_status": "REAL_MALWARE_VALIDATION_BLOCKED_NO_RUN_ARTIFACTS",
        "checks": checks,
        "real_malware_manifest": rel(repo_root / REAL_MALWARE_MANIFEST, repo_root),
        "real_malware_results_root": rel(repo_root / REAL_MALWARE_RESULTS_ROOT, repo_root),
        "repository_payload_findings": payload_findings,
        "non_claims": NON_CLAIMS,
    }, failures


def reproduction_commands(
    surrogate_run_id: str,
    mirai_run_id: str,
    primary_run_id: str,
    evidence_root: Path,
) -> list[str]:
    expected_mirai = ",".join(EXPECTED_MIRAI_SAMPLES)
    surrogate_sample_args = " ".join(f"--sample {sample}" for sample in EXPECTED_SURROGATE_SAMPLES)
    mirai_sample_args = " ".join(f"--sample {sample}" for sample in EXPECTED_MIRAI_SAMPLES)
    return [
        "uv run python tools/experiment_35t.py --run-id "
        f"{surrogate_run_id} --runtime-order abba --reps 5 --trace-records 512 "
        f"--trace-profile p0a_syscall_drop --include-surrogate-samples {surrogate_sample_args}",
        "uv run python tools/check_real_malware_surrogate_gate.py --run-id "
        f"{surrogate_run_id} --no-write",
        "uv run rvmt explain:35t --flow --run-id " + surrogate_run_id,
        "uv run python tools/experiment_35t.py --run-id "
        f"{mirai_run_id} --runtime-order abba --reps 5 --trace-records 512 "
        "--trace-profile p0a_syscall_drop --trace-profile-policy 35t_small_capacity "
        f"--include-extension-samples {mirai_sample_args}",
        "uv run python tools/check_35t_extension_gate.py --run-id "
        f"{mirai_run_id} --expected-samples {expected_mirai} --no-write",
        "uv run rvmt explain:35t --flow --run-id " + mirai_run_id,
        "# Expected boundary: direct external-quarantine payload execution remains separate unless gated run artifacts exist.",
        "uv run python tools/check_real_malware_validation_gate.py --no-write",
        "uv run python tools/check_35t_real_malware_derived_lineage.py --no-write",
        "uv run python tools/check_35t_behavior_baseline_comparison.py --no-write",
        "uv run python tools/check_35t_surrogate_boot_provenance.py --no-write",
        "uv run python tools/check_35t_claim_evidence_table.py --no-write",
        "uv run python tools/check_35t_artifact_package_readiness.py --no-write",
        "uv run python tools/check_35t_evidence_consistency.py --no-write",
        "uv run python tools/check_35t_ccfa_evidence_chain.py --no-write",
        f"# Primary 35T evidence root: docs/results/evidence/{primary_run_id}",
        f"# Strengthened evidence root: {evidence_root.as_posix()}",
    ]


def build_report(
    repo_root_arg: Path,
    evidence_root_arg: Path,
    *,
    primary_run_id: str,
    surrogate_run_id: str,
    mirai_run_id: str,
) -> dict[str, Any]:
    repo_root = repo_root_arg.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    primary_results = repo_root / DEFAULT_RESULTS_BASE / primary_run_id
    surrogate_results = repo_root / DEFAULT_RESULTS_BASE / surrogate_run_id
    mirai_results = repo_root / DEFAULT_RESULTS_BASE / mirai_run_id
    primary_evidence = repo_root / DEFAULT_EVIDENCE_BASE / primary_run_id
    surrogate_evidence = repo_root / DEFAULT_EVIDENCE_BASE / surrogate_run_id
    mirai_evidence = repo_root / DEFAULT_EVIDENCE_BASE / mirai_run_id
    lineage_evidence = repo_root / LINEAGE_EVIDENCE_ROOT
    baseline_evidence = repo_root / BASELINE_EVIDENCE_ROOT
    boot_evidence = repo_root / BOOT_EVIDENCE_ROOT
    claim_table_evidence = repo_root / CLAIM_TABLE_EVIDENCE_ROOT

    failures: list[str] = []
    limitations: list[dict[str, str]] = []

    primary_snapshot, snapshot_failures = check_evidence_snapshot(repo_root, primary_evidence, label="primary_35t")
    failures.extend(snapshot_failures)
    surrogate_snapshot, snapshot_failures = check_evidence_snapshot(repo_root, surrogate_evidence, label="surrogate")
    failures.extend(snapshot_failures)
    mirai_snapshot, snapshot_failures = check_evidence_snapshot(repo_root, mirai_evidence, label="mirai_reference")
    failures.extend(snapshot_failures)
    lineage_snapshot, snapshot_failures = check_evidence_snapshot(
        repo_root, lineage_evidence, label="real_malware_derived_lineage"
    )
    failures.extend(snapshot_failures)
    baseline_snapshot, snapshot_failures = check_evidence_snapshot(
        repo_root, baseline_evidence, label="real_malware_derived_baseline_comparison"
    )
    failures.extend(snapshot_failures)
    boot_snapshot, snapshot_failures = check_evidence_snapshot(
        repo_root, boot_evidence, label="surrogate_boot_provenance"
    )
    failures.extend(snapshot_failures)
    claim_table_snapshot, snapshot_failures = check_evidence_snapshot(
        repo_root, claim_table_evidence, label="paper_claim_evidence_table"
    )
    failures.extend(snapshot_failures)
    if (evidence_root / "evidence_manifest.json").is_file():
        ccfa_snapshot, snapshot_failures = check_evidence_snapshot(repo_root, evidence_root, label="ccfa_strong_chain")
        failures.extend(snapshot_failures)
    else:
        ccfa_snapshot = {
            "label": "ccfa_strong_chain",
            "path": rel(evidence_root, repo_root),
            "present": False,
            "schema": None,
            "status": None,
            "claim_level": None,
            "artifact_count": 0,
            "hash_errors": [],
        }

    surrogate_config, config_failures = check_run_config(
        repo_root,
        surrogate_results,
        label="surrogate",
        expected_samples=EXPECTED_SURROGATE_SAMPLES,
        expected_kind="surrogate",
    )
    failures.extend(config_failures)
    mirai_config, config_failures = check_run_config(
        repo_root,
        mirai_results,
        label="mirai_reference",
        expected_samples=EXPECTED_MIRAI_SAMPLES,
        expected_kind="mirai",
    )
    failures.extend(config_failures)

    surrogate_gate, gate_failures = check_gate_report(
        repo_root,
        surrogate_evidence,
        label="surrogate",
        gate_file="gate_report.json",
        expected_samples=EXPECTED_SURROGATE_SAMPLES,
        expected_status="PASS",
    )
    failures.extend(gate_failures)
    mirai_gate, gate_failures = check_gate_report(
        repo_root,
        mirai_evidence,
        label="mirai_reference",
        gate_file="extension_gate_check.json",
        expected_samples=EXPECTED_MIRAI_SAMPLES,
        expected_status="PASS",
    )
    failures.extend(gate_failures)

    surrogate_metrics, metric_failures = check_metrics(repo_root, surrogate_results, label="surrogate")
    failures.extend(metric_failures)
    mirai_metrics, metric_failures = check_metrics(repo_root, mirai_results, label="mirai_reference")
    failures.extend(metric_failures)
    lineage_check = read_json(
        lineage_evidence / "real_malware_derived_lineage_check.json",
        failures,
        repo_root,
        "real-malware-derived lineage check",
    )
    baseline_comparison = read_json(
        baseline_evidence / "baseline_comparison.json",
        failures,
        repo_root,
        "real-malware-derived baseline comparison",
    )
    surrogate_boot_provenance = read_json(
        boot_evidence / "surrogate_boot_provenance.json",
        failures,
        repo_root,
        "surrogate boot provenance",
    )
    paper_claim_table = read_json(
        claim_table_evidence / "claim_evidence_table.json",
        failures,
        repo_root,
        "paper claim evidence table",
    )

    surrogate_sanitization, sanitize_failures = check_raw_sanitization(
        repo_root, surrogate_evidence, label="surrogate"
    )
    failures.extend(sanitize_failures)
    mirai_sanitization, sanitize_failures = check_raw_sanitization(
        repo_root, mirai_evidence, label="mirai_reference"
    )
    failures.extend(sanitize_failures)

    surrogate_inventory, inventory_failures = build_run_hash_inventory(
        repo_root,
        surrogate_results,
        label="surrogate",
        sample_count=len(EXPECTED_SURROGATE_SAMPLES),
    )
    failures.extend(inventory_failures)
    mirai_inventory, inventory_failures = build_run_hash_inventory(
        repo_root,
        mirai_results,
        label="mirai_reference",
        sample_count=len(EXPECTED_MIRAI_SAMPLES),
    )
    failures.extend(inventory_failures)

    claim_boundary, boundary_failures = check_claim_boundary(repo_root, mirai_gate)
    failures.extend(boundary_failures)

    board_boot = {
        "mirai_reference": check_board_boot(repo_root, mirai_run_id),
        "surrogate": check_board_boot(repo_root, surrogate_run_id),
    }
    if board_boot["mirai_reference"]["status"] != "PASS":
        failures.append("mirai_reference:board_boot_provenance_missing_or_incomplete")
    if board_boot["surrogate"]["status"] != "PASS":
        limitations.append(
            {
                "id": "surrogate_boot_log_not_run_scoped",
                "impact": (
                    "Surrogate run has board/raw UART and sample artifacts, but no separate Linux boot log under "
                    "results/board for that run_id; see "
                    f"{BOOT_EVIDENCE_ROOT.as_posix()} for the recorded blocker and capture runbook."
                ),
            }
        )

    tooling_provenance, tooling_failures = build_tooling_provenance(repo_root)
    failures.extend(tooling_failures)

    limitations.extend(
        [
            {
                "id": "external_payload_execution_deferred",
                "impact": "The strong chain supports real-malware-derived behavior traceability and rule-detection/audit feasibility; uncontrolled or network-enabled external payload execution remains outside the completed claim.",
            },
            {
                "id": "p0a_arg_mem_disabled",
                "impact": "The p0a trace profile proves syscall/control-flow behavior but intentionally does not provide complete fd/path or process-tree reconstruction.",
            },
            {
                "id": "public_package_lightweight",
                "impact": "Raw UART, decoded traces, ELFs, and boot logs are hash-linked local artifacts; public release remains hash/sanitized unless raw escrow is approved.",
            },
        ]
    )

    artifact_hash_manifest = {
        "schema": "rvmt.35t.ccfa_style_artifact_hash_manifest.v1",
        "generated_utc": utc_now(),
        "scope": EXPECTED_SCOPE,
        "runs": [surrogate_inventory, mirai_inventory],
        "board_boot": board_boot,
        "tooling_provenance": tooling_provenance,
        "lineage_evidence": {
            "path": rel(lineage_evidence, repo_root),
            "status": lineage_check.get("status"),
            "row_count": lineage_check.get("row_count"),
            "row_pass_count": lineage_check.get("row_pass_count"),
        },
        "baseline_comparison_evidence": {
            "path": rel(baseline_evidence, repo_root),
            "status": baseline_comparison.get("status"),
            "row_count": baseline_comparison.get("row_count"),
            "row_pass_count": baseline_comparison.get("row_pass_count"),
        },
        "surrogate_boot_provenance": {
            "path": rel(boot_evidence, repo_root),
            "status": surrogate_boot_provenance.get("status"),
            "run_scoped_boot_status": surrogate_boot_provenance.get("run_scoped_boot", {}).get("status")
            if isinstance(surrogate_boot_provenance.get("run_scoped_boot"), dict)
            else None,
            "next_capture_target": surrogate_boot_provenance.get("next_capture_target"),
        },
        "paper_claim_evidence_table": {
            "path": rel(claim_table_evidence, repo_root),
            "status": paper_claim_table.get("status"),
            "deferred_claims": paper_claim_table.get("deferred_claims"),
        },
    }

    commands = reproduction_commands(surrogate_run_id, mirai_run_id, primary_run_id, evidence_root_arg)
    checks = {
        "primary_evidence_manifest_hashes": not primary_snapshot.get("hash_errors"),
        "surrogate_evidence_manifest_hashes": not surrogate_snapshot.get("hash_errors"),
        "mirai_evidence_manifest_hashes": not mirai_snapshot.get("hash_errors"),
        "real_malware_derived_lineage_manifest_hashes": not lineage_snapshot.get("hash_errors"),
        "real_malware_derived_baseline_manifest_hashes": not baseline_snapshot.get("hash_errors"),
        "surrogate_boot_provenance_manifest_hashes": not boot_snapshot.get("hash_errors"),
        "paper_claim_table_manifest_hashes": not claim_table_snapshot.get("hash_errors"),
        "real_malware_derived_lineage_pass": lineage_check.get("status")
        == "REAL_MALWARE_DERIVED_SURROGATE_LINEAGE_PASS"
        and lineage_check.get("row_count") == lineage_check.get("row_pass_count")
        and int(lineage_check.get("row_count") or 0) >= 6,
        "real_malware_derived_baseline_pass": baseline_comparison.get("status")
        == "REAL_MALWARE_DERIVED_BASELINE_COMPARISON_PASS"
        and baseline_comparison.get("row_count") == baseline_comparison.get("row_pass_count")
        and int(baseline_comparison.get("row_count") or 0) >= 6,
        "surrogate_boot_provenance_recorded": surrogate_boot_provenance.get("status")
        in {
            "SURROGATE_BOOT_PROVENANCE_PASS",
            "SURROGATE_BOOT_PROVENANCE_DEFERRED_RUN_SCOPED_LOG_MISSING",
        },
        "paper_claim_table_pass": paper_claim_table.get("status")
        in {
            "PAPER_CLAIM_EVIDENCE_TABLE_PASS",
            "PAPER_CLAIM_EVIDENCE_TABLE_PASS_WITH_SURROGATE_BOOT_DEFERRED",
        },
        "ccfa_snapshot_manifest_hashes": not ccfa_snapshot.get("hash_errors"),
        "surrogate_run_config": all(surrogate_config.get("checks", {}).values()),
        "mirai_run_config": all(mirai_config.get("checks", {}).values()),
        "surrogate_gate_pass": surrogate_gate.get("status") == "PASS"
        and all(sample["status"] == "PASS" for sample in surrogate_gate.get("samples", [])),
        "mirai_gate_pass": mirai_gate.get("status") == "PASS"
        and all(sample["status"] == "PASS" for sample in mirai_gate.get("samples", [])),
        "surrogate_metrics_zero_fp_fn": all(surrogate_metrics.get("checks", {}).values()),
        "mirai_metrics_zero_fp_fn": all(mirai_metrics.get("checks", {}).values()),
        "raw_sanitization_hashes": not surrogate_sanitization.get("hash_errors")
        and not mirai_sanitization.get("hash_errors"),
        "raw_to_derived_hash_inventory": not inventory_failures,
        "tooling_provenance_hashes": tooling_provenance.get("status") == "PASS",
        "claim_boundary": claim_boundary.get("status") == "PASS",
        "mirai_board_boot_provenance": board_boot["mirai_reference"]["status"] == "PASS",
    }
    failures.extend(f"top_level:{key}" for key, ok in checks.items() if not ok)

    return {
        "schema": SCHEMA,
        "status": PASS_STATUS if not failures else FAIL_STATUS,
        "generated_utc": utc_now(),
        "repo_root": repo_root.as_posix(),
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "ccfa_positioning": (
            "CCF-A-style strong evidence-chain discipline: machine-checkable provenance, claim boundaries, "
            "hash-linked raw-to-derived artifacts, reproducibility commands, and explicit limitations. "
            "This is not a venue acceptance guarantee."
        ),
        "evidence_root": rel(evidence_root, repo_root),
        "run_ids": {
            "primary_35t": primary_run_id,
            "surrogate": surrogate_run_id,
            "mirai_reference": mirai_run_id,
        },
        "checks": checks,
        "snapshots": {
            "primary_35t": primary_snapshot,
            "surrogate": surrogate_snapshot,
            "mirai_reference": mirai_snapshot,
            "real_malware_derived_lineage": lineage_snapshot,
            "real_malware_derived_baseline_comparison": baseline_snapshot,
            "surrogate_boot_provenance": boot_snapshot,
            "paper_claim_evidence_table": claim_table_snapshot,
            "ccfa_strong_chain": ccfa_snapshot,
        },
        "real_malware_derived_lineage": lineage_check,
        "real_malware_derived_baseline_comparison": baseline_comparison,
        "surrogate_boot_provenance": surrogate_boot_provenance,
        "paper_claim_evidence_table": paper_claim_table,
        "run_configs": {
            "surrogate": surrogate_config,
            "mirai_reference": mirai_config,
        },
        "gates": {
            "surrogate": surrogate_gate,
            "mirai_reference": mirai_gate,
        },
        "metrics": {
            "surrogate": surrogate_metrics,
            "mirai_reference": mirai_metrics,
        },
        "raw_artifact_sanitization": {
            "surrogate": surrogate_sanitization,
            "mirai_reference": mirai_sanitization,
        },
        "artifact_hash_manifest": artifact_hash_manifest,
        "claim_boundary": claim_boundary,
        "reproduction_commands": commands,
        "limitations": limitations,
        "non_claims": NON_CLAIMS,
        "failures": sorted(set(failures)),
    }


def render_chain_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# 35T CCF-A-style Strong Evidence Chain",
        "",
        f"Status: {report['status']}",
        "",
        f"Scope: {report['scope']}",
        "",
        "This package is a CCF-A-style evidence-chain discipline artifact, not an acceptance guarantee.",
        "",
        "## Run IDs",
        "",
    ]
    for key, value in report["run_ids"].items():
        lines.append(f"- {key}: `{value}`")
    lines += ["", "## Top-level Checks", ""]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Gate Summary", ""]
    for label, gate in report["gates"].items():
        lines.append(f"- {label}: {gate.get('status')} ({len(gate.get('samples', []))} samples)")
    lines += ["", "## Evidence Extensions", ""]
    lines.append(
        "- real_malware_derived_lineage: "
        f"{report['real_malware_derived_lineage'].get('status')} "
        f"({report['real_malware_derived_lineage'].get('row_pass_count')}/"
        f"{report['real_malware_derived_lineage'].get('row_count')} rows)"
    )
    lines.append(
        "- real_malware_derived_baseline_comparison: "
        f"{report['real_malware_derived_baseline_comparison'].get('status')} "
        f"({report['real_malware_derived_baseline_comparison'].get('row_pass_count')}/"
        f"{report['real_malware_derived_baseline_comparison'].get('row_count')} rows)"
    )
    lines.append("- surrogate_boot_provenance: " f"{report['surrogate_boot_provenance'].get('status')}")
    lines.append("- paper_claim_evidence_table: " f"{report['paper_claim_evidence_table'].get('status')}")
    lines += ["", "## Claim Boundary", ""]
    for key, ok in report["claim_boundary"]["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Limitations", ""]
    lines.extend(f"- {row['id']}: {row['impact']}" for row in report["limitations"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def render_claim_boundary_markdown(boundary: dict[str, Any]) -> str:
    lines = [
        "# 35T Claim Boundary",
        "",
        f"Status: {boundary['status']}",
        "",
        f"External-payload gate status: {boundary.get('external_payload_gate_status', boundary['true_real_malware_gate_status'])}",
        "",
        "## Checks",
        "",
    ]
    for key, ok in boundary["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in boundary["non_claims"])
    return "\n".join(lines) + "\n"


def render_reproduction_commands(commands: list[str]) -> str:
    lines = ["# 35T Evidence-chain Reproduction Commands", ""]
    for command in commands:
        if command.startswith("#"):
            lines.append(command)
        else:
            lines += ["```powershell", command, "```"]
    return "\n".join(lines) + "\n"


def render_reviewer_checklist(report: dict[str, Any]) -> str:
    items = [
        "Open `ccfa_evidence_chain.json` and confirm top-level status is PASS_WITH_BOUNDED_LIMITATIONS.",
        "Confirm `claim_boundary.json` keeps external-quarantine payload execution separate from the completed real-malware-derived behavior claim.",
        "Verify `artifact_hash_manifest.json` class digests for raw UART, decoded trace, semantic, audit, alignment, and build provenance files.",
        "Confirm the real-malware-derived lineage package has 6/6 PASS rows and keeps payload-equivalence, network, and accuracy boundaries.",
        "Confirm `baseline_comparison.json` has 6/6 PASS rows for host, strace, QEMU, and board medians.",
        "Confirm `claim_evidence_table.json` marks completed paper claims as PASS and the surrogate boot claim as DEFERRED when run-scoped boot is absent.",
        "Review `surrogate_boot_provenance.json` and `boot_capture_runbook.md` before claiming run-scoped surrogate boot provenance.",
        "Run the no-write checker command from `reproduction_commands.md`.",
        "Run the two gate checkers and both `rvmt explain:35t --flow` commands for the surrogate and Mirai-reference runs.",
        "Review limitations before using the evidence as a paper claim.",
    ]
    lines = ["# Reviewer Checklist", ""]
    lines.extend(f"- [ ] {item}" for item in items)
    lines += ["", "## Current Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def render_readme(report: dict[str, Any]) -> str:
    return (
        "# 35T CCF-A-style Strong Evidence Chain\n\n"
        f"Status: {report['status']}\n\n"
        "This directory consolidates the primary 35T package, the real-malware-surrogate board run, "
        "the non-network Mirai-reference board run, the real-malware-derived behavior lineage matrix, "
        "and the external-payload boundary into one "
        "machine-checkable evidence chain.\n\n"
        "Files:\n\n"
        "- `ccfa_evidence_chain.json` / `.md`: top-level evidence-chain report.\n"
        "- `artifact_hash_manifest.json`: hash-linked local raw-to-derived artifact inventory.\n"
        "- `claim_boundary.json` / `.md`: external-payload, safety-control, and network-exclusion boundary.\n"
        "- linked lineage package: `docs/results/evidence/35t-real-malware-derived-lineage-20260524`.\n"
        "- linked baseline package: `docs/results/evidence/35t-real-malware-derived-baseline-comparison-20260524`.\n"
        "- linked surrogate boot package: `docs/results/evidence/35t-surrogate-boot-provenance-20260524`.\n"
        "- linked paper claim table: `docs/results/evidence/35t-paper-claim-evidence-table-20260524`.\n"
        "- `reproduction_commands.md`: commands reviewers can rerun.\n"
        "- `reviewer_checklist.md`: concise review path.\n\n"
        "The package intentionally records bounded limitations while allowing the paper to use the completed "
        "real-malware-derived rows as behavior traceability and rule-detection/audit feasibility evidence.\n"
    )


def snapshot_manifest(repo_root: Path, evidence_root: Path, report: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for name in SNAPSHOT_FILES:
        path = evidence_root / name
        if not path.is_file():
            continue
        rows.append({"artifact": name, "committed_path": rel(path, repo_root), **file_record(path, repo_root)})
    run_ids = report.get("run_ids", {}) if isinstance(report.get("run_ids"), dict) else {}
    return {
        "schema": "rvmt.35t.ccfa_style_evidence_snapshot.v1",
        "status": "PASS",
        "generated_utc": utc_now(),
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "source_reports": [
            f"docs/results/evidence/{run_ids.get('primary_35t', PRIMARY_RUN_ID)}",
            f"docs/results/evidence/{run_ids.get('surrogate', SURROGATE_RUN_ID)}",
            f"docs/results/evidence/{run_ids.get('mirai_reference', MIRAI_RUN_ID)}",
            LINEAGE_EVIDENCE_ROOT.as_posix(),
            BASELINE_EVIDENCE_ROOT.as_posix(),
            BOOT_EVIDENCE_ROOT.as_posix(),
            CLAIM_TABLE_EVIDENCE_ROOT.as_posix(),
        ],
        "committed_artifacts": rows,
        "non_claims": NON_CLAIMS,
    }


def write_outputs(report: dict[str, Any], repo_root: Path, evidence_root_arg: Path) -> None:
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    evidence_root.mkdir(parents=True, exist_ok=True)
    write_json(evidence_root / "ccfa_evidence_chain.json", report)
    write_json(evidence_root / "artifact_hash_manifest.json", report["artifact_hash_manifest"])
    write_json(evidence_root / "claim_boundary.json", report["claim_boundary"])
    (evidence_root / "ccfa_evidence_chain.md").write_text(
        render_chain_markdown(report), encoding="utf-8", newline="\n"
    )
    (evidence_root / "claim_boundary.md").write_text(
        render_claim_boundary_markdown(report["claim_boundary"]), encoding="utf-8", newline="\n"
    )
    (evidence_root / "reproduction_commands.md").write_text(
        render_reproduction_commands(report["reproduction_commands"]), encoding="utf-8", newline="\n"
    )
    (evidence_root / "reviewer_checklist.md").write_text(
        render_reviewer_checklist(report), encoding="utf-8", newline="\n"
    )
    (evidence_root / "README.md").write_text(render_readme(report), encoding="utf-8", newline="\n")
    write_json(evidence_root / "evidence_manifest.json", snapshot_manifest(repo_root, evidence_root, report))


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        a = root / "a.txt"
        b = root / "b.txt"
        a.write_text("alpha\n", encoding="utf-8")
        b.write_text("beta\n", encoding="utf-8")
        digest1 = class_digest([a, b], root)
        digest2 = class_digest([b, a], root)
        if digest1 != digest2:
            raise AssertionError("class_digest must be order-independent")
        row = {"artifact": "a.txt", "committed_path": "a.txt", "bytes": a.stat().st_size, "sha256": file_digest(a)}
        if manifest_hash_errors(root, [row]):
            raise AssertionError("valid manifest row reported an error")
        row["sha256"] = "0" * 64
        if not manifest_hash_errors(root, [row]):
            raise AssertionError("invalid manifest row did not report an error")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--primary-run-id", default=PRIMARY_RUN_ID)
    parser.add_argument("--surrogate-run-id", default=SURROGATE_RUN_ID)
    parser.add_argument("--mirai-run-id", default=MIRAI_RUN_ID)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        print("SELF_TEST_PASS")
        return 0
    repo_root = args.repo_root.resolve()
    report = build_report(
        repo_root,
        args.evidence_root,
        primary_run_id=args.primary_run_id,
        surrogate_run_id=args.surrogate_run_id,
        mirai_run_id=args.mirai_run_id,
    )
    if not args.no_write:
        write_outputs(report, repo_root, args.evidence_root)
    print(report["status"])
    print(f"evidence_root={report['evidence_root']}")
    if report["failures"]:
        for failure in report["failures"]:
            print(f"FAIL {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
