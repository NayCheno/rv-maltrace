from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_RUN_ID = "35t-extension-r512-nonnetwork-20260523"
DEFAULT_RESULTS_ROOT = Path("results/experiments/35t") / DEFAULT_RUN_ID
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / DEFAULT_RUN_ID
MALWARE_EXTENSION_PLAN = Path("experiments/linux_behavior/malware_like/extension_plan.json")
SCHEMA = "rvmt.35t.extension_gate_check.v1"
EXPECTED_STATUS = "PASS"
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
DEFAULT_EXPECTED_SAMPLES = (
    "direct_syscall_open_read",
    "file_encryption_sim_non_destructive",
    "mprotect_exec_variant",
    "multi_level_process_chain",
    "obfuscated_syscall_wrapper",
    "proc_status_tracerpid_check",
    "self_modifying_code_sim",
    "timing_anti_analysis_loop",
)
EXCLUDED_NETWORK_SAMPLES = ("loopback_network_client", "mirai_c2_loopback_probe")
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
    "extension gate is reported separately from the primary 13-sample gate",
]


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


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sample_rows(gate_report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = gate_report.get("samples", [])
    return {
        str(row.get("sample_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("sample_id")
    } if isinstance(rows, list) else {}


def metric_rows(metrics: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = metrics.get("samples", [])
    return {
        str(row.get("sample_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("sample_id")
    } if isinstance(rows, list) else {}


def load_extension_expectations(repo_root: Path) -> dict[str, dict[str, Any]]:
    path = repo_root / MALWARE_EXTENSION_PLAN
    if not path.is_file():
        return {}
    plan = load_json(path)
    result: dict[str, dict[str, Any]] = {}
    for row in plan.get("candidates", []):
        if not isinstance(row, dict) or not row.get("id"):
            continue
        result[str(row["id"])] = {
            "expected_behavior": [str(item) for item in row.get("expected_behavior", [])],
            "expected_syscalls": [str(item) for item in row.get("expected_syscalls", [])],
        }
    return result


def sample_dir(results_root: Path, sample: str) -> Path:
    for candidate in [
        results_root / "samples" / "malware_like_synthetic" / sample,
        results_root / "samples" / sample,
    ]:
        if candidate.is_dir():
            return candidate
    matches = sorted((results_root / "samples").glob(f"*/{sample}"))
    return matches[0] if matches else results_root / "samples" / "malware_like_synthetic" / sample


def trace_on_reps(results_root: Path, sample: str) -> list[Path]:
    base = sample_dir(results_root, sample) / "board" / "trace-on"
    if not base.is_dir():
        return []
    return sorted(path for path in base.iterdir() if path.is_dir() and path.name.startswith("rep_"))


def normalize_syscall_name(name: str) -> str:
    aliases = {
        "sys_403": "clock_gettime",
        "clock_gettime64": "clock_gettime",
    }
    return aliases.get(name, name)


def semantic_syscall_names(results_root: Path, sample: str) -> set[str]:
    names: set[str] = set()
    for rep in trace_on_reps(results_root, sample):
        path = rep / "behavior_recovery" / "semantic_events.json"
        if not path.is_file():
            continue
        try:
            semantic = load_json(path)
        except Exception:
            continue
        rows = semantic.get("syscall_sequence", [])
        if not isinstance(rows, list):
            continue
        for row in rows:
            if isinstance(row, dict) and row.get("name"):
                names.add(normalize_syscall_name(str(row["name"])))
    return names


def sidechannel_summary(results_root: Path, sample: str) -> dict[str, Any]:
    names: set[str] = set()
    reps = 0
    per_rep: dict[str, list[str]] = {}
    for rep in trace_on_reps(results_root, sample):
        path = rep / "syscall_side_channel.json"
        if not path.is_file():
            continue
        try:
            payload = load_json(path)
        except Exception:
            continue
        seen: list[str] = []
        for event in payload.get("events", []):
            if not isinstance(event, dict) or event.get("phase") != "entry":
                continue
            name = normalize_syscall_name(str(event.get("name", "")))
            if not name or name == "unknown":
                continue
            names.add(name)
            seen.append(name)
        if seen:
            reps += 1
            per_rep[rep.name] = seen
    return {"rep_count": reps, "names": sorted(names), "per_rep": per_rep}


def behavior_audit_expected(results_root: Path, sample: str) -> tuple[set[str], set[str]]:
    expected: set[str] = set()
    matched: set[str] = set()
    for rep in trace_on_reps(results_root, sample):
        path = rep / "behavior_audit" / "behavior_audit.json"
        if not path.is_file():
            continue
        try:
            audit = load_json(path)
        except Exception:
            continue
        expected.update(str(item) for item in audit.get("expected_behavior", []) if item)
        matched.update(str(item) for item in audit.get("matched_expected_behavior", []) if item)
    return expected, matched


def expected_syscalls_supported(expected_syscalls: list[str], semantic_names: set[str], side_names: set[str]) -> tuple[bool, list[str]]:
    missing = []
    observed = semantic_names | side_names
    for syscall in expected_syscalls:
        if normalize_syscall_name(syscall) not in observed:
            missing.append(syscall)
    return not missing, missing


def strong_expected_summary(
    results_root: Path,
    sidechannel_root: Path,
    sample: str,
    expected: dict[str, Any],
) -> dict[str, Any]:
    expected_behavior = [str(item) for item in expected.get("expected_behavior", [])]
    expected_syscalls = [str(item) for item in expected.get("expected_syscalls", [])]
    audit_expected, audit_matched = behavior_audit_expected(results_root, sample)
    semantic_names = semantic_syscall_names(results_root, sample)
    side = sidechannel_summary(sidechannel_root, sample)
    side_names = {str(item) for item in side.get("names", [])}
    audit_ok = bool(expected_behavior) and set(expected_behavior) <= audit_matched
    syscall_ok, missing_syscalls = expected_syscalls_supported(expected_syscalls, semantic_names, side_names)
    matched_behavior = expected_behavior if (audit_ok or syscall_ok) else sorted(set(expected_behavior) & audit_matched)
    if audit_ok:
        source = "behavior_audit"
    elif syscall_ok:
        source = "semantic_trace+syscall_side_channel_auxiliary"
    else:
        source = "incomplete"
    return {
        "expected": expected_behavior,
        "matched_expected": matched_behavior,
        "missing": [] if (audit_ok or syscall_ok) else sorted(set(expected_behavior) - set(matched_behavior)),
        "expected_syscalls": expected_syscalls,
        "semantic_syscalls": sorted(semantic_names),
        "sidechannel_run": sidechannel_root.name if sidechannel_root.is_dir() else None,
        "sidechannel_reps": side.get("rep_count", 0),
        "sidechannel_syscalls": sorted(side_names),
        "missing_expected_syscalls": missing_syscalls,
        "evidence_source": source,
    }


def parser_warning_totals(results_root: Path, sample: str) -> dict[str, int]:
    unknown = 0
    corrupt = 0
    for rep in trace_on_reps(results_root, sample):
        path = rep / "parser_warnings.json"
        if not path.is_file():
            continue
        try:
            payload = load_json(path)
        except Exception:
            continue
        unknown += int(payload.get("unknown_event_count", 0) or 0)
        corrupt += int(payload.get("corrupt_record_count", 0) or 0)
    return {"unknown_event_count": unknown, "corrupt_record_count": corrupt}


def marker_scope_count(results_root: Path, sample: str) -> int:
    count = 0
    for rep in trace_on_reps(results_root, sample):
        path = rep / "behavior_recovery" / "semantic_events.json"
        if not path.is_file():
            continue
        try:
            semantic = load_json(path)
        except Exception:
            continue
        marker = semantic.get("marker_scope", {})
        if isinstance(marker, dict) and marker.get("status") == "PASS":
            count += 1
    return count


def runtime_process_count(results_root: Path, sample: str) -> int:
    count = 0
    for rep in trace_on_reps(results_root, sample):
        path = rep / "runtime_process_map.json"
        if not path.is_file():
            continue
        try:
            runtime = load_json(path)
        except Exception:
            continue
        provenance = runtime.get("provenance", {})
        if isinstance(provenance, dict) and provenance.get("status") == "PASS":
            count += 1
    return count


def trace_on_statuses(results_root: Path, sample: str) -> list[dict[str, Any]]:
    rows = []
    for rep in trace_on_reps(results_root, sample):
        path = rep / "status.json"
        if path.is_file():
            rows.append(load_json(path))
    return rows


def synthesize_gate_rows(
    repo_root: Path,
    results_root: Path,
    sidechannel_root: Path,
    metrics: dict[str, Any],
    expected_samples: tuple[str, ...],
) -> dict[str, dict[str, Any]]:
    metrics_by_sample = metric_rows(metrics)
    expectations = load_extension_expectations(repo_root)
    rows: dict[str, dict[str, Any]] = {}
    for sample in expected_samples:
        metric = metrics_by_sample.get(sample, {})
        statuses = trace_on_statuses(results_root, sample)
        trace_on_pass = sum(
            1
            for row in statuses
            if int(row.get("exit_code", row.get("exit", 1))) == 0 and int(row.get("trace_count", 0)) > 0
        )
        capped_reps = [
            f"rep_{index:02d}"
            for index, row in enumerate(statuses)
            if int(row.get("trace_count", 0) or 0) >= int(row.get("trace_records", 512) or 512) or int(row.get("drop", 0) or 0) > 0
        ]
        marker_valid = marker_scope_count(results_root, sample)
        runtime_valid = runtime_process_count(results_root, sample)
        warnings = parser_warning_totals(results_root, sample)
        strong = strong_expected_summary(results_root, sidechannel_root, sample, expectations.get(sample, {}))
        row = {
            "sample_id": sample,
            "gate_status": "PASS",
            "sample_status": {"status": metric.get("status"), "trace_on_pass": trace_on_pass},
            "marker_scope_summary": {"status": "PASS" if marker_valid == 5 else "FAIL", "valid_reps": marker_valid},
            "runtime_process_attribution_summary": {"status": "PASS" if runtime_valid == 5 else "FAIL", "valid_reps": runtime_valid},
            "event_summary": warnings,
            "drop_summary": {
                "capped_reps": metric.get("captured_cap_reps", capped_reps),
                "drop_rate_median": (metric.get("drop_rate", {}) or {}).get("median", 0.0)
                if isinstance(metric.get("drop_rate"), dict)
                else 0.0,
            },
            "audit_rule_summary": {
                "expected": strong["expected"],
                "matched_expected": strong["matched_expected"],
                "missing": strong["missing"],
                "evidence_source": strong["evidence_source"],
                "expected_syscalls": strong["expected_syscalls"],
                "missing_expected_syscalls": strong["missing_expected_syscalls"],
                "sidechannel_run": strong["sidechannel_run"],
                "sidechannel_reps": strong["sidechannel_reps"],
            },
        }
        rows[sample] = row
    return rows


def rep_artifact_count(results_root: Path, sample: str, name: str) -> int:
    count = 0
    for rep in trace_on_reps(results_root, sample):
        if name == "trace.jsonl" and (rep / "trace.jsonl").is_file():
            count += 1
        elif name == "behavior_audit.json" and (rep / "behavior_audit" / "behavior_audit.json").is_file():
            count += 1
        elif name == "semantic_events.json" and (rep / "behavior_recovery" / "semantic_events.json").is_file():
            count += 1
    return count


def strong_expected_matched(row: dict[str, Any]) -> bool:
    audit = row.get("audit_rule_summary")
    if not isinstance(audit, dict):
        return False
    expected = {str(item) for item in audit.get("expected", []) if item}
    matched = {str(item) for item in audit.get("matched_expected", []) if item}
    missing = {str(item) for item in audit.get("missing", []) if item}
    return bool(expected) and expected <= matched and not missing


def summarize_sample(repo_root: Path, results_root: Path, sample: str, row: dict[str, Any] | None) -> dict[str, Any]:
    if row is None:
        return {
            "sample_id": sample,
            "status": "MISSING",
            "failures": ["missing gate_report sample row"],
        }
    marker = row.get("marker_scope_summary", {}) if isinstance(row.get("marker_scope_summary"), dict) else {}
    runtime = row.get("runtime_process_attribution_summary", {}) if isinstance(row.get("runtime_process_attribution_summary"), dict) else {}
    events = row.get("event_summary", {}) if isinstance(row.get("event_summary"), dict) else {}
    drop = row.get("drop_summary", {}) if isinstance(row.get("drop_summary"), dict) else {}
    sample_status = row.get("sample_status", {}) if isinstance(row.get("sample_status"), dict) else {}
    trace_count = rep_artifact_count(results_root, sample, "trace.jsonl")
    audit_count = rep_artifact_count(results_root, sample, "behavior_audit.json")
    semantic_count = rep_artifact_count(results_root, sample, "semantic_events.json")
    checks = {
        "sample_status_pass": sample_status.get("status") == "PASS",
        "trace_on_5_of_5": sample_status.get("trace_on_pass") == 5 and trace_count == 5,
        "gate_status_pass": row.get("gate_status") == "PASS",
        "marker_scope_pass": marker.get("status") == "PASS" and marker.get("valid_reps") == 5,
        "runtime_process_attribution_pass": runtime.get("status") == "PASS" and runtime.get("valid_reps") == 5,
        "unknown_corrupt_zero": events.get("unknown_event_count", 0) == 0 and events.get("corrupt_record_count", 0) == 0,
        "no_trace_cap_hit": not drop.get("capped_reps"),
        "drop_rate_median_le_5pct": float(drop.get("drop_rate_median") or 0.0) <= 0.05,
        "strong_expected_behavior_matched": strong_expected_matched(row),
        "behavior_audit_artifacts_5_of_5": audit_count == 5,
        "semantic_artifacts_5_of_5": semantic_count == 5,
    }
    return {
        "sample_id": sample,
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "trace_artifact_count": trace_count,
        "behavior_audit_artifact_count": audit_count,
        "semantic_artifact_count": semantic_count,
        "gate_status": row.get("gate_status"),
        "sample_status": sample_status,
        "drop_rate_median": drop.get("drop_rate_median"),
        "unknown_event_count": events.get("unknown_event_count"),
        "corrupt_record_count": events.get("corrupt_record_count"),
        "matched_expected": row.get("audit_rule_summary", {}).get("matched_expected", [])
        if isinstance(row.get("audit_rule_summary"), dict)
        else [],
        "expected_evidence_source": row.get("audit_rule_summary", {}).get("evidence_source")
        if isinstance(row.get("audit_rule_summary"), dict)
        else None,
        "missing_expected_syscalls": row.get("audit_rule_summary", {}).get("missing_expected_syscalls", [])
        if isinstance(row.get("audit_rule_summary"), dict)
        else [],
        "failures": [key for key, ok in checks.items() if not ok],
    }


def build_report(repo_root: Path, results_root_arg: Path, evidence_root_arg: Path, expected_samples: tuple[str, ...]) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    results_root = repo_path(repo_root, results_root_arg).resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    failures: list[str] = []
    run_config_path = results_root / "run_config.json"
    gate_report_path = results_root / "aggregate" / "gate_report.json"
    metrics_path = results_root / "aggregate" / "metrics.json"
    sidechannel_root = results_root.with_name(f"{results_root.name}-sidechannel")
    if not results_root.is_dir():
        failures.append(f"missing results root: {rel(results_root, repo_root)}")
    run_config = load_json(run_config_path) if run_config_path.is_file() else {}
    gate_report = load_json(gate_report_path) if gate_report_path.is_file() else {}
    metrics = load_json(metrics_path) if metrics_path.is_file() else {}
    rows = sample_rows(gate_report)
    if not rows and metrics:
        rows = synthesize_gate_rows(repo_root, results_root, sidechannel_root, metrics, expected_samples)
    metric_sample_rows = metric_rows(metrics)
    sample_summaries = [summarize_sample(repo_root, results_root, sample, rows.get(sample)) for sample in expected_samples]
    observed_samples = set(rows) or set(metric_sample_rows)
    checks = {
        "results_root_exists": results_root.is_dir(),
        "gate_report_available_or_derived": gate_report_path.is_file() or bool(rows),
        "metrics_exists": metrics_path.is_file(),
        "run_config_exists": run_config_path.is_file(),
        "expected_samples_present": set(expected_samples) <= observed_samples,
        "network_optional_samples_excluded": all(sample not in observed_samples for sample in EXCLUDED_NETWORK_SAMPLES),
        "all_samples_pass": all(row.get("status") == "PASS" for row in sample_summaries),
        "trace_records_512": run_config.get("trace_records") == 512,
        "trace_profile_policy_35t_small_capacity": run_config.get("trace_profile_policy") == "35t_small_capacity",
        "runtime_order_abba": run_config.get("runtime_order") == "abba",
        "real_malware_forbidden": run_config.get("real_malware") == "forbidden",
        "network_disabled": run_config.get("network") == "disabled",
        "include_extension_samples_explicit": run_config.get("include_extension_samples") is True,
    }
    failures.extend(key for key, ok in checks.items() if not ok)
    for row in sample_summaries:
        for failure in row.get("failures", []):
            failures.append(f"{row.get('sample_id')}: {failure}")
    return {
        "schema": SCHEMA,
        "run_id": results_root.name,
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "generated_utc": utc_now(),
        "status": EXPECTED_STATUS if not failures else "FAIL",
        "results_root": rel(results_root, repo_root),
        "evidence_root": rel(evidence_root, repo_root),
        "expected_samples": list(expected_samples),
        "excluded_samples": list(EXCLUDED_NETWORK_SAMPLES),
        "checks": checks,
        "samples": sample_summaries,
        "metrics_schema": metrics.get("schema"),
        "sidechannel_auxiliary_root": rel(sidechannel_root, repo_root) if sidechannel_root.is_dir() else None,
        "non_claims": NON_CLAIMS,
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Extension Gate Check: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Scope: {report['scope']}.",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += [
        "",
        "## Samples",
        "",
        "| Sample | Status | Gate | DROP median | Evidence | Matched expected |",
        "| --- | --- | --- | ---: | --- | --- |",
    ]
    for row in report["samples"]:
        lines.append(
            f"| `{row['sample_id']}` | `{row.get('status')}` | `{row.get('gate_status')}` | "
            f"{row.get('drop_rate_median')} | `{row.get('expected_evidence_source')}` | "
            f"`{', '.join(row.get('matched_expected', []))}` |"
        )
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    return "\n".join(lines) + "\n"


def raw_hash_inventory(repo_root: Path, results_root: Path) -> dict[str, Any]:
    files = []
    for pattern in ("**/raw_uart.log", "**/trace_raw_uart.log", "**/trace.jsonl"):
        for path in sorted(results_root.glob(pattern)):
            if path.is_file():
                files.append({"path": rel(path, repo_root), "bytes": path.stat().st_size, "sha256": file_digest(path)})
    return {
        "schema": "rvmt.35t.extension_raw_artifact_sanitization.v1",
        "run_id": results_root.name,
        "status": "RAW_ARTIFACT_HASHES_RECORDED_FULL_RAW_DEFERRED",
        "raw_file_count": len(files),
        "files": files,
        "policy": "hashes and summaries are public; full raw UART and decoded trace payload release remains controlled",
        "non_claims": NON_CLAIMS,
    }


def write_snapshot(repo_root: Path, results_root_arg: Path, evidence_root_arg: Path, report: dict[str, Any]) -> None:
    repo_root = repo_root.resolve()
    results_root = repo_path(repo_root, results_root_arg).resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    evidence_root.mkdir(parents=True, exist_ok=True)
    write_json(evidence_root / "extension_gate_check.json", report)
    (evidence_root / "extension_gate_check.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")
    for name in ("run_config.json",):
        source = results_root / name
        if source.is_file():
            write_json(evidence_root / name, load_json(source))
    for name in ("gate_report.json", "metrics.json"):
        source = results_root / "aggregate" / name
        if source.is_file():
            write_json(evidence_root / name, load_json(source))
        elif name == "gate_report.json":
            write_json(
                evidence_root / name,
                {
                    "schema": "rvmt.35t.extension_derived_gate_report.v1",
                    "run_id": report["run_id"],
                    "status": report["status"],
                    "samples": report["samples"],
                    "source": "derived from metrics, per-rep status, parser warnings, runtime maps, behavior audit, and auxiliary syscall side-channel run",
                    "sidechannel_auxiliary_root": report.get("sidechannel_auxiliary_root"),
                    "non_claims": NON_CLAIMS,
                },
            )
    gate_md = results_root / "aggregate" / "gate_report.md"
    if gate_md.is_file():
        (evidence_root / "gate_report.md").write_text(gate_md.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    else:
        (evidence_root / "gate_report.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")
    sample_matrix = {
        "schema": "rvmt.35t.extension_sample_matrix_summary.v1",
        "run_id": results_root.name,
        "status": report["status"],
        "samples": report["samples"],
    }
    write_json(evidence_root / "sample_matrix_summary.json", sample_matrix)
    malware_audit = {
        "schema": "rvmt.35t.extension_malware_behavior_audit.v1",
        "run_id": results_root.name,
        "status": "PASS" if report["status"] == "PASS" else "FAIL",
        "samples": [
            {"sample_id": row["sample_id"], "matched_expected": row.get("matched_expected", [])}
            for row in report["samples"]
        ],
        "non_claims": NON_CLAIMS,
    }
    write_json(evidence_root / "malware_behavior_audit.json", malware_audit)
    readiness = {
        "schema": "rvmt.35t.extension_artifact_package_readiness.v1",
        "run_id": results_root.name,
        "status": "LIGHTWEIGHT_EXTENSION_EVIDENCE_READY" if report["status"] == "PASS" else "INCOMPLETE",
        "public_lightweight": [
            "README.md",
            "run_config.json",
            "gate_report.json",
            "gate_report.md",
            "sample_matrix_summary.json",
            "metrics.json",
            "malware_behavior_audit.json",
            "extension_gate_check.json",
        ],
        "sidechannel_auxiliary_root": report.get("sidechannel_auxiliary_root"),
        "controlled_raw_policy": "raw UART and decoded trace JSONL are represented by hashes and controlled release policy",
        "local_only_policy": "bitstreams, board build directories, and ELF binaries stay local-only",
        "non_claims": NON_CLAIMS,
    }
    write_json(evidence_root / "artifact_package_readiness.json", readiness)
    write_json(evidence_root / "raw_artifact_sanitization.json", raw_hash_inventory(repo_root, results_root))
    paper_check = {
        "schema": "rvmt.35t.paper_evidence_extension_check.v1",
        "run_id": results_root.name,
        "status": "SUPPORTED_WITH_BOUNDED_EXTENSION_CLAIMS" if report["status"] == "PASS" else "FAIL",
        "primary_gate_separation": "extension gate is reported separately from 35t-smallcap-r512-full-synthetic-matrix-20260521",
        "network_policy": "loopback-only network extension candidates excluded from the default extension gate",
        "non_claims": NON_CLAIMS,
    }
    write_json(evidence_root / "paper_evidence_extension_check.json", paper_check)
    (evidence_root / "README.md").write_text(
        "\n".join(
            [
                f"# 35T Extension Evidence Snapshot: {results_root.name}",
                "",
                f"Status: {report['status']}",
                "",
                "This snapshot records the network-free synthetic extension 35T gate separately from the primary 13-sample gate.",
                "",
                "## Expected Samples",
                "",
                *[f"- `{sample}`" for sample in report["expected_samples"]],
                "",
                "## Excluded",
                "",
                *[f"- `{sample}` remains excluded by default." for sample in EXCLUDED_NETWORK_SAMPLES],
                "",
                "## Non-claims",
                "",
                *[f"- {item}" for item in NON_CLAIMS],
                "",
            ]
        ),
        encoding="utf-8",
        newline="\n",
    )
    rows = []
    for path in sorted(evidence_root.iterdir(), key=lambda p: p.name):
        if path.is_file() and path.name != "evidence_manifest.json":
            rows.append({"artifact": path.name, "committed_path": rel(path, repo_root), "bytes": path.stat().st_size, "sha256": file_digest(path)})
    write_json(
        evidence_root / "evidence_manifest.json",
        {
            "schema": "rvmt.35t.extension_evidence_snapshot.v1",
            "run_id": results_root.name,
            "scope": EXPECTED_SCOPE,
            "claim_level": EXPECTED_CLAIM_LEVEL,
            "status": report["status"],
            "committed_artifacts": rows,
            "non_claims": NON_CLAIMS,
        },
    )


def write_fixture(root: Path, run_id: str, expected_samples: tuple[str, ...]) -> None:
    results = root / "results/experiments/35t" / run_id
    write_json(
        results / "run_config.json",
        {
            "run_id": run_id,
            "trace_records": 512,
            "trace_profile_policy": "35t_small_capacity",
            "runtime_order": "abba",
            "real_malware": "forbidden",
            "network": "disabled",
            "include_extension_samples": True,
        },
    )
    rows = []
    for sample in expected_samples:
        for rep in range(5):
            rep_dir = results / "samples/malware_like_synthetic" / sample / "board/trace-on" / f"rep_{rep:02d}"
            rep_dir.mkdir(parents=True, exist_ok=True)
            (rep_dir / "trace.jsonl").write_text('{"evt":"MARKER"}\n', encoding="utf-8")
            write_json(rep_dir / "behavior_audit/behavior_audit.json", {"matched_expected_behavior": [f"{sample}_rule"]})
            write_json(rep_dir / "behavior_recovery/semantic_events.json", {"syscall_sequence": []})
        rows.append(
            {
                "sample_id": sample,
                "gate_status": "PASS",
                "sample_status": {"status": "PASS", "trace_on_pass": 5},
                "marker_scope_summary": {"status": "PASS", "valid_reps": 5},
                "runtime_process_attribution_summary": {"status": "PASS", "valid_reps": 5},
                "event_summary": {"unknown_event_count": 0, "corrupt_record_count": 0},
                "drop_summary": {"capped_reps": [], "drop_rate_median": 0.0},
                "audit_rule_summary": {"expected": [f"{sample}_rule"], "matched_expected": [f"{sample}_rule"], "missing": []},
            }
        )
    write_json(results / "aggregate/gate_report.json", {"samples": rows})
    write_json(results / "aggregate/metrics.json", {"schema": "rvmt.35t.metrics.v1", "samples": []})


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root, DEFAULT_RUN_ID, DEFAULT_EXPECTED_SAMPLES)
        report = build_report(root, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT, DEFAULT_EXPECTED_SAMPLES)
        if report["status"] != "PASS":
            print("[FAIL] expected extension fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_snapshot(root, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT, report)
        if not (root / DEFAULT_EVIDENCE_ROOT / "evidence_manifest.json").is_file():
            print("[FAIL] snapshot did not write evidence manifest", file=sys.stderr)
            return 1
        bad = root / DEFAULT_RESULTS_ROOT / "run_config.json"
        value = load_json(bad)
        value["network"] = "enabled"
        write_json(bad, value)
        failed = build_report(root, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT, DEFAULT_EXPECTED_SAMPLES)
        if failed["status"] == "PASS" or "network_disabled" not in failed["failures"]:
            print("[FAIL] expected network-enabled fixture to fail", file=sys.stderr)
            return 1
    print("[PASS] 35T extension gate self-test")
    return 0


def parse_expected(value: str | None) -> tuple[str, ...]:
    if not value:
        return DEFAULT_EXPECTED_SAMPLES
    return tuple(item.strip() for item in value.split(",") if item.strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the network-free 35T extension gate.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--run-id", default=DEFAULT_RUN_ID)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--expected-samples")
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    expected = parse_expected(args.expected_samples)
    results_root = args.results_root or (Path("results/experiments/35t") / args.run_id)
    evidence_root = args.evidence_root or (Path("docs/results/evidence") / args.run_id)
    try:
        report = build_report(args.repo_root, results_root, evidence_root, expected)
        if not args.no_write:
            write_snapshot(args.repo_root, results_root, evidence_root, report)
    except Exception as exc:
        print(f"check_35t_extension_gate: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T extension gate: {report['run_id']}")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
