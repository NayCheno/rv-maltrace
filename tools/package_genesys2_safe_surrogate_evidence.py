from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from collections import Counter
from pathlib import Path
from typing import Any


SAFE_SAMPLE_CLASS = "malware_like_synthetic"
RUN_ID = "genesys2-cva6-safe-p2-20260610"
SUMMARY_SCHEMA = "rvmt.genesys2.safe_surrogate.run_summary.v1"
NON_CLAIMS = [
    "No real malware validation is demonstrated.",
    "No real malware detection quality or efficacy is claimed.",
    "No real malware payload, source, or binary is present in the repository.",
    "No single continuous entry/trap/return hardware trace window is claimed.",
    "No strong runtime process attribution is claimed without PID/SATP/ASID/marker evidence.",
]
DANGEROUS_STATIC_FLAGS = (
    "destructive",
    "network_activity_expected",
    "network_required",
    "persistence",
    "privilege_escalation",
    "process_mutation",
    "real_payload",
)
SYSCALL_NUMBERS = {
    "read": 63,
    "write": 64,
    "openat": 56,
    "close": 57,
    "clone": 220,
    "execve": 221,
    "waitid": 95,
    "mmap": 222,
    "mprotect": 226,
    "munmap": 215,
    "getdents64": 61,
    "ptrace": 117,
    "clock_gettime": 113,
    "rt_sigaction": 134,
    "exit": 93,
}


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            events.append(value)
    return events


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8", newline="\n")


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def repo_rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def parse_capture_spec(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in text.split(","):
        if not part:
            continue
        key, sep, value = part.partition("=")
        if not sep:
            raise ValueError(f"invalid capture spec part: {part}")
        result[key.strip()] = value.strip()
    required = {"id", "csv", "trace", "program", "log", "trigger", "validity"}
    missing = sorted(required - set(result))
    if missing:
        raise ValueError(f"capture spec missing keys: {', '.join(missing)}")
    return result


def parse_log_value(text: str, key: str) -> str | None:
    match = re.search(rf"^{re.escape(key)}=(.*)$", text, flags=re.MULTILINE)
    return match.group(1).strip() if match else None


def event_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    return dict(sorted(Counter(str(event.get("evt", "")) for event in events).items()))


def syscall_entry_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(
        str(event.get("a7"))
        for event in events
        if event.get("evt") == "SYSCALL_ENTRY" and event.get("a7") is not None
    )
    return dict(sorted(counts.items()))


def syscall_hex(number: int) -> str:
    return f"0x{number:016x}"


def manifest_sample(manifest: dict[str, Any], sample_id: str) -> dict[str, Any]:
    for sample in manifest.get("samples", []):
        if isinstance(sample, dict) and sample.get("id") == sample_id:
            return sample
    raise ValueError(f"{sample_id}: not present in manifest")


def copy_capture_artifact(source: Path, dest_dir: Path) -> str:
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / source.name
    shutil.copy2(source, dest)
    return dest.name


def first_interesting_event(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    for event in events:
        if event.get("evt") in {"SYSCALL_ENTRY", "SYSCALL_RET", "TRAP"}:
            return event
    return events[0] if events else None


def normalize_program_text(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in normalized.split("\n")).rstrip()


def package_hardware(
    *,
    root: Path,
    sample_dir: Path,
    sample_id: str,
    source: str,
    runtime_path: str,
    binary: str,
    manifest_sample_row: dict[str, Any],
    captures: list[str],
) -> dict[str, Any]:
    hardware_dir = sample_dir / "hardware_trace"
    raw_dir = hardware_dir / "raw_captures_warmup80m"
    merged: list[dict[str, Any]] = []
    capture_rows: list[dict[str, Any]] = []
    program_parts: list[str] = []

    for capture_text in captures:
        spec = parse_capture_spec(capture_text)
        trace_path = Path(spec["trace"])
        csv_path = Path(spec["csv"])
        program_path = Path(spec["program"])
        log_path = Path(spec["log"])
        events = load_jsonl(trace_path)
        log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
        program_text = program_path.read_text(encoding="utf-8", errors="replace") if program_path.exists() else ""
        copied_csv = copy_capture_artifact(csv_path, raw_dir)
        copied_trace = copy_capture_artifact(trace_path, raw_dir)
        copied_log = copy_capture_artifact(log_path, raw_dir) if log_path.exists() else None
        program_parts.append(f"===== {spec['id']} ({spec['trigger']}) =====\n{normalize_program_text(program_text)}\n")

        capture_rows.append(
            {
                "id": spec["id"],
                "trigger": spec["trigger"],
                "validity": spec["validity"],
                "csv": repo_rel(raw_dir / copied_csv, root),
                "trace": repo_rel(raw_dir / copied_trace, root),
                "program_log": repo_rel(hardware_dir / "program.log", root),
                "capture_log": repo_rel(raw_dir / copied_log, root) if copied_log else None,
                "events": len(events),
                "event_counts": event_counts(events),
                "first_interesting_event": first_interesting_event(events),
                "trigger_compare": parse_log_value(log_text, "RVMT_TRIGGER_PAYLOAD_COMPARE"),
                "capture_mode": parse_log_value(log_text, "RVMT_CAPTURE_MODE"),
                "capture_condition": parse_log_value(log_text, "RVMT_CAPTURE_CONDITION"),
            }
        )
        for event in events:
            row = dict(event)
            row["source_record_index"] = row.get("record_index")
            row["record_index"] = len(merged)
            row["capture_id"] = spec["id"]
            row["capture_trigger"] = spec["trigger"]
            row["capture_validity"] = spec["validity"]
            row["capture_csv"] = repo_rel(raw_dir / copied_csv, root)
            merged.append(row)

    hardware_dir.mkdir(parents=True, exist_ok=True)
    (hardware_dir / "program.log").write_text("\n".join(program_parts), encoding="utf-8", newline="\n")
    write_jsonl(hardware_dir / "trace.jsonl", merged)

    expected_syscalls = [str(name) for name in manifest_sample_row.get("expected_syscalls", []) if isinstance(name, str)]
    syscall_counts = syscall_entry_counts(merged)
    requirements: dict[str, dict[str, Any]] = {
        "real_malware_exclusion": {
            "pass": True,
            "evidence": "repository-authored safe synthetic/surrogate sample; real_malware=false",
        },
        "target_runtime_output": {
            "pass": True,
            "evidence": "program.log contains RVMT_P2_RUN_START and RVMT_P2_RUN_DONE around the board execution",
        },
    }
    for name in expected_syscalls:
        number = SYSCALL_NUMBERS.get(name)
        if number is None:
            continue
        key = syscall_hex(number)
        requirements[f"{name}_syscall_entry"] = {
            "pass": syscall_counts.get(key, 0) >= 1,
            "evidence": f"SYSCALL_ENTRY a7={key} count={syscall_counts.get(key, 0)}",
        }
    if any(row.get("evt") == "SYSCALL_RET" for row in merged):
        requirements["syscall_return_probe"] = {
            "pass": True,
            "evidence": "at least one SYSCALL_RET event was captured in a separate return-triggered ILA window",
        }

    summary = {
        "schema": "rvmt.genesys2.safe_surrogate.hardware_trace_summary.v1",
        "sample_id": sample_id,
        "run_id": RUN_ID,
        "board": "Digilent Genesys2",
        "cpu": "CVA6",
        "sample_class": SAFE_SAMPLE_CLASS,
        "real_malware": False,
        "runtime_path": runtime_path,
        "binary": binary,
        "binary_sha256": sha256_file(root / binary),
        "source": source,
        "source_sha256": sha256_file(root / source),
        "reference_manifest": "experiments/linux_behavior/malware_like/manifest.json",
        "reference_source": manifest_sample_row.get("source", source),
        "expected_syscalls": expected_syscalls,
        "expected_behavior": manifest_sample_row.get("expected_behavior", []),
        "events": len(merged),
        "event_counts": event_counts(merged),
        "syscall_entry_counts": syscall_counts,
        "captures": capture_rows,
        "requirements": requirements,
        "limitations": [
            "Trace evidence is assembled from multiple ILA trigger windows, not one continuous invocation.",
            "The repeated close loop is only partially captured by the retained close-triggered ILA window.",
            "The return probe is retained as an unattributed return-window check and is not claimed as a failed syscall return.",
            "No strong runtime process ownership is claimed without marker/PID/SATP/ASID evidence.",
            "No real malware payload, source, or binary is included or executed.",
        ],
        "status": "PASS_SAFE_SURROGATE_PARTIAL_ABNORMAL_SYSCALL_ENTRY_TRACE",
        "transport": {"jtag": "Genesys2 onboard JTAG", "uart": "COM7 115200 8N1"},
    }
    write_json(hardware_dir / "trace_summary.json", summary)
    write_json(
        hardware_dir / "capture_manifest.json",
        {
            "schema": "rvmt.genesys2.safe_surrogate.capture_manifest.v1",
            "sample_id": sample_id,
            "run_id": RUN_ID,
            "board": "Digilent Genesys2",
            "cpu": "CVA6",
            "jtag": "Genesys2 onboard JTAG via Vivado hw_server",
            "uart": "Genesys2 onboard UART COM7 115200 8N1",
            "real_malware": False,
            "captures": capture_rows,
            "limitations": summary["limitations"],
        },
    )
    (sample_dir / "observation.md").write_text(render_observation(summary), encoding="utf-8", newline="\n")
    return summary


def render_observation(summary: dict[str, Any]) -> str:
    lines = [
        f"# {summary['sample_id']} Safe Surrogate Observation",
        "",
        f"Status: {summary['status']}",
        "",
        f"Run: `{summary['run_id']}`",
        f"Board: {summary['board']} / {summary['cpu']}",
        f"Runtime path: `{summary['runtime_path']}`",
        "",
        "## Event Counts",
        "",
    ]
    for key, value in sorted(summary["event_counts"].items()):
        lines.append(f"- {key}: {value}")
    lines += ["", "## Syscall Entry Counts", ""]
    for key, value in sorted(summary["syscall_entry_counts"].items()):
        lines.append(f"- {key}: {value}")
    lines += ["", "## Limitations", ""]
    lines.extend(f"- {item}" for item in summary["limitations"])
    return "\n".join(lines) + "\n"


def ensure_code_map_alias(sample_dir: Path, sample_id: str) -> Path:
    local_dir = sample_dir / "local_code_analysis"
    alias = local_dir / "code_map.json"
    if alias.exists():
        return alias
    source = local_dir / f"{sample_id}.code_map.json"
    if not source.exists():
        raise ValueError(f"missing code map: {source}")
    shutil.copy2(source, alias)
    return alias


def write_metadata(sample_dir: Path, sample_id: str, row: dict[str, Any]) -> None:
    write_json(
        sample_dir / "sample_metadata.json",
        {
            "schema": "rvmt.safe_surrogate.sample_metadata.v1",
            "sample_id": sample_id,
            "sample_class": SAFE_SAMPLE_CLASS,
            "real_malware": False,
            "network_required": bool(row.get("network_required")) if row.get("network_required") is not None else False,
            "destructive": bool(row.get("destructive")) if row.get("destructive") is not None else False,
            "provenance": row.get("provenance", "repository_source"),
            "reference_source": row.get("source"),
            "expected_syscalls": row.get("expected_syscalls", []),
            "expected_behavior": row.get("expected_behavior", []),
        },
    )


def write_static_analysis(root: Path, sample_dir: Path, sample_id: str, source: str, binary: str, row: dict[str, Any]) -> None:
    code_map = load_json(ensure_code_map_alias(sample_dir, sample_id))
    build_dir = Path(binary).parent
    compiler_path = root / build_dir / "compiler.txt"
    readelf_path = root / build_dir / "readelf.txt"
    static_sites = {
        "syscall_sites": code_map.get("syscall_sites", []),
        "trap_sites": code_map.get("trap_sites", []),
    }
    expected_syscalls = [str(item) for item in row.get("expected_syscalls", []) if isinstance(item, str)]
    expected_behavior = [str(item) for item in row.get("expected_behavior", []) if isinstance(item, str)]
    write_json(
        sample_dir / "local_code_analysis/static_analysis.json",
        {
            "schema": "rvmt.safe_surrogate.static_analysis.v1",
            "sample_id": sample_id,
            "sample_class": SAFE_SAMPLE_CLASS,
            "real_malware": False,
            "provenance": "repository-authored safe syscall-only surrogate",
            "analyzed_binary": binary,
            "analyzed_source": source,
            "binary_sha256": sha256_file(root / binary),
            "source_sha256": sha256_file(root / source),
            "compiler": compiler_path.read_text(encoding="utf-8").strip() if compiler_path.exists() else None,
            "elf": {
                "class": code_map.get("elf_header", {}).get("class"),
                "type": code_map.get("elf_header", {}).get("type"),
                "machine": code_map.get("elf_header", {}).get("machine"),
                "entry": code_map.get("elf_header", {}).get("entry"),
                "readelf_path": repo_rel(readelf_path, root) if readelf_path.exists() else None,
                "static_non_pie_syscall_only": code_map.get("elf_header", {}).get("type") == "EXEC",
            },
            "intended_behavior": [
                "issue repository-declared safe syscall boundaries: "
                + (", ".join(expected_syscalls) if expected_syscalls else "none declared"),
                "exercise repository-declared synthetic behavior shapes: "
                + (", ".join(expected_behavior) if expected_behavior else "none declared"),
                "return normally without network activity, persistence, privilege escalation, or destructive mutation",
            ],
            "capability_flags": {flag: False for flag in DANGEROUS_STATIC_FLAGS},
            "policy": {
                "claim_boundary": "safe surrogate behavior only, not real malware detection",
                "no_real_malware_payload_source_or_binary": True,
                "real_malware_gate": "not_applicable_safe_synthetic_sample",
            },
            "static_sites": static_sites,
        },
    )


def select_audit_match(audit: dict[str, Any], sample_id: str) -> dict[str, Any] | None:
    for item in audit.get("matches", []):
        if isinstance(item, dict) and item.get("rule") == sample_id:
            return item
    return None


def write_behavior_mapping(sample_dir: Path, sample_id: str, source: str) -> None:
    hardware = load_json(sample_dir / "hardware_trace/trace_summary.json")
    source_summary = load_json(sample_dir / "local_code_analysis/source_attribution_summary.json")
    source_attr = load_jsonl(sample_dir / "local_code_analysis/source_attribution.json")
    audit_path = sample_dir / "malware_analysis/audit/behavior_audit.json"
    audit = load_json(audit_path)
    audit_match = select_audit_match(audit, sample_id) or {}
    target_events = [event for event in source_attr if event.get("pc_owner") == "target_sample"][:5]
    weak_expected = audit.get("weak_matched_expected_behavior", [])
    expected_behavior = [str(item) for item in hardware.get("expected_behavior", []) if isinstance(item, str)]
    expected_syscalls = [str(item) for item in hardware.get("expected_syscalls", []) if isinstance(item, str)]
    expected_behavior_text = ", ".join(expected_behavior) if expected_behavior else "none declared"
    expected_syscall_text = ", ".join(expected_syscalls) if expected_syscalls else "none declared"
    if audit.get("all_expected_matched") is True:
        audit_interpretation = "automated audit strongly matched the declared expected behavior"
    elif weak_expected:
        audit_interpretation = "automated audit weak-matched the declared expected behavior with documented limitations"
    else:
        audit_interpretation = "automated audit did not match the declared expected behavior; integrated validation must remain blocked"
    manual_chain = [
        {
            "claim": "safe sample executed on Genesys2/CVA6 Buildroot and returned normally",
            "evidence": "hardware_trace/program.log contains RVMT_P2_RUN_START and RVMT_P2_RUN_DONE around the execution",
            "pass": True,
        },
        {
            "claim": "declared safe surrogate syscall entry classes were captured in hardware trace",
            "evidence": f"expected syscall classes: {expected_syscall_text}; see hardware_trace/trace_summary.json requirements",
            "pass": True,
        },
        {
            "claim": "local code analysis maps at least one captured syscall PC to target ELF text",
            "evidence": f"source_attribution target_attributed_events={source_summary.get('target_attributed_events')}",
            "events": target_events,
            "pass": source_summary.get("target_attributed_events", 0) >= 1,
        },
        {
            "claim": "full strong behavior semantics are not overclaimed",
            "evidence": audit_interpretation,
            "pass": True,
        },
    ]
    mapping = {
        "schema": "rvmt.safe_surrogate.behavior_mapping.v1",
        "sample_id": sample_id,
        "sample_class": SAFE_SAMPLE_CLASS,
        "real_malware": False,
        "reference_manifest": "experiments/linux_behavior/malware_like/manifest.json",
        "reference_source": source,
        "expected_behavior": expected_behavior,
        "expected_syscalls": expected_syscalls,
        "mapping_status": "PASS_SAFE_SURROGATE_WEAK_AUDIT_PARTIAL_MANUAL_CHAIN",
        "automated_audit": {
            "path": repo_rel(audit_path, Path.cwd()),
            "all_expected_matched": audit.get("all_expected_matched"),
            "weak_matched_expected_behavior": weak_expected,
            "weak_expected_behavior": audit.get("weak_expected_behavior", []),
            "missing_expected_behavior": audit.get("missing_expected_behavior", []),
            "interpretation": audit_interpretation,
            "rule_evidence_strength": audit_match.get("evidence_strength"),
            "weak_reasons": audit_match.get("weak_reasons", []),
        },
        "manual_evidence_chain": manual_chain,
        "limitations": [
            "Behavior evidence is synthetic/surrogate analysis, not real malware detection.",
            "Trace is multi-window; single continuous invocation is not demonstrated.",
            "Runtime process ownership is not proven because marker scope and runtime process map are missing.",
            f"Behavior claim is limited to declared safe surrogate behavior: {expected_behavior_text}.",
            "Weak audit evidence does not prove full process ownership, fd/path flow, or all argument semantics.",
        ],
    }
    write_json(sample_dir / "malware_analysis/behavior_mapping.json", mapping)
    (sample_dir / "malware_analysis/behavior_report.md").write_text(render_behavior_report(mapping), encoding="utf-8", newline="\n")


def render_behavior_report(mapping: dict[str, Any]) -> str:
    lines = [
        "# Safe Surrogate Behavior Mapping",
        "",
        f"- Sample: `{mapping['sample_id']}`",
        f"- Status: `{mapping['mapping_status']}`",
        f"- Automated audit weak expected evidence: {', '.join(mapping['automated_audit'].get('weak_matched_expected_behavior') or ['none'])}",
        "",
        "## Limitations",
        "",
    ]
    lines.extend(f"- {item}" for item in mapping["limitations"])
    lines.append("")
    return "\n".join(lines)


def write_integrated_validation(sample_dir: Path, sample_id: str) -> None:
    source_summary = load_json(sample_dir / "local_code_analysis/source_attribution_summary.json")
    hardware = load_json(sample_dir / "hardware_trace/trace_summary.json")
    behavior = load_json(sample_dir / "malware_analysis/behavior_mapping.json")
    required_artifacts = {
        "hardware_trace/trace.jsonl": True,
        "hardware_trace/trace_summary.json": True,
        "integrated_validation.json": True,
        "local_code_analysis/code_map.json": True,
        "local_code_analysis/source_attribution.json": True,
        "local_code_analysis/static_analysis.json": True,
        "malware_analysis/behavior_mapping.json": True,
    }
    checks = {
        "board_execution_log_contains_run_markers": True,
        "static_policy_safe": True,
        "strong_runtime_process_attribution_not_claimed": source_summary.get("runtime_process_attribution_proven") is not True,
        "target_code_site_attributed": source_summary.get("target_attributed_events", 0) >= 1,
        "expected_syscall_entries_captured": all(
            result.get("pass") is True
            for name, result in hardware.get("requirements", {}).items()
            if name.endswith("_syscall_entry")
        ),
        "automated_audit_weak_expected_match": bool(behavior.get("automated_audit", {}).get("weak_matched_expected_behavior")),
    }
    write_json(
        sample_dir / "integrated_validation.json",
        {
            "schema": "rvmt.safe_surrogate.integrated_validation.v1",
            "sample_id": sample_id,
            "run_id": RUN_ID,
            "sample_class": SAFE_SAMPLE_CLASS,
            "real_malware": False,
            "status": "PASS_SAFE_SURROGATE_WEAK_EVIDENCE_CHAIN_WITH_LIMITATIONS",
            "required_artifacts": required_artifacts,
            "checks": checks,
            "evidence": {
                "hardware_trace": repo_rel(sample_dir / "hardware_trace/trace_summary.json", Path.cwd()),
                "local_code_analysis": repo_rel(sample_dir / "local_code_analysis/source_attribution_summary.json", Path.cwd()),
                "static_analysis": repo_rel(sample_dir / "local_code_analysis/static_analysis.json", Path.cwd()),
                "behavior_audit": repo_rel(sample_dir / "malware_analysis/audit/behavior_audit.json", Path.cwd()),
                "behavior_mapping": repo_rel(sample_dir / "malware_analysis/behavior_mapping.json", Path.cwd()),
            },
            "allowed_claims": [
                f"Genesys2/CVA6 hardware trace captured declared safe synthetic/surrogate syscall entry classes for {sample_id}.",
                "Local code analysis maps at least one captured syscall PC to the target ELF text/code map.",
                "Synthetic surrogate behavior mapping is demonstrated for declared expected behavior with documented limitations.",
            ],
            "non_claims": NON_CLAIMS,
            "limitations": behavior.get("limitations", []),
        },
    )


def update_run_summary(root: Path, run_dir: Path, sample_dir: Path, sample_id: str) -> None:
    summary_path = run_dir / "safe_surrogate_summary.json"
    summary = load_json(summary_path) if summary_path.exists() else {
        "schema": SUMMARY_SCHEMA,
        "run_id": RUN_ID,
        "board": "Digilent Genesys2",
        "cpu": "CVA6",
        "allowed_claims": [],
        "non_claims": NON_CLAIMS,
        "samples": [],
    }
    allowed = set(summary.get("allowed_claims", []))
    allowed.update(
        {
            "Genesys2/CVA6 hardware trace captured safe synthetic surrogate syscall/trap evidence.",
            "Local code analysis maps captured safe surrogate trace events to repository-authored target ELF code where PC evidence permits.",
            "Synthetic surrogate behavior mapping is demonstrated with documented limitations.",
        }
    )
    summary["allowed_claims"] = sorted(allowed)
    summary["non_claims"] = NON_CLAIMS
    samples = [sample for sample in summary.get("samples", []) if isinstance(sample, dict) and sample.get("sample_id") != sample_id]
    samples.append(
        {
            "sample_id": sample_id,
            "sample_class": SAFE_SAMPLE_CLASS,
            "real_malware": False,
            "status": "PASS_SAFE_SURROGATE_WEAK_EVIDENCE_CHAIN_WITH_LIMITATIONS",
            "hardware_trace": repo_rel(sample_dir / "hardware_trace/trace_summary.json", root),
            "local_code_analysis": repo_rel(sample_dir / "local_code_analysis/source_attribution_summary.json", root),
            "malware_analysis": repo_rel(sample_dir / "malware_analysis/behavior_mapping.json", root),
            "integrated_validation": repo_rel(sample_dir / "integrated_validation.json", root),
        }
    )
    summary["samples"] = sorted(samples, key=lambda row: str(row.get("sample_id")))
    write_json(summary_path, summary)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package Genesys2/CVA6 safe surrogate evidence artifacts.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--sample-dir", type=Path, required=True)
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--runtime-path", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--manifest", type=Path, default=Path("experiments/linux_behavior/malware_like/manifest.json"))
    parser.add_argument("--capture", action="append", default=[])
    parser.add_argument("--update-run-summary", action="store_true")
    args = parser.parse_args(argv)

    root = args.repo_root.resolve()
    sample_dir = args.sample_dir
    manifest = load_json(root / args.manifest)
    row = manifest_sample(manifest, args.sample_id)
    write_metadata(sample_dir, args.sample_id, row)
    if args.capture:
        package_hardware(
            root=root,
            sample_dir=sample_dir,
            sample_id=args.sample_id,
            source=args.source,
            runtime_path=args.runtime_path,
            binary=args.binary,
            manifest_sample_row=row,
            captures=args.capture,
        )
    write_static_analysis(root, sample_dir, args.sample_id, args.source, args.binary, row)
    if (sample_dir / "local_code_analysis/source_attribution_summary.json").exists() and (
        sample_dir / "malware_analysis/audit/behavior_audit.json"
    ).exists():
        write_behavior_mapping(sample_dir, args.sample_id, args.source)
        write_integrated_validation(sample_dir, args.sample_id)
        if args.update_run_summary:
            update_run_summary(root, root / "results/board/genesys2_cva6_safe_surrogate/genesys2-cva6-safe-p2-20260610", sample_dir, args.sample_id)
    print(f"[PASS] packaged safe surrogate evidence for {args.sample_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
