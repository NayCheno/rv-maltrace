from __future__ import annotations

import json
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA = "rvmt.35t.sample_explanation.v1"
SCOPE = "Artix-7 35T / LiteX / VexRiscv"
CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]
FD_PATH_SAMPLES = {
    "file_scan",
    "batch_open_read_write",
    "self_copy_sim",
    "direct_syscall_open_read",
    "obfuscated_syscall_wrapper",
    "file_encryption_sim_non_destructive",
}
PROCESS_TREE_SAMPLES = {"process_chain", "multi_level_process_chain"}
MEMORY_ANTI_ANALYSIS_SAMPLES = {
    "timing_anti_analysis_loop",
    "proc_status_tracerpid_check",
    "self_modifying_code_sim",
    "mprotect_exec_variant",
    "dynamic_executable_memory",
    "anti_debug_like",
}


@dataclass(frozen=True)
class SampleArtifacts:
    repo_root: Path
    run_id: str
    sample_id: str
    sample_class: str
    rep: str
    run_root: Path
    sample_dir: Path
    rep_dir: Path
    paths: dict[str, Path | None]
    data: dict[str, Any]
    missing_artifacts: list[str]
    warnings: list[str]


@dataclass(frozen=True)
class RunArtifacts:
    repo_root: Path
    run_id: str
    run_root: Path
    evidence_root: Path
    paths: dict[str, Path | None]
    data: dict[str, Any]
    missing_artifacts: list[str]
    warnings: list[str]


def _repo_rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _read_json(path: Path, warnings: list[str], label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        warnings.append(f"INVALID_ARTIFACT: {label}: {exc}")
        return None


def _first_existing(candidates: list[Path]) -> Path | None:
    for path in candidates:
        if path.is_file():
            return path
    return None


def _load_optional_json(
    paths: dict[str, Path | None],
    data: dict[str, Any],
    warnings: list[str],
    missing: list[str],
    label: str,
    candidates: list[Path],
) -> None:
    path = _first_existing(candidates)
    paths[label] = path
    if path is None:
        missing.append(label)
        warnings.append(f"MISSING_ARTIFACT: {label}")
        data[label] = None
        return
    data[label] = _read_json(path, warnings, label)


def _load_optional_text_summary(
    paths: dict[str, Path | None],
    data: dict[str, Any],
    warnings: list[str],
    missing: list[str],
    label: str,
    candidates: list[Path],
) -> None:
    path = _first_existing(candidates)
    paths[label] = path
    if path is None:
        missing.append(label)
        warnings.append(f"MISSING_ARTIFACT: {label}")
        data[label] = None
        return
    data[label] = _summarize_trace_jsonl(path, warnings)


def _find_sample_dir(run_root: Path, sample_id: str) -> Path:
    candidates = [
        run_root / "samples" / "malware_like_synthetic" / sample_id,
        run_root / "samples" / "benign" / sample_id,
        run_root / "samples" / sample_id,
    ]
    candidates.extend(sorted((run_root / "samples").glob(f"*/{sample_id}")))
    for path in candidates:
        if path.is_dir():
            return path
    raise FileNotFoundError(f"sample '{sample_id}' not found under {run_root / 'samples'}")


def _available_reps(sample_dir: Path) -> list[str]:
    trace_on = sample_dir / "board" / "trace-on"
    if not trace_on.is_dir():
        return []
    return sorted(path.name for path in trace_on.iterdir() if path.is_dir() and path.name.startswith("rep_"))


def _normalize_rep(rep: str) -> str:
    value = rep.strip()
    if value.startswith("rep_"):
        return value
    if value.isdigit():
        return f"rep_{int(value):02d}"
    return value


def _sample_class_from_manifest(manifest: Any, sample_id: str, sample_dir: Path) -> str:
    if isinstance(manifest, dict):
        for row in manifest.get("samples", []):
            if isinstance(row, dict) and row.get("id") == sample_id:
                return str(row.get("class") or row.get("sample_class") or manifest.get("sample_class") or sample_dir.parent.name)
    return sample_dir.parent.name


def _sample_gate(gate_report: Any, sample_id: str) -> dict[str, Any]:
    if not isinstance(gate_report, dict):
        return {}
    for row in gate_report.get("samples", []):
        if isinstance(row, dict) and row.get("sample_id") == sample_id:
            return row
    return {}


def _gate_rep_status(sample_gate: dict[str, Any], section: str, rep: str) -> str | None:
    summary = sample_gate.get(section)
    if not isinstance(summary, dict):
        return None
    for row in summary.get("reps", []):
        if isinstance(row, dict) and row.get("rep") == rep:
            status = row.get("status")
            return str(status) if status is not None else None
    return None


def _safe_int_from_rep(rep: str) -> int:
    try:
        return int(rep.rsplit("_", 1)[1])
    except Exception:
        return 9999


def _read_trace_count(path: Path | None) -> int:
    if path is None or not path.is_file():
        return 0
    try:
        with path.open(encoding="utf-8") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def _auto_select_rep(run_root: Path, sample_dir: Path, sample_id: str, gate_report: Any) -> str:
    reps = _available_reps(sample_dir)
    if not reps:
        raise FileNotFoundError(f"no trace-on rep directories found under {sample_dir}")

    sample_gate = _sample_gate(gate_report, sample_id)
    event_counts = {
        rep: _read_trace_count(sample_dir / "board" / "trace-on" / rep / "trace.jsonl")
        for rep in reps
    }
    nonzero_counts = [count for count in event_counts.values() if count > 0]
    event_median = statistics.median(nonzero_counts) if nonzero_counts else 0

    def score(rep: str) -> tuple[Any, ...]:
        rep_dir = sample_dir / "board" / "trace-on" / rep
        status = _read_json(rep_dir / "status.json", [], "status") if (rep_dir / "status.json").is_file() else {}
        alignment = (
            _read_json(rep_dir / "alignment" / "alignment.json", [], "alignment")
            if (rep_dir / "alignment" / "alignment.json").is_file()
            else {}
        )
        audit = (
            _read_json(rep_dir / "behavior_audit" / "behavior_audit.json", [], "behavior_audit")
            if (rep_dir / "behavior_audit" / "behavior_audit.json").is_file()
            else {}
        )
        gate_pass = sample_gate.get("gate_status") == "PASS" and isinstance(status, dict) and status.get("status") == "PASS"
        marker_pass = _gate_rep_status(sample_gate, "marker_scope_summary", rep) == "PASS"
        runtime_pass = _gate_rep_status(sample_gate, "runtime_process_attribution_summary", rep) == "PASS"
        expected_ok = bool(audit.get("all_expected_matched")) if isinstance(audit, dict) else False
        matched_count = len(audit.get("matched_expected_behavior", [])) if isinstance(audit, dict) and isinstance(audit.get("matched_expected_behavior"), list) else 0
        drop_rate = float(alignment.get("drop_rate") or 0.0) if isinstance(alignment, dict) else 1.0
        count = event_counts.get(rep, 0)
        return (
            1 if gate_pass else 0,
            1 if marker_pass else 0,
            1 if runtime_pass else 0,
            1 if expected_ok else 0,
            -drop_rate,
            -abs(count - event_median),
            matched_count,
            -_safe_int_from_rep(rep),
        )

    return max(reps, key=score)


def _summarize_trace_jsonl(path: Path, warnings: list[str]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    captured_events = 0
    drop_count = 0
    parser_warning_count = 0
    unknown_event_count = 0
    corrupt_record_count = 0
    first_events: list[dict[str, Any]] = []
    try:
        with path.open(encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    corrupt_record_count += 1
                    if len(warnings) < 20:
                        warnings.append(f"INVALID_TRACE_JSONL: line {line_no}: {exc}")
                    continue
                if not isinstance(row, dict):
                    corrupt_record_count += 1
                    continue
                captured_events += 1
                if len(first_events) < 8:
                    first_events.append(row)
                evt = str(row.get("evt") or "UNKNOWN")
                counts[evt] = counts.get(evt, 0) + 1
                if evt == "DROP":
                    drop_count += 1
                if evt == "UNKNOWN":
                    unknown_event_count += 1
                parser_warning_count += len(row.get("parser_warnings", []) if isinstance(row.get("parser_warnings"), list) else [])
    except OSError as exc:
        warnings.append(f"INVALID_ARTIFACT: trace.jsonl: {exc}")
    return {
        "captured_events": captured_events,
        "event_counts": counts,
        "drop_count": drop_count,
        "parser_warning_count": parser_warning_count,
        "unknown_event_count": unknown_event_count,
        "corrupt_record_count": corrupt_record_count,
        "first_events": first_events,
    }


def load_sample_artifacts(repo_root: Path, run_id: str, sample: str, rep: str) -> SampleArtifacts:
    repo_root = repo_root.resolve()
    run_root = repo_root / "results" / "experiments" / "35t" / run_id
    if not run_root.is_dir():
        raise FileNotFoundError(f"run-id '{run_id}' not found: {run_root}")

    sample_dir = _find_sample_dir(run_root, sample)
    evidence_root = repo_root / "docs" / "results" / "evidence" / run_id
    warnings: list[str] = []
    missing: list[str] = []
    paths: dict[str, Path | None] = {}
    data: dict[str, Any] = {}

    gate_report_candidates = [
        run_root / "aggregate" / "gate_report.json",
        evidence_root / "gate_report.json",
    ]
    gate_report_path = _first_existing(gate_report_candidates)
    gate_report = _read_json(gate_report_path, warnings, "gate_report") if gate_report_path is not None else None
    if rep == "auto":
        selected_rep = _auto_select_rep(run_root, sample_dir, sample, gate_report)
    else:
        selected_rep = _normalize_rep(rep)
    rep_dir = sample_dir / "board" / "trace-on" / selected_rep
    if not rep_dir.is_dir():
        raise FileNotFoundError(f"rep '{selected_rep}' not found: {rep_dir}")

    _load_optional_text_summary(paths, data, warnings, missing, "trace", [rep_dir / "trace.jsonl"])
    _load_optional_json(
        paths,
        data,
        warnings,
        missing,
        "semantic_events",
        [rep_dir / "semantic_events.json", rep_dir / "behavior_recovery" / "semantic_events.json"],
    )
    _load_optional_json(
        paths,
        data,
        warnings,
        missing,
        "behavior_graph",
        [rep_dir / "behavior_graph.json", rep_dir / "behavior_recovery" / "behavior_graph.json"],
    )
    _load_optional_json(
        paths,
        data,
        warnings,
        missing,
        "behavior_audit",
        [rep_dir / "behavior_audit.json", rep_dir / "behavior_audit" / "behavior_audit.json"],
    )
    _load_optional_json(paths, data, warnings, missing, "alignment", [rep_dir / "alignment" / "alignment.json"])
    _load_optional_json(paths, data, warnings, missing, "runtime_process_map", [rep_dir / "runtime_process_map.json"])
    _load_optional_json(
        paths,
        data,
        warnings,
        missing,
        "trace_code_map_summary",
        [rep_dir / "trace_code_map" / "trace_code_map_summary.json"],
    )
    _load_optional_json(paths, data, warnings, missing, "status", [rep_dir / "status.json"])
    _load_optional_json(paths, data, warnings, missing, "parser_warnings", [rep_dir / "parser_warnings.json"])
    _load_optional_json(paths, data, warnings, missing, "gate_report", gate_report_candidates)
    _load_optional_json(paths, data, warnings, missing, "metrics", [run_root / "aggregate" / "metrics.json", evidence_root / "metrics.json"])
    _load_optional_json(
        paths,
        data,
        warnings,
        missing,
        "run_config",
        [run_root / "run_config.json", run_root / "aggregate" / "run_config.json", evidence_root / "run_config.json"],
    )
    _load_optional_json(paths, data, warnings, missing, "manifest", [repo_root / "experiments" / "linux_behavior" / "malware_like" / "manifest.json"])
    _load_optional_json(paths, data, warnings, missing, "behavior_rules", [repo_root / "experiments" / "linux_behavior" / "behavior_audit_rules.json"])

    sample_class = _sample_class_from_manifest(data.get("manifest"), sample, sample_dir)
    return SampleArtifacts(
        repo_root=repo_root,
        run_id=run_id,
        sample_id=sample,
        sample_class=sample_class,
        rep=selected_rep,
        run_root=run_root,
        sample_dir=sample_dir,
        rep_dir=rep_dir,
        paths=paths,
        data=data,
        missing_artifacts=missing,
        warnings=warnings,
    )


def load_run_artifacts(repo_root: Path, run_id: str) -> RunArtifacts:
    repo_root = repo_root.resolve()
    run_root = repo_root / "results" / "experiments" / "35t" / run_id
    evidence_root = repo_root / "docs" / "results" / "evidence" / run_id
    if not run_root.is_dir() and not evidence_root.is_dir():
        raise FileNotFoundError(f"run-id '{run_id}' not found under results or evidence")

    warnings: list[str] = []
    missing: list[str] = []
    paths: dict[str, Path | None] = {}
    data: dict[str, Any] = {}

    _load_optional_json(
        paths,
        data,
        warnings,
        missing,
        "run_config",
        [run_root / "run_config.json", run_root / "aggregate" / "run_config.json", evidence_root / "run_config.json"],
    )
    _load_optional_json(
        paths,
        data,
        warnings,
        missing,
        "gate_report",
        [run_root / "aggregate" / "gate_report.json", evidence_root / "gate_report.json"],
    )
    _load_optional_json(
        paths,
        data,
        warnings,
        missing,
        "metrics",
        [run_root / "aggregate" / "metrics.json", evidence_root / "metrics.json"],
    )
    _load_optional_json(
        paths,
        data,
        warnings,
        missing,
        "sample_matrix_summary",
        [evidence_root / "sample_matrix_summary.json"],
    )
    _load_optional_json(
        paths,
        data,
        warnings,
        missing,
        "extension_gate_check",
        [evidence_root / "extension_gate_check.json", evidence_root / "real_malware_surrogate_validation_gate.json"],
    )
    _load_optional_json(
        paths,
        data,
        warnings,
        missing,
        "artifact_package_readiness",
        [evidence_root / "artifact_package_readiness.json"],
    )
    _load_optional_json(
        paths,
        data,
        warnings,
        missing,
        "raw_artifact_sanitization",
        [evidence_root / "raw_artifact_sanitization.json"],
    )
    _load_optional_json(
        paths,
        data,
        warnings,
        missing,
        "evidence_manifest",
        [evidence_root / "evidence_manifest.json"],
    )
    raw_uart = run_root / "board" / "raw_uart.log"
    paths["raw_uart"] = raw_uart if raw_uart.is_file() else None
    if not raw_uart.is_file():
        missing.append("raw_uart")
        warnings.append("MISSING_ARTIFACT: raw_uart")

    return RunArtifacts(
        repo_root=repo_root,
        run_id=run_id,
        run_root=run_root,
        evidence_root=evidence_root,
        paths=paths,
        data=data,
        missing_artifacts=missing,
        warnings=warnings,
    )


def _syscall_sequence(semantic: Any) -> list[dict[str, Any]]:
    if not isinstance(semantic, dict):
        return []
    rows = semantic.get("syscall_sequence", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _syscall_names(semantic: Any) -> list[str]:
    names = []
    for row in _syscall_sequence(semantic):
        name = str(row.get("name") or "")
        if name:
            names.append(name)
    return names


def _parse_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value)
    try:
        return int(text, 0)
    except ValueError:
        return None


def _is_failed_return(value: Any) -> bool:
    parsed = _parse_int(value)
    if parsed is None:
        return False
    if parsed < 0:
        return True
    return parsed >= (1 << 63)


def _rule_lookup(rules: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(rules, dict):
        return {}
    return {
        str(row.get("id")): row
        for row in rules.get("rules", [])
        if isinstance(row, dict) and row.get("id")
    }


def _indices_for_syscalls(sequence: list[dict[str, Any]], names: list[str]) -> list[int]:
    wanted = set(names)
    indices = []
    for row in sequence:
        if str(row.get("name") or "") in wanted and isinstance(row.get("index"), int):
            indices.append(int(row["index"]))
        if len(indices) >= 12:
            break
    return indices


def _semantic_events_for_indices(sequence: list[dict[str, Any]], indices: list[int]) -> list[str]:
    wanted = set(indices)
    events = []
    for row in sequence:
        if row.get("index") in wanted:
            name = str(row.get("name") or "")
            if name:
                events.append(name)
    return events[:12]


def _point(
    point_id: int,
    severity: str,
    kind: str,
    rule: str | None,
    title: str,
    why: str,
    strength: str,
    source: str,
    trace_indices: list[int] | None = None,
    semantic_events: list[str] | None = None,
    boundaries: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": f"sp-{point_id:03d}",
        "severity": severity,
        "kind": kind,
        "rule": rule,
        "title": title,
        "why_suspicious": why,
        "evidence_strength": strength,
        "evidence_source": source,
        "trace_indices": trace_indices or [],
        "semantic_events": semantic_events or [],
        "boundaries": boundaries or [
            "synthetic behavior-rule audit only",
            "not real malware detection evidence",
        ],
    }


def _source_path(artifacts: SampleArtifacts, label: str) -> str:
    path = artifacts.paths.get(label)
    if path is None:
        return label
    return _repo_rel(path, artifacts.repo_root)


def _humanize_rule(rule: str) -> str:
    return rule.replace("_", " ")


def _rule_points(artifacts: SampleArtifacts, sequence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    audit = artifacts.data.get("behavior_audit")
    if not isinstance(audit, dict):
        return []
    rules = _rule_lookup(artifacts.data.get("behavior_rules"))
    expected = set(str(item) for item in audit.get("expected_behavior", []) if item)
    matched_expected = set(str(item) for item in audit.get("matched_expected_behavior", []) if item)
    weak_expected = set(str(item) for item in audit.get("weak_matched_expected_behavior", []) if item)
    missing_expected = set(str(item) for item in audit.get("missing_expected_behavior", []) if item)
    unexpected = set(str(item) for item in audit.get("unexpected_matched_behavior", []) if item)
    sample_gate = _sample_gate(artifacts.data.get("gate_report"), artifacts.sample_id)
    gate_matched_expected = set(str(item) for item in sample_gate.get("matched_expected", []) if item)
    missing_expected -= gate_matched_expected
    matches = [row for row in audit.get("matches", []) if isinstance(row, dict)]
    match_by_rule = {str(row.get("rule")): row for row in matches if row.get("rule")}
    points: list[dict[str, Any]] = []
    next_id = 1

    for rule in sorted(matched_expected):
        spec = rules.get(rule, {})
        match = match_by_rule.get(rule, {})
        expected_syscalls = [str(item) for item in spec.get("expected_syscalls", []) if item]
        indices = _indices_for_syscalls(sequence, expected_syscalls)
        points.append(
            _point(
                next_id,
                "HIGH",
                "behavior_rule_match",
                rule,
                str(match.get("description") or spec.get("evidence") or _humanize_rule(rule)),
                f"Expected synthetic rule '{rule}' matched the recovered behavior evidence.",
                "strong",
                _source_path(artifacts, "behavior_audit"),
                indices,
                _semantic_events_for_indices(sequence, indices),
            )
        )
        next_id += 1

    for rule in sorted(gate_matched_expected - matched_expected):
        spec = rules.get(rule, {})
        expected_syscalls = [str(item) for item in spec.get("expected_syscalls", []) if item]
        indices = _indices_for_syscalls(sequence, expected_syscalls)
        source = str(sample_gate.get("expected_evidence_source") or "gate_report")
        points.append(
            _point(
                next_id,
                "HIGH" if sample_gate.get("gate_status") == "PASS" else "MEDIUM",
                "gate_corroborated_behavior",
                rule,
                str(spec.get("evidence") or _humanize_rule(rule)),
                f"Gate report marks expected synthetic rule '{rule}' as matched via {source}.",
                "strong",
                _source_path(artifacts, "gate_report"),
                indices,
                _semantic_events_for_indices(sequence, indices),
                ["gate-level corroborated evidence", "not real malware detection evidence"],
            )
        )
        next_id += 1

    for rule in sorted((weak_expected | (expected & set(audit.get("weak_matched_behavior", [])))) - matched_expected - gate_matched_expected):
        spec = rules.get(rule, {})
        match = match_by_rule.get(rule, {})
        reasons = match.get("weak_reasons", []) if isinstance(match.get("weak_reasons"), list) else []
        expected_syscalls = [str(item) for item in spec.get("expected_syscalls", []) if item]
        indices = _indices_for_syscalls(sequence, expected_syscalls)
        points.append(
            _point(
                next_id,
                "MEDIUM",
                "weak_behavior_evidence",
                rule,
                str(match.get("description") or spec.get("evidence") or _humanize_rule(rule)),
                "; ".join(str(item) for item in reasons) or f"Rule '{rule}' has weak evidence only.",
                "weak",
                _source_path(artifacts, "behavior_audit"),
                indices,
                _semantic_events_for_indices(sequence, indices),
                ["weak or inferred evidence", "not real malware detection evidence"],
            )
        )
        next_id += 1

    for rule in sorted(unexpected):
        match = match_by_rule.get(rule, {})
        points.append(
            _point(
                next_id,
                "MEDIUM",
                "unexpected_behavior_match",
                rule,
                str(match.get("description") or _humanize_rule(rule)),
                f"Rule '{rule}' matched but is not listed as expected behavior for this synthetic sample.",
                "strong",
                _source_path(artifacts, "behavior_audit"),
            )
        )
        next_id += 1

    for rule in sorted(missing_expected):
        match = match_by_rule.get(rule, {})
        missing = match.get("missing", []) if isinstance(match.get("missing"), list) else []
        points.append(
            _point(
                next_id,
                "LOW",
                "missing_expected_behavior",
                rule,
                f"Expected behavior not fully recovered: {_humanize_rule(rule)}",
                f"Missing evidence: {', '.join(str(item) for item in missing) or 'not recorded'}",
                "missing",
                _source_path(artifacts, "behavior_audit"),
                boundaries=["bounded evidence gap", "not a negative malware verdict"],
            )
        )
        next_id += 1

    return points


def _has_subsequence(names: list[str], subseq: list[str]) -> bool:
    pos = 0
    for name in names:
        if name == subseq[pos]:
            pos += 1
            if pos == len(subseq):
                return True
    return False


def _pattern_points(artifacts: SampleArtifacts, existing: list[dict[str, Any]], sequence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    names = [str(row.get("name") or "") for row in sequence if row.get("name")]
    existing_rules = {str(point.get("rule")) for point in existing if point.get("rule")}
    points: list[dict[str, Any]] = []
    next_id = len(existing) + 1

    def add(severity: str, kind: str, title: str, why: str, strength: str, source: str, syscalls: list[str], boundaries: list[str] | None = None) -> None:
        nonlocal next_id
        indices = _indices_for_syscalls(sequence, syscalls)
        points.append(
            _point(
                next_id,
                severity,
                kind,
                None,
                title,
                why,
                strength,
                source,
                indices,
                _semantic_events_for_indices(sequence, indices),
                boundaries,
            )
        )
        next_id += 1

    if "ptrace" in names and "anti_analysis_indicator" not in existing_rules:
        target_scoped = any(row.get("name") == "ptrace" and row.get("process_owner") == "target_child" for row in sequence)
        add(
            "MEDIUM" if target_scoped else "INFO",
            "syscall_pattern_cue",
            "ptrace anti-analysis cue",
            "ptrace appears in the recovered syscall stream; attribution should be checked before treating it as target behavior.",
            "weak" if not target_scoped else "strong",
            _source_path(artifacts, "semantic_events"),
            ["ptrace"],
            ["syscall pattern cue", "process attribution may be weak", "not real malware detection evidence"],
        )

    exec_mprotect = [
        row
        for row in sequence
        if row.get("name") == "mprotect" and (_parse_int((row.get("args") or {}).get("a2") if isinstance(row.get("args"), dict) else None) or 0) & 0x4
    ]
    if exec_mprotect and "dynamic_executable_memory" not in existing_rules:
        add(
            "MEDIUM",
            "syscall_pattern_cue",
            "Executable memory permission cue",
            "mprotect appears with PROT_EXEC in recovered syscall arguments.",
            "strong",
            _source_path(artifacts, "semantic_events"),
            ["mprotect"],
        )

    if _has_subsequence(names, ["mmap", "mprotect"]) and "dynamic_executable_memory" not in existing_rules:
        add(
            "MEDIUM",
            "syscall_pattern_cue",
            "Dynamic executable memory shape",
            "mmap is followed by mprotect in the recovered syscall order.",
            "inferred",
            _source_path(artifacts, "semantic_events"),
            ["mmap", "mprotect"],
            ["ordered syscall cue", "argument semantics may be incomplete"],
        )

    if _has_subsequence(names, ["clone", "execve", "waitid"]) and "process_creation_chain" not in existing_rules:
        add(
            "MEDIUM",
            "syscall_pattern_cue",
            "Process-chain cue",
            "clone, execve, and waitid appear in order in the recovered syscall stream.",
            "inferred",
            _source_path(artifacts, "semantic_events"),
            ["clone", "execve", "waitid"],
        )

    if names.count("getdents64") >= 2 and "openat" in names and "many_file_scan" not in existing_rules:
        add(
            "MEDIUM",
            "syscall_pattern_cue",
            "Directory scan cue",
            "openat plus repeated getdents64 appears in the recovered syscall stream.",
            "inferred",
            _source_path(artifacts, "semantic_events"),
            ["openat", "getdents64"],
        )

    if all(name in names for name in ("openat", "read", "write")) and not ({"batch_file_read_write", "self_copy_simulation"} & existing_rules):
        add(
            "MEDIUM",
            "syscall_pattern_cue",
            "File transform cue",
            "openat, read, and write appear in the recovered syscall stream.",
            "inferred",
            _source_path(artifacts, "semantic_events"),
            ["openat", "read", "write"],
        )

    failed = [row for row in sequence if _is_failed_return(row.get("return_value"))]
    if failed and "abnormal_syscall_sequence" not in existing_rules:
        add(
            "LOW",
            "syscall_pattern_cue",
            "Failed syscall return cue",
            "One or more recovered syscall returns look like error values.",
            "inferred",
            _source_path(artifacts, "semantic_events"),
            [str(row.get("name")) for row in failed[:4] if row.get("name")],
            ["abnormal syscall cue", "requires source-level or strace corroboration"],
        )

    direct_sites = [
        row
        for row in sequence
        if "direct" in str(row.get("callsite_kind") or "").lower()
        or "wrapper" in str(row.get("callsite_kind") or "").lower()
    ]
    if direct_sites:
        add(
            "INFO",
            "syscall_pattern_cue",
            "Direct syscall wrapper cue",
            "The trace-code join marks a syscall callsite as direct or wrapper-like.",
            "inferred",
            _source_path(artifacts, "semantic_events"),
            [str(row.get("name")) for row in direct_sites[:4] if row.get("name")],
        )

    return points


def _compute_suspicious_points(artifacts: SampleArtifacts) -> list[dict[str, Any]]:
    sequence = _syscall_sequence(artifacts.data.get("semantic_events"))
    points = _rule_points(artifacts, sequence)
    points.extend(_pattern_points(artifacts, points, sequence))
    severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "WARN": 3, "INFO": 4}
    return sorted(points, key=lambda row: (severity_rank.get(str(row.get("severity")), 9), row.get("id", "")))


def _fd_path_status(sample_id: str, sequence: list[dict[str, Any]]) -> str:
    if sample_id not in FD_PATH_SAMPLES:
        return "not_applicable"
    names = [str(row.get("name") or "") for row in sequence]
    has_path = any(
        isinstance(row.get("path"), str)
        or any(key.endswith("_string") for key in ((row.get("args") or {}).keys() if isinstance(row.get("args"), dict) else []))
        for row in sequence
    )
    if has_path and "openat" in names and any(name in names for name in ("read", "write", "getdents64", "close")):
        return "closed"
    if "openat" in names and any(name in names for name in ("read", "write", "getdents64", "close")):
        return "partial"
    return "missing"


def _process_tree_status(sample_id: str, sequence: list[dict[str, Any]]) -> str:
    if sample_id not in PROCESS_TREE_SAMPLES:
        return "not_applicable"
    names = [str(row.get("name") or "") for row in sequence]
    if all(name in names for name in ("clone", "execve", "waitid")):
        has_exec_path = any(row.get("name") == "execve" and (row.get("path") or (isinstance(row.get("args"), dict) and row["args"].get("a0_string"))) for row in sequence)
        return "closed" if has_exec_path else "partial"
    if any(name in names for name in ("clone", "execve", "waitid")):
        return "partial"
    return "missing"


def _compute_trace_summary(artifacts: SampleArtifacts) -> dict[str, Any]:
    gate_report = artifacts.data.get("gate_report")
    sample_gate = _sample_gate(gate_report, artifacts.sample_id)
    trace = artifacts.data.get("trace") if isinstance(artifacts.data.get("trace"), dict) else {}
    alignment = artifacts.data.get("alignment") if isinstance(artifacts.data.get("alignment"), dict) else {}
    parser_warnings = artifacts.data.get("parser_warnings") if isinstance(artifacts.data.get("parser_warnings"), dict) else {}
    run_config = artifacts.data.get("run_config") if isinstance(artifacts.data.get("run_config"), dict) else {}
    status = artifacts.data.get("status") if isinstance(artifacts.data.get("status"), dict) else {}
    budget = (
        sample_gate.get("trace_records")
        or (gate_report.get("trace_records") if isinstance(gate_report, dict) else None)
        or run_config.get("trace_records")
        or run_config.get("trace_record_count")
    )
    captured_events = trace.get("captured_events") or alignment.get("captured_events") or status.get("trace_count") or 0
    drop_count = alignment.get("drop_count", trace.get("drop_count", status.get("drop", 0)))
    drop_rate = alignment.get("drop_rate")
    if drop_rate is None:
        drop_rate = float(drop_count or 0) / float(captured_events or 1)
    capped = sample_gate.get("drop_summary", {}).get("capped_reps", []) if isinstance(sample_gate.get("drop_summary"), dict) else []
    return {
        "trace_records_budget": budget,
        "captured_events": captured_events,
        "drop_count": drop_count,
        "drop_rate": drop_rate,
        "cap_hit": artifacts.rep in set(capped),
        "unknown_event_count": parser_warnings.get("unknown_event_count", trace.get("unknown_event_count", 0)),
        "corrupt_record_count": parser_warnings.get("corrupt_record_count", trace.get("corrupt_record_count", 0)),
        "marker_scope_status": _gate_rep_status(sample_gate, "marker_scope_summary", artifacts.rep)
        or (artifacts.data.get("semantic_events") or {}).get("marker_scope", {}).get("status")
        if isinstance(artifacts.data.get("semantic_events"), dict)
        else None,
        "runtime_process_attribution_status": _gate_rep_status(sample_gate, "runtime_process_attribution_summary", artifacts.rep)
        or (artifacts.data.get("runtime_process_map") or {}).get("status")
        if isinstance(artifacts.data.get("runtime_process_map"), dict)
        else None,
        "gate_status": sample_gate.get("gate_status"),
        "sample_status": sample_gate.get("sample_status", {}).get("status") if isinstance(sample_gate.get("sample_status"), dict) else status.get("status"),
    }


def _compute_semantic_summary(artifacts: SampleArtifacts) -> dict[str, Any]:
    semantic = artifacts.data.get("semantic_events")
    sequence = _syscall_sequence(semantic)
    names = _syscall_names(semantic)
    graph = artifacts.data.get("behavior_graph") if isinstance(artifacts.data.get("behavior_graph"), dict) else {}
    trace_code = artifacts.data.get("trace_code_map_summary") if isinstance(artifacts.data.get("trace_code_map_summary"), dict) else {}
    basis = "marker_scoped_runtime_map_code_site"
    if trace_code.get("attribution_model"):
        basis = str(trace_code["attribution_model"])
    return {
        "syscall_count": len(names),
        "syscall_sequence_head": names[:16],
        "fd_path_status": _fd_path_status(artifacts.sample_id, sequence),
        "process_tree_status": _process_tree_status(artifacts.sample_id, sequence),
        "behavior_graph_nodes": len(graph.get("nodes", [])) if isinstance(graph.get("nodes"), list) else 0,
        "behavior_graph_edges": len(graph.get("edges", [])) if isinstance(graph.get("edges"), list) else 0,
        "code_attribution_basis": basis,
    }


def _evidence_warnings(artifacts: SampleArtifacts, trace_summary: dict[str, Any], semantic_summary: dict[str, Any]) -> list[dict[str, Any]]:
    warnings: list[dict[str, Any]] = []
    for item in artifacts.warnings:
        severity = "WARN" if item.startswith(("MISSING", "INVALID")) else "INFO"
        warnings.append({"severity": severity, "source": "artifact_loader", "message": item})
    if trace_summary.get("cap_hit"):
        warnings.append({"severity": "WARN", "source": _source_path(artifacts, "gate_report"), "message": "trace cap hit; interpretation may be truncated"})
    if float(trace_summary.get("drop_rate") or 0.0) > 0.05:
        warnings.append({"severity": "WARN", "source": _source_path(artifacts, "alignment"), "message": "DROP rate exceeds 5%; semantic interpretation is weaker"})
    if int(trace_summary.get("unknown_event_count") or 0) > 0 or int(trace_summary.get("corrupt_record_count") or 0) > 0:
        warnings.append({"severity": "WARN", "source": _source_path(artifacts, "parser_warnings"), "message": "unknown or corrupt trace records are present"})
    if trace_summary.get("marker_scope_status") not in {None, "PASS"}:
        warnings.append({"severity": "WARN", "source": _source_path(artifacts, "gate_report"), "message": "marker scope did not pass"})
    if trace_summary.get("runtime_process_attribution_status") not in {None, "PASS"}:
        warnings.append({"severity": "WARN", "source": _source_path(artifacts, "runtime_process_map"), "message": "runtime process attribution did not pass"})
    alignment = artifacts.data.get("alignment") if isinstance(artifacts.data.get("alignment"), dict) else {}
    if alignment and (float(alignment.get("syscall_family_precision") or 1.0) < 0.5 or float(alignment.get("syscall_family_recall") or 1.0) < 0.5):
        warnings.append({"severity": "INFO", "source": _source_path(artifacts, "alignment"), "message": "alignment precision/recall is bounded; do not claim complete semantic reconstruction"})
    if semantic_summary.get("fd_path_status") == "partial":
        warnings.append({"severity": "INFO", "source": _source_path(artifacts, "semantic_events"), "message": "fd/path flow is partial or inferred; path strings are not trace-proven hardware pointer snapshots"})
    if semantic_summary.get("process_tree_status") == "partial":
        warnings.append({"severity": "INFO", "source": _source_path(artifacts, "semantic_events"), "message": "process tree is partial; parent ownership remains bounded"})
    return warnings


def build_explanation(artifacts: SampleArtifacts, *, strict: bool = False) -> dict[str, Any]:
    if strict and artifacts.missing_artifacts:
        missing = ", ".join(artifacts.missing_artifacts)
        raise ValueError(f"strict mode rejected missing artifacts: {missing}")
    trace_summary = _compute_trace_summary(artifacts)
    semantic_summary = _compute_semantic_summary(artifacts)
    suspicious_points = _compute_suspicious_points(artifacts)
    warnings = _evidence_warnings(artifacts, trace_summary, semantic_summary)
    return {
        "schema": SCHEMA,
        "run_id": artifacts.run_id,
        "sample_id": artifacts.sample_id,
        "sample_class": artifacts.sample_class,
        "rep": artifacts.rep,
        "scope": SCOPE,
        "claim_level": CLAIM_LEVEL,
        "artifact_root": _repo_rel(artifacts.rep_dir, artifacts.repo_root),
        "trace_summary": trace_summary,
        "semantic_summary": semantic_summary,
        "suspicious_points": suspicious_points,
        "warnings": warnings,
        "non_claims": NON_CLAIMS,
    }


def _run_samples(gate_report: Any) -> list[dict[str, Any]]:
    if not isinstance(gate_report, dict):
        return []
    samples = gate_report.get("samples", [])
    return [row for row in samples if isinstance(row, dict)] if isinstance(samples, list) else []


def _stat_median(value: Any) -> Any:
    if isinstance(value, dict):
        return value.get("median")
    return value


def _sample_result_dir(run_root: Path, sample_class: str, sample_id: str) -> Path:
    direct = run_root / "samples" / sample_class / sample_id
    if direct.is_dir():
        return direct
    candidates = sorted((run_root / "samples").glob(f"*/{sample_id}"))
    return candidates[0] if candidates else direct


def _count_rep_artifacts(sample_dir: Path, pattern: str) -> int:
    trace_on = sample_dir / "board" / "trace-on"
    if not trace_on.is_dir():
        return 0
    return len(list(trace_on.glob(pattern)))


def _sum_parser_warning_field(sample_dir: Path, field: str) -> int:
    total = 0
    for path in (sample_dir / "board" / "trace-on").glob("rep_*/parser_warnings.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(payload, dict):
            try:
                total += int(payload.get(field) or 0)
            except (TypeError, ValueError):
                pass
    return total


def _matched_expected_from_audits(sample_dir: Path) -> list[str]:
    rules: set[str] = set()
    for path in (sample_dir / "board" / "trace-on").glob("rep_*/behavior_audit/behavior_audit.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        for item in payload.get("matched_expected_behavior", []) if isinstance(payload.get("matched_expected_behavior"), list) else []:
            rules.add(str(item))
    return sorted(rules)


def _metric_samples(artifacts: RunArtifacts, metrics: Any) -> list[dict[str, Any]]:
    if not isinstance(metrics, dict) or not isinstance(metrics.get("samples"), list):
        return []
    rows: list[dict[str, Any]] = []
    for row in metrics["samples"]:
        if not isinstance(row, dict):
            continue
        sample_id = str(row.get("sample_id") or "")
        sample_class = str(row.get("sample_class") or "malware_like_synthetic")
        if not sample_id:
            continue
        sample_dir = _sample_result_dir(artifacts.run_root, sample_class, sample_id)
        trace_count = row.get("trace_on_rep_count") or _count_rep_artifacts(sample_dir, "rep_*/trace.jsonl")
        semantic_count = _count_rep_artifacts(sample_dir, "rep_*/behavior_recovery/semantic_events.json")
        audit_count = _count_rep_artifacts(sample_dir, "rep_*/behavior_audit/behavior_audit.json")
        matched_expected = _matched_expected_from_audits(sample_dir)
        rows.append(
            {
                "sample_id": sample_id,
                "sample_class": sample_class,
                "status": row.get("status"),
                "gate_status": row.get("status"),
                "trace_artifact_count": trace_count,
                "semantic_artifact_count": semantic_count,
                "behavior_audit_artifact_count": audit_count,
                "drop_rate_median": _stat_median(row.get("drop_rate")),
                "unknown_event_count": _sum_parser_warning_field(sample_dir, "unknown_event_count"),
                "corrupt_record_count": _sum_parser_warning_field(sample_dir, "corrupt_record_count"),
                "matched_expected": matched_expected,
                "expected_evidence_source": "behavior_audit" if matched_expected else "semantic_trace",
                "checks": {
                    "sample_status_pass": row.get("status") == "PASS",
                    "gate_status_pass": row.get("status") == "PASS",
                    "no_trace_cap_hit": not bool(row.get("captured_cap_reps")),
                    "semantic_artifacts_5_of_5": semantic_count >= int(trace_count or 0) if trace_count else semantic_count > 0,
                    "behavior_audit_artifacts_5_of_5": audit_count >= int(trace_count or 0) if trace_count else audit_count > 0,
                    "strong_expected_behavior_matched": bool(matched_expected) or bool(row.get("any_behavior_rule_matched")),
                },
            }
        )
    return rows


def _status_from_bool(value: bool | None) -> str:
    if value is True:
        return "PASS"
    if value is False:
        return "FAIL"
    return "UNKNOWN"


def _all_sample_check(samples: list[dict[str, Any]], key: str) -> bool | None:
    values: list[bool] = []
    for row in samples:
        checks = row.get("checks")
        if isinstance(checks, dict) and key in checks:
            values.append(bool(checks[key]))
    if not values:
        return None
    return all(values)


def _count_passed_samples(samples: list[dict[str, Any]]) -> int:
    count = 0
    for row in samples:
        if row.get("status") == "PASS" or row.get("gate_status") == "PASS":
            count += 1
    return count


def _sum_int(samples: list[dict[str, Any]], key: str) -> int:
    total = 0
    for row in samples:
        try:
            total += int(row.get(key) or 0)
        except (TypeError, ValueError):
            pass
    return total


def _min_int(samples: list[dict[str, Any]], key: str) -> int | None:
    values: list[int] = []
    for row in samples:
        try:
            values.append(int(row.get(key)))
        except (TypeError, ValueError):
            pass
    return min(values) if values else None


def _max_float(samples: list[dict[str, Any]], key: str) -> float | None:
    values: list[float] = []
    for row in samples:
        try:
            values.append(float(row.get(key)))
        except (TypeError, ValueError):
            pass
    return max(values) if values else None


def _sample_rules(samples: list[dict[str, Any]]) -> list[str]:
    rules: set[str] = set()
    for row in samples:
        for item in row.get("matched_expected", []) if isinstance(row.get("matched_expected"), list) else []:
            rules.add(str(item))
    return sorted(rules)


def _short_items(items: list[str], *, limit: int = 6) -> list[str]:
    if len(items) <= limit:
        return items
    return [*items[:limit], f"+{len(items) - limit} more"]


def _sample_key_observations(artifacts: RunArtifacts, samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for row in samples:
        sample_id = str(row.get("sample_id") or "")
        if not sample_id:
            continue
        matched_expected = [str(item) for item in row.get("matched_expected", []) if item] if isinstance(row.get("matched_expected"), list) else []
        expected_source = str(row.get("expected_evidence_source") or "behavior_audit")
        observation: dict[str, Any] = {
            "sample_id": sample_id,
            "gate_status": row.get("gate_status") or row.get("status"),
            "trace_artifact_count": row.get("trace_artifact_count"),
            "semantic_artifact_count": row.get("semantic_artifact_count"),
            "behavior_audit_artifact_count": row.get("behavior_audit_artifact_count"),
            "drop_rate_median": row.get("drop_rate_median"),
            "unknown_event_count": row.get("unknown_event_count"),
            "corrupt_record_count": row.get("corrupt_record_count"),
            "matched_expected": matched_expected,
            "expected_evidence_source": expected_source,
            "captured_events": None,
            "syscall_sequence_head": [],
            "fd_path_status": None,
            "process_tree_status": None,
            "top_cues": [],
            "artifact_root": None,
            "load_error": None,
        }
        try:
            sample_artifacts = load_sample_artifacts(artifacts.repo_root, artifacts.run_id, sample_id, "auto")
            explanation = build_explanation(sample_artifacts)
            trace = explanation.get("trace_summary", {})
            semantic = explanation.get("semantic_summary", {})
            observation["captured_events"] = trace.get("captured_events") if isinstance(trace, dict) else None
            observation["syscall_sequence_head"] = (
                [str(item) for item in semantic.get("syscall_sequence_head", [])]
                if isinstance(semantic, dict) and isinstance(semantic.get("syscall_sequence_head"), list)
                else []
            )
            observation["fd_path_status"] = semantic.get("fd_path_status") if isinstance(semantic, dict) else None
            observation["process_tree_status"] = semantic.get("process_tree_status") if isinstance(semantic, dict) else None
            observation["artifact_root"] = explanation.get("artifact_root")
            cues = []
            for point in explanation.get("suspicious_points", []) if isinstance(explanation.get("suspicious_points"), list) else []:
                if not isinstance(point, dict):
                    continue
                rule = point.get("rule")
                if rule and point.get("kind") in {"behavior_rule_match", "gate_corroborated_behavior"}:
                    matched_expected.append(str(rule))
                cues.append(
                    {
                        "severity": point.get("severity"),
                        "rule": rule or point.get("kind"),
                        "title": point.get("title"),
                        "evidence_strength": point.get("evidence_strength"),
                        "evidence_source": point.get("evidence_source"),
                    }
                )
                if len(cues) >= 3:
                    break
            observation["top_cues"] = cues
            observation["matched_expected"] = sorted(set(matched_expected))
        except Exception as exc:
            observation["load_error"] = str(exc)
        observations.append(observation)
    return observations


def _raw_uart_status(path: Path | None) -> str | None:
    if path is None or not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    if "RVMT_EXP_END" in text and "status=PASS" in text:
        return "PASS"
    if "RVMT_EXP_END" in text:
        return "RECORDED"
    return "UNKNOWN"


def _run_source(artifacts: RunArtifacts, label: str) -> str:
    path = artifacts.paths.get(label)
    if path is None:
        return "missing"
    return _repo_rel(path, artifacts.repo_root)


def _step(step: int, name: str, status: str, evidence: str, details: list[str], next_action: str | None = None) -> dict[str, Any]:
    return {
        "step": step,
        "name": name,
        "status": status,
        "evidence": evidence,
        "details": details,
        "next": next_action,
    }


def build_process_view(artifacts: RunArtifacts, *, strict: bool = False) -> dict[str, Any]:
    if strict and artifacts.missing_artifacts:
        missing = ", ".join(artifacts.missing_artifacts)
        raise ValueError(f"strict mode rejected missing artifacts: {missing}")

    gate_report = artifacts.data.get("gate_report")
    run_config = artifacts.data.get("run_config") if isinstance(artifacts.data.get("run_config"), dict) else {}
    samples = _run_samples(gate_report)
    if not samples:
        samples = _metric_samples(artifacts, artifacts.data.get("metrics"))
    sample_total = len(samples)
    sample_pass = _count_passed_samples(samples)
    trace_records = (
        gate_report.get("trace_records") if isinstance(gate_report, dict) else None
    ) or run_config.get("trace_records") or run_config.get("trace_record_count")
    trace_on_min = _min_int(samples, "trace_artifact_count")
    semantic_min = _min_int(samples, "semantic_artifact_count")
    behavior_min = _min_int(samples, "behavior_audit_artifact_count")
    unknown_total = _sum_int(samples, "unknown_event_count")
    corrupt_total = _sum_int(samples, "corrupt_record_count")
    max_drop = _max_float(samples, "drop_rate_median")
    matched_rules = _sample_rules(samples)
    captured_key_information = _sample_key_observations(artifacts, samples)
    raw_uart_status = _raw_uart_status(artifacts.paths.get("raw_uart"))
    network = run_config.get("network")
    real_malware = run_config.get("real_malware")
    side_channel_used = any(
        "side_channel" in str(row.get("expected_evidence_source") or "")
        for row in samples
    )

    board_pass = raw_uart_status == "PASS" or (sample_total > 0 and sample_pass == sample_total)
    trace_pass = (
        sample_total > 0
        and sample_pass == sample_total
        and unknown_total == 0
        and corrupt_total == 0
        and (max_drop is None or max_drop <= 0.05)
        and _all_sample_check(samples, "no_trace_cap_hit") is not False
    )
    attribution_pass = (
        _all_sample_check(samples, "marker_scope_pass") is not False
        and _all_sample_check(samples, "runtime_process_attribution_pass") is not False
        and sample_total > 0
    )
    semantic_pass = (
        sample_total > 0
        and (semantic_min is None or semantic_min > 0)
        and ((artifacts.evidence_root / "sample_matrix_summary.json").is_file() or (semantic_min is not None and semantic_min > 0))
    )
    behavior_pass = (
        sample_total > 0
        and _all_sample_check(samples, "strong_expected_behavior_matched") is not False
        and (behavior_min is None or behavior_min > 0)
    )
    package_inputs = [
        isinstance(artifacts.data.get("evidence_manifest"), dict),
        isinstance(artifacts.data.get("artifact_package_readiness"), dict),
        isinstance(artifacts.data.get("raw_artifact_sanitization"), dict),
    ]
    package_pass = True if all(package_inputs) else None if not any(package_inputs) else False

    steps = [
        _step(
            1,
            "Board workload execution",
            _status_from_bool(board_pass),
            _run_source(artifacts, "raw_uart"),
            [
                f"RVMT_EXP_END: {raw_uart_status or 'not found'}",
                f"samples passed: {sample_pass}/{sample_total or 'unknown'}",
                f"real malware policy: {_fmt_value(real_malware)}",
                f"network policy: {_fmt_value(network)}",
            ],
            "hardware trace capture",
        ),
        _step(
            2,
            "Hardware trace capture",
            _status_from_bool(trace_pass),
            _run_source(artifacts, "gate_report"),
            [
                f"trace records budget: {_fmt_value(trace_records)}",
                f"trace-on reps per sample: {_fmt_value(trace_on_min)} minimum",
                f"unknown/corrupt records: {unknown_total}/{corrupt_total}",
                f"max median DROP: {_fmt_value(max_drop)}",
            ],
            "local code and process attribution",
        ),
        _step(
            3,
            "Local code and process attribution",
            _status_from_bool(attribution_pass),
            _run_source(artifacts, "gate_report"),
            [
                f"marker scope: {_status_from_bool(_all_sample_check(samples, 'marker_scope_pass'))}",
                f"runtime process attribution: {_status_from_bool(_all_sample_check(samples, 'runtime_process_attribution_pass'))}",
                "basis: marker-scoped runtime map plus local trace-code map",
            ],
            "semantic behavior recovery",
        ),
        _step(
            4,
            "Semantic behavior recovery",
            _status_from_bool(semantic_pass),
            _run_source(artifacts, "sample_matrix_summary"),
            [
                f"semantic artifacts per sample: {_fmt_value(semantic_min)} minimum",
                "fd/path and process-tree evidence is bounded, not complete reconstruction",
                f"side-channel auxiliary evidence used: {_fmt_value(side_channel_used)}",
            ],
            "malware-like behavior audit",
        ),
        _step(
            5,
            "Synthetic malware-like behavior audit",
            _status_from_bool(behavior_pass),
            _run_source(artifacts, "extension_gate_check"),
            [
                f"behavior audit artifacts per sample: {_fmt_value(behavior_min)} minimum",
                f"matched expected behaviors: {', '.join(matched_rules) if matched_rules else 'see per-sample audit'}",
                "suspicious cues are audit findings, not malware detection verdicts",
            ],
            "bounded evidence package",
        ),
        _step(
            6,
            "Evidence package and claim boundary",
            _status_from_bool(package_pass),
            _run_source(artifacts, "evidence_manifest"),
            [
                f"artifact package readiness: {_fmt_value((artifacts.data.get('artifact_package_readiness') or {}).get('status') if isinstance(artifacts.data.get('artifact_package_readiness'), dict) else None)}",
                f"raw artifact policy: {_fmt_value((artifacts.data.get('raw_artifact_sanitization') or {}).get('status') if isinstance(artifacts.data.get('raw_artifact_sanitization'), dict) else None)}",
                "full raw public release, real malware detection, CVA6, and classifier accuracy are non-claims",
            ],
            None,
        ),
    ]

    runtime_steps = steps[:5]
    overall = "PASS" if all(step["status"] == "PASS" for step in steps) else "RUNTIME_PASS_PACKAGE_PENDING" if all(step["status"] == "PASS" for step in runtime_steps) else "PARTIAL"
    return {
        "schema": "rvmt.35t.process_view.v1",
        "run_id": artifacts.run_id,
        "scope": SCOPE,
        "claim_level": CLAIM_LEVEL,
        "overall_status": overall,
        "sample_count": sample_total,
        "sample_pass_count": sample_pass,
        "steps": steps,
        "captured_key_information": captured_key_information,
        "warnings": artifacts.warnings,
        "non_claims": NON_CLAIMS,
    }


def _fmt_value(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def _line(label: str, value: Any) -> str:
    return f"{label:<24} {_fmt_value(value)}"


def render_console(explanation: dict[str, Any]) -> str:
    trace = explanation["trace_summary"]
    semantic = explanation["semantic_summary"]
    points = explanation.get("suspicious_points", [])
    warnings = explanation.get("warnings", [])
    lines = [
        "RV-MalTrace 35T Explanation",
        "===========================",
        f"Run:     {explanation['run_id']}",
        f"Sample:  {explanation['sample_id']}",
        f"Class:   {explanation['sample_class']}",
        f"Rep:     {explanation['rep']}",
        f"Scope:   {explanation['scope']}",
        f"Claim:   {explanation['claim_level']}",
        "",
        "[Trace]",
        _line("records budget:", trace.get("trace_records_budget")),
        _line("captured events:", trace.get("captured_events")),
        _line("unknown/corrupt:", f"{trace.get('unknown_event_count', 0)} / {trace.get('corrupt_record_count', 0)}"),
        _line("DROP rate:", trace.get("drop_rate")),
        _line("cap hit:", trace.get("cap_hit")),
        _line("gate status:", trace.get("gate_status")),
        _line("marker scope:", trace.get("marker_scope_status")),
        _line("runtime attribution:", trace.get("runtime_process_attribution_status")),
        "",
        "[Semantic]",
        _line("syscalls recovered:", ", ".join(semantic.get("syscall_sequence_head", [])) or "none"),
        _line("syscall count:", semantic.get("syscall_count")),
        _line("fd/path flow:", semantic.get("fd_path_status")),
        _line("process tree:", semantic.get("process_tree_status")),
        _line("behavior graph:", f"{semantic.get('behavior_graph_nodes')} nodes / {semantic.get('behavior_graph_edges')} edges"),
        _line("code attribution:", semantic.get("code_attribution_basis")),
        "",
        "[Suspicious cues]",
    ]
    if points:
        for point in points:
            source = point.get("evidence_source", "unknown")
            lines.append(
                f"{point.get('severity', 'INFO'):<6} {str(point.get('rule') or point.get('kind')):<28} "
                f"{point.get('title')} (source: {source}; strength: {point.get('evidence_strength')})"
            )
            lines.append(f"       {point.get('why_suspicious')}")
    else:
        lines.append("none")
    lines += ["", "[Evidence warnings]"]
    if warnings:
        for warning in warnings:
            lines.append(f"{warning.get('severity', 'INFO'):<6} {warning.get('message')} (source: {warning.get('source')})")
    else:
        lines.append("none")
    lines += ["", "[Boundaries]"]
    lines.extend(f"- {item}" for item in explanation.get("non_claims", []))
    lines.append("- Suspicious cues are behavior-audit findings, not detection verdicts.")
    return "\n".join(lines) + "\n"


def _clip(value: Any, width: int) -> str:
    text = _fmt_value(value)
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _step_status(view: dict[str, Any], step_name: str) -> str:
    for step in view.get("steps", []):
        if isinstance(step, dict) and step.get("name") == step_name:
            return str(step.get("status") or "UNKNOWN")
    return "UNKNOWN"


def _source_short(value: Any) -> str:
    text = str(value or "")
    if "side_channel" in text:
        return "trace+side"
    if "behavior_audit" in text:
        return "audit"
    if "gate_report" in text:
        return "gate"
    if not text:
        return "unknown"
    return _clip(text, 10)


def _semantic_short(item: dict[str, Any]) -> str:
    fd = item.get("fd_path_status")
    proc = item.get("process_tree_status")
    parts = []
    if fd and fd != "not_applicable":
        parts.append(f"fd:{fd}")
    if proc and proc != "not_applicable":
        parts.append(f"proc:{proc}")
    return " ".join(str(part) for part in parts) or "-"


def _behavior_groups(observations: list[dict[str, Any]]) -> dict[str, list[str]]:
    groups = {
        "file/syscall": [],
        "memory/code": [],
        "process": [],
        "anti-analysis": [],
    }
    for item in observations:
        for behavior in item.get("matched_expected", []) if isinstance(item.get("matched_expected"), list) else []:
            rule = str(behavior)
            lower = rule.lower()
            if any(token in lower for token in ("file", "open", "read", "encryption", "obfuscated")):
                groups["file/syscall"].append(rule)
            if any(token in lower for token in ("memory", "mprotect", "exec", "modifying")):
                groups["memory/code"].append(rule)
            if any(token in lower for token in ("process", "chain", "clone")):
                groups["process"].append(rule)
            if any(token in lower for token in ("timing", "debug", "tracer", "anti")):
                groups["anti-analysis"].append(rule)
    return {key: sorted(set(values)) for key, values in groups.items() if values}


def _pipeline_status_line(view: dict[str, Any]) -> str:
    labels = [
        ("Board", "Board workload execution"),
        ("Trace", "Hardware trace capture"),
        ("Attrib", "Local code and process attribution"),
        ("Sem", "Semantic behavior recovery"),
        ("Audit", "Synthetic malware-like behavior audit"),
        ("Pkg", "Evidence package and claim boundary"),
    ]
    return " -> ".join(f"{label}:{_step_status(view, name)}" for label, name in labels)


def render_process_console(view: dict[str, Any], *, detail: str = "compact") -> str:
    if detail == "full":
        return _render_process_console_full(view)

    observations = view.get("captured_key_information", [])
    lines = [
        "RV-MalTrace 35T Process",
        "=======================",
        f"Run:     {view['run_id']}",
        f"Status:  {view['overall_status']}    Samples: {view.get('sample_pass_count', 0)}/{view.get('sample_count', 0)} passed",
        f"Claim:   {view['claim_level']}",
        "",
        "[Pipeline]",
        _pipeline_status_line(view),
        "",
    ]
    groups = _behavior_groups([item for item in observations if isinstance(item, dict)])
    if groups:
        lines.append("[Behavior highlights]")
        for name, values in groups.items():
            lines.append(f"{name:<14} {', '.join(_short_items(values, limit=4))}")
        lines.append("")

    lines += [
        "[Key captures]",
        f"{'Sample':<32} {'Gate':<6} {'Evts':>5}  {'Behavior':<38} {'Sem':<16} {'Src':<10}",
        f"{'-' * 32} {'-' * 6} {'-' * 5}  {'-' * 38} {'-' * 16} {'-' * 10}",
    ]
    if observations:
        for item in observations:
            if not isinstance(item, dict):
                continue
            behavior = ", ".join(_short_items([str(value) for value in item.get("matched_expected", [])], limit=2))
            lines.append(
                f"{_clip(item.get('sample_id', 'unknown'), 32):<32} "
                f"{_clip(item.get('gate_status', 'UNKNOWN'), 6):<6} "
                f"{_clip(item.get('captured_events'), 5):>5}  "
                f"{_clip(behavior or 'none', 38):<38} "
                f"{_clip(_semantic_short(item), 16):<16} "
                f"{_source_short(item.get('expected_evidence_source')):<10}"
            )
    else:
        lines.append("none")
    lines += [
        "",
        "[Trace health]",
    ]
    for step in view.get("steps", []):
        if isinstance(step, dict) and step.get("name") == "Hardware trace capture":
            for item in step.get("details", []):
                lines.append(f"- {item}")
    lines += [
        "",
        "[Boundaries]",
        "- synthetic malware-like behavior audit only",
        "- no real malware detection, CVA6 claim, classifier accuracy, or complete semantic reconstruction",
        "",
        "Use --detail full for syscall heads, top cues, and evidence paths.",
    ]
    warnings = view.get("warnings", [])
    if warnings:
        lines += ["", "[Artifact warnings]"]
        lines.extend(f"- {item}" for item in warnings)
    return "\n".join(lines) + "\n"


def _render_process_console_full(view: dict[str, Any]) -> str:
    lines = [
        "RV-MalTrace 35T Process View",
        "============================",
        f"Run:     {view['run_id']}",
        f"Scope:   {view['scope']}",
        f"Claim:   {view['claim_level']}",
        f"Status:  {view['overall_status']}",
        f"Samples: {view.get('sample_pass_count', 0)}/{view.get('sample_count', 0)} passed",
        "",
        "[Application flow]",
        "board workload -> hardware trace -> local code/process attribution -> semantic recovery -> behavior audit -> evidence package",
        "",
    ]
    for step in view.get("steps", []):
        lines.append(f"[{step['status']}] {step['step']}. {step['name']}")
        lines.append(f"       evidence: {step['evidence']}")
        for detail in step.get("details", []):
            lines.append(f"       - {detail}")
        if step.get("next"):
            lines.append(f"       next: {step['next']}")
        lines.append("")
    lines += ["[Captured key information]"]
    observations = view.get("captured_key_information", [])
    if observations:
        for item in observations:
            sample = item.get("sample_id", "unknown")
            matched = _short_items([str(value) for value in item.get("matched_expected", [])], limit=4)
            syscalls = _short_items([str(value) for value in item.get("syscall_sequence_head", [])], limit=8)
            lines.append(f"[{item.get('gate_status', 'UNKNOWN')}] {sample}")
            lines.append(
                "       trace: "
                f"{_fmt_value(item.get('captured_events'))} events, "
                f"drop median {_fmt_value(item.get('drop_rate_median'))}, "
                f"unknown/corrupt {item.get('unknown_event_count', 0)}/{item.get('corrupt_record_count', 0)}"
            )
            lines.append(f"       key behavior: {', '.join(matched) if matched else 'none recorded'}")
            lines.append(f"       syscalls: {', '.join(syscalls) if syscalls else 'none recovered'}")
            lines.append(
                "       semantic: "
                f"fd/path={_fmt_value(item.get('fd_path_status'))}, "
                f"process-tree={_fmt_value(item.get('process_tree_status'))}"
            )
            lines.append(f"       evidence source: {_fmt_value(item.get('expected_evidence_source'))}")
            cues = item.get("top_cues", [])
            if cues:
                for cue in cues:
                    lines.append(
                        "       cue: "
                        f"{cue.get('severity', 'INFO')} {cue.get('rule')} - {cue.get('title')} "
                        f"(strength: {cue.get('evidence_strength')}; source: {cue.get('evidence_source')})"
                    )
            if item.get("load_error"):
                lines.append(f"       load warning: {item['load_error']}")
            lines.append("")
    else:
        lines.append("none")
        lines.append("")
    lines += ["[Boundaries]"]
    lines.extend(f"- {item}" for item in view.get("non_claims", []))
    lines.append("- This is a bounded synthetic malware-like behavior audit process, not a real malware detector.")
    warnings = view.get("warnings", [])
    if warnings:
        lines += ["", "[Artifact warnings]"]
        lines.extend(f"- {item}" for item in warnings)
    return "\n".join(lines) + "\n"


def render_process_markdown(view: dict[str, Any]) -> str:
    lines = [
        "# RV-MalTrace 35T Process View",
        "",
        f"- Run: `{view['run_id']}`",
        f"- Scope: {view['scope']}",
        f"- Claim: {view['claim_level']}",
        f"- Status: `{view['overall_status']}`",
        f"- Samples: `{view.get('sample_pass_count', 0)}/{view.get('sample_count', 0)}` passed",
        "",
        "## Application Flow",
        "",
        "`board workload -> hardware trace -> local code/process attribution -> semantic recovery -> behavior audit -> evidence package`",
        "",
        "## Steps",
        "",
    ]
    for step in view.get("steps", []):
        lines.append(f"### {step['step']}. {step['name']}")
        lines.append("")
        lines.append(f"- Status: `{step['status']}`")
        lines.append(f"- Evidence: `{step['evidence']}`")
        for detail in step.get("details", []):
            lines.append(f"- {detail}")
        if step.get("next"):
            lines.append(f"- Next: {step['next']}")
        lines.append("")
    lines += ["## Captured Key Information", ""]
    observations = view.get("captured_key_information", [])
    if observations:
        for item in observations:
            matched = _short_items([str(value) for value in item.get("matched_expected", [])], limit=4)
            syscalls = _short_items([str(value) for value in item.get("syscall_sequence_head", [])], limit=8)
            lines.append(f"### {item.get('sample_id', 'unknown')}")
            lines.append("")
            lines.append(f"- Gate: `{item.get('gate_status', 'UNKNOWN')}`")
            lines.append(
                f"- Trace: `{_fmt_value(item.get('captured_events'))}` events, "
                f"DROP median `{_fmt_value(item.get('drop_rate_median'))}`, "
                f"unknown/corrupt `{item.get('unknown_event_count', 0)}/{item.get('corrupt_record_count', 0)}`"
            )
            lines.append(f"- Key behavior: `{', '.join(matched) if matched else 'none recorded'}`")
            lines.append(f"- Syscalls: `{', '.join(syscalls) if syscalls else 'none recovered'}`")
            lines.append(f"- Semantic: fd/path `{_fmt_value(item.get('fd_path_status'))}`, process-tree `{_fmt_value(item.get('process_tree_status'))}`")
            lines.append(f"- Evidence source: `{_fmt_value(item.get('expected_evidence_source'))}`")
            for cue in item.get("top_cues", []):
                lines.append(
                    f"- Cue: **{cue.get('severity', 'INFO')}** `{cue.get('rule')}` - {cue.get('title')} "
                    f"(strength: `{cue.get('evidence_strength')}`, source: `{cue.get('evidence_source')}`)"
                )
            if item.get("load_error"):
                lines.append(f"- Load warning: `{item['load_error']}`")
            lines.append("")
    else:
        lines.append("- none")
        lines.append("")
    lines += ["## Boundaries", ""]
    lines.extend(f"- {item}" for item in view.get("non_claims", []))
    lines.append("- This is a bounded synthetic malware-like behavior audit process, not a real malware detector.")
    return "\n".join(lines) + "\n"


def render_markdown(explanation: dict[str, Any]) -> str:
    trace = explanation["trace_summary"]
    semantic = explanation["semantic_summary"]
    lines = [
        "# RV-MalTrace 35T Explanation",
        "",
        f"- Run: `{explanation['run_id']}`",
        f"- Sample: `{explanation['sample_id']}`",
        f"- Class: `{explanation['sample_class']}`",
        f"- Rep: `{explanation['rep']}`",
        f"- Scope: {explanation['scope']}",
        f"- Claim: {explanation['claim_level']}",
        "",
        "## Trace",
        "",
    ]
    for key, value in trace.items():
        lines.append(f"- {key}: `{_fmt_value(value)}`")
    lines += ["", "## Semantic", ""]
    for key, value in semantic.items():
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)
        lines.append(f"- {key}: `{_fmt_value(value)}`")
    lines += ["", "## Suspicious Cues", ""]
    for point in explanation.get("suspicious_points", []):
        lines.append(
            f"- **{point['severity']}** `{point.get('rule') or point['kind']}`: {point['title']} "
            f"(source: `{point['evidence_source']}`, strength: `{point['evidence_strength']}`)"
        )
        lines.append(f"  {point['why_suspicious']}")
    if not explanation.get("suspicious_points"):
        lines.append("- none")
    lines += ["", "## Evidence Warnings", ""]
    for warning in explanation.get("warnings", []):
        lines.append(f"- **{warning['severity']}** {warning['message']} (source: `{warning['source']}`)")
    if not explanation.get("warnings"):
        lines.append("- none")
    lines += ["", "## Boundaries", ""]
    lines.extend(f"- {item}" for item in explanation.get("non_claims", []))
    lines.append("- Suspicious cues are behavior-audit findings, not detection verdicts.")
    return "\n".join(lines) + "\n"
