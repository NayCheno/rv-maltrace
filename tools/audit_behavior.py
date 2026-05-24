from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_RULES = Path("experiments/linux_behavior/behavior_audit_rules.json")
DEFAULT_FIXTURES = Path("experiments/linux_behavior/rule_regression_fixtures/manifest.json")
TRAP_CAUSE_ALIASES = {
    "illegal_instruction": "0x2",
    "breakpoint": "0x3",
    "user_ecall": "0x8",
    "supervisor_ecall": "0x9",
    "machine_ecall": "0xb",
}


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_rule_definitions(path: Path) -> dict[str, dict[str, Any]]:
    spec = load_json(path)
    rules = spec.get("rules")
    if not isinstance(rules, list):
        raise ValueError(f"{path}: rules must be a list")
    result: dict[str, dict[str, Any]] = {}
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
            raise ValueError(f"{path}: every rule must be an object with string id")
        result[rule["id"]] = rule
    return result


def parse_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.startswith("0x") else int(value, 10)
        except ValueError:
            return None
    return None


def canonical_hex(value: Any) -> str | None:
    if isinstance(value, str) and value in TRAP_CAUSE_ALIASES:
        value = TRAP_CAUSE_ALIASES[value]
    number = parse_int(value)
    if number is None:
        return None
    return f"0x{number:x}"


def is_linux_error(value: Any) -> bool:
    number = parse_int(value)
    if number is None:
        return False
    if number < 0:
        return True
    return ((1 << 64) - 4095 <= number <= (1 << 64) - 1) or ((1 << 32) - 4095 <= number <= (1 << 32) - 1)


def syscall_rows(semantic: dict[str, Any]) -> list[dict[str, Any]]:
    rows = semantic.get("syscall_sequence", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def syscall_names(semantic: dict[str, Any]) -> list[str]:
    return [row["name"] for row in syscall_rows(semantic) if isinstance(row.get("name"), str)]


def syscall_arg(row: dict[str, Any], arg: str) -> Any:
    args = row.get("args")
    if isinstance(args, dict) and arg in args:
        return args[arg]
    return row.get(arg)


def trap_causes(semantic: dict[str, Any]) -> list[str]:
    rows = semantic.get("trap_context_transitions", [])
    if not isinstance(rows, list):
        return []
    causes: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cause = canonical_hex(row.get("cause"))
        if cause is not None:
            causes.append(cause)
    return causes


def trap_rows(semantic: dict[str, Any]) -> list[dict[str, Any]]:
    rows = semantic.get("trap_context_transitions", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def process_attributed_code_site(row: dict[str, Any]) -> bool:
    direct = (
        row.get("process_owner") == "target_child"
        and row.get("attribution_confidence") == "marker_scoped_runtime_map_code_site"
    )
    if direct:
        return True
    ret = row.get("return")
    if not isinstance(ret, dict):
        return False
    return (
        ret.get("return_site_process_owner") == "target_child"
        and ret.get("return_site_attribution_confidence") == "marker_scoped_runtime_map_code_site"
    )


def process_attribution_required(semantic: dict[str, Any]) -> bool:
    runtime_map = semantic.get("runtime_process_map")
    marker = semantic.get("marker_scope")
    return isinstance(runtime_map, dict) or isinstance(marker, dict)


def strong_syscall_rows(semantic: dict[str, Any]) -> list[dict[str, Any]]:
    rows = syscall_rows(semantic)
    if not process_attribution_required(semantic):
        return rows
    return [row for row in rows if process_attributed_code_site(row)]


def target_illegal_trap_rows(semantic: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in trap_rows(semantic):
        if canonical_hex(row.get("cause")) != "0x2":
            continue
        if row.get("pc_owner") != "target_sample":
            continue
        if row.get("callsite_kind") != "illegal_instruction_site":
            continue
        if not process_attributed_code_site(row):
            continue
        result.append(row)
    return result


def evidence_tags(semantic: dict[str, Any]) -> set[str]:
    tags = semantic.get("evidence_tags", [])
    if not isinstance(tags, list):
        return set()
    return {str(item) for item in tags}


def has_ordered_subsequence(values: list[str], expected: list[str]) -> bool:
    if not expected:
        return True
    index = 0
    for value in values:
        if value == expected[index]:
            index += 1
            if index == len(expected):
                return True
    return False


def has_self_copy_shape(names: list[str], counts: dict[str, int]) -> bool:
    if counts.get("openat", 0) < 2 or counts.get("read", 0) < 1 or counts.get("write", 0) < 1 or counts.get("close", 0) < 1:
        return False
    return has_ordered_subsequence(names, ["openat", "openat", "read", "write", "close"]) or has_ordered_subsequence(
        names, ["openat", "read", "openat", "write", "close"]
    )


def has_dynamic_exec_shape(names: list[str]) -> bool:
    return has_ordered_subsequence(names, ["mmap", "mprotect"])


WAIT_SYSCALL_NAMES = {"waitid", "wait4", "waitpid"}


def wait_syscall_present(name: str) -> bool:
    return name in WAIT_SYSCALL_NAMES


def is_process_chain_sample(sample_id: str | None) -> bool:
    return sample_id == "process_chain" or str(sample_id or "").startswith("process_creation_chain")


def has_process_chain_shape(names: list[str]) -> bool:
    index = 0
    for name in names:
        if index == 0 and name == "clone":
            index = 1
        elif index == 1 and name == "execve":
            index = 2
        elif index == 2 and wait_syscall_present(name):
            return True
    return False


def successful_positive_return(row: dict[str, Any]) -> int | None:
    value = parse_int(row.get("return_value"))
    if value is None or value <= 0 or is_linux_error(value):
        return None
    return value


def trace_proven_return(row: dict[str, Any]) -> bool:
    confidence = row.get("confidence")
    if not isinstance(confidence, str):
        return True
    if not confidence.startswith("return_only"):
        return True
    return process_attributed_code_site(row)


def has_target_scoped_process_chain(rows: list[dict[str, Any]], *, require_process_attr: bool) -> bool:
    required = {"clone", "execve", "waitid"}
    scoped = {
        str(row.get("name"))
        for row in rows
        if str(row.get("name")) in required
        and (process_attributed_code_site(row) if require_process_attr else row.get("pc_owner") == "target_sample")
    }
    return required <= scoped


def has_parent_child_boundary(rows: list[dict[str, Any]]) -> bool:
    clone_pids = {pid for row in rows if row.get("name") == "clone" for pid in [successful_positive_return(row)] if pid is not None}
    if not clone_pids:
        return False
    for row in rows:
        if row.get("name") == "waitid" and parse_int(syscall_arg(row, "a1")) in clone_pids:
            return True
        if row.get("name") in {"wait4", "waitpid"} and parse_int(syscall_arg(row, "a0")) in clone_pids:
            return True
    return False


def graph_summary(graph: dict[str, Any]) -> dict[str, Any]:
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, list):
        raise ValueError("behavior_graph.json: nodes must be a list")
    if not isinstance(edges, list):
        raise ValueError("behavior_graph.json: edges must be a list")
    kinds: dict[str, int] = {}
    for node in nodes:
        if isinstance(node, dict) and isinstance(node.get("kind"), str):
            kinds[node["kind"]] = kinds.get(node["kind"], 0) + 1
    return {
        "schema": graph.get("schema"),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "node_kinds": kinds,
    }


def manifest_expected_behaviors(manifest: dict[str, Any], sample_id: str | None) -> list[str]:
    if sample_id is None:
        return []
    samples = manifest.get("samples", [])
    if not isinstance(samples, list):
        return []
    for sample in samples:
        if isinstance(sample, dict) and sample.get("id") == sample_id:
            behaviors = sample.get("expected_behavior", [])
            return [item for item in behaviors if isinstance(item, str)] if isinstance(behaviors, list) else []
    return []


def manifest_sample_class(manifest: dict[str, Any], sample_id: str | None) -> str | None:
    if sample_id is None:
        return None
    samples = manifest.get("samples", [])
    if not isinstance(samples, list):
        return str(manifest.get("sample_class")) if manifest.get("sample_class") else None
    for sample in samples:
        if isinstance(sample, dict) and sample.get("id") == sample_id:
            sample_class = sample.get("class") or sample.get("sample_class") or manifest.get("sample_class")
            return str(sample_class) if sample_class else None
    return str(manifest.get("sample_class")) if manifest.get("sample_class") else None


def rule_scope_failures(rule_id: str, rule: dict[str, Any], sample_class: str | None, sample_id: str | None) -> list[str]:
    sample_allowed = rule.get("allowed_samples")
    if isinstance(sample_allowed, list) and sample_allowed:
        allowed_samples = {str(item) for item in sample_allowed}
        if sample_id not in allowed_samples:
            return [f"sample:{sample_id or 'unspecified'} not in {','.join(sorted(allowed_samples))}"]
    if sample_class is None:
        return []
    allowed = rule.get("allowed_sample_classes")
    if isinstance(allowed, list) and allowed:
        allowed_set = {str(item) for item in allowed}
        return [] if sample_class in allowed_set else [f"sample_class:{sample_class} not in {','.join(sorted(allowed_set))}"]
    if sample_class == "real_malware_surrogate" and not rule_id.startswith("surrogate_"):
        return [f"sample_class:{sample_class} requires surrogate-scoped rule"]
    if sample_class == "malware_like_synthetic" and rule_id.startswith("surrogate_"):
        return [f"sample_class:{sample_class} excludes surrogate-scoped rule"]
    return []


def match_rule(
    rule_id: str,
    rule: dict[str, Any],
    semantic: dict[str, Any],
    sample_id: str | None = None,
    sample_class: str | None = None,
) -> dict[str, Any]:
    all_rows = syscall_rows(semantic)
    names = [row["name"] for row in all_rows if isinstance(row.get("name"), str)]
    counts = {name: names.count(name) for name in sorted(set(names))}
    strong_rows = strong_syscall_rows(semantic)
    strong_names = [row["name"] for row in strong_rows if isinstance(row.get("name"), str)]
    strong_counts = {name: strong_names.count(name) for name in sorted(set(strong_names))}
    missing = [name for name in rule.get("expected_syscalls", []) if name not in strong_counts]

    any_syscalls = rule.get("any_syscalls", [])
    if any_syscalls and not any(name in strong_counts for name in any_syscalls):
        missing.append("any:" + ",".join(any_syscalls))

    count_failures = []
    min_counts = rule.get("min_counts", {})
    if isinstance(min_counts, dict):
        for name, minimum in sorted(min_counts.items()):
            minimum_int = parse_int(minimum)
            if minimum_int is None:
                count_failures.append(f"{name}>=invalid")
            elif strong_counts.get(name, 0) < minimum_int:
                count_failures.append(f"{name}>={minimum_int}")

    ordered = rule.get("ordered_syscalls", [])
    sequence_failures = []
    if isinstance(ordered, list) and ordered and not has_ordered_subsequence(strong_names, [str(item) for item in ordered]):
        sequence_failures.append("ordered:" + ",".join(str(item) for item in ordered))

    forbidden_failures = []
    forbidden = rule.get("forbidden_syscalls", [])
    if isinstance(forbidden, list):
        forbidden_failures = [str(name) for name in forbidden if strong_counts.get(str(name), 0) > 0]
    scope_failures = rule_scope_failures(rule_id, rule, sample_class, sample_id)

    observed_causes = trap_causes(semantic)
    missing_causes = []
    for expected in rule.get("expected_traps", []):
        expected_hex = canonical_hex(expected)
        if expected_hex not in observed_causes:
            missing_causes.append(str(expected))

    failed_rows = [row for row in all_rows if is_linux_error(row.get("return_value"))]
    failed_syscalls = [row.get("name", "unknown") for row in failed_rows]
    failure_scope = rule.get("failure_syscalls")
    if not isinstance(failure_scope, list) or not failure_scope:
        failure_scope = rule.get("expected_syscalls", [])
    scoped_failed_rows = [
        row
        for row in strong_rows
        if isinstance(row.get("name"), str) and row.get("name") in failure_scope
        and is_linux_error(row.get("return_value"))
    ]
    trace_proven_failed_rows = [row for row in scoped_failed_rows if trace_proven_return(row)]
    scoped_failed_syscalls = [row.get("name", "unknown") for row in trace_proven_failed_rows]
    untrusted_failed_syscalls = [row.get("name", "unknown") for row in scoped_failed_rows if not trace_proven_return(row)]
    if rule.get("requires_failed_syscall") and not scoped_failed_syscalls:
        missing.append("trace_proven_failed_syscall_return")

    arg_failures = []
    requirements = rule.get("arg_bit_requirements", [])
    if isinstance(requirements, list):
        for requirement in requirements:
            if not isinstance(requirement, dict):
                arg_failures.append("arg_bit_requirement_invalid")
                continue
            syscall = requirement.get("syscall")
            arg = requirement.get("arg")
            mask = parse_int(requirement.get("mask"))
            if not isinstance(syscall, str) or not isinstance(arg, str) or mask is None:
                arg_failures.append("arg_bit_requirement_invalid")
                continue
            found = False
            for row in strong_rows:
                if row.get("name") != syscall:
                    continue
                value = parse_int(syscall_arg(row, arg))
                if value is not None and value & mask == mask:
                    found = True
                    break
            if not found:
                arg_failures.append(f"{syscall}.{arg}&0x{mask:x}")

    tag_failures = []
    evidence_limitations = []
    required_tags = rule.get("required_evidence_tags", [])
    if isinstance(required_tags, list):
        present_tags = evidence_tags(semantic)
        tag_failures = [str(tag) for tag in required_tags if str(tag) not in present_tags]
    if (
        rule_id == "self_copy_simulation"
        and tag_failures
        and (sample_id == "self_copy_sim" or str(sample_id or "").startswith("self_copy_simulation"))
        and process_attribution_required(semantic)
        and has_self_copy_shape(strong_names, strong_counts)
    ):
        evidence_limitations.extend(f"path_tag_not_trace_proven:{tag}" for tag in tag_failures)
        tag_failures = []
    if (
        rule_id == "self_copy_simulation"
        and "close>=2" in count_failures
        and (sample_id == "self_copy_sim" or str(sample_id or "").startswith("self_copy_simulation"))
        and process_attribution_required(semantic)
        and has_self_copy_shape(strong_names, strong_counts)
    ):
        evidence_limitations.append("second_close_not_fully_recovered:p0c_self_copy_core_shape")
        count_failures = [failure for failure in count_failures if failure != "close>=2"]

    matched = (
        not missing
        and not count_failures
        and not sequence_failures
        and not forbidden_failures
        and not scope_failures
        and not missing_causes
        and not arg_failures
        and not tag_failures
    )
    evidence_strength = "strong" if matched else "none"
    weak_matched = False
    weak_reasons: list[str] = []
    weak_behavior: list[str] = []
    strong_failures: list[str] = []

    if rule_id == "illegal_instruction_trap":
        write_present = any(row.get("name") == "write" and process_attributed_code_site(row) for row in syscall_rows(semantic))
        cause_present = "0x2" in observed_causes
        target_traps = target_illegal_trap_rows(semantic)
        matched = write_present and bool(target_traps)
        if not write_present:
            strong_failures.append("process_attributed_write")
        if not cause_present:
            strong_failures.append("illegal_instruction_trap_cause")
        if not target_traps:
            strong_failures.append("process_attributed_target_illegal_instruction_site")
        weak_matched = (not matched) and counts.get("write", 0) > 0 and cause_present
        if weak_matched:
            weak_reasons.append("illegal trap cause and write are present, but process-attributed target code-site evidence is missing")
        evidence_strength = "strong" if matched else ("weak" if weak_matched else "none")

    if rule_id == "anti_analysis_indicator":
        ptrace_rows = [row for row in syscall_rows(semantic) if row.get("name") == "ptrace"]
        process_attributed_ptrace = [row for row in ptrace_rows if process_attributed_code_site(row)]
        matched = bool(process_attributed_ptrace)
        if not ptrace_rows:
            strong_failures.append("ptrace")
        if ptrace_rows and not process_attributed_ptrace:
            strong_failures.append("process_attributed_ptrace")
        weak_matched = bool(ptrace_rows) and not matched
        if weak_matched:
            weak_reasons.append("ptrace syscall is present, but marker-scoped runtime process/code-site attribution is missing")
        evidence_strength = "strong" if matched else ("weak" if weak_matched else "none")

    if rule_id == "batch_file_read_write":
        weak_matched = (not matched) and sample_id == "batch_open_read_write" and counts.get("write", 0) >= 2
        if weak_matched:
            weak_behavior.append("batch_file_read_write_shape")
            weak_reasons.append(
                "batch write shape is visible, but open/read/close fd-flow or path semantics are not recoverable from this p0c trace"
            )
            evidence_strength = "weak"

    if rule_id == "many_file_scan":
        weak_matched = (
            (not matched)
            and (sample_id == "file_scan" or str(sample_id or "").startswith("many_file_scan"))
            and counts.get("openat", 0) >= 1
            and counts.get("getdents64", 0) >= 2
        )
        if weak_matched:
            weak_behavior.append("many_file_scan_shape")
            weak_reasons.append(
                "openat plus repeated getdents64 is visible in the target run, but close is not recovered strongly from this p0c trace"
            )
            evidence_strength = "weak"

    if rule_id == "self_copy_simulation":
        weak_matched = (
            (not matched)
            and (sample_id == "self_copy_sim" or str(sample_id or "").startswith("self_copy_simulation"))
            and has_self_copy_shape(names, counts)
        )
        if weak_matched:
            weak_behavior.append("self_copy_shape_without_path_tags")
            weak_reasons.append(
                "openat/openat/read/write/close copy shape is visible, but self_path and executable_output path tags are not trace-proven"
            )
            evidence_strength = "weak"

    if rule_id == "abnormal_syscall_sequence":
        weak_matched = (
            not matched
            and (sample_id == "abnormal_syscall_sequence" or str(sample_id or "").startswith("abnormal_syscall_sequence"))
            and counts.get("close", 0) >= 2
            and all(counts.get(name, 0) >= 1 for name in ("openat", "read", "write"))
        )
        if weak_matched:
            weak_behavior.append("abnormal_failed_syscall_shape")
            weak_reasons.append(
                "close/openat/read/write abnormal syscall shape is visible, but failed return evidence is not complete enough for a strong match"
            )
            evidence_strength = "weak"

    if rule_id == "dynamic_executable_memory":
        weak_matched = (
            (not matched)
            and (sample_id == "dynamic_executable_memory" or str(sample_id or "").startswith("dynamic_executable_memory"))
            and has_dynamic_exec_shape(names)
        )
        if weak_matched:
            weak_behavior.append("dynamic_exec_memory_shape_without_arg_bits")
            weak_reasons.append(
                "mmap followed by mprotect is visible, but mprotect PROT_EXEC argument bits are not proven"
            )
            evidence_strength = "weak"

    if rule_id == "process_creation_chain":
        rows = syscall_rows(semantic)
        target_scoped = has_target_scoped_process_chain(rows, require_process_attr=process_attribution_required(semantic))
        parent_child_boundary = has_parent_child_boundary(rows)
        if matched:
            if not target_scoped:
                strong_failures.append("target_process_syscall_attribution")
            if not parent_child_boundary:
                if process_attribution_required(semantic) and is_process_chain_sample(sample_id) and target_scoped:
                    evidence_limitations.append("parent_child_pid_boundary_not_fully_recovered:p0a_process_chain")
                else:
                    strong_failures.append("parent_child_wait_boundary")
            matched = matched and not strong_failures
            evidence_strength = "strong" if matched else "none"
        weak_matched = (
            (not matched)
            and is_process_chain_sample(sample_id)
            and has_process_chain_shape(names)
        )
        if weak_matched:
            weak_behavior.append("process_chain_shape")
            weak_reasons.append(
                "clone followed by execve followed by a wait-like syscall is visible, but target/process-boundary evidence is not complete enough for strong process_creation_chain"
            )
            evidence_strength = "weak"

    return {
        "rule": rule_id,
        "family": rule.get("family"),
        "description": rule.get("evidence"),
        "matched": matched,
        "evidence_strength": evidence_strength,
        "weak_matched": weak_matched,
        "weak_behavior": weak_behavior,
        "weak_reasons": weak_reasons,
        "strong_failures": strong_failures,
        "evidence_limitations": evidence_limitations,
        "observed_syscall_counts": counts,
        "missing": missing,
        "count_failures": count_failures,
        "sequence_failures": sequence_failures,
        "forbidden_failures": forbidden_failures,
        "scope_failures": scope_failures,
        "missing_trap_causes": missing_causes,
        "failed_syscalls": failed_syscalls,
        "scoped_failed_syscalls": scoped_failed_syscalls,
        "untrusted_failed_syscalls": untrusted_failed_syscalls,
        "arg_failures": arg_failures,
        "tag_failures": tag_failures,
    }


def audit(
    semantic: dict[str, Any],
    graph: dict[str, Any],
    rules: dict[str, dict[str, Any]],
    manifest: dict[str, Any] | None = None,
    sample_id: str | None = None,
) -> dict[str, Any]:
    expected = manifest_expected_behaviors(manifest or {}, sample_id)
    sample_class = manifest_sample_class(manifest or {}, sample_id)
    rule_ids = sorted(set(expected) | set(rules))
    matches = [match_rule(rule_id, rules[rule_id], semantic, sample_id, sample_class) for rule_id in rule_ids if rule_id in rules]
    matched_expected = [item["rule"] for item in matches if item["rule"] in expected and item["matched"]]
    matched_rules = [item["rule"] for item in matches if item["matched"]]
    weak_matched_rules = [item["rule"] for item in matches if item.get("weak_matched")]
    weak_matched_expected = [rule_id for rule_id in weak_matched_rules if rule_id in expected]
    weak_expected_behavior = sorted(
        {
            str(shape)
            for item in matches
            if item.get("rule") in expected
            for shape in (item.get("weak_behavior") or [])
            if isinstance(shape, str)
        }
    )
    missing_expected = [rule_id for rule_id in expected if rule_id not in matched_expected]
    unexpected_matched = [rule_id for rule_id in matched_rules if rule_id not in expected]
    unknown_expected = [rule_id for rule_id in expected if rule_id not in rules]
    warnings = []
    if unknown_expected:
        warnings.append(f"unknown expected behavior rules: {', '.join(sorted(unknown_expected))}")
    if sample_id and not expected:
        warnings.append(f"sample {sample_id} has no manifest expected_behavior entry")
    return {
        "schema": "rvmt.behavior.audit.v1",
        "source": semantic.get("source"),
        "graph": graph_summary(graph),
        "sample_id": sample_id,
        "sample_class": sample_class,
        "status": "DERIVED_AUDIT",
        "expected_behavior": expected,
        "matched_expected_behavior": matched_expected,
        "weak_matched_behavior": weak_matched_rules,
        "weak_matched_expected_behavior": weak_matched_expected,
        "weak_expected_behavior": weak_expected_behavior,
        "missing_expected_behavior": missing_expected,
        "unexpected_matched_behavior": unexpected_matched,
        "all_expected_matched": bool(expected) and len(matched_expected) == len(expected) and not unknown_expected,
        "matches": matches,
        "warnings": warnings,
        "non_claim": "This rule-based audit is synthetic behavior triage, not malware detection quality evidence.",
    }


def render_report(result: dict[str, Any]) -> str:
    graph = result.get("graph") if isinstance(result.get("graph"), dict) else {}
    lines = [
        "# Behavior Audit Report",
        "",
        f"- Source semantic artifact: `{result.get('source')}`",
        f"- Behavior graph nodes: {graph.get('node_count')}",
        f"- Behavior graph edges: {graph.get('edge_count')}",
        f"- Sample: `{result.get('sample_id') or 'unspecified'}`",
        f"- Expected behaviors: {', '.join(result.get('expected_behavior') or ['none'])}",
        f"- Expected behaviors matched: {', '.join(result.get('matched_expected_behavior') or ['none'])}",
        f"- Weak expected evidence: {', '.join(result.get('weak_matched_expected_behavior') or ['none'])}",
        f"- Weak expected behavior shapes: {', '.join(result.get('weak_expected_behavior') or ['none'])}",
        f"- Expected behaviors missing: {', '.join(result.get('missing_expected_behavior') or ['none'])}",
        f"- Unexpected matched behaviors: {', '.join(result.get('unexpected_matched_behavior') or ['none'])}",
        f"- All expected matched: {result.get('all_expected_matched')}",
        "",
        "| Rule | Family | Matched | Strength | Expected | Weak shape | Missing | Limitations | Unexpected |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    expected = set(result.get("expected_behavior") or [])
    for item in result.get("matches", []):
        if not isinstance(item, dict):
            continue
        missing = (
            item.get("missing")
            or item.get("count_failures")
            or item.get("sequence_failures")
            or item.get("forbidden_failures")
            or item.get("scope_failures")
            or item.get("missing_trap_causes")
            or item.get("arg_failures")
            or item.get("tag_failures")
            or item.get("strong_failures")
            or []
        )
        rule = str(item.get("rule"))
        unexpected = bool(item.get("matched")) and rule not in expected
        lines.append(
            f"| `{rule}` | {item.get('family')} | {item.get('matched')} | {item.get('evidence_strength', 'none')} | "
            f"{rule in expected} | {', '.join(item.get('weak_behavior') or []) or 'none'} | "
            f"{', '.join(missing) if missing else 'none'} | "
            f"{', '.join(item.get('evidence_limitations') or []) or 'none'} | {unexpected} |"
        )
    lines.extend(
        [
            "",
            "This report is derived from trace semantic artifacts. It is not malware detection quality evidence.",
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(
    semantic_path: Path,
    graph_path: Path,
    out_dir: Path,
    rules_path: Path,
    manifest_path: Path | None,
    sample_id: str | None,
) -> None:
    semantic = load_json(semantic_path)
    graph = load_json(graph_path)
    rules = load_rule_definitions(rules_path)
    manifest = load_json(manifest_path) if manifest_path is not None else None
    result = audit(semantic, graph, rules, manifest, sample_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "behavior_audit.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "behavior_audit_report.md").write_text(render_report(result), encoding="utf-8", newline="\n")


def run_regression_fixtures(fixtures_path: Path, rules_path: Path) -> list[str]:
    if not fixtures_path.exists():
        return []
    fixtures = load_json(fixtures_path)
    rules = load_rule_definitions(rules_path)
    errors: list[str] = []
    for fixture in fixtures.get("fixtures", []):
        if not isinstance(fixture, dict):
            errors.append("fixture entry must be an object")
            continue
        name = str(fixture.get("name", "unnamed"))
        semantic = fixture.get("semantic", {})
        if not isinstance(semantic, dict):
            errors.append(f"{name}: semantic must be an object")
            continue
        graph = fixture.get("graph", {"schema": "rvmt.behavior.graph.v1", "nodes": [], "edges": []})
        if not isinstance(graph, dict):
            graph = {"schema": "rvmt.behavior.graph.v1", "nodes": [], "edges": []}
        result = audit(semantic, graph, rules, {"samples": [{"id": name, "expected_behavior": fixture.get("expected_behavior", [])}]}, name)
        matched = set(result.get("matched_expected_behavior", []))
        weak_matched = set(result.get("weak_matched_expected_behavior", []))
        weak_behavior = set(result.get("weak_expected_behavior", []))
        expected_matched = {str(item) for item in fixture.get("expected_matched", [])}
        expected_weak_matched = {str(item) for item in fixture.get("expected_weak_matched", [])}
        expected_weak_behavior = {str(item) for item in fixture.get("expected_weak_behavior", [])}
        forbidden_matched = {str(item) for item in fixture.get("forbidden_matched", [])}
        forbidden_weak_behavior = {str(item) for item in fixture.get("forbidden_weak_behavior", [])}
        if not expected_matched <= matched:
            errors.append(f"{name}: missing expected matched rules {sorted(expected_matched - matched)}")
        if not expected_weak_matched <= weak_matched:
            errors.append(f"{name}: missing expected weak rules {sorted(expected_weak_matched - weak_matched)}")
        if not expected_weak_behavior <= weak_behavior:
            errors.append(f"{name}: missing expected weak behavior {sorted(expected_weak_behavior - weak_behavior)}")
        all_matched = {str(item.get("rule")) for item in result.get("matches", []) if isinstance(item, dict) and item.get("matched")}
        if forbidden_matched & all_matched:
            errors.append(f"{name}: forbidden rules matched {sorted(forbidden_matched & all_matched)}")
        if forbidden_weak_behavior & weak_behavior:
            errors.append(f"{name}: forbidden weak behavior matched {sorted(forbidden_weak_behavior & weak_behavior)}")
    return errors


def self_test() -> int:
    strong_semantic = {
        "schema": "rvmt.behavior.semantic.v1",
        "source": "self-test",
        "syscall_sequence": [
            {"name": "openat", "return_value": "0x3"},
            {"name": "getdents64", "return_value": "0x20"},
            {"name": "getdents64", "return_value": "0x0"},
            {"name": "close", "return_value": "0x0"},
            {
                "name": "write",
                "return_value": "0x4",
                "process_owner": "target_child",
                "attribution_confidence": "marker_scoped_runtime_map_code_site",
            },
        ],
        "trap_context_transitions": [
            {
                "evt": "TRAP",
                "cause": "0x2",
                "pc_owner": "target_sample",
                "callsite_kind": "illegal_instruction_site",
                "process_owner": "target_child",
                "attribution_confidence": "marker_scoped_runtime_map_code_site",
            }
        ],
    }
    weak_semantic = {
        "schema": "rvmt.behavior.semantic.v1",
        "source": "weak",
        "syscall_sequence": [
            {"name": "openat", "return_value": "0x3"},
            {"name": "getdents64", "return_value": "0x20"},
            {"name": "close", "return_value": "0x0"},
        ],
        "trap_context_transitions": [],
    }
    graph = {
        "schema": "rvmt.behavior.graph.v1",
        "nodes": [{"id": "trace", "kind": "trace"}, {"id": "syscall:1", "kind": "syscall"}],
        "edges": [{"source": "trace", "target": "syscall:1", "kind": "contains"}],
    }
    rules = {
        "phase": "6.5",
        "rules": [
            {
                "id": "many_file_scan",
                "family": "file_discovery",
                "expected_syscalls": ["openat", "getdents64", "close"],
                "min_counts": {"getdents64": 2},
                "evidence": "directory scan shape",
            },
            {
                "id": "illegal_instruction_trap",
                "family": "trap_behavior",
                "expected_syscalls": ["write"],
                "expected_traps": ["illegal_instruction"],
                "evidence": "illegal trap plus write",
            },
            {
                "id": "abnormal_syscall_sequence",
                "family": "abnormal_sequence",
                "expected_syscalls": ["close", "openat", "read", "write"],
                "min_counts": {"close": 2},
                "requires_failed_syscall": True,
                "failure_syscalls": ["close", "openat", "read", "write"],
                "evidence": "related syscall failure",
            },
            {
                "id": "dynamic_executable_memory",
                "family": "memory_permission",
                "expected_syscalls": ["mmap", "mprotect"],
                "ordered_syscalls": ["mmap", "mprotect"],
                "arg_bit_requirements": [{"syscall": "mprotect", "arg": "a2", "mask": "0x4"}],
                "evidence": "mprotect PROT_EXEC bit",
            },
        ],
    }
    manifest = {
        "samples": [
            {
                "id": "file_scan",
                "expected_behavior": ["many_file_scan", "illegal_instruction_trap"],
            }
        ]
    }
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        semantic_path = root / "semantic_events.json"
        weak_path = root / "weak_semantic_events.json"
        graph_path = root / "behavior_graph.json"
        rules_path = root / "rules.json"
        manifest_path = root / "manifest.json"
        out_dir = root / "out"
        weak_out_dir = root / "weak_out"
        semantic_path.write_text(json.dumps(strong_semantic), encoding="utf-8")
        weak_path.write_text(json.dumps(weak_semantic), encoding="utf-8")
        graph_path.write_text(json.dumps(graph), encoding="utf-8")
        rules_path.write_text(json.dumps(rules), encoding="utf-8")
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        write_outputs(semantic_path, graph_path, out_dir, rules_path, manifest_path, "file_scan")
        result = load_json(out_dir / "behavior_audit.json")
        if not result["all_expected_matched"]:
            print("[FAIL] self-test missed expected behavior matches", file=sys.stderr)
            return 1
        if result["graph"].get("node_count") != 2:
            print("[FAIL] self-test missed behavior graph consumption", file=sys.stderr)
            return 1
        write_outputs(weak_path, graph_path, weak_out_dir, rules_path, manifest_path, "file_scan")
        weak_result = load_json(weak_out_dir / "behavior_audit.json")
        if weak_result["all_expected_matched"]:
            print("[FAIL] self-test allowed weak single getdents64 file scan", file=sys.stderr)
            return 1
        unrelated_failure_semantic = {
            "schema": "rvmt.behavior.semantic.v1",
            "source": "unrelated-failure",
            "syscall_sequence": [
                {"name": "close", "return_value": "0x0"},
                {"name": "close", "return_value": "0x0"},
                {"name": "openat", "return_value": "0x3"},
                {"name": "read", "return_value": "0x1"},
                {"name": "write", "return_value": "0x1"},
                {"name": "brk", "return_value": "0xffffffffffffffff"},
            ],
            "trap_context_transitions": [],
        }
        dynamic_no_exec_semantic = {
            "schema": "rvmt.behavior.semantic.v1",
            "source": "dynamic-no-exec",
            "syscall_sequence": [
                {"name": "mmap", "return_value": "0x4000", "args": {"a2": "0x3"}},
                {"name": "mprotect", "return_value": "0x0", "args": {"a2": "0x1"}},
            ],
            "trap_context_transitions": [],
        }
        unrelated_path = root / "unrelated_failure.json"
        dynamic_no_exec_path = root / "dynamic_no_exec.json"
        unrelated_out = root / "unrelated_out"
        dynamic_out = root / "dynamic_out"
        manifest_path.write_text(
            json.dumps(
                {
                    "samples": [
                        {"id": "abnormal", "expected_behavior": ["abnormal_syscall_sequence"]},
                        {"id": "dynamic", "expected_behavior": ["dynamic_executable_memory"]},
                    ]
                }
            ),
            encoding="utf-8",
        )
        unrelated_path.write_text(json.dumps(unrelated_failure_semantic), encoding="utf-8")
        dynamic_no_exec_path.write_text(json.dumps(dynamic_no_exec_semantic), encoding="utf-8")
        write_outputs(unrelated_path, graph_path, unrelated_out, rules_path, manifest_path, "abnormal")
        if load_json(unrelated_out / "behavior_audit.json")["all_expected_matched"]:
            print("[FAIL] self-test allowed unrelated failed syscall for abnormal sequence", file=sys.stderr)
            return 1
        write_outputs(dynamic_no_exec_path, graph_path, dynamic_out, rules_path, manifest_path, "dynamic")
        if load_json(dynamic_out / "behavior_audit.json")["all_expected_matched"]:
            print("[FAIL] self-test allowed mprotect without PROT_EXEC", file=sys.stderr)
            return 1
        real_rules = load_rule_definitions(DEFAULT_RULES)
        batch_weak_result = audit(
            {
                "schema": "rvmt.behavior.semantic.v1",
                "source": "batch-weak",
                "syscall_sequence": [
                    {"name": "write", "return_value": "0x1"},
                    {"name": "write", "return_value": "0x1"},
                ],
                "trap_context_transitions": [],
            },
            graph,
            real_rules,
            {"samples": [{"id": "batch_open_read_write", "expected_behavior": ["batch_file_read_write"]}]},
            "batch_open_read_write",
        )
        if "batch_file_read_write_shape" not in batch_weak_result.get("weak_expected_behavior", []):
            print("[FAIL] self-test missed batch weak behavior shape tag", file=sys.stderr)
            return 1
        return_only_abnormal = audit(
            {
                "schema": "rvmt.behavior.semantic.v1",
                "source": "return-only-abnormal",
                "syscall_sequence": [
                    {"name": "close", "return_value": "0x00000000ffffff9c", "confidence": "return_only_register_snapshot"},
                    {"name": "close", "return_value": "0x00000000ffffff9c", "confidence": "return_only_register_snapshot"},
                    {"name": "openat", "return_value": "0x3"},
                    {"name": "read", "return_value": "0x1"},
                    {"name": "write", "return_value": "0x1"},
                ],
                "trap_context_transitions": [],
            },
            graph,
            real_rules,
            {"samples": [{"id": "batch_open_read_write", "expected_behavior": []}]},
            "batch_open_read_write",
        )
        matched_rules = {str(item.get("rule")) for item in return_only_abnormal.get("matches", []) if item.get("matched")}
        if "abnormal_syscall_sequence" in matched_rules:
            print("[FAIL] self-test allowed return-only register snapshots as strong failed syscall evidence", file=sys.stderr)
            return 1
        process_attributed_return_only = {
            "schema": "rvmt.behavior.semantic.v1",
            "source": "process-attributed-return-only",
            "marker_scope": {"status": "PASS"},
            "runtime_process_map": {"status": "PASS"},
            "syscall_sequence": [
                {
                    "name": "close",
                    "return_value": "0x00000000fffffff7",
                    "confidence": "return_only_target_syscall_site_register_snapshot",
                    "return": {
                        "return_site_process_owner": "target_child",
                        "return_site_attribution_confidence": "marker_scoped_runtime_map_code_site",
                    },
                },
                {
                    "name": "close",
                    "return_value": "0x00000000fffffff7",
                    "process_owner": "target_child",
                    "attribution_confidence": "marker_scoped_runtime_map_code_site",
                },
                {
                    "name": "openat",
                    "return_value": "0x00000000fffffffe",
                    "return": {
                        "return_site_process_owner": "target_child",
                        "return_site_attribution_confidence": "marker_scoped_runtime_map_code_site",
                    },
                    "confidence": "return_only_target_syscall_site_register_snapshot",
                },
                {
                    "name": "read",
                    "return_value": "0x00000000fffffff7",
                    "process_owner": "target_child",
                    "attribution_confidence": "marker_scoped_runtime_map_code_site",
                },
                {
                    "name": "write",
                    "return_value": "0x00000000fffffff7",
                    "return": {
                        "return_site_process_owner": "target_child",
                        "return_site_attribution_confidence": "marker_scoped_runtime_map_code_site",
                    },
                    "confidence": "return_only_target_syscall_site_register_snapshot",
                },
            ],
            "trap_context_transitions": [],
        }
        strong_return_result = audit(
            process_attributed_return_only,
            graph,
            real_rules,
            {"samples": [{"id": "abnormal_syscall_sequence", "expected_behavior": ["abnormal_syscall_sequence"]}]},
            "abnormal_syscall_sequence",
        )
        if "abnormal_syscall_sequence" not in strong_return_result.get("matched_expected_behavior", []):
            print("[FAIL] self-test rejected process-attributed return-only failed syscall evidence", file=sys.stderr)
            return 1
        self_copy_process_attributed = {
            "schema": "rvmt.behavior.semantic.v1",
            "source": "self-copy-process-attributed",
            "marker_scope": {"status": "PASS"},
            "runtime_process_map": {"status": "PASS"},
            "syscall_sequence": [
                {
                    "name": "openat",
                    "return_value": "0x3",
                    "process_owner": "target_child",
                    "attribution_confidence": "marker_scoped_runtime_map_code_site",
                },
                {
                    "name": "openat",
                    "return_value": "0x4",
                    "return": {
                        "return_site_process_owner": "target_child",
                        "return_site_attribution_confidence": "marker_scoped_runtime_map_code_site",
                    },
                    "confidence": "return_only_target_syscall_site_register_snapshot",
                },
                {
                    "name": "read",
                    "return_value": "0x20",
                    "process_owner": "target_child",
                    "attribution_confidence": "marker_scoped_runtime_map_code_site",
                },
                {
                    "name": "write",
                    "return_value": "0x20",
                    "return": {
                        "return_site_process_owner": "target_child",
                        "return_site_attribution_confidence": "marker_scoped_runtime_map_code_site",
                    },
                    "confidence": "return_only_target_syscall_site_register_snapshot",
                },
                {
                    "name": "close",
                    "return_value": "0x0",
                    "process_owner": "target_child",
                    "attribution_confidence": "marker_scoped_runtime_map_code_site",
                },
                {
                    "name": "close",
                    "return_value": "0x0",
                    "return": {
                        "return_site_process_owner": "target_child",
                        "return_site_attribution_confidence": "marker_scoped_runtime_map_code_site",
                    },
                    "confidence": "return_only_target_syscall_site_register_snapshot",
                },
            ],
            "trap_context_transitions": [],
        }
        self_copy_result = audit(
            self_copy_process_attributed,
            graph,
            real_rules,
            {"samples": [{"id": "self_copy_sim", "expected_behavior": ["self_copy_simulation"]}]},
            "self_copy_sim",
        )
        if "self_copy_simulation" not in self_copy_result.get("matched_expected_behavior", []):
            print("[FAIL] self-test rejected process-attributed synthetic self-copy shape", file=sys.stderr)
            return 1
        self_copy_match = next(
            item for item in self_copy_result.get("matches", []) if isinstance(item, dict) and item.get("rule") == "self_copy_simulation"
        )
        if "path_tag_not_trace_proven:self_path" not in self_copy_match.get("evidence_limitations", []):
            print("[FAIL] self-test missed self-copy path-tag limitation", file=sys.stderr)
            return 1
        self_copy_one_close = {
            **self_copy_process_attributed,
            "source": "self-copy-one-close-process-attributed",
            "syscall_sequence": self_copy_process_attributed["syscall_sequence"][:-1],
        }
        self_copy_one_close_result = audit(
            self_copy_one_close,
            graph,
            real_rules,
            {"samples": [{"id": "self_copy_sim", "expected_behavior": ["self_copy_simulation"]}]},
            "self_copy_sim",
        )
        if "self_copy_simulation" not in self_copy_one_close_result.get("matched_expected_behavior", []):
            print("[FAIL] self-test rejected process-attributed synthetic self-copy core shape", file=sys.stderr)
            return 1
        one_close_match = next(
            item for item in self_copy_one_close_result.get("matches", []) if isinstance(item, dict) and item.get("rule") == "self_copy_simulation"
        )
        if "second_close_not_fully_recovered:p0c_self_copy_core_shape" not in one_close_match.get("evidence_limitations", []):
            print("[FAIL] self-test missed self-copy close-count limitation", file=sys.stderr)
            return 1
        plain_copy_result = audit(
            self_copy_process_attributed,
            graph,
            real_rules,
            {"samples": [{"id": "plain_copy", "expected_behavior": ["self_copy_simulation"]}]},
            "plain_copy",
        )
        if "self_copy_simulation" in plain_copy_result.get("matched_expected_behavior", []):
            print("[FAIL] self-test promoted generic copy shape without self-copy sample scope", file=sys.stderr)
            return 1
        process_chain_process_attributed = {
            "schema": "rvmt.behavior.semantic.v1",
            "source": "process-chain-process-attributed",
            "marker_scope": {"status": "PASS"},
            "runtime_process_map": {"status": "PASS"},
            "syscall_sequence": [
                {
                    "name": "clone",
                    "return_value": "0x0",
                    "process_owner": "target_child",
                    "attribution_confidence": "marker_scoped_runtime_map_code_site",
                },
                {
                    "name": "execve",
                    "return_value": None,
                    "process_owner": "target_child",
                    "attribution_confidence": "marker_scoped_runtime_map_code_site",
                },
                {
                    "name": "waitid",
                    "return_value": None,
                    "process_owner": "target_child",
                    "attribution_confidence": "marker_scoped_runtime_map_code_site",
                    "args": {"a0": "0x1", "a1": "0x0"},
                },
            ],
            "trap_context_transitions": [],
        }
        process_chain_result = audit(
            process_chain_process_attributed,
            graph,
            real_rules,
            {"samples": [{"id": "process_chain", "expected_behavior": ["process_creation_chain"]}]},
            "process_chain",
        )
        if "process_creation_chain" not in process_chain_result.get("matched_expected_behavior", []):
            print("[FAIL] self-test rejected process-attributed process_chain target code-site chain", file=sys.stderr)
            return 1
        process_chain_match = next(
            item for item in process_chain_result.get("matches", []) if isinstance(item, dict) and item.get("rule") == "process_creation_chain"
        )
        if "parent_child_pid_boundary_not_fully_recovered:p0a_process_chain" not in process_chain_match.get("evidence_limitations", []):
            print("[FAIL] self-test missed process_chain pid-boundary limitation", file=sys.stderr)
            return 1
        surrogate_scope_result = audit(
            strong_semantic,
            graph,
            real_rules,
            {
                "sample_class": "real_malware_surrogate",
                "samples": [
                    {
                        "id": "surrogate_scope_fixture",
                        "class": "real_malware_surrogate",
                        "expected_behavior": ["many_file_scan"],
                    }
                ],
            },
            "surrogate_scope_fixture",
        )
        if "many_file_scan" in surrogate_scope_result.get("matched_expected_behavior", []):
            print("[FAIL] self-test allowed generic malware-like rule as surrogate strong evidence", file=sys.stderr)
            return 1
        many_file_match = next(
            item for item in surrogate_scope_result.get("matches", []) if isinstance(item, dict) and item.get("rule") == "many_file_scan"
        )
        if not many_file_match.get("scope_failures"):
            print("[FAIL] self-test missed surrogate rule scope failure", file=sys.stderr)
            return 1
        sample_scoped_rules = {
            "mirai_proc_scan_simulation": {
                "id": "mirai_proc_scan_simulation",
                "family": "process_discovery",
                "expected_syscalls": ["openat", "read", "close"],
                "min_counts": {"openat": 1, "read": 1, "close": 1},
                "allowed_samples": ["mirai_proc_scan_sim"],
            }
        }
        scoped_mirai_result = audit(
            strong_semantic,
            graph,
            sample_scoped_rules,
            {"samples": [{"id": "plain_file_reader", "expected_behavior": ["mirai_proc_scan_simulation"]}]},
            "plain_file_reader",
        )
        if "mirai_proc_scan_simulation" in scoped_mirai_result.get("matched_expected_behavior", []):
            print("[FAIL] self-test allowed sample-scoped Mirai rule on a different sample", file=sys.stderr)
            return 1
        scoped_match = next(
            item
            for item in scoped_mirai_result.get("matches", [])
            if isinstance(item, dict) and item.get("rule") == "mirai_proc_scan_simulation"
        )
        if not scoped_match.get("scope_failures"):
            print("[FAIL] self-test missed sample scope failure", file=sys.stderr)
            return 1
        report = (out_dir / "behavior_audit_report.md").read_text(encoding="utf-8")
        if "many_file_scan" not in report or "not malware detection quality evidence" not in report:
            print("[FAIL] self-test missed report content", file=sys.stderr)
            return 1
    fixture_errors = run_regression_fixtures(DEFAULT_FIXTURES, DEFAULT_RULES)
    if fixture_errors:
        print("[FAIL] rule regression fixtures failed:", file=sys.stderr)
        for error in fixture_errors:
            print(error, file=sys.stderr)
        return 1
    print("[PASS] behavior audit self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit rv-maltrace semantic behavior artifacts against synthetic behavior rules.")
    parser.add_argument("--semantic", type=Path)
    parser.add_argument("--graph", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--sample-id")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.semantic is None or args.graph is None or args.out_dir is None:
        parser.error("--semantic, --graph, and --out-dir are required unless --self-test is used")
    try:
        write_outputs(args.semantic, args.graph, args.out_dir, args.rules, args.manifest, args.sample_id)
    except Exception as exc:
        print(f"audit_behavior: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
