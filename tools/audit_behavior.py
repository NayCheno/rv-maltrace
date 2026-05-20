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
    return (1 << 64) - 4095 <= number <= (1 << 64) - 1


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


def match_rule(rule_id: str, rule: dict[str, Any], semantic: dict[str, Any]) -> dict[str, Any]:
    names = syscall_names(semantic)
    counts = {name: names.count(name) for name in sorted(set(names))}
    missing = [name for name in rule.get("expected_syscalls", []) if name not in counts]

    any_syscalls = rule.get("any_syscalls", [])
    if any_syscalls and not any(name in counts for name in any_syscalls):
        missing.append("any:" + ",".join(any_syscalls))

    count_failures = []
    min_counts = rule.get("min_counts", {})
    if isinstance(min_counts, dict):
        for name, minimum in sorted(min_counts.items()):
            minimum_int = parse_int(minimum)
            if minimum_int is None:
                count_failures.append(f"{name}>=invalid")
            elif counts.get(name, 0) < minimum_int:
                count_failures.append(f"{name}>={minimum_int}")

    ordered = rule.get("ordered_syscalls", [])
    sequence_failures = []
    if isinstance(ordered, list) and ordered and not has_ordered_subsequence(names, [str(item) for item in ordered]):
        sequence_failures.append("ordered:" + ",".join(str(item) for item in ordered))

    observed_causes = trap_causes(semantic)
    missing_causes = []
    for expected in rule.get("expected_traps", []):
        expected_hex = canonical_hex(expected)
        if expected_hex not in observed_causes:
            missing_causes.append(str(expected))

    failed_rows = [row for row in syscall_rows(semantic) if is_linux_error(row.get("return_value"))]
    failed_syscalls = [row.get("name", "unknown") for row in failed_rows]
    failure_scope = rule.get("failure_syscalls")
    if not isinstance(failure_scope, list) or not failure_scope:
        failure_scope = rule.get("expected_syscalls", [])
    scoped_failed_syscalls = [
        row.get("name", "unknown")
        for row in failed_rows
        if isinstance(row.get("name"), str) and row.get("name") in failure_scope
    ]
    if rule.get("requires_failed_syscall") and not scoped_failed_syscalls:
        missing.append("failed_syscall_return")

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
            for row in syscall_rows(semantic):
                if row.get("name") != syscall:
                    continue
                value = parse_int(syscall_arg(row, arg))
                if value is not None and value & mask == mask:
                    found = True
                    break
            if not found:
                arg_failures.append(f"{syscall}.{arg}&0x{mask:x}")

    tag_failures = []
    required_tags = rule.get("required_evidence_tags", [])
    if isinstance(required_tags, list):
        present_tags = evidence_tags(semantic)
        tag_failures = [str(tag) for tag in required_tags if str(tag) not in present_tags]

    matched = not missing and not count_failures and not sequence_failures and not missing_causes and not arg_failures and not tag_failures
    return {
        "rule": rule_id,
        "family": rule.get("family"),
        "description": rule.get("evidence"),
        "matched": matched,
        "observed_syscall_counts": counts,
        "missing": missing,
        "count_failures": count_failures,
        "sequence_failures": sequence_failures,
        "missing_trap_causes": missing_causes,
        "failed_syscalls": failed_syscalls,
        "scoped_failed_syscalls": scoped_failed_syscalls,
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
    rule_ids = sorted(set(expected) | set(rules))
    matches = [match_rule(rule_id, rules[rule_id], semantic) for rule_id in rule_ids if rule_id in rules]
    matched_expected = [item["rule"] for item in matches if item["rule"] in expected and item["matched"]]
    matched_rules = [item["rule"] for item in matches if item["matched"]]
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
        "status": "DERIVED_AUDIT",
        "expected_behavior": expected,
        "matched_expected_behavior": matched_expected,
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
        f"- Expected behaviors missing: {', '.join(result.get('missing_expected_behavior') or ['none'])}",
        f"- Unexpected matched behaviors: {', '.join(result.get('unexpected_matched_behavior') or ['none'])}",
        f"- All expected matched: {result.get('all_expected_matched')}",
        "",
        "| Rule | Family | Matched | Expected | Missing | Unexpected |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    expected = set(result.get("expected_behavior") or [])
    for item in result.get("matches", []):
        if not isinstance(item, dict):
            continue
        missing = (
            item.get("missing")
            or item.get("count_failures")
            or item.get("sequence_failures")
            or item.get("missing_trap_causes")
            or item.get("arg_failures")
            or item.get("tag_failures")
            or []
        )
        rule = str(item.get("rule"))
        unexpected = bool(item.get("matched")) and rule not in expected
        lines.append(
            f"| `{rule}` | {item.get('family')} | {item.get('matched')} | {rule in expected} | "
            f"{', '.join(missing) if missing else 'none'} | {unexpected} |"
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
        expected_matched = {str(item) for item in fixture.get("expected_matched", [])}
        forbidden_matched = {str(item) for item in fixture.get("forbidden_matched", [])}
        if not expected_matched <= matched:
            errors.append(f"{name}: missing expected matched rules {sorted(expected_matched - matched)}")
        all_matched = {str(item.get("rule")) for item in result.get("matches", []) if isinstance(item, dict) and item.get("matched")}
        if forbidden_matched & all_matched:
            errors.append(f"{name}: forbidden rules matched {sorted(forbidden_matched & all_matched)}")
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
            {"name": "write", "return_value": "0x4"},
        ],
        "trap_context_transitions": [{"evt": "TRAP", "cause": "0x2"}],
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
