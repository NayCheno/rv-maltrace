from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_SPEC = Path("experiments/linux_behavior/behavior_audit_rules.json")
DEFAULT_DOC = Path("docs/04-runtime-linux/linux_behavior_audit.md")
DEFAULT_TOOL = Path("tools/audit_behavior.py")
DEFAULT_MANIFEST = Path("experiments/linux_behavior/malware_like/manifest.json")
DEFAULT_POLICY = Path("experiments/linux_behavior/policy.json")
DEFAULT_UV_DOC = Path("docs/10-process/uv_workflow.md")

SPEC_KEYS = {
    "phase",
    "status",
    "policy_ref",
    "dataset_ref",
    "input_artifacts",
    "output_artifacts",
    "rules",
    "non_goals",
}
RULE_KEYS = {
    "id",
    "family",
    "expected_syscalls",
    "any_syscalls",
    "min_counts",
    "ordered_syscalls",
    "requires_failed_syscall",
    "failure_syscalls",
    "arg_bit_requirements",
    "expected_traps",
    "evidence",
}
EXPECTED_RULES: dict[str, dict[str, Any]] = {
    "many_file_scan": {
        "family": "file_discovery",
        "expected_syscalls": ["openat", "getdents64", "close"],
        "min_counts": {"getdents64": 2},
    },
    "batch_file_read_write": {
        "family": "collection_staging",
        "expected_syscalls": ["openat", "read", "write", "close"],
        "min_counts": {"openat": 2, "close": 2},
        "ordered_syscalls": ["openat", "read", "close", "openat", "write", "close"],
    },
    "self_copy_simulation": {
        "family": "dropper_like",
        "expected_syscalls": ["openat", "read", "write", "close"],
        "min_counts": {"openat": 2, "close": 2},
        "ordered_syscalls": ["openat", "read", "openat", "write", "close"],
    },
    "abnormal_syscall_sequence": {
        "family": "abnormal_sequence",
        "expected_syscalls": ["close", "openat", "read", "write"],
        "min_counts": {"close": 2},
        "requires_failed_syscall": True,
        "failure_syscalls": ["close", "openat", "read", "write"],
    },
    "illegal_instruction_trap": {
        "family": "trap_behavior",
        "expected_syscalls": ["write"],
        "expected_traps": ["illegal_instruction"],
    },
    "process_creation_chain": {
        "family": "process_chain",
        "expected_syscalls": ["clone", "execve", "waitid"],
        "ordered_syscalls": ["clone", "execve", "waitid"],
    },
    "dynamic_executable_memory": {
        "family": "memory_permission",
        "expected_syscalls": ["mmap", "mprotect"],
        "ordered_syscalls": ["mmap", "mprotect"],
        "arg_bit_requirements": [{"syscall": "mprotect", "arg": "a2", "mask": "0x4"}],
    },
    "anti_analysis_indicator": {
        "family": "anti_analysis",
        "any_syscalls": ["ptrace", "clock_gettime"],
    },
}
REQUIRED_DOC_TEXT = (
    "Phase 6.5 defines the rule-based synthetic behavior audit",
    "synthetic case-study gate, not board evidence, Linux experiment evidence, or malware detection quality evidence",
    "experiments/linux_behavior/behavior_audit_rules.json",
    "semantic_events.json",
    "behavior_graph.json",
    "behavior_audit.json",
    "behavior_audit_report.md",
    "tools/audit_behavior.py",
    "experiments/linux_behavior/malware_like/manifest.json",
    "must not be used to claim malware detection quality",
)
FORBIDDEN_DOC_PATTERNS = (
    re.compile(r"\bPASS\b", re.IGNORECASE),
    re.compile(
        r"\bmalware\s+detection\s+quality\s+(?:is|are|has|have)?\s*"
        r"(?:been\s+)?(?:validated|proven|measured|passed|complete)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:phase\s*6(?:\.5)?\s+)?(?:behavior\s+audit|audit)\s+"
        r"(?:validation\s+)?(?:is|has)?\s*(?:been\s+)?(?:complete|validated|passed)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\breal\s+malware\s+(?:is\s+)?(?:allowed|included|executed|validated)\b", re.IGNORECASE),
)


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def normalized_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def rules_by_id(spec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rules = spec.get("rules")
    if not isinstance(rules, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for rule in rules:
        if isinstance(rule, dict) and isinstance(rule.get("id"), str):
            result[rule["id"]] = rule
    return result


def check_policy(path: Path) -> list[str]:
    policy = load_json(path)
    errors: list[str] = []
    if policy.get("real_malware_policy") != "FORBIDDEN_EARLY":
        errors.append(f"{path}: Phase 6.1 real malware policy must remain FORBIDDEN_EARLY")
    if "malware_like_synthetic" not in policy.get("allowed_sample_classes", []):
        errors.append(f"{path}: malware_like_synthetic must remain allowed")
    if "real_malware" not in policy.get("blocked_sample_classes", []):
        errors.append(f"{path}: real_malware must remain blocked")
    return errors


def check_spec(path: Path) -> list[str]:
    spec = load_json(path)
    errors: list[str] = []
    extra_keys = set(spec) - SPEC_KEYS
    missing_keys = SPEC_KEYS - set(spec)
    if extra_keys:
        errors.append(f"{path}: unexpected spec keys are not allowed: {sorted(extra_keys)}")
    if missing_keys:
        errors.append(f"{path}: missing required spec keys: {sorted(missing_keys)}")
    if spec.get("phase") != "6.5":
        errors.append(f"{path}: phase must be 6.5")
    if spec.get("status") != "TODO(EXPERIMENT)":
        errors.append(f"{path}: status must remain TODO(EXPERIMENT)")
    if spec.get("policy_ref") != "experiments/linux_behavior/policy.json":
        errors.append(f"{path}: policy_ref must point at the Phase 6.1 policy")
    if spec.get("dataset_ref") != "experiments/linux_behavior/malware_like/manifest.json":
        errors.append(f"{path}: dataset_ref must point at the Phase 6.3 manifest")
    if spec.get("input_artifacts") != ["semantic_events.json", "behavior_graph.json"]:
        errors.append(f"{path}: input_artifacts must be semantic_events.json and behavior_graph.json")
    if spec.get("output_artifacts") != ["behavior_audit.json", "behavior_audit_report.md"]:
        errors.append(f"{path}: output_artifacts must be behavior_audit.json and behavior_audit_report.md")
    if spec.get("non_goals") != ["real malware execution", "malware detection quality claim", "classifier accuracy claim"]:
        errors.append(f"{path}: non_goals must block real malware, detection-quality, and classifier claims")

    rules = rules_by_id(spec)
    if set(rules) != set(EXPECTED_RULES):
        errors.append(f"{path}: rule ids differ from expected set: {sorted(rules)}")
    for rule_id, expected in EXPECTED_RULES.items():
        rule = rules.get(rule_id, {})
        extra_rule_keys = set(rule) - RULE_KEYS
        if extra_rule_keys:
            errors.append(f"{path}: {rule_id} has unexpected keys: {sorted(extra_rule_keys)}")
        for field, value in expected.items():
            if rule.get(field) != value:
                errors.append(f"{path}: {rule_id}.{field} must be {value!r}")
        if not isinstance(rule.get("evidence"), str) or not rule.get("evidence"):
            errors.append(f"{path}: {rule_id}.evidence must explain the audit evidence")
    return errors


def parse_table_rows(text: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip("|").split("|")]
        if cells and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            continue
        if cells and cells[0] == "Order":
            continue
        rows.append(cells)
    return rows


def check_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    normalized = normalized_text(text)
    errors: list[str] = []
    for required in REQUIRED_DOC_TEXT:
        if normalized_text(required) not in normalized:
            errors.append(f"{path}: missing required text: {required}")
    for pattern in FORBIDDEN_DOC_PATTERNS:
        if pattern.search(text):
            errors.append(f"{path}: must not claim Phase 6.5 pass or malware-detection quality")
    rows = parse_table_rows(text)
    by_rule = {row[1]: row for row in rows if len(row) >= 5}
    for index, rule_id in enumerate(EXPECTED_RULES, start=1):
        row = by_rule.get(rule_id)
        if row is None:
            errors.append(f"{path}: missing rule row for {rule_id}")
            continue
        if row[0] != str(index):
            errors.append(f"{path}: {rule_id} order must be {index}")
        if row[4] != "TODO(EXPERIMENT)":
            errors.append(f"{path}: {rule_id} status must remain TODO(EXPERIMENT)")
    return errors


def check_manifest(path: Path, spec: Path) -> list[str]:
    manifest = load_json(path)
    rules = set(rules_by_id(load_json(spec)))
    errors: list[str] = []
    samples = manifest.get("samples", [])
    if not isinstance(samples, list):
        return [f"{path}: samples must be a list"]
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        behaviors = sample.get("expected_behavior", [])
        if not isinstance(behaviors, list):
            errors.append(f"{path}: {sample.get('id')}.expected_behavior must be a list")
            continue
        unknown = [item for item in behaviors if isinstance(item, str) and item not in rules]
        if unknown:
            errors.append(f"{path}: {sample.get('id')}.expected_behavior has undefined audit rules: {unknown}")
    return errors


def check_uv_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    for token, label in (
        ("tools/audit_behavior.py --self-test", "audit self-test command"),
        ("--graph build/behavior_recovery_smoke/behavior_graph.json", "audit graph argument"),
        ("tools/check_linux_behavior_audit.py", "Phase 6.5 checker command"),
        ("docs/04-runtime-linux/linux_behavior_audit.md", "Phase 6.5 doc reference"),
        ("experiments/linux_behavior/behavior_audit_rules.json", "Phase 6.5 spec reference"),
    ):
        if token not in text:
            errors.append(f"{path}: missing {label}")
    return errors


def check_tool(root: Path, tool: Path) -> list[str]:
    tool_path = resolve(root, tool)
    errors: list[str] = []
    if not tool_path.exists():
        return [f"missing audit tool: {tool_path}"]
    source = tool_path.read_text(encoding="utf-8")
    for token in (
        "load_rule_definitions",
        "graph_summary",
        "behavior_audit.json",
        "behavior_audit_report.md",
        "not malware detection quality evidence",
        "--graph",
    ):
        if token not in source:
            errors.append(f"{tool_path}: missing audit token {token}")
    if errors:
        return errors
    result = subprocess.run([sys.executable, str(tool_path), "--self-test"], cwd=root, text=True, capture_output=True)
    if result.returncode != 0:
        errors.append(f"{tool_path}: self-test failed: {result.stderr.strip()}")
    return errors


def run_checks(root: Path, spec: Path, doc: Path, tool: Path, manifest: Path, policy: Path, uv_doc: Path) -> list[str]:
    paths = {
        "spec": resolve(root, spec),
        "doc": resolve(root, doc),
        "tool": resolve(root, tool),
        "manifest": resolve(root, manifest),
        "policy": resolve(root, policy),
        "uv workflow": resolve(root, uv_doc),
    }
    errors = [f"missing {label}: {path}" for label, path in paths.items() if not path.exists()]
    if errors:
        return errors
    errors.extend(check_policy(paths["policy"]))
    errors.extend(check_spec(paths["spec"]))
    errors.extend(check_doc(paths["doc"]))
    errors.extend(check_manifest(paths["manifest"], paths["spec"]))
    errors.extend(check_uv_doc(paths["uv workflow"]))
    errors.extend(check_tool(root, paths["tool"]))
    return errors


def write_fixture(root: Path) -> None:
    (root / "experiments/linux_behavior/malware_like").mkdir(parents=True)
    (root / "docs").mkdir(parents=True)
    (root / "tools").mkdir(parents=True)
    rules = []
    for rule_id, expected in EXPECTED_RULES.items():
        rule = {
            "id": rule_id,
            "family": expected["family"],
            "evidence": "fixture evidence",
        }
        for field in (
            "expected_syscalls",
            "any_syscalls",
            "min_counts",
            "ordered_syscalls",
            "requires_failed_syscall",
            "failure_syscalls",
            "arg_bit_requirements",
            "expected_traps",
        ):
            if field in expected:
                rule[field] = expected[field]
        rules.append(rule)
    samples = [{"id": rule_id, "expected_behavior": [rule_id]} for rule_id in list(EXPECTED_RULES)[:6]]
    (root / DEFAULT_SPEC).write_text(
        json.dumps(
            {
                "phase": "6.5",
                "status": "TODO(EXPERIMENT)",
                "policy_ref": "experiments/linux_behavior/policy.json",
                "dataset_ref": "experiments/linux_behavior/malware_like/manifest.json",
                "input_artifacts": ["semantic_events.json", "behavior_graph.json"],
                "output_artifacts": ["behavior_audit.json", "behavior_audit_report.md"],
                "rules": rules,
                "non_goals": ["real malware execution", "malware detection quality claim", "classifier accuracy claim"],
            }
        ),
        encoding="utf-8",
    )
    (root / DEFAULT_DOC).write_text(
        """# Linux Behavior Audit

Phase 6.5 defines the rule-based synthetic behavior audit. This is a synthetic case-study gate, not board evidence, Linux experiment evidence, or malware detection quality evidence.
experiments/linux_behavior/behavior_audit_rules.json
semantic_events.json
behavior_graph.json
behavior_audit.json
behavior_audit_report.md
tools/audit_behavior.py
experiments/linux_behavior/malware_like/manifest.json

| Order | Rule | Behavior family | Required evidence | Status |
| ---: | --- | --- | --- | --- |
| 1 | many_file_scan | file_discovery | openat/getdents64/close | TODO(EXPERIMENT) |
| 2 | batch_file_read_write | collection_staging | openat/read/write/close | TODO(EXPERIMENT) |
| 3 | self_copy_simulation | dropper_like | copy shape | TODO(EXPERIMENT) |
| 4 | abnormal_syscall_sequence | abnormal_sequence | failed syscall | TODO(EXPERIMENT) |
| 5 | illegal_instruction_trap | trap_behavior | illegal trap | TODO(EXPERIMENT) |
| 6 | process_creation_chain | process_chain | clone/execve/waitid | TODO(EXPERIMENT) |
| 7 | dynamic_executable_memory | memory_permission | mmap/mprotect | TODO(EXPERIMENT) |
| 8 | anti_analysis_indicator | anti_analysis | ptrace/timing | TODO(EXPERIMENT) |

must not be used to claim malware detection quality
""",
        encoding="utf-8",
    )
    (root / DEFAULT_MANIFEST).write_text(json.dumps({"samples": samples}), encoding="utf-8")
    (root / DEFAULT_POLICY).write_text(
        json.dumps(
            {
                "real_malware_policy": "FORBIDDEN_EARLY",
                "allowed_sample_classes": ["benign", "malware_like_synthetic"],
                "blocked_sample_classes": ["real_malware"],
            }
        ),
        encoding="utf-8",
    )
    (root / DEFAULT_TOOL).write_text(
        "load_rule_definitions\ngraph_summary\nbehavior_audit.json\nbehavior_audit_report.md\n"
        "not malware detection quality evidence\n--graph\n",
        encoding="utf-8",
    )
    (root / DEFAULT_UV_DOC).write_text(
        "uv run python tools/audit_behavior.py --self-test\n"
        "uv run python tools/audit_behavior.py --semantic build/behavior_recovery_smoke/semantic_events.json "
        "--graph build/behavior_recovery_smoke/behavior_graph.json\n"
        "uv run python tools/check_linux_behavior_audit.py\n"
        "docs/04-runtime-linux/linux_behavior_audit.md\n"
        "experiments/linux_behavior/behavior_audit_rules.json\n",
        encoding="utf-8",
    )


def expect_error(root: Path, expected: str) -> bool:
    errors = []
    errors.extend(check_spec(root / DEFAULT_SPEC))
    errors.extend(check_doc(root / DEFAULT_DOC))
    errors.extend(check_manifest(root / DEFAULT_MANIFEST, root / DEFAULT_SPEC))
    errors.extend(check_uv_doc(root / DEFAULT_UV_DOC))
    return any(expected in error for error in errors)


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = []
        errors.extend(check_spec(root / DEFAULT_SPEC))
        errors.extend(check_doc(root / DEFAULT_DOC))
        errors.extend(check_manifest(root / DEFAULT_MANIFEST, root / DEFAULT_SPEC))
        errors.extend(check_uv_doc(root / DEFAULT_UV_DOC))
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1

    for phrase in (
        "PASS",
        "Phase 6.5 behavior audit validation is complete.",
        "behavior audit has passed.",
        "malware detection quality is validated",
        "real malware is allowed",
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            doc = root / DEFAULT_DOC
            doc.write_text(doc.read_text(encoding="utf-8") + f"\n{phrase}\n", encoding="utf-8")
            if not expect_error(root, "must not claim Phase 6.5"):
                print(f"[FAIL] self-test missed unsafe doc phrase: {phrase}", file=sys.stderr)
                return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["status"] = "PASS"
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "status must remain TODO"):
            print("[FAIL] self-test missed premature audit PASS", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["rules"] = spec["rules"][:-1]
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "rule ids differ"):
            print("[FAIL] self-test missed missing audit rule", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        manifest = load_json(root / DEFAULT_MANIFEST)
        manifest["samples"].append({"id": "unknown", "expected_behavior": ["undefined_rule"]})
        (root / DEFAULT_MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
        if not expect_error(root, "undefined audit rules"):
            print("[FAIL] self-test missed undefined manifest rule", file=sys.stderr)
            return 1

    print("[PASS] linux behavior audit checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Phase 6.5 Linux behavior audit rules.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--tool", type=Path, default=DEFAULT_TOOL)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--uv-doc", type=Path, default=DEFAULT_UV_DOC)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        errors = run_checks(args.root.resolve(), args.spec, args.doc, args.tool, args.manifest, args.policy, args.uv_doc)
    except Exception as exc:
        print(f"check_linux_behavior_audit: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] Phase 6.5 Linux behavior audit rules are specified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
