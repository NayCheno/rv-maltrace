from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_SPEC = Path("experiments/linux_behavior/recovery_targets.json")
DEFAULT_DOC = Path("docs/04-runtime-linux/linux_behavior_recovery_targets.md")
DEFAULT_TOOL = Path("tools/recover_behavior.py")
DEFAULT_GOLDEN = Path("sim/golden/behavior_recovery.trace.jsonl")
DEFAULT_UV_DOC = Path("docs/10-process/uv_workflow.md")

SPEC_KEYS = {
    "phase",
    "status",
    "policy_ref",
    "dataset_refs",
    "input_artifact",
    "output_artifacts",
    "targets",
}
EXPECTED_TARGETS = {
    "syscall_sequence": {
        "source_events": ["SYSCALL_ENTRY", "SYSCALL_RET"],
        "output": "semantic_events.syscall_sequence",
        "required_fields": ["cycle", "pc", "priv", "a7", "return_value", "return_pc", "duration"],
    },
    "control_flow_segment": {
        "source_events": ["BRANCH", "JUMP"],
        "output": "semantic_events.control_flow_segments",
        "required_fields": ["cycle", "pc", "target"],
    },
    "trap_context_transition": {
        "source_events": ["TRAP", "CSR", "SATP", "PRIV"],
        "output": "semantic_events.trap_context_transitions",
        "required_fields": ["cycle", "pc", "evt"],
    },
    "privilege_boundary": {
        "source_events": ["SYSCALL_ENTRY", "SYSCALL_RET", "TRAP", "PRIV"],
        "output": "semantic_events.privilege_boundaries",
        "required_fields": ["cycle", "pc", "priv"],
    },
    "basic_behavior_graph": {
        "source_events": ["SYSCALL_ENTRY", "SYSCALL_RET", "BRANCH", "JUMP", "TRAP", "CSR", "SATP", "PRIV"],
        "output": "behavior_graph",
        "required_fields": ["nodes", "edges"],
    },
}
EXPECTED_GOLDEN_SYSCALL_RETURN = {
    "return_value": "0x0000000000000005",
    "return_pc": "0x0000000080001004",
    "duration": 1,
}
TARGET_KEYS = {
    "id",
    "source_events",
    "output",
    "required_fields",
}
REQUIRED_DOC_TEXT = (
    "Phase 6.4 defines the behavior recovery targets for Linux experiments.",
    "target specification and tooling plan, not board or Linux experiment evidence.",
    "experiments/linux_behavior/recovery_targets.json",
    "trace.jsonl",
    "semantic_events.json",
    "behavior_graph.json",
    "recovery_report.md",
    "tools/recover_behavior.py",
    "syscall_sequence",
    "control_flow_segment",
    "trap_context_transition",
    "privilege_boundary",
    "basic_behavior_graph",
    "must not be used to claim malware detection quality",
)
FORBIDDEN_DOC_PATTERNS = (
    re.compile(r"\bPASS\b", re.IGNORECASE),
    re.compile(
        r"\b(?:phase\s*6(?:\.4)?\s+)?(?:recovery|validation|experiment|experiments|linux\s+experiment|linux\s+behavior\s+experiments|behavior\s+recovery)\s+"
        r"(?:validation\s+)?(?:is|are|has|have)?\s*(?:been\s+)?(?:complete|validated|passed)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bmalware\s+detection\s+quality\s+(?:is|are|has|have)?\s*"
        r"(?:been\s+)?(?:validated|proven|measured|passed|complete)\b",
        re.IGNORECASE,
    ),
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


def targets_by_id(spec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    targets = spec.get("targets")
    if not isinstance(targets, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for item in targets:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            result[item["id"]] = item
    return result


def check_spec(path: Path) -> list[str]:
    spec = load_json(path)
    errors: list[str] = []
    extra_keys = set(spec) - SPEC_KEYS
    missing_keys = SPEC_KEYS - set(spec)
    if extra_keys:
        errors.append(f"{path}: unexpected spec keys are not allowed: {sorted(extra_keys)}")
    if missing_keys:
        errors.append(f"{path}: missing required spec keys: {sorted(missing_keys)}")
    if spec.get("phase") != "6.4":
        errors.append(f"{path}: phase must be 6.4")
    if spec.get("status") != "TODO(EXPERIMENT)":
        errors.append(f"{path}: status must remain TODO(EXPERIMENT)")
    if spec.get("policy_ref") != "experiments/linux_behavior/policy.json":
        errors.append(f"{path}: policy_ref must point at the Phase 6.1 policy")
    if spec.get("dataset_refs") != [
        "experiments/linux_behavior/benign/manifest.json",
        "experiments/linux_behavior/malware_like/manifest.json",
    ]:
        errors.append(f"{path}: dataset_refs must point at the Phase 6.2 and 6.3 manifests")
    if spec.get("input_artifact") != "trace.jsonl":
        errors.append(f"{path}: input_artifact must be trace.jsonl")
    if spec.get("output_artifacts") != ["semantic_events.json", "behavior_graph.json", "recovery_report.md"]:
        errors.append(f"{path}: output_artifacts must be semantic_events.json, behavior_graph.json, recovery_report.md")
    targets = targets_by_id(spec)
    if set(targets) != set(EXPECTED_TARGETS):
        errors.append(f"{path}: target ids differ from expected set: {sorted(targets)}")
    for target_id, expected in EXPECTED_TARGETS.items():
        target = targets.get(target_id, {})
        extra_target_keys = set(target) - TARGET_KEYS
        missing_target_keys = TARGET_KEYS - set(target)
        if extra_target_keys:
            errors.append(f"{path}: {target_id} has unexpected target keys: {sorted(extra_target_keys)}")
        if missing_target_keys:
            errors.append(f"{path}: {target_id} is missing target keys: {sorted(missing_target_keys)}")
        for field, value in expected.items():
            if target.get(field) != value:
                errors.append(f"{path}: {target_id}.{field} must be {value!r}")
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
            errors.append(f"{path}: must not claim Phase 6.4 pass or malware-detection quality")
    rows = parse_table_rows(text)
    by_target = {row[1]: row for row in rows if len(row) >= 5}
    for order, target_id in enumerate(EXPECTED_TARGETS, start=1):
        row = by_target.get(target_id)
        if row is None:
            errors.append(f"{path}: missing target row for {target_id}")
            continue
        if row[0] != str(order):
            errors.append(f"{path}: {target_id} order must be {order}")
        if row[4] != "TODO(EXPERIMENT)":
            errors.append(f"{path}: {target_id} status must remain TODO(EXPERIMENT)")
    return errors


def check_uv_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    for token, label in (
        ("tools/recover_behavior.py --self-test", "recover self-test command"),
        ("tools/check_linux_behavior_recovery.py", "Phase 6.4 checker command"),
        ("docs/04-runtime-linux/linux_behavior_recovery_targets.md", "Phase 6.4 doc reference"),
        ("experiments/linux_behavior/recovery_targets.json", "Phase 6.4 spec reference"),
    ):
        if token not in text:
            errors.append(f"{path}: missing {label}")
    return errors


def check_recover_tool(root: Path, tool: Path, golden: Path) -> list[str]:
    tool_path = resolve(root, tool)
    golden_path = resolve(root, golden)
    errors: list[str] = []
    if not tool_path.exists():
        return [f"missing recovery tool: {tool_path}"]
    if not golden_path.exists():
        return [f"missing recovery golden trace: {golden_path}"]
    source = tool_path.read_text(encoding="utf-8")
    for token in ("recover_syscalls", "recover_control_flow", "recover_trap_context", "recover_privilege_boundaries", "build_graph"):
        if token not in source:
            errors.append(f"{tool_path}: missing recovery function {token}")
    if errors:
        return errors
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "out"
        cmd = [sys.executable, str(tool_path), "--trace", str(golden_path), "--out-dir", str(out_dir)]
        result = subprocess.run(cmd, cwd=root, text=True, capture_output=True)
        if result.returncode != 0:
            errors.append(f"{tool_path}: golden recovery failed: {result.stderr.strip()}")
            return errors
        semantic_path = out_dir / "semantic_events.json"
        graph_path = out_dir / "behavior_graph.json"
        report_path = out_dir / "recovery_report.md"
        for artifact in (semantic_path, graph_path, report_path):
            if not artifact.exists():
                errors.append(f"{tool_path}: missing generated artifact {artifact.name}")
        if errors:
            return errors
        semantic = load_json(semantic_path)
        graph = load_json(graph_path)
        if not semantic.get("syscall_sequence"):
            errors.append(f"{tool_path}: golden recovery missed syscall_sequence")
        if not semantic.get("control_flow_segments"):
            errors.append(f"{tool_path}: golden recovery missed control_flow_segments")
        if not semantic.get("trap_context_transitions"):
            errors.append(f"{tool_path}: golden recovery missed trap_context_transitions")
        if not semantic.get("privilege_boundaries"):
            errors.append(f"{tool_path}: golden recovery missed privilege_boundaries")
        if not graph.get("nodes") or not graph.get("edges"):
            errors.append(f"{tool_path}: golden recovery missed behavior_graph nodes/edges")
        recovered_targets = {
            "syscall_sequence": semantic.get("syscall_sequence", []),
            "control_flow_segment": semantic.get("control_flow_segments", []),
            "trap_context_transition": semantic.get("trap_context_transitions", []),
            "privilege_boundary": semantic.get("privilege_boundaries", []),
        }
        for target_id, rows in recovered_targets.items():
            if not rows:
                continue
            required_fields = EXPECTED_TARGETS[target_id]["required_fields"]
            missing = [field for field in required_fields if field not in rows[0]]
            if missing:
                errors.append(f"{tool_path}: {target_id} missing recovered fields: {', '.join(missing)}")
        syscall_rows = semantic.get("syscall_sequence") or []
        if syscall_rows:
            syscall = syscall_rows[0]
            syscall_return = syscall.get("return")
            if not isinstance(syscall_return, dict):
                errors.append(f"{tool_path}: syscall_sequence missing nested return record")
            for field, expected in EXPECTED_GOLDEN_SYSCALL_RETURN.items():
                if syscall.get(field) != expected:
                    errors.append(f"{tool_path}: syscall_sequence.{field} must recover {expected!r}")
                if not isinstance(syscall_return, dict):
                    continue
                if syscall_return.get(field) != expected:
                    errors.append(f"{tool_path}: syscall_sequence.return.{field} must recover {expected!r}")
        report = report_path.read_text(encoding="utf-8")
        for target in EXPECTED_TARGETS:
            if target not in report:
                errors.append(f"{report_path}: missing target summary {target}")
    return errors


def run_checks(root: Path, spec: Path, doc: Path, tool: Path, golden: Path, uv_doc: Path) -> list[str]:
    spec_path = resolve(root, spec)
    doc_path = resolve(root, doc)
    uv_path = resolve(root, uv_doc)
    errors: list[str] = []
    for path, label in ((spec_path, "spec"), (doc_path, "doc"), (uv_path, "uv workflow")):
        if not path.exists():
            errors.append(f"missing {label}: {path}")
    if errors:
        return errors
    errors.extend(check_spec(spec_path))
    errors.extend(check_doc(doc_path))
    errors.extend(check_uv_doc(uv_path))
    errors.extend(check_recover_tool(root, tool, golden))
    return errors


def write_fixture(root: Path) -> None:
    (root / "experiments/linux_behavior").mkdir(parents=True)
    (root / DEFAULT_DOC).parent.mkdir(parents=True)
    (root / DEFAULT_UV_DOC).parent.mkdir(parents=True, exist_ok=True)
    (root / "sim/golden").mkdir(parents=True)
    (root / "tools").mkdir(parents=True)
    targets = []
    for target_id, expected in EXPECTED_TARGETS.items():
        targets.append({"id": target_id, **expected})
    (root / DEFAULT_SPEC).write_text(
        json.dumps(
            {
                "phase": "6.4",
                "status": "TODO(EXPERIMENT)",
                "policy_ref": "experiments/linux_behavior/policy.json",
                "dataset_refs": [
                    "experiments/linux_behavior/benign/manifest.json",
                    "experiments/linux_behavior/malware_like/manifest.json",
                ],
                "input_artifact": "trace.jsonl",
                "output_artifacts": ["semantic_events.json", "behavior_graph.json", "recovery_report.md"],
                "targets": targets,
            }
        ),
        encoding="utf-8",
    )
    (root / DEFAULT_DOC).write_text(
        """# Linux Behavior Recovery Targets

Phase 6.4 defines the behavior recovery targets for Linux experiments.
target specification and tooling plan, not board or Linux experiment evidence.
experiments/linux_behavior/recovery_targets.json
trace.jsonl
semantic_events.json
behavior_graph.json
recovery_report.md
tools/recover_behavior.py

| Order | Target | Source events | Output artifact path | Status |
| ---: | --- | --- | --- | --- |
| 1 | syscall_sequence | SYSCALL_ENTRY,SYSCALL_RET | semantic_events.syscall_sequence | TODO(EXPERIMENT) |
| 2 | control_flow_segment | BRANCH,JUMP | semantic_events.control_flow_segments | TODO(EXPERIMENT) |
| 3 | trap_context_transition | TRAP,CSR,SATP,PRIV | semantic_events.trap_context_transitions | TODO(EXPERIMENT) |
| 4 | privilege_boundary | SYSCALL_ENTRY,SYSCALL_RET,TRAP,PRIV | semantic_events.privilege_boundaries | TODO(EXPERIMENT) |
| 5 | basic_behavior_graph | all | behavior_graph | TODO(EXPERIMENT) |

must not be used to claim malware detection quality
""",
        encoding="utf-8",
    )
    (root / DEFAULT_TOOL).write_text(
        "recover_syscalls\nrecover_control_flow\nrecover_trap_context\nrecover_privilege_boundaries\nbuild_graph\n",
        encoding="utf-8",
    )
    (root / DEFAULT_GOLDEN).write_text('{"evt":"SYSCALL_ENTRY"}\n', encoding="utf-8")
    (root / DEFAULT_UV_DOC).write_text(
        "uv run python tools/recover_behavior.py --self-test\n"
        "uv run python tools/check_linux_behavior_recovery.py\n"
        "docs/04-runtime-linux/linux_behavior_recovery_targets.md\n"
        "experiments/linux_behavior/recovery_targets.json\n",
        encoding="utf-8",
    )


def expect_error(root: Path, expected: str) -> bool:
    errors = []
    errors.extend(check_spec(root / DEFAULT_SPEC))
    errors.extend(check_doc(root / DEFAULT_DOC))
    errors.extend(check_uv_doc(root / DEFAULT_UV_DOC))
    return any(expected in error for error in errors)


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors: list[str] = []
        errors.extend(check_spec(root / DEFAULT_SPEC))
        errors.extend(check_doc(root / DEFAULT_DOC))
        errors.extend(check_uv_doc(root / DEFAULT_UV_DOC))
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["status"] = "PASS"
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "status must remain TODO"):
            print("[FAIL] self-test missed premature spec PASS", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["targets"] = spec["targets"][:-1]
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "target ids differ"):
            print("[FAIL] self-test missed missing recovery target", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["malware_detection_quality"] = "validated"
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "unexpected spec keys"):
            print("[FAIL] self-test missed top-level overclaim key", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["targets"][0]["malware_detection_quality"] = "validated"
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "unexpected target keys"):
            print("[FAIL] self-test missed target-level overclaim key", file=sys.stderr)
            return 1

    for phrase in (
        "PASS",
        "Phase 6.4 recovery validation is complete.",
        "Linux behavior experiments are validated.",
        "Phase 6.4 experiments have passed.",
        "Phase 6.4 validation is complete.",
        "Linux behavior experiments have been validated.",
        "malware detection quality is validated",
        "Malware detection quality has passed.",
        "Malware detection quality is complete.",
        "Malware detection quality has been validated.",
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            doc = root / DEFAULT_DOC
            doc.write_text(doc.read_text(encoding="utf-8") + f"\n{phrase}\n", encoding="utf-8")
            if not expect_error(root, "must not claim Phase 6.4"):
                print(f"[FAIL] self-test missed unsafe doc phrase: {phrase}", file=sys.stderr)
                return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        tool = Path.cwd() / DEFAULT_TOOL
        golden = Path.cwd() / DEFAULT_GOLDEN
        errors = check_recover_tool(Path.cwd(), tool, golden)
        if errors:
            for error in errors:
                print(f"[FAIL] self-test recover-tool smoke failed: {error}", file=sys.stderr)
            return 1

    for token, expected in (
        ("tools/recover_behavior.py --self-test", "recover self-test command"),
        ("tools/check_linux_behavior_recovery.py", "checker command"),
        ("docs/04-runtime-linux/linux_behavior_recovery_targets.md", "doc reference"),
        ("experiments/linux_behavior/recovery_targets.json", "spec reference"),
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            uv_doc = root / DEFAULT_UV_DOC
            uv_doc.write_text(uv_doc.read_text(encoding="utf-8").replace(token, ""), encoding="utf-8")
            if not expect_error(root, expected):
                print(f"[FAIL] self-test missed missing uv reference: {token}", file=sys.stderr)
                return 1

    print("[PASS] linux behavior recovery target self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Phase 6.4 Linux behavior recovery targets.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--tool", type=Path, default=DEFAULT_TOOL)
    parser.add_argument("--golden", type=Path, default=DEFAULT_GOLDEN)
    parser.add_argument("--uv-doc", type=Path, default=DEFAULT_UV_DOC)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        errors = run_checks(args.root.resolve(), args.spec, args.doc, args.tool, args.golden, args.uv_doc)
    except Exception as exc:
        print(f"check_linux_behavior_recovery: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] Phase 6.4 Linux behavior recovery targets are specified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
