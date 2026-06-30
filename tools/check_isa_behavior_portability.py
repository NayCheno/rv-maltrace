from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    resolve,
)


DEFAULT_SPEC = Path("experiments/analysis/isa_behavior_portability.json")
DEFAULT_DOC = Path("docs/05-semantic-analysis/isa_behavior_portability.md")
DEFAULT_UV_DOC = Path("docs/10-process/uv_workflow.md")
EXPECTED_MAPPINGS = ["syscall_abi", "control_flow", "privilege_transition", "anti_analysis", "dynamic_code"]
EXPECTED_MAPPING_STATUSES = {
    "syscall_abi": "PASS_CONTROLLED_CASE_STUDY",
    "control_flow": "PASS_SCOPE_LIMITED_CASE_STUDY",
    "privilege_transition": "PASS_SCOPED_SYSCALL_TRAP_BOUNDARY",
    "anti_analysis": "PASS_CONTROLLED_CASE_STUDY",
    "dynamic_code": "PASS_CONTROLLED_CASE_STUDY",
}
FORBIDDEN_PATTERNS = (
    re.compile(
        r"\bx86\s*(?:instruction|opcode)\s*(?:to|->)\s*RISC[- ]?V\s*(?:instruction|opcode)\s+"
        r"(?:mapping|translation|porting)?\s*(?:is\s+)?(?:allowed|validated|complete|portable|matched)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\braw\s+opcode\s+signature\s+(?:is\s+)?(?:portable|validated|matched|complete)\b", re.IGNORECASE),
    re.compile(r"\bmalware\s+detection\s+quality\s+(?:is\s+)?(?:validated|measured|proven|complete)\b", re.IGNORECASE),
    re.compile(r"\breal\s+malware\s+corpus\s+coverage\s+(?:is\s+)?(?:validated|measured|complete)\b", re.IGNORECASE),
)
REQUIRED_DOC_TEXT = (
    "Phase 10.1 records how RV-MalTrace treats x86-to-RISC-V malware differences.",
    "controlled behavior-rubric evidence",
    "not malware detection quality evidence",
    "not real-malware corpus coverage",
    "not an x86 instruction translation plan",
    "experiments/analysis/isa_behavior_portability.json",
    "Instruction-level malware signatures are architecture-dependent.",
    "architecture-neutral behavior semantics",
    "syscall_abi",
    "control_flow",
    "privilege_transition",
    "anti_analysis",
    "dynamic_code",
    "must not be used to claim real malware corpus coverage",
)


def normalized_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def check_forbidden(path: Path, text: str) -> list[str]:
    return [
        f"{path}: must compare behavior semantics, not raw opcodes or detection quality"
        for pattern in FORBIDDEN_PATTERNS
        if pattern.search(text)
    ]


def mappings_by_id(spec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    mappings = spec.get("mappings", [])
    if not isinstance(mappings, list):
        return {}
    return {item.get("id"): item for item in mappings if isinstance(item, dict) and isinstance(item.get("id"), str)}


def check_spec(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    spec = load_json(path)
    errors = check_forbidden(path, text)
    if spec.get("phase") != "10.1":
        errors.append(f"{path}: phase must be 10.1")
    if spec.get("status") != "PASS_CONTROLLED_BEHAVIOR_RUBRIC":
        errors.append(f"{path}: status must be PASS_CONTROLLED_BEHAVIOR_RUBRIC")
    if spec.get("scope") != "isa_specific_capture_to_architecture_neutral_behavior":
        errors.append(f"{path}: unexpected scope")
    policy = spec.get("policy", {})
    if not isinstance(policy, dict):
        errors.append(f"{path}: policy must be an object")
    else:
        if policy.get("raw_opcode_mapping") != "FORBIDDEN":
            errors.append(f"{path}: raw_opcode_mapping must be FORBIDDEN")
        if policy.get("primary_comparison_unit") != "behavior_semantics":
            errors.append(f"{path}: primary_comparison_unit must be behavior_semantics")
        if policy.get("claim_boundary") != "controlled behavior-rubric evidence only":
            errors.append(f"{path}: claim_boundary must stay controlled behavior-rubric evidence only")
    if spec.get("outputs") != ["isa_behavior_portability_report.md"]:
        errors.append(f"{path}: outputs must be isa_behavior_portability_report.md")
    mappings = mappings_by_id(spec)
    if list(mappings) != EXPECTED_MAPPINGS:
        errors.append(f"{path}: mappings must be {EXPECTED_MAPPINGS} in order")
    for mapping_id in EXPECTED_MAPPINGS:
        mapping = mappings.get(mapping_id, {})
        for field in ("x86_signal", "riscv_signal", "normalized_behavior"):
            if not isinstance(mapping.get(field), str) or not mapping.get(field):
                errors.append(f"{path}: {mapping_id}.{field} must be a non-empty string")
        expected_status = EXPECTED_MAPPING_STATUSES[mapping_id]
        if mapping.get("status") != expected_status:
            errors.append(f"{path}: {mapping_id}.status must be {expected_status}")
    non_goals = spec.get("non_goals", [])
    for required in (
        "x86 instruction to RISC-V instruction translation",
        "raw opcode signature matching",
        "malware detection quality claim",
        "real malware corpus coverage claim",
    ):
        if required not in non_goals:
            errors.append(f"{path}: non_goals missing {required}")
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
    errors = check_forbidden(path, text)
    for required in REQUIRED_DOC_TEXT:
        if normalized_text(required) not in normalized:
            errors.append(f"{path}: missing required text: {required}")
    rows = parse_table_rows(text)
    by_mapping = {row[1]: row for row in rows if len(row) >= 6}
    for index, mapping_id in enumerate(EXPECTED_MAPPINGS, start=1):
        row = by_mapping.get(mapping_id)
        if row is None:
            errors.append(f"{path}: missing mapping row for {mapping_id}")
            continue
        if row[0] != str(index):
            errors.append(f"{path}: {mapping_id} order must be {index}")
        expected_status = EXPECTED_MAPPING_STATUSES[mapping_id]
        if row[5] != expected_status:
            errors.append(f"{path}: {mapping_id} status must be {expected_status}")
    return errors


def check_uv_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors = []
    for token, label in (
        ("tools/check_ccfa_case_study_manifest.py --root .", "current case-study checker command"),
        ("tools/check_linux_behavior_recovery.py", "Linux recovery checker command"),
        ("tools/check_isa_behavior_portability.py", "Phase 10.1 checker command"),
        ("docs/05-semantic-analysis/isa_behavior_portability.md", "Phase 10.1 doc reference"),
        ("experiments/analysis/isa_behavior_portability.json", "Phase 10.1 spec reference"),
    ):
        if token not in text:
            errors.append(f"{path}: missing {label}")
    return errors


def run_checks(root: Path, spec: Path, doc: Path, uv_doc: Path) -> list[str]:
    paths = {
        "spec": resolve(root, spec),
        "doc": resolve(root, doc),
        "uv workflow": resolve(root, uv_doc),
    }
    errors = [f"missing {label}: {path}" for label, path in paths.items() if not path.exists()]
    if errors:
        return errors
    errors.extend(check_spec(paths["spec"]))
    errors.extend(check_doc(paths["doc"]))
    errors.extend(check_uv_doc(paths["uv workflow"]))
    return errors


def write_fixture(root: Path) -> None:
    (root / "experiments/analysis").mkdir(parents=True)
    (root / DEFAULT_DOC).parent.mkdir(parents=True, exist_ok=True)
    (root / DEFAULT_UV_DOC).parent.mkdir(parents=True, exist_ok=True)
    mappings = [
        {
            "id": mapping_id,
            "x86_signal": "x86 behavior signal",
            "riscv_signal": "RISC-V behavior signal",
            "normalized_behavior": "architecture-neutral behavior semantics",
            "status": EXPECTED_MAPPING_STATUSES[mapping_id],
        }
        for mapping_id in EXPECTED_MAPPINGS
    ]
    (root / DEFAULT_SPEC).write_text(
        json.dumps(
            {
                "phase": "10.1",
                "status": "PASS_CONTROLLED_BEHAVIOR_RUBRIC",
                "scope": "isa_specific_capture_to_architecture_neutral_behavior",
                "policy": {
                    "raw_opcode_mapping": "FORBIDDEN",
                    "primary_comparison_unit": "behavior_semantics",
                    "claim_boundary": "controlled behavior-rubric evidence only",
                },
                "inputs": ["trace.jsonl", "semantic_events.json", "behavior_graph.json"],
                "outputs": ["isa_behavior_portability_report.md"],
                "mappings": mappings,
                "non_goals": [
                    "x86 instruction to RISC-V instruction translation",
                    "raw opcode signature matching",
                    "malware detection quality claim",
                    "real malware corpus coverage claim",
                ],
            }
        ),
        encoding="utf-8",
    )
    (root / DEFAULT_DOC).write_text(
        """# ISA Behavior Portability

Phase 10.1 records how RV-MalTrace treats x86-to-RISC-V malware differences.
controlled behavior-rubric evidence
not malware detection quality evidence
not real-malware corpus coverage
not an x86 instruction translation plan
experiments/analysis/isa_behavior_portability.json
Instruction-level malware signatures are architecture-dependent.
architecture-neutral behavior semantics
must not be used to claim real malware corpus coverage

| Order | Mapping | x86 signal | RISC-V signal | Normalized behavior | Status |
| ---: | --- | --- | --- | --- | --- |
| 1 | syscall_abi | x86 syscall | ecall | behavior | PASS_CONTROLLED_CASE_STUDY |
| 2 | control_flow | x86 branch | RISC-V branch | behavior | PASS_SCOPE_LIMITED_CASE_STUDY |
| 3 | privilege_transition | ring | U/S/M | behavior | PASS_SCOPED_SYSCALL_TRAP_BOUNDARY |
| 4 | anti_analysis | ptrace | ptrace | behavior | PASS_CONTROLLED_CASE_STUDY |
| 5 | dynamic_code | mmap | mmap | behavior | PASS_CONTROLLED_CASE_STUDY |
""",
        encoding="utf-8",
    )
    (root / DEFAULT_UV_DOC).write_text(
        "uv run python tools/check_ccfa_case_study_manifest.py --root .\n"
        "uv run python tools/check_linux_behavior_recovery.py\n"
        "uv run python tools/check_isa_behavior_portability.py\n"
        "docs/05-semantic-analysis/isa_behavior_portability.md\n"
        "experiments/analysis/isa_behavior_portability.json\n",
        encoding="utf-8",
    )


def expect_error(root: Path, expected: str) -> bool:
    return any(expected in error for error in run_checks(root, DEFAULT_SPEC, DEFAULT_DOC, DEFAULT_UV_DOC))


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = run_checks(root, DEFAULT_SPEC, DEFAULT_DOC, DEFAULT_UV_DOC)
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["policy"]["raw_opcode_mapping"] = "ALLOWED"
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "raw_opcode_mapping must be FORBIDDEN"):
            print("[FAIL] self-test missed allowed raw opcode mapping", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["mappings"][0]["status"] = "TODO(EXPERIMENT)"
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "syscall_abi.status must be PASS_CONTROLLED_CASE_STUDY"):
            print("[FAIL] self-test missed stale mapping TODO status", file=sys.stderr)
            return 1

    for phrase in (
        "x86 opcode to RISC-V opcode mapping is validated",
        "raw opcode signature is portable",
        "malware detection quality is validated",
        "real malware corpus coverage is complete",
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            doc = root / DEFAULT_DOC
            doc.write_text(doc.read_text(encoding="utf-8") + f"\n{phrase}\n", encoding="utf-8")
            if not expect_error(root, "must compare behavior semantics"):
                print(f"[FAIL] self-test missed unsafe doc phrase: {phrase}", file=sys.stderr)
                return 1

    print("[PASS] ISA behavior portability checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check ISA behavior portability rubric.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--uv-doc", type=Path, default=DEFAULT_UV_DOC)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    try:
        errors = run_checks(args.root.resolve(), args.spec, args.doc, args.uv_doc)
    except Exception as exc:
        print(f"check_isa_behavior_portability: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] ISA behavior portability rubric is specified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
