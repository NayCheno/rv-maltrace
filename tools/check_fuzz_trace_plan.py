from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_SPEC = Path("sim/golden/fuzz_invariants.json")
DEFAULT_DOC = Path("docs/validation/fuzz_trace_validation.md")
DEFAULT_GENERATOR = Path("tools/gen_rv_trace_fuzz.py")
DEFAULT_CHECKER = Path("tools/check_fuzz_trace.py")
DEFAULT_SMOKE = Path("sim/golden/fuzz_trace_smoke.trace.jsonl")
DEFAULT_UV_DOC = Path("docs/process/uv_workflow.md")
EXPECTED_CASES = ["fuzz_trace_smoke", "fuzz_cf", "fuzz_trap", "fuzz_syscall", "fuzz_context", "fuzz_overflow"]
EXPECTED_INVARIANTS = [
    "known_event_types",
    "trace_schema_required_fields",
    "control_flow_targets_aligned",
    "trap_not_retire",
    "syscall_pairing",
    "context_events_well_formed",
    "drop_count_monotonic",
]
REQUIRED_DOC_TEXT = (
    "Phase 8 defines bounded fuzz/stress inputs for RV-MalTrace trace validation.",
    "not a processor fuzzing campaign or CVA6 bug-discovery claim",
    "sim/golden/fuzz_invariants.json",
    "tools/gen_rv_trace_fuzz.py",
    "tools/check_fuzz_trace.py",
    "fuzz_trace_invariants.json",
    "fuzz_trace_report.md",
    "fuzz_cf",
    "fuzz_trap",
    "fuzz_syscall",
    "fuzz_context",
    "fuzz_overflow",
)
FORBIDDEN_DOC_PATTERNS = (
    re.compile(r"\bPASS\b", re.IGNORECASE),
    re.compile(r"\bprocessor\s+bug[- ]discovery\s+(?:is\s+)?(?:complete|validated|passed)\b", re.IGNORECASE),
    re.compile(r"\bRISCV-DV\s+(?:campaign\s+)?(?:is\s+)?(?:complete|validated|passed)\b", re.IGNORECASE),
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


def check_spec(path: Path) -> list[str]:
    spec = load_json(path)
    errors: list[str] = []
    if spec.get("schema") != "rvmt.fuzz.invariants.v1":
        errors.append(f"{path}: schema must be rvmt.fuzz.invariants.v1")
    if spec.get("status") != "TODO(SIM)":
        errors.append(f"{path}: status must remain TODO(SIM)")
    if "not CVA6 bug discovery" not in str(spec.get("purpose", "")):
        errors.append(f"{path}: purpose must keep fuzzing scoped to trace validation")
    if spec.get("invariant_catalog") != EXPECTED_INVARIANTS:
        errors.append(f"{path}: invariant_catalog must match expected invariants")
    cases = spec.get("cases", [])
    if not isinstance(cases, list):
        return errors + [f"{path}: cases must be a list"]
    by_id = {case.get("id"): case for case in cases if isinstance(case, dict)}
    if list(by_id) != EXPECTED_CASES:
        errors.append(f"{path}: case order/ids must be {EXPECTED_CASES}")
    for case_id in EXPECTED_CASES:
        case = by_id.get(case_id, {})
        invariants = case.get("invariants")
        if not isinstance(invariants, list) or not invariants:
            errors.append(f"{path}: {case_id}.invariants must be a non-empty list")
            continue
        unknown = [item for item in invariants if item not in EXPECTED_INVARIANTS]
        if unknown:
            errors.append(f"{path}: {case_id}.invariants has unknown values: {unknown}")
        if case_id == "fuzz_trace_smoke" and case.get("trace_fixture") != "sim/golden/fuzz_trace_smoke.trace.jsonl":
            errors.append(f"{path}: fuzz_trace_smoke must point at the smoke trace fixture")
        if case_id == "fuzz_syscall":
            if case.get("shape_seed") != "build/fuzz_trace_seeds/fuzz_syscall/main.S":
                errors.append(f"{path}: fuzz_syscall.shape_seed path mismatch")
            if case.get("execution_status") != "TODO(HARNESS)":
                errors.append(f"{path}: fuzz_syscall must stay TODO(HARNESS) until U-mode/SRET harness exists")
            if "U-mode ECALL" not in str(case.get("execution_gate", "")):
                errors.append(f"{path}: fuzz_syscall.execution_gate must name the U-mode ECALL harness requirement")
        elif case_id != "fuzz_trace_smoke" and case.get("generated_program") != f"build/fuzz_trace_seeds/{case_id}/main.S":
            errors.append(f"{path}: {case_id}.generated_program path mismatch")
        min_counts = case.get("min_counts")
        if not isinstance(min_counts, dict) or not min_counts:
            errors.append(f"{path}: {case_id}.min_counts must require target events")
        if case_id == "fuzz_cf" and not {"BRANCH", "JUMP"} <= set(min_counts or {}):
            errors.append(f"{path}: fuzz_cf must require BRANCH and JUMP")
        if case_id == "fuzz_syscall" and not {"SYSCALL_ENTRY", "SYSCALL_RET"} <= set(min_counts or {}):
            errors.append(f"{path}: fuzz_syscall must require entry and return")
        if case_id == "fuzz_context" and "SATP" not in set(min_counts or {}):
            errors.append(f"{path}: fuzz_context must require SATP context evidence")
        if case_id == "fuzz_overflow" and "DROP" not in set(min_counts or {}):
            errors.append(f"{path}: fuzz_overflow must require visible DROP")
        if case_id == "fuzz_trap" and case.get("allowed_trap_causes") != ["0x2", "0x3"]:
            errors.append(f"{path}: fuzz_trap must constrain allowed trap causes")
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
            errors.append(f"{path}: must not claim fuzzing PASS or processor bug discovery")
    rows = parse_table_rows(text)
    by_case = {row[1]: row for row in rows if len(row) >= 5}
    for index, case_id in enumerate(EXPECTED_CASES[1:], start=1):
        row = by_case.get(case_id)
        if row is None:
            errors.append(f"{path}: missing case row for {case_id}")
            continue
        if row[0] != str(index):
            errors.append(f"{path}: {case_id} order must be {index}")
        expected_status = "TODO(HARNESS)" if case_id == "fuzz_syscall" else "TODO(SIM)"
        if row[4] != expected_status:
            errors.append(f"{path}: {case_id} status must remain {expected_status}")
    return errors


def check_uv_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    for token, label in (
        ("tools/gen_rv_trace_fuzz.py --self-test", "fuzz generator self-test"),
        ("tools/check_fuzz_trace.py --self-test", "fuzz checker self-test"),
        ("tools/check_fuzz_trace.py --trace sim/golden/fuzz_trace_smoke.trace.jsonl --case fuzz_trace_smoke", "fuzz smoke checker command"),
        ("tools/check_fuzz_trace_plan.py", "fuzz plan checker command"),
        ("docs/validation/fuzz_trace_validation.md", "fuzz doc reference"),
        ("sim/golden/fuzz_invariants.json", "fuzz invariant spec reference"),
    ):
        if token not in text:
            errors.append(f"{path}: missing {label}")
    return errors


def check_tools(root: Path, generator: Path, checker: Path, smoke: Path) -> list[str]:
    errors: list[str] = []
    for path, label in ((generator, "generator"), (checker, "checker"), (smoke, "smoke trace")):
        if not resolve(root, path).exists():
            errors.append(f"missing {label}: {resolve(root, path)}")
    if errors:
        return errors
    for cmd, label in (
        ([sys.executable, str(resolve(root, generator)), "--self-test"], "generator self-test"),
        ([sys.executable, str(resolve(root, checker)), "--self-test"], "checker self-test"),
    ):
        result = subprocess.run(cmd, cwd=root, text=True, capture_output=True)
        if result.returncode != 0:
            errors.append(f"{label} failed: {result.stderr.strip() or result.stdout.strip()}")
    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp)
        result = subprocess.run(
            [
                sys.executable,
                str(resolve(root, checker)),
                "--trace",
                str(resolve(root, smoke)),
                "--invariants",
                str(resolve(root, DEFAULT_SPEC)),
                "--case",
                "fuzz_trace_smoke",
                "--out-dir",
                str(tmp_root / "smoke_report"),
            ],
            cwd=root,
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            errors.append(f"checker smoke trace failed: {result.stderr.strip() or result.stdout.strip()}")
        smoke_report = tmp_root / "smoke_report" / "fuzz_trace_invariants.json"
        smoke_markdown = tmp_root / "smoke_report" / "fuzz_trace_report.md"
        if not smoke_report.exists():
            errors.append("checker smoke trace did not write fuzz_trace_invariants.json")
        else:
            payload = load_json(smoke_report)
            if payload.get("status") != "PASS":
                errors.append("checker smoke trace report did not record PASS")
        if not smoke_markdown.exists():
            errors.append("checker smoke trace did not write fuzz_trace_report.md")
        elif "not a processor bug-discovery" not in smoke_markdown.read_text(encoding="utf-8"):
            errors.append("checker smoke trace markdown report is missing the processor bug-discovery non-claim")
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "seeds"
        result = subprocess.run([sys.executable, str(resolve(root, generator)), "--out-dir", str(out_dir)], cwd=root, text=True, capture_output=True)
        if result.returncode != 0:
            errors.append(f"generator smoke failed: {result.stderr.strip()}")
        for case_id in EXPECTED_CASES[1:]:
            if not (out_dir / case_id / "main.S").exists():
                errors.append(f"generator smoke did not create {case_id}/main.S")
    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp)
        weak_traces = {
            "fuzz_cf": [
                {"cycle": True, "evt": "BRANCH", "pc": "0x1000", "instr": "0x63", "target": "0x1000", "taken": True},
                {"cycle": 2, "evt": "JUMP", "pc": "0x1004", "instr": "0x6f", "target": "0x1004"},
            ],
            "fuzz_syscall": [
                {"cycle": 1, "evt": "SYSCALL_ENTRY", "priv": "U", "syscall_id": "0x0", "a0": "0x1", "a1": "0x0", "a2": "0x0", "a3": "0x0", "a4": "0x0", "a5": "0x0", "a6": "0x0", "a7": "0x40"},
                {"cycle": 2, "evt": "SYSCALL_RET", "priv": "S", "syscall_id": "0x0", "duration": 1, "target": "0x1000"},
            ],
            "fuzz_context": [{"cycle": 1, "evt": "DROP", "value": "0x1"}],
            "fuzz_overflow": [{"cycle": 1, "evt": "BRANCH", "target": "0x1000", "taken": True}],
            "fuzz_trap": [
                {"cycle": 1, "evt": "TRAP", "pc": "0x0000000000001000", "cause": "0x2", "tval": "0xffffffff", "priv": "U"},
                {"cycle": 2, "evt": "RETIRE", "pc": "0x1000", "instr": "0xffffffff"},
            ],
        }
        for case_id, events in weak_traces.items():
            trace_path = tmp_root / f"{case_id}.jsonl"
            trace_path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(resolve(root, checker)),
                    "--trace",
                    str(trace_path),
                    "--invariants",
                    str(resolve(root, DEFAULT_SPEC)),
                    "--case",
                    case_id,
                ],
                cwd=root,
                text=True,
                capture_output=True,
            )
            if result.returncode == 0:
                errors.append(f"checker weak-trace negative unexpectedly passed for {case_id}")
    return errors


def run_checks(root: Path, spec: Path, doc: Path, generator: Path, checker: Path, smoke: Path, uv_doc: Path) -> list[str]:
    paths = {
        "spec": resolve(root, spec),
        "doc": resolve(root, doc),
        "generator": resolve(root, generator),
        "checker": resolve(root, checker),
        "smoke": resolve(root, smoke),
        "uv workflow": resolve(root, uv_doc),
    }
    errors = [f"missing {label}: {path}" for label, path in paths.items() if not path.exists()]
    if errors:
        return errors
    errors.extend(check_spec(paths["spec"]))
    errors.extend(check_doc(paths["doc"]))
    errors.extend(check_uv_doc(paths["uv workflow"]))
    errors.extend(check_tools(root, generator, checker, smoke))
    return errors


def write_fixture(root: Path) -> None:
    (root / "sim/golden").mkdir(parents=True)
    (root / "docs").mkdir(parents=True)
    (root / "tools").mkdir(parents=True)
    cases = [
        {
            "id": "fuzz_trace_smoke",
            "trace_fixture": "sim/golden/fuzz_trace_smoke.trace.jsonl",
            "min_counts": {"SYSCALL_ENTRY": 1, "SYSCALL_RET": 1, "BRANCH": 1, "JUMP": 1, "TRAP": 1, "PRIV": 1, "SATP": 1, "DROP": 1},
            "allowed_trap_causes": ["0x2"],
            "invariants": EXPECTED_INVARIANTS,
        }
    ]
    for case_id in EXPECTED_CASES[1:]:
        min_counts = {"MARKER": 1}
        if case_id == "fuzz_cf":
            min_counts = {"BRANCH": 1, "JUMP": 1}
        elif case_id == "fuzz_trap":
            min_counts = {"TRAP": 1}
        elif case_id == "fuzz_syscall":
            min_counts = {"SYSCALL_ENTRY": 1, "SYSCALL_RET": 1}
        elif case_id == "fuzz_context":
            min_counts = {"SATP": 1}
        elif case_id == "fuzz_overflow":
            min_counts = {"BRANCH": 1, "DROP": 1}
        case = {"id": case_id, "generated_program": f"build/fuzz_trace_seeds/{case_id}/main.S", "min_counts": min_counts, "invariants": ["known_event_types"]}
        if case_id == "fuzz_syscall":
            case.pop("generated_program")
            case["shape_seed"] = "build/fuzz_trace_seeds/fuzz_syscall/main.S"
            case["execution_status"] = "TODO(HARNESS)"
            case["execution_gate"] = "Requires a U-mode ECALL harness"
        if case_id == "fuzz_trap":
            case["allowed_trap_causes"] = ["0x2", "0x3"]
        cases.append(case)
    (root / DEFAULT_SPEC).write_text(
        json.dumps(
            {
                "schema": "rvmt.fuzz.invariants.v1",
                "status": "TODO(SIM)",
                "purpose": "Bounded fuzz/stress cases validate trace invariants, not CVA6 bug discovery.",
                "invariant_catalog": EXPECTED_INVARIANTS,
                "cases": cases,
            }
        ),
        encoding="utf-8",
    )
    (root / DEFAULT_DOC).write_text(
        """# Fuzz Trace Validation

Phase 8 defines bounded fuzz/stress inputs for RV-MalTrace trace validation.
not a processor fuzzing campaign or CVA6 bug-discovery claim
sim/golden/fuzz_invariants.json
tools/gen_rv_trace_fuzz.py
tools/check_fuzz_trace.py
fuzz_trace_invariants.json
fuzz_trace_report.md
fuzz_cf
fuzz_trap
fuzz_syscall
fuzz_context
fuzz_overflow

| Order | Case | Stress focus | Required invariant families | Status |
| ---: | --- | --- | --- | --- |
| 1 | fuzz_cf | control | known | TODO(SIM) |
| 2 | fuzz_trap | trap | known | TODO(SIM) |
| 3 | fuzz_syscall | syscall | known | TODO(HARNESS) |
| 4 | fuzz_context | context | known | TODO(SIM) |
| 5 | fuzz_overflow | overflow | known | TODO(SIM) |
""",
        encoding="utf-8",
    )
    (root / DEFAULT_UV_DOC).write_text(
        "uv run python tools/gen_rv_trace_fuzz.py --self-test\n"
        "uv run python tools/check_fuzz_trace.py --self-test\n"
        "uv run python tools/check_fuzz_trace.py --trace sim/golden/fuzz_trace_smoke.trace.jsonl --case fuzz_trace_smoke\n"
        "uv run python tools/check_fuzz_trace_plan.py\n"
        "docs/validation/fuzz_trace_validation.md\n"
        "sim/golden/fuzz_invariants.json\n",
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
        errors = []
        errors.extend(check_spec(root / DEFAULT_SPEC))
        errors.extend(check_doc(root / DEFAULT_DOC))
        errors.extend(check_uv_doc(root / DEFAULT_UV_DOC))
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1
        repo_root = Path.cwd()
        tool_errors = check_tools(repo_root, DEFAULT_GENERATOR, DEFAULT_CHECKER, DEFAULT_SMOKE)
        if tool_errors:
            for error in tool_errors:
                print(f"[FAIL] self-test report-output gate failed: {error}", file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["status"] = "PASS"
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "status must remain TODO"):
            print("[FAIL] self-test missed premature fuzz PASS", file=sys.stderr)
            return 1
    for phrase in ("PASS", "processor bug-discovery is complete", "RISCV-DV campaign is complete"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            doc = root / DEFAULT_DOC
            doc.write_text(doc.read_text(encoding="utf-8") + f"\n{phrase}\n", encoding="utf-8")
            if not expect_error(root, "must not claim fuzzing PASS"):
                print(f"[FAIL] self-test missed unsafe doc phrase: {phrase}", file=sys.stderr)
                return 1
    print("[PASS] fuzz trace validation plan self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check bounded fuzz trace validation plan.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--generator", type=Path, default=DEFAULT_GENERATOR)
    parser.add_argument("--checker", type=Path, default=DEFAULT_CHECKER)
    parser.add_argument("--smoke", type=Path, default=DEFAULT_SMOKE)
    parser.add_argument("--uv-doc", type=Path, default=DEFAULT_UV_DOC)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        errors = run_checks(args.root.resolve(), args.spec, args.doc, args.generator, args.checker, args.smoke, args.uv_doc)
    except Exception as exc:
        print(f"check_fuzz_trace_plan: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] bounded fuzz trace validation plan is specified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
