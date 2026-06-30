from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    resolve,
)


DEFAULT_SPEC = Path("sim/golden/fuzz_invariants.json")
DEFAULT_DOC = Path("docs/06-validation-gates/fuzz_trace_validation.md")
DEFAULT_GENERATOR = Path("tools/gen_rv_trace_fuzz.py")
DEFAULT_CHECKER = Path("tools/check_fuzz_trace.py")
DEFAULT_SMOKE = Path("sim/golden/fuzz_trace_smoke.trace.jsonl")
DEFAULT_UV_DOC = Path("docs/10-process/uv_workflow.md")
DEFAULT_SIM_SUMMARY = Path("results/vivado_sim/summary.json")
DEFAULT_SIM_REPORT = Path("docs/07-evaluation-evidence/reports/sim_results.md")
EXPECTED_CASES = ["fuzz_trace_smoke", "fuzz_cf", "fuzz_trap", "fuzz_syscall", "fuzz_context", "fuzz_overflow"]
SPEC_STATUS = "PASS_GOLDEN_TRACE_FIXTURES_WITH_SYSCALL_EVIDENCE"
GOLDEN_TRACE_STATUS = "PASS_GOLDEN_TRACE_FIXTURE"
SYSCALL_EVIDENCE_STATUS = "PASS_GOLDEN_TRACE_FIXTURE_WITH_SYSCALL_EVIDENCE"
EXPECTED_INVARIANTS = [
    "known_event_types",
    "trace_schema_required_fields",
    "control_flow_targets_aligned",
    "trap_not_retire",
    "syscall_pairing",
    "same_cycle_event_order",
    "dual_commit_order",
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
    SPEC_STATUS,
    GOLDEN_TRACE_STATUS,
    SYSCALL_EVIDENCE_STATUS,
    "syscall_ret",
    "dual_commit_order",
    "rvfi_adapter",
    "existing trace-unit and RVFI adapter syscall evidence",
    "seed assembly is still not treated as executed processor evidence",
)
FORBIDDEN_DOC_PATTERNS = (
    re.compile(r"TODO\(SIM\)"),
    re.compile(r"TODO\(HARNESS\)"),
    re.compile(r"SYSCALL_HARNESS_OPEN"),
    re.compile(r"PASS_SHAPE_FIXTURE_HARNESS_OPEN"),
    re.compile(r"\bprocessor\s+bug[- ]discovery\s+(?:is\s+)?(?:complete|validated|passed)\b", re.IGNORECASE),
    re.compile(r"\bRISCV-DV\s+(?:campaign\s+)?(?:is\s+)?(?:complete|validated|passed)\b", re.IGNORECASE),
)


def resolve_artifact_path(root: Path, path_text: str) -> Path:
    normalized = path_text.replace("\\", "/")
    path = Path(normalized)
    return resolve(root, path)


def normalized_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def check_spec(path: Path) -> list[str]:
    spec = load_json(path)
    errors: list[str] = []
    if spec.get("schema") != "rvmt.fuzz.invariants.v1":
        errors.append(f"{path}: schema must be rvmt.fuzz.invariants.v1")
    if spec.get("status") != SPEC_STATUS:
        errors.append(f"{path}: status must be {SPEC_STATUS}")
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
            if case.get("execution_status") != SYSCALL_EVIDENCE_STATUS:
                errors.append(f"{path}: fuzz_syscall execution_status must be {SYSCALL_EVIDENCE_STATUS}")
            evidence = case.get("syscall_harness_evidence")
            if not isinstance(evidence, dict):
                errors.append(f"{path}: fuzz_syscall.syscall_harness_evidence must be an object")
            else:
                expected_evidence = {
                    "trace_unit_test": "syscall_ret",
                    "rvfi_adapter_test": "rvfi_adapter",
                    "summary": "results/vivado_sim/summary.json",
                    "report": "docs/07-evaluation-evidence/reports/sim_results.md",
                    "seed_execution_claimed": False,
                }
                for key, expected in expected_evidence.items():
                    if evidence.get(key) != expected:
                        errors.append(f"{path}: fuzz_syscall.syscall_harness_evidence.{key} mismatch")
        else:
            if case.get("execution_status") != GOLDEN_TRACE_STATUS:
                errors.append(f"{path}: {case_id} execution_status must be {GOLDEN_TRACE_STATUS}")
            if case_id != "fuzz_trace_smoke" and case.get("generated_program") != f"build/fuzz_trace_seeds/{case_id}/main.S":
                errors.append(f"{path}: {case_id}.generated_program path mismatch")
        if case_id != "fuzz_trace_smoke" and case.get("trace_fixture") != f"sim/golden/{case_id}.trace.jsonl":
            errors.append(f"{path}: {case_id}.trace_fixture path mismatch")
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
            errors.append(f"{path}: must not claim fuzzing TODO or processor bug discovery")
    rows = parse_table_rows(text)
    by_case = {row[1]: row for row in rows if len(row) >= 5}
    for index, case_id in enumerate(EXPECTED_CASES[1:], start=1):
        row = by_case.get(case_id)
        if row is None:
            errors.append(f"{path}: missing case row for {case_id}")
            continue
        if row[0] != str(index):
            errors.append(f"{path}: {case_id} order must be {index}")
        expected_status = SYSCALL_EVIDENCE_STATUS if case_id == "fuzz_syscall" else GOLDEN_TRACE_STATUS
        if row[4] != expected_status:
            errors.append(f"{path}: {case_id} status must be {expected_status}")
    return errors


def check_uv_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    for token, label in (
        ("tools/gen_rv_trace_fuzz.py --self-test", "fuzz generator self-test"),
        ("tools/check_fuzz_trace.py --self-test", "fuzz checker self-test"),
        ("tools/check_fuzz_trace.py --trace sim/golden/fuzz_trace_smoke.trace.jsonl --case fuzz_trace_smoke", "fuzz smoke checker command"),
        ("tools/check_fuzz_trace_plan.py", "fuzz plan checker command"),
        ("docs/06-validation-gates/fuzz_trace_validation.md", "fuzz doc reference"),
        ("sim/golden/fuzz_invariants.json", "fuzz invariant spec reference"),
        ("results/vivado_sim/summary.json", "syscall evidence summary reference"),
        ("docs/07-evaluation-evidence/reports/sim_results.md", "syscall evidence report reference"),
    ):
        if token not in text:
            errors.append(f"{path}: missing {label}")
    return errors


def check_syscall_harness_evidence(root: Path, summary_path: Path, report_path: Path) -> list[str]:
    errors: list[str] = []
    summary = load_json(resolve(root, summary_path))
    if summary.get("overall") != "PASS":
        errors.append(f"{summary_path}: overall must be PASS")
    tests = summary.get("tests")
    if not isinstance(tests, dict):
        return errors + [f"{summary_path}: tests must be an object"]
    expectations = {
        "syscall_ret": {"SYSCALL_ENTRY": 1, "SYSCALL_RET": 1, "TRAP": 1},
        "rvfi_adapter": {"SYSCALL_ENTRY": 1, "SYSCALL_RET": 1},
    }
    for test_id, min_counts in expectations.items():
        row = tests.get(test_id)
        if not isinstance(row, dict):
            errors.append(f"{summary_path}: missing test row {test_id}")
            continue
        if row.get("status") != "PASS":
            errors.append(f"{summary_path}: {test_id} status must be PASS")
        counts = row.get("counts")
        if not isinstance(counts, dict):
            errors.append(f"{summary_path}: {test_id}.counts must be an object")
            continue
        for event, minimum in min_counts.items():
            if int(counts.get(event, 0)) < minimum:
                errors.append(f"{summary_path}: {test_id} must include at least {minimum} {event}")
        compare_log = row.get("compare_log")
        if not isinstance(compare_log, str) or not compare_log:
            errors.append(f"{summary_path}: {test_id}.compare_log path required")
            continue
        compare_path = resolve_artifact_path(root, compare_log)
        if not compare_path.is_file():
            errors.append(f"{summary_path}: {test_id} compare log missing: {compare_log}")
            continue
        compare_text = compare_path.read_text(encoding="utf-8", errors="replace")
        for token in ("[PASS]", "SYSCALL_ENTRY", "SYSCALL_RET", "required event matched"):
            if token not in compare_text:
                errors.append(f"{compare_log}: missing syscall evidence token {token}")
    report_text = resolve(root, report_path).read_text(encoding="utf-8", errors="replace")
    for token in ("syscall_ret", "SRET-to-U", "rvfi_adapter", "U-mode syscall entry/return correlation"):
        if token not in report_text:
            errors.append(f"{report_path}: missing syscall evidence text: {token}")
    return errors


def check_tools(root: Path, generator: Path, checker: Path, smoke: Path, sim_summary: Path, sim_report: Path) -> list[str]:
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
    spec_data = load_json(resolve(root, DEFAULT_SPEC))
    cases = spec_data.get("cases") if isinstance(spec_data.get("cases"), list) else []
    fixture_cases = [case for case in cases if isinstance(case, dict) and isinstance(case.get("trace_fixture"), str)]
    for case in fixture_cases:
        case_id = str(case.get("id"))
        trace_fixture = resolve(root, Path(str(case.get("trace_fixture"))))
        if not trace_fixture.is_file():
            errors.append(f"{case_id}: missing trace fixture: {trace_fixture}")
            continue
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    sys.executable,
                    str(resolve(root, checker)),
                    "--trace",
                    str(trace_fixture),
                    "--invariants",
                    str(resolve(root, DEFAULT_SPEC)),
                    "--case",
                    case_id,
                    "--out-dir",
                    str(Path(tmp) / case_id),
                ],
                cwd=root,
                text=True,
                capture_output=True,
            )
            if result.returncode != 0:
                errors.append(f"checker fixture failed for {case_id}: {result.stderr.strip() or result.stdout.strip()}")
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "seeds"
        result = subprocess.run([sys.executable, str(resolve(root, generator)), "--out-dir", str(out_dir)], cwd=root, text=True, capture_output=True)
        if result.returncode != 0:
            errors.append(f"generator smoke failed: {result.stderr.strip()}")
        for case_id in EXPECTED_CASES[1:]:
            if not (out_dir / case_id / "main.S").exists():
                errors.append(f"generator smoke did not create {case_id}/main.S")
    errors.extend(check_syscall_harness_evidence(root, sim_summary, sim_report))
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


def run_checks(root: Path, spec: Path, doc: Path, generator: Path, checker: Path, smoke: Path, uv_doc: Path, sim_summary: Path, sim_report: Path) -> list[str]:
    paths = {
        "spec": resolve(root, spec),
        "doc": resolve(root, doc),
        "generator": resolve(root, generator),
        "checker": resolve(root, checker),
        "smoke": resolve(root, smoke),
        "uv workflow": resolve(root, uv_doc),
        "simulation summary": resolve(root, sim_summary),
        "simulation report": resolve(root, sim_report),
    }
    errors = [f"missing {label}: {path}" for label, path in paths.items() if not path.exists()]
    if errors:
        return errors
    errors.extend(check_spec(paths["spec"]))
    errors.extend(check_doc(paths["doc"]))
    errors.extend(check_uv_doc(paths["uv workflow"]))
    errors.extend(check_tools(root, generator, checker, smoke, sim_summary, sim_report))
    return errors


def write_fixture(root: Path) -> None:
    (root / "sim/golden").mkdir(parents=True)
    (root / "docs").mkdir(parents=True)
    (root / "tools").mkdir(parents=True)
    (root / DEFAULT_DOC).parent.mkdir(parents=True, exist_ok=True)
    (root / DEFAULT_UV_DOC).parent.mkdir(parents=True, exist_ok=True)
    cases = [
        {
            "id": "fuzz_trace_smoke",
            "execution_status": GOLDEN_TRACE_STATUS,
            "trace_fixture": "sim/golden/fuzz_trace_smoke.trace.jsonl",
            "min_counts": {"SYSCALL_ENTRY": 1, "SYSCALL_RET": 1, "BRANCH": 1, "JUMP": 1, "TRAP": 1, "PRIV": 1, "SATP": 1, "DROP": 1},
            "allowed_trap_causes": ["0x2"],
            "invariants": EXPECTED_INVARIANTS,
        }
    ]
    for case_id in EXPECTED_CASES[1:]:
        min_counts = {"MARKER": 1}
        if case_id == "fuzz_cf":
            min_counts = {"BRANCH": 1, "JUMP": 1, "DROP": 1}
        elif case_id == "fuzz_trap":
            min_counts = {"TRAP": 1, "DROP": 1}
        elif case_id == "fuzz_syscall":
            min_counts = {"SYSCALL_ENTRY": 1, "SYSCALL_RET": 1, "DROP": 1}
        elif case_id == "fuzz_context":
            min_counts = {"SATP": 1, "DROP": 1}
        elif case_id == "fuzz_overflow":
            min_counts = {"BRANCH": 1, "DROP": 1}
        case = {
            "id": case_id,
            "execution_status": GOLDEN_TRACE_STATUS,
            "generated_program": f"build/fuzz_trace_seeds/{case_id}/main.S",
            "trace_fixture": f"sim/golden/{case_id}.trace.jsonl",
            "min_counts": min_counts,
            "invariants": ["known_event_types"],
        }
        if case_id == "fuzz_syscall":
            case.pop("generated_program")
            case["shape_seed"] = "build/fuzz_trace_seeds/fuzz_syscall/main.S"
            case["execution_status"] = SYSCALL_EVIDENCE_STATUS
            case["syscall_harness_evidence"] = {
                "trace_unit_test": "syscall_ret",
                "rvfi_adapter_test": "rvfi_adapter",
                "summary": "results/vivado_sim/summary.json",
                "report": "docs/07-evaluation-evidence/reports/sim_results.md",
                "seed_execution_claimed": False,
            }
        if case_id == "fuzz_trap":
            case["allowed_trap_causes"] = ["0x2", "0x3"]
        cases.append(case)
    (root / DEFAULT_SPEC).write_text(
        json.dumps(
            {
                "schema": "rvmt.fuzz.invariants.v1",
                "status": SPEC_STATUS,
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
dual_commit_order
fuzz_trace_invariants.json
fuzz_trace_report.md
fuzz_cf
fuzz_trap
fuzz_syscall
fuzz_context
fuzz_overflow
PASS_GOLDEN_TRACE_FIXTURES_WITH_SYSCALL_EVIDENCE
PASS_GOLDEN_TRACE_FIXTURE
PASS_GOLDEN_TRACE_FIXTURE_WITH_SYSCALL_EVIDENCE
syscall_ret
rvfi_adapter
existing trace-unit and RVFI adapter syscall evidence
seed assembly is still not treated as executed processor evidence

| Order | Case | Stress focus | Required invariant families | Status |
| ---: | --- | --- | --- | --- |
| 1 | fuzz_cf | control | known | PASS_GOLDEN_TRACE_FIXTURE |
| 2 | fuzz_trap | trap | known | PASS_GOLDEN_TRACE_FIXTURE |
| 3 | fuzz_syscall | syscall | known | PASS_GOLDEN_TRACE_FIXTURE_WITH_SYSCALL_EVIDENCE |
| 4 | fuzz_context | context | known | PASS_GOLDEN_TRACE_FIXTURE |
| 5 | fuzz_overflow | overflow | known | PASS_GOLDEN_TRACE_FIXTURE |
""",
        encoding="utf-8",
    )
    (root / DEFAULT_UV_DOC).write_text(
        "uv run python tools/gen_rv_trace_fuzz.py --self-test\n"
        "uv run python tools/check_fuzz_trace.py --self-test\n"
        "uv run python tools/check_fuzz_trace.py --trace sim/golden/fuzz_trace_smoke.trace.jsonl --case fuzz_trace_smoke\n"
        "uv run python tools/check_fuzz_trace_plan.py\n"
        "docs/06-validation-gates/fuzz_trace_validation.md\n"
        "sim/golden/fuzz_invariants.json\n"
        "results/vivado_sim/summary.json\n"
        "docs/07-evaluation-evidence/reports/sim_results.md\n",
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
        tool_errors = check_tools(repo_root, DEFAULT_GENERATOR, DEFAULT_CHECKER, DEFAULT_SMOKE, DEFAULT_SIM_SUMMARY, DEFAULT_SIM_REPORT)
        if tool_errors:
            for error in tool_errors:
                print(f"[FAIL] self-test report-output gate failed: {error}", file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        summary_path = root / DEFAULT_SIM_SUMMARY
        report_path = root / DEFAULT_SIM_REPORT
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        (summary_path.parent / "syscall_ret").mkdir(parents=True, exist_ok=True)
        (summary_path.parent / "rvfi_adapter").mkdir(parents=True, exist_ok=True)
        (summary_path.parent / "syscall_ret" / "compare.log").write_text("[PASS] SYSCALL_ENTRY\n", encoding="utf-8")
        (summary_path.parent / "rvfi_adapter" / "compare.log").write_text(
            "[PASS] required event matched SYSCALL_ENTRY\n[PASS] required event matched SYSCALL_RET\n",
            encoding="utf-8",
        )
        summary_path.write_text(
            json.dumps(
                {
                    "overall": "PASS",
                    "tests": {
                        "syscall_ret": {
                            "status": "PASS",
                            "counts": {"SYSCALL_ENTRY": 1},
                            "compare_log": (DEFAULT_SIM_SUMMARY.parent / "syscall_ret" / "compare.log").as_posix(),
                        },
                        "rvfi_adapter": {
                            "status": "PASS",
                            "counts": {"SYSCALL_ENTRY": 1, "SYSCALL_RET": 1},
                            "compare_log": (DEFAULT_SIM_SUMMARY.parent / "rvfi_adapter" / "compare.log").as_posix(),
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        report_path.write_text("syscall_ret SRET-to-U rvfi_adapter U-mode syscall entry/return correlation\n", encoding="utf-8")
        if not check_syscall_harness_evidence(root, DEFAULT_SIM_SUMMARY, DEFAULT_SIM_REPORT):
            print("[FAIL] self-test missed incomplete syscall evidence summary", file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        summary_path = root / DEFAULT_SIM_SUMMARY
        report_path = root / DEFAULT_SIM_REPORT
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        for test_id in ("syscall_ret", "rvfi_adapter"):
            log_dir = summary_path.parent / test_id
            log_dir.mkdir(parents=True, exist_ok=True)
            (log_dir / "compare.log").write_text(
                "[PASS] required event matched SYSCALL_ENTRY\n[PASS] required event matched SYSCALL_RET\n[PASS] required event matched TRAP\n",
                encoding="utf-8",
            )
        summary_path.write_text(
            json.dumps(
                {
                    "overall": "PASS",
                    "tests": {
                        "syscall_ret": {
                            "status": "PASS",
                            "counts": {"SYSCALL_ENTRY": 1, "SYSCALL_RET": 1, "TRAP": 1},
                            "compare_log": r"results\vivado_sim\syscall_ret\compare.log",
                        },
                        "rvfi_adapter": {
                            "status": "PASS",
                            "counts": {"SYSCALL_ENTRY": 1, "SYSCALL_RET": 1},
                            "compare_log": r"results\vivado_sim\rvfi_adapter\compare.log",
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        report_path.write_text("syscall_ret SRET-to-U rvfi_adapter U-mode syscall entry/return correlation\n", encoding="utf-8")
        path_errors = check_syscall_harness_evidence(root, DEFAULT_SIM_SUMMARY, DEFAULT_SIM_REPORT)
        if path_errors:
            for error in path_errors:
                print(f"[FAIL] self-test rejected Windows-style artifact path: {error}", file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["status"] = "TODO(SIM)"
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, f"status must be {SPEC_STATUS}"):
            print("[FAIL] self-test missed stale fuzz TODO status", file=sys.stderr)
            return 1
    for phrase in ("TODO(SIM)", "TODO(HARNESS)", "PASS_SHAPE_FIXTURE_HARNESS_OPEN", "processor bug-discovery is complete", "RISCV-DV campaign is complete"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            doc = root / DEFAULT_DOC
            doc.write_text(doc.read_text(encoding="utf-8") + f"\n{phrase}\n", encoding="utf-8")
            if not expect_error(root, "must not claim fuzzing TODO or processor bug discovery"):
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
    parser.add_argument("--sim-summary", type=Path, default=DEFAULT_SIM_SUMMARY)
    parser.add_argument("--sim-report", type=Path, default=DEFAULT_SIM_REPORT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        errors = run_checks(args.root.resolve(), args.spec, args.doc, args.generator, args.checker, args.smoke, args.uv_doc, args.sim_summary, args.sim_report)
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
