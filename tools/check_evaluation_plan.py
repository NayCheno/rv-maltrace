from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path


DEFAULT_DOC = Path("docs/research/evaluation_plan.md")
DEFAULT_UV_DOC = Path("docs/process/uv_workflow.md")

REQUIRED_TEXT = (
    "This document turns `docs/planning/next-plan.md` Section 9 and Stage 3 into a checkable evaluation plan.",
    "research design and artifact gate, not evaluation evidence.",
    "RQ1",
    "Correctness: can committed syscall/control-flow/trap/context events be captured accurately?",
    "RQ2",
    "Semantic reconstruction: can syscall arguments, return values, paths, fd behavior, and behavior graphs be recovered?",
    "RQ3",
    "Low perturbation",
    "RQ4",
    "Evasion resistance",
    "RQ5",
    "Hardware cost",
    "RQ6",
    "Malware behavior usefulness",
    "`strace` / `ptrace`",
    "eBPF-only",
    "QEMU plugin",
    "RV-MalScope event-only",
    "RV-MalScope + pointer snapshot",
    "RV-MalScope + kernel helper/eBPF companion",
    "Class A",
    "Class B",
    "Class C",
    "syscall precision / recall",
    "argument reconstruction accuracy",
    "path string reconstruction accuracy",
    "trace drop rate",
    "LUT / FF / BRAM overhead",
    "Fmax degradation",
    "simulation correctness",
    "board baseline",
    "Linux syscall trace",
    "Do not claim board or Linux validation from simulation-only artifacts.",
    "uv run python tools/check_evaluation_plan.py",
)

FORBIDDEN_PATTERNS = (
    re.compile(r"\bPASS\b", re.IGNORECASE),
    re.compile(r"\b(?:evaluation|experiment|study|suite)\s+(?:is|are|has|have)?\s*(?:been\s+)?(?:complete|completed|validated|passed)\b", re.IGNORECASE),
    re.compile(r"\bCCF-A\s+(?:ready|readiness|accepted|acceptable|guaranteed)\b", re.IGNORECASE),
    re.compile(r"\bboard\s+(?:validation|trace|baseline)\s+(?:is|has)?\s*(?:been\s+)?(?:complete|completed|validated|passed)\b", re.IGNORECASE),
    re.compile(r"\bLinux\s+(?:syscall\s+)?trace\s+(?:is|has)?\s*(?:been\s+)?(?:complete|completed|validated|passed)\b", re.IGNORECASE),
)

EXPECTED_RQ_IDS = ("RQ1", "RQ2", "RQ3", "RQ4", "RQ5", "RQ6")
EXPECTED_BASELINES = (
    "strace / ptrace",
    "eBPF-only",
    "QEMU plugin",
    "software instrumentation",
    "RV-MalScope event-only",
    "RV-MalScope + pointer snapshot",
    "RV-MalScope + kernel helper/eBPF companion",
)
EXPECTED_DATASETS = ("Class A", "Class B", "Class C")
EXPECTED_METRICS = (
    "syscall precision / recall",
    "argument reconstruction accuracy",
    "path string reconstruction accuracy",
    "fd graph accuracy",
    "runtime overhead",
    "cycle-level perturbation",
    "trace drop rate",
    "trace bytes per syscall",
    "LUT / FF / BRAM overhead",
    "Fmax degradation",
    "anti-analysis detection outcome",
)
EXPECTED_GATES = (
    "simulation correctness",
    "direct-core CVA6 smoke",
    "board baseline",
    "board trace",
    "Linux syscall trace",
    "semantic reconstruction",
    "evasion suite",
    "hardware cost",
    "ablation study",
    "case studies",
    "artifact package",
)
EXPECTED_STATUSES = ("TODO", "TODO(BOARD)", "TODO(LINUX)")


def normalized_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def parse_table_rows(text: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip().replace("`", "") for cell in line.strip("|").split("|")]
        if cells and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            continue
        rows.append(cells)
    return rows


def section_text(text: str, heading: str) -> str:
    pattern = re.compile(rf"^##\s+{re.escape(heading)}\s*$", re.MULTILINE)
    match = pattern.search(text)
    if match is None:
        return ""
    next_match = re.search(r"^##\s+", text[match.end() :], re.MULTILINE)
    end = match.end() + next_match.start() if next_match else len(text)
    return text[match.end() : end]


def section_table_rows(text: str, heading: str, header_first_cell: str) -> list[list[str]]:
    rows = parse_table_rows(section_text(text, heading))
    return [row for row in rows if row and row[0] != header_first_cell]


def is_negated_context(text: str, start: int) -> bool:
    prefix = text[max(0, start - 96) : start].lower()
    return any(marker in prefix for marker in ("do not", "must not", "should not", "never ")) or bool(
        re.search(r"\bnot(?:\s+\w+){0,6}\s*$", prefix)
    )


def check_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    normalized = normalized_text(text)
    errors: list[str] = []

    for required in REQUIRED_TEXT:
        if normalized_text(required) not in normalized:
            errors.append(f"{path}: missing required text: {required}")

    for pattern in FORBIDDEN_PATTERNS:
        for match in pattern.finditer(text):
            if is_negated_context(text, match.start()):
                continue
            errors.append(f"{path}: must not claim completed evaluation, board, Linux, or CCF-A evidence")
            break

    rq_section_rows = section_table_rows(text, "Research Questions", "ID")
    baseline_section_rows = section_table_rows(text, "Baselines", "Baseline")
    dataset_section_rows = section_table_rows(text, "Datasets", "Class")
    metric_section_rows = section_table_rows(text, "Metrics", "Metric")
    gate_section_rows = section_table_rows(text, "Artifact Gates", "Gate")
    rows = rq_section_rows + baseline_section_rows + dataset_section_rows + metric_section_rows + gate_section_rows

    if not rq_section_rows:
        errors.append(f"{path}: missing Research Questions table")
    if not baseline_section_rows:
        errors.append(f"{path}: missing Baselines table")
    if not dataset_section_rows:
        errors.append(f"{path}: missing Datasets table")
    if not metric_section_rows:
        errors.append(f"{path}: missing Metrics table")
    if not gate_section_rows:
        errors.append(f"{path}: missing Artifact Gates table")

    rq_rows = {row[0]: row for row in rows if row and row[0] in EXPECTED_RQ_IDS}
    rq_ids = [row[0] for row in rq_section_rows]
    if rq_ids != list(EXPECTED_RQ_IDS):
        errors.append(f"{path}: research question rows must be exactly {list(EXPECTED_RQ_IDS)}")
    for rq_id, row in rq_rows.items():
        if len(row) < 4 or row[3] != "TODO":
            errors.append(f"{path}: {rq_id} status must remain TODO")

    dataset_rows = {row[0]: row for row in rows if row and row[0] in EXPECTED_DATASETS}
    dataset_ids = [row[0] for row in dataset_section_rows]
    if dataset_ids != list(EXPECTED_DATASETS):
        errors.append(f"{path}: dataset rows must be exactly {list(EXPECTED_DATASETS)}")
    for dataset_id, row in dataset_rows.items():
        if len(row) < 4 or row[3] != "TODO":
            errors.append(f"{path}: {dataset_id} status must remain TODO")

    baseline_rows = {row[0]: row for row in rows if row and row[0] in EXPECTED_BASELINES}
    baseline_ids = [row[0] for row in baseline_section_rows]
    if baseline_ids != list(EXPECTED_BASELINES):
        errors.append(f"{path}: baseline rows must be exactly {list(EXPECTED_BASELINES)}")
    for baseline_id, row in baseline_rows.items():
        if len(row) < 4 or row[3] != "TODO":
            errors.append(f"{path}: {baseline_id} status must remain TODO")

    metric_rows = {row[0]: row for row in rows if row and row[0] in EXPECTED_METRICS}
    metric_ids = [row[0] for row in metric_section_rows]
    if metric_ids != list(EXPECTED_METRICS):
        errors.append(f"{path}: metric rows must be exactly {list(EXPECTED_METRICS)}")

    gate_rows = {row[0]: row for row in rows if row and row[0] in EXPECTED_GATES}
    gate_ids = [row[0] for row in gate_section_rows]
    if gate_ids != list(EXPECTED_GATES):
        errors.append(f"{path}: artifact gate rows must be exactly {list(EXPECTED_GATES)}")
    for gate_id, row in gate_rows.items():
        if len(row) < 3:
            errors.append(f"{path}: {gate_id} gate row is malformed")
            continue
        expected_status = "TODO"
        if gate_id in {"board baseline", "board trace"}:
            expected_status = "TODO(BOARD)"
        elif gate_id == "Linux syscall trace":
            expected_status = "TODO(LINUX)"
        if row[2] != expected_status:
            errors.append(f"{path}: {gate_id} status must remain {expected_status}")

    if "results/board/genesys2_baseline/<run-id>/" not in text:
        errors.append(f"{path}: board baseline gate must use results/board/genesys2_baseline/<run-id>/")
    if "results/board/genesys2_trace_validation/<run-id>/" not in text:
        errors.append(f"{path}: board trace gate must use results/board/genesys2_trace_validation/<run-id>/")

    statuses = [cell for row in rows for cell in row if cell in EXPECTED_STATUSES or cell.startswith("TODO")]
    if "TODO(BOARD)" not in statuses:
        errors.append(f"{path}: board gates must use TODO(BOARD)")
    if "TODO(LINUX)" not in statuses:
        errors.append(f"{path}: Linux gates must use TODO(LINUX)")
    unexpected_statuses = sorted({cell for cell in statuses if cell not in EXPECTED_STATUSES})
    if unexpected_statuses:
        errors.append(f"{path}: unexpected TODO-style statuses: {unexpected_statuses}")

    return errors


def check_uv_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    for token in ("tools/check_evaluation_plan.py", "docs/research/evaluation_plan.md"):
        if token not in text:
            errors.append(f"{path}: missing {token}")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        tools = root / "tools"
        doc = root / DEFAULT_DOC
        uv_doc = root / DEFAULT_UV_DOC
        doc.parent.mkdir(parents=True)
        uv_doc.parent.mkdir(parents=True)
        tools.mkdir()

        source_doc = DEFAULT_DOC.read_text(encoding="utf-8")
        doc.write_text(source_doc, encoding="utf-8")
        uv_doc.write_text(
            "uv run python tools/check_evaluation_plan.py\n"
            "docs/research/evaluation_plan.md\n",
            encoding="utf-8",
        )

        if check_doc(doc) or check_uv_doc(uv_doc):
            print("[FAIL] self-test rejected valid evaluation plan fixture", file=sys.stderr)
            return 1

        doc.write_text(source_doc.replace("| RQ1 |", "| RQX |", 1), encoding="utf-8")
        if not any("research question rows" in error for error in check_doc(doc)):
            print("[FAIL] self-test missed missing RQ row", file=sys.stderr)
            return 1

        doc.write_text(source_doc.replace("TODO(BOARD)", "PASS", 1), encoding="utf-8")
        if not any("must not claim" in error for error in check_doc(doc)):
            print("[FAIL] self-test missed PASS evidence claim", file=sys.stderr)
            return 1

        doc.write_text(
            source_doc.replace(
                "| artifact package | scripts, manifests, expected outputs, and reproduction notes | TODO |",
                "| extra gate | extra artifacts | TODO |\n"
                "| artifact package | scripts, manifests, expected outputs, and reproduction notes | TODO |",
            ),
            encoding="utf-8",
        )
        if not any("artifact gate rows" in error for error in check_doc(doc)):
            print("[FAIL] self-test missed extra artifact gate row", file=sys.stderr)
            return 1

        doc.write_text(source_doc + "\nDo not claim board trace passed before evidence exists.\n", encoding="utf-8")
        if check_doc(doc):
            print("[FAIL] self-test rejected negated forbidden wording", file=sys.stderr)
            return 1

        doc.write_text(source_doc + "\nThis gate is not PASS before evidence exists.\n", encoding="utf-8")
        if check_doc(doc):
            print("[FAIL] self-test rejected not-PASS wording", file=sys.stderr)
            return 1

        uv_doc.write_text("uv run rvmt tasks:list\n", encoding="utf-8")
        if not check_uv_doc(uv_doc):
            print("[FAIL] self-test missed missing uv workflow reference", file=sys.stderr)
            return 1

    print("[PASS] evaluation plan self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the RV-MalTrace evaluation plan gate.")
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--uv-doc", type=Path, default=DEFAULT_UV_DOC)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    errors: list[str] = []
    try:
        errors.extend(check_doc(args.doc))
        errors.extend(check_uv_doc(args.uv_doc))
    except Exception as exc:
        print(f"check_evaluation_plan: error: {exc}", file=sys.stderr)
        return 2

    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1

    print(f"[PASS] evaluation plan gate: {args.doc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
