from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

from experiment_common import (
    resolve,
)


DEFAULT_CRITERIA = Path("docs/03-platform-architecture/genesys2/baseline_pass_criteria.md")
DEFAULT_BOARD_DOC = Path("docs/03-platform-architecture/genesys2/board_bringup.md")
DEFAULT_BITSTREAM = Path("build/vivado/genesys2-cv64a6_imafdc_sv39/work-fpga/ariane_xilinx.bit")
DEFAULT_EVIDENCE_PARENT = Path("results/board/genesys2_baseline")

CRITERIA = {
    "Bitstream generated": "PASS",
    "Board clock/reset stable": "TODO (BOARD)",
    "UART output visible": "TODO (BOARD)",
    "Bare-metal program can run": "TODO (BOARD)",
    "No trace modification yet": "PASS",
}
BOARD_EVIDENCE = {
    "Board clock/reset stable": "01_led_clock_reset/observation.md",
    "UART output visible": "02_uart_hello/observation.md",
    "Bare-metal program can run": "04_cva6_baremetal_boot/observation.md",
}
BOARD_DOC_EVIDENCE = {
    "Clock/reset sanity": "01_led_clock_reset/observation.md",
    "LED Blink / Clock Reset Sanity": "01_led_clock_reset/observation.md",
    "UART hello": "02_uart_hello/observation.md",
    "UART Hello": "02_uart_hello/observation.md",
    "Bare-metal program runs": "04_cva6_baremetal_boot/observation.md",
    "CVA6 Bare-metal Boot": "04_cva6_baremetal_boot/observation.md",
    **BOARD_EVIDENCE,
}
FORBIDDEN_HARDWARE_PASS = (
    "Board clock/reset stable",
    "UART output visible",
    "Bare-metal program can run",
)
PRE_EVIDENCE_BOUNDARY = "Pre-evidence physical-board criteria stay TODO (BOARD)"
ACCEPTED_EVIDENCE_BOUNDARY = "Phase 4.4 baseline board bring-up is accepted"
TRACE_SCOPE_BOUNDARY = "does not claim trace-enabled board export, production streaming/DMA"
STALE_INCOMPLETE_BOUNDARY = "Baseline board bring-up is not complete"


def parse_table_rows(text: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip("|").split("|")]
        if cells and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            continue
        if cells and cells[0] in {"Criterion", "Gate", "Order"}:
            continue
        rows.append(cells)
    return rows


def pass_observation(path: Path) -> bool:
    if not path.is_file():
        return False
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if not lines:
        return False
    return lines[0] == "PASS" or lines[0] == "Status: PASS"


def infer_documented_evidence_root(root: Path, criteria: Path, explicit: Path | None) -> tuple[Path | None, list[str]]:
    if explicit is not None:
        return explicit, []
    path = resolve(root, criteria)
    if not path.exists():
        return None, []
    text = path.read_text(encoding="utf-8", errors="replace")
    run_ids = sorted(set(re.findall(r"results/board/genesys2_baseline/([A-Za-z0-9._-]+)/?", text)))
    if not run_ids:
        return None, []
    if len(run_ids) > 1:
        return None, [f"{path}: multiple documented baseline evidence roots; pass --evidence-root explicitly: {run_ids}"]
    return DEFAULT_EVIDENCE_PARENT / run_ids[0], []


def check_evidence_root(root: Path, evidence_root: Path | None) -> list[str]:
    if evidence_root is None:
        return []
    evidence = resolve(root, evidence_root)
    errors: list[str] = []
    if not evidence.is_dir():
        errors.append(f"evidence root does not exist or is not a directory: {evidence}")
    expected_parent = (root / "results" / "board" / "genesys2_baseline").resolve()
    try:
        relative = evidence.resolve().relative_to(expected_parent)
    except ValueError:
        errors.append(f"evidence root must be under {expected_parent}: {evidence}")
    else:
        if len(relative.parts) != 1:
            errors.append(f"evidence root must be exactly one <run-id> below {expected_parent}: {evidence}")
    return errors


def check_criteria_doc(root: Path, criteria: Path, bitstream: Path, evidence_root: Path | None) -> list[str]:
    path = resolve(root, criteria)
    errors: list[str] = []
    if not path.exists():
        return [f"missing criteria doc: {path}"]
    text = path.read_text(encoding="utf-8")
    normalized_text = " ".join(text.split())
    if "This document separates repository-local evidence from physical board evidence." not in text:
        errors.append(f"{path}: missing repository-local vs board-evidence boundary")
    rows = parse_table_rows(text)
    matching: dict[str, list[list[str]]] = {}
    for row in rows:
        if row:
            matching.setdefault(row[0], []).append(row)

    expected_names = set(CRITERIA)
    actual_names = set(matching)
    if actual_names != expected_names:
        errors.append(f"{path}: criteria rows differ from expected set: {sorted(actual_names)}")

    for name, expected_status in CRITERIA.items():
        rows_for_name = matching.get(name, [])
        if len(rows_for_name) != 1:
            errors.append(f"{path}: expected exactly one row for {name}, found {len(rows_for_name)}")
            continue
        row = rows_for_name[0]
        if len(row) < 4:
            errors.append(f"{path}: malformed row for {name}: {row}")
            continue
        status = row[1]
        if name in BOARD_EVIDENCE and evidence_root is not None:
            observation = resolve(root, evidence_root / BOARD_EVIDENCE[name])
            expected_with_evidence = "PASS" if pass_observation(observation) else "TODO (BOARD)"
            if status != expected_with_evidence:
                errors.append(f"{path}: status for {name} is {status}, expected {expected_with_evidence} from {observation}")
        elif status != expected_status:
            errors.append(f"{path}: status for {name} is {status}, expected {expected_status}")
        if name in FORBIDDEN_HARDWARE_PASS and evidence_root is None and status == "PASS":
            errors.append(f"{path}: hardware criterion {name} cannot be PASS without --evidence-root")

    bitstream_path = resolve(root, bitstream)
    if not bitstream_path.is_file() or bitstream_path.stat().st_size <= 0:
        errors.append(f"missing or empty bitstream evidence: {bitstream_path}")
    if STALE_INCOMPLETE_BOUNDARY in normalized_text:
        errors.append(f"{path}: stale incomplete baseline wording remains")
    if evidence_root is None:
        if PRE_EVIDENCE_BOUNDARY not in normalized_text:
            errors.append(f"{path}: missing pre-evidence TODO boundary")
        if ACCEPTED_EVIDENCE_BOUNDARY in normalized_text:
            errors.append(f"{path}: claims accepted baseline without documented evidence root")
    else:
        if ACCEPTED_EVIDENCE_BOUNDARY not in normalized_text:
            errors.append(f"{path}: missing accepted baseline evidence boundary")
        if TRACE_SCOPE_BOUNDARY not in normalized_text:
            errors.append(f"{path}: missing trace/export scope boundary")
    return errors


def check_board_doc(root: Path, board_doc: Path, evidence_root: Path | None) -> list[str]:
    path = resolve(root, board_doc)
    if not path.exists():
        return [f"missing board doc: {path}"]
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    if "docs/03-platform-architecture/genesys2/baseline_pass_criteria.md" not in text:
        errors.append(f"{path}: missing baseline pass criteria link")
    rows = parse_table_rows(text)
    for row in rows:
        name: str | None = None
        status_index: int | None = None
        if row and row[0] in BOARD_DOC_EVIDENCE and len(row) > 1:
            name = row[0]
            status_index = 1
        elif len(row) > 2 and row[1] in BOARD_DOC_EVIDENCE:
            name = row[1]
            status_index = 2
        if name is None or status_index is None:
            continue
        status = row[status_index]
        if evidence_root is None:
            if status == "PASS":
                errors.append(f"{path}: hardware board row {name} is PASS before evidence")
            continue
        observation = resolve(root, evidence_root / BOARD_DOC_EVIDENCE[name])
        expected = "PASS" if pass_observation(observation) else "TODO (BOARD)"
        if status != expected:
            errors.append(f"{path}: status for {name} is {status}, expected {expected} from {observation}")
    return errors


def run_checks(root: Path, criteria: Path, board_doc: Path, bitstream: Path, evidence_root: Path | None) -> list[str]:
    effective_evidence_root, errors = infer_documented_evidence_root(root, criteria, evidence_root)
    errors.extend(check_evidence_root(root, effective_evidence_root))
    errors.extend(check_criteria_doc(root, criteria, bitstream, effective_evidence_root))
    errors.extend(check_board_doc(root, board_doc, effective_evidence_root))
    return errors


def write_fixture(root: Path) -> None:
    docs = root / DEFAULT_CRITERIA.parent
    docs.mkdir(parents=True)
    bitstream = root / DEFAULT_BITSTREAM
    bitstream.parent.mkdir(parents=True)
    bitstream.write_text("bitstream\n", encoding="utf-8")
    (root / DEFAULT_CRITERIA).write_text(
        "\n".join(
            [
                "# Baseline Pass Criteria",
                "",
                "This document separates repository-local evidence from physical board evidence.",
                "",
                "| Criterion | Current Status | Required Evidence | Source |",
                "| --- | --- | --- | --- |",
                "| Bitstream generated | PASS | bitstream | checker |",
                "| Board clock/reset stable | TODO (BOARD) | 01_led_clock_reset/observation.md | runbook |",
                "| UART output visible | TODO (BOARD) | 02_uart_hello/observation.md | runbook |",
                "| Bare-metal program can run | TODO (BOARD) | 04_cva6_baremetal_boot/observation.md | runbook |",
                "| No trace modification yet | PASS | no trace path | runbook |",
                "",
                "Pre-evidence physical-board criteria stay TODO (BOARD) until matching observation files exist under `results/board/genesys2_baseline/<run-id>/`.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (root / DEFAULT_BOARD_DOC).write_text(
        "\n".join(
            [
                "See docs/03-platform-architecture/genesys2/baseline_pass_criteria.md",
                "",
                "| Gate | Status | Evidence |",
                "| --- | --- | --- |",
                "| Clock/reset sanity | TODO (BOARD) | notes |",
                "| UART hello | TODO (BOARD) | notes |",
                "| Bare-metal program runs | TODO (BOARD) | notes |",
                "",
                "| Order | Step | Status | Evidence directory |",
                "| ---: | --- | --- | --- |",
                "| 1 | LED Blink / Clock Reset Sanity | TODO (BOARD) | `01_led_clock_reset/` |",
                "| 2 | UART Hello | TODO (BOARD) | `02_uart_hello/` |",
                "| 4 | CVA6 Bare-metal Boot | TODO (BOARD) | `04_cva6_baremetal_boot/` |",
                "",
                "| Criterion | Status | Evidence |",
                "| --- | --- | --- |",
                "| Board clock/reset stable | TODO (BOARD) | notes |",
                "| UART output visible | TODO (BOARD) | notes |",
                "| Bare-metal program can run | TODO (BOARD) | notes |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def mark_fixture_evidence_pass(root: Path, evidence: Path) -> None:
    evidence_abs = resolve(root, evidence)
    for observation_path in BOARD_EVIDENCE.values():
        observation = evidence_abs / observation_path
        observation.parent.mkdir(parents=True, exist_ok=True)
        observation.write_text("PASS\n", encoding="utf-8")

    criteria = root / DEFAULT_CRITERIA
    criteria_text = criteria.read_text(encoding="utf-8")
    for name in BOARD_EVIDENCE:
        criteria_text = criteria_text.replace(f"| {name} | TODO (BOARD) |", f"| {name} | PASS |")
    criteria_text = criteria_text.replace(
        "Pre-evidence physical-board criteria stay TODO (BOARD) until matching observation files exist under `results/board/genesys2_baseline/<run-id>/`.",
        "\n".join(
            [
                "Phase 4.4 baseline board bring-up is accepted for run `run1`: the three physical-board rows above have PASS evidence under",
                "`results/board/genesys2_baseline/run1/`.",
                "This baseline PASS is scoped to the existing CVA6 FPGA build. It does not claim trace-enabled board export, production streaming/DMA, full-retire trace, or Linux boot.",
            ]
        ),
    )
    criteria.write_text(criteria_text, encoding="utf-8")

    board_doc = root / DEFAULT_BOARD_DOC
    board_doc_text = board_doc.read_text(encoding="utf-8")
    for name in ("Clock/reset sanity", "UART hello", "Bare-metal program runs"):
        board_doc_text = board_doc_text.replace(f"| {name} | TODO (BOARD) |", f"| {name} | PASS |")
    for name in ("LED Blink / Clock Reset Sanity", "UART Hello", "CVA6 Bare-metal Boot"):
        board_doc_text = board_doc_text.replace(f"| {name} | TODO (BOARD) |", f"| {name} | PASS |")
    for name in BOARD_EVIDENCE:
        board_doc_text = board_doc_text.replace(f"| {name} | TODO (BOARD) |", f"| {name} | PASS |")
    board_doc.write_text(board_doc_text, encoding="utf-8")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = run_checks(root, DEFAULT_CRITERIA, DEFAULT_BOARD_DOC, DEFAULT_BITSTREAM, None)
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        criteria = root / DEFAULT_CRITERIA
        criteria.write_text(criteria.read_text(encoding="utf-8").replace("| UART output visible | TODO (BOARD) |", "| UART output visible | PASS |"), encoding="utf-8")
        errors = run_checks(root, DEFAULT_CRITERIA, DEFAULT_BOARD_DOC, DEFAULT_BITSTREAM, None)
        if not any("UART output visible" in error and "expected TODO" in error for error in errors):
            print("[FAIL] self-test missed premature UART PASS", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / DEFAULT_BITSTREAM).unlink()
        errors = run_checks(root, DEFAULT_CRITERIA, DEFAULT_BOARD_DOC, DEFAULT_BITSTREAM, None)
        if not any("bitstream" in error for error in errors):
            print("[FAIL] self-test missed missing bitstream", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        evidence = Path("results") / "board" / "genesys2_baseline" / "run1"
        evidence_abs = root / evidence
        observation = evidence_abs / "02_uart_hello" / "observation.md"
        observation.parent.mkdir(parents=True)
        observation.write_text("PASS\n", encoding="utf-8")
        errors = run_checks(root, DEFAULT_CRITERIA, DEFAULT_BOARD_DOC, DEFAULT_BITSTREAM, evidence)
        if not any("UART output visible" in error and "expected PASS" in error for error in errors):
            print("[FAIL] self-test missed stale TODO with PASS evidence", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        evidence = Path("results") / "board" / "genesys2_baseline" / "run1"
        evidence_abs = root / evidence
        observation = evidence_abs / "02_uart_hello" / "observation.md"
        observation.parent.mkdir(parents=True)
        observation.write_text("Status: FAIL\nExpected PASS criteria not met\n", encoding="utf-8")
        criteria = root / DEFAULT_CRITERIA
        criteria.write_text(criteria.read_text(encoding="utf-8").replace("| UART output visible | TODO (BOARD) |", "| UART output visible | PASS |"), encoding="utf-8")
        errors = run_checks(root, DEFAULT_CRITERIA, DEFAULT_BOARD_DOC, DEFAULT_BITSTREAM, evidence)
        if not any("UART output visible" in error and "expected TODO" in error for error in errors):
            print("[FAIL] self-test missed FAIL observation mentioning PASS", file=sys.stderr)
            return 1

    for bad_text in ("\nPASS\n", " PASS \n", "status: pass\n", "Status : PASS\n"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            evidence = Path("results") / "board" / "genesys2_baseline" / "run1"
            evidence_abs = root / evidence
            observation = evidence_abs / "02_uart_hello" / "observation.md"
            observation.parent.mkdir(parents=True)
            observation.write_text(bad_text, encoding="utf-8")
            criteria = root / DEFAULT_CRITERIA
            criteria.write_text(criteria.read_text(encoding="utf-8").replace("| UART output visible | TODO (BOARD) |", "| UART output visible | PASS |"), encoding="utf-8")
            errors = run_checks(root, DEFAULT_CRITERIA, DEFAULT_BOARD_DOC, DEFAULT_BITSTREAM, evidence)
            if not any("UART output visible" in error and "expected TODO" in error for error in errors):
                print(f"[FAIL] self-test accepted non-exact PASS observation: {bad_text!r}", file=sys.stderr)
                return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = run_checks(root, DEFAULT_CRITERIA, DEFAULT_BOARD_DOC, DEFAULT_BITSTREAM, Path("does-not-exist"))
        if not any("evidence root does not exist" in error for error in errors):
            print("[FAIL] self-test missed nonexistent evidence root", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        evidence = Path("somewhere_else") / "run1"
        evidence_abs = root / evidence
        observation = evidence_abs / "02_uart_hello" / "observation.md"
        observation.parent.mkdir(parents=True)
        observation.write_text("PASS\n", encoding="utf-8")
        errors = run_checks(root, DEFAULT_CRITERIA, DEFAULT_BOARD_DOC, DEFAULT_BITSTREAM, evidence)
        if not any("evidence root must be under" in error for error in errors):
            print("[FAIL] self-test missed evidence root outside board results", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        evidence = root / "results" / "board" / "genesys2_baseline"
        errors = run_checks(root, DEFAULT_CRITERIA, DEFAULT_BOARD_DOC, DEFAULT_BITSTREAM, evidence)
        if not any("exactly one <run-id>" in error for error in errors):
            print("[FAIL] self-test missed parent evidence root", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        evidence = root / "results" / "board" / "genesys2_baseline" / "run1" / "nested"
        evidence.mkdir(parents=True)
        errors = run_checks(root, DEFAULT_CRITERIA, DEFAULT_BOARD_DOC, DEFAULT_BITSTREAM, evidence)
        if not any("exactly one <run-id>" in error for error in errors):
            print("[FAIL] self-test missed nested evidence root", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        evidence = root / "results" / "board" / "genesys2_baseline" / "run1"
        observation = evidence / "02_uart_hello" / "observation.md"
        observation.parent.mkdir(parents=True)
        observation.write_text("PASS\n", encoding="utf-8")
        errors = run_checks(root, DEFAULT_CRITERIA, DEFAULT_BOARD_DOC, DEFAULT_BITSTREAM, evidence)
        if not any("UART output visible" in error and "expected PASS" in error for error in errors):
            print("[FAIL] self-test missed stale TODO with PASS evidence", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        evidence = Path("results") / "board" / "genesys2_baseline" / "run1"
        mark_fixture_evidence_pass(root, evidence)
        errors = run_checks(root, DEFAULT_CRITERIA, DEFAULT_BOARD_DOC, DEFAULT_BITSTREAM, None)
        if errors:
            for error in errors:
                print(f"[FAIL] self-test rejected accepted evidence fixture: {error}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        evidence = Path("results") / "board" / "genesys2_baseline" / "run1"
        mark_fixture_evidence_pass(root, evidence)
        criteria = root / DEFAULT_CRITERIA
        criteria.write_text(
            criteria.read_text(encoding="utf-8").replace(
                "Phase 4.4 baseline board bring-up is accepted",
                "Baseline board bring-up is not complete",
            ),
            encoding="utf-8",
        )
        errors = run_checks(root, DEFAULT_CRITERIA, DEFAULT_BOARD_DOC, DEFAULT_BITSTREAM, None)
        if not any("stale incomplete baseline wording" in error for error in errors):
            print("[FAIL] self-test missed stale incomplete baseline wording", file=sys.stderr)
            return 1

    print("[PASS] baseline pass criteria self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Phase 4.4 baseline pass criteria evidence boundaries.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root. Defaults to the current directory.")
    parser.add_argument("--criteria", type=Path, default=DEFAULT_CRITERIA)
    parser.add_argument("--board-doc", type=Path, default=DEFAULT_BOARD_DOC)
    parser.add_argument("--bitstream", type=Path, default=DEFAULT_BITSTREAM)
    parser.add_argument("--evidence-root", type=Path, default=None, help="Optional concrete results/board/genesys2_baseline/<run-id> directory.")
    parser.add_argument("--self-test", action="store_true", help="Run positive and negative coverage checks.")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    errors = run_checks(args.root.resolve(), args.criteria, args.board_doc, args.bitstream, args.evidence_root)
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] baseline pass criteria are evidence-scoped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
