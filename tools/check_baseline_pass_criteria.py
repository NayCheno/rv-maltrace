from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path


DEFAULT_CRITERIA = Path("docs/03-platform-architecture/genesys2/baseline_pass_criteria.md")
DEFAULT_BOARD_DOC = Path("docs/03-platform-architecture/genesys2/board_bringup.md")
DEFAULT_BITSTREAM = Path("build/vivado/genesys2-cv64a6_imafdc_sv39/work-fpga/ariane_xilinx.bit")

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
FORBIDDEN_HARDWARE_PASS = (
    "Board clock/reset stable",
    "UART output visible",
    "Bare-metal program can run",
)


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


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
    if "Baseline board bring-up is not complete" not in text:
        errors.append(f"{path}: missing incomplete-until-board-evidence boundary")
    return errors


def check_board_doc(root: Path, board_doc: Path) -> list[str]:
    path = resolve(root, board_doc)
    if not path.exists():
        return [f"missing board doc: {path}"]
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    if "docs/03-platform-architecture/genesys2/baseline_pass_criteria.md" not in text:
        errors.append(f"{path}: missing baseline pass criteria link")
    rows = parse_table_rows(text)
    for name in FORBIDDEN_HARDWARE_PASS:
        for row in rows:
            if row and row[0] == name and len(row) > 1 and row[1] == "PASS":
                errors.append(f"{path}: hardware pass criterion {name} is PASS before evidence")
    return errors


def run_checks(root: Path, criteria: Path, board_doc: Path, bitstream: Path, evidence_root: Path | None) -> list[str]:
    errors = check_evidence_root(root, evidence_root)
    errors.extend(check_criteria_doc(root, criteria, bitstream, evidence_root))
    errors.extend(check_board_doc(root, board_doc))
    return errors


def write_fixture(root: Path) -> None:
    docs = root / "docs" / "board"
    docs.mkdir(parents=True)
    bitstream = root / DEFAULT_BITSTREAM
    bitstream.parent.mkdir(parents=True)
    bitstream.write_text("bitstream\n", encoding="utf-8")
    (docs / "baseline_pass_criteria.md").write_text(
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
                "Baseline board bring-up is not complete until the three `TODO (BOARD)` rows above have physical evidence.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (docs / "board_bringup.md").write_text(
        "See docs/03-platform-architecture/genesys2/baseline_pass_criteria.md\n\n| Gate | Status | Evidence |\n| --- | --- | --- |\n| Clock/reset sanity | TODO (BOARD) | notes |\n",
        encoding="utf-8",
    )


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
