from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path


DEFAULT_RUNBOOK = Path("docs/03-platform-architecture/genesys2/baseline_bringup_runbook.md")
DEFAULT_BOARD_DOC = Path("docs/03-platform-architecture/genesys2/board_bringup.md")

STEPS = (
    (1, "01_led_clock_reset", "LED Blink / Clock Reset Sanity", "TODO (BOARD)"),
    (2, "02_uart_hello", "UART Hello", "TODO (BOARD)"),
    (3, "03_minimal_core_boot", "Minimal RISC-V Core Boot", "TODO (BOARD)"),
    (4, "04_cva6_baremetal_boot", "CVA6 Bare-metal Boot", "TODO (BOARD)"),
    (5, "05_linux_boot_optional", "CVA6 Simple Linux Boot (Optional)", "TODO (OPTIONAL)"),
)
FORBIDDEN_SUCCESS_CLAIMS = (
    "physical board success: PASS",
    "board clock/reset stable | PASS",
    "UART output visible | PASS",
    "bare-metal program can run | PASS",
)
BASELINE_BOARD_GATES = {
    "Clock/reset sanity": "TODO (BOARD)",
    "UART hello": "TODO (BOARD)",
    "Bare-metal program runs": "TODO (BOARD)",
}
RUNBOOK_HEADINGS = (
    "Preconditions",
    "Evidence Layout",
    "1. LED Blink / Clock Reset Sanity",
    "2. UART Hello",
    "3. Minimal RISC-V Core Boot",
    "4. CVA6 Bare-metal Boot",
    "5. CVA6 Simple Linux Boot (Optional)",
)


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def heading_line(text: str, number: int, title: str) -> int | None:
    pattern = re.compile(rf"^##\s+{number}\.\s+{re.escape(title)}\s*$", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        return None
    return text[: match.start()].count("\n") + 1


def step_heading_matches(text: str) -> list[tuple[int, str]]:
    matches: list[tuple[int, str]] = []
    for match in re.finditer(r"^##\s+(\d+)\.\s+(.+?)\s*$", text, re.MULTILINE):
        matches.append((int(match.group(1)), match.group(2)))
    return matches


def h2_headings(text: str) -> list[str]:
    return [match.group(1).strip() for match in re.finditer(r"^##\s+(.+?)\s*$", text, re.MULTILINE)]


def section_text(text: str, heading: str) -> str | None:
    pattern = re.compile(rf"^##\s+{re.escape(heading)}\s*$", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        return None
    next_match = re.search(r"^##\s+", text[match.end() :], re.MULTILINE)
    end = match.end() + next_match.start() if next_match else len(text)
    return text[match.start() : end]


def section_count(text: str, heading: str) -> int:
    pattern = re.compile(rf"^##\s+{re.escape(heading)}\s*$", re.MULTILINE)
    return len(pattern.findall(text))


def parse_table_rows(text: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip("|").split("|")]
        if cells and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            continue
        if cells and cells[0] in {"Gate", "Order", "Step"}:
            continue
        rows.append(cells)
    return rows


def check_runbook(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    if "This runbook is a procedure, not a board-success record." not in text:
        errors.append(f"{path}: missing no-success-claim boundary statement")
    if "results/board/genesys2_baseline/<run-id>/" not in text:
        errors.append(f"{path}: missing baseline evidence root")

    actual_h2 = h2_headings(text)
    if actual_h2 != list(RUNBOOK_HEADINGS):
        errors.append(f"{path}: H2 headings differ from expected runbook headings: {actual_h2}")

    previous_line = 0
    expected_headings = [(number, title) for number, _, title, _ in STEPS]
    actual_headings = step_heading_matches(text)
    if actual_headings != expected_headings:
        errors.append(f"{path}: ordered step headings differ from expected 1..5 sequence: {actual_headings}")
    for number, step_id, title, _ in STEPS:
        line = heading_line(text, number, title)
        if line is None:
            errors.append(f"{path}: missing ordered step heading: {number}. {title}")
            continue
        if line <= previous_line:
            errors.append(f"{path}: step out of order: {title}")
        previous_line = line
        if f"results/board/genesys2_baseline/<run-id>/{step_id}/" not in text:
            errors.append(f"{path}: missing evidence directory for {step_id}")

    return errors


def check_board_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    if "docs/03-platform-architecture/genesys2/baseline_bringup_runbook.md" not in text:
        errors.append(f"{path}: missing runbook link")
    lowered = text.lower()
    for phrase in FORBIDDEN_SUCCESS_CLAIMS:
        if phrase.lower() in lowered:
            errors.append(f"{path}: forbidden physical-board success claim before evidence: {phrase}")
    all_rows = parse_table_rows(text)
    for gate, expected_status in BASELINE_BOARD_GATES.items():
        matching_rows = [row for row in all_rows if row and row[0] == gate]
        if not matching_rows:
            errors.append(f"{path}: missing baseline board gate row: {gate}")
            continue
        if len(matching_rows) != 1:
            errors.append(f"{path}: duplicate baseline board gate rows for {gate}: {matching_rows}")
            continue
        if len(matching_rows[0]) < 3:
            errors.append(f"{path}: malformed baseline board gate row for {gate}: {matching_rows[0]}")
            continue
        status = matching_rows[0][1]
        if status != expected_status:
            errors.append(f"{path}: wrong baseline board gate status for {gate}: {status}, expected {expected_status}")
    if section_count(text, "Baseline Bring-up Sequence") != 1:
        errors.append(f"{path}: Baseline Bring-up Sequence section must appear exactly once")
    sequence = section_text(text, "Baseline Bring-up Sequence")
    if sequence is None:
        errors.append(f"{path}: missing Baseline Bring-up Sequence section")
        return errors
    rows = parse_table_rows(sequence)
    expected_rows = [
        [str(number), title, expected_status, f"{step_id}/"]
        for number, step_id, title, expected_status in STEPS
    ]
    actual_rows = [row for row in rows if len(row) >= 4 and row[0].isdigit()]
    extra_rows = [row for row in rows if len(row) >= 4 and not row[0].isdigit()]
    if extra_rows:
        errors.append(f"{path}: unexpected non-step rows in Baseline Bring-up Sequence table: {extra_rows}")
    if len(actual_rows) != len(rows):
        short_rows = [row for row in rows if len(row) < 4]
        if short_rows:
            errors.append(f"{path}: malformed rows in Baseline Bring-up Sequence table: {short_rows}")
    if actual_rows != expected_rows:
        errors.append(f"{path}: Baseline Bring-up Sequence table differs from expected rows: {actual_rows}")
    previous_order = 0
    for number, step_id, title, expected_status in STEPS:
        expected_dir = f"{step_id}/"
        matching_rows = [row for row in rows if len(row) >= 4 and row[1] == title]
        if not matching_rows:
            errors.append(f"{path}: missing bring-up sequence row: {title}")
            continue
        row = matching_rows[0]
        try:
            order = int(row[0])
        except ValueError:
            errors.append(f"{path}: non-numeric order for {title}: {row[0]}")
            continue
        if order != number:
            errors.append(f"{path}: wrong order for {title}: {order}, expected {number}")
        if order <= previous_order:
            errors.append(f"{path}: bring-up sequence row out of order: {title}")
        previous_order = order
        if row[2] != expected_status:
            errors.append(f"{path}: wrong status for {title}: {row[2]}, expected {expected_status}")
        if row[3] != expected_dir:
            errors.append(f"{path}: wrong evidence directory for {title}: {row[3]}, expected {expected_dir}")
    return errors


def run_checks(root: Path, runbook: Path, board_doc: Path) -> list[str]:
    runbook_path = resolve(root, runbook)
    board_doc_path = resolve(root, board_doc)
    errors: list[str] = []
    if not runbook_path.exists():
        errors.append(f"missing runbook: {runbook_path}")
    else:
        errors.extend(check_runbook(runbook_path))
    if not board_doc_path.exists():
        errors.append(f"missing board bring-up doc: {board_doc_path}")
    else:
        errors.extend(check_board_doc(board_doc_path))
    return errors


def write_good_fixture(root: Path) -> None:
    docs = root / "docs" / "board"
    docs.mkdir(parents=True)
    runbook_lines = [
        "# Baseline Bring-up Runbook",
        "",
        "This runbook is a procedure, not a board-success record.",
        "",
        "## Preconditions",
        "",
        "Run the preflight checks.",
        "",
        "## Evidence Layout",
        "",
        "results/board/genesys2_baseline/<run-id>/",
        "",
    ]
    board_lines = [
        "# Genesys 2 Board Bring-up",
        "",
        "Runbook: docs/03-platform-architecture/genesys2/baseline_bringup_runbook.md",
        "",
        "| Gate | Status | Evidence |",
        "| --- | --- | --- |",
        "| Clock/reset sanity | TODO (BOARD) | Requires board observation notes |",
        "| UART hello | TODO (BOARD) | Requires UART log |",
        "| Bare-metal program runs | TODO (BOARD) | Requires UART/tohost log |",
        "",
        "## Baseline Bring-up Sequence",
        "",
        "| Order | Step | Status | Evidence directory |",
        "| ---: | --- | --- | --- |",
    ]
    for number, step_id, title, status in STEPS:
        runbook_lines.extend(
            [
                f"## {number}. {title}",
                "",
                f"results/board/genesys2_baseline/<run-id>/{step_id}/",
                "",
            ]
        )
        board_lines.append(f"| {number} | {title} | {status} | {step_id}/ |")
    (docs / "baseline_bringup_runbook.md").write_text("\n".join(runbook_lines), encoding="utf-8")
    (docs / "board_bringup.md").write_text("\n".join(board_lines), encoding="utf-8")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        runbook = root / DEFAULT_RUNBOOK
        runbook.write_text(runbook.read_text(encoding="utf-8").replace("## 2. UART Hello", "## 2. UART"), encoding="utf-8")
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("UART Hello" in error for error in errors):
            print("[FAIL] self-test missed missing UART step", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        runbook = root / DEFAULT_RUNBOOK
        runbook.write_text(
            runbook.read_text(encoding="utf-8").replace("## 3. Minimal RISC-V Core Boot", "## 99. Minimal RISC-V Core Boot"),
            encoding="utf-8",
        )
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("3. Minimal RISC-V Core Boot" in error for error in errors):
            print("[FAIL] self-test missed renumbered minimal boot step", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        runbook = root / DEFAULT_RUNBOOK
        runbook.write_text(runbook.read_text(encoding="utf-8") + "\n## 6. Physical Board Success\n", encoding="utf-8")
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("ordered step headings differ" in error for error in errors):
            print("[FAIL] self-test missed extra numbered heading", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        runbook = root / DEFAULT_RUNBOOK
        runbook.write_text(runbook.read_text(encoding="utf-8") + "\n## Physical Board Success\n", encoding="utf-8")
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("H2 headings differ" in error for error in errors):
            print("[FAIL] self-test missed extra unnumbered runbook heading", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        runbook = root / DEFAULT_RUNBOOK
        runbook.write_text(runbook.read_text(encoding="utf-8").replace("## Evidence Layout", "## Evidence Layout\n\n## Evidence Layout", 1), encoding="utf-8")
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("H2 headings differ" in error for error in errors):
            print("[FAIL] self-test missed duplicate unnumbered runbook heading", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        runbook = root / DEFAULT_RUNBOOK
        runbook.write_text(
            runbook.read_text(encoding="utf-8").replace("## 2. UART Hello", "## 2. UART Hello\n\n## 2. UART Hello", 1),
            encoding="utf-8",
        )
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("ordered step headings differ" in error for error in errors):
            print("[FAIL] self-test missed duplicate numbered heading", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        board_doc = root / DEFAULT_BOARD_DOC
        board_doc.write_text(board_doc.read_text(encoding="utf-8").replace("docs/03-platform-architecture/genesys2/baseline_bringup_runbook.md", ""), encoding="utf-8")
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("runbook link" in error for error in errors):
            print("[FAIL] self-test missed missing runbook link", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        board_doc = root / DEFAULT_BOARD_DOC
        board_doc.write_text(board_doc.read_text(encoding="utf-8").replace("03_minimal_core_boot/", "03_wrong_minimal_core_boot/"), encoding="utf-8")
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("wrong evidence directory" in error and "Minimal RISC-V Core Boot" in error for error in errors):
            print("[FAIL] self-test missed board evidence directory drift", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        board_doc = root / DEFAULT_BOARD_DOC
        board_doc.write_text(
            board_doc.read_text(encoding="utf-8").replace(
                "| 3 | Minimal RISC-V Core Boot | TODO (BOARD) | 03_minimal_core_boot/ |",
                "| 3 | Minimal RISC-V Core Boot | PASS | 03_minimal_core_boot/ |",
            ),
            encoding="utf-8",
        )
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("wrong status" in error and "Minimal RISC-V Core Boot" in error for error in errors):
            print("[FAIL] self-test missed board status drift", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        board_doc = root / DEFAULT_BOARD_DOC
        text = board_doc.read_text(encoding="utf-8")
        text = text.replace(
            "| 2 | UART Hello | TODO (BOARD) | 02_uart_hello/ |\n| 3 | Minimal RISC-V Core Boot | TODO (BOARD) | 03_minimal_core_boot/ |",
            "| 3 | Minimal RISC-V Core Boot | TODO (BOARD) | 03_minimal_core_boot/ |\n| 2 | UART Hello | TODO (BOARD) | 02_uart_hello/ |",
        )
        board_doc.write_text(text, encoding="utf-8")
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("Sequence table differs" in error for error in errors):
            print("[FAIL] self-test missed visually reordered board table rows", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        board_doc = root / DEFAULT_BOARD_DOC
        board_doc.write_text(board_doc.read_text(encoding="utf-8") + "\nPhysical board success: PASS.\n", encoding="utf-8")
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("forbidden physical-board success claim" in error for error in errors):
            print("[FAIL] self-test missed physical board success overclaim", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        board_doc = root / DEFAULT_BOARD_DOC
        text = board_doc.read_text(encoding="utf-8")
        text = text.replace("| Clock/reset sanity | TODO (BOARD) |", "| Clock/reset sanity | PASS |")
        text = text.replace("| UART hello | TODO (BOARD) |", "| UART hello | PASS |")
        text = text.replace("| Bare-metal program runs | TODO (BOARD) |", "| Bare-metal program runs | PASS |")
        board_doc.write_text(text, encoding="utf-8")
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("wrong baseline board gate status" in error for error in errors):
            print("[FAIL] self-test missed baseline board gate PASS overclaim", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        board_doc = root / DEFAULT_BOARD_DOC
        text = board_doc.read_text(encoding="utf-8").replace(
            "| Clock/reset sanity | TODO (BOARD) | Requires board observation notes |",
            "| Clock/reset sanity | TODO (BOARD) | Requires board observation notes |\n| Clock/reset sanity | PASS | Overclaim |",
        )
        board_doc.write_text(text, encoding="utf-8")
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("duplicate baseline board gate rows" in error for error in errors):
            print("[FAIL] self-test missed duplicate baseline board gate overclaim", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        board_doc = root / DEFAULT_BOARD_DOC
        text = board_doc.read_text(encoding="utf-8").replace(
            "| Clock/reset sanity | TODO (BOARD) | Requires board observation notes |",
            "| Clock/reset sanity | TODO (BOARD) | Requires board observation notes |\n| Clock/reset sanity | PASS |",
        )
        board_doc.write_text(text, encoding="utf-8")
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("duplicate baseline board gate rows" in error for error in errors):
            print("[FAIL] self-test missed short duplicate baseline board gate overclaim", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        board_doc = root / DEFAULT_BOARD_DOC
        text = board_doc.read_text(encoding="utf-8").replace(
            "| Clock/reset sanity | TODO (BOARD) | Requires board observation notes |",
            "| Clock/reset sanity | TODO (BOARD) | Requires board observation notes |\n| Clock/reset sanity | PASS | --- |",
        )
        board_doc.write_text(text, encoding="utf-8")
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("duplicate baseline board gate rows" in error for error in errors):
            print("[FAIL] self-test missed dashed duplicate baseline board gate overclaim", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        board_doc = root / DEFAULT_BOARD_DOC
        board_doc.write_text(board_doc.read_text(encoding="utf-8") + "\n## Baseline Bring-up Sequence\n\n| PASS | Physical board success | PASS | bogus/ |\n", encoding="utf-8")
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("must appear exactly once" in error for error in errors):
            print("[FAIL] self-test missed duplicate Baseline Bring-up Sequence section", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        board_doc = root / DEFAULT_BOARD_DOC
        text = board_doc.read_text(encoding="utf-8").replace(
            "| 3 | Minimal RISC-V Core Boot | TODO (BOARD) | 03_minimal_core_boot/ |",
            "| PASS | Physical board success | PASS | bogus/ |\n| 3 | Minimal RISC-V Core Boot | TODO (BOARD) | 03_minimal_core_boot/ |",
        )
        board_doc.write_text(text, encoding="utf-8")
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("unexpected non-step rows" in error for error in errors):
            print("[FAIL] self-test missed non-step board sequence row", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_good_fixture(root)
        board_doc = root / DEFAULT_BOARD_DOC
        text = board_doc.read_text(encoding="utf-8").replace(
            "| 5 | CVA6 Simple Linux Boot (Optional) | TODO (OPTIONAL) | 05_linux_boot_optional/ |",
            "| 5 | CVA6 Simple Linux Boot (Optional) | TODO (OPTIONAL) | 05_linux_boot_optional/ |\n| 6 | Physical Board Success | PASS | --- |",
        )
        board_doc.write_text(text, encoding="utf-8")
        errors = run_checks(root, DEFAULT_RUNBOOK, DEFAULT_BOARD_DOC)
        if not any("Sequence table differs" in error for error in errors):
            print("[FAIL] self-test missed dashed extra board sequence row", file=sys.stderr)
            return 1

    print("[PASS] bring-up runbook self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Phase 4.3 Genesys 2 baseline bring-up runbook consistency.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root. Defaults to the current directory.")
    parser.add_argument("--runbook", type=Path, default=DEFAULT_RUNBOOK)
    parser.add_argument("--board-doc", type=Path, default=DEFAULT_BOARD_DOC)
    parser.add_argument("--self-test", action="store_true", help="Run positive and negative coverage checks.")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    errors = run_checks(args.root.resolve(), args.runbook, args.board_doc)
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] baseline bring-up runbook is ordered and evidence-scoped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
