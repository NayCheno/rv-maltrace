from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path


DEFAULT_DECISION = Path("docs/02-trace-architecture/trace_export_decision.md")
DEFAULT_BOARD_DOC = Path("docs/03-platform-architecture/genesys2/board_bringup.md")
SELECTED = "BRAM ring buffer + ILA/JTAG dump"
DEFERRED = {
    "UART streaming",
    "AXI DMA / Ethernet streaming",
}
REQUIRED_REQUIREMENTS = (
    "bounded BRAM ring",
    "Vivado ILA/JTAG",
    "Full retire remains disabled",
    "Drop mode stays allowed",
    "must not add ready/stall/backpressure",
)
EVENT_POLICY_RE = re.compile(
    r"Phase 5\.2 event selection applies before queueing:\s+syscall,\s+trap,\s+context,\s+and branch first\.",
    re.MULTILINE,
)
TRANSPORTS_RE = (
    r"(?:UART(?:\s+streaming)?|"
    r"AXI\s+DMA\s*/\s*Ethernet(?:\s+streaming)?|"
    r"AXI/Ethernet(?:\s+streaming)?|"
    r"AXI\s+DMA(?:\s+streaming)?|"
    r"Ethernet(?:\s+streaming)?)"
)
FIRST_EXPORT_RE = (
    r"\b(?:actual\s+)?first(?:\s+board|\s+hardware|\s+trace-enabled)?\s+"
    r"(?:export|implementation|run|path|export\s+path|implementation\s+path)"
)
FORBIDDEN_DECISION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            rf"{FIRST_EXPORT_RE}\s+(?:may|can|will|should|must)\s+use\s+{TRANSPORTS_RE}\b",
            re.IGNORECASE,
        ),
        "first export must not select UART, AXI DMA, or Ethernet",
    ),
    (
        re.compile(
            rf"{FIRST_EXPORT_RE}\s+(?:is|=|selects?|chooses?)\s+{TRANSPORTS_RE}\b",
            re.IGNORECASE,
        ),
        "first export must not select UART, AXI DMA, or Ethernet",
    ),
    (
        re.compile(r"\b(?:not|without)\s+branch\s+first\b", re.IGNORECASE),
        "branch-first event policy is negated",
    ),
    (
        re.compile(
            r"\bbranch(?:-first|\s+first)?\s+(?:is\s+)?"
            r"(?:not\s+(?:required|needed)|optional|disabled|omitted|excluded|deferred)\b",
            re.IGNORECASE,
        ),
        "branch-first event policy is negated",
    ),
    (
        re.compile(
            r"\b(?:omit(?:s|ted)?|exclude(?:s|d|ing)?|disable(?:s|d)?|defer(?:s|red|ring)?|without)\s+branch\b",
            re.IGNORECASE,
        ),
        "branch-first event policy is negated",
    ),
    (
        re.compile(
            r"\b(?:hardware\s+trace\s+export|first\s+hardware\s+trace|BRAM/JTAG\s+path)\s+"
            r"(?:is\s+)?(?:implemented|complete|validated|passing|PASS)\b",
            re.IGNORECASE,
        ),
        "decision doc must not claim hardware trace export is implemented",
    ),
    (
        re.compile(r"\bhardware\s+validation\s+(?:is\s+)?(?:complete|passing|PASS)\b", re.IGNORECASE),
        "decision doc must not claim hardware validation has passed",
    ),
    (
        re.compile(r"\bhardware\s+validation\s+passed\b", re.IGNORECASE),
        "decision doc must not claim hardware validation has passed",
    ),
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
        if cells and cells[0] == "Option":
            continue
        rows.append(cells)
    return rows


def section_text(text: str, heading: str) -> str | None:
    pattern = re.compile(rf"^##\s+{re.escape(heading)}\s*$", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        return None
    next_match = re.search(r"^##\s+", text[match.end() :], re.MULTILINE)
    end = match.end() + next_match.start() if next_match else len(text)
    return text[match.start() : end]


def check_decision_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    decision = section_text(text, "Decision")
    if decision is None:
        errors.append(f"{path}: missing Decision section")
    elif not re.search(rf"```text\s*{re.escape(SELECTED)}\s*```", decision, re.MULTILINE):
        errors.append(f"{path}: Decision section must select exactly {SELECTED}")
    if "This is a bring-up choice, not the final high-throughput transport." not in text:
        errors.append(f"{path}: missing bring-up-only boundary")

    rows = parse_table_rows(text)
    by_option = {row[0]: row for row in rows if row}
    expected = {SELECTED, *DEFERRED}
    if set(by_option) != expected:
        errors.append(f"{path}: option rows differ from expected set: {sorted(by_option)}")
    selected_row = by_option.get(SELECTED)
    if selected_row is None or len(selected_row) < 5 or selected_row[1] != "SELECTED":
        errors.append(f"{path}: selected BRAM/JTAG option must be status SELECTED")
    for option in sorted(DEFERRED):
        row = by_option.get(option)
        if row is None or len(row) < 5 or row[1] != "DEFERRED":
            errors.append(f"{path}: {option} must be status DEFERRED")

    for requirement in REQUIRED_REQUIREMENTS:
        if requirement not in text:
            errors.append(f"{path}: missing first-version requirement: {requirement}")
    if not EVENT_POLICY_RE.search(text):
        errors.append(f"{path}: missing exact syscall/trap/context/branch-first event policy")
    for pattern, message in FORBIDDEN_DECISION_PATTERNS:
        if pattern.search(text):
            errors.append(f"{path}: {message}")
    return errors


def check_board_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    if "docs/02-trace-architecture/trace_export_decision.md" not in text:
        errors.append(f"{path}: missing trace export decision link")
    if "BRAM ring buffer plus ILA/JTAG dump" not in text:
        errors.append(f"{path}: missing BRAM/JTAG trace-enabled bring-up step")
    if re.search(r"UART streaming\s*\|\s*SELECTED", text):
        errors.append(f"{path}: UART streaming must not be selected for first board export")
    return errors


def run_checks(root: Path, decision: Path, board_doc: Path) -> list[str]:
    decision_path = resolve(root, decision)
    board_doc_path = resolve(root, board_doc)
    errors: list[str] = []
    if not decision_path.exists():
        errors.append(f"missing trace export decision doc: {decision_path}")
    else:
        errors.extend(check_decision_doc(decision_path))
    if not board_doc_path.exists():
        errors.append(f"missing board bring-up doc: {board_doc_path}")
    else:
        errors.extend(check_board_doc(board_doc_path))
    return errors


def write_fixture(root: Path) -> None:
    decision = root / DEFAULT_DECISION
    board_doc = root / DEFAULT_BOARD_DOC
    decision.parent.mkdir(parents=True)
    board_doc.parent.mkdir(parents=True)
    decision.write_text(
        f"""# Trace Export Decision

## Decision

```text
{SELECTED}
```

This is a bring-up choice, not the final high-throughput transport.

| Option | Status | Advantages | Risks | First-version Decision |
| --- | --- | --- | --- | --- |
| {SELECTED} | SELECTED | Easiest board bring-up; no high-speed peripheral dependency; suitable for first hardware validation | Capacity is limited | Use first |
| UART streaming | DEFERRED | Simple | Low bandwidth | Later |
| AXI DMA / Ethernet streaming | DEFERRED | High bandwidth | Complex | Later |

- bounded BRAM ring
- Vivado ILA/JTAG
- Full retire remains disabled
- Phase 5.2 event selection applies before queueing: syscall, trap, context,
  and branch first.
- Drop mode stays allowed
- must not add ready/stall/backpressure
""",
        encoding="utf-8",
    )
    board_doc.write_text(
        "See docs/02-trace-architecture/trace_export_decision.md\nExport the first hardware trace through BRAM ring buffer plus ILA/JTAG dump.\n",
        encoding="utf-8",
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = run_checks(root, DEFAULT_DECISION, DEFAULT_BOARD_DOC)
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        decision = root / DEFAULT_DECISION
        decision.write_text(decision.read_text(encoding="utf-8").replace("| UART streaming | DEFERRED |", "| UART streaming | SELECTED |"), encoding="utf-8")
        errors = run_checks(root, DEFAULT_DECISION, DEFAULT_BOARD_DOC)
        if not any("UART streaming" in error for error in errors):
            print("[FAIL] self-test missed UART selected for first export", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        decision = root / DEFAULT_DECISION
        decision.write_text(decision.read_text(encoding="utf-8").replace(f"```text\n{SELECTED}\n```", "```text\nUART streaming\n```"), encoding="utf-8")
        errors = run_checks(root, DEFAULT_DECISION, DEFAULT_BOARD_DOC)
        if not any("Decision section" in error for error in errors):
            print("[FAIL] self-test missed wrong Decision block", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        decision = root / DEFAULT_DECISION
        decision.write_text(decision.read_text(encoding="utf-8").replace("  and branch first.\n", ""), encoding="utf-8")
        errors = run_checks(root, DEFAULT_DECISION, DEFAULT_BOARD_DOC)
        if not any("branch-first event policy" in error for error in errors):
            print("[FAIL] self-test missed missing branch requirement", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        decision = root / DEFAULT_DECISION
        decision.write_text(decision.read_text(encoding="utf-8").replace("and branch first.", "and not branch first."), encoding="utf-8")
        errors = run_checks(root, DEFAULT_DECISION, DEFAULT_BOARD_DOC)
        if not any("negated" in error for error in errors):
            print("[FAIL] self-test missed negated branch requirement", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        decision = root / DEFAULT_DECISION
        decision.write_text(decision.read_text(encoding="utf-8").replace("bounded BRAM ring", "unbounded FIFO"), encoding="utf-8")
        errors = run_checks(root, DEFAULT_DECISION, DEFAULT_BOARD_DOC)
        if not any("bounded BRAM ring" in error for error in errors):
            print("[FAIL] self-test missed missing BRAM ring requirement", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        board_doc = root / DEFAULT_BOARD_DOC
        board_doc.write_text("Export through UART streaming.\n", encoding="utf-8")
        errors = run_checks(root, DEFAULT_DECISION, DEFAULT_BOARD_DOC)
        if not any("trace export decision link" in error for error in errors):
            print("[FAIL] self-test missed missing board-doc decision link", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        decision = root / DEFAULT_DECISION
        decision.write_text(
            decision.read_text(encoding="utf-8") + "\nActual first export may use UART streaming.\n",
            encoding="utf-8",
        )
        errors = run_checks(root, DEFAULT_DECISION, DEFAULT_BOARD_DOC)
        if not any("first export must not select" in error for error in errors):
            print("[FAIL] self-test missed contradictory UART first-export text", file=sys.stderr)
            return 1

    for bad_text in (
        "The first export path is UART streaming.",
        "The first hardware export will use AXI DMA streaming.",
        "The first board export will use Ethernet streaming.",
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            decision = root / DEFAULT_DECISION
            decision.write_text(
                decision.read_text(encoding="utf-8") + f"\n{bad_text}\n",
                encoding="utf-8",
            )
            errors = run_checks(root, DEFAULT_DECISION, DEFAULT_BOARD_DOC)
            if not any("first export must not select" in error for error in errors):
                print(f"[FAIL] self-test missed contradictory transport text: {bad_text}", file=sys.stderr)
                return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        decision = root / DEFAULT_DECISION
        decision.write_text(
            decision.read_text(encoding="utf-8") + "\nBranch first is not required for Phase 5.2.\n",
            encoding="utf-8",
        )
        errors = run_checks(root, DEFAULT_DECISION, DEFAULT_BOARD_DOC)
        if not any("branch-first event policy is negated" in error for error in errors):
            print("[FAIL] self-test missed appended branch-policy negation", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        decision = root / DEFAULT_DECISION
        decision.write_text(
            decision.read_text(encoding="utf-8") + "\nBranch first is not needed for Phase 5.2.\n",
            encoding="utf-8",
        )
        errors = run_checks(root, DEFAULT_DECISION, DEFAULT_BOARD_DOC)
        if not any("branch-first event policy is negated" in error for error in errors):
            print("[FAIL] self-test missed not-needed branch-policy negation", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        decision = root / DEFAULT_DECISION
        decision.write_text(
            decision.read_text(encoding="utf-8") + "\nHardware trace export implemented: PASS.\n",
            encoding="utf-8",
        )
        errors = run_checks(root, DEFAULT_DECISION, DEFAULT_BOARD_DOC)
        if not any("must not claim hardware trace export is implemented" in error for error in errors):
            print("[FAIL] self-test missed hardware trace implementation overclaim", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        decision = root / DEFAULT_DECISION
        decision.write_text(
            decision.read_text(encoding="utf-8") + "\nHardware validation passed on Genesys 2.\n",
            encoding="utf-8",
        )
        errors = run_checks(root, DEFAULT_DECISION, DEFAULT_BOARD_DOC)
        if not any("must not claim hardware validation has passed" in error for error in errors):
            print("[FAIL] self-test missed hardware validation overclaim", file=sys.stderr)
            return 1

    print("[PASS] trace export decision self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Phase 5.1 trace export path decision.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root. Defaults to the current directory.")
    parser.add_argument("--decision", type=Path, default=DEFAULT_DECISION)
    parser.add_argument("--board-doc", type=Path, default=DEFAULT_BOARD_DOC)
    parser.add_argument("--self-test", action="store_true", help="Run positive and negative coverage checks.")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    errors = run_checks(args.root.resolve(), args.decision, args.board_doc)
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] trace export decision selects BRAM/JTAG for first board run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
