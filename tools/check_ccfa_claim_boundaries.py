from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path


DEFAULT_MATRIX = Path("docs/07-evaluation-evidence/reports/ccfa_readiness_matrix.md")
DEFAULT_REPORTS = [
    DEFAULT_MATRIX,
    Path("docs/07-evaluation-evidence/reports/genesys2_cva6_evidence_chain_20260610.md"),
    Path("docs/07-evaluation-evidence/reports/genesys2_cva6_evidence_chain_20260611.md"),
    Path("docs/07-evaluation-evidence/reports/ccfa_remaining_blockers_20260611.md"),
]

REQUIRED_GATES = [
    "simulation claim",
    "Genesys2 board trace claim",
    "Linux workload claim",
    "marker-scoped runtime attribution claim",
    "safe surrogate behavior audit claim",
    "real malware claim",
]

REQUIRED_REPORT_FIELDS = [
    "allowed claims",
    "non-claims",
    "artifact root",
    "run id",
    "board / CPU / bitstream hash",
    "command transcript",
    "checker command",
]

SAFE_NEGATORS = (
    "not ",
    "no ",
    "non-claim",
    "non-claims",
    "false",
    "forbidden",
    "deferred",
    "blocked",
    "outside",
    "not claimed",
    "not demonstrated",
    "must not",
    "do not",
)

OVERCLAIM_RULES = [
    (
        "safe surrogate written as real malware",
        ("safe surrogate", "real malware"),
        SAFE_NEGATORS,
    ),
    (
        "synthetic malware-like sample written as real malware",
        ("malware-like", "real malware"),
        SAFE_NEGATORS,
    ),
    (
        "ILA/debug capture written as final production sink",
        ("ila", "production sink"),
        SAFE_NEGATORS + ("debug capture path",),
    ),
    (
        "multi-window capture written as continuous execution trace",
        ("multi-window", "continuous execution trace"),
        SAFE_NEGATORS + ("not a", "not yet"),
    ),
    (
        "missing process attribution written as proven",
        ("process attribution missing", "proven"),
        SAFE_NEGATORS,
    ),
    (
        "simulation evidence written as physical board evidence",
        ("simulation evidence", "physical board evidence"),
        SAFE_NEGATORS,
    ),
]


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def display(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def normalized_lines(text: str) -> list[str]:
    return [" ".join(line.strip().split()).lower() for line in text.splitlines() if line.strip()]


def contains_all(line: str, tokens: tuple[str, ...]) -> bool:
    return all(token.lower() in line for token in tokens)


def has_negator(line: str, negators: tuple[str, ...]) -> bool:
    return any(token.lower() in line for token in negators)


def check_matrix(root: Path, matrix_arg: Path) -> list[str]:
    path = resolve(root, matrix_arg)
    if not path.is_file():
        return [f"missing readiness matrix: {display(path, root)}"]
    text = path.read_text(encoding="utf-8", errors="replace")
    lowered = text.lower()
    errors: list[str] = []
    for gate in REQUIRED_GATES:
        if gate.lower() not in lowered:
            errors.append(f"{display(path, root)}: missing claim gate {gate!r}")
    for field in REQUIRED_REPORT_FIELDS:
        if field.lower() not in lowered:
            errors.append(f"{display(path, root)}: missing required report field {field!r}")
    required_commands = [
        "uv run python tools/run_check_suite.py --suite genesys2-current",
        "uv run python tools/run_check_suite.py --suite genesys2-artifacts",
        "uv run python tools/check_ccfa_claim_boundaries.py --root .",
    ]
    for command in required_commands:
        if command.lower() not in lowered:
            errors.append(f"{display(path, root)}: missing validation command {command!r}")
    if "overall status: not ccf-a ready" not in lowered:
        errors.append(f"{display(path, root)}: must explicitly state current status is not CCF-A ready")
    return errors


def check_overclaim_text(root: Path, report_args: list[Path]) -> list[str]:
    errors: list[str] = []
    for report_arg in report_args:
        path = resolve(root, report_arg)
        if not path.is_file():
            errors.append(f"missing report: {display(path, root)}")
            continue
        for line_no, line in enumerate(normalized_lines(path.read_text(encoding="utf-8", errors="replace")), start=1):
            for label, tokens, negators in OVERCLAIM_RULES:
                if contains_all(line, tokens) and not has_negator(line, negators):
                    errors.append(f"{display(path, root)}:{line_no}: overclaim rejected: {label}")
    return errors


def run_checks(root: Path, matrix: Path, reports: list[Path]) -> list[str]:
    errors = check_matrix(root, matrix)
    errors.extend(check_overclaim_text(root, reports))
    return errors


def write_good_fixture(root: Path) -> list[Path]:
    report = root / "ccfa_readiness_matrix.md"
    report.write_text(
        "\n".join(
            [
                "# CCF-A Readiness Matrix",
                "Overall status: NOT CCF-A READY.",
                "simulation claim | allowed claims | non-claims | artifact root | run id | board / CPU / bitstream hash | command transcript | checker command",
                "Genesys2 board trace claim",
                "Linux workload claim",
                "marker-scoped runtime attribution claim",
                "safe surrogate behavior audit claim",
                "real malware claim",
                "Simulation evidence is not physical board evidence.",
                "Safe surrogate evidence is not real malware validation.",
                "ILA/debug capture is not a final production sink.",
                "Multi-window capture is not continuous execution trace.",
                "Process attribution missing must not be written as proven.",
                "uv run python tools/run_check_suite.py --suite genesys2-current",
                "uv run python tools/run_check_suite.py --suite genesys2-artifacts",
                "uv run python tools/check_ccfa_claim_boundaries.py --root .",
            ]
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return [report]


def self_test() -> int:
    bad_lines = [
        "The safe surrogate run is real malware validation.",
        "The malware-like synthetic suite is real malware detection evidence.",
        "The ILA debug capture is the final production sink.",
        "The multi-window capture is a continuous execution trace.",
        "Process attribution missing is proven by this run.",
        "Simulation evidence is physical board evidence.",
    ]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        reports = write_good_fixture(root)
        errors = run_checks(root, reports[0], reports)
        if errors:
            print("[FAIL] good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
    for index, bad_line in enumerate(bad_lines):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = write_good_fixture(root)
            (root / f"bad_{index}.md").write_text(bad_line + "\n", encoding="utf-8", newline="\n")
            errors = run_checks(root, reports[0], reports + [root / f"bad_{index}.md"])
            if not any("overclaim rejected" in error for error in errors):
                print(f"[FAIL] bad fixture was not rejected: {bad_line}", file=sys.stderr)
                return 1
    print("[PASS] CCF-A claim-boundary checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check CCF-A claim boundaries and reject overclaims.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--report", type=Path, action="append", help="Report to scan. May be repeated.")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    reports = args.report if args.report else DEFAULT_REPORTS
    errors = run_checks(root, args.matrix, reports)
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] CCF-A claim boundaries are explicit and overclaims are rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
