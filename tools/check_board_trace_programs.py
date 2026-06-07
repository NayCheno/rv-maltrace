from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_MANIFEST = Path("board/trace_validation/manifest.json")
DEFAULT_DOC = Path("docs/03-platform-architecture/genesys2/board_trace_validation.md")
DEFAULT_BOARD_DOC = Path("docs/03-platform-architecture/genesys2/board_bringup.md")

EXPECTED_PROGRAMS = {
    "hello_write": {
        "source": "board/trace_validation/programs/hello_write.c",
        "expected": "board/trace_validation/expected/hello_write.expected.json",
        "evidence_dir": "01_hello_write",
        "syscalls": [("write", 64)],
        "events": {"SYSCALL_ENTRY", "SYSCALL_RET"},
        "source_tokens": ("SYS_write",),
    },
    "file_open_read_write": {
        "source": "board/trace_validation/programs/file_open_read_write.c",
        "expected": "board/trace_validation/expected/file_open_read_write.expected.json",
        "evidence_dir": "02_file_open_read_write",
        "syscalls": [
            ("openat", 56),
            ("write", 64),
            ("close", 57),
            ("openat", 56),
            ("read", 63),
            ("write", 64),
            ("close", 57),
        ],
        "events": {"SYSCALL_ENTRY", "SYSCALL_RET"},
        "source_tokens": (
            "SYS_openat",
            "SYS_read",
            "SYS_write",
            "SYS_close",
            "/tmp/rvmt_trace_validation_input.txt",
            "O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC",
            "count <= 0",
        ),
    },
    "fork_exec": {
        "source": "board/trace_validation/programs/fork_exec.c",
        "expected": "board/trace_validation/expected/fork_exec.expected.json",
        "evidence_dir": "03_fork_exec",
        "syscalls": [("clone", 220), ("execve", 221), ("wait4", 260)],
        "events": {"SYSCALL_ENTRY", "SYSCALL_RET", "PRIV"},
        "source_tokens": ("SYS_clone", "SYS_execve", "SYS_wait4"),
    },
    "illegal_instruction": {
        "source": "board/trace_validation/programs/illegal_instruction.c",
        "expected": "board/trace_validation/expected/illegal_instruction.expected.json",
        "evidence_dir": "04_illegal_instruction",
        "syscalls": [("write", 64)],
        "events": {"TRAP"},
        "source_tokens": ("SYS_write", ".word 0xffffffff"),
    },
}
REQUIRED_DOC_TEXT = (
    "This document is a run plan and does not claim the programs have passed on hardware.",
    "results/board/genesys2_trace_validation/<run-id>/",
    "`program.log`",
    "`trace.jsonl`",
    "`compare.log`",
    "`observation.md`",
    "The first-board trace profile from Phase 5.2 remains active",
)
FORBIDDEN_DOC_PATTERNS = (
    re.compile(r"\bPASS\b", re.IGNORECASE),
    re.compile(r"\bhardware\s+(?:passed|validated|complete)\b", re.IGNORECASE),
    re.compile(r"\bboard\s+trace\s+(?:passed|validated|complete)\b", re.IGNORECASE),
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


def by_program(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    programs = manifest.get("programs")
    if not isinstance(programs, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for item in programs:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            result[item["id"]] = item
    return result


def syscall_pairs(expected_json: dict[str, Any]) -> list[tuple[str, int]]:
    syscalls = expected_json.get("required_syscalls", [])
    pairs: list[tuple[str, int]] = []
    if isinstance(syscalls, list):
        for item in syscalls:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                pairs.append((item["name"], item.get("number")))
    return pairs


def check_manifest(root: Path, path: Path) -> list[str]:
    manifest = load_json(path)
    errors: list[str] = []
    if manifest.get("phase") != "5.3":
        errors.append(f"{path}: phase must be 5.3")
    if manifest.get("status") != "TODO(BOARD)":
        errors.append(f"{path}: status must remain TODO(BOARD)")
    if manifest.get("evidence_root") != "results/board/genesys2_trace_validation/<run-id>":
        errors.append(f"{path}: evidence_root must use the trace validation run-id directory")

    programs = by_program(manifest)
    if set(programs) != set(EXPECTED_PROGRAMS):
        errors.append(f"{path}: program ids differ from expected set: {sorted(programs)}")
    for program_id, spec in EXPECTED_PROGRAMS.items():
        item = programs.get(program_id, {})
        for field in ("source", "expected", "evidence_dir"):
            if item.get(field) != spec[field]:
                errors.append(f"{path}: {program_id}.{field} must be {spec[field]}")
        source_path = resolve(root, Path(spec["source"]))
        expected_path = resolve(root, Path(spec["expected"]))
        if not source_path.exists():
            errors.append(f"{path}: missing source for {program_id}: {source_path}")
        if not expected_path.exists():
            errors.append(f"{path}: missing expected file for {program_id}: {expected_path}")
        if source_path.exists():
            source_text = source_path.read_text(encoding="utf-8")
            for token in spec["source_tokens"]:
                if token not in source_text:
                    errors.append(f"{source_path}: missing source token {token}")
        if expected_path.exists():
            expected_json = load_json(expected_path)
            errors.extend(check_expected_file(expected_path, program_id, spec, expected_json))
    return errors


def check_expected_file(path: Path, program_id: str, spec: dict[str, Any], expected_json: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if expected_json.get("program") != program_id:
        errors.append(f"{path}: program must be {program_id}")
    if expected_json.get("mode") != "linux_user":
        errors.append(f"{path}: mode must be linux_user")
    if expected_json.get("status") != "TODO(BOARD)":
        errors.append(f"{path}: status must remain TODO(BOARD)")
    if expected_json.get("evidence_dir") != spec["evidence_dir"]:
        errors.append(f"{path}: evidence_dir must be {spec['evidence_dir']}")
    if syscall_pairs(expected_json) != spec["syscalls"]:
        errors.append(f"{path}: required_syscalls must be {spec['syscalls']}")
    events = expected_json.get("required_events")
    if set(events or []) != spec["events"]:
        errors.append(f"{path}: required_events must be {sorted(spec['events'])}")
    forbidden = set(expected_json.get("forbidden_events", []))
    if "RETIRE" not in forbidden:
        errors.append(f"{path}: RETIRE must remain forbidden for first-board validation")
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


def check_doc(path: Path, board_doc: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    normalized = normalized_text(text)
    errors: list[str] = []
    for required in REQUIRED_DOC_TEXT:
        if normalized_text(required) not in normalized:
            errors.append(f"{path}: missing required text: {required}")
    for pattern in FORBIDDEN_DOC_PATTERNS:
        if pattern.search(text):
            errors.append(f"{path}: must not claim Phase 5.3 board PASS/validation")

    rows = parse_table_rows(text)
    by_program = {row[1]: row for row in rows if len(row) >= 6}
    for index, (program_id, spec) in enumerate(EXPECTED_PROGRAMS.items(), start=1):
        row = by_program.get(program_id)
        if row is None:
            errors.append(f"{path}: missing table row for {program_id}")
            continue
        if row[0] != str(index):
            errors.append(f"{path}: {program_id} order must be {index}")
        if spec["source"] not in row[2]:
            errors.append(f"{path}: {program_id} source path mismatch")
        if row[4] != "TODO(BOARD)":
            errors.append(f"{path}: {program_id} status must remain TODO(BOARD)")
        if row[5] != f"{spec['evidence_dir']}/":
            errors.append(f"{path}: {program_id} evidence directory mismatch")

    board_text = board_doc.read_text(encoding="utf-8")
    if "docs/03-platform-architecture/genesys2/board_trace_validation.md" not in board_text:
        errors.append(f"{board_doc}: missing Phase 5.3 validation program link")
    if "board/trace_validation/manifest.json" not in board_text:
        errors.append(f"{board_doc}: missing trace validation manifest reference")
    return errors


def run_checks(root: Path, manifest: Path, doc: Path, board_doc: Path) -> list[str]:
    manifest_path = resolve(root, manifest)
    doc_path = resolve(root, doc)
    board_doc_path = resolve(root, board_doc)
    errors: list[str] = []
    for path, label in ((manifest_path, "manifest"), (doc_path, "doc"), (board_doc_path, "board doc")):
        if not path.exists():
            errors.append(f"missing {label}: {path}")
    if errors:
        return errors
    errors.extend(check_manifest(root, manifest_path))
    errors.extend(check_doc(doc_path, board_doc_path))
    return errors


def write_fixture(root: Path) -> None:
    for path in (
        "board/trace_validation/programs",
        "board/trace_validation/expected",
        "docs",
    ):
        (root / path).mkdir(parents=True)
    programs = []
    for program_id, spec in EXPECTED_PROGRAMS.items():
        source = root / spec["source"]
        source.write_text("\n".join(spec["source_tokens"]) + "\n", encoding="utf-8")
        expected = root / spec["expected"]
        expected.write_text(
            json.dumps(
                {
                    "program": program_id,
                    "mode": "linux_user",
                    "status": "TODO(BOARD)",
                    "required_syscalls": [
                        {"name": name, "number": number} for name, number in spec["syscalls"]
                    ],
                    "required_events": sorted(spec["events"]),
                    "forbidden_events": ["RETIRE"],
                    "evidence_dir": spec["evidence_dir"],
                }
            ),
            encoding="utf-8",
        )
        programs.append(
            {
                "id": program_id,
                "source": spec["source"],
                "expected": spec["expected"],
                "evidence_dir": spec["evidence_dir"],
                "expected_summary": "fixture",
            }
        )
    (root / DEFAULT_MANIFEST).write_text(
        json.dumps(
            {
                "phase": "5.3",
                "status": "TODO(BOARD)",
                "evidence_root": "results/board/genesys2_trace_validation/<run-id>",
                "programs": programs,
            }
        ),
        encoding="utf-8",
    )
    (root / DEFAULT_DOC).write_text(
        """# Board Trace Validation Programs

This document is a run plan and does not claim the programs have passed on hardware.
results/board/genesys2_trace_validation/<run-id>/

| Order | Program | Source | Expected trace evidence | Status | Evidence directory |
| ---: | --- | --- | --- | --- | --- |
| 1 | hello_write | `board/trace_validation/programs/hello_write.c` | syscall `write` (`a7=64`) | TODO(BOARD) | `01_hello_write/` |
| 2 | file_open_read_write | `board/trace_validation/programs/file_open_read_write.c` | creates `/tmp/rvmt_trace_validation_input.txt`, then syscalls `openat` (`a7=56`), `read` (`a7=63`), `write` (`a7=64`), `close` (`a7=57`) | TODO(BOARD) | `02_file_open_read_write/` |
| 3 | fork_exec | `board/trace_validation/programs/fork_exec.c` | syscalls `clone` (`a7=220`), `execve` (`a7=221`), `wait4` (`a7=260`) | TODO(BOARD) | `03_fork_exec/` |
| 4 | illegal_instruction | `board/trace_validation/programs/illegal_instruction.c` | trap event from an illegal instruction | TODO(BOARD) | `04_illegal_instruction/` |

`program.log`
`trace.jsonl`
`compare.log`
`observation.md`
The first-board trace profile from Phase 5.2 remains active
""",
        encoding="utf-8",
    )
    (root / DEFAULT_BOARD_DOC).write_text(
        "Phase 5.3 is tracked in docs/03-platform-architecture/genesys2/board_trace_validation.md and board/trace_validation/manifest.json.\n",
        encoding="utf-8",
    )


def expect_error(root: Path, expected: str) -> bool:
    return any(expected in error for error in run_checks(root, DEFAULT_MANIFEST, DEFAULT_DOC, DEFAULT_BOARD_DOC))


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = run_checks(root, DEFAULT_MANIFEST, DEFAULT_DOC, DEFAULT_BOARD_DOC)
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        expected = root / "board/trace_validation/expected/hello_write.expected.json"
        data = load_json(expected)
        data["status"] = "PASS"
        expected.write_text(json.dumps(data), encoding="utf-8")
        if not expect_error(root, "status must remain TODO(BOARD)"):
            print("[FAIL] self-test missed premature expected PASS", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        expected = root / "board/trace_validation/expected/file_open_read_write.expected.json"
        data = load_json(expected)
        data["required_syscalls"][0]["number"] = 999
        expected.write_text(json.dumps(data), encoding="utf-8")
        if not expect_error(root, "required_syscalls"):
            print("[FAIL] self-test missed wrong syscall number", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        source = root / "board/trace_validation/programs/fork_exec.c"
        source.write_text("SYS_clone\nSYS_wait4\n", encoding="utf-8")
        if not expect_error(root, "SYS_execve"):
            print("[FAIL] self-test missed missing source syscall token", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        manifest = load_json(root / DEFAULT_MANIFEST)
        manifest["programs"] = manifest["programs"][:-1]
        (root / DEFAULT_MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
        if not expect_error(root, "program ids differ"):
            print("[FAIL] self-test missed missing manifest program", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8").replace("TODO(BOARD)", "PASS", 1), encoding="utf-8")
        if not expect_error(root, "must not claim Phase 5.3"):
            print("[FAIL] self-test missed premature doc PASS", file=sys.stderr)
            return 1

    print("[PASS] board trace validation program self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Phase 5.3 board trace validation programs.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--board-doc", type=Path, default=DEFAULT_BOARD_DOC)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        errors = run_checks(args.root.resolve(), args.manifest, args.doc, args.board_doc)
    except Exception as exc:
        print(f"check_board_trace_programs: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] Phase 5.3 board trace validation programs are specified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
