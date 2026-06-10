from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any


DEFAULT_MANIFEST = Path("board/trace_validation/manifest.json")
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260609-2345-phase6-syscall-ret-fix")
REQUIRED_SAMPLE_FILES = (
    "program.log",
    "trace.jsonl",
    "trace_summary.json",
    "capture_manifest.json",
    "compare.log",
    "observation.md",
)
EXPECTED_BOARD = "Digilent Genesys2"
EXPECTED_CPU = "CVA6"


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def display(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            rows.append(value)
    return rows


def parse_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 16) if text.startswith("0x") else int(text, 10)
        except ValueError:
            return None
    return None


def require(condition: bool, errors: list[str], message: str) -> None:
    if not condition:
        errors.append(message)


def by_program(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    programs = manifest.get("programs")
    if not isinstance(programs, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for item in programs:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            result[item["id"]] = item
    return result


def expected_syscall_counts(expected: dict[str, Any]) -> Counter[int]:
    counts: Counter[int] = Counter()
    for item in expected.get("required_syscalls", []):
        if not isinstance(item, dict):
            continue
        number = parse_int(item.get("number"))
        if number is not None:
            counts[number] += 1
    return counts


def event_counts(events: list[dict[str, Any]]) -> Counter[str]:
    return Counter(str(event.get("evt")) for event in events if event.get("evt") is not None)


def syscall_entry_counts(events: list[dict[str, Any]]) -> Counter[int]:
    counts: Counter[int] = Counter()
    for event in events:
        if event.get("evt") != "SYSCALL_ENTRY":
            continue
        number = parse_int(event.get("a7"))
        if number is not None:
            counts[number] += 1
    return counts


def nonempty(path: Path) -> bool:
    return path.is_file() and path.stat().st_size > 0


def check_compare_log(path: Path, root: Path, errors: list[str]) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    require("[PASS]" in text, errors, f"{display(path, root)}: compare log must contain PASS rows")
    require("[FAIL]" not in text, errors, f"{display(path, root)}: compare log must not contain FAIL rows")


def check_capture_manifest(
    sample_id: str,
    sample_dir: Path,
    capture_manifest: dict[str, Any],
    root: Path,
    errors: list[str],
) -> None:
    label = display(sample_dir / "capture_manifest.json", root)
    require(capture_manifest.get("sample_id") == sample_id, errors, f"{label}: sample_id mismatch")
    require(capture_manifest.get("board") == EXPECTED_BOARD, errors, f"{label}: board must be {EXPECTED_BOARD}")
    require(capture_manifest.get("cpu") == EXPECTED_CPU, errors, f"{label}: cpu must be {EXPECTED_CPU}")
    require("COM7" in str(capture_manifest.get("uart", "")), errors, f"{label}: UART must record COM7")
    require("onboard" in str(capture_manifest.get("jtag", "")).lower(), errors, f"{label}: JTAG must record onboard path")

    captures = capture_manifest.get("captures")
    require(isinstance(captures, list) and bool(captures), errors, f"{label}: captures must be nonempty")
    if not isinstance(captures, list):
        return
    for index, capture in enumerate(captures):
        if not isinstance(capture, dict):
            errors.append(f"{label}: captures[{index}] must be an object")
            continue
        for key in ("csv", "trace"):
            raw_path = capture.get(key)
            require(isinstance(raw_path, str) and bool(raw_path), errors, f"{label}: captures[{index}].{key} missing")
            if isinstance(raw_path, str) and raw_path:
                path = resolve(root, Path(raw_path))
                require(nonempty(path), errors, f"{label}: captures[{index}].{key} missing or empty: {display(path, root)}")


def check_summary(
    sample_id: str,
    expected: dict[str, Any],
    summary: dict[str, Any],
    events: list[dict[str, Any]],
    sample_dir: Path,
    root: Path,
    errors: list[str],
) -> None:
    label = display(sample_dir / "trace_summary.json", root)
    require(summary.get("schema") == "rvmt.genesys2.board_trace_summary.v1", errors, f"{label}: schema mismatch")
    require(summary.get("sample_id") == sample_id, errors, f"{label}: sample_id mismatch")
    require(summary.get("board") == EXPECTED_BOARD, errors, f"{label}: board must be {EXPECTED_BOARD}")
    require(summary.get("cpu") == EXPECTED_CPU, errors, f"{label}: cpu must be {EXPECTED_CPU}")
    require(summary.get("compare_pass") is True, errors, f"{label}: compare_pass must be true")
    require(summary.get("requirement_checks_pass") is True, errors, f"{label}: requirement_checks_pass must be true")
    require(summary.get("events") == len(events), errors, f"{label}: events count must match trace.jsonl")

    actual_events = event_counts(events)
    for event_name in expected.get("required_events", []):
        require(actual_events[str(event_name)] > 0, errors, f"{label}: missing required event {event_name}")
    for event_name in expected.get("forbidden_events", []):
        require(actual_events[str(event_name)] == 0, errors, f"{label}: forbidden event present: {event_name}")

    actual_syscalls = syscall_entry_counts(events)
    for number, minimum in expected_syscall_counts(expected).items():
        require(
            actual_syscalls[number] >= minimum,
            errors,
            f"{label}: syscall 0x{number:x} entry count {actual_syscalls[number]} < {minimum}",
        )

    if sample_id == "hello_write":
        require(actual_syscalls[64] >= 1, errors, f"{label}: hello_write must include write syscall entry a7=0x40")
        require(actual_events["SYSCALL_RET"] >= 1, errors, f"{label}: hello_write must include SYSCALL_RET")
        if summary.get("paired_entry_return_in_single_capture") is not True:
            limitations = " ".join(str(item) for item in summary.get("limitations", []))
            lowered = limitations.lower()
            require("window" in lowered or "capture" in lowered, errors, f"{label}: hello_write ret limitation must identify capture window")
            require("ila" in lowered or "depth" in lowered or "trigger" in lowered, errors, f"{label}: hello_write ret limitation must identify concrete cause")


def check_sample(root: Path, run_root: Path, item: dict[str, Any], errors: list[str]) -> None:
    sample_id = item.get("id")
    if not isinstance(sample_id, str):
        errors.append("manifest program row missing id")
        return
    expected_path = resolve(root, Path(str(item.get("expected", ""))))
    if not expected_path.is_file():
        errors.append(f"{sample_id}: missing expected file {display(expected_path, root)}")
        return
    expected = load_json(expected_path)
    sample_dir = run_root / str(item.get("evidence_dir", expected.get("evidence_dir", "")))
    require(sample_dir.is_dir(), errors, f"{sample_id}: missing evidence directory {display(sample_dir, root)}")
    if not sample_dir.is_dir():
        return

    for name in REQUIRED_SAMPLE_FILES:
        path = sample_dir / name
        require(nonempty(path), errors, f"{sample_id}: missing or empty {display(path, root)}")
    require(any(path.is_file() and path.stat().st_size > 0 for path in sample_dir.glob("*.csv")), errors, f"{sample_id}: missing ILA raw CSV")
    if any(not nonempty(sample_dir / name) for name in REQUIRED_SAMPLE_FILES):
        return

    events = load_jsonl(sample_dir / "trace.jsonl")
    require(events, errors, f"{sample_id}: trace.jsonl must contain events")
    summary = load_json(sample_dir / "trace_summary.json")
    capture_manifest = load_json(sample_dir / "capture_manifest.json")
    check_compare_log(sample_dir / "compare.log", root, errors)
    check_capture_manifest(sample_id, sample_dir, capture_manifest, root, errors)
    check_summary(sample_id, expected, summary, events, sample_dir, root, errors)


def run_checks(root: Path, manifest_path: Path, run_root_path: Path) -> list[str]:
    manifest_full = resolve(root, manifest_path)
    run_root = resolve(root, run_root_path)
    errors: list[str] = []
    if not manifest_full.is_file():
        return [f"missing manifest: {display(manifest_full, root)}"]
    if not run_root.is_dir():
        return [f"missing run root: {display(run_root, root)}"]
    manifest = load_json(manifest_full)
    programs = by_program(manifest)
    require(set(programs) == {"hello_write", "file_open_read_write", "fork_exec", "illegal_instruction"}, errors, "manifest program set mismatch")
    for item in programs.values():
        check_sample(root, run_root, item, errors)
    return errors


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_fixture(root: Path) -> tuple[Path, Path]:
    manifest_path = root / DEFAULT_MANIFEST
    run_root = root / DEFAULT_RUN_ROOT
    programs = []
    specs = {
        "hello_write": (
            "01_hello_write",
            [{"evt": "SYSCALL_ENTRY", "a7": "0x40"}, {"evt": "SYSCALL_RET"}],
            ["SYSCALL_ENTRY", "SYSCALL_RET"],
            [(64, "write")],
        ),
        "file_open_read_write": (
            "02_file_open_read_write",
            [
                {"evt": "SYSCALL_ENTRY", "a7": "0x38"},
                {"evt": "SYSCALL_ENTRY", "a7": "0x40"},
                {"evt": "SYSCALL_ENTRY", "a7": "0x39"},
                {"evt": "SYSCALL_ENTRY", "a7": "0x38"},
                {"evt": "SYSCALL_ENTRY", "a7": "0x3f"},
                {"evt": "SYSCALL_ENTRY", "a7": "0x40"},
                {"evt": "SYSCALL_ENTRY", "a7": "0x39"},
                {"evt": "SYSCALL_RET"},
            ],
            ["SYSCALL_ENTRY", "SYSCALL_RET"],
            [(56, "openat"), (64, "write"), (57, "close"), (56, "openat"), (63, "read"), (64, "write"), (57, "close")],
        ),
        "fork_exec": (
            "03_fork_exec",
            [
                {"evt": "SYSCALL_ENTRY", "a7": "0xdc"},
                {"evt": "SYSCALL_ENTRY", "a7": "0xdd"},
                {"evt": "SYSCALL_ENTRY", "a7": "0x104"},
                {"evt": "SYSCALL_RET"},
                {"evt": "PRIV"},
            ],
            ["SYSCALL_ENTRY", "SYSCALL_RET", "PRIV"],
            [(220, "clone"), (221, "execve"), (260, "wait4")],
        ),
        "illegal_instruction": (
            "04_illegal_instruction",
            [{"evt": "TRAP"}, {"evt": "SYSCALL_ENTRY", "a7": "0x40"}],
            ["TRAP"],
            [(64, "write")],
        ),
    }
    for sample_id, (evidence_dir, events, required_events, syscalls) in specs.items():
        expected_path = root / "board" / "trace_validation" / "expected" / f"{sample_id}.expected.json"
        write_json(
            expected_path,
            {
                "program": sample_id,
                "mode": "linux_user",
                "status": "TODO(BOARD)",
                "required_syscalls": [{"name": name, "number": number} for number, name in syscalls],
                "required_events": required_events,
                "forbidden_events": ["RETIRE"],
                "evidence_dir": evidence_dir,
            },
        )
        sample_dir = run_root / evidence_dir
        sample_dir.mkdir(parents=True, exist_ok=True)
        (sample_dir / "program.log").write_text("RVMT_SAMPLE_DONE\n", encoding="utf-8")
        (sample_dir / "trace.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
        (sample_dir / f"{sample_id}.csv").write_text("sample,data\n1,2\n", encoding="utf-8")
        (sample_dir / f"{sample_id}.trace.jsonl").write_text(json.dumps(events[0]) + "\n", encoding="utf-8")
        (sample_dir / "compare.log").write_text("[PASS] fixture\n", encoding="utf-8")
        (sample_dir / "observation.md").write_text("# observation\n", encoding="utf-8")
        counts = event_counts(events)
        write_json(
            sample_dir / "trace_summary.json",
            {
                "schema": "rvmt.genesys2.board_trace_summary.v1",
                "run_id": run_root.name,
                "sample_id": sample_id,
                "board": EXPECTED_BOARD,
                "cpu": EXPECTED_CPU,
                "events": len(events),
                "event_counts": dict(counts),
                "compare_pass": True,
                "requirement_checks_pass": True,
                "paired_entry_return_in_single_capture": False,
                "limitations": ["Current ILA depth/capture window separates entry and return."],
            },
        )
        write_json(
            sample_dir / "capture_manifest.json",
            {
                "schema": "rvmt.genesys2.capture_manifest.v1",
                "run_id": run_root.name,
                "sample_id": sample_id,
                "board": EXPECTED_BOARD,
                "cpu": EXPECTED_CPU,
                "uart": "Genesys2 onboard UART COM7 115200 8N1",
                "jtag": "Genesys2 onboard JTAG",
                "captures": [
                    {
                        "id": sample_id,
                        "csv": (sample_dir / f"{sample_id}.csv").as_posix(),
                        "trace": (sample_dir / f"{sample_id}.trace.jsonl").as_posix(),
                    }
                ],
            },
        )
        programs.append({"id": sample_id, "expected": expected_path.relative_to(root).as_posix(), "evidence_dir": evidence_dir})
    write_json(manifest_path, {"phase": "5.3", "status": "TODO(BOARD)", "programs": programs})
    return manifest_path, run_root


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest, run_root = write_fixture(root)
        errors = run_checks(root, manifest, run_root)
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1

    mutations = (
        (
            "missing csv",
            lambda root: next((root / DEFAULT_RUN_ROOT / "01_hello_write").glob("*.csv")).unlink(),
            "missing ILA raw CSV",
        ),
        (
            "missing hello ret",
            lambda root: (root / DEFAULT_RUN_ROOT / "01_hello_write/trace.jsonl").write_text('{"evt":"SYSCALL_ENTRY","a7":"0x40"}\n', encoding="utf-8"),
            "SYSCALL_RET",
        ),
        (
            "forbidden retire",
            lambda root: (root / DEFAULT_RUN_ROOT / "02_file_open_read_write/trace.jsonl").write_text(
                (root / DEFAULT_RUN_ROOT / "02_file_open_read_write/trace.jsonl").read_text(encoding="utf-8") + '{"evt":"RETIRE"}\n',
                encoding="utf-8",
            ),
            "forbidden event present",
        ),
    )
    for name, mutate, expected in mutations:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, run_root = write_fixture(root)
            mutate(root)
            errors = run_checks(root, manifest, run_root)
            if not any(expected in error for error in errors):
                print(f"[FAIL] self-test missed {name}: expected {expected}", file=sys.stderr)
                return 1

    print("[PASS] board trace evidence self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check actual Genesys2/CVA6 Phase 5.3 board trace evidence artifacts.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        root = args.root.resolve()
        errors = run_checks(root, args.manifest, args.run_root)
    except Exception as exc:
        print(f"check_board_trace_evidence: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print(f"[PASS] Genesys2/CVA6 board trace evidence is present: {args.run_root.as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
