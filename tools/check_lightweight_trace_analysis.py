from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_SPEC = Path("experiments/analysis/lightweight_trace_profile.json")
DEFAULT_DOC = Path("docs/05-semantic-analysis/lightweight_trace_analysis.md")
DEFAULT_TOOL = Path("tools/analyze_trace_lightweight.py")
DEFAULT_COMPRESS = Path("tools/compress_trace.py")
DEFAULT_TRACE = Path("results/vivado_sim/board_minimal/trace.jsonl")
DEFAULT_COMPRESSION_TRACE = Path("sim/golden/compression_edges.trace.jsonl")
DEFAULT_UV_DOC = Path("docs/10-process/uv_workflow.md")
EXPECTED_PROFILES = ["board_minimal", "semantic_mvp"]
SCOPED_CURRENT_STATUS = "PASS_SCOPED_GENESYS2_CURRENT"
FORBIDDEN_CLAIM_PATTERNS = (
    re.compile(r"\bruntime\s+overhead\s+(?:is\s+)?(?:measured|validated|passed|complete)\b", re.IGNORECASE),
    re.compile(r"\btrace[- ]enabled\s+FPGA\s+bandwidth\s+(?:is\s+)?(?:measured|validated|passed|complete)\b", re.IGNORECASE),
    re.compile(r"\bmalware\s+detection\s+(?:quality\s+)?(?:is\s+)?(?:measured|validated|passed|complete)\b", re.IGNORECASE),
)
REQUIRED_DOC_TEXT = (
    "Phase 9.1 defines the selective committed semantic trace analysis gate.",
    "scoped Genesys2/CVA6 evidence for the semantic MVP event families",
    "experiments/analysis/lightweight_trace_profile.json",
    "tools/analyze_trace_lightweight.py",
    "compact JSONL roundtrip",
    "drop accounting",
    "not a claim that every raw board trace is marker-free",
    "must not be used to claim runtime overhead",
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


def check_forbidden(path: Path, text: str) -> list[str]:
    return [
        f"{path}: must not claim runtime overhead, bandwidth, or detection quality"
        for pattern in FORBIDDEN_CLAIM_PATTERNS
        if pattern.search(text)
    ]


def check_spec(path: Path) -> list[str]:
    spec = load_json(path)
    errors: list[str] = []
    errors.extend(check_forbidden(path, path.read_text(encoding="utf-8")))
    if spec.get("phase") != "9.1":
        errors.append(f"{path}: phase must be 9.1")
    if spec.get("status") != "PASS_SCOPED_CURRENT_EVIDENCE":
        errors.append(f"{path}: status must be PASS_SCOPED_CURRENT_EVIDENCE")
    if spec.get("scope") != "selective_committed_semantic_trace_analysis":
        errors.append(f"{path}: unexpected scope")
    if spec.get("input_artifacts") != ["trace.jsonl"]:
        errors.append(f"{path}: input_artifacts must be trace.jsonl")
    if spec.get("output_artifacts") != ["lightweight_trace_analysis.json", "lightweight_trace_report.md"]:
        errors.append(f"{path}: output artifacts mismatch")
    profiles = spec.get("profiles", [])
    if not isinstance(profiles, list):
        return errors + [f"{path}: profiles must be a list"]
    by_id = {profile.get("id"): profile for profile in profiles if isinstance(profile, dict)}
    if list(by_id) != EXPECTED_PROFILES:
        errors.append(f"{path}: profiles must be {EXPECTED_PROFILES} in order")
    board = by_id.get("board_minimal", {})
    if board.get("status") != "CHECKED(SIM)":
        errors.append(f"{path}: board_minimal status must be CHECKED(SIM)")
    if board.get("allowed_other_events") != []:
        errors.append(f"{path}: board_minimal allowed_other_events must be empty")
    if set(board.get("forbidden_behavior_events", [])) != {"RETIRE", "JUMP", "MARKER", "ARG_MEM"}:
        errors.append(f"{path}: board_minimal forbidden_behavior_events mismatch")
    semantic = by_id.get("semantic_mvp", {})
    if semantic.get("status") != SCOPED_CURRENT_STATUS:
        errors.append(f"{path}: semantic_mvp status must be {SCOPED_CURRENT_STATUS}")
    if semantic.get("allowed_other_events") != []:
        errors.append(f"{path}: semantic_mvp allowed_other_events must be empty")
    gates = spec.get("gates", [])
    gate_ids = [gate.get("id") for gate in gates if isinstance(gate, dict)]
    if gate_ids != [
        "compact_roundtrip",
        "board_minimal_profile",
        "filter_regression",
        "current_arg_mem_pointer_prefix",
        "current_trace_export_boundary",
    ]:
        errors.append(f"{path}: gates must include sim gates plus current ARG_MEM and trace-export gates")
    non_goals = spec.get("non_goals", [])
    for required in (
        "full instruction trace by default",
        "full memory trace by default",
        "runtime overhead claim without paired runs",
        "trace-enabled FPGA bandwidth claim without implementation artifacts",
    ):
        if required not in non_goals:
            errors.append(f"{path}: non_goals missing {required}")
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
    errors.extend(check_forbidden(path, text))
    rows = parse_table_rows(text)
    by_profile = {row[1]: row for row in rows if len(row) >= 6}
    if by_profile.get("board_minimal", ["", "", "", "", "", ""])[5] != "CHECKED(SIM)":
        errors.append(f"{path}: board_minimal row must stay CHECKED(SIM)")
    if by_profile.get("semantic_mvp", ["", "", "", "", "", ""])[5] != SCOPED_CURRENT_STATUS:
        errors.append(f"{path}: semantic_mvp row must be {SCOPED_CURRENT_STATUS}")
    return errors


def check_uv_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    for token, label in (
        ("tools/analyze_trace_lightweight.py --self-test", "analysis self-test"),
        ("tools/check_lightweight_trace_analysis.py", "lightweight checker"),
        ("docs/05-semantic-analysis/lightweight_trace_analysis.md", "lightweight doc reference"),
        ("experiments/analysis/lightweight_trace_profile.json", "lightweight spec reference"),
        ("tools/compress_trace.py sim/golden/compression_edges.trace.jsonl --check-roundtrip --stats", "compression roundtrip command"),
        ("tools/check_hardware_pointer_prefixes.py --root .", "current ARG_MEM pointer-prefix command"),
        ("tools/check_trace_export_decision.py --root .", "current trace-export boundary command"),
        ("tools/check_ccfa_case_study_manifest.py --root .", "current case-study command"),
    ):
        if token not in text:
            errors.append(f"{path}: missing {label}")
    return errors


def check_tools(root: Path, tool: Path, compress: Path, trace: Path, compression_trace: Path) -> list[str]:
    errors: list[str] = []
    for path, label in ((tool, "analysis tool"), (compress, "compression tool"), (trace, "board minimal trace"), (compression_trace, "compression trace")):
        if not resolve(root, path).exists():
            errors.append(f"missing {label}: {resolve(root, path)}")
    if errors:
        return errors
    errors.extend(check_forbidden(resolve(root, tool), resolve(root, tool).read_text(encoding="utf-8")))
    for cmd, label in (
        ([sys.executable, str(resolve(root, tool)), "--self-test"], "analysis self-test"),
        ([sys.executable, str(resolve(root, compress)), str(resolve(root, compression_trace)), "--check-roundtrip", "--stats"], "compression roundtrip"),
    ):
        result = subprocess.run(cmd, cwd=root, text=True, capture_output=True)
        if result.returncode != 0:
            errors.append(f"{label} failed: {result.stderr.strip() or result.stdout.strip()}")
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "lightweight"
        result = subprocess.run(
            [
                sys.executable,
                str(resolve(root, tool)),
                "--trace",
                str(resolve(root, trace)),
                "--profile",
                "board_minimal",
                "--out-dir",
                str(out_dir),
            ],
            cwd=root,
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            errors.append(f"board_minimal analysis failed: {result.stderr.strip()}")
        else:
            payload = load_json(out_dir / "lightweight_trace_analysis.json")
            if not payload.get("profile", {}).get("profile_matched"):
                errors.append("board_minimal analysis did not match board_minimal profile")
            if payload.get("roundtrip") != "PASS":
                errors.append("board_minimal analysis did not record compact roundtrip PASS")
            if payload.get("bytes", {}).get("compact_jsonl", 0) <= 0:
                errors.append("board_minimal analysis missing compact byte stats")
        bad_trace = out_dir / "bad_trace.jsonl"
        bad_trace.write_text('{"cycle":1,"evt":"FOO"}\n', encoding="utf-8")
        bad_out = out_dir / "bad"
        result = subprocess.run(
            [
                sys.executable,
                str(resolve(root, tool)),
                "--trace",
                str(bad_trace),
                "--profile",
                "board_minimal",
                "--out-dir",
                str(bad_out),
            ],
            cwd=root,
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            errors.append(f"board_minimal unexpected-event analysis failed unexpectedly: {result.stderr.strip()}")
        else:
            bad_payload = load_json(bad_out / "lightweight_trace_analysis.json")
            if bad_payload.get("profile", {}).get("profile_matched"):
                errors.append("board_minimal analysis allowed an unexpected event")
    return errors


def run_checks(root: Path, spec: Path, doc: Path, tool: Path, compress: Path, trace: Path, compression_trace: Path, uv_doc: Path) -> list[str]:
    paths = {
        "spec": resolve(root, spec),
        "doc": resolve(root, doc),
        "tool": resolve(root, tool),
        "compress": resolve(root, compress),
        "trace": resolve(root, trace),
        "compression trace": resolve(root, compression_trace),
        "uv workflow": resolve(root, uv_doc),
    }
    errors = [f"missing {label}: {path}" for label, path in paths.items() if not path.exists()]
    if errors:
        return errors
    errors.extend(check_spec(paths["spec"]))
    errors.extend(check_doc(paths["doc"]))
    errors.extend(check_uv_doc(paths["uv workflow"]))
    errors.extend(check_tools(root, tool, compress, trace, compression_trace))
    return errors


def write_fixture(root: Path) -> None:
    (root / "experiments/analysis").mkdir(parents=True)
    (root / DEFAULT_DOC).parent.mkdir(parents=True)
    (root / DEFAULT_UV_DOC).parent.mkdir(parents=True)
    (root / "tools").mkdir(parents=True)
    profiles = [
        {
            "id": "board_minimal",
            "behavior_events": ["BRANCH", "SYSCALL_ENTRY", "SYSCALL_RET", "TRAP", "CSR", "SATP", "PRIV"],
            "accounting_events": ["DROP"],
            "allowed_other_events": [],
            "forbidden_behavior_events": ["RETIRE", "JUMP", "MARKER", "ARG_MEM"],
            "status": "CHECKED(SIM)",
        },
        {
            "id": "semantic_mvp",
            "behavior_events": ["BRANCH", "JUMP", "SYSCALL_ENTRY", "SYSCALL_RET", "TRAP", "CSR", "SATP", "PRIV", "ARG_MEM"],
            "accounting_events": ["DROP"],
            "allowed_other_events": [],
            "forbidden_behavior_events": ["MARKER"],
            "status": SCOPED_CURRENT_STATUS,
        },
    ]
    (root / DEFAULT_SPEC).write_text(
        json.dumps(
            {
                "phase": "9.1",
                "status": "PASS_SCOPED_CURRENT_EVIDENCE",
                "scope": "selective_committed_semantic_trace_analysis",
                "input_artifacts": ["trace.jsonl"],
                "output_artifacts": ["lightweight_trace_analysis.json", "lightweight_trace_report.md"],
                "profiles": profiles,
                "gates": [
                    {"id": "compact_roundtrip", "status": "CHECKED(SIM)", "command": "cmd"},
                    {"id": "board_minimal_profile", "status": "CHECKED(SIM)", "command": "cmd"},
                    {"id": "filter_regression", "status": "CHECKED(SIM)", "command": "cmd"},
                    {"id": "current_arg_mem_pointer_prefix", "status": SCOPED_CURRENT_STATUS, "command": "cmd"},
                    {"id": "current_trace_export_boundary", "status": SCOPED_CURRENT_STATUS, "command": "cmd"},
                ],
                "non_goals": [
                    "full instruction trace by default",
                    "full memory trace by default",
                    "runtime overhead claim without paired runs",
                    "trace-enabled FPGA bandwidth claim without implementation artifacts",
                ],
            }
        ),
        encoding="utf-8",
    )
    (root / DEFAULT_DOC).write_text(
        """# Lightweight Trace Analysis

Phase 9.1 defines the selective committed semantic trace analysis gate.
scoped Genesys2/CVA6 evidence for the semantic MVP event families
experiments/analysis/lightweight_trace_profile.json
tools/analyze_trace_lightweight.py
compact JSONL roundtrip
drop accounting
not a claim that every raw board trace is marker-free
must not be used to claim runtime overhead

| Order | Profile | Behavior events | Accounting events | Forbidden behavior events | Status |
| ---: | --- | --- | --- | --- | --- |
| 1 | board_minimal | events | DROP | RETIRE | CHECKED(SIM) |
| 2 | semantic_mvp | events | DROP | MARKER | PASS_SCOPED_GENESYS2_CURRENT |
""",
        encoding="utf-8",
    )
    (root / DEFAULT_UV_DOC).write_text(
        "uv run python tools/analyze_trace_lightweight.py --self-test\n"
        "uv run python tools/check_lightweight_trace_analysis.py\n"
        "docs/05-semantic-analysis/lightweight_trace_analysis.md\n"
        "experiments/analysis/lightweight_trace_profile.json\n"
        "uv run python tools/compress_trace.py sim/golden/compression_edges.trace.jsonl --check-roundtrip --stats\n"
        "uv run python tools/check_hardware_pointer_prefixes.py --root .\n"
        "uv run python tools/check_trace_export_decision.py --root .\n"
        "uv run python tools/check_ccfa_case_study_manifest.py --root .\n",
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

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["profiles"][0]["forbidden_behavior_events"] = ["MARKER"]
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "board_minimal forbidden_behavior_events mismatch"):
            print("[FAIL] self-test missed weakened board_minimal profile", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["profiles"][0]["allowed_other_events"] = ["FOO"]
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "board_minimal allowed_other_events must be empty"):
            print("[FAIL] self-test missed loosened board_minimal allowed_other_events", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["profiles"][1]["status"] = "TODO(EXPERIMENT)"
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "semantic_mvp status must be PASS_SCOPED_GENESYS2_CURRENT"):
            print("[FAIL] self-test missed stale semantic_mvp TODO status", file=sys.stderr)
            return 1

    for phrase in (
        "runtime overhead is measured",
        "trace-enabled FPGA bandwidth is validated",
        "malware detection quality is measured",
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            doc = root / DEFAULT_DOC
            doc.write_text(doc.read_text(encoding="utf-8") + f"\n{phrase}\n", encoding="utf-8")
            if not expect_error(root, "must not claim runtime overhead"):
                print(f"[FAIL] self-test missed unsafe doc phrase: {phrase}", file=sys.stderr)
                return 1

    for target, phrase in (
        (DEFAULT_SPEC, "runtime overhead is measured"),
        (DEFAULT_TOOL, "malware detection quality is measured"),
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            path = root / target
            if target == DEFAULT_SPEC:
                payload = load_json(path)
                payload["unsafe_claim"] = phrase
                path.write_text(json.dumps(payload), encoding="utf-8")
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    path.write_text("# fixture analysis tool\n", encoding="utf-8")
                path.write_text(path.read_text(encoding="utf-8") + f"\n{phrase}\n", encoding="utf-8")
            errors = []
            if target == DEFAULT_SPEC:
                errors.extend(check_spec(path))
            else:
                errors.extend(check_forbidden(path, path.read_text(encoding="utf-8")))
            if not any("must not claim runtime overhead" in error for error in errors):
                print(f"[FAIL] self-test missed unsafe phrase in {target}: {phrase}", file=sys.stderr)
                return 1

    print("[PASS] lightweight trace analysis checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check lightweight selective trace analysis gate.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--tool", type=Path, default=DEFAULT_TOOL)
    parser.add_argument("--compress", type=Path, default=DEFAULT_COMPRESS)
    parser.add_argument("--trace", type=Path, default=DEFAULT_TRACE)
    parser.add_argument("--compression-trace", type=Path, default=DEFAULT_COMPRESSION_TRACE)
    parser.add_argument("--uv-doc", type=Path, default=DEFAULT_UV_DOC)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        errors = run_checks(args.root.resolve(), args.spec, args.doc, args.tool, args.compress, args.trace, args.compression_trace, args.uv_doc)
    except Exception as exc:
        print(f"check_lightweight_trace_analysis: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] lightweight selective trace analysis gate is specified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
