from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_MANIFEST = Path("board/trace_validation/manifest.json")
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260609-2345-phase6-syscall-ret-fix")
EXPECTED_BOARD = "Digilent Genesys2"
EXPECTED_CPU = "CVA6"
EXPECTED_PROGRAMS = {"hello_write", "file_open_read_write", "fork_exec", "illegal_instruction"}
REQUIRED_LOCAL_FILES = (
    "local_code_analysis/code_map.json",
    "local_code_analysis/source_attribution.json",
    "local_code_analysis/source_attribution_summary.json",
    "local_code_analysis/observation.md",
    "runtime_minimal_code_analysis/code_map.json",
    "runtime_minimal_code_analysis/source_attribution.json",
    "runtime_minimal_code_analysis/source_attribution_summary.json",
    "behavior/semantic_events.json",
    "behavior/behavior_graph.json",
    "behavior/recovery_report.md",
)


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def display(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def normalize_path_text(value: Any) -> str:
    return str(value).replace("\\", "/")


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


def require(condition: bool, errors: list[str], message: str) -> None:
    if not condition:
        errors.append(message)


def nonempty(path: Path) -> bool:
    return path.is_file() and path.stat().st_size > 0


def by_program(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = manifest.get("programs")
    if not isinstance(rows, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("id"), str):
            result[row["id"]] = row
    return result


def summary_samples(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = summary.get("samples")
    if not isinstance(rows, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("sample_id"), str):
            result[row["sample_id"]] = row
    return result


def count_trace_events(trace_path: Path) -> int:
    return len(load_jsonl(trace_path))


def check_code_map(
    *,
    root: Path,
    sample_id: str,
    sample_dir: Path,
    manifest_row: dict[str, Any],
    code_map: dict[str, Any],
    expected_elf: str,
    expected_role: str,
    label: str,
    errors: list[str],
) -> None:
    require(code_map.get("schema") == "rvmt.code_map.v1", errors, f"{label}: schema mismatch")
    require(code_map.get("sample_id") == sample_id, errors, f"{label}: sample_id mismatch")
    require(code_map.get("binary_role") == expected_role, errors, f"{label}: binary_role must be {expected_role}")
    require(normalize_path_text(code_map.get("elf")) == expected_elf, errors, f"{label}: ELF path mismatch")
    require(resolve(root, Path(expected_elf)).is_file(), errors, f"{label}: ELF artifact missing: {expected_elf}")
    require(code_map.get("runtime_path") == f"/tmp/rvmt_phase6/{sample_id}", errors, f"{label}: runtime_path mismatch")
    source = normalize_path_text(code_map.get("source"))
    expected_source = normalize_path_text(manifest_row.get("source"))
    require(source == expected_source, errors, f"{label}: source path mismatch")
    require(resolve(root, Path(expected_source)).is_file(), errors, f"{label}: source file missing: {expected_source}")
    require("35T" not in json.dumps(code_map), errors, f"{label}: must not use 35T evidence")
    require(isinstance(code_map.get("load_ranges"), list) and bool(code_map.get("load_ranges")), errors, f"{label}: load_ranges missing")


def check_source_attribution(
    *,
    root: Path,
    sample_id: str,
    sample_dir: Path,
    trace_events: int,
    summary: dict[str, Any],
    rows: list[dict[str, Any]],
    expected_elf: str,
    expected_code_map: Path,
    expected_role: str,
    label: str,
    errors: list[str],
) -> None:
    require(summary.get("schema") == "rvmt.trace_code_join.summary.v1", errors, f"{label}: schema mismatch")
    require(summary.get("sample_id") == sample_id, errors, f"{label}: sample_id mismatch")
    require(summary.get("binary_role") == expected_role, errors, f"{label}: binary_role must be {expected_role}")
    require(normalize_path_text(summary.get("elf")) == expected_elf, errors, f"{label}: ELF path mismatch")
    require(normalize_path_text(summary.get("code_map")) == display(expected_code_map, root), errors, f"{label}: code_map path mismatch")
    require(summary.get("runtime_path") == f"/tmp/rvmt_phase6/{sample_id}", errors, f"{label}: runtime_path mismatch")
    require(summary.get("events") == trace_events, errors, f"{label}: events must match trace.jsonl")
    require(len(rows) == trace_events, errors, f"{label}: source_attribution row count must match trace.jsonl")
    require(summary.get("runtime_process_attribution_proven") is False, errors, f"{label}: must not claim runtime process attribution")
    require(summary.get("runtime_process_map_status") == "MISSING", errors, f"{label}: runtime_process_map_status must be MISSING")
    marker_scope = summary.get("marker_scope")
    require(isinstance(marker_scope, dict), errors, f"{label}: marker_scope missing")
    if isinstance(marker_scope, dict):
        require(marker_scope.get("status") == "MISSING", errors, f"{label}: marker_scope.status must be MISSING")
    require(summary.get("process_attribution") == "not_proven", errors, f"{label}: process_attribution must be not_proven")
    require("35T" not in json.dumps(summary), errors, f"{label}: must not use 35T evidence")


def check_behavior(
    *,
    root: Path,
    sample_id: str,
    sample_dir: Path,
    trace_events: int,
    errors: list[str],
) -> None:
    semantic_path = sample_dir / "behavior/semantic_events.json"
    graph_path = sample_dir / "behavior/behavior_graph.json"
    report_path = sample_dir / "behavior/recovery_report.md"
    semantic = load_json(semantic_path)
    graph = load_json(graph_path)
    report = report_path.read_text(encoding="utf-8", errors="replace")
    label = display(semantic_path, root)
    require(semantic.get("schema") == "rvmt.behavior.semantic.v1", errors, f"{label}: schema mismatch")
    require(normalize_path_text(semantic.get("source")) == display(sample_dir / "trace.jsonl", root), errors, f"{label}: source mismatch")
    require(isinstance(semantic.get("syscall_sequence"), list), errors, f"{label}: syscall_sequence missing")
    require(isinstance(semantic.get("control_flow_segments"), list), errors, f"{label}: control_flow_segments missing")
    recovered_total = len(semantic.get("syscall_sequence", [])) + len(semantic.get("control_flow_segments", []))
    require(recovered_total > 0, errors, f"{label}: behavior recovery must produce semantic rows")
    require(semantic.get("code_map", {}).get("sample_id") == sample_id, errors, f"{label}: code_map sample_id mismatch")

    graph_label = display(graph_path, root)
    require(graph.get("schema") == "rvmt.behavior.graph.v1", errors, f"{graph_label}: schema mismatch")
    require(isinstance(graph.get("nodes"), list) and bool(graph.get("nodes")), errors, f"{graph_label}: nodes missing")
    require(isinstance(graph.get("edges"), list), errors, f"{graph_label}: edges missing")
    require(f"- Input events: {trace_events}" in report, errors, f"{display(report_path, root)}: input event count mismatch")
    require("not malware detection evidence" in report, errors, f"{display(report_path, root)}: missing non-detection boundary")


def check_sample(
    root: Path,
    run_root: Path,
    manifest_row: dict[str, Any],
    run_summary_row: dict[str, Any],
    errors: list[str],
) -> None:
    sample_id = str(manifest_row.get("id"))
    evidence_dir = str(manifest_row.get("evidence_dir"))
    sample_dir = run_root / evidence_dir
    require(sample_dir.is_dir(), errors, f"{sample_id}: missing sample directory {display(sample_dir, root)}")
    if not sample_dir.is_dir():
        return
    for relative in REQUIRED_LOCAL_FILES:
        require(nonempty(sample_dir / relative), errors, f"{sample_id}: missing or empty {display(sample_dir / relative, root)}")
    if any(not nonempty(sample_dir / relative) for relative in REQUIRED_LOCAL_FILES):
        return
    trace_path = sample_dir / "trace.jsonl"
    require(nonempty(trace_path), errors, f"{sample_id}: missing or empty trace.jsonl")
    if not nonempty(trace_path):
        return
    trace_events = count_trace_events(trace_path)

    expected_full_elf = f"build/board/genesys2_cva6_phase6_linux_user/{sample_id}.riscv64"
    expected_minimal_elf = f"build/board/genesys2_cva6_phase6_linux_user_minimal/{sample_id}.riscv64"
    full_code_map_path = sample_dir / "local_code_analysis/code_map.json"
    minimal_code_map_path = sample_dir / "runtime_minimal_code_analysis/code_map.json"
    full_summary_path = sample_dir / "local_code_analysis/source_attribution_summary.json"
    minimal_summary_path = sample_dir / "runtime_minimal_code_analysis/source_attribution_summary.json"
    full_attr_path = sample_dir / "local_code_analysis/source_attribution.json"
    minimal_attr_path = sample_dir / "runtime_minimal_code_analysis/source_attribution.json"

    check_code_map(
        root=root,
        sample_id=sample_id,
        sample_dir=sample_dir,
        manifest_row=manifest_row,
        code_map=load_json(full_code_map_path),
        expected_elf=expected_full_elf,
        expected_role="linux_user",
        label=display(full_code_map_path, root),
        errors=errors,
    )
    check_code_map(
        root=root,
        sample_id=sample_id,
        sample_dir=sample_dir,
        manifest_row=manifest_row,
        code_map=load_json(minimal_code_map_path),
        expected_elf=expected_minimal_elf,
        expected_role="linux_user_minimal",
        label=display(minimal_code_map_path, root),
        errors=errors,
    )
    check_source_attribution(
        root=root,
        sample_id=sample_id,
        sample_dir=sample_dir,
        trace_events=trace_events,
        summary=load_json(full_summary_path),
        rows=load_jsonl(full_attr_path),
        expected_elf=expected_full_elf,
        expected_code_map=full_code_map_path,
        expected_role="linux_user",
        label=display(full_summary_path, root),
        errors=errors,
    )
    check_source_attribution(
        root=root,
        sample_id=sample_id,
        sample_dir=sample_dir,
        trace_events=trace_events,
        summary=load_json(minimal_summary_path),
        rows=load_jsonl(minimal_attr_path),
        expected_elf=expected_minimal_elf,
        expected_code_map=minimal_code_map_path,
        expected_role="linux_user_minimal",
        label=display(minimal_summary_path, root),
        errors=errors,
    )
    check_behavior(root=root, sample_id=sample_id, sample_dir=sample_dir, trace_events=trace_events, errors=errors)

    observation = (sample_dir / "local_code_analysis/observation.md").read_text(encoding="utf-8", errors="replace")
    require("not malware detection evidence" in observation, errors, f"{sample_id}: local observation missing non-detection boundary")
    require("Process attribution: `not_proven`" in observation, errors, f"{sample_id}: local observation must keep process attribution not_proven")
    require(run_summary_row.get("sample_id") == sample_id, errors, f"{sample_id}: run summary sample_id mismatch")
    require(run_summary_row.get("status") == "LOCAL_CODE_MAP_GENERATED_PROCESS_NOT_PROVEN", errors, f"{sample_id}: run summary status mismatch")
    require(run_summary_row.get("process_attribution") == "not_proven", errors, f"{sample_id}: run summary process attribution must be not_proven")
    require(run_summary_row.get("runtime_process_map_status") == "MISSING", errors, f"{sample_id}: run summary runtime process map must be MISSING")
    require(run_summary_row.get("marker_scope_status") == "MISSING", errors, f"{sample_id}: run summary marker scope must be MISSING")
    require(run_summary_row.get("events") == trace_events, errors, f"{sample_id}: run summary event count mismatch")


def run_checks(root: Path, manifest_path: Path, run_root_path: Path) -> list[str]:
    manifest_full = resolve(root, manifest_path)
    run_root = resolve(root, run_root_path)
    errors: list[str] = []
    if not manifest_full.is_file():
        return [f"missing manifest: {display(manifest_full, root)}"]
    if not run_root.is_dir():
        return [f"missing run root: {display(run_root, root)}"]
    summary_path = run_root / "local_code_analysis_summary.json"
    if not summary_path.is_file():
        return [f"missing run local code summary: {display(summary_path, root)}"]
    manifest = load_json(manifest_full)
    programs = by_program(manifest)
    require(set(programs) == EXPECTED_PROGRAMS, errors, "manifest program set mismatch")

    summary = load_json(summary_path)
    require(summary.get("schema") == "rvmt.genesys2.local_code_analysis_summary.v1", errors, f"{display(summary_path, root)}: schema mismatch")
    require(summary.get("board") == EXPECTED_BOARD, errors, f"{display(summary_path, root)}: board mismatch")
    require(summary.get("cpu") == EXPECTED_CPU, errors, f"{display(summary_path, root)}: cpu mismatch")
    require(summary.get("status") == "LOCAL_CODE_ANALYSIS_GENERATED_PROCESS_NOT_PROVEN", errors, f"{display(summary_path, root)}: status mismatch")
    require("35T" not in json.dumps(summary), errors, f"{display(summary_path, root)}: must not use 35T evidence")
    limitations = " ".join(str(item) for item in summary.get("global_limitations", []))
    require("process ownership is not proven" in limitations, errors, f"{display(summary_path, root)}: missing process boundary")
    require("not malware detection evidence" in limitations, errors, f"{display(summary_path, root)}: missing non-detection boundary")

    summary_rows = summary_samples(summary)
    require(set(summary_rows) == EXPECTED_PROGRAMS, errors, f"{display(summary_path, root)}: sample set mismatch")
    for sample_id in sorted(EXPECTED_PROGRAMS):
        if sample_id in programs and sample_id in summary_rows:
            check_sample(root, run_root, programs[sample_id], summary_rows[sample_id], errors)
    return errors


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def write_fixture(root: Path) -> tuple[Path, Path]:
    manifest_path = root / DEFAULT_MANIFEST
    run_root = root / DEFAULT_RUN_ROOT
    samples: list[dict[str, Any]] = []
    programs: list[dict[str, Any]] = []
    evidence_dirs = {
        "hello_write": "01_hello_write",
        "file_open_read_write": "02_file_open_read_write",
        "fork_exec": "03_fork_exec",
        "illegal_instruction": "04_illegal_instruction",
    }
    for sample_id, evidence_dir in evidence_dirs.items():
        source = f"board/trace_validation/programs/{sample_id}.c"
        source_path = root / source
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        programs.append({"id": sample_id, "source": source, "evidence_dir": evidence_dir})

        sample_dir = run_root / evidence_dir
        full_elf = f"build/board/genesys2_cva6_phase6_linux_user/{sample_id}.riscv64"
        minimal_elf = f"build/board/genesys2_cva6_phase6_linux_user_minimal/{sample_id}.riscv64"
        for elf in (full_elf, minimal_elf):
            elf_path = root / elf
            elf_path.parent.mkdir(parents=True, exist_ok=True)
            elf_path.write_bytes(b"\x7fELFfixture")
        trace_rows = [{"evt": "SYSCALL_ENTRY", "a7": "0x40", "pc": "0x1000"}, {"evt": "BRANCH", "pc": "0x2000"}]
        write_jsonl(sample_dir / "trace.jsonl", trace_rows)
        for relative, elf, role in (
            ("local_code_analysis", full_elf, "linux_user"),
            ("runtime_minimal_code_analysis", minimal_elf, "linux_user_minimal"),
        ):
            code_dir = sample_dir / relative
            code_map = {
                "schema": "rvmt.code_map.v1",
                "sample_id": sample_id,
                "binary_role": role,
                "elf": elf,
                "source": source,
                "runtime_path": f"/tmp/rvmt_phase6/{sample_id}",
                "load_ranges": [{"start": "0x1000", "end": "0x1100"}],
            }
            write_json(code_dir / "code_map.json", code_map)
            rows = [{"evt": row["evt"], "pc": row["pc"], "pc_owner": "unknown"} for row in trace_rows]
            write_jsonl(code_dir / "source_attribution.json", rows)
            write_json(
                code_dir / "source_attribution_summary.json",
                {
                    "schema": "rvmt.trace_code_join.summary.v1",
                    "sample_id": sample_id,
                    "binary_role": role,
                    "elf": elf,
                    "code_map": display(code_dir / "code_map.json", root),
                    "runtime_path": f"/tmp/rvmt_phase6/{sample_id}",
                    "trace": display(sample_dir / "trace.jsonl", root),
                    "events": len(trace_rows),
                    "target_attributed_events": 0,
                    "process_attribution": "not_proven",
                    "runtime_process_attribution_proven": False,
                    "runtime_process_map_status": "MISSING",
                    "marker_scope": {"status": "MISSING", "markers": [], "begin_index": None, "end_index": None},
                },
            )
            (code_dir / "observation.md").write_text(
                "Process attribution: `not_proven`\nThis local analysis is code/trace correlation evidence, not malware detection evidence.\n",
                encoding="utf-8",
            )
        write_json(
            sample_dir / "behavior/semantic_events.json",
            {
                "schema": "rvmt.behavior.semantic.v1",
                "source": display(sample_dir / "trace.jsonl", root),
                "trace": {"events": len(trace_rows)},
                "code_map": {"sample_id": sample_id},
                "syscall_sequence": [{"name": "write"}],
                "control_flow_segments": [],
            },
        )
        write_json(
            sample_dir / "behavior/behavior_graph.json",
            {"schema": "rvmt.behavior.graph.v1", "nodes": [{"id": "trace", "kind": "trace"}], "edges": []},
        )
        (sample_dir / "behavior/recovery_report.md").write_text(
            f"- Input events: {len(trace_rows)}\nThis report is derived trace semantics, not malware detection evidence.\n",
            encoding="utf-8",
        )
        samples.append(
            {
                "sample_id": sample_id,
                "events": len(trace_rows),
                "status": "LOCAL_CODE_MAP_GENERATED_PROCESS_NOT_PROVEN",
                "process_attribution": "not_proven",
                "runtime_process_map_status": "MISSING",
                "marker_scope_status": "MISSING",
            }
        )
    write_json(manifest_path, {"programs": programs})
    write_json(
        run_root / "local_code_analysis_summary.json",
        {
            "schema": "rvmt.genesys2.local_code_analysis_summary.v1",
            "board": EXPECTED_BOARD,
            "cpu": EXPECTED_CPU,
            "run_id": run_root.name,
            "status": "LOCAL_CODE_ANALYSIS_GENERATED_PROCESS_NOT_PROVEN",
            "global_limitations": [
                "No runtime process map, PID/SATP/ASID, or marker-scope evidence is present, so process ownership is not proven.",
                "Behavior recovery is derived trace semantics and is not malware detection evidence.",
            ],
            "samples": samples,
        },
    )
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
            "missing behavior",
            lambda root: (root / DEFAULT_RUN_ROOT / "01_hello_write/behavior/semantic_events.json").unlink(),
            "semantic_events.json",
        ),
        (
            "process overclaim",
            lambda root: write_json(
                root / DEFAULT_RUN_ROOT / "01_hello_write/local_code_analysis/source_attribution_summary.json",
                {
                    **load_json(root / DEFAULT_RUN_ROOT / "01_hello_write/local_code_analysis/source_attribution_summary.json"),
                    "runtime_process_attribution_proven": True,
                },
            ),
            "must not claim runtime process attribution",
        ),
        (
            "wrong board",
            lambda root: write_json(
                root / DEFAULT_RUN_ROOT / "local_code_analysis_summary.json",
                {**load_json(root / DEFAULT_RUN_ROOT / "local_code_analysis_summary.json"), "board": "Arty A7 35T"},
            ),
            "board mismatch",
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
    print("[PASS] board local code analysis self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Genesys2/CVA6 Phase 5.3 local code analysis evidence artifacts.")
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
        print(f"check_board_local_code_analysis: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print(f"[PASS] Genesys2/CVA6 board local code analysis evidence is present: {args.run_root.as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
