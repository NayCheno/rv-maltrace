from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_RESULTS_ROOT = Path("results/experiments/35t") / RUN_ID
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / RUN_ID
SAMPLES = [
    "illegal_trap",
    "process_chain",
    "dynamic_executable_memory",
    "file_scan",
    "batch_open_read_write",
    "self_copy_sim",
]


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def symbol_function_count(code_map: dict[str, Any]) -> int:
    functions = code_map.get("function_ranges")
    if isinstance(functions, list) and functions:
        return len(functions)
    symbols = code_map.get("symbols", [])
    if not isinstance(symbols, list):
        return 0
    count = 0
    for row in symbols:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "")
        if not name or name.startswith("$"):
            continue
        if row.get("type") == 2:
            count += 1
    return count


def source_line_count(code_map: dict[str, Any]) -> int:
    locations = code_map.get("source_locations", [])
    return len(locations) if isinstance(locations, list) else 0


def trace_code_summary_path(results_root: Path, sample: str) -> Path:
    return (
        results_root
        / "samples/malware_like_synthetic"
        / sample
        / "board/trace-on/rep_00/trace_code_map/trace_code_map_summary.json"
    )


def code_map_path(results_root: Path, sample: str) -> Path:
    return results_root / "samples/malware_like_synthetic" / sample / "build" / f"{sample}.code_map.json"


def summarize_sample(results_root: Path, sample: str) -> dict[str, Any]:
    cpath = code_map_path(results_root, sample)
    if not cpath.exists():
        return {
            "sample": sample,
            "status": "UNAVAILABLE",
            "code_map_path": cpath.as_posix(),
            "reason": "code map missing",
        }
    code_map = load_json(cpath)
    function_count = symbol_function_count(code_map)
    line_count = source_line_count(code_map)
    tpath = trace_code_summary_path(results_root, sample)
    trace_code = load_json(tpath) if tpath.exists() else {}
    function_level = "available" if function_count else "unavailable"
    source_line_level = "available" if line_count else "unavailable"
    status = "PASS" if function_count and line_count else "PARTIAL" if function_count else "UNAVAILABLE"
    return {
        "sample": sample,
        "status": status,
        "code_map_path": cpath.as_posix(),
        "trace_code_summary_path": tpath.as_posix() if tpath.exists() else None,
        "code_map_schema": code_map.get("schema"),
        "trace_code_schema": trace_code.get("schema"),
        "function_level": function_level,
        "function_count": function_count,
        "function_basis": "ELF symbol table" if function_count else "unavailable",
        "source_line_level": source_line_level,
        "source_line_count": line_count,
        "source_line_basis": "source_locations/DWARF line records" if line_count else "unavailable: no source_locations/DWARF line records",
        "process_attributed_code_site_events": trace_code.get("process_attributed_code_site_events"),
        "target_attributed_events": trace_code.get("target_attributed_events"),
        "runtime_process_attribution_proven": trace_code.get("runtime_process_attribution_proven"),
        "limitations": [
            "function-level attribution is symbol/range based, not source-line attribution",
            "source-line attribution remains unavailable unless source_locations or DWARF-derived line records are present",
        ]
        if not line_count
        else ["source-line attribution depends on debug-line provenance"],
    }


def build_summary(results_root: Path) -> dict[str, Any]:
    samples = [summarize_sample(results_root, sample) for sample in SAMPLES]
    function_available = sum(1 for row in samples if row.get("function_level") == "available")
    source_line_available = sum(1 for row in samples if row.get("source_line_level") == "available")
    if source_line_available == len(samples):
        status = "PASS"
    elif function_available:
        status = "PARTIAL"
    else:
        status = "UNAVAILABLE"
    return {
        "schema": "rvmt.35t.source_attribution_summary.v1",
        "run_id": RUN_ID,
        "scope": "Artix-7 35T / LiteX / VexRiscv",
        "claim_level": "35T hardware-trace-assisted synthetic malware-like behavior audit prototype",
        "status": status,
        "function_level": {
            "status": "available" if function_available else "unavailable",
            "samples_available": function_available,
            "sample_count": len(samples),
            "basis": "ELF symbol table",
        },
        "source_line_level": {
            "status": "available" if source_line_available == len(samples) else "unavailable",
            "samples_available": source_line_available,
            "sample_count": len(samples),
            "basis": "source_locations/DWARF line records",
        },
        "samples": samples,
        "board_validation_needed": source_line_available != len(samples),
        "limitations": [
            "current evidence supports function-level attribution from symbols",
            "current evidence does not support source-line attribution for every case-study sample",
            "this does not prove complete semantic reconstruction",
        ],
        "non_claims": [
            "no CVA6 board claim",
            "no real malware detection claim",
            "no mature detector claim",
            "no classifier accuracy claim",
            "no complete semantic reconstruction claim",
        ],
    }


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        f"# 35T Source Attribution Summary: {summary['run_id']}",
        "",
        f"Status: {summary['status']}",
        "",
        "Scope: Artix-7 35T / LiteX / VexRiscv only.",
        "",
        f"Claim level: {summary['claim_level']}.",
        "",
        "## Overall",
        "",
        f"- Function level: {summary['function_level']['status']} ({summary['function_level']['samples_available']}/{summary['function_level']['sample_count']} samples)",
        f"- Source-line level: {summary['source_line_level']['status']} ({summary['source_line_level']['samples_available']}/{summary['source_line_level']['sample_count']} samples)",
        "",
        "## Samples",
        "",
    ]
    for row in summary["samples"]:
        lines.append(
            f"- {row['sample']}: status={row['status']}; function={row.get('function_level')}; source_line={row.get('source_line_level')}"
        )
    lines += ["", "## Limitations", ""]
    for item in summary["limitations"]:
        lines.append(f"- {item}")
    lines += ["", "## Non-claims", ""]
    for item in summary["non_claims"]:
        lines.append(f"- {item}")
    return "\n".join(lines) + "\n"


def write_outputs(summary: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "source_attribution_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "source_attribution_summary.md").write_text(
        render_markdown(summary),
        encoding="utf-8",
        newline="\n",
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        results = root / DEFAULT_RESULTS_ROOT
        for sample in SAMPLES:
            cdir = results / "samples/malware_like_synthetic" / sample / "build"
            cdir.mkdir(parents=True, exist_ok=True)
            (cdir / f"{sample}.code_map.json").write_text(
                json.dumps(
                    {
                        "schema": "rvmt.code_map.v1",
                        "symbols": [{"name": "main", "start": "0x1000", "end": "0x1010", "type": 2}],
                        "source_locations": [],
                    }
                ),
                encoding="utf-8",
            )
            tdir = results / "samples/malware_like_synthetic" / sample / "board/trace-on/rep_00/trace_code_map"
            tdir.mkdir(parents=True, exist_ok=True)
            (tdir / "trace_code_map_summary.json").write_text(
                json.dumps(
                    {
                        "schema": "rvmt.trace_code_join.summary.v1",
                        "runtime_process_attribution_proven": True,
                        "process_attributed_code_site_events": 1,
                        "target_attributed_events": 1,
                    }
                ),
                encoding="utf-8",
            )
        summary = build_summary(results)
        if summary["status"] != "PARTIAL":
            print("[FAIL] expected symbol-only fixture to be PARTIAL", file=sys.stderr)
            return 1
        if summary["function_level"]["samples_available"] != len(SAMPLES):
            print("[FAIL] expected function-level availability for every fixture sample", file=sys.stderr)
            return 1
    print("[PASS] 35T source attribution summary self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize 35T function/source-line attribution availability.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    results_root = args.results_root or repo_root / DEFAULT_RESULTS_ROOT
    evidence_root = args.evidence_root or repo_root / DEFAULT_EVIDENCE_ROOT
    try:
        summary = build_summary(results_root.resolve())
        write_outputs(summary, evidence_root.resolve())
    except Exception as exc:
        print(f"summarize_35t_source_attribution: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] 35T source attribution summary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
