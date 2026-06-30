from __future__ import annotations

import argparse
import csv
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    load_jsonl,
)

from join_trace_code_map import code_map_index, pc_annotation, parse_int


ROOT = Path(__file__).resolve().parents[1]
RELATED_EVENTS = {"TRAP", "SYSCALL_ENTRY", "SYSCALL_RET", "ECALL", "PRIV", "CSR", "SATP", "UNKNOWN"}


def repo_rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def sample_root(run_id: str, sample_class: str, sample_id: str) -> Path:
    return ROOT / "results" / "experiments" / "35t" / run_id / "samples" / sample_class / sample_id


def related_event(event: dict[str, Any]) -> bool:
    if str(event.get("evt")) in RELATED_EVENTS:
        return True
    if event.get("cause") is not None:
        return True
    if event.get("syscall_id") is not None:
        return True
    return False


def illegal_sites(code_map: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for row in code_map.get("trap_sites", []):
        if not isinstance(row, dict):
            continue
        if row.get("kind") not in {None, "illegal_instruction"}:
            continue
        pc = parse_int(row.get("pc"))
        if pc is None:
            continue
        rows.append({**row, "_pc": pc})
    rows.sort(key=lambda row: int(row["_pc"]))
    return rows


def nearest_site(pc_value: Any, sites: list[dict[str, Any]]) -> dict[str, Any]:
    pc = parse_int(pc_value)
    if pc is None or not sites:
        return {"nearest_illegal_site": None, "nearest_illegal_symbol": None, "pc_delta": None}
    nearest = min(sites, key=lambda row: abs(pc - int(row["_pc"])))
    delta = pc - int(nearest["_pc"])
    return {
        "nearest_illegal_site": f"0x{int(nearest['_pc']):016x}",
        "nearest_illegal_symbol": nearest.get("symbol"),
        "pc_delta": delta,
    }


def parser_warnings(event: dict[str, Any]) -> list[str]:
    warnings = event.get("parser_warnings")
    if isinstance(warnings, list):
        return [str(item) for item in warnings]
    if warnings is None:
        return []
    return [str(warnings)]


def event_row(
    rep: str,
    event_index: int,
    event: dict[str, Any],
    code_map: dict[str, Any],
    code_index: dict[str, Any],
    sites: list[dict[str, Any]],
) -> dict[str, Any]:
    ann = pc_annotation(event.get("pc"), code_map, code_index)
    nearest = nearest_site(event.get("pc"), sites)
    raw_words = event.get("raw_words")
    if not isinstance(raw_words, list):
        raw_words = []
    warnings = parser_warnings(event)
    return {
        "rep": rep,
        "event_index": event_index,
        "record_index": event.get("record_index"),
        "evt": event.get("evt"),
        "evt_code": event.get("evt_code"),
        "pc": event.get("pc"),
        "cause": event.get("cause"),
        "priv": event.get("priv"),
        "raw_header": event.get("raw_header"),
        "code_map_owner": ann.get("pc_owner"),
        "code_confidence": ann.get("code_confidence"),
        "callsite_kind": ann.get("callsite_kind"),
        "symbol": ann.get("symbol"),
        "symbol_offset": ann.get("symbol_offset"),
        **nearest,
        "parser_warnings": warnings,
        "raw_words": [str(item) for item in raw_words],
    }


def is_expected_illegal_hit(row: dict[str, Any]) -> bool:
    return (
        row.get("evt") == "TRAP"
        and row.get("cause") == "0x00000002"
        and row.get("code_map_owner") == "target_sample"
        and row.get("callsite_kind") == "illegal_instruction_site"
    )


def summarize_rep(rows: list[dict[str, Any]]) -> dict[str, Any]:
    trap_rows = [row for row in rows if row.get("evt") == "TRAP"]
    cause2_rows = [row for row in trap_rows if row.get("cause") == "0x00000002"]
    expected_hits = [row for row in rows if is_expected_illegal_hit(row)]
    deltas = [abs(int(row["pc_delta"])) for row in rows if isinstance(row.get("pc_delta"), int)]
    cause2_by_owner: dict[str, int] = {}
    for row in cause2_rows:
        owner = str(row.get("code_map_owner", "unknown"))
        cause2_by_owner[owner] = cause2_by_owner.get(owner, 0) + 1
    return {
        "related_events": len(rows),
        "trap_events": len(trap_rows),
        "cause_0x2_traps": len(cause2_rows),
        "cause_0x2_traps_by_owner": dict(sorted(cause2_by_owner.items())),
        "expected_illegal_instruction_hits": len(expected_hits),
        "min_abs_pc_delta_to_illegal_site": min(deltas) if deltas else None,
        "parser_warning_events": sum(1 for row in rows if row.get("parser_warnings")),
    }


def diagnose(rep_summaries: list[dict[str, Any]]) -> str:
    if rep_summaries and all(int(row.get("expected_illegal_instruction_hits", 0)) > 0 for row in rep_summaries):
        return "MATCHED_EXPECTED_ILLEGAL_INSTRUCTION_SITE_ALL_REPS"
    if any(int(row.get("cause_0x2_traps", 0)) > 0 for row in rep_summaries):
        return "ILLEGAL_CAUSE_PRESENT_WITHOUT_CURRENT_CODE_SITE_MATCH_ALL_REPS"
    return "NO_ILLEGAL_CAUSE_TRAP_IN_RELATED_EVENTS"


def md_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        text = " ".join(str(item) for item in value)
    else:
        text = str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict[str, Any], csv_path: Path, json_path: Path) -> str:
    code_map = report["code_map"]
    lines = [
        "# Trap Attribution Debug",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Sample: `{report['sample_class']}/{report['sample_id']}`",
        f"- Code map: `{code_map.get('path')}`",
        f"- ELF: `{code_map.get('elf')}`",
        f"- Binary role: `{code_map.get('binary_role')}`",
        f"- Runtime path: `{code_map.get('runtime_path')}`",
        f"- Trap sites: `{len(code_map.get('trap_sites', []))}`",
        f"- Diagnosis: `{report['diagnosis']}`",
        f"- Full JSON: `{repo_rel(json_path)}`",
        f"- Full CSV: `{repo_rel(csv_path)}`",
        "",
        "## Per-Rep Summary",
        "",
        "| rep | related | traps | cause=0x2 traps | expected illegal hits | min abs pc delta | parser warning events |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for rep in report["reps"]:
        summary = rep["summary"]
        lines.append(
            f"| `{rep['rep']}` | {summary['related_events']} | {summary['trap_events']} | "
            f"{summary['cause_0x2_traps']} | {summary['expected_illegal_instruction_hits']} | "
            f"{summary['min_abs_pc_delta_to_illegal_site']} | {summary['parser_warning_events']} |"
        )
    lines.extend(
        [
            "",
            "## Related Events",
            "",
            "| rep | idx | rec | evt | pc | cause | priv | owner | callsite | symbol | nearest illegal site | pc_delta | parser warnings | raw_words |",
            "| --- | ---: | ---: | --- | --- | --- | --- | --- | --- | --- | --- | ---: | --- | --- |",
        ]
    )
    for rep in report["reps"]:
        for row in rep["rows"]:
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{md_cell(row.get('rep'))}`",
                        md_cell(row.get("event_index")),
                        md_cell(row.get("record_index")),
                        f"`{md_cell(row.get('evt'))}`",
                        f"`{md_cell(row.get('pc'))}`",
                        f"`{md_cell(row.get('cause'))}`",
                        f"`{md_cell(row.get('priv'))}`",
                        f"`{md_cell(row.get('code_map_owner'))}`",
                        f"`{md_cell(row.get('callsite_kind'))}`",
                        f"`{md_cell(row.get('symbol'))}`",
                        f"`{md_cell(row.get('nearest_illegal_site'))}`",
                        md_cell(row.get("pc_delta")),
                        md_cell(row.get("parser_warnings")),
                        f"`{md_cell(row.get('raw_words'))}`",
                    ]
                )
                + " |"
            )
    lines.append("")
    return "\n".join(lines)


def write_report(run_id: str, sample_class: str, sample_id: str, code_map_path: Path, out_dir: Path) -> dict[str, Path]:
    code_map = load_json(code_map_path)
    code_index = code_map_index(code_map)
    sites = illegal_sites(code_map)
    root = sample_root(run_id, sample_class, sample_id)
    rep_dirs = sorted((root / "board" / "trace-on").glob("rep_*"))
    if not rep_dirs:
        raise ValueError(f"no trace-on rep dirs under {root}")

    reps = []
    rep_summaries = []
    for rep_dir in rep_dirs:
        trace_path = rep_dir / "trace.jsonl"
        events = load_jsonl(trace_path)
        rows = [
            event_row(rep_dir.name, index, event, code_map, code_index, sites)
            for index, event in enumerate(events)
            if related_event(event)
        ]
        summary = summarize_rep(rows)
        rep_summaries.append(summary)
        reps.append(
            {
                "rep": rep_dir.name,
                "trace": repo_rel(trace_path),
                "events_total": len(events),
                "summary": summary,
                "rows": rows,
            }
        )

    report = {
        "schema": "rvmt.trap_attribution_debug.v1",
        "run_id": run_id,
        "sample_class": sample_class,
        "sample_id": sample_id,
        "code_map": {
            "path": repo_rel(code_map_path),
            "elf": code_map.get("elf"),
            "binary_role": code_map.get("binary_role"),
            "runtime_path": code_map.get("runtime_path"),
            "sha256": code_map.get("sha256"),
            "elf_header": code_map.get("elf_header"),
            "trap_sites": [{key: value for key, value in row.items() if key != "_pc"} for row in sites],
        },
        "diagnosis": diagnose(rep_summaries),
        "summary": {
            "reps": len(reps),
            "reps_with_expected_illegal_hits": sum(
                1 for row in rep_summaries if int(row.get("expected_illegal_instruction_hits", 0)) > 0
            ),
            "related_events": sum(int(row.get("related_events", 0)) for row in rep_summaries),
            "trap_events": sum(int(row.get("trap_events", 0)) for row in rep_summaries),
            "cause_0x2_traps": sum(int(row.get("cause_0x2_traps", 0)) for row in rep_summaries),
            "parser_warning_events": sum(int(row.get("parser_warning_events", 0)) for row in rep_summaries),
        },
        "reps": reps,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "trap_attribution_debug.json"
    csv_path = out_dir / "trap_attribution_debug.csv"
    md_path = out_dir / "trap_attribution_debug.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = [
            "rep",
            "event_index",
            "record_index",
            "evt",
            "evt_code",
            "pc",
            "cause",
            "priv",
            "raw_header",
            "code_map_owner",
            "code_confidence",
            "callsite_kind",
            "symbol",
            "symbol_offset",
            "nearest_illegal_site",
            "nearest_illegal_symbol",
            "pc_delta",
            "parser_warnings",
            "raw_words",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for rep in reps:
            for row in rep["rows"]:
                csv_row = dict(row)
                csv_row["parser_warnings"] = ";".join(str(item) for item in row.get("parser_warnings", []))
                csv_row["raw_words"] = " ".join(str(item) for item in row.get("raw_words", []))
                writer.writerow({key: csv_row.get(key) for key in fieldnames})
    md_path.write_text(render_markdown(report, csv_path, json_path), encoding="utf-8", newline="\n")
    return {"json": json_path, "csv": csv_path, "md": md_path}


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        run_id = "self-test-debug"
        sample_class = "malware_like_synthetic"
        sample_id = "illegal_trap"
        root = sample_root(run_id, sample_class, sample_id)
        try:
            rep = root / "board" / "trace-on" / "rep_00"
            rep.mkdir(parents=True)
            trace = [
                {"evt": "SYSCALL_ENTRY", "pc": "0x0000000000010004", "record_index": 0, "raw_words": ["0x1"]},
                {"evt": "TRAP", "pc": "0x0000000000010008", "cause": "0x00000002", "record_index": 1, "raw_words": ["0x2"]},
            ]
            (rep / "trace.jsonl").write_text("".join(json.dumps(row) + "\n" for row in trace), encoding="utf-8")
            code_map = {
                "schema": "rvmt.code_map.v1",
                "sample_id": sample_id,
                "elf": "self.elf",
                "binary_role": "self-test",
                "runtime_path": "/usr/bin/self",
                "load_ranges": [{"start": "0x0000000000010000", "end": "0x0000000000011000"}],
                "sections": [{"name": ".text", "start": "0x0000000000010000", "end": "0x0000000000011000"}],
                "symbols": [{"name": "main", "start": "0x0000000000010000", "end": "0x0000000000010100"}],
                "trap_sites": [{"pc": "0x0000000000010008", "kind": "illegal_instruction", "symbol": "main"}],
                "syscall_sites": [{"pc": "0x0000000000010004", "symbol": "main"}],
            }
            code_map_path = base / "code_map.json"
            code_map_path.write_text(json.dumps(code_map), encoding="utf-8")
            outputs = write_report(run_id, sample_class, sample_id, code_map_path, base / "out")
            report = load_json(outputs["json"])
            if report["diagnosis"] != "MATCHED_EXPECTED_ILLEGAL_INSTRUCTION_SITE_ALL_REPS":
                print("[FAIL] debug_trap_attribution missed expected illegal hit", file=sys.stderr)
                return 1
        finally:
            shutil.rmtree(ROOT / "results" / "experiments" / "35t" / run_id, ignore_errors=True)
    print("[PASS] debug_trap_attribution self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate per-rep trap/syscall/priv attribution debug artifacts.")
    parser.add_argument("--run-id", default="35t-p0c-abba-r512-20260520-com5")
    parser.add_argument("--sample-class", default="malware_like_synthetic")
    parser.add_argument("--sample-id", default="illegal_trap")
    parser.add_argument("--code-map", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = sample_root(args.run_id, args.sample_class, args.sample_id)
    code_map = args.code_map or (root / "build" / f"{args.sample_id}.code_map.json")
    out_dir = args.out_dir or (root / "aggregate" / "trap_attribution_debug")
    try:
        outputs = write_report(args.run_id, args.sample_class, args.sample_id, code_map, out_dir)
    except Exception as exc:
        print(f"debug_trap_attribution: error: {exc}", file=sys.stderr)
        return 2
    print(f"[PASS] trap attribution debug written: {outputs['md']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
