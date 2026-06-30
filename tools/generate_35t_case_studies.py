from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULT_ROOT = Path("results/experiments/35t")
DEFAULT_SAMPLES = ("illegal_trap", "anti_debug_like", "dynamic_executable_memory")


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def load_jsonl(path: Path, limit: int) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rows.append(json.loads(line))
        if len(rows) >= limit:
            break
    return rows


def repo_rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def find_sample_root(run_root: Path, sample_id: str) -> Path:
    matches = list((run_root / "samples").glob(f"*/*"))
    for path in matches:
        if path.name == sample_id:
            return path
    raise FileNotFoundError(f"sample not found in run: {sample_id}")


def write_case_study(run_root: Path, sample_id: str, limit: int) -> None:
    sample_root = find_sample_root(run_root, sample_id)
    rep_dir = next(iter(sorted((sample_root / "board" / "trace-on").glob("rep_*"))), None)
    if rep_dir is None:
        raise FileNotFoundError(f"{sample_id}: no trace-on rep found")
    trace_path = rep_dir / "trace.jsonl"
    semantic_path = rep_dir / "behavior_recovery" / "semantic_events.json"
    graph_path = rep_dir / "behavior_recovery" / "behavior_graph.json"
    audit_path = rep_dir / "behavior_audit" / "behavior_audit.json"
    alignment_path = rep_dir / "alignment" / "alignment.json"
    status_path = rep_dir / "status.json"
    out = run_root / "case_studies" / sample_id
    out.mkdir(parents=True, exist_ok=True)

    trace_excerpt = load_jsonl(trace_path, limit)
    semantic = load_json(semantic_path)
    graph = load_json(graph_path)
    audit = load_json(audit_path)
    alignment = load_json(alignment_path) if alignment_path.exists() else {}
    status = load_json(status_path) if status_path.exists() else {}

    semantic_excerpt = {
        "schema": semantic.get("schema"),
        "source": semantic.get("source"),
        "syscall_sequence": semantic.get("syscall_sequence", [])[:limit],
        "trap_context_transitions": semantic.get("trap_context_transitions", [])[:limit],
    }
    graph_excerpt = {
        "schema": graph.get("schema"),
        "nodes": graph.get("nodes", [])[:limit],
        "edges": graph.get("edges", [])[:limit],
    }
    (out / "trace_excerpt.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in trace_excerpt),
        encoding="utf-8",
        newline="\n",
    )
    (out / "semantic_excerpt.json").write_text(json.dumps(semantic_excerpt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "behavior_graph_excerpt.json").write_text(json.dumps(graph_excerpt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    matched = audit.get("matched_expected_behavior", [])
    missing = audit.get("missing_expected_behavior", [])
    lines = [
        f"# 35T Case Study: {sample_id}",
        "",
        f"- Run: `{run_root.name}`",
        f"- Source rep: `{repo_rel(rep_dir)}`",
        f"- Trace excerpt: `{repo_rel(out / 'trace_excerpt.jsonl')}`",
        f"- Semantic excerpt: `{repo_rel(out / 'semantic_excerpt.json')}`",
        f"- Behavior graph excerpt: `{repo_rel(out / 'behavior_graph_excerpt.json')}`",
        f"- Trace records referenced: first {len(trace_excerpt)} records from `{repo_rel(trace_path)}`.",
        f"- Semantic syscall/trap records referenced: first {limit} recovered rows from `{repo_rel(semantic_path)}`.",
        "",
        "## Audit",
        "",
        f"- Matched expected: {', '.join(matched) if matched else 'none'}",
        f"- Missing expected: {', '.join(missing) if missing else 'none'}",
        "",
        "## Limitations",
        "",
        f"- DROP count: {status.get('drop', 'unknown')}",
        f"- Captured trace count: {status.get('trace_count', 'unknown')}",
        f"- Alignment recall: {alignment.get('syscall_family_recall', 'unknown')}",
        f"- Pointer semantics may be missing unless the selected profile explicitly enabled and gated `ARG_MEM`.",
        "- This is 35T/VexRiscv synthetic behavior evidence only; it is not a CVA6 board result or a real malware detection claim.",
        "",
    ]
    (out / "case_study.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate 35T case-study excerpts from an experiment run.")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--root", type=Path, default=DEFAULT_RESULT_ROOT)
    parser.add_argument("--sample", action="append")
    parser.add_argument("--limit", type=int, default=24)
    args = parser.parse_args(argv)
    run_root = resolve(args.root) / args.run_id
    gate = run_root / "aggregate" / "gate_report.json"
    if gate.exists():
        claim = load_json(gate).get("claim_level")
        if claim == "prototype_only":
            print("generate_35t_case_studies: gate claim_level is prototype_only; refusing case-study promotion", file=sys.stderr)
            return 1
    for sample in args.sample or list(DEFAULT_SAMPLES):
        write_case_study(run_root, sample, args.limit)
    print(f"[PASS] 35T case studies written under {run_root / 'case_studies'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
