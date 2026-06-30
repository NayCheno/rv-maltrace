from __future__ import annotations

import argparse
import html
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
)


NON_CLAIM = "This is synthetic behavior audit evidence, not malware detection quality evidence."


def load_trace(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            events.append(value)
    return events


def manifest_sample(manifest: dict[str, Any], sample_id: str) -> dict[str, Any]:
    samples = manifest.get("samples", [])
    if not isinstance(samples, list):
        return {}
    for sample in samples:
        if isinstance(sample, dict) and sample.get("id") == sample_id:
            return sample
    return {}


def matched_rules(audit: dict[str, Any]) -> list[str]:
    expected = audit.get("matched_expected_behavior")
    if isinstance(expected, list):
        return [str(item) for item in expected]
    matches = audit.get("matches", [])
    if not isinstance(matches, list):
        return []
    return [str(item.get("rule")) for item in matches if isinstance(item, dict) and item.get("matched")]


def weak_matched_rules(audit: dict[str, Any]) -> list[str]:
    expected = audit.get("weak_matched_expected_behavior")
    if isinstance(expected, list):
        return [str(item) for item in expected]
    weak = audit.get("weak_expected_behavior")
    if isinstance(weak, list):
        return [str(item) for item in weak]
    return []


def render_timeline(trace: list[dict[str, Any]], semantic: dict[str, Any], sample_id: str) -> str:
    rows = []
    for index, event in enumerate(trace):
        evt = html.escape(str(event.get("evt", "UNKNOWN")))
        cycle = html.escape(str(event.get("cycle", "")))
        pc = html.escape(str(event.get("pc", "")))
        detail_parts = []
        for key in ("a7", "target", "cause", "priv", "old_priv", "new_priv"):
            if key in event:
                detail_parts.append(f"{key}={event[key]}")
        rows.append(
            "<tr>"
            f"<td>{index}</td><td>{cycle}</td><td>{evt}</td><td><code>{pc}</code></td>"
            f"<td><code>{html.escape(', '.join(detail_parts))}</code></td>"
            "</tr>"
        )
    syscall_count = len(semantic.get("syscall_sequence", []) if isinstance(semantic.get("syscall_sequence"), list) else [])
    return "\n".join(
        [
            "<!doctype html>",
            "<html><head><meta charset=\"utf-8\"><title>RV-MalTrace Timeline</title>",
            "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#17202a}"
            "table{border-collapse:collapse;width:100%}td,th{border:1px solid #d5d8dc;padding:6px}"
            "th{background:#edf2f7}code{font-size:12px}.note{color:#566573}</style></head><body>",
            f"<h1>Behavior Timeline: {html.escape(sample_id)}</h1>",
            f"<p class=\"note\">{html.escape(NON_CLAIM)}</p>",
            f"<p>Input trace events: {len(trace)}. Recovered syscalls: {syscall_count}.</p>",
            "<table><thead><tr><th>#</th><th>Cycle</th><th>Event</th><th>PC</th><th>Details</th></tr></thead><tbody>",
            *rows,
            "</tbody></table></body></html>",
            "",
        ]
    )


def render_graph(graph: dict[str, Any], sample_id: str) -> str:
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    if not isinstance(nodes, list):
        nodes = []
    if not isinstance(edges, list):
        edges = []
    node_rows = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_rows.append(
            "<tr>"
            f"<td><code>{html.escape(str(node.get('id', '')))}</code></td>"
            f"<td>{html.escape(str(node.get('kind', '')))}</td>"
            f"<td>{html.escape(str(node.get('label', '')))}</td>"
            "</tr>"
        )
    edge_rows = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        edge_rows.append(
            "<tr>"
            f"<td><code>{html.escape(str(edge.get('source', '')))}</code></td>"
            f"<td>{html.escape(str(edge.get('kind', '')))}</td>"
            f"<td><code>{html.escape(str(edge.get('target', '')))}</code></td>"
            "</tr>"
        )
    return "\n".join(
        [
            "<!doctype html>",
            "<html><head><meta charset=\"utf-8\"><title>RV-MalTrace Behavior Graph</title>",
            "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#17202a}"
            "table{border-collapse:collapse;width:100%;margin-bottom:20px}td,th{border:1px solid #d5d8dc;padding:6px}"
            "th{background:#edf2f7}code{font-size:12px}.note{color:#566573}</style></head><body>",
            f"<h1>Behavior Graph: {html.escape(sample_id)}</h1>",
            f"<p class=\"note\">{html.escape(NON_CLAIM)}</p>",
            f"<p>Nodes: {len(nodes)}. Edges: {len(edges)}.</p>",
            "<h2>Nodes</h2><table><thead><tr><th>ID</th><th>Kind</th><th>Label</th></tr></thead><tbody>",
            *node_rows,
            "</tbody></table>",
            "<h2>Edges</h2><table><thead><tr><th>Source</th><th>Kind</th><th>Target</th></tr></thead><tbody>",
            *edge_rows,
            "</tbody></table></body></html>",
            "",
        ]
    )


def render_scorecard(sample_id: str, sample: dict[str, Any], audit: dict[str, Any]) -> str:
    rules = matched_rules(audit)
    weak_rules = weak_matched_rules(audit)
    displayed_rules = rules or weak_rules
    matched_text = ", ".join(displayed_rules) if displayed_rules else "none"
    evidence_strength = "strong" if rules else ("weak" if weak_rules else "none")
    expected = sample.get("expected_behavior", audit.get("expected_behavior", []))
    if not isinstance(expected, list):
        expected = []
    lines = [
        "# RV-MalTrace Behavior Audit Scorecard",
        "",
        f"Sample: {sample_id}",
        f"Class: {sample.get('class', 'unknown')}",
        f"Real malware: {str(sample.get('real_malware', False)).lower()}",
        "",
        f"Matched malware-like behavior rule: {matched_text}",
        f"Evidence strength: {evidence_strength}",
        "",
        "## Expected behavior rules",
        "",
    ]
    if expected:
        lines.extend(f"- {item}" for item in expected)
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Audit Summary",
            "",
            f"- All expected matched: {audit.get('all_expected_matched')}",
            f"- Warnings: {', '.join(audit.get('warnings') or ['none'])}",
            "",
            "## Rule Evidence",
            "",
            "| Rule | Family | Matched | Missing |",
            "| --- | --- | --- | --- |",
        ]
    )
    matches = audit.get("matches", [])
    if isinstance(matches, list):
        for item in matches:
            if not isinstance(item, dict):
                continue
            missing = (
                item.get("missing")
                or item.get("count_failures")
                or item.get("sequence_failures")
                or item.get("missing_trap_causes")
                or item.get("arg_failures")
                or []
            )
            lines.append(
                f"| `{item.get('rule')}` | {item.get('family')} | {item.get('matched')} | "
                f"{', '.join(str(value) for value in missing) if missing else 'none'} |"
            )
    lines.extend(["", "## Non-Claim", "", NON_CLAIM, ""])
    return "\n".join(lines)


def write_outputs(
    trace_path: Path,
    semantic_path: Path,
    graph_path: Path,
    audit_path: Path,
    manifest_path: Path,
    sample_id: str,
    out_dir: Path,
) -> None:
    trace = load_trace(trace_path)
    semantic = load_json(semantic_path)
    graph = load_json(graph_path)
    audit = load_json(audit_path)
    manifest = load_json(manifest_path)
    sample = manifest_sample(manifest, sample_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "timeline.html").write_text(render_timeline(trace, semantic, sample_id), encoding="utf-8", newline="\n")
    (out_dir / "graph.html").write_text(render_graph(graph, sample_id), encoding="utf-8", newline="\n")
    (out_dir / "scorecard.md").write_text(render_scorecard(sample_id, sample, audit), encoding="utf-8", newline="\n")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        trace_path = root / "trace.jsonl"
        semantic_path = root / "semantic_events.json"
        graph_path = root / "behavior_graph.json"
        audit_path = root / "behavior_audit.json"
        manifest_path = root / "manifest.json"
        out_dir = root / "visual"
        trace_path.write_text(
            '{"cycle":1,"evt":"SYSCALL_ENTRY","pc":"0x1000","a7":"0x75","priv":"U"}\n',
            encoding="utf-8",
        )
        semantic_path.write_text(
            json.dumps({"schema": "rvmt.behavior.semantic.v1", "syscall_sequence": [{"name": "ptrace"}]}),
            encoding="utf-8",
        )
        graph_path.write_text(
            json.dumps({"schema": "rvmt.behavior.graph.v1", "nodes": [{"id": "trace", "kind": "trace"}], "edges": []}),
            encoding="utf-8",
        )
        audit_path.write_text(
            json.dumps(
                {
                    "all_expected_matched": True,
                    "matched_expected_behavior": ["anti_analysis_indicator"],
                    "matches": [{"rule": "anti_analysis_indicator", "family": "anti_analysis", "matched": True}],
                    "warnings": [],
                }
            ),
            encoding="utf-8",
        )
        manifest_path.write_text(
            json.dumps(
                {
                    "samples": [
                        {
                            "id": "anti_debug_like",
                            "class": "malware_like_synthetic",
                            "real_malware": False,
                            "expected_behavior": ["anti_analysis_indicator"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        write_outputs(trace_path, semantic_path, graph_path, audit_path, manifest_path, "anti_debug_like", out_dir)
        scorecard = (out_dir / "scorecard.md").read_text(encoding="utf-8")
        if "Matched malware-like behavior rule: anti_analysis_indicator" not in scorecard:
            print("[FAIL] self-test missed scorecard matched rule", file=sys.stderr)
            return 1
        combined = "\n".join((out_dir / name).read_text(encoding="utf-8") for name in ("timeline.html", "graph.html", "scorecard.md"))
        if "malware detected: yes" in combined.lower():
            print("[FAIL] self-test emitted forbidden detection claim", file=sys.stderr)
            return 1
        if "not malware detection quality evidence" not in combined:
            print("[FAIL] self-test missed non-claim text", file=sys.stderr)
            return 1
    print("[PASS] behavior demo render self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render static RV-MalTrace behavior demo artifacts.")
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--semantic", type=Path)
    parser.add_argument("--graph", type=Path)
    parser.add_argument("--audit", type=Path)
    parser.add_argument("--manifest", type=Path, default=Path("experiments/linux_behavior/malware_like/manifest.json"))
    parser.add_argument("--sample-id")
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    required = (args.trace, args.semantic, args.graph, args.audit, args.sample_id, args.out_dir)
    if any(value is None for value in required):
        parser.error("--trace, --semantic, --graph, --audit, --sample-id, and --out-dir are required unless --self-test is used")
    try:
        write_outputs(args.trace, args.semantic, args.graph, args.audit, args.manifest, args.sample_id, args.out_dir)
    except Exception as exc:
        print(f"render_behavior_demo: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
