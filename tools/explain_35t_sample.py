from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rv_maltrace.explain import (  # noqa: E402
    build_explanation,
    build_process_view,
    load_run_artifacts,
    load_sample_artifacts,
    render_console,
    render_markdown,
    render_process_console,
    render_process_markdown,
)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8", newline="\n")


def write_self_test_fixture(root: Path) -> None:
    run = root / "results/experiments/35t/self-test"
    rep = run / "samples/malware_like_synthetic/file_scan/board/trace-on/rep_00"
    write_json(run / "run_config.json", {"run_id": "self-test", "trace_records": 512, "real_malware": "forbidden", "network": "disabled"})
    write_json(
        run / "aggregate/gate_report.json",
        {
            "schema": "rvmt.35t.gate_report.v1",
            "run_id": "self-test",
            "trace_records": 512,
            "samples": [
                {
                    "sample_id": "file_scan",
                    "sample_class": "malware_like_synthetic",
                    "gate_status": "PASS",
                    "sample_status": {"status": "PASS"},
                    "marker_scope_summary": {"reps": [{"rep": "rep_00", "status": "PASS"}]},
                    "runtime_process_attribution_summary": {"reps": [{"rep": "rep_00", "status": "PASS"}]},
                    "drop_summary": {"capped_reps": []},
                }
            ],
        },
    )
    write_json(run / "aggregate/metrics.json", {"schema": "rvmt.35t.metrics.v1", "samples": []})
    write_json(
        root / "experiments/linux_behavior/malware_like/manifest.json",
        {
            "sample_class": "malware_like_synthetic",
            "samples": [{"id": "file_scan", "class": "malware_like_synthetic", "real_malware": False}],
        },
    )
    write_json(
        root / "experiments/linux_behavior/behavior_audit_rules.json",
        {
            "rules": [
                {
                    "id": "many_file_scan",
                    "expected_syscalls": ["openat", "getdents64", "close"],
                    "evidence": "directory scan syscall shape",
                }
            ]
        },
    )
    write_jsonl(
        rep / "trace.jsonl",
        [
            {"evt": "MARKER", "record_index": 0, "value": "0xb0000000"},
            {"evt": "SYSCALL_ENTRY", "index": 1, "name": "openat"},
            {"evt": "SYSCALL_ENTRY", "index": 2, "name": "getdents64"},
            {"evt": "SYSCALL_ENTRY", "index": 3, "name": "getdents64"},
            {"evt": "SYSCALL_ENTRY", "index": 4, "name": "close"},
            {"evt": "MARKER", "record_index": 5, "value": "0xe0000000"},
        ],
    )
    write_json(
        rep / "behavior_recovery/semantic_events.json",
        {
            "schema": "rvmt.behavior.semantic.v1",
            "status": "DERIVED",
            "marker_scope": {"status": "PASS"},
            "syscall_sequence": [
                {"index": 1, "name": "openat", "args": {"a1_string": "fixtures/scan_root"}, "process_owner": "target_child"},
                {"index": 2, "name": "getdents64", "process_owner": "target_child"},
                {"index": 3, "name": "getdents64", "process_owner": "target_child"},
                {"index": 4, "name": "close", "process_owner": "target_child"},
            ],
        },
    )
    write_json(rep / "behavior_recovery/behavior_graph.json", {"schema": "rvmt.behavior.graph.v1", "nodes": [{"id": "trace"}], "edges": []})
    write_json(
        rep / "behavior_audit/behavior_audit.json",
        {
            "schema": "rvmt.behavior.audit.v1",
            "sample_id": "file_scan",
            "status": "DERIVED_AUDIT",
            "expected_behavior": ["many_file_scan"],
            "matched_expected_behavior": ["many_file_scan"],
            "missing_expected_behavior": [],
            "unexpected_matched_behavior": [],
            "weak_matched_behavior": [],
            "weak_matched_expected_behavior": [],
            "all_expected_matched": True,
            "matches": [
                {
                    "rule": "many_file_scan",
                    "description": "repeated directory scan behavior",
                    "matched": True,
                    "evidence_strength": "strong",
                }
            ],
        },
    )
    write_json(rep / "alignment/alignment.json", {"schema": "rvmt.35t.alignment.v1", "captured_events": 6, "drop_count": 0, "drop_rate": 0.0})
    write_json(rep / "runtime_process_map.json", {"schema": "rvmt.runtime_process_map.v1", "status": "PASS"})
    write_json(rep / "trace_code_map/trace_code_map_summary.json", {"schema": "rvmt.trace_code_join.summary.v1", "attribution_model": "marker_scoped_runtime_map_code_site"})
    write_json(rep / "status.json", {"status": "PASS", "trace_count": 6})
    write_json(rep / "parser_warnings.json", {"schema": "rvmt.trace.parser_warnings.v1", "unknown_event_count": 0, "corrupt_record_count": 0})


def run_self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_self_test_fixture(root)
        artifacts = load_sample_artifacts(root, "self-test", "file_scan", "auto")
        explanation = build_explanation(artifacts, strict=True)
        if explanation["schema"] != "rvmt.35t.sample_explanation.v1":
            print("[FAIL] unexpected explanation schema", file=sys.stderr)
            return 1
        if explanation["rep"] != "rep_00":
            print("[FAIL] auto rep did not select rep_00", file=sys.stderr)
            return 1
        if not explanation["suspicious_points"]:
            print("[FAIL] missing suspicious point", file=sys.stderr)
            return 1
        text = render_console(explanation)
        if "RV-MalTrace 35T Explanation" not in text or "many_file_scan" not in text:
            print("[FAIL] console renderer omitted expected content", file=sys.stderr)
            return 1
        markdown = render_markdown(explanation)
        if "Suspicious Cues" not in markdown:
            print("[FAIL] markdown renderer omitted expected content", file=sys.stderr)
            return 1
        process_view = build_process_view(load_run_artifacts(root, "self-test"))
        if process_view["schema"] != "rvmt.35t.process_view.v1":
            print("[FAIL] unexpected process view schema", file=sys.stderr)
            return 1
        if not process_view.get("captured_key_information"):
            print("[FAIL] process view omitted captured key information", file=sys.stderr)
            return 1
        process_text = render_process_console(process_view)
        if "RV-MalTrace 35T Process" not in process_text or "Key captures" not in process_text:
            print("[FAIL] process renderer omitted expected content", file=sys.stderr)
            return 1
    print("[PASS] 35T explain interface self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explain a 35T sample trace in the terminal.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--run-id", required=False)
    parser.add_argument("--sample", required=False)
    parser.add_argument("--rep", default="auto")
    parser.add_argument("--format", choices=("console", "json", "markdown"), default="console")
    parser.add_argument("--out")
    parser.add_argument("--tee-out")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--flow", action="store_true")
    parser.add_argument("--detail", choices=("compact", "full"), default="compact")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()
    if not args.run_id:
        parser.error("--run-id is required unless --self-test is used")
    if not args.flow and not args.sample:
        parser.error("--sample is required unless --flow or --self-test is used")

    try:
        if args.flow:
            view = build_process_view(load_run_artifacts(args.repo_root, args.run_id), strict=args.strict)
            if args.format == "json":
                text = json.dumps(view, indent=2, sort_keys=True) + "\n"
            elif args.format == "markdown":
                text = render_process_markdown(view)
            else:
                text = render_process_console(view, detail=args.detail)
        else:
            artifacts = load_sample_artifacts(args.repo_root, args.run_id, args.sample, args.rep)
            explanation = build_explanation(artifacts, strict=args.strict)
            if args.format == "json":
                text = json.dumps(explanation, indent=2, sort_keys=True) + "\n"
            elif args.format == "markdown":
                text = render_markdown(explanation)
            else:
                text = render_console(explanation)
    except Exception as exc:
        print(f"explain_35t_sample: error: {exc}", file=sys.stderr)
        return 2

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
        return 0

    print(text, end="")
    if args.tee_out:
        Path(args.tee_out).write_text(text, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
