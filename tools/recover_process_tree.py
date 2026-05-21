from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rv_maltrace.process_tree import load_semantic_events, recover_process_tree, render_markdown  # noqa: E402


def write_outputs(semantic_events: Path, out_dir: Path, sample: str) -> dict[str, object]:
    syscalls = load_semantic_events(semantic_events)
    summary = recover_process_tree(syscalls, sample=sample)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "process_tree_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (out_dir / "process_tree_summary.md").write_text(render_markdown(summary), encoding="utf-8", newline="\n")
    return summary


def self_test() -> int:
    complete = [
        {
            "seq": 0,
            "name": "clone",
            "process_owner": "target_child",
            "args": {"a0": "0x11"},
            "return_value": "0x7b",
            "confidence": "paired_target_ecall_return",
        },
        {
            "seq": 1,
            "name": "execve",
            "process_owner": "target_child",
            "args": {"a0": "0x1000", "a0_string": "/usr/bin/child"},
            "return_value": None,
            "confidence": "target_ecall_boundary",
        },
        {
            "seq": 2,
            "name": "waitid",
            "process_owner": "target_child",
            "args": {"a0": "0x1", "a1": "0x7b"},
            "return_value": "0x0",
            "confidence": "paired_target_ecall_return",
        },
    ]
    summary = recover_process_tree(complete, sample="self-test")
    if summary["status"] != "PASS":
        print("[FAIL] expected complete process-tree fixture to pass", file=sys.stderr)
        print(json.dumps(summary, indent=2), file=sys.stderr)
        return 1
    partial = recover_process_tree([{**complete[0], "return_value": "0x0"}, complete[1], complete[2]], sample="partial")
    if partial["status"] != "PARTIAL" or not partial["limitations"]:
        print("[FAIL] expected missing clone return PID fixture to be partial", file=sys.stderr)
        return 1
    print("[PASS] process tree self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Recover process-tree summaries from rv-maltrace semantic events.")
    parser.add_argument("--semantic-events", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--sample", default="process_chain")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.semantic_events is None or args.out_dir is None:
        parser.error("--semantic-events and --out-dir are required unless --self-test is used")
    try:
        summary = write_outputs(args.semantic_events, args.out_dir, args.sample)
    except Exception as exc:
        print(f"recover_process_tree: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] process tree summary for {args.sample}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
