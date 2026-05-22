from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rv_maltrace.fd_path_flow import load_semantic_events, recover_fd_path_flow, render_markdown  # noqa: E402


def write_outputs(semantic_events: Path, out_dir: Path, sample: str) -> dict[str, object]:
    syscalls = load_semantic_events(semantic_events)
    summary = recover_fd_path_flow(syscalls, sample=sample)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "fd_path_flow_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    (out_dir / "fd_path_flow_summary.md").write_text(render_markdown(summary), encoding="utf-8", newline="\n")
    return summary


def self_test() -> int:
    synthetic = [
        {
            "seq": 0,
            "name": "openat",
            "process_owner": "target_child",
            "args": {"a0": "0xffffffffffffff9c", "a1": "0x1000", "a1_string": "/tmp/a", "a2": "0x0"},
            "return_value": "0x3",
            "confidence": "paired_target_ecall_return",
        },
        {
            "seq": 1,
            "name": "read",
            "process_owner": "target_child",
            "args": {"a0": "0x3", "a1": "0x2000", "a2": "0x10"},
            "return_value": "0x10",
            "confidence": "paired_target_ecall_return",
        },
        {
            "seq": 2,
            "name": "close",
            "process_owner": "target_child",
            "args": {"a0": "0x3"},
            "return_value": "0x0",
            "confidence": "paired_target_ecall_return",
        },
        {
            "seq": 3,
            "name": "openat",
            "process_owner": "target_child",
            "args": {"a0": "0xffffffffffffff9c", "a1": "0x1100", "a1_string": "/missing"},
            "return_value": "0x00000000fffffffe",
            "confidence": "paired_target_ecall_return",
        },
        {
            "seq": 4,
            "name": "read",
            "process_owner": "target_child",
            "args": {"a0": "0x3", "a1": "0x2000", "a2": "0x10"},
            "return_value": "0x0",
            "confidence": "paired_target_ecall_return",
        },
    ]
    summary = recover_fd_path_flow(synthetic, sample="self-test")
    if summary["status"] != "PARTIAL":
        print("[FAIL] expected closed fd reuse and failed openat to make summary PARTIAL", file=sys.stderr)
        return 1
    if not summary["flows"] or summary["flows"][0]["path"] != "/tmp/a":
        print("[FAIL] missed openat path/fd flow", file=sys.stderr)
        return 1
    if summary["flows"][0].get("status") != "closed" or summary["flows"][0].get("fd_generation") != 1:
        print("[FAIL] missed fd lifetime/generation metadata", file=sys.stderr)
        return 1
    if summary["flows"][0].get("path_source") != "dereferenced_user_string":
        print("[FAIL] missed fd/path source metadata", file=sys.stderr)
        return 1
    if not summary["unresolved_fds"]:
        print("[FAIL] missed fd use after close", file=sys.stderr)
        return 1
    no_path = [
        {
            "seq": 0,
            "name": "openat",
            "process_owner": "target_child",
            "args": {"a0": "0xffffffffffffff9c", "a1": "0x1000"},
            "return_value": "0x3",
            "confidence": "paired_target_ecall_return",
        }
    ]
    partial = recover_fd_path_flow(no_path, sample="no-path")
    if partial["status"] != "PARTIAL" or "pointers are not dereferenced" not in " ".join(partial["limitations"]):
        print("[FAIL] missed path-string unavailable limitation", file=sys.stderr)
        return 1
    print("[PASS] fd/path flow self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Recover fd/path flow summaries from rv-maltrace semantic events.")
    parser.add_argument("--semantic-events", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--sample", default="unknown")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.semantic_events is None or args.out_dir is None:
        parser.error("--semantic-events and --out-dir are required unless --self-test is used")
    try:
        summary = write_outputs(args.semantic_events, args.out_dir, args.sample)
    except Exception as exc:
        print(f"recover_fd_path_flow: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] fd/path flow summary for {args.sample}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
