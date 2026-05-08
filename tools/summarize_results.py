from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from parse_trace import load_trace, summarize


NON_FAILING_STATUSES = {"PASS", "BLOCKED"}


def compare_status(path: Path) -> str:
    if not path.exists():
        return "MISSING"
    text = path.read_text(encoding="utf-8", errors="replace")
    if "[BLOCKED]" in text:
        return "BLOCKED"
    if "[FAIL]" in text:
        return "FAIL"
    if "[PASS]" in text:
        return "PASS"
    return "UNKNOWN"


def load_expected_metadata(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def collect(result_dir: Path) -> dict[str, Any]:
    tests: dict[str, Any] = {}
    expected_dir = Path("sim/golden")
    discovered_tests = sorted(path.name for path in result_dir.iterdir() if path.is_dir()) if result_dir.exists() else []
    expected_files = {
        path.stem.removesuffix(".expected"): path
        for path in expected_dir.glob("*.expected.json")
    }
    expected_metadata = {
        name: load_expected_metadata(path)
        for name, path in expected_files.items()
    }
    expected_tests = sorted(
        name
        for name in expected_files
        if not (expected_metadata[name].get("summary_optional") and name not in discovered_tests)
    )
    test_names = sorted(set(expected_tests) | set(discovered_tests))

    for test_name in test_names:
        test_dir = result_dir / test_name
        trace_path = test_dir / "trace.jsonl"
        compare_log = test_dir / "compare.log"
        metadata = expected_metadata.get(test_name, {})
        trace_summary: dict[str, Any] = {"events": 0, "counts": {}}
        status = "MISSING"
        if test_dir.exists():
            status = compare_status(compare_log)
        if test_dir.exists() and trace_path.exists():
            try:
                trace_summary = summarize(load_trace(trace_path))
            except Exception as exc:
                trace_summary = {"events": 0, "counts": {}, "error": str(exc)}
                status = "FAIL"
        else:
            status = "MISSING"
        if trace_summary.get("events", 0) == 0:
            status = "FAIL" if status == "PASS" else status
        tests[test_name] = {
            "status": status,
            "trace": str(trace_path),
            "compare_log": str(compare_log),
            "note": metadata.get("summary_note", ""),
            **trace_summary,
        }
    if tests and all(item["status"] == "PASS" for item in tests.values()):
        overall = "PASS"
    elif tests and all(item["status"] in NON_FAILING_STATUSES for item in tests.values()):
        overall = "PASS_WITH_BLOCKED"
    else:
        overall = "FAIL"
    return {"overall": overall, "tests": tests}


def print_table(payload: dict[str, Any]) -> None:
    print(f"overall: {payload['overall']}")
    print("test,status,events,retire,branch,jump,ecall,trap,csr,satp,priv,drop")
    for name, item in payload["tests"].items():
        counts = item.get("counts", {})
        print(
            ",".join(
                [
                    name,
                    item["status"],
                    str(item.get("events", 0)),
                    str(counts.get("RETIRE", 0)),
                    str(counts.get("BRANCH", 0)),
                    str(counts.get("JUMP", 0)),
                    str(counts.get("ECALL", 0)),
                    str(counts.get("TRAP", 0)),
                    str(counts.get("CSR", 0)),
                    str(counts.get("SATP", 0)),
                    str(counts.get("PRIV", 0)),
                    str(counts.get("DROP", 0)),
                ]
            )
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize rv-maltrace simulation results.")
    parser.add_argument("result_dir", type=Path, nargs="?", default=Path("results/vivado_sim"))
    parser.add_argument("--out", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        payload = collect(args.result_dir)
    except Exception as exc:
        print(f"summarize_results: error: {exc}", file=sys.stderr)
        return 2

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.json:
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print_table(payload)
    return 0 if payload["overall"] in {"PASS", "PASS_WITH_BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
