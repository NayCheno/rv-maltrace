from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rv_maltrace.trace_profiles import allowed_events_for_profile, profile_names  # noqa: E402


DEFAULT_RESULT_ROOT = Path("results/experiments/35t")
BENIGN_MANIFEST = Path("experiments/linux_behavior/benign/manifest.json")
MALWARE_MANIFEST = Path("experiments/linux_behavior/malware_like/manifest.json")
TRACE_ON = "trace-on"
TRACE_OFF = "trace-off"


@dataclass(frozen=True)
class SampleRef:
    sample_class: str
    sample_id: str
    expected_behavior: tuple[str, ...]


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def repo_rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def median(values: Iterable[float]) -> float | None:
    rows = list(values)
    return statistics.median(rows) if rows else None


def load_samples(selectors: Iterable[str]) -> list[SampleRef]:
    wanted = {item for item in selectors if item}
    result: list[SampleRef] = []
    benign = load_json(resolve(BENIGN_MANIFEST))
    malware = load_json(resolve(MALWARE_MANIFEST))
    for row in benign.get("samples", []):
        if not isinstance(row, dict) or row.get("default_enabled") is not True or row.get("network_required"):
            continue
        result.append(SampleRef("benign", str(row["id"]), tuple(str(item) for item in row.get("expected_behavior", []))))
    for row in malware.get("samples", []):
        if not isinstance(row, dict):
            continue
        result.append(
            SampleRef(
                "malware_like_synthetic",
                str(row["id"]),
                tuple(str(item) for item in row.get("expected_behavior", [])),
            )
        )
    if not wanted:
        return result
    selected = [sample for sample in result if sample.sample_id in wanted or sample.sample_class in wanted]
    found = {sample.sample_id for sample in selected} | {sample.sample_class for sample in selected}
    missing = sorted(wanted - found)
    if missing:
        raise ValueError(f"unknown sample selectors: {', '.join(missing)}")
    return selected


def sample_dir(run_root: Path, sample: SampleRef) -> Path:
    return run_root / "samples" / sample.sample_class / sample.sample_id


def status_rows(root: Path, mode: str) -> list[dict[str, Any]]:
    rows = []
    for status_path in sorted((root / "board" / mode).glob("rep_*/status.json")):
        row = load_json(status_path)
        row["_path"] = repo_rel(status_path)
        rows.append(row)
    return rows


def event_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        evt = str(event.get("evt", "NONE"))
        counts[evt] = counts.get(evt, 0) + 1
    return dict(sorted(counts.items()))


def merge_counts(rows: Iterable[dict[str, int]]) -> dict[str, int]:
    merged: dict[str, int] = {}
    for row in rows:
        for key, value in row.items():
            merged[key] = merged.get(key, 0) + int(value)
    return dict(sorted(merged.items()))


def trace_summaries(root: Path, trace_records: int | None) -> list[dict[str, Any]]:
    summaries = []
    for rep_dir in sorted((root / "board" / TRACE_ON).glob("rep_*")):
        trace_path = rep_dir / "trace.jsonl"
        status_path = rep_dir / "status.json"
        status = load_json(status_path) if status_path.exists() else {}
        events = load_jsonl(trace_path)
        captured = len(events)
        drop = int(status.get("drop", 0) or 0)
        summaries.append(
            {
                "rep": rep_dir.name,
                "status": status.get("status", "MISSING"),
                "captured_events": captured,
                "drop": drop,
                "drop_rate": drop / (drop + captured) if drop + captured else 0.0,
                "capped_at_trace_records": bool(trace_records is not None and captured == trace_records),
                "event_counts": event_counts(events),
                "trace": repo_rel(trace_path),
            }
        )
    return summaries


def load_alignments(root: Path) -> list[dict[str, Any]]:
    return [load_json(path) for path in sorted((root / "board" / TRACE_ON).glob("rep_*/alignment/alignment.json"))]


def load_audits(root: Path) -> list[dict[str, Any]]:
    return [load_json(path) for path in sorted((root / "board" / TRACE_ON).glob("rep_*/behavior_audit/behavior_audit.json"))]


def sample_status(root: Path, reps: int) -> dict[str, Any]:
    gt_status = load_json(root / "groundtruth" / "status.json") if (root / "groundtruth" / "status.json").exists() else {"status": "MISSING"}
    on_rows = status_rows(root, TRACE_ON)
    off_rows = status_rows(root, TRACE_OFF)
    failures = []
    if gt_status.get("status") != "PASS":
        failures.append("groundtruth")
    if sum(1 for row in on_rows if row.get("status") == "PASS") < reps:
        failures.append("trace-on")
    if sum(1 for row in off_rows if row.get("status") == "PASS") < reps:
        failures.append("trace-off")
    if not list((root / "board" / TRACE_ON).glob("rep_*/trace.jsonl")):
        failures.append("trace-jsonl")
    return {
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "groundtruth": gt_status.get("status", "MISSING"),
        "trace_on_pass": sum(1 for row in on_rows if row.get("status") == "PASS"),
        "trace_off_pass": sum(1 for row in off_rows if row.get("status") == "PASS"),
    }


def alignment_summary(rows: list[dict[str, Any]], trace_rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "precision_median": median(float(row.get("syscall_family_precision", 0.0)) for row in rows),
        "recall_median": median(float(row.get("syscall_family_recall", 0.0)) for row in rows),
        "ordered_lcs_median": median(float(row.get("ordered_lcs", 0.0)) for row in rows),
        "ordered_lcs_ratio_median": median(float(row.get("ordered_lcs_ratio", 0.0)) for row in rows),
        "paired_return_ratio_median": median(float(row.get("paired_return_ratio", 0.0)) for row in rows),
        "return_sign_match_ratio_median": median(float(row.get("return_sign_match_ratio", 0.0)) for row in rows),
        "argument_accuracy_median": median(
            float(row["argument_accuracy_ratio"]) for row in rows if row.get("argument_accuracy_ratio") is not None
        ),
        "drop_rate_median": median(float(row.get("drop_rate", trace.get("drop_rate", 0.0))) for row, trace in zip(rows, trace_rows)),
    }


def audit_rule_summary(sample: SampleRef, audits: list[dict[str, Any]]) -> dict[str, Any]:
    expected = set(sample.expected_behavior) if sample.sample_class == "malware_like_synthetic" else set()
    matched: set[str] = set()
    missing_by_rule: dict[str, list[str]] = {}
    for audit in audits:
        for item in audit.get("matches", []):
            if not isinstance(item, dict):
                continue
            rule = str(item.get("rule"))
            if item.get("matched"):
                matched.add(rule)
            missing = []
            for key in ("missing", "count_failures", "sequence_failures", "missing_trap_causes", "arg_failures", "tag_failures"):
                values = item.get(key, [])
                if isinstance(values, list):
                    missing.extend(str(value) for value in values)
            if missing:
                missing_by_rule.setdefault(rule, [])
                missing_by_rule[rule].extend(missing)
    return {
        "expected": sorted(expected),
        "matched": sorted(matched),
        "matched_expected": sorted(expected & matched),
        "missing": sorted(expected - matched),
        "missing_details": {key: sorted(set(values)) for key, values in sorted(missing_by_rule.items()) if key in expected},
        "unexpected_matched": sorted(matched - expected),
    }


def gate_sample(
    run_root: Path,
    sample: SampleRef,
    reps: int,
    trace_records: int | None,
    allowed_events: set[str] | None,
) -> dict[str, Any]:
    root = sample_dir(run_root, sample)
    traces = trace_summaries(root, trace_records)
    counts = merge_counts(row["event_counts"] for row in traces)
    unexpected = sorted(set(counts) - allowed_events) if allowed_events is not None else []
    status = sample_status(root, reps)
    alignments = load_alignments(root)
    audits = load_audits(root)
    audit_summary = audit_rule_summary(sample, audits)
    drop_rates = [float(row["drop_rate"]) for row in traces]
    captured = [float(row["captured_events"]) for row in traces]
    sample_gate = "PASS"
    if status["status"] != "PASS" or unexpected or audit_summary["missing"] or audit_summary["unexpected_matched"]:
        sample_gate = "FAIL"
    elif traces and any(row["capped_at_trace_records"] for row in traces):
        sample_gate = "BLOCKED"
    return {
        "sample_class": sample.sample_class,
        "sample_id": sample.sample_id,
        "gate_status": sample_gate,
        "sample_status": status,
        "drop_summary": {
            "drop_median": median(float(row["drop"]) for row in traces),
            "drop_rate_median": median(drop_rates),
            "drop_rate_worst": max(drop_rates) if drop_rates else None,
            "captured_events_median": median(captured),
            "capped_reps": [row["rep"] for row in traces if row["capped_at_trace_records"]],
        },
        "event_summary": {
            "counts": counts,
            "unexpected_events": unexpected,
        },
        "alignment_summary": alignment_summary(alignments, traces),
        "audit_rule_summary": audit_summary,
    }


def claim_level(samples: list[dict[str, Any]], run_config: dict[str, Any]) -> str:
    if any(row["gate_status"] == "FAIL" for row in samples):
        return "prototype_only"
    profile = run_config.get("trace_profile")
    sample_count = len(samples)
    median_drop = median(
        float(row["drop_summary"]["drop_rate_median"])
        for row in samples
        if row["drop_summary"].get("drop_rate_median") is not None
    )
    median_recall = median(
        float(row["alignment_summary"]["recall_median"])
        for row in samples
        if row["alignment_summary"].get("recall_median") is not None
    )
    if profile and str(profile).startswith("p0") and sample_count <= 4:
        return "microbench_ready" if median_drop is not None and median_drop <= 0.15 else "prototype_only"
    if sample_count >= 13 and median_drop is not None and median_recall is not None and median_drop <= 0.15 and median_recall >= 0.30:
        return "full_matrix_ready"
    return "prototype_only"


def check_run(run_root: Path, samples: list[SampleRef], reps: int) -> dict[str, Any]:
    run_config = load_json(run_root / "run_config.json") if (run_root / "run_config.json").exists() else {}
    trace_profile = run_config.get("trace_profile")
    trace_records = int(run_config["trace_records"]) if run_config.get("trace_records") is not None else None
    allowed_events = allowed_events_for_profile(str(trace_profile)) if trace_profile in profile_names() else None
    sample_rows = [gate_sample(run_root, sample, reps, trace_records, allowed_events) for sample in samples]
    return {
        "schema": "rvmt.35t.next_gate.v1",
        "run_id": run_root.name,
        "artifact_root": repo_rel(run_root),
        "trace_profile": trace_profile,
        "trace_records": trace_records,
        "allowed_events": sorted(allowed_events) if allowed_events is not None else None,
        "sample_status": {row["sample_id"]: row["sample_status"] for row in sample_rows},
        "drop_summary": {row["sample_id"]: row["drop_summary"] for row in sample_rows},
        "event_summary": {row["sample_id"]: row["event_summary"] for row in sample_rows},
        "alignment_summary": {row["sample_id"]: row["alignment_summary"] for row in sample_rows},
        "audit_rule_summary": {row["sample_id"]: row["audit_rule_summary"] for row in sample_rows},
        "samples": sample_rows,
        "claim_level": claim_level(sample_rows, run_config),
        "non_claims": [
            "No CVA6 board claim.",
            "No real malware detection claim.",
            "No mature detector claim.",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# 35T Next Gate Report",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Artifact root: `{report['artifact_root']}`",
        f"- Trace profile: `{report.get('trace_profile') or 'not recorded'}`",
        f"- Claim level: `{report['claim_level']}`",
        "- Boundary: 35T/VexRiscv only; no CVA6 board claim; no real malware claim.",
        "",
        "| Sample | Gate | Drop median | Drop rate median | Capped reps | Unexpected events | Align recall | Missing expected | Unexpected matched |",
        "| --- | --- | ---: | ---: | --- | --- | ---: | --- | --- |",
    ]
    for row in report["samples"]:
        drop = row["drop_summary"]
        align = row["alignment_summary"]
        audit = row["audit_rule_summary"]
        capped = ", ".join(drop.get("capped_reps", [])) or "none"
        unexpected_events = ", ".join(row["event_summary"].get("unexpected_events", [])) or "none"
        missing = ", ".join(audit.get("missing", [])) or "none"
        unexpected_matched = ", ".join(audit.get("unexpected_matched", [])) or "none"
        lines.append(
            f"| `{row['sample_id']}` | {row['gate_status']} | {drop.get('drop_median')} | "
            f"{drop.get('drop_rate_median')} | {capped} | {unexpected_events} | "
            f"{align.get('recall_median')} | {missing} | {unexpected_matched} |"
        )
    lines.extend(["", "## Rule Details", ""])
    for row in report["samples"]:
        audit = row["audit_rule_summary"]
        lines.extend(
            [
                f"### `{row['sample_id']}`",
                "",
                f"- Expected: {', '.join(audit.get('expected', [])) or 'none'}",
                f"- Matched: {', '.join(audit.get('matched', [])) or 'none'}",
                f"- Missing: {', '.join(audit.get('missing', [])) or 'none'}",
                f"- Unexpected matched: {', '.join(audit.get('unexpected_matched', [])) or 'none'}",
                "",
            ]
        )
    lines.extend(
        [
            "## Gate Boundary",
            "",
            "This report separates trace capacity, semantic recovery, and audit-rule failures. It is prototype evidence, not a mature malware detector result.",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(run_root: Path, report: dict[str, Any]) -> None:
    aggregate = run_root / "aggregate"
    aggregate.mkdir(parents=True, exist_ok=True)
    (aggregate / "gate_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (aggregate / "gate_report.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        run_root = Path(tmp) / "35t-self"
        sample = SampleRef("malware_like_synthetic", "illegal_trap", ("illegal_instruction_trap",))
        (run_root / "aggregate").mkdir(parents=True)
        (run_root / "run_config.json").write_text(
            json.dumps({"trace_profile": "p0_syscall_trap_context", "trace_records": 2, "reps": 1}),
            encoding="utf-8",
        )
        root = sample_dir(run_root, sample)
        gt = root / "groundtruth"
        gt.mkdir(parents=True)
        (gt / "status.json").write_text('{"status":"PASS"}\n', encoding="utf-8")
        for mode in (TRACE_OFF, TRACE_ON):
            rep = root / "board" / mode / "rep_00"
            rep.mkdir(parents=True)
            (rep / "status.json").write_text('{"status":"PASS","runtime_ns":1,"drop":0}\n', encoding="utf-8")
            if mode == TRACE_ON:
                (rep / "trace.jsonl").write_text(
                    '{"evt":"SYSCALL_ENTRY"}\n{"evt":"TRAP"}\n',
                    encoding="utf-8",
                )
                align = rep / "alignment"
                align.mkdir()
                (align / "alignment.json").write_text(
                    '{"syscall_family_precision":1,"syscall_family_recall":1,"ordered_lcs":1,"ordered_lcs_ratio":1,"return_sign_match_ratio":1}\n',
                    encoding="utf-8",
                )
                audit = rep / "behavior_audit"
                audit.mkdir()
                (audit / "behavior_audit.json").write_text(
                    json.dumps(
                        {
                            "matches": [
                                {"rule": "illegal_instruction_trap", "matched": True},
                                {"rule": "many_file_scan", "matched": False, "missing": ["getdents64"]},
                            ]
                        }
                    ),
                    encoding="utf-8",
                )
        report = check_run(run_root, [sample], 1)
        write_report(run_root, report)
        if report["claim_level"] != "microbench_ready":
            print("[FAIL] gate self-test missed microbench-ready claim level", file=sys.stderr)
            return 1
        if not (run_root / "aggregate" / "gate_report.json").exists():
            print("[FAIL] gate self-test did not write JSON report", file=sys.stderr)
            return 1
    print("[PASS] 35T next gate self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the strict next-gate report for a 35T experiment run.")
    parser.add_argument("--run-id", default="manual")
    parser.add_argument("--root", type=Path, default=DEFAULT_RESULT_ROOT)
    parser.add_argument("--reps", type=int)
    parser.add_argument("--sample", action="append", default=[])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    run_root = resolve(args.root) / args.run_id
    run_config = load_json(run_root / "run_config.json")
    reps = args.reps if args.reps is not None else int(run_config.get("reps", 5))
    samples = load_samples(args.sample or run_config.get("samples", []))
    report = check_run(run_root, samples, reps)
    write_report(run_root, report)
    print(f"[PASS] 35T next gate report written: {run_root / 'aggregate' / 'gate_report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
