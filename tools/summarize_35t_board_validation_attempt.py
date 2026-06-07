from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
DEFAULT_VALIDATION_RUN_ID = "35t-targeted-board-validation-20260522"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]


def repo_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def gate_sample_rows(gate: dict[str, Any]) -> list[dict[str, Any]]:
    rows = gate.get("samples", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def gate_failed_samples(gate: dict[str, Any]) -> list[dict[str, Any]]:
    failures = []
    for row in gate_sample_rows(gate):
        if row.get("gate_status") == "PASS":
            continue
        failures.append(
            {
                "sample_id": row.get("sample_id"),
                "gate_status": row.get("gate_status"),
                "gate_failures": row.get("gate_failures", []),
                "gate_blockers": row.get("gate_blockers", []),
            }
        )
    return failures


def status_rows(results_root: Path, mode: str) -> list[dict[str, Any]]:
    rows = []
    for path in sorted((results_root / "samples").glob(f"*/*/board/{mode}/rep_*/status.json")):
        row = load_json(path)
        row["_path"] = path.as_posix()
        rows.append(row)
    return rows


def phase_statuses(results_root: Path) -> dict[str, Any]:
    groundtruth = [load_json(path) for path in sorted((results_root / "samples").glob("*/*/groundtruth/status.json"))]
    trace_on = status_rows(results_root, "trace-on")
    trace_off = status_rows(results_root, "trace-off")
    semantic_events = sorted((results_root / "samples").glob("*/*/board/trace-on/rep_*/behavior_recovery/semantic_events.json"))
    rootfs_log = results_root / "rootfs/build-artix7-linux-images.log"
    raw_uart = results_root / "board/raw_uart.log"
    aggregate = results_root / "aggregate"
    gate_report = aggregate / "gate_report.json"
    return {
        "groundtruth": {
            "status": "PASS" if groundtruth and all(row.get("status") == "PASS" for row in groundtruth) else "MISSING_OR_FAIL",
            "status_files": len(groundtruth),
            "pass_count": sum(1 for row in groundtruth if row.get("status") == "PASS"),
        },
        "rootfs": {
            "status": "PASS" if rootfs_log.exists() else "MISSING_OR_FAIL",
            "log": rootfs_log.as_posix(),
        },
        "board": {
            "status": "PASS"
            if raw_uart.exists()
            and trace_on
            and trace_off
            and all(row.get("status") == "PASS" for row in [*trace_on, *trace_off])
            else "MISSING_OR_FAIL",
            "raw_uart": raw_uart.as_posix(),
            "trace_on_reps": len(trace_on),
            "trace_off_reps": len(trace_off),
            "trace_on_pass": sum(1 for row in trace_on if row.get("status") == "PASS"),
            "trace_off_pass": sum(1 for row in trace_off if row.get("status") == "PASS"),
        },
        "analyze": {
            "status": "PASS" if semantic_events else "MISSING_OR_FAIL",
            "semantic_event_files": len(semantic_events),
        },
        "report": {
            "status": "PASS" if (aggregate / "metrics.json").exists() and gate_report.exists() else "MISSING_OR_FAIL",
            "metrics": (aggregate / "metrics.json").as_posix(),
            "gate_report": gate_report.as_posix(),
        },
    }


def build_summary(repo_root: Path, results_root: Path, evidence_root: Path) -> dict[str, Any]:
    phases = phase_statuses(results_root)
    bundle_path = results_root / "board_validation_bundle/bundle_manifest.json"
    bundle = load_json(bundle_path) if bundle_path.exists() else {}
    validation_mode = str(bundle.get("validation_mode", "single_channel")) if bundle else "single_channel"
    trace_gate_run_id = str(bundle.get("trace_gate_run_id") or results_root.name)
    semantic_run_id = str(bundle.get("semantic_run_id") or results_root.name)
    gate_path = (
        results_root / "board_validation_bundle/gate_report.json"
        if validation_mode == "dual_channel"
        else results_root / "aggregate/gate_report.json"
    )
    gate = load_json(gate_path) if gate_path.exists() else {}
    side_channel_gate_path = results_root / "aggregate/gate_report.json"
    side_channel_gate = load_json(side_channel_gate_path) if side_channel_gate_path.exists() else {}
    board_status_path = evidence_root / "board_validation_status.json"
    board_status = load_json(board_status_path) if board_status_path.exists() else {}
    sample_status = gate.get("sample_status", {}) if isinstance(gate.get("sample_status"), dict) else {}
    sample_pass_count = sum(1 for row in sample_status.values() if isinstance(row, dict) and row.get("status") == "PASS")
    sample_count = len(sample_status)
    gate_samples = gate_sample_rows(gate)
    sample_gate_pass_count = sum(1 for row in gate_samples if row.get("gate_status") == "PASS")
    sample_gate_count = len(gate_samples)
    side_gate_samples = gate_sample_rows(side_channel_gate)
    side_gate_pass_count = sum(1 for row in side_gate_samples if row.get("gate_status") == "PASS")
    phase_pass = all(row.get("status") == "PASS" for row in phases.values())
    bundle_status = bundle.get("status", "MISSING")
    checker_status = bundle.get("checker_status", "MISSING")
    if checker_status == "PASS":
        status = "BOARD_VALIDATION_PASS"
    elif phase_pass and gate.get("claim_level") == "full_matrix_ready":
        status = "BOARD_RUN_COMPLETE_VALIDATION_PARTIAL"
    else:
        status = "BOARD_RUN_INCOMPLETE_OR_FAIL"
    if status == "BOARD_RUN_COMPLETE_VALIDATION_PARTIAL":
        assessment = "actual 35T board run completed and full-matrix gate passed, but strict fd/path and process-tree validation remain partial"
    elif status == "BOARD_VALIDATION_PASS" and validation_mode == "dual_channel":
        assessment = "strict dual-channel validation bundle passed: the trace-gate channel passes the full matrix and the side-channel channel supplies selected semantic closure"
    elif status == "BOARD_VALIDATION_PASS" and sample_gate_count and sample_gate_pass_count != sample_gate_count:
        assessment = "strict selected-artifact validation bundle passed; the targeted run remains prototype_only because strict sample gate_status did not fully pass"
    elif status == "BOARD_VALIDATION_PASS":
        assessment = "strict 35T board-validation bundle passed"
    else:
        assessment = "actual 35T board-validation attempt is incomplete or failed"
    return {
        "schema": "rvmt.35t.board_validation_attempt_summary.v1",
        "source_run_id": RUN_ID,
        "validation_run_id": results_root.name,
        "validation_mode": validation_mode,
        "trace_gate_run_id": trace_gate_run_id,
        "semantic_run_id": semantic_run_id,
        "status": status,
        "scope": "Artix-7 35T / LiteX / VexRiscv",
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "hardware_validated": checker_status == "PASS",
        "results_root": rel(results_root, repo_root),
        "bundle_root": rel(results_root / "board_validation_bundle", repo_root),
        "phase_statuses": phases,
        "next_gate": {
            "schema": gate.get("schema"),
            "claim_level": gate.get("claim_level"),
            "trace_records": gate.get("trace_records"),
            "trace_profile_policy": gate.get("trace_profile_policy"),
            "sample_status_count": sample_count,
            "sample_status_pass_count": sample_pass_count,
            "sample_status_all_pass": bool(sample_count and sample_pass_count == sample_count),
            "sample_gate_count": sample_gate_count,
            "sample_gate_pass_count": sample_gate_pass_count,
            "sample_gate_all_pass": bool(sample_gate_count and sample_gate_pass_count == sample_gate_count),
            "strict_failed_samples": gate_failed_samples(gate),
            "gate_report": rel(gate_path, repo_root),
        },
        "side_channel_gate": {
            "schema": side_channel_gate.get("schema"),
            "claim_level": side_channel_gate.get("claim_level"),
            "sample_gate_count": len(side_gate_samples),
            "sample_gate_pass_count": side_gate_pass_count,
            "sample_gate_all_pass": bool(side_gate_samples and side_gate_pass_count == len(side_gate_samples)),
            "strict_failed_samples": gate_failed_samples(side_channel_gate),
            "gate_report": rel(side_channel_gate_path, repo_root),
        },
        "bundle": {
            "status": bundle_status,
            "checker_status": checker_status,
            "selected_statuses": bundle.get("selected_statuses", {}),
            "missing_artifacts": bundle.get("missing_artifacts", []),
            "checker_failures": bundle.get("checker_failures", []),
            "manifest": rel(bundle_path, repo_root),
        },
        "board_validation_status": {
            "status": board_status.get("status"),
            "hardware_validated": board_status.get("hardware_validated"),
            "failures": board_status.get("failures", []),
            "path": rel(board_status_path, repo_root),
        },
        "assessment": assessment,
        "non_claims": NON_CLAIMS,
    }


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        f"# 35T Board Validation Attempt: {summary['validation_run_id']}",
        "",
        f"Status: {summary['status']}",
        "",
        "Scope: Artix-7 35T / LiteX / VexRiscv only.",
        "",
        f"Claim level: {summary['claim_level']}.",
        "",
        f"Hardware validated: {str(summary['hardware_validated']).lower()}",
        "",
        f"Validation mode: {summary.get('validation_mode', 'single_channel')}",
        "",
        summary["assessment"],
        "",
        "## Phases",
        "",
    ]
    for phase, row in summary["phase_statuses"].items():
        lines.append(f"- {phase}: {row.get('status')}")
    gate = summary["next_gate"]
    lines += [
        "",
        "## Next Gate",
        "",
        f"- claim_level: {gate.get('claim_level')}",
        f"- trace_gate_run_id: {summary.get('trace_gate_run_id')}",
        f"- sample_status: {gate.get('sample_status_pass_count')}/{gate.get('sample_status_count')} PASS",
        f"- sample_gate_status: {gate.get('sample_gate_pass_count')}/{gate.get('sample_gate_count')} PASS",
        f"- strict_sample_gate: {'PASS' if gate.get('sample_gate_all_pass') else 'FAIL'}",
        f"- trace_records: {gate.get('trace_records')}",
        f"- trace_profile_policy: {gate.get('trace_profile_policy')}",
        "",
        "## Bundle",
        "",
        f"- status: {summary['bundle'].get('status')}",
        f"- checker_status: {summary['bundle'].get('checker_status')}",
    ]
    selected = summary["bundle"].get("selected_statuses", {})
    for key in ("fd_path_flow", "process_tree", "source_attribution"):
        lines.append(f"- {key}: {selected.get(key)}")
    side_gate = summary.get("side_channel_gate", {})
    if side_gate:
        lines += [
            "",
            "## Side-Channel Gate",
            "",
            f"- semantic_run_id: {summary.get('semantic_run_id')}",
            f"- claim_level: {side_gate.get('claim_level')}",
            f"- sample_gate_status: {side_gate.get('sample_gate_pass_count')}/{side_gate.get('sample_gate_count')} PASS",
            f"- strict_sample_gate: {'PASS' if side_gate.get('sample_gate_all_pass') else 'FAIL'}",
        ]
    if gate.get("strict_failed_samples"):
        lines += ["", "## Strict Sample-Gate Failures", ""]
        for item in gate["strict_failed_samples"]:
            lines.append(
                "- {sample_id}: failures={failures}; blockers={blockers}".format(
                    sample_id=item.get("sample_id"),
                    failures=", ".join(str(value) for value in item.get("gate_failures", [])) or "none",
                    blockers=", ".join(str(value) for value in item.get("gate_blockers", [])) or "none",
                )
            )
    if side_gate.get("strict_failed_samples"):
        lines += ["", "## Side-Channel Sample-Gate Failures", ""]
        for item in side_gate["strict_failed_samples"]:
            lines.append(
                "- {sample_id}: failures={failures}; blockers={blockers}".format(
                    sample_id=item.get("sample_id"),
                    failures=", ".join(str(value) for value in item.get("gate_failures", [])) or "none",
                    blockers=", ".join(str(value) for value in item.get("gate_blockers", [])) or "none",
                )
            )
    if summary["bundle"].get("checker_failures"):
        lines += ["", "## Checker Failures", ""]
        lines.extend(f"- {item}" for item in summary["bundle"]["checker_failures"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in summary["non_claims"])
    return "\n".join(lines) + "\n"


def write_outputs(summary: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "board_validation_attempt_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "board_validation_attempt_summary.md").write_text(
        render_markdown(summary),
        encoding="utf-8",
        newline="\n",
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        results = root / "results/experiments/35t/35t-targeted-board-validation-self-test"
        evidence = root / DEFAULT_EVIDENCE_ROOT
        for sample in ("hello", "file_scan"):
            gt = results / "samples/benign" / sample / "groundtruth"
            gt.mkdir(parents=True, exist_ok=True)
            (gt / "status.json").write_text('{"status":"PASS"}\n', encoding="utf-8")
            for mode in ("trace-on", "trace-off"):
                rep = results / "samples/benign" / sample / "board" / mode / "rep_00"
                rep.mkdir(parents=True, exist_ok=True)
                (rep / "status.json").write_text('{"status":"PASS"}\n', encoding="utf-8")
                if mode == "trace-on":
                    sem = rep / "behavior_recovery"
                    sem.mkdir()
                    (sem / "semantic_events.json").write_text('{"syscall_sequence":[]}\n', encoding="utf-8")
        (results / "rootfs").mkdir(parents=True)
        (results / "rootfs/build-artix7-linux-images.log").write_text("ok\n", encoding="utf-8")
        (results / "board").mkdir(parents=True)
        (results / "board/raw_uart.log").write_text("ok\n", encoding="utf-8")
        aggregate = results / "aggregate"
        aggregate.mkdir(parents=True)
        (aggregate / "metrics.json").write_text("{}\n", encoding="utf-8")
        (aggregate / "gate_report.json").write_text(
            json.dumps(
                {
                    "schema": "rvmt.35t.next_gate.v2",
                    "claim_level": "full_matrix_ready",
                    "trace_records": 512,
                    "trace_profile_policy": "35t_small_capacity",
                    "sample_status": {"hello": {"status": "PASS"}, "file_scan": {"status": "PASS"}},
                }
            ),
            encoding="utf-8",
        )
        bundle = results / "board_validation_bundle"
        bundle.mkdir()
        (bundle / "bundle_manifest.json").write_text(
            json.dumps(
                {
                    "status": "CANDIDATE_PARTIAL",
                    "checker_status": "RESULTS_PARTIAL",
                    "selected_statuses": {"fd_path_flow": "PARTIAL", "process_tree": "PARTIAL", "source_attribution": "PARTIAL"},
                    "checker_failures": ["board validation result content check failed: fd_path_flow"],
                    "missing_artifacts": [],
                }
            ),
            encoding="utf-8",
        )
        evidence.mkdir(parents=True)
        (evidence / "board_validation_status.json").write_text(
            '{"status":"RESULTS_PARTIAL","hardware_validated":false,"failures":[]}\n',
            encoding="utf-8",
        )
        summary = build_summary(root, results, evidence)
        if summary["status"] != "BOARD_RUN_COMPLETE_VALIDATION_PARTIAL":
            print("[FAIL] expected partial validation attempt summary", file=sys.stderr)
            print(json.dumps(summary, indent=2), file=sys.stderr)
            return 1
        write_outputs(summary, evidence)
        if not (evidence / "board_validation_attempt_summary.json").exists():
            print("[FAIL] missing attempt summary output", file=sys.stderr)
            return 1
    print("[PASS] 35T board validation attempt summary self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize a targeted 35T board-validation attempt.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--validation-run-id", default=DEFAULT_VALIDATION_RUN_ID)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    results_root = repo_path(repo_root, args.results_root or Path("results/experiments/35t") / args.validation_run_id).resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        summary = build_summary(repo_root, results_root, evidence_root)
        write_outputs(summary, evidence_root)
    except Exception as exc:
        print(f"summarize_35t_board_validation_attempt: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] 35T board validation attempt summary")
    return 0 if summary["status"] in {"BOARD_VALIDATION_PASS", "BOARD_RUN_COMPLETE_VALIDATION_PARTIAL"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
