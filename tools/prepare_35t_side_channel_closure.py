from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    read_json,
    rel,
    repo_path,
    utc_now,
    write_json,
)


SOURCE_RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
BASELINE_SIDE_CHANNEL_RUN_ID = "35t-targeted-board-validation-20260522"
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / SOURCE_RUN_ID
DEFAULT_RESULTS_ROOT = Path("results/experiments/35t")
DEFAULT_TRACE_RECORDS = 2048
DEFAULT_REPS = 5
DEFAULT_DROP_LIMIT = 0.05
DEFAULT_FOCUS_SAMPLES = [
    "batch_open_read_write",
    "illegal_trap",
    "process_chain",
    "dynamic_executable_memory",
]
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]


def utc_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d")


def artix7_trace_build_name(trace_records: int) -> str:
    return "embedfire_rise_pro_trace" if trace_records == 256 else f"embedfire_rise_pro_trace_r{trace_records}"


def artix7_trace_build_dir(repo_root: Path, trace_records: int) -> Path:
    return repo_root / "vendor/litex/linux-on-litex-vexriscv/build" / artix7_trace_build_name(trace_records)


def artix7_trace_csr_csv(repo_root: Path, trace_records: int) -> Path:
    return artix7_trace_build_dir(repo_root, trace_records) / "csr.csv"


def shell_join(parts: list[str]) -> str:
    quoted: list[str] = []
    for part in parts:
        if not part or any(char.isspace() for char in part):
            quoted.append("'" + part.replace("'", "'\"'\"'") + "'")
        else:
            quoted.append(part)
    return " ".join(quoted)


def sample_rows(gate_report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = gate_report.get("samples", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def sample_status_rows(gate_report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = gate_report.get("sample_status", {})
    return {str(key): row for key, row in rows.items() if isinstance(row, dict)} if isinstance(rows, dict) else {}


def failed_sample_summary(gate_report: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in sample_rows(gate_report):
        if row.get("gate_status") == "PASS":
            continue
        marker = row.get("marker_scope_summary", {}) if isinstance(row.get("marker_scope_summary"), dict) else {}
        runtime = (
            row.get("runtime_process_attribution_summary", {})
            if isinstance(row.get("runtime_process_attribution_summary"), dict)
            else {}
        )
        drop = row.get("drop_summary", {}) if isinstance(row.get("drop_summary"), dict) else {}
        audit = row.get("audit_rule_summary", {}) if isinstance(row.get("audit_rule_summary"), dict) else {}
        result.append(
            {
                "sample_id": row.get("sample_id"),
                "gate_status": row.get("gate_status"),
                "gate_failures": row.get("gate_failures", []),
                "gate_blockers": row.get("gate_blockers", []),
                "drop_rate_median": drop.get("drop_rate_median"),
                "drop_median": drop.get("drop_median"),
                "capped_reps": drop.get("capped_reps", []),
                "marker_scope_status": marker.get("status"),
                "runtime_process_attribution_status": runtime.get("status"),
                "missing_expected": audit.get("missing", []),
                "missing_details": audit.get("missing_details", {}),
            }
        )
    return result


def ordered_focus_samples(failures: list[dict[str, Any]], explicit_samples: list[str]) -> list[str]:
    if explicit_samples:
        return explicit_samples
    failed = {str(row.get("sample_id")) for row in failures if row.get("sample_id")}
    ordered = [sample for sample in DEFAULT_FOCUS_SAMPLES if sample in failed]
    ordered.extend(sorted(failed - set(ordered)))
    return ordered or DEFAULT_FOCUS_SAMPLES


def experiment_base_args(args: argparse.Namespace, run_id: str, samples: list[str]) -> list[str]:
    cmd = [
        "--run-id",
        run_id,
        "--reps",
        str(args.reps),
        "--trace-records",
        str(args.trace_records),
        "--trace-profile",
        args.trace_profile,
        "--trace-profile-policy",
        args.trace_profile_policy,
        "--runtime-order",
        args.runtime_order,
        "--warmup",
        str(args.warmup),
    ]
    for sample in samples:
        cmd.extend(["--sample", sample])
    return cmd


def experiment_command(
    stage: str,
    args: argparse.Namespace,
    *,
    run_id: str,
    samples: list[str],
    include_board_io: bool = False,
    syscall_side_channel: bool = False,
) -> list[str]:
    cmd = ["uv", "run", "python", "tools/experiment_35t.py", "--stage", stage]
    cmd.extend(experiment_base_args(args, run_id, samples))
    if include_board_io:
        cmd.extend(
            [
                "--port",
                args.port,
                "--baud",
                str(args.baud),
                "--duration",
                str(args.duration),
                "--board-runner-path",
                args.board_runner_path,
            ]
        )
        if syscall_side_channel:
            cmd.append("--syscall-side-channel")
    return cmd


def gate_event_summary_bad(row: dict[str, Any]) -> int:
    summary = row.get("event_summary", {}) if isinstance(row.get("event_summary"), dict) else {}
    return int(summary.get("unknown_event_count", 0) or 0) + int(summary.get("corrupt_record_count", 0) or 0)


def verify_closure_run(
    repo_root: Path,
    results_root: Path,
    run_id: str,
    focus_samples: list[str],
    trace_records: int,
    drop_limit: float,
) -> dict[str, Any]:
    gate_path = repo_path(repo_root, results_root / run_id / "aggregate/gate_report.json")
    failures: list[str] = []
    gate = read_json(gate_path, failures, repo_root, "closure gate report")
    if failures:
        return {
            "status": "NOT_RUN",
            "gate_report": rel(gate_path, repo_root),
            "failures": failures,
            "sample_checks": [],
        }

    rows_by_sample = {str(row.get("sample_id")): row for row in sample_rows(gate)}
    statuses = sample_status_rows(gate)
    sample_checks: list[dict[str, Any]] = []
    expected = set(focus_samples)
    actual = set(rows_by_sample)
    if actual != expected:
        failures.append(f"closure sample set mismatch: expected={sorted(expected)} actual={sorted(actual)}")
    if gate.get("schema") != "rvmt.35t.next_gate.v2":
        failures.append("closure gate schema mismatch")
    if gate.get("run_id") != run_id:
        failures.append("closure gate run_id mismatch")
    if int(gate.get("trace_records", 0) or 0) < trace_records:
        failures.append("closure trace_records below target")
    if gate.get("trace_profile_policy") != "35t_small_capacity":
        failures.append("closure trace_profile_policy mismatch")

    for sample in focus_samples:
        row = rows_by_sample.get(sample, {})
        status = statuses.get(sample, {})
        drop = row.get("drop_summary", {}) if isinstance(row.get("drop_summary"), dict) else {}
        marker = row.get("marker_scope_summary", {}) if isinstance(row.get("marker_scope_summary"), dict) else {}
        runtime = (
            row.get("runtime_process_attribution_summary", {})
            if isinstance(row.get("runtime_process_attribution_summary"), dict)
            else {}
        )
        audit = row.get("audit_rule_summary", {}) if isinstance(row.get("audit_rule_summary"), dict) else {}
        capped_reps = drop.get("capped_reps", []) if isinstance(drop.get("capped_reps", []), list) else []
        drop_rate = float(drop.get("drop_rate_median", 1.0) if drop.get("drop_rate_median") is not None else 1.0)
        sample_failures: list[str] = []
        if not row:
            sample_failures.append("missing_sample_row")
        if row.get("gate_status") != "PASS":
            sample_failures.append("gate_status")
        if status.get("status") != "PASS":
            sample_failures.append("sample_status")
        if marker.get("status") != "PASS":
            sample_failures.append("marker_scope")
        if runtime.get("status") != "PASS":
            sample_failures.append("runtime_process_attribution")
        if capped_reps:
            sample_failures.append("trace_record_cap_hit")
        if drop_rate > drop_limit:
            sample_failures.append("drop_rate_median_gt_limit")
        if audit.get("missing"):
            sample_failures.append("missing_expected")
        if gate_event_summary_bad(row):
            sample_failures.append("unknown_or_corrupt_events")
        if sample_failures:
            failures.append(f"{sample}: {', '.join(sample_failures)}")
        sample_checks.append(
            {
                "sample_id": sample,
                "status": "PASS" if not sample_failures else "FAIL",
                "failures": sample_failures,
                "gate_status": row.get("gate_status"),
                "sample_status": status.get("status"),
                "drop_rate_median": drop.get("drop_rate_median"),
                "capped_reps": capped_reps,
                "marker_scope_status": marker.get("status"),
                "runtime_process_attribution_status": runtime.get("status"),
                "missing_expected": audit.get("missing", []),
            }
        )

    return {
        "status": "PASS" if not failures else "FAIL",
        "gate_report": rel(gate_path, repo_root),
        "failures": failures,
        "sample_checks": sample_checks,
    }


def build_plan(repo_root: Path, args: argparse.Namespace) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    results_root = args.results_root
    baseline_gate_path = repo_path(repo_root, results_root / args.baseline_run_id / "aggregate/gate_report.json")
    baseline_failures: list[str] = []
    baseline_gate = read_json(baseline_gate_path, baseline_failures, repo_root, "baseline side-channel gate")
    current_failures = failed_sample_summary(baseline_gate) if baseline_gate else []
    focus_samples = ordered_focus_samples(current_failures, args.sample)
    closure_run_root = results_root / args.closure_run_id
    trace_csr = artix7_trace_csr_csv(repo_root, args.trace_records)
    trace_build = artix7_trace_build_dir(repo_root, args.trace_records)
    trace_csr_status = "PRESENT" if trace_csr.exists() else "MISSING"
    commands = [
        {
            "phase": "trace-build",
            "hardware_required": False,
            "command": shell_join(
                [
                    "uv",
                    "run",
                    "rvmt",
                    "board:artix7:trace-build",
                    "--run-id",
                    args.closure_run_id,
                    "--trace-records",
                    str(args.trace_records),
                    "--baud",
                    str(args.baud),
                ]
            ),
            "expected_output": rel(trace_csr, repo_root),
            "pass_condition": "trace-capacity-specific LiteX CSR map and bitstream are generated",
        },
        {
            "phase": "groundtruth",
            "hardware_required": False,
            "command": shell_join(experiment_command("groundtruth", args, run_id=args.closure_run_id, samples=focus_samples)),
            "expected_output": rel(closure_run_root / "samples", repo_root),
            "pass_condition": "host and QEMU baselines are present for the focused closure samples",
        },
        {
            "phase": "rootfs",
            "hardware_required": False,
            "command": shell_join(experiment_command("rootfs", args, run_id=args.closure_run_id, samples=focus_samples)),
            "expected_output": "build/board/artix7_35t/rootfs_exp_overlay/usr/bin/rvmt_exp_runner",
            "pass_condition": "35T runner and focused sample binaries are rebuilt into the rootfs overlay",
        },
        {
            "phase": "trace-load",
            "hardware_required": True,
            "command": shell_join(
                [
                    "uv",
                    "run",
                    "rvmt",
                    "board:artix7:trace-load",
                    "--run-id",
                    args.closure_run_id,
                    "--trace-records",
                    str(args.trace_records),
                    "--port",
                    args.port,
                    "--baud",
                    str(args.baud),
                ]
            ),
            "expected_output": rel(trace_build / "gateware/embedfire_rise_pro.bit", repo_root),
            "pass_condition": "the board is programmed with the same trace depth used by the closure run",
        },
        {
            "phase": "linux-boot-after-trace-load",
            "hardware_required": True,
            "command": shell_join(
                [
                    "uv",
                    "run",
                    "rvmt",
                    "board:artix7:linux-boot-capture",
                    "--run-id",
                    args.closure_run_id,
                    "--port",
                    args.port,
                    "--baud",
                    str(args.baud),
                    "--duration",
                    str(args.duration),
                ]
            ),
            "expected_output": rel(Path("results/board/artix7_35t_litex") / args.closure_run_id / "06_linux_boot/uart_linux_boot.log", repo_root),
            "pass_condition": "Linux is reloaded after trace bitstream programming and reaches RVMT_LINUX_USER_PASS",
        },
        {
            "phase": "board-side-channel-rerun",
            "hardware_required": True,
            "command": shell_join(
                experiment_command(
                    "board",
                    args,
                    run_id=args.closure_run_id,
                    samples=focus_samples,
                    include_board_io=True,
                    syscall_side_channel=True,
                )
            ),
            "expected_output": rel(closure_run_root / "board/raw_uart.log", repo_root),
            "pass_condition": "UART capture contains syscall side-channel observations, begin/end markers, and trace dumps for every focused rep",
        },
        {
            "phase": "analyze",
            "hardware_required": False,
            "command": shell_join(experiment_command("analyze", args, run_id=args.closure_run_id, samples=focus_samples)),
            "expected_output": rel(closure_run_root / "samples", repo_root),
            "pass_condition": "semantic recovery, behavior audit, alignment, and trace-code joins are regenerated",
        },
        {
            "phase": "report",
            "hardware_required": False,
            "command": shell_join(experiment_command("report", args, run_id=args.closure_run_id, samples=focus_samples)),
            "expected_output": rel(closure_run_root / "aggregate/gate_report.json", repo_root),
            "pass_condition": "aggregate reports are regenerated for the focused closure run",
        },
        {
            "phase": "strict-gate",
            "hardware_required": False,
            "command": shell_join(
                [
                    "uv",
                    "run",
                    "python",
                    "tools/check_35t_next_gate.py",
                    "--run-id",
                    args.closure_run_id,
                    "--root",
                    args.results_root.as_posix(),
                    "--reps",
                    str(args.reps),
                    *[part for sample in focus_samples for part in ("--sample", sample)],
                ]
            ),
            "expected_output": rel(closure_run_root / "aggregate/gate_report.json", repo_root),
            "pass_condition": "all focused samples have strict gate_status PASS",
        },
    ]
    verification = verify_closure_run(
        repo_root,
        results_root,
        args.closure_run_id,
        focus_samples,
        args.trace_records,
        args.drop_limit,
    )
    if verification["status"] == "NOT_RUN":
        status = "READY_TO_RUN_ON_35T_BOARD" if trace_csr_status == "PRESENT" else "TRACE_BUILD_REQUIRED"
    else:
        status = verification["status"]
    return {
        "schema": "rvmt.35t.side_channel_closure_plan.v1",
        "generated_utc": utc_now(),
        "status": status,
        "source_run_id": SOURCE_RUN_ID,
        "baseline_side_channel_run_id": args.baseline_run_id,
        "baseline_side_channel_gate": rel(baseline_gate_path, repo_root),
        "baseline_read_failures": baseline_failures,
        "current_side_channel_failures": current_failures,
        "closure_run_id": args.closure_run_id,
        "closure_results_root": closure_run_root.as_posix(),
        "focus_samples": focus_samples,
        "target_trace_records": args.trace_records,
        "baseline_trace_records": baseline_gate.get("trace_records"),
        "reps": args.reps,
        "runtime_order": args.runtime_order,
        "trace_profile": args.trace_profile,
        "trace_profile_policy": args.trace_profile_policy,
        "trace_build_dir": rel(trace_build, repo_root),
        "trace_csr_csv": rel(trace_csr, repo_root),
        "trace_csr_status": trace_csr_status,
        "drop_rate_median_limit": args.drop_limit,
        "port": args.port,
        "baud": args.baud,
        "duration": args.duration,
        "board_runner_path": args.board_runner_path,
        "syscall_side_channel": True,
        "closure_requirements": [
            "focused closure samples have strict gate_status PASS",
            "sample_status PASS for every focused sample",
            "marker_scope PASS with begin/end markers in every focused rep",
            "runtime_process_attribution PASS for every focused rep",
            "no focused rep hits the trace record cap",
            f"drop_rate_median <= {args.drop_limit}",
            "no missing expected strong behavior rules",
            "UNKNOWN and corrupt event counts remain zero",
        ],
        "commands": commands,
        "closure_verification": verification,
        "promotion_rule": "Do not update paper-facing claims to side-channel 13/13 until closure_verification.status is PASS.",
        "non_claims": NON_CLAIMS,
    }


def render_markdown(plan: dict[str, Any]) -> str:
    lines = [
        f"# 35T Side-Channel Closure Plan: {plan['closure_run_id']}",
        "",
        f"Status: {plan['status']}",
        "",
        "Scope: Artix-7 35T / LiteX / VexRiscv only.",
        "",
        f"Baseline side-channel run: `{plan['baseline_side_channel_run_id']}`",
        "",
        f"Closure results root: `{plan['closure_results_root']}`",
        "",
        f"Target trace records: `{plan['target_trace_records']}`",
        "",
        f"Trace CSR map: `{plan['trace_csr_csv']}` ({plan['trace_csr_status']})",
        "",
        f"Focused samples: {', '.join(f'`{sample}`' for sample in plan['focus_samples'])}",
        "",
        "## Current Failures",
        "",
    ]
    if plan["baseline_read_failures"]:
        lines.extend(f"- {item}" for item in plan["baseline_read_failures"])
    elif not plan["current_side_channel_failures"]:
        lines.append("- none")
    else:
        lines.extend(
            "- {sample}: failures={failures}; blockers={blockers}; drop_rate={drop}; marker={marker}; runtime={runtime}; missing={missing}".format(
                sample=item.get("sample_id"),
                failures=", ".join(str(v) for v in item.get("gate_failures", [])) or "none",
                blockers=", ".join(str(v) for v in item.get("gate_blockers", [])) or "none",
                drop=item.get("drop_rate_median"),
                marker=item.get("marker_scope_status"),
                runtime=item.get("runtime_process_attribution_status"),
                missing=", ".join(str(v) for v in item.get("missing_expected", [])) or "none",
            )
            for item in plan["current_side_channel_failures"]
        )

    lines += ["", "## Closure Requirements", ""]
    lines.extend(f"- {item}" for item in plan["closure_requirements"])
    lines += ["", "## Commands", ""]
    for item in plan["commands"]:
        hardware = "yes" if item["hardware_required"] else "no"
        lines.extend(
            [
                f"### {item['phase']}",
                "",
                f"Hardware required: {hardware}",
                "",
                "```bash",
                item["command"],
                "```",
                "",
                f"Expected output: `{item['expected_output']}`",
                "",
                f"Pass condition: {item['pass_condition']}",
                "",
            ]
        )
    verification = plan["closure_verification"]
    lines += [
        "## Verification",
        "",
        f"- status: {verification['status']}",
        f"- gate_report: `{verification['gate_report']}`",
    ]
    if verification["failures"]:
        lines.extend(f"- failure: {item}" for item in verification["failures"])
    else:
        lines.append("- failure: none")
    for sample in verification.get("sample_checks", []):
        lines.append(
            "- {sample}: {status}; drop_rate={drop}; marker={marker}; runtime={runtime}; capped_reps={capped}; missing={missing}".format(
                sample=sample.get("sample_id"),
                status=sample.get("status"),
                drop=sample.get("drop_rate_median"),
                marker=sample.get("marker_scope_status"),
                runtime=sample.get("runtime_process_attribution_status"),
                capped=len(sample.get("capped_reps", []) or []),
                missing=", ".join(str(v) for v in sample.get("missing_expected", [])) or "none",
            )
        )
    lines += ["", "## Promotion Rule", "", plan["promotion_rule"], "", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in plan["non_claims"])
    return "\n".join(lines) + "\n"


def write_outputs(plan: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    write_json(evidence_root / "side_channel_closure_plan.json", plan)
    (evidence_root / "side_channel_closure_plan.md").write_text(
        render_markdown(plan),
        encoding="utf-8",
        newline="\n",
    )


def make_gate(run_id: str, samples: list[str], *, fail_sample: str | None = None, trace_records: int = 2048) -> dict[str, Any]:
    rows = []
    status_rows = {}
    event_summary = {}
    for sample in samples:
        failed = sample == fail_sample
        rows.append(
            {
                "sample_id": sample,
                "gate_status": "FAIL" if failed else "PASS",
                "gate_failures": ["missing_strong_expected"] if failed else [],
                "gate_blockers": ["trace_record_cap_hit"] if failed else [],
                "drop_summary": {"drop_rate_median": 0.2 if failed else 0.0, "capped_reps": ["rep_00"] if failed else []},
                "marker_scope_summary": {"status": "FAIL" if failed else "PASS"},
                "runtime_process_attribution_summary": {"status": "BLOCKED" if failed else "PASS"},
                "audit_rule_summary": {"missing": [sample] if failed else []},
                "event_summary": {"unknown_event_count": 0, "corrupt_record_count": 0},
            }
        )
        status_rows[sample] = {"status": "PASS"}
        event_summary[sample] = {"unknown_event_count": 0, "corrupt_record_count": 0}
    return {
        "schema": "rvmt.35t.next_gate.v2",
        "run_id": run_id,
        "claim_level": "focused_side_channel_ready" if fail_sample is None else "prototype_only",
        "trace_records": trace_records,
        "trace_profile_policy": "35t_small_capacity",
        "samples": rows,
        "sample_status": status_rows,
        "event_summary": event_summary,
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        baseline = DEFAULT_RESULTS_ROOT / BASELINE_SIDE_CHANNEL_RUN_ID / "aggregate/gate_report.json"
        closure = DEFAULT_RESULTS_ROOT / "closure-self-test" / "aggregate/gate_report.json"
        write_json(root / baseline, make_gate(BASELINE_SIDE_CHANNEL_RUN_ID, DEFAULT_FOCUS_SAMPLES, fail_sample="process_chain", trace_records=512))
        (artix7_trace_csr_csv(root, 2048)).parent.mkdir(parents=True, exist_ok=True)
        (artix7_trace_csr_csv(root, 2048)).write_text("csr_base,rvmt_trace,0xf0000000\n", encoding="utf-8")
        args = argparse.Namespace(
            repo_root=root,
            evidence_root=DEFAULT_EVIDENCE_ROOT,
            results_root=DEFAULT_RESULTS_ROOT,
            baseline_run_id=BASELINE_SIDE_CHANNEL_RUN_ID,
            closure_run_id="closure-self-test",
            trace_records=2048,
            trace_profile="p0c_syscall_trap_drop",
            trace_profile_policy="35t_small_capacity",
            runtime_order="classic",
            warmup=0,
            reps=5,
            sample=[],
            port="COM5",
            baud=921600,
            duration=3600.0,
            board_runner_path="/usr/bin/rvmt_exp_runner",
            drop_limit=0.05,
        )
        plan = build_plan(root, args)
        if plan["status"] != "READY_TO_RUN_ON_35T_BOARD" or plan["focus_samples"] != ["process_chain"]:
            print("[FAIL] expected focused not-run plan from baseline failure", file=sys.stderr)
            print(json.dumps(plan, indent=2), file=sys.stderr)
            return 1
        write_json(root / closure, make_gate("closure-self-test", ["process_chain"], trace_records=2048))
        verified = build_plan(root, args)
        if verified["status"] != "PASS":
            print("[FAIL] expected closure verification PASS", file=sys.stderr)
            print(json.dumps(verified, indent=2), file=sys.stderr)
            return 1
        write_outputs(verified, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "side_channel_closure_plan.md").exists():
            print("[FAIL] expected markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        baseline = DEFAULT_RESULTS_ROOT / BASELINE_SIDE_CHANNEL_RUN_ID / "aggregate/gate_report.json"
        closure = DEFAULT_RESULTS_ROOT / "closure-self-test" / "aggregate/gate_report.json"
        write_json(root / baseline, make_gate(BASELINE_SIDE_CHANNEL_RUN_ID, DEFAULT_FOCUS_SAMPLES, fail_sample="process_chain", trace_records=512))
        (artix7_trace_csr_csv(root, 2048)).parent.mkdir(parents=True, exist_ok=True)
        (artix7_trace_csr_csv(root, 2048)).write_text("csr_base,rvmt_trace,0xf0000000\n", encoding="utf-8")
        write_json(root / closure, make_gate("closure-self-test", ["process_chain"], fail_sample="process_chain", trace_records=2048))
        args.repo_root = root
        failed = build_plan(root, args)
        if failed["status"] != "FAIL":
            print("[FAIL] expected closure verification FAIL", file=sys.stderr)
            print(json.dumps(failed, indent=2), file=sys.stderr)
            return 1

    print("[PASS] 35T side-channel closure plan self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare and verify the focused 35T syscall side-channel closure rerun.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--baseline-run-id", default=BASELINE_SIDE_CHANNEL_RUN_ID)
    parser.add_argument("--closure-run-id", default=f"35t-sidechannel-closure-r{DEFAULT_TRACE_RECORDS}-{utc_date()}")
    parser.add_argument("--trace-records", type=int, default=DEFAULT_TRACE_RECORDS)
    parser.add_argument("--trace-profile", default="p0c_syscall_trap_drop")
    parser.add_argument("--trace-profile-policy", choices=("35t_small_capacity",), default="35t_small_capacity")
    parser.add_argument("--runtime-order", choices=("classic", "abba"), default="classic")
    parser.add_argument("--warmup", type=int, default=0)
    parser.add_argument("--reps", type=int, default=DEFAULT_REPS)
    parser.add_argument("--sample", action="append", default=[])
    parser.add_argument("--port", default="COM5")
    parser.add_argument("--baud", type=int, default=921600)
    parser.add_argument("--duration", type=float, default=3600.0)
    parser.add_argument("--board-runner-path", default="/usr/bin/rvmt_exp_runner")
    parser.add_argument("--drop-limit", type=float, default=DEFAULT_DROP_LIMIT)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    try:
        plan = build_plan(repo_root, args)
        if not args.no_write:
            write_outputs(plan, repo_path(repo_root, args.evidence_root).resolve())
    except Exception as exc:
        print(f"prepare_35t_side_channel_closure: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{plan['status']}] 35T side-channel closure plan for {plan['closure_run_id']}")
    for item in plan["commands"]:
        print(f"{item['phase']}: {item['command']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
