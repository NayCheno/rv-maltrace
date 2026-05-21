from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / RUN_ID
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
DEFAULT_FOCUS_SAMPLES = [
    "illegal_trap",
    "process_chain",
    "dynamic_executable_memory",
    "file_scan",
    "batch_open_read_write",
    "self_copy_sim",
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


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def repo_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return path.as_posix()


def shell_join(parts: list[str]) -> str:
    quoted = []
    for part in parts:
        if not part or any(char.isspace() for char in part):
            quoted.append("'" + part.replace("'", "'\"'\"'") + "'")
        else:
            quoted.append(part)
    return " ".join(quoted)


def experiment_base_args(args: argparse.Namespace) -> list[str]:
    return [
        "--run-id",
        args.validation_run_id,
        "--reps",
        str(args.reps),
        "--trace-records",
        str(args.trace_records),
        "--trace-profile-policy",
        args.trace_profile_policy,
        "--runtime-order",
        args.runtime_order,
    ]


def experiment_command(stage: str, args: argparse.Namespace, *, include_board_io: bool = False) -> list[str]:
    cmd = ["uv", "run", "python", "tools/experiment_35t.py", "--stage", stage, *experiment_base_args(args)]
    if include_board_io:
        cmd.extend(["--port", args.port, "--baud", str(args.baud), "--duration", str(args.duration), "--board-runner-path", args.board_runner_path])
        if args.syscall_side_channel:
            cmd.append("--syscall-side-channel")
    return cmd


def build_runbook(repo_root: Path, args: argparse.Namespace) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    results_root = Path("results/experiments/35t") / args.validation_run_id
    bundle_root = results_root / "board_validation_bundle"
    commands = [
        {
            "phase": "groundtruth",
            "hardware_required": False,
            "command": shell_join(experiment_command("groundtruth", args)),
            "expected_output": rel(results_root / "samples", repo_root),
            "pass_condition": "required host/qemu baselines complete or failures are recorded explicitly",
        },
        {
            "phase": "rootfs",
            "hardware_required": False,
            "command": shell_join(experiment_command("rootfs", args)),
            "expected_output": "build/board/artix7_35t",
            "pass_condition": "35T LiteX/VexRiscv rootfs experiment overlay is rebuilt",
        },
        {
            "phase": "board",
            "hardware_required": True,
            "command": shell_join(experiment_command("board", args, include_board_io=True)),
            "expected_output": rel(results_root / "board/raw_uart.log", repo_root),
            "pass_condition": "UART capture contains target-scoped markers and trace dumps for the full 13-sample matrix",
        },
        {
            "phase": "analyze",
            "hardware_required": False,
            "command": shell_join(experiment_command("analyze", args)),
            "expected_output": rel(results_root / "samples", repo_root),
            "pass_condition": "semantic recovery, behavior audit, lightweight trace analysis, alignment, and trace-code joins are regenerated",
        },
        {
            "phase": "report",
            "hardware_required": False,
            "command": shell_join(experiment_command("report", args)),
            "expected_output": rel(results_root / "aggregate", repo_root),
            "pass_condition": "aggregate 35T reports are regenerated and failures remain explicit",
        },
        {
            "phase": "package",
            "hardware_required": False,
            "command": shell_join(
                [
                    "uv",
                    "run",
                    "python",
                    "tools/package_35t_board_validation.py",
                    "--repo-root",
                    ".",
                    "--source-results-root",
                    results_root.as_posix(),
                    "--out-dir",
                    bundle_root.as_posix(),
                ]
            ),
            "expected_output": rel(bundle_root / "bundle_manifest.json", repo_root),
            "pass_condition": "bundle is PASS only if fd/path and process-tree summaries are PASS; otherwise it remains CANDIDATE_PARTIAL",
        },
        {
            "phase": "check",
            "hardware_required": False,
            "command": shell_join(
                [
                    "uv",
                    "run",
                    "python",
                    "tools/check_35t_board_validation.py",
                    "--repo-root",
                    ".",
                    "--results-root",
                    bundle_root.as_posix(),
                    "--require-results",
                ]
            ),
            "expected_output": rel(DEFAULT_EVIDENCE_ROOT / "board_validation_status.json", repo_root),
            "pass_condition": "status is PASS only when required artifacts and content checks pass",
        },
    ]
    return {
        "schema": "rvmt.35t.board_validation_runbook.v1",
        "source_run_id": RUN_ID,
        "validation_run_id": args.validation_run_id,
        "generated_utc": utc_now(),
        "status": "READY_TO_RUN_ON_35T_BOARD",
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "hardware_required": True,
        "board_target": "Artix-7 35T / LiteX / VexRiscv",
        "results_root": results_root.as_posix(),
        "bundle_root": bundle_root.as_posix(),
        "trace_records": args.trace_records,
        "trace_profile_policy": args.trace_profile_policy,
        "runtime_order": args.runtime_order,
        "reps": args.reps,
        "port": args.port,
        "baud": args.baud,
        "board_runner_path": args.board_runner_path,
        "duration": args.duration,
        "syscall_side_channel": bool(args.syscall_side_channel),
        "matrix_scope": "full 13-sample 35T matrix",
        "focus_samples": DEFAULT_FOCUS_SAMPLES,
        "required_capture_items": [
            "target-scoped marker begin/end around each sample repetition",
            "runtime process map for runner_parent, target_child, kernel, and unknown roles",
            "reliable target syscall entry/return pairing for fd operations",
            "openat and execve path strings or a board-side/runner-side path side channel tied to target syscall events",
            "clone/fork return value from the parent side and wait PID in the same evidence window",
            "child runtime process ownership evidence across exec",
            "exact board runtime ELF/code-map identity",
            "DWARF/debug-line metadata or an addr2line-compatible source-location side channel if source-line attribution is claimed",
        ],
        "commands": commands,
        "non_claims": NON_CLAIMS,
    }


def render_markdown(runbook: dict[str, Any]) -> str:
    lines = [
        f"# 35T Board Validation Runbook: {runbook['validation_run_id']}",
        "",
        f"Status: {runbook['status']}",
        "",
        "Scope: Artix-7 35T / LiteX / VexRiscv only.",
        "",
        f"Claim level: {runbook['claim_level']}.",
        "",
        f"Source run: `{runbook['source_run_id']}`",
        "",
        f"Results root: `{runbook['results_root']}`",
        "",
        f"Bundle root: `{runbook['bundle_root']}`",
        "",
        "## Capture Requirements",
        "",
    ]
    lines.extend(f"- {item}" for item in runbook["required_capture_items"])
    lines += ["", "## Commands", ""]
    for item in runbook["commands"]:
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
    lines += ["## Non-claims", ""]
    lines.extend(f"- {item}" for item in runbook["non_claims"])
    return "\n".join(lines) + "\n"


def write_outputs(runbook: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "board_validation_runbook.json").write_text(
        json.dumps(runbook, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "board_validation_runbook.md").write_text(
        render_markdown(runbook),
        encoding="utf-8",
        newline="\n",
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        args = argparse.Namespace(
            validation_run_id="35t-targeted-board-validation-self-test",
            reps=5,
            trace_records=512,
            trace_profile_policy="35t_small_capacity",
            runtime_order="classic",
            port="COM5",
            baud=921600,
            board_runner_path="/usr/bin/rvmt_exp_runner",
            duration=3600.0,
            syscall_side_channel=True,
        )
        runbook = build_runbook(root, args)
        if runbook["source_run_id"] != RUN_ID or runbook["validation_run_id"] != args.validation_run_id:
            print("[FAIL] runbook source/validation run ids are incorrect", file=sys.stderr)
            return 1
        if runbook["trace_records"] != 512 or runbook["trace_profile_policy"] != "35t_small_capacity":
            print("[FAIL] runbook does not preserve 35T trace baseline", file=sys.stderr)
            return 1
        commands = "\n".join(item["command"] for item in runbook["commands"])
        if "--syscall-side-channel" not in commands:
            print("[FAIL] runbook board command does not enable syscall side-channel capture", file=sys.stderr)
            return 1
        if "CVA6" in commands or "real malware detector" in commands:
            print("[FAIL] runbook contains forbidden scope wording", file=sys.stderr)
            return 1
        if "--results-root results/experiments/35t/35t-targeted-board-validation-self-test/board_validation_bundle" not in commands:
            print("[FAIL] runbook does not check the generated bundle", file=sys.stderr)
            return 1
        evidence = root / DEFAULT_EVIDENCE_ROOT
        write_outputs(runbook, evidence)
        if not (evidence / "board_validation_runbook.json").exists() or not (evidence / "board_validation_runbook.md").exists():
            print("[FAIL] runbook outputs missing", file=sys.stderr)
            return 1
    print("[PASS] 35T board validation runbook self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare the actual 35T board-validation runbook and command sequence.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--validation-run-id", default=f"35t-targeted-board-validation-{utc_date()}")
    parser.add_argument("--port", default="COM5")
    parser.add_argument("--baud", type=int, default=921600)
    parser.add_argument("--board-runner-path", default="/usr/bin/rvmt_exp_runner")
    parser.add_argument("--duration", type=float, default=3600.0)
    parser.add_argument("--reps", type=int, default=5)
    parser.add_argument("--trace-records", type=int, default=512)
    parser.add_argument("--trace-profile-policy", choices=("35t_small_capacity",), default="35t_small_capacity")
    parser.add_argument("--runtime-order", choices=("classic", "abba"), default="classic")
    parser.add_argument("--no-syscall-side-channel", dest="syscall_side_channel", action="store_false")
    parser.set_defaults(syscall_side_channel=True)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    try:
        runbook = build_runbook(repo_root, args)
        if not args.no_write:
            write_outputs(runbook, repo_path(repo_root, args.evidence_root).resolve())
    except Exception as exc:
        print(f"prepare_35t_board_validation_run: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{runbook['status']}] 35T board validation runbook for {runbook['validation_run_id']}")
    for item in runbook["commands"]:
        print(f"{item['phase']}: {item['command']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
