from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
EXPECTED_PHASES = ["groundtruth", "rootfs", "board", "analyze", "report", "package", "check"]
REQUIRED_SCRIPTS = [
    "tools/experiment_35t.py",
    "tools/package_35t_board_validation.py",
    "tools/check_35t_board_validation.py",
    "tools/prepare_35t_board_validation_run.py",
]
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


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


def command_version(command: list[str]) -> dict[str, Any]:
    executable = shutil.which(command[0])
    if executable is None:
        return {"available": False, "command": command[0], "version": None, "error": "not found on PATH"}
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception as exc:
        return {"available": False, "command": command[0], "version": None, "error": str(exc)}
    first_line = completed.stdout.splitlines()[0] if completed.stdout.splitlines() else ""
    return {
        "available": completed.returncode == 0,
        "command": command[0],
        "version": first_line,
        "exit_code": completed.returncode,
    }


def serial_status(port: str) -> dict[str, Any]:
    try:
        import serial  # type: ignore[import-not-found]
        from serial.tools import list_ports  # type: ignore[import-not-found]
    except Exception as exc:
        return {
            "pyserial_available": False,
            "requested_port": port,
            "available_ports": [],
            "requested_port_present": False,
            "error": str(exc),
        }
    available = []
    for row in list_ports.comports():
        available.append(
            {
                "device": row.device,
                "description": row.description,
            }
        )
    requested = port.lower()
    return {
        "pyserial_available": True,
        "pyserial_version": getattr(serial, "__version__", None),
        "requested_port": port,
        "available_ports": available,
        "requested_port_present": any(str(row["device"]).lower() == requested for row in available),
    }


def build_preflight(repo_root: Path, evidence_root_arg: Path, require_board: bool) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    runbook_path = evidence_root / "board_validation_runbook.json"
    failures: list[str] = []
    warnings: list[str] = []
    runbook: dict[str, Any] = {}
    if not runbook_path.exists():
        failures.append(f"missing board validation runbook: {rel(runbook_path, repo_root)}")
    else:
        try:
            runbook = load_json(runbook_path)
        except Exception as exc:
            failures.append(f"invalid board validation runbook JSON: {exc}")

    commands = runbook.get("commands", [])
    phases = [str(item.get("phase")) for item in commands] if isinstance(commands, list) else []
    board_commands = [
        str(item.get("command", ""))
        for item in commands
        if isinstance(item, dict) and str(item.get("phase")) == "board"
    ] if isinstance(commands, list) else []
    runbook_checks = {
        "schema": runbook.get("schema") == "rvmt.35t.board_validation_runbook.v1",
        "source_run_id": runbook.get("source_run_id") == RUN_ID,
        "scope": runbook.get("scope") == EXPECTED_SCOPE,
        "claim_level": runbook.get("claim_level") == EXPECTED_CLAIM_LEVEL,
        "status": runbook.get("status") == "READY_TO_RUN_ON_35T_BOARD",
        "trace_records": runbook.get("trace_records") == 512,
        "trace_profile_policy": runbook.get("trace_profile_policy") == "35t_small_capacity",
        "phases": phases == EXPECTED_PHASES,
        "hardware_required": runbook.get("hardware_required") is True,
        "syscall_side_channel": runbook.get("syscall_side_channel") is True and any("--syscall-side-channel" in command for command in board_commands),
    }
    for key, ok in runbook_checks.items():
        if not ok:
            failures.append(f"runbook check failed: {key}")

    script_checks = {}
    for script in REQUIRED_SCRIPTS:
        path = repo_root / script
        ok = path.exists()
        script_checks[script] = {"ok": ok, "path": script}
        if not ok:
            failures.append(f"missing required script: {script}")

    host_tools = {
        "uv": command_version(["uv", "--version"]),
        "python": command_version([sys.executable, "--version"]),
        "docker": command_version(["docker", "--version"]),
    }
    if not host_tools["uv"]["available"]:
        failures.append("uv is required for the runbook commands")
    if not host_tools["python"]["available"]:
        failures.append("python is required for local analysis commands")
    if not host_tools["docker"]["available"]:
        warnings.append("docker is not available on PATH; groundtruth/rootfs stages may not run on this host")

    port = str(runbook.get("port") or "COM5")
    serial = serial_status(port)
    if not serial.get("pyserial_available"):
        warnings.append("pyserial is not available; board UART capture cannot run until installed")
    if not serial.get("requested_port_present"):
        warnings.append(f"requested board UART port {port} is not currently visible")

    results_root = repo_path(repo_root, Path(str(runbook.get("results_root") or ""))).resolve() if runbook.get("results_root") else None
    bundle_root = repo_path(repo_root, Path(str(runbook.get("bundle_root") or ""))).resolve() if runbook.get("bundle_root") else None
    result_paths = {
        "results_root": rel(results_root, repo_root) if results_root is not None else None,
        "results_root_exists": bool(results_root and results_root.exists()),
        "bundle_root": rel(bundle_root, repo_root) if bundle_root is not None else None,
        "bundle_root_exists": bool(bundle_root and bundle_root.exists()),
    }
    if result_paths["results_root_exists"]:
        warnings.append("target validation results root already exists; inspect before overwriting or rerunning")

    hardware_ready = bool(serial.get("pyserial_available") and serial.get("requested_port_present"))
    if require_board and not hardware_ready:
        failures.append("board UART preflight was required, but the requested port is not ready")

    if failures:
        status = "FAIL"
    elif hardware_ready:
        status = "READY_FOR_BOARD_RUN"
    else:
        status = "READY_PENDING_BOARD_CONNECTION"

    return {
        "schema": "rvmt.35t.board_validation_preflight.v1",
        "source_run_id": RUN_ID,
        "validation_run_id": runbook.get("validation_run_id"),
        "generated_utc": utc_now(),
        "status": status,
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "hardware_ready": hardware_ready,
        "hardware_ready_basis": "requested UART port is visible through pyserial; this does not prove the 35T board image is running",
        "require_board": require_board,
        "runbook_path": rel(runbook_path, repo_root),
        "runbook_checks": runbook_checks,
        "script_checks": script_checks,
        "host_tools": host_tools,
        "serial": serial,
        "result_paths": result_paths,
        "failures": failures,
        "warnings": warnings,
        "non_claims": NON_CLAIMS,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Board Validation Preflight: {report.get('validation_run_id')}",
        "",
        f"Status: {report['status']}",
        "",
        "Scope: Artix-7 35T / LiteX / VexRiscv only.",
        "",
        f"Claim level: {report['claim_level']}.",
        "",
        f"Hardware ready: {str(report['hardware_ready']).lower()}",
        "",
        f"Hardware ready basis: {report['hardware_ready_basis']}",
        "",
        "## Runbook Checks",
        "",
    ]
    for key, ok in report["runbook_checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Required Scripts", ""]
    for script, row in report["script_checks"].items():
        lines.append(f"- {script}: {'PASS' if row.get('ok') else 'FAIL'}")
    lines += ["", "## Host Tools", ""]
    for name, row in report["host_tools"].items():
        status = "PASS" if row.get("available") else "WARN"
        version = row.get("version") or row.get("error")
        lines.append(f"- {name}: {status} ({version})")
    serial = report["serial"]
    lines += ["", "## Serial Port", ""]
    lines.append(f"- pyserial: {'PASS' if serial.get('pyserial_available') else 'WARN'}")
    lines.append(f"- requested port: `{serial.get('requested_port')}`")
    lines.append(f"- requested port visible: {'PASS' if serial.get('requested_port_present') else 'WARN'}")
    if serial.get("available_ports"):
        for row in serial["available_ports"]:
            lines.append(f"- available: {row.get('device')} ({row.get('description')})")
    else:
        lines.append("- available: none reported")
    lines += ["", "## Result Paths", ""]
    for key, value in report["result_paths"].items():
        lines.append(f"- {key}: {value}")
    lines += ["", "## Warnings", ""]
    if report["warnings"]:
        lines.extend(f"- {item}" for item in report["warnings"])
    else:
        lines.append("- none")
    lines += ["", "## Failures", ""]
    if report["failures"]:
        lines.extend(f"- {item}" for item in report["failures"])
    else:
        lines.append("- none")
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "board_validation_preflight.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "board_validation_preflight.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        evidence = root / DEFAULT_EVIDENCE_ROOT
        evidence.mkdir(parents=True)
        for script in REQUIRED_SCRIPTS:
            path = root / script
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# self-test\n", encoding="utf-8")
        runbook = {
            "schema": "rvmt.35t.board_validation_runbook.v1",
            "source_run_id": RUN_ID,
            "validation_run_id": "35t-targeted-board-validation-self-test",
            "scope": EXPECTED_SCOPE,
            "claim_level": EXPECTED_CLAIM_LEVEL,
            "status": "READY_TO_RUN_ON_35T_BOARD",
            "trace_records": 512,
            "trace_profile_policy": "35t_small_capacity",
            "hardware_required": True,
            "syscall_side_channel": True,
            "port": "COM_SELF_TEST",
            "results_root": "results/experiments/35t/35t-targeted-board-validation-self-test",
            "bundle_root": "results/experiments/35t/35t-targeted-board-validation-self-test/board_validation_bundle",
            "commands": [
                {
                    "phase": phase,
                    "command": "uv run python tools/experiment_35t.py --stage board --syscall-side-channel" if phase == "board" else "",
                    "hardware_required": phase == "board",
                }
                for phase in EXPECTED_PHASES
            ],
            "non_claims": NON_CLAIMS,
        }
        (evidence / "board_validation_runbook.json").write_text(json.dumps(runbook), encoding="utf-8")
        report = build_preflight(root, DEFAULT_EVIDENCE_ROOT, require_board=False)
        if report["status"] == "FAIL":
            print("[FAIL] preflight self-test should tolerate absent board when not required", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        if not all(report["runbook_checks"].values()):
            print("[FAIL] preflight self-test runbook checks failed", file=sys.stderr)
            return 1
        write_outputs(report, evidence)
        if not (evidence / "board_validation_preflight.json").exists() or not (evidence / "board_validation_preflight.md").exists():
            print("[FAIL] preflight output files missing", file=sys.stderr)
            return 1
        bad = dict(runbook)
        bad["trace_records"] = 256
        (evidence / "board_validation_runbook.json").write_text(json.dumps(bad), encoding="utf-8")
        bad_report = build_preflight(root, DEFAULT_EVIDENCE_ROOT, require_board=False)
        if bad_report["status"] != "FAIL":
            print("[FAIL] preflight self-test should fail when trace baseline drifts", file=sys.stderr)
            return 1
    print("[PASS] 35T board preflight self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check readiness for the targeted 35T board-validation runbook.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--require-board", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    try:
        report = build_preflight(repo_root, args.evidence_root, args.require_board)
        if not args.no_write:
            write_outputs(report, repo_path(repo_root, args.evidence_root).resolve())
    except Exception as exc:
        print(f"check_35t_board_preflight: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T board validation preflight")
    for failure in report["failures"]:
        print(f"FAIL: {failure}", file=sys.stderr)
    for warning in report["warnings"]:
        print(f"WARN: {warning}", file=sys.stderr)
    if report["status"] == "FAIL":
        return 1
    if args.require_board and not report["hardware_ready"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
