from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    repo_rel,
    require,
    sha256_file,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/official_image_capability_matrix.json")
SCHEMA = "rvmt.genesys2.official_image_capability_matrix.v1"
ALLOWED_STATUSES = {
    "AVAILABLE",
    "MISSING_TOOL_ONLY",
    "MISSING_KERNEL_INTERFACE",
    "SYSCALL_ENOSYS",
    "PERMISSION_DENIED",
    "SIGILL_COUNTER_GATED",
    "OPERATION_NOT_SUPPORTED",
    "INCONCLUSIVE",
}


def artifact_row(root: Path, path: Path) -> dict[str, Any]:
    return {
        "path": repo_rel(root, path),
        "exists": path.is_file(),
        "sha256": sha256_file(path) if path.is_file() else None,
        "size_bytes": path.stat().st_size if path.is_file() else None,
    }


def parse_shell_log(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    tools: dict[str, dict[str, Any]] = {}
    paths: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        if line.startswith("RVMT_TOOL_PRESENT "):
            _, _, rest = line.partition("RVMT_TOOL_PRESENT ")
            parts = rest.split(None, 1)
            if parts:
                tools[parts[0]] = {"status": "AVAILABLE", "path": parts[1] if len(parts) > 1 else ""}
        elif line.startswith("RVMT_TOOL_MISSING "):
            name = line.split(None, 1)[1].strip()
            tools[name] = {"status": "MISSING_TOOL_ONLY"}
        elif line.startswith("RVMT_PATH_PRESENT "):
            value = line.split(None, 1)[1].strip()
            paths[value] = {"status": "AVAILABLE"}
        elif line.startswith("RVMT_PATH_MISSING "):
            value = line.split(None, 1)[1].strip()
            paths[value] = {"status": "MISSING_KERNEL_INTERFACE"}
    return {
        "begin_seen": "RVMT_CAPABILITY_BEGIN" in text,
        "done_seen": "RVMT_CAPABILITY_DONE" in text,
        "tools": tools,
        "paths": paths,
        "randomize_va_space_values": re.findall(r"(?m)^[012]\s*$", text),
    }


def parse_probe_log(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    probes: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        if not line.startswith("RVMT_CAP_PROBE "):
            continue
        fields: dict[str, str] = {}
        for item in line.split()[1:]:
            if "=" in item:
                key, value = item.split("=", 1)
                fields[key] = value
        name = fields.pop("name", "")
        status = fields.pop("status", "INCONCLUSIVE")
        if name:
            probes[name] = {"status": status, "raw_fields": fields, "raw_line": line}
    rc_match = re.search(r"RVMT_CAPABILITY_PROBE_RC=(\d+)", text)
    return {
        "begin_seen": "RVMT_CAPABILITY_PROBE_BEGIN" in text,
        "done_seen": "RVMT_CAPABILITY_PROBE_DONE" in text,
        "returncode": int(rc_match.group(1)) if rc_match else None,
        "probes": probes,
    }


def normalized_capabilities(shell: dict[str, Any], probe: dict[str, Any]) -> dict[str, Any]:
    caps = dict(probe.get("probes") or {})
    tools = shell.get("tools") or {}
    paths = shell.get("paths") or {}
    if "perf_event_open_null" in caps and tools.get("perf", {}).get("status") == "MISSING_TOOL_ONLY":
        caps["perf_tool"] = {"status": "MISSING_TOOL_ONLY", "note": "tool presence is not kernel capability"}
    if "bpf_null" in caps and tools.get("bpftool", {}).get("status") == "MISSING_TOOL_ONLY":
        caps["bpftool"] = {"status": "MISSING_TOOL_ONLY", "note": "tool presence is not kernel capability"}
    for key in ("/sys/kernel/debug", "/sys/kernel/tracing", "/sys/fs/bpf", "/sys/bus/event_source/devices"):
        if key in paths:
            caps[key] = paths[key]
    return caps


def package_summary(
    *,
    root: Path,
    run_root: Path,
    build_manifest: Path,
    transfer_log: Path,
    shell_log: Path,
    probe_log: Path,
    target: str,
) -> dict[str, Any]:
    shell = parse_shell_log(shell_log)
    probe = parse_probe_log(probe_log)
    capabilities = normalized_capabilities(shell, probe)
    missing_core_logs = not (shell["begin_seen"] and shell["done_seen"] and probe["begin_seen"] and probe["done_seen"])
    rdcycle_status = capabilities.get("rdcycle", {}).get("status")
    status = "PASS" if not missing_core_logs else "INCONCLUSIVE_CAPABILITY_CAPTURE_INCOMPLETE"
    return {
        "schema": SCHEMA,
        "status": status,
        "run_root": repo_rel(root, run_root),
        "target": target,
        "artifacts": {
            "build_manifest": artifact_row(root, build_manifest),
            "transfer_log": artifact_row(root, transfer_log),
            "capability_shell_log": artifact_row(root, shell_log),
            "capability_probe_uart_log": artifact_row(root, probe_log),
        },
        "shell_probe": shell,
        "syscall_csr_probe": probe,
        "capability_matrix": capabilities,
        "claim_boundary": {
            "tool_missing_does_not_imply_kernel_missing": True,
            "rdtime_is_non_cycle_source": capabilities.get("rdtime", {}).get("status") == "AVAILABLE",
            "rdcycle_sigill_means_user_access_gated_not_hardware_absent": rdcycle_status == "SIGILL_COUNTER_GATED",
            "cycle_level_overhead_claimed": False,
            "ebpf_claimed_available": capabilities.get("bpf_null", {}).get("status") == "AVAILABLE",
        },
        "non_claims": [
            "This matrix classifies observed official-image user-space tools, kernel paths, syscall errno, and CSR accessibility.",
            "rdtime and clock_gettime availability are non-cycle timing observations and do not close cycle-overhead claims.",
            "A missing perf or bpftool binary is not treated as kernel feature absence without the syscall/path probe rows.",
        ],
    }


def check_summary(root: Path, summary: Path) -> list[str]:
    errors: list[str] = []
    data = load_json(summary)
    require(errors, data.get("schema") == SCHEMA, "schema mismatch")
    require(errors, data.get("status") == "PASS" or str(data.get("status")).startswith(("BLOCKED_", "INCONCLUSIVE_")), "status mismatch")
    for name, row in (data.get("artifacts") or {}).items():
        if not isinstance(row, dict):
            errors.append(f"artifact row invalid: {name}")
            continue
        path = root / str(row.get("path"))
        require(errors, path.is_file(), f"artifact missing: {name}")
        if path.is_file():
            require(errors, row.get("sha256") == sha256_file(path), f"artifact sha256 mismatch: {name}")
    caps = data.get("capability_matrix") if isinstance(data.get("capability_matrix"), dict) else {}
    for name in ("rdcycle", "rdinstret", "rdtime", "clock_gettime_monotonic", "perf_event_open_null", "bpf_null", "ptrace_traceme", "prctl_get_name_badptr"):
        require(errors, name in caps, f"capability missing: {name}")
    for name, row in caps.items():
        if isinstance(row, dict):
            require(errors, row.get("status") in ALLOWED_STATUSES, f"{name}: invalid status {row.get('status')}")
    boundary = data.get("claim_boundary") if isinstance(data.get("claim_boundary"), dict) else {}
    require(errors, boundary.get("tool_missing_does_not_imply_kernel_missing") is True, "tool/kernel boundary missing")
    require(errors, boundary.get("cycle_level_overhead_claimed") is False, "must not claim cycle overhead")
    if caps.get("rdtime", {}).get("status") == "AVAILABLE":
        require(errors, boundary.get("rdtime_is_non_cycle_source") is True, "rdtime non-cycle boundary missing")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-official-capability-") as tmp:
        root = Path(tmp)
        run_root = root / "run"
        run_root.mkdir()
        build = run_root / "build_manifest.json"
        transfer = run_root / "transfer.log"
        shell = run_root / "capability_shell.log"
        probe = run_root / "capability_probe_uart.log"
        build.write_text("{}\n", encoding="utf-8")
        transfer.write_text("transfer\n", encoding="utf-8")
        shell.write_text(
            "RVMT_CAPABILITY_BEGIN\nRVMT_TOOL_MISSING perf\nRVMT_TOOL_PRESENT busybox /bin/busybox\n"
            "RVMT_PATH_MISSING /sys/fs/bpf\nRVMT_CAPABILITY_DONE\n",
            encoding="utf-8",
        )
        probe.write_text(
            "RVMT_CAPABILITY_PROBE_BEGIN pid=1\n"
            "RVMT_CAP_PROBE name=rdcycle status=SIGILL_COUNTER_GATED signal=SIGILL\n"
            "RVMT_CAP_PROBE name=rdinstret status=SIGILL_COUNTER_GATED signal=SIGILL\n"
            "RVMT_CAP_PROBE name=rdtime status=AVAILABLE value0=1 value1=2 delta=1\n"
            "RVMT_CAP_PROBE name=clock_gettime_monotonic status=AVAILABLE rc=0 errno=0\n"
            "RVMT_CAP_PROBE name=perf_event_open_null status=SYSCALL_ENOSYS rc=-1 errno=38\n"
            "RVMT_CAP_PROBE name=bpf_null status=PERMISSION_DENIED rc=-1 errno=1\n"
            "RVMT_CAP_PROBE name=ptrace_traceme status=AVAILABLE rc=0 errno=0\n"
            "RVMT_CAP_PROBE name=prctl_get_name_badptr status=AVAILABLE rc=-1 errno=14\n"
            "RVMT_CAPABILITY_PROBE_DONE\nRVMT_CAPABILITY_PROBE_RC=0\n",
            encoding="utf-8",
        )
        summary = root / DEFAULT_SUMMARY
        write_json(summary, package_summary(root=root, run_root=run_root, build_manifest=build, transfer_log=transfer, shell_log=shell, probe_log=probe, target="/tmp/probe"))
        errors = check_summary(root, summary)
        if errors:
            print("[FAIL] self-test checker rejected fixture", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
            return 1
    print("[PASS] official image capability checker self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check the official CVA6 SD-image capability matrix.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = args.summary if args.summary.is_absolute() else root / args.summary
    if not summary.is_file():
        print(f"[FAIL] official image capability summary missing: {summary}", file=sys.stderr)
        return 1
    errors = check_summary(root, summary)
    if errors:
        print("[FAIL] official image capability matrix is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] official image capability matrix accepted: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
