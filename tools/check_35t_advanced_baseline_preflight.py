from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


PRIMARY_RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
RUN_ID = "35t-advanced-baseline-preflight-20260523"
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / PRIMARY_RUN_ID
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]


QEMU_PROBE_SCRIPT = r"""
set +e
qemu_path="$(command -v qemu-riscv64 2>/dev/null || true)"
qemu_version=""
if [ -n "$qemu_path" ]; then
  qemu_version="$(qemu-riscv64 --version 2>&1 | head -n 1 || true)"
fi
qemu_system_path="$(command -v qemu-system-riscv64 2>/dev/null || true)"
qemu_system_version=""
if [ -n "$qemu_system_path" ]; then
  qemu_system_version="$(qemu-system-riscv64 --version 2>&1 | head -n 1 || true)"
fi
help_has_plugin=0
if [ -n "$qemu_path" ] && qemu-riscv64 --help 2>&1 | grep -- "-plugin" >/dev/null; then
  help_has_plugin=1
fi
system_help_has_plugin=0
if [ -n "$qemu_system_path" ] && qemu-system-riscv64 --help 2>&1 | grep -- "-plugin" >/dev/null; then
  system_help_has_plugin=1
fi
headers="$(find /usr -name qemu-plugin.h 2>/dev/null | paste -sd ';' -)"
header_count=0
if [ -n "$headers" ]; then
  header_count="$(printf '%s' "$headers" | tr ';' '\n' | grep -c . || true)"
fi
printf 'qemu_path=%s\n' "$qemu_path"
printf 'qemu_version=%s\n' "$qemu_version"
printf 'qemu_system_path=%s\n' "$qemu_system_path"
printf 'qemu_system_version=%s\n' "$qemu_system_version"
printf 'help_has_plugin=%s\n' "$help_has_plugin"
printf 'system_help_has_plugin=%s\n' "$system_help_has_plugin"
printf 'qemu_plugin_header_count=%s\n' "$header_count"
printf 'qemu_plugin_headers=%s\n' "$headers"
true
""".strip()


EBPF_PROBE_SCRIPT = r"""
set +e
printf 'kernel=%s\n' "$(uname -r 2>/dev/null || true)"
printf 'clang_path=%s\n' "$(command -v clang 2>/dev/null || true)"
printf 'llc_path=%s\n' "$(command -v llc 2>/dev/null || true)"
printf 'bpftool_path=%s\n' "$(command -v bpftool 2>/dev/null || true)"
printf 'bpftrace_path=%s\n' "$(command -v bpftrace 2>/dev/null || true)"
if [ -e /sys/kernel/tracing/kprobe_events ]; then
  printf 'kprobe_events_path=%s\n' "/sys/kernel/tracing/kprobe_events"
elif [ -e /sys/kernel/debug/tracing/kprobe_events ]; then
  printf 'kprobe_events_path=%s\n' "/sys/kernel/debug/tracing/kprobe_events"
else
  printf 'kprobe_events_path=\n'
fi
if [ -w /sys/kernel/tracing/kprobe_events ] || [ -w /sys/kernel/debug/tracing/kprobe_events ]; then
  printf 'kprobe_events_writable=1\n'
else
  printf 'kprobe_events_writable=0\n'
fi
if mount | grep tracefs >/dev/null 2>&1; then
  printf 'tracefs_mounted=1\n'
else
  printf 'tracefs_mounted=0\n'
fi
if mount | grep ' bpf ' >/dev/null 2>&1; then
  printf 'bpffs_mounted=1\n'
else
  printf 'bpffs_mounted=0\n'
fi
true
""".strip()


EBPF_CAPABILITY_PROBE_SCRIPT = r"""
set +e
mkdir -p /sys/kernel/tracing /sys/kernel/debug/tracing 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing >/tmp/rvmt_tracefs_mount.log 2>&1 || true
mount -t debugfs debugfs /sys/kernel/debug >/tmp/rvmt_debugfs_mount.log 2>&1 || true
printf 'tracefs_mount_log=%s\n' "$(tail -n 1 /tmp/rvmt_tracefs_mount.log 2>/dev/null || true)"
printf 'debugfs_mount_log=%s\n' "$(tail -n 1 /tmp/rvmt_debugfs_mount.log 2>/dev/null || true)"
""".strip() + "\n" + EBPF_PROBE_SCRIPT


EBPF_SMOKE_SCRIPT = r"""
if command -v bpftrace >/dev/null 2>&1 && { [ -w /sys/kernel/tracing/kprobe_events ] || [ -w /sys/kernel/debug/tracing/kprobe_events ]; }; then
  printf 'import os\nfor _ in range(10):\n    os.getpid()\n' > /tmp/rvmt_getpid.py
  timeout 15 bpftrace -e 'kprobe:__x64_sys_getpid { @rvmt_getpid = count(); } interval:s:1 { exit(); }' -c 'python3 /tmp/rvmt_getpid.py' > /tmp/rvmt_bpftrace.out 2> /tmp/rvmt_bpftrace.err
  smoke_exit="$?"
  smoke_count="$(awk -F': *' '/@rvmt_getpid/ {print $2}' /tmp/rvmt_bpftrace.out | tail -n 1)"
  printf 'bpftrace_smoke_exit=%s\n' "$smoke_exit"
  printf 'bpftrace_smoke_count=%s\n' "$smoke_count"
  printf 'bpftrace_smoke_stdout=%s\n' "$(tr '\n' '|' < /tmp/rvmt_bpftrace.out | cut -c 1-240)"
  printf 'bpftrace_smoke_stderr=%s\n' "$(tr '\n' '|' < /tmp/rvmt_bpftrace.err | cut -c 1-240)"
else
  printf 'bpftrace_smoke_exit=not_run\n'
  printf 'bpftrace_smoke_count=0\n'
  printf 'bpftrace_smoke_stdout=\n'
  printf 'bpftrace_smoke_stderr=missing_bpftrace_or_writable_kprobe_events\n'
fi
true
""".strip()


EBPF_CAPABILITY_PROBE_SCRIPT = EBPF_CAPABILITY_PROBE_SCRIPT + "\n" + EBPF_SMOKE_SCRIPT


def repo_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def docker_compose_base() -> list[str]:
    return ["docker", "compose", "-f", "docker-compose.toolchain.yml"]


def run_docker_bash(repo_root: Path, script: str, timeout_s: int, extra_run_args: tuple[str, ...] = ()) -> dict[str, Any]:
    cmd = [*docker_compose_base(), "run", "--rm", *extra_run_args, "linux-behavior", "bash", "-lc", script]
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(repo_root),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
        )
    except FileNotFoundError as exc:
        return {
            "argv": cmd,
            "exit_code": 127,
            "stdout": "",
            "stderr": str(exc),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "argv": cmd,
            "exit_code": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or f"timeout after {timeout_s}s",
        }
    return {
        "argv": cmd,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def run_wsl_bash(repo_root: Path, script: str, timeout_s: int, *, root_user: bool = False) -> dict[str, Any] | None:
    if not shutil.which("wsl.exe") and not shutil.which("wsl"):
        return None
    cmd = ["wsl.exe", "--user", "root", "--exec", "sh", "-lc", script] if root_user else ["wsl.exe", "--exec", "sh", "-lc", script]
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(repo_root),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired as exc:
        return {
            "argv": cmd,
            "exit_code": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or f"timeout after {timeout_s}s",
        }
    return {
        "argv": cmd,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def parse_key_values(stdout: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key and all(ch.isalnum() or ch == "_" for ch in key):
            values[key] = value.strip()
    return values


def bool_field(values: dict[str, str], key: str) -> bool:
    return values.get(key) in {"1", "true", "True", "yes", "YES"}


def int_field(values: dict[str, str], key: str) -> int:
    try:
        return int(values.get(key, "0"))
    except ValueError:
        return 0


def positive_int_field(values: dict[str, str], key: str) -> bool:
    try:
        return int(values.get(key, "0")) > 0
    except ValueError:
        return False


def evaluate_qemu_plugin(values: dict[str, str], exit_code: int) -> dict[str, Any]:
    checks = {
        "container_command_passed": exit_code == 0,
        "qemu_riscv64_available": bool(values.get("qemu_path")),
        "qemu_system_riscv64_available": bool(values.get("qemu_system_path")),
        "qemu_user_exposes_plugin_option": bool_field(values, "help_has_plugin"),
        "qemu_system_exposes_plugin_option": bool_field(values, "system_help_has_plugin"),
        "qemu_plugin_header_available": int_field(values, "qemu_plugin_header_count") > 0,
    }
    reasons = []
    if not checks["container_command_passed"]:
        reasons.append("probe command failed")
    if not checks["qemu_riscv64_available"] and not checks["qemu_system_riscv64_available"]:
        reasons.append("neither qemu-riscv64 nor qemu-system-riscv64 is available in this probe environment")
    if not checks["qemu_user_exposes_plugin_option"] and not checks["qemu_system_exposes_plugin_option"]:
        reasons.append("neither qemu-riscv64 nor qemu-system-riscv64 exposes -plugin in the current package")
    if not checks["qemu_plugin_header_available"]:
        reasons.append("qemu-plugin.h is not installed in the current package set")
    has_plugin_binary = checks["qemu_user_exposes_plugin_option"] or checks["qemu_system_exposes_plugin_option"]
    status = (
        "READY"
        if checks["container_command_passed"] and has_plugin_binary and checks["qemu_plugin_header_available"]
        else "BLOCKED_CURRENT_ENVIRONMENT"
    )
    return {
        "baseline": "qemu_plugin",
        "status": status,
        "checks": checks,
        "reason": "; ".join(reasons) if reasons else "QEMU plugin prerequisites are present",
        "observed": {
            "qemu_path": values.get("qemu_path", ""),
            "qemu_version": values.get("qemu_version", ""),
            "qemu_system_path": values.get("qemu_system_path", ""),
            "qemu_system_version": values.get("qemu_system_version", ""),
            "qemu_plugin_header_count": int_field(values, "qemu_plugin_header_count"),
            "qemu_plugin_headers": values.get("qemu_plugin_headers", ""),
        },
    }


def evaluate_ebpf_only(values: dict[str, str], exit_code: int) -> dict[str, Any]:
    checks = {
        "container_command_passed": exit_code == 0,
        "bpf_compiler_available": bool(values.get("clang_path")) or bool(values.get("llc_path")),
        "bpf_loader_or_tracer_available": bool(values.get("bpftool_path")) or bool(values.get("bpftrace_path")),
        "tracefs_mounted": bool_field(values, "tracefs_mounted"),
        "kprobe_events_available": bool(values.get("kprobe_events_path")),
        "kprobe_events_writable": bool_field(values, "kprobe_events_writable"),
        "bpftrace_smoke_passed": values.get("bpftrace_smoke_exit") == "0" and positive_int_field(values, "bpftrace_smoke_count"),
    }
    reasons = []
    if not checks["bpf_compiler_available"]:
        reasons.append("clang/llc BPF compiler tooling is not installed")
    if not checks["bpf_loader_or_tracer_available"]:
        reasons.append("bpftool/bpftrace loader or tracer tooling is not installed")
    if not checks["tracefs_mounted"]:
        reasons.append("tracefs is not mounted in this probe environment")
    if not checks["kprobe_events_available"]:
        reasons.append("kprobe_events is not visible through tracefs/debugfs")
    if not checks["kprobe_events_writable"]:
        reasons.append("kprobe_events is not writable from this probe environment")
    if not checks["bpftrace_smoke_passed"]:
        reasons.append("bpftrace kprobe smoke did not run or did not capture events")
    status = "READY" if all(checks.values()) else "BLOCKED_CURRENT_ENVIRONMENT"
    return {
        "baseline": "ebpf_only",
        "status": status,
        "checks": checks,
        "reason": "; ".join(reasons) if reasons else "eBPF kprobe baseline prerequisites are present",
        "observed": {
            "kernel": values.get("kernel", ""),
            "clang_path": values.get("clang_path", ""),
            "llc_path": values.get("llc_path", ""),
            "bpftool_path": values.get("bpftool_path", ""),
            "bpftrace_path": values.get("bpftrace_path", ""),
            "kprobe_events_path": values.get("kprobe_events_path", ""),
            "bpffs_mounted": bool_field(values, "bpffs_mounted"),
            "bpftrace_smoke_exit": values.get("bpftrace_smoke_exit", ""),
            "bpftrace_smoke_count": int_field(values, "bpftrace_smoke_count"),
            "bpftrace_smoke_stdout": values.get("bpftrace_smoke_stdout", ""),
            "bpftrace_smoke_stderr": values.get("bpftrace_smoke_stderr", ""),
        },
    }


def compact_probe(result: dict[str, Any], values: dict[str, str]) -> dict[str, Any]:
    return {
        "argv": result["argv"],
        "exit_code": result["exit_code"],
        "fields": values,
        "stderr": result.get("stderr", "")[-2000:],
    }


def summarize_environment_rows(baseline: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    ready = [row for row in rows if row.get("status") == "READY"]
    if ready:
        chosen = ready[0]
        return {
            **chosen,
            "reason": f"{chosen['environment']}: {chosen['reason']}",
            "environment_results": rows,
        }
    checks: dict[str, bool] = {}
    for row in rows:
        for key, ok in row.get("checks", {}).items():
            checks[f"{row['environment']}.{key}"] = bool(ok)
    reasons = "; ".join(f"{row['environment']}: {row['reason']}" for row in rows)
    observed = {str(row["environment"]): row.get("observed", {}) for row in rows}
    return {
        "baseline": baseline,
        "status": "BLOCKED_CURRENT_ENVIRONMENT",
        "checks": checks,
        "reason": reasons or "no baseline probe environments were available",
        "observed": observed,
        "environment_results": rows,
    }


def next_actions_for(baseline_rows: dict[str, dict[str, Any]]) -> list[str]:
    actions: list[str] = []
    ebpf_status = baseline_rows.get("ebpf_only", {}).get("status")
    qemu_status = baseline_rows.get("qemu_plugin", {}).get("status")
    if ebpf_status == "READY":
        actions.append(
            "run a separate 13-sample eBPF-only event and overhead baseline in the READY environment before reporting ebpf_only as PASS"
        )
    else:
        actions.append(
            "install BPF compiler/loader tooling and run in an environment with mounted writable tracefs/kprobe access before running eBPF-only baseline"
        )
    if qemu_status == "READY":
        actions.append(
            "run a separate 13-sample QEMU-plugin trace and timing baseline before reporting qemu_plugin as PASS"
        )
    else:
        actions.append(
            "provide qemu-plugin.h plus either a plugin-capable qemu-riscv64 user-mode binary or a qemu-system-riscv64 harness before running qemu_plugin baseline"
        )
    return actions


def apply_completed_evidence_context(report: dict[str, Any], evidence_root: Path) -> dict[str, Any]:
    ebpf_summary_path = evidence_root / "ebpf_baseline_summary.json"
    if not ebpf_summary_path.exists():
        return report
    try:
        ebpf_summary = json.loads(ebpf_summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return report
    if ebpf_summary.get("status") != "PASS":
        return report
    report = dict(report)
    report["next_actions"] = [
        item for item in report.get("next_actions", []) if "eBPF-only" not in item and "eBPF-only baseline" not in item
    ]
    return report


def build_report_from_environment_probe_results(environments: dict[str, dict[str, dict[str, Any]]]) -> dict[str, Any]:
    qemu_rows = []
    ebpf_rows = []
    probes: dict[str, Any] = {}
    for env_name, env_results in environments.items():
        qemu_result = env_results["qemu_plugin"]
        ebpf_result = env_results["ebpf_only"]
        qemu_values = parse_key_values(str(qemu_result.get("stdout", "")))
        ebpf_values = parse_key_values(str(ebpf_result.get("stdout", "")))
        qemu = evaluate_qemu_plugin(qemu_values, int(qemu_result.get("exit_code", 1)))
        ebpf = evaluate_ebpf_only(ebpf_values, int(ebpf_result.get("exit_code", 1)))
        qemu["environment"] = env_name
        ebpf["environment"] = env_name
        qemu_rows.append(qemu)
        ebpf_rows.append(ebpf)
        probes[f"{env_name}.qemu_plugin"] = compact_probe(qemu_result, qemu_values)
        probes[f"{env_name}.ebpf_only"] = compact_probe(ebpf_result, ebpf_values)
    qemu = summarize_environment_rows("qemu_plugin", qemu_rows)
    ebpf = summarize_environment_rows("ebpf_only", ebpf_rows)
    baseline_rows = {
        "ebpf_only": ebpf,
        "qemu_plugin": qemu,
    }
    ready = all(row["status"] == "READY" for row in baseline_rows.values())
    return {
        "schema": "rvmt.35t.advanced_baseline_preflight.v1",
        "run_id": RUN_ID,
        "source_run_id": PRIMARY_RUN_ID,
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "status": "READY_TO_RUN_ADVANCED_BASELINES" if ready else "BLOCKED_CURRENT_ENVIRONMENT",
        "baselines": baseline_rows,
        "probe_environments": sorted(environments),
        "probes": probes,
        "interpretation": [
            "this preflight checks whether current local Docker and WSL environments can run the remaining advanced baselines",
            "READY or BLOCKED statuses are environment evidence, not completed baseline comparisons",
            "baseline prerequisites are evaluated per environment and are not combined across environments",
            "software instrumentation evidence is tracked separately and is not a substitute for eBPF-only or QEMU-plugin evidence",
        ],
        "next_actions": next_actions_for(baseline_rows),
        "non_claims": NON_CLAIMS,
    }


def build_report_from_probe_results(qemu_result: dict[str, Any], ebpf_result: dict[str, Any]) -> dict[str, Any]:
    return build_report_from_environment_probe_results(
        {"docker_linux_behavior": {"qemu_plugin": qemu_result, "ebpf_only": ebpf_result}}
    )


def collect_report(repo_root: Path, timeout_s: int) -> dict[str, Any]:
    environments = {
        "docker_linux_behavior": {
            "qemu_plugin": run_docker_bash(repo_root, QEMU_PROBE_SCRIPT, timeout_s),
            "ebpf_only": run_docker_bash(repo_root, EBPF_PROBE_SCRIPT, timeout_s),
        },
        "docker_linux_behavior_cap_sys_admin": {
            "qemu_plugin": run_docker_bash(
                repo_root,
                QEMU_PROBE_SCRIPT,
                timeout_s,
                ("--cap-add", "SYS_ADMIN", "--cap-add", "SYS_PTRACE"),
            ),
            "ebpf_only": run_docker_bash(
                repo_root,
                EBPF_CAPABILITY_PROBE_SCRIPT,
                timeout_s,
                ("--cap-add", "SYS_ADMIN", "--cap-add", "SYS_PTRACE"),
            ),
        }
    }
    wsl_qemu = run_wsl_bash(repo_root, QEMU_PROBE_SCRIPT, timeout_s)
    wsl_ebpf = run_wsl_bash(repo_root, EBPF_PROBE_SCRIPT, timeout_s)
    if wsl_qemu is not None and wsl_ebpf is not None:
        environments["wsl"] = {"qemu_plugin": wsl_qemu, "ebpf_only": wsl_ebpf}
    wsl_root_qemu = run_wsl_bash(repo_root, QEMU_PROBE_SCRIPT, timeout_s, root_user=True)
    wsl_root_ebpf = run_wsl_bash(repo_root, EBPF_PROBE_SCRIPT, timeout_s, root_user=True)
    if wsl_root_qemu is not None and wsl_root_ebpf is not None:
        environments["wsl_root"] = {"qemu_plugin": wsl_root_qemu, "ebpf_only": wsl_root_ebpf}
    return build_report_from_environment_probe_results(environments)


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Advanced Baseline Preflight: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Scope: {report['scope']}.",
        "",
        f"Claim level: {report['claim_level']}.",
        "",
        "## Baselines",
        "",
        "| Baseline | Status | Reason |",
        "| --- | --- | --- |",
    ]
    for name, row in report["baselines"].items():
        lines.append(f"| `{name}` | `{row['status']}` | {row['reason']} |")
    lines += ["", "## Checks", ""]
    for name, row in report["baselines"].items():
        lines.append(f"### {name}")
        lines.append("")
        if row.get("environment_results"):
            lines.append("Environment results:")
            for env_row in row["environment_results"]:
                lines.append(f"- `{env_row['environment']}`: `{env_row['status']}` - {env_row['reason']}")
            lines.append("")
        for key, ok in row["checks"].items():
            lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
        lines.append("")
    lines += ["## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Next Actions", ""]
    lines.extend(f"- {item}" for item in report["next_actions"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "advanced_baseline_preflight.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "advanced_baseline_preflight.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def fake_probe(stdout: str, exit_code: int = 0) -> dict[str, Any]:
    return {"argv": ["fake"], "exit_code": exit_code, "stdout": stdout, "stderr": ""}


def self_test() -> int:
    ready = build_report_from_probe_results(
        fake_probe(
            "\n".join(
                [
                    "qemu_path=/usr/bin/qemu-riscv64",
                    "qemu_version=qemu-riscv64 version test",
                    "help_has_plugin=1",
                    "qemu_plugin_header_count=1",
                    "qemu_plugin_headers=/usr/include/qemu/qemu-plugin.h",
                ]
            )
        ),
        fake_probe(
            "\n".join(
                [
                    "kernel=test",
                    "clang_path=/usr/bin/clang",
                    "llc_path=/usr/bin/llc",
                    "bpftool_path=/usr/sbin/bpftool",
                    "bpftrace_path=",
                    "kprobe_events_path=/sys/kernel/tracing/kprobe_events",
                    "kprobe_events_writable=1",
                    "tracefs_mounted=1",
                    "bpffs_mounted=1",
                    "bpftrace_smoke_exit=0",
                    "bpftrace_smoke_count=10",
                ]
            )
        ),
    )
    if ready["status"] != "READY_TO_RUN_ADVANCED_BASELINES":
        print("[FAIL] expected ready fixture to pass advanced baseline preflight", file=sys.stderr)
        return 1

    blocked = build_report_from_probe_results(
        fake_probe("qemu_path=/usr/bin/qemu-riscv64\nhelp_has_plugin=0\nqemu_plugin_header_count=0\n"),
        fake_probe("kernel=test\ntracefs_mounted=0\nkprobe_events_writable=0\n"),
    )
    if blocked["status"] != "BLOCKED_CURRENT_ENVIRONMENT":
        print("[FAIL] expected missing-tool fixture to block advanced baseline preflight", file=sys.stderr)
        return 1
    if blocked["baselines"]["qemu_plugin"]["status"] != "BLOCKED_CURRENT_ENVIRONMENT":
        print("[FAIL] expected qemu plugin fixture to be blocked", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        evidence = Path(tmp) / DEFAULT_EVIDENCE_ROOT
        write_outputs(blocked, evidence)
        if not (evidence / "advanced_baseline_preflight.md").exists():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1
    print("[PASS] 35T advanced baseline preflight self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check whether remaining 35T advanced baselines can run locally.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--timeout-s", type=int, default=120)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        report = collect_report(repo_root, args.timeout_s)
        report = apply_completed_evidence_context(report, evidence_root)
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_advanced_baseline_preflight: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T advanced baseline preflight")
    for name, row in report["baselines"].items():
        print(f"{name}: {row['status']} - {row['reason']}")
    return 0 if report["status"] in {"READY_TO_RUN_ADVANCED_BASELINES", "BLOCKED_CURRENT_ENVIRONMENT"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
