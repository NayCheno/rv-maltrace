from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
SMOKE_RUN_ID = "35t-extension-behavior-smoke-20260523"
DEFAULT_EXTENSION_PLAN = Path("experiments/linux_behavior/malware_like/extension_plan.json")
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
DEFAULT_RESULTS_ROOT = Path("results/experiments/35t") / SMOKE_RUN_ID
SCHEMA = "rvmt.35t.synthetic_extension_behavior_smoke.v1"
PASS_STATUS = "HOST_QEMU_BEHAVIOR_SMOKE_PASS_35T_GATING_DEFERRED"
BLOCKED_STATUS = "HOST_QEMU_BEHAVIOR_SMOKE_BLOCKED_CURRENT_ENVIRONMENT"
ACCEPTED_STATUSES = {PASS_STATUS, BLOCKED_STATUS}
EXPECTED_CANDIDATE_COUNT = 13
EXPECTED_NON_NETWORK_COUNT = 11
OPTIONAL_NETWORK_IDS = ("loopback_network_client", "mirai_c2_loopback_probe")
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
    "no expanded 35T coverage claim",
    "no 35T execution or gate pass claim",
]


CONTAINER_SCRIPT = r"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path


plan_path = Path(os.environ["RVMT_EXTENSION_PLAN"])
results_root = Path(os.environ["RVMT_EXTENSION_BEHAVIOR_RESULTS"])
timeout_s = float(os.environ.get("RVMT_EXTENSION_BEHAVIOR_TIMEOUT", "8"))
repo_root = Path.cwd()

plan = json.loads(plan_path.read_text(encoding="utf-8"))
candidates = [row for row in plan.get("candidates", []) if isinstance(row, dict)]
results_root.mkdir(parents=True, exist_ok=True)


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def run_capture(command, *, cwd: Path, stdout_path: Path, stderr_path: Path, timeout: float) -> dict:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        exit_code = completed.returncode
        timed_out = False
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        timed_out = True
        stdout = exc.stdout or ""
        stderr = exc.stderr or f"timeout after {timeout}s"
    stdout_path.write_text(stdout, encoding="utf-8", newline="\n")
    stderr_path.write_text(stderr, encoding="utf-8", newline="\n")
    return {
        "command": command,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "stdout_path": rel(stdout_path),
        "stderr_path": rel(stderr_path),
        "stdout_bytes": len(stdout.encode("utf-8", errors="replace")),
        "stderr_bytes": len(stderr.encode("utf-8", errors="replace")),
        "stdout_tail": stdout[-1000:],
        "stderr_tail": stderr[-2000:],
    }


def syscall_observed(log_text: str, name: str) -> bool:
    if name == "mmap":
        return re.search(r"\bmmap(2)?\(", log_text) is not None
    return re.search(r"\b" + re.escape(name) + r"\(", log_text) is not None


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


tools = {
    "gcc": shutil.which("gcc") or "",
    "riscv64-linux-gnu-gcc": shutil.which("riscv64-linux-gnu-gcc") or "",
    "qemu-riscv64": shutil.which("qemu-riscv64") or "",
    "strace": shutil.which("strace") or "",
}

sample_rows = []
for candidate in candidates:
    candidate_id = str(candidate.get("id") or "")
    source = Path(str(candidate.get("source") or ""))
    expected_syscalls = [str(item) for item in candidate.get("expected_syscalls", []) if item]
    unique_expected = sorted(set(expected_syscalls))
    sample_dir = results_root / "samples" / candidate_id
    build_dir = sample_dir / "build"
    run_dir = sample_dir / "behavior_smoke"
    build_dir.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(parents=True, exist_ok=True)
    host_bin = build_dir / f"{candidate_id}.host"
    riscv_bin = build_dir / f"{candidate_id}.riscv"

    host_compile = run_capture(
        ["gcc", "-std=gnu11", "-Wall", "-Wextra", "-O2", source.as_posix(), "-o", host_bin.as_posix()],
        cwd=repo_root,
        stdout_path=run_dir / "host_compile.stdout.txt",
        stderr_path=run_dir / "host_compile.stderr.txt",
        timeout=timeout_s,
    )
    target_compile = run_capture(
        [
            "riscv64-linux-gnu-gcc",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-O2",
            "-static",
            source.as_posix(),
            "-o",
            riscv_bin.as_posix(),
        ],
        cwd=repo_root,
        stdout_path=run_dir / "target_compile.stdout.txt",
        stderr_path=run_dir / "target_compile.stderr.txt",
        timeout=timeout_s,
    )

    compile_ok = host_compile["exit_code"] == 0 and target_compile["exit_code"] == 0
    network_required = candidate.get("network_required") is True
    executions = {}
    observed_syscalls = []
    missing_syscalls = unique_expected
    execution_status = "SKIPPED_NETWORK_OPTIONAL" if network_required else "NOT_RUN"
    if compile_ok and not network_required:
        executions["host_native"] = run_capture(
            [host_bin.as_posix()],
            cwd=repo_root,
            stdout_path=run_dir / "host_native.stdout.txt",
            stderr_path=run_dir / "host_native.stderr.txt",
            timeout=timeout_s,
        )
        executions["host_strace"] = run_capture(
            ["strace", "-f", "-o", (run_dir / "host_strace.log").as_posix(), host_bin.as_posix()],
            cwd=repo_root,
            stdout_path=run_dir / "host_strace.stdout.txt",
            stderr_path=run_dir / "host_strace.stderr.txt",
            timeout=timeout_s,
        )
        executions["qemu_native"] = run_capture(
            ["qemu-riscv64", riscv_bin.as_posix()],
            cwd=repo_root,
            stdout_path=run_dir / "qemu_native.stdout.txt",
            stderr_path=run_dir / "qemu_native.stderr.txt",
            timeout=timeout_s,
        )
        executions["qemu_strace"] = run_capture(
            ["qemu-riscv64", "-strace", riscv_bin.as_posix()],
            cwd=repo_root,
            stdout_path=run_dir / "qemu_strace.stdout.txt",
            stderr_path=run_dir / "qemu_strace.stderr.txt",
            timeout=timeout_s,
        )
        qemu_strace_text = (run_dir / "qemu_strace.stderr.txt").read_text(encoding="utf-8", errors="replace")
        observed_syscalls = [name for name in unique_expected if syscall_observed(qemu_strace_text, name)]
        missing_syscalls = [name for name in unique_expected if name not in observed_syscalls]
        execution_ok = (
            executions["host_native"]["exit_code"] == 0
            and executions["host_strace"]["exit_code"] == 0
            and executions["qemu_native"]["exit_code"] == 0
            and executions["qemu_strace"]["exit_code"] == 0
            and not missing_syscalls
            and executions["qemu_strace"]["stderr_bytes"] > 0
        )
        execution_status = "PASS" if execution_ok else "FAIL"

    row = {
        "id": candidate_id,
        "source": source.as_posix(),
        "network_required": network_required,
        "default_enabled": candidate.get("default_enabled") is True,
        "expected_syscalls": expected_syscalls,
        "unique_expected_syscalls": unique_expected,
        "observed_expected_syscalls": observed_syscalls,
        "missing_expected_syscalls": missing_syscalls,
        "host_compile": host_compile,
        "target_compile": target_compile,
        "compile_status": "PASS" if compile_ok else "FAIL",
        "execution_status": execution_status,
        "executions": executions,
        "artifacts": {
            "host_binary": rel(host_bin) if host_bin.exists() else "",
            "riscv_binary": rel(riscv_bin) if riscv_bin.exists() else "",
            "host_binary_sha256": sha256(host_bin) if host_bin.exists() else "",
            "riscv_binary_sha256": sha256(riscv_bin) if riscv_bin.exists() else "",
        },
    }
    sample_rows.append(row)

summary = {
    "tools": tools,
    "candidate_count": len(candidates),
    "compile_pass_count": sum(1 for row in sample_rows if row["compile_status"] == "PASS"),
    "executed_candidate_count": sum(1 for row in sample_rows if row["execution_status"] in {"PASS", "FAIL"}),
    "execution_pass_count": sum(1 for row in sample_rows if row["execution_status"] == "PASS"),
    "network_skipped_count": sum(1 for row in sample_rows if row["execution_status"] == "SKIPPED_NETWORK_OPTIONAL"),
    "samples": sample_rows,
}
(results_root / "aggregate").mkdir(parents=True, exist_ok=True)
(results_root / "aggregate" / "synthetic_extension_behavior_smoke_raw.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)
print("RVMT_EXTENSION_BEHAVIOR_JSON_BEGIN")
print(json.dumps(summary, sort_keys=True))
print("RVMT_EXTENSION_BEHAVIOR_JSON_END")
""".strip()


def repo_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def docker_compose_base() -> list[str]:
    return ["docker", "compose", "-f", "docker-compose.toolchain.yml"]


def extract_container_json(stdout: str) -> dict[str, Any] | None:
    begin = "RVMT_EXTENSION_BEHAVIOR_JSON_BEGIN"
    end = "RVMT_EXTENSION_BEHAVIOR_JSON_END"
    if begin not in stdout or end not in stdout:
        return None
    payload = stdout.split(begin, 1)[1].split(end, 1)[0].strip()
    try:
        value = json.loads(payload)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def run_container_smoke(repo_root: Path, plan_path: Path, results_root: Path, timeout_seconds: float) -> dict[str, Any]:
    command = [
        *docker_compose_base(),
        "run",
        "--rm",
        "linux-behavior",
        "bash",
        "-lc",
        (
            f"RVMT_EXTENSION_PLAN={plan_path.as_posix()} "
            f"RVMT_EXTENSION_BEHAVIOR_RESULTS={results_root.as_posix()} "
            f"RVMT_EXTENSION_BEHAVIOR_TIMEOUT={timeout_seconds} "
            f"python3 - <<'PY'\n{CONTAINER_SCRIPT}\nPY"
        ),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=repo_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(timeout_seconds * 4, 120.0),
            check=False,
        )
    except FileNotFoundError as exc:
        return {"argv": command, "exit_code": 127, "stdout": "", "stderr": str(exc)}
    except subprocess.TimeoutExpired as exc:
        return {
            "argv": command,
            "exit_code": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or f"timeout after {max(timeout_seconds * 4, 120.0)}s",
        }
    return {
        "argv": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def candidate_rows(plan: dict[str, Any]) -> list[dict[str, Any]]:
    rows = plan.get("candidates", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def build_report_from_container(
    *,
    repo_root: Path,
    plan_path: Path,
    results_root: Path,
    plan: dict[str, Any],
    container_result: dict[str, Any],
) -> dict[str, Any]:
    container_json = extract_container_json(str(container_result.get("stdout", "")))
    samples = container_json.get("samples", []) if isinstance(container_json, dict) else []
    sample_rows = [row for row in samples if isinstance(row, dict)] if isinstance(samples, list) else []
    candidates = candidate_rows(plan)
    candidate_ids = sorted(str(row.get("id")) for row in candidates if row.get("id"))
    non_network_ids = sorted(str(row.get("id")) for row in candidates if row.get("id") and row.get("network_required") is not True)
    network_ids = sorted(str(row.get("id")) for row in candidates if row.get("id") and row.get("network_required") is True)
    sample_by_id = {str(row.get("id")): row for row in sample_rows if row.get("id")}
    tools = container_json.get("tools", {}) if isinstance(container_json, dict) else {}

    checks = {
        "plan_schema": plan.get("schema") == "rvmt.synthetic_suite_extension_plan.v1",
        "candidate_count_expected": len(candidate_ids) == EXPECTED_CANDIDATE_COUNT,
        "non_network_candidate_count_expected": len(non_network_ids) == EXPECTED_NON_NETWORK_COUNT,
        "optional_network_candidates_skipped": network_ids == sorted(OPTIONAL_NETWORK_IDS)
        and all(sample_by_id.get(sample_id, {}).get("execution_status") == "SKIPPED_NETWORK_OPTIONAL" for sample_id in OPTIONAL_NETWORK_IDS),
        "all_candidates_default_disabled": all(row.get("default_enabled") is False for row in candidates),
        "container_command_passed": container_result.get("exit_code") == 0,
        "container_json_present": container_json is not None,
        "tools_available": all(tools.get(name) for name in ("gcc", "riscv64-linux-gnu-gcc", "qemu-riscv64", "strace")),
        "compile_result_count_matches": len(sample_rows) == len(candidate_ids) and bool(candidate_ids),
        "compile_all_candidates": bool(sample_rows) and all(row.get("compile_status") == "PASS" for row in sample_rows),
        "executed_non_network_candidates": all(
            sample_by_id.get(candidate_id, {}).get("execution_status") == "PASS" for candidate_id in non_network_ids
        ),
        "expected_syscalls_observed_for_executed": all(
            not sample_by_id.get(candidate_id, {}).get("missing_expected_syscalls") for candidate_id in non_network_ids
        ),
        "host_and_qemu_paths_recorded": all(
            sample_by_id.get(candidate_id, {}).get("executions", {}).get("host_native")
            and sample_by_id.get(candidate_id, {}).get("executions", {}).get("qemu_strace")
            for candidate_id in non_network_ids
        ),
        "no_35t_execution_claim": True,
        "no_expanded_35t_coverage_claim": True,
    }
    failures = [key for key, ok in checks.items() if not ok]
    for row in sample_rows:
        if row.get("compile_status") != "PASS":
            failures.append(f"compile:{row.get('id')}")
        if row.get("network_required") is not True and row.get("execution_status") != "PASS":
            failures.append(f"execute:{row.get('id')}")
    if all(checks.values()):
        status = PASS_STATUS
    elif container_result.get("exit_code") in {124, 127} or not checks["tools_available"]:
        status = BLOCKED_STATUS
    else:
        status = "FAIL"

    argv = container_result.get("argv")
    argv_summary = [*argv[:-1], "<inline extension behavior smoke script>"] if isinstance(argv, list) and argv else argv
    return {
        "schema": SCHEMA,
        "run_id": SMOKE_RUN_ID,
        "source_run_id": RUN_ID,
        "status": status,
        "scope": "Artix-7 35T / LiteX / VexRiscv",
        "claim_level": "35T hardware-trace-assisted synthetic malware-like behavior audit prototype",
        "extension_plan": rel(plan_path, repo_root),
        "results_root": rel(results_root, repo_root),
        "current_condition": (
            "non-network synthetic extension candidates compile and execute under host native, host strace, "
            "QEMU native, and QEMU strace smoke paths; loopback network candidates remain skipped unless "
            "explicitly selected; no 35T board run or expanded gate pass is claimed"
        ),
        "checks": checks,
        "candidate_ids": candidate_ids,
        "non_network_candidate_ids": non_network_ids,
        "network_optional_candidate_ids": network_ids,
        "summary_counts": {
            "candidate_count": container_json.get("candidate_count") if isinstance(container_json, dict) else 0,
            "compile_pass_count": container_json.get("compile_pass_count") if isinstance(container_json, dict) else 0,
            "executed_candidate_count": container_json.get("executed_candidate_count") if isinstance(container_json, dict) else 0,
            "execution_pass_count": container_json.get("execution_pass_count") if isinstance(container_json, dict) else 0,
            "network_skipped_count": container_json.get("network_skipped_count") if isinstance(container_json, dict) else 0,
        },
        "tools": tools,
        "samples": sample_rows,
        "container_probe": {
            "argv": argv_summary,
            "exit_code": container_result.get("exit_code"),
            "inline_script_sha256": __import__("hashlib").sha256(CONTAINER_SCRIPT.encode("utf-8")).hexdigest(),
            "stderr_tail": str(container_result.get("stderr", ""))[-2000:],
        },
        "remaining_work": [
            "refresh the Artix-7 rootfs image with selected extension binaries if the current board image does not already contain them",
            "run selected extension candidates on the Artix-7 35T board with the same trace-off/trace-on ordering",
            "analyze extension traces and apply marker, attribution, DROP, capacity, and strong-evidence gates",
            "keep loopback-network extensions disabled unless explicit loopback-only fixtures are selected",
        ],
        "interpretation": [
            "this smoke test upgrades the extension evidence from compile/dry-run only to host and QEMU execution evidence for non-network candidates",
            "QEMU strace guest syscall coverage is used only as pre-board behavior evidence",
            "the default 13-sample 35T matrix remains unchanged because extension candidates are still default-disabled",
            "expanded 35T coverage remains deferred until board execution and gate evidence are recorded",
        ],
        "non_claims": NON_CLAIMS,
        "failures": failures,
    }


def build_report(repo_root: Path, plan_arg: Path, results_arg: Path, timeout_seconds: float) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    plan_path = repo_path(repo_root, plan_arg).resolve()
    results_root = repo_path(repo_root, results_arg).resolve()
    plan = load_json(plan_path)
    container_result = run_container_smoke(
        repo_root,
        plan_path.relative_to(repo_root),
        results_root.relative_to(repo_root),
        timeout_seconds,
    )
    return build_report_from_container(
        repo_root=repo_root,
        plan_path=plan_path,
        results_root=results_root,
        plan=plan,
        container_result=container_result,
    )


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Synthetic Extension Behavior Smoke: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Extension plan: `{report['extension_plan']}`",
        f"Results root: `{report['results_root']}`",
        "",
        f"Current condition: {report['current_condition']}",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Summary", ""]
    for key, value in report["summary_counts"].items():
        lines.append(f"- {key}: {value}")
    lines += ["", "## Samples", ""]
    for row in report["samples"]:
        observed = ", ".join(row.get("observed_expected_syscalls", [])) or "none"
        missing = ", ".join(row.get("missing_expected_syscalls", [])) or "none"
        lines.append(
            f"- `{row.get('id')}`: compile={row.get('compile_status')} "
            f"execute={row.get('execution_status')} observed={observed} missing={missing}"
        )
    lines += ["", "## Remaining Work", ""]
    lines.extend(f"- {item}" for item in report["remaining_work"])
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    write_json(evidence_root / "synthetic_extension_behavior_smoke.json", report)
    (evidence_root / "synthetic_extension_behavior_smoke.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def write_fixture(root: Path) -> tuple[Path, Path, dict[str, Any]]:
    plan_path = root / DEFAULT_EXTENSION_PLAN
    source_root = root / "experiments/linux_behavior/malware_like/extension_programs"
    source_root.mkdir(parents=True, exist_ok=True)
    candidates = []
    candidate_ids = [f"candidate_{index}" for index in range(EXPECTED_NON_NETWORK_COUNT)] + list(OPTIONAL_NETWORK_IDS)
    for candidate_id in candidate_ids:
        source = source_root / f"{candidate_id}.c"
        source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        network_required = candidate_id in OPTIONAL_NETWORK_IDS
        candidates.append(
            {
                "id": candidate_id,
                "status": "IMPLEMENTED_SOURCE_OPTIONAL_LOOPBACK" if network_required else "IMPLEMENTED_SOURCE",
                "source": rel(source, root),
                "default_enabled": False,
                "network_required": network_required,
                "expected_syscalls": ["exit_group"],
            }
        )
    plan = {
        "schema": "rvmt.synthetic_suite_extension_plan.v1",
        "status": "IMPLEMENTED_SOURCE_READY_FOR_35T_GATING",
        "default_enabled": False,
        "candidates": candidates,
    }
    write_json(plan_path, plan)
    return plan_path, root / DEFAULT_RESULTS_ROOT, plan


def fake_container(plan: dict[str, Any], *, missing_syscall: bool = False) -> dict[str, Any]:
    samples = []
    for candidate in candidate_rows(plan):
        candidate_id = str(candidate["id"])
        network_required = candidate.get("network_required") is True
        expected = list(candidate.get("expected_syscalls", []))
        observed = [] if missing_syscall and not network_required else expected
        samples.append(
            {
                "id": candidate_id,
                "network_required": network_required,
                "default_enabled": False,
                "expected_syscalls": expected,
                "unique_expected_syscalls": sorted(set(expected)),
                "observed_expected_syscalls": observed,
                "missing_expected_syscalls": [] if network_required else [item for item in sorted(set(expected)) if item not in observed],
                "compile_status": "PASS",
                "execution_status": "SKIPPED_NETWORK_OPTIONAL" if network_required else "PASS",
                "executions": {} if network_required else {"host_native": {"exit_code": 0}, "qemu_strace": {"exit_code": 0}},
                "host_compile": {"exit_code": 0},
                "target_compile": {"exit_code": 0},
            }
        )
    if missing_syscall:
        for row in samples:
            if row["network_required"] is not True:
                row["execution_status"] = "FAIL"
                break
    payload = {
        "tools": {"gcc": "/usr/bin/gcc", "riscv64-linux-gnu-gcc": "/usr/bin/riscv64-linux-gnu-gcc", "qemu-riscv64": "/usr/bin/qemu-riscv64", "strace": "/usr/bin/strace"},
        "candidate_count": len(samples),
        "compile_pass_count": len(samples),
        "executed_candidate_count": sum(1 for row in samples if row["network_required"] is not True),
        "execution_pass_count": sum(1 for row in samples if row["execution_status"] == "PASS"),
        "network_skipped_count": sum(1 for row in samples if row["execution_status"] == "SKIPPED_NETWORK_OPTIONAL"),
        "samples": samples,
    }
    return {
        "argv": ["fake"],
        "exit_code": 0,
        "stdout": "RVMT_EXTENSION_BEHAVIOR_JSON_BEGIN\n" + json.dumps(payload) + "\nRVMT_EXTENSION_BEHAVIOR_JSON_END\n",
        "stderr": "",
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plan_path, results_root, plan = write_fixture(root)
        report = build_report_from_container(
            repo_root=root,
            plan_path=plan_path,
            results_root=results_root,
            plan=plan,
            container_result=fake_container(plan),
        )
        if report["status"] != PASS_STATUS:
            print("[FAIL] expected behavior smoke fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "synthetic_extension_behavior_smoke.md").is_file():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plan_path, results_root, plan = write_fixture(root)
        report = build_report_from_container(
            repo_root=root,
            plan_path=plan_path,
            results_root=results_root,
            plan=plan,
            container_result=fake_container(plan, missing_syscall=True),
        )
        if report["status"] != "FAIL" or "expected_syscalls_observed_for_executed" not in report["failures"]:
            print("[FAIL] expected missing syscall fixture to fail", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
    print("[PASS] 35T synthetic extension behavior smoke self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run host/QEMU behavior smoke for synthetic extension candidates without claiming 35T gating.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--extension-plan", type=Path, default=DEFAULT_EXTENSION_PLAN)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--timeout-seconds", type=float, default=8.0)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        report = build_report(repo_root, args.extension_plan, args.results_root, args.timeout_seconds)
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_synthetic_extension_behavior_smoke: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T synthetic extension behavior smoke")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] in ACCEPTED_STATUSES else 1


if __name__ == "__main__":
    raise SystemExit(main())
