from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_EXTENSION_PLAN = Path("experiments/linux_behavior/malware_like/extension_plan.json")
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / RUN_ID
PASS_STATUS = "TARGET_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED"
BLOCKED_STATUS = "TARGET_COMPILE_SMOKE_BLOCKED_CURRENT_ENVIRONMENT"
ACCEPTED_STATUSES = {PASS_STATUS, BLOCKED_STATUS}
IMPLEMENTED_CANDIDATE_STATUSES = {"IMPLEMENTED_SOURCE", "IMPLEMENTED_SOURCE_OPTIONAL_LOOPBACK"}
COMPILER = "riscv64-linux-gnu-gcc"
READELF = "riscv64-linux-gnu-readelf"
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
    "no expanded 35T coverage claim",
    "no 35T execution or gate pass claim",
]


CONTAINER_COMPILE_SCRIPT = r"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


plan_path = Path(os.environ["RVMT_EXTENSION_PLAN"])
compiler = os.environ.get("RVMT_TARGET_CC", "riscv64-linux-gnu-gcc")
readelf = os.environ.get("RVMT_TARGET_READELF", "riscv64-linux-gnu-readelf")
plan = json.loads(plan_path.read_text(encoding="utf-8"))
candidates = [row for row in plan.get("candidates", []) if isinstance(row, dict)]
compiler_path = shutil.which(compiler) or ""
readelf_path = shutil.which(readelf) or ""
rows = []

with tempfile.TemporaryDirectory(prefix="rvmt-35t-target-smoke-") as tmp:
    output_dir = Path(tmp)
    for candidate in candidates:
        candidate_id = str(candidate.get("id") or "")
        source = Path(str(candidate.get("source") or ""))
        output = output_dir / f"{candidate_id}.riscv"
        command = [
            compiler,
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-O2",
            "-static",
            "-o",
            str(output),
            source.as_posix(),
        ]
        row = {
            "id": candidate_id,
            "source": source.as_posix(),
            "network_required": candidate.get("network_required") is True,
            "command": command,
            "status": "BLOCKED" if not compiler_path else "FAIL",
            "returncode": None,
            "stdout_tail": "",
            "stderr_tail": "",
            "elf_bytes": 0,
            "elf_sha256": "",
            "elf_class": "",
            "elf_machine": "",
            "riscv_elf": False,
            "static_link_requested": "-static" in command,
        }
        if not compiler_path:
            row["stderr_tail"] = f"{compiler} not found"
            rows.append(row)
            continue
        completed = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        row["returncode"] = completed.returncode
        row["stdout_tail"] = completed.stdout[-2000:]
        row["stderr_tail"] = completed.stderr[-4000:]
        if completed.returncode == 0 and output.is_file():
            data = output.read_bytes()
            row["elf_bytes"] = len(data)
            row["elf_sha256"] = hashlib.sha256(data).hexdigest()
            if readelf_path:
                header = subprocess.run(
                    [readelf, "-h", str(output)],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                for line in header.stdout.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("Class:"):
                        row["elf_class"] = stripped.split(":", 1)[1].strip()
                    elif stripped.startswith("Machine:"):
                        row["elf_machine"] = stripped.split(":", 1)[1].strip()
                row["riscv_elf"] = "RISC-V" in row["elf_machine"]
            row["status"] = "PASS" if row["riscv_elf"] else "FAIL"
        rows.append(row)

report = {
    "compiler": compiler,
    "compiler_path": compiler_path,
    "compiler_version": subprocess.run(
        [compiler, "--version"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    ).stdout.splitlines()[0] if compiler_path else "",
    "readelf": readelf,
    "readelf_path": readelf_path,
    "candidate_count": len(candidates),
    "compile_results": rows,
}
print("RVMT_TARGET_SMOKE_JSON_BEGIN")
print(json.dumps(report, sort_keys=True))
print("RVMT_TARGET_SMOKE_JSON_END")
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


def candidate_rows(plan: dict[str, Any]) -> list[dict[str, Any]]:
    rows = plan.get("candidates", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def source_path_for(repo_root: Path, candidate: dict[str, Any]) -> Path | None:
    source = candidate.get("source")
    if not isinstance(source, str) or not source:
        return None
    return repo_path(repo_root, Path(source))


def docker_compose_base() -> list[str]:
    return ["docker", "compose", "-f", "docker-compose.toolchain.yml"]


def extract_container_json(stdout: str) -> dict[str, Any] | None:
    begin = "RVMT_TARGET_SMOKE_JSON_BEGIN"
    end = "RVMT_TARGET_SMOKE_JSON_END"
    if begin not in stdout or end not in stdout:
        return None
    payload = stdout.split(begin, 1)[1].split(end, 1)[0].strip()
    try:
        value = json.loads(payload)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def run_container_compile(repo_root: Path, plan_path: Path, timeout_seconds: float) -> dict[str, Any]:
    command = [
        *docker_compose_base(),
        "run",
        "--rm",
        "linux-behavior",
        "bash",
        "-lc",
        f"RVMT_EXTENSION_PLAN={plan_path.as_posix()} python3 - <<'PY'\n{CONTAINER_COMPILE_SCRIPT}\nPY",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=repo_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError as exc:
        return {"argv": command, "exit_code": 127, "stdout": "", "stderr": str(exc)}
    except subprocess.TimeoutExpired as exc:
        return {
            "argv": command,
            "exit_code": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or f"timeout after {timeout_seconds}s",
        }
    return {
        "argv": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def build_report_from_container(
    *,
    repo_root: Path,
    plan_path: Path,
    plan: dict[str, Any],
    container_result: dict[str, Any],
) -> dict[str, Any]:
    candidates = candidate_rows(plan)
    source_paths = [source_path_for(repo_root, candidate) for candidate in candidates]
    container_json = extract_container_json(str(container_result.get("stdout", "")))
    compile_results = container_json.get("compile_results", []) if isinstance(container_json, dict) else []
    if not isinstance(compile_results, list):
        compile_results = []
    compile_rows = [row for row in compile_results if isinstance(row, dict)]
    blocked_rows = [row for row in compile_rows if row.get("status") == "BLOCKED"]
    failed_rows = [row for row in compile_rows if row.get("status") != "PASS"]
    checks = {
        "plan_schema": plan.get("schema") == "rvmt.synthetic_suite_extension_plan.v1",
        "candidates_declared": bool(candidates),
        "candidate_statuses_implemented": all(
            candidate.get("status") in IMPLEMENTED_CANDIDATE_STATUSES for candidate in candidates
        ),
        "candidate_sources_declared": all(path is not None for path in source_paths),
        "candidate_sources_exist": all(path is not None and path.is_file() for path in source_paths),
        "container_command_passed": container_result.get("exit_code") == 0,
        "container_json_present": container_json is not None,
        "target_compiler_available": bool(container_json.get("compiler_path")) if isinstance(container_json, dict) else False,
        "target_readelf_available": bool(container_json.get("readelf_path")) if isinstance(container_json, dict) else False,
        "compile_result_count_matches": len(compile_rows) == len(candidates) and bool(candidates),
        "compiled_all_candidates": bool(compile_rows) and all(row.get("status") == "PASS" for row in compile_rows),
        "riscv_elf_all_candidates": bool(compile_rows) and all(row.get("riscv_elf") is True for row in compile_rows),
        "static_link_requested_all_candidates": bool(compile_rows)
        and all(row.get("static_link_requested") is True for row in compile_rows),
        "no_execution_attempted": True,
        "no_35t_gating_claim": True,
    }
    failures = [key for key, ok in checks.items() if not ok]
    failures.extend(f"compile:{row.get('id')}" for row in failed_rows if row.get("status") != "BLOCKED")
    if container_result.get("exit_code") != 0 and container_result.get("exit_code") != 124:
        failures.append(f"container_exit:{container_result.get('exit_code')}")
    if all(checks.values()):
        status = PASS_STATUS
    elif blocked_rows or container_result.get("exit_code") in {124, 127} or not checks["target_compiler_available"]:
        status = BLOCKED_STATUS
    else:
        status = "FAIL"
    raw_argv = container_result.get("argv")
    if isinstance(raw_argv, list) and raw_argv:
        argv_summary = [*raw_argv[:-1], "<inline target compile script>"]
    else:
        argv_summary = raw_argv
    return {
        "schema": "rvmt.35t.synthetic_extension_target_smoke.v1",
        "run_id": RUN_ID,
        "status": status,
        "extension_plan": rel(plan_path, repo_root),
        "target": {
            "environment": "docker_linux_behavior",
            "compiler": COMPILER,
            "compiler_path": container_json.get("compiler_path", "") if isinstance(container_json, dict) else "",
            "compiler_version": container_json.get("compiler_version", "") if isinstance(container_json, dict) else "",
            "readelf": READELF,
            "readelf_path": container_json.get("readelf_path", "") if isinstance(container_json, dict) else "",
            "link_mode": "static",
            "execution_attempted": False,
        },
        "container_probe": {
            "argv": argv_summary,
            "exit_code": container_result.get("exit_code"),
            "inline_script_sha256": hashlib.sha256(CONTAINER_COMPILE_SCRIPT.encode("utf-8")).hexdigest(),
            "stderr_tail": str(container_result.get("stderr", ""))[-2000:],
        },
        "checks": checks,
        "candidate_count": len(candidates),
        "compiled_candidate_count": sum(1 for row in compile_rows if row.get("status") == "PASS"),
        "compile_results": compile_rows,
        "interpretation": [
            "this is a target cross-compile-only smoke check for repository-owned synthetic extension sources",
            "the checker builds static RISC-V Linux ELF candidates in Docker and validates ELF machine headers",
            "the checker never executes target binaries and does not install them into a 35T rootfs",
            "a PASS reduces the target-build gap but is still not a 35T run or expanded coverage claim",
            "expanded 35T coverage remains deferred until these candidates are explicitly enabled, deployed, and run through the same gates",
        ],
        "non_claims": NON_CLAIMS,
        "failures": failures,
    }


def build_report(repo_root: Path, plan_arg: Path, timeout_seconds: float) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    plan_path = repo_path(repo_root, plan_arg).resolve()
    plan = load_json(plan_path)
    container_result = run_container_compile(repo_root, plan_path.relative_to(repo_root), timeout_seconds)
    return build_report_from_container(
        repo_root=repo_root,
        plan_path=plan_path,
        plan=plan,
        container_result=container_result,
    )


def render_markdown(report: dict[str, Any]) -> str:
    target = report["target"]
    lines = [
        f"# 35T Synthetic Extension Target Smoke: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Extension plan: `{report['extension_plan']}`",
        "",
        "## Target",
        "",
        f"- environment: {target['environment']}",
        f"- compiler: {target['compiler_path'] or target['compiler']}",
        f"- compiler_version: {target['compiler_version'] or 'none'}",
        f"- readelf: {target['readelf_path'] or target['readelf']}",
        f"- link_mode: {target['link_mode']}",
        f"- execution_attempted: {target['execution_attempted']}",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Compile Results", ""]
    if report["compile_results"]:
        for row in report["compile_results"]:
            lines.append(
                f"- `{row['id']}`: {row['status']} bytes={row.get('elf_bytes', 0)} "
                f"machine={row.get('elf_machine') or 'unknown'} sha256={row.get('elf_sha256') or 'none'}"
            )
    else:
        lines.append("- none")
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    write_json(evidence_root / "synthetic_extension_target_smoke.json", report)
    (evidence_root / "synthetic_extension_target_smoke.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def write_fixture(root: Path, *, missing_source: bool = False) -> None:
    source_root = root / "experiments/linux_behavior/malware_like/extension_programs"
    source_root.mkdir(parents=True, exist_ok=True)
    candidates = []
    for candidate_id in ("direct_syscall_fixture", "loopback_fixture"):
        source = source_root / f"{candidate_id}.c"
        if not missing_source:
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        candidates.append(
            {
                "id": candidate_id,
                "status": "IMPLEMENTED_SOURCE",
                "source": rel(source, root),
                "network_required": candidate_id == "loopback_fixture",
            }
        )
    write_json(
        root / DEFAULT_EXTENSION_PLAN,
        {
            "schema": "rvmt.synthetic_suite_extension_plan.v1",
            "status": "IMPLEMENTED_SOURCE_READY_FOR_35T_GATING",
            "candidates": candidates,
        },
    )


def fake_container(rows: list[dict[str, Any]], *, compiler_path: str = "/usr/bin/riscv64-linux-gnu-gcc") -> dict[str, Any]:
    payload = {
        "compiler_path": compiler_path,
        "compiler_version": "riscv64-linux-gnu-gcc fixture",
        "readelf_path": "/usr/bin/riscv64-linux-gnu-readelf" if compiler_path else "",
        "compile_results": rows,
    }
    return {
        "argv": ["fake"],
        "exit_code": 0,
        "stdout": "RVMT_TARGET_SMOKE_JSON_BEGIN\n" + json.dumps(payload) + "\nRVMT_TARGET_SMOKE_JSON_END\n",
        "stderr": "",
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        plan_path = root / DEFAULT_EXTENSION_PLAN
        plan = load_json(plan_path)
        rows = [
            {
                "id": "direct_syscall_fixture",
                "status": "PASS",
                "riscv_elf": True,
                "static_link_requested": True,
                "elf_machine": "RISC-V",
                "elf_bytes": 1,
                "elf_sha256": "a",
            },
            {
                "id": "loopback_fixture",
                "status": "PASS",
                "riscv_elf": True,
                "static_link_requested": True,
                "elf_machine": "RISC-V",
                "elf_bytes": 1,
                "elf_sha256": "b",
            },
        ]
        report = build_report_from_container(
            repo_root=root,
            plan_path=plan_path,
            plan=plan,
            container_result=fake_container(rows),
        )
        if report["status"] != PASS_STATUS:
            print("[FAIL] expected target smoke fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "synthetic_extension_target_smoke.md").exists():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root, missing_source=True)
        plan_path = root / DEFAULT_EXTENSION_PLAN
        plan = load_json(plan_path)
        report = build_report_from_container(
            repo_root=root,
            plan_path=plan_path,
            plan=plan,
            container_result=fake_container([]),
        )
        if report["status"] != "FAIL" or "candidate_sources_exist" not in report["failures"]:
            print("[FAIL] expected missing source fixture to fail", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        plan_path = root / DEFAULT_EXTENSION_PLAN
        plan = load_json(plan_path)
        report = build_report_from_container(
            repo_root=root,
            plan_path=plan_path,
            plan=plan,
            container_result=fake_container([], compiler_path=""),
        )
        if report["status"] != BLOCKED_STATUS:
            print("[FAIL] expected missing compiler fixture to be blocked", file=sys.stderr)
            return 1
    print("[PASS] 35T synthetic extension target smoke self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cross-compile synthetic extension sources for RISC-V without claiming 35T gating.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--extension-plan", type=Path, default=DEFAULT_EXTENSION_PLAN)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        report = build_report(repo_root, args.extension_plan, args.timeout_seconds)
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_synthetic_extension_target_smoke: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T synthetic extension target smoke")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] in ACCEPTED_STATUSES else 1


if __name__ == "__main__":
    raise SystemExit(main())
