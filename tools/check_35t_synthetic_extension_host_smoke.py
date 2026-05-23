from __future__ import annotations

import argparse
import json
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_EXTENSION_PLAN = Path("experiments/linux_behavior/malware_like/extension_plan.json")
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / RUN_ID
PASS_STATUS = "HOST_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED"
BLOCKED_STATUS = "HOST_COMPILE_SMOKE_BLOCKED_CURRENT_ENVIRONMENT"
ACCEPTED_STATUSES = {PASS_STATUS, BLOCKED_STATUS}
IMPLEMENTED_PLAN_STATUS = "IMPLEMENTED_SOURCE_READY_FOR_35T_GATING"
IMPLEMENTED_CANDIDATE_STATUSES = {"IMPLEMENTED_SOURCE", "IMPLEMENTED_SOURCE_OPTIONAL_LOOPBACK"}
COMPILER_CANDIDATES = ("cc", "gcc", "clang")
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
    "no expanded 35T coverage claim",
]


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


def choose_compiler(
    requested: str | None,
    lookup: Callable[[str], str | None] = shutil.which,
) -> str | None:
    if requested:
        requested_path = Path(requested)
        if requested_path.exists():
            return str(requested_path)
        found = lookup(requested)
        return found or requested
    for name in COMPILER_CANDIDATES:
        found = lookup(name)
        if found:
            return found
    return None


def choose_wsl_compiler(
    lookup: Callable[[str], str | None] = shutil.which,
    *,
    timeout_seconds: float = 10.0,
) -> str | None:
    if not lookup("wsl.exe") and not lookup("wsl"):
        return None
    for name in COMPILER_CANDIDATES:
        try:
            completed = subprocess.run(
                ["wsl.exe", "--exec", "sh", "-lc", f"command -v {shlex.quote(name)}"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode == 0 and completed.stdout.strip():
            return completed.stdout.strip().splitlines()[0]
    return None


def wsl_path(path: Path, *, timeout_seconds: float = 10.0) -> str:
    completed = subprocess.run(
        ["wsl.exe", "--exec", "wslpath", "-a", str(path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
        check=False,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise RuntimeError(f"wslpath failed for {path}: {completed.stderr.strip()}")
    return completed.stdout.strip().splitlines()[0]


def compile_candidate(
    *,
    compiler: str,
    candidate: dict[str, Any],
    source: Path,
    output_dir: Path,
    repo_root: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    candidate_id = str(candidate.get("id"))
    output = output_dir / candidate_id
    command = [
        compiler,
        "-std=gnu11",
        "-D_GNU_SOURCE",
        "-Wall",
        "-Wextra",
        "-O2",
        rel(source, repo_root),
        "-o",
        str(output),
    ]
    completed = subprocess.run(
        command,
        cwd=repo_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
        check=False,
    )
    return {
        "id": candidate_id,
        "source": rel(source, repo_root),
        "network_required": candidate.get("network_required") is True,
        "status": "PASS" if completed.returncode == 0 else "FAIL",
        "returncode": completed.returncode,
        "command": command,
        "stdout_tail": completed.stdout[-2000:],
        "stderr_tail": completed.stderr[-4000:],
    }


def compile_candidate_wsl(
    *,
    compiler: str,
    candidate: dict[str, Any],
    source: Path,
    output_dir: Path,
    repo_root: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    candidate_id = str(candidate.get("id"))
    output = output_dir / candidate_id
    source_rel = rel(source, repo_root)
    repo_wsl = wsl_path(repo_root, timeout_seconds=timeout_seconds)
    output_wsl = wsl_path(output, timeout_seconds=timeout_seconds)
    shell_command = " ".join(
        [
            "cd",
            shlex.quote(repo_wsl),
            "&&",
            shlex.quote(compiler),
            "-std=gnu11",
            "-D_GNU_SOURCE",
            "-Wall",
            "-Wextra",
            "-O2",
            shlex.quote(source_rel),
            "-o",
            shlex.quote(output_wsl),
        ]
    )
    command = ["wsl.exe", "--exec", "sh", "-lc", shell_command]
    completed = subprocess.run(
        command,
        cwd=repo_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
        check=False,
    )
    return {
        "id": candidate_id,
        "source": source_rel,
        "network_required": candidate.get("network_required") is True,
        "status": "PASS" if completed.returncode == 0 else "FAIL",
        "returncode": completed.returncode,
        "command": command,
        "stdout_tail": completed.stdout[-2000:],
        "stderr_tail": completed.stderr[-4000:],
    }


def build_report(
    repo_root: Path,
    plan_arg: Path,
    *,
    compiler_arg: str | None = None,
    force_compile: bool = False,
    timeout_seconds: float = 20.0,
    platform_name: str | None = None,
    compiler_lookup: Callable[[str], str | None] = shutil.which,
    allow_wsl: bool = True,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    plan_path = repo_path(repo_root, plan_arg).resolve()
    plan = load_json(plan_path)
    candidates = candidate_rows(plan)
    source_paths = [source_path_for(repo_root, candidate) for candidate in candidates]
    source_rows = [
        {
            "id": candidate.get("id"),
            "source": rel(path, repo_root) if path else None,
            "exists": bool(path and path.is_file()),
            "status": candidate.get("status"),
            "network_required": candidate.get("network_required") is True,
        }
        for candidate, path in zip(candidates, source_paths)
    ]
    checks = {
        "plan_schema": plan.get("schema") == "rvmt.synthetic_suite_extension_plan.v1",
        "plan_status_implemented_source": plan.get("status") == IMPLEMENTED_PLAN_STATUS,
        "candidates_declared": bool(candidates),
        "candidate_statuses_implemented": all(
            candidate.get("status") in IMPLEMENTED_CANDIDATE_STATUSES for candidate in candidates
        ),
        "candidate_sources_declared": all(path is not None for path in source_paths),
        "candidate_sources_exist": all(path is not None and path.is_file() for path in source_paths),
        "network_candidates_compile_only": all(
            row.get("network_required") is not True or row.get("status") == "IMPLEMENTED_SOURCE_OPTIONAL_LOOPBACK"
            for row in candidates
        ),
        "no_execution_attempted": True,
        "no_35t_gating_claim": True,
    }
    failures = [key for key, ok in checks.items() if not ok]
    system_name = platform_name or platform.system()
    is_linux = system_name.lower() == "linux"
    compiler: str | None = None
    compile_environment = "native"
    wsl_compiler = None
    if is_linux or force_compile:
        compiler = choose_compiler(compiler_arg, compiler_lookup)
    elif allow_wsl:
        wsl_compiler = choose_wsl_compiler(compiler_lookup, timeout_seconds=timeout_seconds)
        if wsl_compiler:
            compiler = wsl_compiler
            compile_environment = "wsl"
    blocked_reasons: list[str] = []
    if not is_linux and not force_compile and compile_environment != "wsl":
        blocked_reasons.append(f"host_platform_{system_name}_is_not_linux")
    if compiler is None:
        blocked_reasons.append("no_c_compiler_found")

    compile_attempted = False
    compile_results: list[dict[str, Any]] = []
    if failures:
        status = "FAIL"
    elif blocked_reasons:
        status = BLOCKED_STATUS
    else:
        compile_attempted = True
        with tempfile.TemporaryDirectory(prefix="rvmt-35t-extension-host-smoke-") as tmp:
            output_dir = Path(tmp)
            for candidate, source in zip(candidates, source_paths):
                if source is None:
                    continue
                try:
                    if compile_environment == "wsl":
                        result = compile_candidate_wsl(
                            compiler=str(compiler),
                            candidate=candidate,
                            source=source,
                            output_dir=output_dir,
                            repo_root=repo_root,
                            timeout_seconds=timeout_seconds,
                        )
                    else:
                        result = compile_candidate(
                            compiler=str(compiler),
                            candidate=candidate,
                            source=source,
                            output_dir=output_dir,
                            repo_root=repo_root,
                            timeout_seconds=timeout_seconds,
                        )
                except subprocess.TimeoutExpired as exc:
                    result = {
                        "id": candidate.get("id"),
                        "source": rel(source, repo_root),
                        "network_required": candidate.get("network_required") is True,
                        "status": "FAIL",
                        "returncode": None,
                        "command": exc.cmd,
                        "stdout_tail": str(exc.stdout or "")[-2000:],
                        "stderr_tail": f"compile timeout after {timeout_seconds}s\n{str(exc.stderr or '')[-3500:]}",
                    }
                compile_results.append(result)
        failed_compiles = [row for row in compile_results if row.get("status") != "PASS"]
        status = PASS_STATUS if not failed_compiles and len(compile_results) == len(candidates) else "FAIL"
        failures.extend(f"compile:{row.get('id')}" for row in failed_compiles)
        if len(compile_results) != len(candidates):
            failures.append("compile_result_count")

    return {
        "schema": "rvmt.35t.synthetic_extension_host_smoke.v1",
        "run_id": RUN_ID,
        "status": status,
        "extension_plan": rel(plan_path, repo_root),
        "host": {
            "platform": system_name,
            "python": sys.version.split()[0],
            "compiler": compiler,
            "compile_environment": compile_environment,
            "wsl_compiler": wsl_compiler,
            "allow_wsl": allow_wsl,
            "force_compile": force_compile,
            "compile_attempted": compile_attempted,
            "blocked_reasons": blocked_reasons,
        },
        "checks": checks,
        "candidate_count": len(candidates),
        "source_rows": source_rows,
        "compile_results": compile_results,
        "compiled_candidate_count": sum(1 for row in compile_results if row.get("status") == "PASS"),
        "interpretation": [
            "this is a host compile-only smoke check for repository-owned synthetic extension sources",
            "the checker never executes the extension binaries and does not start loopback network activity",
            "a PASS means the extension sources compile on this host; it is still not a 35T run",
            "on Windows, a WSL compiler may satisfy the host compile-only condition when the repository is mounted and gcc/clang/cc is available",
            "a blocked status records that the current host lacks the Linux, WSL, or compiler conditions needed for compile smoke",
            "expanded 35T coverage remains deferred until these candidates are explicitly enabled, built for the target, and run through the same gates",
        ],
        "non_claims": NON_CLAIMS,
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    host = report["host"]
    lines = [
        f"# 35T Synthetic Extension Host Smoke: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Extension plan: `{report['extension_plan']}`",
        "",
        "## Host",
        "",
        f"- platform: {host['platform']}",
        f"- compile_environment: {host.get('compile_environment')}",
        f"- compiler: {host['compiler'] or 'none'}",
        f"- wsl_compiler: {host.get('wsl_compiler') or 'none'}",
        f"- compile_attempted: {host['compile_attempted']}",
        f"- blocked_reasons: {', '.join(host['blocked_reasons']) if host['blocked_reasons'] else 'none'}",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Sources", ""]
    for row in report["source_rows"]:
        exists = "present" if row["exists"] else "missing"
        network = "network_optional" if row["network_required"] else "non_network"
        lines.append(f"- `{row['id']}`: `{row['source']}` ({exists}, {network})")
    lines += ["", "## Compile Results", ""]
    if report["compile_results"]:
        for row in report["compile_results"]:
            lines.append(f"- `{row['id']}`: {row['status']} returncode={row['returncode']}")
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
    (evidence_root / "synthetic_extension_host_smoke.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "synthetic_extension_host_smoke.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def write_fixture(root: Path, *, missing_source: bool = False) -> None:
    source_root = root / "experiments/linux_behavior/malware_like/extension_programs"
    source_root.mkdir(parents=True, exist_ok=True)
    candidates = []
    for candidate_id, network_required in (("direct_syscall_fixture", False), ("loopback_fixture", True)):
        source = source_root / f"{candidate_id}.c"
        if not missing_source:
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        candidates.append(
            {
                "id": candidate_id,
                "status": "IMPLEMENTED_SOURCE_OPTIONAL_LOOPBACK" if network_required else "IMPLEMENTED_SOURCE",
                "source": rel(source, root),
                "network_required": network_required,
            }
        )
    write_json(
        root / DEFAULT_EXTENSION_PLAN,
        {
            "schema": "rvmt.synthetic_suite_extension_plan.v1",
            "status": IMPLEMENTED_PLAN_STATUS,
            "candidates": candidates,
        },
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        report = build_report(
            root,
            DEFAULT_EXTENSION_PLAN,
            platform_name="Windows",
            compiler_lookup=lambda _name: None,
            allow_wsl=False,
        )
        if report["status"] != BLOCKED_STATUS or "host_platform_Windows_is_not_linux" not in report["host"]["blocked_reasons"]:
            print("[FAIL] expected Windows fixture to be environment-blocked", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "synthetic_extension_host_smoke.md").exists():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        report = build_report(
            root,
            DEFAULT_EXTENSION_PLAN,
            platform_name="Linux",
            compiler_lookup=lambda _name: None,
            allow_wsl=False,
        )
        if report["status"] != BLOCKED_STATUS or "no_c_compiler_found" not in report["host"]["blocked_reasons"]:
            print("[FAIL] expected no-compiler Linux fixture to be environment-blocked", file=sys.stderr)
            return 1

    if platform.system().lower() == "linux" and choose_compiler(None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            report = build_report(root, DEFAULT_EXTENSION_PLAN)
            if report["status"] != PASS_STATUS:
                print("[FAIL] expected compile-capable Linux fixture to pass", file=sys.stderr)
                print(json.dumps(report, indent=2), file=sys.stderr)
                return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root, missing_source=True)
        report = build_report(root, DEFAULT_EXTENSION_PLAN, platform_name="Windows", compiler_lookup=lambda _name: None)
        if report["status"] != "FAIL" or "candidate_sources_exist" not in report["failures"]:
            print("[FAIL] expected missing-source fixture to fail", file=sys.stderr)
            return 1
    print("[PASS] 35T synthetic extension host smoke self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compile-smoke synthetic extension sources without claiming 35T gating.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--extension-plan", type=Path, default=DEFAULT_EXTENSION_PLAN)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--compiler")
    parser.add_argument("--force-compile", action="store_true")
    parser.add_argument("--disable-wsl", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        report = build_report(
            repo_root,
            args.extension_plan,
            compiler_arg=args.compiler,
            force_compile=args.force_compile,
            timeout_seconds=args.timeout_seconds,
            allow_wsl=not args.disable_wsl,
        )
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_synthetic_extension_host_smoke: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T synthetic extension host smoke")
    for reason in report["host"]["blocked_reasons"]:
        print(f"blocked: {reason}", file=sys.stderr)
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] in ACCEPTED_STATUSES else 1


if __name__ == "__main__":
    raise SystemExit(main())
