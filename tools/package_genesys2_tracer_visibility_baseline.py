from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    repo_rel_from,
    sha256_file,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "rvmt.genesys2.tracer_visibility_baseline.v1"
DEFAULT_SOURCE = Path("board/trace_validation/programs/tracer_visibility_probe.c")
DEFAULT_OUT_ROOT = Path("build/tracer_visibility_baseline")
DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/tracer_visibility_baseline_summary.json")
PROBE_RE = re.compile(r"RVMT_TRACER_VISIBILITY\s+(?P<fields>.+)")


repo_rel = repo_rel_from(ROOT)


def artifact_row(path: Path, role: str) -> dict[str, Any]:
    return {
        "path": repo_rel(path),
        "role": role,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def docker_compose_command(compose_file: Path, service: str, shell_command: str) -> list[str]:
    docker = shutil.which("docker") or "docker"
    return [
        docker,
        "compose",
        "-f",
        compose_file.as_posix(),
        "run",
        "--rm",
        "--build",
        service,
        "bash",
        "-lc",
        shell_command,
    ]


def run(command: list[str], *, cwd: Path, dry_run: bool) -> None:
    print("+ " + " ".join(command))
    if dry_run:
        return
    subprocess.run(command, cwd=cwd, check=True)


def shell_quote(path: Path | str) -> str:
    value = path.as_posix() if isinstance(path, Path) else str(path).replace("\\", "/")
    return "'" + value.replace("'", "'\"'\"'") + "'"


def build_shell(source: Path, out_root: Path) -> str:
    native = out_root / "tracer_visibility_probe.native"
    riscv = out_root / "tracer_visibility_probe.riscv64"
    commands = [
        "set -euo pipefail",
        f"mkdir -p {shell_quote(out_root)}",
        (
            "gcc -O2 -Wall -Wextra -Werror "
            f"-o {shell_quote(native)} {shell_quote(source)} "
            f"> {shell_quote(out_root / 'native_build.log')} 2>&1"
        ),
        (
            "riscv64-linux-gnu-gcc -O2 -static -s -Wall -Wextra -Werror -Wl,--build-id=none "
            f"-o {shell_quote(riscv)} {shell_quote(source)} "
            f"> {shell_quote(out_root / 'riscv64_build.log')} 2>&1"
        ),
        f"gcc --version | head -n 1 > {shell_quote(out_root / 'native_compiler_version.txt')}",
        f"riscv64-linux-gnu-gcc --version | head -n 1 > {shell_quote(out_root / 'riscv64_compiler_version.txt')}",
        f"{shell_quote(native)} > {shell_quote(out_root / 'native_plain.stdout')} 2> {shell_quote(out_root / 'native_plain.stderr')}",
        (
            f"strace -f -o {shell_quote(out_root / 'native_strace.trace')} "
            f"{shell_quote(native)} > {shell_quote(out_root / 'native_strace.stdout')} "
            f"2> {shell_quote(out_root / 'native_strace.stderr')}"
        ),
        f"qemu-riscv64 {shell_quote(riscv)} > {shell_quote(out_root / 'qemu_user.stdout')} 2> {shell_quote(out_root / 'qemu_user.stderr')}",
        (
            f"qemu-riscv64 -strace {shell_quote(riscv)} "
            f"> {shell_quote(out_root / 'qemu_user_strace.stdout')} "
            f"2> {shell_quote(out_root / 'qemu_user_strace.stderr')}"
        ),
    ]
    return " && ".join(commands)


def parse_probe_stdout(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    match = PROBE_RE.search(text)
    if not match:
        raise ValueError(f"missing RVMT_TRACER_VISIBILITY row in {path}")
    row: dict[str, Any] = {}
    for item in match.group("fields").split():
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        if key in {"pid", "ppid", "tracer_pid", "ptrace_traceme_rc", "ptrace_errno"}:
            row[key] = int(value, 10)
        else:
            row[key] = value
    return row


def summarize(root: Path, source: Path, out_root: Path, summary: Path) -> dict[str, Any]:
    artifacts: dict[str, Any] = {
        "source": artifact_row(source, "safe_probe_source"),
        "native_binary": artifact_row(out_root / "tracer_visibility_probe.native", "native_linux_probe_binary"),
        "riscv64_binary": artifact_row(out_root / "tracer_visibility_probe.riscv64", "riscv64_linux_probe_binary"),
        "native_build_log": artifact_row(out_root / "native_build.log", "build_log"),
        "riscv64_build_log": artifact_row(out_root / "riscv64_build.log", "build_log"),
        "native_compiler_version": artifact_row(out_root / "native_compiler_version.txt", "compiler_version"),
        "riscv64_compiler_version": artifact_row(out_root / "riscv64_compiler_version.txt", "compiler_version"),
    }
    mode_specs = {
        "native_plain": ("native_plain.stdout", "native_plain.stderr", None),
        "native_strace": ("native_strace.stdout", "native_strace.stderr", "native_strace.trace"),
        "qemu_user": ("qemu_user.stdout", "qemu_user.stderr", None),
        "qemu_user_strace": ("qemu_user_strace.stdout", "qemu_user_strace.stderr", None),
    }
    modes: dict[str, Any] = {}
    for mode, (stdout_name, stderr_name, trace_name) in mode_specs.items():
        stdout = out_root / stdout_name
        stderr = out_root / stderr_name
        row = {
            "mode": mode,
            "probe": parse_probe_stdout(stdout),
            "stdout": artifact_row(stdout, "probe_stdout"),
            "stderr": artifact_row(stderr, "probe_stderr"),
        }
        if trace_name is not None:
            row["strace_log"] = artifact_row(out_root / trace_name, "software_strace_log")
        modes[mode] = row

    native_plain = modes["native_plain"]["probe"]
    native_strace = modes["native_strace"]["probe"]
    qemu_strace_stderr = out_root / "qemu_user_strace.stderr"
    native_strace_detected = int(native_strace.get("tracer_pid", 0)) > 0 or (
        int(native_strace.get("ptrace_traceme_rc", 0)) == -1 and int(native_strace.get("ptrace_errno", 0)) != 0
    )
    native_plain_untraced = int(native_plain.get("tracer_pid", -1)) == 0 and int(native_plain.get("ptrace_traceme_rc", -1)) == 0
    qemu_strace_log_observed = qemu_strace_stderr.stat().st_size > 0
    status = (
        "PASS_LOCAL_SOFTWARE_TRACER_BASELINE"
        if native_plain_untraced and native_strace_detected and qemu_strace_log_observed
        else "BLOCKED_LOCAL_SOFTWARE_TRACER_BASELINE_INCOMPLETE"
    )
    data = {
        "schema": SCHEMA,
        "status": status,
        "canonical_evidence_root": "results/evaluation/genesys2-cva6/current",
        "scope": "safe local software-tracer visibility baseline for NDSS comparison tables",
        "source": repo_rel(source),
        "source_sha256": sha256_file(source),
        "run_root": repo_rel(out_root),
        "artifacts": artifacts,
        "modes": modes,
        "observations": {
            "native_plain_untraced": native_plain_untraced,
            "native_strace_detected_by_tracerpid_or_ptrace": native_strace_detected,
            "qemu_user_strace_log_observed": qemu_strace_log_observed,
        },
        "claim_boundary": {
            "local_software_baseline_only": True,
            "safe_probe_only": True,
            "hardware_trace_claimed": False,
            "genesys2_board_claimed": False,
            "real_malware_claimed": False,
            "malware_detection_accuracy_claimed": False,
            "qemu_and_strace_are_oracles_only": True,
            "anti_analysis_advantage_claimed": False,
        },
        "non_claims": [
            "This baseline records software tracer visibility for a safe probe in Docker; it is not Genesys2 hardware evidence.",
            "qemu-riscv64 and strace outputs are validation/comparison oracles only and must not be reported as hardware-recovered semantics.",
            "The probe is not malware and does not establish malware detection accuracy or general anti-analysis invisibility.",
        ],
    }
    write_json(summary, data)
    return data


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-tracer-visibility-") as tmp:
        root = Path(tmp)
        source = root / DEFAULT_SOURCE
        out_root = root / DEFAULT_OUT_ROOT
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("int main(void) { return 0; }\n", encoding="utf-8", newline="\n")
        out_root.mkdir(parents=True, exist_ok=True)
        for path in (
            out_root / "tracer_visibility_probe.native",
            out_root / "tracer_visibility_probe.riscv64",
            out_root / "native_build.log",
            out_root / "riscv64_build.log",
            out_root / "native_compiler_version.txt",
            out_root / "riscv64_compiler_version.txt",
            out_root / "native_plain.stderr",
            out_root / "native_strace.stderr",
            out_root / "qemu_user.stderr",
            out_root / "native_strace.trace",
        ):
            path.write_text("fixture\n", encoding="utf-8", newline="\n")
        (out_root / "native_plain.stdout").write_text(
            "RVMT_TRACER_VISIBILITY pid=10 ppid=1 tracer_pid=0 ptrace_traceme_rc=0 ptrace_errno=0 parent_comm=bash self_comm=probe uname_sysname=Linux uname_machine=x86_64\n",
            encoding="utf-8",
            newline="\n",
        )
        (out_root / "native_strace.stdout").write_text(
            "RVMT_TRACER_VISIBILITY pid=11 ppid=1 tracer_pid=123 ptrace_traceme_rc=-1 ptrace_errno=1 parent_comm=strace self_comm=probe uname_sysname=Linux uname_machine=x86_64\n",
            encoding="utf-8",
            newline="\n",
        )
        (out_root / "qemu_user.stdout").write_text(
            "RVMT_TRACER_VISIBILITY pid=12 ppid=1 tracer_pid=0 ptrace_traceme_rc=0 ptrace_errno=0 parent_comm=qemu-riscv64 self_comm=probe uname_sysname=Linux uname_machine=riscv64\n",
            encoding="utf-8",
            newline="\n",
        )
        (out_root / "qemu_user_strace.stdout").write_text(
            "RVMT_TRACER_VISIBILITY pid=13 ppid=1 tracer_pid=0 ptrace_traceme_rc=0 ptrace_errno=0 parent_comm=qemu-riscv64 self_comm=probe uname_sysname=Linux uname_machine=riscv64\n",
            encoding="utf-8",
            newline="\n",
        )
        (out_root / "qemu_user_strace.stderr").write_text("123 write(1,...)\n", encoding="utf-8", newline="\n")
        summary = root / DEFAULT_SUMMARY
        old_root = globals()["ROOT"]
        globals()["ROOT"] = root
        try:
            data = summarize(root, source, out_root, summary)
        finally:
            globals()["ROOT"] = old_root
        if data.get("status") != "PASS_LOCAL_SOFTWARE_TRACER_BASELINE":
            print("[FAIL] tracer visibility fixture did not pass", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 tracer visibility baseline packager self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run and package a safe local tracer-visibility baseline in Docker.")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--out-root", type=Path, default=DEFAULT_OUT_ROOT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--compose-file", type=Path, default=Path("docker-compose.toolchain.yml"))
    parser.add_argument("--service", default="linux-behavior")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not args.source.is_file():
        parser.error(f"source missing: {args.source}")
    shell = build_shell(args.source, args.out_root)
    run(docker_compose_command(args.compose_file, args.service, shell), cwd=ROOT, dry_run=args.dry_run)
    if args.dry_run:
        print(f"[DRY-RUN] would write {args.summary}")
        return 0
    data = summarize(ROOT, args.source, args.out_root, args.summary)
    print(f"[{data['status']}] wrote tracer visibility baseline to {args.summary}")
    return 0 if str(data["status"]).startswith("PASS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
