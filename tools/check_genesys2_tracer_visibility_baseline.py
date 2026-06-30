from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_dict,
    load_json,
    repo_path,
    require,
    sha256_file,
)

from package_genesys2_tracer_visibility_baseline import SCHEMA, parse_probe_stdout, write_json


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/tracer_visibility_baseline_summary.json")


def check_artifact(errors: list[str], root: Path, row: dict[str, Any], label: str) -> Path | None:
    value = row.get("path")
    if not isinstance(value, str) or not value:
        errors.append(f"{label}: missing path")
        return None
    path = repo_path(root, value)
    if not path.is_file():
        errors.append(f"{label}: artifact missing: {value}")
        return None
    require(errors, row.get("sha256") == sha256_file(path), f"{label}: sha256 mismatch")
    require(errors, row.get("size_bytes") == path.stat().st_size, f"{label}: size_bytes mismatch")
    return path


def mode_probe(errors: list[str], root: Path, modes: dict[str, Any], mode: str) -> dict[str, Any]:
    row = as_dict(modes.get(mode))
    require(errors, row.get("mode") == mode, f"{mode}: mode id mismatch")
    stdout = check_artifact(errors, root, as_dict(row.get("stdout")), f"{mode}.stdout")
    check_artifact(errors, root, as_dict(row.get("stderr")), f"{mode}.stderr")
    if "strace_log" in row:
        check_artifact(errors, root, as_dict(row.get("strace_log")), f"{mode}.strace_log")
    probe = as_dict(row.get("probe"))
    if stdout is not None:
        try:
            parsed = parse_probe_stdout(stdout)
        except Exception as exc:
            errors.append(f"{mode}.stdout parse failed: {exc}")
        else:
            require(errors, parsed == probe, f"{mode}: probe row must match stdout parse")
    return probe


def check_summary(root: Path, summary: Path) -> list[str]:
    errors: list[str] = []
    data = load_json(summary)
    require(errors, data.get("schema") == SCHEMA, f"schema must be {SCHEMA}")
    require(errors, data.get("status") == "PASS_LOCAL_SOFTWARE_TRACER_BASELINE", "status must be PASS_LOCAL_SOFTWARE_TRACER_BASELINE")
    require(errors, data.get("canonical_evidence_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    artifacts = as_dict(data.get("artifacts"))
    for name in (
        "source",
        "native_binary",
        "riscv64_binary",
        "native_build_log",
        "riscv64_build_log",
        "native_compiler_version",
        "riscv64_compiler_version",
    ):
        check_artifact(errors, root, as_dict(artifacts.get(name)), f"artifacts.{name}")

    modes = as_dict(data.get("modes"))
    native_plain = mode_probe(errors, root, modes, "native_plain")
    native_strace = mode_probe(errors, root, modes, "native_strace")
    mode_probe(errors, root, modes, "qemu_user")
    mode_probe(errors, root, modes, "qemu_user_strace")

    observations = as_dict(data.get("observations"))
    native_plain_untraced = int(native_plain.get("tracer_pid", -1)) == 0 and int(native_plain.get("ptrace_traceme_rc", -1)) == 0
    native_strace_detected = int(native_strace.get("tracer_pid", 0)) > 0 or (
        int(native_strace.get("ptrace_traceme_rc", 0)) == -1 and int(native_strace.get("ptrace_errno", 0)) != 0
    )
    qemu_strace_stderr = repo_path(root, as_dict(as_dict(modes.get("qemu_user_strace")).get("stderr")).get("path", ""))
    qemu_strace_log_observed = qemu_strace_stderr.is_file() and qemu_strace_stderr.stat().st_size > 0
    require(errors, observations.get("native_plain_untraced") is native_plain_untraced, "native_plain observation mismatch")
    require(
        errors,
        observations.get("native_strace_detected_by_tracerpid_or_ptrace") is native_strace_detected,
        "native_strace observation mismatch",
    )
    require(errors, observations.get("qemu_user_strace_log_observed") is qemu_strace_log_observed, "qemu_user_strace observation mismatch")
    require(errors, native_plain_untraced, "native_plain must be untraced and allow PTRACE_TRACEME")
    require(errors, native_strace_detected, "native_strace must expose tracer visibility via TracerPid or ptrace failure")
    require(errors, qemu_strace_log_observed, "qemu_user_strace stderr log must be nonempty")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("local_software_baseline_only") is True, "baseline must be local-software only")
    require(errors, boundary.get("safe_probe_only") is True, "baseline must be marked safe probe only")
    require(errors, boundary.get("hardware_trace_claimed") is False, "baseline must not claim hardware trace")
    require(errors, boundary.get("genesys2_board_claimed") is False, "baseline must not claim Genesys2 board evidence")
    require(errors, boundary.get("real_malware_claimed") is False, "baseline must not claim real malware")
    require(errors, boundary.get("malware_detection_accuracy_claimed") is False, "baseline must not claim malware detection accuracy")
    require(errors, boundary.get("qemu_and_strace_are_oracles_only") is True, "qemu/strace must be oracle-only")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-check-tracer-visibility-") as tmp:
        root = Path(tmp)
        summary = root / DEFAULT_SUMMARY
        out_root = root / "build/tracer_visibility_baseline"
        source = root / "board/trace_validation/programs/tracer_visibility_probe.c"
        out_root.mkdir(parents=True, exist_ok=True)
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("int main(void) { return 0; }\n", encoding="utf-8", newline="\n")

        def put(name: str, text: str = "fixture\n") -> Path:
            path = out_root / name
            path.write_text(text, encoding="utf-8", newline="\n")
            return path

        native_stdout = put(
            "native_plain.stdout",
            "RVMT_TRACER_VISIBILITY pid=10 ppid=1 tracer_pid=0 ptrace_traceme_rc=0 ptrace_errno=0 parent_comm=bash self_comm=probe uname_sysname=Linux uname_machine=x86_64\n",
        )
        native_strace_stdout = put(
            "native_strace.stdout",
            "RVMT_TRACER_VISIBILITY pid=11 ppid=1 tracer_pid=222 ptrace_traceme_rc=-1 ptrace_errno=1 parent_comm=strace self_comm=probe uname_sysname=Linux uname_machine=x86_64\n",
        )
        qemu_stdout = put(
            "qemu_user.stdout",
            "RVMT_TRACER_VISIBILITY pid=12 ppid=1 tracer_pid=0 ptrace_traceme_rc=0 ptrace_errno=0 parent_comm=qemu self_comm=probe uname_sysname=Linux uname_machine=riscv64\n",
        )
        qemu_strace_stdout = put(
            "qemu_user_strace.stdout",
            "RVMT_TRACER_VISIBILITY pid=13 ppid=1 tracer_pid=0 ptrace_traceme_rc=0 ptrace_errno=0 parent_comm=qemu self_comm=probe uname_sysname=Linux uname_machine=riscv64\n",
        )
        files = {
            "source": source,
            "native_binary": put("tracer_visibility_probe.native"),
            "riscv64_binary": put("tracer_visibility_probe.riscv64"),
            "native_build_log": put("native_build.log"),
            "riscv64_build_log": put("riscv64_build.log"),
            "native_compiler_version": put("native_compiler_version.txt"),
            "riscv64_compiler_version": put("riscv64_compiler_version.txt"),
        }
        stderr_files = {
            "native_plain": put("native_plain.stderr", ""),
            "native_strace": put("native_strace.stderr", ""),
            "qemu_user": put("qemu_user.stderr", ""),
            "qemu_user_strace": put("qemu_user_strace.stderr", "123 write(1,...)\n"),
        }
        strace_log = put("native_strace.trace", "execve(...)\n")

        def artifact(path: Path, role: str) -> dict[str, Any]:
            return {
                "path": path.relative_to(root).as_posix(),
                "role": role,
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }

        write_json(
            summary,
            {
                "schema": SCHEMA,
                "status": "PASS_LOCAL_SOFTWARE_TRACER_BASELINE",
                "canonical_evidence_root": "results/evaluation/genesys2-cva6/current",
                "artifacts": {name: artifact(path, name) for name, path in files.items()},
                "modes": {
                    "native_plain": {
                        "mode": "native_plain",
                        "probe": parse_probe_stdout(native_stdout),
                        "stdout": artifact(native_stdout, "probe_stdout"),
                        "stderr": artifact(stderr_files["native_plain"], "probe_stderr"),
                    },
                    "native_strace": {
                        "mode": "native_strace",
                        "probe": parse_probe_stdout(native_strace_stdout),
                        "stdout": artifact(native_strace_stdout, "probe_stdout"),
                        "stderr": artifact(stderr_files["native_strace"], "probe_stderr"),
                        "strace_log": artifact(strace_log, "software_strace_log"),
                    },
                    "qemu_user": {
                        "mode": "qemu_user",
                        "probe": parse_probe_stdout(qemu_stdout),
                        "stdout": artifact(qemu_stdout, "probe_stdout"),
                        "stderr": artifact(stderr_files["qemu_user"], "probe_stderr"),
                    },
                    "qemu_user_strace": {
                        "mode": "qemu_user_strace",
                        "probe": parse_probe_stdout(qemu_strace_stdout),
                        "stdout": artifact(qemu_strace_stdout, "probe_stdout"),
                        "stderr": artifact(stderr_files["qemu_user_strace"], "probe_stderr"),
                    },
                },
                "observations": {
                    "native_plain_untraced": True,
                    "native_strace_detected_by_tracerpid_or_ptrace": True,
                    "qemu_user_strace_log_observed": True,
                },
                "claim_boundary": {
                    "local_software_baseline_only": True,
                    "safe_probe_only": True,
                    "hardware_trace_claimed": False,
                    "genesys2_board_claimed": False,
                    "real_malware_claimed": False,
                    "malware_detection_accuracy_claimed": False,
                    "qemu_and_strace_are_oracles_only": True,
                },
            },
        )
        errors = check_summary(root, summary)
        if errors:
            print("[FAIL] tracer visibility checker self-test", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 tracer visibility baseline checker self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check the safe local tracer-visibility baseline summary.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = args.summary if args.summary.is_absolute() else root / args.summary
    errors = check_summary(root, summary)
    if errors:
        print("[FAIL] tracer visibility baseline summary is not acceptable", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"[PASS] tracer visibility baseline accepted: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
