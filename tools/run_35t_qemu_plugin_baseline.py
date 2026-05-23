from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

from experiment_35t import Sample, selected_samples  # noqa: E402


SOURCE_RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
RUN_ID = "35t-qemu-plugin-baseline-20260523"
DEFAULT_RESULTS_ROOT = Path("results/experiments/35t") / RUN_ID
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / SOURCE_RUN_ID
DEFAULT_QEMU_BUILD_ROOT = DEFAULT_RESULTS_ROOT / "qemu_user_plugin/qemu-8.2.2"
DEFAULT_QEMU_BIN = DEFAULT_QEMU_BUILD_ROOT / "build/qemu-riscv64"
SCHEMA = "rvmt.35t.qemu_plugin_baseline.v1"
PASS_STATUS = "QEMU_PLUGIN_BASELINE_PASS_13_SAMPLES"
BLOCKED_STATUS = "QEMU_PLUGIN_BASELINE_BLOCKED_CURRENT_ENVIRONMENT"
ACCEPTED_STATUSES = {PASS_STATUS, BLOCKED_STATUS}
PLUGIN_SOURCE_NAME = "rvmt_qemu_syscall_count_plugin.c"
PLUGIN_SO_NAME = "rvmt_qemu_syscall_count_plugin.so"
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
    "QEMU-plugin syscall-count evidence is a simulator software baseline, not hardware trace evidence",
]

SYSCALL_NAMES = {
    17: "getcwd",
    25: "fcntl",
    34: "mkdirat",
    35: "unlinkat",
    56: "openat",
    57: "close",
    62: "lseek",
    63: "read",
    64: "write",
    78: "readlinkat",
    80: "fstat",
    93: "exit",
    94: "exit_group",
    95: "waitid",
    96: "set_tid_address",
    98: "futex",
    99: "set_robust_list",
    113: "clock_gettime",
    160: "uname",
    172: "getpid",
    174: "getuid",
    175: "geteuid",
    176: "getgid",
    177: "getegid",
    198: "socket",
    203: "connect",
    214: "brk",
    215: "munmap",
    220: "clone",
    221: "execve",
    222: "mmap",
    226: "mprotect",
    261: "prlimit64",
    278: "getrandom",
}

PLUGIN_SOURCE = r"""
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint64_t calls[1024];
static uint64_t errors[1024];

static void on_syscall(qemu_plugin_id_t id, unsigned int vcpu_index,
                       int64_t num, uint64_t a1, uint64_t a2,
                       uint64_t a3, uint64_t a4, uint64_t a5,
                       uint64_t a6, uint64_t a7, uint64_t a8)
{
    (void)id;
    (void)vcpu_index;
    (void)a1;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;
    (void)a6;
    (void)a7;
    (void)a8;
    if (num >= 0 && num < 1024) {
        __sync_fetch_and_add(&calls[num], 1);
    }
}

static void on_syscall_ret(qemu_plugin_id_t id, unsigned int vcpu_index,
                           int64_t num, int64_t ret)
{
    (void)id;
    (void)vcpu_index;
    if (num >= 0 && num < 1024 && ret < 0) {
        __sync_fetch_and_add(&errors[num], 1);
    }
}

static void on_exit(qemu_plugin_id_t id, void *p)
{
    (void)id;
    (void)p;
    qemu_plugin_outs("RVMT_QEMU_PLUGIN_SYSCALL_COUNTS_BEGIN\n");
    for (int i = 0; i < 1024; ++i) {
        if (calls[i]) {
            char line[128];
            snprintf(line, sizeof(line),
                     "syscall=%d calls=%llu errors=%llu\n",
                     i,
                     (unsigned long long)calls[i],
                     (unsigned long long)errors[i]);
            qemu_plugin_outs(line);
        }
    }
    qemu_plugin_outs("RVMT_QEMU_PLUGIN_SYSCALL_COUNTS_END\n");
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    (void)info;
    (void)argc;
    (void)argv;
    qemu_plugin_register_vcpu_syscall_cb(id, on_syscall);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, on_syscall_ret);
    qemu_plugin_register_atexit_cb(id, on_exit, NULL);
    return 0;
}
""".strip()


CONTAINER_SCRIPT = r"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path


repo_root = Path.cwd()
manifest_path = Path(os.environ["RVMT_QEMU_PLUGIN_SAMPLE_MANIFEST"])
qemu_bin = Path(os.environ["RVMT_QEMU_PLUGIN_QEMU_BIN"])
qemu_include = Path(os.environ["RVMT_QEMU_PLUGIN_QEMU_INCLUDE"])
plugin_src = Path(os.environ["RVMT_QEMU_PLUGIN_SOURCE"])
plugin_so = Path(os.environ["RVMT_QEMU_PLUGIN_SO"])
results_root = Path(os.environ["RVMT_QEMU_PLUGIN_RESULTS"])
reps = int(os.environ.get("RVMT_QEMU_PLUGIN_REPS", "3"))
timeout_s = float(os.environ.get("RVMT_QEMU_PLUGIN_TIMEOUT", "20"))


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def run_capture(command, *, cwd: Path, stdout_path: Path, stderr_path: Path, timeout: float) -> dict:
    start = time.time_ns()
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
    end = time.time_ns()
    stdout_path.write_text(stdout, encoding="utf-8", newline="\n")
    stderr_path.write_text(stderr, encoding="utf-8", newline="\n")
    return {
        "command": command,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "runtime_ns": end - start,
        "stdout_path": rel(stdout_path),
        "stderr_path": rel(stderr_path),
        "stdout_bytes": len(stdout.encode("utf-8", errors="replace")),
        "stderr_bytes": len(stderr.encode("utf-8", errors="replace")),
    }


def parse_counts(text: str) -> dict[str, dict[str, int]]:
    if "RVMT_QEMU_PLUGIN_SYSCALL_COUNTS_BEGIN" not in text:
        return {}
    body = text.split("RVMT_QEMU_PLUGIN_SYSCALL_COUNTS_BEGIN", 1)[1].split(
        "RVMT_QEMU_PLUGIN_SYSCALL_COUNTS_END", 1
    )[0]
    rows = {}
    for line in body.splitlines():
        match = re.search(r"syscall=(\d+)\s+calls=(\d+)\s+errors=(\d+)", line)
        if match:
            rows[match.group(1)] = {
                "calls": int(match.group(2)),
                "errors": int(match.group(3)),
            }
    return rows


samples = json.loads(manifest_path.read_text(encoding="utf-8"))["samples"]
results_root.mkdir(parents=True, exist_ok=True)
plugin_so.parent.mkdir(parents=True, exist_ok=True)

compile_cmd = [
    "gcc",
    "-fPIC",
    "-shared",
    "-O2",
    "-Wall",
    "-Wextra",
    f"-I{qemu_include.as_posix()}",
    plugin_src.as_posix(),
    "-o",
    plugin_so.as_posix(),
]
compile_result = run_capture(
    compile_cmd,
    cwd=repo_root,
    stdout_path=results_root / "plugin_compile.stdout.txt",
    stderr_path=results_root / "plugin_compile.stderr.txt",
    timeout=timeout_s,
)

sample_rows = []
for sample in samples:
    sample_id = sample["sample_id"]
    sample_class = sample["sample_class"]
    binary = Path(sample["riscv_binary"])
    args = [str(item) for item in sample.get("args", [])]
    out_dir = results_root / "samples" / sample_class / sample_id / "qemu_plugin"
    out_dir.mkdir(parents=True, exist_ok=True)
    timings_path = out_dir / "timings.jsonl"
    all_counts: dict[str, dict[str, int]] = {}
    rep_rows = []
    with timings_path.open("w", encoding="utf-8", newline="\n") as timing_fh:
        for rep in range(reps):
            stdout_path = out_dir / f"qemu_plugin.{rep}.stdout.txt"
            stderr_path = out_dir / f"qemu_plugin.{rep}.stderr.txt"
            result = run_capture(
                [
                    qemu_bin.as_posix(),
                    "-d",
                    "plugin",
                    "-plugin",
                    plugin_so.as_posix(),
                    binary.as_posix(),
                    *args,
                ],
                cwd=repo_root,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                timeout=timeout_s,
            )
            text = stdout_path.read_text(encoding="utf-8", errors="replace") + "\n" + stderr_path.read_text(
                encoding="utf-8", errors="replace"
            )
            counts = parse_counts(text)
            for number, row in counts.items():
                current = all_counts.setdefault(number, {"calls": 0, "errors": 0})
                current["calls"] += row["calls"]
                current["errors"] += row["errors"]
            result["rep"] = rep
            result["plugin_count_rows"] = len(counts)
            rep_rows.append(result)
            timing_fh.write(
                json.dumps(
                    {
                        "baseline": "qemu_plugin",
                        "rep": rep,
                        "exit_code": result["exit_code"],
                        "runtime_ns": result["runtime_ns"],
                        "plugin_count_rows": len(counts),
                    },
                    sort_keys=True,
                )
                + "\n"
            )
    status = "PASS" if rep_rows and all(row["exit_code"] == 0 and row["plugin_count_rows"] > 0 for row in rep_rows) else "FAIL"
    sample_rows.append(
        {
            "sample_id": sample_id,
            "sample_class": sample_class,
            "status": status,
            "reps": reps,
            "riscv_binary": rel(binary),
            "timings_path": rel(timings_path),
            "rep_results": rep_rows,
            "syscall_counts": all_counts,
        }
    )

summary = {
    "qemu_bin": rel(qemu_bin),
    "qemu_version": subprocess.run(
        [qemu_bin.as_posix(), "--version"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    ).stdout.splitlines()[0],
    "qemu_help_has_plugin": "-plugin" in subprocess.run(
        [qemu_bin.as_posix(), "--help"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    ).stdout,
    "plugin_source": rel(plugin_src),
    "plugin_so": rel(plugin_so),
    "plugin_compile": compile_result,
    "sample_count": len(sample_rows),
    "pass_count": sum(1 for row in sample_rows if row["status"] == "PASS"),
    "samples": sample_rows,
}
(results_root / "aggregate").mkdir(parents=True, exist_ok=True)
(results_root / "aggregate/qemu_plugin_baseline_raw.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="\n",
)
print("RVMT_QEMU_PLUGIN_BASELINE_JSON_BEGIN")
print(json.dumps(summary, sort_keys=True))
print("RVMT_QEMU_PLUGIN_BASELINE_JSON_END")
""".strip()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def repo_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def docker_compose_base() -> list[str]:
    return ["docker", "compose", "-f", "docker-compose.toolchain.yml"]


def sample_args(sample: Sample) -> list[str]:
    if sample.source.endswith("rvmt_benign_workload.c"):
        return [sample.sample_id]
    return []


def sample_manifest(repo_root: Path, samples: list[Sample]) -> dict[str, Any]:
    rows = []
    for sample in samples:
        binary = (
            Path("results/experiments/35t")
            / SOURCE_RUN_ID
            / "samples"
            / sample.sample_class
            / sample.sample_id
            / "build"
            / f"{sample.sample_id}.riscv"
        )
        rows.append(
            {
                "sample_id": sample.sample_id,
                "sample_class": sample.sample_class,
                "source": sample.source,
                "args": sample_args(sample),
                "riscv_binary": binary.as_posix(),
                "riscv_binary_exists": repo_path(repo_root, binary).is_file(),
            }
        )
    return {"source_run_id": SOURCE_RUN_ID, "samples": rows}


def extract_container_json(stdout: str) -> dict[str, Any] | None:
    begin = "RVMT_QEMU_PLUGIN_BASELINE_JSON_BEGIN"
    end = "RVMT_QEMU_PLUGIN_BASELINE_JSON_END"
    if begin not in stdout or end not in stdout:
        return None
    payload = stdout.split(begin, 1)[1].split(end, 1)[0].strip()
    try:
        value = json.loads(payload)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def run_container_baseline(
    repo_root: Path,
    *,
    sample_manifest_path: Path,
    qemu_bin: Path,
    qemu_include: Path,
    plugin_src: Path,
    plugin_so: Path,
    results_root: Path,
    reps: int,
    timeout_seconds: float,
) -> dict[str, Any]:
    command = [
        *docker_compose_base(),
        "run",
        "--rm",
        "linux-behavior",
        "bash",
        "-lc",
        (
            f"RVMT_QEMU_PLUGIN_SAMPLE_MANIFEST={sample_manifest_path.as_posix()} "
            f"RVMT_QEMU_PLUGIN_QEMU_BIN={qemu_bin.as_posix()} "
            f"RVMT_QEMU_PLUGIN_QEMU_INCLUDE={qemu_include.as_posix()} "
            f"RVMT_QEMU_PLUGIN_SOURCE={plugin_src.as_posix()} "
            f"RVMT_QEMU_PLUGIN_SO={plugin_so.as_posix()} "
            f"RVMT_QEMU_PLUGIN_RESULTS={results_root.as_posix()} "
            f"RVMT_QEMU_PLUGIN_REPS={reps} "
            f"RVMT_QEMU_PLUGIN_TIMEOUT={timeout_seconds} "
            f"RVMT_FIXTURE_ROOT=experiments/linux_behavior/benign/fixtures "
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
            timeout=max(120.0, timeout_seconds * reps * 20),
            check=False,
        )
    except FileNotFoundError as exc:
        return {"argv": command, "exit_code": 127, "stdout": "", "stderr": str(exc)}
    except subprocess.TimeoutExpired as exc:
        return {
            "argv": command,
            "exit_code": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or f"timeout after {max(120.0, timeout_seconds * reps * 20)}s",
        }
    return {
        "argv": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def with_syscall_names(counts: dict[str, Any]) -> dict[str, dict[str, Any]]:
    named: dict[str, dict[str, Any]] = {}
    for key, value in counts.items():
        try:
            number = int(key)
        except ValueError:
            number = -1
        label = SYSCALL_NAMES.get(number, f"sys_{key}")
        row = value if isinstance(value, dict) else {}
        named[label] = {
            "number": number,
            "calls": int(row.get("calls") or 0),
            "errors": int(row.get("errors") or 0),
        }
    return dict(sorted(named.items(), key=lambda item: item[1]["number"]))


def build_report_from_container(
    *,
    repo_root: Path,
    results_root: Path,
    evidence_root: Path,
    manifest: dict[str, Any],
    qemu_bin: Path,
    qemu_build_root: Path,
    plugin_src: Path,
    plugin_so: Path,
    container_result: dict[str, Any],
    reps: int,
) -> dict[str, Any]:
    container_json = extract_container_json(str(container_result.get("stdout", "")))
    samples = container_json.get("samples", []) if isinstance(container_json, dict) else []
    sample_rows = [row for row in samples if isinstance(row, dict)] if isinstance(samples, list) else []
    for row in sample_rows:
        row["syscall_name_counts"] = with_syscall_names(row.get("syscall_counts", {}))
    qemu_help_has_plugin = bool(container_json.get("qemu_help_has_plugin")) if isinstance(container_json, dict) else False
    plugin_compile = container_json.get("plugin_compile", {}) if isinstance(container_json, dict) else {}
    pass_count = sum(1 for row in sample_rows if row.get("status") == "PASS")
    sample_count = len(sample_rows)
    manifest_samples = manifest.get("samples", []) if isinstance(manifest.get("samples"), list) else []
    binary_missing = [row["riscv_binary"] for row in manifest_samples if not row.get("riscv_binary_exists")]
    checks = {
        "qemu_binary_exists": repo_path(repo_root, qemu_bin).is_file(),
        "qemu_help_has_plugin": qemu_help_has_plugin,
        "qemu_source_include_exists": repo_path(repo_root, qemu_build_root / "include/qemu/qemu-plugin.h").is_file(),
        "sample_manifest_count_13": len(manifest_samples) == 13,
        "sample_binaries_present": not binary_missing,
        "container_command_passed": container_result.get("exit_code") == 0,
        "container_json_present": container_json is not None,
        "plugin_compiled": plugin_compile.get("exit_code") == 0 and repo_path(repo_root, plugin_so).is_file(),
        "sample_count_13": sample_count == 13,
        "all_samples_passed": sample_count == 13 and pass_count == 13,
        "all_reps_have_plugin_counts": all(
            isinstance(row.get("rep_results"), list)
            and len(row["rep_results"]) == reps
            and all(int(rep.get("plugin_count_rows") or 0) > 0 for rep in row["rep_results"])
            for row in sample_rows
        ),
        "timing_paths_recorded": all(row.get("timings_path") for row in sample_rows),
        "non_claims_recorded": True,
    }
    failures = [key for key, ok in checks.items() if not ok]
    if all(checks.values()):
        status = PASS_STATUS
    elif container_result.get("exit_code") in {124, 127} or not checks["qemu_binary_exists"]:
        status = BLOCKED_STATUS
    else:
        status = "FAIL"
    argv = container_result.get("argv")
    argv_summary = [*argv[:-1], "<inline qemu plugin baseline script>"] if isinstance(argv, list) and argv else argv
    qemu_tar = repo_path(repo_root, DEFAULT_RESULTS_ROOT / "qemu_user_plugin/qemu-8.2.2.tar.xz")
    return {
        "schema": SCHEMA,
        "run_id": RUN_ID,
        "source_run_id": SOURCE_RUN_ID,
        "generated_utc": utc_now(),
        "status": status,
        "scope": "Artix-7 35T / LiteX / VexRiscv",
        "claim_level": "35T hardware-trace-assisted synthetic malware-like behavior audit prototype",
        "results_root": rel(results_root, repo_root),
        "evidence_root": rel(evidence_root, repo_root),
        "qemu": {
            "binary": rel(qemu_bin, repo_root),
            "build_root": rel(qemu_build_root, repo_root),
            "version": container_json.get("qemu_version", "") if isinstance(container_json, dict) else "",
            "help_has_plugin": qemu_help_has_plugin,
            "source_tar_sha256": hashlib.sha256(qemu_tar.read_bytes()).hexdigest() if qemu_tar.is_file() else "",
        },
        "plugin": {
            "source": rel(plugin_src, repo_root),
            "source_sha256": hashlib.sha256(plugin_src.read_bytes()).hexdigest() if plugin_src.is_file() else "",
            "shared_object": rel(plugin_so, repo_root),
            "compile": plugin_compile,
        },
        "sample_count": sample_count,
        "pass_count": pass_count,
        "reps": reps,
        "samples": sample_rows,
        "checks": checks,
        "container_probe": {
            "argv": argv_summary,
            "exit_code": container_result.get("exit_code"),
            "stderr_tail": str(container_result.get("stderr", ""))[-2000:],
            "inline_script_sha256": hashlib.sha256(CONTAINER_SCRIPT.encode("utf-8")).hexdigest(),
        },
        "interpretation": [
            "this is a QEMU user-mode TCG-plugin syscall-count baseline for the existing 13 synthetic 35T samples",
            "the baseline uses an upstream QEMU 8.2.2 riscv64-linux-user build configured with --enable-plugins",
            "per-sample plugin output and timing are recorded under the local results tree",
            "this simulator software baseline must not be reported as hardware trace, real malware detection, or complete semantic reconstruction",
        ],
        "non_claims": NON_CLAIMS,
        "failures": failures,
        "missing_sample_binaries": binary_missing,
    }


def build_report(
    *,
    repo_root: Path,
    results_root_arg: Path,
    evidence_root_arg: Path,
    qemu_bin_arg: Path,
    qemu_build_root_arg: Path,
    reps: int,
    timeout_seconds: float,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    results_root = repo_path(repo_root, results_root_arg).resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    qemu_bin = repo_path(repo_root, qemu_bin_arg).resolve()
    qemu_build_root = repo_path(repo_root, qemu_build_root_arg).resolve()
    plugin_src = results_root / PLUGIN_SOURCE_NAME
    plugin_so = results_root / PLUGIN_SO_NAME
    manifest_path = results_root / "sample_manifest.json"
    results_root.mkdir(parents=True, exist_ok=True)
    plugin_src.write_text(PLUGIN_SOURCE + "\n", encoding="utf-8", newline="\n")
    samples = selected_samples([])
    manifest = sample_manifest(repo_root, samples)
    write_json(manifest_path, manifest)
    container_result = run_container_baseline(
        repo_root,
        sample_manifest_path=manifest_path.relative_to(repo_root),
        qemu_bin=qemu_bin.relative_to(repo_root),
        qemu_include=(qemu_build_root / "include/qemu").relative_to(repo_root),
        plugin_src=plugin_src.relative_to(repo_root),
        plugin_so=plugin_so.relative_to(repo_root),
        results_root=results_root.relative_to(repo_root),
        reps=reps,
        timeout_seconds=timeout_seconds,
    )
    return build_report_from_container(
        repo_root=repo_root,
        results_root=results_root,
        evidence_root=evidence_root,
        manifest=manifest,
        qemu_bin=qemu_bin,
        qemu_build_root=qemu_build_root,
        plugin_src=plugin_src,
        plugin_so=plugin_so,
        container_result=container_result,
        reps=reps,
    )


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T QEMU-Plugin Baseline: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Source run: `{report['source_run_id']}`",
        f"Results root: `{report['results_root']}`",
        "",
        "## QEMU",
        "",
        f"- binary: `{report['qemu']['binary']}`",
        f"- version: {report['qemu']['version'] or 'unknown'}",
        f"- help_has_plugin: {report['qemu']['help_has_plugin']}",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += [
        "",
        "## Samples",
        "",
        "| Sample | Class | Status | Reps | Syscalls | Timing |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in report["samples"]:
        syscall_count = len(row.get("syscall_counts", {})) if isinstance(row.get("syscall_counts"), dict) else 0
        lines.append(
            f"| `{row.get('sample_id')}` | `{row.get('sample_class')}` | `{row.get('status')}` | "
            f"{row.get('reps')} | {syscall_count} | `{row.get('timings_path')}` |"
        )
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    write_json(evidence_root / "qemu_plugin_baseline_summary.json", report)
    (evidence_root / "qemu_plugin_baseline_summary.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def fake_container(samples: list[dict[str, Any]], reps: int) -> dict[str, Any]:
    rows = []
    for sample in samples:
        rows.append(
            {
                "sample_id": sample["sample_id"],
                "sample_class": sample["sample_class"],
                "status": "PASS",
                "reps": reps,
                "riscv_binary": sample["riscv_binary"],
                "timings_path": f"results/{sample['sample_id']}/timings.jsonl",
                "rep_results": [{"rep": rep, "exit_code": 0, "plugin_count_rows": 2} for rep in range(reps)],
                "syscall_counts": {"56": {"calls": 1, "errors": 0}, "94": {"calls": 1, "errors": 0}},
            }
        )
    payload = {
        "qemu_bin": "fixture/qemu-riscv64",
        "qemu_version": "qemu-riscv64 version 8.2.2",
        "qemu_help_has_plugin": True,
        "plugin_compile": {"exit_code": 0},
        "sample_count": len(rows),
        "pass_count": len(rows),
        "samples": rows,
    }
    return {
        "argv": ["fake"],
        "exit_code": 0,
        "stdout": "RVMT_QEMU_PLUGIN_BASELINE_JSON_BEGIN\n" + json.dumps(payload) + "\nRVMT_QEMU_PLUGIN_BASELINE_JSON_END\n",
        "stderr": "",
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        evidence = root / DEFAULT_EVIDENCE_ROOT
        results = root / DEFAULT_RESULTS_ROOT
        qemu_root = root / DEFAULT_QEMU_BUILD_ROOT
        qemu_bin = root / DEFAULT_QEMU_BIN
        (qemu_root / "include/qemu").mkdir(parents=True, exist_ok=True)
        (qemu_root / "include/qemu/qemu-plugin.h").write_text("fixture\n", encoding="utf-8")
        qemu_bin.parent.mkdir(parents=True, exist_ok=True)
        qemu_bin.write_text("fixture\n", encoding="utf-8")
        (results / "qemu_user_plugin").mkdir(parents=True, exist_ok=True)
        (results / "qemu_user_plugin/qemu-8.2.2.tar.xz").write_text("fixture\n", encoding="utf-8")
        plugin_src = results / PLUGIN_SOURCE_NAME
        plugin_so = results / PLUGIN_SO_NAME
        plugin_src.write_text(PLUGIN_SOURCE + "\n", encoding="utf-8")
        plugin_so.write_text("fixture\n", encoding="utf-8")
        samples = [
            {
                "sample_id": f"s{i}",
                "sample_class": "fixture",
                "source": "fixture.c",
                "args": [],
                "riscv_binary": f"fixture/s{i}.riscv",
                "riscv_binary_exists": True,
            }
            for i in range(13)
        ]
        report = build_report_from_container(
            repo_root=root,
            results_root=results,
            evidence_root=evidence,
            manifest={"samples": samples},
            qemu_bin=qemu_bin,
            qemu_build_root=qemu_root,
            plugin_src=plugin_src,
            plugin_so=plugin_so,
            container_result=fake_container(samples, reps=2),
            reps=2,
        )
        if report["status"] != PASS_STATUS:
            print("[FAIL] expected QEMU-plugin baseline fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, evidence)
        if not (evidence / "qemu_plugin_baseline_summary.md").is_file():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

        bad = build_report_from_container(
            repo_root=root,
            results_root=results,
            evidence_root=evidence,
            manifest={"samples": samples[:-1]},
            qemu_bin=qemu_bin,
            qemu_build_root=qemu_root,
            plugin_src=plugin_src,
            plugin_so=plugin_so,
            container_result=fake_container(samples[:-1], reps=2),
            reps=2,
        )
        if bad["status"] != "FAIL" or "sample_manifest_count_13" not in bad["failures"]:
            print("[FAIL] expected incomplete fixture to fail", file=sys.stderr)
            return 1
    print("[PASS] 35T QEMU-plugin baseline self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a QEMU TCG-plugin syscall baseline for the 13 existing 35T synthetic samples.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--qemu-bin", type=Path, default=DEFAULT_QEMU_BIN)
    parser.add_argument("--qemu-build-root", type=Path, default=DEFAULT_QEMU_BUILD_ROOT)
    parser.add_argument("--reps", type=int, default=3)
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
            repo_root=repo_root,
            results_root_arg=args.results_root,
            evidence_root_arg=args.evidence_root,
            qemu_bin_arg=args.qemu_bin,
            qemu_build_root_arg=args.qemu_build_root,
            reps=args.reps,
            timeout_seconds=args.timeout_seconds,
        )
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"run_35t_qemu_plugin_baseline: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T QEMU-plugin baseline")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] in ACCEPTED_STATUSES else 1


if __name__ == "__main__":
    raise SystemExit(main())
