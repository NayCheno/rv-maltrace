from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from rv_maltrace.cli import (  # noqa: E402
    ARTIX7_TRACE_RAW_RECORD_WORDS,
    artix7_trace_csr_base,
    raw_trace_record_to_event,
)
from rv_maltrace.trace_profiles import (  # noqa: E402
    get_trace_profile,
    profile_names,
    trace_control_mask_for_profile,
)


BENIGN_MANIFEST = Path("experiments/linux_behavior/benign/manifest.json")
MALWARE_MANIFEST = Path("experiments/linux_behavior/malware_like/manifest.json")
RULES_PATH = Path("experiments/linux_behavior/behavior_audit_rules.json")
ROOTFS_EXP_BIN_DIR = Path("build/board/artix7_35t/rootfs_exp_overlay/usr/bin")
TRACE_OFF = "trace-off"
TRACE_ON = "trace-on"
RUNTIME_CLASSIC = "classic"
RUNTIME_ABBA = "abba"
TRACE_PROFILE_POLICY_UNIFORM = "uniform"
TRACE_PROFILE_POLICY_35T_SMALL_CAPACITY = "35t_small_capacity"
TRACE_PROFILE_POLICY_CHOICES = (TRACE_PROFILE_POLICY_UNIFORM, TRACE_PROFILE_POLICY_35T_SMALL_CAPACITY)
TRACE_PROFILE_POLICY_35T_TRAP_SAMPLES = frozenset({"illegal_trap"})
REQUIRED_BASELINES = ("host_native", "host_strace", "qemu_native", "qemu_strace")
OPTIONAL_BASELINES = ("ebpf_only", "qemu_plugin", "software_instrumentation")
UART_TIMESTAMP_RE = re.compile(r"\[[0-9]+(?:\.[0-9]+)?\]\s*")
UART_MARKERS = (
    "RVMT_EXP_REP_BEGIN",
    "RVMT_EXP_REP_RESULT",
    "RVMT_EXP_REP_END",
    "RVMT_EXP_END",
    "RVMT_RUNTIME_PROCESS_MAP_BEGIN",
    "RVMT_RUNTIME_PROCESS_MAP_ENTRY",
    "RVMT_RUNTIME_PROCESS_PROVENANCE",
    "RVMT_RUNTIME_PROCESS_MAP_END",
    "RVMT_RUNTIME_PROCESS",
    "RVMT_TRACE_DUMP_BEGIN",
    "RVMT_TRACE_DUMP_END",
    "RVMT_TRACE_RECORD",
)
UART_MARKER_PATTERNS = tuple((re.compile(r"\s*".join(re.escape(char) for char in marker)), marker) for marker in UART_MARKERS)
UART_FIELD_KEYS = (
    "class",
    "sample",
    "mode",
    "rep",
    "order_index",
    "warmup",
    "exit",
    "runtime_ns",
    "trace_count",
    "drop",
    "schema",
    "role",
    "pid",
    "tgid",
    "status",
    "comm_hex",
    "exe_hex",
    "start",
    "end",
    "perms",
    "offset",
    "dev",
    "inode",
    "path_hex",
    "collector",
    "method",
    "proc_sample_time",
    "warnings_hex",
)
UART_FIELD_KEY_PATTERN = "|".join(re.escape(key) for key in UART_FIELD_KEYS)
UART_FIELD_RE = re.compile(
    rf"\b({UART_FIELD_KEY_PATTERN})=([^\s]*?)(?=(?:{UART_FIELD_KEY_PATTERN})=|\s+(?:{UART_FIELD_KEY_PATTERN})=|$)"
)


@dataclass(frozen=True)
class Sample:
    sample_class: str
    sample_id: str
    source: str
    command: list[str]
    expected_behavior: list[str]
    evidence_dir: str


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def repo_rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def sh_quote(value: str | os.PathLike[str]) -> str:
    text = str(value)
    return "'" + text.replace("'", "'\"'\"'") + "'"


def result_root(run_id: str) -> Path:
    return ROOT / "results" / "experiments" / "35t" / run_id


def sample_root(run_id: str, sample: Sample) -> Path:
    return result_root(run_id) / "samples" / sample.sample_class / sample.sample_id


def aggregate_root(run_id: str) -> Path:
    return result_root(run_id) / "aggregate"


def load_samples() -> list[Sample]:
    benign = load_json(ROOT / BENIGN_MANIFEST)
    malware = load_json(ROOT / MALWARE_MANIFEST)
    samples: list[Sample] = []
    for row in benign.get("samples", []):
        if not isinstance(row, dict) or row.get("default_enabled") is not True:
            continue
        if row.get("network_required"):
            continue
        source = row.get("source")
        if not isinstance(source, str):
            raise ValueError(f"{BENIGN_MANIFEST}: benign sample {row.get('id')} is missing source")
        samples.append(
            Sample(
                sample_class="benign",
                sample_id=str(row["id"]),
                source=source,
                command=[str(item) for item in row.get("command", [])],
                expected_behavior=[str(item) for item in row.get("expected_behavior", [])],
                evidence_dir=str(row.get("evidence_dir", "")),
            )
        )
    for row in malware.get("samples", []):
        if not isinstance(row, dict):
            continue
        samples.append(
            Sample(
                sample_class="malware_like_synthetic",
                sample_id=str(row["id"]),
                source=str(row["source"]),
                command=[str(item) for item in row.get("command", [])],
                expected_behavior=[str(item) for item in row.get("expected_behavior", [])],
                evidence_dir=str(row.get("evidence_dir", "")),
            )
        )
    return samples


def selected_samples(sample_ids: Iterable[str] | None = None) -> list[Sample]:
    samples = load_samples()
    wanted = {item for item in (sample_ids or []) if item}
    if not wanted:
        return samples
    result = [sample for sample in samples if sample.sample_id in wanted or sample.sample_class in wanted]
    missing = sorted(wanted - {sample.sample_id for sample in result} - {sample.sample_class for sample in result})
    if missing:
        raise ValueError(f"unknown sample selectors: {', '.join(missing)}")
    return result


def trace_profile_for_sample(sample: Sample, default_profile: str, policy: str) -> str:
    if policy == TRACE_PROFILE_POLICY_35T_SMALL_CAPACITY:
        if sample.sample_id in TRACE_PROFILE_POLICY_35T_TRAP_SAMPLES:
            return "p0c_syscall_trap_drop"
        return "p0a_syscall_drop"
    return default_profile


def trace_profiles_by_sample(samples: list[Sample], default_profile: str, policy: str) -> dict[str, str]:
    return {sample.sample_id: trace_profile_for_sample(sample, default_profile, policy) for sample in samples}


def sample_groups_by_trace_profile(
    samples: list[Sample], default_profile: str, policy: str
) -> list[tuple[str, list[Sample]]]:
    groups: dict[str, list[Sample]] = {}
    for sample in samples:
        profile = trace_profile_for_sample(sample, default_profile, policy)
        get_trace_profile(profile)
        groups.setdefault(profile, []).append(sample)
    return list(groups.items())


def run_command(cmd: list[str], *, cwd: Path = ROOT, dry_run: bool = False, log_path: Path | None = None) -> int:
    display = " ".join(sh_quote(part) if " " in str(part) else str(part) for part in cmd)
    if dry_run:
        print(f"+ {display}" + (f" > {log_path}" if log_path else ""))
        return 0
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    if log_path is None:
        completed = subprocess.run(cmd, cwd=str(cwd))
        return completed.returncode
    with log_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(f"$ {display}\n")
        handle.flush()
        completed = subprocess.run(cmd, cwd=str(cwd), stdout=handle, stderr=subprocess.STDOUT)
    return completed.returncode


def docker_compose_base() -> list[str]:
    return ["docker", "compose", "-f", "docker-compose.toolchain.yml"]


def groundtruth_shell(sample: Sample, run_id: str, reps: int) -> str:
    out_dir = sample_root(run_id, sample)
    build_dir = out_dir / "build"
    gt_dir = out_dir / "groundtruth"
    source = ROOT / sample.source
    build_dir_posix = repo_rel(build_dir)
    gt_dir_posix = repo_rel(gt_dir)
    source_posix = repo_rel(source)
    host_bin_posix = f"{build_dir_posix}/{sample.sample_id}.host"
    rv_bin_posix = f"{build_dir_posix}/{sample.sample_id}.riscv"
    if sample.source.endswith("rvmt_benign_workload.c"):
        host_args = [sample.sample_id]
        rv_args = [sample.sample_id]
    else:
        host_args = []
        rv_args = []
    host_args_shell = " ".join(sh_quote(arg) for arg in host_args)
    rv_args_shell = " ".join(sh_quote(arg) for arg in rv_args)
    fixture_env = "env RVMT_FIXTURE_ROOT=experiments/linux_behavior/benign/fixtures"
    return f"""
set -u
sample={sh_quote(sample.sample_id)}
mkdir -p {sh_quote(build_dir_posix)} {sh_quote(gt_dir_posix)}
sha256sum {sh_quote(source_posix)} > {sh_quote(f"{build_dir_posix}/source.sha256")}
gcc --version | head -n 1 > {sh_quote(f"{build_dir_posix}/compiler.txt")}
riscv64-linux-gnu-gcc --version | head -n 1 >> {sh_quote(f"{build_dir_posix}/compiler.txt")}
gcc -O2 -Wall -Wextra -o {sh_quote(host_bin_posix)} {sh_quote(source_posix)}
riscv64-linux-gnu-gcc -O2 -static -o {sh_quote(rv_bin_posix)} {sh_quote(source_posix)}
sha256sum {sh_quote(host_bin_posix)} > {sh_quote(f"{build_dir_posix}/host_elf.sha256")}
sha256sum {sh_quote(rv_bin_posix)} > {sh_quote(f"{build_dir_posix}/riscv_elf.sha256")}
: > {sh_quote(f"{gt_dir_posix}/timings.jsonl")}
fail_count=0
run_timed() {{
  label="$1"
  rep="$2"
  stdout="$3"
  stderr="$4"
  shift 4
  start="$(date +%s%N)"
  "$@" > "$stdout" 2> "$stderr"
  code="$?"
  end="$(date +%s%N)"
  runtime="$((end - start))"
  printf '{{"baseline":"%s","rep":%s,"exit_code":%s,"runtime_ns":%s}}\\n' "$label" "$rep" "$code" "$runtime" >> {sh_quote(f"{gt_dir_posix}/timings.jsonl")}
  if [ "$code" -ne 0 ]; then
    fail_count="$((fail_count + 1))"
  fi
}}
rep=0
while [ "$rep" -lt {reps} ]; do
  run_timed host_native "$rep" {sh_quote(gt_dir_posix)}/host_native.$rep.stdout.txt {sh_quote(gt_dir_posix)}/host_native.$rep.stderr.txt {fixture_env} {sh_quote(host_bin_posix)} {host_args_shell}
  run_timed host_strace "$rep" {sh_quote(gt_dir_posix)}/host_strace.$rep.stdout.txt {sh_quote(gt_dir_posix)}/host_strace.$rep.stderr.txt {fixture_env} strace -f -o {sh_quote(gt_dir_posix)}/host_strace.$rep.strace.log {sh_quote(host_bin_posix)} {host_args_shell}
  run_timed qemu_native "$rep" {sh_quote(gt_dir_posix)}/qemu_native.$rep.stdout.txt {sh_quote(gt_dir_posix)}/qemu_native.$rep.stderr.txt {fixture_env} qemu-riscv64 {sh_quote(rv_bin_posix)} {rv_args_shell}
  run_timed qemu_strace "$rep" {sh_quote(gt_dir_posix)}/qemu_strace.$rep.stdout.txt {sh_quote(gt_dir_posix)}/qemu_strace.$rep.strace.log {fixture_env} qemu-riscv64 -strace {sh_quote(rv_bin_posix)} {rv_args_shell}
  rep="$((rep + 1))"
done
cat > {sh_quote(f"{gt_dir_posix}/optional_baselines.json")} <<'JSON'
{{
  "ebpf_only": {{"status": "BLOCKED", "reason": "No privileged eBPF collector is implemented for the 35T experiment runner."}},
  "qemu_plugin": {{"status": "BLOCKED", "reason": "No RV-MalTrace QEMU plugin path is configured; set RVMT_QEMU_PLUGIN in a future extension."}},
  "software_instrumentation": {{"status": "BLOCKED", "reason": "No software instrumentation command is configured; set RVMT_INSTRUMENTATION_CMD in a future extension."}}
}}
JSON
if [ "$fail_count" -eq 0 ]; then
  status=PASS
else
  status=FAIL
fi
cat > {sh_quote(f"{gt_dir_posix}/status.json")} <<JSON
{{"status":"$status","sample":"{sample.sample_id}","class":"{sample.sample_class}","reps":{reps},"failed_required_baseline_runs":$fail_count}}
JSON
""".strip()


def stage_groundtruth(args: argparse.Namespace, samples: list[Sample]) -> None:
    for sample in samples:
        shell = groundtruth_shell(sample, args.run_id, args.reps)
        log_path = sample_root(args.run_id, sample) / "groundtruth" / "groundtruth_build_run.log"
        cmd = [*docker_compose_base(), "run", "--rm", "--build", "linux-behavior", "bash", "-lc", shell]
        code = run_command(cmd, dry_run=args.dry_run, log_path=log_path)
        if code != 0 and not args.dry_run:
            status = {
                "status": "FAIL",
                "sample": sample.sample_id,
                "class": sample.sample_class,
                "stage": "groundtruth",
                "exit_code": code,
                "log": repo_rel(log_path),
            }
            status_path = sample_root(args.run_id, sample) / "groundtruth" / "status.json"
            status_path.parent.mkdir(parents=True, exist_ok=True)
            status_path.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if code != 0 and not args.keep_going:
            raise SystemExit(code)


def stage_rootfs(args: argparse.Namespace) -> None:
    log_path = result_root(args.run_id) / "rootfs" / "build-artix7-linux-images.log"
    cmd = [*docker_compose_base(), "run", "--rm", "--build", "litex-build", "bash", "docker/litex/build-artix7-linux-images.sh"]
    code = run_command(cmd, dry_run=args.dry_run, log_path=log_path)
    if code != 0:
        raise SystemExit(code)


def serial_capture(port: str, baud: int, duration: float, commands: list[str], log_path: Path, *, dry_run: bool) -> None:
    print(f"+ capture 35T experiment UART on {port} {baud} 8N1 for {duration:g}s to {log_path}")
    for command in commands:
        print(f"+ send: {command}")
    if dry_run:
        return
    try:
        import serial
    except ImportError as exc:
        raise RuntimeError("pyserial is required for exp:35t board stage") from exc
    log_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    deadline = start + duration
    expected_exp_ends = sum(1 for command in commands if "rvmt_exp_runner" in command)
    exp_end_count = 0
    marker_buffer = ""

    def write_log(handle, text: str) -> None:
        nonlocal exp_end_count, marker_buffer
        for line in text.splitlines(keepends=True):
            handle.write(f"[{time.monotonic() - start:010.3f}] {line}")
            marker_buffer += line
            if not line.endswith(("\n", "\r")):
                marker_buffer = marker_buffer[-512:]
                continue
            if "RVMT_EXP_END status=" in clean_uart_line(marker_buffer):
                exp_end_count += 1
            marker_buffer = ""
        handle.flush()

    with serial.Serial(port, baud, timeout=0.1) as ser, log_path.open("w", encoding="utf-8", newline="\n") as log:
        log.write(f"# port={port} baud={baud} framing=8N1\n")
        time.sleep(1.0)
        while ser.in_waiting:
            write_log(log, ser.read(4096).decode("utf-8", errors="replace"))
        for command in commands:
            log.write(f"[{time.monotonic() - start:010.3f}] >> {command}\n")
            for char in command:
                ser.write(char.encode("utf-8"))
                ser.flush()
                time.sleep(0.004)
            ser.write(b"\r")
            ser.flush()
            until = min(deadline, time.monotonic() + 2.0)
            while time.monotonic() < until:
                chunk = ser.read(4096)
                if chunk:
                    write_log(log, chunk.decode("utf-8", errors="replace"))
        while time.monotonic() < deadline:
            chunk = ser.read(4096)
            if chunk:
                write_log(log, chunk.decode("utf-8", errors="replace"))
                if expected_exp_ends and exp_end_count >= expected_exp_ends:
                    break


def stage_board(args: argparse.Namespace, samples: list[Sample]) -> None:
    csr_base = artix7_trace_csr_base(ROOT, args.trace_records, allow_default=args.dry_run)
    commands = ["root", "cd /opt/rvmt"]
    for profile_name, profile_samples in sample_groups_by_trace_profile(
        samples, args.trace_profile, args.trace_profile_policy
    ):
        selectors = " ".join(sample.sample_id for sample in profile_samples)
        control_mask = trace_control_mask_for_profile(profile_name)
        runner_args = f"--control-mask 0x{control_mask:x} --warmup {args.warmup}"
        if args.runtime_order == RUNTIME_ABBA:
            commands.append(
                f"/usr/bin/rvmt_exp_runner 0x{csr_base:08x} {args.trace_records} {args.reps} abba {runner_args} {selectors}"
            )
        else:
            commands.extend(
                [
                    f"/usr/bin/rvmt_exp_runner 0x{csr_base:08x} {args.trace_records} {args.reps} trace-off {runner_args} {selectors}",
                    f"/usr/bin/rvmt_exp_runner 0x{csr_base:08x} {args.trace_records} {args.reps} trace-on {runner_args} {selectors}",
                ]
            )
    raw_log = result_root(args.run_id) / "board" / "raw_uart.log"
    serial_capture(args.port, args.baud, args.duration, commands, raw_log, dry_run=args.dry_run)
    if not args.dry_run:
        parse_board_log(raw_log, args.run_id)


def clean_uart_line(line: str) -> str:
    line = UART_TIMESTAMP_RE.sub("", line).strip()
    line = re.sub(rf"(?<=[^\s])(?=(?:{UART_FIELD_KEY_PATTERN})=)", " ", line)
    for pattern, marker in UART_MARKER_PATTERNS:
        line = pattern.sub(marker, line)
    if line.startswith(">> "):
        return ""
    return line


def marker_fragment(line: str, marker: str) -> str:
    index = line.find(marker)
    if index < 0:
        return ""
    return line[index:]


def trace_payload_words(payload: str) -> list[str]:
    words: list[str] = []
    pending = ""
    for token in re.findall(r"\b[0-9a-fA-F]+\b", payload):
        if len(token) > 8 and not pending:
            if len(token) == 9:
                token = token[1:] if token[0] != "0" else token[:-1]
                words.append(token)
                continue
            if len(token) % 8 == 0:
                words.extend(token[index : index + 8] for index in range(0, len(token), 8))
                continue
            token = token[-8:]
        if len(token) == 8 and not pending:
            words.append(token)
            continue
        pending += token
        if len(pending) == 8:
            words.append(pending)
            pending = ""
        elif len(pending) > 8:
            if len(pending) == 9:
                words.append(pending[1:] if pending[0] != "0" else pending[:-1])
            pending = ""
    return words


def trace_record_index_and_payload(payload: str) -> tuple[int, str] | None:
    parts = payload.split()
    if not parts:
        return None
    index_text = parts[0]
    payload_start = 1
    if len(index_text) > 8 and index_text.isdigit():
        repaired_index = index_text[:-8]
        repaired_first_word = index_text[-8:]
        if repaired_index:
            return int(repaired_index), " ".join([repaired_first_word, *parts[1:]])
    if len(index_text) < 3 and len(parts) > 2 and parts[1].isdigit() and len(parts[1]) < 3:
        joined = index_text + parts[1]
        if joined.isdigit():
            index_text = joined
            payload_start = 2
    if not index_text.isdigit():
        return None
    return int(index_text), " ".join(parts[payload_start:])


def marker_fields(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in UART_FIELD_RE.findall(line):
        result[key] = value
    return result


def int_field(fields: dict[str, str], key: str, default: int = 0) -> int:
    raw = fields.get(key)
    if raw is None:
        return default
    match = re.match(r"-?\d+", raw)
    return int(match.group(0)) if match else default


def hex_text_field(fields: dict[str, str], key: str) -> str:
    raw = fields.get(key, "")
    if not raw:
        return ""
    try:
        return bytes.fromhex(raw).decode("utf-8", errors="replace")
    except ValueError:
        return ""


def runtime_process_map_begin(fields: dict[str, str]) -> dict[str, Any]:
    return {
        "schema": fields.get("schema", "rvmt.runtime_process_map.v1"),
        "sample_class": fields.get("class", "unknown"),
        "sample_id": fields.get("sample", "unknown"),
        "mode": fields.get("mode", "unknown"),
        "rep": int_field(fields, "rep"),
        "warmup": fields.get("warmup", "0") == "1",
        "status": "STARTED",
        "processes": [],
        "owners": {},
        "provenance": {
            "collector": "rvmt_exp_runner",
            "method": "uart_process_map_lines",
            "status": "STARTED",
        },
        "_process_by_role": {},
    }


def runtime_process(runtime_map: dict[str, Any], role: str) -> dict[str, Any]:
    by_role = runtime_map.setdefault("_process_by_role", {})
    if not isinstance(by_role, dict):
        by_role = {}
        runtime_map["_process_by_role"] = by_role
    existing = by_role.get(role)
    if isinstance(existing, dict):
        return existing
    process = {
        "role": role,
        "pid": None,
        "tgid": None,
        "comm": "",
        "exe": "",
        "maps": [],
        "provenance": {"source": "rvmt_exp_runner_uart"},
    }
    by_role[role] = process
    processes = runtime_map.setdefault("processes", [])
    if isinstance(processes, list):
        processes.append(process)
    return process


def update_runtime_process_map(runtime_map: dict[str, Any], line: str) -> None:
    marker = marker_fragment(line, "RVMT_RUNTIME_PROCESS_MAP_ENTRY")
    if marker:
        fields = marker_fields(marker)
        role = fields.get("role", "unknown")
        process = runtime_process(runtime_map, role)
        maps = process.setdefault("maps", [])
        if isinstance(maps, list):
            maps.append(
                {
                    "start": fields.get("start"),
                    "end": fields.get("end"),
                    "perms": fields.get("perms"),
                    "offset": fields.get("offset"),
                    "dev": fields.get("dev"),
                    "inode": int_field(fields, "inode", 0),
                    "path": hex_text_field(fields, "path_hex"),
                }
            )
        return

    marker = marker_fragment(line, "RVMT_RUNTIME_PROCESS_PROVENANCE")
    if marker:
        fields = marker_fields(marker)
        runtime_map["provenance"] = {
            "collector": fields.get("collector", "rvmt_exp_runner"),
            "method": fields.get("method", "unknown"),
            "proc_sample_time": fields.get("proc_sample_time", "unknown"),
            "status": fields.get("status", "UNKNOWN"),
            "warnings": hex_text_field(fields, "warnings_hex"),
        }
        return

    marker = marker_fragment(line, "RVMT_RUNTIME_PROCESS ")
    if marker:
        fields = marker_fields(marker)
        role = fields.get("role", "unknown")
        process = runtime_process(runtime_map, role)
        process.update(
            {
                "role": role,
                "pid": int_field(fields, "pid", -1),
                "tgid": int_field(fields, "tgid", -1),
                "comm": hex_text_field(fields, "comm_hex"),
                "exe": hex_text_field(fields, "exe_hex"),
                "status": fields.get("status", "UNKNOWN"),
            }
        )


def finalize_runtime_process_map(runtime_map: dict[str, Any]) -> dict[str, Any]:
    by_role = runtime_map.pop("_process_by_role", {})
    if isinstance(by_role, dict):
        runtime_map["owners"] = {role: proc for role, proc in sorted(by_role.items()) if isinstance(proc, dict)}
    target = runtime_map.get("owners", {}).get("target_child") if isinstance(runtime_map.get("owners"), dict) else None
    if isinstance(target, dict):
        runtime_map["pid"] = target.get("pid")
        runtime_map["tgid"] = target.get("tgid")
        runtime_map["comm"] = target.get("comm")
        runtime_map["exe"] = target.get("exe")
        runtime_map["maps"] = target.get("maps", [])
    else:
        runtime_map["pid"] = None
        runtime_map["tgid"] = None
        runtime_map["comm"] = ""
        runtime_map["exe"] = ""
        runtime_map["maps"] = []
    roles = set(runtime_map.get("owners", {}).keys()) if isinstance(runtime_map.get("owners"), dict) else set()
    required_roles = {"runner_parent", "target_child", "kernel", "unknown"}
    provenance = runtime_map.get("provenance") if isinstance(runtime_map.get("provenance"), dict) else {}
    status = str(runtime_map.get("status", provenance.get("status", "UNKNOWN")))
    if not required_roles <= roles or not runtime_map["maps"] or provenance.get("status") != "PASS":
        status = "BLOCKED" if status == "PASS" else status
    runtime_map["process_roles"] = sorted(roles)
    runtime_map["status"] = status
    return runtime_map


def trace_lines_to_events(lines: list[str]) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for line in lines:
        stripped = clean_uart_line(line)
        if not stripped:
            continue
        same_line_drop = re.search(r"\bRVMT_TRACE_DROP\s+(?:0x)?([0-9a-fA-F]+)\b", stripped)
        if same_line_drop:
            drop_count = int(same_line_drop.group(1), 16)
            if drop_count:
                events.append({"cycle": 0, "evt": "DROP", "value": f"0x{drop_count:x}"})
            continue
        match = re.search(r"RVMT_TRACE_RECORD\s+(.+)$", stripped)
        if not match:
            continue
        record = trace_record_index_and_payload(match.group(1))
        if record is None:
            continue
        record_index, payload = record
        word_tokens = trace_payload_words(payload)
        words = [int(item, 16) for item in word_tokens[:ARTIX7_TRACE_RAW_RECORD_WORDS]]
        if len(words) in (8, ARTIX7_TRACE_RAW_RECORD_WORDS):
            events.append(raw_trace_record_to_event(record_index, words))
        else:
            events.append(
                {
                    "cycle": 0,
                    "evt": "UNKNOWN",
                    "evt_code": None,
                    "parser_warnings": ["corrupt_raw_record_word_count"],
                    "raw_header": f"0x{words[0] & 0xffffffff:08x}" if words else None,
                    "raw_words": [f"0x{word & 0xffffffff:08x}" for word in words],
                    "record_index": record_index,
                }
            )
    return events


def parser_warning_rows(events: list[dict[str, object]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for index, event in enumerate(events):
        warnings = event.get("parser_warnings", [])
        if not isinstance(warnings, list) or not warnings:
            continue
        rows.append(
            {
                "event_index": index,
                "record_index": event.get("record_index"),
                "evt": event.get("evt"),
                "evt_code": event.get("evt_code"),
                "warnings": warnings,
                "raw_header": event.get("raw_header"),
                "raw_words": event.get("raw_words"),
            }
        )
    return rows


def write_parser_warnings(rep_dir: Path, events: list[dict[str, object]]) -> None:
    warnings = parser_warning_rows(events)
    payload = {
        "schema": "rvmt.trace.parser_warnings.v1",
        "warning_count": len(warnings),
        "unknown_event_count": sum(1 for event in events if event.get("evt") == "UNKNOWN"),
        "corrupt_record_count": sum(
            1
            for row in warnings
            if any(str(item).startswith("corrupt_") for item in row.get("warnings", []))
        ),
        "warnings": warnings,
    }
    (rep_dir / "parser_warnings.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_board_rep(
    run_id: str,
    current: dict[str, Any],
    trace_lines: list[str],
    runtime_process_map: dict[str, Any] | None = None,
) -> None:
    sample = Sample(
        sample_class=current["class"],
        sample_id=current["sample"],
        source="",
        command=[],
        expected_behavior=[],
        evidence_dir="",
    )
    mode = current["mode"]
    rep = int(current["rep"])
    is_warmup = bool(current.get("warmup"))
    rep_name = f"warmup_{rep:02d}" if is_warmup else f"rep_{rep:02d}"
    rep_dir = sample_root(run_id, sample) / "board" / mode / rep_name
    rep_dir.mkdir(parents=True, exist_ok=True)
    (rep_dir / "status.json").write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if runtime_process_map is not None:
        finalized = finalize_runtime_process_map(runtime_process_map)
        (rep_dir / "runtime_process_map.json").write_text(json.dumps(finalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if trace_lines:
        (rep_dir / "trace_raw_uart.log").write_text("\n".join(trace_lines) + "\n", encoding="utf-8")
        events = trace_lines_to_events(trace_lines)
        (rep_dir / "trace.jsonl").write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")
        write_parser_warnings(rep_dir, events)


def write_board_timing_rows(run_id: str, rows: list[dict[str, Any]]) -> None:
    by_sample: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        key = (str(row.get("class", "unknown")), str(row.get("sample", "unknown")))
        by_sample.setdefault(key, []).append(row)
    for (sample_class, sample_id), sample_rows in by_sample.items():
        sample = Sample(
            sample_class=sample_class,
            sample_id=sample_id,
            source="",
            command=[],
            expected_behavior=[],
            evidence_dir="",
        )
        timing_path = sample_root(run_id, sample) / "board" / "timings.jsonl"
        timing_path.parent.mkdir(parents=True, exist_ok=True)
        normalized = []
        for row in sample_rows:
            normalized.append(
                {
                    "sample_class": sample_class,
                    "sample": sample_id,
                    "mode": row.get("mode"),
                    "rep": row.get("rep"),
                    "order_index": row.get("order_index"),
                    "warmup": bool(row.get("warmup")),
                    "status": row.get("status"),
                    "exit_code": row.get("exit_code"),
                    "runtime_ns": row.get("runtime_ns"),
                    "trace_count": row.get("trace_count"),
                    "drop": row.get("drop"),
                }
            )
        timing_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in normalized), encoding="utf-8")


def parse_board_log(raw_log: Path, run_id: str) -> None:
    current: dict[str, Any] | None = None
    runtime_process_map: dict[str, Any] | None = None
    capturing_trace = False
    trace_lines: list[str] = []
    timing_rows: list[dict[str, Any]] = []
    for raw_line in raw_log.read_text(encoding="utf-8", errors="replace").splitlines():
        line = clean_uart_line(raw_line)
        if not line:
            continue
        marker = marker_fragment(line, "RVMT_EXP_REP_BEGIN")
        if marker:
            fields = marker_fields(marker)
            current = {
                "class": fields.get("class", "unknown"),
                "sample": fields.get("sample", "unknown"),
                "mode": fields.get("mode", "unknown"),
                "rep": int_field(fields, "rep"),
                "order_index": int_field(fields, "order_index"),
                "warmup": fields.get("warmup", "0") == "1",
                "status": "STARTED",
            }
            trace_lines = []
            runtime_process_map = None
            capturing_trace = False
            continue
        marker = marker_fragment(line, "RVMT_RUNTIME_PROCESS_MAP_BEGIN")
        if current is not None and marker:
            runtime_process_map = runtime_process_map_begin(marker_fields(marker))
            continue
        if current is not None and runtime_process_map is not None and marker_fragment(line, "RVMT_RUNTIME_PROCESS_MAP_END"):
            fields = marker_fields(line)
            runtime_process_map["status"] = fields.get("status", runtime_process_map.get("status", "UNKNOWN"))
            current["runtime_process_map_status"] = runtime_process_map["status"]
            continue
        if current is not None and runtime_process_map is not None and marker_fragment(line, "RVMT_RUNTIME_PROCESS"):
            update_runtime_process_map(runtime_process_map, line)
            continue
        marker = marker_fragment(line, "RVMT_EXP_REP_RESULT")
        if current is not None and marker:
            fields = marker_fields(marker)
            current.update(
                {
                    "status": "PASS" if fields.get("exit") == "0" else "FAIL",
                    "exit_code": int_field(fields, "exit", 127),
                    "runtime_ns": int_field(fields, "runtime_ns"),
                    "trace_count": int_field(fields, "trace_count"),
                    "drop": int_field(fields, "drop"),
                    "order_index": int_field(fields, "order_index", int(current.get("order_index", 0))),
                    "warmup": fields.get("warmup", "1" if current.get("warmup") else "0") == "1",
                }
            )
            timing_rows.append(dict(current))
            continue
        if current is not None and marker_fragment(line, "RVMT_TRACE_DUMP_BEGIN"):
            capturing_trace = True
            trace_lines.append(line)
            continue
        if current is not None and marker_fragment(line, "RVMT_TRACE_DUMP_END"):
            trace_lines.append(line)
            capturing_trace = False
            continue
        if current is not None and capturing_trace:
            trace_lines.append(line)
            continue
        if current is not None and marker_fragment(line, "RVMT_EXP_REP_END"):
            write_board_rep(run_id, current, trace_lines, runtime_process_map)
            current = None
            trace_lines = []
            runtime_process_map = None
            capturing_trace = False
    if current is not None:
        current["status"] = "FAIL"
        current["error"] = "missing RVMT_EXP_REP_END"
        write_board_rep(run_id, current, trace_lines, runtime_process_map)
        timing_rows.append(dict(current))
    write_board_timing_rows(run_id, timing_rows)


def parse_strace_names(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    syscall_re = re.compile(r"(?:^\s*\d+\s+)?([A-Za-z_][A-Za-z0-9_]*)\(")
    ret_re = re.compile(r"\)\s+=\s+(-?[0-9]+)")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = syscall_re.search(line)
        if not match:
            continue
        name = match.group(1)
        if name in {"strace", "qemu"}:
            continue
        ret_match = ret_re.search(line)
        rows.append({"name": name, "return_sign": "neg" if ret_match and ret_match.group(1).startswith("-") else "nonneg", "text": line})
    return rows


def semantic_syscalls(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    semantic = load_json(path)
    rows = semantic.get("syscall_sequence", [])
    return [row for row in rows if isinstance(row, dict)]


def lcs_len(left: list[str], right: list[str]) -> int:
    previous = [0] * (len(right) + 1)
    for item in left:
        current = [0]
        for j, other in enumerate(right, start=1):
            current.append(previous[j - 1] + 1 if item == other else max(previous[j], current[-1]))
        previous = current
    return previous[-1]


def edit_distance(left: list[str], right: list[str]) -> int:
    previous = list(range(len(right) + 1))
    for i, item in enumerate(left, start=1):
        current = [i]
        for j, other in enumerate(right, start=1):
            current.append(min(previous[j] + 1, current[-1] + 1, previous[j - 1] + (0 if item == other else 1)))
        previous = current
    return previous[-1]


def return_sign(value: Any) -> str:
    if value is None:
        return "unknown"
    try:
        number = int(str(value), 0)
    except ValueError:
        return "unknown"
    if number < 0 or ((1 << 64) - 4095 <= number <= (1 << 64) - 1) or ((1 << 32) - 4095 <= number <= (1 << 32) - 1):
        return "neg"
    return "nonneg"


def align_trace_to_groundtruth(
    gt_path: Path,
    semantic_path: Path,
    out_dir: Path,
    *,
    trace_path: Path | None = None,
    status_path: Path | None = None,
) -> dict[str, Any]:
    gt = parse_strace_names(gt_path)
    sem = semantic_syscalls(semantic_path)
    gt_names = [row["name"] for row in gt]
    sem_names = [str(row.get("name")) for row in sem]
    gt_set = set(gt_names)
    sem_set = set(sem_names)
    tp = len(gt_set & sem_set)
    precision = tp / len(sem_set) if sem_set else 0.0
    recall = tp / len(gt_set) if gt_set else 0.0
    ordered = lcs_len(gt_names, sem_names)
    edit = edit_distance(gt_names, sem_names)
    paired = min(len(gt), len(sem))
    paired_returns = sum(1 for row in sem if row.get("return_value") is not None)
    sign_matches = 0
    arg_values = 0
    arg_matches = 0
    for index in range(paired):
        if return_sign(sem[index].get("return_value")) == gt[index].get("return_sign"):
            sign_matches += 1
        gt_text = str(gt[index].get("text", "")).lower()
        args = sem[index].get("args")
        if not isinstance(args, dict):
            continue
        for value in args.values():
            if value in (None, ""):
                continue
            arg_values += 1
            tokens = {str(value).lower()}
            try:
                number = int(str(value), 0)
            except ValueError:
                number = None
            if number is not None:
                tokens.add(str(number))
                tokens.add(hex(number))
            if any(token in gt_text for token in tokens if token):
                arg_matches += 1
    args_present = sum(1 for row in sem if isinstance(row.get("args"), dict) and any(row["args"].values()))
    captured_events = trace_event_count(trace_path) if trace_path is not None else None
    drop_count = None
    if status_path is not None and status_path.exists():
        drop_count = int(load_json(status_path).get("drop", 0) or 0)
    drop_rate = (
        drop_count / (drop_count + captured_events)
        if drop_count is not None and captured_events is not None and (drop_count + captured_events) > 0
        else None
    )
    result = {
        "schema": "rvmt.35t.alignment.v1",
        "groundtruth": repo_rel(gt_path),
        "semantic": repo_rel(semantic_path),
        "trace": repo_rel(trace_path) if trace_path is not None else None,
        "groundtruth_syscalls": len(gt),
        "semantic_syscalls": len(sem),
        "syscall_family_precision": precision,
        "syscall_family_recall": recall,
        "ordered_lcs": ordered,
        "ordered_lcs_ratio": ordered / len(gt_names) if gt_names else 0.0,
        "edit_distance": edit,
        "paired_return_ratio": paired_returns / len(sem) if sem else 0.0,
        "return_sign_match_ratio": sign_matches / paired if paired else 0.0,
        "argument_availability_ratio": args_present / len(sem) if sem else 0.0,
        "argument_accuracy_ratio": (arg_matches / arg_values) if arg_values else None,
        "argument_accuracy_method": "best-effort scalar-token overlap with QEMU -strace text",
        "captured_events": captured_events,
        "drop_count": drop_count,
        "drop_rate": drop_rate,
    }
    result["family_set"] = {"precision": precision, "recall": recall, "true_positive_families": sorted(gt_set & sem_set)}
    result["ordered_sequence"] = {"lcs": ordered, "lcs_ratio": result["ordered_lcs_ratio"], "edit_distance": edit}
    result["paired_semantics"] = {
        "paired_return_ratio": result["paired_return_ratio"],
        "return_sign_match_ratio": result["return_sign_match_ratio"],
        "argument_availability_ratio": result["argument_availability_ratio"],
        "argument_accuracy_ratio": result["argument_accuracy_ratio"],
    }
    result["drop_aware"] = {"captured_events": captured_events, "drop_count": drop_count, "drop_rate": drop_rate}
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "alignment.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def run_analysis_command(cmd: list[str], log_path: Path, *, dry_run: bool) -> int:
    return run_command(cmd, dry_run=dry_run, log_path=log_path)


def board_runtime_elf(sample: Sample) -> Path:
    if sample.source.endswith("rvmt_benign_workload.c"):
        name = "rvmt_benign_workload"
    elif sample.command:
        name = Path(sample.command[0]).name
    else:
        name = sample.sample_id
    if not name:
        name = sample.sample_id
    return ROOT / ROOTFS_EXP_BIN_DIR / name


def code_map_candidates(sample: Sample, build_dir: Path) -> list[dict[str, str | Path | None]]:
    candidates: list[dict[str, str | Path | None]] = []
    board_elf = board_runtime_elf(sample)
    if board_elf.exists():
        candidates.append(
            {
                "elf": board_elf,
                "binary_role": "board_rootfs_overlay",
                "runtime_path": f"/usr/bin/{board_elf.name}",
            }
        )
    groundtruth_elf = build_dir / f"{sample.sample_id}.riscv"
    if groundtruth_elf.exists():
        candidates.append(
            {
                "elf": groundtruth_elf,
                "binary_role": "groundtruth_qemu_static",
                "runtime_path": None,
            }
        )
    return candidates


def refresh_decoded_trace(rep_dir: Path) -> None:
    raw = rep_dir / "trace_raw_uart.log"
    if not raw.exists():
        return
    events = trace_lines_to_events(raw.read_text(encoding="utf-8", errors="replace").splitlines())
    (rep_dir / "trace.jsonl").write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")
    write_parser_warnings(rep_dir, events)


def ensure_code_map(args: argparse.Namespace, sample: Sample) -> Path | None:
    build_dir = sample_root(args.run_id, sample) / "build"
    code_map = build_dir / f"{sample.sample_id}.code_map.json"
    candidates = code_map_candidates(sample, build_dir)
    if args.dry_run:
        display = candidates[0]["elf"] if candidates else build_dir / f"{sample.sample_id}.riscv"
        print(f"+ build code map {display} -> {code_map}")
        return code_map
    if not candidates:
        return None
    selected = candidates[0]
    elf = selected["elf"]
    if not isinstance(elf, Path):
        return None
    log_path = build_dir / "build_code_map.log"
    cmd = [
        sys.executable,
        "tools/build_code_map.py",
        "--elf",
        str(elf),
        "--sample-id",
        sample.sample_id,
        "--source",
        sample.source,
        "--binary-role",
        str(selected["binary_role"]),
        "--out-dir",
        str(build_dir),
    ]
    runtime_path = selected.get("runtime_path")
    if runtime_path:
        cmd.extend(["--runtime-path", str(runtime_path)])
    code = run_analysis_command(cmd, log_path, dry_run=False)
    return code_map if code == 0 and code_map.exists() else None


def stage_analyze(args: argparse.Namespace, samples: list[Sample]) -> None:
    for sample in samples:
        sample_dir = sample_root(args.run_id, sample)
        code_map = ensure_code_map(args, sample)
        gt_strace = sample_dir / "groundtruth" / "qemu_strace.0.strace.log"
        rep_dirs = sorted((sample_dir / "board" / TRACE_ON).glob("rep_*"))
        if args.dry_run and not rep_dirs:
            rep_dirs = [sample_dir / "board" / TRACE_ON / f"rep_{rep:02d}" for rep in range(args.reps)]
        for rep_dir in rep_dirs:
            if not args.dry_run:
                refresh_decoded_trace(rep_dir)
            trace = rep_dir / "trace.jsonl"
            if not trace.exists() and not args.dry_run:
                continue
            runtime_process_map = rep_dir / "runtime_process_map.json"
            semantic_dir = rep_dir / "behavior_recovery"
            audit_dir = rep_dir / "behavior_audit"
            lightweight_dir = rep_dir / "lightweight"
            align_dir = rep_dir / "alignment"
            trace_code_dir = rep_dir / "trace_code_map"
            failures = []
            if code_map is None:
                failures.append({"stage": "build_code_map", "error": "missing code map"})
            else:
                join_cmd = [
                    sys.executable,
                    "tools/join_trace_code_map.py",
                    "--trace",
                    str(trace),
                    "--code-map",
                    str(code_map),
                    "--out",
                    str(trace_code_dir / "trace.code_map.jsonl"),
                    "--summary-out",
                    str(trace_code_dir / "trace_code_map_summary.json"),
                ]
                if runtime_process_map.exists() or args.dry_run:
                    join_cmd.extend(["--runtime-process-map", str(runtime_process_map)])
                code = run_analysis_command(
                    join_cmd,
                    rep_dir / "join_trace_code_map.log",
                    dry_run=args.dry_run,
                )
                if code != 0:
                    failures.append({"stage": "join_trace_code_map", "exit_code": code})
            recover_cmd = [sys.executable, "tools/recover_behavior.py", "--trace", str(trace), "--out-dir", str(semantic_dir)]
            if code_map is not None:
                recover_cmd.extend(["--code-map", str(code_map)])
            if runtime_process_map.exists() or args.dry_run:
                recover_cmd.extend(["--runtime-process-map", str(runtime_process_map)])
            code = run_analysis_command(
                recover_cmd,
                rep_dir / "recover_behavior.log",
                dry_run=args.dry_run,
            )
            if code != 0:
                failures.append({"stage": "recover_behavior", "exit_code": code})
            code = run_analysis_command(
                [
                    sys.executable,
                    "tools/analyze_trace_lightweight.py",
                    "--trace",
                    str(trace),
                    "--out-dir",
                    str(lightweight_dir),
                    "--profile",
                    "board_minimal",
                ],
                rep_dir / "lightweight.log",
                dry_run=args.dry_run,
            )
            if code != 0:
                failures.append({"stage": "lightweight", "exit_code": code})
            audit_cmd = [
                sys.executable,
                "tools/audit_behavior.py",
                "--semantic",
                str(semantic_dir / "semantic_events.json"),
                "--graph",
                str(semantic_dir / "behavior_graph.json"),
                "--rules",
                str(ROOT / RULES_PATH),
                "--out-dir",
                str(audit_dir),
            ]
            if sample.sample_class == "malware_like_synthetic":
                audit_cmd.extend(["--manifest", str(ROOT / MALWARE_MANIFEST), "--sample-id", sample.sample_id])
            code = run_analysis_command(audit_cmd, rep_dir / "audit_behavior.log", dry_run=args.dry_run)
            if code != 0:
                failures.append({"stage": "audit_behavior", "exit_code": code})
            if args.dry_run:
                print(f"+ align {gt_strace} {semantic_dir / 'semantic_events.json'} -> {align_dir / 'alignment.json'}")
            else:
                try:
                    align_trace_to_groundtruth(
                        gt_strace,
                        semantic_dir / "semantic_events.json",
                        align_dir,
                        trace_path=trace,
                        status_path=rep_dir / "status.json",
                    )
                except Exception as exc:  # noqa: BLE001 - keep batch execution moving and record the failed rep.
                    failures.append({"stage": "alignment", "error": str(exc)})
                status = {"status": "PASS" if not failures else "FAIL", "failures": failures}
                (rep_dir / "analysis_status.json").write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    debug_cmd = [sys.executable, "tools/debug_rule_evidence.py", "--run-id", args.run_id]
    for sample in samples:
        debug_cmd.extend(["--sample", sample.sample_id])
    run_analysis_command(
        debug_cmd,
        aggregate_root(args.run_id) / "debug_rule_evidence.log",
        dry_run=args.dry_run,
    )


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def median(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def summarize_numbers(values: list[float]) -> dict[str, float | None]:
    sorted_values = sorted(values)
    if len(sorted_values) >= 4:
        lower = sorted_values[: len(sorted_values) // 2]
        upper = sorted_values[(len(sorted_values) + 1) // 2 :]
        iqr = statistics.median(upper) - statistics.median(lower)
    else:
        iqr = None
    return {
        "median": median(values),
        "min": min(values) if values else None,
        "max": max(values) if values else None,
        "spread": (max(values) - min(values)) if values else None,
        "iqr": iqr,
    }


def trace_event_count(path: Path) -> int:
    return len(load_jsonl(path))


def trace_event_counts(path: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in load_jsonl(path):
        evt = str(event.get("evt", "NONE"))
        counts[evt] = counts.get(evt, 0) + 1
    return dict(sorted(counts.items()))


def collect_metrics(run_id: str, samples: list[Sample]) -> dict[str, Any]:
    run_config = load_json(result_root(run_id) / "run_config.json") if (result_root(run_id) / "run_config.json").exists() else {}
    trace_records = int(run_config["trace_records"]) if run_config.get("trace_records") is not None else None
    rows: list[dict[str, Any]] = []
    confusion = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    rule_confusion = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for sample in samples:
        sample_dir = sample_root(run_id, sample)
        gt_timings = load_jsonl(sample_dir / "groundtruth" / "timings.jsonl")
        gt_by_baseline: dict[str, list[float]] = {}
        for row in gt_timings:
            gt_by_baseline.setdefault(str(row.get("baseline")), []).append(float(row.get("runtime_ns", 0)))

        board_by_mode: dict[str, list[dict[str, Any]]] = {TRACE_OFF: [], TRACE_ON: []}
        for mode in (TRACE_OFF, TRACE_ON):
            for status_path in sorted((sample_dir / "board" / mode).glob("rep_*/status.json")):
                board_by_mode[mode].append(load_json(status_path))

        audit_matches = False
        expected_matched = False
        audit_paths = sorted((sample_dir / "board" / TRACE_ON).glob("rep_*/behavior_audit/behavior_audit.json"))
        expected_rules = set(sample.expected_behavior) if sample.sample_class == "malware_like_synthetic" else set()
        for audit_path in audit_paths:
            audit = load_json(audit_path)
            matches = audit.get("matches", [])
            if isinstance(matches, list):
                if any(isinstance(item, dict) and item.get("matched") for item in matches):
                    audit_matches = True
                for item in matches:
                    if not isinstance(item, dict):
                        continue
                    expected_rule = str(item.get("rule")) in expected_rules
                    matched_rule = bool(item.get("matched"))
                    if expected_rule and matched_rule:
                        rule_confusion["tp"] += 1
                    elif expected_rule and not matched_rule:
                        rule_confusion["fn"] += 1
                    elif not expected_rule and matched_rule:
                        rule_confusion["fp"] += 1
                    else:
                        rule_confusion["tn"] += 1
            if audit.get("all_expected_matched"):
                expected_matched = True

        if audit_paths:
            if sample.sample_class == "malware_like_synthetic":
                if expected_matched:
                    confusion["tp"] += 1
                else:
                    confusion["fn"] += 1
            else:
                if audit_matches:
                    confusion["fp"] += 1
                else:
                    confusion["tn"] += 1

        trace_on_runtime = [float(row.get("runtime_ns", 0)) for row in board_by_mode[TRACE_ON] if row.get("status") == "PASS"]
        trace_off_runtime = [float(row.get("runtime_ns", 0)) for row in board_by_mode[TRACE_OFF] if row.get("status") == "PASS"]
        trace_events: list[float] = []
        trace_bytes: list[float] = []
        compact_bytes: list[float] = []
        events_per_sec: list[float] = []
        jsonl_bytes_per_sec: list[float] = []
        compact_bytes_per_sec: list[float] = []
        drop_rates: list[float] = []
        captured_cap_reps: list[str] = []
        event_count_totals: dict[str, int] = {}
        drops = [float(row.get("drop", 0)) for row in board_by_mode[TRACE_ON]]
        for rep_dir in sorted((sample_dir / "board" / TRACE_ON).glob("rep_*")):
            status = load_json(rep_dir / "status.json") if (rep_dir / "status.json").exists() else {}
            runtime_s = float(status.get("runtime_ns", 0)) / 1_000_000_000.0
            trace_path = rep_dir / "trace.jsonl"
            events = float(trace_event_count(trace_path))
            if trace_records is not None and int(events) == trace_records:
                captured_cap_reps.append(rep_dir.name)
            for evt, count in trace_event_counts(trace_path).items():
                event_count_totals[evt] = event_count_totals.get(evt, 0) + count
            jsonl_bytes = float(trace_path.stat().st_size) if trace_path.exists() else 0.0
            lightweight = rep_dir / "lightweight" / "lightweight_trace_analysis.json"
            compact = 0.0
            if lightweight.exists():
                compact = float(load_json(lightweight).get("bytes", {}).get("compact_jsonl", 0))
            drop_count = float(status.get("drop", 0))
            trace_events.append(events)
            trace_bytes.append(jsonl_bytes)
            compact_bytes.append(compact)
            if runtime_s > 0:
                events_per_sec.append(events / runtime_s)
                jsonl_bytes_per_sec.append(jsonl_bytes / runtime_s)
                compact_bytes_per_sec.append(compact / runtime_s)
            drop_rates.append(drop_count / (drop_count + events) if (drop_count + events) > 0 else 0.0)
        alignments = [load_json(path) for path in sorted((sample_dir / "board" / TRACE_ON).glob("rep_*/alignment/alignment.json"))]
        alignment_precision = [float(row.get("syscall_family_precision", 0)) for row in alignments]
        alignment_recall = [float(row.get("syscall_family_recall", 0)) for row in alignments]
        alignment_arg_accuracy = [float(row["argument_accuracy_ratio"]) for row in alignments if row.get("argument_accuracy_ratio") is not None]
        rows.append(
            {
                "sample_class": sample.sample_class,
                "sample_id": sample.sample_id,
                "groundtruth": {baseline: summarize_numbers(values) for baseline, values in sorted(gt_by_baseline.items())},
                "board_trace_on_runtime_ns": summarize_numbers(trace_on_runtime),
                "board_trace_off_runtime_ns": summarize_numbers(trace_off_runtime),
                "trace_events": summarize_numbers([float(value) for value in trace_events]),
                "trace_jsonl_bytes": summarize_numbers([float(value) for value in trace_bytes]),
                "trace_compact_bytes": summarize_numbers([float(value) for value in compact_bytes]),
                "trace_events_per_sec": summarize_numbers(events_per_sec),
                "trace_jsonl_bytes_per_sec": summarize_numbers(jsonl_bytes_per_sec),
                "trace_compact_bytes_per_sec": summarize_numbers(compact_bytes_per_sec),
                "drop_count": summarize_numbers(drops),
                "drop_rate": summarize_numbers(drop_rates),
                "captured_cap_reps": captured_cap_reps,
                "trace_on_rep_count": len(list((sample_dir / "board" / TRACE_ON).glob("rep_*"))),
                "event_counts": dict(sorted(event_count_totals.items())),
                "alignment_precision": summarize_numbers(alignment_precision),
                "alignment_recall": summarize_numbers(alignment_recall),
                "alignment_argument_accuracy": summarize_numbers(alignment_arg_accuracy),
                "expected_behavior_matched": expected_matched,
                "any_behavior_rule_matched": audit_matches,
                "status": "PASS" if len(trace_on_runtime) > 0 and len(trace_off_runtime) > 0 else "INCOMPLETE",
            }
        )
    return {"schema": "rvmt.35t.metrics.v1", "samples": rows, "confusion": confusion, "rule_confusion": rule_confusion}


def write_reports(run_id: str, samples: list[Sample]) -> None:
    aggregate = aggregate_root(run_id)
    aggregate.mkdir(parents=True, exist_ok=True)
    metrics = collect_metrics(run_id, samples)
    (aggregate / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (aggregate / "metrics.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "class",
                "sample",
                "status",
                "trace_on_median_ns",
                "trace_off_median_ns",
                "events_median",
                "jsonl_bytes_median",
                "compact_bytes_median",
                "events_per_sec_median",
                "jsonl_bytes_per_sec_median",
                "drop_median",
                "drop_rate_median",
                "precision_median",
                "recall_median",
                "argument_accuracy_median",
            ]
        )
        for row in metrics["samples"]:
            writer.writerow(
                [
                    row["sample_class"],
                    row["sample_id"],
                    row["status"],
                    row["board_trace_on_runtime_ns"]["median"],
                    row["board_trace_off_runtime_ns"]["median"],
                    row["trace_events"]["median"],
                    row["trace_jsonl_bytes"]["median"],
                    row["trace_compact_bytes"]["median"],
                    row["trace_events_per_sec"]["median"],
                    row["trace_jsonl_bytes_per_sec"]["median"],
                    row["drop_count"]["median"],
                    row["drop_rate"]["median"],
                    row["alignment_precision"]["median"],
                    row["alignment_recall"]["median"],
                    row["alignment_argument_accuracy"]["median"],
                ]
            )
    confusion = metrics["confusion"]
    rule_confusion = metrics["rule_confusion"]
    (aggregate / "accuracy_report.md").write_text(
        "\n".join(
            [
                "# 35T Malware-like Behavior Audit Accuracy",
                "",
                "This report measures synthetic malware-like behavior audit accuracy. It is not a real malware detection claim.",
                "",
                "## Sample-level confusion matrix",
                "",
                f"- TP: {confusion['tp']}",
                f"- FP: {confusion['fp']}",
                f"- TN: {confusion['tn']}",
                f"- FN: {confusion['fn']}",
                "",
                "## Rule-level confusion matrix",
                "",
                f"- TP: {rule_confusion['tp']}",
                f"- FP: {rule_confusion['fp']}",
                f"- TN: {rule_confusion['tn']}",
                f"- FN: {rule_confusion['fn']}",
                "",
            ]
        ),
        encoding="utf-8",
        newline="\n",
    )
    (aggregate / "overhead_report.md").write_text(render_overhead_report(metrics), encoding="utf-8", newline="\n")
    run_config = load_json(result_root(run_id) / "run_config.json") if (result_root(run_id) / "run_config.json").exists() else {}
    (aggregate / "bandwidth_report.md").write_text(render_bandwidth_report(metrics, run_config), encoding="utf-8", newline="\n")
    (aggregate / "artifact_index.md").write_text(render_artifact_index(run_id, samples), encoding="utf-8", newline="\n")


def render_overhead_report(metrics: dict[str, Any]) -> str:
    lines = [
        "# 35T Runtime And Perturbation Report",
        "",
        "| Sample | Trace-off median ns | Trace-off min/max ns | Trace-off spread ns | Trace-off IQR ns | Trace-on median ns | Trace-on min/max ns | Trace-on spread ns | Trace-on IQR ns | Measured trace ratio | Host native ns | Host strace ratio | QEMU native ns | QEMU strace ratio |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in metrics["samples"]:
        off_stats = row["board_trace_off_runtime_ns"]
        on_stats = row["board_trace_on_runtime_ns"]
        off = off_stats["median"]
        on = on_stats["median"]
        ratio = (on / off) if on is not None and off not in (None, 0) else None
        groundtruth = row.get("groundtruth", {})
        host_native = groundtruth.get("host_native", {}).get("median")
        host_strace = groundtruth.get("host_strace", {}).get("median")
        qemu_native = groundtruth.get("qemu_native", {}).get("median")
        qemu_strace = groundtruth.get("qemu_strace", {}).get("median")
        host_ratio = (host_strace / host_native) if host_strace is not None and host_native not in (None, 0) else None
        qemu_ratio = (qemu_strace / qemu_native) if qemu_strace is not None and qemu_native not in (None, 0) else None
        lines.append(
            f"| `{row['sample_id']}` | {off} | {off_stats['min']} / {off_stats['max']} | {off_stats['spread']} | {off_stats.get('iqr')} | "
            f"{on} | {on_stats['min']} / {on_stats['max']} | {on_stats['spread']} | {on_stats.get('iqr')} | {ratio if ratio is not None else 'n/a'} | "
            f"{host_native} | {host_ratio if host_ratio is not None else 'n/a'} | "
            f"{qemu_native} | {qemu_ratio if qemu_ratio is not None else 'n/a'} |"
        )
    lines.extend(
        [
            "",
            "Trace-off and trace-on are both executed on the 35T trace-capable image; trace-off disables capture through the trace CSR.",
            "Ratios below 1.0 are reported only as measured ratios, not as acceleration claims.",
            "",
        ]
    )
    return "\n".join(lines)


def render_bandwidth_report(metrics: dict[str, Any], run_config: dict[str, Any] | None = None) -> str:
    run_config = run_config or {}
    trace_records = run_config.get("trace_records")
    capped_samples = [
        row["sample_id"]
        for row in metrics["samples"]
        if trace_records is not None and row.get("captured_cap_reps")
    ]
    worst = max(
        (row for row in metrics["samples"] if row["drop_rate"]["median"] is not None),
        key=lambda row: row["drop_rate"]["median"],
        default=None,
    )
    lines = [
        "# 35T Trace Bandwidth And Drop Report",
        "",
        "| Sample | Events median | Cap hits | JSONL bytes median | Compact bytes median | Events/sec median | JSONL bytes/sec median | DROP median | Drop rate median | Align recall median | Event counts |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in metrics["samples"]:
        counts = ", ".join(f"{key}:{value}" for key, value in row.get("event_counts", {}).items()) or "none"
        lines.append(
            f"| `{row['sample_id']}` | {row['trace_events']['median']} | {len(row.get('captured_cap_reps', []))} | {row['trace_jsonl_bytes']['median']} | "
            f"{row['trace_compact_bytes']['median']} | {row['trace_events_per_sec']['median']} | "
            f"{row['trace_jsonl_bytes_per_sec']['median']} | {row['drop_count']['median']} | {row['drop_rate']['median']} | "
            f"{row['alignment_recall']['median']} | {counts} |"
        )
    lines.extend(
        [
            "",
            f"- Trace records cap: `{trace_records if trace_records is not None else 'not recorded'}`.",
            f"- Samples with `captured_events == trace_records`: {', '.join(f'`{item}`' for item in capped_samples) if capped_samples else 'none'}.",
            (
                f"- Worst median DROP sample: `{worst['sample_id']}` at {worst['drop_rate']['median']}."
                if worst is not None
                else "- Worst median DROP sample: n/a."
            ),
            "- DROP rate is computed as `drop / (drop + captured_events)` for each trace-on rep.",
            "- Current bandwidth is not sufficient evidence for mature semantic recovery unless the gate report shows low DROP and adequate alignment recall.",
            "",
            "This report covers captured trace volume and DROP accounting, not high-bandwidth streaming capacity.",
            "",
        ]
    )
    return "\n".join(lines)


def render_artifact_index(run_id: str, samples: list[Sample]) -> str:
    lines = ["# 35T Experiment Artifact Index", "", f"Run ID: `{run_id}`", ""]
    for sample in samples:
        root = repo_rel(sample_root(run_id, sample))
        lines.append(f"- `{sample.sample_class}/{sample.sample_id}`: `{root}`")
    lines.append("")
    return "\n".join(lines)


def stage_report(args: argparse.Namespace, samples: list[Sample]) -> None:
    if args.dry_run:
        print(f"+ write aggregate reports under {aggregate_root(args.run_id)}")
        return
    write_reports(args.run_id, samples)


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        strace = root / "qemu.strace"
        semantic = root / "semantic.json"
        out = root / "align"
        strace.write_text("123 openat(AT_FDCWD, \"x\", O_RDONLY) = 3\n123 read(3, \"a\", 1) = 1\n123 close(3) = 0\n", encoding="utf-8")
        semantic.write_text(
            json.dumps(
                {
                    "syscall_sequence": [
                        {"name": "openat", "return_value": "0x3", "args": {"a0": "0x0"}},
                        {"name": "read", "return_value": "0x1", "args": {"a0": "0x3"}},
                        {"name": "close", "return_value": "0x0", "args": {"a0": "0x3"}},
                    ]
                }
            ),
            encoding="utf-8",
        )
        alignment = align_trace_to_groundtruth(strace, semantic, out)
        if alignment["syscall_family_precision"] != 1.0 or alignment["ordered_lcs"] != 3:
            print("[FAIL] alignment self-test failed", file=sys.stderr)
            return 1
        repaired_words = trace_payload_words("00000001 c0000ffff 000000020")
        if repaired_words != ["00000001", "0000ffff", "00000002"]:
            print("[FAIL] trace payload word repair self-test failed", file=sys.stderr)
            return 1
        split_index = trace_record_index_and_payload("1 46 00000004")
        if split_index != (146, "00000004"):
            print("[FAIL] trace record index repair self-test failed", file=sys.stderr)
            return 1

        raw = root / "raw_uart.log"
        raw.write_text(
            "\n".join(
                [
                    "RVMT_EXP_REP_BEGIN class=benign sample=hello mode=trace-on rep=0",
                    "RVMT_RUNTIME_PROCESS_MAP_BEGIN schema=rvmt.runtime_process_map.v1 class=benign sample=hello mode=trace-on rep=0 warmup=0",
                    "RVMT_RUNTIME_PROCESS role=runner_parent pid=10 tgid=10 status=PASS comm_hex=72766d745f6578705f72756e6e6572 exe_hex=2f7573722f62696e2f72766d745f6578705f72756e6e6572",
                    "RVMT_RUNTIME_PROCESS_MAP_ENTRY role=runner_parent start=0x00010000 end=0x00020000 perms=r-xp offset=0x00000000 dev=00:00 inode=1 path_hex=2f7573722f62696e2f72766d745f6578705f72756e6e6572",
                    "RVMT_RUNTIME_PROCESS role=target_child pid=11 tgid=11 status=PASS comm_hex=72766d745f62656e69676e5f776f726b6c6f6164 exe_hex=2f7573722f62696e2f72766d745f62656e69676e5f776f726b6c6f6164",
                    "RVMT_RUNTIME_PROCESS_MAP_ENTRY role=target_child start=0x00010000 end=0x00020000 perms=r-xp offset=0x00000000 dev=00:00 inode=2 path_hex=2f7573722f62696e2f72766d745f62656e69676e5f776f726b6c6f6164",
                    "RVMT_RUNTIME_PROCESS role=kernel pid=0 tgid=0 status=PASS comm_hex=6b65726e656c exe_hex=",
                    "RVMT_RUNTIME_PROCESS role=unknown pid=-1 tgid=-1 status=PASS comm_hex=756e6b6e6f776e exe_hex=",
                    "RVMT_RUNTIME_PROCESS_PROVENANCE collector=rvmt_exp_runner method=ptrace_exec_stop_procfs_snapshot proc_sample_time=post_exec_pre_detach status=PASS warnings_hex=",
                    "RVMT_RUNTIME_PROCESS_MAP_END status=PASS",
                    "command echo RVMT_EXP_REP_RESULT class=benign sample=hello mode=trace-on rep=0 exit=0 runtime_ns=10 trace_count=2 drop=0",
                    "RVMT_TRACE_DUMP_BEGIN",
                    "RVMT_TRACE_RECORD 0 00000004 00000001 00001000 00000073 00000000 00000000 00000000 00000000 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000040",
                    "[000001.000] RVMT_TRACE_RE[000001.100] CORD 1 00000004 00000001 00001000 00000073 00000000 00000000 00000000 00000000 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000[000001.200] 040",
                    "RVMT_TRACE_DUMP_END",
                    "prompt-noise RVMT_EXP_REP_END class=benign sample=hello mode=trace-on rep=0",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        old_root = result_root("self-test")
        if old_root.exists():
            shutil.rmtree(old_root)
        parse_board_log(raw, "self-test")
        trace = result_root("self-test") / "samples" / "benign" / "hello" / "board" / TRACE_ON / "rep_00" / "trace.jsonl"
        if not trace.exists() or trace_event_count(trace) != 2:
            print("[FAIL] board log parser self-test failed", file=sys.stderr)
            return 1
        runtime_map = trace.parent / "runtime_process_map.json"
        if not runtime_map.exists() or load_json(runtime_map).get("schema") != "rvmt.runtime_process_map.v1":
            print("[FAIL] board log parser missed runtime process map", file=sys.stderr)
            return 1
        sample = Sample("benign", "hello", "board/artix7_35t/linux/rvmt_benign_workload.c", ["./rvmt_benign_workload", "hello"], [], "01_hello")
        sample_dir = sample_root("self-test", sample)
        gt_dir = sample_dir / "groundtruth"
        gt_dir.mkdir(parents=True, exist_ok=True)
        (gt_dir / "timings.jsonl").write_text(
            "".join(json.dumps({"baseline": baseline, "rep": 0, "exit_code": 0, "runtime_ns": 10}) + "\n" for baseline in REQUIRED_BASELINES),
            encoding="utf-8",
        )
        (gt_dir / "status.json").write_text('{"status":"PASS"}\n', encoding="utf-8")
        (gt_dir / "optional_baselines.json").write_text(
            json.dumps({baseline: {"status": "BLOCKED", "reason": "self-test"} for baseline in OPTIONAL_BASELINES}) + "\n",
            encoding="utf-8",
        )
        off_dir = sample_dir / "board" / TRACE_OFF / "rep_00"
        off_dir.mkdir(parents=True, exist_ok=True)
        (off_dir / "status.json").write_text('{"status":"PASS","runtime_ns":10,"drop":0}\n', encoding="utf-8")
        rep_dir = trace.parent
        for rel, payload in (
            ("behavior_recovery/semantic_events.json", {"syscall_sequence": []}),
            ("behavior_recovery/behavior_graph.json", {"nodes": [], "edges": []}),
            ("behavior_audit/behavior_audit.json", {"matches": [], "all_expected_matched": False}),
            ("lightweight/lightweight_trace_analysis.json", {"bytes": {"compact_jsonl": 1}}),
            ("alignment/alignment.json", {"syscall_family_precision": 1.0, "syscall_family_recall": 1.0}),
        ):
            path = rep_dir / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        for rel in ("behavior_recovery/recovery_report.md", "behavior_audit/behavior_audit_report.md", "lightweight/lightweight_trace_report.md"):
            path = rep_dir / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# self-test\n", encoding="utf-8")
        write_reports("self-test", [sample])
        if not (aggregate_root("self-test") / "metrics.csv").exists():
            print("[FAIL] aggregate renderer self-test failed", file=sys.stderr)
            return 1
        shutil.rmtree(old_root)
    print("[PASS] 35T experiment self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run and analyze the Artix-7 35T RV-MalTrace experiment matrix.")
    parser.add_argument("--stage", choices=("groundtruth", "rootfs", "board", "analyze", "report", "all", "self-test"), default="all")
    parser.add_argument("--run-id", default="manual")
    parser.add_argument("--port", default="COM5")
    parser.add_argument("--baud", type=int, default=921600)
    parser.add_argument("--reps", type=int, default=5)
    parser.add_argument("--duration", type=float, default=3600.0)
    parser.add_argument("--trace-records", type=int, default=256)
    parser.add_argument("--trace-profile", choices=profile_names(), default="p0_syscall_trap_context")
    parser.add_argument("--trace-profile-policy", choices=TRACE_PROFILE_POLICY_CHOICES, default=TRACE_PROFILE_POLICY_UNIFORM)
    parser.add_argument("--runtime-order", choices=(RUNTIME_CLASSIC, RUNTIME_ABBA), default=RUNTIME_CLASSIC)
    parser.add_argument("--warmup", type=int, default=0)
    parser.add_argument("--sample", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--keep-going", action="store_true", default=True)
    args = parser.parse_args(argv)

    if args.stage == "self-test":
        return self_test()
    samples = selected_samples(args.sample)
    profile = get_trace_profile(args.trace_profile)
    sample_profiles = trace_profiles_by_sample(samples, profile.name, args.trace_profile_policy)
    sample_control_masks = {
        sample_id: f"0x{get_trace_profile(profile_name).control_mask:x}" for sample_id, profile_name in sample_profiles.items()
    }
    config = {
        "run_id": args.run_id,
        "port": args.port,
        "baud": args.baud,
        "reps": args.reps,
        "duration": args.duration,
        "trace_records": args.trace_records,
        "trace_profile": profile.name,
        "trace_profile_policy": args.trace_profile_policy,
        "trace_profiles_by_sample": sample_profiles,
        "trace_controls": profile.trace_controls,
        "trace_control_mask": f"0x{profile.control_mask:x}",
        "trace_control_masks_by_sample": sample_control_masks,
        "runtime_order": args.runtime_order,
        "warmup": args.warmup,
        "samples": [sample.sample_id for sample in samples],
        "network": "disabled",
        "real_malware": "forbidden",
        "artifact_root": repo_rel(result_root(args.run_id)),
    }
    if args.dry_run:
        print(json.dumps({"dry_run": True, **config}, indent=2, sort_keys=True))
    else:
        result_root(args.run_id).mkdir(parents=True, exist_ok=True)
        (result_root(args.run_id) / "run_config.json").write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    stages = ["groundtruth", "rootfs", "board", "analyze", "report"] if args.stage == "all" else [args.stage]
    for stage in stages:
        if stage == "groundtruth":
            stage_groundtruth(args, samples)
        elif stage == "rootfs":
            stage_rootfs(args)
        elif stage == "board":
            stage_board(args, samples)
        elif stage == "analyze":
            stage_analyze(args, samples)
        elif stage == "report":
            stage_report(args, samples)
        else:
            raise ValueError(stage)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
