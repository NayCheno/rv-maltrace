from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    write_json,
)

from docker_common import docker_compose_base


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from experiment_35t import Sample, selected_samples, sh_quote  # noqa: E402


RUN_ID = "35t-ebpf-baseline-20260523"
SOURCE_RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_RESULTS_ROOT = Path("results/experiments/35t") / RUN_ID
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / SOURCE_RUN_ID
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
SUMMARY_SCHEMA = "rvmt.35t.ebpf_baseline.v1"
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]


X86_64_SYSCALL_IDS = {
    "read": 0,
    "write": 1,
    "open": 2,
    "close": 3,
    "mmap": 9,
    "mprotect": 10,
    "munmap": 11,
    "clone": 56,
    "execve": 59,
    "ptrace": 101,
    "clock_gettime": 228,
    "getdents64": 217,
    "waitid": 247,
    "openat": 257,
    "clone3": 435,
}
SYSCALL_NAMES = {value: key for key, value in X86_64_SYSCALL_IDS.items()}
SYS_RE = re.compile(r"@sys\[(\d+)\]:\s*(\d+)")
EVENTS_RE = re.compile(r"@events:\s*(\d+)")


def repo_rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def sample_args(sample: Sample) -> list[str]:
    if sample.source.endswith("rvmt_benign_workload.c"):
        return [sample.sample_id]
    return []


def bpf_comm(index: int) -> str:
    return f"rvmt_bpf_{index:02d}"


def sample_shell(sample: Sample, index: int, results_root: Path, reps: int) -> str:
    sample_dir = results_root / "samples" / sample.sample_class / sample.sample_id
    build_dir = sample_dir / "build"
    out_dir = sample_dir / "ebpf_only"
    source = ROOT / sample.source
    comm = bpf_comm(index)
    binary = build_dir / comm
    args = " ".join(sh_quote(arg) for arg in sample_args(sample))
    bpftrace_args = " ".join(sample_args(sample))
    fixture_env = "env RVMT_FIXTURE_ROOT=experiments/linux_behavior/benign/fixtures"
    command = f"{fixture_env} {sh_quote(repo_rel(binary))} {args}".strip()
    bpftrace_command = f"{fixture_env} {repo_rel(binary)} {bpftrace_args}".strip()
    bt_path = out_dir / "ebpf_only.bt"
    return f"""
mkdir -p {sh_quote(repo_rel(build_dir))} {sh_quote(repo_rel(out_dir))}
gcc -O2 -Wall -Wextra -no-pie -o {sh_quote(repo_rel(binary))} {sh_quote(repo_rel(source))}
sha256sum {sh_quote(repo_rel(source))} > {sh_quote(repo_rel(build_dir / "source.sha256"))}
sha256sum {sh_quote(repo_rel(binary))} > {sh_quote(repo_rel(build_dir / "ebpf_host_elf.sha256"))}
cat > {sh_quote(repo_rel(bt_path))} <<'BT'
tracepoint:raw_syscalls:sys_enter /comm == "{comm}"/ {{ @sys[args->id] = count(); @events = count(); }}
BT
: > {sh_quote(repo_rel(out_dir / "timings.jsonl"))}
fail_count=0
rep=0
while [ "$rep" -lt {reps} ]; do
  native_stdout={sh_quote(repo_rel(out_dir))}/native.$rep.stdout.txt
  native_stderr={sh_quote(repo_rel(out_dir))}/native.$rep.stderr.txt
  start="$(date +%s%N)"
  {command} > "$native_stdout" 2> "$native_stderr"
  native_code="$?"
  end="$(date +%s%N)"
  native_runtime="$((end - start))"

  bpf_stdout={sh_quote(repo_rel(out_dir))}/ebpf_only.$rep.stdout.txt
  bpf_stderr={sh_quote(repo_rel(out_dir))}/ebpf_only.$rep.stderr.txt
  bpftrace_out={sh_quote(repo_rel(out_dir))}/ebpf_only.$rep.bpftrace.out
  bpftrace_err={sh_quote(repo_rel(out_dir))}/ebpf_only.$rep.bpftrace.err
  start="$(date +%s%N)"
  bpftrace {sh_quote(repo_rel(bt_path))} -c {sh_quote(bpftrace_command)} > "$bpftrace_out" 2> "$bpftrace_err"
  bpf_code="$?"
  end="$(date +%s%N)"
  bpf_runtime="$((end - start))"
  printf '{{"baseline":"ebpf_only","rep":%s,"native_exit_code":%s,"ebpf_exit_code":%s,"native_runtime_ns":%s,"ebpf_runtime_ns":%s,"bpftrace_stdout":"%s","bpftrace_stderr":"%s"}}\\n' "$rep" "$native_code" "$bpf_code" "$native_runtime" "$bpf_runtime" "$bpftrace_out" "$bpftrace_err" >> {sh_quote(repo_rel(out_dir / "timings.jsonl"))}
  if [ "$native_code" -ne 0 ] || [ "$bpf_code" -ne 0 ]; then
    fail_count="$((fail_count + 1))"
  fi
  rep="$((rep + 1))"
done
if [ "$fail_count" -eq 0 ]; then status=PASS; else status=FAIL; fi
cat > {sh_quote(repo_rel(out_dir / "status.json"))} <<JSON
{{"status":"$status","sample":"{sample.sample_id}","class":"{sample.sample_class}","reps":{reps},"failed_runs":$fail_count,"instrumentation":"bpftrace tracepoint:raw_syscalls:sys_enter comm filter","comm":"{comm}"}}
JSON
""".strip()


def build_shell(samples: list[Sample], results_root: Path, reps: int) -> str:
    lines = [
        "set -u",
        "mkdir -p /sys/kernel/tracing /sys/kernel/debug",
        "mount -t tracefs tracefs /sys/kernel/tracing >/dev/null 2>&1 || true",
        "mount -t debugfs debugfs /sys/kernel/debug >/dev/null 2>&1 || true",
        "test -w /sys/kernel/tracing/kprobe_events || test -w /sys/kernel/debug/tracing/kprobe_events",
        "command -v bpftrace >/dev/null",
        f"mkdir -p {sh_quote(repo_rel(results_root / 'aggregate'))}",
        "gcc --version | head -n 1",
        "bpftrace --version",
    ]
    lines.extend(sample_shell(sample, index, results_root, reps) for index, sample in enumerate(samples))
    return "\n\n".join(lines) + "\n"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        if isinstance(value, dict):
            rows.append(value)
    return rows


def parse_bpftrace_counts(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    syscalls: dict[int, int] = {}
    for match in SYS_RE.finditer(text):
        syscalls[int(match.group(1))] = int(match.group(2))
    events_match = EVENTS_RE.search(text)
    event_count = int(events_match.group(1)) if events_match else sum(syscalls.values())
    named = {SYSCALL_NAMES.get(syscall_id, str(syscall_id)): count for syscall_id, count in sorted(syscalls.items())}
    return {
        "event_count": event_count,
        "syscall_counts": named,
        "raw_syscall_counts": {str(key): value for key, value in sorted(syscalls.items())},
    }


def summarize_numbers(values: list[float]) -> dict[str, float] | None:
    if not values:
        return None
    values = sorted(values)
    mid = len(values) // 2
    median = values[mid] if len(values) % 2 else (values[mid - 1] + values[mid]) / 2
    return {
        "min": values[0],
        "median": median,
        "max": values[-1],
        "spread": values[-1] - values[0],
    }


def expected_syscall_counts(sample: Sample, aggregate_counts: dict[str, int]) -> dict[str, int]:
    return {name: int(aggregate_counts.get(name, 0)) for name in expected_syscalls(sample)}


def expected_syscalls(sample: Sample) -> list[str]:
    # The Sample dataclass carries behaviors, not syscall names; reload the
    # source manifests when strict expected syscall checks are needed.
    for manifest_path in (
        ROOT / "experiments/linux_behavior/benign/manifest.json",
        ROOT / "experiments/linux_behavior/malware_like/manifest.json",
    ):
        manifest = load_json(manifest_path)
        for row in manifest.get("samples", []):
            if isinstance(row, dict) and row.get("id") == sample.sample_id:
                return [str(item) for item in row.get("expected_syscalls", [])]
    return []


def build_summary(results_root: Path, evidence_root: Path, samples: list[Sample], reps: int) -> dict[str, Any]:
    sample_rows = []
    pass_count = 0
    for sample in samples:
        out_dir = results_root / "samples" / sample.sample_class / sample.sample_id / "ebpf_only"
        status = load_json(out_dir / "status.json") if (out_dir / "status.json").exists() else {"status": "MISSING"}
        timings = load_jsonl(out_dir / "timings.jsonl")
        aggregate_counts: dict[str, int] = {}
        rep_rows = []
        for row in timings:
            bpftrace_path = Path(str(row.get("bpftrace_stdout", "")))
            counts = parse_bpftrace_counts(bpftrace_path if bpftrace_path.is_absolute() else ROOT / bpftrace_path)
            for name, count in counts["syscall_counts"].items():
                aggregate_counts[name] = aggregate_counts.get(name, 0) + int(count)
            native_runtime = row.get("native_runtime_ns")
            ebpf_runtime = row.get("ebpf_runtime_ns")
            ratio = None
            if isinstance(native_runtime, int) and native_runtime > 0 and isinstance(ebpf_runtime, int):
                ratio = ebpf_runtime / native_runtime
            rep_rows.append(
                {
                    "rep": row.get("rep"),
                    "native_exit_code": row.get("native_exit_code"),
                    "ebpf_exit_code": row.get("ebpf_exit_code"),
                    "native_runtime_ns": native_runtime,
                    "ebpf_runtime_ns": ebpf_runtime,
                    "ebpf_over_native": ratio,
                    "event_count": counts["event_count"],
                    "bpftrace_stdout": row.get("bpftrace_stdout"),
                    "bpftrace_stderr": row.get("bpftrace_stderr"),
                }
            )
        expected_counts = expected_syscall_counts(sample, aggregate_counts)
        expected_observed = all(count > 0 for count in expected_counts.values()) if expected_counts else False
        has_events = any(int(row.get("event_count") or 0) > 0 for row in rep_rows)
        sample_status = "PASS" if status.get("status") == "PASS" and has_events and expected_observed else "FAIL"
        if sample_status == "PASS":
            pass_count += 1
        sample_rows.append(
            {
                "sample_id": sample.sample_id,
                "sample_class": sample.sample_class,
                "status": sample_status,
                "run_status": status.get("status"),
                "reps": reps,
                "comm": status.get("comm"),
                "native_runtime_ns": summarize_numbers(
                    [float(row["native_runtime_ns"]) for row in rep_rows if isinstance(row.get("native_runtime_ns"), int)]
                ),
                "ebpf_runtime_ns": summarize_numbers(
                    [float(row["ebpf_runtime_ns"]) for row in rep_rows if isinstance(row.get("ebpf_runtime_ns"), int)]
                ),
                "ebpf_over_native": summarize_numbers(
                    [float(row["ebpf_over_native"]) for row in rep_rows if isinstance(row.get("ebpf_over_native"), (int, float))]
                ),
                "event_count": summarize_numbers(
                    [float(row["event_count"]) for row in rep_rows if isinstance(row.get("event_count"), int)]
                ),
                "syscall_counts": aggregate_counts,
                "expected_syscall_counts": expected_counts,
                "expected_syscalls_observed": expected_observed,
                "rep_rows": rep_rows,
                "status_path": repo_rel(out_dir / "status.json"),
                "timings_path": repo_rel(out_dir / "timings.jsonl"),
                "raw_logs_committed": False,
            }
        )
    status = "PASS" if sample_rows and pass_count == len(sample_rows) == 13 else "FAIL"
    return {
        "schema": SUMMARY_SCHEMA,
        "run_id": RUN_ID,
        "source_run_id": SOURCE_RUN_ID,
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "status": status,
        "baseline": "ebpf_only",
        "instrumentation": "bpftrace tracepoint:raw_syscalls:sys_enter comm-filtered host binaries",
        "sample_count": len(sample_rows),
        "pass_count": pass_count,
        "reps": reps,
        "samples": sample_rows,
        "results_root": repo_rel(results_root),
        "evidence_root": repo_rel(evidence_root),
        "artifact_policy": "raw bpftrace stdout/stderr logs remain in local results; committed evidence contains summary only",
        "limitations": [
            "this is a host Linux eBPF/bpftrace baseline for the 13 synthetic samples, not a hardware trace result",
            "runtime ratios are conservative end-to-end bpftrace launcher measurements and not in-kernel steady-state overhead",
            "comm-filtered syscall counts include dynamic loader activity and should not be treated as precise semantic reconstruction",
            "child processes are captured only while they retain the sample comm before execve; process-tree completeness is not claimed",
            "this baseline is not a QEMU-plugin, DBI, pointer-snapshot, real malware, or CVA6 validation substitute",
        ],
        "non_claims": NON_CLAIMS,
    }


def format_summary(value: Any) -> str:
    if not isinstance(value, dict) or value.get("median") is None:
        return "n/a"
    return f"{float(value['median']):.6g}"


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        f"# 35T eBPF-only Baseline: {summary['run_id']}",
        "",
        f"Status: {summary['status']}",
        "",
        f"Scope: {summary['scope']}.",
        "",
        f"Claim level: {summary['claim_level']}.",
        "",
        f"Instrumentation: {summary['instrumentation']}.",
        "",
        "## Samples",
        "",
        "| Sample | Class | Status | Events median | eBPF/native median | Expected syscalls observed |",
        "| --- | --- | --- | ---: | ---: | --- |",
    ]
    for row in summary["samples"]:
        lines.append(
            "| `{sample}` | `{klass}` | `{status}` | {events} | {ratio} | {observed} |".format(
                sample=row["sample_id"],
                klass=row["sample_class"],
                status=row["status"],
                events=format_summary(row.get("event_count")),
                ratio=format_summary(row.get("ebpf_over_native")),
                observed="yes" if row.get("expected_syscalls_observed") else "no",
            )
        )
    lines += ["", "## Limitations", ""]
    lines.extend(f"- {item}" for item in summary["limitations"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in summary["non_claims"])
    return "\n".join(lines) + "\n"


def write_summary_outputs(summary: dict[str, Any], results_root: Path, evidence_root: Path) -> None:
    aggregate = results_root / "aggregate"
    write_json(aggregate / "ebpf_baseline_summary.json", summary)
    markdown = render_markdown(summary)
    (aggregate / "ebpf_baseline_summary.md").write_text(markdown, encoding="utf-8", newline="\n")
    write_json(evidence_root / "ebpf_baseline_summary.json", summary)
    (evidence_root / "ebpf_baseline_summary.md").write_text(markdown, encoding="utf-8", newline="\n")


def run_baseline(
    results_root: Path,
    evidence_root: Path,
    reps: int,
    sample_selectors: list[str],
    dry_run: bool,
    build_image: bool,
) -> dict[str, Any]:
    samples = selected_samples(sample_selectors)
    results_root.mkdir(parents=True, exist_ok=True)
    shell_path = results_root / "run_ebpf_baseline.sh"
    shell_path.write_text(build_shell(samples, results_root, reps), encoding="utf-8", newline="\n")
    write_json(
        results_root / "run_config.json",
        {
            "schema": "rvmt.35t.ebpf_baseline_run_config.v1",
            "run_id": RUN_ID,
            "source_run_id": SOURCE_RUN_ID,
            "baseline": "ebpf_only",
            "reps": reps,
            "samples": [sample.sample_id for sample in samples],
            "scope": EXPECTED_SCOPE,
            "claim_level": EXPECTED_CLAIM_LEVEL,
            "real_malware": False,
            "build_image": build_image,
        },
    )
    if not dry_run:
        cmd = [*docker_compose_base(), "run", "--rm"]
        if build_image:
            cmd.append("--build")
        cmd.extend(
            [
                "--cap-add",
                "SYS_ADMIN",
                "--cap-add",
                "SYS_PTRACE",
                "linux-behavior",
                "bash",
                repo_rel(shell_path),
            ]
        )
        completed = subprocess.run(cmd, cwd=str(ROOT))
        if completed.returncode != 0:
            raise RuntimeError(f"eBPF baseline docker run failed with exit code {completed.returncode}")
    summary = build_summary(results_root, evidence_root, samples, reps)
    write_summary_outputs(summary, results_root, evidence_root)
    return summary


def write_fixture_summary(results: Path, evidence: Path, samples: list[Sample], reps: int) -> None:
    for index, sample in enumerate(samples):
        out_dir = results / "samples" / sample.sample_class / sample.sample_id / "ebpf_only"
        out_dir.mkdir(parents=True, exist_ok=True)
        write_json(
            out_dir / "status.json",
            {"status": "PASS", "sample": sample.sample_id, "class": sample.sample_class, "reps": reps, "comm": bpf_comm(index)},
        )
        expected = expected_syscalls(sample)
        lines = ["Attaching 1 probe..."]
        for name in expected:
            syscall_id = X86_64_SYSCALL_IDS.get(name)
            if syscall_id is not None:
                lines.append(f"@sys[{syscall_id}]: 1")
        lines.append(f"@events: {max(1, len(expected))}")
        (out_dir / "ebpf_only.0.bpftrace.out").write_text("\n".join(lines) + "\n", encoding="utf-8")
        (out_dir / "timings.jsonl").write_text(
            json.dumps(
                {
                    "baseline": "ebpf_only",
                    "rep": 0,
                    "native_exit_code": 0,
                    "ebpf_exit_code": 0,
                    "native_runtime_ns": 100,
                    "ebpf_runtime_ns": 300,
                    "bpftrace_stdout": repo_rel(out_dir / "ebpf_only.0.bpftrace.out"),
                    "bpftrace_stderr": repo_rel(out_dir / "ebpf_only.0.bpftrace.err"),
                }
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
    evidence.mkdir(parents=True, exist_ok=True)


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        results = root / DEFAULT_RESULTS_ROOT
        evidence = root / DEFAULT_EVIDENCE_ROOT
        samples = selected_samples([])
        write_fixture_summary(results, evidence, samples, reps=1)
        summary = build_summary(results, evidence, samples, reps=1)
        if summary["status"] != "PASS" or summary["pass_count"] != 13:
            print("[FAIL] expected eBPF fixture summary to pass", file=sys.stderr)
            print(json.dumps(summary, indent=2), file=sys.stderr)
            return 1
        text = build_shell(samples[:1], results, 1)
        if "bpftrace" not in text or "tracepoint:raw_syscalls:sys_enter" not in text:
            print("[FAIL] generated shell does not contain bpftrace controls", file=sys.stderr)
            return 1
    print("[PASS] 35T eBPF baseline self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an eBPF/bpftrace baseline for 35T synthetic samples.")
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--reps", type=int, default=3)
    parser.add_argument("--sample", action="append", default=[])
    parser.add_argument("--build-image", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    results_root = args.results_root if args.results_root.is_absolute() else ROOT / args.results_root
    evidence_root = args.evidence_root if args.evidence_root.is_absolute() else ROOT / args.evidence_root
    try:
        summary = run_baseline(results_root, evidence_root, args.reps, args.sample, args.dry_run, args.build_image)
    except Exception as exc:
        print(f"run_35t_ebpf_baseline: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] eBPF baseline at {repo_rel(results_root)}")
    return 0 if summary["status"] == "PASS" or args.dry_run else 1


if __name__ == "__main__":
    raise SystemExit(main())
