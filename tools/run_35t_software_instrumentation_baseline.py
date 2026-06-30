from __future__ import annotations

import argparse
import json
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


RUN_ID = "35t-software-instrumentation-baseline-20260523"
DEFAULT_RESULTS_ROOT = Path("results/experiments/35t") / RUN_ID
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]


RUNTIME_C = r"""
#define _GNU_SOURCE
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static int rvmt_fd = -1;
static __thread int rvmt_in_hook = 0;

static void rvmt_write_line(char kind, void *this_fn, void *call_site)
    __attribute__((no_instrument_function));
static void rvmt_open_log(void) __attribute__((constructor, no_instrument_function));
static void rvmt_close_log(void) __attribute__((destructor, no_instrument_function));

static void rvmt_write_line(char kind, void *this_fn, void *call_site) {
  if (rvmt_fd < 0 || rvmt_in_hook) {
    return;
  }
  rvmt_in_hook = 1;
  char line[160];
  int n = snprintf(
      line,
      sizeof(line),
      "%c pid=%ld fn=%p caller=%p\n",
      kind,
      (long)syscall(SYS_getpid),
      this_fn,
      call_site);
  if (n > 0) {
    syscall(SYS_write, rvmt_fd, line, (size_t)n);
  }
  rvmt_in_hook = 0;
}

static void rvmt_open_log(void) {
  const char *path = getenv("RVMT_SW_INST_LOG");
  if (path == NULL || path[0] == '\0') {
    return;
  }
  rvmt_fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
}

static void rvmt_close_log(void) {
  if (rvmt_fd >= 0) {
    syscall(SYS_close, rvmt_fd);
    rvmt_fd = -1;
  }
}

void __cyg_profile_func_enter(void *this_fn, void *call_site)
    __attribute__((no_instrument_function));
void __cyg_profile_func_exit(void *this_fn, void *call_site)
    __attribute__((no_instrument_function));

void __cyg_profile_func_enter(void *this_fn, void *call_site) {
  rvmt_write_line('E', this_fn, call_site);
}

void __cyg_profile_func_exit(void *this_fn, void *call_site) {
  rvmt_write_line('X', this_fn, call_site);
}
""".strip()


def repo_rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def sample_args(sample: Sample) -> list[str]:
    if sample.source.endswith("rvmt_benign_workload.c"):
        return [sample.sample_id]
    return []


def sample_shell(sample: Sample, results_root: Path, reps: int, runtime_path: Path) -> str:
    sample_dir = results_root / "samples" / sample.sample_class / sample.sample_id
    build_dir = sample_dir / "build"
    out_dir = sample_dir / "software_instrumentation"
    source = ROOT / sample.source
    binary = build_dir / f"{sample.sample_id}.swinst.host"
    args = " ".join(sh_quote(arg) for arg in sample_args(sample))
    fixture_env = "env RVMT_FIXTURE_ROOT=experiments/linux_behavior/benign/fixtures"
    return f"""
mkdir -p {sh_quote(repo_rel(build_dir))} {sh_quote(repo_rel(out_dir))}
gcc -O2 -Wall -Wextra -finstrument-functions -rdynamic -no-pie -o {sh_quote(repo_rel(binary))} {sh_quote(repo_rel(source))} {sh_quote(repo_rel(runtime_path))}
sha256sum {sh_quote(repo_rel(source))} > {sh_quote(repo_rel(build_dir / "source.sha256"))}
sha256sum {sh_quote(repo_rel(binary))} > {sh_quote(repo_rel(build_dir / "swinst_host_elf.sha256"))}
: > {sh_quote(repo_rel(out_dir / "timings.jsonl"))}
fail_count=0
rep=0
while [ "$rep" -lt {reps} ]; do
  log={sh_quote(repo_rel(out_dir))}/software_instrumentation.$rep.func.log
  stdout={sh_quote(repo_rel(out_dir))}/software_instrumentation.$rep.stdout.txt
  stderr={sh_quote(repo_rel(out_dir))}/software_instrumentation.$rep.stderr.txt
  start="$(date +%s%N)"
  {fixture_env} RVMT_SW_INST_LOG="$log" {sh_quote(repo_rel(binary))} {args} > "$stdout" 2> "$stderr"
  code="$?"
  end="$(date +%s%N)"
  runtime="$((end - start))"
  entries="$(grep -c '^E ' "$log" 2>/dev/null || true)"
  exits="$(grep -c '^X ' "$log" 2>/dev/null || true)"
  bytes="$(wc -c < "$log" 2>/dev/null || echo 0)"
  printf '{{"baseline":"software_instrumentation","rep":%s,"exit_code":%s,"runtime_ns":%s,"function_entries":%s,"function_exits":%s,"log_bytes":%s}}\\n' "$rep" "$code" "$runtime" "$entries" "$exits" "$bytes" >> {sh_quote(repo_rel(out_dir / "timings.jsonl"))}
  if [ "$code" -ne 0 ] || [ "$entries" -le 0 ]; then
    fail_count="$((fail_count + 1))"
  fi
  rep="$((rep + 1))"
done
if [ "$fail_count" -eq 0 ]; then status=PASS; else status=FAIL; fi
cat > {sh_quote(repo_rel(out_dir / "status.json"))} <<JSON
{{"status":"$status","sample":"{sample.sample_id}","class":"{sample.sample_class}","reps":{reps},"failed_runs":$fail_count,"instrumentation":"gcc -finstrument-functions"}}
JSON
""".strip()


def build_shell(samples: list[Sample], results_root: Path, reps: int, runtime_path: Path) -> str:
    lines = [
        "set -u",
        f"mkdir -p {sh_quote(repo_rel(results_root / 'aggregate'))}",
        "gcc --version | head -n 1",
    ]
    lines.extend(sample_shell(sample, results_root, reps, runtime_path) for sample in samples)
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


def build_summary(results_root: Path, samples: list[Sample], reps: int) -> dict[str, Any]:
    sample_rows = []
    pass_count = 0
    for sample in samples:
        out_dir = results_root / "samples" / sample.sample_class / sample.sample_id / "software_instrumentation"
        status = load_json(out_dir / "status.json") if (out_dir / "status.json").exists() else {"status": "MISSING"}
        timings = load_jsonl(out_dir / "timings.jsonl")
        if status.get("status") == "PASS":
            pass_count += 1
        sample_rows.append(
            {
                "sample_id": sample.sample_id,
                "sample_class": sample.sample_class,
                "status": status.get("status"),
                "reps": reps,
                "runtime_ns": summarize_numbers([float(row["runtime_ns"]) for row in timings if isinstance(row.get("runtime_ns"), int)]),
                "function_entries": summarize_numbers([float(row["function_entries"]) for row in timings if isinstance(row.get("function_entries"), int)]),
                "function_exits": summarize_numbers([float(row["function_exits"]) for row in timings if isinstance(row.get("function_exits"), int)]),
                "log_bytes": summarize_numbers([float(row["log_bytes"]) for row in timings if isinstance(row.get("log_bytes"), int)]),
                "status_path": repo_rel(out_dir / "status.json"),
                "timings_path": repo_rel(out_dir / "timings.jsonl"),
                "raw_logs_committed": False,
            }
        )
    status = "PASS" if sample_rows and pass_count == len(sample_rows) else "FAIL"
    return {
        "schema": "rvmt.35t.software_instrumentation_baseline.v1",
        "run_id": RUN_ID,
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "status": status,
        "baseline": "software_instrumentation",
        "instrumentation": "gcc -finstrument-functions host binary",
        "sample_count": len(sample_rows),
        "pass_count": pass_count,
        "reps": reps,
        "samples": sample_rows,
        "artifact_policy": "raw function logs remain in local results; committed evidence contains summary only",
        "limitations": [
            "source-level function instrumentation is user-visible and perturbing",
            "function entry/exit logs are not syscall argument or path reconstruction",
            "this baseline is not eBPF-only, QEMU-plugin, DBI, or real malware detection evidence",
        ],
        "non_claims": NON_CLAIMS,
    }


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        f"# 35T Software Instrumentation Baseline: {summary['run_id']}",
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
        "| Sample | Class | Status | Runtime median ns | Function entries median | Log bytes median |",
        "| --- | --- | --- | ---: | ---: | ---: |",
    ]
    for row in summary["samples"]:
        lines.append(
            "| `{sample}` | `{klass}` | `{status}` | {runtime} | {entries} | {bytes} |".format(
                sample=row["sample_id"],
                klass=row["sample_class"],
                status=row["status"],
                runtime=format_summary(row.get("runtime_ns")),
                entries=format_summary(row.get("function_entries")),
                bytes=format_summary(row.get("log_bytes")),
            )
        )
    lines += ["", "## Limitations", ""]
    lines.extend(f"- {item}" for item in summary["limitations"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in summary["non_claims"])
    return "\n".join(lines) + "\n"


def format_summary(value: Any) -> str:
    if not isinstance(value, dict) or value.get("median") is None:
        return "n/a"
    return f"{float(value['median']):.6g}"


def write_summary_outputs(summary: dict[str, Any], results_root: Path) -> None:
    aggregate = results_root / "aggregate"
    write_json(aggregate / "software_instrumentation_baseline_summary.json", summary)
    (aggregate / "software_instrumentation_baseline_summary.md").write_text(
        render_markdown(summary),
        encoding="utf-8",
        newline="\n",
    )


def run_baseline(results_root: Path, reps: int, sample_selectors: list[str], dry_run: bool) -> dict[str, Any]:
    samples = selected_samples(sample_selectors)
    results_root.mkdir(parents=True, exist_ok=True)
    runtime_path = results_root / "rvmt_sw_instrument.c"
    runtime_path.write_text(RUNTIME_C + "\n", encoding="utf-8", newline="\n")
    shell_path = results_root / "run_software_instrumentation.sh"
    shell_path.write_text(build_shell(samples, results_root, reps, runtime_path), encoding="utf-8", newline="\n")
    write_json(
        results_root / "run_config.json",
        {
            "schema": "rvmt.35t.software_instrumentation_run_config.v1",
            "run_id": RUN_ID,
            "baseline": "software_instrumentation",
            "reps": reps,
            "samples": [sample.sample_id for sample in samples],
            "scope": EXPECTED_SCOPE,
            "claim_level": EXPECTED_CLAIM_LEVEL,
            "real_malware": False,
        },
    )
    if not dry_run:
        cmd = [*docker_compose_base(), "run", "--rm", "--build", "linux-behavior", "bash", repo_rel(shell_path)]
        completed = subprocess.run(cmd, cwd=str(ROOT))
        if completed.returncode != 0:
            raise RuntimeError(f"software instrumentation docker run failed with exit code {completed.returncode}")
    summary = build_summary(results_root, samples, reps)
    write_summary_outputs(summary, results_root)
    return summary


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        sample = Sample(
            sample_class="benign",
            sample_id="hello",
            source="board/artix7_35t/linux/rvmt_benign_workload.c",
            command=["./rvmt_benign_workload", "hello"],
            expected_behavior=[],
            evidence_dir="01_hello",
        )
        results = root / DEFAULT_RESULTS_ROOT
        out_dir = results / "samples/benign/hello/software_instrumentation"
        write_json(out_dir / "status.json", {"status": "PASS"})
        (out_dir / "timings.jsonl").write_text(
            '{"runtime_ns":100,"function_entries":2,"function_exits":2,"log_bytes":96}\n',
            encoding="utf-8",
            newline="\n",
        )
        summary = build_summary(results, [sample], reps=1)
        if summary["status"] != "PASS" or summary["pass_count"] != 1:
            print("[FAIL] expected fixture summary to pass", file=sys.stderr)
            return 1
        text = build_shell([sample], results, 1, results / "rvmt_sw_instrument.c")
        if "-finstrument-functions" not in text or "RVMT_SW_INST_LOG" not in text:
            print("[FAIL] generated shell does not contain instrumentation controls", file=sys.stderr)
            return 1
    print("[PASS] 35T software instrumentation baseline self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a source-level software instrumentation baseline for 35T samples.")
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--reps", type=int, default=5)
    parser.add_argument("--sample", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    results_root = args.results_root if args.results_root.is_absolute() else ROOT / args.results_root
    try:
        summary = run_baseline(results_root, args.reps, args.sample, args.dry_run)
    except Exception as exc:
        print(f"run_35t_software_instrumentation_baseline: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] software instrumentation baseline at {repo_rel(results_root)}")
    return 0 if summary["status"] == "PASS" or args.dry_run else 1


if __name__ == "__main__":
    raise SystemExit(main())
