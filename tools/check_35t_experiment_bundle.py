from __future__ import annotations

import argparse
import json
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULT_ROOT = Path("results/experiments/35t")
BENIGN_MANIFEST = Path("experiments/linux_behavior/benign/manifest.json")
MALWARE_MANIFEST = Path("experiments/linux_behavior/malware_like/manifest.json")
REQUIRED_BASELINES = ("host_native", "host_strace", "qemu_native", "qemu_strace")
OPTIONAL_BASELINES = ("ebpf_only", "qemu_plugin", "software_instrumentation")
AGGREGATE_ARTIFACTS = (
    "metrics.json",
    "metrics.csv",
    "accuracy_report.md",
    "overhead_report.md",
    "bandwidth_report.md",
    "artifact_index.md",
)
GATE_ARTIFACTS = (
    "gate_report.json",
    "gate_report.md",
)
TRACE_ANALYSIS_ARTIFACTS = (
    "behavior_recovery/semantic_events.json",
    "behavior_recovery/behavior_graph.json",
    "behavior_recovery/recovery_report.md",
    "behavior_audit/behavior_audit.json",
    "behavior_audit/behavior_audit_report.md",
    "lightweight/lightweight_trace_analysis.json",
    "lightweight/lightweight_trace_report.md",
    "alignment/alignment.json",
)


@dataclass(frozen=True)
class SampleRef:
    sample_class: str
    sample_id: str


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_samples(root: Path, selectors: Iterable[str]) -> list[SampleRef]:
    wanted = {item for item in selectors if item}
    samples: list[SampleRef] = []
    benign = load_json(resolve(root, BENIGN_MANIFEST))
    malware = load_json(resolve(root, MALWARE_MANIFEST))
    for row in benign.get("samples", []):
        if not isinstance(row, dict) or row.get("default_enabled") is not True or row.get("network_required"):
            continue
        samples.append(SampleRef("benign", str(row["id"])))
    for row in malware.get("samples", []):
        if isinstance(row, dict):
            samples.append(SampleRef("malware_like_synthetic", str(row["id"])))
    if not wanted:
        return samples
    selected = [sample for sample in samples if sample.sample_id in wanted or sample.sample_class in wanted]
    found = {sample.sample_id for sample in selected} | {sample.sample_class for sample in selected}
    missing = sorted(wanted - found)
    if missing:
        raise ValueError(f"unknown sample selectors: {', '.join(missing)}")
    return selected


def require_file(errors: list[str], path: Path, label: str) -> None:
    if not path.is_file():
        errors.append(f"missing {label}: {path}")


def check_groundtruth(run_root: Path, sample: SampleRef, reps: int) -> list[str]:
    errors: list[str] = []
    gt_dir = run_root / "samples" / sample.sample_class / sample.sample_id / "groundtruth"
    require_file(errors, gt_dir / "status.json", "groundtruth status")
    require_file(errors, gt_dir / "timings.jsonl", "groundtruth timings")
    require_file(errors, gt_dir / "optional_baselines.json", "optional baseline status")
    if (gt_dir / "status.json").exists():
        status = load_json(gt_dir / "status.json")
        if status.get("status") != "PASS":
            errors.append(f"{sample.sample_id}: groundtruth status must be PASS")
    if (gt_dir / "timings.jsonl").exists():
        rows = [json.loads(line) for line in (gt_dir / "timings.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        counts = {baseline: 0 for baseline in REQUIRED_BASELINES}
        for row in rows:
            baseline = row.get("baseline")
            if baseline in counts and row.get("exit_code") == 0:
                counts[str(baseline)] += 1
        for baseline, count in counts.items():
            if count < reps:
                errors.append(f"{sample.sample_id}: baseline {baseline} has {count}/{reps} passing timing rows")
    if (gt_dir / "optional_baselines.json").exists():
        optional = load_json(gt_dir / "optional_baselines.json")
        for baseline in OPTIONAL_BASELINES:
            row = optional.get(baseline)
            if not isinstance(row, dict):
                errors.append(f"{sample.sample_id}: optional baseline {baseline} missing status object")
                continue
            if row.get("status") not in {"PASS", "BLOCKED", "N/A"}:
                errors.append(f"{sample.sample_id}: optional baseline {baseline} must be PASS, BLOCKED, or N/A")
            if row.get("status") in {"BLOCKED", "N/A"} and not row.get("reason"):
                errors.append(f"{sample.sample_id}: optional baseline {baseline} needs a reason")
    return errors


def check_board(run_root: Path, sample: SampleRef, reps: int) -> list[str]:
    errors: list[str] = []
    sample_dir = run_root / "samples" / sample.sample_class / sample.sample_id
    for mode in ("trace-off", "trace-on"):
        for rep in range(reps):
            rep_dir = sample_dir / "board" / mode / f"rep_{rep:02d}"
            status_path = rep_dir / "status.json"
            require_file(errors, status_path, f"{sample.sample_id} {mode} rep {rep} status")
            if status_path.exists():
                status = load_json(status_path)
                if status.get("status") != "PASS":
                    errors.append(f"{status_path}: status must be PASS")
                if "runtime_ns" not in status:
                    errors.append(f"{status_path}: missing runtime_ns")
            if mode == "trace-on":
                require_file(errors, rep_dir / "trace.jsonl", f"{sample.sample_id} trace-on rep {rep} trace")
                for artifact in TRACE_ANALYSIS_ARTIFACTS:
                    require_file(errors, rep_dir / artifact, f"{sample.sample_id} trace-on rep {rep} {artifact}")
    return errors


def check_aggregate(run_root: Path) -> list[str]:
    errors: list[str] = []
    aggregate = run_root / "aggregate"
    for artifact in AGGREGATE_ARTIFACTS:
        require_file(errors, aggregate / artifact, f"aggregate {artifact}")
    run_config = load_json(run_root / "run_config.json") if (run_root / "run_config.json").exists() else {}
    gate_required = bool(run_config.get("next_gate_required") or run_config.get("gate_checked")) or any((aggregate / artifact).exists() for artifact in GATE_ARTIFACTS)
    if gate_required:
        for artifact in GATE_ARTIFACTS:
            require_file(errors, aggregate / artifact, f"aggregate {artifact}")
        gate_json = aggregate / "gate_report.json"
        if gate_json.exists():
            try:
                gate = load_json(gate_json)
                if gate.get("schema") != "rvmt.35t.next_gate.v1":
                    errors.append(f"{gate_json}: unexpected gate report schema")
            except Exception as exc:  # noqa: BLE001 - collect checker errors.
                errors.append(f"{gate_json}: invalid gate report JSON: {exc}")
    accuracy = aggregate / "accuracy_report.md"
    if accuracy.exists():
        text = accuracy.read_text(encoding="utf-8")
        if "Malware-like Behavior Audit Accuracy" not in text:
            errors.append(f"{accuracy}: report title must use malware-like behavior audit accuracy")
        if "real malware detection" in text.lower() and "not a real malware detection claim" not in text.lower():
            errors.append(f"{accuracy}: must not claim real malware detection accuracy")
    return errors


def check_run(run_root: Path, samples: list[SampleRef], reps: int) -> list[str]:
    errors: list[str] = []
    require_file(errors, run_root / "run_config.json", "run config")
    errors.extend(check_aggregate(run_root))
    for sample in samples:
        errors.extend(check_groundtruth(run_root, sample, reps))
        errors.extend(check_board(run_root, sample, reps))
    return errors


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        run_root = Path(tmp) / "run"
        sample = SampleRef("benign", "hello")
        write_json(run_root / "run_config.json", {"samples": ["hello"], "reps": 1})
        aggregate = run_root / "aggregate"
        aggregate.mkdir(parents=True)
        for artifact in AGGREGATE_ARTIFACTS:
            (aggregate / artifact).write_text("# 35T Malware-like Behavior Audit Accuracy\n\nnot a real malware detection claim\n", encoding="utf-8")
        gt = run_root / "samples" / sample.sample_class / sample.sample_id / "groundtruth"
        write_json(gt / "status.json", {"status": "PASS"})
        (gt / "timings.jsonl").write_text(
            "".join(json.dumps({"baseline": baseline, "rep": 0, "exit_code": 0, "runtime_ns": 1}) + "\n" for baseline in REQUIRED_BASELINES),
            encoding="utf-8",
        )
        write_json(gt / "optional_baselines.json", {baseline: {"status": "BLOCKED", "reason": "self-test"} for baseline in OPTIONAL_BASELINES})
        for mode in ("trace-off", "trace-on"):
            rep_dir = run_root / "samples" / sample.sample_class / sample.sample_id / "board" / mode / "rep_00"
            write_json(rep_dir / "status.json", {"status": "PASS", "runtime_ns": 1})
            if mode == "trace-on":
                (rep_dir / "trace.jsonl").write_text('{"cycle":1,"evt":"SYSCALL_ENTRY"}\n', encoding="utf-8")
                for artifact in TRACE_ANALYSIS_ARTIFACTS:
                    path = rep_dir / artifact
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if path.suffix == ".json":
                        write_json(path, {"status": "PASS"})
                    else:
                        path.write_text("# report\n", encoding="utf-8")
        errors = check_run(run_root, [sample], 1)
        if errors:
            print("[FAIL] 35T bundle checker self-test failed:", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
    print("[PASS] 35T experiment bundle self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a 35T experiment artifact bundle.")
    parser.add_argument("--run-id", default="manual")
    parser.add_argument("--root", type=Path, default=DEFAULT_RESULT_ROOT)
    parser.add_argument("--reps", type=int)
    parser.add_argument("--sample", action="append", default=[])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    result_root = resolve(ROOT, args.root)
    run_root = result_root / args.run_id
    run_config = load_json(run_root / "run_config.json")
    selectors = args.sample or run_config.get("samples", [])
    if not isinstance(selectors, list):
        selectors = []
    reps = args.reps if args.reps is not None else int(run_config.get("reps", 5))
    samples = load_samples(ROOT, [str(item) for item in selectors])
    errors = check_run(run_root, samples, reps)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"[PASS] 35T experiment bundle is complete: {run_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
