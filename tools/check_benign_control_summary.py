from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_dict,
    as_float,
    as_int,
    as_list,
    load_json,
    repo_path,
    require,
    write_json,
)


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/benign_control_summary.json")
REQUIRED_SAMPLES = {"hello", "ls", "cat", "cp", "sha256sum"}


def require_file(errors: list[str], root: Path, value: Any, context: str) -> None:
    if not value:
        errors.append(f"{context}: path missing")
        return
    if not repo_path(root, value).is_file():
        errors.append(f"{context}: file missing: {value}")


def check_summary(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == "rvmt.genesys2.benign_control_summary.v1", "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")
    require(errors, repo_path(root, data.get("run_root")).is_dir(), "run_root must exist")
    require_file(errors, root, data.get("source_manifest"), "source_manifest")
    require_file(errors, root, data.get("rules"), "rules")
    require_file(errors, root, data.get("wrapper_source"), "wrapper_source")
    require_file(errors, root, data.get("wrapper_binary"), "wrapper_binary")

    toolchain = as_dict(data.get("toolchain"))
    require(errors, toolchain.get("docker_service") == "linux-behavior", "toolchain docker service mismatch")
    require(errors, "gcc" in str(toolchain.get("compiler") or "").lower(), "compiler version missing")
    require(errors, "strace" in str(toolchain.get("strace") or "").lower(), "strace version missing")

    aggregate = as_dict(data.get("aggregate"))
    require(errors, as_int(aggregate.get("sample_count")) >= 5, "at least five benign samples required")
    require(errors, as_int(aggregate.get("non_network_sample_count")) >= 5, "at least five non-network benign samples required")
    require(errors, as_int(aggregate.get("unexpected_false_positive_count"), default=-1) == 0, "unexpected false positives must be zero")
    require(errors, as_float(aggregate.get("benign_false_positive_rate"), default=1.0) == 0.0, "benign false-positive rate must be 0.0")

    rows = {str(row.get("sample_id")): row for row in as_list(data.get("samples")) if isinstance(row, dict) and row.get("sample_id")}
    missing = sorted(REQUIRED_SAMPLES - set(rows))
    require(errors, not missing, f"missing benign samples: {', '.join(missing)}")
    for sample_id, row in rows.items():
        require(errors, row.get("sample_class") == "benign", f"{sample_id}: sample_class must be benign")
        require(errors, row.get("status") == "PASS", f"{sample_id}: status must be PASS")
        require(errors, row.get("network_required") is False, f"{sample_id}: network_required must be false")
        require(errors, row.get("default_enabled") is True, f"{sample_id}: default_enabled must be true")
        require(errors, as_int(row.get("returncode"), default=-1) == 0, f"{sample_id}: returncode must be 0")
        coverage = as_dict(row.get("expected_syscall_coverage"))
        require(errors, bool(coverage) and all(value is True for value in coverage.values()), f"{sample_id}: expected syscall coverage incomplete")
        require(errors, row.get("false_positive") is False, f"{sample_id}: false_positive must be false")
        require(errors, not as_list(row.get("unexpected_matched_rules")), f"{sample_id}: unexpected matched rules must be empty")
        for key in ("strace_log", "stdout", "stderr", "semantic_events", "behavior_graph", "behavior_audit"):
            require_file(errors, root, row.get(key), f"{sample_id}.{key}")
        semantic = load_json(repo_path(root, row.get("semantic_events")))
        graph = load_json(repo_path(root, row.get("behavior_graph")))
        audit = load_json(repo_path(root, row.get("behavior_audit")))
        require(errors, semantic.get("sample_class") == "benign", f"{sample_id}: semantic sample_class mismatch")
        require(errors, graph.get("sample_class") == "benign", f"{sample_id}: graph sample_class mismatch")
        require(errors, graph.get("real_malware") is False, f"{sample_id}: graph must set real_malware=false")
        require(errors, audit.get("sample_class") == "benign", f"{sample_id}: audit sample_class mismatch")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("local_linux_behavior_control") is True, "local Linux control boundary missing")
    require(errors, boundary.get("genesys2_board_trace_claimed") is False, "Genesys2 board trace must not be claimed")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")
    require(errors, boundary.get("malware_detection_accuracy_claimed") is False, "malware detection accuracy must not be claimed")
    require(errors, boundary.get("allowed_benign_overlap_is_not_false_positive") is True, "benign overlap boundary missing")
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "not genesys2/cva6 board trace evidence" in non_claims, "non_claims must reject board-trace substitution")
    require(errors, "not real-malware detection accuracy" in non_claims or "not real malware detection accuracy" in non_claims, "non_claims must reject detection accuracy")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        run = root / "build/benign_control"
        run.mkdir(parents=True)
        (run / "rvmt_benign_workload").write_text("bin\n", encoding="utf-8")
        manifest = root / "experiments/linux_behavior/benign/manifest.json"
        rules = root / "experiments/linux_behavior/behavior_audit_rules.json"
        source = root / "board/artix7_35t/linux/rvmt_benign_workload.c"
        for path in (manifest, rules, source):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n", encoding="utf-8")
        samples = []
        for sample_id in REQUIRED_SAMPLES:
            sample_dir = run / sample_id
            sample_dir.mkdir()
            for name in ("host.strace.log", "stdout.txt", "stderr.txt"):
                (sample_dir / name).write_text("fixture\n", encoding="utf-8")
            for name, payload in (
                ("semantic_events.json", {"sample_class": "benign"}),
                ("behavior_graph.json", {"sample_class": "benign", "real_malware": False}),
                ("behavior_audit.json", {"sample_class": "benign"}),
            ):
                write_json(sample_dir / name, payload)
            samples.append(
                {
                    "sample_id": sample_id,
                    "sample_class": "benign",
                    "status": "PASS",
                    "network_required": False,
                    "default_enabled": True,
                    "returncode": 0,
                    "expected_syscall_coverage": {"write": True},
                    "false_positive": False,
                    "unexpected_matched_rules": [],
                    "strace_log": (sample_dir / "host.strace.log").relative_to(root).as_posix(),
                    "stdout": (sample_dir / "stdout.txt").relative_to(root).as_posix(),
                    "stderr": (sample_dir / "stderr.txt").relative_to(root).as_posix(),
                    "semantic_events": (sample_dir / "semantic_events.json").relative_to(root).as_posix(),
                    "behavior_graph": (sample_dir / "behavior_graph.json").relative_to(root).as_posix(),
                    "behavior_audit": (sample_dir / "behavior_audit.json").relative_to(root).as_posix(),
                }
            )
        summary = {
            "schema": "rvmt.genesys2.benign_control_summary.v1",
            "status": "PASS",
            "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
            "run_root": run.relative_to(root).as_posix(),
            "source_manifest": manifest.relative_to(root).as_posix(),
            "rules": rules.relative_to(root).as_posix(),
            "wrapper_source": source.relative_to(root).as_posix(),
            "wrapper_binary": (run / "rvmt_benign_workload").relative_to(root).as_posix(),
            "toolchain": {"docker_service": "linux-behavior", "compiler": "gcc fixture", "strace": "strace fixture"},
            "aggregate": {
                "sample_count": 5,
                "non_network_sample_count": 5,
                "unexpected_false_positive_count": 0,
                "benign_false_positive_rate": 0.0,
            },
            "samples": samples,
            "claim_boundary": {
                "local_linux_behavior_control": True,
                "genesys2_board_trace_claimed": False,
                "real_malware_validation_claimed": False,
                "malware_detection_accuracy_claimed": False,
                "allowed_benign_overlap_is_not_false_positive": True,
            },
            "non_claims": [
                "Benign control evidence is local Linux behavior evidence, not Genesys2/CVA6 board trace evidence.",
                "Benign false-positive rate here is a controlled safe-workload audit metric, not real-malware detection accuracy.",
            ],
        }
        errors = check_summary(summary, root)
        if errors:
            print("[FAIL] benign control good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        summary["claim_boundary"]["genesys2_board_trace_claimed"] = True
        errors = check_summary(summary, root)
        if not errors:
            print("[FAIL] benign control bad fixture passed", file=sys.stderr)
            return 1
    print("[PASS] benign control checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check local benign-control behavior evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] missing benign control summary: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root)
    except Exception as exc:
        print(f"[FAIL] benign control checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] benign control summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] benign control summary accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
