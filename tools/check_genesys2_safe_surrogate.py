from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    write_json,
)


DEFAULT_RUN_ROOT = Path("results/board/genesys2_cva6_safe_surrogate/genesys2-cva6-safe-p2-20260610")
SUMMARY_FILE = "safe_surrogate_summary.json"
REQUIRED_SAMPLE_ARTIFACTS = {
    "sample_metadata.json",
    "hardware_trace/trace.jsonl",
    "hardware_trace/trace_summary.json",
    "local_code_analysis/code_map.json",
    "local_code_analysis/static_analysis.json",
    "local_code_analysis/source_attribution.json",
    "malware_analysis/behavior_mapping.json",
    "integrated_validation.json",
}
REQUIRED_NON_CLAIM_TOKENS = (
    "No real malware validation",
    "No real malware detection",
    "No real malware payload",
    "No single continuous",
    "No strong runtime process attribution",
)
FORBIDDEN_ALLOWED_CLAIM_TOKENS = (
    "real malware",
    "35T",
    "detection quality",
    "malware detection",
)
SAFE_SAMPLE_CLASSES = {"malware_like_synthetic", "surrogate"}
DANGEROUS_STATIC_FLAGS = (
    "destructive",
    "network_activity_expected",
    "network_required",
    "persistence",
    "privilege_escalation",
    "process_mutation",
    "real_payload",
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{index}: expected JSON object")
        events.append(value)
    return events


def resolve_repo_path(root: Path, path: str | Path) -> Path:
    value = Path(path)
    return value if value.is_absolute() else root / value


def require(condition: bool, errors: list[str], message: str) -> None:
    if not condition:
        errors.append(message)


def require_false(value: Any, errors: list[str], message: str) -> None:
    if value is not False:
        errors.append(message)


def iter_real_malware_flags(value: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if key == "real_malware":
                yield child_path, item
            yield from iter_real_malware_flags(item, child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from iter_real_malware_flags(item, f"{path}[{index}]")


def check_real_malware_flags(label: str, value: dict[str, Any], errors: list[str]) -> None:
    for path, item in iter_real_malware_flags(value):
        if item is not False:
            errors.append(f"{label}: {path} must be false")


def check_claim_boundaries(label: str, allowed_claims: list[Any], non_claims: list[Any], errors: list[str]) -> None:
    allowed_text = "\n".join(str(item) for item in allowed_claims)
    for token in FORBIDDEN_ALLOWED_CLAIM_TOKENS:
        if token.lower() in allowed_text.lower():
            errors.append(f"{label}: allowed_claims must not contain {token!r}")
    non_claim_text = "\n".join(str(item) for item in non_claims)
    for token in REQUIRED_NON_CLAIM_TOKENS:
        if token.lower() not in non_claim_text.lower():
            errors.append(f"{label}: non_claims must include boundary token {token!r}")


def check_required_artifacts(sample_dir: Path, errors: list[str]) -> None:
    for relative in sorted(REQUIRED_SAMPLE_ARTIFACTS):
        path = sample_dir / relative
        if not path.exists():
            errors.append(f"{sample_dir}: missing required artifact {relative}")


def check_hardware_trace(sample_dir: Path, summary: dict[str, Any], trace_events: list[dict[str, Any]], errors: list[str]) -> None:
    label = str(sample_dir / "hardware_trace/trace_summary.json")
    require(summary.get("board") == "Digilent Genesys2", errors, f"{label}: board must be Digilent Genesys2")
    require(summary.get("cpu") == "CVA6", errors, f"{label}: cpu must be CVA6")
    require(summary.get("real_malware") is False, errors, f"{label}: real_malware must be false")
    require(summary.get("sample_class") in SAFE_SAMPLE_CLASSES, errors, f"{label}: sample_class must be safe")
    require("35T" not in json.dumps(summary), errors, f"{label}: must not use 35T evidence")
    require(trace_events, errors, f"{label}: trace.jsonl must contain decoded events")

    requirements = summary.get("requirements")
    if isinstance(requirements, dict):
        for name, result in requirements.items():
            if isinstance(result, dict) and result.get("pass") is not True:
                errors.append(f"{label}: requirement {name} must pass")

    if summary.get("sample_id") == "illegal_trap":
        require(
            any(event.get("evt") == "SYSCALL_ENTRY" and event.get("a7") == "0x0000000000000040" for event in trace_events),
            errors,
            f"{label}: illegal_trap must include SYSCALL_ENTRY a7=0x40",
        )
        require(
            any(event.get("evt") == "TRAP" and event.get("cause") == "0x0000000000000002" for event in trace_events),
            errors,
            f"{label}: illegal_trap must include TRAP cause=0x2",
        )


def check_local_code_analysis(sample_dir: Path, static_analysis: dict[str, Any], source_summary: dict[str, Any], errors: list[str]) -> None:
    label = str(sample_dir / "local_code_analysis")
    require(static_analysis.get("real_malware") is False, errors, f"{label}: static_analysis.real_malware must be false")
    require(static_analysis.get("sample_class") in SAFE_SAMPLE_CLASSES, errors, f"{label}: sample_class must be safe")
    flags = static_analysis.get("capability_flags")
    if not isinstance(flags, dict):
        errors.append(f"{label}: static_analysis.capability_flags must exist")
    else:
        for flag in DANGEROUS_STATIC_FLAGS:
            require_false(flags.get(flag), errors, f"{label}: capability_flags.{flag} must be false")
    policy = static_analysis.get("policy")
    require(isinstance(policy, dict), errors, f"{label}: static_analysis.policy must exist")
    if isinstance(policy, dict):
        require(
            policy.get("no_real_malware_payload_source_or_binary") is True,
            errors,
            f"{label}: policy must forbid real malware payload/source/binary",
        )
    require(
        source_summary.get("target_attributed_events", 0) >= 1,
        errors,
        f"{label}: source attribution must include at least one target-attributed event",
    )
    require(
        source_summary.get("runtime_process_attribution_proven") is not True,
        errors,
        f"{label}: current safe surrogate must not overclaim runtime process attribution",
    )


def check_behavior_mapping(sample_dir: Path, mapping: dict[str, Any], errors: list[str]) -> None:
    label = str(sample_dir / "malware_analysis/behavior_mapping.json")
    require(mapping.get("real_malware") is False, errors, f"{label}: real_malware must be false")
    require(mapping.get("sample_class") in SAFE_SAMPLE_CLASSES, errors, f"{label}: sample_class must be safe")
    manual_chain = mapping.get("manual_evidence_chain")
    require(isinstance(manual_chain, list) and bool(manual_chain), errors, f"{label}: manual_evidence_chain must exist")
    if isinstance(manual_chain, list):
        for index, item in enumerate(manual_chain):
            if isinstance(item, dict):
                require(item.get("pass") is True, errors, f"{label}: manual_evidence_chain[{index}].pass must be true")
            else:
                errors.append(f"{label}: manual_evidence_chain[{index}] must be an object")
    automated = mapping.get("automated_audit")
    require(isinstance(automated, dict), errors, f"{label}: automated_audit must exist")
    if isinstance(automated, dict):
        weak = automated.get("weak_matched_expected_behavior", [])
        strong = automated.get("all_expected_matched")
        require(
            strong is True or bool(weak),
            errors,
            f"{label}: automated audit must provide strong or weak expected behavior evidence",
        )


def check_integrated_validation(sample_dir: Path, integrated: dict[str, Any], errors: list[str]) -> None:
    label = str(sample_dir / "integrated_validation.json")
    require(integrated.get("real_malware") is False, errors, f"{label}: real_malware must be false")
    require(integrated.get("sample_class") in SAFE_SAMPLE_CLASSES, errors, f"{label}: sample_class must be safe")
    required = integrated.get("required_artifacts")
    require(isinstance(required, dict), errors, f"{label}: required_artifacts must exist")
    if isinstance(required, dict):
        for name, value in required.items():
            require(value is True, errors, f"{label}: required_artifacts[{name!r}] must be true")
    checks = integrated.get("checks")
    require(isinstance(checks, dict), errors, f"{label}: checks must exist")
    if isinstance(checks, dict):
        for name, value in checks.items():
            require(value is True, errors, f"{label}: checks[{name!r}] must be true")
    check_claim_boundaries(label, integrated.get("allowed_claims", []), integrated.get("non_claims", []), errors)


def check_sample(root: Path, sample: dict[str, Any], errors: list[str]) -> None:
    sample_id = sample.get("sample_id")
    integrated_path = sample.get("integrated_validation")
    if not isinstance(sample_id, str):
        errors.append("run summary: sample_id must be a string")
        return
    if not isinstance(integrated_path, str):
        errors.append(f"run summary: {sample_id}.integrated_validation must be a path")
        return

    sample_dir = resolve_repo_path(root, integrated_path).parent
    check_required_artifacts(sample_dir, errors)
    if any(not (sample_dir / relative).exists() for relative in REQUIRED_SAMPLE_ARTIFACTS):
        return

    metadata = load_json(sample_dir / "sample_metadata.json")
    hardware_summary = load_json(sample_dir / "hardware_trace/trace_summary.json")
    trace_events = load_jsonl(sample_dir / "hardware_trace/trace.jsonl")
    static_analysis = load_json(sample_dir / "local_code_analysis/static_analysis.json")
    source_summary = load_json(sample_dir / "local_code_analysis/source_attribution_summary.json")
    behavior_mapping = load_json(sample_dir / "malware_analysis/behavior_mapping.json")
    integrated = load_json(sample_dir / "integrated_validation.json")

    for label, artifact in (
        ("sample metadata", metadata),
        ("hardware trace summary", hardware_summary),
        ("static analysis", static_analysis),
        ("behavior mapping", behavior_mapping),
        ("integrated validation", integrated),
    ):
        check_real_malware_flags(f"{sample_id} {label}", artifact, errors)

    for artifact_name, artifact in (
        ("metadata", metadata),
        ("hardware summary", hardware_summary),
        ("static analysis", static_analysis),
        ("behavior mapping", behavior_mapping),
        ("integrated validation", integrated),
    ):
        require(artifact.get("sample_id") == sample_id, errors, f"{sample_id} {artifact_name}: sample_id mismatch")

    require(metadata.get("sample_class") in SAFE_SAMPLE_CLASSES, errors, f"{sample_id}: sample metadata class must be safe")
    require(metadata.get("real_malware") is False, errors, f"{sample_id}: sample metadata real_malware must be false")
    require(metadata.get("network_required") is False, errors, f"{sample_id}: sample metadata network_required must be false")
    require(metadata.get("destructive") is False, errors, f"{sample_id}: sample metadata destructive must be false")
    require("35T" not in json.dumps(metadata), errors, f"{sample_id}: metadata must not use 35T evidence")

    check_hardware_trace(sample_dir, hardware_summary, trace_events, errors)
    check_local_code_analysis(sample_dir, static_analysis, source_summary, errors)
    check_behavior_mapping(sample_dir, behavior_mapping, errors)
    check_integrated_validation(sample_dir, integrated, errors)


def run_checks(root: Path, run_root: Path) -> list[str]:
    errors: list[str] = []
    run_dir = resolve_repo_path(root, run_root)
    summary_path = run_dir / SUMMARY_FILE
    if not summary_path.exists():
        return [f"missing run summary: {summary_path}"]
    summary = load_json(summary_path)
    require(summary.get("schema") == "rvmt.genesys2.safe_surrogate.run_summary.v1", errors, f"{summary_path}: schema mismatch")
    require(summary.get("board") == "Digilent Genesys2", errors, f"{summary_path}: board must be Digilent Genesys2")
    require(summary.get("cpu") == "CVA6", errors, f"{summary_path}: cpu must be CVA6")
    require("35T" not in json.dumps(summary), errors, f"{summary_path}: must not use 35T evidence")
    check_claim_boundaries(str(summary_path), summary.get("allowed_claims", []), summary.get("non_claims", []), errors)
    check_real_malware_flags(str(summary_path), summary, errors)

    samples = summary.get("samples")
    if not isinstance(samples, list) or not samples:
        errors.append(f"{summary_path}: samples must be a nonempty list")
        return errors
    for sample in samples:
        if not isinstance(sample, dict):
            errors.append(f"{summary_path}: sample entries must be objects")
            continue
        require(sample.get("real_malware") is False, errors, f"{summary_path}: {sample.get('sample_id')}.real_malware must be false")
        require(sample.get("sample_class") in SAFE_SAMPLE_CLASSES, errors, f"{summary_path}: {sample.get('sample_id')}.sample_class must be safe")
        check_sample(root, sample, errors)
    return errors


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def write_fixture(root: Path) -> None:
    run_dir = root / DEFAULT_RUN_ROOT
    sample_dir = run_dir / "illegal_trap"
    trace_events = [
        {"evt": "SYSCALL_ENTRY", "a7": "0x0000000000000040", "pc": "0x000100f8"},
        {"evt": "TRAP", "cause": "0x0000000000000002", "pc": "0x8025aef8"},
    ]
    write_json(
        run_dir / SUMMARY_FILE,
        {
            "schema": "rvmt.genesys2.safe_surrogate.run_summary.v1",
            "run_id": "genesys2-cva6-safe-p2-fixture",
            "board": "Digilent Genesys2",
            "cpu": "CVA6",
            "allowed_claims": ["Genesys2/CVA6 safe synthetic surrogate trace evidence is present."],
            "non_claims": [
                "No real malware validation is demonstrated.",
                "No real malware detection quality or efficacy is claimed.",
                "No real malware payload, source, or binary is present in the repository.",
                "No single continuous entry/trap/return hardware trace window is claimed.",
                "No strong runtime process attribution is claimed without PID/SATP/ASID/marker evidence.",
            ],
            "samples": [
                {
                    "sample_id": "illegal_trap",
                    "sample_class": "malware_like_synthetic",
                    "real_malware": False,
                    "status": "PASS_SAFE_SURROGATE_EVIDENCE_CHAIN_WITH_LIMITATIONS",
                    "hardware_trace": str(sample_dir / "hardware_trace/trace_summary.json"),
                    "local_code_analysis": str(sample_dir / "local_code_analysis/source_attribution_summary.json"),
                    "malware_analysis": str(sample_dir / "malware_analysis/behavior_mapping.json"),
                    "integrated_validation": str(sample_dir / "integrated_validation.json"),
                }
            ],
        },
    )
    write_json(
        sample_dir / "sample_metadata.json",
        {
            "sample_id": "illegal_trap",
            "sample_class": "malware_like_synthetic",
            "real_malware": False,
            "network_required": False,
            "destructive": False,
        },
    )
    write_text(sample_dir / "hardware_trace/trace.jsonl", "\n".join(json.dumps(event) for event in trace_events) + "\n")
    write_json(
        sample_dir / "hardware_trace/trace_summary.json",
        {
            "schema": "rvmt.genesys2.safe_surrogate.hardware_trace_summary.v1",
            "sample_id": "illegal_trap",
            "sample_class": "malware_like_synthetic",
            "real_malware": False,
            "board": "Digilent Genesys2",
            "cpu": "CVA6",
            "requirements": {
                "target_write_syscall_entry": {"pass": True},
                "illegal_instruction_trap_cause": {"pass": True},
            },
        },
    )
    write_json(sample_dir / "hardware_trace/capture_manifest.json", {"sample_id": "illegal_trap", "real_malware": False})
    write_json(sample_dir / "local_code_analysis/code_map.json", {"sample_id": "illegal_trap"})
    write_json(
        sample_dir / "local_code_analysis/static_analysis.json",
        {
            "sample_id": "illegal_trap",
            "sample_class": "malware_like_synthetic",
            "real_malware": False,
            "capability_flags": {flag: False for flag in DANGEROUS_STATIC_FLAGS},
            "policy": {"no_real_malware_payload_source_or_binary": True},
        },
    )
    write_json(sample_dir / "local_code_analysis/source_attribution.json", {"sample_id": "illegal_trap"})
    write_json(
        sample_dir / "local_code_analysis/source_attribution_summary.json",
        {
            "sample_id": "illegal_trap",
            "target_attributed_events": 1,
            "runtime_process_attribution_proven": False,
        },
    )
    write_json(
        sample_dir / "malware_analysis/behavior_mapping.json",
        {
            "sample_id": "illegal_trap",
            "sample_class": "malware_like_synthetic",
            "real_malware": False,
            "automated_audit": {"all_expected_matched": False, "weak_matched_expected_behavior": ["illegal_instruction_trap"]},
            "manual_evidence_chain": [{"pass": True}],
        },
    )
    write_json(
        sample_dir / "integrated_validation.json",
        {
            "sample_id": "illegal_trap",
            "sample_class": "malware_like_synthetic",
            "real_malware": False,
            "required_artifacts": {relative: True for relative in REQUIRED_SAMPLE_ARTIFACTS if relative != "sample_metadata.json"},
            "checks": {"write_syscall_entry_captured": True, "trap_cause2_captured": True},
            "allowed_claims": ["Genesys2/CVA6 safe synthetic surrogate trace evidence is present."],
            "non_claims": [
                "No real malware validation is demonstrated.",
                "No real malware detection quality or efficacy is claimed.",
                "No real malware payload, source, or binary is present in the repository.",
                "No single continuous entry/trap/return hardware trace window is claimed.",
                "No strong runtime process attribution is claimed without PID/SATP/ASID/marker evidence.",
            ],
        },
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = run_checks(root, DEFAULT_RUN_ROOT)
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1

    mutations = (
        ("missing artifact", lambda root: (root / DEFAULT_RUN_ROOT / "illegal_trap/hardware_trace/trace.jsonl").unlink(), "missing required artifact"),
        (
            "real malware flag",
            lambda root: write_json(
                root / DEFAULT_RUN_ROOT / "illegal_trap/local_code_analysis/static_analysis.json",
                {
                    "sample_id": "illegal_trap",
                    "sample_class": "malware_like_synthetic",
                    "real_malware": True,
                    "capability_flags": {flag: False for flag in DANGEROUS_STATIC_FLAGS},
                    "policy": {"no_real_malware_payload_source_or_binary": True},
                },
            ),
            "real_malware",
        ),
        (
            "allowed real malware claim",
            lambda root: write_json(
                root / DEFAULT_RUN_ROOT / "illegal_trap/integrated_validation.json",
                {
                    "sample_id": "illegal_trap",
                    "sample_class": "malware_like_synthetic",
                    "real_malware": False,
                    "required_artifacts": {relative: True for relative in REQUIRED_SAMPLE_ARTIFACTS if relative != "sample_metadata.json"},
                    "checks": {"write_syscall_entry_captured": True, "trap_cause2_captured": True},
                    "allowed_claims": ["Real malware detection is validated."],
                    "non_claims": [
                        "No real malware validation is demonstrated.",
                        "No real malware detection quality or efficacy is claimed.",
                        "No real malware payload, source, or binary is present in the repository.",
                        "No single continuous entry/trap/return hardware trace window is claimed.",
                        "No strong runtime process attribution is claimed without PID/SATP/ASID/marker evidence.",
                    ],
                },
            ),
            "allowed_claims",
        ),
        (
            "missing trap event",
            lambda root: write_text(
                root / DEFAULT_RUN_ROOT / "illegal_trap/hardware_trace/trace.jsonl",
                json.dumps({"evt": "SYSCALL_ENTRY", "a7": "0x0000000000000040"}) + "\n",
            ),
            "TRAP cause=0x2",
        ),
        (
            "wrong board",
            lambda root: write_json(
                root / DEFAULT_RUN_ROOT / SUMMARY_FILE,
                {**load_json(root / DEFAULT_RUN_ROOT / SUMMARY_FILE), "board": "Arty A7 35T"},
            ),
            "Digilent Genesys2",
        ),
    )
    for name, mutate, expected in mutations:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            mutate(root)
            errors = run_checks(root, DEFAULT_RUN_ROOT)
            if not any(expected in error for error in errors):
                print(f"[FAIL] self-test missed {name}: expected {expected}", file=sys.stderr)
                return 1

    print("[PASS] Genesys2 safe surrogate evidence self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Genesys2/CVA6 safe surrogate evidence chains.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    try:
        errors = run_checks(args.root.resolve(), args.run_root)
    except Exception as exc:
        print(f"check_genesys2_safe_surrogate: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] Genesys2/CVA6 safe surrogate evidence chain is gated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
