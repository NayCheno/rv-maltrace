from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any


DEFAULT_MANIFEST = Path("experiments/linux_behavior/malware_like/manifest.json")
DEFAULT_RUN_ROOT = Path("results/board/genesys2_cva6_safe_surrogate/genesys2-cva6-safe-p2-20260610")
SUMMARY_FILE = "safe_surrogate_summary.json"
SAFE_SAMPLE_CLASSES = {"malware_like_synthetic", "surrogate"}
EXPECTED_BOARD = "Digilent Genesys2"
EXPECTED_CPU = "CVA6"
REQUIRED_DIRECT_ARTIFACTS = (
    "sample_metadata.json",
    "hardware_trace/trace.jsonl",
    "hardware_trace/trace_summary.json",
    "local_code_analysis/code_map.json",
    "local_code_analysis/static_analysis.json",
    "local_code_analysis/source_attribution.json",
    "local_code_analysis/source_attribution_summary.json",
    "integrated_validation.json",
)
BEHAVIOR_ARTIFACT_OPTIONS = (
    "malware_analysis/behavior_mapping.json",
    "malware_analysis/behavior_report.md",
)
REQUIRED_NON_CLAIM_TOKENS = (
    "No real malware validation",
    "No real malware detection",
    "No real malware payload",
)
FORBIDDEN_ALLOWED_CLAIM_TOKENS = (
    "real malware",
    "malware detection",
    "35T",
)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            rows.append(value)
    return rows


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def display(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def nonempty(path: Path) -> bool:
    return path.is_file() and path.stat().st_size > 0


def contains_forbidden_legacy_reference(value: Any) -> bool:
    return "35t" in json.dumps(value, sort_keys=True).lower()


def iter_real_malware_flags(value: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}"
            if key == "real_malware":
                yield child, item
            yield from iter_real_malware_flags(item, child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from iter_real_malware_flags(item, f"{path}[{index}]")


def samples_by_manifest_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = manifest.get("samples")
    if not isinstance(rows, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("id"), str):
            result[row["id"]] = row
    return result


def samples_by_summary_id(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = summary.get("samples")
    if not isinstance(rows, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("sample_id"), str):
            result[row["sample_id"]] = row
    return result


def check_manifest_sample(root: Path, sample_id: str, row: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    label = f"manifest:{sample_id}"
    if row.get("class") not in SAFE_SAMPLE_CLASSES:
        errors.append(f"{label}: class must be safe synthetic/surrogate")
    if row.get("real_malware") is not False:
        errors.append(f"{label}: real_malware must be false")
    if row.get("destructive") is not False:
        errors.append(f"{label}: destructive must be false")
    if row.get("network_required") is not False:
        errors.append(f"{label}: network_required must be false")
    if row.get("provenance") != "repository_source":
        errors.append(f"{label}: provenance must be repository_source")
    source = row.get("source")
    if not isinstance(source, str) or not nonempty(resolve(root, Path(source))):
        errors.append(f"{label}: repository source missing or empty")
    if contains_forbidden_legacy_reference(row):
        errors.append(f"{label}: must not reference legacy board evidence")
    return errors


def sample_dir_from_summary(root: Path, run_root: Path, row: dict[str, Any], sample_id: str) -> Path:
    integrated = row.get("integrated_validation")
    if isinstance(integrated, str):
        return resolve(root, Path(integrated)).parent
    return run_root / sample_id


def missing_artifacts(sample_dir: Path) -> list[str]:
    missing = [relative for relative in REQUIRED_DIRECT_ARTIFACTS if not nonempty(sample_dir / relative)]
    if not any(nonempty(sample_dir / relative) for relative in BEHAVIOR_ARTIFACT_OPTIONS):
        missing.append("malware_analysis/behavior_mapping.json or malware_analysis/behavior_report.md")
    return missing


def check_claim_boundaries(label: str, value: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    allowed = value.get("allowed_claims", [])
    non_claims = value.get("non_claims", [])
    allowed_text = "\n".join(str(item) for item in allowed)
    for token in FORBIDDEN_ALLOWED_CLAIM_TOKENS:
        if token.lower() in allowed_text.lower():
            errors.append(f"{label}: allowed_claims must not contain {token!r}")
    non_claim_text = "\n".join(str(item) for item in non_claims)
    for token in REQUIRED_NON_CLAIM_TOKENS:
        if token.lower() not in non_claim_text.lower():
            errors.append(f"{label}: non_claims must include {token!r}")
    return errors


def check_json_boundaries(label: str, value: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if contains_forbidden_legacy_reference(value):
        errors.append(f"{label}: must not reference legacy board evidence")
    for path, item in iter_real_malware_flags(value):
        if item is not False:
            errors.append(f"{label}: {path} must be false")
    return errors


def check_complete_sample(
    root: Path,
    sample_id: str,
    sample_dir: Path,
    summary_row: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    status = summary_row.get("status")
    if not isinstance(status, str) or not status.startswith("PASS_SAFE_SURROGATE"):
        errors.append(f"{sample_id}: run summary status must start with PASS_SAFE_SURROGATE")

    json_artifacts = (
        ("metadata", sample_dir / "sample_metadata.json"),
        ("hardware trace summary", sample_dir / "hardware_trace/trace_summary.json"),
        ("static analysis", sample_dir / "local_code_analysis/static_analysis.json"),
        ("source attribution summary", sample_dir / "local_code_analysis/source_attribution_summary.json"),
        ("integrated validation", sample_dir / "integrated_validation.json"),
    )
    for label, path in json_artifacts:
        try:
            value = load_json(path)
        except Exception as exc:
            errors.append(f"{display(path, root)}: cannot parse {label}: {exc}")
            continue
        errors.extend(check_json_boundaries(f"{sample_id} {label}", value))
        if value.get("sample_id") != sample_id:
            errors.append(f"{sample_id} {label}: sample_id mismatch")
        if label in {"metadata", "hardware trace summary", "static analysis", "integrated validation"}:
            if value.get("sample_class") not in SAFE_SAMPLE_CLASSES:
                errors.append(f"{sample_id} {label}: sample_class must be safe")
        if label == "hardware trace summary":
            if value.get("board") != EXPECTED_BOARD:
                errors.append(f"{sample_id}: hardware board mismatch")
            if value.get("cpu") != EXPECTED_CPU:
                errors.append(f"{sample_id}: hardware cpu mismatch")
        if label == "integrated validation":
            errors.extend(check_claim_boundaries(f"{sample_id} integrated validation", value))

    behavior_mapping = sample_dir / "malware_analysis/behavior_mapping.json"
    if behavior_mapping.exists():
        try:
            behavior = load_json(behavior_mapping)
        except Exception as exc:
            errors.append(f"{display(behavior_mapping, root)}: cannot parse behavior mapping: {exc}")
        else:
            errors.extend(check_json_boundaries(f"{sample_id} behavior mapping", behavior))
            if behavior.get("sample_id") != sample_id:
                errors.append(f"{sample_id} behavior mapping: sample_id mismatch")
            if behavior.get("sample_class") not in SAFE_SAMPLE_CLASSES:
                errors.append(f"{sample_id} behavior mapping: sample_class must be safe")

    trace_path = sample_dir / "hardware_trace/trace.jsonl"
    try:
        if not load_jsonl(trace_path):
            errors.append(f"{display(trace_path, root)}: trace must contain at least one decoded event")
    except Exception as exc:
        errors.append(f"{display(trace_path, root)}: cannot parse trace: {exc}")
    return errors


def build_report(root: Path, manifest_path: Path, run_root_path: Path) -> tuple[dict[str, Any], list[str]]:
    manifest_full = resolve(root, manifest_path)
    run_root = resolve(root, run_root_path)
    errors: list[str] = []
    if not manifest_full.is_file():
        return {}, [f"missing manifest: {display(manifest_full, root)}"]
    if not run_root.is_dir():
        return {}, [f"missing run root: {display(run_root, root)}"]
    summary_path = run_root / SUMMARY_FILE
    if not summary_path.is_file():
        return {}, [f"missing run summary: {display(summary_path, root)}"]

    manifest = load_json(manifest_full)
    summary = load_json(summary_path)
    if summary.get("board") != EXPECTED_BOARD:
        errors.append(f"{display(summary_path, root)}: board must be {EXPECTED_BOARD}")
    if summary.get("cpu") != EXPECTED_CPU:
        errors.append(f"{display(summary_path, root)}: cpu must be {EXPECTED_CPU}")
    errors.extend(check_json_boundaries("run summary", summary))
    errors.extend(check_claim_boundaries("run summary", summary))

    manifest_samples = samples_by_manifest_id(manifest)
    summary_samples = samples_by_summary_id(summary)
    if not manifest_samples:
        errors.append(f"{display(manifest_full, root)}: samples must be nonempty")

    sample_reports: list[dict[str, Any]] = []
    for sample_id in sorted(manifest_samples):
        manifest_row = manifest_samples[sample_id]
        manifest_errors = check_manifest_sample(root, sample_id, manifest_row)
        summary_row = summary_samples.get(sample_id)
        if summary_row is None:
            errors.extend(manifest_errors)
            sample_reports.append(
                {
                    "sample_id": sample_id,
                    "source": manifest_row.get("source"),
                    "sample_class": manifest_row.get("class"),
                    "real_malware": manifest_row.get("real_malware"),
                    "status": "NOT_RUN",
                    "present_in_run_summary": False,
                    "missing_artifacts": list(REQUIRED_DIRECT_ARTIFACTS)
                    + ["malware_analysis/behavior_mapping.json or malware_analysis/behavior_report.md"],
                    "errors": manifest_errors,
                }
            )
            continue

        sample_dir = sample_dir_from_summary(root, run_root, summary_row, sample_id)
        missing = missing_artifacts(sample_dir)
        sample_errors = manifest_errors
        if not missing:
            sample_errors.extend(check_complete_sample(root, sample_id, sample_dir, summary_row))
        errors.extend(sample_errors)
        status = "PASS_SAFE_SURROGATE_EVIDENCE_CHAIN" if not missing and not sample_errors else "INCOMPLETE"
        sample_reports.append(
            {
                "sample_id": sample_id,
                "source": manifest_row.get("source"),
                "sample_class": manifest_row.get("class"),
                "real_malware": manifest_row.get("real_malware"),
                "status": status,
                "present_in_run_summary": True,
                "sample_dir": display(sample_dir, root),
                "missing_artifacts": missing,
                "errors": sample_errors,
            }
        )

    extra_summary_samples = sorted(set(summary_samples) - set(manifest_samples))
    for sample_id in extra_summary_samples:
        errors.append(f"{display(summary_path, root)}: unexpected sample outside manifest: {sample_id}")

    complete = [row for row in sample_reports if row["status"] == "PASS_SAFE_SURROGATE_EVIDENCE_CHAIN"]
    incomplete = [row for row in sample_reports if row["status"] != "PASS_SAFE_SURROGATE_EVIDENCE_CHAIN"]
    if incomplete:
        errors.append(f"safe surrogate manifest coverage incomplete: {len(complete)}/{len(sample_reports)} samples complete")
    report = {
        "schema": "rvmt.genesys2.safe_surrogate.manifest_coverage.v1",
        "manifest": display(manifest_full, root),
        "run_root": display(run_root, root),
        "run_summary": display(summary_path, root),
        "run_id": summary.get("run_id", run_root.name),
        "board": EXPECTED_BOARD,
        "cpu": EXPECTED_CPU,
        "sample_class": manifest.get("sample_class"),
        "real_malware": False,
        "status": "PASS" if not incomplete and not errors else "INCOMPLETE",
        "complete_samples": len(complete),
        "total_samples": len(sample_reports),
        "missing_samples": [row["sample_id"] for row in incomplete],
        "samples": sample_reports,
        "allowed_claims": [
            "Genesys2/CVA6 safe synthetic/surrogate evidence chains are complete only for samples marked PASS in this report.",
        ],
        "non_claims": [
            "No real malware validation is demonstrated.",
            "No real malware detection quality or efficacy is claimed.",
            "No real malware payload, source, or binary is present in the repository.",
            "Samples marked NOT_RUN or INCOMPLETE are not current hardware evidence.",
        ],
    }
    return report, errors


def write_sample_fixture(root: Path, run_root: Path, sample_id: str, source: str) -> dict[str, Any]:
    sample_dir = run_root / sample_id
    source_path = root / source
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    write_json(
        sample_dir / "sample_metadata.json",
        {
            "sample_id": sample_id,
            "sample_class": "malware_like_synthetic",
            "real_malware": False,
            "network_required": False,
            "destructive": False,
        },
    )
    (sample_dir / "hardware_trace/trace.jsonl").parent.mkdir(parents=True, exist_ok=True)
    (sample_dir / "hardware_trace/trace.jsonl").write_text('{"evt": "SYSCALL_ENTRY", "a7": "0x40"}\n', encoding="utf-8")
    write_json(
        sample_dir / "hardware_trace/trace_summary.json",
        {
            "sample_id": sample_id,
            "sample_class": "malware_like_synthetic",
            "real_malware": False,
            "board": EXPECTED_BOARD,
            "cpu": EXPECTED_CPU,
        },
    )
    write_json(sample_dir / "local_code_analysis/code_map.json", {"sample_id": sample_id, "real_malware": False})
    write_json(
        sample_dir / "local_code_analysis/static_analysis.json",
        {"sample_id": sample_id, "sample_class": "malware_like_synthetic", "real_malware": False},
    )
    (sample_dir / "local_code_analysis/source_attribution.json").write_text(
        '{"evt": "SYSCALL_ENTRY", "pc_owner": "target_sample"}\n',
        encoding="utf-8",
    )
    write_json(sample_dir / "local_code_analysis/source_attribution_summary.json", {"sample_id": sample_id, "real_malware": False})
    write_json(
        sample_dir / "malware_analysis/behavior_mapping.json",
        {"sample_id": sample_id, "sample_class": "malware_like_synthetic", "real_malware": False},
    )
    write_json(
        sample_dir / "integrated_validation.json",
        {
            "sample_id": sample_id,
            "sample_class": "malware_like_synthetic",
            "real_malware": False,
            "allowed_claims": ["Genesys2/CVA6 safe synthetic surrogate evidence is present."],
            "non_claims": [
                "No real malware validation is demonstrated.",
                "No real malware detection quality or efficacy is claimed.",
                "No real malware payload, source, or binary is present in the repository.",
            ],
        },
    )
    return {
        "sample_id": sample_id,
        "sample_class": "malware_like_synthetic",
        "real_malware": False,
        "status": "PASS_SAFE_SURROGATE_EVIDENCE_CHAIN_WITH_LIMITATIONS",
        "integrated_validation": display(sample_dir / "integrated_validation.json", root),
    }


def write_fixture(root: Path, include_beta_evidence: bool = True) -> tuple[Path, Path]:
    manifest_path = root / DEFAULT_MANIFEST
    run_root = root / DEFAULT_RUN_ROOT
    samples = [
        {
            "id": "alpha",
            "class": "malware_like_synthetic",
            "status": "TODO(EXPERIMENT)",
            "provenance": "repository_source",
            "real_malware": False,
            "destructive": False,
            "network_required": False,
            "source": "experiments/linux_behavior/malware_like/programs/alpha.c",
            "command": ["./alpha"],
            "evidence_dir": "01_alpha",
            "expected_syscalls": ["write"],
            "expected_behavior": ["alpha"],
        },
        {
            "id": "beta",
            "class": "malware_like_synthetic",
            "status": "TODO(EXPERIMENT)",
            "provenance": "repository_source",
            "real_malware": False,
            "destructive": False,
            "network_required": False,
            "source": "experiments/linux_behavior/malware_like/programs/beta.c",
            "command": ["./beta"],
            "evidence_dir": "02_beta",
            "expected_syscalls": ["write"],
            "expected_behavior": ["beta"],
        },
    ]
    write_json(
        manifest_path,
        {
            "phase": "fixture",
            "sample_class": "malware_like_synthetic",
            "samples": samples,
        },
    )
    summary_samples = [write_sample_fixture(root, run_root, "alpha", samples[0]["source"])]
    if include_beta_evidence:
        summary_samples.append(write_sample_fixture(root, run_root, "beta", samples[1]["source"]))
    else:
        beta_source = root / samples[1]["source"]
        beta_source.parent.mkdir(parents=True, exist_ok=True)
        beta_source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    write_json(
        run_root / SUMMARY_FILE,
        {
            "schema": "rvmt.genesys2.safe_surrogate.run_summary.v1",
            "run_id": "fixture",
            "board": EXPECTED_BOARD,
            "cpu": EXPECTED_CPU,
            "real_malware": False,
            "allowed_claims": ["Genesys2/CVA6 safe synthetic surrogate evidence is present."],
            "non_claims": [
                "No real malware validation is demonstrated.",
                "No real malware detection quality or efficacy is claimed.",
                "No real malware payload, source, or binary is present in the repository.",
            ],
            "samples": summary_samples,
        },
    )
    return manifest_path, run_root


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest, run_root = write_fixture(root)
        _report, errors = build_report(root, manifest, run_root)
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest, run_root = write_fixture(root, include_beta_evidence=False)
        _report, errors = build_report(root, manifest, run_root)
        if not any("1/2 samples complete" in error for error in errors):
            print("[FAIL] self-test missed incomplete manifest coverage", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest, run_root = write_fixture(root)
        summary_path = run_root / SUMMARY_FILE
        summary = load_json(summary_path)
        summary["board"] = "Arty A7 35T"
        write_json(summary_path, summary)
        _report, errors = build_report(root, manifest, run_root)
        if not any("legacy board evidence" in error for error in errors):
            print("[FAIL] self-test missed legacy evidence reference", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest, run_root = write_fixture(root)
        static_path = run_root / "alpha/local_code_analysis/static_analysis.json"
        static = load_json(static_path)
        static["real_malware"] = True
        write_json(static_path, static)
        _report, errors = build_report(root, manifest, run_root)
        if not any("real_malware" in error for error in errors):
            print("[FAIL] self-test missed real malware flag", file=sys.stderr)
            return 1

    print("[PASS] Genesys2 safe surrogate manifest coverage self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check full Genesys2/CVA6 safe surrogate manifest coverage.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--allow-incomplete", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    try:
        root = args.root.resolve()
        report, errors = build_report(root, args.manifest, args.run_root)
        if args.json_out:
            write_json(resolve(root, args.json_out), report)
    except Exception as exc:
        print(f"check_genesys2_safe_surrogate_coverage: error: {exc}", file=sys.stderr)
        return 2

    if errors:
        for error in errors:
            prefix = "[WARN]" if args.allow_incomplete and "coverage incomplete" in error else "[FAIL]"
            print(f"{prefix} {error}", file=sys.stderr)
        if args.allow_incomplete and all("coverage incomplete" in error for error in errors):
            print(
                "[WARN] Genesys2/CVA6 safe surrogate manifest coverage is incomplete; report generated for status tracking"
            )
            return 0
        return 1
    print("[PASS] Genesys2/CVA6 safe surrogate manifest coverage is complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
