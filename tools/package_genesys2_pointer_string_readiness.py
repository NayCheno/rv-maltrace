from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "pointer_string_readiness_summary.json"
EXTERNAL_SUMMARY_PATH = "results/evaluation/genesys2-cva6/current/external_closure/hardware_pointer_strings_summary.json"
EXPECTED_SYSCALLS = ("openat", "write", "execve")

SOURCE_EVIDENCE = (
    ("hardware_pointer_prefix_summary", DEFAULT_CURRENT_ROOT / "hardware_pointer_prefix_summary.json"),
    ("pointer_snapshot_guardrails", DEFAULT_CURRENT_ROOT / "pointer_snapshot_guardrails.json"),
    ("semantic_reconstruction_summary", DEFAULT_CURRENT_ROOT / "semantic_reconstruction_summary.json"),
    ("fd_path_graph_summary", DEFAULT_CURRENT_ROOT / "fd_path_graph_summary.json"),
    ("baseline_alignment_summary", DEFAULT_CURRENT_ROOT / "baseline_alignment_summary.json"),
    ("trace_format_arg_mem_schema", Path("docs/02-trace-architecture/trace_format.md")),
    ("cva6_signal_map_pointer_hooks", Path("docs/02-trace-architecture/signal_map.md")),
    ("rv_maltrace_cli_trace_parser", Path("src/rv_maltrace/cli.py")),
    ("package_hardware_pointer_prefixes", Path("tools/package_hardware_pointer_prefixes.py")),
    ("check_hardware_pointer_prefixes", Path("tools/check_hardware_pointer_prefixes.py")),
)


def repo_rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def repo_path(path: str | Path) -> Path:
    value = Path(path)
    return value if value.is_absolute() else ROOT / value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def evidence_row(artifact_id: str, path_value: str | Path) -> dict[str, Any]:
    path = repo_path(path_value)
    row: dict[str, Any] = {
        "id": artifact_id,
        "path": repo_rel(path),
        "exists": path.is_file(),
        "sha256": sha256_file(path) if path.is_file() else None,
    }
    if path.suffix == ".json" and path.is_file():
        try:
            data = load_json(path)
        except Exception as exc:
            row["json_error"] = str(exc)
        else:
            row["schema"] = data.get("schema")
            row["status"] = data.get("status")
    return row


def pointer_group_stats(prefix_summary: dict[str, Any]) -> dict[str, Any]:
    group_count = 0
    gapped_group_count = 0
    bounded_prefix_group_count = 0
    nul_seen_count = 0
    max_contiguous_prefix_bytes = 0
    syscall_counts = {name: 0 for name in EXPECTED_SYSCALLS}
    for sample in as_list(prefix_summary.get("samples")):
        if not isinstance(sample, dict):
            continue
        for repetition in as_list(sample.get("repetitions")):
            if not isinstance(repetition, dict):
                continue
            for group in as_list(repetition.get("groups")):
                if not isinstance(group, dict):
                    continue
                group_count += 1
                syscall_name = str(group.get("syscall_name") or "")
                if syscall_name in syscall_counts:
                    syscall_counts[syscall_name] += 1
                if as_int(group.get("gap_count")) > 0:
                    gapped_group_count += 1
                if group.get("confidence") == "bounded_hardware_prefix":
                    bounded_prefix_group_count += 1
                if group.get("nul_seen_in_contiguous_prefix") is True:
                    nul_seen_count += 1
                max_contiguous_prefix_bytes = max(max_contiguous_prefix_bytes, as_int(group.get("contiguous_prefix_bytes")))
    return {
        "observed_group_count": group_count,
        "gapped_group_count": gapped_group_count,
        "bounded_prefix_group_count": bounded_prefix_group_count,
        "nul_seen_in_contiguous_prefix_count": nul_seen_count,
        "max_contiguous_prefix_bytes": max_contiguous_prefix_bytes,
        "syscall_group_counts": syscall_counts,
    }


def package_summary(current_root: Path) -> dict[str, Any]:
    prefix_path = current_root / "hardware_pointer_prefix_summary.json"
    guardrails_path = current_root / "pointer_snapshot_guardrails.json"
    prefix = load_json(ROOT / prefix_path)
    guardrails = load_json(ROOT / guardrails_path)
    source_rows = [evidence_row(artifact_id, path) for artifact_id, path in SOURCE_EVIDENCE]
    coverage = as_dict(prefix.get("required_syscall_coverage"))
    policy = as_dict(guardrails.get("policy"))
    stats = pointer_group_stats(prefix)
    failures: list[str] = []
    if prefix.get("schema") != "rvmt.hardware_pointer_prefixes.v1" or prefix.get("status") != "PASS":
        failures.append("hardware_pointer_prefix_summary must be PASS rvmt.hardware_pointer_prefixes.v1")
    if prefix.get("hardware_pointer_bytes_observed") is not True:
        failures.append("hardware pointer bytes must be observed before full-string readiness is meaningful")
    if prefix.get("hardware_pointer_prefixes_claimed") is not True:
        failures.append("bounded hardware pointer prefixes must be claimed")
    if prefix.get("hardware_pointer_strings_claimed") is not False or prefix.get("full_string_claimed") is not False:
        failures.append("current prefix evidence must not claim full hardware pointer strings")
    if prefix.get("companion_derived_strings_as_hardware") is not False:
        failures.append("companion strings must not be reported as hardware")
    if as_int(prefix.get("kernel_fragment_count"), default=-1) != 0:
        failures.append("kernel ARG_MEM fragments must remain absent")
    if as_int(prefix.get("pointer_group_count")) <= 0 or as_int(prefix.get("captured_byte_count")) <= 0:
        failures.append("current prefix evidence must contain pointer groups and captured bytes")
    for syscall_name in EXPECTED_SYSCALLS:
        if coverage.get(syscall_name) is not True:
            failures.append(f"missing current hardware prefix syscall coverage: {syscall_name}")
    if guardrails.get("schema") != "rvmt.pointer_snapshot_guardrails.v1" or guardrails.get("status") != "PASS":
        failures.append("pointer_snapshot_guardrails must be PASS rvmt.pointer_snapshot_guardrails.v1")
    if guardrails.get("hardware_pointer_strings_claimed") is not False:
        failures.append("guardrails must not claim hardware-derived pointer strings")
    if policy.get("captures_kernel_memory") is not False or policy.get("full_memory_dump") is not False:
        failures.append("guardrails must reject kernel memory capture and full memory dumps")
    for row in source_rows:
        if row.get("exists") is not True:
            failures.append(f"missing source evidence {row.get('path')}")

    return {
        "schema": "rvmt.genesys2.pointer_string_readiness.v1",
        "status": "PASS" if not failures else "FAIL",
        "canonical_evaluation_root": repo_rel(ROOT / current_root),
        "scope": "readiness package for future full hardware pointer-string evidence on Genesys2/CVA6",
        "source_evidence": source_rows,
        "current_prefix_evidence": {
            "summary_path": repo_rel(ROOT / prefix_path),
            "summary_schema": prefix.get("schema"),
            "summary_status": prefix.get("status"),
            "run_root": prefix.get("run_root"),
            "trace_sink_mode": prefix.get("trace_sink_mode"),
            "source_record_format": prefix.get("source_record_format"),
            "total_repetitions": prefix.get("total_repetitions"),
            "sample_count": prefix.get("sample_count"),
            "pointer_group_count": prefix.get("pointer_group_count"),
            "captured_byte_count": prefix.get("captured_byte_count"),
            "required_syscall_coverage": {name: coverage.get(name) is True for name in EXPECTED_SYSCALLS},
            "hardware_pointer_bytes_observed": prefix.get("hardware_pointer_bytes_observed") is True,
            "hardware_pointer_prefixes_claimed": prefix.get("hardware_pointer_prefixes_claimed") is True,
            "hardware_pointer_strings_claimed": prefix.get("hardware_pointer_strings_claimed") is True,
            "full_string_claimed": prefix.get("full_string_claimed") is True,
            "companion_derived_strings_as_hardware": prefix.get("companion_derived_strings_as_hardware") is True,
            "kernel_fragment_count": prefix.get("kernel_fragment_count"),
            "guardrails": {
                "summary_path": repo_rel(ROOT / guardrails_path),
                "hardware_user_pointer_snapshot": guardrails.get("hardware_user_pointer_snapshot") is True,
                "hardware_pointer_strings_claimed": guardrails.get("hardware_pointer_strings_claimed") is True,
                "captures_kernel_memory": policy.get("captures_kernel_memory") is True,
                "full_memory_dump": policy.get("full_memory_dump") is True,
                "max_bytes_per_pointer": policy.get("max_bytes_per_pointer"),
                "redaction_policy": policy.get("redaction_policy"),
            },
            "observed_boundaries": {
                **stats,
                "contains_gapped_groups": stats["gapped_group_count"] > 0,
                "has_bounded_prefix_groups": stats["bounded_prefix_group_count"] > 0,
                "mem_last_observed": False,
                "groups_promoted_from_gapped_fragments": 0,
                "contiguous_offset_zero_full_string_evidence_available": False,
            },
        },
        "future_full_string_contract": {
            "required_summary_schema": "rvmt.genesys2.hardware_pointer_strings.v1",
            "external_summary_path": EXTERNAL_SUMMARY_PATH,
            "required_syscalls": list(EXPECTED_SYSCALLS),
            "minimum_requirements": {
                "contiguous_bytes_from_offset_zero_required": True,
                "terminator_or_documented_bounded_truncation_required": True,
                "mem_last_or_terminator_evidence_required": True,
                "gap_free_group_reconstruction_required": True,
                "per_group_artifact_hash_required": True,
                "companion_substitution_forbidden": True,
                "gapped_fragment_promotion_forbidden": True,
                "kernel_fragment_count_must_be_zero": True,
                "full_memory_dump_forbidden": True,
                "raw_payload_redaction_policy_required": True,
            },
            "required_evidence_artifact_kinds": [
                "rtl_design_manifest",
                "pointer_capture_manifest",
                "pointer_group_reconstruction",
                "mem_last_or_terminator_report",
                "redaction_policy",
                "kernel_space_filter_report",
                "companion_substitution_audit",
                "resource_timing_report",
            ],
            "required_summary_fields": [
                "evidence_artifacts",
                "full_string_claimed",
                "full_string_group_count",
                "pointer_groups",
                "syscall_coverage",
                "contiguous_from_offset_zero",
                "mem_last_observed",
                "companion_derived_strings_as_hardware",
                "kernel_fragment_count",
                "full_memory_dump_count",
                "redaction_policy",
                "failed_attempts",
            ],
            "acceptance_criteria": [
                "full_string_claimed=true is accepted only for pointer groups with contiguous bytes from offset 0 through a NUL terminator or a documented bounded truncation boundary",
                "mem_last_observed or an equivalent terminator report is required for every accepted full-string group",
                "gapped ARG_MEM fragments remain fragments and are not joined or promoted into full strings",
                "companion-derived qemu/strace strings are never counted as hardware-derived pointer strings",
                "kernel-space fragments, full memory dumps, and unredacted raw payload publication remain forbidden",
                "openat/write/execve coverage is reported with per-syscall accepted, rejected, and negative-case counts",
                "each accepted pointer group is backed by hashed RTL, capture, reconstruction, redaction, and resource/timing artifacts",
            ],
        },
        "claim_boundary": {
            "pointer_string_readiness_claimed": True,
            "hardware_pointer_prefix_evidence_available": True,
            "full_hardware_pointer_strings_claimed": False,
            "hardware_pointer_strings_claimed": False,
            "full_string_claimed": False,
            "bounded_prefix_substituted_for_full_strings": False,
            "companion_derived_strings_as_hardware": False,
            "raw_pointer_payload_release_claimed": False,
            "kernel_memory_capture_claimed": False,
            "full_memory_dump_claimed": False,
            "real_malware_validation_claimed": False,
            "rtl_extension_required_for_closure": True,
            "external_execution_required_for_closure": True,
        },
        "validation_commands": [
            "uv run python tools/package_genesys2_pointer_string_readiness.py",
            "uv run python tools/check_genesys2_pointer_string_readiness.py --root .",
        ],
        "non_claims": [
            "This is a readiness package and does not claim full hardware pointer-string evidence is complete.",
            "Current Genesys2/CVA6 compact BRAM ARG_MEM evidence remains bounded-prefix evidence, not full strings.",
            "Companion qemu/strace or fd/path graph strings must not be substituted for hardware-derived pointer strings.",
            "Gapped hardware fragments must not be joined into full strings without a future gap-free RTL/capture artifact.",
            "Raw pointer payload release, kernel memory capture, full memory dumps, and real-malware validation are not claimed.",
            "The future full hardware pointer-string closure gate remains OPEN_EXTERNAL_ARTIFACTS_REQUIRED until external RTL and board artifacts are accepted.",
        ],
        "failures": failures,
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        artifact = root / "artifact.json"
        write_json(artifact, {"schema": "rvmt.fixture.v1", "status": "PASS"})
        row = evidence_row("fixture", artifact)
    if row.get("exists") is not True or row.get("schema") != "rvmt.fixture.v1" or not row.get("sha256"):
        print("[FAIL] pointer string readiness packager self-test failed", file=sys.stderr)
        return 1
    print("[PASS] pointer string readiness packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package readiness evidence for future Genesys2 full hardware pointer-string runs.")
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        current_root = args.current_root
        out = args.out if args.out.is_absolute() else ROOT / args.out
        summary = package_summary(current_root)
        write_json(out, summary)
    except Exception as exc:
        print(f"package_genesys2_pointer_string_readiness: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] wrote pointer string readiness summary to {args.out}")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
