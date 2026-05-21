from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from rv_maltrace.fd_path_flow import load_semantic_events as load_fd_events  # noqa: E402
from rv_maltrace.fd_path_flow import recover_fd_path_flow  # noqa: E402
from rv_maltrace.fd_path_flow import render_markdown as render_fd_markdown  # noqa: E402
from rv_maltrace.process_tree import load_semantic_events as load_process_events  # noqa: E402
from rv_maltrace.process_tree import recover_process_tree  # noqa: E402
from rv_maltrace.process_tree import render_markdown as render_process_markdown  # noqa: E402
from summarize_35t_source_attribution import build_summary as build_source_summary  # noqa: E402
from summarize_35t_source_attribution import render_markdown as render_source_markdown  # noqa: E402
from check_35t_board_validation import check_board_validation  # noqa: E402


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_RESULTS_ROOT = Path("results/experiments/35t") / RUN_ID
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / RUN_ID
DEFAULT_OUT_DIR = DEFAULT_RESULTS_ROOT / "board_validation_bundle"
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
FD_PATH_SAMPLES = ("file_scan", "batch_open_read_write", "self_copy_sim")
PROCESS_TREE_SAMPLES = ("process_chain",)
REQUIRED_OUTPUT_ARTIFACTS = (
    "run_config.json",
    "gate_report.json",
    "gate_report.md",
    "fd_path_flow_summary.json",
    "fd_path_flow_summary.md",
    "process_tree_summary.json",
    "process_tree_summary.md",
    "source_attribution_summary.json",
    "source_attribution_summary.md",
    "command_log.md",
)
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def repo_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def file_record(path: Path, repo_root: Path, *, artifact: str, source_path: Path | None, mode: str) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "artifact": artifact,
        "bundle_path": rel(path, repo_root),
        "source_path": rel(source_path, repo_root) if source_path is not None else None,
        "mode": mode,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def clear_known_outputs(out_dir: Path) -> None:
    for name in [*REQUIRED_OUTPUT_ARTIFACTS, "bundle_manifest.json", "bundle_manifest.md"]:
        path = out_dir / name
        if path.exists():
            path.unlink()


def copy_if_present(
    artifact: str,
    candidates: list[Path],
    out_dir: Path,
    repo_root: Path,
    records: list[dict[str, Any]],
    missing: list[dict[str, Any]],
) -> None:
    dest = out_dir / artifact
    for candidate in candidates:
        if candidate.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(candidate, dest)
            records.append(file_record(dest, repo_root, artifact=artifact, source_path=candidate, mode="copied"))
            return
    missing.append(
        {
            "artifact": artifact,
            "candidate_sources": [rel(path, repo_root) for path in candidates],
            "reason": "source artifact missing",
        }
    )


def semantic_event_paths(results_root: Path, sample: str) -> list[Path]:
    base = results_root / "samples" / "malware_like_synthetic" / sample / "board" / "trace-on"
    return [base / f"rep_{rep:02d}" / "behavior_recovery" / "semantic_events.json" for rep in range(5)]


def status_rank(status: Any) -> int:
    return {"PASS": 3, "PARTIAL": 2, "UNAVAILABLE": 1}.get(str(status), 0)


def select_best_summary(candidates: list[dict[str, Any]], score_key: str) -> dict[str, Any] | None:
    if not candidates:
        return None
    return max(candidates, key=lambda row: (status_rank(row["summary"].get("status")), int(row.get(score_key, 0))))


def unavailable_fd_summary(reason: str) -> dict[str, Any]:
    return {
        "schema": "rvmt.fd_path_flow.summary.v1",
        "sample": "unavailable",
        "status": "UNAVAILABLE",
        "flows": [],
        "execve_events": [],
        "return_only_fd_ops": [],
        "return_only_execve_events": [],
        "unresolved_fds": [],
        "unresolved_paths": [],
        "pending_openats": [],
        "open_fds_at_end": [],
        "observed_counts": {"flows": 0, "execve_events": 0, "return_only_fd_ops": 0, "pending_openats": 0, "unresolved_fds": 0},
        "limitations": [reason],
        "non_claims": NON_CLAIMS[-3:],
    }


def unavailable_process_summary(reason: str) -> dict[str, Any]:
    return {
        "schema": "rvmt.process_tree.summary.v1",
        "sample": "process_chain",
        "status": "UNAVAILABLE",
        "root_process": "target_process",
        "processes": [],
        "edges": [],
        "clone_return_candidates": [],
        "wait_pid_candidates": [],
        "unmatched_clone_return_candidates": [],
        "pending_exec_paths": [],
        "events": [],
        "observed_counts": {"clone_or_fork": 0, "execve": 0, "wait": 0},
        "limitations": [reason],
        "non_claims": NON_CLAIMS[-3:],
    }


def write_fd_summary(results_root: Path, out_dir: Path, repo_root: Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    existing_json = results_root / "fd_path_flow_summary.json"
    existing_md = results_root / "fd_path_flow_summary.md"
    if existing_json.exists() and existing_md.exists():
        shutil.copyfile(existing_json, out_dir / "fd_path_flow_summary.json")
        shutil.copyfile(existing_md, out_dir / "fd_path_flow_summary.md")
        records.append(file_record(out_dir / "fd_path_flow_summary.json", repo_root, artifact="fd_path_flow_summary.json", source_path=existing_json, mode="copied"))
        records.append(file_record(out_dir / "fd_path_flow_summary.md", repo_root, artifact="fd_path_flow_summary.md", source_path=existing_md, mode="copied"))
        return load_json(out_dir / "fd_path_flow_summary.json")

    candidates: list[dict[str, Any]] = []
    for sample in FD_PATH_SAMPLES:
        for path in semantic_event_paths(results_root, sample):
            if not path.exists():
                continue
            summary = recover_fd_path_flow(load_fd_events(path), sample=sample)
            candidates.append(
                {
                    "sample": sample,
                    "semantic_events": path,
                    "summary": summary,
                    "flow_count": len(summary.get("flows", [])),
                }
            )
    selected = select_best_summary(candidates, "flow_count")
    if selected is None:
        summary = unavailable_fd_summary("no fd/path semantic_events.json files were found under the source run")
    else:
        summary = dict(selected["summary"])
        summary["selected_candidate"] = {
            "sample": selected["sample"],
            "semantic_events": rel(selected["semantic_events"], repo_root),
        }
        summary["candidate_status_counts"] = {
            status: sum(1 for row in candidates if row["summary"].get("status") == status)
            for status in ("PASS", "PARTIAL", "UNAVAILABLE")
        }
        summary["bundle_selection_policy"] = "select the strongest fd/path candidate without upgrading its status"
    write_json(out_dir / "fd_path_flow_summary.json", summary)
    (out_dir / "fd_path_flow_summary.md").write_text(render_fd_markdown(summary), encoding="utf-8", newline="\n")
    records.append(file_record(out_dir / "fd_path_flow_summary.json", repo_root, artifact="fd_path_flow_summary.json", source_path=None, mode="generated_from_semantic_events"))
    records.append(file_record(out_dir / "fd_path_flow_summary.md", repo_root, artifact="fd_path_flow_summary.md", source_path=None, mode="generated_from_semantic_events"))
    return summary


def write_process_summary(results_root: Path, out_dir: Path, repo_root: Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    existing_json = results_root / "process_tree_summary.json"
    existing_md = results_root / "process_tree_summary.md"
    if existing_json.exists() and existing_md.exists():
        shutil.copyfile(existing_json, out_dir / "process_tree_summary.json")
        shutil.copyfile(existing_md, out_dir / "process_tree_summary.md")
        records.append(file_record(out_dir / "process_tree_summary.json", repo_root, artifact="process_tree_summary.json", source_path=existing_json, mode="copied"))
        records.append(file_record(out_dir / "process_tree_summary.md", repo_root, artifact="process_tree_summary.md", source_path=existing_md, mode="copied"))
        return load_json(out_dir / "process_tree_summary.json")

    candidates: list[dict[str, Any]] = []
    for sample in PROCESS_TREE_SAMPLES:
        for path in semantic_event_paths(results_root, sample):
            if not path.exists():
                continue
            summary = recover_process_tree(load_process_events(path), sample=sample)
            candidates.append(
                {
                    "sample": sample,
                    "semantic_events": path,
                    "summary": summary,
                    "edge_count": len(summary.get("edges", [])),
                }
            )
    selected = select_best_summary(candidates, "edge_count")
    if selected is None:
        summary = unavailable_process_summary("no process-chain semantic_events.json files were found under the source run")
    else:
        summary = dict(selected["summary"])
        summary["selected_candidate"] = {
            "sample": selected["sample"],
            "semantic_events": rel(selected["semantic_events"], repo_root),
        }
        summary["candidate_status_counts"] = {
            status: sum(1 for row in candidates if row["summary"].get("status") == status)
            for status in ("PASS", "PARTIAL", "UNAVAILABLE")
        }
        summary["bundle_selection_policy"] = "select the strongest process-tree candidate without upgrading its status"
    write_json(out_dir / "process_tree_summary.json", summary)
    (out_dir / "process_tree_summary.md").write_text(render_process_markdown(summary), encoding="utf-8", newline="\n")
    records.append(file_record(out_dir / "process_tree_summary.json", repo_root, artifact="process_tree_summary.json", source_path=None, mode="generated_from_semantic_events"))
    records.append(file_record(out_dir / "process_tree_summary.md", repo_root, artifact="process_tree_summary.md", source_path=None, mode="generated_from_semantic_events"))
    return summary


def write_source_summary(results_root: Path, out_dir: Path, repo_root: Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    existing_json = results_root / "source_attribution_summary.json"
    existing_md = results_root / "source_attribution_summary.md"
    if existing_json.exists() and existing_md.exists():
        shutil.copyfile(existing_json, out_dir / "source_attribution_summary.json")
        shutil.copyfile(existing_md, out_dir / "source_attribution_summary.md")
        records.append(file_record(out_dir / "source_attribution_summary.json", repo_root, artifact="source_attribution_summary.json", source_path=existing_json, mode="copied"))
        records.append(file_record(out_dir / "source_attribution_summary.md", repo_root, artifact="source_attribution_summary.md", source_path=existing_md, mode="copied"))
        return load_json(out_dir / "source_attribution_summary.json")

    summary = build_source_summary(results_root)
    write_json(out_dir / "source_attribution_summary.json", summary)
    (out_dir / "source_attribution_summary.md").write_text(render_source_markdown(summary), encoding="utf-8", newline="\n")
    records.append(file_record(out_dir / "source_attribution_summary.json", repo_root, artifact="source_attribution_summary.json", source_path=None, mode="generated_from_code_maps"))
    records.append(file_record(out_dir / "source_attribution_summary.md", repo_root, artifact="source_attribution_summary.md", source_path=None, mode="generated_from_code_maps"))
    return summary


def write_generated_command_log(out_dir: Path, repo_root: Path, records: list[dict[str, Any]]) -> None:
    path = out_dir / "command_log.md"
    lines = [
        f"# 35T Board Validation Bundle Command Log: {RUN_ID}",
        "",
        f"Generated UTC: {utc_now()}",
        "",
        "Scope: Artix-7 35T / LiteX / VexRiscv only.",
        "",
        f"Claim level: {EXPECTED_CLAIM_LEVEL}.",
        "",
        "This log records bundle packaging only. It does not assert that a new board run passed.",
        "",
        "## Non-claims",
        "",
    ]
    lines.extend(f"- {item}" for item in NON_CLAIMS)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    records.append(file_record(path, repo_root, artifact="command_log.md", source_path=None, mode="generated_packaging_log"))


def render_manifest_markdown(manifest: dict[str, Any]) -> str:
    lines = [
        f"# 35T Board Validation Bundle Manifest: {manifest['source_run_id']}",
        "",
        f"Status: {manifest['status']}",
        "",
        f"Checker status: {manifest['checker_status']}",
        "",
        f"Hardware validated: {str(manifest['hardware_validated']).lower()}",
        "",
        "Scope: Artix-7 35T / LiteX / VexRiscv only.",
        "",
        f"Claim level: {manifest['claim_level']}.",
        "",
        "## Selected Summaries",
        "",
        f"- fd/path flow: {manifest['selected_statuses']['fd_path_flow']}",
        f"- process tree: {manifest['selected_statuses']['process_tree']}",
        f"- source attribution: {manifest['selected_statuses']['source_attribution']}",
        "",
        "## Artifacts",
        "",
    ]
    for item in manifest["artifacts"]:
        lines.append(f"- {item['artifact']}: {item['mode']} ({item['bytes']} bytes)")
    if manifest["missing_artifacts"]:
        lines += ["", "## Missing", ""]
        for item in manifest["missing_artifacts"]:
            lines.append(f"- {item['artifact']}: {item['reason']}")
    lines += ["", "## Checker Failures", ""]
    if manifest["checker_failures"]:
        for item in manifest["checker_failures"]:
            lines.append(f"- {item}")
    else:
        lines.append("- none")
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in manifest["non_claims"])
    return "\n".join(lines) + "\n"


def package_bundle(
    repo_root: Path,
    source_results_root_arg: Path,
    evidence_root_arg: Path,
    out_dir_arg: Path,
    command_log_arg: Path | None,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    source_results_root = repo_path(repo_root, source_results_root_arg).resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    out_dir = repo_path(repo_root, out_dir_arg).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    clear_known_outputs(out_dir)

    records: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    copy_if_present(
        "run_config.json",
        [source_results_root / "run_config.json"],
        out_dir,
        repo_root,
        records,
        missing,
    )
    copy_if_present(
        "gate_report.json",
        [source_results_root / "aggregate" / "gate_report.json", source_results_root / "gate_report.json"],
        out_dir,
        repo_root,
        records,
        missing,
    )
    copy_if_present(
        "gate_report.md",
        [source_results_root / "aggregate" / "gate_report.md", source_results_root / "gate_report.md"],
        out_dir,
        repo_root,
        records,
        missing,
    )

    fd_summary = write_fd_summary(source_results_root, out_dir, repo_root, records)
    process_summary = write_process_summary(source_results_root, out_dir, repo_root, records)
    source_summary = write_source_summary(source_results_root, out_dir, repo_root, records)

    command_log_source = repo_path(repo_root, command_log_arg).resolve() if command_log_arg else evidence_root / "command_log.md"
    if command_log_source.exists():
        shutil.copyfile(command_log_source, out_dir / "command_log.md")
        records.append(file_record(out_dir / "command_log.md", repo_root, artifact="command_log.md", source_path=command_log_source, mode="copied"))
    else:
        write_generated_command_log(out_dir, repo_root, records)

    run_config_path = out_dir / "run_config.json"
    validation_run_id = source_results_root.name
    if run_config_path.exists():
        try:
            run_config = load_json(run_config_path)
            if isinstance(run_config.get("run_id"), str) and run_config.get("run_id"):
                validation_run_id = str(run_config["run_id"])
        except Exception:
            validation_run_id = source_results_root.name

    provisional_manifest = {
        "schema": "rvmt.35t.board_validation_bundle.v1",
        "source_run_id": RUN_ID,
        "validation_run_id": validation_run_id,
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
    }
    write_json(out_dir / "bundle_manifest.json", provisional_manifest)
    checker_report = check_board_validation(repo_root, evidence_root, out_dir, require_results=True, write_outputs=False)
    checker_status = checker_report["status"]
    status = "PASS" if checker_status == "PASS" else "CANDIDATE_PARTIAL"
    manifest = {
        "schema": "rvmt.35t.board_validation_bundle.v1",
        "source_run_id": RUN_ID,
        "validation_run_id": validation_run_id,
        "generated_utc": utc_now(),
        "status": status,
        "checker_status": checker_status,
        "hardware_validated": checker_report["hardware_validated"],
        "source_results_root": rel(source_results_root, repo_root),
        "evidence_root": rel(evidence_root, repo_root),
        "bundle_root": rel(out_dir, repo_root),
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "selected_statuses": {
            "fd_path_flow": fd_summary.get("status"),
            "process_tree": process_summary.get("status"),
            "source_attribution": source_summary.get("status"),
        },
        "artifacts": sorted(records, key=lambda row: row["artifact"]),
        "missing_artifacts": missing,
        "checker_failures": checker_report["failures"],
        "required_output_artifacts": list(REQUIRED_OUTPUT_ARTIFACTS),
        "non_claims": NON_CLAIMS,
    }
    write_json(out_dir / "bundle_manifest.json", manifest)
    (out_dir / "bundle_manifest.md").write_text(render_manifest_markdown(manifest), encoding="utf-8", newline="\n")
    return manifest


def write_semantic(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json(path, {"schema": "rvmt.behavior.semantic.v1", "syscall_sequence": rows})


def write_self_test_run(root: Path, results: Path, *, complete: bool, run_id: str = RUN_ID) -> None:
    results.mkdir(parents=True)
    write_json(results / "run_config.json", {"run_id": run_id, "trace_records": 512, "trace_profile_policy": "35t_small_capacity"})
    aggregate = results / "aggregate"
    aggregate.mkdir()
    write_json(
        aggregate / "gate_report.json",
        {
            "schema": "rvmt.35t.next_gate.v2",
            "run_id": run_id,
            "trace_records": 512,
            "trace_profile_policy": "35t_small_capacity",
            "sample_status": {"file_scan": {"status": "PASS"}, "process_chain": {"status": "PASS"}},
        },
    )
    (aggregate / "gate_report.md").write_text("# gate\n", encoding="utf-8", newline="\n")
    fd_rows = [
        {
            "seq": 0,
            "name": "openat",
            "process_owner": "target_child",
            "args": {"a0": "0xffffffffffffff9c", "a1": "0x1000", "a1_string": "/tmp/a"} if complete else {"a0": "0xffffffffffffff9c", "a1": "0x1000"},
            "return_value": "0x3",
            "confidence": "paired_target_ecall_return",
        },
        {
            "seq": 1,
            "name": "read",
            "process_owner": "target_child",
            "args": {"a0": "0x3", "a1": "0x2000", "a2": "0x10"},
            "return_value": "0x10",
            "confidence": "paired_target_ecall_return",
        },
        {
            "seq": 2,
            "name": "close",
            "process_owner": "target_child",
            "args": {"a0": "0x3"},
            "return_value": "0x0",
            "confidence": "paired_target_ecall_return",
        },
    ]
    write_semantic(
        results / "samples/malware_like_synthetic/file_scan/board/trace-on/rep_00/behavior_recovery/semantic_events.json",
        fd_rows,
    )
    process_rows = [
        {
            "seq": 0,
            "name": "clone",
            "process_owner": "target_child",
            "args": {"a0": "0x11"},
            "return_value": "0x7b" if complete else "0x0",
            "confidence": "paired_target_ecall_return",
        },
        {
            "seq": 1,
            "name": "execve",
            "process_owner": "target_child",
            "args": {"a0": "0x1000", "a0_string": "/usr/bin/child"} if complete else {"a0": "0x1000"},
            "return_value": None,
            "confidence": "target_ecall_boundary",
        },
        {
            "seq": 2,
            "name": "waitid",
            "process_owner": "target_child",
            "args": {"a0": "0x1", "a1": "0x7b"},
            "return_value": "0x0",
            "confidence": "paired_target_ecall_return",
        },
    ]
    write_semantic(
        results / "samples/malware_like_synthetic/process_chain/board/trace-on/rep_00/behavior_recovery/semantic_events.json",
        process_rows,
    )
    for sample in ("illegal_trap", "process_chain", "dynamic_executable_memory", "file_scan", "batch_open_read_write", "self_copy_sim"):
        code_dir = results / "samples/malware_like_synthetic" / sample / "build"
        code_dir.mkdir(parents=True, exist_ok=True)
        write_json(
            code_dir / f"{sample}.code_map.json",
            {
                "schema": "rvmt.code_map.v1",
                "symbols": [{"name": "main", "start": "0x1000", "end": "0x1010", "type": 2}],
                "function_ranges": [{"function": "main", "start": "0x1000", "end": "0x1010", "confidence": "symbol_table"}],
                "source_locations": [],
            },
        )


def write_self_test_evidence(evidence: Path) -> None:
    evidence.mkdir(parents=True)
    write_json(
        evidence / "board_validation_plan.json",
        {
            "schema": "rvmt.35t.targeted_board_validation_plan.v1",
            "source_run_id": RUN_ID,
            "scope": EXPECTED_SCOPE,
            "claim_level": EXPECTED_CLAIM_LEVEL,
            "status": "AWAITING_BOARD_RUN",
            "board_validation_required": True,
            "hardware_validated": False,
            "required_capture_items": ["target-scoped marker begin/end"],
            "non_claims": NON_CLAIMS,
        },
    )
    (evidence / "command_log.md").write_text("# self-test command log\n", encoding="utf-8", newline="\n")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        evidence = root / DEFAULT_EVIDENCE_ROOT
        write_self_test_evidence(evidence)

        complete_results = root / "complete-results"
        write_self_test_run(root, complete_results, complete=True, run_id="35t-targeted-board-validation-self-test")
        complete_out = root / "complete-bundle"
        complete_manifest = package_bundle(root, complete_results, DEFAULT_EVIDENCE_ROOT, complete_out, None)
        if complete_manifest["status"] != "PASS" or not complete_manifest["hardware_validated"]:
            print("[FAIL] expected complete self-test bundle to pass board-validation checker", file=sys.stderr)
            print(json.dumps(complete_manifest, indent=2), file=sys.stderr)
            return 1
        if complete_manifest.get("validation_run_id") != "35t-targeted-board-validation-self-test":
            print("[FAIL] expected package manifest to preserve validation_run_id", file=sys.stderr)
            return 1

        partial_results = root / "partial-results"
        write_self_test_run(root, partial_results, complete=False)
        partial_out = root / "partial-bundle"
        partial_manifest = package_bundle(root, partial_results, DEFAULT_EVIDENCE_ROOT, partial_out, None)
        if partial_manifest["status"] == "PASS" or partial_manifest["hardware_validated"]:
            print("[FAIL] expected partial self-test bundle not to pass board-validation checker", file=sys.stderr)
            print(json.dumps(partial_manifest, indent=2), file=sys.stderr)
            return 1
    print("[PASS] 35T board validation bundle packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package a 35T run into a targeted board-validation result bundle.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--source-run-id", default=RUN_ID)
    parser.add_argument("--source-results-root", type=Path)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--command-log", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.source_run_id != RUN_ID:
        print(f"package_35t_board_validation: error: unsupported 35T source run id: {args.source_run_id}", file=sys.stderr)
        return 2
    source_results_root = args.source_results_root or Path("results/experiments/35t") / args.source_run_id
    out_dir = args.out_dir or Path("results/experiments/35t") / args.source_run_id / "board_validation_bundle"
    try:
        manifest = package_bundle(args.repo_root, source_results_root, args.evidence_root, out_dir, args.command_log)
    except Exception as exc:
        print(f"package_35t_board_validation: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{manifest['status']}] 35T board validation bundle at {manifest['bundle_root']}")
    if manifest["checker_failures"]:
        for failure in manifest["checker_failures"]:
            print(f"CHECKER: {failure}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
