from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

from experiment_common import (
    load_json,
    load_jsonl,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULT_ROOT = Path("results/experiments/35t")
BENIGN_MANIFEST = Path("experiments/linux_behavior/benign/manifest.json")
MALWARE_MANIFEST = Path("experiments/linux_behavior/malware_like/manifest.json")
RULES_PATH = Path("experiments/linux_behavior/behavior_audit_rules.json")
TRACE_ON = "trace-on"
FOCUS_RULE_BY_SAMPLE = {
    "file_scan": "many_file_scan",
    "self_copy_sim": "self_copy_simulation",
    "abnormal_syscall_sequence": "abnormal_syscall_sequence",
    "dynamic_executable_memory": "dynamic_executable_memory",
    "process_chain": "process_creation_chain",
}
PROCESS_SYSCALLS = {"clone", "execve", "waitid", "wait4", "waitpid"}


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def repo_rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def parse_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.startswith("0x") else int(value, 10)
        except ValueError:
            return None
    return None


def syscall_arg(row: dict[str, Any], arg: str) -> Any:
    args = row.get("args")
    if isinstance(args, dict) and arg in args:
        return args[arg]
    return row.get(arg)


def event_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        evt = str(event.get("evt", "NONE"))
        counts[evt] = counts.get(evt, 0) + 1
    return dict(sorted(counts.items()))


def load_rules(path: Path) -> dict[str, dict[str, Any]]:
    spec = load_json(path)
    return {str(rule["id"]): rule for rule in spec.get("rules", []) if isinstance(rule, dict) and isinstance(rule.get("id"), str)}


def load_samples(selectors: Iterable[str]) -> list[dict[str, Any]]:
    wanted = {item for item in selectors if item}
    rows: list[dict[str, Any]] = []
    for manifest_path, sample_class in ((BENIGN_MANIFEST, "benign"), (MALWARE_MANIFEST, "malware_like_synthetic")):
        manifest = load_json(resolve(manifest_path))
        for row in manifest.get("samples", []):
            if not isinstance(row, dict):
                continue
            if sample_class == "benign" and (row.get("default_enabled") is not True or row.get("network_required")):
                continue
            item = dict(row)
            item["sample_class"] = sample_class
            rows.append(item)
    if not wanted:
        return [row for row in rows if row.get("id") in FOCUS_RULE_BY_SAMPLE]
    selected = [row for row in rows if str(row.get("id")) in wanted or str(row.get("sample_class")) in wanted]
    found = {str(row.get("id")) for row in selected} | {str(row.get("sample_class")) for row in selected}
    missing = sorted(wanted - found)
    if missing:
        raise ValueError(f"unknown sample selectors: {', '.join(missing)}")
    return selected


def sample_root(run_root: Path, sample: dict[str, Any]) -> Path:
    return run_root / "samples" / str(sample["sample_class"]) / str(sample["id"])


def syscall_rows(semantic: dict[str, Any]) -> list[dict[str, Any]]:
    rows = semantic.get("syscall_sequence", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def syscall_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for row in rows:
        args = row.get("args") if isinstance(row.get("args"), dict) else {}
        result.append(
            {
                "seq": row.get("seq"),
                "name": row.get("name"),
                "nr": row.get("nr"),
                "a0": args.get("a0"),
                "a1": args.get("a1"),
                "a2": args.get("a2"),
                "a3": args.get("a3"),
                "a4": args.get("a4"),
                "a5": args.get("a5"),
                "a6": args.get("a6"),
                "a7": row.get("a7"),
                "return_value": row.get("return_value"),
                "confidence": row.get("confidence"),
                "number_source": row.get("number_source"),
                "pc_owner": row.get("pc_owner"),
                "callsite_kind": row.get("callsite_kind"),
                "return_pc_owner": (row.get("return") or {}).get("return_pc_owner") if isinstance(row.get("return"), dict) else None,
            }
        )
    return result


def scoped_boundaries(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for index, event in enumerate(events):
        evt = event.get("evt")
        if evt not in {"TRAP", "ECALL", "SYSCALL_ENTRY", "SYSCALL_RET"}:
            continue
        if event.get("pc_owner") != "target_sample" and event.get("evt") not in {"SYSCALL_ENTRY", "SYSCALL_RET"}:
            continue
        if event.get("pc_owner") == "kernel" and event.get("evt") == "TRAP":
            continue
        rows.append(
            {
                "index": index,
                "evt": evt,
                "pc": event.get("pc"),
                "target": event.get("target"),
                "pc_owner": event.get("pc_owner"),
                "callsite_kind": event.get("callsite_kind"),
                "instr": event.get("instr"),
                "cause": event.get("cause"),
                "syscall_id": event.get("syscall_id"),
                "a7": event.get("a7"),
                "a0": event.get("a0"),
                "a1": event.get("a1"),
                "a2": event.get("a2"),
                "duration": event.get("duration"),
            }
        )
    return rows


def syscall_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        name = str(row.get("name", "unknown"))
        counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items()))


def target_attribution(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        owner = str(row.get("pc_owner", "unknown"))
        counts[owner] = counts.get(owner, 0) + 1
    return dict(sorted(counts.items()))


def expected_rule_match(audit: dict[str, Any], rule_id: str) -> dict[str, Any]:
    for row in audit.get("matches", []):
        if isinstance(row, dict) and row.get("rule") == rule_id:
            return row
    return {"rule": rule_id, "matched": False, "missing": ["rule_not_evaluated"]}


def source_strings(sample: dict[str, Any]) -> list[str]:
    source = sample.get("source")
    if not isinstance(source, str):
        return []
    path = resolve(Path(source))
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    return sorted(set(match.group(1) for match in re.finditer(r'"([^"\\]*(?:\\.[^"\\]*)*)"', text)))


def self_copy_tag_provenance(semantic: dict[str, Any], static_strings: list[str]) -> dict[str, Any]:
    tags = semantic.get("evidence_tags", [])
    trace_tags = {str(item) for item in tags if isinstance(item, str)} if isinstance(tags, list) else set()
    return {
        "trace_evidence_tags": sorted(trace_tags),
        "static_has_self_path": any("/proc/self/exe" in item for item in static_strings),
        "static_has_executable_output": any("/tmp/rvmt_self_copy_sim.bin" in item for item in static_strings),
        "self_path_provenance": "trace" if "self_path" in trace_tags else ("static_string_only" if any("/proc/self/exe" in item for item in static_strings) else "missing"),
        "executable_output_provenance": "trace"
        if "executable_output" in trace_tags
        else ("static_string_only" if any("/tmp/rvmt_self_copy_sim.bin" in item for item in static_strings) else "missing"),
    }


def wait_syscall_present(name: str) -> bool:
    return name in {"waitid", "wait4", "waitpid"}


def ordered_process_chain(rows: list[dict[str, Any]], *, waitid_only: bool = False) -> bool:
    index = 0
    for row in rows:
        name = str(row.get("name"))
        if index == 0 and name == "clone":
            index = 1
        elif index == 1 and name == "execve":
            index = 2
        elif index == 2 and (name == "waitid" if waitid_only else wait_syscall_present(name)):
            return True
    return False


def process_chain_evidence(rows: list[dict[str, Any]]) -> dict[str, Any]:
    process_rows = [row for row in rows if str(row.get("name")) in PROCESS_SYSCALLS]
    clone_parent_pids: list[int] = []
    wait_pid_args: list[int] = []
    for row in process_rows:
        if row.get("name") == "clone":
            value = parse_int(row.get("return_value"))
            if value is not None and value > 0 and value < (1 << 31):
                clone_parent_pids.append(value)
        if row.get("name") == "waitid":
            value = parse_int(syscall_arg(row, "a1"))
            if value is not None:
                wait_pid_args.append(value)
        if row.get("name") in {"wait4", "waitpid"}:
            value = parse_int(syscall_arg(row, "a0"))
            if value is not None:
                wait_pid_args.append(value)
    by_name: dict[str, int] = {}
    target_by_name: dict[str, int] = {}
    for row in process_rows:
        name = str(row.get("name"))
        by_name[name] = by_name.get(name, 0) + 1
        if row.get("pc_owner") == "target_sample":
            target_by_name[name] = target_by_name.get(name, 0) + 1
    return {
        "process_syscall_counts": dict(sorted(by_name.items())),
        "process_syscalls": syscall_summary(process_rows),
        "clone_exec_wait_like_order": ordered_process_chain(process_rows),
        "clone_exec_waitid_order": ordered_process_chain(process_rows, waitid_only=True),
        "target_attribution": {
            "target_scoped_counts": dict(sorted(target_by_name.items())),
            "target_has_clone_exec_waitid": all(target_by_name.get(name, 0) > 0 for name in ("clone", "execve", "waitid")),
        },
        "parent_child_boundary": {
            "clone_parent_return_pids": clone_parent_pids,
            "wait_pid_args": wait_pid_args,
            "clone_pid_wait_pid_overlap": sorted(set(clone_parent_pids) & set(wait_pid_args)),
            "proven": bool(set(clone_parent_pids) & set(wait_pid_args)),
        },
    }


def classify_missing(rule_id: str, match: dict[str, Any], rows: list[dict[str, Any]], semantic: dict[str, Any]) -> dict[str, Any]:
    counts = syscall_counts(rows)
    missing: list[str] = []
    for key in ("missing", "count_failures", "sequence_failures", "arg_failures", "tag_failures", "strong_failures"):
        values = match.get(key, [])
        if isinstance(values, list):
            missing.extend(str(item) for item in values)
    if match.get("matched"):
        return {
            "category": "recovered_strong",
            "missing_reason": "none",
            "detail": "Strong rule evidence is present.",
        }
    if rule_id == "process_creation_chain" and match.get("weak_behavior"):
        process = process_chain_evidence(rows)
        strong_failures = set(str(item) for item in match.get("strong_failures", []) if isinstance(item, str))
        if "target_process_syscall_attribution" in strong_failures:
            return {
                "category": "target_attribution",
                "missing_reason": "target_process_syscall_attribution",
                "detail": "Weak process_chain_shape is present, but clone/execve/waitid are not all target_sample attributed.",
            }
        if "parent_child_wait_boundary" in strong_failures:
            return {
                "category": "process_boundary_attribution",
                "missing_reason": "parent_child_wait_boundary",
                "detail": "Weak process_chain_shape is present, but clone parent return pid cannot be tied to the wait syscall pid argument.",
            }
        if process.get("clone_exec_wait_like_order"):
            return {
                "category": "rule_condition",
                "missing_reason": ", ".join(missing) or "process-chain strong condition",
                "detail": "Weak process_chain_shape is present, but a strong process_creation_chain condition is not satisfied.",
            }
    if match.get("weak_behavior"):
        return {
            "category": "recovered_expected_weak_shape",
            "missing_reason": ", ".join(match.get("weak_behavior", [])),
            "detail": "; ".join(match.get("weak_reasons", [])) or "Expected weak shape is present.",
        }
    if rule_id == "many_file_scan":
        if counts.get("openat", 0) >= 1 and counts.get("getdents64", 0) >= 2 and counts.get("close", 0) == 0:
            return {
                "category": "p0c_profile_limitation",
                "missing_reason": "close boundary not recovered",
                "detail": "openat and repeated getdents64 are stable; close is absent from recovered syscall rows.",
            }
        return {"category": "syscall_boundary_recovery", "missing_reason": ", ".join(missing) or "shape missing", "detail": "file scan syscall shape is incomplete."}
    if rule_id == "self_copy_simulation":
        if match.get("tag_failures"):
            return {
                "category": "p0c_profile_limitation",
                "missing_reason": "path evidence tags not trace-proven",
                "detail": "p0c has ARG_MEM disabled, so path strings and fd-flow tags are not trace-proven.",
            }
        if match.get("sequence_failures") or match.get("count_failures"):
            return {"category": "syscall_boundary_recovery", "missing_reason": ", ".join(missing), "detail": "copy syscall sequence is incomplete or reordered."}
    if rule_id == "abnormal_syscall_sequence":
        if "failed_syscall_return" in match.get("missing", []):
            return {
                "category": "return_value_decoding",
                "missing_reason": "failed_syscall_return",
                "detail": "Check RV32 negative errno values such as 0xfffffxxx as failed Linux returns.",
            }
    if rule_id == "dynamic_executable_memory":
        if match.get("arg_failures"):
            if counts.get("mmap", 0) and counts.get("mprotect", 0):
                return {
                    "category": "argument_recovery",
                    "missing_reason": ", ".join(str(item) for item in match.get("arg_failures", [])),
                    "detail": "mmap/mprotect order is present but mprotect PROT_EXEC argument bits are not proven.",
                }
            return {"category": "syscall_boundary_recovery", "missing_reason": ", ".join(missing), "detail": "mmap/mprotect boundary is incomplete."}
    if rule_id == "process_creation_chain":
        process = process_chain_evidence(rows)
        strong_failures = set(str(item) for item in match.get("strong_failures", []) if isinstance(item, str))
        if "target_process_syscall_attribution" in strong_failures:
            return {
                "category": "target_attribution",
                "missing_reason": "target_process_syscall_attribution",
                "detail": "clone/execve/waitid are not all target_sample attributed.",
            }
        if "parent_child_wait_boundary" in strong_failures:
            return {
                "category": "process_boundary_attribution",
                "missing_reason": "parent_child_wait_boundary",
                "detail": "clone parent return pid cannot be tied to the wait syscall pid argument.",
            }
        if counts.get("clone", 0) and not counts.get("execve", 0):
            return {
                "category": "execve_visibility",
                "missing_reason": "execve",
                "detail": "clone is visible but execve is absent from recovered process syscall rows.",
            }
        if counts.get("clone", 0) and counts.get("execve", 0) and not any(counts.get(name, 0) for name in ("waitid", "wait4", "waitpid")):
            return {
                "category": "wait_syscall_mapping",
                "missing_reason": "waitid/wait4/waitpid",
                "detail": "clone and execve are visible but no wait-like syscall is recovered.",
            }
        if process.get("clone_exec_wait_like_order"):
            return {
                "category": "rule_condition",
                "missing_reason": ", ".join(missing) or "process-chain strong condition",
                "detail": "process-chain weak shape is visible but strong rule conditions are not satisfied.",
            }
        return {
            "category": "syscall_boundary_recovery",
            "missing_reason": ", ".join(missing) or "process-chain shape missing",
            "detail": "clone/execve/wait-like process syscall shape is incomplete.",
        }
    return {"category": "rule_condition", "missing_reason": ", ".join(missing) or "unknown", "detail": "Rule condition was not satisfied."}


def render_rep_markdown(report: dict[str, Any]) -> str:
    rule = report["rule"]
    match = report["match"]
    lines = [
        f"# Rule Evidence Debug: {report['sample_id']} {report['rep']}",
        "",
        f"- Rule: `{rule['id']}`",
        f"- Strong matched: {match.get('matched')}",
        f"- Weak matched: {match.get('weak_matched')}",
        f"- Weak behavior: {', '.join(match.get('weak_behavior') or []) or 'none'}",
        f"- Missing category: `{report['missing_classification']['category']}`",
        f"- Missing reason: {report['missing_classification']['missing_reason']}",
        f"- Trace events: {report['raw_trace_event_summary']['events']}",
        f"- Event counts: `{report['raw_trace_event_summary']['event_counts']}`",
        f"- Target/non-target syscall attribution: `{report['target_attribution']}`",
        "",
        "## Syscalls",
        "",
        "| Seq | Name | Nr | a0 | a1 | a2 | Return | Confidence | Owner |",
        "| ---: | --- | ---: | --- | --- | --- | --- | --- | --- |",
    ]
    for row in report["syscalls"]:
        lines.append(
            f"| {row.get('seq')} | `{row.get('name')}` | {row.get('nr')} | {row.get('a0')} | {row.get('a1')} | "
            f"{row.get('a2')} | {row.get('return_value')} | {row.get('confidence')} | {row.get('pc_owner')} |"
        )
    if report.get("process_chain_evidence") is not None:
        lines.extend(
            [
                "",
                "## Process Chain Evidence",
                "",
                "```json",
                json.dumps(report["process_chain_evidence"], indent=2, sort_keys=True),
                "```",
            ]
        )
    lines.extend(["", "## Rule Expected Fields", "", "```json", json.dumps(rule, indent=2, sort_keys=True), "```", ""])
    return "\n".join(lines)


def write_rep_debug(run_root: Path, sample: dict[str, Any], rep_dir: Path, rules: dict[str, dict[str, Any]]) -> dict[str, Any]:
    sample_id = str(sample["id"])
    rule_id = FOCUS_RULE_BY_SAMPLE.get(sample_id)
    if rule_id is None:
        expected = sample.get("expected_behavior", [])
        rule_id = str(expected[0]) if isinstance(expected, list) and expected else ""
    semantic_path = rep_dir / "behavior_recovery" / "semantic_events.json"
    audit_path = rep_dir / "behavior_audit" / "behavior_audit.json"
    trace_code_path = rep_dir / "trace_code_map" / "trace.code_map.jsonl"
    trace_path = trace_code_path if trace_code_path.exists() else rep_dir / "trace.jsonl"
    semantic = load_json(semantic_path)
    audit = load_json(audit_path)
    events = load_jsonl(trace_path)
    syscalls = syscall_summary(syscall_rows(semantic))
    match = expected_rule_match(audit, rule_id)
    static_strings = source_strings(sample)
    report = {
        "schema": "rvmt.rule_evidence_debug.v1",
        "run_id": run_root.name,
        "sample_id": sample_id,
        "rep": rep_dir.name,
        "trace": repo_rel(trace_path),
        "semantic": repo_rel(semantic_path),
        "audit": repo_rel(audit_path),
        "raw_trace_event_summary": {
            "events": len(events),
            "event_counts": event_counts(events),
            "parser_warnings": semantic.get("parser_warnings", {}),
        },
        "code_map_scoped_boundaries": scoped_boundaries(events),
        "syscalls": syscalls,
        "target_attribution": target_attribution(syscalls),
        "target_sample_vs_non_target": target_attribution(syscalls),
        "rule": rules.get(rule_id, {"id": rule_id, "missing_rule_definition": True}),
        "match": match,
        "missing_classification": classify_missing(rule_id, match, syscall_rows(semantic), semantic),
        "self_copy_tag_provenance": self_copy_tag_provenance(semantic, static_strings) if sample_id == "self_copy_sim" else None,
        "process_chain_evidence": process_chain_evidence(syscall_rows(semantic)) if sample_id == "process_chain" else None,
        "static_strings_relevant": [item for item in static_strings if "proc/self/exe" in item or "rvmt_self_copy_sim" in item],
    }
    out_dir = sample_root(run_root, sample) / "aggregate" / "rule_evidence_debug_post_fix"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{rep_dir.name}.json"
    md_path = out_dir / f"{rep_dir.name}.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_rep_markdown(report), encoding="utf-8", newline="\n")
    return {**report, "debug_json": repo_rel(json_path), "debug_markdown": repo_rel(md_path)}


def render_summary(report: dict[str, Any]) -> str:
    lines = [
        "# Rule Evidence Debug Summary",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Artifact root: `{report['artifact_root']}`",
        "",
        "| Sample | Rule | Strong reps | Weak shapes | Dominant category | Debug path |",
        "| --- | --- | ---: | --- | --- | --- |",
    ]
    for sample in report["samples"]:
        lines.append(
            f"| `{sample['sample_id']}` | `{sample['rule']}` | {sample['strong_reps']}/{sample['total_reps']} | "
            f"{', '.join(sample['weak_shapes']) or 'none'} | {sample['dominant_category']} | `{sample['debug_dir']}` |"
        )
    lines.append("")
    return "\n".join(lines)


def write_outputs(run_root: Path, samples: list[dict[str, Any]], rules_path: Path) -> dict[str, Any]:
    rules = load_rules(rules_path)
    sample_summaries = []
    for sample in samples:
        rep_reports = []
        for rep_dir in sorted((sample_root(run_root, sample) / "board" / TRACE_ON).glob("rep_*")):
            if not (rep_dir / "behavior_recovery" / "semantic_events.json").exists():
                continue
            rep_reports.append(write_rep_debug(run_root, sample, rep_dir, rules))
        weak_shapes = sorted(
            {
                str(shape)
                for report in rep_reports
                for shape in (report.get("match", {}).get("weak_behavior") or [])
                if isinstance(shape, str)
            }
        )
        categories: dict[str, int] = {}
        for report in rep_reports:
            category = str((report.get("missing_classification") or {}).get("category", "unknown"))
            categories[category] = categories.get(category, 0) + 1
        dominant = sorted(categories.items(), key=lambda item: (-item[1], item[0]))[0][0] if categories else "missing"
        sample_id = str(sample["id"])
        debug_dir = sample_root(run_root, sample) / "aggregate" / "rule_evidence_debug_post_fix"
        sample_summaries.append(
            {
                "sample_id": sample_id,
                "rule": FOCUS_RULE_BY_SAMPLE.get(sample_id, ""),
                "total_reps": len(rep_reports),
                "strong_reps": sum(1 for report in rep_reports if report.get("match", {}).get("matched")),
                "weak_reps": sum(1 for report in rep_reports if report.get("match", {}).get("weak_matched")),
                "weak_shapes": weak_shapes,
                "dominant_category": dominant,
                "debug_dir": repo_rel(debug_dir),
                "reps": [
                    {
                        "rep": report["rep"],
                        "matched": report.get("match", {}).get("matched"),
                        "weak_matched": report.get("match", {}).get("weak_matched"),
                        "weak_behavior": report.get("match", {}).get("weak_behavior") or [],
                        "category": (report.get("missing_classification") or {}).get("category"),
                        "debug_json": report["debug_json"],
                        "debug_markdown": report["debug_markdown"],
                    }
                    for report in rep_reports
                ],
            }
        )
    summary = {
        "schema": "rvmt.rule_evidence_debug_summary.v1",
        "run_id": run_root.name,
        "artifact_root": repo_rel(run_root),
        "samples": sample_summaries,
    }
    aggregate = run_root / "aggregate"
    aggregate.mkdir(parents=True, exist_ok=True)
    (aggregate / "rule_evidence_debug_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (aggregate / "rule_evidence_debug_summary.md").write_text(render_summary(summary), encoding="utf-8", newline="\n")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explain recovered rule evidence and missing semantic blockers for 35T p0c runs.")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--root", type=Path, default=DEFAULT_RESULT_ROOT)
    parser.add_argument("--sample", action="append", default=[])
    parser.add_argument("--rules", type=Path, default=RULES_PATH)
    args = parser.parse_args(argv)
    try:
        run_root = resolve(args.root) / args.run_id
        samples = load_samples(args.sample)
        summary = write_outputs(run_root, samples, resolve(args.rules))
    except Exception as exc:
        print(f"debug_rule_evidence: error: {exc}", file=sys.stderr)
        return 2
    print(f"[PASS] rule evidence debug written: {run_root / 'aggregate' / 'rule_evidence_debug_summary.json'}")
    if not summary.get("samples"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
