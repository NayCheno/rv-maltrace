from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_MANIFEST = Path("experiments/linux_behavior/malware_like/manifest.json")
DEFAULT_EXTENSION_PLAN = Path("experiments/linux_behavior/malware_like/extension_plan.json")
DEFAULT_EXTENSION_SOURCE_DIR = Path("experiments/linux_behavior/malware_like/extension_programs")
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / RUN_ID
READY_STATUS = "READY_FOR_SYNTHETIC_EXTENSION_IMPLEMENTATION"
IMPLEMENTED_STATUS = "IMPLEMENTED_EXTENSION_SOURCES_READY_FOR_35T_GATING"
PASS_STATUSES = {READY_STATUS, IMPLEMENTED_STATUS}
IMPLEMENTED_CANDIDATE_STATUSES = {"IMPLEMENTED_SOURCE", "IMPLEMENTED_SOURCE_OPTIONAL_LOOPBACK"}
EXPECTED_CURRENT_SAMPLES = {
    "file_scan",
    "batch_open_read_write",
    "self_copy_sim",
    "abnormal_syscall_sequence",
    "illegal_trap",
    "process_chain",
    "dynamic_executable_memory",
    "anti_debug_like",
}
REQUIRED_TOPICS = {
    "direct-syscall",
    "timing checks",
    "/proc/self/status TracerPid check",
    "packed code",
    "self-modifying code",
    "mmap/mprotect executable memory variants",
    "fork/exec chains",
    "network workloads",
    "file encryption simulation without destructive payload",
    "Mirai-reference /proc process enumeration",
    "Mirai-reference watchdog probe",
    "Mirai-reference encoded string table",
    "Mirai-reference C2/report callback loopback probe",
}
REQUIRED_REAL_MALWARE_POLICIES = {
    "sample_source_policy",
    "legal_ethical_policy",
    "containment_environment",
    "network_isolation",
    "non_destructive_replay_mode",
    "artifact_sanitization",
}
FORBIDDEN_EXPANDED_CLAIMS = (
    re.compile(r"\bexpanded\s+35T\s+coverage\s+PASS\b", re.IGNORECASE),
    re.compile(r"\breal\s+malware\s+(?:coverage|validation|dataset)\b", re.IGNORECASE),
    re.compile(r"\bnetwork\s+workloads?\s+enabled\s+by\s+default\b", re.IGNORECASE),
)
FORBIDDEN_DESTRUCTIVE_SOURCE_PATTERNS = (
    re.compile(r"\bunlink\s*\("),
    re.compile(r"\bremove\s*\("),
    re.compile(r"\brmdir\s*\("),
    re.compile(r"\brename\s*\("),
    re.compile(r"\bsystem\s*\("),
)
NETWORK_SOURCE_TOKENS = ("<sys/socket.h>", "SYS_socket", "SYS_connect", "SYS_accept", "SYS_bind", "connect(")
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]


def repo_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def sample_ids(manifest: dict[str, Any]) -> set[str]:
    rows = manifest.get("samples", [])
    if not isinstance(rows, list):
        return set()
    return {str(row.get("id")) for row in rows if isinstance(row, dict) and row.get("id")}


def rows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    value = manifest.get("samples", [])
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def candidate_rows(plan: dict[str, Any]) -> list[dict[str, Any]]:
    value = plan.get("candidates", [])
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def forbidden_claims(*objects: dict[str, Any]) -> list[str]:
    text = "\n".join(json.dumps(obj, sort_keys=True) for obj in objects)
    findings = []
    for pattern in FORBIDDEN_EXPANDED_CLAIMS:
        match = pattern.search(text)
        if match:
            findings.append(match.group(0))
    return findings


def source_path_for(repo_root: Path, candidate: dict[str, Any]) -> Path | None:
    source = candidate.get("source")
    if not isinstance(source, str) or not source:
        return None
    return repo_path(repo_root, Path(source))


def command_is_bound(candidate: dict[str, Any]) -> bool:
    command = candidate.get("command")
    return isinstance(command, list) and command[:1] == [f"./{candidate.get('id')}"]


def list_field(candidate: dict[str, Any], key: str) -> list[Any]:
    value = candidate.get(key, [])
    return value if isinstance(value, list) else []


def source_texts(repo_root: Path, candidates: list[dict[str, Any]]) -> dict[str, str]:
    texts: dict[str, str] = {}
    for candidate in candidates:
        path = source_path_for(repo_root, candidate)
        if path and path.is_file():
            texts[str(candidate.get("id"))] = path.read_text(encoding="utf-8")
    return texts


def has_forbidden_destructive_source(texts: dict[str, str]) -> bool:
    return any(pattern.search(text) for text in texts.values() for pattern in FORBIDDEN_DESTRUCTIVE_SOURCE_PATTERNS)


def non_network_sources_are_network_free(candidates: list[dict[str, Any]], texts: dict[str, str]) -> bool:
    for candidate in candidates:
        if candidate.get("network_required") is True:
            continue
        text = texts.get(str(candidate.get("id")), "")
        if any(token in text for token in NETWORK_SOURCE_TOKENS):
            return False
    return True


def network_sources_are_loopback_only(candidates: list[dict[str, Any]], texts: dict[str, str]) -> bool:
    for candidate in candidates:
        if candidate.get("network_required") is not True:
            continue
        text = texts.get(str(candidate.get("id")), "")
        if "INADDR_LOOPBACK" not in text and "127.0.0.1" not in text:
            return False
    return True


def build_report(repo_root: Path, manifest_arg: Path, plan_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    manifest_path = repo_path(repo_root, manifest_arg)
    plan_path = repo_path(repo_root, plan_arg)
    manifest = load_json(manifest_path)
    plan = load_json(plan_path)
    current = rows(manifest)
    candidates = candidate_rows(plan)
    topics = {str(row.get("topic")) for row in candidates if row.get("topic")}
    policy = plan.get("required_before_real_malware", {})
    if not isinstance(policy, dict):
        policy = {}
    network_candidates = [row for row in candidates if row.get("network_required") is True]
    texts = source_texts(repo_root, candidates)
    source_candidates = [row for row in candidates if source_path_for(repo_root, row) is not None]
    implemented_candidates = [row for row in candidates if row.get("status") in IMPLEMENTED_CANDIDATE_STATUSES]
    source_paths = [source_path_for(repo_root, row) for row in candidates]
    base_checks = {
        "manifest_schema": manifest.get("sample_class") == "malware_like_synthetic",
        "current_suite_exact_8": sample_ids(manifest) == EXPECTED_CURRENT_SAMPLES,
        "current_suite_synthetic_only": all(row.get("real_malware") is False for row in current),
        "current_suite_non_destructive": all(row.get("destructive") is False for row in current),
        "current_suite_network_free": all(row.get("network_required") is False for row in current),
        "plan_schema": plan.get("schema") == "rvmt.synthetic_suite_extension_plan.v1",
        "plan_synthetic_only": plan.get("sample_class") == "malware_like_synthetic" and plan.get("real_malware_in_scope") is False,
        "plan_default_disabled": plan.get("default_enabled") is False and all(row.get("default_enabled") is False for row in candidates),
        "candidate_topics_complete": REQUIRED_TOPICS.issubset(topics),
        "candidate_count": len(candidates) >= len(REQUIRED_TOPICS),
        "candidate_safety": all(row.get("real_malware") is False and row.get("destructive") is False for row in candidates),
        "network_candidates_default_disabled": all(row.get("default_enabled") is False for row in network_candidates),
        "network_policy_bounded": "disabled_by_default" in str(plan.get("network_policy", "")),
        "real_malware_policies_listed": REQUIRED_REAL_MALWARE_POLICIES.issubset(set(policy)),
        "real_malware_policies_deferred": all(str(policy.get(key)).startswith("REQUIRED_BEFORE") for key in REQUIRED_REAL_MALWARE_POLICIES),
        "no_expanded_claims": not forbidden_claims(manifest, plan),
    }
    implementation_checks = {
        "plan_status_implemented_source": plan.get("status") == "IMPLEMENTED_SOURCE_READY_FOR_35T_GATING",
        "candidate_sources_declared": len(source_candidates) == len(candidates) and bool(candidates),
        "candidate_sources_exist": all(path is not None and path.is_file() for path in source_paths),
        "candidate_sources_under_extension_dir": all(
            path is not None and rel(path, repo_root).startswith(DEFAULT_EXTENSION_SOURCE_DIR.as_posix() + "/")
            for path in source_paths
        ),
        "candidate_statuses_implemented": len(implemented_candidates) == len(candidates) and bool(candidates),
        "candidate_commands_bound": all(command_is_bound(row) for row in candidates),
        "candidate_expected_syscalls_recorded": all(bool(list_field(row, "expected_syscalls")) for row in candidates),
        "candidate_expected_behaviors_recorded": all(bool(list_field(row, "expected_behavior")) for row in candidates),
        "implementation_sources_non_destructive": not has_forbidden_destructive_source(texts),
        "non_network_sources_network_free": non_network_sources_are_network_free(candidates, texts),
        "optional_network_sources_loopback_only": network_sources_are_loopback_only(candidates, texts),
    }
    checks = {**base_checks, **implementation_checks}
    base_ready = all(base_checks.values())
    implementation_ready = base_ready and all(implementation_checks.values())
    if implementation_ready:
        status = IMPLEMENTED_STATUS
    elif base_ready:
        status = READY_STATUS
    else:
        status = "FAIL"
    return {
        "schema": "rvmt.35t.synthetic_suite_extension.check.v1",
        "run_id": RUN_ID,
        "status": status,
        "manifest": rel(manifest_path, repo_root),
        "extension_plan": rel(plan_path, repo_root),
        "checks": checks,
        "current_samples": sorted(sample_ids(manifest)),
        "candidate_count": len(candidates),
        "implemented_candidate_count": len(implemented_candidates),
        "implemented_candidate_ids": sorted(str(row.get("id")) for row in implemented_candidates if row.get("id")),
        "candidate_topics": sorted(topics),
        "extension_source_files": sorted(
            rel(path, repo_root) for path in source_paths if path is not None and path.is_file()
        ),
        "network_optional_candidates": sorted(str(row.get("id")) for row in network_candidates if row.get("id")),
        "real_malware_policy_gates": {key: policy.get(key) for key in sorted(REQUIRED_REAL_MALWARE_POLICIES)},
        "interpretation": [
            "current 35T claim remains limited to the existing 8 synthetic malware-like samples",
            "extension candidates are source-implemented, synthetic-only, non-destructive, and disabled by default when implementation checks pass",
            "implemented extension sources are not counted as expanded 35T coverage until they are explicitly selected and run through the same gates",
            "network behavior remains optional and disabled by default until a loopback fixture is explicitly provided",
            "real malware remains out of scope until source, legal, containment, replay, isolation, and sanitization policies are complete",
        ],
        "non_claims": NON_CLAIMS,
        "failures": [key for key, ok in checks.items() if not ok],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Synthetic Suite Extension Check: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Manifest: `{report['manifest']}`",
        "",
        f"Extension plan: `{report['extension_plan']}`",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Candidate Topics", ""]
    lines.extend(f"- {topic}" for topic in report["candidate_topics"])
    lines += ["", "## Implemented Source Files", ""]
    lines.extend(f"- `{path}`" for path in report["extension_source_files"] or ["none"])
    lines += ["", "## Optional Network Candidates", ""]
    lines.extend(f"- {item}" for item in report["network_optional_candidates"] or ["none"])
    lines += ["", "## Real Malware Policy Gates", ""]
    for key, value in report["real_malware_policy_gates"].items():
        lines.append(f"- {key}: {value}")
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "synthetic_suite_extension_check.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "synthetic_suite_extension_check.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def fixture_manifest(path: Path, *, network_required: bool = False) -> None:
    write_json(
        path,
        {
            "sample_class": "malware_like_synthetic",
            "samples": [
                {"id": sample, "real_malware": False, "destructive": False, "network_required": network_required}
                for sample in sorted(EXPECTED_CURRENT_SAMPLES)
            ],
        },
    )


def fixture_plan(root: Path, *, missing_topic: bool = False, missing_source: bool = False) -> None:
    candidates = []
    for index, topic in enumerate(sorted(REQUIRED_TOPICS)):
        if missing_topic and index == 0:
            continue
        candidate_id = f"candidate_{index}"
        source = DEFAULT_EXTENSION_SOURCE_DIR / f"{candidate_id}.c"
        candidates.append(
            {
                "id": candidate_id,
                "topic": topic,
                "status": "IMPLEMENTED_SOURCE_OPTIONAL_LOOPBACK" if topic == "network workloads" else "IMPLEMENTED_SOURCE",
                "real_malware": False,
                "destructive": False,
                "network_required": topic == "network workloads",
                "default_enabled": False,
                "source": source.as_posix(),
                "command": [f"./{candidate_id}"],
                "expected_syscalls": ["socket", "connect", "close"] if topic == "network workloads" else ["openat", "read", "close"],
                "expected_behavior": [topic.replace(" ", "_")],
            }
        )
        if not missing_source:
            source_path = root / source
            source_path.parent.mkdir(parents=True, exist_ok=True)
            if topic == "network workloads":
                source_path.write_text("/* INADDR_LOOPBACK SYS_socket */\n", encoding="utf-8")
            else:
                source_path.write_text("/* openat read close */\n", encoding="utf-8")
    write_json(
        root / DEFAULT_EXTENSION_PLAN,
        {
            "schema": "rvmt.synthetic_suite_extension_plan.v1",
            "status": "IMPLEMENTED_SOURCE_READY_FOR_35T_GATING",
            "sample_class": "malware_like_synthetic",
            "real_malware_in_scope": False,
            "default_enabled": False,
            "network_policy": "disabled_by_default_loopback_only_when_explicit",
            "required_before_real_malware": {
                key: "REQUIRED_BEFORE_SCOPE_EXPANSION" for key in REQUIRED_REAL_MALWARE_POLICIES
            },
            "candidates": candidates,
        },
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixture_manifest(root / DEFAULT_MANIFEST)
        fixture_plan(root)
        report = build_report(root, DEFAULT_MANIFEST, DEFAULT_EXTENSION_PLAN)
        if report["status"] != IMPLEMENTED_STATUS:
            print("[FAIL] expected complete fixture to pass synthetic extension check", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "synthetic_suite_extension_check.md").exists():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixture_manifest(root / DEFAULT_MANIFEST, network_required=True)
        fixture_plan(root)
        report = build_report(root, DEFAULT_MANIFEST, DEFAULT_EXTENSION_PLAN)
        if report["status"] != "FAIL":
            print("[FAIL] expected network-enabled current suite fixture to fail", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixture_manifest(root / DEFAULT_MANIFEST)
        fixture_plan(root, missing_topic=True)
        report = build_report(root, DEFAULT_MANIFEST, DEFAULT_EXTENSION_PLAN)
        if report["status"] != "FAIL":
            print("[FAIL] expected missing-topic fixture to fail", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixture_manifest(root / DEFAULT_MANIFEST)
        fixture_plan(root, missing_source=True)
        report = build_report(root, DEFAULT_MANIFEST, DEFAULT_EXTENSION_PLAN)
        if report["status"] != READY_STATUS:
            print("[FAIL] expected source-missing fixture to remain plan-ready but not implementation-ready", file=sys.stderr)
            return 1
    print("[PASS] 35T synthetic suite extension self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check bounded 35T synthetic malware-like suite extension readiness.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--extension-plan", type=Path, default=DEFAULT_EXTENSION_PLAN)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        report = build_report(repo_root, args.manifest, args.extension_plan)
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_synthetic_suite_extension: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T synthetic suite extension check")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] in PASS_STATUSES else 1


if __name__ == "__main__":
    raise SystemExit(main())
