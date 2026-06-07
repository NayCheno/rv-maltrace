from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
DEFAULT_SPEC = Path("experiments/linux_behavior/semantic_threat_model.json")
DEFAULT_DOC = Path("docs/05-semantic-analysis/semantic_threat_model.md")
STATUS = "TRUSTED_KERNEL_USER_MODE_THREAT_MODEL_BOUNDARY_SPECIFIED"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
EXPECTED_TRUSTED = {
    "hardware_trace_tap",
    "fpga_bitstream_under_test",
    "linux_kernel",
    "board_runner",
    "offline_analysis_tools",
}
EXPECTED_IN_SCOPE = {
    "user_mode_malware_like_workload",
    "user_mode_syscall_behavior",
    "user_mode_ptrace_or_tracerpid_checks",
    "user_mode_timing_checks",
    "user_mode_file_process_memory_mapping_behavior",
}
EXPECTED_OUT_OF_SCOPE = {
    "kernel_rootkit",
    "malicious_kernel",
    "malicious_kernel_module",
    "compromised_ebpf_program",
    "compromised_board_runner",
    "firmware_or_bitstream_tampering",
    "real_malware_detection_accuracy",
}
EXPECTED_ROUTES = {
    "event_only_hardware_trace": "CURRENT_35T_CLAIM",
    "selective_memory_snapshot": "DEFERRED",
    "kernel_helper_metadata": "OPTIONAL_DEFERRED_COMPANION",
    "ebpf_metadata_alignment": "OPTIONAL_DEFERRED_COMPANION",
}
EXPECTED_NON_CLAIMS = [
    "no kernel rootkit resistance claim",
    "no malicious kernel resistance claim",
    "no eBPF tamper resistance claim",
    "no real malware detection claim",
    "no complete pointer semantic reconstruction claim",
    "no helper or eBPF MVP dependency claim",
]
FORBIDDEN_POSITIVE_PATTERNS = [
    re.compile(r"\b(?:resists|detects|prevents|defeats)\s+(?:a\s+)?kernel\s+rootkit\b", re.IGNORECASE),
    re.compile(r"\bkernel\s+rootkit\s+(?:resistance|detection)\s+(?:is\s+)?(?:proved|validated|supported)\b", re.IGNORECASE),
    re.compile(r"\bmalicious\s+kernel\s+(?:resistance|detection)\s+(?:is\s+)?(?:proved|validated|supported)\b", re.IGNORECASE),
    re.compile(r"\beBPF\s+(?:is\s+)?(?:an?\s+)?MVP\s+dependency\b", re.IGNORECASE),
    re.compile(r"\bhelper\s+(?:or\s+eBPF\s+)?(?:is\s+)?(?:an?\s+)?MVP\s+dependency\b", re.IGNORECASE),
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


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


def contains_all(text: str, needles: list[str]) -> bool:
    lowered = text.lower()
    return all(needle.lower() in lowered for needle in needles)


def positive_forbidden_claims(text: str) -> list[str]:
    findings = []
    for pattern in FORBIDDEN_POSITIVE_PATTERNS:
        for match in pattern.finditer(text):
            start = max(0, match.start() - 120)
            end = min(len(text), match.end() + 80)
            context = text[start:end].lower()
            if "no " in context or "not " in context or "out of scope" in context or "non-claim" in context:
                continue
            findings.append(match.group(0))
            break
    return findings


def route_map(spec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    routes = spec.get("semantic_routes", [])
    if not isinstance(routes, list):
        return {}
    return {str(row.get("route")): row for row in routes if isinstance(row, dict) and row.get("route")}


def build_report(repo_root: Path, evidence_root_arg: Path, spec_arg: Path, doc_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    spec_path = repo_path(repo_root, spec_arg).resolve()
    doc_path = repo_path(repo_root, doc_arg).resolve()
    spec = load_json(spec_path)
    doc_text = doc_path.read_text(encoding="utf-8")
    trusted = set(spec.get("trusted_components", [])) if isinstance(spec.get("trusted_components"), list) else set()
    attacker = spec.get("attacker_model", {}) if isinstance(spec.get("attacker_model"), dict) else {}
    in_scope = set(attacker.get("in_scope", [])) if isinstance(attacker.get("in_scope"), list) else set()
    out_of_scope = set(attacker.get("out_of_scope", [])) if isinstance(attacker.get("out_of_scope"), list) else set()
    routes = route_map(spec)
    non_claims = spec.get("non_claims", []) if isinstance(spec.get("non_claims"), list) else []
    combined_text = json.dumps(spec, sort_keys=True) + "\n" + doc_text
    forbidden = positive_forbidden_claims(combined_text)
    checks = {
        "spec_schema": spec.get("schema") == "rvmt.semantic_threat_model.v1",
        "spec_status": spec.get("status") == "BOUNDARY_SPECIFIED",
        "claim_level": spec.get("claim_level") == EXPECTED_CLAIM_LEVEL,
        "trusted_components": EXPECTED_TRUSTED.issubset(trusted),
        "user_mode_attacker_in_scope": EXPECTED_IN_SCOPE.issubset(in_scope),
        "kernel_rootkit_out_of_scope": EXPECTED_OUT_OF_SCOPE.issubset(out_of_scope),
        "routes_have_expected_status": all(
            route in routes and routes[route].get("status") == expected_status
            for route, expected_status in EXPECTED_ROUTES.items()
        ),
        "helper_and_ebpf_are_optional_companions": all(
            route in routes
            and "trusted" in str(routes[route].get("trust_dependency", "")).lower()
            and (
                "optional" in str(routes[route].get("status", "")).lower()
                or "optional" in str(routes[route].get("boundary", "")).lower()
                or "not an mvp dependency" in str(routes[route].get("boundary", "")).lower()
            )
            for route in ("kernel_helper_metadata", "ebpf_metadata_alignment")
        ),
        "required_wording_in_spec": contains_all(
            " ".join(str(item) for item in spec.get("required_wording", [])),
            ["trusted kernel", "user-mode malware-like workload", "kernel rootkit out of scope"],
        ),
        "required_wording_in_doc": contains_all(
            doc_text,
            ["trusted kernel", "user-mode malware-like workload", "kernel rootkit out of scope"],
        ),
        "non_claims_present": all(item in non_claims for item in EXPECTED_NON_CLAIMS),
        "no_forbidden_positive_claims": not forbidden,
    }
    status = STATUS if all(checks.values()) else "FAIL"
    return {
        "schema": "rvmt.35t.threat_model_boundary.v1",
        "run_id": RUN_ID,
        "generated_utc": utc_now(),
        "status": status,
        "spec": rel(spec_path, repo_root),
        "document": rel(doc_path, repo_root),
        "evidence_root": rel(evidence_root, repo_root),
        "checks": checks,
        "trusted_components": sorted(trusted),
        "in_scope": sorted(in_scope),
        "out_of_scope": sorted(out_of_scope),
        "routes": {
            route: {
                "status": row.get("status"),
                "trust_dependency": row.get("trust_dependency"),
                "boundary": row.get("boundary"),
            }
            for route, row in sorted(routes.items())
        },
        "interpretation": [
            "current 35T semantic evidence assumes a trusted kernel and user-mode malware-like workload",
            "kernel helper and eBPF routes are optional deferred companions and cannot support malicious-kernel or kernel-rootkit resistance claims",
            "hardware event-only trace remains the current authoritative 35T claim while pointer snapshot/helper/eBPF enrichment is deferred",
        ],
        "non_claims": EXPECTED_NON_CLAIMS,
        "forbidden_positive_findings": forbidden,
        "failures": [key for key, ok in checks.items() if not ok],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Threat Model Boundary: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Spec: `{report['spec']}`",
        f"Document: `{report['document']}`",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## In Scope", ""]
    lines.extend(f"- {item}" for item in report["in_scope"])
    lines += ["", "## Out Of Scope", ""]
    lines.extend(f"- {item}" for item in report["out_of_scope"])
    lines += ["", "## Routes", "", "| Route | Status | Trust Dependency | Boundary |", "| --- | --- | --- | --- |"]
    for route, row in report["routes"].items():
        lines.append(f"| `{route}` | `{row.get('status')}` | {row.get('trust_dependency')} | {row.get('boundary')} |")
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "threat_model_boundary.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "threat_model_boundary.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")


def write_fixture(root: Path) -> None:
    spec = {
        "schema": "rvmt.semantic_threat_model.v1",
        "status": "BOUNDARY_SPECIFIED",
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "trusted_components": sorted(EXPECTED_TRUSTED),
        "attacker_model": {
            "in_scope": sorted(EXPECTED_IN_SCOPE),
            "out_of_scope": sorted(EXPECTED_OUT_OF_SCOPE),
        },
        "semantic_routes": [
            {
                "route": route,
                "status": status,
                "trust_dependency": "trusted linux kernel" if route in {"kernel_helper_metadata", "ebpf_metadata_alignment"} else "hardware trace tap",
                "boundary": "optional deferred companion" if route in {"kernel_helper_metadata", "ebpf_metadata_alignment"} else "current or deferred route",
            }
            for route, status in EXPECTED_ROUTES.items()
        ],
        "required_wording": ["trusted kernel", "user-mode malware-like workload", "kernel rootkit out of scope"],
        "non_claims": EXPECTED_NON_CLAIMS,
    }
    spec_path = root / DEFAULT_SPEC
    doc_path = root / DEFAULT_DOC
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    doc_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    doc_path.write_text(
        "trusted kernel\nuser-mode malware-like workload\nkernel rootkit out of scope\nno kernel rootkit resistance claim\n",
        encoding="utf-8",
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT, DEFAULT_SPEC, DEFAULT_DOC)
        if report["status"] != STATUS:
            print(f"[FAIL] expected fixture status {STATUS}, got {report['status']}: {report['failures']}", file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "threat_model_boundary.md").exists():
            print("[FAIL] self-test did not write markdown output", file=sys.stderr)
            return 1
        spec_path = root / DEFAULT_SPEC
        spec = load_json(spec_path)
        spec["attacker_model"]["out_of_scope"].remove("kernel_rootkit")
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        failed = build_report(root, DEFAULT_EVIDENCE_ROOT, DEFAULT_SPEC, DEFAULT_DOC)
        if failed["status"] == STATUS:
            print("[FAIL] missing kernel_rootkit out-of-scope boundary should fail", file=sys.stderr)
            return 1
    print("[PASS] 35T threat model self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the 35T semantic threat model boundary.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        repo_root = args.repo_root.resolve()
        report = build_report(repo_root, args.evidence_root, args.spec, args.doc)
        if not args.no_write:
            write_outputs(report, repo_path(repo_root, args.evidence_root))
    except Exception as exc:
        print(f"check_35t_threat_model: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T threat model boundary")
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
