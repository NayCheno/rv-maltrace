from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PRIMARY_RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
SURROGATE_RUN_ID = "35t-surrogate-darthra-p0a-r512-abba-r5-20260524"
MIRAI_RUN_ID = "35t-mirai-reference-nonnetwork-p0a-r512-abba-r5-v3-20260524"
DEFAULT_EVIDENCE_BASE = Path("docs/results/evidence")
DEFAULT_EVIDENCE_ROOT = DEFAULT_EVIDENCE_BASE / "35t-paper-claim-evidence-table-20260524"
LINEAGE_EVIDENCE_ROOT = DEFAULT_EVIDENCE_BASE / "35t-real-malware-derived-lineage-20260524"
BASELINE_EVIDENCE_ROOT = DEFAULT_EVIDENCE_BASE / "35t-real-malware-derived-baseline-comparison-20260524"
BOOT_EVIDENCE_ROOT = DEFAULT_EVIDENCE_BASE / "35t-surrogate-boot-provenance-20260524"
REAL_MALWARE_MANIFEST = Path("experiments/linux_behavior/real_malware/manifest.json")
REAL_MALWARE_RESULTS_ROOT = Path("results/experiments/real_malware/manual")
SCHEMA = "rvmt.35t.paper_claim_evidence_table.v1"
PASS_STATUS = "PAPER_CLAIM_EVIDENCE_TABLE_PASS"
DEFERRED_BOOT_STATUS = "PAPER_CLAIM_EVIDENCE_TABLE_PASS_WITH_SURROGATE_BOOT_DEFERRED"
FAIL_STATUS = "FAIL"
SNAPSHOT_FILES = (
    "README.md",
    "claim_evidence_table.json",
    "claim_evidence_table.md",
)
NON_CLAIMS = [
    "not true real-malware execution",
    "not a CCF-A acceptance guarantee",
    "not payload-equivalence evidence",
    "not network-enabled malware behavior",
    "not malware-family classifier accuracy",
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


def read_json(path: Path, failures: list[str], repo_root: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        failures.append(f"missing {label}: {rel(path, repo_root)}")
        return {}
    try:
        return load_json(path)
    except Exception as exc:
        failures.append(f"invalid {label}: {rel(path, repo_root)}: {exc}")
        return {}


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_record(path: Path, repo_root: Path) -> dict[str, Any]:
    return {"path": rel(path, repo_root), "bytes": path.stat().st_size, "sha256": file_digest(path)}


def manifest_rows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    rows = manifest.get("committed_artifacts", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def manifest_hash_errors(repo_root: Path, rows: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for row in rows:
        artifact = str(row.get("artifact") or "")
        committed_path = row.get("committed_path")
        if not artifact:
            errors.append("manifest row missing artifact name")
            continue
        if artifact in seen:
            errors.append(f"duplicate manifest artifact: {artifact}")
        seen.add(artifact)
        if not isinstance(committed_path, str) or not committed_path:
            errors.append(f"{artifact}: missing committed_path")
            continue
        path = repo_path(repo_root, Path(committed_path))
        if not path.is_file():
            errors.append(f"{artifact}: committed_path does not exist: {rel(path, repo_root)}")
            continue
        if row.get("bytes") != path.stat().st_size:
            errors.append(f"{artifact}: byte count mismatch")
        if row.get("sha256") != file_digest(path):
            errors.append(f"{artifact}: sha256 mismatch")
    return errors


def check_snapshot(repo_root: Path, evidence_root: Path, label: str) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    manifest = read_json(evidence_root / "evidence_manifest.json", failures, repo_root, f"{label} manifest")
    rows = manifest_rows(manifest)
    hash_errors = manifest_hash_errors(repo_root, rows) if manifest else []
    failures.extend(f"{label}:manifest:{item}" for item in hash_errors)
    return {
        "label": label,
        "path": rel(evidence_root, repo_root),
        "present": evidence_root.is_dir(),
        "schema": manifest.get("schema"),
        "status": manifest.get("status"),
        "claim_level": manifest.get("claim_level"),
        "artifact_count": len(rows),
        "hash_errors": hash_errors,
    }, failures


def dict_rows(value: Any) -> list[dict[str, Any]]:
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def claim_status(checks: dict[str, bool], *, allow_deferred: bool = False, deferred: bool = False) -> str:
    if not all(checks.values()):
        return "FAIL"
    if allow_deferred and deferred:
        return "DEFERRED"
    return "PASS"


def sample_statuses(gate: dict[str, Any]) -> list[str]:
    return [str(row.get("status") or "") for row in dict_rows(gate.get("samples", []))]


def build_report(
    repo_root_arg: Path,
    evidence_root_arg: Path,
    *,
    primary_run_id: str,
    surrogate_run_id: str,
    mirai_run_id: str,
) -> dict[str, Any]:
    repo_root = repo_root_arg.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    failures: list[str] = []

    paths = {
        "primary": repo_root / DEFAULT_EVIDENCE_BASE / primary_run_id,
        "surrogate": repo_root / DEFAULT_EVIDENCE_BASE / surrogate_run_id,
        "mirai_reference": repo_root / DEFAULT_EVIDENCE_BASE / mirai_run_id,
        "lineage": repo_root / LINEAGE_EVIDENCE_ROOT,
        "baseline": repo_root / BASELINE_EVIDENCE_ROOT,
        "surrogate_boot": repo_root / BOOT_EVIDENCE_ROOT,
    }
    snapshots: dict[str, dict[str, Any]] = {}
    for label, path in paths.items():
        snapshot, snapshot_failures = check_snapshot(repo_root, path, label)
        snapshots[label] = snapshot
        failures.extend(snapshot_failures)

    surrogate_gate = read_json(paths["surrogate"] / "gate_report.json", failures, repo_root, "surrogate gate")
    mirai_gate = read_json(paths["mirai_reference"] / "extension_gate_check.json", failures, repo_root, "mirai gate")
    lineage_check = read_json(
        paths["lineage"] / "real_malware_derived_lineage_check.json",
        failures,
        repo_root,
        "lineage check",
    )
    baseline_check = read_json(paths["baseline"] / "baseline_comparison.json", failures, repo_root, "baseline comparison")
    boot_check = read_json(
        paths["surrogate_boot"] / "surrogate_boot_provenance.json",
        failures,
        repo_root,
        "surrogate boot provenance",
    )
    real_malware_manifest = read_json(repo_root / REAL_MALWARE_MANIFEST, failures, repo_root, "real-malware manifest")

    boot_status = str(boot_check.get("status") or "")
    boot_deferred = boot_status == "SURROGATE_BOOT_PROVENANCE_DEFERRED_RUN_SCOPED_LOG_MISSING"
    boot_pass = boot_status == "SURROGATE_BOOT_PROVENANCE_PASS"
    manual_results_absent = not (repo_root / REAL_MALWARE_RESULTS_ROOT).exists()

    claim_rows = [
        {
            "id": "c1_primary_35t_package_integrity",
            "paper_wording": "The primary 35T evidence package is hash-manifested and locally reproducible.",
            "evidence": [snapshots["primary"]["path"], "tools/check_35t_artifact_package_readiness.py"],
            "checks": {
                "snapshot_present": snapshots["primary"]["present"],
                "manifest_hashes_valid": not snapshots["primary"]["hash_errors"],
                "artifact_count_positive": int(snapshots["primary"]["artifact_count"] or 0) > 0,
            },
            "limitations": ["Primary package is synthetic-behavior 35T evidence, not true real-malware evidence."],
        },
        {
            "id": "c2_surrogate_darthra_board_gate",
            "paper_wording": "Three DarthRa-derived safe surrogates pass the Artix-7 35T board validation gate.",
            "evidence": [snapshots["surrogate"]["path"], f"results/experiments/35t/{surrogate_run_id}"],
            "checks": {
                "snapshot_present": snapshots["surrogate"]["present"],
                "manifest_hashes_valid": not snapshots["surrogate"]["hash_errors"],
                "gate_status_pass": surrogate_gate.get("status") == "PASS",
                "three_samples": len(dict_rows(surrogate_gate.get("samples", []))) >= 3,
                "all_samples_pass": sample_statuses(surrogate_gate).count("PASS") >= 3,
            },
            "limitations": ["Repository-authored safe reimplementations retain behavior shape only."],
        },
        {
            "id": "c3_mirai_reference_nonnetwork_board_gate",
            "paper_wording": "Three non-network Mirai-reference behavior simulations pass the Artix-7 35T board validation gate.",
            "evidence": [snapshots["mirai_reference"]["path"], f"results/experiments/35t/{mirai_run_id}"],
            "checks": {
                "snapshot_present": snapshots["mirai_reference"]["present"],
                "manifest_hashes_valid": not snapshots["mirai_reference"]["hash_errors"],
                "gate_status_pass": mirai_gate.get("status") == "PASS",
                "three_samples": len(dict_rows(mirai_gate.get("samples", []))) >= 3,
                "all_samples_pass": sample_statuses(mirai_gate).count("PASS") >= 3,
                "network_optional_samples_excluded": mirai_gate.get("checks", {}).get("network_optional_samples_excluded") is True
                if isinstance(mirai_gate.get("checks"), dict)
                else False,
            },
            "limitations": ["Network-required Mirai behavior remains excluded from this non-network claim."],
        },
        {
            "id": "c4_real_malware_derived_lineage",
            "paper_wording": "Six board-tested behaviors have explicit real-malware-derived lineage, risk removal, and non-claim boundaries.",
            "evidence": [snapshots["lineage"]["path"], "experiments/linux_behavior/real_malware_surrogate/behavior_lineage_matrix.json"],
            "checks": {
                "snapshot_present": snapshots["lineage"]["present"],
                "manifest_hashes_valid": not snapshots["lineage"]["hash_errors"],
                "lineage_status_pass": lineage_check.get("status") == "REAL_MALWARE_DERIVED_SURROGATE_LINEAGE_PASS",
                "six_rows": int(lineage_check.get("row_count") or 0) >= 6,
                "all_rows_pass": lineage_check.get("row_count") == lineage_check.get("row_pass_count"),
            },
            "limitations": ["Lineage is behavior-derived and explicitly not payload-equivalence evidence."],
        },
        {
            "id": "c5_same_set_baseline_comparison",
            "paper_wording": "The six real-malware-derived behaviors have same-set host, strace, QEMU, and 35T board medians recorded.",
            "evidence": [snapshots["baseline"]["path"], "tools/check_35t_behavior_baseline_comparison.py"],
            "checks": {
                "snapshot_present": snapshots["baseline"]["present"],
                "manifest_hashes_valid": not snapshots["baseline"]["hash_errors"],
                "baseline_status_pass": baseline_check.get("status") == "REAL_MALWARE_DERIVED_BASELINE_COMPARISON_PASS",
                "six_rows": int(baseline_check.get("row_count") or 0) >= 6,
                "all_rows_pass": baseline_check.get("row_count") == baseline_check.get("row_pass_count"),
            },
            "limitations": ["Ratios are descriptive; this is not an advanced QEMU-plugin/eBPF comparison."],
        },
        {
            "id": "c6_surrogate_boot_provenance",
            "paper_wording": "The surrogate run records boot provenance status and explicitly names the run-scoped boot-log blocker.",
            "evidence": [snapshots["surrogate_boot"]["path"], "tools/check_35t_surrogate_boot_provenance.py"],
            "checks": {
                "snapshot_present": snapshots["surrogate_boot"]["present"],
                "manifest_hashes_valid": not snapshots["surrogate_boot"]["hash_errors"],
                "boot_status_recorded": boot_pass or boot_deferred,
                "run_artifacts_present": all(boot_check.get("run_artifacts", {}).get("checks", {}).values())
                if isinstance(boot_check.get("run_artifacts"), dict)
                else False,
            },
            "allow_deferred": True,
            "deferred": boot_deferred,
            "limitations": [
                "A deferred status means the paper must not claim a surrogate run-scoped Linux boot log until that log is captured."
            ],
        },
        {
            "id": "c7_true_real_malware_boundary",
            "paper_wording": "True real-malware validation remains a blocked boundary, not a PASS claim.",
            "evidence": [rel(repo_root / REAL_MALWARE_MANIFEST, repo_root), rel(repo_root / REAL_MALWARE_RESULTS_ROOT, repo_root)],
            "checks": {
                "manifest_status_blocked": str(real_malware_manifest.get("status") or "").startswith("BLOCKED"),
                "sample_class_real_malware": real_malware_manifest.get("sample_class") == "real_malware",
                "external_quarantine_hash_only": real_malware_manifest.get("payload_policy") == "external_quarantine_hash_only",
                "repository_payloads_disallowed": real_malware_manifest.get("repository_payloads_allowed") is False,
                "manual_results_absent": manual_results_absent,
            },
            "limitations": ["No true real-malware board-execution evidence is claimed in this package."],
        },
    ]

    deferred_claims: list[str] = []
    for claim in claim_rows:
        checks = claim.get("checks", {}) if isinstance(claim.get("checks"), dict) else {}
        status = claim_status(
            checks,
            allow_deferred=claim.get("allow_deferred") is True,
            deferred=claim.get("deferred") is True,
        )
        claim["status"] = status
        if status == "DEFERRED":
            deferred_claims.append(str(claim["id"]))
        elif status != "PASS":
            failures.extend(f"{claim['id']}:{key}" for key, ok in checks.items() if not ok)

    status = FAIL_STATUS if failures else DEFERRED_BOOT_STATUS if deferred_claims else PASS_STATUS
    return {
        "schema": SCHEMA,
        "status": status,
        "generated_utc": utc_now(),
        "repo_root": repo_root.as_posix(),
        "evidence_root": rel(evidence_root, repo_root),
        "scope": "Artix-7 35T / LiteX / VexRiscv",
        "claim_table_policy": (
            "Paper claims are only allowed when their machine-checkable evidence row is PASS. "
            "DEFERRED rows may be discussed as limitations or required follow-up, not as completed claims."
        ),
        "run_ids": {
            "primary_35t": primary_run_id,
            "surrogate": surrogate_run_id,
            "mirai_reference": mirai_run_id,
        },
        "snapshots": snapshots,
        "claims": claim_rows,
        "deferred_claims": deferred_claims,
        "non_claims": NON_CLAIMS,
        "failures": sorted(set(failures)),
    }


def md_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# 35T Paper Claim Evidence Table",
        "",
        f"Status: {report['status']}",
        "",
        report["claim_table_policy"],
        "",
        "| Claim ID | Status | Paper wording | Evidence | Limitation |",
        "|---|---|---|---|---|",
    ]
    for claim in report["claims"]:
        lines.append(
            "| `{id}` | {status} | {wording} | {evidence} | {limitations} |".format(
                id=claim["id"],
                status=claim["status"],
                wording=md_cell(claim["paper_wording"]),
                evidence=md_cell("; ".join(str(item) for item in claim["evidence"])),
                limitations=md_cell("; ".join(str(item) for item in claim["limitations"])),
            )
        )
    lines += ["", "## Deferred Claims", ""]
    lines.extend(f"- `{item}`" for item in report["deferred_claims"] or ["none"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    return "\n".join(lines) + "\n"


def snapshot_manifest(repo_root: Path, evidence_root: Path, report: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for name in SNAPSHOT_FILES:
        path = evidence_root / name
        if path.is_file():
            rows.append({"artifact": name, "committed_path": rel(path, repo_root), **file_record(path, repo_root)})
    return {
        "schema": "rvmt.35t.paper_claim_evidence_table_snapshot.v1",
        "status": "PASS",
        "generated_utc": utc_now(),
        "claim_level": "35T paper-ready claim/evidence mapping",
        "source_reports": [
            f"docs/results/evidence/{report['run_ids']['primary_35t']}",
            f"docs/results/evidence/{report['run_ids']['surrogate']}",
            f"docs/results/evidence/{report['run_ids']['mirai_reference']}",
            LINEAGE_EVIDENCE_ROOT.as_posix(),
            BASELINE_EVIDENCE_ROOT.as_posix(),
            BOOT_EVIDENCE_ROOT.as_posix(),
        ],
        "committed_artifacts": rows,
        "non_claims": NON_CLAIMS,
    }


def render_readme(report: dict[str, Any]) -> str:
    return (
        "# 35T Paper Claim Evidence Table\n\n"
        f"Status: {report['status']}\n\n"
        "This package maps paper-facing 35T claims to concrete checker outputs, evidence roots, "
        "claim boundaries, and limitations.\n\n"
        "A DEFERRED claim is not a completed result; it is retained as an explicit blocker.\n"
    )


def write_outputs(report: dict[str, Any], repo_root: Path, evidence_root_arg: Path) -> None:
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    evidence_root.mkdir(parents=True, exist_ok=True)
    write_json(evidence_root / "claim_evidence_table.json", report)
    (evidence_root / "claim_evidence_table.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")
    (evidence_root / "README.md").write_text(render_readme(report), encoding="utf-8", newline="\n")
    write_json(evidence_root / "evidence_manifest.json", snapshot_manifest(repo_root, evidence_root, report))


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        a = root / "a.txt"
        a.write_text("alpha\n", encoding="utf-8")
        row = {"artifact": "a.txt", "committed_path": "a.txt", "bytes": a.stat().st_size, "sha256": file_digest(a)}
        if manifest_hash_errors(root, [row]):
            raise AssertionError("valid manifest row reported an error")
        row["bytes"] += 1
        if not manifest_hash_errors(root, [row]):
            raise AssertionError("invalid manifest row did not report an error")
    if claim_status({"a": True}, allow_deferred=True, deferred=True) != "DEFERRED":
        raise AssertionError("deferred claim status failed")
    if claim_status({"a": False}, allow_deferred=True, deferred=True) != "FAIL":
        raise AssertionError("failed checks must fail even when deferred")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--primary-run-id", default=PRIMARY_RUN_ID)
    parser.add_argument("--surrogate-run-id", default=SURROGATE_RUN_ID)
    parser.add_argument("--mirai-run-id", default=MIRAI_RUN_ID)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        print("SELF_TEST_PASS")
        return 0
    repo_root = args.repo_root.resolve()
    report = build_report(
        repo_root,
        args.evidence_root,
        primary_run_id=args.primary_run_id,
        surrogate_run_id=args.surrogate_run_id,
        mirai_run_id=args.mirai_run_id,
    )
    if not args.no_write:
        write_outputs(report, repo_root, args.evidence_root)
    print(report["status"])
    print(f"evidence_root={report['evidence_root']}")
    if report["failures"]:
        for failure in report["failures"]:
            print(f"FAIL {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
