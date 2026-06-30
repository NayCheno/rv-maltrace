from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from experiment_common import (
    file_digest,
    load_json,
    rel,
    repo_path,
    utc_now,
    write_json,
)


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_RESULTS_ROOT = Path("results/experiments/35t") / RUN_ID
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
DEFAULT_OUT_DIR = DEFAULT_RESULTS_ROOT / "raw_artifact_escrow_package"
SCHEMA = "rvmt.35t.raw_artifact_escrow.v1"
STATUS = "LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED"
RAW_SANITIZATION_STATUS = "RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED"
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
]


@dataclass(frozen=True)
class RawClassSpec:
    artifact_id: str
    description: str
    min_count: int
    globs: tuple[str, ...]


RAW_CLASSES = (
    RawClassSpec(
        "raw_uart_log",
        "raw board UART capture logs",
        1,
        ("**/raw_uart.log",),
    ),
    RawClassSpec(
        "decoded_trace_jsonl",
        "decoded per-repetition trace JSONL",
        13,
        ("samples/**/board/trace-on/rep_*/trace.jsonl",),
    ),
)


def class_digest(rows: list[dict[str, Any]]) -> str | None:
    if not rows:
        return None
    digest = hashlib.sha256()
    for row in sorted(rows, key=lambda value: str(value["source_path"])):
        digest.update(str(row["source_path"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(row["bytes"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(row["sha256"]).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def resolve_files(results_root: Path, spec: RawClassSpec) -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()
    for pattern in spec.globs:
        for path in results_root.glob(pattern):
            if not path.is_file():
                continue
            rel_parts = path.resolve().relative_to(results_root.resolve()).parts
            if rel_parts and rel_parts[0] in {"paper_artifact_package", "raw_artifact_escrow_package"}:
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            files.append(path)
            seen.add(resolved)
    return sorted(files, key=lambda item: item.as_posix())


def payload_path_for(source: Path, results_root: Path, out_dir: Path) -> Path:
    return out_dir / "raw_payload" / source.resolve().relative_to(results_root.resolve())


def source_row(repo_root: Path, results_root: Path, out_dir: Path, source: Path) -> dict[str, Any]:
    payload_path = payload_path_for(source, results_root, out_dir)
    return {
        "source_path": rel(source, repo_root),
        "payload_path": rel(payload_path, repo_root),
        "bytes": source.stat().st_size,
        "sha256": file_digest(source),
    }


def source_inventory(repo_root: Path, results_root: Path, out_dir: Path, spec: RawClassSpec) -> dict[str, Any]:
    files = resolve_files(results_root, spec)
    rows = [source_row(repo_root, results_root, out_dir, path) for path in files]
    return {
        "artifact_id": spec.artifact_id,
        "description": spec.description,
        "file_count": len(files),
        "min_count": spec.min_count,
        "total_bytes": sum(int(row["bytes"]) for row in rows),
        "class_digest": class_digest(rows),
        "files": rows,
        "status": "READY_FOR_LOCAL_ESCROW" if len(rows) >= spec.min_count else "MISSING",
    }


def payload_manifest(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "rvmt.35t.raw_artifact_escrow_payload_manifest.v1",
        "run_id": RUN_ID,
        "generated_utc": report["generated_utc"],
        "status": report["payload_status"],
        "source_results_root": report["source_results_root"],
        "package_dir": report["package_dir"],
        "raw_artifact_classes": report["raw_artifact_classes"],
        "access_policy": report["access_policy"],
        "non_claims": NON_CLAIMS,
    }


def render_access_policy(report: dict[str, Any]) -> str:
    policy = report["access_policy"]
    lines = [
        f"# 35T Raw Artifact Escrow Access Policy: {report['run_id']}",
        "",
        f"Status: {policy['status']}",
        "",
        f"Storage: {policy['storage']}",
        "",
        f"Public release: {policy['public_release']}",
        "",
        "## Conditions",
        "",
    ]
    lines.extend(f"- {item}" for item in policy["release_conditions"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in NON_CLAIMS)
    return "\n".join(lines) + "\n"


def render_payload_hashes(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Raw Artifact Escrow Hash Manifest: {report['run_id']}",
        "",
        "| Class | Files | Bytes | Class Digest |",
        "| --- | ---: | ---: | --- |",
    ]
    for row in report["raw_artifact_classes"]:
        lines.append(
            "| `{artifact_id}` | {count} | {bytes} | `{digest}` |".format(
                artifact_id=row["artifact_id"],
                count=row["file_count"],
                bytes=row["total_bytes"],
                digest=row["class_digest"],
            )
        )
    lines += ["", "## Files", "", "| Payload Path | Bytes | SHA-256 |", "| --- | ---: | --- |"]
    for raw_class in report["raw_artifact_classes"]:
        for row in raw_class["files"]:
            lines.append(f"| `{row['payload_path']}` | {row['bytes']} | `{row['sha256']}` |")
    return "\n".join(lines) + "\n"


def render_readme(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Raw Artifact Escrow Package: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Scope: {report['scope']}.",
        "",
        f"Claim level: {report['claim_level']}.",
        "",
        "This is a local controlled escrow package for raw UART logs and decoded trace JSONL. It is not a public release.",
        "",
        "## Contents",
        "",
        "- `raw_payload/`: copied local raw UART and decoded trace JSONL files",
        "- `payload_manifest.json`: complete path, size, and hash inventory",
        "- `payload_hash_manifest.md`: human-readable hash inventory",
        "- `access_policy.md`: local access and public-release conditions",
        "",
        "## Raw Classes",
        "",
        "| Class | Files | Bytes | Status |",
        "| --- | ---: | ---: | --- |",
    ]
    for row in report["raw_artifact_classes"]:
        lines.append(f"| `{row['artifact_id']}` | {row['file_count']} | {row['total_bytes']} | `{row['status']}` |")
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in NON_CLAIMS)
    return "\n".join(lines) + "\n"


def render_evidence(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Raw Artifact Escrow: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Payload status: {report['payload_status']}",
        "",
        f"Package dir: `{report['package_dir']}`",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += [
        "",
        "## Raw Artifact Classes",
        "",
        "| Class | Files | Bytes | Class Digest |",
        "| --- | ---: | ---: | --- |",
    ]
    for row in report["raw_artifact_classes"]:
        lines.append(
            "| `{artifact_id}` | {count}/{minimum} | {bytes} | `{digest}` |".format(
                artifact_id=row["artifact_id"],
                count=row["file_count"],
                minimum=row["min_count"],
                bytes=row["total_bytes"],
                digest=row["class_digest"],
            )
        )
    lines += [
        "",
        "## Interpretation",
        "",
    ]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def copy_payload_files(repo_root: Path, results_root: Path, out_dir: Path, classes: list[dict[str, Any]]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for raw_class in classes:
        for row in raw_class["files"]:
            source = repo_path(repo_root, Path(str(row["source_path"]))).resolve()
            dest = repo_path(repo_root, Path(str(row["payload_path"]))).resolve()
            expected_base = (out_dir / "raw_payload").resolve()
            if not dest.is_relative_to(expected_base):
                raise ValueError(f"refusing to write outside escrow payload dir: {dest}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, dest)


def write_package_outputs(repo_root: Path, out_dir: Path, report: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "payload_manifest.json", payload_manifest(report))
    (out_dir / "payload_hash_manifest.md").write_text(render_payload_hashes(report), encoding="utf-8", newline="\n")
    (out_dir / "access_policy.md").write_text(render_access_policy(report), encoding="utf-8", newline="\n")
    (out_dir / "README.md").write_text(render_readme(report), encoding="utf-8", newline="\n")


def payload_file_ok(repo_root: Path, row: dict[str, Any]) -> bool:
    payload = repo_path(repo_root, Path(str(row["payload_path"])))
    return payload.is_file() and payload.stat().st_size == row["bytes"] and file_digest(payload) == row["sha256"]


def package_generated_files(repo_root: Path, out_dir: Path) -> list[str]:
    names = ("README.md", "payload_manifest.json", "payload_hash_manifest.md", "access_policy.md")
    return [rel(out_dir / name, repo_root) for name in names]


def build_report(
    repo_root_arg: Path,
    results_root_arg: Path,
    evidence_root_arg: Path,
    out_dir_arg: Path,
    *,
    write_payload: bool,
) -> dict[str, Any]:
    repo_root = repo_root_arg.resolve()
    results_root = repo_path(repo_root, results_root_arg).resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    out_dir = repo_path(repo_root, out_dir_arg).resolve()
    raw_sanitization_path = evidence_root / "raw_artifact_sanitization.json"
    raw_sanitization = load_json(raw_sanitization_path) if raw_sanitization_path.is_file() else {}

    classes = [source_inventory(repo_root, results_root, out_dir, spec) for spec in RAW_CLASSES]
    if write_payload:
        copy_payload_files(repo_root, results_root, out_dir, classes)

    payload_manifest_path = out_dir / "payload_manifest.json"
    generated_files = package_generated_files(repo_root, out_dir)
    payload_rows = [row for raw_class in classes for row in raw_class["files"]]
    checks = {
        "results_root_exists": results_root.is_dir(),
        "raw_sanitization_ready": raw_sanitization.get("status") == RAW_SANITIZATION_STATUS,
        "all_raw_classes_present": all(raw_class["file_count"] >= raw_class["min_count"] for raw_class in classes),
        "payload_files_present_and_hashed": all(payload_file_ok(repo_root, row) for row in payload_rows),
        "package_manifest_present": payload_manifest_path.is_file() if not write_payload else True,
        "package_generated_files_present": all(repo_path(repo_root, Path(path)).is_file() for path in generated_files)
        if not write_payload
        else True,
        "public_release_deferred": True,
    }
    failures = [key for key, ok in checks.items() if not ok]
    report = {
        "schema": SCHEMA,
        "run_id": RUN_ID,
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "generated_utc": utc_now(),
        "status": STATUS if not failures else "FAIL",
        "payload_status": "LOCAL_CONTROLLED_ESCROW_PACKAGE_READY" if not failures else "INCOMPLETE",
        "source_results_root": rel(results_root, repo_root),
        "evidence_root": rel(evidence_root, repo_root),
        "package_dir": rel(out_dir, repo_root),
        "generated_files": generated_files,
        "payload_file_count": len(payload_rows),
        "payload_total_bytes": sum(int(row["bytes"]) for row in payload_rows),
        "raw_artifact_classes": classes,
        "checks": checks,
        "access_policy": {
            "status": "LOCAL_CONTROLLED_ACCESS_PUBLIC_RELEASE_DEFERRED",
            "storage": "local workspace results directory",
            "public_release": "not public; explicit sanitization and distribution approval required",
            "release_conditions": [
                "raw UART and decoded trace JSONL remain local until reviewed for disclosure risk",
                "public release requires an approved controlled-release destination or sanitized replacements",
                "hashes in this report are the verification handle for any later release",
            ],
        },
        "interpretation": [
            "full raw UART and decoded trace JSONL are copied into a local controlled escrow package",
            "the evidence summary records counts, sizes, and hashes but does not publish raw payloads in docs",
            "P6 full public raw release remains deferred until an approved release or sanitized replacement exists",
        ],
        "non_claims": NON_CLAIMS,
        "failures": failures,
    }
    if write_payload:
        write_package_outputs(repo_root, out_dir, report)
        checks["package_manifest_present"] = payload_manifest_path.is_file()
        checks["package_generated_files_present"] = all(repo_path(repo_root, Path(path)).is_file() for path in generated_files)
        report["failures"] = [key for key, ok in checks.items() if not ok]
        report["status"] = STATUS if not report["failures"] else "FAIL"
        report["payload_status"] = "LOCAL_CONTROLLED_ESCROW_PACKAGE_READY" if not report["failures"] else "INCOMPLETE"
    return report


def write_evidence(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    write_json(evidence_root / "raw_artifact_escrow.json", report)
    (evidence_root / "raw_artifact_escrow.md").write_text(render_evidence(report), encoding="utf-8", newline="\n")


def write_fixture(root: Path, *, missing_trace: bool = False) -> None:
    results = root / DEFAULT_RESULTS_ROOT
    evidence = root / DEFAULT_EVIDENCE_ROOT
    (results / "board").mkdir(parents=True, exist_ok=True)
    (results / "board/raw_uart.log").write_text("uart line\n", encoding="utf-8")
    if not missing_trace:
        for idx in range(13):
            trace = results / f"samples/malware_like_synthetic/sample_{idx}/board/trace-on/rep_00/trace.jsonl"
            trace.parent.mkdir(parents=True, exist_ok=True)
            trace.write_text(json.dumps({"record_index": idx, "evt": "SYSCALL"}) + "\n", encoding="utf-8")
    write_json(
        evidence / "raw_artifact_sanitization.json",
        {"schema": "rvmt.35t.raw_artifact_sanitization.v1", "status": RAW_SANITIZATION_STATUS},
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        report = build_report(root, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT, DEFAULT_OUT_DIR, write_payload=True)
        if report["status"] != STATUS or report["payload_file_count"] != 14:
            print("[FAIL] expected fixture escrow package to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_evidence(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "raw_artifact_escrow.md").is_file():
            print("[FAIL] missing escrow markdown evidence", file=sys.stderr)
            return 1
        verify = build_report(root, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT, DEFAULT_OUT_DIR, write_payload=False)
        if verify["status"] != STATUS:
            print("[FAIL] expected no-write fixture verification to pass", file=sys.stderr)
            print(json.dumps(verify, indent=2), file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root, missing_trace=True)
        report = build_report(root, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT, DEFAULT_OUT_DIR, write_payload=True)
        if report["status"] != "FAIL" or "all_raw_classes_present" not in report["failures"]:
            print("[FAIL] expected missing trace fixture to fail", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
    print("[PASS] 35T raw artifact escrow self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create or verify a local 35T raw artifact escrow package.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        report = build_report(
            args.repo_root,
            args.results_root,
            args.evidence_root,
            args.out_dir,
            write_payload=not args.no_write,
        )
        if not args.no_write:
            evidence_root = repo_path(args.repo_root.resolve(), args.evidence_root)
            write_evidence(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_raw_artifact_escrow: error: {exc}", file=sys.stderr)
        return 1
    print(f"[{report['status']}] raw artifact escrow: {report['payload_file_count']} files")
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
